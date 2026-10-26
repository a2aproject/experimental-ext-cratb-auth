# SPDX-License-Identifier: Apache-2.0
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .models import (
    IdentityChallenge,
    TunneledChallenge,
    TunneledResponse,
)
from .wallet import SDJWTWallet

EXTENSION_URI = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"

_AGENT_CARD_PREFIX = "a2a_agent_card:"


_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
# Malformed percent escapes, and encoded separators (%2f, %5c) or percent signs (%25).
_FORBIDDEN_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})|%(?:2[fF]|5[cC]|25)")


def _canonical_https_url(url: str) -> str:
    """
    Spec 8.1.1 canonical HTTPS URL. Rejects ambiguous forms with ValueError instead of repairing
    them: userinfo, query, fragment, backslashes, whitespace/control characters, malformed or
    forbidden percent escapes, dot-segments, IP-form hosts and invalid ports.
    """
    if any(c in url for c in "\\?#") or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        raise ValueError(f"'{url}' contains a query, fragment, backslash, whitespace or control character")
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ValueError(f"'{url}' is not an absolute https URL")
    if "@" in parts.netloc:
        raise ValueError(f"'{url}' contains userinfo")
    host = parts.hostname.lower()
    labels = host.split(".")
    if (
        not all(_DNS_LABEL.match(label) for label in labels)
        or labels[-1].isdigit()
        or labels[-1].startswith("0x")
    ):
        raise ValueError(f"'{url}' does not have an ASCII DNS host name")
    port_text = parts.netloc.rpartition(":")[2] if ":" in parts.netloc else ""
    if port_text and (not port_text.isdigit() or port_text.startswith("0")):
        raise ValueError(f"'{url}' has an invalid port")
    port = parts.port or 443  # raises ValueError for an out-of-range port
    path = parts.path or "/"
    if _FORBIDDEN_ESCAPE.search(path):
        raise ValueError(f"'{url}' has a malformed or forbidden percent escape in its path")
    if any(seg.lower().replace("%2e", ".") in (".", "..") for seg in path.split("/")):
        raise ValueError(f"'{url}' contains a dot-segment")
    return f"https://{host}{'' if port == 443 else f':{port}'}{path}"


def _https_origin(url: str) -> tuple:
    """(scheme, host, effective port) of a canonical https URL; ValueError for anything else."""
    parts = urlsplit(_canonical_https_url(url))
    return ("https", parts.hostname, parts.port or 443)


def _check_verifier_origin(
    client_id: str, contacted_url: Optional[str], expected_url: Optional[str] = None
) -> None:
    """
    Spec 8.1.1 Direct Holder authentication: the challenge's `client_id` must name the peer the
    Holder actually contacted. The suffix of an `a2a_agent_card:` identifier (or the whole value
    for a plain URL) must be a canonical https URL with the same origin as `contacted_url`. If the
    caller passes `expected_url` (the independently obtained Agent Card or interface URL), the
    suffix must equal it exactly. A missing `contacted_url` or any mismatch refuses presentation
    generation.
    """
    if not contacted_url:
        raise ValueError("contacted_url is required: cannot authenticate the verifier's client_id")
    url = client_id[len(_AGENT_CARD_PREFIX):] if client_id.startswith(_AGENT_CARD_PREFIX) else client_id
    try:
        suffix = _canonical_https_url(url)
        same = _https_origin(suffix) == _https_origin(contacted_url)
        expected = _canonical_https_url(expected_url) if expected_url else None
    except ValueError as exc:
        raise ValueError(f"Challenge client_id '{client_id}' cannot be bound to the contacted peer: {exc}") from exc
    if not same:
        raise ValueError(
            f"Challenge client_id '{client_id}' does not match the contacted verifier '{contacted_url}'"
        )
    if expected is not None and suffix != expected:
        raise ValueError(
            f"Challenge client_id '{client_id}' does not equal the expected Agent Card URL '{expected_url}'"
        )


class ClientAuthHandler:
    """
    A2A Client handler that processes AUTH_REQUIRED task status responses and generates IdentityResponses.
    """
    def __init__(self, wallet: SDJWTWallet) -> None:
        self.wallet = wallet

    def is_auth_required(self, task_status_response: Dict[str, Any]) -> bool:
        """
        Checks if the A2A response is in state TASK_STATE_AUTH_REQUIRED and contains an IdentityChallenge.
        """
        state = task_status_response.get("state")
        if state is None:
            state = task_status_response.get("status", {}).get("state", "")
        if state != "TASK_STATE_AUTH_REQUIRED":
            return False
        message = task_status_response.get("message")
        if message is None:
            message = task_status_response.get("status", {}).get("message", {})
        meta = message.get("metadata", {})
        return EXTENSION_URI in meta

    def handle_auth_challenge(
        self,
        task_status_response: Dict[str, Any],
        contacted_url: str,
        conversation_id: Optional[str] = None,
        domains: Optional[List[str]] = None,
        expected_client_url: Optional[str] = None,
        channel_binding: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Extracts the IdentityChallenge and generates a follow-up message metadata payload containing vp_token.

        `contacted_url` is the https interface or Agent Card URL the caller actually connected to
        (the SDK has no TLS context). The challenge `client_id` must have the same origin (spec 8.1.1);
        otherwise nothing is signed. `expected_client_url` is the independently obtained Agent Card
        or interface URL; when given, the `client_id` suffix must equal it exactly.
        `channel_binding` is the encoded tls-exporter value of the TLS 1.3 connection that will
        carry the Identity Response; it is required when the Verifier's Agent Card declares
        `channel_binding` (spec 12.8).
        """
        message = task_status_response.get("message")
        if message is None:
            message = task_status_response.get("status", {}).get("message", {})
        ext_meta = message.get("metadata", {}).get(EXTENSION_URI, {})

        challenge = IdentityChallenge.model_validate(ext_meta)

        _check_verifier_origin(challenge.client_id, contacted_url, expected_client_url)

        if challenge.response_mode and challenge.response_mode != "a2a_metadata":
            raise ValueError(
                f"Unsupported response_mode '{challenge.response_mode}'; expected 'a2a_metadata'"
            )

        vp_response = self.wallet.create_vp_token(
            dcql_query=challenge.dcql_query,
            nonce=challenge.nonce,
            client_id=challenge.client_id,
            conversation_id=conversation_id,
            domains=domains,
            channel_binding=channel_binding,
        )

        return {
            EXTENSION_URI: vp_response.model_dump(by_alias=True)
        }

    def extract_tunneled_challenge(
        self, task_status_response: Dict[str, Any]
    ) -> Optional[TunneledChallenge]:
        """
        Spec 12.6.1 Rule 5: returns the tunneled challenge if this response carries one, else None.
        A tunneled challenge is never conflated with the relaying agent's own IdentityChallenge.
        """
        message = task_status_response.get("message")
        if message is None:
            message = task_status_response.get("status", {}).get("message", {})
        ext_meta = (
            message.get("metadata", {}).get(EXTENSION_URI, {})
        )
        raw = ext_meta.get("tunneled_challenge")
        if not raw:
            return None
        return TunneledChallenge.model_validate(raw)

    def handle_tunneled_challenge(
        self,
        tunneled: TunneledChallenge,
        conversation_id: Optional[str] = None,
        domains: Optional[List[str]] = None,
        tunnel_policy: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Spec 12.6.1 Rules 2 & 3: binds the KB-JWT to the *terminal verifier's* nonce and client_id
        taken from the inner challenge, and returns metadata carrying a tunneled_response envelope.
        `tunnel_policy` is required (spec 12.6.1: missing policy MUST cause refusal) and must
        provide `is_terminal_allowed(client_id) -> bool`.
        """
        challenge = tunneled.challenge

        if tunnel_policy is None or not hasattr(tunnel_policy, "is_terminal_allowed"):
            raise ValueError("A tunnel_policy with is_terminal_allowed() is required to answer a tunneled challenge")
        if not tunnel_policy.is_terminal_allowed(challenge.client_id):
            raise ValueError(
                f"Terminal client_id '{challenge.client_id}' not permitted by TunnelPolicy"
            )

        vp_response = self.wallet.create_vp_token(
            dcql_query=challenge.dcql_query,
            nonce=challenge.nonce,        # Rule 2: terminal verifier's nonce
            client_id=challenge.client_id,  # Rule 2: terminal verifier's client_id
            conversation_id=conversation_id,
            domains=domains,
            # Spec 12.8: a tunneled presentation never carries channel_binding; the terminal
            # verifier receives it over the relay's connection, not this one.
        )
        envelope = TunneledResponse(
            origin_task_id=tunneled.origin_task_id,
            response=vp_response.vp_token,
        )
        return {EXTENSION_URI: {"tunneled_response": envelope.model_dump()}}

