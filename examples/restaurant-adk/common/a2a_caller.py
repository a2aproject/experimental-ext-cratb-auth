# SPDX-License-Identifier: Apache-2.0
"""A2A client module for verifiable credential authentication.

Sends A2A messages, handles OpenID4VP challenges, and presents VP tokens.
Also handles the Delegated Challenge Tunneling Profile (spec 12.6.1):
- An Intermediate Agent gets TunnelRequired when a challenge asks for a
  credential that its own wallet does not hold.
- A Holder Agent answers a tunneled_challenge only if its TunnelPolicy allows it.
"""

import os
import uuid
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional

import httpx
from google.adk.agents.remote_a2a_agent import AGENT_CARD_WELL_KNOWN_PATH
from google.protobuf.json_format import MessageToDict, ParseDict

from a2a.client import A2ACardResolver, ClientCallContext, ClientConfig, ClientFactory
from a2a.types import a2a_pb2

from a2a_agentic_id import (
    EXTENSION_URI,
    ClientAuthHandler,
    IdentityChallenge,
    SDJWTWallet,
    TunneledChallenge,
)

from common.exchange_log import (
    MULTI_HOP,
    SINGLE_HOP,
    fmt_dcql,
    hop_banner,
    hop_route,
    hop_steps,
    log,
    log_recv,
    log_send,
    redact,
    truncate,
)

_HTTP_TIMEOUT_SECONDS = float(os.environ.get("A2A_CALL_TIMEOUT_SECONDS", "180.0"))
# One send, one direct challenge, and one tunneled challenge.
_MAX_ATTEMPTS = 3
_VP_FORMATS = {"vp_formats_supported": {"dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}}}

# One A2A client for each agent base URL.
_CLIENTS: Dict[str, Any] = {}


class IdentityGateError(Exception):
    """Raised when identity gate rejects request."""

    def __init__(self, error_code: Optional[str], message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


class TunnelRequired(Exception):
    """Raised when a callee asks for a credential that the caller does not hold.

    The caller is an Intermediate Agent. It must relay the challenge to the
    Holder Agent as a tunneled_challenge (spec 12.6.1 Rule 1). It must not
    answer the challenge with its own wallet (Rule 5).
    """

    def __init__(self, tunneled: TunneledChallenge) -> None:
        super().__init__(
            f"Challenge from '{tunneled.challenge.client_id}' must be tunneled to the holder"
        )
        self.tunneled = tunneled


@dataclass(frozen=True)
class TunnelPolicy:
    """Holder rules for tunneled challenges.

    A tunneled challenge arrives through an intermediate agent. The spec does
    not require these rules. Without them, the holder signs every challenge
    that an intermediate relays.
    """

    allowed_verifiers: FrozenSet[str]
    allowed_credentials: FrozenSet[str]

    def is_terminal_allowed(self, client_id: str) -> bool:
        """Terminal check the SDK's handle_tunneled_challenge requires (spec 12.6.1)."""
        return client_id in self.allowed_verifiers

    def rejection(self, challenge: IdentityChallenge) -> Optional[str]:
        """Return the reason to refuse the challenge, or None to accept it."""
        if challenge.client_id not in self.allowed_verifiers:
            return f"verifier '{challenge.client_id}' is not allowed"
        requested = {cred.id for cred in challenge.dcql_query.credentials}
        refused = requested - self.allowed_credentials
        if refused:
            return f"credentials {sorted(refused)} are not allowed"
        return None


@dataclass(frozen=True)
class A2ACallResult:
    """Text and extension metadata of the callee's final reply."""

    text: str
    ext_metadata: Dict[str, Any]


@dataclass(frozen=True)
class _Reply:
    """One reply from the callee."""

    state: Optional[int]
    task_id: str
    text: str
    ext_metadata: Dict[str, Any]


async def _get_client(base_url: str, caller: str, callee: str) -> Any:
    """Return the A2A client for an agent. Fetch its agent card on the first call."""
    if base_url in _CLIENTS:
        return _CLIENTS[base_url]

    httpx_client = httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS)
    log_send(caller, callee, f"GET {AGENT_CARD_WELL_KNOWN_PATH} (discovering agent capabilities)")
    resolver = A2ACardResolver(httpx_client, base_url, agent_card_path=AGENT_CARD_WELL_KNOWN_PATH)
    card = await resolver.get_agent_card()
    extensions = {ext.uri for ext in card.capabilities.extensions}
    log_recv(caller, callee, f"agent-card: name='{card.name}', {len(extensions)} extension(s) declared")
    if EXTENSION_URI not in extensions:
        raise IdentityGateError(None, f"Agent card at {base_url} does not declare {EXTENSION_URI}")

    client = ClientFactory(ClientConfig(httpx_client=httpx_client, streaming=False)).create(card)
    _CLIENTS[base_url] = client
    return client


def _agent_message(task: a2a_pb2.Task) -> Optional[a2a_pb2.Message]:
    """Return the agent reply from the task artifacts, status, or history."""
    if task.artifacts:
        return a2a_pb2.Message(role=a2a_pb2.Role.ROLE_AGENT, parts=task.artifacts[-1].parts)
    if task.status.message.parts:
        return task.status.message
    for message in reversed(task.history):
        if message.role == a2a_pb2.Role.ROLE_AGENT:
            return message
    return None


def _ext_metadata(message: a2a_pb2.Message) -> Dict[str, Any]:
    """Return the extension metadata of a reply.

    Spec A.3 puts it at message.metadata[ext_uri] (for a challenge, the task's
    status message). Part metadata is read as a fallback for callees that still
    emit the earlier layout.
    """
    meta = MessageToDict(message.metadata)
    if EXTENSION_URI in meta:
        return meta[EXTENSION_URI]
    for part in message.parts:
        meta = MessageToDict(part.metadata)
        if EXTENSION_URI in meta:
            return meta[EXTENSION_URI]
    return {}


async def _send(client: Any, text: str, *, context_id: str, ext_metadata: Dict[str, Any]) -> _Reply:
    """Send one A2A message and return the callee's reply."""
    request = a2a_pb2.SendMessageRequest()
    request.message.message_id = uuid.uuid4().hex
    request.message.context_id = context_id
    request.message.role = a2a_pb2.Role.ROLE_USER
    request.message.parts.add().text = text
    # Spec A.2/A.4 place extension content on the Message. Unmodified ADK servers
    # only surface request-level metadata to the identity gate, so send both.
    ParseDict({EXTENSION_URI: ext_metadata}, request.message.metadata)
    ParseDict({EXTENSION_URI: ext_metadata}, request.metadata)
    # Spec 6 / A.2: activation is an explicit A2A-Extensions service parameter.
    call_context = ClientCallContext(service_parameters={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"})

    state, task_id, message = None, context_id, None
    async for item in client.send_message(request, context=call_context):
        if item.HasField("task"):
            state, task_id, message = item.task.status.state, item.task.id, _agent_message(item.task)
        elif item.HasField("message"):
            message = item.message

    if message is None:
        if state is None:
            raise IdentityGateError(None, "Callee returned neither a task nor a message")
        return _Reply(state, task_id, "", {})
    text = "\n".join(part.text for part in message.parts if part.text)
    return _Reply(state, task_id, text, _ext_metadata(message))


def _answer_direct_challenge(
    challenge: IdentityChallenge,
    *,
    origin_task_id: str,
    wallet: SDJWTWallet,
    can_tunnel: bool,
    context_id: str,
    caller: str,
    callee: str,
) -> Dict[str, Any]:
    """Create the vp_token metadata for a challenge from the callee.

    Raises TunnelRequired if this agent is a relay and does not hold the
    credential. Raises IdentityGateError if the wallet cannot answer.
    """
    verifier = challenge.client_id
    cred_ids = [c.id for c in challenge.dcql_query.credentials]
    missing = [cid for cid in cred_ids if wallet.get_credential(cid) is None]
    received = (
        f"OpenID4VP challenge: nonce={redact(challenge.nonce)} aud={verifier} "
        f"DCQL=[{fmt_dcql(challenge.dcql_query)}]"
    )

    if missing and can_tunnel:
        # This agent is the relay. The holder is further upstream.
        hop_banner(
            caller,
            MULTI_HOP,
            f"{verifier} verifies {', '.join(repr(c) for c in missing)} through {caller}",
            hop_route("upstream holder", verifier, caller),
            f"{verifier} asks for a credential that {caller} does not hold. {caller} acts as relay only.",
        )
        log_recv(caller, callee, received, hop=MULTI_HOP, step=1)
        log(
            caller,
            f"OpenID4VP: wallet does not hold {missing}. This agent is not the holder. "
            f"It must not answer with another credential (Rule 5). -> tunnel it upstream",
            hop=MULTI_HOP,
            step=1,
        )
        raise TunnelRequired(TunneledChallenge(origin_task_id=origin_task_id, challenge=challenge))

    hop_banner(
        caller,
        SINGLE_HOP,
        f"{callee} verifies {caller}'s {', '.join(repr(c) for c in cred_ids)}",
        hop_route(caller, callee),
        f"{callee} challenges {caller} directly. {caller} holds the credential.",
    )
    log_recv(caller, callee, received, hop=SINGLE_HOP, step=1)
    if missing:
        log(caller, f"wallet does not hold {missing} -> cannot answer", hop=SINGLE_HOP, step=2)
        raise IdentityGateError(None, f"Wallet does not hold the requested credentials {missing}")

    log(
        caller,
        f"OpenID4VP: matched DCQL -> creating SD-JWT VP token ({', '.join(cred_ids)}) "
        f"bound to nonce={redact(challenge.nonce)} aud={verifier}",
        hop=SINGLE_HOP,
        step=2,
    )
    response = wallet.create_vp_token(
        challenge.dcql_query,
        nonce=challenge.nonce,
        client_id=verifier,
        conversation_id=context_id,
    )
    return {"vp_token": response.vp_token}


def _answer_tunneled_challenge(
    tunneled: TunneledChallenge,
    *,
    wallet: SDJWTWallet,
    policy: Optional[TunnelPolicy],
    context_id: str,
    caller: str,
    callee: str,
) -> Dict[str, Any]:
    """Create the tunneled_response metadata for a tunneled challenge.

    Raises IdentityGateError if the policy refuses the challenge, or if the
    wallet does not hold the requested credentials.
    """
    challenge = tunneled.challenge
    hop_banner(
        caller,
        MULTI_HOP,
        f"{challenge.client_id} verifies {caller}'s "
        f"{', '.join(repr(c.id) for c in challenge.dcql_query.credentials)} through {callee}",
        hop_route(caller, challenge.client_id, callee),
        f"{callee} relays a challenge from {challenge.client_id}. {callee} is not the verifier.",
    )
    log_recv(
        caller,
        callee,
        f"tunneled_challenge (12.6.1): from terminal verifier '{challenge.client_id}', "
        f"relayed by '{callee}'. nonce={redact(challenge.nonce)} "
        f"DCQL=[{fmt_dcql(challenge.dcql_query)}]",
        hop=MULTI_HOP,
        step=2,
    )

    if policy is None:
        log(caller, "tunneled_challenge refused: this agent accepts no tunneled challenges", hop=MULTI_HOP, step=3)
        raise IdentityGateError(None, "Tunneled challenges are not accepted by this agent")
    reason = policy.rejection(challenge)
    if reason:
        log(caller, f"tunneled_challenge refused by holder policy: {reason}", hop=MULTI_HOP, step=3)
        raise IdentityGateError(None, f"Tunneled challenge refused: {reason}")

    log(
        caller,
        f"holder policy accepts: verifier '{challenge.client_id}' and the requested credentials are allowed",
        hop=MULTI_HOP,
        step=3,
    )
    log(
        caller,
        f"OpenID4VP: binding KB-JWT to terminal verifier aud='{challenge.client_id}', "
        f"not to relay '{callee}' (12.6.1 Rule 2). The relay cannot reuse it.",
        hop=MULTI_HOP,
        step=3,
    )
    try:
        metadata = ClientAuthHandler(wallet).handle_tunneled_challenge(
            tunneled,
            conversation_id=context_id,
            domains=[challenge.client_id],
            tunnel_policy=policy,
        )
    except ValueError as exc:
        raise IdentityGateError(None, f"Cannot answer tunneled challenge: {exc}") from exc
    return metadata[EXTENSION_URI]


async def call_with_identity(
    base_url: str,
    text: str,
    *,
    context_id: str,
    wallet: SDJWTWallet,
    caller: str,
    callee: str,
    can_tunnel: bool = False,
    tunnel_policy: Optional[TunnelPolicy] = None,
    forward_vp_token: Optional[Dict[str, List[str]]] = None,
) -> A2ACallResult:
    """Send text to target agent and satisfy OpenID4VP challenges.

    Args:
        can_tunnel: Set to True for an Intermediate Agent. If a challenge asks
            for a credential that the wallet does not hold, the function raises
            TunnelRequired. It does not answer with a different credential.
        tunnel_policy: Set for a Holder Agent. The function answers a
            tunneled_challenge only if the policy accepts it. If the policy is
            None, the function refuses all tunneled challenges.
        forward_vp_token: Set to send a vp_token from a tunneled_response in
            the first message. The function sends it unchanged (spec 12.6.1 Rule 4).
    """
    client = await _get_client(base_url, caller, callee)

    ext_metadata: Dict[str, Any] = _VP_FORMATS
    note = f'send message: "{truncate(text, 60)}"'
    # Hop tag of the next send: (hop, step), or None for a plain message.
    send_hop: Optional[tuple[str, int]] = None
    if forward_vp_token is not None:
        ext_metadata = {"vp_token": forward_vp_token}
        note = (
            f"forward holder's vp_token unchanged (12.6.1 Rule 4): credentials={sorted(forward_vp_token)}. "
            f"{callee} validates it."
        )
        send_hop = (MULTI_HOP, 4)

    for _ in range(_MAX_ATTEMPTS):
        hop, sent_step = send_hop or (None, None)
        log_send(caller, callee, note, hop=hop, step=sent_step)
        reply = await _send(client, text, context_id=context_id, ext_metadata=ext_metadata)
        ext = reply.ext_metadata

        # Spec 12.6.1 Rule 5: examine a tunneled challenge before a direct
        # challenge. The two challenges have different nonces and client_ids.
        if ext.get("tunneled_challenge"):
            ext_metadata = _answer_tunneled_challenge(
                TunneledChallenge.model_validate(ext["tunneled_challenge"]),
                wallet=wallet,
                policy=tunnel_policy,
                context_id=context_id,
                caller=caller,
                callee=callee,
            )
            note = "send tunneled_response to relay (12.6.1 Rule 3). The relay forwards it."
            send_hop = (MULTI_HOP, 3)
            continue

        if reply.state == a2a_pb2.TaskState.TASK_STATE_AUTH_REQUIRED or ext.get("status") == "identity_required":
            ext_metadata = _answer_direct_challenge(
                IdentityChallenge.model_validate(ext),
                origin_task_id=reply.task_id,
                wallet=wallet,
                can_tunnel=can_tunnel,
                context_id=context_id,
                caller=caller,
                callee=callee,
            )
            note = "resend message with OpenID4VP presentation (vp_token)"
            send_hop = (SINGLE_HOP, 2)
            continue

        # The verifier logs the result. The caller logs the reply with the same
        # hop tag, as the last step of the sequence.
        step = hop_steps(hop) if hop else None
        if reply.state == a2a_pb2.TaskState.TASK_STATE_FAILED or ext.get("status") == "failed":
            log_recv(caller, callee, f"OpenID4VP auth FAILED: {ext.get('error') or reply.text}", hop=hop, step=step)
            raise IdentityGateError(ext.get("error"), reply.text)
        if hop == MULTI_HOP and sent_step == 3:
            log_recv(caller, callee, "relay returned the terminal verifier's reply: presentation accepted", hop=hop, step=step)
        elif hop:
            log_recv(caller, callee, "presentation accepted by verifier", hop=hop, step=step)
        log_recv(caller, callee, f'response: "{truncate(reply.text, 70)}"')
        return A2ACallResult(text=reply.text, ext_metadata=ext)

    raise IdentityGateError(None, "Identity challenge/response exceeded retry limit")
