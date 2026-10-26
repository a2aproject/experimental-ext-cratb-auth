# SPDX-License-Identifier: Apache-2.0
"""Server-side identity gate adapting ServerAuthRequiredInterceptor to ADK callbacks.

Verifies caller SD-JWT credentials during before_agent_callback execution.
Supports mid-task step-up challenges via after_agent_callback.
Supports the Intermediate Agent role of the Delegated Challenge Tunneling
Profile (spec 12.6.1) through tunnel_upstream and take_tunneled_response.
"""

from typing import Any, Dict, Optional

from google.adk.agents.callback_context import CallbackContext
from google.genai import types as genai_types

from a2a_agentic_id import (
    EXTENSION_URI,
    A2ATaskMessage,
    A2ATaskStatusResponse,
    DCQLQuery,
    SDJWTVerifier,
    ServerAuthRequiredInterceptor,
    TunneledChallenge,
    TunneledResponse,
)
from a2a_agentic_id import ExtensionSupportRequiredError
from a2a_agentic_id.verifier import VerificationResult

from common.exchange_log import (
    MULTI_HOP,
    SINGLE_HOP,
    Hop,
    fmt_claims,
    fmt_dcql,
    hop_route,
    log,
    log_recv,
    log_send,
    redact,
)
from common.identity import CALLER_OF

STATE_VERIFIED_IDENTITY = "identity_gate.verified"
STATE_PENDING_EXTENSION_METADATA = "identity_gate.pending_extension_metadata"
STATE_PENDING_TUNNELS = "identity_gate.pending_tunnels"


def _cred_ids(dcql_query: Any) -> str:
    """Return the credential IDs of a DCQL query, for log messages."""
    creds = getattr(dcql_query, "credentials", None) or []
    return ", ".join(f"'{c.id}'" for c in creds) or "'?'"


def extract_incoming_extension_metadata(context: Any) -> Dict[str, Any]:
    """Return the extension metadata of the incoming A2A request."""
    a2a_metadata = context.custom_metadata.get("a2a_metadata")
    if not isinstance(a2a_metadata, dict):
        return {}
    return a2a_metadata.get(EXTENSION_URI, {})


def _metadata_content(metadata: Dict[str, Any], text: str) -> genai_types.Content:
    """Return a reply whose part carries extension metadata."""
    part = genai_types.Part(text=text)
    part.part_metadata = {EXTENSION_URI: metadata}
    return genai_types.Content(role="model", parts=[part])


class IdentityGate:
    """ADK before_agent_callback hook for credential verification."""

    def __init__(self, verifier: SDJWTVerifier, dcql_query: Optional[DCQLQuery] = None) -> None:
        self.name = verifier.client_id
        self.dcql_query = dcql_query
        # ADK callbacks run in-process and expose no transport connection to bind to (spec 5.5
        # item 2). A deployment behind a real A2A transport must pass the connection identity as
        # A2ATaskMessage.channel_id and leave require_channel_binding at its default.
        self._interceptor = ServerAuthRequiredInterceptor(
            verifier=verifier, dcql_query=dcql_query, require_channel_binding=False
        )
        # ADK session id -> the task id the interceptor allocated for it (A2A 3.4.2: task ids are
        # server-generated, so the ADK session id is never used as one).
        self._task_ids: Dict[str, str] = {}

    def task_id_for(self, session_id: str) -> str:
        """The interceptor-allocated task id for an ADK session, once its first turn has been seen."""
        return self._task_ids.get(session_id, session_id)

    def __call__(self, callback_context: CallbackContext) -> Optional[genai_types.Content]:
        """Intercept unauthenticated turns and process OpenID4VP challenges."""
        callee = callback_context.agent_name or self.name
        caller = CALLER_OF.get(callee, "caller_agent")
        hop = Hop(SINGLE_HOP, callee)
        incoming = extract_incoming_extension_metadata(callback_context)
        session_id = callback_context.session.id
        task_id = self._task_ids.get(session_id)  # None on the first turn: the interceptor allocates it
        headers = {"A2A-Version": "1.0"}
        if incoming:
            headers["A2A-Extensions"] = EXTENSION_URI
        task_message = A2ATaskMessage(
            id=task_id,
            context_id=session_id,
            headers=headers,
            metadata={EXTENSION_URI: incoming} if incoming else {},
        )

        new_presentation = False
        if task_id is None or task_id not in self._interceptor.authenticated_tasks:
            if "vp_token" in incoming:
                new_presentation = True
                hop.recv(caller, 2, "OpenID4VP: received presentation with vp_token")
                hop.log(2, "OpenID4VP: validating KB-JWT key binding (nonce & aud) + issuer signature")
            else:
                hop.banner(
                    f"{callee} verifies {caller}'s {_cred_ids(self.dcql_query)}",
                    hop_route(caller, callee),
                    f"{caller} is the direct caller and holds the credential.",
                )
                hop.log(1, f"OpenID4VP: unauthenticated request from {caller} -> issuing challenge")

        result: Optional[VerificationResult] = None

        def _next_handler(request: A2ATaskMessage, verified: Optional[VerificationResult]):
            nonlocal result
            result = verified
            return A2ATaskStatusResponse(
                id=request.id,
                context_id=request.context_id,
                state="TASK_STATE_WORKING",
                message={"role": "ROLE_AGENT", "parts": []},
            )

        try:
            response = self._interceptor.process_incoming_request(task_message, _next_handler)
        except ExtensionSupportRequiredError as exc:
            # Spec 6.2: this is a protocol error (-32008), which an ADK callback cannot emit.
            # A real A2A binding adapter would map it; here the turn is refused with plain text.
            log(callee, f"RESULT: REJECTED -> {exc.message} (extension {exc.extension_uri})")
            return genai_types.Content(role="model", parts=[genai_types.Part(text=exc.message)])

        self._task_ids.setdefault(session_id, response.id)
        task_id = self._task_ids[session_id]

        if response.status.state != "TASK_STATE_WORKING":
            payload = response.status.message.get("metadata", {}).get(EXTENSION_URI, {})
            parts = response.status.message.get("parts", [])
            text = parts[0]["text"] if parts else "Identity verification failed."
            if response.status.state == "TASK_STATE_AUTH_REQUIRED" or payload.get("status") == "identity_required":
                hop.send(
                    caller,
                    1,
                    f"OpenID4VP challenge: nonce={redact(payload.get('nonce', ''))} aud={callee} "
                    f"DCQL=[{fmt_dcql(payload.get('dcql_query', {}))}]",
                )
            else:
                log(
                    callee,
                    f"RESULT: REJECTED -> {text} ({payload.get('error')})",
                    hop=SINGLE_HOP if new_presentation else None,
                    step=3 if new_presentation else None,
                )
            return _metadata_content(payload, text)

        if result is not None:
            callback_context.state[STATE_VERIFIED_IDENTITY] = {
                "issuer": result.issuer,
                "credential_type": result.credential_type,
                "id_claim": result.id_claim,
                "disclosed_claims": result.disclosed_claims,
            }
            if new_presentation:
                hop.log(3, f"RESULT: VERIFIED -> '{result.credential_type}' ({fmt_claims(result.disclosed_claims)})")
                hop.log(3, f"authenticated task session opened: task_id={redact(task_id)}")
        return None

    def step_up(
        self,
        tool_context: Any,
        dcql_query: DCQLQuery,
        *,
        holder: str,
        prompt: str,
        relay: Optional[str] = None,
        verifier: Optional[SDJWTVerifier] = None,
    ) -> VerificationResult | Dict[str, Any]:
        """Ask for a credential mid-task, or verify the presentation of it.

        Turn 1: the request has no vp_token. This agent issues a step-up
        challenge and returns {"status": "awaiting_consent_presentation"}.
        Turn 2: this agent verifies the vp_token. It returns the
        VerificationResult, or a dict with an error.

        Set relay if the holder is not the direct caller. The log then shows a
        MULTI-HOP sequence. Otherwise it shows a SINGLE-HOP sequence.
        Set verifier to trust a different issuer than the gate's own verifier.
        """
        task_id = self.task_id_for(tool_context.session.id)
        caller = relay or CALLER_OF[self.name]
        hop = Hop(MULTI_HOP if relay else SINGLE_HOP, self.name)
        vp_token = extract_incoming_extension_metadata(tool_context).get("vp_token")

        if not vp_token:
            challenge = self._interceptor.issue_step_up_challenge(task_id, dcql_query, self.name)
            if relay:
                why = (
                    f"{holder} holds the credential, but {relay} is the direct caller. "
                    f"{relay} must tunnel the challenge (spec 12.6.1)."
                )
            else:
                why = f"{holder} is the direct caller and holds the credential."
            hop.banner(
                f"{self.name} verifies {holder}'s {_cred_ids(dcql_query)} (step-up)",
                hop_route(holder, self.name, relay),
                why,
            )
            hop.send(
                caller,
                1,
                f"OpenID4VP step-up challenge: nonce={redact(challenge.nonce)} aud={challenge.client_id} "
                f"DCQL=[{fmt_dcql(challenge.dcql_query)}]",
            )
            mark_pending_extension_metadata(tool_context, challenge.model_dump(), prompt)
            return {"status": "awaiting_consent_presentation"}

        presentations = vp_token.get(dcql_query.credentials[0].id) or []
        if not presentations:
            return {"error": "The consent presentation is empty."}

        received_step = hop.steps - 1
        if relay:
            hop.recv(caller, received_step, f"OpenID4VP: received {holder}'s presentation, forwarded by relay {relay}")
            hop.log(
                received_step,
                f"OpenID4VP: validating it here, at the terminal verifier. "
                f"The KB-JWT must name aud={self.name}, not {relay}.",
            )
        else:
            hop.recv(caller, received_step, "OpenID4VP: received step-up presentation")
            hop.log(received_step, "OpenID4VP: validating step-up KB-JWT key binding (nonce & aud) + issuer signature")
        try:
            result = self._interceptor.verify_step_up_response(
                task_id, tool_context.session.id, presentations[0], dcql_query, verifier=verifier
            )
        except Exception as exc:
            hop.log(hop.steps, f"RESULT: REJECTED -> {exc}")
            return {"error": f"Consent verification failed: {exc}"}
        hop.log(
            hop.steps,
            f"RESULT: VERIFIED -> '{result.credential_type}' from {holder} ({fmt_claims(result.disclosed_claims)})",
        )
        return result


def mark_pending_extension_metadata(tool_context: Any, metadata: Dict[str, Any], text: str) -> None:
    """Store extension metadata. emit_pending_extension_metadata sends it on the reply."""
    tool_context.state[STATE_PENDING_EXTENSION_METADATA] = {"metadata": metadata, "text": text}


def tunnel_upstream(
    tool_context: Any,
    tunneled: TunneledChallenge,
    *,
    relay: str,
    downstream_url: str,
    downstream_text: str,
) -> None:
    """Relay a downstream challenge to the holder (spec 12.6.1 Rule 1).

    Records the pending downstream call, keyed by origin_task_id. Then marks
    the tunneled_challenge for emission on the outgoing turn. The challenge
    is sent unchanged. The relay does not issue a nonce of its own for it.
    """
    challenge = tunneled.challenge
    pending = dict(tool_context.state.get(STATE_PENDING_TUNNELS) or {})
    pending[tunneled.origin_task_id] = {
        "url": downstream_url,
        "text": downstream_text,
        "verifier": challenge.client_id,
    }
    tool_context.state[STATE_PENDING_TUNNELS] = pending

    log_send(
        relay,
        CALLER_OF[relay],
        f"tunneled_challenge (12.6.1 Rule 1): the challenge of '{challenge.client_id}', unchanged. "
        f"origin_task_id={redact(tunneled.origin_task_id)} nonce={redact(challenge.nonce)} "
        f"aud={challenge.client_id} DCQL=[{fmt_dcql(challenge.dcql_query)}]",
        hop=MULTI_HOP,
        step=2,
    )
    mark_pending_extension_metadata(
        tool_context,
        {"tunneled_challenge": tunneled.model_dump()},
        f"'{challenge.client_id}' requests a presentation from the holder.",
    )


def take_tunneled_response(
    tool_context: Any, *, relay: str
) -> Optional[tuple[TunneledResponse, Dict[str, Any]]]:
    """Read a tunneled_response and match it to a pending tunnel (spec 12.6.1 Rule 3).

    Returns (response, pending_call), or None if the turn has no tunneled_response.
    Raises ValueError if origin_task_id does not match a pending tunnel.
    Removes the matched entry, so that the same response cannot be forwarded two times.
    The relay does not validate the vp_token (Rule 4). Only the terminal verifier validates it.
    """
    raw = extract_incoming_extension_metadata(tool_context).get("tunneled_response")
    if not raw:
        return None
    response = TunneledResponse.model_validate(raw)

    pending = dict(tool_context.state.get(STATE_PENDING_TUNNELS) or {})
    call = pending.pop(response.origin_task_id, None)
    if call is None:
        log(
            relay,
            f"tunneled_response refused: unknown origin_task_id={redact(response.origin_task_id)}",
            hop=MULTI_HOP,
            step=3,
        )
        raise ValueError("Tunneled response does not match a pending tunneled challenge.")
    tool_context.state[STATE_PENDING_TUNNELS] = pending

    log_recv(
        relay,
        CALLER_OF[relay],
        f"tunneled_response (12.6.1 Rule 3): origin_task_id={redact(response.origin_task_id)}, "
        f"credentials={sorted(response.response)}",
        hop=MULTI_HOP,
        step=3,
    )
    log(
        relay,
        f"relay only: origin_task_id matches the pending tunnel to {call['verifier']}. "
        f"This agent does not validate the vp_token (Rule 4). {call['verifier']} validates it.",
        hop=MULTI_HOP,
        step=3,
    )
    return response, call


def emit_pending_extension_metadata(callback_context: CallbackContext) -> Optional[genai_types.Content]:
    """Emit pending extension metadata on outgoing turn if recorded."""
    pending = callback_context.state.get(STATE_PENDING_EXTENSION_METADATA)
    if not pending:
        return None
    callback_context.state[STATE_PENDING_EXTENSION_METADATA] = None
    return _metadata_content(pending["metadata"], pending["text"])
