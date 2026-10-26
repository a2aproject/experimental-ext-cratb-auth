# SPDX-License-Identifier: Apache-2.0
import secrets
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional
import jwt
from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import a2a_wire
from .crypto import generate_nonce
from .models import (
    DCQLQuery,
    ErrorCode,
    ExtensionSupportRequiredError,
    IdentityChallenge,
    TaskNotFoundError,
    VersionNotSupportedError,
)
from .verifier import CredentialVerificationError, SDJWTVerifier, VerificationResult

EXTENSION_URI = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"

# A2A v1.0.0 task states (a2a.proto TaskState). This SDK speaks v1.0.0 only: the legacy v0.3
# spellings ("auth-required", "working", ...) are not accepted anywhere.
TASK_STATE_SUBMITTED = "TASK_STATE_SUBMITTED"
TASK_STATE_WORKING = "TASK_STATE_WORKING"
TASK_STATE_INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
TASK_STATE_AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED"
TASK_STATE_COMPLETED = "TASK_STATE_COMPLETED"
TASK_STATE_FAILED = "TASK_STATE_FAILED"
TASK_STATE_CANCELED = "TASK_STATE_CANCELED"
TASK_STATE_REJECTED = "TASK_STATE_REJECTED"

_TASK_STATES = frozenset({
    TASK_STATE_SUBMITTED, TASK_STATE_WORKING, TASK_STATE_INPUT_REQUIRED, TASK_STATE_AUTH_REQUIRED,
    TASK_STATE_COMPLETED, TASK_STATE_FAILED, TASK_STATE_CANCELED, TASK_STATE_REJECTED,
})
# Terminal states (a2a.proto): the Authenticated Task Session is discarded on these (spec 5.5 item 4).
_TERMINAL_CANONICAL = frozenset({
    TASK_STATE_COMPLETED, TASK_STATE_FAILED, TASK_STATE_CANCELED, TASK_STATE_REJECTED,
})

# The only A2A protocol version this SDK speaks. Requests MUST state it in `A2A-Version`.
SUPPORTED_A2A_VERSION = "1.0"
A2A_VERSION_HEADER = "A2A-Version"


def validate_task_state(state: str) -> str:
    """Returns `state` if it is an A2A v1.0.0 `TASK_STATE_*` value; anything else raises."""
    if state not in _TASK_STATES:
        raise ValueError(
            f"Unknown A2A task state {state!r}; this SDK speaks A2A v1.0.0 and expects one of {sorted(_TASK_STATES)}"
        )
    return state


class A2ATaskMessage(BaseModel):
    """
    Representation of an A2A task or message payload.
    """
    model_config = ConfigDict(populate_by_name=True)

    # Initial Requests may arrive without a task id / context id; the server allocates them
    # when it issues the challenge (A2A v1.0). Follow-ups must carry the allocated values.
    id: Optional[str] = None
    context_id: Optional[str] = Field(default=None, alias="contextId")
    headers: Dict[str, str] = {}
    metadata: Dict[str, Any] = {}
    parts: list[Dict[str, Any]] = []
    # Opaque identifier of the authenticated transport channel the message arrived on (e.g. a
    # TLS connection / session id or channel-binding value). Supplied by the transport adapter,
    # never taken from message content. Spec 5.5 item 2.
    channel_id: Optional[str] = None
    # Encoded RFC 9266 tls-exporter value of the TLS connection the message arrived on (see
    # crypto.encode_tls_exporter). Supplied by the transport adapter, never taken from message
    # content. Required when the verifier declares channel binding. Spec 12.8.
    tls_exporter: Optional[str] = None


class A2ATaskStatus(BaseModel):
    """
    A2A v1.0.0 TaskStatus. Spec 7.3.3 / 11.2 nest state and message here, under task.status.
    `state` must be a `TASK_STATE_*` value.
    """
    state: str
    message: Dict[str, Any] = {}

    @model_validator(mode="after")
    def _canonical_state(self) -> "A2ATaskStatus":
        validate_task_state(self.state)
        return self

    @property
    def wire_state(self) -> str:
        return self.state


class A2ATaskStatusResponse(BaseModel):
    """
    A2A v1.0.0 Task emitted by the Verifier Agent (spec 7.3.3 and 11.2):
        {"id": ..., "contextId": ..., "status": {"state": "TASK_STATE_...", "message": {...}}}
    There is no `kind` discriminator. The status message is normalised to a v1.0.0 Message:
    `messageId`, `role` (`ROLE_*`), `parts`, plus the Task's `taskId` and `contextId`.
    """
    model_config = ConfigDict(populate_by_name=True)

    id: str
    context_id: str = Field(alias="contextId")
    status: A2ATaskStatus

    def __init__(
        self,
        id: str,
        context_id: Optional[str] = None,
        contextId: Optional[str] = None,
        state: Optional[str] = None,
        message: Optional[Dict[str, Any]] = None,
        status: Optional[A2ATaskStatus] = None,
        **kwargs: Any,
    ) -> None:
        actual_context_id = context_id or contextId or ""
        if status is None and state is not None:
            status = A2ATaskStatus(state=state, message=message or {})
        if isinstance(status, dict):  # an inbound Task (e.g. parsed JSON) carries `status` as a plain object
            status = A2ATaskStatus.model_validate(status)
        if status is not None and status.message:
            status = A2ATaskStatus(
                state=status.state,
                message=a2a_wire.canonical_message(status.message, task_id=id, context_id=actual_context_id or None),
            )
        super().__init__(
            id=id,
            contextId=actual_context_id,
            status=status,  # type: ignore[arg-type]
            **kwargs,
        )

    @model_validator(mode="before")
    @classmethod
    def _lift_flat_status(cls, data: Any) -> Any:
        """
        Accept the flat construction form A2ATaskStatusResponse(state=..., message=...) used
        throughout the agents, and lift it into the nested status object.
        """
        if not isinstance(data, dict) or "status" in data:
            return data
        if "state" not in data:
            return data
        data = dict(data)
        data["status"] = {
            "state": data.pop("state"),
            "message": data.pop("message", {}) or {},
        }
        return data

    @property
    def state(self) -> str:
        """Convenience accessor for status.state."""
        return self.status.state

    def to_wire(self) -> Dict[str, Any]:
        """The A2A v1.0.0 Task object (no JSON-RPC envelope)."""
        return self.model_dump(by_alias=True)

    def to_send_message_response(self) -> Dict[str, Any]:
        """`SendMessageResponse` carrying this Task: `{"task": {...}}`."""
        return a2a_wire.send_message_response(task=self.to_wire())

    def to_jsonrpc_response(self, request_id: Any) -> Dict[str, Any]:
        """JSON-RPC 2.0 response: `{"jsonrpc": "2.0", "id": ..., "result": {"task": {...}}}`."""
        return a2a_wire.jsonrpc_result(request_id, self.to_send_message_response())

    @property
    def message(self) -> Dict[str, Any]:
        """Convenience accessor for status.message."""
        return self.status.message


class ServerAuthRequiredInterceptor:
    """
    A2A Server extension interceptor enforcing the AUTH_REQUIRED handshake for verifiable presentations.
    """
    # Terminal A2A v1.0.0 task states per spec Section 5.5 item 4.
    TERMINAL_STATES = _TERMINAL_CANONICAL

    def __init__(
        self,
        verifier: SDJWTVerifier,
        required: bool = True,
        dcql_query: Optional[DCQLQuery] = None,
        issuer_public_key_jwk: Optional[Dict[str, Any]] = None,
        response_uri: Optional[str] = None,
        challenge_ttl: Optional[float] = 300.0,
        time_fn: Callable[[], float] = time.time,
        max_buffered_requests: int = 1024,
        max_buffered_bytes: int = 256 * 1024,
        buffer_ttl: Optional[float] = None,
        require_channel_binding: bool = True,
    ) -> None:
        self.verifier = verifier
        # Spec 5.5 item 2: the Authenticated Task Session MUST be bound to the client's
        # transport channel. When True (default), an Identity Response without a channel_id is
        # rejected; set False only for transports that cannot expose a channel identity.
        self.require_channel_binding = require_channel_binding
        # Challenge lifetime in seconds; None disables expiry. Enforced against issue time.
        self.challenge_ttl = challenge_ttl
        self._time = time_fn
        # Admission limits for the pre-authentication buffer (spec 7.3.5 "bounded cleanup").
        # buffer_ttl defaults to challenge_ttl so an abandoned request cannot outlive its challenge.
        self.max_buffered_requests = max_buffered_requests
        self.max_buffered_bytes = max_buffered_bytes
        self.buffer_ttl = challenge_ttl if buffer_ttl is None else buffer_ttl
        self.required = required
        self.dcql_query = dcql_query or DCQLQuery.default_agent_identity_query()
        self.issuer_public_key_jwk = issuer_public_key_jwk
        if response_uri:
            self.response_uri = response_uri
        elif self.verifier.client_id.endswith("/a2a"):
            self.response_uri = self.verifier.client_id
        else:
            self.response_uri = self.verifier.client_id.rstrip("/") + "/a2a"

        # task_id -> set of outstanding nonces. Composite (task_id, nonce) keying per spec
        # Section 12.1: a task may have more than one nonce outstanding (e.g. a step-up
        # challenge issued while the original session is still open), and consuming one
        # nonce must not affect any other nonce issued for the same task_id.
        self.active_nonces: Dict[str, set[str]] = {}
        self.task_contexts: Dict[str, str] = {}
        # task_id -> channel the session is bound to (spec 5.5 item 2)
        self.task_channels: Dict[str, str] = {}
        self.authenticated_tasks: set[str] = set()
        # Task ids this Verifier allocated (A2A 3.4.2: ids are server-generated).
        self.allocated_tasks: set[str] = set()
        self.authenticated_results: Dict[str, VerificationResult] = {}
        self.buffered_requests: Dict[str, A2ATaskMessage] = {}
        # task_id -> {nonce: issue time}. Nonces without a recorded time never expire here.
        self.nonce_issued_at: Dict[str, Dict[str, float]] = {}
        self.buffered_at: Dict[str, float] = {}
        # Task ids whose initial request was already released. Kept after the buffer is gone so a
        # late or duplicate response cannot recreate dispatch eligibility (spec 7.3.5).
        self.released_tasks: set[str] = set()
        # Nonces that were issued and then consumed, per task. Lets a replay be told apart from a
        # nonce that never existed (spec 12.1: previously used nonce -> VP_NONCE_MISMATCH).
        self.consumed_nonces: Dict[str, set[str]] = {}
        self._release_lock = threading.Lock()

    def _purge_expired_buffers(self) -> None:
        if self.buffer_ttl is None:
            return
        now = self._time()
        for task_id in [t for t, at in self.buffered_at.items() if now - at > self.buffer_ttl]:
            self.buffered_requests.pop(task_id, None)
            self.buffered_at.pop(task_id, None)

    def _admit_buffer(self, request: A2ATaskMessage) -> None:
        """Bounded admission of the Initial Request (spec 7.3.2): size and count limits."""
        self._purge_expired_buffers()
        size = len(request.model_dump_json())
        if size > self.max_buffered_bytes:
            raise CredentialVerificationError(
                ErrorCode.VP_MALFORMED,
                f"Initial request is {size} bytes; the pre-authentication buffer accepts at most {self.max_buffered_bytes}",
            )
        if request.id not in self.buffered_requests and len(self.buffered_requests) >= self.max_buffered_requests:
            raise CredentialVerificationError(
                ErrorCode.VP_MALFORMED,
                "Too many pending unauthenticated requests; try again later",
            )
        self.buffered_requests[request.id] = request.model_copy(deep=True)
        self.buffered_at[request.id] = self._time()

    def _record_nonce(self, task_id: str, nonce: str) -> None:
        self.active_nonces.setdefault(task_id, set()).add(nonce)
        self.nonce_issued_at.setdefault(task_id, {})[nonce] = self._time()

    def _check_nonce_fresh(self, task_id: str, nonce: str) -> None:
        issued = self.nonce_issued_at.get(task_id, {}).get(nonce)
        if self.challenge_ttl is not None and issued is not None:
            if self._time() - issued > self.challenge_ttl:
                raise CredentialVerificationError(
                    ErrorCode.VP_NONCE_EXPIRED,
                    f"Challenge nonce expired: issued {int(self._time() - issued)}s ago, lifetime is {self.challenge_ttl}s",
                )

    def _is_known_task(self, task_id: str) -> bool:
        return (
            task_id in self.allocated_tasks
            or task_id in self.authenticated_tasks
            or task_id in self.buffered_requests
            or task_id in self.active_nonces
        )

    @staticmethod
    def _check_a2a_version(headers: Dict[str, str]) -> None:
        """Raises VersionNotSupportedError unless the request states A2A-Version 1.0 (Major.Minor)."""
        value = next((v for k, v in headers.items() if k.lower() == A2A_VERSION_HEADER.lower()), None)
        if value is None:
            raise VersionNotSupportedError("0.3", "The A2A-Version header is required; an absent header means 0.3")
        stated = str(value).strip()
        if stated.split(".")[:2] != SUPPORTED_A2A_VERSION.split("."):
            raise VersionNotSupportedError(stated)

    @staticmethod
    def _has_extension_activation(headers: Dict[str, str], extension_uri: str) -> bool:
        """
        Exact extension token matching across bindings.
        Header keys are case-insensitive. Values may be comma-separated lists of URIs.
        """
        for k, v in headers.items():
            if k.lower() == "a2a-extensions":
                tokens = [t.strip() for t in v.split(",") if t.strip()]
                if extension_uri in tokens:
                    return True
        return False

    @staticmethod
    def _peek_kb_jwt_nonce(vp_str: str) -> Optional[str]:
        """
        Reads the 'nonce' claim out of a presentation's KB-JWT without verifying its signature,
        purely to select which of the task's outstanding nonces (Section 12.1) it is answering.
        Signature/holder-binding checks still happen in SDJWTVerifier.verify_presentation.
        """
        try:
            kb_jwt_str = vp_str.split("~")[-1]
            payload = jwt.decode(kb_jwt_str, options={"verify_signature": False})
            return payload.get("nonce")
        except Exception:
            return None

    def close_task_session(self, task_id: str) -> None:
        """
        Discards the Authenticated Task Session for `task_id` (spec Section 5.5 item 4).

        Idempotent: closing an unknown or already-closed task is a no-op. Also clears any
        nonce still outstanding for the task, since no further challenge can be answered
        once the task is terminal.
        """
        self.authenticated_tasks.discard(task_id)
        self.allocated_tasks.discard(task_id)
        self.authenticated_results.pop(task_id, None)
        self.active_nonces.pop(task_id, None)
        self.nonce_issued_at.pop(task_id, None)
        self.task_contexts.pop(task_id, None)
        self.task_channels.pop(task_id, None)
        self.buffered_requests.pop(task_id, None)
        self.buffered_at.pop(task_id, None)
        self.consumed_nonces.pop(task_id, None)
        self.released_tasks.discard(task_id)

    def _finalize(self, response: A2ATaskStatusResponse) -> A2ATaskStatusResponse:
        """Discards the Authenticated Task Session if this response is terminal (Section 5.5 item 4)."""
        is_terminal = response.status.state in _TERMINAL_CANONICAL
        if is_terminal and response.id in self.authenticated_tasks:
            self.close_task_session(response.id)
        return response

    def process_incoming_request(
        self,
        request: A2ATaskMessage,
        next_handler: Callable[[A2ATaskMessage, Optional[VerificationResult]], A2ATaskStatusResponse],
    ) -> A2ATaskStatusResponse:
        """
        Intercepts an incoming A2A message/send request to enforce the identity challenge/response handshake.

        Raises ExtensionSupportRequiredError (spec 6.2) when the extension is required but the
        request does not activate it; the binding adapter maps it to -32008 / 400 / FAILED_PRECONDITION.
        """
        # A2A v1.0.0 only: the request MUST state A2A-Version 1.0. An absent header means 0.3 under
        # A2A Section 3.6, and any other version is unsupported (VersionNotSupportedError).
        self._check_a2a_version(request.headers)

        # A2A v1.0.0 Section 3.4.2: task ids are server-generated, and a client-provided `taskId`
        # "MUST reference an existing task"; otherwise the agent MUST return TaskNotFoundError.
        # A follow-up is therefore accepted only for a task this Verifier allocated (spec 5.5).
        if request.id:
            if not self._is_known_task(request.id):
                raise TaskNotFoundError(request.id)
        else:
            request = request.model_copy(update={"id": secrets.token_hex(16)})
            self.allocated_tasks.add(request.id)
        if not request.context_id:
            request = request.model_copy(update={"context_id": uuid.uuid4().hex})

        # Case-insensitive header lookup and exact token matching across bindings
        ext_header_present = self._has_extension_activation(request.headers, EXTENSION_URI)
        if not ext_header_present and self.required:
            # Spec 6.2: a protocol error before task admission, never a failed Task.
            raise ExtensionSupportRequiredError(EXTENSION_URI)

        # Validate context continuity for requests on already-authenticated tasks
        if request.id in self.authenticated_tasks:
            # Spec 5.5 items 2-3: only the bound channel may continue the session. A message
            # from any other connection is not accepted under the cached identity. Rejecting it
            # does not terminate the task, so a task_id holder cannot close the owner's session.
            bound_channel = self.task_channels.get(request.id)
            if bound_channel is not None and request.channel_id != bound_channel:
                return self._build_error_response(
                    request.id,
                    request.context_id,
                    ErrorCode.VP_CONVERSATION_MISMATCH,
                    "Message on an authenticated task arrived from a different transport channel than the one bound at authentication",
                )
            expected_context = self.task_contexts.get(request.id)
            if expected_context and request.context_id != expected_context:
                # Rejecting one message is not terminating the task: a caller that merely
                # knows the task id must not be able to close someone else's session.
                return self._build_error_response(
                    request.id,
                    request.context_id,
                    ErrorCode.VP_CONVERSATION_MISMATCH,
                    f"Follow-up request contextId '{request.context_id}' does not match established task contextId '{expected_context}'",
                )
            # Spec 5.5 item 4: a vp_token on an authenticated task is only legitimate as the
            # answer to an outstanding step-up challenge, which is verified through
            # verify_step_up_response. With none outstanding it is unsolicited input and is
            # rejected here instead of reaching the business handler unverified.
            auth_ext = request.metadata.get(EXTENSION_URI, {}) if isinstance(request.metadata, dict) else {}
            if isinstance(auth_ext, dict) and "vp_token" in auth_ext and not self.active_nonces.get(request.id):
                # Not finalized, for the same reason as the context check above.
                return self._build_error_response(
                    request.id,
                    request.context_id,
                    ErrorCode.VP_NONCE_MISMATCH,
                    "Unsolicited vp_token on an authenticated task: no step-up challenge is outstanding",
                )
            return self._finalize(next_handler(request, self.authenticated_results.get(request.id)))

        ext_meta = request.metadata.get(EXTENSION_URI, {}) if isinstance(request.metadata, dict) else {}
        vp_token = ext_meta.get("vp_token") if isinstance(ext_meta, dict) else None

        # Spec 7.3.4 step 6: a task with an outstanding challenge is in AUTH_REQUIRED.
        # A message with no usable vp_token is either a classified Identity Response or an
        # unauthenticated follow-up. Both get VP_MISSING; neither starts a second challenge or
        # a new nonce, and neither reaches the business handler.
        if not vp_token and (self.active_nonces.get(request.id) or request.id in self.buffered_requests):
            return self._finalize(self._build_error_response(
                request.id,
                request.context_id,
                ErrorCode.VP_MISSING,
                "An identity challenge is pending for this task; send an Identity Response with a vp_token",
            ))

        if not vp_token:
            # Bounded admission of the Initial Request before any challenge is issued
            try:
                self._admit_buffer(request)
            except CredentialVerificationError as e:
                return self._finalize(self._build_error_response(
                    request.id, request.context_id, e.error_code, e.message,
                ))
            # Issue IdentityChallenge with AUTH_REQUIRED state
            nonce = generate_nonce()
            self._record_nonce(request.id, nonce)
            if request.context_id:
                self.task_contexts[request.id] = request.context_id

            challenge = IdentityChallenge(
                nonce=nonce,
                dcql_query=self.dcql_query,
                client_id=self.verifier.client_id,
                response_uri=self.response_uri,
            )
            return A2ATaskStatusResponse(
                id=request.id,
                context_id=request.context_id,
                state=TASK_STATE_AUTH_REQUIRED,
                message={
                    "role": a2a_wire.ROLE_AGENT,
                    "parts": [a2a_wire.text_part("Identity verification required.")],
                    "metadata": {
                        EXTENSION_URI: challenge.model_dump(by_alias=True)
                    },
                },
            )

        # Validate IdentityResponse
        outstanding = self.active_nonces.get(request.id)
        if not outstanding:
            # A previously consumed nonce (replay) -> VP_NONCE_MISMATCH (spec 12.1). Otherwise
            # nothing was outstanding or it was cleaned up -> VP_NONCE_EXPIRED.
            replayed = False
            if isinstance(vp_token, dict):
                for plist in vp_token.values():
                    if isinstance(plist, list) and plist and isinstance(plist[0], str):
                        if self._peek_kb_jwt_nonce(plist[0]) in self.consumed_nonces.get(request.id, set()):
                            replayed = True
            return self._finalize(self._build_error_response(
                request.id,
                request.context_id,
                ErrorCode.VP_NONCE_MISMATCH if replayed else ErrorCode.VP_NONCE_EXPIRED,
                "Presented nonce was already used for this task" if replayed
                else "No active nonce found for this task ID; challenge may have expired",
            ))

        stored_nonce = None
        nonce_consumed = False
        try:
            # Multi-credential DCQL verification
            # Ensure every required credential query in dcql_query.credentials is provided in vp_token
            results_by_query: Dict[str, VerificationResult] = {}
            all_disclosed_claims: Dict[str, Any] = {}

            for cred_query in self.dcql_query.credentials:
                pres_list = vp_token.get(cred_query.id, [])
                if not pres_list or not pres_list[0]:
                    raise CredentialVerificationError(
                        ErrorCode.VP_DCQL_UNSATISFIED,
                        f"Presented vp_token does not satisfy DCQL query requirements for '{cred_query.id}'",
                    )

            # Section 12.1: select which of the task's outstanding nonces this response is
            # answering. Peek KB-JWT across presentations to identify the matching nonce.
            presented_nonce = None
            for cred_query in self.dcql_query.credentials:
                vp_str = vp_token[cred_query.id][0]
                peeked = self._peek_kb_jwt_nonce(vp_str)
                if peeked:
                    presented_nonce = peeked
                    if peeked in outstanding:
                        stored_nonce = peeked
                        break

            if not stored_nonce:
                if presented_nonce is not None and presented_nonce not in outstanding:
                    # Unknown, mismatched, or forged nonce returns VP_NONCE_MISMATCH per spec §12.1
                    raise CredentialVerificationError(
                        ErrorCode.VP_NONCE_MISMATCH,
                        f"Presented nonce '{presented_nonce}' does not match any outstanding challenge for this task ID",
                    )
                elif len(outstanding) == 1:
                    stored_nonce = next(iter(outstanding))
                else:
                    raise CredentialVerificationError(
                        ErrorCode.VP_NONCE_MISMATCH,
                        "Presented nonce does not match any outstanding challenge for this task ID",
                    )

            # Compare incoming response context_id against established task contextId
            # (a context mismatch does not consume the nonce, as before).
            expected_context = self.task_contexts.get(request.id) or request.context_id
            if expected_context and request.context_id != expected_context:
                raise CredentialVerificationError(
                    ErrorCode.VP_CONVERSATION_MISMATCH,
                    f"Response contextId '{request.context_id}' does not match established task contextId '{expected_context}'",
                )

            try:
                # Expiry is checked inside the try so the identified nonce is consumed
                # (Section 12.1) even when it is rejected as expired.
                self._check_nonce_fresh(request.id, stored_nonce)

                # Verify each credential query against its designated presentation
                for cred_query in self.dcql_query.credentials:
                    vp_str = vp_token[cred_query.id][0]
                    res_item = self.verifier.verify_presentation(
                        presentation_str=vp_str,
                        nonce=stored_nonce,
                        expected_context_id=expected_context,
                        single_cred_query=cred_query,
                        issuer_public_key_jwk=self.issuer_public_key_jwk,
                        tls_exporter=request.tls_exporter,
                    )
                    results_by_query[cred_query.id] = res_item
                    all_disclosed_claims.update(res_item.disclosed_claims)

                # Form composite VerificationResult
                primary_id = (
                    "agent_identity"
                    if "agent_identity" in results_by_query
                    else self.dcql_query.credentials[0].id
                )
                primary_res = results_by_query[primary_id]

                composite_res = VerificationResult(
                    is_valid=True,
                    issuer=primary_res.issuer,
                    credential_type=primary_res.credential_type,
                    id_claim=primary_res.id_claim,
                    disclosed_claims=all_disclosed_claims,
                    raw_issuer_jwt_payload=primary_res.raw_issuer_jwt_payload,
                    kb_jwt_payload=primary_res.kb_jwt_payload,
                    query_id=primary_id,
                    results=results_by_query,
                )

                # Spec 5.5 item 2: no session without a channel to bind it to. Checked before the
                # one-time release so a refusal leaves the retained original untouched.
                if self.require_channel_binding and not request.channel_id:
                    raise CredentialVerificationError(
                        ErrorCode.VP_CONVERSATION_MISMATCH,
                        "Transport channel identity is required to bind the task session",
                    )

                # Spec 7.3.5: atomically claim the one-time release of the retained
                # original. Only the first accepted response gets it; a duplicate or concurrent
                # response fails closed and never dispatches again.
                with self._release_lock:
                    if request.id in self.released_tasks:
                        original_request = None
                    else:
                        original_request = self.buffered_requests.pop(request.id, None)
                        self.buffered_at.pop(request.id, None)
                        if original_request is not None:
                            self.released_tasks.add(request.id)
                if original_request is None:
                    raise CredentialVerificationError(
                        ErrorCode.VP_MISSING,
                        f"No buffered pre-auth request found for task ID '{request.id}'",
                    )

                # The released request is the immutable original snapshot. The Identity
                # Response (vp_token, its metadata, its parts) is never merged into it.
                self.authenticated_tasks.add(request.id)
                if request.channel_id:
                    self.task_channels[request.id] = request.channel_id
                self.authenticated_results[request.id] = composite_res
                return self._finalize(next_handler(original_request, composite_res))
            finally:
                # Section 12.1: the nonce MUST be consumed once identified and matched
                if stored_nonce:
                    nonce_consumed = True
                    outstanding.discard(stored_nonce)
                    self.consumed_nonces.setdefault(request.id, set()).add(stored_nonce)
                    self.nonce_issued_at.get(request.id, {}).pop(stored_nonce, None)
                    if not outstanding:
                        self.active_nonces.pop(request.id, None)
                        self.nonce_issued_at.pop(request.id, None)

        except CredentialVerificationError as e:
            # Spec 7.3.5: input that did not identify and consume a challenge (unknown nonce,
            # wrong context, missing presentation) must not delete the pending original; the
            # challenge is still live. Only a failed attempt that consumed its nonce ends the flow.
            if nonce_consumed:
                self.buffered_requests.pop(request.id, None)
                self.buffered_at.pop(request.id, None)
            return self._finalize(self._build_error_response(
                request.id,
                request.context_id,
                e.error_code,
                e.message,
            ))
        except Exception as e:
            if nonce_consumed:
                self.buffered_requests.pop(request.id, None)
                self.buffered_at.pop(request.id, None)
            return self._finalize(self._build_error_response(
                request.id,
                request.context_id,
                ErrorCode.VP_SIGNATURE_INVALID,
                f"Unexpected verification error: {str(e)}",
            ))

    def issue_step_up_challenge(
        self,
        task_id: str,
        dcql_query: DCQLQuery,
        client_id: Optional[str] = None,
        response_uri: Optional[str] = None,
    ) -> IdentityChallenge:
        """
        Spec Section 5.5 item 3 / 12.6.1: issues a fresh step-up IdentityChallenge for an
        already-authenticated task, reusing task_id/context_id. A new nonce is generated and
        added to the task's set of outstanding nonces alongside any others (Section 12.1).
        """
        nonce = generate_nonce()
        self._record_nonce(task_id, nonce)
        target_client_id = client_id or self.verifier.client_id
        target_response_uri = response_uri or (
            self.response_uri
            if client_id is None
            else (target_client_id if target_client_id.endswith("/a2a") else target_client_id.rstrip("/") + "/a2a")
        )
        return IdentityChallenge(
            nonce=nonce,
            dcql_query=dcql_query,
            client_id=target_client_id,
            response_uri=target_response_uri,
        )

    def verify_step_up_response(
        self,
        task_id: str,
        context_id: str,
        vp_str: str,
        dcql_query: DCQLQuery,
        issuer_public_key_jwk: Optional[Dict[str, Any]] = None,
        verifier: Optional[SDJWTVerifier] = None,
        tls_exporter: Optional[str] = None,
    ) -> VerificationResult:
        """
        Verifies a step-up IdentityResponse against the nonce issued by `issue_step_up_challenge`,
        without disturbing the task's existing Authenticated Task Session or any other nonce
        outstanding for the same task_id (Section 12.1's closing sentence).

        `tls_exporter` is the encoded tls-exporter value of the bound session connection the
        step-up response arrived on; required when the verifier declares channel binding (spec 5.5, 12.8).
        """
        outstanding = self.active_nonces.get(task_id)
        if not outstanding:
            raise CredentialVerificationError(
                ErrorCode.VP_NONCE_EXPIRED,
                "No active step-up nonce found for this task ID; challenge may have expired",
            )

        stored_nonce = None
        presented_nonce = self._peek_kb_jwt_nonce(vp_str)
        if presented_nonce in outstanding:
            stored_nonce = presented_nonce
        elif presented_nonce is not None and presented_nonce not in outstanding:
            raise CredentialVerificationError(
                ErrorCode.VP_NONCE_MISMATCH,
                f"Presented step-up nonce '{presented_nonce}' does not match any outstanding challenge for this task ID",
            )
        elif len(outstanding) == 1:
            stored_nonce = next(iter(outstanding))
        else:
            raise CredentialVerificationError(
                ErrorCode.VP_NONCE_MISMATCH,
                "Presented nonce does not match any outstanding challenge for this task ID",
            )

        try:
            self._check_nonce_fresh(task_id, stored_nonce)
            active_verifier = verifier or self.verifier
            res = active_verifier.verify_presentation(
                presentation_str=vp_str,
                nonce=stored_nonce,
                expected_context_id=context_id,
                dcql_query=dcql_query,
                issuer_public_key_jwk=issuer_public_key_jwk if issuer_public_key_jwk is not None else self.issuer_public_key_jwk,
                tls_exporter=tls_exporter,
            )
            return res
        finally:
            if stored_nonce:
                outstanding.discard(stored_nonce)
                self.consumed_nonces.setdefault(task_id, set()).add(stored_nonce)
                self.nonce_issued_at.get(task_id, {}).pop(stored_nonce, None)
                if not outstanding:
                    self.active_nonces.pop(task_id, None)
                    self.nonce_issued_at.pop(task_id, None)

    def _build_error_response(
        self,
        task_id: str,
        context_id: str,
        error_code: ErrorCode,
        message: str,
    ) -> A2ATaskStatusResponse:
        return A2ATaskStatusResponse(
            id=task_id,
            context_id=context_id,
            state=TASK_STATE_FAILED,
            message={
                "role": a2a_wire.ROLE_AGENT,
                "parts": [a2a_wire.text_part(message)],
                "metadata": {
                    EXTENSION_URI: {
                        "status": "failed",
                        "error": error_code.value,
                    }
                },
            },
        )
