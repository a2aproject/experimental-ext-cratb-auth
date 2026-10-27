# SPDX-License-Identifier: Apache-2.0
import re
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import a2a_wire as _a2a_wire

# The spec's illustrative type identifier for the AIAgentIdentityCredential (spec 8.3, 9.2, 9.6).
# Deployments should publish their own under a namespace they control.
AI_AGENT_IDENTITY_VCT = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"

# Channel binding types a Verifier may require in KB-JWTs (spec 4.1, 12.8). RFC 9266.
TLS_EXPORTER = "tls-exporter"
CHANNEL_BINDING_TYPES = frozenset({TLS_EXPORTER})

_URN_PATTERN = re.compile(r"^urn:[A-Za-z0-9][A-Za-z0-9-]{0,31}:\S+$", re.IGNORECASE)


def is_collision_resistant_type(value: Any) -> bool:
    """
    True if `value` is a collision-resistant credential type identifier as spec 9.2 and 9.6
    require for `vct` and `meta.vct_values` (SD-JWT VC draft-19, RFC 7515 Section 2).

    A bare label such as "AIAgentIdentityCredential" is not namespaced and so is not collision
    resistant. This profile accepts an absolute http(s) URI with a host, or a URN
    (urn:<nid>:<nss>), with no whitespace or control characters.
    """
    if not isinstance(value, str) or not value:
        return False
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return False
    if value[:4].lower() == "urn:":
        return bool(_URN_PATTERN.match(value))
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        return False
    return parts.scheme.lower() in ("https", "http") and bool(host)


class ErrorCode(str, Enum):
    """
    Error codes defined in Section 11.1 of the A2A Agentic Identity Credentials Extension specification.
    """
    VP_FORMAT_UNSUPPORTED = "VP_FORMAT_UNSUPPORTED"
    VP_MALFORMED = "VP_MALFORMED"
    VP_KEY_BINDING_MISSING = "VP_KEY_BINDING_MISSING"
    VP_NONCE_MISMATCH = "VP_NONCE_MISMATCH"
    VP_AUDIENCE_MISMATCH = "VP_AUDIENCE_MISMATCH"
    VP_SIGNATURE_INVALID = "VP_SIGNATURE_INVALID"
    VP_CREDENTIAL_EXPIRED = "VP_CREDENTIAL_EXPIRED"
    VP_DCQL_UNSATISFIED = "VP_DCQL_UNSATISFIED"
    VP_MISSING = "VP_MISSING"
    VP_NONCE_EXPIRED = "VP_NONCE_EXPIRED"
    VP_CONVERSATION_MISMATCH = "VP_CONVERSATION_MISMATCH"
    VP_DOMAIN_NOT_ALLOWED = "VP_DOMAIN_NOT_ALLOWED"
    VP_CHANNEL_BINDING_MISMATCH = "VP_CHANNEL_BINDING_MISMATCH"
    VP_CREDENTIAL_REVOKED = "VP_CREDENTIAL_REVOKED"


class A2AProtocolError(Exception):
    """
    Base for A2A protocol-level errors (A2A v1.0.0 Section 3.3.2, 5.4): errors that are returned
    as protocol errors, not as a failed Task and not as one of this extension's Section 11.1 task
    error codes. A binding adapter catches one and answers with the representation for its
    binding: `to_jsonrpc_error()`, `to_http_error()` (with `HTTP_STATUS`) or `to_grpc_status()`.

    Every A2A-specific error carries a `google.rpc.ErrorInfo` (reason = the error type in
    UPPER_SNAKE_CASE without the `Error` suffix, domain `a2a-protocol.org`) in the binding's
    details array (A2A v1.0.0 Sections 9.5, 10.6, 11.6).
    """
    ERROR_TYPE = ""
    JSON_RPC_CODE = 0
    HTTP_STATUS = 0
    GRPC_STATUS = ""
    REASON = ""
    DOMAIN = _a2a_wire.ERROR_DOMAIN

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def error_metadata(self) -> Dict[str, str]:
        """Extra `ErrorInfo.metadata` for this error (empty by default)."""
        return {}

    def error_info(self) -> Dict[str, Any]:
        return _a2a_wire.error_info(self.ERROR_TYPE, self.error_metadata())

    def to_jsonrpc_error(self, request_id: Any = None) -> Dict[str, Any]:
        return _a2a_wire.jsonrpc_error(self.ERROR_TYPE, self.message, [self.error_info()], request_id)

    def to_http_error(self) -> Dict[str, Any]:
        """HTTP+JSON body (`google.rpc.Status` JSON). Send it with status `HTTP_STATUS`."""
        return _a2a_wire.http_error(self.ERROR_TYPE, self.message, [self.error_info()])

    def to_grpc_status(self) -> Dict[str, Any]:
        """gRPC `google.rpc.Status` as a dict: `code` is `GRPC_STATUS`, `details` holds the ErrorInfo."""
        return _a2a_wire.grpc_status(self.ERROR_TYPE, self.message, [self.error_info()])


class ExtensionSupportRequiredError(A2AProtocolError):
    """
    A2A `ExtensionSupportRequiredError` (spec Section 6.2): the extension is required but the
    client did not declare it. Raised before task admission.
    """
    ERROR_TYPE = "ExtensionSupportRequiredError"
    JSON_RPC_CODE = -32008
    HTTP_STATUS = 400
    GRPC_STATUS = "FAILED_PRECONDITION"
    REASON = "EXTENSION_SUPPORT_REQUIRED"

    def __init__(self, extension_uri: str, message: str = "Required extension support was not declared") -> None:
        super().__init__(message)
        self.extension_uri = extension_uri

    def error_metadata(self) -> Dict[str, str]:
        # `extensionUri` is this extension's metadata convention; base A2A does not define it.
        return {"extensionUri": self.extension_uri}


class TaskNotFoundError(A2AProtocolError):
    """
    A2A `TaskNotFoundError`: the task id does not identify a task the Verifier knows.

    A2A v1.0.0 Section 3.4.2 makes task ids server-generated and says a client-provided `taskId`
    "MUST reference an existing task"; otherwise the agent MUST return this error. The Initial
    Request therefore carries no task id (spec 7.3.2) and the Verifier allocates it (spec 5.5).
    """
    ERROR_TYPE = "TaskNotFoundError"
    JSON_RPC_CODE = -32001
    HTTP_STATUS = 404
    GRPC_STATUS = "NOT_FOUND"
    REASON = "TASK_NOT_FOUND"

    def __init__(self, task_id: str, message: str = "Task not found") -> None:
        super().__init__(message)
        self.task_id = task_id

    def error_metadata(self) -> Dict[str, str]:
        return {"taskId": self.task_id}


class VersionNotSupportedError(A2AProtocolError):
    """
    A2A `VersionNotSupportedError`: the protocol version in the request (`A2A-Version`) is absent
    or not supported. This SDK speaks A2A v1.0.0 only.
    """
    ERROR_TYPE = "VersionNotSupportedError"
    JSON_RPC_CODE = -32009
    HTTP_STATUS = 400
    GRPC_STATUS = "FAILED_PRECONDITION"
    REASON = "VERSION_NOT_SUPPORTED"

    def __init__(self, requested_version: str, message: str = "A2A protocol version not supported; this agent speaks 1.0") -> None:
        super().__init__(message)
        self.requested_version = requested_version

    def error_metadata(self) -> Dict[str, str]:
        return {"requestedVersion": self.requested_version, "supportedVersions": "1.0"}


class DCQLClaimQuery(BaseModel):
    """
    Query selecting a claim by its JSON path and optional allowed values.

    Closed schema (spec 9.6, security considerations: the dcql_query MUST be validated against
    the DCQL schema; unsupported semantics MUST NOT be silently ignored). `claims[].id`, which
    only exists to be referenced by `claim_sets`, is therefore rejected along with `claim_sets`.
    """
    model_config = ConfigDict(extra="forbid")

    path: List[str] = Field(min_length=1)
    values: Optional[List[str]] = None

    @field_validator("path")
    @classmethod
    def _path_segments_are_keys(cls, path: List[str]) -> List[str]:
        # Spec 9.6: unsupported DCQL semantics MUST NOT be silently ignored. This profile
        # supports object-key paths only; array selection (null / integer segments) is rejected.
        if any(not isinstance(seg, str) or not seg for seg in path):
            raise ValueError("DCQL claim path segments must be non-empty strings (array selection is not supported)")
        return path


_DCQL_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
# `meta` keys this profile understands for dc+sd-jwt (spec 9.6).
_DC_SD_JWT_META_KEYS = frozenset({"vct_values", "trusted_authorities"})


class DCQLCredentialQuery(BaseModel):
    """
    Query selecting a specific credential and the claims required.

    Closed schema: only the DCQL features this profile implements are accepted, so an
    unsupported one (`claim_sets`, `multiple: true`, ...) fails loudly instead of being silently
    ignored (spec 9.6).
    """
    model_config = ConfigDict(extra="forbid")

    id: str = "agent_identity"
    format: str = "dc+sd-jwt"
    meta: Dict[str, Any] = Field(default_factory=dict)
    claims: List[DCQLClaimQuery] = Field(default_factory=list)
    # Accepted only at their DCQL defaults: this profile returns one credential per query and
    # always requires the KB-JWT holder binding. Never serialized, so the wire form matches the
    # spec's 9.6 example (a default value is the same as an absent one).
    multiple: bool = Field(default=False, exclude=True)
    require_cryptographic_holder_binding: bool = Field(default=True, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def _reject_unsupported_features(cls, data: Any) -> Any:
        if isinstance(data, dict) and "claim_sets" in data:
            raise ValueError("DCQL 'claim_sets' is not supported by this profile")
        return data

    @field_validator("id")
    @classmethod
    def _id_syntax(cls, v: str) -> str:
        # Spec 9.6.1 / OID4VP 6.1: non-empty string of alphanumerics, underscore or hyphen.
        if not _DCQL_ID_PATTERN.match(v):
            raise ValueError(f"DCQL credential query id {v!r} must be a non-empty string of [A-Za-z0-9_-]")
        return v

    @model_validator(mode="after")
    def _validate_query(self) -> "DCQLCredentialQuery":
        if self.multiple:
            raise ValueError("DCQL 'multiple: true' is not supported by this profile (one credential per query)")
        if not self.require_cryptographic_holder_binding:
            raise ValueError(
                "DCQL 'require_cryptographic_holder_binding: false' is not supported: "
                "this profile always requires the KB-JWT holder binding"
            )
        if "claims" in self.model_fields_set and not self.claims:
            raise ValueError("DCQL 'claims', when present, must be a non-empty array")

        if self.format == "dc+sd-jwt":
            if not isinstance(self.meta, dict):
                raise ValueError("DCQL 'meta' must be an object")
            unknown = sorted(set(self.meta) - _DC_SD_JWT_META_KEYS)
            if unknown:
                raise ValueError(f"Unsupported DCQL meta field(s) for dc+sd-jwt: {unknown}")
            # Spec 9.6 / OID4VP B.3.5: every dc+sd-jwt query MUST carry a non-empty
            # meta.vct_values array of valid collision-resistant type identifiers.
            vcts = self.meta.get("vct_values")
            if not isinstance(vcts, list) or not vcts or not all(isinstance(v, str) and v for v in vcts):
                raise ValueError(
                    f"dc+sd-jwt credential query '{self.id}' requires meta.vct_values: a non-empty array of type identifiers"
                )
            bare = [v for v in vcts if not is_collision_resistant_type(v)]
            if bare:
                raise ValueError(
                    f"meta.vct_values of query '{self.id}' must be collision-resistant type identifiers "
                    f"(an absolute https URI or a URN, e.g. {AI_AGENT_IDENTITY_VCT}); not namespaced: {bare}"
                )
            # Spec 9.6: meta.trusted_authorities MAY be present (OID4VP 6.1.1 shape). It is an
            # optional hint for Holder candidate selection and never replaces the Verifier's own
            # issuer-trust validation, so it is accepted and validated here.
            if "trusted_authorities" in self.meta:
                auths = self.meta["trusted_authorities"]
                ok = isinstance(auths, list) and bool(auths) and all(
                    isinstance(a, dict)
                    and set(a) == {"type", "values"}
                    and isinstance(a["type"], str) and a["type"]
                    and isinstance(a["values"], list) and a["values"]
                    and all(isinstance(v, str) and v for v in a["values"])
                    for a in auths
                )
                if not ok:
                    raise ValueError(
                        "meta.trusted_authorities must be a non-empty array of {type, values} objects "
                        "with a non-empty string type and a non-empty array of string values"
                    )
        return self


class DCQLQuery(BaseModel):
    """
    Digital Credentials Query Language (DCQL) container.

    Without `credential_sets`, every Credential Query is requested (spec 9.6). `credential_sets`
    is not supported by this profile and is rejected rather than silently ignored.
    """
    model_config = ConfigDict(extra="forbid")

    credentials: List[DCQLCredentialQuery] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _reject_credential_sets(cls, data: Any) -> Any:
        if isinstance(data, dict) and "credential_sets" in data:
            raise ValueError(
                "DCQL 'credential_sets' is not supported by this profile; all credential queries are requested"
            )
        return data

    @model_validator(mode="after")
    def _validate_credentials(self) -> "DCQLQuery":
        if not self.credentials:
            raise ValueError("DCQL 'credentials' must be a non-empty array")
        ids = [c.id for c in self.credentials]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            # Spec 9.6.1: the same id MUST NOT be assigned to two credential queries.
            raise ValueError(f"DCQL credential query ids must be unique; duplicated: {dupes}")
        return self

    @classmethod
    def default_agent_identity_query(cls) -> "DCQLQuery":
        """
        Returns the default DCQL query for AIAgentIdentityCredential per spec Section 9.6.
        """
        return cls(
            credentials=[
                DCQLCredentialQuery(
                    id="agent_identity",
                    format="dc+sd-jwt",
                    meta={"vct_values": [AI_AGENT_IDENTITY_VCT]},
                    claims=[
                        DCQLClaimQuery(path=["name"]),
                        DCQLClaimQuery(path=["description"]),
                        DCQLClaimQuery(path=["owner"]),
                    ],
                )
            ]
        )


class VPFormatsSupported(BaseModel):
    """
    Supported VP formats and signing algorithms per spec Section 4.1.
    """
    sd_jwt_alg_values: List[str] = Field(
        default=["ES256"], alias="sd-jwt_alg_values"
    )
    kb_jwt_alg_values: List[str] = Field(
        default=["ES256"], alias="kb-jwt_alg_values"
    )

    model_config = ConfigDict(populate_by_name=True)


class AgentCardExtensionParams(BaseModel):
    """
    Parameters embedded in the AgentCard extensions array.
    """
    vp_formats_supported: Dict[str, VPFormatsSupported] = Field(
        default_factory=lambda: {"dc+sd-jwt": VPFormatsSupported()}
    )
    # Spec 4.1 / 12.8: channel binding types the Verifier requires in every KB-JWT. Absent means
    # presentations are not channel-bound. The only type defined is "tls-exporter" (RFC 9266).
    channel_binding: Optional[List[str]] = None

    @field_validator("channel_binding")
    @classmethod
    def _known_channel_binding_types(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None:
            unknown = [t for t in v if t not in CHANNEL_BINDING_TYPES]
            if not v or unknown:
                raise ValueError(
                    f"channel_binding must be a non-empty list of {sorted(CHANNEL_BINDING_TYPES)}, got {v}"
                )
        return v


class IdentityChallenge(BaseModel):
    """
    Emitted by Verifier Agent in task.status.message.metadata[ext_uri] with state TASK_STATE_AUTH_REQUIRED.
    """
    status: str = "identity_required"
    nonce: str
    dcql_query: DCQLQuery
    client_id: str
    response_uri: str
    response_mode: str = "a2a_metadata"
    state: Optional[str] = None
    vp_formats_supported: Optional[Dict[str, Any]] = None


class IdentityResponse(BaseModel):
    """
    Sent by Holder Agent in message.metadata[ext_uri] in the Identity Response.
    """
    vp_token: Dict[str, List[str]]


class TunneledChallenge(BaseModel):
    """
    Spec 12.6.1 Rule 1. Wraps a Terminal Verifier Agent's IdentityChallenge for relay by an
    Intermediate Agent into an upstream task. Carried at message.metadata[ext_uri].tunneled_challenge.
    """
    origin_task_id: str
    challenge: IdentityChallenge


class TunneledResponse(BaseModel):
    """
    Spec 12.6.1 Rule 3. Wraps a Holder Agent's IdentityResponse vp_token for relay back through an
    Intermediate Agent. Carried at message.metadata[ext_uri].tunneled_response.
    """
    origin_task_id: str
    response: Dict[str, List[str]]


class OwnerType(str, Enum):
    """
    Allowed values for owner.type per Section 5.2 of the specification.
    """
    LEGAL_PERSON = "legal_person"
    NATURAL_PERSON = "natural_person"


class OwnerClaim(BaseModel):
    """
    Subject responsible for operating an agent (Legal Person or Natural Person).
    Disclosed as a single atomic unit.
    """
    id: str
    name: str
    type: Optional[OwnerType] = None


class StatusListReference(BaseModel):
    """
    Reference to a Token Status List entry per IETF TSL draft.
    """
    idx: int
    uri: str


class StatusClaim(BaseModel):
    status_list: StatusListReference


class KeyProtectionLevel(str, Enum):
    """
    Issuer-attested level of protection for the holder private key, per Section 5.2.

    SOFTWARE     - key held in OS-level storage.
    HARDWARE_TEE - key held in a Trusted Execution Environment or Secure Enclave.
    HARDWARE_HSM - key held in a FIPS 140-3 Level 3+ HSM or Secure Element.
    """
    SOFTWARE = "software"
    HARDWARE_TEE = "hardware_tee"
    HARDWARE_HSM = "hardware_hsm"


class AIAgentIdentityCredential(BaseModel):
    """
    Decoded claims representation of the AIAgentIdentityCredential.
    """
    iss: str
    iat: int
    exp: int
    vct: str
    id: str

    @field_validator("vct")
    @classmethod
    def _vct_is_collision_resistant(cls, v: str) -> str:
        if not is_collision_resistant_type(v):
            raise ValueError("vct must be a collision-resistant type identifier (an absolute https URI or a URN)")
        return v
    name: Optional[str] = None
    description: Optional[str] = None
    owner: Optional[OwnerClaim] = None
    key_protection_level: Optional[KeyProtectionLevel] = None
    cnf: Optional[Dict[str, Any]] = None
    status: Optional[StatusClaim] = None
