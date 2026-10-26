# SPDX-License-Identifier: Apache-2.0
"""
A2A v1.0.0 wire shapes and binding error bodies (spec 6.2, 7.3.2, 7.3.3, 11.2).

Pure builders with no I/O. The canonical forms follow the A2A v1.0.0 `a2a.proto` and JSON
bindings (https://a2a-protocol.org/v1.0.0/specification/):

  * Message  : `messageId`, `role`, `parts` are REQUIRED; server messages carry `contextId`
               (and `taskId` when a task exists). No `kind` discriminator.
  * Part     : exactly one of `text` / `raw` / `url` / `data`; no `kind`.
  * Task     : `id` and `status` are REQUIRED; `contextId` identifies the context.
  * Enums    : `TASK_STATE_*` and `ROLE_*` strings.
  * Response : `SendMessageResponse` is a oneof of `task` | `message`.
  * Errors   : an A2A-specific error carries a `google.rpc.ErrorInfo` (reason, domain
               `a2a-protocol.org`) in `error.data` (JSON-RPC), `error.details` (HTTP+JSON) or
               `status.details` (gRPC).

No transport lives here: these functions return plain dicts that a binding adapter serializes.
"""

import uuid
from typing import Any, Dict, List, Mapping, Optional

ROLE_USER = "ROLE_USER"
ROLE_AGENT = "ROLE_AGENT"

_ROLES = frozenset({ROLE_USER, ROLE_AGENT})

ERROR_INFO_TYPE = "type.googleapis.com/google.rpc.ErrorInfo"
ERROR_DOMAIN = "a2a-protocol.org"

# Part members that carry content. A canonical Part has exactly one of the first four.
_PART_CONTENT_KEYS = ("text", "raw", "url", "data")


def new_message_id() -> str:
    """A fresh unique message identifier (the A2A spec suggests a UUID)."""
    return str(uuid.uuid4())


def validate_role(role: Any) -> str:
    """Returns `role` if it is `ROLE_USER` or `ROLE_AGENT`. This SDK is A2A v1.0.0 only: 'user' and 'agent' are rejected."""
    if role not in _ROLES:
        raise ValueError(f"Unknown A2A message role {role!r}; A2A v1.0.0 expects 'ROLE_USER' or 'ROLE_AGENT'")
    return role


def text_part(text: str) -> Dict[str, Any]:
    return {"text": text}


def validate_part(part: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Checks a Part against A2A v1.0.0: no legacy `kind` discriminator, and exactly one of `text`,
    `raw`, `url` or `data`.
    """
    if "kind" in part:
        raise ValueError("A2A v1.0.0 Parts have no 'kind' discriminator; use {'text': ...}")
    out = dict(part)
    present = [k for k in _PART_CONTENT_KEYS if k in out]
    if len(present) != 1:
        raise ValueError(f"A2A Part must contain exactly one of {list(_PART_CONTENT_KEYS)}; got {present or 'none'}")
    return out


def canonical_message(
    message: Mapping[str, Any],
    task_id: Optional[str] = None,
    context_id: Optional[str] = None,
    default_role: str = ROLE_AGENT,
) -> Dict[str, Any]:
    """
    Completes a server message into an A2A v1.0.0 Message: generates `messageId` when absent and
    fills `taskId` / `contextId` when given and not already set (existing values are never
    overwritten). The role defaults to `default_role`. Legacy shapes (`kind`, 'agent'/'user'
    roles) are rejected, not rewritten.
    """
    if "kind" in message:
        raise ValueError("A2A v1.0.0 Messages have no 'kind' discriminator")
    out: Dict[str, Any] = dict(message)
    out.setdefault("messageId", new_message_id())
    out["role"] = validate_role(out["role"]) if "role" in out else default_role
    out["parts"] = [validate_part(p) for p in out.get("parts", [])]
    if task_id:
        out.setdefault("taskId", task_id)
    if context_id:
        out.setdefault("contextId", context_id)
    return out


# --------------------------------------------------------------------------- envelopes


def send_message_response(task: Optional[Mapping[str, Any]] = None, message: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """
    `SendMessageResponse`: contains exactly one of `task` or `message` (A2A v1.0.0 a2a.proto).
    """
    if (task is None) == (message is None):
        raise ValueError("SendMessageResponse contains exactly one of 'task' or 'message'")
    return {"task": dict(task)} if task is not None else {"message": dict(message)}  # type: ignore[arg-type]


def jsonrpc_result(request_id: Any, result: Mapping[str, Any]) -> Dict[str, Any]:
    """JSON-RPC 2.0 success envelope echoing the request `id`."""
    return {"jsonrpc": "2.0", "id": request_id, "result": dict(result)}


def jsonrpc_send_message_request(
    message: Mapping[str, Any], request_id: Any = None, params_extra: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    """A `SendMessage` JSON-RPC request carrying one Message (spec 7.3.2)."""
    params: Dict[str, Any] = {"message": canonical_message(message, default_role=ROLE_USER)}
    if params_extra:
        params.update(params_extra)
    return {"jsonrpc": "2.0", "id": request_id if request_id is not None else new_message_id(), "method": "SendMessage", "params": params}


# --------------------------------------------------------------------------- error bodies

# (JSON-RPC code, gRPC status, HTTP status) from the A2A v1.0.0 error mapping table (5.4).
_ERROR_MAPPING = {
    "TaskNotFoundError": (-32001, "NOT_FOUND", 404),
    "ExtensionSupportRequiredError": (-32008, "FAILED_PRECONDITION", 400),
    "VersionNotSupportedError": (-32009, "FAILED_PRECONDITION", 400),
}


def error_reason(error_type: str) -> str:
    """The A2A `ErrorInfo.reason`: UPPER_SNAKE_CASE of the error type without the `Error` suffix."""
    base = error_type[:-5] if error_type.endswith("Error") else error_type
    out: List[str] = []
    for i, ch in enumerate(base):
        if ch.isupper() and i and (not base[i - 1].isupper() or (i + 1 < len(base) and base[i + 1].islower())):
            out.append("_")
        out.append(ch.upper())
    return "".join(out)


def error_info(error_type: str, metadata: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """A `google.rpc.ErrorInfo` detail object; A2A makes it mandatory for A2A-specific errors."""
    info: Dict[str, Any] = {"@type": ERROR_INFO_TYPE, "reason": error_reason(error_type), "domain": ERROR_DOMAIN}
    if metadata:
        info["metadata"] = dict(metadata)
    return info


def jsonrpc_error(error_type: str, message: str, details: List[Mapping[str, Any]], request_id: Any = None) -> Dict[str, Any]:
    """JSON-RPC error: `error.code`, `error.message`, `error.data` (array of `@type` objects)."""
    code = _ERROR_MAPPING[error_type][0]
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message, "data": [dict(d) for d in details]}}


def http_error(error_type: str, message: str, details: List[Mapping[str, Any]]) -> Dict[str, Any]:
    """
    HTTP+JSON error body (`google.rpc.Status` JSON): `error.code` is the HTTP status, `error.status`
    the gRPC status name, `error.details` the array of `@type` objects. Send with the HTTP status
    from `http_status(error_type)`.
    """
    _, grpc_status, http = _ERROR_MAPPING[error_type]
    return {"error": {"code": http, "status": grpc_status, "message": message, "details": [dict(d) for d in details]}}


def grpc_status(error_type: str, message: str, details: List[Mapping[str, Any]]) -> Dict[str, Any]:
    """
    gRPC `google.rpc.Status` as a plain dict: `code` is the status name, `details` the array of
    `@type` objects (each a google.protobuf.Any).
    """
    _, status, _ = _ERROR_MAPPING[error_type]
    return {"code": status, "message": message, "details": [dict(d) for d in details]}


def http_status(error_type: str) -> int:
    return _ERROR_MAPPING[error_type][2]
