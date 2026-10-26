# SPDX-License-Identifier: Apache-2.0
"""
Relay-side helper for the Delegated Challenge Tunneling Profile (spec 12.6.1).

An Intermediate Agent uses `TunnelRelay` to forward a Terminal Verifier Agent's challenge to a
Holder Agent (Rule 1), to match the Holder's answer to that challenge (Rule 3), and to keep
Task-1 in TASK_STATE_AUTH_REQUIRED while the tunnel is open (Rule 6).

The relay never validates the tunneled presentation (Rule 4). Only the Terminal Verifier does.
The module keeps state in memory and has no I/O. It does not change `ServerAuthRequiredInterceptor`.

Call order. If the same agent also runs `ServerAuthRequiredInterceptor`, call
`TunnelRelay.is_tunneled_response(message)` first and handle such a message with `take_response`.
Do not pass it to the interceptor. On a task with an outstanding challenge of its own, the interceptor
classifies any message that has no `vp_token` as `VP_MISSING` (spec 7.3.4), and the spec excludes a
message that carries `tunneled_response` from that rule (spec 7.3.4, 8.2).
"""

import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional

from . import a2a_wire
from .interceptor import (
    EXTENSION_URI,
    TASK_STATE_AUTH_REQUIRED,
    A2ATaskMessage,
    A2ATaskStatusResponse,
)
from .models import IdentityChallenge, TunneledChallenge, TunneledResponse


class TunnelError(str, Enum):
    """Spec 12.6.1 Rule 7. Reported in `ext_uri.tunnel_error`, never in `ext_uri.error`."""

    TUNNEL_ORIGIN_UNKNOWN = "TUNNEL_ORIGIN_UNKNOWN"
    TUNNEL_REFUSED = "TUNNEL_REFUSED"
    TUNNEL_EXPIRED = "TUNNEL_EXPIRED"


class TunnelRelayError(Exception):
    """A tunnel failure that the relay reports to the Holder under Rule 7."""

    def __init__(self, tunnel_error: TunnelError, message: str) -> None:
        super().__init__(message)
        self.tunnel_error = tunnel_error
        self.message = message


@dataclass(frozen=True)
class PendingTunnel:
    """One relayed challenge, waiting for the Holder's answer."""

    origin_task_id: str
    terminal_client_id: str
    task1_id: str
    task1_context_id: str
    deadline: float


class TunnelRelay:
    """
    In-memory pending-tunnel store for an Intermediate Agent.

    `max_lifetime` is the longest time a tunnel may stay open, in seconds. Set it to a value that
    is not later than the Terminal Verifier's nonce window (Rule 8). The relay cannot read that
    window, so the integrator chooses the value. `clock` is injectable for tests.
    """

    def __init__(
        self,
        max_lifetime: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
        max_ended_records: int = 1024,
    ) -> None:
        if max_lifetime <= 0:
            raise ValueError("max_lifetime must be greater than zero")
        if max_ended_records < 1:
            raise ValueError("max_ended_records must be at least 1")
        self.max_lifetime = max_lifetime
        self._clock = clock
        self._pending: Dict[str, PendingTunnel] = {}
        # Tunnels that ended, kept as ids only, so a late answer gets TUNNEL_EXPIRED and not
        # TUNNEL_ORIGIN_UNKNOWN. The set holds no challenge content.
        self._ended: "OrderedDict[str, None]" = OrderedDict()
        self.max_ended_records = max_ended_records

    # -- Rule 1 and Rule 6 -------------------------------------------------------------------

    def open_tunnel(
        self,
        origin_task_id: str,
        challenge: IdentityChallenge,
        task1_id: str,
        task1_context_id: str,
        parts: Optional[list] = None,
    ) -> A2ATaskStatusResponse:
        """
        Record a pending tunnel and return the Task-1 status that carries the relayed challenge.

        Rule 1: the challenge goes into `tunneled_challenge`, unchanged. Rule 6: the Task-1 state
        is TASK_STATE_AUTH_REQUIRED. The `ext_uri.status` value is not set, because the wrapper
        already shows that a challenge is relayed.
        """
        self._purge()
        if origin_task_id in self._pending:
            raise ValueError(f"A tunnel for origin_task_id '{origin_task_id}' is already open")
        self._pending[origin_task_id] = PendingTunnel(
            origin_task_id=origin_task_id,
            terminal_client_id=challenge.client_id,
            task1_id=task1_id,
            task1_context_id=task1_context_id,
            deadline=self._clock() + self.max_lifetime,
        )
        self._ended.pop(origin_task_id, None)
        tunneled = TunneledChallenge(origin_task_id=origin_task_id, challenge=challenge)
        return A2ATaskStatusResponse(
            id=task1_id,
            context_id=task1_context_id,
            state=TASK_STATE_AUTH_REQUIRED,
            message={
                "role": a2a_wire.ROLE_AGENT,
                "parts": parts or [a2a_wire.text_part("Identity verification required.")],
                "metadata": {EXTENSION_URI: {"tunneled_challenge": tunneled.model_dump()}},
            },
        )

    # -- Rule 3 and Rule 7 -------------------------------------------------------------------

    @staticmethod
    def is_tunneled_response(request: A2ATaskMessage) -> bool:
        """True if the message carries `tunneled_response`. Use it before the interceptor."""
        ext = request.metadata.get(EXTENSION_URI, {}) if isinstance(request.metadata, dict) else {}
        return isinstance(ext, dict) and bool(ext.get("tunneled_response"))

    def take_response(self, request: A2ATaskMessage) -> Optional[TunneledResponse]:
        """
        Match a Holder message to a pending tunnel.

        Returns None if the message carries no `tunneled_response`. Otherwise returns the
        response, unchanged, and closes the tunnel, so one answer cannot be forwarded twice.
        The relay does not read or validate the `vp_token` (Rule 4).
        Raises TunnelRelayError with TUNNEL_ORIGIN_UNKNOWN or TUNNEL_EXPIRED (Rule 7).
        """
        if not self.is_tunneled_response(request):
            return None
        raw = request.metadata[EXTENSION_URI]["tunneled_response"]
        response = TunneledResponse.model_validate(raw)
        self._purge()
        pending = self._pending.get(response.origin_task_id)
        if pending is None:
            if response.origin_task_id in self._ended:
                raise TunnelRelayError(
                    TunnelError.TUNNEL_EXPIRED,
                    "The tunnel for this origin_task_id has ended",
                )
            raise TunnelRelayError(
                TunnelError.TUNNEL_ORIGIN_UNKNOWN,
                "The origin_task_id does not match a pending tunneled challenge",
            )
        if request.id != pending.task1_id:
            # The answer came on another Task-1. Do not close the tunnel for a task that does not own it.
            raise TunnelRelayError(
                TunnelError.TUNNEL_ORIGIN_UNKNOWN,
                "The origin_task_id does not belong to this task",
            )
        del self._pending[response.origin_task_id]
        self._mark_ended(response.origin_task_id)
        return response

    # -- Rule 8 ------------------------------------------------------------------------------

    def close_for_task(self, task_id: str) -> int:
        """
        End every tunnel for a task that reached a terminal state: Task-1 (as `task1_id`) or
        Task-2 (as `origin_task_id`). Returns the number of tunnels ended.
        """
        ids = [
            key for key, p in self._pending.items()
            if p.task1_id == task_id or p.origin_task_id == task_id
        ]
        for key in ids:
            del self._pending[key]
            self._mark_ended(key)
        return len(ids)

    def is_open(self, origin_task_id: str) -> bool:
        self._purge()
        return origin_task_id in self._pending

    def _purge(self) -> None:
        now = self._clock()
        for key in [k for k, p in self._pending.items() if p.deadline <= now]:
            del self._pending[key]
            self._mark_ended(key)

    def _mark_ended(self, origin_task_id: str) -> None:
        """Remember an ended tunnel id. The oldest ids drop first, so memory stays bounded."""
        self._ended[origin_task_id] = None
        while len(self._ended) > self.max_ended_records:
            self._ended.popitem(last=False)

    # -- Rule 7 reporting --------------------------------------------------------------------

    @staticmethod
    def error_response(
        task1_id: str, task1_context_id: str, error: TunnelRelayError
    ) -> A2ATaskStatusResponse:
        """
        Build the Task-1 status that reports a tunnel failure in `ext_uri.tunnel_error`.
        The task state stays TASK_STATE_AUTH_REQUIRED: Rule 7 does not say that a tunnel error
        ends Task-1, and the Holder may be able to retry.
        """
        return A2ATaskStatusResponse(
            id=task1_id,
            context_id=task1_context_id,
            state=TASK_STATE_AUTH_REQUIRED,
            message={
                "role": a2a_wire.ROLE_AGENT,
                "parts": [a2a_wire.text_part(error.message)],
                "metadata": {EXTENSION_URI: {"tunnel_error": error.tunnel_error.value}},
            },
        )
