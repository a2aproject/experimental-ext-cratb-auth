# SPDX-License-Identifier: Apache-2.0
"""Formatted console logger for protocol exchanges and agent decisions."""

from dataclasses import dataclass
from datetime import datetime
import os
import sys
from typing import Any, Dict, Optional

# Enable ANSI escape sequences on Windows consoles.
if sys.platform == "win32":
    os.system("")

_COLORS = {
    "customer_agent": "\033[1;32m",
    "foh_agent": "\033[1;33m",
    "chef_agent": "\033[1;31m",
    "kitchen_as": "\033[1;36m",
    "kitchen_mcp": "\033[1;35m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

# Hop tags. Each credential exchange has a hop type and numbered steps.
# Use the step numbers to read the logs of all terminals together.
#
# SINGLE-HOP (3 steps). The verifier challenges its direct caller.
#   1  verifier -> holder:   challenge (nonce, aud=verifier, DCQL)
#   2  holder   -> verifier: presentation (vp_token)
#   3  verifier:             result
#
# MULTI-HOP (5 steps, spec 12.6.1). The verifier challenges through a relay.
#   1  verifier -> relay:    challenge (nonce, aud=verifier, DCQL)
#   2  relay    -> holder:   tunneled_challenge. The relay cannot answer it.
#   3  holder   -> relay:    tunneled_response. The KB-JWT is bound to the verifier.
#   4  relay    -> verifier: vp_token, unchanged. The relay does not validate it.
#   5  verifier:             result
SINGLE_HOP = "SINGLE-HOP"
MULTI_HOP = "MULTI-HOP"
_HOP_STEPS = {SINGLE_HOP: 3, MULTI_HOP: 5}
_HOP_COLORS = {SINGLE_HOP: "\033[1;34m", MULTI_HOP: "\033[1;95m"}
_legend_printed = False


def _ts() -> str:
    """Return local timestamp string in HH:MM:SS.mmm format."""
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def _format_tag(component: str) -> str:
    """Return colored component tag."""
    color = _COLORS.get(component, "")
    return f"{color}[{component}]{_RESET}"


def banner(component: str, title: str, rows: Dict[str, str], footer: str) -> None:
    """Print the startup banner of a service."""
    color = _COLORS.get(component, "")
    width = max(len(label) for label in rows) + 2
    print(f"{color}{'=' * 65}{_RESET}")
    print(f"{color}{_BOLD}{component} -- {title}{_RESET}")
    print(f"{color}{'=' * 65}{_RESET}")
    for label, value in rows.items():
        print(f"  {_BOLD}{label + ':':<{width}}{_RESET}{value}")
    print(f"{_DIM}{footer}{_RESET}\n", flush=True)


def redact(s: Optional[str], keep: int = 8) -> str:
    """Truncate secrets or tokens to a prefix followed by an ellipsis."""
    if not s:
        return ""
    if len(s) <= keep:
        return s
    return f"{s[:keep]}..."


def truncate(s: Optional[str], max_len: int = 60) -> str:
    """Shorten string to fit within a single terminal line."""
    if not s:
        return ""
    single_line = " ".join(s.split())
    if len(single_line) <= max_len:
        return single_line
    return f"{single_line[:max_len - 3]}..."


def fmt_dcql(dcql_query: Any) -> str:
    """Format a DCQL query into a compact descriptor string."""
    if not dcql_query:
        return "[]"
    creds = getattr(dcql_query, "credentials", None)
    if creds is None and isinstance(dcql_query, dict):
        creds = dcql_query.get("credentials", [])
    if not creds:
        return "[]"

    parts = []
    for cred in creds:
        cred_id = getattr(cred, "id", None) or (cred.get("id") if isinstance(cred, dict) else "?")
        claims = getattr(cred, "claims", None) or (cred.get("claims") if isinstance(cred, dict) else None) or []
        claim_paths = []
        for claim in claims:
            path = getattr(claim, "path", None) or (claim.get("path") if isinstance(claim, dict) else None) or []
            if path:
                claim_paths.append(".".join(str(p) for p in path))
        claims_str = ", ".join(claim_paths) if claim_paths else "*"
        parts.append(f"{cred_id}: [{claims_str}]")
    return "; ".join(parts)


def fmt_claims(claims: Optional[Dict[str, Any]]) -> str:
    """Format disclosed claims into a compact key-value string."""
    if not claims:
        return "{}"
    items = [f"{k}={v!r}" for k, v in claims.items()]
    return ", ".join(items)


def hop_steps(hop: str) -> int:
    """Return the number of steps in a hop sequence."""
    return _HOP_STEPS[hop]


def hop_route(holder: str, verifier: str, relay: Optional[str] = None) -> str:
    """Return the path of a credential exchange, from holder to verifier."""
    if relay:
        return f"{holder} (holder) --> {relay} (relay) --> {verifier} (verifier)"
    return f"{holder} (holder) --> {verifier} (verifier)"


def _hop_prefix(hop: Optional[str], step: Optional[int]) -> str:
    """Return the colored hop tag, for example '[MULTI-HOP 2/5] '."""
    if not hop:
        return ""
    label = hop if step is None else f"{hop} {step}/{_HOP_STEPS[hop]}"
    return f"{_HOP_COLORS[hop]}[{label}]{_RESET} "


def _print_legend(component: str) -> None:
    """Print the meaning of the hop tags one time for each process."""
    global _legend_printed
    if _legend_printed:
        return
    _legend_printed = True
    log(
        component,
        f"{_hop_prefix(SINGLE_HOP, None)}= the verifier challenges its direct caller. "
        "The caller presents its own credential (3 steps).",
    )
    log(
        component,
        f"{_hop_prefix(MULTI_HOP, None)}= the verifier challenges through a relay. "
        "The relay tunnels the challenge to the holder (spec 12.6.1, 5 steps).",
    )


def hop_banner(
    component: str, hop: str, title: str, route: str, why: Optional[str] = None
) -> None:
    """Print the header lines that open a hop sequence."""
    _print_legend(component)
    prefix = _hop_prefix(hop, None)
    log(component, f"{prefix}{_BOLD}===== {title} ====={_RESET}")
    log(component, f"{prefix}  route: {route}")
    if why:
        log(component, f"{prefix}  why:   {why}")


@dataclass(frozen=True)
class Hop:
    """Log lines of one agent in one hop sequence (SINGLE_HOP or MULTI_HOP)."""

    kind: str
    component: str

    @property
    def steps(self) -> int:
        return _HOP_STEPS[self.kind]

    def banner(self, title: str, route: str, why: Optional[str] = None) -> None:
        hop_banner(self.component, self.kind, title, route, why)

    def log(self, step: int, message: str) -> None:
        log(self.component, message, hop=self.kind, step=step)

    def send(self, peer: str, step: int, message: str) -> None:
        log_send(self.component, peer, message, hop=self.kind, step=step)

    def recv(self, peer: str, step: int, message: str) -> None:
        log_recv(self.component, peer, message, hop=self.kind, step=step)


def log(
    component: str, message: str, *, hop: Optional[str] = None, step: Optional[int] = None
) -> None:
    """Print an internal agent decision or status message."""
    ts = _ts()
    tag = _format_tag(component)
    print(f"{_DIM}{ts}{_RESET} {tag} {_hop_prefix(hop, step)}{message}", flush=True)


def log_send(
    component: str,
    peer: str,
    message: str,
    *,
    hop: Optional[str] = None,
    step: Optional[int] = None,
) -> None:
    """Print an outgoing protocol transmission log."""
    ts = _ts()
    tag = _format_tag(component)
    peer_tag = _format_tag(peer)
    print(
        f"{_DIM}{ts}{_RESET} {tag} {_hop_prefix(hop, step)}{_BOLD}->{_RESET} {peer_tag}: {message}",
        flush=True,
    )


def log_recv(
    component: str,
    peer: str,
    message: str,
    *,
    hop: Optional[str] = None,
    step: Optional[int] = None,
) -> None:
    """Print an incoming protocol reception log."""
    ts = _ts()
    tag = _format_tag(component)
    peer_tag = _format_tag(peer)
    print(
        f"{_DIM}{ts}{_RESET} {tag} {_hop_prefix(hop, step)}{_BOLD}<-{_RESET} {peer_tag}: {message}",
        flush=True,
    )
