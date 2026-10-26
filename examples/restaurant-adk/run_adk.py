# SPDX-License-Identifier: Apache-2.0
"""Launcher for ADK web server processes.

Applies protobuf patches, sets logging labels, and filters sibling A2A routes.

Usage:
    python run_adk.py web chef_app --port 8002 --a2a
    python run_adk.py web foh_app --port 8001 --a2a
    python run_adk.py web customer_app --port 8000
"""

import logging
import os
import sys
import warnings

# Suppress experimental feature warnings unless explicitly enabled.
_suppress_warnings = True
if "--show-warnings" in sys.argv:
    _suppress_warnings = False
    sys.argv.remove("--show-warnings")
elif os.environ.get("SUPPRESS_EXPERIMENTAL_WARNINGS", "").lower() in ("0", "false", "no"):
    _suppress_warnings = False

if _suppress_warnings:
    os.environ["ADK_SUPPRESS_A2A_EXPERIMENTAL_FEATURE_WARNINGS"] = "1"
    os.environ["ADK_SUPPRESS_EXPERIMENTAL_FEATURE_WARNINGS"] = "1"
    warnings.filterwarnings("ignore", category=UserWarning, message=r".*EXPERIMENTAL.*")

# Suppress LiteLLM logging and network fetches. Set these before ADK imports LiteLLM.
os.environ.setdefault("LITELLM_LOG", "ERROR")
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import common.protobuf_patch  # noqa: F401

from google.adk.cli import main

# Agent labels for log prefixing: app name -> label.
_AGENT_LABELS = {
    "chef_app": "CHEF_AGENT",
    "foh_app": "FOH_AGENT",
    "customer_app": "CUSTOMER_AGENT",
}


def _resolve_agent() -> tuple[str, str] | None:
    """Read agent application name and label from command line arguments."""
    app_name = next((arg for arg in sys.argv[1:] if arg in _AGENT_LABELS), None)
    if app_name is None:
        return None
    return app_name, _AGENT_LABELS[app_name]


class _SiblingA2ALogFilter(logging.Filter):
    """Filter out misleading ADK logs about configuring sibling A2A agents."""

    def __init__(self, current_app: str) -> None:
        super().__init__()
        self.current_app = current_app

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "A2A agent:" in msg:
            return self.current_app in msg
        return True


def _label_adk_logs(label: str, app_name: str) -> None:
    """Configure root logger with agent label prefix and filter sibling routes."""
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            f"[{label}] %(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
        )
    )
    handler.addFilter(_SiblingA2ALogFilter(app_name))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


if __name__ == "__main__":
    resolved = _resolve_agent()
    if resolved is not None:
        app_name, label = resolved
        _label_adk_logs(label, app_name)
    main()
