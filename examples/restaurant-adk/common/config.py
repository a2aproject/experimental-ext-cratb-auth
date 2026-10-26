# SPDX-License-Identifier: Apache-2.0
"""Configuration settings and network ports for the restaurant demo."""

import logging
import os

# Suppress LiteLLM network fetches and verbose logging.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
os.environ.setdefault("LITELLM_LOG", "ERROR")

from google.adk.models.lite_llm import LiteLlm
import litellm

# Disable LiteLLM debug output and telemetry logging.
litellm.suppress_debug_info = True
litellm.turn_off_message_logging = True
for logger_name in ("LiteLLM", "LiteLLM Proxy", "LiteLLM Router"):
    logging.getLogger(logger_name).setLevel(logging.ERROR)

# Server ports
CHEF_PORT = 8002
FOH_PORT = 8001
KITCHEN_AS_PORT = 8006
KITCHEN_MCP_PORT = 8007

# A2A base URLs. The agent card is at <base URL>/.well-known/agent-card.json.
FOH_AGENT_URL = f"http://127.0.0.1:{FOH_PORT}/a2a/foh_app"
CHEF_AGENT_URL = f"http://127.0.0.1:{CHEF_PORT}/a2a/chef_app"

# Kitchen service endpoints
KITCHEN_AS_ISSUER = f"http://127.0.0.1:{KITCHEN_AS_PORT}"
KITCHEN_MCP_URL = f"http://127.0.0.1:{KITCHEN_MCP_PORT}/mcp"

# Agent that verifies the customer's signed substitution consent:
#   "chef" - chef_agent verifies it. foh_agent tunnels the challenge (spec 12.6.1).
#   "foh"  - foh_agent verifies it and tells chef_agent the result (single hop).
CONSENT_VERIFIER = os.environ.get("CONSENT_VERIFIER", "chef").strip().lower()
if CONSENT_VERIFIER not in ("chef", "foh"):
    raise ValueError(
        f"CONSENT_VERIFIER must be 'chef' or 'foh', not '{CONSENT_VERIFIER}'"
    )

# HS256 secret for kitchen_as access tokens.
# Dev-only demo secret. Real deployments MUST provision >=32 bytes and inject via env.
KITCHEN_AS_JWT_SECRET = os.environ.get(
    "KITCHEN_AS_JWT_SECRET", "dev-only-kitchen-as-secret-change-me-32bytes-min"
)

# Align LiteLLM proxy environment variables if set.
if os.environ.get("LITELLM_PROXY_BASE_URL") and not os.environ.get(
    "LITELLM_PROXY_API_BASE"
):
    os.environ["LITELLM_PROXY_API_BASE"] = os.environ["LITELLM_PROXY_BASE_URL"]

litellm.use_litellm_proxy = True

DEFAULT_MODEL = os.environ.get("LITELLM_PROXY_MODEL", "gemini-3.8-flash")


def build_model(per_agent_env_var: str | None = None) -> LiteLlm:
    """Instantiate a LiteLlm model configured for the specified agent."""
    model_name = DEFAULT_MODEL
    if per_agent_env_var:
        model_name = os.environ.get(per_agent_env_var, DEFAULT_MODEL)
    return LiteLlm(model=model_name)

