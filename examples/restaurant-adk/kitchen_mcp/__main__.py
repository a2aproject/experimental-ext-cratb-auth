# SPDX-License-Identifier: Apache-2.0
"""Launches the Kitchen MCP resource server: `python -m kitchen_mcp`."""

import common.protobuf_patch  # noqa: F401  (prepends a2a_agentic_id to sys.path)

import uvicorn

from common.config import KITCHEN_AS_ISSUER, KITCHEN_MCP_PORT, KITCHEN_MCP_URL
from common.exchange_log import banner
from kitchen_mcp.server import create_logged_app, server

if __name__ == "__main__":
    banner(
        "kitchen_mcp",
        f"MCP Resource Server on port {KITCHEN_MCP_PORT}",
        {
            "Endpoint": KITCHEN_MCP_URL,
            "Auth Server": f"{KITCHEN_AS_ISSUER} (x401 Token Exchange)",
            "Security": "Requires Bearer JWT with RFC 9728 discovery (401 probe)",
            "Loaded Tools": ", ".join(t.name for t in server._tool_manager.list_tools()),
        },
        "Ready to serve requests...",
    )
    uvicorn.run(create_logged_app(), host="127.0.0.1", port=KITCHEN_MCP_PORT, log_level="info", access_log=False)
