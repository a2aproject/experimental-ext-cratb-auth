# SPDX-License-Identifier: Apache-2.0
"""Launches the Kitchen x401 Authorization Server: `python -m kitchen_as`."""

import common.protobuf_patch  # noqa: F401  (prepends a2a_agentic_id to sys.path)

import uvicorn

from common.config import KITCHEN_AS_ISSUER, KITCHEN_AS_PORT
from common.exchange_log import banner
from common.kitchen_scopes import DCQL_SCOPE_MAPPING
from kitchen_as.app import app

if __name__ == "__main__":
    banner(
        "kitchen_as",
        f"x401 Token Exchange AS on port {KITCHEN_AS_PORT}",
        {
            "Issuer": KITCHEN_AS_ISSUER,
            "Nonce Endpoint": f"{KITCHEN_AS_ISSUER}/nonce (POST)",
            "Token Endpoint": f"{KITCHEN_AS_ISSUER}/token (RFC 8693 POST)",
            "Metadata": f"{KITCHEN_AS_ISSUER}/.well-known/oauth-authorization-server",
            "Published Scopes": ", ".join(DCQL_SCOPE_MAPPING),
        },
        "Ready to issue nonces and exchange tokens...",
    )
    uvicorn.run(app, host="127.0.0.1", port=KITCHEN_AS_PORT, log_level="info", access_log=False)
