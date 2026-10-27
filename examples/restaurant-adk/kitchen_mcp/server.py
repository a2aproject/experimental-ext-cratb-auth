# SPDX-License-Identifier: Apache-2.0
"""Kitchen MCP resource server.

Exposes authenticated MCP tools over HTTP.
Requires Bearer tokens issued by kitchen_as.
Validates required scopes against common/kitchen_api.py.
"""

import time
from typing import Any, Callable, Dict, List, Optional

import jwt

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer

from common.config import KITCHEN_AS_ISSUER, KITCHEN_AS_JWT_SECRET, KITCHEN_MCP_URL
from common.exchange_log import log
from common.kitchen_api import KitchenError, kitchen


class KitchenTokenVerifier(TokenVerifier):
    """Verify HS256 access tokens issued by kitchen_as."""

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        try:
            payload = jwt.decode(
                token,
                key=KITCHEN_AS_JWT_SECRET,
                algorithms=["HS256"],
                issuer=KITCHEN_AS_ISSUER,
                audience=KITCHEN_MCP_URL,
            )
        except jwt.InvalidTokenError as exc:
            log("kitchen_mcp", f"verify_token FAILED: {exc}")
            return None
        scope = payload.get("scope", "")
        client_id = payload.get("sub", "unknown")
        scopes_list = scope.split() if scope else []
        log("kitchen_mcp", f"verify_token OK sub={client_id!r} scopes={scopes_list!r}")
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes_list,
            expires_at=payload.get("exp"),
            resource=payload.get("aud"),
        )


def _granted_scopes(tool_name: str) -> List[str]:
    """Return verified scopes from the Bearer token."""
    access_token = get_access_token()
    scopes = access_token.scopes if access_token else []
    client_id = access_token.client_id if access_token else "anonymous"
    log("kitchen_mcp", f"tool invoked: [{tool_name}] by client={client_id!r} with scopes={scopes!r}")
    return scopes


def _kitchen_error_result(tool_name: str, exc: KitchenError) -> Dict[str, Any]:
    """Format and log a kitchen operation error."""
    log("kitchen_mcp", f"tool rejected: [{tool_name}] error {exc.status_code}: {exc.message}")
    return {"error": exc.message, "status_code": exc.status_code}


server = MCPServer(
    name="kitchen_mcp",
    token_verifier=KitchenTokenVerifier(),
    log_level="WARNING",
    auth=AuthSettings(
        issuer_url=KITCHEN_AS_ISSUER,
        resource_server_url=KITCHEN_MCP_URL,
        validate_token_resource=True,
    ),
)


@server.tool()
def list_ingredients() -> Dict[str, Any]:
    """List available kitchen ingredients and quantities."""
    tool_name = "list_ingredients"
    scopes = _granted_scopes(tool_name)
    try:
        ingredients = kitchen.list_ingredients(granted_scopes=scopes)
        log("kitchen_mcp", f"tool completed: [{tool_name}] -> {len(ingredients)} ingredient items listed")
        return {"ingredients": ingredients}
    except KitchenError as exc:
        return _kitchen_error_result(tool_name, exc)


@server.tool()
def prepare_dish(dish_name: str, ingredients: List[str]) -> Dict[str, Any]:
    """Prepare a dish using the specified ingredients."""
    tool_name = "prepare_dish"
    scopes = _granted_scopes(tool_name)
    try:
        res = kitchen.prepare_dish(dish_name, ingredients, granted_scopes=scopes)
        log("kitchen_mcp", f"tool completed: [{tool_name}] dish={dish_name!r} with ingredients={ingredients!r} -> status={res.get('status')}")
        return res
    except KitchenError as exc:
        return _kitchen_error_result(tool_name, exc)


_STATUS_REASONS = {
    401: "Unauthorized (unauthenticated rejection with WWW-Authenticate PRM header)",
    403: "Forbidden (insufficient scopes)",
}


class KitchenMCPLoggingMiddleware:
    """ASGI middleware for request and response logging."""

    def __init__(self, app: Callable[..., Any]) -> None:
        self.app = app

    async def __call__(self, scope: Dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")
        start_time = time.time()

        async def send_wrapper(message: Dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                status = message.get("status", 200)
                duration_ms = (time.time() - start_time) * 1000
                reason = _STATUS_REASONS.get(status, "Error" if status >= 400 else "OK")
                log("kitchen_mcp", f"HTTP {method} {path} -> {status} {reason} ({duration_ms:.1f}ms)")
            await send(message)

        await self.app(scope, receive, send_wrapper)


def create_logged_app() -> Any:
    """Return the MCPServer application wrapped with logging middleware."""
    inner_app = server.streamable_http_app()
    return KitchenMCPLoggingMiddleware(inner_app)
