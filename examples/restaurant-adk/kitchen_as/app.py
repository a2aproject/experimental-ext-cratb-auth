# SPDX-License-Identifier: Apache-2.0
"""Starlette ASGI application for KitchenOAuthAS routes.

Routes:
- POST /nonce: Issue single-use nonce.
- POST /token: RFC 8693 token exchange.
- GET /.well-known/oauth-authorization-server: Server metadata.
"""

import time

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from common.exchange_log import log
from kitchen_as.server import KitchenOAuthAS, TokenExchangeError, TokenExchangeRequest

auth_server = KitchenOAuthAS()


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()
        method = request.method
        path = request.url.path
        log("kitchen_as", f"HTTP {method} {path} received")
        response = await call_next(request)
        duration_ms = (time.time() - start_time) * 1000
        log("kitchen_as", f"HTTP {method} {path} -> {response.status_code} ({duration_ms:.1f}ms)")
        return response


async def issue_nonce(request: Request) -> JSONResponse:
    return JSONResponse({"nonce": auth_server.issue_nonce()})


async def token(request: Request) -> JSONResponse:
    form = await request.form()
    try:
        body = TokenExchangeRequest.model_validate(dict(form))
    except ValidationError as exc:
        return JSONResponse({"error": "invalid_request", "error_description": str(exc)}, status_code=400)

    try:
        result = auth_server.token_exchange(body)
    except TokenExchangeError as exc:
        return JSONResponse(
            {"error": exc.oauth_error, "error_description": exc.message}, status_code=400
        )
    return JSONResponse(result)


async def metadata(request: Request) -> JSONResponse:
    return JSONResponse(auth_server.get_server_metadata())


app = Starlette(
    routes=[
        Route("/nonce", issue_nonce, methods=["POST"]),
        Route("/token", token, methods=["POST"]),
        Route("/.well-known/oauth-authorization-server", metadata, methods=["GET"]),
    ],
    middleware=[
        Middleware(LoggingMiddleware),
    ],
)
