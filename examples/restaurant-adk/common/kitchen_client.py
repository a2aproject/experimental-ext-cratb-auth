# SPDX-License-Identifier: Apache-2.0
"""Client for the Kitchen MCP resource server.

Discovers authorization server metadata with RFC 9728.
Exchanges the EmployeeCredential for an access token with RFC 8693.
Executes MCP kitchen tools with the bearer token.
"""

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from a2a_agentic_id import DCQLClaimQuery, DCQLCredentialQuery, DCQLQuery
from restaurant_domain.x401 import build_result_artifact, encode_result_artifact

from common.config import KITCHEN_MCP_URL
from common.exchange_log import log, log_recv, log_send, truncate
from common.identity import CHEF_AGENT, build_employee_wallet
from common.kitchen_api import KitchenError

_TOKEN_REFRESH_MARGIN_SECONDS = 60
_RESOURCE_METADATA_RE = re.compile(r'resource_metadata="([^"]+)"')

_cached_token: Optional[str] = None
_cached_exp: float = 0.0


async def _probe_unauthenticated(client: httpx.AsyncClient) -> str:
    """Send unauthenticated probe to get Protected Resource Metadata URL."""
    log_send("chef_agent", "kitchen_mcp", "probing unauthenticated (expect 401 + PRM ref)")
    probe_payload = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "chef_agent-unauth-probe", "version": "0.1"},
        },
    }
    resp = await client.post(
        KITCHEN_MCP_URL,
        json=probe_payload,
        headers={"Accept": "application/json, text/event-stream"},
    )
    if resp.status_code != 401:
        raise KitchenError(
            f"kitchen_mcp returned {resp.status_code}, expected 401",
            status_code=resp.status_code,
        )

    www_authenticate = resp.headers.get("WWW-Authenticate", "")
    match = _RESOURCE_METADATA_RE.search(www_authenticate)
    if not match:
        raise KitchenError(
            "kitchen_mcp 401 missing resource_metadata in WWW-Authenticate",
            status_code=502,
        )
    prm_url = match.group(1)
    log_recv("chef_agent", "kitchen_mcp", f"401, PRM at {prm_url}")
    return prm_url


async def _discover_as_metadata(client: httpx.AsyncClient) -> Dict[str, Any]:
    """Retrieve Authorization Server metadata from the PRM document."""
    prm_url = await _probe_unauthenticated(client)
    resp = await client.get(prm_url)
    resp.raise_for_status()
    prm = resp.json()

    auth_servers = prm.get("authorization_servers") or []
    if not auth_servers:
        raise KitchenError("PRM document names no authorization_servers", status_code=502)

    as_issuer = auth_servers[0].rstrip("/")
    as_meta_url = f"{as_issuer}/.well-known/oauth-authorization-server"
    as_resp = await client.get(as_meta_url)
    as_resp.raise_for_status()
    meta = as_resp.json()

    scopes_cnt = len(meta.get("dcql_scope_mapping") or {})
    log_recv("chef_agent", "kitchen_as", f"issuer={as_issuer}, {scopes_cnt} scopes published")
    return meta


def _merged_dcql_query(as_metadata: Dict[str, Any]) -> DCQLQuery:
    """Merge published DCQL requirements into a single query."""
    scope_mapping = as_metadata.get("dcql_scope_mapping") or {}
    claims_by_cred: Dict[Tuple[str, str], Dict[Tuple[str, ...], List[str]]] = {}
    vcts_by_cred: Dict[Tuple[str, str], List[str]] = {}
    for raw_query in scope_mapping.values():
        for raw_cred in raw_query.get("credentials", []):
            key = (raw_cred["id"], raw_cred.get("format", "dc+sd-jwt"))
            paths = claims_by_cred.setdefault(key, {})
            for vct in (raw_cred.get("meta") or {}).get("vct_values", []):
                if vct not in vcts_by_cred.setdefault(key, []):
                    vcts_by_cred[key].append(vct)
            for raw_claim in raw_cred.get("claims", []):
                path = raw_claim.get("path") or []
                if path:
                    paths[tuple(path)] = path

    if not claims_by_cred:
        raise KitchenError("AS metadata dcql_scope_mapping names no credentials", status_code=502)

    log("chef_agent", f"merged DCQL: {len(claims_by_cred)} credential(s) requested")
    return DCQLQuery(
        credentials=[
            DCQLCredentialQuery(
                id=cred_id,
                format=fmt,
                meta={"vct_values": vcts_by_cred.get((cred_id, fmt), [])},
                claims=[DCQLClaimQuery(path=path) for path in paths.values()],
            )
            for (cred_id, fmt), paths in claims_by_cred.items()
        ]
    )


async def _fetch_nonce(client: httpx.AsyncClient, nonce_endpoint: str) -> str:
    """Request a single-use nonce from the authorization server."""
    log_send("chef_agent", "kitchen_as", "POST /nonce")
    resp = await client.post(nonce_endpoint)
    resp.raise_for_status()
    nonce = resp.json()["nonce"]
    log_recv("chef_agent", "kitchen_as", f"nonce={nonce}")
    return nonce


async def _exchange_for_token(client: httpx.AsyncClient) -> Dict[str, Any]:
    """Execute RFC 8693 token exchange with the authorization server."""
    as_metadata = await _discover_as_metadata(client)
    issuer = as_metadata["issuer"]
    nonce_endpoint = as_metadata["nonce_endpoint"]
    token_endpoint = as_metadata["token_endpoint"]
    dcql_query = _merged_dcql_query(as_metadata)

    nonce = await _fetch_nonce(client, nonce_endpoint)
    wallet = build_employee_wallet(CHEF_AGENT)
    log("chef_agent", "creating VP token (EmployeeCredential)")
    vp_resp = wallet.create_vp_token(dcql_query=dcql_query, nonce=nonce, client_id=issuer)
    subject_token = encode_result_artifact(build_result_artifact(vp_resp.vp_token))

    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token_type": "urn:x401:params:oauth:token-type:result_artifact",
        "subject_token": subject_token,
        "nonce": nonce,
        "resource": KITCHEN_MCP_URL,
    }
    log_send("chef_agent", "kitchen_as", "POST /token")
    resp = await client.post(token_endpoint, data=data)
    if resp.is_error:
        error_body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
        log("chef_agent", f"token exchange failed: {error_body}")
        desc = error_body.get("error_description", error_body) if isinstance(error_body, dict) else error_body
        raise KitchenError(f"kitchen_as token exchange failed: {desc}", status_code=resp.status_code)

    token_data = resp.json()
    log_recv(
        "chef_agent",
        "kitchen_as",
        f"granted scope={token_data.get('scope')!r} expires_in={token_data.get('expires_in')}",
    )
    return token_data


async def _get_token() -> str:
    """Return a valid cached bearer token, or fetch a new one."""
    global _cached_token, _cached_exp
    now = time.time()
    if _cached_token is None or now >= _cached_exp - _TOKEN_REFRESH_MARGIN_SECONDS:
        log("chef_agent", "token expired/absent, refreshing")
        async with httpx.AsyncClient() as client:
            result = await _exchange_for_token(client)
        _cached_token = result["access_token"]
        _cached_exp = now + result.get("expires_in", 3600)
    else:
        log("chef_agent", "reusing cached token")
    return _cached_token


async def _call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Execute an MCP tool call on kitchen_mcp."""
    token = await _get_token()
    headers = {"Authorization": f"Bearer {token}"}
    log_send("chef_agent", "kitchen_mcp", f"call_tool {name} {arguments}")
    # mcp 2.x: headers/timeout are configured on the httpx2.AsyncClient passed to the transport.
    # A bare httpx2.AsyncClient defaults to a 5s timeout, too short for the long-lived GET stream,
    # so keep v1's values: timeout=30, sse_read_timeout=300.
    http_client = httpx2.AsyncClient(
        headers=headers,
        timeout=httpx2.Timeout(30, read=300),
    )
    async with http_client:
        async with streamable_http_client(KITCHEN_MCP_URL, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(name, arguments)

    if not result.content:
        raise KitchenError("kitchen_mcp returned an empty tool result", status_code=502)
    content_item = result.content[0]
    raw_text = getattr(content_item, "text", None)
    if raw_text is None:
        raise KitchenError("kitchen_mcp returned a non-text tool result", status_code=502)
    payload = json.loads(raw_text)

    if "error" in payload:
        log_recv("chef_agent", "kitchen_mcp", f"error: {payload['error']}")
        raise KitchenError(payload["error"], status_code=payload.get("status_code", 400))
    log_recv("chef_agent", "kitchen_mcp", f"result: {truncate(str(payload), 100)}")
    return payload


async def list_ingredients() -> Dict[str, int]:
    """Return kitchen ingredient quantities."""
    payload = await _call_tool("list_ingredients", {})
    return payload["ingredients"]


async def prepare_dish(dish_name: str, ingredients: List[str]) -> Dict[str, Any]:
    """Prepare a dish with specified ingredients."""
    return await _call_tool("prepare_dish", {"dish_name": dish_name, "ingredients": ingredients})
