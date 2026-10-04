"""Integration-level confirmation that /mcp is reachable through the
real app (app.main), bypasses Auth/Policy/HPC middleware exactly as
intended, is gated by MCPBearerAuthASGIMiddleware's own check instead,
and that a real MCP protocol handshake actually completes.

That last point matters: this app sets
FastAPI(root_path="/_svc/gateway") for Studio's reverse-proxy URL
generation, and FastAPI.__call__ forces scope["root_path"] to that
value on every request. Starlette's Mount then computes this mount's
own child root_path as "/_svc/gateway" + "/mcp", which
starlette.routing.get_route_path can no longer correctly subtract from
the (never actually so-prefixed) scope["path"] -- every request inside
the mount 404s unless that's corrected first (see
app/services/mcp_auth.py's own docstring for the full mechanism and
the fix). A test that only checked "not 401" would have silently passed
throughout -- it genuinely did, during development -- while the mount
was completely broken underneath; the handshake test below exists
specifically so that regressing this again fails loudly.
"""
import asyncio
from unittest.mock import AsyncMock, patch

import httpx

import app.main as _main_mod

KEY = "omni_sk_" + "a" * 40

INITIALIZE_BODY = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "id": 1,
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "1.0"},
    },
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


def _mcp_post(client, body, headers=None):
    return client.request("POST", "/mcp/", json=body, headers={**MCP_HEADERS, **(headers or {})}, timeout=5)


def test_mcp_without_a_token_returns_this_mounts_own_401_not_authmiddlewares(client):
    """AuthMiddleware's own 401 body is {"error": "missing token"} --
    getting MCPBearerAuthASGIMiddleware's distinct message instead
    proves AuthMiddleware's _SKIP_PREFIXES actually skipped this path,
    rather than it happening to also reject with the same status."""
    resp = _mcp_post(client, INITIALIZE_BODY)
    assert resp.status_code == 401
    assert resp.json() == {"error": "missing or invalid omni_sk_ API key"}


def test_mcp_with_a_non_api_key_bearer_is_rejected(client):
    resp = _mcp_post(client, INITIALIZE_BODY, headers={"Authorization": "Bearer not-an-api-key"})
    assert resp.status_code == 401


def test_mcp_with_an_invalid_api_key_is_rejected(client):
    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=None)):
        resp = _mcp_post(client, INITIALIZE_BODY, headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 401


def test_mcp_initialize_handshake_succeeds_with_a_valid_api_key():
    """The real protocol-level proof: a valid key completes a genuine
    MCP initialize exchange and gets back this server's own name and
    capabilities -- not just "some non-401 response."

    Bypasses the module's shared `client` fixture: that fixture's
    SyncASGIClient calls asyncio.run() per request without ever driving
    the app's own ASGI lifespan, so mcp_server.session_manager's task
    group (entered inside app.main.lifespan, see that module) is never
    initialized -- any real Streamable HTTP request fails with "Task
    group is not initialized." Entering session_manager.run() and
    issuing the request inside the same asyncio.run() call is what
    app.main.lifespan would already be doing for us in production.
    """

    async def _do_request():
        async with _main_mod.mcp_server.session_manager.run():
            transport = httpx.ASGITransport(app=_main_mod.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
                return await c.post(
                    "/mcp/",
                    json=INITIALIZE_BODY,
                    headers={**MCP_HEADERS, "Authorization": f"Bearer {KEY}"},
                )

    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value={"user_id": "5", "org_id": "42"})):
        resp = asyncio.run(_do_request())

    assert resp.status_code == 200
    body = resp.text
    assert '"serverInfo"' in body
    assert '"omnibioai"' in body
