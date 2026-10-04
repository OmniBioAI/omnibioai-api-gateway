"""M17 (hosted MCP, design audit gap #10): Bearer-token gating for the
Streamable HTTP transport mounted at /mcp.

Deliberately NOT the `mcp` SDK's own OAuth-flavored auth subsystem
(token_verifier + AuthSettings): that subsystem publishes OAuth
discovery metadata (.well-known/oauth-protected-resource) naming an
issuer, implying a standards-compliant authorization server a generic
MCP client could use to obtain a token via the interactive
authorization-code + PKCE "connector" flow. omnibioai-auth doesn't run
that flow (its own OAuth endpoints are client_credentials and one
first-party, platform-admin-only authorization_code path for LIMS, not
a general-purpose one) -- publishing discovery metadata claiming
otherwise would be misleading, not just incomplete. See this
milestone's checkpoint note for that still-open remainder of gap #10.

What's actually implemented: an omni_sk_ API key, already a real,
independently-verifiable Bearer token (the exact mechanism every other
/v1 route already trusts), gates access to /mcp the same way. A raw
ASGI wrapper, not Starlette's BaseHTTPMiddleware, so a long-lived
Streamable HTTP session is never buffered -- just one header check
before the mounted MCP app ever runs.

Also works around a real Starlette/FastAPI incompatibility found while
building this: app.main's app = FastAPI(..., root_path="/_svc/gateway")
makes FastAPI.__call__ force scope["root_path"] = "/_svc/gateway" on
every request. Starlette's Mount then computes this mount's own child
root_path as "/_svc/gateway" + "/mcp" (routing.Mount.matches:
"root_path": root_path + matched_path) -- but scope["path"] was never
actually prefixed with "/_svc/gateway" to begin with (root_path here
is FastAPI's own constructor override, not a prefix a real ASGI-aware
proxy stripped and reflected in both fields consistently), so
starlette.routing.get_route_path's path.startswith(root_path) check
fails and falls back to the full, unstripped path -- which then
matches nothing inside the mounted Streamable HTTP app. Every other
route in this service is a flat APIRouter-prefixed route, never a
nested Mount, so nothing had hit this before /mcp. Fixed below by
resetting root_path to just this mount's own prefix before forwarding,
which is what it would already correctly be if the outer app had no
root_path override at all.
"""
import contextvars

from starlette.responses import JSONResponse

from app.services.iam_client import is_api_key

# Set once per inbound ASGI call by MCPBearerAuthASGIMiddleware, read by
# mcp_server.py's tool handlers to authenticate their own loopback call
# into this gateway's /v1/literature/* routes. contextvars are task-
# scoped, and each inbound HTTP call (including each one within a
# longer-lived Streamable HTTP session) runs in its own task, so this
# is never shared across two different callers' requests.
_current_api_key: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mcp_current_api_key", default=None,
)


def get_current_mcp_api_key() -> str | None:
    return _current_api_key.get()


class MCPBearerAuthASGIMiddleware:
    """Wraps the mounted MCP Streamable HTTP app. Rejects (401) any
    request without a valid omni_sk_ key before it ever reaches the MCP
    protocol handler; on success, stores the raw key for this request's
    tool handlers to use via get_current_mcp_api_key()."""

    def __init__(self, app, iam):
        self.app = app
        self.iam = iam

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # See this module's own docstring: undoes app.main's root_path
        # override before it reaches Starlette's route matching inside
        # the mounted app, where it would otherwise 404 every request.
        scope = {**scope, "root_path": "/mcp"}

        headers = dict(scope.get("headers") or [])
        auth_header = headers.get(b"authorization", b"").decode("latin-1")
        token = auth_header.removeprefix("Bearer ").strip()

        if not token or not is_api_key(token):
            response = JSONResponse({"error": "missing or invalid omni_sk_ API key"}, status_code=401)
            return await response(scope, receive, send)

        user = await self.iam.validate_api_key(token)
        if not user:
            response = JSONResponse({"error": "invalid api key"}, status_code=401)
            return await response(scope, receive, send)

        _current_api_key.set(token)
        return await self.app(scope, receive, send)
