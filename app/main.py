"""
OmniBioAI app.main.

Purpose:
    Defines HTTP route handlers for app.main, including health and version.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import Config
from app.middleware.s2s import TraceMiddleware
from app.middleware.auth import AuthMiddleware
from app.middleware.policy import PolicyMiddleware
from app.middleware.hpc import HPCMiddleware
from app.middleware.audit import AuditMiddleware

from app.services.iam_client import IAMClient
from app.services.policy_client import PolicyClient
from app.services.hpc_policy_client import HPCPolicyClient

from app.routes.auth_verify import router as auth_verify_router
from app.routes.gateway import router
from app.routes.v1 import router as v1_router
from app.services.mcp_auth import MCPBearerAuthASGIMiddleware
from app.services.mcp_server import build_mcp_server

iam = IAMClient(Config.IAM_URL, Config.REDIS_URL)
policy = PolicyClient(Config.POLICY_URL)
hpc = HPCPolicyClient(Config.HPC_URL)

# M17 (hosted MCP, design audit gap #10): built once at import time, not
# inside lifespan -- app.mount() below needs the already-built
# Starlette app synchronously, and mcp_server.session_manager (used in
# lifespan further down) only exists after streamable_http_app() has
# been called on this same instance.
mcp_server = build_mcp_server()
mcp_streamable_http_app = mcp_server.streamable_http_app(
    streamable_http_path="/",
    # host is a label the SDK uses only to decide whether to
    # *auto*-enable DNS-rebinding Host-header protection for a
    # looks-like-a-local-demo app ("127.0.0.1"/"localhost"/"::1") --
    # not a bind address (uvicorn's own --host already controls that,
    # see Dockerfile). Left at its own default, every real request's
    # Host header (never literally "localhost") would silently 404
    # as if DNS rebinding protection were rejecting it, since the
    # auto-enabled allowlist only accepts those three loopback names.
    host="0.0.0.0",
)

_invalidation_task: asyncio.Task | None = None


async def _invalidation_loop():
    """
    Long-running task that subscribes to Redis "policy:invalidate" pub/sub.
    On each message, evicts the IAM token cache entry so the next request
    re-validates against the auth service (zero-trust: revoke = immediate effect).
    Restarts automatically on failure.
    """
    async def on_invalidate(user_id: str, token: str, api_key_hash: str = ""):
        if token:
            await iam.evict(token)
        if api_key_hash:
            await iam.evict_api_key(api_key_hash)

    while True:
        try:
            await iam.subscribe_invalidation(on_invalidate)
        except Exception:
            await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _invalidation_task
    _invalidation_task = asyncio.create_task(_invalidation_loop())
    # M17: the Streamable HTTP session manager's task group must be
    # running before any /mcp request arrives, or every one fails with
    # "Task group is not initialized" -- entering it here, open for
    # this app's whole lifetime, is the SDK's own documented pattern
    # for mounting an MCPServer into an existing ASGI app rather than
    # running it standalone (see StreamableHTTPSessionManager.run's own
    # docstring).
    async with mcp_server.session_manager.run():
        yield
    if _invalidation_task:
        _invalidation_task.cancel()
        try:
            await _invalidation_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="OmniBioAI API Gateway", lifespan=lifespan, root_path="/_svc/gateway")

# Middleware is applied LIFO: last added = outermost = runs first for requests.
# Desired request flow:
#   TraceMiddleware → AuthMiddleware → PolicyMiddleware → HPCMiddleware → AuditMiddleware → handler
app.add_middleware(AuditMiddleware)
app.add_middleware(HPCMiddleware, hpc=hpc)
app.add_middleware(PolicyMiddleware, policy=policy)
app.add_middleware(AuthMiddleware, iam=iam)
app.add_middleware(TraceMiddleware)


# Registered BEFORE the catch-all gateway router: Starlette matches routes
# in registration order, and /auth/verify (2 path segments) would
# otherwise be shadowed by gateway's own /{service}/{path:path} pattern
# (service="auth", path="verify").
app.include_router(auth_verify_router)
# /v1 before the catch-all too, or /{service}/{path} would take "v1" as a
# service name.
app.include_router(v1_router)

# M17 (hosted MCP, design audit gap #10): also before the catch-all,
# same reason -- /{service}/{path:path} would otherwise match
# service="mcp" and swallow every request here itself, never reaching
# this mount at all. Mounted, not routed through app.include_router,
# since Streamable HTTP's own ASGI app owns the full request/response
# (including a long-lived streaming session) for this path --
# AuthMiddleware/PolicyMiddleware/HPCMiddleware above all skip "/mcp"
# explicitly (see each one's own _SKIP_PREFIXES) specifically so none
# of them buffers or blocks that stream; MCPBearerAuthASGIMiddleware
# here is this mount's own, equivalent gate (see app/services/mcp_auth.py).
app.mount("/mcp", MCPBearerAuthASGIMiddleware(mcp_streamable_http_app, iam))

app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/version")
async def version():
    return {"service": "omnibioai-api-gateway", "version": "0.1.0"}
