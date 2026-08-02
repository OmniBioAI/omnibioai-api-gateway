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

iam = IAMClient(Config.IAM_URL, Config.REDIS_URL)
policy = PolicyClient(Config.POLICY_URL)
hpc = HPCPolicyClient(Config.HPC_URL)

_invalidation_task: asyncio.Task | None = None


async def _invalidation_loop():
    """
    Long-running task that subscribes to Redis "policy:invalidate" pub/sub.
    On each message, evicts the IAM token cache entry so the next request
    re-validates against the auth service (zero-trust: revoke = immediate effect).
    Restarts automatically on failure.
    """
    async def on_invalidate(user_id: str, token: str):
        if token:
            await iam.evict(token)

    while True:
        try:
            await iam.subscribe_invalidation(on_invalidate)
        except Exception:
            await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _invalidation_task
    _invalidation_task = asyncio.create_task(_invalidation_loop())
    yield
    if _invalidation_task:
        _invalidation_task.cancel()
        try:
            await _invalidation_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="OmniBioAI API Gateway", lifespan=lifespan)

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
app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok"}
