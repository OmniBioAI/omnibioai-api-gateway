import asyncio
import pytest
import httpx
from unittest.mock import AsyncMock, patch

# Import the app module once — IAMClient/PolicyClient/HPCPolicyClient are
# created as module-level singletons here and injected into the middleware.
# No real connections are made at import time (lazy pools).
import app.main as _main_mod
import app.services.audit_client as _audit_client_mod


class SyncASGIClient:
    """Small synchronous adapter around httpx's async ASGI transport."""

    def __init__(self, app):
        self.app = app

    def request(self, method, path, **kwargs):
        async def send():
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(send())

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)


@pytest.fixture(scope="session")
def client():
    # Stub subscribe_invalidation so the background invalidation task never
    # hits Redis during the test session.
    with patch.object(
        _main_mod.iam,
        "subscribe_invalidation",
        AsyncMock(side_effect=Exception("no redis in tests")),
    ):
        yield SyncASGIClient(_main_mod.app)


@pytest.fixture(autouse=True)
def _isolate_external_io():
    """
    Keep the test suite from touching real infrastructure.

    - audit_client._emit() must never write to the real audit:events Redis
      stream: it's the same shared instance the live gateway container
      uses, and prior to this fixture every test run genuinely logged
      upstream_forward/request events for a "workbench" host that only
      exists as FastAPI's TestClient ("http://testserver/..."), polluting
      real audit data with fake entries indistinguishable from production
      traffic.
    - ProxyClient.forward() must never attempt a real network call —
      "workbench" and friends aren't reachable from the test process, so
      every proxied test request was silently hitting a real connection
      failure. Default to a deterministic success; tests that specifically
      exercise upstream-failure behavior override this themselves.
    """
    with (
        patch.object(_audit_client_mod._redis, "xadd", AsyncMock(return_value="0-0")),
        patch(
            "app.routes.gateway.proxy.forward",
            AsyncMock(return_value=(200, {"ok": True})),
        ),
    ):
        yield


@pytest.fixture
def valid_user():
    return {
        "user_id": "123",
        "email": "test@omnibioai.com",
        "roles": ["user"],
        "permissions": ["read:samples"],
    }


@pytest.fixture
def authed(valid_user):
    """Patch iam/policy/hpc so a request is fully authorized."""
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(
            _main_mod.policy,
            "evaluate",
            AsyncMock(return_value={"allowed": True}),
        ),
        patch.object(
            _main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})
        ),
    ):
        yield
