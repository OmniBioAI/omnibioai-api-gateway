"""PR12 SS3 API Gateway Security Tests.

End-to-end through the real middleware chain (TraceMiddleware ->
AuthMiddleware -> PolicyMiddleware -> HPCMiddleware -> AuditMiddleware ->
proxy), not unit tests of an individual middleware in isolation (those
already exist: test_auth_middleware.py, test_policy_middleware.py,
test_hpc_middleware.py). Uses a non-HPC-gated route (model-registry) for
the plain-200 case so this exercises exactly Trace/Auth/Policy/Audit
without also needing an HPC mock -- HPC gating on compute services is
already covered end-to-end by test_hpc_middleware.py.
"""
from unittest.mock import AsyncMock, patch

import app.main as _main_mod


# ---------------------------------------------------------------------------
# Case 1: No JWT -> 401
# ---------------------------------------------------------------------------

def test_no_jwt_returns_401(client):
    resp = client.get("/model-registry/v1")

    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Case 2: Invalid JWT -> 401
# ---------------------------------------------------------------------------

def test_invalid_jwt_returns_401(client):
    with patch.object(_main_mod.iam, "validate", AsyncMock(return_value=None)):
        resp = client.get(
            "/model-registry/v1",
            headers={"Authorization": "Bearer not-a-real-token"},
        )

    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Case 3: Valid JWT, insufficient permission -> 403
# ---------------------------------------------------------------------------

def test_valid_jwt_insufficient_permission_returns_403(client, valid_user):
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(
            _main_mod.policy,
            "evaluate",
            AsyncMock(return_value={"allowed": False, "reason": "missing permission: model.use"}),
        ),
    ):
        resp = client.get(
            "/model-registry/v1",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert resp.status_code == 403
    assert resp.json()["error"] == "forbidden"


# ---------------------------------------------------------------------------
# Case 4: Valid JWT with required permission -> 200
# ---------------------------------------------------------------------------

def test_valid_jwt_with_permission_returns_200(client, valid_user):
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(
            _main_mod.policy,
            "evaluate",
            AsyncMock(return_value={"allowed": True}),
        ),
    ):
        resp = client.get(
            "/model-registry/v1",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert resp.status_code == 200
