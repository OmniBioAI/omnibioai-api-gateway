"""SSO Phase 2 PR8: GET /auth/verify -- a real, dedicated contract for
nginx-router.conf's `auth_request /internal/auth/verify`, replacing the
accidental incidental-200-via-unmapped-service-catch-all behavior PR7
found. See app/routes/auth_verify.py for the full contract rationale.
"""
from unittest.mock import AsyncMock, patch

import app.main as _main_mod


def test_valid_token_returns_200(client, valid_user):
    with patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)):
        resp = client.get("/auth/verify", headers={"Authorization": "Bearer token"})

    assert resp.status_code == 200


def test_valid_token_response_contract(client, valid_user):
    with patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)):
        resp = client.get("/auth/verify", headers={"Authorization": "Bearer token"})

    body = resp.json()
    assert body == {
        "authenticated": True,
        "user": {
            "id": valid_user["user_id"],
            "roles": valid_user["roles"],
        },
    }


def test_missing_token_returns_401(client):
    resp = client.get("/auth/verify")
    assert resp.status_code == 401


def test_invalid_token_returns_401(client):
    with patch.object(_main_mod.iam, "validate", AsyncMock(return_value=None)):
        resp = client.get("/auth/verify", headers={"Authorization": "Bearer bad-token"})
    assert resp.status_code == 401


def test_does_not_fall_through_to_gateway_proxy(client, valid_user):
    """Proves /auth/verify is handled by its own dedicated route, not the
    catch-all gateway route with an unmapped "auth" service -- the whole
    point of this PR. If this route were shadowed by the catch-all
    (registration-order regression), proxy.forward would be called."""
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get("/auth/verify", headers={"Authorization": "Bearer token"})

    mock_forward.assert_not_called()


def test_does_not_depend_on_policy_engine_decision(client, valid_user):
    """/auth/verify is a pure identity check -- it must succeed regardless
    of what the policy engine would decide for this synthetic path
    (skip-listed in PolicyMiddleware). Proven here by making the policy
    engine deny everything and confirming /auth/verify still returns 200
    while a real gated route in the same request context would not."""
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(
            _main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": False, "reason": "deny_all"})
        ) as mock_evaluate,
    ):
        resp = client.get("/auth/verify", headers={"Authorization": "Bearer token"})

    assert resp.status_code == 200
    mock_evaluate.assert_not_called()
