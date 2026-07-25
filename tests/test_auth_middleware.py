"""
Tests for AuthMiddleware (app/middleware/auth.py).

The middleware:
  - Skips /health and / (no auth needed there)
  - Returns 401 {"error": "missing token"} when Authorization is absent
  - Returns 401 {"error": "invalid token"} when iam.validate returns None
  - Strips the "Bearer " prefix before calling iam.validate
  - Attaches the user dict to request.state.user on success
"""
from unittest.mock import AsyncMock, patch

import app.main as _main_mod


def test_missing_token_returns_401(client):
    resp = client.get("/workbench/")
    assert resp.status_code == 401
    assert resp.json().get("error") == "missing token"


def test_invalid_token_returns_401(client):
    with patch.object(_main_mod.iam, "validate", AsyncMock(return_value=None)):
        resp = client.get(
            "/workbench/", headers={"Authorization": "Bearer invalid.token.here"}
        )
    assert resp.status_code == 401
    assert resp.json().get("error") == "invalid token"


def test_valid_token_passes_auth(client, valid_user):
    # workbench is an HPC compute service, so hpc.evaluate must also be mocked.
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
        resp = client.get(
            "/workbench/", headers={"Authorization": "Bearer valid.token"}
        )
    # ProxyClient.forward() is mocked to a default success in conftest — the
    # point here is only that auth passed, i.e. status must not be 401.
    assert resp.status_code != 401


def test_bearer_prefix_stripped(client, valid_user):
    """iam.validate must receive the raw token, not the full header value."""
    mock_validate = AsyncMock(return_value=valid_user)
    with (
        patch.object(_main_mod.iam, "validate", mock_validate),
        patch.object(
            _main_mod.policy,
            "evaluate",
            AsyncMock(return_value={"allowed": True}),
        ),
        patch.object(
            _main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})
        ),
    ):
        client.get(
            "/workbench/", headers={"Authorization": "Bearer mytoken123"}
        )

    call_args = mock_validate.call_args
    assert call_args is not None
    token_arg = call_args[0][0] if call_args[0] else call_args[1].get("token", "")
    assert token_arg == "mytoken123"
    assert not token_arg.startswith("Bearer")


def test_unauthenticated_non_health_path_returns_401(client):
    resp = client.get("/auth/verify")
    assert resp.status_code == 401


def test_health_skip_path_bypasses_auth(client):
    resp = client.get("/health")
    assert resp.status_code == 200
