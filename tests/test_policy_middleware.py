"""
Tests for PolicyMiddleware (app/middleware/policy.py).

PolicyClient.evaluate() returns {"allowed": bool, "reason": str}.
The middleware returns 403 {"error": "forbidden", "reason": ...} on denial.
"""
from unittest.mock import AsyncMock, patch

import app.main as _main_mod


def test_policy_denial_returns_403(client, valid_user):
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(
            _main_mod.policy,
            "evaluate",
            AsyncMock(return_value={"allowed": False, "reason": "no_permission"}),
        ),
    ):
        resp = client.get(
            "/workbench/", headers={"Authorization": "Bearer token"}
        )
    assert resp.status_code == 403
    data = resp.json()
    assert data.get("error") == "forbidden"
    assert data.get("reason") == "no_permission"


def test_policy_approval_passes_through(client, valid_user):
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
            "/workbench/", headers={"Authorization": "Bearer token"}
        )
    assert resp.status_code != 403


def test_policy_denial_without_reason(client, valid_user):
    """reason key absent — middleware should default gracefully."""
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(
            _main_mod.policy,
            "evaluate",
            AsyncMock(return_value={"allowed": False}),
        ),
    ):
        resp = client.get(
            "/workbench/", headers={"Authorization": "Bearer token"}
        )
    assert resp.status_code == 403
    assert resp.json().get("error") == "forbidden"


# ---------------------------------------------------------------------------
# IAM Foundation gateway integration: PolicyMiddleware derives the required
# IAM permission from SERVICE_MAP (app/core/router.py) and hands it to
# PolicyClient.evaluate as context -- the policy engine's remote call
# remains the actual allow/deny decision either way (see policy.py's own
# docstring); these tests only cover the derivation and pass-through.
# ---------------------------------------------------------------------------

def test_evaluate_called_with_derived_permission_for_mapped_service(client, valid_user):
    mock_evaluate = AsyncMock(return_value={"allowed": True})
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", mock_evaluate),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
    ):
        client.get("/workbench/ping", headers={"Authorization": "Bearer token"})

    call_kwargs = mock_evaluate.call_args.kwargs
    assert call_kwargs["required_permission"] == "workflow.execute"
    assert call_kwargs["service"] == "workbench"


def test_evaluate_called_with_model_use_for_model_registry(client, valid_user):
    mock_evaluate = AsyncMock(return_value={"allowed": True})
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", mock_evaluate),
    ):
        client.get("/model-registry/models", headers={"Authorization": "Bearer token"})

    call_kwargs = mock_evaluate.call_args.kwargs
    assert call_kwargs["required_permission"] == "model.use"
    assert call_kwargs["service"] == "model-registry"


def test_evaluate_called_with_none_for_unmapped_service(client, valid_user):
    mock_evaluate = AsyncMock(return_value={"allowed": True})
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", mock_evaluate),
    ):
        client.get("/nonexistent-service/x", headers={"Authorization": "Bearer token"})

    call_kwargs = mock_evaluate.call_args.kwargs
    assert call_kwargs["required_permission"] is None
    assert call_kwargs["service"] == "nonexistent-service"


def test_policy_middleware_no_user_returns_403():
    """PolicyMiddleware must return 403 when request.state.user is absent."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient
    from app.middleware.policy import PolicyMiddleware

    async def dummy(request):
        return PlainTextResponse("ok")

    inner_app = Starlette(routes=[Route("/secure", dummy)])
    inner_app.add_middleware(PolicyMiddleware, policy=AsyncMock())

    with TestClient(inner_app, raise_server_exceptions=False) as c:
        resp = c.get("/secure")

    assert resp.status_code == 403
    assert resp.json()["error"] == "forbidden"
