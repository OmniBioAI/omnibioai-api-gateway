"""PR12 SS5 Organization Context Propagation.

    API Gateway
        +-- Workbench
        +-- Workflow Bundles
        +-- LIMS
        +-- RAG
        +-- Model Registry
        +-- Tool Images

Verifies user_id/organization_id/roles(via permissions)/permissions reach
every service this gateway actually proxies to (app/core/router.py's
SERVICE_MAP: workbench, tes, toolserver, model-registry, rag) via the
generic gateway route (app/routes/gateway.py) -- there's no per-service
special-casing to verify separately, one code path serves all of them.

Workflow Bundles, LIMS, and Tool Images are NOT in SERVICE_MAP today --
this gateway has no route to them at all (a request to any of them 404s
at resolve_service() with {"error": "unknown service"} before any identity
header is even built). That's a real gap relative to the architecture
diagram above, documented here rather than silently worked around --
adding those routes would be a SERVICE_MAP/routing change, not an
authorization-hardening one, and is out of this PR's scope (see this PR's
report).
"""
from unittest.mock import AsyncMock, patch

import pytest

import app.main as _main_mod
from app.core.router import SERVICE_MAP

ORG_AWARE_USER = {
    "user_id": "u-1",
    "email": "u1@omnibioai.test",
    "roles": ["org_member"],
    "permissions": ["workflow.execute", "dataset.read", "model.use"],
    "org_id": "org-7",
}


@pytest.mark.parametrize("service", sorted(SERVICE_MAP.keys()))
def test_org_context_reaches_every_mapped_service(client, service):
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=ORG_AWARE_USER)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        resp = client.get(f"/{service}/ping", headers={"Authorization": "Bearer tok"})

    assert resp.status_code == 200
    call_kwargs = mock_forward.call_args.kwargs
    assert call_kwargs["url"].startswith(SERVICE_MAP[service])

    headers = call_kwargs["headers"]
    assert headers["X-User-Id"] == "u-1"
    assert headers["X-Organization-ID"] == "org-7"
    assert set(headers["X-Permissions"].split(",")) == {
        "workflow.execute", "dataset.read", "model.use",
    }


@pytest.mark.parametrize("missing_service", ["lims", "workflow-bundles", "tool-images"])
def test_services_not_in_service_map_are_unreachable(client, valid_user, missing_service):
    """Documents the gap: LIMS, Workflow Bundles, and Tool Images are not
    in SERVICE_MAP -- a request to any of them never reaches the identity
    -header-building code at all, let alone a real backend."""
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
    ):
        resp = client.get(f"/{missing_service}/ping", headers={"Authorization": "Bearer tok"})

    assert resp.json() == {"error": "unknown service"}
