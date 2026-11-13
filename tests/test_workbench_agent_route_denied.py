"""
The gateway's /workbench/ catch-all does not forward the agent graph route,
the async agent run API or agent_workflow_studio's native run, however the
path is spelled. Other Workbench paths are still forwarded.

Developer:
    Manish Kumar <manish@omnibioai.org>
"""
from unittest.mock import AsyncMock, patch

import pytest

from app.routes.gateway import denied_workbench_path

DENIED = [
    "/workbench/api/agent/route/",
    "/workbench/api/agent/route",
    "/workbench/api//agent/route/",
    "/workbench/api/agent/./route/",
    "/workbench/api/agent/x/../route/",
    "/workbench/api/agent/%72oute/",
    "/workbench/api/agent/%2572oute/",
    "/workbench/api%2Fagent%2Froute/",
    "/workbench/API/Agent/Route/",
    "/workbench/ops/agent/run/",
    "/workbench/ops/agent/run/abc123/status/",
    "/workbench/plugins/agent_workflow_studio/api/ui-run/",
    "/workbench/plugins/agent%5Fworkflow%5Fstudio/api/ui-run/",
]
ALLOWED = [
    "/workbench/api/agent/graphs/",
    "/workbench/api/agent/router/",
    "/workbench/ops/agent/graphs/",
    "/workbench/plugins/agent_workflow_studio/api/ui-artifacts/r1/",
    "/workbench/plugins/variant_annotation/api/ui-run/",
    "/workbench/health",
]


@pytest.mark.parametrize("path", DENIED)
@pytest.mark.parametrize("method", ["POST", "GET"])
def test_denied_paths_are_not_forwarded(client, authed, path, method):
    forward = AsyncMock(return_value=(200, {"ok": True}))
    with patch("app.routes.gateway.proxy.forward", forward):
        resp = client.request(method, path, headers={"Authorization": "Bearer tok"}, json={})
    assert resp.status_code == 403
    forward.assert_not_awaited()


@pytest.mark.parametrize("path", ALLOWED)
def test_other_workbench_paths_are_forwarded(client, authed, path):
    forward = AsyncMock(return_value=(200, {"ok": True}))
    with patch("app.routes.gateway.proxy.forward", forward):
        resp = client.request("POST", path, headers={"Authorization": "Bearer tok"}, json={})
    assert resp.status_code == 200
    forward.assert_awaited_once()


def test_same_paths_on_other_services_are_untouched():
    # The deny is scoped to service == "workbench" in the route; the helper
    # itself only looks at the path.
    assert denied_workbench_path("api/agent/route/")
    assert not denied_workbench_path("api/agent/graphs/")
    assert not denied_workbench_path("api/agent/routes-legacy/")
