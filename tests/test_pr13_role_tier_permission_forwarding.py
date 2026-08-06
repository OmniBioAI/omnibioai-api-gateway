"""PR13: confirms the Gateway forwards each role tier's permission set,
and the correct per-service required_permission, to the Policy Engine for
every SERVICE_MAP-mapped service. This repo's own decision-making is
unchanged (no functional code here) -- the actual allow/deny logic lives
in and is tested by omnibioai-policy-engine (see its
test_pr13_permission_map_coverage-equivalent additions). This test proves
only what this repo is responsible for: the right input reaches Policy
Engine's /policy/evaluate call, matching this file's existing convention
(test_pr12_org_context_propagation.py) of mocking PolicyClient.evaluate
rather than re-verifying its internals.
"""
from unittest.mock import AsyncMock, patch

import pytest

import app.main as _main_mod
from app.core.router import SERVICE_MAP, SERVICE_PERMISSION_MAP

# Role tiers from this PR's scenario matrix. Only `permissions` matters to
# the gateway (it forwards whatever the IAM validate response carries,
# unmodified) -- `roles` is included for completeness/realism only, since
# PolicyClient.evaluate does also forward `roles` to the Policy Engine
# (used there only for the legacy admin-override/tenancy checks, not the
# permission gate this PR activates).
ROLE_TIERS = {
    "platform_admin": {"roles": ["platform_admin"], "permissions": ["manage_all_orgs"]},
    "org_admin": {
        "roles": ["org_admin"],
        "permissions": ["manage_org", "manage_teams", "manage_api_keys", "manage_oauth_clients", "manage_sso"],
    },
    "scientist": {"roles": ["scientist"], "permissions": ["workflow.execute", "dataset.read", "model.use"]},
    "viewer": {"roles": ["viewer"], "permissions": ["dataset.read", "workflow.read"]},
}


def _user_for_tier(tier: str) -> dict:
    return {
        "user_id": "u-tier-test",
        "email": "tier-test@omnibioai.test",
        "org_id": "org-tier-test",
        **ROLE_TIERS[tier],
    }


@pytest.mark.parametrize("tier", sorted(ROLE_TIERS.keys()))
@pytest.mark.parametrize("service", sorted(SERVICE_MAP.keys()))
def test_policy_evaluate_receives_tier_permissions_and_required_permission(client, tier, service):
    user = _user_for_tier(tier)
    mock_evaluate = AsyncMock(return_value={"allowed": True})
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=user)),
        patch.object(_main_mod.policy, "evaluate", mock_evaluate),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
    ):
        resp = client.get(f"/{service}/ping", headers={"Authorization": "Bearer tok"})

    assert resp.status_code == 200
    call_kwargs = mock_evaluate.call_args.kwargs
    assert call_kwargs["user"]["permissions"] == user["permissions"]
    assert call_kwargs["required_permission"] == SERVICE_PERMISSION_MAP[service]
    assert call_kwargs["service"] == service


@pytest.mark.parametrize("service", sorted(SERVICE_MAP.keys()))
def test_x_permissions_header_reflects_the_callers_tier(client, service):
    """Complements test_pr12_org_context_propagation.py's own
    X-Permissions assertion -- that test uses one fixed permission set;
    this confirms it varies correctly per role tier, specifically for
    Scientist and Viewer (the two new PR13 default roles)."""
    for tier in ("scientist", "viewer"):
        user = _user_for_tier(tier)
        mock_forward = AsyncMock(return_value=(200, {"ok": True}))
        with (
            patch.object(_main_mod.iam, "validate", AsyncMock(return_value=user)),
            patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
            patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
            patch("app.routes.gateway.proxy.forward", mock_forward),
        ):
            resp = client.get(f"/{service}/ping", headers={"Authorization": "Bearer tok"})

        assert resp.status_code == 200
        headers = mock_forward.call_args.kwargs["headers"]
        assert set(headers["X-Permissions"].split(",")) == set(user["permissions"])
