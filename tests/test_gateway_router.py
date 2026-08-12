"""
Tests for the gateway catch-all route (app/routes/gateway.py).

Route pattern: /{service}/{path:path}
resolve_service() maps service slug → upstream URL.
Unknown service → {"error": "unknown service"} with HTTP 200.
Known service → proxy attempt. ProxyClient.forward() is mocked (see
                conftest._isolate_external_io) to a deterministic success by
                default, so these tests never make real network calls; tests
                that need failure behavior override the mock themselves and
                assert the gateway now propagates the real upstream status
                code instead of always returning 200.
"""
from unittest.mock import AsyncMock, patch

import app.main as _main_mod
from app.core.router import SERVICE_MAP


def test_unknown_service_returns_error_body(client, valid_user):
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(
            _main_mod.policy,
            "evaluate",
            AsyncMock(return_value={"allowed": True}),
        ),
    ):
        resp = client.get(
            "/nonexistent-service/some/path",
            headers={"Authorization": "Bearer token"},
        )
    assert resp.status_code == 200
    assert resp.json().get("error") == "unknown service"


def test_known_service_does_not_return_unknown_error(client, valid_user):
    """A known service must be forwarded — the gateway error body must not appear."""
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
            "/workbench/ping", headers={"Authorization": "Bearer token"}
        )
    assert resp.json().get("error") != "unknown service"


def test_service_map_contains_expected_services():
    for svc in ("workbench", "tes", "toolserver", "model-registry", "rag"):
        assert svc in SERVICE_MAP, f"{svc} missing from SERVICE_MAP"


def test_authed_fixture_provides_full_auth(client, authed):
    """Smoke-test the authed fixture: a known service must reach the proxy."""
    resp = client.get("/workbench/health", headers={"Authorization": "Bearer tok"})
    assert resp.json().get("error") != "unknown service"


def test_gateway_audit_emit_exception_silenced(client, valid_user):
    """asyncio.create_task failures in the upstream audit block must be silenced."""
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
        patch(
            "app.routes.gateway.proxy.forward",
            AsyncMock(return_value=(500, {"error": "upstream_failure", "detail": "connection refused"})),
        ),
        patch("app.routes.gateway.asyncio.create_task", side_effect=RuntimeError("no loop")),
    ):
        resp = client.get(
            "/workbench/ping", headers={"Authorization": "Bearer token"}
        )
    # Exception must be swallowed — response still arrives, carrying the real
    # upstream status (500 here) rather than a 200 masking the failure.
    assert resp.status_code == 500


# ---------------------------------------------------------------------------
# SSO Phase 2 PR4: signed identity propagation (Authorization forwarded
# downstream alongside the existing X-User-Id/X-Trace-Id/X-Internal-Service).
# ---------------------------------------------------------------------------

def test_authenticated_request_forwards_authorization_header(client, valid_user):
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get("/workbench/ping", headers={"Authorization": "Bearer original-jwt-value"})

    headers = mock_forward.call_args.kwargs["headers"]
    assert "Authorization" in headers


def test_forwarded_jwt_value_is_unchanged(client, valid_user):
    """The exact token string the client sent (and AuthMiddleware already
    validated) must reach the upstream call unmodified."""
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get("/workbench/ping", headers={"Authorization": "Bearer original-jwt-value"})

    headers = mock_forward.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer original-jwt-value"


def test_no_duplicate_authorization_header_keys(client, valid_user):
    """Only one Authorization entry must reach the upstream call -- not
    both a lowercase passthrough copy and the explicit canonical one."""
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get("/workbench/ping", headers={"Authorization": "Bearer original-jwt-value"})

    headers = mock_forward.call_args.kwargs["headers"]
    authorization_keys = [k for k in headers if k.lower() == "authorization"]
    assert authorization_keys == ["Authorization"]


def test_x_user_id_still_present_alongside_authorization(client, valid_user):
    """Backward compatibility: existing headers must not be removed."""
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get("/workbench/ping", headers={"Authorization": "Bearer original-jwt-value"})

    headers = mock_forward.call_args.kwargs["headers"]
    assert headers["X-User-Id"] == valid_user["user_id"]
    assert "X-Trace-Id" in headers
    assert headers["X-Internal-Service"] == "gateway"
    assert "Authorization" in headers


# ---------------------------------------------------------------------------
# IAM Foundation gateway integration (Step 7): identity propagation headers,
# additive alongside the pre-existing X-User-Id/Authorization/X-Trace-Id/
# X-Internal-Service headers covered above.
# ---------------------------------------------------------------------------

def test_identity_headers_forwarded_for_user_token(client):
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    user = {
        "user_id": "123",
        "email": "test@omnibioai.com",
        "roles": ["user"],
        "permissions": ["workflow.execute", "model.use"],
        "org_id": "org-42",
    }
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get("/workbench/ping", headers={"Authorization": "Bearer original-jwt-value"})

    headers = mock_forward.call_args.kwargs["headers"]
    assert headers["X-Organization-ID"] == "org-42"
    assert headers["X-Client-ID"] == ""
    assert set(headers["X-Permissions"].split(",")) == {"workflow.execute", "model.use"}
    assert headers["X-Token-Type"] == "user"


def test_identity_headers_default_empty_when_org_id_absent(client, valid_user):
    """valid_user (conftest) carries no org_id -- must produce an empty
    string, not the literal "None", on the wire."""
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get("/workbench/ping", headers={"Authorization": "Bearer tok"})

    headers = mock_forward.call_args.kwargs["headers"]
    assert headers["X-Organization-ID"] == ""


def test_unauthenticated_request_behavior_unchanged(client):
    """No Authorization header at all -- AuthMiddleware must still
    short-circuit with 401 before the gateway route (and this PR's new
    header logic) ever runs, exactly as before this PR."""
    resp = client.get("/workbench/ping")
    assert resp.status_code == 401
    assert resp.json() == {"error": "missing token"}


def test_invalid_token_request_behavior_unchanged(client):
    with patch.object(_main_mod.iam, "validate", AsyncMock(return_value=None)):
        resp = client.get(
            "/workbench/ping", headers={"Authorization": "Bearer not-a-valid-token"}
        )
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid token"}


def test_unknown_service_response_unchanged(client, valid_user):
    """Same status code and response body as before this PR for the
    unknown-service path -- no header logic runs for it either way since
    it returns before upstream_headers is even built."""
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
    ):
        resp = client.get(
            "/nonexistent-service/some/path",
            headers={"Authorization": "Bearer token"},
        )
    assert resp.status_code == 200
    assert resp.json() == {"error": "unknown service"}


# ---------------------------------------------------------------------------
# Tenant-isolation audit finding: a client-supplied header of the same
# name as one of the gateway's own identity headers (any case) used to
# survive alongside the gateway's own value as a second, distinct dict
# entry -- both were sent as separate header lines on the wire. See
# app.routes.gateway._RESERVED_UPSTREAM_HEADERS's own docstring for the
# full finding. These tests cover every identity header the gateway
# sets, mirroring test_no_duplicate_authorization_header_keys above
# (the one header this already worked correctly for, pre-dating this
# fix) for the rest.
# ---------------------------------------------------------------------------

_SPOOFED_ORG_USER = {
    "user_id": "123",
    "email": "test@omnibioai.com",
    "roles": ["user"],
    "permissions": ["workflow.execute"],
    "org_id": "org-42",
}


def test_client_supplied_organization_id_header_does_not_reach_upstream(client):
    """A client-forged X-Organization-ID must never be sent -- only the
    gateway's own, JWT-derived value."""
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=_SPOOFED_ORG_USER)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get(
            "/workbench/ping",
            headers={
                "Authorization": "Bearer original-jwt-value",
                "X-Organization-ID": "attacker-org",
            },
        )

    headers = mock_forward.call_args.kwargs["headers"]
    org_id_keys = [k for k in headers if k.lower() == "x-organization-id"]
    assert org_id_keys == ["X-Organization-ID"]
    assert headers["X-Organization-ID"] == "org-42"


def test_client_supplied_lowercase_organization_id_header_does_not_reach_upstream(client):
    """Same attack via the lowercase header-name spelling -- Python dict
    keys are case-sensitive even though HTTP header names aren't, which
    is exactly the gap this fix closes."""
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=_SPOOFED_ORG_USER)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get(
            "/workbench/ping",
            headers={
                "Authorization": "Bearer original-jwt-value",
                "x-organization-id": "attacker-org",
            },
        )

    headers = mock_forward.call_args.kwargs["headers"]
    org_id_keys = [k for k in headers if k.lower() == "x-organization-id"]
    assert org_id_keys == ["X-Organization-ID"]
    assert headers["X-Organization-ID"] == "org-42"


def test_client_supplied_user_id_header_does_not_reach_upstream(client, valid_user):
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get(
            "/workbench/ping",
            headers={"Authorization": "Bearer tok", "X-User-Id": "attacker-user"},
        )

    headers = mock_forward.call_args.kwargs["headers"]
    user_id_keys = [k for k in headers if k.lower() == "x-user-id"]
    assert user_id_keys == ["X-User-Id"]
    assert headers["X-User-Id"] == valid_user["user_id"]


def test_client_supplied_permissions_header_does_not_reach_upstream(client, valid_user):
    """A forged X-Permissions could otherwise be used to attempt a
    privilege-escalation signal to any future downstream service that
    trusts it instead of independently re-verifying the JWT."""
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get(
            "/workbench/ping",
            headers={"Authorization": "Bearer tok", "X-Permissions": "platform.admin"},
        )

    headers = mock_forward.call_args.kwargs["headers"]
    permissions_keys = [k for k in headers if k.lower() == "x-permissions"]
    assert permissions_keys == ["X-Permissions"]
    assert headers["X-Permissions"] == "read:samples"  # valid_user's real permissions


def test_client_supplied_client_id_and_token_type_headers_do_not_reach_upstream(client, valid_user):
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get(
            "/workbench/ping",
            headers={
                "Authorization": "Bearer tok",
                "X-Client-ID": "attacker-client",
                "X-Token-Type": "service",
            },
        )

    headers = mock_forward.call_args.kwargs["headers"]
    assert [k for k in headers if k.lower() == "x-client-id"] == ["X-Client-ID"]
    assert [k for k in headers if k.lower() == "x-token-type"] == ["X-Token-Type"]
    assert headers["X-Client-ID"] == ""
    assert headers["X-Token-Type"] == "user"


def test_client_supplied_internal_service_header_does_not_reach_upstream(client, valid_user):
    """X-Internal-Service is how downstream services could distinguish
    gateway-originated traffic -- a client-forged copy must not survive
    alongside the real one."""
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get(
            "/workbench/ping",
            headers={"Authorization": "Bearer tok", "X-Internal-Service": "not-the-gateway"},
        )

    headers = mock_forward.call_args.kwargs["headers"]
    assert [k for k in headers if k.lower() == "x-internal-service"] == ["X-Internal-Service"]
    assert headers["X-Internal-Service"] == "gateway"


def test_legitimate_non_reserved_headers_still_pass_through(client, valid_user):
    """This fix must not become an accidental allow-list that drops
    ordinary, non-identity client headers -- only the specific reserved
    set is excluded."""
    mock_forward = AsyncMock(return_value=(200, {"ok": True}))
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", mock_forward),
    ):
        client.get(
            "/workbench/ping",
            headers={"Authorization": "Bearer tok", "X-Request-Purpose": "integration-test"},
        )

    headers = mock_forward.call_args.kwargs["headers"]
    # Starlette normalizes incoming header keys to lowercase regardless
    # of how the client sent them -- a non-reserved header passes through
    # under that lowercase key unchanged (unlike the reserved ones,
    # which the gateway re-sets itself under their canonical casing).
    assert headers.get("x-request-purpose") == "integration-test"
