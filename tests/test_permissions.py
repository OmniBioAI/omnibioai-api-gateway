"""Tests for app/core/permissions.py — require_permission dependency and
app/core/router.py's SERVICE_MAP -> IAM permission derivation.

require_permission is not wired into the catch-all proxy route (see
app/middleware/policy.py's own docstring for why: PolicyMiddleware's
remote policy-engine call is the authorization decision there, not a
second local one) -- these are direct unit tests of the dependency
itself, for use by any route this gateway defines natively.
"""
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.core.permissions import require_permission
from app.core.router import resolve_required_permission


def _request_with_identity(identity):
    request = MagicMock()
    request.state = MagicMock()
    request.state.identity = identity
    return request


def test_correct_permission_returns_identity():
    check = require_permission("workflow.execute")
    request = _request_with_identity({"user_id": "1", "permissions": ["workflow.execute"]})
    result = check(request)
    assert result["user_id"] == "1"


def test_missing_permission_raises_403():
    check = require_permission("workflow.execute")
    request = _request_with_identity({"user_id": "1", "permissions": []})
    with pytest.raises(HTTPException) as ctx:
        check(request)
    assert ctx.value.status_code == 403


def test_unknown_permission_raises_403_never_fails_open():
    """A permission string with no corresponding IAM grant on this
    identity must still be denied -- never a wildcard/fail-open path."""
    check = require_permission("fake.permission")
    request = _request_with_identity({"user_id": "1", "permissions": ["workflow.execute", "model.use"]})
    with pytest.raises(HTTPException) as ctx:
        check(request)
    assert ctx.value.status_code == 403


def test_missing_permissions_claim_raises_403():
    check = require_permission("workflow.execute")
    request = _request_with_identity({"user_id": "1"})
    with pytest.raises(HTTPException) as ctx:
        check(request)
    assert ctx.value.status_code == 403


def test_no_identity_raises_401():
    check = require_permission("workflow.execute")
    request = _request_with_identity(None)
    with pytest.raises(HTTPException) as ctx:
        check(request)
    assert ctx.value.status_code == 401


@pytest.mark.parametrize(
    "service,expected_permission",
    [
        ("workbench", "workflow.execute"),
        ("tes", "workflow.execute"),
        ("toolserver", "workflow.execute"),
        ("model-registry", "model.use"),
        ("rag", "dataset.read"),
        ("nonexistent-service", None),
    ],
)
def test_resolve_required_permission(service, expected_permission):
    assert resolve_required_permission(service) == expected_permission
