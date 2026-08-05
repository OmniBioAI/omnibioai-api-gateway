"""Tests for app/services/policy_client.py — PolicyClient unit tests."""
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.policy_client import PolicyClient


@pytest.fixture
def policy_client():
    mock_http = AsyncMock()
    with patch("app.services.policy_client.httpx.AsyncClient", return_value=mock_http):
        client = PolicyClient("http://policy-service")
    return client, mock_http


_USER = {
    "user_id": "u1",
    "email": "u@test.com",
    "roles": ["user"],
    "permissions": ["read"],
}


async def test_evaluate_success(policy_client):
    client, mock_http = policy_client
    resp = MagicMock()
    resp.json.return_value = {"allowed": True}
    mock_http.post.return_value = resp
    result = await client.evaluate(_USER, "/samples", "GET", trace_id="tid1")
    assert result == {"allowed": True}


async def test_evaluate_sends_correct_payload(policy_client):
    client, mock_http = policy_client
    resp = MagicMock()
    resp.json.return_value = {"allowed": True}
    mock_http.post.return_value = resp
    await client.evaluate(_USER, "/samples/123", "POST", trace_id="t1")
    call_kwargs = mock_http.post.call_args
    payload = call_kwargs[1]["json"]
    assert payload["user_id"] == "u1"
    assert payload["resource"] == "/samples/123"
    assert payload["action"] == "post.samples.123"


async def test_evaluate_sends_correct_headers(policy_client):
    client, mock_http = policy_client
    resp = MagicMock()
    resp.json.return_value = {"allowed": False}
    mock_http.post.return_value = resp
    await client.evaluate(_USER, "/path", "GET", trace_id="trace-123")
    headers = mock_http.post.call_args[1]["headers"]
    assert headers["X-Internal-Service"] == "gateway"
    assert headers["X-Trace-Id"] == "trace-123"
    assert headers["X-User-Id"] == "u1"


async def test_evaluate_timeout_first_attempt_retries(policy_client):
    client, mock_http = policy_client
    resp = MagicMock()
    resp.json.return_value = {"allowed": True}
    mock_http.post.side_effect = [httpx.TimeoutException("t/o"), resp]
    result = await client.evaluate(_USER, "/p", "GET")
    assert result == {"allowed": True}
    assert mock_http.post.call_count == 2


async def test_evaluate_timeout_both_attempts_returns_policy_timeout(policy_client):
    client, mock_http = policy_client
    mock_http.post.side_effect = httpx.TimeoutException("t/o")
    result = await client.evaluate(_USER, "/p", "GET")
    assert result == {"allowed": False, "reason": "policy_timeout"}


async def test_evaluate_generic_exception_returns_policy_error(policy_client):
    client, mock_http = policy_client
    mock_http.post.side_effect = RuntimeError("conn refused")
    result = await client.evaluate(_USER, "/p", "GET")
    assert result == {"allowed": False, "reason": "policy_error"}


async def test_evaluate_default_trace_id(policy_client):
    client, mock_http = policy_client
    resp = MagicMock()
    resp.json.return_value = {"allowed": True}
    mock_http.post.return_value = resp
    result = await client.evaluate(_USER, "/path", "DELETE")
    assert result == {"allowed": True}


async def test_evaluate_empty_user_fields(policy_client):
    client, mock_http = policy_client
    resp = MagicMock()
    resp.json.return_value = {"allowed": False, "reason": "no_perms"}
    mock_http.post.return_value = resp
    result = await client.evaluate({}, "/path", "GET")
    assert result["allowed"] is False


async def test_evaluate_sends_org_id(policy_client):
    """PR12: org_id must reach the Policy Engine so it can enforce
    org-tenancy scoping -- previously dropped even though it's already on
    `user` (AuthMiddleware/IAMClient.validate())."""
    client, mock_http = policy_client
    resp = MagicMock()
    resp.json.return_value = {"allowed": True}
    mock_http.post.return_value = resp
    user = {**_USER, "org_id": "org-42"}
    await client.evaluate(user, "/samples", "GET")
    payload = mock_http.post.call_args[1]["json"]
    assert payload["org_id"] == "org-42"


async def test_evaluate_org_id_none_when_absent(policy_client):
    client, mock_http = policy_client
    resp = MagicMock()
    resp.json.return_value = {"allowed": True}
    mock_http.post.return_value = resp
    await client.evaluate(_USER, "/samples", "GET")
    payload = mock_http.post.call_args[1]["json"]
    assert payload["org_id"] is None
