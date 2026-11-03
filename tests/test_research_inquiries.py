"""Public ingress tests for the research-inquiry relay; no real network."""

import pytest
from unittest.mock import AsyncMock, patch

import httpx

from app.core.config import Config


class MockClient:
    def __init__(self, response):
        self.response = response
        self.request = AsyncMock(return_value=response)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


def valid_payload():
    return {
        "full_name": "Synthetic Researcher",
        "institutional_email": "researcher@example.edu",
        "institution": "Example University",
        "department": "Computational Biology",
        "country": "United States",
        "research_interest": "multi_omics",
        "proposed_collaboration": "Synthetic benchmark evaluation.",
        "potential_datasets": "",
        "institutional_website": "https://example.edu",
        "additional_information": "",
        "consent": True,
        "company_fax": "",
    }


def test_public_route_requires_no_admin_token_and_relays_real_201(client, monkeypatch):
    monkeypatch.setattr(Config, "RESEARCH_INQUIRY_BACKEND_URL", "http://auth:8001")
    upstream = httpx.Response(
        201,
        json={
            "status": "received",
            "inquiry_id": "00000000-0000-4000-8000-000000000001",
            "submitted_at": "2026-11-02T00:00:00Z",
        },
        headers={"Content-Type": "application/json"},
    )
    mocked = MockClient(upstream)
    with patch("app.routes.research_inquiries._upstream_client", return_value=mocked):
        response = client.post("/api/v1/research-inquiries", json=valid_payload(), headers={"Origin": "https://omnibioai.org"})
    assert response.status_code == 201
    assert response.json()["inquiry_id"] == "00000000-0000-4000-8000-000000000001"
    assert mocked.request.await_args.args[:2] == ("POST", "http://auth:8001/api/v1/research-inquiries")


def test_unconfigured_network_failure_and_oversize_never_return_success(client, monkeypatch):
    monkeypatch.setattr(Config, "RESEARCH_INQUIRY_BACKEND_URL", "")
    assert client.post("/api/v1/research-inquiries", json=valid_payload()).status_code == 503
    monkeypatch.setattr(Config, "RESEARCH_INQUIRY_BACKEND_URL", "http://auth:8001")
    assert (
        client.post(
            "/api/v1/research-inquiries",
            content=b"x" * 17000,
            headers={"Content-Type": "application/json"},
        ).status_code
        == 413
    )
    with patch("app.routes.research_inquiries._upstream_client", side_effect=httpx.ConnectError("synthetic failure")):
        assert client.post("/api/v1/research-inquiries", json=valid_payload()).status_code == 503


def test_upstream_cors_and_rate_limit_responses_are_preserved(client, monkeypatch):
    monkeypatch.setattr(Config, "RESEARCH_INQUIRY_BACKEND_URL", "http://auth:8001")
    upstream = httpx.Response(429, json={"error": "Too many requests"}, headers={
        "Content-Type": "application/json",
        "Retry-After": "60",
        "Access-Control-Allow-Origin": "https://omnibioai.org",
        "Cache-Control": "no-store",
    })
    with patch("app.routes.research_inquiries._upstream_client", return_value=MockClient(upstream)):
        response = client.post("/api/v1/research-inquiries", json=valid_payload(), headers={"Origin": "https://omnibioai.org"})
    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["access-control-allow-origin"] == "https://omnibioai.org"


@pytest.mark.parametrize("status", [200, 400])
def test_options_text_preflight(client, monkeypatch, status):
    monkeypatch.setattr(Config, "RESEARCH_INQUIRY_BACKEND_URL", "http://auth:8001")
    headers = {"Content-Type": "text/plain", "Vary": "Origin"}
    if status == 200:
        headers["Access-Control-Allow-Origin"] = "https://omnibioai.org"
    mocked = MockClient(httpx.Response(status, text="OK" if status == 200 else "denied", headers=headers))
    with patch("app.routes.research_inquiries._upstream_client", return_value=mocked):
        response = client.request("OPTIONS", "/api/v1/research-inquiries", headers={
            "Origin": "https://omnibioai.org", "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type"})
    assert response.status_code == status
    assert mocked.request.await_args.kwargs["headers"]["access-control-request-method"] == "POST"
    assert (response.headers.get("access-control-allow-origin") is not None) == (status == 200)


@pytest.mark.parametrize(("method", "path"), [
    ("GET", "/api/v1/research-inquiries"), ("PUT", "/api/v1/research-inquiries"),
    ("DELETE", "/api/v1/research-inquiries"), ("PATCH", "/api/v1/research-inquiries"),
    ("POST", "/api/v1/research-inquiries/"), ("POST", "/api/v1/research-inquiries/extra"),
    ("GET", "/api/v1/admin/research-inquiries"), ("POST", "/api/v1/admin/research-inquiries/x/notifications/retry"),
    ("POST", "/auth/api/v1/research-inquiries"),
])
def test_no_unintended_anonymous_bypass(client, method, path):
    assert client.request(method, path).status_code == 401


@pytest.mark.parametrize("status", [400, 403, 409, 413, 415, 422, 429])
def test_safe_error_contract(client, monkeypatch, status):
    monkeypatch.setattr(Config, "RESEARCH_INQUIRY_BACKEND_URL", "http://auth:8001")
    mocked = MockClient(httpx.Response(status, json={"error": "Safe error", "internal": "private"}))
    with patch("app.routes.research_inquiries._upstream_client", return_value=mocked):
        response = client.post("/api/v1/research-inquiries", json=valid_payload())
    assert response.status_code == status and response.json() == {"error": "Safe error"}


@pytest.mark.parametrize("upstream", [
    httpx.Response(500, json={"error": "database password detail"}),
    httpx.Response(201, json={"status": "received", "inquiry_id": "made-up"}),
    httpx.Response(201, text="invalid"),
    httpx.Response(302, headers={"Location": "https://attacker.example"}),
])
def test_untrusted_upstream_never_becomes_success(client, monkeypatch, upstream):
    monkeypatch.setattr(Config, "RESEARCH_INQUIRY_BACKEND_URL", "http://auth:8001")
    with patch("app.routes.research_inquiries._upstream_client", return_value=MockClient(upstream)):
        response = client.post("/api/v1/research-inquiries", json=valid_payload())
    assert response.status_code in {502, 503}
    assert "password" not in response.text and "location" not in response.headers


def test_timeout_is_safe(client, monkeypatch):
    monkeypatch.setattr(Config, "RESEARCH_INQUIRY_BACKEND_URL", "http://auth:8001")
    with patch("app.routes.research_inquiries._upstream_client", side_effect=httpx.ReadTimeout("private host")):
        response = client.post("/api/v1/research-inquiries", json=valid_payload())
    assert response.status_code == 503 and "private host" not in response.text


def test_streamed_limit_and_body_header_forwarding(client, monkeypatch):
    import json
    monkeypatch.setattr(Config, "RESEARCH_INQUIRY_BACKEND_URL", "http://auth:8001")
    mocked = MockClient(httpx.Response(422, json={"error": "Validation failed"}))
    with patch("app.routes.research_inquiries._upstream_client", return_value=mocked):
        response = client.post("/api/v1/research-inquiries", json=valid_payload(), headers={
            "Authorization": "Bearer never-forward", "Cookie": "secret=never-forward",
            "X-Forwarded-For": "1.2.3.4", "CF-Connecting-IP": "1.2.3.4", "X-Trace-Id": "arbitrary-personal-data"})
        assert response.status_code == 422
        forwarded = mocked.request.await_args.kwargs
        assert json.loads(forwarded["content"]) == valid_payload()
        assert forwarded["headers"]["Content-Type"] == "application/json"
        assert forwarded["headers"]["CF-Connecting-IP"] != "1.2.3.4"
        assert "Authorization" not in forwarded["headers"] and "Cookie" not in forwarded["headers"]
        assert forwarded["headers"]["X-Trace-ID"] == response.headers["X-Trace-Id"]
        assert "arbitrary" not in response.headers["X-Trace-Id"]
        async def chunks():
            yield b"x" * 9000
            yield b"x" * 9000
        oversized = client.post("/api/v1/research-inquiries", content=chunks())
        assert oversized.status_code == 413 and mocked.request.await_count == 1
