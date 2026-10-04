"""app/services/mcp_auth.py: Bearer-token gating for the mounted /mcp
Streamable HTTP app. Raw ASGI-level tests -- MCPBearerAuthASGIMiddleware
is deliberately not Starlette's BaseHTTPMiddleware (see its own
docstring), so it's exercised at the scope/receive/send level directly
rather than through a TestClient wrapping a real downstream app.
"""
from unittest.mock import AsyncMock

import pytest

from app.services.mcp_auth import MCPBearerAuthASGIMiddleware, get_current_mcp_api_key

KEY = "omni_sk_" + "a" * 40


def _http_scope(auth_header: str | None):
    headers = []
    if auth_header is not None:
        headers.append((b"authorization", auth_header.encode()))
    return {"type": "http", "method": "GET", "path": "/mcp", "headers": headers}


class _RecordingReceive:
    async def __call__(self):
        return {"type": "http.disconnect"}


class _RecordingSend:
    def __init__(self):
        self.messages = []

    async def __call__(self, message):
        self.messages.append(message)


def _status_of(send: _RecordingSend) -> int:
    start = next(m for m in send.messages if m["type"] == "http.response.start")
    return start["status"]


@pytest.fixture
def inner_app():
    """Records that it was called, and what get_current_mcp_api_key()
    returned at the moment it ran -- proving the contextvar was set
    *before* the inner app runs, not just that auth passed."""
    calls = []

    async def app(scope, receive, send):
        calls.append(get_current_mcp_api_key())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    app.calls = calls
    return app


@pytest.fixture
def iam():
    return AsyncMock()


def test_missing_authorization_header_is_rejected_without_calling_inner_app(inner_app, iam):
    middleware = MCPBearerAuthASGIMiddleware(inner_app, iam)
    send = _RecordingSend()
    import asyncio
    asyncio.run(middleware(_http_scope(None), _RecordingReceive(), send))

    assert _status_of(send) == 401
    assert inner_app.calls == []
    iam.validate_api_key.assert_not_called()


def test_non_api_key_bearer_token_is_rejected(inner_app, iam):
    middleware = MCPBearerAuthASGIMiddleware(inner_app, iam)
    send = _RecordingSend()
    import asyncio
    asyncio.run(middleware(_http_scope("Bearer not-an-api-key"), _RecordingReceive(), send))

    assert _status_of(send) == 401
    assert inner_app.calls == []
    iam.validate_api_key.assert_not_called()


def test_invalid_api_key_is_rejected(inner_app, iam):
    iam.validate_api_key.return_value = None
    middleware = MCPBearerAuthASGIMiddleware(inner_app, iam)
    send = _RecordingSend()
    import asyncio
    asyncio.run(middleware(_http_scope(f"Bearer {KEY}"), _RecordingReceive(), send))

    assert _status_of(send) == 401
    assert inner_app.calls == []


def test_valid_api_key_reaches_the_inner_app_with_the_key_set(inner_app, iam):
    iam.validate_api_key.return_value = {"user_id": "5", "org_id": "42"}
    middleware = MCPBearerAuthASGIMiddleware(inner_app, iam)
    send = _RecordingSend()
    import asyncio
    asyncio.run(middleware(_http_scope(f"Bearer {KEY}"), _RecordingReceive(), send))

    assert _status_of(send) == 200
    assert inner_app.calls == [KEY]
    iam.validate_api_key.assert_awaited_once_with(KEY)


def test_contextvar_is_unset_outside_any_request():
    assert get_current_mcp_api_key() is None


def test_non_http_scope_passes_through_untouched(iam):
    calls = []

    async def app(scope, receive, send):
        calls.append(scope["type"])

    middleware = MCPBearerAuthASGIMiddleware(app, iam)
    import asyncio
    asyncio.run(middleware({"type": "lifespan"}, _RecordingReceive(), _RecordingSend()))
    assert calls == ["lifespan"]
    iam.validate_api_key.assert_not_called()
