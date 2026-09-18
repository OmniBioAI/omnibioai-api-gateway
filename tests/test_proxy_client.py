"""ProxyClient.forward() must faithfully relay a proxied request's method,
url, headers, and body to the upstream service, return its status/JSON
body on success, and fail closed with a 500 "upstream_failure" response
(never an unhandled exception) whenever the upstream call itself raises.

Developer:
    Manish Kumar <manish@omnibioai.org>
"""
from unittest.mock import AsyncMock, MagicMock, patch


async def test_forward_success_returns_status_and_json():
    """forward() must return (status_code, json_body) on success."""
    from app.core.proxy import ProxyClient

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "ok"}

    mock_http = AsyncMock()
    mock_http.request.return_value = mock_response

    with patch("app.core.proxy.httpx.AsyncClient", return_value=mock_http):
        client = ProxyClient()

    status, body = await client.forward(
        url="http://upstream/api",
        method="GET",
        headers={"X-Trace-Id": "t1"},
        body=None,
    )
    assert status == 200
    assert body == {"result": "ok"}


async def test_forward_exception_returns_500():
    """forward() must return (500, upstream_failure) on any exception."""
    from app.core.proxy import ProxyClient

    mock_http = AsyncMock()
    mock_http.request.side_effect = RuntimeError("connection refused")

    with patch("app.core.proxy.httpx.AsyncClient", return_value=mock_http):
        client = ProxyClient()

    status, body = await client.forward(
        url="http://upstream/api",
        method="POST",
        body={"key": "val"},
    )
    assert status == 500
    assert body["error"] == "upstream_failure"
    assert "connection refused" in body["detail"]


async def test_forward_passes_method_url_headers_body():
    """forward() must pass all args through to the underlying http client."""
    from app.core.proxy import ProxyClient

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"id": "new"}

    mock_http = AsyncMock()
    mock_http.request.return_value = mock_response

    with patch("app.core.proxy.httpx.AsyncClient", return_value=mock_http):
        client = ProxyClient()

    await client.forward(
        url="http://svc/resource",
        method="PUT",
        headers={"X-User-Id": "u1"},
        body={"field": "value"},
    )

    call_kwargs = mock_http.request.call_args[1]
    assert call_kwargs["method"] == "PUT"
    assert call_kwargs["url"] == "http://svc/resource"
    assert call_kwargs["headers"] == {"X-User-Id": "u1"}
    assert call_kwargs["json"] == {"field": "value"}
