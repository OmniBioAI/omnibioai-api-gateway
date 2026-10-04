"""app/services/mcp_server.py: the hosted MCP tools, each a loopback
call into this gateway's own /v1/literature/* REST routes carrying the
caller's own omni_sk_ key -- reusing that existing rate-limit/quota/
billing logic unchanged, not reimplementing it for this transport.
"""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.services.mcp_auth import _current_api_key
from app.services.mcp_server import MCPToolCallError, _call_self, build_mcp_server

KEY = "omni_sk_" + "a" * 40


@pytest.fixture(autouse=True)
def api_key_context():
    """Simulates MCPBearerAuthASGIMiddleware having already set the
    contextvar for this "request" -- these tests exercise the tool
    logic in isolation, not the middleware that sets it up."""
    token = _current_api_key.set(KEY)
    yield
    _current_api_key.reset(token)


def test_build_mcp_server_registers_the_three_tools():
    server = build_mcp_server()
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert names == {"answer_with_citations", "search_literature", "list_domains"}


class TestCallSelf:
    def test_forwards_the_api_key_as_a_bearer_token(self):
        forward = AsyncMock(return_value=(200, {"answer": "ok"}))
        with patch("app.services.mcp_server.proxy.forward", forward):
            result = asyncio.run(_call_self("/v1/literature/answers", "POST", {"question": "q"}))
        assert result == {"answer": "ok"}
        kwargs = forward.call_args.kwargs
        assert kwargs["headers"] == {"Authorization": f"Bearer {KEY}"}
        assert kwargs["method"] == "POST"
        assert kwargs["body"] == {"question": "q"}
        assert kwargs["url"].endswith("/v1/literature/answers")

    def test_raises_mcp_tool_call_error_on_a_non_2xx_response(self):
        forward = AsyncMock(return_value=(402, {"error": {"type": "quota_exceeded", "message": "no quota"}}))
        with patch("app.services.mcp_server.proxy.forward", forward):
            with pytest.raises(MCPToolCallError):
                asyncio.run(_call_self("/v1/literature/answers", "POST", {"question": "q"}))

    def test_raises_without_an_authenticated_key(self):
        """Defensive backstop -- MCPBearerAuthASGIMiddleware should
        already have rejected this request, but the tool layer must
        never silently call out with no Authorization header at all."""
        reset_token = _current_api_key.set(None)
        try:
            with pytest.raises(MCPToolCallError):
                asyncio.run(_call_self("/v1/literature/answers", "POST", {"question": "q"}))
        finally:
            _current_api_key.reset(reset_token)


class TestToolHandlers:
    def _tool(self, server, name):
        tools = {t.name: t for t in asyncio.run(server.list_tools())}
        assert name in tools
        return server

    def test_answer_with_citations_calls_the_answers_endpoint(self):
        server = build_mcp_server()
        forward = AsyncMock(return_value=(200, {"answer": "TP53 is a tumor suppressor."}))
        with patch("app.services.mcp_server.proxy.forward", forward):
            result = asyncio.run(server.call_tool("answer_with_citations", {"question": "What does TP53 do?"}))
        kwargs = forward.call_args.kwargs
        assert kwargs["url"].endswith("/v1/literature/answers")
        assert kwargs["body"] == {"question": "What does TP53 do?", "domain": "default"}

    def test_search_literature_calls_the_search_endpoint(self):
        server = build_mcp_server()
        forward = AsyncMock(return_value=(200, {"results": []}))
        with patch("app.services.mcp_server.proxy.forward", forward):
            asyncio.run(server.call_tool("search_literature", {"question": "q", "domain": "Oncology"}))
        kwargs = forward.call_args.kwargs
        assert kwargs["url"].endswith("/v1/literature/search")
        assert kwargs["body"] == {"question": "q", "domain": "Oncology"}

    def test_list_domains_calls_the_domains_endpoint_with_no_body(self):
        server = build_mcp_server()
        forward = AsyncMock(return_value=(200, {"domains": []}))
        with patch("app.services.mcp_server.proxy.forward", forward):
            asyncio.run(server.call_tool("list_domains", {}))
        kwargs = forward.call_args.kwargs
        assert kwargs["url"].endswith("/v1/literature/domains")
        assert kwargs["method"] == "GET"
        assert kwargs["body"] is None
