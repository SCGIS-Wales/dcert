"""Tests for dcert.middleware."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import mcp_types as mt
import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.middleware.caching import ResponseCachingMiddleware
from fastmcp.tools.base import ToolResult

from dcert.middleware import (
    ResilienceMiddleware,
    build_call_tool_handler,
    build_middleware,
    create_caching_middleware,
    create_resilience_middleware,
    truncate_tool_result,
)
from dcert.resilience import resilience_config_from_env


@pytest.fixture
def config(monkeypatch):
    for name in list(__import__("os").environ):
        if name.startswith("DCERT_MCP_"):
            monkeypatch.delenv(name)
    return replace(resilience_config_from_env(), retry_base_delay=0.0, retry_max_delay=0.0)


def _context(tool: str = "echo") -> MiddlewareContext:
    return MiddlewareContext(
        message=mt.CallToolRequestParams(name=tool, arguments={}), method="tools/call"
    )


def _result(text: str = "ok") -> ToolResult:
    return ToolResult(content=[mt.TextContent(type="text", text=text)])


# ---------------------------------------------------------------------------
# truncate_tool_result
# ---------------------------------------------------------------------------


def test_truncate_tool_result_truncates_text_blocks():
    result = ToolResult(
        content=[
            mt.TextContent(type="text", text="a" * 500),
            mt.ImageContent(type="image", data="AA==", mimeType="image/png"),
        ]
    )
    truncated = truncate_tool_result(result, 100)
    assert "[Truncated:" in truncated.content[0].text
    assert truncated.content[1] is result.content[1]
    assert result.content[0].text == "a" * 500


def test_truncate_tool_result_disabled():
    result = _result("a" * 500)
    assert truncate_tool_result(result, 0) is result


# ---------------------------------------------------------------------------
# Handler behaviour
# ---------------------------------------------------------------------------


async def test_handler_passthrough(config):
    handle = build_call_tool_handler(config)
    call_next = AsyncMock(return_value=_result("hello"))
    result = await handle(_context(), call_next)
    assert result.content[0].text == "hello"
    call_next.assert_awaited_once()


async def test_handler_truncates(config):
    handle = build_call_tool_handler(replace(config, max_response_bytes=64))
    call_next = AsyncMock(return_value=_result("x" * 1000))
    result = await handle(_context(), call_next)
    assert "[Truncated:" in result.content[0].text


async def test_handler_timeout(config):
    handle = build_call_tool_handler(replace(config, tool_timeout=0.01))

    async def slow(_context):
        await asyncio.sleep(1)
        return _result()

    with pytest.raises(ToolError, match="echo timed out after 0.01s"):
        await handle(_context(), slow)


async def test_handler_retries_connection_errors(config):
    handle = build_call_tool_handler(replace(config, retry_max_attempts=3))
    call_next = AsyncMock(side_effect=[ConnectionResetError("gone"), _result("back")])
    with patch("dcert.resilience.asyncio.sleep", new=AsyncMock()) as sleep:
        result = await handle(_context(), call_next)
    assert result.content[0].text == "back"
    assert call_next.await_count == 2
    sleep.assert_awaited_once()


async def test_handler_does_not_retry_other_errors(config):
    handle = build_call_tool_handler(config)
    call_next = AsyncMock(side_effect=ValueError("bad"))
    with pytest.raises(ValueError, match="bad"):
        await handle(_context(), call_next)
    assert call_next.await_count == 1


async def test_handler_retry_disabled(config):
    handle = build_call_tool_handler(replace(config, retry_enabled=False))
    call_next = AsyncMock(side_effect=ConnectionResetError("gone"))
    with pytest.raises(ConnectionResetError, match="gone"):
        await handle(_context(), call_next)
    assert call_next.await_count == 1


async def test_handler_circuit_breaker_opens(config):
    cfg = replace(config, retry_enabled=False, circuit_breaker_threshold=1)
    handle = build_call_tool_handler(cfg)
    call_next = AsyncMock(side_effect=ConnectionResetError("gone"))
    with pytest.raises(ConnectionResetError, match="gone"):
        await handle(_context(), call_next)
    with pytest.raises(ToolError, match="Circuit breaker is open; echo rejected"):
        await handle(_context(), call_next)
    assert call_next.await_count == 1


async def test_handler_circuit_breaker_disabled(config):
    cfg = replace(config, retry_enabled=False, circuit_breaker_enabled=False)
    cfg = replace(cfg, circuit_breaker_threshold=1)
    handle = build_call_tool_handler(cfg)
    call_next = AsyncMock(side_effect=[ConnectionResetError("gone"), _result("ok")])
    with pytest.raises(ConnectionResetError, match="gone"):
        await handle(_context(), call_next)
    assert (await handle(_context(), call_next)).content[0].text == "ok"


async def test_handler_rate_limiter(config):
    cfg = replace(config, rate_limit_enabled=True, rate_limit_rps=1000.0, rate_limit_burst=1)
    handle = build_call_tool_handler(cfg)
    call_next = AsyncMock(return_value=_result())
    with patch("dcert.resilience.asyncio.sleep", new=AsyncMock()) as sleep:
        await handle(_context(), call_next)
        await handle(_context(), call_next)
    sleep.assert_awaited_once()


async def test_handler_bulkhead_limits_concurrency(config):
    handle = build_call_tool_handler(replace(config, bulkhead_max=2))
    active = 0
    peak = 0

    async def slow(_context):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return _result()

    await asyncio.gather(*(handle(_context(), slow) for _ in range(6)))
    assert peak == 2


# ---------------------------------------------------------------------------
# Middleware assembly
# ---------------------------------------------------------------------------


async def test_resilience_middleware_delegates(config):
    handler = AsyncMock(return_value=_result("via handler"))
    middleware = ResilienceMiddleware(handler)
    result = await middleware.on_call_tool(_context(), AsyncMock())
    assert result.content[0].text == "via handler"


def test_create_resilience_middleware(config):
    assert isinstance(create_resilience_middleware(config), Middleware)


def test_create_caching_middleware(config):
    assert isinstance(create_caching_middleware(config), ResponseCachingMiddleware)


def test_build_middleware_without_cache(config):
    chain = build_middleware(config)
    assert len(chain) == 1
    assert isinstance(chain[0], ResilienceMiddleware)


def test_build_middleware_with_cache(config):
    chain = build_middleware(replace(config, cache_enabled=True))
    assert [type(m) for m in chain] == [ResponseCachingMiddleware, ResilienceMiddleware]


# ---------------------------------------------------------------------------
# End to end through a FastMCP server
# ---------------------------------------------------------------------------


async def test_middleware_in_fastmcp_server(config):
    server = FastMCP("test")
    calls = 0

    @server.tool
    def echo(text: str) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConnectionResetError("first call fails")
        return text * 100

    for middleware in build_middleware(replace(config, max_response_bytes=50)):
        server.add_middleware(middleware)

    with patch("dcert.resilience.asyncio.sleep", new=AsyncMock()):
        async with Client(server) as client:
            result = await client.call_tool("echo", {"text": "abc"})
    assert calls == 2
    assert "[Truncated:" in result.content[0].text
