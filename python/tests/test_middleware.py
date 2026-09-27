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
    ReadOnlyCachingMiddleware,
    ResilienceMiddleware,
    build_annotation_lookup,
    build_call_tool_handler,
    build_middleware,
    create_caching_middleware,
    create_resilience_middleware,
    is_cacheable,
    is_retry_safe,
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


READ_ONLY = mt.ToolAnnotations(read_only_hint=True, idempotent_hint=True)
IDEMPOTENT_WRITE = mt.ToolAnnotations(read_only_hint=False, idempotent_hint=True)
ISSUING = mt.ToolAnnotations(read_only_hint=False, idempotent_hint=False)


def _annotated(annotations: mt.ToolAnnotations | None):
    """An annotation lookup that reports *annotations* for every tool."""

    async def lookup(_context):
        return annotations

    return lookup


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
    handle = build_call_tool_handler(replace(config, retry_max_attempts=3), _annotated(READ_ONLY))
    call_next = AsyncMock(side_effect=[ConnectionResetError("gone"), _result("back")])
    with patch("dcert.resilience.asyncio.sleep", new=AsyncMock()) as sleep:
        result = await handle(_context(), call_next)
    assert result.content[0].text == "back"
    assert call_next.await_count == 2
    sleep.assert_awaited_once()


async def test_handler_retries_idempotent_writes(config):
    handle = build_call_tool_handler(config, _annotated(IDEMPOTENT_WRITE))
    call_next = AsyncMock(side_effect=[ConnectionResetError("gone"), _result("back")])
    with patch("dcert.resilience.asyncio.sleep", new=AsyncMock()):
        assert (await handle(_context(), call_next)).content[0].text == "back"
    assert call_next.await_count == 2


@pytest.mark.parametrize("annotations", [ISSUING, None])
async def test_handler_never_retries_unsafe_tools(config, annotations):
    """A call that may have issued a certificate must not run a second time."""
    handle = build_call_tool_handler(config, _annotated(annotations))
    call_next = AsyncMock(side_effect=[ConnectionResetError("gone"), _result("again")])
    with pytest.raises(ConnectionResetError, match="gone"):
        await handle(_context("vault_issue"), call_next)
    assert call_next.await_count == 1


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
    middleware = create_caching_middleware(config)
    assert isinstance(middleware, ReadOnlyCachingMiddleware)
    assert isinstance(middleware, ResponseCachingMiddleware)


async def test_caching_bypassed_for_unsafe_tools(config):
    middleware = create_caching_middleware(config, _annotated(ISSUING))
    call_next = AsyncMock(side_effect=[_result("key-1"), _result("key-2")])
    first = await middleware.on_call_tool(_context("create_csr"), call_next)
    second = await middleware.on_call_tool(_context("create_csr"), call_next)
    assert [first.content[0].text, second.content[0].text] == ["key-1", "key-2"]


# ---------------------------------------------------------------------------
# Annotation gates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("annotations", "cacheable", "retry_safe"),
    [
        (READ_ONLY, True, True),
        (mt.ToolAnnotations(read_only_hint=True, idempotent_hint=False), False, True),
        (IDEMPOTENT_WRITE, False, True),
        (ISSUING, False, False),
        (mt.ToolAnnotations(), False, False),
        (None, False, False),
    ],
)
def test_annotation_gates(annotations, cacheable, retry_safe):
    assert is_cacheable(annotations) is cacheable
    assert is_retry_safe(annotations) is retry_safe


async def test_annotation_lookup_without_server_context():
    assert await build_annotation_lookup()(_context()) is None


async def test_annotation_lookup_memoises_known_tools():
    server = FastMCP("test")

    @server.tool(annotations=READ_ONLY)
    def echo(text: str) -> str:
        return text

    lookup = build_annotation_lookup()
    seen = []
    resolved = []

    class Probe(Middleware):
        async def on_call_tool(self, context, call_next):
            with patch.object(FastMCP, "get_tool", wraps=server.get_tool) as get_tool:
                seen.append(await lookup(context))
            resolved.append(get_tool.await_count)
            return await call_next(context)

    server.add_middleware(Probe())
    async with Client(server) as client:
        await client.call_tool("echo", {"text": "a"})
        await client.call_tool("echo", {"text": "b"})
    assert [a.read_only_hint for a in seen] == [True, True]
    assert resolved == [1, 0]


async def test_annotation_lookup_unknown_tool():
    server = FastMCP("test")
    lookup = build_annotation_lookup()
    seen = []

    class Probe(Middleware):
        async def on_call_tool(self, context, call_next):
            seen.append(await lookup(context))
            return await call_next(context)

    server.add_middleware(Probe())
    async with Client(server) as client:
        with pytest.raises(ToolError):
            await client.call_tool("missing", {})
    assert seen == [None]


def test_build_middleware_without_cache(config):
    chain = build_middleware(config)
    assert len(chain) == 1
    assert isinstance(chain[0], ResilienceMiddleware)


def test_build_middleware_with_cache(config):
    chain = build_middleware(replace(config, cache_enabled=True))
    assert [type(m) for m in chain] == [ReadOnlyCachingMiddleware, ResilienceMiddleware]


# ---------------------------------------------------------------------------
# End to end through a FastMCP server
# ---------------------------------------------------------------------------


async def test_middleware_in_fastmcp_server(config):
    server = FastMCP("test")
    calls = 0

    @server.tool(annotations=READ_ONLY)
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


async def test_cache_replays_only_read_only_tools_end_to_end(config):
    server = FastMCP("test")
    counts = {"lookup": 0, "issue": 0}

    @server.tool(annotations=READ_ONLY)
    def lookup(host: str) -> str:
        counts["lookup"] += 1
        return f"{host}-{counts['lookup']}"

    @server.tool(annotations=ISSUING)
    def issue(cn: str) -> str:
        counts["issue"] += 1
        return f"{cn}-{counts['issue']}"

    for middleware in build_middleware(replace(config, cache_enabled=True)):
        server.add_middleware(middleware)

    async with Client(server) as client:
        looked = [(await client.call_tool("lookup", {"host": "h"})).data for _ in range(2)]
        issued = [(await client.call_tool("issue", {"cn": "c"})).data for _ in range(2)]
    assert looked == ["h-1", "h-1"]
    assert issued == ["c-1", "c-2"]
