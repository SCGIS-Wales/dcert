"""FastMCP middleware applying the resilience settings to the proxy.

FastMCP dispatches ``tools/call`` to ``Middleware.on_call_tool`` on an
instance, so a minimal subclass is unavoidable; all behaviour lives in the
closure built by :func:`build_call_tool_handler` around the shared
:func:`dcert.resilience.build_guard`.

Caching and retry are gated on each tool's MCP annotations, read from the
backend at runtime: a tool that creates keys, issues certificates or changes
Vault state must neither be answered from a cache nor re-run after a failure
whose outcome is unknown.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import mcp_types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.server.middleware.caching import (
    CallToolSettings,
    ListToolsSettings,
    ResponseCachingMiddleware,
)
from fastmcp.tools.base import ToolResult

from dcert.resilience import (
    CircuitBreakerOpen,
    ResilienceConfig,
    build_guard,
    is_cacheable,
    is_retry_safe,
    truncate_response,
)

__all__ = [
    "AnnotationLookup",
    "CallToolHandler",
    "ReadOnlyCachingMiddleware",
    "ResilienceMiddleware",
    "build_annotation_lookup",
    "build_call_tool_handler",
    "build_middleware",
    "create_caching_middleware",
    "create_resilience_middleware",
    "is_cacheable",
    "is_retry_safe",
    "truncate_tool_result",
]

CallToolContext = MiddlewareContext[mt.CallToolRequestParams]
CallToolNext = CallNext[mt.CallToolRequestParams, ToolResult]
CallToolHandler = Callable[[CallToolContext, CallToolNext], Awaitable[ToolResult]]
AnnotationLookup = Callable[[CallToolContext], Awaitable[mt.ToolAnnotations | None]]
Sleep = Callable[[float], Awaitable[None]]


def build_annotation_lookup(timeout: float | None = None) -> AnnotationLookup:
    """Return a lookup of the called tool's annotations, memoised per tool name.

    Tools come from the backend binary, which does not change while the proxy
    runs, so each name is resolved once. Unknown tools are not memoised. The
    lookup reaches the backend, so it is bounded by *timeout* seconds
    (unbounded when ``None``) and raises :class:`ToolError` when exceeded.
    """
    known: dict[str, mt.ToolAnnotations | None] = {}

    async def lookup(context: CallToolContext) -> mt.ToolAnnotations | None:
        name = context.message.name
        if name in known:
            return known[name]
        if context.fastmcp_context is None:
            return None
        try:
            async with asyncio.timeout(timeout):
                tool = await context.fastmcp_context.fastmcp.get_tool(name)
        except TimeoutError:
            raise ToolError(f"Looking up {name} timed out after {timeout}s") from None
        if tool is None:
            return None
        known[name] = tool.annotations
        return tool.annotations

    return lookup


def truncate_tool_result(result: ToolResult, max_bytes: int) -> ToolResult:
    """Return *result* with each text block truncated to *max_bytes*."""
    if max_bytes <= 0:
        return result
    content = [
        block.model_copy(update={"text": truncate_response(block.text, max_bytes)})
        if isinstance(block, mt.TextContent)
        else block
        for block in result.content
    ]
    return result.model_copy(update={"content": content})


def build_call_tool_handler(
    config: ResilienceConfig,
    annotations: AnnotationLookup | None = None,
    sleep: Sleep | None = None,
) -> CallToolHandler:
    """Build the ``tools/call`` handler implementing the resilience stack.

    Layers, outermost first: bulkhead, rate limiter, circuit breaker, retry
    with backoff, per call timeout, response truncation. Retries apply only to
    tools whose annotations make them safe to re-run (see :func:`is_retry_safe`).
    *sleep* replaces :func:`asyncio.sleep` for backoff, mainly for tests.
    """
    lookup = annotations or build_annotation_lookup(config.connect_timeout)
    guard = build_guard(config, sleep=sleep)

    async def handle(context: CallToolContext, call_next: CallToolNext) -> ToolResult:
        tool = context.message.name
        retry = is_retry_safe(await lookup(context))

        async def attempt(_attempt: int) -> ToolResult:
            return await call_next(context)

        try:
            result = await guard.run(attempt, name=tool, timeout=config.tool_timeout, retry=retry)
        except CircuitBreakerOpen as exc:
            raise ToolError(str(exc)) from None
        except TimeoutError:
            raise ToolError(f"{tool} timed out after {config.tool_timeout}s") from None
        return truncate_tool_result(result, config.max_response_bytes)

    return handle


class ResilienceMiddleware(Middleware):
    """Thin adapter that routes ``tools/call`` to a handler closure."""

    def __init__(self, handler: CallToolHandler) -> None:
        self._handler = handler

    async def on_call_tool(self, context: CallToolContext, call_next: CallToolNext) -> ToolResult:
        return await self._handler(context, call_next)


def create_resilience_middleware(
    config: ResilienceConfig, annotations: AnnotationLookup | None = None
) -> Middleware:
    """Return the middleware applying *config* to every tool call."""
    return ResilienceMiddleware(build_call_tool_handler(config, annotations))


class ReadOnlyCachingMiddleware(ResponseCachingMiddleware):
    """FastMCP's response cache, bypassed for tools that are not safe to replay.

    Replaying a cached ``create_csr`` or ``vault_issue`` result would hand two
    callers the same private key or certificate, so only tools annotated as
    read-only and idempotent are cached (see :func:`is_cacheable`).
    """

    def __init__(
        self,
        annotations: AnnotationLookup,
        call_tool_settings: CallToolSettings,
        list_tools_settings: ListToolsSettings,
    ) -> None:
        super().__init__(
            call_tool_settings=call_tool_settings, list_tools_settings=list_tools_settings
        )
        self._annotations = annotations

    async def on_call_tool(self, context: CallToolContext, call_next: CallToolNext) -> ToolResult:
        if not is_cacheable(await self._annotations(context)):
            return await call_next(context)
        return await super().on_call_tool(context, call_next)


def create_caching_middleware(
    config: ResilienceConfig, annotations: AnnotationLookup | None = None
) -> Middleware:
    """Return FastMCP's response cache configured from *config*."""
    return ReadOnlyCachingMiddleware(
        annotations or build_annotation_lookup(config.connect_timeout),
        call_tool_settings=CallToolSettings(ttl=config.cache_tool_ttl),
        list_tools_settings=ListToolsSettings(ttl=config.cache_list_ttl),
    )


def build_middleware(config: ResilienceConfig) -> list[Middleware]:
    """Return the middleware chain for *config*, outermost first."""
    annotations = build_annotation_lookup(config.connect_timeout)
    chain: list[Middleware] = []
    if config.cache_enabled:
        chain.append(create_caching_middleware(config, annotations))
    chain.append(create_resilience_middleware(config, annotations))
    return chain
