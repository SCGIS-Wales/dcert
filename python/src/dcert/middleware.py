"""FastMCP middleware applying the resilience settings to the proxy.

FastMCP dispatches ``tools/call`` to ``Middleware.on_call_tool`` on an
instance, so a minimal subclass is unavoidable; all behaviour lives in the
closure built by :func:`build_call_tool_handler`.
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
    ResilienceConfig,
    backoff_delays,
    create_circuit_breaker,
    create_rate_limiter,
    is_connection_error,
    run_with_retry,
    truncate_response,
)

CallToolContext = MiddlewareContext[mt.CallToolRequestParams]
CallToolNext = CallNext[mt.CallToolRequestParams, ToolResult]
CallToolHandler = Callable[[CallToolContext, CallToolNext], Awaitable[ToolResult]]


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


def build_call_tool_handler(config: ResilienceConfig) -> CallToolHandler:
    """Build the ``tools/call`` handler implementing the resilience stack.

    Layers, outermost first: bulkhead, rate limiter, circuit breaker, retry
    with backoff, per call timeout, response truncation.
    """
    semaphore = asyncio.Semaphore(config.bulkhead_max)
    breaker = (
        create_circuit_breaker(
            config.circuit_breaker_threshold, config.circuit_breaker_reset_timeout
        )
        if config.circuit_breaker_enabled
        else None
    )
    limiter = (
        create_rate_limiter(config.rate_limit_rps, config.rate_limit_burst)
        if config.rate_limit_enabled
        else None
    )
    retries = max(0, config.retry_max_attempts - 1) if config.retry_enabled else 0
    delays = list(
        backoff_delays(
            retries, config.retry_base_delay, config.retry_max_delay, config.retry_multiplier
        )
    )

    async def record_failure(_exc: BaseException, _attempt: int) -> None:
        if breaker is not None:
            await breaker.record_failure()

    async def handle(context: CallToolContext, call_next: CallToolNext) -> ToolResult:
        tool = context.message.name
        async with semaphore:
            if limiter is not None:
                await limiter.acquire()
            if breaker is not None and not await breaker.allow():
                raise ToolError(
                    f"Circuit breaker is open; {tool} rejected. "
                    "The backend has failed repeatedly and will be probed again shortly."
                )

            async def attempt(_attempt: int) -> ToolResult:
                async with asyncio.timeout(config.tool_timeout):
                    return await call_next(context)

            try:
                result = await run_with_retry(
                    attempt,
                    delays=delays,
                    is_retryable=is_connection_error,
                    on_failure=record_failure,
                )
            except TimeoutError:
                raise ToolError(f"{tool} timed out after {config.tool_timeout}s") from None
            if breaker is not None:
                await breaker.record_success()
            return truncate_tool_result(result, config.max_response_bytes)

    return handle


class ResilienceMiddleware(Middleware):
    """Thin adapter that routes ``tools/call`` to a handler closure."""

    def __init__(self, handler: CallToolHandler) -> None:
        self._handler = handler

    async def on_call_tool(self, context: CallToolContext, call_next: CallToolNext) -> ToolResult:
        return await self._handler(context, call_next)


def create_resilience_middleware(config: ResilienceConfig) -> Middleware:
    """Return the middleware applying *config* to every tool call."""
    return ResilienceMiddleware(build_call_tool_handler(config))


def create_caching_middleware(config: ResilienceConfig) -> Middleware:
    """Return FastMCP's response cache configured from *config*."""
    return ResponseCachingMiddleware(
        call_tool_settings=CallToolSettings(ttl=config.cache_tool_ttl),
        list_tools_settings=ListToolsSettings(ttl=config.cache_list_ttl),
    )


def build_middleware(config: ResilienceConfig) -> list[Middleware]:
    """Return the middleware chain for *config*, outermost first."""
    chain: list[Middleware] = []
    if config.cache_enabled:
        chain.append(create_caching_middleware(config))
    chain.append(create_resilience_middleware(config))
    return chain
