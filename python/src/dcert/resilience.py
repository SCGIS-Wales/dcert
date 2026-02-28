"""Resilience patterns for the dcert MCP Python proxy.

Provides production-grade resilience at two layers:

1. **Tool-level** (applied in ``DcertClient._call``):
   - Bulkhead: ``asyncio.Semaphore`` limiting concurrent tool calls.
   - Reconnection loop: auto-reconnects to the Rust subprocess on crash.
   - Circuit breaker: trips after repeated connection failures.
   - Retry with exponential backoff + jitter for transient errors.
   - Per-call timeout with a Python 3.10 compatibility shim.

2. **Proxy-level** (applied as FastMCP middleware via ``build_middleware``):
   - TimingMiddleware: measures total request time.
   - ErrorHandlingMiddleware: catches exceptions, returns structured errors.
   - RateLimitingMiddleware: token-bucket rate limiting (disabled by default).
   - RetryMiddleware: exponential backoff for connection errors.
   - ResponseCachingMiddleware: TTL-based caching (disabled by default).

All settings are configurable via ``DCERT_MCP_*`` environment variables,
CLI flags, or the ``ResilienceConfig`` / ``OTelConfig`` dataclasses.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Python 3.10 compatibility shim for asyncio.wait_for
# ---------------------------------------------------------------------------

_NEEDS_WAIT_FOR_COMPAT = sys.version_info < (3, 11)


async def _wait_for_compat(coro, timeout):
    """``asyncio.wait_for`` wrapper that works around a Python 3.10 bug.

    On Python <3.11, ``asyncio.wait_for`` can leak ``CancelledError``
    instead of raising ``TimeoutError``.  This shim catches the leak
    and re-raises as ``TimeoutError``.
    """
    if not _NEEDS_WAIT_FOR_COMPAT:
        return await asyncio.wait_for(coro, timeout=timeout)

    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.CancelledError:
        raise TimeoutError(
            f"Operation timed out after {timeout}s (Python {sys.version_info[:2]} compat)"
        ) from None


# ---------------------------------------------------------------------------
# Response Payload Management
# ---------------------------------------------------------------------------

#: Maximum response size in bytes before truncation (256 KB).
DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024


def truncate_response(text: str, max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES) -> str:
    """Truncate a response string if it exceeds *max_bytes*.

    Truncation happens at a newline boundary (looking back up to 200
    characters) so the output is not broken mid-line.  A notice is
    appended explaining how much was cut.

    Setting *max_bytes* to ``0`` disables truncation.
    """
    if max_bytes <= 0 or len(text.encode("utf-8", errors="replace")) <= max_bytes:
        return text

    # Encode to find exact byte boundary, then decode back
    encoded = text.encode("utf-8", errors="replace")[:max_bytes]
    truncated = encoded.decode("utf-8", errors="ignore")

    # Try to break at a newline within the last 200 chars
    last_nl = truncated.rfind("\n", max(0, len(truncated) - 200))
    if last_nl > 0:
        truncated = truncated[:last_nl]

    original_size = len(text.encode("utf-8", errors="replace"))
    shown_size = len(truncated.encode("utf-8", errors="replace"))
    notice = (
        f"\n\n[Truncated: response was {original_size:,} bytes, "
        f"showing first {shown_size:,} bytes. "
        f"Use more specific queries or filters to reduce output size.]"
    )
    return truncated + notice


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean from an environment variable."""
    val = os.environ.get(name, "").lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if val in ("0", "false", "no", "off"):
        return False
    return default


def _env_int(name: str, default: int) -> int:
    """Read an integer from an environment variable."""
    val = os.environ.get(name)
    if val is not None:
        try:
            return int(val)
        except ValueError:
            pass
    return default


def _env_float(name: str, default: float) -> float:
    """Read a float from an environment variable."""
    val = os.environ.get(name)
    if val is not None:
        try:
            return float(val)
        except ValueError:
            pass
    return default


@dataclass(frozen=True)
class ResilienceConfig:
    """All resilience knobs in one place.

    Defaults are read from ``DCERT_MCP_*`` environment variables so that
    they can be set in MCP server configuration without changing code.
    """

    # -- Retry --
    retry_enabled: bool = field(default_factory=lambda: not _env_bool("DCERT_MCP_NO_RETRY"))
    retry_max_attempts: int = field(
        default_factory=lambda: _env_int("DCERT_MCP_RETRY_MAX_ATTEMPTS", 3)
    )
    retry_base_delay: float = field(
        default_factory=lambda: _env_float("DCERT_MCP_RETRY_BASE_DELAY", 0.5)
    )
    retry_max_delay: float = field(
        default_factory=lambda: _env_float("DCERT_MCP_RETRY_MAX_DELAY", 10.0)
    )
    retry_multiplier: float = field(
        default_factory=lambda: _env_float("DCERT_MCP_RETRY_MULTIPLIER", 1.5)
    )

    # -- Circuit breaker --
    circuit_breaker_enabled: bool = field(
        default_factory=lambda: not _env_bool("DCERT_MCP_NO_CIRCUIT_BREAKER")
    )
    circuit_breaker_threshold: int = field(
        default_factory=lambda: _env_int("DCERT_MCP_CB_THRESHOLD", 5)
    )
    circuit_breaker_reset_timeout: int = field(
        default_factory=lambda: _env_int("DCERT_MCP_CB_RESET_TIMEOUT", 30)
    )

    # -- Bulkhead --
    bulkhead_max: int = field(default_factory=lambda: _env_int("DCERT_MCP_BULKHEAD_MAX", 10))

    # -- Rate limiting (disabled by default) --
    rate_limit_enabled: bool = field(
        default_factory=lambda: _env_bool("DCERT_MCP_RATE_LIMIT_ENABLED")
    )
    rate_limit_rps: float = field(
        default_factory=lambda: _env_float("DCERT_MCP_RATE_LIMIT_RPS", 10.0)
    )
    rate_limit_burst: int = field(
        default_factory=lambda: _env_int("DCERT_MCP_RATE_LIMIT_BURST", 20)
    )

    # -- Response caching (disabled by default) --
    cache_enabled: bool = field(default_factory=lambda: _env_bool("DCERT_MCP_CACHE_ENABLED"))
    cache_tool_ttl: int = field(default_factory=lambda: _env_int("DCERT_MCP_CACHE_TOOL_TTL", 300))
    cache_list_ttl: int = field(default_factory=lambda: _env_int("DCERT_MCP_CACHE_LIST_TTL", 60))

    # -- Response payload management --
    max_response_bytes: int = field(
        default_factory=lambda: _env_int("DCERT_MCP_MAX_RESPONSE_BYTES", DEFAULT_MAX_RESPONSE_BYTES)
    )

    # -- Timeout --
    tool_timeout: float = field(default_factory=lambda: _env_float("DCERT_MCP_TOOL_TIMEOUT", 300.0))
    reconnect_max: int = field(default_factory=lambda: _env_int("DCERT_MCP_RECONNECT_MAX", 3))


# ---------------------------------------------------------------------------
# Circuit breaker (pure-Python, no external dependency)
# ---------------------------------------------------------------------------


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is open."""


class CircuitBreaker:
    """Lightweight three-state circuit breaker.

    States: ``closed`` (normal) -> ``open`` (blocking) -> ``half_open`` (probe).
    """

    def __init__(self, threshold: int = 5, reset_timeout: float = 30.0) -> None:
        self._threshold = threshold
        self._reset_timeout = reset_timeout
        self._failure_count = 0
        self._state = "closed"
        self._last_failure_time: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._state

    async def allow(self) -> bool:
        """Check whether a request is allowed through."""
        async with self._lock:
            if self._state == "closed":
                return True
            if self._state == "open":
                if time.monotonic() - self._last_failure_time >= self._reset_timeout:
                    self._state = "half_open"
                    logger.info("Circuit breaker transitioning to half-open")
                    return True
                return False
            # half_open: allow one probe
            return True

    async def record_success(self) -> None:
        """Record a successful call."""
        async with self._lock:
            self._failure_count = 0
            if self._state != "closed":
                logger.info("Circuit breaker closed (success)")
                self._state = "closed"

    async def record_failure(self) -> None:
        """Record a failed call."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._state == "half_open":
                self._state = "open"
                logger.warning("Circuit breaker re-opened (half-open probe failed)")
            elif self._failure_count >= self._threshold:
                self._state = "open"
                logger.warning("Circuit breaker opened after %d failures", self._failure_count)


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Async token-bucket rate limiter."""

    def __init__(self, rps: float = 10.0, burst: int = 20) -> None:
        self._rps = rps
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available."""
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._burst, self._tokens + elapsed * self._rps)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            await asyncio.sleep(1.0 / self._rps)


# ---------------------------------------------------------------------------
# OpenTelemetry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OTelConfig:
    """OpenTelemetry configuration."""

    enabled: bool = field(default_factory=lambda: _env_bool("DCERT_MCP_OTEL_ENABLED"))
    service_name: str = field(
        default_factory=lambda: os.environ.get("DCERT_MCP_OTEL_SERVICE_NAME", "dcert-mcp")
    )
    exporter: str = field(
        default_factory=lambda: os.environ.get("DCERT_MCP_OTEL_EXPORTER", "console")
    )


def setup_otel(config: OTelConfig) -> None:
    """Best-effort OpenTelemetry setup.

    If the OpenTelemetry SDK is not installed this is a no-op.
    Install the optional dependency group::

        pip install dcert[otel]
    """
    if not config.enabled:
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider

        resource = Resource.create({"service.name": config.service_name})

        if config.exporter == "otlp":
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            exporter = OTLPSpanExporter()
            processor = BatchSpanProcessor(exporter)
        else:
            from opentelemetry.sdk.trace.export import (
                ConsoleSpanExporter,
                SimpleSpanProcessor,
            )

            exporter = ConsoleSpanExporter()
            processor = SimpleSpanProcessor(exporter)

        provider = TracerProvider(resource=resource)
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        logger.info(
            "OpenTelemetry enabled: service=%s exporter=%s",
            config.service_name,
            config.exporter,
        )
    except ImportError:
        logger.warning("OpenTelemetry SDK not installed. Install with: pip install dcert[otel]")
