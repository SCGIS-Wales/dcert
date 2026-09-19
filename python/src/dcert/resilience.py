"""Resilience primitives for the dcert MCP Python wrapper.

Everything here is a plain function or an immutable record of closures:

- :func:`create_circuit_breaker` builds a three state breaker whose half
  open state admits exactly one probe.
- :func:`create_rate_limiter` builds a token bucket limiter that sleeps for
  the exact time until a token is available instead of polling.
- :func:`backoff_delays` yields exponential delays with full jitter.
- :func:`run_with_retry` drives an operation through those delays.
- :func:`truncate_response` caps large text payloads.

Baseline values come from ``config.yaml``; each can be overridden with an
environment variable:

=============================== =================================
Variable                        Effect
=============================== =================================
``DCERT_MCP_NO_RETRY``          disable retries
``DCERT_MCP_RETRY_MAX_ATTEMPTS`` total attempts per call
``DCERT_MCP_RETRY_BASE_DELAY``  first backoff delay (seconds)
``DCERT_MCP_RETRY_MAX_DELAY``   largest backoff delay (seconds)
``DCERT_MCP_RETRY_MULTIPLIER``  growth factor between delays
``DCERT_MCP_NO_CIRCUIT_BREAKER`` disable the circuit breaker
``DCERT_MCP_CB_THRESHOLD``      failures before the breaker opens
``DCERT_MCP_CB_RESET_TIMEOUT``  seconds before a probe is allowed
``DCERT_MCP_BULKHEAD_MAX``      maximum concurrent tool calls
``DCERT_MCP_RATE_LIMIT_ENABLED`` enable rate limiting
``DCERT_MCP_RATE_LIMIT_RPS``    sustained requests per second
``DCERT_MCP_RATE_LIMIT_BURST``  burst capacity
``DCERT_MCP_CACHE_ENABLED``     enable response caching
``DCERT_MCP_CACHE_TOOL_TTL``    tool result cache TTL (seconds)
``DCERT_MCP_CACHE_LIST_TTL``    listing cache TTL (seconds)
``DCERT_MCP_MAX_RESPONSE_BYTES`` truncation limit, 0 disables
``DCERT_MCP_TOOL_TIMEOUT``      per call timeout (seconds)
``DCERT_MCP_RECONNECT_MAX``     reconnect attempts per call
``DCERT_MCP_OTEL_ENABLED``      enable OpenTelemetry tracing
``DCERT_MCP_OTEL_SERVICE_NAME`` service name for traces
``DCERT_MCP_OTEL_EXPORTER``     ``console`` or ``otlp``
=============================== =================================
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from collections.abc import Awaitable, Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Literal, TypeVar

import anyio
from mcp import MCPError
from mcp_types import CONNECTION_CLOSED

from dcert.config import OTelDefaults, ResilienceDefaults, load_config

logger = logging.getLogger(__name__)

T = TypeVar("T")

BreakerState = Literal["closed", "open", "half_open"]

#: Exceptions that indicate the subprocess or its transport went away.
CONNECTION_ERRORS: tuple[type[BaseException], ...] = (
    ConnectionError,
    EOFError,
    anyio.ClosedResourceError,
    anyio.BrokenResourceError,
    anyio.EndOfStream,
)


class CircuitBreakerOpen(Exception):
    """Raised when a call is rejected because the circuit breaker is open."""


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


def env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean from the environment, falling back to *default*."""
    value = os.environ.get(name, "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def env_int(name: str, default: int) -> int:
    """Read an integer from the environment, falling back to *default*."""
    value = os.environ.get(name)
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    """Read a float from the environment, falling back to *default*."""
    value = os.environ.get(name)
    try:
        return float(value) if value is not None else default
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Configuration records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResilienceConfig:
    """Every resilience knob, resolved from the config file and environment."""

    retry_enabled: bool
    retry_max_attempts: int
    retry_base_delay: float
    retry_max_delay: float
    retry_multiplier: float
    circuit_breaker_enabled: bool
    circuit_breaker_threshold: int
    circuit_breaker_reset_timeout: float
    bulkhead_max: int
    rate_limit_enabled: bool
    rate_limit_rps: float
    rate_limit_burst: int
    cache_enabled: bool
    cache_tool_ttl: int
    cache_list_ttl: int
    max_response_bytes: int
    tool_timeout: float
    reconnect_max: int


def resilience_config_from_env(defaults: ResilienceDefaults | None = None) -> ResilienceConfig:
    """Build a :class:`ResilienceConfig` from *defaults* and ``DCERT_MCP_*`` variables."""
    base = defaults or load_config().resilience
    return ResilienceConfig(
        retry_enabled=not env_bool("DCERT_MCP_NO_RETRY"),
        retry_max_attempts=env_int("DCERT_MCP_RETRY_MAX_ATTEMPTS", base.retry_max_attempts),
        retry_base_delay=env_float("DCERT_MCP_RETRY_BASE_DELAY", base.retry_base_delay),
        retry_max_delay=env_float("DCERT_MCP_RETRY_MAX_DELAY", base.retry_max_delay),
        retry_multiplier=env_float("DCERT_MCP_RETRY_MULTIPLIER", base.retry_multiplier),
        circuit_breaker_enabled=not env_bool("DCERT_MCP_NO_CIRCUIT_BREAKER"),
        circuit_breaker_threshold=env_int("DCERT_MCP_CB_THRESHOLD", base.circuit_breaker_threshold),
        circuit_breaker_reset_timeout=env_float(
            "DCERT_MCP_CB_RESET_TIMEOUT", base.circuit_breaker_reset_timeout
        ),
        bulkhead_max=env_int("DCERT_MCP_BULKHEAD_MAX", base.bulkhead_max),
        rate_limit_enabled=env_bool("DCERT_MCP_RATE_LIMIT_ENABLED"),
        rate_limit_rps=env_float("DCERT_MCP_RATE_LIMIT_RPS", base.rate_limit_rps),
        rate_limit_burst=env_int("DCERT_MCP_RATE_LIMIT_BURST", base.rate_limit_burst),
        cache_enabled=env_bool("DCERT_MCP_CACHE_ENABLED"),
        cache_tool_ttl=env_int("DCERT_MCP_CACHE_TOOL_TTL", base.cache_tool_ttl),
        cache_list_ttl=env_int("DCERT_MCP_CACHE_LIST_TTL", base.cache_list_ttl),
        max_response_bytes=env_int("DCERT_MCP_MAX_RESPONSE_BYTES", base.max_response_bytes),
        tool_timeout=env_float("DCERT_MCP_TOOL_TIMEOUT", base.tool_timeout),
        reconnect_max=env_int("DCERT_MCP_RECONNECT_MAX", base.reconnect_max),
    )


@dataclass(frozen=True)
class OTelConfig:
    """OpenTelemetry settings."""

    enabled: bool
    service_name: str
    exporter: str


def otel_config_from_env(defaults: OTelDefaults | None = None) -> OTelConfig:
    """Build an :class:`OTelConfig` from *defaults* and ``DCERT_MCP_OTEL_*`` variables."""
    base = defaults or load_config().otel
    return OTelConfig(
        enabled=env_bool("DCERT_MCP_OTEL_ENABLED"),
        service_name=os.environ.get("DCERT_MCP_OTEL_SERVICE_NAME", base.service_name),
        exporter=os.environ.get("DCERT_MCP_OTEL_EXPORTER", base.exporter),
    )


# ---------------------------------------------------------------------------
# Response payload management
# ---------------------------------------------------------------------------


def truncate_response(text: str, max_bytes: int | None = None) -> str:
    """Truncate *text* when its UTF-8 encoding exceeds *max_bytes*.

    The cut is moved back to the last newline within 200 characters so
    output is not broken mid line, and a notice explains what was removed.
    ``0`` disables truncation; ``None`` uses the configured default.
    """
    limit = load_config().resilience.max_response_bytes if max_bytes is None else max_bytes
    encoded = text.encode("utf-8", errors="replace")
    if limit <= 0 or len(encoded) <= limit:
        return text
    truncated = encoded[:limit].decode("utf-8", errors="ignore")
    last_newline = truncated.rfind("\n", max(0, len(truncated) - 200))
    if last_newline > 0:
        truncated = truncated[:last_newline]
    shown = len(truncated.encode("utf-8", errors="replace"))
    return (
        f"{truncated}\n\n[Truncated: response was {len(encoded):,} bytes, "
        f"showing first {shown:,} bytes. "
        "Use more specific queries or filters to reduce output size.]"
    )


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CircuitBreaker:
    """Handle returned by :func:`create_circuit_breaker`."""

    allow: Callable[[], Awaitable[bool]]
    record_success: Callable[[], Awaitable[None]]
    record_failure: Callable[[], Awaitable[None]]
    state: Callable[[], BreakerState]


def create_circuit_breaker(
    threshold: int,
    reset_timeout: float,
    clock: Callable[[], float] = time.monotonic,
) -> CircuitBreaker:
    """Create a three state circuit breaker.

    The breaker opens after *threshold* consecutive failures. Once
    *reset_timeout* seconds have passed it becomes half open and admits a
    single probe; every other caller is rejected until that probe reports.
    A successful probe closes the breaker, a failed one reopens it. A probe
    that never reports (for example, because it was cancelled) is replaced
    after another *reset_timeout* seconds.

    Raises:
        ValueError: If *threshold* is below 1 or *reset_timeout* is negative.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if reset_timeout < 0:
        raise ValueError("reset_timeout must not be negative")

    state: BreakerState = "closed"
    failures = 0
    opened_at = 0.0
    probe_started: float | None = None
    lock = asyncio.Lock()

    async def allow() -> bool:
        nonlocal state, probe_started
        async with lock:
            if state == "closed":
                return True
            now = clock()
            if state == "open":
                if now - opened_at < reset_timeout:
                    return False
                state = "half_open"
                probe_started = now
                logger.info("Circuit breaker half open, admitting one probe")
                return True
            if probe_started is not None and now - probe_started < reset_timeout:
                return False
            probe_started = now
            return True

    async def record_success() -> None:
        nonlocal state, failures, probe_started
        async with lock:
            failures = 0
            probe_started = None
            if state != "closed":
                logger.info("Circuit breaker closed after a successful call")
                state = "closed"

    async def record_failure() -> None:
        nonlocal state, failures, opened_at, probe_started
        async with lock:
            failures += 1
            opened_at = clock()
            probe_started = None
            if state == "half_open":
                state = "open"
                logger.warning("Circuit breaker reopened: half open probe failed")
            elif state == "closed" and failures >= threshold:
                state = "open"
                logger.warning("Circuit breaker opened after %d failures", failures)

    return CircuitBreaker(
        allow=allow,
        record_success=record_success,
        record_failure=record_failure,
        state=lambda: state,
    )


# ---------------------------------------------------------------------------
# Token bucket rate limiter
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RateLimiter:
    """Handle returned by :func:`create_rate_limiter`."""

    acquire: Callable[[], Awaitable[None]]
    tokens: Callable[[], float]


def create_rate_limiter(
    rps: float,
    burst: int,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> RateLimiter:
    """Create a token bucket limiter allowing *rps* sustained calls per second.

    Each caller reserves a token under the lock and then sleeps for exactly
    the time until its reservation is funded, so there is no polling.

    Raises:
        ValueError: If *rps* is not positive or *burst* is below 1.
    """
    if rps <= 0:
        raise ValueError("rps must be positive")
    if burst < 1:
        raise ValueError("burst must be at least 1")

    tokens = float(burst)
    last_refill = clock()
    lock = asyncio.Lock()

    async def acquire() -> None:
        nonlocal tokens, last_refill
        async with lock:
            now = clock()
            tokens = min(float(burst), tokens + (now - last_refill) * rps)
            last_refill = now
            tokens -= 1.0
            wait = -tokens / rps if tokens < 0 else 0.0
        if wait > 0:
            await (sleep or asyncio.sleep)(wait)

    return RateLimiter(acquire=acquire, tokens=lambda: tokens)


# ---------------------------------------------------------------------------
# Retry with exponential backoff
# ---------------------------------------------------------------------------


def backoff_delays(
    attempts: int,
    base: float,
    max_delay: float,
    multiplier: float,
    jitter: bool = True,
) -> Iterator[float]:
    """Yield *attempts* exponential backoff delays with full jitter.

    Delay ``i`` is drawn uniformly from ``[0, min(max_delay, base * multiplier ** i)]``
    when *jitter* is enabled, otherwise it is the upper bound itself.

    Raises:
        ValueError: If any argument is negative or *multiplier* is not positive.
    """
    if attempts < 0 or base < 0 or max_delay < 0:
        raise ValueError("attempts, base and max_delay must not be negative")
    if multiplier <= 0:
        raise ValueError("multiplier must be positive")
    for attempt in range(attempts):
        ceiling = min(max_delay, base * multiplier**attempt)
        # Jitter spreads retries; it is not used for anything security related.
        yield random.uniform(0.0, ceiling) if jitter else ceiling  # noqa: S311


def is_connection_error(exc: BaseException) -> bool:
    """Return ``True`` when *exc* (or its cause chain) is a transport failure."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, CONNECTION_ERRORS):
            return True
        if isinstance(current, MCPError) and current.code == CONNECTION_CLOSED:
            return True
        current = current.__cause__ or current.__context__
    return False


async def run_with_retry(
    operation: Callable[[int], Awaitable[T]],
    *,
    delays: Sequence[float],
    is_retryable: Callable[[BaseException], bool],
    on_failure: Callable[[BaseException, int], Awaitable[None]] | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> T:
    """Run *operation* until it succeeds or the retries are exhausted.

    *operation* receives the zero based attempt number. Only exceptions for
    which *is_retryable* returns ``True`` are retried, each retry sleeping
    for the next value in *delays*. ``asyncio.CancelledError`` is never
    caught. *on_failure* is awaited for every retryable failure, including
    the last one.
    """
    attempt = 0
    while True:
        try:
            return await operation(attempt)
        except Exception as exc:
            if not is_retryable(exc):
                raise
            if on_failure is not None:
                await on_failure(exc, attempt)
            if attempt >= len(delays):
                raise
            logger.warning("Attempt %d failed (%s); retrying", attempt + 1, exc)
            await (sleep or asyncio.sleep)(delays[attempt])
            attempt += 1


# ---------------------------------------------------------------------------
# OpenTelemetry
# ---------------------------------------------------------------------------


def setup_otel(config: OTelConfig) -> None:
    """Configure OpenTelemetry tracing when enabled and the SDK is installed.

    Install the optional dependency group with ``pip install dcert[otel]``.
    """
    if not config.enabled:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SpanProcessor

        processor: SpanProcessor
        if config.exporter == "otlp":
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            processor = BatchSpanProcessor(OTLPSpanExporter())
        else:
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

            processor = SimpleSpanProcessor(ConsoleSpanExporter())
    except ImportError:
        logger.warning("OpenTelemetry SDK not installed. Install with: pip install dcert[otel]")
        return
    provider = TracerProvider(resource=Resource.create({"service.name": config.service_name}))
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)
    logger.info(
        "OpenTelemetry enabled: service=%s exporter=%s", config.service_name, config.exporter
    )
