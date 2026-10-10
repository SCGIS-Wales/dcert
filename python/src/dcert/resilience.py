"""Resilience primitives for the dcert MCP Python wrapper.

Everything here is a plain function or an immutable record of closures:

- :func:`create_circuit_breaker` builds a three state breaker whose half
  open state admits exactly one probe.
- :func:`create_rate_limiter` builds a token bucket limiter that sleeps for
  the exact time until a token is available instead of polling.
- :func:`backoff_delays` yields exponential delays with full jitter.
- :func:`run_with_retry` drives an operation through those delays.
- :func:`build_guard` stacks bulkhead, rate limiter, circuit breaker, retry
  and per call timeout into one closure shared by the proxy middleware and
  the typed client.
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
``DCERT_MCP_CONNECT_TIMEOUT``   subprocess start and lookup timeout (seconds)
``DCERT_MCP_RECONNECT_MAX``     reconnect attempts per call
``DCERT_MCP_OTEL_ENABLED``      enable OpenTelemetry tracing
``DCERT_MCP_OTEL_SERVICE_NAME`` service name for traces
``DCERT_MCP_OTEL_EXPORTER``     ``console`` or ``otlp``
=============================== =================================

A value outside its valid range raises :class:`ValueError` naming the
variable when the configuration is built.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from collections.abc import Awaitable, Callable, Iterator, Sequence
from dataclasses import dataclass, fields
from typing import Literal, Protocol, TypeVar

import anyio
from mcp import MCPError
from mcp_types import CONNECTION_CLOSED, ToolAnnotations

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
    """Raised by a guard when a call is rejected because the breaker is open."""


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

#: Environment variable, lower bound and whether the bound itself is allowed,
#: for every numeric field of :class:`ResilienceConfig`.
_LIMITS: dict[str, tuple[str, float, bool]] = {
    "retry_max_attempts": ("DCERT_MCP_RETRY_MAX_ATTEMPTS", 1, True),
    "retry_base_delay": ("DCERT_MCP_RETRY_BASE_DELAY", 0, True),
    "retry_max_delay": ("DCERT_MCP_RETRY_MAX_DELAY", 0, True),
    "retry_multiplier": ("DCERT_MCP_RETRY_MULTIPLIER", 0, False),
    "circuit_breaker_threshold": ("DCERT_MCP_CB_THRESHOLD", 1, True),
    "circuit_breaker_reset_timeout": ("DCERT_MCP_CB_RESET_TIMEOUT", 0, True),
    "bulkhead_max": ("DCERT_MCP_BULKHEAD_MAX", 1, True),
    "rate_limit_rps": ("DCERT_MCP_RATE_LIMIT_RPS", 0, False),
    "rate_limit_burst": ("DCERT_MCP_RATE_LIMIT_BURST", 1, True),
    "cache_tool_ttl": ("DCERT_MCP_CACHE_TOOL_TTL", 0, True),
    "cache_list_ttl": ("DCERT_MCP_CACHE_LIST_TTL", 0, True),
    "max_response_bytes": ("DCERT_MCP_MAX_RESPONSE_BYTES", 0, True),
    "tool_timeout": ("DCERT_MCP_TOOL_TIMEOUT", 0, False),
    "connect_timeout": ("DCERT_MCP_CONNECT_TIMEOUT", 0, False),
    "reconnect_max": ("DCERT_MCP_RECONNECT_MAX", 0, True),
    "truncation_lookback_chars": ("truncation_lookback_chars", 0, True),
}


@dataclass(frozen=True)
class ResilienceConfig:
    """Every resilience knob, resolved from the config file and environment.

    Raises:
        ValueError: On construction (including :func:`dataclasses.replace`)
            when a value is outside its valid range; the message names the
            environment variable that sets it.
    """

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
    connect_timeout: float
    reconnect_max: int
    truncation_lookback_chars: int

    def __post_init__(self) -> None:
        for field in fields(self):
            if field.name not in _LIMITS:
                continue
            variable, bound, inclusive = _LIMITS[field.name]
            value = getattr(self, field.name)
            if value < bound or (not inclusive and value == bound):
                relation = "at least" if inclusive else "greater than"
                raise ValueError(f"{variable} must be {relation} {bound}, got {value}")


def resilience_config_from_env(defaults: ResilienceDefaults | None = None) -> ResilienceConfig:
    """Build a :class:`ResilienceConfig` from *defaults* and ``DCERT_MCP_*`` variables.

    Raises:
        ValueError: If a variable sets a value outside its valid range.
    """
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
        connect_timeout=env_float("DCERT_MCP_CONNECT_TIMEOUT", base.connect_timeout),
        reconnect_max=env_int("DCERT_MCP_RECONNECT_MAX", base.reconnect_max),
        truncation_lookback_chars=base.truncation_lookback_chars,
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
# Tool annotation gates
# ---------------------------------------------------------------------------


def is_cacheable(annotations: ToolAnnotations | None) -> bool:
    """Whether a result may be replayed: only read-only, idempotent tools."""
    return (
        annotations is not None
        and annotations.read_only_hint is True
        and annotations.idempotent_hint is True
    )


def is_retry_safe(annotations: ToolAnnotations | None) -> bool:
    """Whether a failed call may be re-run: read-only or idempotent tools."""
    return annotations is not None and (
        annotations.read_only_hint is True or annotations.idempotent_hint is True
    )


# ---------------------------------------------------------------------------
# Response payload management
# ---------------------------------------------------------------------------


def truncate_response(text: str, max_bytes: int | None = None, lookback: int | None = None) -> str:
    """Truncate *text* when its UTF-8 encoding exceeds *max_bytes*.

    The cut is moved back to the last newline within *lookback* characters so
    output is not broken mid line, and a notice explains what was removed.
    ``0`` disables truncation; ``None`` uses the configured defaults.
    """
    defaults = load_config().resilience
    limit = defaults.max_response_bytes if max_bytes is None else max_bytes
    window = defaults.truncation_lookback_chars if lookback is None else lookback
    encoded = text.encode("utf-8", errors="replace")
    if limit <= 0 or len(encoded) <= limit:
        return text
    truncated = encoded[:limit].decode("utf-8", errors="ignore")
    last_newline = truncated.rfind("\n", max(0, len(truncated) - window))
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
    """Return ``True`` when *exc* or an explicit cause of it is a transport failure.

    Only the ``raise ... from`` chain (``__cause__``) is followed. The implicit
    ``__context__`` is whatever happened to be in flight when *exc* was raised,
    for example a transport error inside an ``except`` block that then raised
    a ``ValueError``, and following it would retry calls that did not fail
    because of the transport.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, CONNECTION_ERRORS):
            return True
        if isinstance(current, MCPError) and current.code == CONNECTION_CLOSED:
            return True
        current = current.__cause__
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
# Guard: the whole stack as one closure
# ---------------------------------------------------------------------------

#: Awaited with the exception and the zero based attempt number for every
#: retryable failure and for a timeout; returns whether the circuit breaker
#: should count the failure.
FailureHook = Callable[[BaseException, int], Awaitable[bool]]


class GuardedCall(Protocol):
    """Signature of :attr:`Guard.run`."""

    def __call__(
        self,
        operation: Callable[[int], Awaitable[T]],
        *,
        name: str,
        timeout: float,
        retry: bool = True,
        on_failure: FailureHook | None = None,
    ) -> Awaitable[T]: ...


@dataclass(frozen=True)
class Guard:
    """Handle returned by :func:`build_guard`."""

    run: GuardedCall
    breaker: CircuitBreaker | None
    limiter: RateLimiter | None


def build_guard(
    config: ResilienceConfig,
    *,
    retries: int | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> Guard:
    """Build the guard applying *config* to every call passed to ``run``.

    Layers, outermost first: bulkhead, rate limiter, circuit breaker, retry
    with backoff, per call timeout. ``run(operation, name=..., timeout=...)``
    awaits *operation* with the zero based attempt number and returns its
    result, or raises:

    - :class:`CircuitBreakerOpen` when the breaker rejects the call;
    - :class:`TimeoutError` when an attempt exceeds *timeout* seconds (the
      breaker counts it);
    - the operation's own exception otherwise. Transport failures (see
      :func:`is_connection_error`) are retried while ``retry`` is true and
      delays remain; nothing else is retried.

    *retries* is the number of retries after the first attempt and defaults
    to ``retry_max_attempts - 1``; ``retry_enabled`` turns retries off
    either way. *sleep* replaces :func:`asyncio.sleep` for backoff and rate
    limiting, mainly for tests.

    ``on_failure`` of ``run`` is awaited for every counted failure and
    decides whether the breaker records it, so a caller that tears down a
    shared transport can count one loss once rather than once per in flight
    call. Without it every failure is recorded.
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
        create_rate_limiter(config.rate_limit_rps, config.rate_limit_burst, sleep=sleep)
        if config.rate_limit_enabled
        else None
    )
    count = max(0, config.retry_max_attempts - 1) if retries is None else retries
    delays = list(
        backoff_delays(
            count if config.retry_enabled else 0,
            config.retry_base_delay,
            config.retry_max_delay,
            config.retry_multiplier,
        )
    )

    async def record(exc: BaseException, attempt: int, hook: FailureHook | None) -> None:
        counts = True if hook is None else await hook(exc, attempt)
        if counts and breaker is not None:
            await breaker.record_failure()

    async def run(
        operation: Callable[[int], Awaitable[T]],
        *,
        name: str,
        timeout: float,
        retry: bool = True,
        on_failure: FailureHook | None = None,
    ) -> T:
        attempts = 0

        async def attempt(number: int) -> T:
            nonlocal attempts
            attempts = number
            async with asyncio.timeout(timeout):
                return await operation(number)

        async def failed(exc: BaseException, number: int) -> None:
            await record(exc, number, on_failure)

        async with semaphore:
            if limiter is not None:
                await limiter.acquire()
            if breaker is not None and not await breaker.allow():
                raise CircuitBreakerOpen(
                    f"Circuit breaker is open; {name} rejected. "
                    "The backend has failed repeatedly and will be probed again shortly."
                )
            try:
                result = await run_with_retry(
                    attempt,
                    delays=delays if retry else [],
                    is_retryable=is_connection_error,
                    on_failure=failed,
                    sleep=sleep,
                )
            except TimeoutError as exc:
                await record(exc, attempts, on_failure)
                raise
            if breaker is not None:
                await breaker.record_success()
            return result

    return Guard(run=run, breaker=breaker, limiter=limiter)


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
        from opentelemetry.sdk.trace import SpanProcessor, TracerProvider

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
