"""Tests for dcert.resilience."""

from __future__ import annotations

import asyncio
import sys
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import anyio
import pytest
from mcp import MCPError
from mcp_types import CONNECTION_CLOSED, INVALID_PARAMS

from dcert.config import load_config
from dcert.resilience import (
    CircuitBreakerOpen,
    OTelConfig,
    ResilienceConfig,
    backoff_delays,
    create_circuit_breaker,
    create_rate_limiter,
    env_bool,
    env_float,
    env_int,
    is_connection_error,
    otel_config_from_env,
    resilience_config_from_env,
    run_with_retry,
    setup_otel,
    truncate_response,
)


@pytest.fixture
def clean_env(monkeypatch):
    for name in list(__import__("os").environ):
        if name.startswith("DCERT_MCP_"):
            monkeypatch.delenv(name)


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "True", "YES", " on "])
def test_env_bool_true(monkeypatch, value):
    monkeypatch.setenv("TEST_VAR", value)
    assert env_bool("TEST_VAR") is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "False", "NO"])
def test_env_bool_false(monkeypatch, value):
    monkeypatch.setenv("TEST_VAR", value)
    assert env_bool("TEST_VAR", default=True) is False


def test_env_bool_unset_or_garbage(monkeypatch):
    monkeypatch.delenv("TEST_UNSET", raising=False)
    assert env_bool("TEST_UNSET") is False
    assert env_bool("TEST_UNSET", default=True) is True
    monkeypatch.setenv("TEST_UNSET", "maybe")
    assert env_bool("TEST_UNSET", default=True) is True


def test_env_int(monkeypatch):
    monkeypatch.setenv("TEST_INT", "42")
    assert env_int("TEST_INT", 0) == 42
    monkeypatch.setenv("TEST_INT", "not-a-number")
    assert env_int("TEST_INT", 99) == 99
    monkeypatch.delenv("TEST_INT")
    assert env_int("TEST_INT", 7) == 7


def test_env_float(monkeypatch):
    monkeypatch.setenv("TEST_FLOAT", "3.14")
    assert env_float("TEST_FLOAT", 0.0) == pytest.approx(3.14)
    monkeypatch.setenv("TEST_FLOAT", "abc")
    assert env_float("TEST_FLOAT", 1.5) == pytest.approx(1.5)


# ---------------------------------------------------------------------------
# Configuration records
# ---------------------------------------------------------------------------


def test_resilience_config_defaults(clean_env):
    cfg = resilience_config_from_env()
    base = load_config().resilience
    assert cfg.retry_enabled is True
    assert cfg.retry_max_attempts == base.retry_max_attempts
    assert cfg.circuit_breaker_enabled is True
    assert cfg.circuit_breaker_threshold == base.circuit_breaker_threshold
    assert cfg.bulkhead_max == base.bulkhead_max
    assert cfg.rate_limit_enabled is False
    assert cfg.cache_enabled is False
    assert cfg.max_response_bytes == 256 * 1024
    assert cfg.tool_timeout == pytest.approx(300.0)
    assert cfg.reconnect_max == 3


def test_resilience_config_env_overrides(clean_env, monkeypatch):
    overrides = {
        "DCERT_MCP_NO_RETRY": "1",
        "DCERT_MCP_RETRY_MAX_ATTEMPTS": "5",
        "DCERT_MCP_RETRY_BASE_DELAY": "0.1",
        "DCERT_MCP_NO_CIRCUIT_BREAKER": "true",
        "DCERT_MCP_CB_RESET_TIMEOUT": "2.5",
        "DCERT_MCP_BULKHEAD_MAX": "20",
        "DCERT_MCP_RATE_LIMIT_ENABLED": "1",
        "DCERT_MCP_RATE_LIMIT_RPS": "50",
        "DCERT_MCP_CACHE_ENABLED": "1",
        "DCERT_MCP_MAX_RESPONSE_BYTES": "1024",
        "DCERT_MCP_TOOL_TIMEOUT": "12",
        "DCERT_MCP_RECONNECT_MAX": "0",
    }
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    cfg = resilience_config_from_env()
    assert cfg.retry_enabled is False
    assert cfg.retry_max_attempts == 5
    assert cfg.retry_base_delay == pytest.approx(0.1)
    assert cfg.circuit_breaker_enabled is False
    assert cfg.circuit_breaker_reset_timeout == pytest.approx(2.5)
    assert cfg.bulkhead_max == 20
    assert cfg.rate_limit_enabled is True
    assert cfg.rate_limit_rps == pytest.approx(50.0)
    assert cfg.cache_enabled is True
    assert cfg.max_response_bytes == 1024
    assert cfg.tool_timeout == pytest.approx(12.0)
    assert cfg.reconnect_max == 0


def test_resilience_config_is_frozen(clean_env):
    cfg = resilience_config_from_env()
    with pytest.raises(AttributeError, match="cannot assign"):
        cfg.bulkhead_max = 1  # type: ignore[misc]
    assert replace(cfg, bulkhead_max=1).bulkhead_max == 1
    assert isinstance(cfg, ResilienceConfig)


def test_otel_config_defaults(clean_env):
    cfg = otel_config_from_env()
    assert cfg == OTelConfig(enabled=False, service_name="dcert-mcp", exporter="console")


def test_otel_config_env_overrides(clean_env, monkeypatch):
    monkeypatch.setenv("DCERT_MCP_OTEL_ENABLED", "true")
    monkeypatch.setenv("DCERT_MCP_OTEL_SERVICE_NAME", "my-service")
    monkeypatch.setenv("DCERT_MCP_OTEL_EXPORTER", "otlp")
    assert otel_config_from_env() == OTelConfig(True, "my-service", "otlp")


# ---------------------------------------------------------------------------
# truncate_response
# ---------------------------------------------------------------------------


def test_short_response_unchanged():
    assert truncate_response("Hello, world!") == "Hello, world!"


def test_truncation_at_max_bytes():
    result = truncate_response("a" * 300_000, max_bytes=1024)
    assert len(result.encode("utf-8")) < 1500
    assert "[Truncated: response was 300,000 bytes" in result


def test_truncation_uses_config_default():
    text = "a" * (256 * 1024 + 1)
    assert "[Truncated:" in truncate_response(text)


def test_truncation_disabled_with_zero():
    text = "a" * 300_000
    assert truncate_response(text, max_bytes=0) == text


def test_truncation_at_newline_boundary():
    text = "\n".join(f"line {i}" for i in range(1000))
    result = truncate_response(text, max_bytes=200)
    body = result.split("\n\n[Truncated:")[0]
    assert not body.endswith("\n")
    assert all(line.startswith("line ") for line in body.split("\n"))


def test_exact_boundary():
    text = "x" * 100
    assert truncate_response(text, max_bytes=100) == text


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


async def test_breaker_initially_closed():
    cb = create_circuit_breaker(3, 1.0)
    assert cb.state() == "closed"
    assert await cb.allow() is True


async def test_breaker_trips_after_threshold():
    cb = create_circuit_breaker(3, 30.0)
    for _ in range(3):
        await cb.record_failure()
    assert cb.state() == "open"
    assert await cb.allow() is False


async def test_breaker_success_resets_count():
    cb = create_circuit_breaker(3, 30.0)
    await cb.record_failure()
    await cb.record_failure()
    await cb.record_success()
    await cb.record_failure()
    assert cb.state() == "closed"


async def test_breaker_half_open_admits_exactly_one_probe():
    clock = FakeClock()
    cb = create_circuit_breaker(1, 10.0, clock=clock)
    await cb.record_failure()
    assert await cb.allow() is False
    clock.now += 10.0
    assert await cb.allow() is True
    assert cb.state() == "half_open"
    assert await cb.allow() is False
    assert await cb.allow() is False


async def test_breaker_probe_success_closes():
    clock = FakeClock()
    cb = create_circuit_breaker(1, 10.0, clock=clock)
    await cb.record_failure()
    clock.now += 10.0
    assert await cb.allow() is True
    await cb.record_success()
    assert cb.state() == "closed"
    assert await cb.allow() is True
    assert await cb.allow() is True


async def test_breaker_probe_failure_reopens():
    clock = FakeClock()
    cb = create_circuit_breaker(1, 10.0, clock=clock)
    await cb.record_failure()
    clock.now += 10.0
    assert await cb.allow() is True
    await cb.record_failure()
    assert cb.state() == "open"
    assert await cb.allow() is False
    clock.now += 10.0
    assert await cb.allow() is True


async def test_breaker_stale_probe_is_replaced():
    clock = FakeClock()
    cb = create_circuit_breaker(1, 10.0, clock=clock)
    await cb.record_failure()
    clock.now += 10.0
    assert await cb.allow() is True
    clock.now += 10.0
    assert await cb.allow() is True


@pytest.mark.parametrize(("threshold", "reset"), [(0, 1.0), (-1, 1.0), (1, -0.1)])
def test_breaker_validation(threshold, reset):
    with pytest.raises(ValueError, match="threshold|reset_timeout"):
        create_circuit_breaker(threshold, reset)


def test_circuit_breaker_open_exception():
    assert issubclass(CircuitBreakerOpen, Exception)
    assert str(CircuitBreakerOpen("circuit is open")) == "circuit is open"


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


async def test_rate_limiter_within_burst_does_not_sleep():
    sleep = AsyncMock()
    rl = create_rate_limiter(100.0, 5, clock=FakeClock(), sleep=sleep)
    for _ in range(5):
        await rl.acquire()
    sleep.assert_not_awaited()
    assert rl.tokens() == pytest.approx(0.0)


async def test_rate_limiter_sleeps_exact_deficit():
    sleep = AsyncMock()
    clock = FakeClock()
    rl = create_rate_limiter(2.0, 1, clock=clock, sleep=sleep)
    await rl.acquire()
    await rl.acquire()
    sleep.assert_awaited_once_with(pytest.approx(0.5))
    await rl.acquire()
    assert sleep.await_args_list[-1].args[0] == pytest.approx(1.0)


async def test_rate_limiter_refills_with_time():
    sleep = AsyncMock()
    clock = FakeClock()
    rl = create_rate_limiter(10.0, 1, clock=clock, sleep=sleep)
    await rl.acquire()
    clock.now += 0.1
    await rl.acquire()
    sleep.assert_not_awaited()


async def test_rate_limiter_uses_asyncio_sleep_by_default():
    rl = create_rate_limiter(1000.0, 1)
    with patch("dcert.resilience.asyncio.sleep", new=AsyncMock()) as sleep:
        await rl.acquire()
        await rl.acquire()
    sleep.assert_awaited_once()


@pytest.mark.parametrize(("rps", "burst"), [(0, 1), (-1.0, 1), (1.0, 0)])
def test_rate_limiter_validation(rps, burst):
    with pytest.raises(ValueError, match="rps|burst"):
        create_rate_limiter(rps, burst)


# ---------------------------------------------------------------------------
# Backoff
# ---------------------------------------------------------------------------


def test_backoff_without_jitter():
    delays = list(backoff_delays(5, 0.5, 3.0, 2.0, jitter=False))
    assert delays == [0.5, 1.0, 2.0, 3.0, 3.0]


def test_backoff_with_full_jitter_is_bounded():
    for _ in range(20):
        delays = list(backoff_delays(4, 0.5, 3.0, 2.0))
        assert len(delays) == 4
        for delay, ceiling in zip(delays, [0.5, 1.0, 2.0, 3.0], strict=True):
            assert 0.0 <= delay <= ceiling


def test_backoff_zero_attempts():
    assert list(backoff_delays(0, 0.5, 3.0, 2.0)) == []


@pytest.mark.parametrize(
    ("attempts", "base", "max_delay", "multiplier"),
    [(-1, 0.5, 1.0, 2.0), (1, -0.5, 1.0, 2.0), (1, 0.5, -1.0, 2.0), (1, 0.5, 1.0, 0.0)],
)
def test_backoff_validation(attempts, base, max_delay, multiplier):
    with pytest.raises(ValueError, match="negative|positive"):
        list(backoff_delays(attempts, base, max_delay, multiplier))


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------


def _wrapped(inner: BaseException) -> RuntimeError:
    try:
        raise RuntimeError("Server session was closed unexpectedly") from inner
    except RuntimeError as exc:
        return exc


@pytest.mark.parametrize(
    "exc",
    [
        ConnectionResetError("reset"),
        BrokenPipeError("pipe"),
        EOFError(),
        anyio.ClosedResourceError(),
        anyio.BrokenResourceError(),
        anyio.EndOfStream(),
        _wrapped(anyio.ClosedResourceError()),
        MCPError(code=CONNECTION_CLOSED, message="closed"),
    ],
)
def test_is_connection_error_true(exc):
    assert is_connection_error(exc) is True


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("bad"),
        TypeError("bad"),
        TimeoutError(),
        RuntimeError("plain"),
        MCPError(code=INVALID_PARAMS, message="bad params"),
    ],
)
def test_is_connection_error_false(exc):
    assert is_connection_error(exc) is False


def test_is_connection_error_handles_cycles():
    exc = RuntimeError("loop")
    exc.__cause__ = exc
    assert is_connection_error(exc) is False


# ---------------------------------------------------------------------------
# run_with_retry
# ---------------------------------------------------------------------------


async def test_retry_success_first_attempt():
    operation = AsyncMock(return_value="ok")
    sleep = AsyncMock()
    result = await run_with_retry(operation, delays=[1.0], is_retryable=lambda _: True, sleep=sleep)
    assert result == "ok"
    sleep.assert_not_awaited()


async def test_retry_backoff_timing():
    operation = AsyncMock(side_effect=[ConnectionError("a"), ConnectionError("b"), "ok"])
    failures = []

    async def on_failure(exc, attempt):
        failures.append((str(exc), attempt))

    with patch("dcert.resilience.asyncio.sleep", new=AsyncMock()) as sleep:
        result = await run_with_retry(
            operation,
            delays=[0.25, 0.5, 1.0],
            is_retryable=is_connection_error,
            on_failure=on_failure,
        )
    assert result == "ok"
    assert [call.args[0] for call in sleep.await_args_list] == [0.25, 0.5]
    assert failures == [("a", 0), ("b", 1)]
    assert [call.args[0] for call in operation.await_args_list] == [0, 1, 2]


async def test_retry_non_retryable_raises_immediately():
    operation = AsyncMock(side_effect=ValueError("bad input"))
    sleep = AsyncMock()
    with pytest.raises(ValueError, match="bad input"):
        await run_with_retry(
            operation, delays=[1.0, 1.0], is_retryable=is_connection_error, sleep=sleep
        )
    sleep.assert_not_awaited()
    assert operation.await_count == 1


async def test_retry_exhausted_raises_last_and_records_final_failure():
    operation = AsyncMock(side_effect=ConnectionError("down"))
    on_failure = AsyncMock()
    sleep = AsyncMock()
    with pytest.raises(ConnectionError, match="down"):
        await run_with_retry(
            operation,
            delays=[0.1],
            is_retryable=is_connection_error,
            on_failure=on_failure,
            sleep=sleep,
        )
    assert operation.await_count == 2
    assert on_failure.await_count == 2
    sleep.assert_awaited_once_with(0.1)


async def test_retry_never_swallows_cancellation():
    operation = AsyncMock(side_effect=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await run_with_retry(operation, delays=[0.1], is_retryable=lambda _: True)
    assert operation.await_count == 1


# ---------------------------------------------------------------------------
# OpenTelemetry
# ---------------------------------------------------------------------------


def test_setup_otel_disabled_is_noop():
    setup_otel(OTelConfig(enabled=False, service_name="x", exporter="console"))


def test_setup_otel_without_sdk_logs_warning(caplog):
    with patch.dict(sys.modules, {"opentelemetry": None}):
        setup_otel(OTelConfig(enabled=True, service_name="x", exporter="console"))
    assert "OpenTelemetry SDK not installed" in caplog.text


def test_setup_otel_with_fake_sdk():
    """Exercise the wiring with stub modules standing in for the SDK."""
    from types import ModuleType
    from unittest.mock import MagicMock

    fake = {
        name: ModuleType(name)
        for name in [
            "opentelemetry",
            "opentelemetry.trace",
            "opentelemetry.sdk",
            "opentelemetry.sdk.resources",
            "opentelemetry.sdk.trace",
            "opentelemetry.sdk.trace.export",
            "opentelemetry.exporter",
            "opentelemetry.exporter.otlp",
            "opentelemetry.exporter.otlp.proto",
            "opentelemetry.exporter.otlp.proto.grpc",
            "opentelemetry.exporter.otlp.proto.grpc.trace_exporter",
        ]
    }
    trace = fake["opentelemetry.trace"]
    trace.set_tracer_provider = MagicMock()
    fake["opentelemetry"].trace = trace
    fake["opentelemetry.sdk.resources"].Resource = MagicMock()
    provider = MagicMock()
    fake["opentelemetry.sdk.trace"].TracerProvider = MagicMock(return_value=provider)
    export = fake["opentelemetry.sdk.trace.export"]
    export.SpanProcessor = MagicMock
    export.BatchSpanProcessor = MagicMock()
    export.SimpleSpanProcessor = MagicMock()
    export.ConsoleSpanExporter = MagicMock()
    fake["opentelemetry.exporter.otlp.proto.grpc.trace_exporter"].OTLPSpanExporter = MagicMock()

    with patch.dict(sys.modules, fake):
        setup_otel(OTelConfig(enabled=True, service_name="svc", exporter="console"))
        setup_otel(OTelConfig(enabled=True, service_name="svc", exporter="otlp"))
    assert trace.set_tracer_provider.call_count == 2
    export.SimpleSpanProcessor.assert_called_once()
    export.BatchSpanProcessor.assert_called_once()
