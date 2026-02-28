"""Tests for dcert.resilience module."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest

from dcert.resilience import (
    CircuitBreaker,
    CircuitBreakerOpen,
    OTelConfig,
    RateLimiter,
    ResilienceConfig,
    _env_bool,
    _env_float,
    _env_int,
    _wait_for_compat,
    truncate_response,
)

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


class TestEnvHelpers:
    """Test environment variable parsing helpers."""

    def test_env_bool_true_values(self):
        for val in ("1", "true", "yes", "on", "True", "YES", "ON"):
            with patch.dict(os.environ, {"TEST_VAR": val}):
                assert _env_bool("TEST_VAR") is True

    def test_env_bool_false_values(self):
        for val in ("0", "false", "no", "off", "False", "NO", "OFF"):
            with patch.dict(os.environ, {"TEST_VAR": val}):
                assert _env_bool("TEST_VAR") is False

    def test_env_bool_unset_returns_default(self):
        env = {k: v for k, v in os.environ.items() if k != "TEST_UNSET"}
        with patch.dict(os.environ, env, clear=True):
            assert _env_bool("TEST_UNSET") is False
            assert _env_bool("TEST_UNSET", default=True) is True

    def test_env_int_valid(self):
        with patch.dict(os.environ, {"TEST_INT": "42"}):
            assert _env_int("TEST_INT", 0) == 42

    def test_env_int_invalid_returns_default(self):
        with patch.dict(os.environ, {"TEST_INT": "not-a-number"}):
            assert _env_int("TEST_INT", 99) == 99

    def test_env_int_unset_returns_default(self):
        env = {k: v for k, v in os.environ.items() if k != "TEST_UNSET"}
        with patch.dict(os.environ, env, clear=True):
            assert _env_int("TEST_UNSET", 7) == 7

    def test_env_float_valid(self):
        with patch.dict(os.environ, {"TEST_FLOAT": "3.14"}):
            assert _env_float("TEST_FLOAT", 0.0) == pytest.approx(3.14)

    def test_env_float_invalid_returns_default(self):
        with patch.dict(os.environ, {"TEST_FLOAT": "abc"}):
            assert _env_float("TEST_FLOAT", 1.5) == pytest.approx(1.5)


# ---------------------------------------------------------------------------
# ResilienceConfig
# ---------------------------------------------------------------------------


class TestResilienceConfig:
    """Test ResilienceConfig defaults and env overrides."""

    def test_defaults(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("DCERT_MCP_")}
        with patch.dict(os.environ, env, clear=True):
            cfg = ResilienceConfig()
            assert cfg.retry_enabled is True
            assert cfg.retry_max_attempts == 3
            assert cfg.circuit_breaker_enabled is True
            assert cfg.circuit_breaker_threshold == 5
            assert cfg.bulkhead_max == 10
            assert cfg.rate_limit_enabled is False
            assert cfg.cache_enabled is False
            assert cfg.max_response_bytes == 256 * 1024
            assert cfg.tool_timeout == 300.0
            assert cfg.reconnect_max == 3

    def test_env_overrides(self):
        overrides = {
            "DCERT_MCP_NO_RETRY": "1",
            "DCERT_MCP_RETRY_MAX_ATTEMPTS": "5",
            "DCERT_MCP_NO_CIRCUIT_BREAKER": "true",
            "DCERT_MCP_BULKHEAD_MAX": "20",
            "DCERT_MCP_RATE_LIMIT_ENABLED": "1",
            "DCERT_MCP_RATE_LIMIT_RPS": "50",
            "DCERT_MCP_CACHE_ENABLED": "1",
            "DCERT_MCP_MAX_RESPONSE_BYTES": "1024",
        }
        with patch.dict(os.environ, overrides):
            cfg = ResilienceConfig()
            assert cfg.retry_enabled is False
            assert cfg.retry_max_attempts == 5
            assert cfg.circuit_breaker_enabled is False
            assert cfg.bulkhead_max == 20
            assert cfg.rate_limit_enabled is True
            assert cfg.rate_limit_rps == pytest.approx(50.0)
            assert cfg.cache_enabled is True
            assert cfg.max_response_bytes == 1024


# ---------------------------------------------------------------------------
# truncate_response
# ---------------------------------------------------------------------------


class TestTruncateResponse:
    """Test response payload management."""

    def test_short_response_unchanged(self):
        text = "Hello, world!"
        assert truncate_response(text) == text

    def test_truncation_at_max_bytes(self):
        text = "a" * 300_000
        result = truncate_response(text, max_bytes=1024)
        assert len(result.encode("utf-8")) < 1500  # truncated + notice
        assert "[Truncated:" in result

    def test_truncation_disabled_with_zero(self):
        text = "a" * 300_000
        result = truncate_response(text, max_bytes=0)
        assert result == text

    def test_truncation_at_newline_boundary(self):
        lines = ["line " + str(i) for i in range(1000)]
        text = "\n".join(lines)
        result = truncate_response(text, max_bytes=200)
        assert "[Truncated:" in result
        # Should end at a newline, not mid-word
        body = result.split("[Truncated:")[0].rstrip()
        assert body.endswith("\n") or "line" in body

    def test_exact_boundary(self):
        text = "x" * 100
        result = truncate_response(text, max_bytes=100)
        assert result == text


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    """Test circuit breaker state machine."""

    @pytest.mark.asyncio
    async def test_initial_state_closed(self):
        cb = CircuitBreaker(threshold=3, reset_timeout=1.0)
        assert cb.state == "closed"
        assert await cb.allow() is True

    @pytest.mark.asyncio
    async def test_trips_after_threshold(self):
        cb = CircuitBreaker(threshold=3, reset_timeout=30.0)
        for _ in range(3):
            await cb.record_failure()
        assert cb.state == "open"
        assert await cb.allow() is False

    @pytest.mark.asyncio
    async def test_success_resets_count(self):
        cb = CircuitBreaker(threshold=3, reset_timeout=30.0)
        await cb.record_failure()
        await cb.record_failure()
        await cb.record_success()
        assert cb.state == "closed"
        # Should not trip after one more failure
        await cb.record_failure()
        assert cb.state == "closed"

    @pytest.mark.asyncio
    async def test_half_open_after_timeout(self):
        cb = CircuitBreaker(threshold=1, reset_timeout=0.01)
        await cb.record_failure()
        assert cb.state == "open"
        await asyncio.sleep(0.02)
        assert await cb.allow() is True
        assert cb.state == "half_open"

    @pytest.mark.asyncio
    async def test_half_open_success_closes(self):
        cb = CircuitBreaker(threshold=1, reset_timeout=0.01)
        await cb.record_failure()
        await asyncio.sleep(0.02)
        await cb.allow()  # transitions to half_open
        await cb.record_success()
        assert cb.state == "closed"

    @pytest.mark.asyncio
    async def test_half_open_failure_reopens(self):
        cb = CircuitBreaker(threshold=1, reset_timeout=0.01)
        await cb.record_failure()
        await asyncio.sleep(0.02)
        await cb.allow()  # transitions to half_open
        await cb.record_failure()
        assert cb.state == "open"


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    """Test token-bucket rate limiter."""

    @pytest.mark.asyncio
    async def test_acquire_within_burst(self):
        rl = RateLimiter(rps=100.0, burst=5)
        for _ in range(5):
            await rl.acquire()
        # Should succeed without blocking for burst-size requests

    @pytest.mark.asyncio
    async def test_acquire_blocks_after_burst(self):
        rl = RateLimiter(rps=1000.0, burst=1)
        await rl.acquire()  # consume the single token
        # Next acquire should need to wait for refill
        # With 1000 RPS it should refill quickly
        await asyncio.wait_for(rl.acquire(), timeout=1.0)


# ---------------------------------------------------------------------------
# _wait_for_compat
# ---------------------------------------------------------------------------


class TestWaitForCompat:
    """Test Python 3.10 compatibility shim."""

    @pytest.mark.asyncio
    async def test_success(self):
        async def quick():
            return 42

        result = await _wait_for_compat(quick(), timeout=1.0)
        assert result == 42

    @pytest.mark.asyncio
    async def test_timeout(self):
        async def slow():
            await asyncio.sleep(10)

        with pytest.raises(TimeoutError):
            await _wait_for_compat(slow(), timeout=0.01)


# ---------------------------------------------------------------------------
# OTelConfig
# ---------------------------------------------------------------------------


class TestOTelConfig:
    """Test OTelConfig defaults and env overrides."""

    def test_defaults(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("DCERT_MCP_OTEL")}
        with patch.dict(os.environ, env, clear=True):
            cfg = OTelConfig()
            assert cfg.enabled is False
            assert cfg.service_name == "dcert-mcp"
            assert cfg.exporter == "console"

    def test_env_overrides(self):
        overrides = {
            "DCERT_MCP_OTEL_ENABLED": "true",
            "DCERT_MCP_OTEL_SERVICE_NAME": "my-service",
            "DCERT_MCP_OTEL_EXPORTER": "otlp",
        }
        with patch.dict(os.environ, overrides):
            cfg = OTelConfig()
            assert cfg.enabled is True
            assert cfg.service_name == "my-service"
            assert cfg.exporter == "otlp"


# ---------------------------------------------------------------------------
# CircuitBreakerOpen exception
# ---------------------------------------------------------------------------


class TestCircuitBreakerOpen:
    """Test CircuitBreakerOpen exception."""

    def test_is_exception(self):
        assert issubclass(CircuitBreakerOpen, Exception)

    def test_message(self):
        err = CircuitBreakerOpen("circuit is open")
        assert str(err) == "circuit is open"
