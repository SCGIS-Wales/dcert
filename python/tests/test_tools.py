"""Tests for dcert.tools."""

from __future__ import annotations

import asyncio
import inspect
from contextlib import asynccontextmanager
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from dcert import tools as tools_mod
from dcert.resilience import resilience_config_from_env
from dcert.tools import (
    TOOL_FUNCTIONS,
    DcertConnectionError,
    DcertError,
    DcertTimeoutError,
    DcertToolError,
    Session,
    analyze_certificate,
    build_arguments,
    call_tool,
    check_expiry,
    check_revocation,
    close_default_session,
    compare_certificates,
    content_blocks,
    convert_pem_to_pfx,
    convert_pfx_to_pem,
    create_keystore,
    create_session,
    create_truststore,
    default_session,
    error_message,
    export_pem,
    extract_text,
    tls_connection_info,
    verify_key_match,
)

OK = SimpleNamespace(content=[SimpleNamespace(type="text", text='{"status": "ok"}')])


class FakeClient:
    """Minimal stand in for ``fastmcp.Client``."""

    def __init__(self, call_tool):
        self.call_tool = call_tool
        self.entered = 0
        self.exited = 0

    async def __aenter__(self):
        self.entered += 1
        return self

    async def __aexit__(self, *exc):
        self.exited += 1


@pytest.fixture
def config(monkeypatch):
    for name in list(__import__("os").environ):
        if name.startswith("DCERT_MCP_"):
            monkeypatch.delenv(name)
    return replace(
        resilience_config_from_env(),
        retry_base_delay=0.0,
        retry_max_delay=0.0,
        circuit_breaker_enabled=False,
        rate_limit_enabled=False,
    )


@pytest.fixture
def open_session(config):
    """Return ``open_session(call_tool, **overrides)`` yielding a connected session."""

    @asynccontextmanager
    async def opener(call_tool, **overrides):
        clients: list[FakeClient] = []

        def factory():
            clients.append(FakeClient(call_tool))
            return clients[-1]

        options = {"timeout": 5.0, "max_reconnects": 0, "resilience": config}
        options.update(overrides)
        async with create_session(
            binary_path="/fake/dcert-mcp", client_factory=factory, **options
        ) as session:
            yield session, clients

    return opener


# ---------------------------------------------------------------------------
# Exceptions and helpers
# ---------------------------------------------------------------------------


def test_exception_hierarchy():
    assert issubclass(DcertError, Exception)
    for cls in (DcertTimeoutError, DcertConnectionError, DcertToolError):
        assert issubclass(cls, DcertError)
    err = DcertToolError("msg", tool="analyze_certificate", error_content=["err"])
    assert (err.tool, err.error_content, str(err)) == ("analyze_certificate", ["err"], "msg")


def test_content_blocks_and_extract_text():
    assert content_blocks([SimpleNamespace(text="a")]) == [SimpleNamespace(text="a")]
    assert content_blocks(SimpleNamespace(content=None)) == []
    assert extract_text([SimpleNamespace(text="hello")]) == "hello"
    assert extract_text([SimpleNamespace(text="a"), SimpleNamespace(text="b")]) == "a\nb"
    assert extract_text([]) is None
    assert extract_text([SimpleNamespace(value=42)]) is None
    assert extract_text(SimpleNamespace(content=[SimpleNamespace(text="x")])) == "x"


def test_error_message():
    assert error_message(OK) is None
    assert error_message([SimpleNamespace(type="error", text="boom")]) == "boom"
    flagged = SimpleNamespace(is_error=True, content=[SimpleNamespace(text="bad")])
    assert error_message(flagged) == "bad"
    assert error_message(SimpleNamespace(is_error=True, content=[])) is not None


def test_build_arguments():
    assert build_arguments("t", {"a": 1}) == {"a": 1}
    assert build_arguments("t", {"a": 1}, {"b": None, "c": ""}) == {"a": 1, "c": ""}
    assert build_arguments("t", {"a": 1}, defaulted={"d": (30, 30), "e": (1, 2)}) == {
        "a": 1,
        "e": 1,
    }
    with pytest.raises(ValueError, match="t\\(\\) requires 'a' parameter"):
        build_arguments("t", {"a": None})


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------


async def test_session_connects_and_disconnects(open_session):
    async with open_session(AsyncMock(return_value=OK)) as (session, clients):
        assert isinstance(session, Session)
        assert session.binary == "/fake/dcert-mcp"
        assert session.connected() is True
        assert clients[0].entered == 1
    assert clients[0].exited == 1
    assert session.connected() is False


async def test_session_disconnect_errors_are_logged(open_session, caplog):
    call = AsyncMock(return_value=OK)
    async with open_session(call) as (session, clients):
        clients[0].__aexit__ = AsyncMock(side_effect=RuntimeError("boom"))
    assert session.connected() is False


async def test_session_is_frozen(open_session):
    async with open_session(AsyncMock(return_value=OK)) as (session, _clients):
        with pytest.raises(AttributeError, match="cannot assign"):
            session.binary = "x"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Tool wrappers: payload construction
# ---------------------------------------------------------------------------


CASES = [
    (
        analyze_certificate,
        {"target": "example.com"},
        "analyze_certificate",
        {"target": "example.com"},
    ),
    (
        analyze_certificate,
        {"target": "e", "fingerprint": False, "extensions": False, "check_revocation": True},
        "analyze_certificate",
        {"target": "e", "fingerprint": False, "extensions": False, "check_revocation": True},
    ),
    (check_expiry, {"target": "e", "days": 60}, "check_expiry", {"target": "e", "days": 60}),
    (check_expiry, {"target": "e", "days": 30}, "check_expiry", {"target": "e"}),
    (check_revocation, {"target": "e"}, "check_revocation", {"target": "e"}),
    (
        compare_certificates,
        {"target_a": "a", "target_b": "b"},
        "compare_certificates",
        {"target_a": "a", "target_b": "b"},
    ),
    (
        tls_connection_info,
        {"target": "e", "min_tls": "1.2", "max_tls": "1.3"},
        "tls_connection_info",
        {"target": "e", "min_tls": "1.2", "max_tls": "1.3"},
    ),
    (
        export_pem,
        {"target": "e", "exclude_expired": True, "output_path": "c.pem"},
        "export_pem",
        {"target": "e", "exclude_expired": True, "output_path": "c.pem"},
    ),
    (
        verify_key_match,
        {"target": "cert.pem", "key_path": "key.pem"},
        "verify_key_match",
        {"target": "cert.pem", "key_path": "key.pem"},
    ),
    (
        convert_pfx_to_pem,
        {"pkcs12_path": "t.pfx", "password": "p", "output_dir": "/out"},
        "convert_pfx_to_pem",
        {"pkcs12_path": "t.pfx", "password": "p", "output_dir": "/out"},
    ),
    (
        convert_pfx_to_pem,
        {"pkcs12_path": "t.pfx", "password": "p"},
        "convert_pfx_to_pem",
        {"pkcs12_path": "t.pfx", "password": "p"},
    ),
    (
        convert_pem_to_pfx,
        {"cert_path": "c", "key_path": "k", "password": "p", "output_path": "o", "ca_path": "ca"},
        "convert_pem_to_pfx",
        {"cert_path": "c", "key_path": "k", "password": "p", "output_path": "o", "ca_path": "ca"},
    ),
    (
        create_keystore,
        {"cert_path": "c", "key_path": "k", "password": "p", "output_path": "o", "alias": "mykey"},
        "create_keystore",
        {"cert_path": "c", "key_path": "k", "password": "p", "output_path": "o", "alias": "mykey"},
    ),
    (
        create_keystore,
        {"cert_path": "c", "key_path": "k", "password": "p", "output_path": "o", "alias": "server"},
        "create_keystore",
        {"cert_path": "c", "key_path": "k", "password": "p", "output_path": "o"},
    ),
    (
        create_truststore,
        {"cert_paths": ["ca1.pem", "ca2.pem"], "output_path": "t.p12", "password": "secret"},
        "create_truststore",
        {"cert_paths": ["ca1.pem", "ca2.pem"], "output_path": "t.p12", "password": "secret"},
    ),
    (
        create_truststore,
        {"cert_paths": ["ca.pem"], "output_path": "t.p12"},
        "create_truststore",
        {"cert_paths": ["ca.pem"], "output_path": "t.p12"},
    ),
    (
        create_truststore,
        {"cert_paths": ["ca.pem"], "output_path": "t.p12", "password": "changeit"},
        "create_truststore",
        {"cert_paths": ["ca.pem"], "output_path": "t.p12"},
    ),
]


@pytest.mark.parametrize(("func", "kwargs", "tool", "expected"), CASES)
async def test_tool_payloads(open_session, func, kwargs, tool, expected):
    call = AsyncMock(return_value=OK)
    async with open_session(call) as (session, _clients):
        result = await func(session=session, **kwargs)
    assert result == '{"status": "ok"}'
    call.assert_awaited_once_with(tool, expected, raise_on_error=False)


async def test_connection_overrides_are_forwarded(open_session):
    call = AsyncMock(return_value=OK)
    async with open_session(call) as (session, _clients):
        await analyze_certificate(
            session=session,
            target="https://api.example.com",
            connect_to="10.0.0.5",
            resolve="api.example.com:443:10.0.0.6",
            proxy="http://proxy.corp:3128",
            noproxy="internal.corp",
            client_cert="c.pem",
            client_key="k.pem",
            pkcs12="c.p12",
            cert_password="pw",
            ca_cert="ca.pem",
        )
    call.assert_awaited_once_with(
        "analyze_certificate",
        {
            "target": "https://api.example.com",
            "connect_to": "10.0.0.5",
            "resolve": "api.example.com:443:10.0.0.6",
            "proxy": "http://proxy.corp:3128",
            "noproxy": "internal.corp",
            "client_cert": "c.pem",
            "client_key": "k.pem",
            "pkcs12": "c.p12",
            "cert_password": "pw",
            "ca_cert": "ca.pem",
        },
        raise_on_error=False,
    )


async def test_connection_overrides_accept_lists_and_empty_strings(open_session):
    call = AsyncMock(return_value=OK)
    async with open_session(call) as (session, _clients):
        await tls_connection_info(
            session=session,
            target="e",
            connect_to=["a:443:b:8443"],
            resolve=["a:443:10.0.0.5", "*:8443:10.0.0.6"],
        )
        await check_expiry(session=session, target="e", proxy="", noproxy="")
        await export_pem(session=session, target="e")
    assert call.await_args_list[0].args[1] == {
        "target": "e",
        "connect_to": ["a:443:b:8443"],
        "resolve": ["a:443:10.0.0.5", "*:8443:10.0.0.6"],
    }
    assert call.await_args_list[1].args[1] == {"target": "e", "proxy": "", "noproxy": ""}
    assert call.await_args_list[2].args[1] == {"target": "e"}


async def test_input_validation(open_session):
    async with open_session(AsyncMock(return_value=OK)) as (session, _clients):
        with pytest.raises(TypeError, match="target"):
            await analyze_certificate(session=session)  # type: ignore[call-arg]
        with pytest.raises(TypeError, match="target_b"):
            await compare_certificates(session=session, target_a="a")  # type: ignore[call-arg]
        with pytest.raises(ValueError, match="at least one cert_path"):
            await create_truststore(session=session, cert_paths=[], output_path="o")
        with pytest.raises(ValueError, match="requires 'target'"):
            await analyze_certificate(session=session, target=None)  # type: ignore[arg-type]


def test_all_tool_functions_present():
    assert len(TOOL_FUNCTIONS) == 11
    # inspect, not asyncio: asyncio.iscoroutinefunction is deprecated from 3.14.
    assert all(inspect.iscoroutinefunction(f) for f in TOOL_FUNCTIONS)


# ---------------------------------------------------------------------------
# Session.call behaviour
# ---------------------------------------------------------------------------


async def test_call_returns_raw_result_without_text(open_session):
    raw = SimpleNamespace(content=[SimpleNamespace(type="image", data="AA==")])
    async with open_session(AsyncMock(return_value=raw)) as (session, _clients):
        assert await session.call("tool", {}) is raw


async def test_call_truncates_long_text(open_session, config):
    long_result = SimpleNamespace(content=[SimpleNamespace(text="x" * 5000)])
    cfg = replace(config, max_response_bytes=100)
    async with open_session(AsyncMock(return_value=long_result), resilience=cfg) as (s, _c):
        result = await s.call("tool", {})
    assert "[Truncated:" in result


async def test_timeout_raises(open_session):
    async def slow(*_args, **_kwargs):
        await asyncio.sleep(1)

    async with open_session(slow, timeout=0.01) as (session, _clients):
        with pytest.raises(DcertTimeoutError, match="analyze_certificate timed out after 0.01s"):
            await analyze_certificate(session=session, target="e")


async def test_per_call_timeout_override(open_session):
    async def slow(*_args, **_kwargs):
        await asyncio.sleep(1)

    async with open_session(slow, timeout=5.0) as (session, _clients):
        with pytest.raises(DcertTimeoutError, match="0.01s"):
            await session.call("tool", {}, timeout=0.01)


async def test_tool_error_content_raises(open_session):
    bad = [SimpleNamespace(type="error", text="something went wrong")]
    async with open_session(AsyncMock(return_value=bad)) as (session, _clients):
        with pytest.raises(DcertToolError, match="something went wrong") as info:
            await session.call("test_tool", {})
    assert info.value.tool == "test_tool"
    assert info.value.error_content is bad


async def test_is_error_result_raises(open_session):
    bad = SimpleNamespace(is_error=True, content=[SimpleNamespace(text="denied")])
    async with open_session(AsyncMock(return_value=bad)) as (session, _clients):
        with pytest.raises(DcertToolError, match="denied"):
            await session.call("test_tool", {})


async def test_reconnect_on_connection_failure(open_session):
    closed = RuntimeError("closed")
    closed.__cause__ = ConnectionResetError("gone")
    call = AsyncMock(side_effect=[closed, OK])
    with patch("dcert.resilience.asyncio.sleep", new=AsyncMock()) as sleep:
        async with open_session(call, max_reconnects=2) as (session, clients):
            assert await session.call("tool", {}) == '{"status": "ok"}'
            assert len(clients) == 2
            assert clients[0].exited == 1
    sleep.assert_awaited_once()


async def test_reconnects_exhausted(open_session):
    call = AsyncMock(side_effect=ConnectionResetError("gone"))
    with patch("dcert.resilience.asyncio.sleep", new=AsyncMock()):
        async with open_session(call, max_reconnects=2) as (session, clients):
            with pytest.raises(DcertConnectionError, match="gone"):
                await session.call("tool", {})
            assert call.await_count == 3
            assert len(clients) == 3


@pytest.mark.parametrize("exc", [ValueError("bad value"), TypeError("bad type")])
async def test_non_connection_errors_surface_immediately(open_session, exc):
    call = AsyncMock(side_effect=exc)
    async with open_session(call, max_reconnects=3) as (session, clients):
        with pytest.raises(type(exc), match="bad"):
            await session.call("tool", {})
        assert call.await_count == 1
        assert len(clients) == 1
        assert session.connected() is True


async def test_cancellation_is_never_caught(open_session):
    call = AsyncMock(side_effect=asyncio.CancelledError())
    async with open_session(call, max_reconnects=3) as (session, _clients):
        with pytest.raises(asyncio.CancelledError):
            await session.call("tool", {})
    assert call.await_count == 1


async def test_circuit_breaker_rejects_after_failures(open_session, config):
    cfg = replace(config, circuit_breaker_enabled=True, circuit_breaker_threshold=1)
    call = AsyncMock(side_effect=ConnectionResetError("gone"))
    async with open_session(call, resilience=cfg) as (session, _clients):
        with pytest.raises(DcertConnectionError, match="gone"):
            await session.call("tool", {})
        with pytest.raises(DcertConnectionError, match="Circuit breaker is open"):
            await session.call("tool", {})
    assert call.await_count == 1


async def test_circuit_breaker_records_success(open_session, config):
    cfg = replace(config, circuit_breaker_enabled=True, circuit_breaker_threshold=2)
    call = AsyncMock(side_effect=[ConnectionResetError("gone"), OK, ConnectionResetError("x"), OK])
    async with open_session(call, resilience=cfg) as (session, _clients):
        for _ in range(2):
            with pytest.raises(DcertConnectionError, match="gone|x"):
                await session.call("tool", {})
            assert await session.call("tool", {}) == '{"status": "ok"}'


async def test_rate_limiter_is_applied(open_session, config):
    cfg = replace(config, rate_limit_enabled=True, rate_limit_rps=1000.0, rate_limit_burst=1)
    with patch("dcert.resilience.asyncio.sleep", new=AsyncMock()) as sleep:
        async with open_session(AsyncMock(return_value=OK), resilience=cfg) as (session, _c):
            await session.call("tool", {})
            await session.call("tool", {})
    sleep.assert_awaited_once()


async def test_concurrent_calls(open_session):
    call = AsyncMock(return_value=OK)
    async with open_session(call) as (session, _clients):
        results = await asyncio.gather(
            analyze_certificate(session=session, target="a.com"),
            check_expiry(session=session, target="b.com"),
            tls_connection_info(session=session, target="c.com"),
        )
    assert results == ['{"status": "ok"}'] * 3
    assert call.await_count == 3


async def test_connect_failure_propagates(config):
    def factory():
        raise ConnectionRefusedError("cannot spawn")

    with pytest.raises(ConnectionRefusedError, match="cannot spawn"):
        async with create_session(
            binary_path="/fake/dcert-mcp", client_factory=factory, resilience=config
        ):
            pass


# ---------------------------------------------------------------------------
# Shared default session
# ---------------------------------------------------------------------------


@pytest.fixture
async def fake_default(monkeypatch):
    """Replace create_session with a fake yielding fresh Session records."""
    created: list[Session] = []
    calls: list[tuple[str, dict]] = []

    @asynccontextmanager
    async def fake_create_session(*_args, **_kwargs):
        state = {"connected": True}

        async def call(tool, params, *, timeout=None):
            calls.append((tool, dict(params)))
            return "ok"

        session = Session(binary="/fake", call=call, connected=lambda: state["connected"])
        created.append(session)
        try:
            yield session
        finally:
            state["connected"] = False

    monkeypatch.setattr(tools_mod, "create_session", fake_create_session)
    await close_default_session()
    yield created, calls
    await close_default_session()


async def test_default_session_is_shared(fake_default):
    created, calls = fake_default
    assert await analyze_certificate(target="a.com") == "ok"
    assert await check_expiry(target="b.com") == "ok"
    assert len(created) == 1
    assert calls == [
        ("analyze_certificate", {"target": "a.com"}),
        ("check_expiry", {"target": "b.com"}),
    ]
    assert await default_session() is created[0]


async def test_default_session_reconnects_when_disconnected(fake_default):
    created, _calls = fake_default
    await call_tool("t", {})
    await close_default_session()
    assert created[0].connected() is False
    await call_tool("t", {})
    assert len(created) == 2


async def test_default_session_concurrent_first_use_creates_one(fake_default):
    created, _calls = fake_default
    await asyncio.gather(*(call_tool("t", {}) for _ in range(5)))
    assert len(created) == 1


async def test_close_default_session_when_none():
    await close_default_session()
    await close_default_session()
