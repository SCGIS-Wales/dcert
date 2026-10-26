"""Tests for dcert.tools."""

from __future__ import annotations

import asyncio
import inspect
from contextlib import asynccontextmanager
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import mcp_types as mt
import pytest

from dcert import tools as tools_mod
from dcert.config import load_config
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
    explain_cipher_suite,
    export_pem,
    extract_text,
    list_cipher_suites,
    list_tls_policies,
    show_tls_policy,
    tls_connection_info,
    tls_policy_test,
    tls_scan,
    verify_key_match,
)

OK = SimpleNamespace(content=[SimpleNamespace(type="text", text='{"status": "ok"}')])
READ_ONLY = mt.ToolAnnotations(read_only_hint=True, idempotent_hint=True)
ISSUING = mt.ToolAnnotations(read_only_hint=False, idempotent_hint=False)
#: Every tool the tests call, as the backend would list it: safe to re-run.
SAFE_TOOLS = [
    SimpleNamespace(name=name, annotations=READ_ONLY)
    for name in ("tool", "test_tool", *(f.__name__ for f in TOOL_FUNCTIONS))
]


class FakeClient:
    """Minimal stand in for ``fastmcp.Client``."""

    def __init__(self, call_tool, tools=None, list_tools=None):
        self.call_tool = call_tool
        self.tools = SAFE_TOOLS if tools is None else tools
        self.list_tools = list_tools or self._list_tools
        self.entered = 0
        self.exited = 0

    async def _list_tools(self):
        return self.tools

    async def __aenter__(self):
        self.entered += 1
        return self

    async def __aexit__(self, *exc):
        self.exited += 1


@pytest.fixture
def open_session(config):
    """Return ``open_session(call_tool, **overrides)`` yielding a connected session.

    The breaker and limiter are off unless a test passes its own ``resilience``;
    ``sleep`` replaces backoff sleeps and ``tools``/``list_tools`` shape the
    fake client's tool listing.
    """
    quiet = replace(config, circuit_breaker_enabled=False, rate_limit_enabled=False)

    @asynccontextmanager
    async def opener(call_tool, *, tools=None, list_tools=None, **overrides):
        clients: list[FakeClient] = []

        def factory():
            clients.append(FakeClient(call_tool, tools=tools, list_tools=list_tools))
            return clients[-1]

        options = {
            "timeout": 5.0,
            "max_reconnects": 0,
            "resilience": quiet,
            "sleep": AsyncMock(),
        }
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


async def test_session_disconnect_errors_are_logged(config, caplog):
    class Broken(FakeClient):
        async def __aexit__(self, *exc):
            await super().__aexit__(*exc)
            raise RuntimeError("boom")

    clients: list[FakeClient] = []

    def factory():
        clients.append(Broken(AsyncMock(return_value=OK)))
        return clients[-1]

    with caplog.at_level("DEBUG", logger="dcert.tools"):
        async with create_session(
            binary_path="/fake/dcert-mcp", client_factory=factory, resilience=config
        ) as session:
            pass
    assert session.connected() is False
    assert clients[0].exited == 1
    assert "Error while disconnecting" in caplog.text


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
        convert_pfx_to_pem,
        {"pkcs12_path": "t.pfx", "password": "p", "output_dir": load_config().tools.output_dir},
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
    (
        create_truststore,
        {"cert_paths": ["leaf.pem"], "output_path": "t.p12", "allow_non_ca": True},
        "create_truststore",
        {"cert_paths": ["leaf.pem"], "output_path": "t.p12", "allow_non_ca": True},
    ),
    (list_cipher_suites, {}, "list_cipher_suites", {}),
    (
        list_cipher_suites,
        {"protocol": "1.3", "offerable": True},
        "list_cipher_suites",
        {"protocol": "1.3", "offerable": True},
    ),
    (explain_cipher_suite, {"suite": "C02F"}, "explain_cipher_suite", {"suite": "C02F"}),
    (tls_scan, {"target": "e"}, "tls_scan", {"target": "e"}),
    (list_tls_policies, {}, "list_tls_policies", {}),
    (
        tls_policy_test,
        {
            "target": "e",
            "policy": "P",
            "versions": ("1.2", "1.3"),
            "strict": True,
            "resolve": "e:443:10.0.0.1",
        },
        "tls_policy_test",
        {
            "target": "e",
            "policy": "P",
            "versions": ["1.2", "1.3"],
            "strict": True,
            "resolve": "e:443:10.0.0.1",
        },
    ),
    (
        tls_policy_test,
        {"target": "e", "identify": True},
        "tls_policy_test",
        {"target": "e", "identify": True},
    ),
    (list_tls_policies, {"provider": "aws_alb"}, "list_tls_policies", {"provider": "aws_alb"}),
    (
        show_tls_policy,
        {"policy_id": "P", "provider": "aws_nlb"},
        "show_tls_policy",
        {"id": "P", "provider": "aws_nlb"},
    ),
    (
        tls_scan,
        {
            "target": "e",
            "allow_legacy_tls": True,
            "max_handshakes": 50,
            "resolve": ["e:443:10.0.0.1"],
        },
        "tls_scan",
        {
            "target": "e",
            "allow_legacy_tls": True,
            "max_handshakes": 50,
            "resolve": ["e:443:10.0.0.1"],
        },
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
    assert len(TOOL_FUNCTIONS) == 17
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
    sleep = AsyncMock()
    async with open_session(call, max_reconnects=2, sleep=sleep) as (session, clients):
        assert await session.call("tool", {}) == '{"status": "ok"}'
        assert len(clients) == 2
        assert clients[0].exited == 1
    sleep.assert_awaited_once()


async def test_reconnects_exhausted(open_session):
    call = AsyncMock(side_effect=ConnectionResetError("gone"))
    async with open_session(call, max_reconnects=2) as (session, clients):
        with pytest.raises(DcertConnectionError, match="gone"):
            await session.call("tool", {})
        assert call.await_count == 3
        assert len(clients) == 3


async def test_reconnect_disabled_by_no_retry(open_session, config):
    call = AsyncMock(side_effect=ConnectionResetError("gone"))
    cfg = replace(config, retry_enabled=False, circuit_breaker_enabled=False)
    async with open_session(call, max_reconnects=2, resilience=cfg) as (session, clients):
        with pytest.raises(DcertConnectionError, match="gone"):
            await session.call("tool", {})
    assert call.await_count == 1
    assert len(clients) == 1


@pytest.mark.parametrize("annotations", [ISSUING, mt.ToolAnnotations(), None])
async def test_unsafe_tools_are_never_retried(open_session, annotations):
    """A call that may have issued a certificate must not run a second time."""
    call = AsyncMock(side_effect=[ConnectionResetError("gone"), OK])
    tools = [SimpleNamespace(name="vault_issue", annotations=annotations)]
    async with open_session(call, max_reconnects=3, tools=tools) as (session, clients):
        with pytest.raises(DcertConnectionError, match="gone"):
            await session.call("vault_issue", {})
        assert call.await_count == 1
        assert len(clients) == 1
        assert session.connected() is False


async def test_unlisted_tool_is_not_retried(open_session):
    call = AsyncMock(side_effect=[ConnectionResetError("gone"), OK])
    async with open_session(call, max_reconnects=3, tools=[]) as (session, _clients):
        with pytest.raises(DcertConnectionError, match="gone"):
            await session.call("tool", {})
    assert call.await_count == 1


async def test_tool_listing_is_read_once(open_session):
    listing = AsyncMock(return_value=SAFE_TOOLS)
    async with open_session(AsyncMock(return_value=OK), list_tools=listing) as (session, _c):
        await session.call("tool", {})
        await session.call("test_tool", {})
    listing.assert_awaited_once()


async def test_tool_listing_failure_disables_retry(open_session, caplog):
    call = AsyncMock(side_effect=[ConnectionResetError("gone"), OK])
    listing = AsyncMock(side_effect=RuntimeError("no listing"))
    async with open_session(call, max_reconnects=3, list_tools=listing) as (session, _c):
        with pytest.raises(DcertConnectionError, match="gone"):
            await session.call("tool", {})
    assert call.await_count == 1
    assert "Cannot list tools" in caplog.text


async def test_tool_listing_timeout_disables_retry(open_session, config):
    async def never(*_args, **_kwargs):
        await asyncio.sleep(10)

    call = AsyncMock(side_effect=[ConnectionResetError("gone"), OK])
    cfg = replace(config, connect_timeout=0.01)
    async with open_session(call, max_reconnects=3, list_tools=never, resilience=cfg) as (s, _c):
        with pytest.raises(DcertConnectionError, match="gone"):
            await s.call("tool", {})
    assert call.await_count == 1


async def test_concurrent_transport_loss_reconnects_once(open_session, config):
    """In flight calls that fail together share one reconnect and one breaker failure."""
    cfg = replace(config, circuit_breaker_enabled=True, circuit_breaker_threshold=2)
    release = asyncio.Event()
    arrived = asyncio.Event()
    failing = {"count": 0}

    async def call(_tool, _params, raise_on_error):
        if failing["count"] < 3:
            failing["count"] += 1
            if failing["count"] == 3:
                arrived.set()
            await release.wait()
            raise ConnectionResetError("gone")
        return OK

    async with open_session(call, max_reconnects=1, resilience=cfg) as (session, clients):
        tasks = [asyncio.create_task(session.call("tool", {})) for _ in range(3)]
        await arrived.wait()
        release.set()
        assert await asyncio.gather(*tasks) == ['{"status": "ok"}'] * 3
        assert len(clients) == 2
        assert clients[0].exited == 1
        # Only one failure was recorded, so a threshold of two leaves the breaker closed.
        assert await session.call("tool", {}) == '{"status": "ok"}'


async def test_timeout_disconnects_and_counts_against_breaker(open_session, config):
    async def slow(*_args, **_kwargs):
        await asyncio.sleep(1)

    cfg = replace(config, circuit_breaker_enabled=True, circuit_breaker_threshold=1)
    async with open_session(slow, timeout=0.01, resilience=cfg) as (session, clients):
        with pytest.raises(DcertTimeoutError):
            await session.call("tool", {})
        assert clients[0].exited == 1
        assert session.connected() is False
        with pytest.raises(DcertConnectionError, match="Circuit breaker is open"):
            await session.call("tool", {})


async def test_connect_timeout_at_session_start(config):
    class Hanging(FakeClient):
        async def __aenter__(self):
            await asyncio.sleep(10)

    cfg = replace(config, connect_timeout=0.01)
    with pytest.raises(ConnectionError, match="Connecting to dcert-mcp timed out after 0.01s"):
        async with create_session(
            binary_path="/fake/dcert-mcp",
            client_factory=lambda: Hanging(AsyncMock(return_value=OK)),
            resilience=cfg,
        ):
            pass


async def test_connect_timeout_on_reconnect(config):
    """A hung replacement subprocess surfaces as a connection error, not a tool timeout."""

    class Hanging(FakeClient):
        async def __aenter__(self):
            await asyncio.sleep(10)

    call = AsyncMock(side_effect=ConnectionResetError("gone"))
    clients: list[FakeClient] = []

    def factory():
        clients.append(Hanging(call) if clients else FakeClient(call))
        return clients[-1]

    cfg = replace(config, connect_timeout=0.01, circuit_breaker_enabled=False)
    async with create_session(
        binary_path="/fake/dcert-mcp",
        client_factory=factory,
        resilience=cfg,
        max_reconnects=1,
        sleep=AsyncMock(),
    ) as session:
        with pytest.raises(DcertConnectionError, match="Connecting to dcert-mcp timed out"):
            await session.call("tool", {})
    assert len(clients) == 2


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
    sleep = AsyncMock()
    async with open_session(AsyncMock(return_value=OK), resilience=cfg, sleep=sleep) as (s, _c):
        await s.call("tool", {})
        await s.call("tool", {})
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


def test_default_session_is_rebuilt_for_a_new_event_loop(monkeypatch, caplog):
    """A session from an earlier asyncio.run() holds a dead transport and is replaced."""
    created = []

    @asynccontextmanager
    async def fake_create_session(*_args, **_kwargs):
        async def call(tool, params, *, timeout=None):
            return "ok"

        session = Session(binary="/fake", call=call, connected=lambda: True)
        created.append(session)
        yield session

    monkeypatch.setattr(tools_mod, "create_session", fake_create_session)
    assert asyncio.run(call_tool("t", {})) == "ok"
    assert asyncio.run(call_tool("t", {})) == "ok"
    assert len(created) == 2
    assert "Dropping the default session of a previous event loop" in caplog.text
    asyncio.run(close_default_session())


@pytest.mark.parametrize("kwargs", [{}, {"policy": "P", "identify": True}])
async def test_tls_policy_test_needs_exactly_one_of_policy_or_identify(kwargs):
    with pytest.raises(ValueError, match="exactly one"):
        await tls_policy_test(target="e", **kwargs)
