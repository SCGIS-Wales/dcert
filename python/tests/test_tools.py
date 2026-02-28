"""Tests for dcert async tool wrappers."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from dcert.resilience import ResilienceConfig
from dcert.tools import (
    DcertClient,
    DcertConnectionError,
    DcertError,
    DcertTimeoutError,
    DcertToolError,
    _extract_text,
    _validate_required,
)


def _make_stub_client(**overrides):
    """Create a DcertClient stub bypassing __init__ with resilience attrs set."""
    client = DcertClient.__new__(DcertClient)
    client._timeout = overrides.pop("timeout", 300.0)
    client._max_reconnects = overrides.pop("max_reconnects", 3)
    client._binary_path = overrides.pop("binary_path", "/fake/dcert-mcp")
    client._env = overrides.pop("env", None)
    client._resilience = overrides.pop(
        "resilience",
        ResilienceConfig(circuit_breaker_enabled=False, rate_limit_enabled=False),
    )
    client._semaphore = asyncio.Semaphore(client._resilience.bulkhead_max)
    client._circuit_breaker = None
    client._rate_limiter = None
    client._client = overrides.pop("mock_client", None)
    client._connected = overrides.pop("connected", True)
    return client


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Test the dcert exception class hierarchy."""

    def test_base_error(self):
        assert issubclass(DcertError, Exception)

    def test_timeout_is_dcert_error(self):
        assert issubclass(DcertTimeoutError, DcertError)

    def test_connection_is_dcert_error(self):
        assert issubclass(DcertConnectionError, DcertError)

    def test_tool_error_is_dcert_error(self):
        assert issubclass(DcertToolError, DcertError)

    def test_tool_error_attributes(self):
        err = DcertToolError("msg", tool="analyze_certificate", error_content=["err"])
        assert err.tool == "analyze_certificate"
        assert err.error_content == ["err"]
        assert str(err) == "msg"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestExtractText:
    """Test the _extract_text helper."""

    def test_single_text_content(self):
        item = SimpleNamespace(text="hello")
        assert _extract_text([item]) == "hello"

    def test_multiple_items_joins_text(self):
        items = [SimpleNamespace(text="a"), SimpleNamespace(text="b")]
        assert _extract_text(items) == "a\nb"

    def test_non_list_returns_raw(self):
        assert _extract_text("raw") == "raw"

    def test_empty_list_returns_raw(self):
        assert _extract_text([]) == []

    def test_single_item_no_text(self):
        item = SimpleNamespace(value=42)
        assert _extract_text([item]) == [item]


class TestValidateRequired:
    """Test the _validate_required helper."""

    def test_all_present(self):
        _validate_required({"a": 1, "b": 2}, ["a", "b"], "test_tool")

    def test_missing_raises(self):
        with pytest.raises(ValueError, match="test_tool.*'target'"):
            _validate_required({"other": 1}, ["target"], "test_tool")

    def test_none_value_raises(self):
        with pytest.raises(ValueError, match="'target'"):
            _validate_required({"target": None}, ["target"], "test_tool")


# ---------------------------------------------------------------------------
# Client lifecycle
# ---------------------------------------------------------------------------


class TestClientLifecycle:
    """Test DcertClient connect/disconnect."""

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager connects and disconnects."""
        with (
            patch("dcert.tools._find_binary", return_value="/fake/dcert-mcp"),
            patch("dcert.tools.Client") as mock_client_cls,
        ):
            mock_instance = AsyncMock()
            mock_client_cls.return_value = mock_instance

            async with DcertClient(binary_path="/fake/dcert-mcp") as client:
                assert client._connected is True
                mock_instance.__aenter__.assert_awaited_once()

            mock_instance.__aexit__.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_disconnect_on_error(self):
        """Test client disconnects even when __aexit__ raises."""
        with (
            patch("dcert.tools._find_binary", return_value="/fake/dcert-mcp"),
            patch("dcert.tools.Client") as mock_client_cls,
        ):
            mock_instance = AsyncMock()
            mock_instance.__aexit__.side_effect = RuntimeError("boom")
            mock_client_cls.return_value = mock_instance

            async with DcertClient(binary_path="/fake/dcert-mcp") as client:
                pass  # noqa: SIM105

            # Client should be disconnected despite error
            assert client._connected is False


# ---------------------------------------------------------------------------
# Tool calls — happy path
# ---------------------------------------------------------------------------


class TestToolCallHappyPath:
    """Test tool wrappers with successful results."""

    @pytest.fixture
    def mock_client(self):
        """Create a connected DcertClient with mocked transport."""
        mock = AsyncMock()
        text_result = SimpleNamespace(text='{"status": "ok"}')
        mock.call_tool = AsyncMock(return_value=[text_result])
        return _make_stub_client(mock_client=mock)

    @pytest.mark.asyncio
    async def test_analyze_certificate(self, mock_client):
        result = await mock_client.analyze_certificate(target="example.com")
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "analyze_certificate", {"target": "example.com"}
        )

    @pytest.mark.asyncio
    async def test_check_expiry(self, mock_client):
        result = await mock_client.check_expiry(target="example.com", days=60)
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "check_expiry", {"target": "example.com", "days": 60}
        )

    @pytest.mark.asyncio
    async def test_check_revocation(self, mock_client):
        result = await mock_client.check_revocation(target="example.com")
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "check_revocation", {"target": "example.com"}
        )

    @pytest.mark.asyncio
    async def test_compare_certificates(self, mock_client):
        result = await mock_client.compare_certificates(
            target_a="example.com", target_b="example.org"
        )
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "compare_certificates",
            {"target_a": "example.com", "target_b": "example.org"},
        )

    @pytest.mark.asyncio
    async def test_tls_connection_info(self, mock_client):
        result = await mock_client.tls_connection_info(target="example.com", min_tls="1.2")
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "tls_connection_info", {"target": "example.com", "min_tls": "1.2"}
        )

    @pytest.mark.asyncio
    async def test_export_pem(self, mock_client):
        result = await mock_client.export_pem(target="example.com", exclude_expired=True)
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "export_pem", {"target": "example.com", "exclude_expired": True}
        )

    @pytest.mark.asyncio
    async def test_verify_key_match(self, mock_client):
        result = await mock_client.verify_key_match(target="cert.pem", key_path="key.pem")
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "verify_key_match", {"target": "cert.pem", "key_path": "key.pem"}
        )

    @pytest.mark.asyncio
    async def test_convert_pfx_to_pem(self, mock_client):
        result = await mock_client.convert_pfx_to_pem(
            pkcs12_path="test.pfx", password="pass123", output_dir="/tmp/out"
        )
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "convert_pfx_to_pem",
            {"pkcs12_path": "test.pfx", "password": "pass123", "output_dir": "/tmp/out"},
        )

    @pytest.mark.asyncio
    async def test_convert_pem_to_pfx(self, mock_client):
        result = await mock_client.convert_pem_to_pfx(
            cert_path="cert.pem",
            key_path="key.pem",
            password="pass",
            output_path="out.pfx",
        )
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "convert_pem_to_pfx",
            {
                "cert_path": "cert.pem",
                "key_path": "key.pem",
                "password": "pass",
                "output_path": "out.pfx",
            },
        )

    @pytest.mark.asyncio
    async def test_create_keystore(self, mock_client):
        result = await mock_client.create_keystore(
            cert_path="cert.pem",
            key_path="key.pem",
            password="pass",
            output_path="keystore.p12",
            alias="mykey",
        )
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "create_keystore",
            {
                "cert_path": "cert.pem",
                "key_path": "key.pem",
                "password": "pass",
                "output_path": "keystore.p12",
                "alias": "mykey",
            },
        )

    @pytest.mark.asyncio
    async def test_create_truststore(self, mock_client):
        result = await mock_client.create_truststore(
            cert_paths=["ca1.pem", "ca2.pem"],
            output_path="truststore.p12",
            password="secret",
        )
        assert result == '{"status": "ok"}'
        mock_client._client.call_tool.assert_awaited_once_with(
            "create_truststore",
            {
                "cert_paths": ["ca1.pem", "ca2.pem"],
                "output_path": "truststore.p12",
                "password": "secret",
            },
        )


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------


class TestTimeout:
    """Test timeout behavior."""

    @pytest.mark.asyncio
    async def test_timeout_raises(self):
        mock = AsyncMock()
        mock.call_tool = AsyncMock(side_effect=asyncio.TimeoutError)
        client = _make_stub_client(timeout=0.01, max_reconnects=0, mock_client=mock)

        with pytest.raises(DcertTimeoutError, match="analyze_certificate.*timed out"):
            await client.analyze_certificate(target="example.com")


# ---------------------------------------------------------------------------
# Reconnection
# ---------------------------------------------------------------------------


class TestReconnection:
    """Test automatic reconnection on failure."""

    @pytest.mark.asyncio
    async def test_reconnect_on_connection_failure(self):
        mock = AsyncMock()
        text_result = SimpleNamespace(text="ok")
        # First call fails, second succeeds
        mock.call_tool = AsyncMock(side_effect=[RuntimeError("connection lost"), [text_result]])
        client = _make_stub_client(max_reconnects=2, mock_client=mock)

        # Patch _reconnect to just reset the connection
        async def fake_reconnect():
            client._connected = True

        client._reconnect = fake_reconnect

        result = await client._call("test_tool", {})
        assert result == "ok"


# ---------------------------------------------------------------------------
# Tool errors
# ---------------------------------------------------------------------------


class TestToolErrors:
    """Test MCP tool error handling."""

    @pytest.mark.asyncio
    async def test_error_content_raises(self):
        error_item = SimpleNamespace(type="error", text="something went wrong")
        mock = AsyncMock()
        mock.call_tool = AsyncMock(return_value=[error_item])
        client = _make_stub_client(max_reconnects=0, mock_client=mock)

        with pytest.raises(DcertToolError, match="something went wrong"):
            await client._call("test_tool", {})


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    """Test input validation for required parameters."""

    @pytest.mark.asyncio
    async def test_analyze_certificate_requires_target(self):
        client = _make_stub_client(max_reconnects=0)
        with pytest.raises(TypeError):
            await client.analyze_certificate()

    @pytest.mark.asyncio
    async def test_compare_certificates_requires_both(self):
        client = _make_stub_client(max_reconnects=0)
        with pytest.raises(TypeError):
            await client.compare_certificates(target_a="a")

    @pytest.mark.asyncio
    async def test_create_truststore_empty_paths(self):
        client = _make_stub_client(max_reconnects=0)
        with pytest.raises(ValueError, match="at least one cert_path"):
            await client.create_truststore(cert_paths=[], output_path="out.p12")


# ---------------------------------------------------------------------------
# All methods exist
# ---------------------------------------------------------------------------


class TestAllMethodsExist:
    """Verify all 11 tool wrapper methods exist."""

    EXPECTED_METHODS = [
        "analyze_certificate",
        "check_expiry",
        "check_revocation",
        "compare_certificates",
        "tls_connection_info",
        "export_pem",
        "verify_key_match",
        "convert_pfx_to_pem",
        "convert_pem_to_pfx",
        "create_keystore",
        "create_truststore",
    ]

    def test_all_methods_present(self):
        for method in self.EXPECTED_METHODS:
            assert hasattr(DcertClient, method), f"Missing method: {method}"
            assert callable(getattr(DcertClient, method))

    def test_method_count(self):
        methods = [
            m
            for m in dir(DcertClient)
            if not m.startswith("_") and callable(getattr(DcertClient, m))
        ]
        assert len(methods) == 11


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


class TestModuleLevelFunctions:
    """Test module-level convenience function imports."""

    def test_all_functions_importable(self):
        from dcert.tools import (
            analyze_certificate,
            check_expiry,
            check_revocation,
            compare_certificates,
            convert_pem_to_pfx,
            convert_pfx_to_pem,
            create_keystore,
            create_truststore,
            export_pem,
            tls_connection_info,
            verify_key_match,
        )

        funcs = [
            analyze_certificate,
            check_expiry,
            check_revocation,
            compare_certificates,
            tls_connection_info,
            export_pem,
            verify_key_match,
            convert_pfx_to_pem,
            convert_pem_to_pfx,
            create_keystore,
            create_truststore,
        ]
        assert all(callable(f) for f in funcs)
        assert len(funcs) == 11


# ---------------------------------------------------------------------------
# Concurrent calls
# ---------------------------------------------------------------------------


class TestConcurrentCalls:
    """Test concurrent tool calls on the same client."""

    @pytest.mark.asyncio
    async def test_concurrent_calls(self):
        text_result = SimpleNamespace(text="ok")
        mock = AsyncMock()
        mock.call_tool = AsyncMock(return_value=[text_result])
        client = _make_stub_client(max_reconnects=0, mock_client=mock)

        results = await asyncio.gather(
            client.analyze_certificate(target="a.com"),
            client.check_expiry(target="b.com"),
            client.tls_connection_info(target="c.com"),
        )
        assert len(results) == 3
        assert all(r == "ok" for r in results)
        assert mock.call_tool.await_count == 3
