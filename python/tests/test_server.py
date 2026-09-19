"""Tests for the package surface, dcert.server and dcert.client."""

from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from fastmcp.server.middleware.caching import ResponseCachingMiddleware

import dcert
from dcert.client import create_client
from dcert.middleware import ResilienceMiddleware
from dcert.resilience import resilience_config_from_env
from dcert.server import (
    PASSTHROUGH_ENV_VARS,
    build_subprocess_env,
    create_server,
    create_transport,
)

# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------


def test_version():
    assert dcert.__version__


def test_all_exports_resolve():
    for name in dcert.__all__:
        assert hasattr(dcert, name), name


def test_all_exports_content():
    exports = set(dcert.__all__)
    for name in [
        "create_server",
        "create_client",
        "__version__",
        "Session",
        "create_session",
        "DcertError",
        "DcertTimeoutError",
        "DcertConnectionError",
        "DcertToolError",
        "ResilienceConfig",
        "resilience_config_from_env",
        "OTelConfig",
        "CircuitBreaker",
        "CircuitBreakerOpen",
        "create_circuit_breaker",
        "RateLimiter",
        "create_rate_limiter",
        "backoff_delays",
        "setup_otel",
        "truncate_response",
    ]:
        assert name in exports, name
    for tool in [
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
    ]:
        assert tool in exports, tool
    assert "DcertClient" not in exports


def test_py_typed_and_config_shipped():
    pkg_dir = Path(dcert.__file__).parent
    assert (pkg_dir / "py.typed").exists()
    assert (pkg_dir / "config.yaml").exists()


# ---------------------------------------------------------------------------
# Environment building
# ---------------------------------------------------------------------------


def test_build_subprocess_env_passthrough():
    env = {
        "HTTP_PROXY": "http://proxy:8080",
        "HTTPS_PROXY": "http://proxy:8443",
        "NO_PROXY": "localhost,.internal",
        "HOME": "/home/user",
        "SECRET_TOKEN": "nope",
    }
    with patch.dict("os.environ", env, clear=True):
        result = build_subprocess_env()
    assert result == {k: v for k, v in env.items() if k != "SECRET_TOKEN"}


def test_build_subprocess_env_extra_overrides():
    with patch.dict("os.environ", {"HOME": "/home/user"}, clear=True):
        result = build_subprocess_env(extra_env={"HOME": "/override", "CUSTOM": "value"})
    assert result == {"HOME": "/override", "CUSTOM": "value"}


def test_build_subprocess_env_custom_passthrough():
    with patch.dict("os.environ", {"FOO": "bar", "HOME": "/home/user"}, clear=True):
        assert build_subprocess_env(passthrough=["FOO"]) == {"FOO": "bar"}
        assert build_subprocess_env(passthrough=[]) == {}


def test_build_subprocess_env_skips_unset():
    with patch.dict("os.environ", {}, clear=True):
        assert build_subprocess_env() == {}
        assert build_subprocess_env(extra_env={}) == {}


@pytest.mark.parametrize(
    "var",
    [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "DCERT_PATH",
        "DCERT_MCP_TIMEOUT",
        "DCERT_MCP_CONNECTION_TIMEOUT",
    ],
)
def test_passthrough_env_vars(var):
    assert var in PASSTHROUGH_ENV_VARS


# ---------------------------------------------------------------------------
# Server and client creation
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_binary(tmp_path):
    binary = tmp_path / "dcert-mcp"
    binary.write_text("#!/bin/sh\necho hello")
    binary.chmod(0o755)
    return binary


@pytest.fixture
def no_binary(monkeypatch):
    monkeypatch.delenv("DCERT_MCP_BINARY", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent")
    with (
        patch("dcert.binary.find_bundled_binary", return_value=None),
        patch("dcert.download.ensure_binary", return_value=None),
    ):
        yield


def test_create_transport_explicit(fake_binary):
    transport = create_transport(str(fake_binary), {"EXTRA": "1"})
    assert transport.command == str(fake_binary)
    assert transport.env is not None
    assert transport.env["EXTRA"] == "1"


def test_create_transport_auto_detect(fake_binary, monkeypatch):
    monkeypatch.setenv("DCERT_MCP_BINARY", str(fake_binary))
    assert create_transport(None, None).command == str(fake_binary)


def _dcert_middleware(server):
    """Our middleware in registration order (fastmcp adds its own as well)."""
    ours = (ResponseCachingMiddleware, ResilienceMiddleware)
    return [type(m) for m in server.middleware if isinstance(m, ours)]


def test_create_server_with_binary(fake_binary):
    server = create_server(binary_path=str(fake_binary))
    assert server.name == "dcert-mcp"
    assert _dcert_middleware(server) == [ResilienceMiddleware]


def test_create_server_custom_name_and_env(fake_binary):
    server = create_server(binary_path=str(fake_binary), name="my-dcert", env={"X": "1"})
    assert server.name == "my-dcert"


def test_create_server_with_cache(fake_binary, monkeypatch):
    monkeypatch.delenv("DCERT_MCP_CACHE_ENABLED", raising=False)
    cfg = replace(resilience_config_from_env(), cache_enabled=True)
    server = create_server(binary_path=str(fake_binary), resilience=cfg)
    assert _dcert_middleware(server) == [ResponseCachingMiddleware, ResilienceMiddleware]


def test_create_server_binary_not_found(no_binary):
    with pytest.raises(FileNotFoundError, match="dcert-mcp binary not found"):
        create_server()


def test_create_client_with_binary(fake_binary):
    client = create_client(binary_path=str(fake_binary), env={"EXTRA_VAR": "extra"})
    assert client.transport.command == str(fake_binary)


def test_create_client_binary_not_found(no_binary):
    with pytest.raises(FileNotFoundError, match="dcert-mcp binary not found"):
        create_client()
