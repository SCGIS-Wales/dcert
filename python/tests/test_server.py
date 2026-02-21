"""Tests for dcert server and client modules."""

import os
import platform
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------


def test_version():
    """Test package version is set."""
    from dcert import __version__

    assert __version__  # version is set (value managed by auto-tag)


def test_exports():
    """Test that public API is properly exported."""
    import dcert

    assert hasattr(dcert, "create_server")
    assert hasattr(dcert, "create_client")
    assert hasattr(dcert, "__version__")
    assert callable(dcert.create_server)
    assert callable(dcert.create_client)


def test_all_exports():
    """Test __all__ matches expected exports."""
    import dcert

    assert set(dcert.__all__) == {"create_server", "create_client", "__version__"}


def test_py_typed_marker():
    """Test PEP 561 py.typed marker exists."""
    import dcert

    pkg_dir = Path(dcert.__file__).parent
    assert (pkg_dir / "py.typed").exists()


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------


def test_find_binary_env_var(tmp_path):
    """Test binary discovery via DCERT_MCP_BINARY env var."""
    from dcert.server import _find_binary

    fake_binary = tmp_path / "dcert-mcp"
    fake_binary.write_text("#!/bin/sh\necho hello")
    fake_binary.chmod(0o755)

    with patch.dict(os.environ, {"DCERT_MCP_BINARY": str(fake_binary)}):
        result = _find_binary()
        assert result == str(fake_binary)


def test_find_binary_env_var_not_found():
    """Test error when DCERT_MCP_BINARY points to nonexistent file."""
    from dcert.server import _find_binary

    with (
        patch.dict(os.environ, {"DCERT_MCP_BINARY": "/nonexistent/dcert-mcp"}),
        pytest.raises(FileNotFoundError, match="DCERT_MCP_BINARY"),
    ):
        _find_binary()


def test_find_binary_env_var_not_executable(tmp_path):
    """Test error when DCERT_MCP_BINARY exists but is not executable."""
    from dcert.server import _find_binary

    fake_binary = tmp_path / "dcert-mcp"
    fake_binary.write_text("not executable")
    fake_binary.chmod(0o644)

    with (
        patch.dict(os.environ, {"DCERT_MCP_BINARY": str(fake_binary)}),
        pytest.raises(FileNotFoundError, match="DCERT_MCP_BINARY"),
    ):
        _find_binary()


def test_find_binary_path_lookup(tmp_path):
    """Test binary discovery via PATH."""
    from dcert.server import _find_binary

    fake_binary = tmp_path / "dcert-mcp"
    fake_binary.write_text("#!/bin/sh\necho hello")
    fake_binary.chmod(0o755)

    env = {k: v for k, v in os.environ.items() if k != "DCERT_MCP_BINARY"}
    env["PATH"] = f"{tmp_path}:{env.get('PATH', '')}"

    with (
        patch.dict(os.environ, env, clear=True),
        patch("dcert.download.ensure_binary", return_value=None),
    ):
        result = _find_binary()
        assert result == str(fake_binary)


def test_find_binary_not_found():
    """Test error when binary cannot be found."""
    from dcert.server import _find_binary

    env = {k: v for k, v in os.environ.items() if k != "DCERT_MCP_BINARY"}
    env["PATH"] = "/nonexistent"

    with (
        patch.dict(os.environ, env, clear=True),
        patch("dcert.download.ensure_binary", return_value=None),
        pytest.raises(FileNotFoundError, match="dcert-mcp binary not found"),
    ):
        _find_binary()


def test_find_binary_bundled(tmp_path):
    """Test binary discovery from bundled bin/ directory."""
    import dcert.server as server_mod
    from dcert.server import _find_binary

    pkg_dir = Path(server_mod.__file__).parent
    bin_dir = pkg_dir / "bin"
    bin_dir.mkdir(exist_ok=True)
    bundled = bin_dir / "dcert-mcp"
    bundled.write_text("#!/bin/sh\necho hello")
    bundled.chmod(0o755)

    try:
        env = {k: v for k, v in os.environ.items() if k != "DCERT_MCP_BINARY"}
        env["PATH"] = "/nonexistent"
        with patch.dict(os.environ, env, clear=True):
            result = _find_binary()
            assert result == str(bundled)
    finally:
        bundled.unlink()
        bin_dir.rmdir()


def test_find_binary_bundled_platform_specific(tmp_path):
    """Test platform-specific bundled binary discovery."""
    import dcert.server as server_mod
    from dcert.server import _find_binary

    pkg_dir = Path(server_mod.__file__).parent
    bin_dir = pkg_dir / "bin"
    bin_dir.mkdir(exist_ok=True)

    system = platform.system().lower()
    machine = platform.machine().lower()
    arch_map = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64", "amd64": "amd64"}
    arch = arch_map.get(machine, machine)
    binary_name = f"dcert-mcp-{system}-{arch}"

    bundled = bin_dir / binary_name
    bundled.write_text("#!/bin/sh\necho hello")
    bundled.chmod(0o755)

    try:
        env = {k: v for k, v in os.environ.items() if k != "DCERT_MCP_BINARY"}
        env["PATH"] = "/nonexistent"
        with patch.dict(os.environ, env, clear=True):
            result = _find_binary()
            assert result == str(bundled)
    finally:
        bundled.unlink()
        bin_dir.rmdir()


# ---------------------------------------------------------------------------
# Environment building
# ---------------------------------------------------------------------------


def test_build_subprocess_env_passthrough():
    """Test that _build_subprocess_env forwards expected variables."""
    from dcert.server import _build_subprocess_env

    test_vars = {
        "HTTP_PROXY": "http://proxy:8080",
        "HTTPS_PROXY": "http://proxy:8443",
        "NO_PROXY": "localhost,.internal",
        "HOME": "/home/user",
    }

    with patch.dict(os.environ, test_vars, clear=True):
        result = _build_subprocess_env()
        assert result["HTTP_PROXY"] == "http://proxy:8080"
        assert result["HTTPS_PROXY"] == "http://proxy:8443"
        assert result["NO_PROXY"] == "localhost,.internal"
        assert result["HOME"] == "/home/user"


def test_build_subprocess_env_extra_overrides():
    """Test that extra_env overrides passthrough values."""
    from dcert.server import _build_subprocess_env

    with patch.dict(os.environ, {"HOME": "/home/user"}, clear=True):
        result = _build_subprocess_env(extra_env={"HOME": "/override", "CUSTOM": "value"})
        assert result["HOME"] == "/override"
        assert result["CUSTOM"] == "value"


def test_build_subprocess_env_custom_passthrough():
    """Test _build_subprocess_env with a custom passthrough list."""
    from dcert.server import _build_subprocess_env

    with patch.dict(os.environ, {"FOO": "bar", "HOME": "/home/user"}, clear=True):
        result = _build_subprocess_env(passthrough=["FOO"])
        assert result == {"FOO": "bar"}
        assert "HOME" not in result


def test_build_subprocess_env_skips_unset():
    """Test that unset variables are not included."""
    from dcert.server import _build_subprocess_env

    with patch.dict(os.environ, {}, clear=True):
        result = _build_subprocess_env()
        assert result == {}


def test_build_subprocess_env_empty_extra():
    """Test passing empty extra_env dict."""
    from dcert.server import _build_subprocess_env

    with patch.dict(os.environ, {"HOME": "/home/user"}, clear=True):
        result = _build_subprocess_env(extra_env={})
        assert result["HOME"] == "/home/user"


# ---------------------------------------------------------------------------
# PASSTHROUGH_ENV_VARS completeness
# ---------------------------------------------------------------------------


def test_passthrough_env_vars_includes_proxy():
    """Test that PASSTHROUGH_ENV_VARS includes all proxy variants."""
    from dcert.server import PASSTHROUGH_ENV_VARS

    for var in ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"]:
        assert var in PASSTHROUGH_ENV_VARS, f"{var} missing from PASSTHROUGH_ENV_VARS"


def test_passthrough_env_vars_includes_tls():
    """Test that PASSTHROUGH_ENV_VARS includes TLS CA variables."""
    from dcert.server import PASSTHROUGH_ENV_VARS

    for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"]:
        assert var in PASSTHROUGH_ENV_VARS, f"{var} missing from PASSTHROUGH_ENV_VARS"


def test_passthrough_env_vars_includes_dcert():
    """Test that PASSTHROUGH_ENV_VARS includes dcert-specific variables."""
    from dcert.server import PASSTHROUGH_ENV_VARS

    for var in ["DCERT_PATH", "DCERT_MCP_TIMEOUT", "DCERT_MCP_CONNECTION_TIMEOUT"]:
        assert var in PASSTHROUGH_ENV_VARS, f"{var} missing from PASSTHROUGH_ENV_VARS"


# ---------------------------------------------------------------------------
# Server / Client creation
# ---------------------------------------------------------------------------


def test_create_server_with_binary(tmp_path):
    """Test create_server with explicit binary path."""
    from dcert.server import create_server

    fake_binary = tmp_path / "dcert-mcp"
    fake_binary.write_text("#!/bin/sh\necho hello")
    fake_binary.chmod(0o755)

    server = create_server(binary_path=str(fake_binary))
    assert server is not None


def test_create_server_custom_name(tmp_path):
    """Test create_server with a custom server name."""
    from dcert.server import create_server

    fake_binary = tmp_path / "dcert-mcp"
    fake_binary.write_text("#!/bin/sh\necho hello")
    fake_binary.chmod(0o755)

    server = create_server(binary_path=str(fake_binary), name="my-dcert")
    assert server is not None


def test_create_server_with_extra_env(tmp_path):
    """Test create_server with extra environment variables."""
    from dcert.server import create_server

    fake_binary = tmp_path / "dcert-mcp"
    fake_binary.write_text("#!/bin/sh\necho hello")
    fake_binary.chmod(0o755)

    server = create_server(
        binary_path=str(fake_binary),
        env={"CUSTOM_VAR": "custom_value"},
    )
    assert server is not None


def test_create_server_binary_not_found():
    """Test create_server raises when binary not found."""
    from dcert.server import create_server

    env = {k: v for k, v in os.environ.items() if k != "DCERT_MCP_BINARY"}
    env["PATH"] = "/nonexistent"

    with (
        patch.dict(os.environ, env, clear=True),
        patch("dcert.download.ensure_binary", return_value=None),
        pytest.raises(FileNotFoundError),
    ):
        create_server()


def test_create_client_with_binary(tmp_path):
    """Test create_client with explicit binary path."""
    from dcert.client import create_client

    fake_binary = tmp_path / "dcert-mcp"
    fake_binary.write_text("#!/bin/sh\necho hello")
    fake_binary.chmod(0o755)

    client = create_client(binary_path=str(fake_binary))
    assert client is not None


def test_create_client_with_extra_env(tmp_path):
    """Test create_client with extra environment variables."""
    from dcert.client import create_client

    fake_binary = tmp_path / "dcert-mcp"
    fake_binary.write_text("#!/bin/sh\necho hello")
    fake_binary.chmod(0o755)

    client = create_client(
        binary_path=str(fake_binary),
        env={"EXTRA_VAR": "extra"},
    )
    assert client is not None


def test_create_client_binary_not_found():
    """Test create_client raises when binary not found."""
    from dcert.client import create_client

    env = {k: v for k, v in os.environ.items() if k != "DCERT_MCP_BINARY"}
    env["PATH"] = "/nonexistent"

    with (
        patch.dict(os.environ, env, clear=True),
        patch("dcert.download.ensure_binary", return_value=None),
        pytest.raises(FileNotFoundError),
    ):
        create_client()


# ---------------------------------------------------------------------------
# CLI module
# ---------------------------------------------------------------------------


def test_cli_module_exists():
    """Test that CLI entry point module exists."""
    from dcert import cli

    assert hasattr(cli, "main")
    assert callable(cli.main)


def test_cli_help(capsys):
    """Test CLI --help exits cleanly."""
    from dcert.cli import main

    with (
        pytest.raises(SystemExit) as exc_info,
        patch("sys.argv", ["dcert-python", "--help"]),
    ):
        main()
    assert exc_info.value.code == 0


def test_cli_invalid_transport(capsys):
    """Test CLI rejects invalid transport."""
    from dcert.cli import main

    with (
        pytest.raises(SystemExit) as exc_info,
        patch("sys.argv", ["dcert-python", "--transport", "invalid"]),
    ):
        main()
    assert exc_info.value.code != 0


def test_cli_binary_not_found(capsys):
    """Test CLI exits with error when binary not found."""
    from dcert.cli import main

    env = {k: v for k, v in os.environ.items() if k != "DCERT_MCP_BINARY"}
    env["PATH"] = "/nonexistent"

    with (
        patch.dict(os.environ, env, clear=True),
        patch("dcert.download.ensure_binary", return_value=None),
        patch("sys.argv", ["dcert-python"]),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()
    assert exc_info.value.code == 1


def test_cli_stdio_transport(tmp_path):
    """Test CLI with stdio transport calls server.run()."""
    from unittest.mock import MagicMock

    from dcert.cli import main

    mock_server = MagicMock()

    fake_binary = tmp_path / "dcert-mcp"
    fake_binary.write_text("#!/bin/sh\necho hello")
    fake_binary.chmod(0o755)

    with (
        patch("sys.argv", ["dcert-python", "--binary", str(fake_binary)]),
        patch("dcert.server.create_server", return_value=mock_server) as mock_create,
    ):
        main()

    mock_create.assert_called_once_with(binary_path=str(fake_binary))
    mock_server.run.assert_called_once_with()


def test_cli_http_transport(tmp_path):
    """Test CLI with http transport passes host and port."""
    from unittest.mock import MagicMock

    from dcert.cli import main

    mock_server = MagicMock()

    fake_binary = tmp_path / "dcert-mcp"
    fake_binary.write_text("#!/bin/sh\necho hello")
    fake_binary.chmod(0o755)

    with (
        patch(
            "sys.argv",
            [
                "dcert-python",
                "--binary",
                str(fake_binary),
                "--transport",
                "http",
                "--host",
                "127.0.0.1",
                "--port",
                "9090",
            ],
        ),
        patch("dcert.server.create_server", return_value=mock_server),
    ):
        main()

    mock_server.run.assert_called_once_with(transport="http", host="127.0.0.1", port=9090)
