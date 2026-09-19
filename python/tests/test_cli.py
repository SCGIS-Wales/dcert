"""Tests for dcert.cli using click's CliRunner."""

import os
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from dcert import cli
from dcert.cli import dcert_main, dcert_mcp_main, environment_overrides, main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def fake_binary(tmp_path):
    binary = tmp_path / "dcert-mcp"
    binary.write_text("#!/bin/sh\necho hello")
    binary.chmod(0o755)
    return str(binary)


@pytest.fixture
def isolated_env():
    with patch.dict(os.environ, {}, clear=False):
        for name in list(os.environ):
            if name.startswith("DCERT_MCP_"):
                del os.environ[name]
        yield


# ---------------------------------------------------------------------------
# dcert-python
# ---------------------------------------------------------------------------


def test_help(runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "--transport" in result.output
    assert "--rate-limit" in result.output


def test_invalid_transport(runner):
    result = runner.invoke(main, ["--transport", "invalid"])
    assert result.exit_code == 2
    assert "Invalid value for '--transport'" in result.output


@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_rate_limit_must_be_positive(runner, value):
    result = runner.invoke(main, ["--rate-limit", value])
    assert result.exit_code == 2
    assert "--rate-limit" in result.output


@pytest.mark.parametrize(
    ("option", "value"), [("--port", "0"), ("--port", "70000"), ("--bulkhead-max", "0")]
)
def test_range_validation(runner, option, value):
    result = runner.invoke(main, [option, value])
    assert result.exit_code == 2
    assert option in result.output


def test_binary_must_exist(runner):
    result = runner.invoke(main, ["--binary", "/nonexistent/dcert-mcp"])
    assert result.exit_code == 2
    assert "--binary" in result.output


def test_stdio_transport(runner, fake_binary, isolated_env):
    server = MagicMock()
    with patch("dcert.server.create_server", return_value=server) as create:
        result = runner.invoke(main, ["--binary", fake_binary])
    assert result.exit_code == 0, result.output
    create.assert_called_once_with(binary_path=fake_binary)
    server.run.assert_called_once_with()


def test_http_transport(runner, fake_binary, isolated_env):
    server = MagicMock()
    args = ["--binary", fake_binary, "--transport", "http", "--host", "127.0.0.1", "--port", "9090"]
    with patch("dcert.server.create_server", return_value=server):
        result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    server.run.assert_called_once_with(transport="http", host="127.0.0.1", port=9090)


def test_defaults_come_from_config(runner, fake_binary, isolated_env):
    server = MagicMock()
    with patch("dcert.server.create_server", return_value=server):
        runner.invoke(main, ["--binary", fake_binary, "--transport", "sse"])
    server.run.assert_called_once_with(
        transport="sse", host=cli._CONFIG.server.host, port=cli._CONFIG.server.port
    )


def test_flags_bridge_to_environment(runner, fake_binary, isolated_env):
    seen = {}

    def capture(**_kwargs):
        seen.update({k: v for k, v in os.environ.items() if k.startswith("DCERT_MCP_")})
        return MagicMock()

    args = [
        "--binary",
        fake_binary,
        "--no-retry",
        "--no-circuit-breaker",
        "--rate-limit",
        "5.5",
        "--cache",
        "--bulkhead-max",
        "4",
        "--otel",
        "--otel-exporter",
        "otlp",
    ]
    with (
        patch("dcert.server.create_server", side_effect=capture),
        patch("dcert.resilience.setup_otel") as setup,
    ):
        result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    assert seen == {
        "DCERT_MCP_NO_RETRY": "1",
        "DCERT_MCP_NO_CIRCUIT_BREAKER": "1",
        "DCERT_MCP_RATE_LIMIT_ENABLED": "1",
        "DCERT_MCP_RATE_LIMIT_RPS": "5.5",
        "DCERT_MCP_CACHE_ENABLED": "1",
        "DCERT_MCP_BULKHEAD_MAX": "4",
        "DCERT_MCP_OTEL_ENABLED": "1",
        "DCERT_MCP_OTEL_EXPORTER": "otlp",
    }
    otel_config = setup.call_args.args[0]
    assert otel_config.enabled is True
    assert otel_config.exporter == "otlp"


def test_environment_overrides_empty():
    assert (
        environment_overrides(
            no_retry=False,
            no_circuit_breaker=False,
            rate_limit=None,
            cache=False,
            bulkhead_max=None,
            otel=False,
            otel_exporter=None,
        )
        == {}
    )


def test_binary_not_found(runner, isolated_env):
    with patch(
        "dcert.server.create_server", side_effect=FileNotFoundError("dcert-mcp binary not found")
    ):
        result = runner.invoke(main, [])
    assert result.exit_code == 1
    assert "Error: dcert-mcp binary not found" in result.output


def test_checksum_failure_reported(runner, isolated_env):
    with patch("dcert.server.create_server", side_effect=RuntimeError("integrity verification")):
        result = runner.invoke(main, [])
    assert result.exit_code == 1
    assert "integrity verification" in result.output


# ---------------------------------------------------------------------------
# --setup
# ---------------------------------------------------------------------------


def test_setup_success(runner, tmp_path):
    fake_path = str(tmp_path / "dcert-mcp")
    with patch("dcert.download.ensure_binary", return_value=fake_path) as ensure:
        result = runner.invoke(main, ["--setup"])
    assert result.exit_code == 0
    assert fake_path in result.output
    ensure.assert_called_once()


def test_setup_no_checksums(runner):
    with patch("dcert.download.ensure_binary", return_value=None):
        result = runner.invoke(main, ["--setup"])
    assert result.exit_code == 1
    assert "No checksums available" in result.output


@pytest.mark.parametrize("exc", [RuntimeError("Checksum mismatch"), OSError("network down")])
def test_setup_download_error(runner, exc):
    with patch("dcert.download.ensure_binary", side_effect=exc):
        result = runner.invoke(main, ["--setup"])
    assert result.exit_code == 1
    assert str(exc) in result.output


# ---------------------------------------------------------------------------
# dcert / dcert-mcp exec wrappers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("entry", "name"), [(dcert_main, "dcert"), (dcert_mcp_main, "dcert-mcp")])
def test_exec_wrappers(entry, name, tmp_path):
    binary = str(tmp_path / name)
    with (
        patch("dcert.cli.find_binary", return_value=binary) as find,
        patch("dcert.cli.os.execvp") as execvp,
        patch("dcert.cli.sys.argv", [name, "--version", "x"]),
    ):
        entry()
    find.assert_called_once_with(name)
    execvp.assert_called_once_with(binary, [binary, "--version", "x"])


@pytest.mark.parametrize("exc", [FileNotFoundError("not found"), RuntimeError("integrity")])
def test_exec_wrapper_errors(capsys, exc):
    with (
        patch("dcert.cli.find_binary", side_effect=exc),
        patch("dcert.cli.os.execvp") as execvp,
        pytest.raises(SystemExit) as info,
    ):
        dcert_main()
    assert info.value.code == 1
    assert f"Error: {exc}" in capsys.readouterr().err
    execvp.assert_not_called()
