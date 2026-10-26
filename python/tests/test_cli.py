"""Tests for dcert.cli using click's CliRunner."""

from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from fastmcp.server.auth.providers.jwt import JWTVerifier

from dcert import cli
from dcert.auth import BearerTokenVerifier, HostHeaderGuard
from dcert.cli import dcert_main, dcert_mcp_main, main, otel_overrides, resilience_overrides
from dcert.resilience import OTelConfig, resilience_config_from_env


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
def isolated_env(clean_env):
    """Alias of the shared ``clean_env`` fixture, kept for readability here."""


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


def test_binary_must_be_executable(runner, tmp_path):
    plain = tmp_path / "dcert-mcp"
    plain.write_text("not executable")
    plain.chmod(0o644)
    result = runner.invoke(main, ["--binary", str(plain)])
    assert result.exit_code == 2
    assert "--binary" in result.output
    assert "executable" in result.output


def test_choices_come_from_config(runner):
    result = runner.invoke(main, ["--help"])
    assert f"[{'|'.join(cli._CONFIG.server.transports)}]" in result.output
    assert f"[{'|'.join(cli._CONFIG.otel.exporters)}]" in result.output
    assert f"default: {cli._CONFIG.server.default_transport}" in result.output


TOKEN = "t" * 40


def test_stdio_transport(runner, fake_binary, isolated_env):
    server = MagicMock()
    with patch("dcert.server.create_server", return_value=server) as create:
        result = runner.invoke(main, ["--binary", fake_binary])
    assert result.exit_code == 0, result.output
    create.assert_called_once_with(
        binary_path=fake_binary, resilience=resilience_config_from_env(), auth=None
    )
    server.run.assert_called_once_with()


def _run_kwargs(server):
    """Return the keyword arguments of the single ``server.run`` call."""
    server.run.assert_called_once()
    return server.run.call_args.kwargs


def test_http_transport(runner, fake_binary, isolated_env, monkeypatch):
    monkeypatch.setenv(cli._CONFIG.server.auth.token_env, TOKEN)
    server = MagicMock()
    args = ["--binary", fake_binary, "--transport", "http", "--host", "127.0.0.1", "--port", "9090"]
    with patch("dcert.server.create_server", return_value=server) as create:
        result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    assert isinstance(create.call_args.kwargs["auth"], BearerTokenVerifier)
    kwargs = _run_kwargs(server)
    assert (kwargs["transport"], kwargs["host"], kwargs["port"]) == ("http", "127.0.0.1", 9090)
    (guard,) = kwargs["middleware"]
    assert guard.cls is HostHeaderGuard
    assert guard.kwargs["hosts"] == frozenset({"127.0.0.1", "localhost", "::1"})


def test_defaults_come_from_config(runner, fake_binary, isolated_env):
    server = MagicMock()
    with patch("dcert.server.create_server", return_value=server):
        result = runner.invoke(
            main, ["--binary", fake_binary, "--transport", "sse", "--auth-token", TOKEN]
        )
    assert result.exit_code == 0, result.output
    kwargs = _run_kwargs(server)
    assert (kwargs["transport"], kwargs["host"], kwargs["port"]) == (
        "sse",
        cli._CONFIG.server.host,
        cli._CONFIG.server.port,
    )


@pytest.mark.parametrize("transport", ["http", "sse"])
def test_network_transports_refuse_to_start_without_auth(
    runner, fake_binary, isolated_env, transport
):
    with patch("dcert.server.create_server") as create:
        result = runner.invoke(main, ["--binary", fake_binary, "--transport", transport])
    assert result.exit_code == 1
    assert "refusing to start" in result.output
    assert cli._CONFIG.server.auth.token_env in result.output
    create.assert_not_called()


def test_short_token_is_refused(runner, fake_binary, isolated_env):
    result = runner.invoke(
        main, ["--binary", fake_binary, "--transport", "http", "--auth-token", "short"]
    )
    assert result.exit_code == 1
    assert "at least" in result.output


def test_oidc_configuration_builds_a_jwt_verifier(runner, fake_binary, isolated_env):
    server = MagicMock()
    args = [
        "--binary",
        fake_binary,
        "--transport",
        "http",
        "--oidc-issuer",
        "https://idp.example.com",
        "--oidc-audience",
        "dcert",
        "--oidc-jwks-uri",
        "https://idp.example.com/keys",
        "--host",
        "0.0.0.0",
        "--allowed-hosts",
        "mcp.example.com,Other.Example.com",
    ]
    with patch("dcert.server.create_server", return_value=server) as create:
        result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    assert isinstance(create.call_args.kwargs["auth"], JWTVerifier)
    hosts = _run_kwargs(server)["middleware"][0].kwargs["hosts"]
    assert {"mcp.example.com", "other.example.com", "localhost"} <= hosts
    assert "0.0.0.0" not in hosts


def test_flags_override_the_configuration(runner, fake_binary, isolated_env):
    seen = {}

    def capture(**kwargs):
        seen.update(kwargs)
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
    assert seen["resilience"] == replace(
        resilience_config_from_env(),
        retry_enabled=False,
        circuit_breaker_enabled=False,
        rate_limit_enabled=True,
        rate_limit_rps=5.5,
        cache_enabled=True,
        bulkhead_max=4,
    )
    assert setup.call_args.args[0] == OTelConfig(True, cli._CONFIG.otel.service_name, "otlp")


def test_overrides_without_flags_are_identity(isolated_env):
    cfg = resilience_config_from_env()
    assert (
        resilience_overrides(
            cfg,
            no_retry=False,
            no_circuit_breaker=False,
            rate_limit=None,
            cache=False,
            bulkhead_max=None,
        )
        == cfg
    )
    otel = OTelConfig(enabled=False, service_name="svc", exporter="console")
    assert otel_overrides(otel, otel=False, otel_exporter=None) == otel


def test_invalid_environment_value_is_a_clean_error(runner, fake_binary, isolated_env, monkeypatch):
    """A bad DCERT_MCP_* value names the variable instead of printing a traceback."""
    monkeypatch.setenv("DCERT_MCP_CB_THRESHOLD", "0")
    with patch("dcert.server.create_server") as create:
        result = runner.invoke(main, ["--binary", fake_binary])
    assert result.exit_code == 1
    assert "DCERT_MCP_CB_THRESHOLD must be at least 1, got 0" in result.output
    assert "Traceback" not in result.output
    create.assert_not_called()


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

    def ensure(_version, notify=None):
        notify("Downloading dcert binaries from https://example.invalid/x")
        return fake_path

    with patch("dcert.download.ensure_binary", side_effect=ensure) as ensure_binary:
        result = runner.invoke(main, ["--setup"])
    assert result.exit_code == 0
    assert fake_path in result.output
    assert "Downloading dcert binaries" in result.output
    ensure_binary.assert_called_once()


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
        patch("dcert.cli.os.execv") as execv,
        patch("dcert.cli.sys.argv", [name, "--version", "x"]),
    ):
        entry()
    find.assert_called_once_with(name, notify=cli._notify)
    execv.assert_called_once_with(binary, [binary, "--version", "x"])


@pytest.mark.parametrize("exc", [FileNotFoundError("not found"), RuntimeError("integrity")])
def test_exec_wrapper_errors(capsys, exc):
    with (
        patch("dcert.cli.find_binary", side_effect=exc),
        patch("dcert.cli.os.execv") as execv,
        pytest.raises(SystemExit) as info,
    ):
        dcert_main()
    assert info.value.code == 1
    assert f"Error: {exc}" in capsys.readouterr().err
    execv.assert_not_called()


def test_exec_wrapper_refuses_to_exec_itself(capsys, fake_binary):
    """The resolver handing back the running wrapper must not become an exec loop."""
    with (
        patch("dcert.cli.find_binary", return_value=fake_binary),
        patch("dcert.cli.os.execv") as execv,
        patch("dcert.cli.sys.argv", [fake_binary, "--version"]),
        pytest.raises(SystemExit) as info,
    ):
        dcert_mcp_main()
    assert info.value.code == 1
    err = capsys.readouterr().err
    assert "refusing to exec itself" in err
    assert "DCERT_MCP_BINARY" in err
    execv.assert_not_called()


def test_exec_wrapper_prints_download_progress(capsys, fake_binary):
    def find(name, notify=None):
        notify(f"Downloading {name}")
        return fake_binary

    with (
        patch("dcert.cli.find_binary", side_effect=find),
        patch("dcert.cli.os.execv"),
        patch("dcert.cli.sys.argv", ["dcert"]),
    ):
        dcert_main()
    assert "Downloading dcert" in capsys.readouterr().err
