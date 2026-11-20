"""Tests for dcert_mcp.cli using click's CliRunner."""

from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from fastmcp.server.auth.providers.jwt import JWTVerifier

from dcert_mcp import cli
from dcert_mcp.auth import BearerTokenVerifier, HostHeaderGuard
from dcert_mcp.cli import main, otel_overrides, resilience_overrides
from dcert_mcp.resilience import OTelConfig, resilience_config_from_env


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
# dcert-mcp-proxy
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
    with patch("dcert_mcp.server.create_server", return_value=server) as create:
        result = runner.invoke(main, ["--binary", fake_binary])
    assert result.exit_code == 0, result.output
    create.assert_called_once_with(
        binary_path=fake_binary, env={}, resilience=resilience_config_from_env(), auth=None
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
    with patch("dcert_mcp.server.create_server", return_value=server) as create:
        result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    assert isinstance(create.call_args.kwargs["auth"], BearerTokenVerifier)
    kwargs = _run_kwargs(server)
    assert (kwargs["transport"], kwargs["host"], kwargs["port"]) == ("http", "127.0.0.1", 9090)
    (guard,) = kwargs["middleware"]
    assert guard.cls is HostHeaderGuard
    assert guard.kwargs["hosts"] == frozenset({"127.0.0.1", "localhost", "::1"})


def test_network_transports_deny_private_targets_in_the_child(
    runner, fake_binary, isolated_env, monkeypatch
):
    monkeypatch.setenv(cli._CONFIG.server.auth.token_env, TOKEN)
    monkeypatch.delenv(cli.DENY_PRIVATE_TARGETS_ENV, raising=False)
    for transport in ("http", "sse"):
        with patch("dcert_mcp.server.create_server", return_value=MagicMock()) as create:
            result = runner.invoke(main, ["--binary", fake_binary, "--transport", transport])
        assert result.exit_code == 0, result.output
        assert create.call_args.kwargs["env"] == {cli.DENY_PRIVATE_TARGETS_ENV: "1"}


def test_operator_choice_of_private_targets_is_kept(runner, fake_binary, isolated_env, monkeypatch):
    monkeypatch.setenv(cli._CONFIG.server.auth.token_env, TOKEN)
    monkeypatch.setenv(cli.DENY_PRIVATE_TARGETS_ENV, "0")
    with patch("dcert_mcp.server.create_server", return_value=MagicMock()) as create:
        result = runner.invoke(main, ["--binary", fake_binary, "--transport", "http"])
    assert result.exit_code == 0, result.output
    assert create.call_args.kwargs["env"] == {}


def test_defaults_come_from_config(runner, fake_binary, isolated_env):
    server = MagicMock()
    with patch("dcert_mcp.server.create_server", return_value=server):
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
    with patch("dcert_mcp.server.create_server") as create:
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
    with patch("dcert_mcp.server.create_server", return_value=server) as create:
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
        patch("dcert_mcp.server.create_server", side_effect=capture),
        patch("dcert_mcp.resilience.setup_otel") as setup,
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
    with patch("dcert_mcp.server.create_server") as create:
        result = runner.invoke(main, ["--binary", fake_binary])
    assert result.exit_code == 1
    assert "DCERT_MCP_CB_THRESHOLD must be at least 1, got 0" in result.output
    assert "Traceback" not in result.output
    create.assert_not_called()


def test_binary_not_found(runner, isolated_env):
    with patch(
        "dcert_mcp.server.create_server",
        side_effect=FileNotFoundError("dcert-mcp binary not found"),
    ):
        result = runner.invoke(main, [])
    assert result.exit_code == 1
    assert "Error: dcert-mcp binary not found" in result.output


def test_checksum_failure_reported(runner, isolated_env):
    with patch(
        "dcert_mcp.server.create_server", side_effect=RuntimeError("integrity verification")
    ):
        result = runner.invoke(main, [])
    assert result.exit_code == 1
    assert "integrity verification" in result.output
