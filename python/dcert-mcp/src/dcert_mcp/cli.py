"""Command line entry point of the FastMCP proxy (``dcert-mcp-proxy``).

The ``dcert`` and ``dcert-mcp`` commands are the Rust executables themselves,
installed as wheel scripts, so no Python runs for them.
"""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Literal

import click
from starlette.middleware import Middleware

from dcert_mcp.auth import AuthSettings, HostHeaderGuard, build_auth
from dcert_mcp.auth import allowed_hosts as build_allowed_hosts
from dcert_mcp.config import load_config
from dcert_mcp.resilience import OTelConfig, ResilienceConfig

_CONFIG = load_config()

#: The ``dcert-mcp`` setting that refuses private, loopback and metadata
#: destinations (``src/mcp/config.rs``).
DENY_PRIVATE_TARGETS_ENV = "DCERT_MCP_DENY_PRIVATE_TARGETS"
#: Transports FastMCP's ``run`` accepts; ``config.yaml`` lists the subset offered.
Transport = Literal["stdio", "http", "sse"]


def resilience_overrides(
    config: ResilienceConfig,
    *,
    no_retry: bool,
    no_circuit_breaker: bool,
    rate_limit: float | None,
    cache: bool,
    bulkhead_max: int | None,
) -> ResilienceConfig:
    """Return *config* with the CLI flags applied.

    Raises:
        ValueError: If a flag sets a value outside its valid range.
    """
    return replace(
        config,
        retry_enabled=config.retry_enabled and not no_retry,
        circuit_breaker_enabled=config.circuit_breaker_enabled and not no_circuit_breaker,
        rate_limit_enabled=config.rate_limit_enabled or rate_limit is not None,
        rate_limit_rps=config.rate_limit_rps if rate_limit is None else rate_limit,
        cache_enabled=config.cache_enabled or cache,
        bulkhead_max=config.bulkhead_max if bulkhead_max is None else bulkhead_max,
    )


def otel_overrides(config: OTelConfig, *, otel: bool, otel_exporter: str | None) -> OTelConfig:
    """Return *config* with the CLI flags applied."""
    return replace(
        config,
        enabled=config.enabled or otel,
        exporter=config.exporter if otel_exporter is None else otel_exporter,
    )


@click.command(name="dcert-mcp-proxy", context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--transport",
    type=click.Choice(_CONFIG.server.transports),
    default=_CONFIG.server.default_transport,
    show_default=True,
    help="Transport mode.",
)
@click.option(
    "--host",
    default=_CONFIG.server.host,
    show_default=True,
    help="Bind address for HTTP/SSE mode.",
)
@click.option(
    "--auth-token",
    envvar=_CONFIG.server.auth.token_env,
    show_envvar=True,
    default=None,
    help=(
        "Static bearer token required by HTTP/SSE mode "
        f"(at least {_CONFIG.server.auth.min_token_length} characters). "
        "Prefer the environment variable: a flag value is visible in process listings."
    ),
)
@click.option(
    "--oidc-issuer",
    envvar=_CONFIG.server.auth.oidc_issuer_env,
    show_envvar=True,
    default=None,
    help="OIDC issuer (https) whose access tokens HTTP/SSE mode accepts.",
)
@click.option(
    "--oidc-audience",
    envvar=_CONFIG.server.auth.oidc_audience_env,
    show_envvar=True,
    default=None,
    help="Audience the OIDC access tokens must carry.",
)
@click.option(
    "--oidc-jwks-uri",
    envvar=_CONFIG.server.auth.oidc_jwks_env,
    show_envvar=True,
    default=None,
    help="JWKS URL (https) with the OIDC signing keys.",
)
@click.option(
    "--allowed-hosts",
    multiple=True,
    metavar="HOST[,HOST...]",
    help=(
        "Extra Host header values HTTP/SSE mode accepts besides loopback and the "
        "bind address (repeatable or comma separated)."
    ),
)
@click.option(
    "--port",
    type=click.IntRange(1, 65535),
    default=_CONFIG.server.port,
    show_default=True,
    help="Port for HTTP/SSE mode.",
)
@click.option(
    "--binary",
    type=click.Path(exists=True, dir_okay=False, executable=True),
    default=None,
    help="Path to the dcert-mcp binary (found on PATH if not set).",
)
@click.option("--no-retry", is_flag=True, help="Disable automatic retry on connection errors.")
@click.option("--no-circuit-breaker", is_flag=True, help="Disable the circuit breaker.")
@click.option(
    "--rate-limit",
    type=click.FloatRange(min=0, min_open=True),
    default=None,
    metavar="RPS",
    help="Enable rate limiting at RPS requests per second (must be positive).",
)
@click.option("--cache", is_flag=True, help="Enable response caching.")
@click.option(
    "--bulkhead-max",
    type=click.IntRange(min=1),
    default=None,
    metavar="N",
    help=f"Maximum concurrent tool calls (default: {_CONFIG.resilience.bulkhead_max}).",
)
@click.option("--otel", is_flag=True, help="Enable OpenTelemetry tracing.")
@click.option(
    "--otel-exporter",
    type=click.Choice(_CONFIG.otel.exporters),
    default=None,
    help=f"OpenTelemetry exporter (default: {_CONFIG.otel.exporter}).",
)
def main(
    transport: Transport,
    host: str,
    auth_token: str | None,
    oidc_issuer: str | None,
    oidc_audience: str | None,
    oidc_jwks_uri: str | None,
    allowed_hosts: tuple[str, ...],
    port: int,
    binary: str | None,
    no_retry: bool,
    no_circuit_breaker: bool,
    rate_limit: float | None,
    cache: bool,
    bulkhead_max: int | None,
    otel: bool,
    otel_exporter: str | None,
) -> None:
    """Run the dcert MCP proxy server for TLS certificate analysis."""
    from dcert_mcp.resilience import otel_config_from_env, resilience_config_from_env, setup_otel
    from dcert_mcp.server import create_server

    try:
        resilience = resilience_overrides(
            resilience_config_from_env(),
            no_retry=no_retry,
            no_circuit_breaker=no_circuit_breaker,
            rate_limit=rate_limit,
            cache=cache,
            bulkhead_max=bulkhead_max,
        )
    except ValueError as exc:
        raise click.ClickException(f"invalid resilience setting: {exc}") from exc

    auth = None
    if transport != "stdio":
        settings = AuthSettings(
            token=auth_token or None,
            oidc_issuer=oidc_issuer or None,
            oidc_audience=oidc_audience or None,
            oidc_jwks_uri=oidc_jwks_uri or None,
        )
        try:
            auth = build_auth(settings, _CONFIG.server.auth)
        except ValueError as exc:
            raise click.ClickException(f"refusing to start: {exc}") from exc

    setup_otel(otel_overrides(otel_config_from_env(), otel=otel, otel_exporter=otel_exporter))
    try:
        server = create_server(
            binary_path=binary,
            env=child_policy_env(transport),
            resilience=resilience,
            auth=auth,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc

    if transport == "stdio":
        server.run()
    else:
        hosts = build_allowed_hosts(_CONFIG.server.loopback_hosts, host, allowed_hosts)
        server.run(
            transport=transport,
            host=host,
            port=port,
            middleware=[Middleware(HostHeaderGuard, hosts=hosts)],
        )


def child_policy_env(transport: str) -> dict[str, str]:
    """Return the destination policy defaults for the ``dcert-mcp`` child.

    The child always speaks stdio to this proxy, so it would choose its stdio
    default and allow private destinations. Served over HTTP or SSE, the
    proxy takes requests from the network, so private, loopback and metadata
    addresses are refused unless the operator set the variable themselves,
    as ``dcert-mcp --mode http`` does.
    """
    if transport == "stdio" or DENY_PRIVATE_TARGETS_ENV in os.environ:
        return {}
    return {DENY_PRIVATE_TARGETS_ENV: "1"}


if __name__ == "__main__":
    main()
