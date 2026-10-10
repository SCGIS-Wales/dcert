"""Command line entry points.

- ``dcert`` and ``dcert-mcp`` replace the current process with the Rust
  binary of the same name, forwarding every argument.
- ``dcert-python`` runs the FastMCP proxy server.
"""

from __future__ import annotations

import os
import sys
from dataclasses import replace
from typing import Literal

import click

from dcert.binary import find_binary, is_running_script
from dcert.config import load_config
from dcert.resilience import OTelConfig, ResilienceConfig

_CONFIG = load_config()
#: Transports FastMCP's ``run`` accepts; ``config.yaml`` lists the subset offered.
Transport = Literal["stdio", "http", "sse"]


def _notify(message: str) -> None:
    """Print a progress message from the library on stderr."""
    click.echo(message, err=True)


def exec_binary(name: str) -> None:
    """Replace the current process with the Rust binary *name*.

    Exits with status 1 and a message on stderr when the binary cannot be
    resolved, a downloaded archive fails verification, or the resolved path
    is this very wrapper script (which would exec itself forever).
    """
    try:
        binary = find_binary(name, notify=_notify)
    except (FileNotFoundError, RuntimeError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    if is_running_script(binary):
        binaries = _CONFIG.binaries
        variable = binaries.env.get(name, binaries.fallback_env)
        click.echo(
            f"Error: {name} resolved to this wrapper script ({binary}), refusing to exec "
            f"itself. Set {variable} to the compiled binary or run: dcert-python --setup",
            err=True,
        )
        sys.exit(1)
    # The path comes from the trusted resolver, not from user input, and is
    # absolute or a PATH hit, so no further lookup happens here.
    os.execv(binary, [binary, *sys.argv[1:]])  # noqa: S606


def dcert_main() -> None:
    """Entry point for the ``dcert`` command."""
    exec_binary("dcert")


def dcert_mcp_main() -> None:
    """Entry point for the ``dcert-mcp`` command."""
    exec_binary("dcert-mcp")


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


def run_setup() -> None:
    """Download the ``dcert-mcp`` binary and report where it was installed."""
    from dcert import __version__
    from dcert.download import ensure_binary

    try:
        path = ensure_binary(__version__, notify=_notify)
    except (OSError, RuntimeError) as exc:
        raise click.ClickException(f"downloading binary failed: {exc}") from exc
    if path is None:
        raise click.ClickException(
            "No checksums available for this platform. Install the binary manually."
        )
    click.echo(f"dcert-mcp binary ready at: {path}")


@click.command(name="dcert-python", context_settings={"help_option_names": ["-h", "--help"]})
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
    help=(
        "Bind address for HTTP/SSE mode. The proxy has no authentication; "
        "bind to 0.0.0.0 only behind a trusted gateway."
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
    help="Path to the dcert-mcp binary (auto detected if not set).",
)
@click.option("--setup", is_flag=True, help="Download the dcert-mcp binary and exit.")
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
    port: int,
    binary: str | None,
    setup: bool,
    no_retry: bool,
    no_circuit_breaker: bool,
    rate_limit: float | None,
    cache: bool,
    bulkhead_max: int | None,
    otel: bool,
    otel_exporter: str | None,
) -> None:
    """Run the dcert MCP proxy server for TLS certificate analysis."""
    if setup:
        run_setup()
        return

    from dcert.resilience import otel_config_from_env, resilience_config_from_env, setup_otel
    from dcert.server import create_server

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

    setup_otel(otel_overrides(otel_config_from_env(), otel=otel, otel_exporter=otel_exporter))
    try:
        server = create_server(binary_path=binary, resilience=resilience)
    except (FileNotFoundError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc

    if transport == "stdio":
        server.run()
    else:
        server.run(transport=transport, host=host, port=port)


if __name__ == "__main__":
    main()
