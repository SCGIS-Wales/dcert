"""Command line entry points.

- ``dcert`` and ``dcert-mcp`` replace the current process with the Rust
  binary of the same name, forwarding every argument.
- ``dcert-python`` runs the FastMCP proxy server.
"""

from __future__ import annotations

import os
import sys
from typing import Literal

import click

from dcert.binary import find_binary
from dcert.config import load_config

_CONFIG = load_config()
Transport = Literal["stdio", "http", "sse"]
TRANSPORTS: tuple[Transport, ...] = ("stdio", "http", "sse")
OTEL_EXPORTERS = ("console", "otlp")


def exec_binary(name: str) -> None:
    """Replace the current process with the Rust binary *name*.

    Exits with status 1 and a message on stderr when the binary cannot be
    resolved or a downloaded archive fails verification.
    """
    try:
        binary = find_binary(name)
    except (FileNotFoundError, RuntimeError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    # The path comes from the trusted resolver, not from user input.
    os.execvp(binary, [binary, *sys.argv[1:]])  # noqa: S606


def dcert_main() -> None:
    """Entry point for the ``dcert`` command."""
    exec_binary("dcert")


def dcert_mcp_main() -> None:
    """Entry point for the ``dcert-mcp`` command."""
    exec_binary("dcert-mcp")


def environment_overrides(
    *,
    no_retry: bool,
    no_circuit_breaker: bool,
    rate_limit: float | None,
    cache: bool,
    bulkhead_max: int | None,
    otel: bool,
    otel_exporter: str | None,
) -> dict[str, str]:
    """Translate CLI flags into the ``DCERT_MCP_*`` variables they stand for."""
    overrides: dict[str, str] = {}
    if no_retry:
        overrides["DCERT_MCP_NO_RETRY"] = "1"
    if no_circuit_breaker:
        overrides["DCERT_MCP_NO_CIRCUIT_BREAKER"] = "1"
    if rate_limit is not None:
        overrides["DCERT_MCP_RATE_LIMIT_ENABLED"] = "1"
        overrides["DCERT_MCP_RATE_LIMIT_RPS"] = str(rate_limit)
    if cache:
        overrides["DCERT_MCP_CACHE_ENABLED"] = "1"
    if bulkhead_max is not None:
        overrides["DCERT_MCP_BULKHEAD_MAX"] = str(bulkhead_max)
    if otel:
        overrides["DCERT_MCP_OTEL_ENABLED"] = "1"
    if otel_exporter is not None:
        overrides["DCERT_MCP_OTEL_EXPORTER"] = otel_exporter
    return overrides


def run_setup() -> None:
    """Download the ``dcert-mcp`` binary and report where it was installed."""
    from dcert import __version__
    from dcert.download import ensure_binary

    try:
        path = ensure_binary(__version__)
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
    type=click.Choice(TRANSPORTS),
    default="stdio",
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
    type=click.Path(exists=True, dir_okay=False),
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
    type=click.Choice(OTEL_EXPORTERS),
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

    os.environ.update(
        environment_overrides(
            no_retry=no_retry,
            no_circuit_breaker=no_circuit_breaker,
            rate_limit=rate_limit,
            cache=cache,
            bulkhead_max=bulkhead_max,
            otel=otel,
            otel_exporter=otel_exporter,
        )
    )

    from dcert.resilience import otel_config_from_env, setup_otel
    from dcert.server import create_server

    setup_otel(otel_config_from_env())
    try:
        server = create_server(binary_path=binary)
    except (FileNotFoundError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc

    if transport == "stdio":
        server.run()
    else:
        server.run(transport=transport, host=host, port=port)


if __name__ == "__main__":
    main()
