"""CLI entry points for dcert.

Provides three commands:
  - ``dcert``:        Thin wrapper that execs the bundled Rust ``dcert`` binary.
  - ``dcert-mcp``:    Thin wrapper that execs the bundled Rust ``dcert-mcp`` binary.
  - ``dcert-python``: Python MCP proxy server wrapping the Rust binary via FastMCP.
"""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
from pathlib import Path


def _is_python_script(path: str) -> bool:
    """Check if *path* is a Python console-script wrapper (not a compiled binary).

    Reads the first 128 bytes; if the file starts with ``#!`` and the first
    line contains ``python``, it is a pip-generated console_script wrapper
    and must be skipped to avoid an infinite exec loop (see helm-mcp PR #33).
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(128)
        first_line = head.split(b"\n", 1)[0].lower()
        return head[:2] == b"#!" and b"python" in first_line
    except OSError:
        return False


def _find_bundled_binary(name: str) -> str | None:
    """Locate a binary bundled inside the package ``bin/`` directory.

    If the binary exists but is not executable, it is chmod'd on first use.

    Returns:
        Absolute path to the binary, or ``None`` if not found.
    """
    pkg_dir = Path(__file__).parent
    bundled = pkg_dir / "bin" / name
    if not bundled.is_file():
        return None
    # Ensure the binary is executable (pip may not preserve permissions
    # for package-data files extracted from wheels).
    if not os.access(str(bundled), os.X_OK):
        try:
            bundled.chmod(bundled.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        except OSError:
            return None
    return str(bundled)


def _find_binary(name: str) -> str:
    """Find a binary by name: bundled in package, then PATH, then auto-download.

    Skips Python console-script wrappers on PATH to avoid infinite exec
    loops when pip installs the universal wheel.

    Raises:
        FileNotFoundError: If the binary cannot be located.
    """
    # 1. Bundled binary inside the Python package
    bundled = _find_bundled_binary(name)
    if bundled:
        return bundled

    # 2. Binary on PATH — skip Python console-script wrappers
    found = shutil.which(name)
    if found and not _is_python_script(found):
        return found

    # 3. Auto-download from GitHub Releases (fallback for universal wheel)
    from dcert import __version__
    from dcert.download import ensure_binary

    try:
        downloaded = ensure_binary(__version__)
        if downloaded:
            return downloaded
    except Exception:
        pass

    raise FileNotFoundError(
        f"{name} binary not found. Install dcert via:\n"
        "  brew tap SCGIS-Wales/tap && brew install dcert\n"
        "  or: pip install dcert  (platform wheel bundles the binary)"
    )


def dcert_main() -> None:
    """Entry point for the ``dcert`` command.

    Locates the bundled Rust ``dcert`` binary and replaces the current
    process with it, forwarding all command-line arguments.
    """
    try:
        binary = _find_binary("dcert")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    os.execvp(binary, [binary] + sys.argv[1:])


def dcert_mcp_main() -> None:
    """Entry point for the ``dcert-mcp`` command.

    Locates the bundled Rust ``dcert-mcp`` binary and replaces the current
    process with it, forwarding all command-line arguments.
    """
    try:
        binary = _find_binary("dcert-mcp")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    os.execvp(binary, [binary] + sys.argv[1:])


def main() -> None:
    """Run the dcert MCP proxy server (``dcert-python`` command)."""
    parser = argparse.ArgumentParser(
        description="dcert: MCP server for TLS certificate analysis",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "sse"],
        default="stdio",
        help="Transport mode (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host for HTTP/SSE mode (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for HTTP/SSE mode (default: 8080)",
    )
    parser.add_argument(
        "--binary",
        default=None,
        help="Path to dcert-mcp binary (auto-detected if not set)",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Download the dcert-mcp binary and exit",
    )

    # -- Resiliency flags --
    parser.add_argument(
        "--no-retry",
        action="store_true",
        help="Disable automatic retry on connection errors",
    )
    parser.add_argument(
        "--no-circuit-breaker",
        action="store_true",
        help="Disable circuit breaker",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        metavar="RPS",
        help="Enable rate limiting at RPS requests per second",
    )
    parser.add_argument(
        "--cache",
        action="store_true",
        help="Enable response caching",
    )
    parser.add_argument(
        "--bulkhead-max",
        type=int,
        default=None,
        metavar="N",
        help="Maximum concurrent tool calls (default: 10)",
    )

    # -- OpenTelemetry --
    parser.add_argument(
        "--otel",
        action="store_true",
        help="Enable OpenTelemetry tracing",
    )
    parser.add_argument(
        "--otel-exporter",
        choices=["console", "otlp"],
        default=None,
        help="OpenTelemetry exporter (default: console)",
    )

    args = parser.parse_args()

    if args.setup:
        from dcert import __version__
        from dcert.download import ensure_binary

        try:
            path = ensure_binary(__version__)
            if path:
                print(f"dcert-mcp binary ready at: {path}")
            else:
                print(
                    "No checksums available for this platform. Install the binary manually.",
                    file=sys.stderr,
                )
                sys.exit(1)
        except Exception as e:
            print(f"Error downloading binary: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Apply CLI overrides to environment so ResilienceConfig picks them up
    if args.no_retry:
        os.environ["DCERT_MCP_NO_RETRY"] = "1"
    if args.no_circuit_breaker:
        os.environ["DCERT_MCP_NO_CIRCUIT_BREAKER"] = "1"
    if args.rate_limit is not None:
        os.environ["DCERT_MCP_RATE_LIMIT_ENABLED"] = "1"
        os.environ["DCERT_MCP_RATE_LIMIT_RPS"] = str(args.rate_limit)
    if args.cache:
        os.environ["DCERT_MCP_CACHE_ENABLED"] = "1"
    if args.bulkhead_max is not None:
        os.environ["DCERT_MCP_BULKHEAD_MAX"] = str(args.bulkhead_max)

    # OpenTelemetry
    if args.otel:
        os.environ["DCERT_MCP_OTEL_ENABLED"] = "1"
    if args.otel_exporter is not None:
        os.environ["DCERT_MCP_OTEL_EXPORTER"] = args.otel_exporter

    from dcert.resilience import OTelConfig, setup_otel

    setup_otel(OTelConfig())

    from dcert.server import create_server

    try:
        server = create_server(binary_path=args.binary)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.transport == "stdio":
        server.run()
    else:
        server.run(transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
