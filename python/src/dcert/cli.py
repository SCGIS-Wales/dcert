"""CLI entry points for dcert.

Provides three commands:
  - ``dcert``:        Thin wrapper that execs the bundled Rust ``dcert`` binary.
  - ``dcert-mcp``:    Thin wrapper that execs the bundled Rust ``dcert-mcp`` binary.
  - ``dcert-python``: Python MCP proxy server wrapping the Rust binary via FastMCP.
"""

import argparse
import os
import shutil
import stat
import sys
from pathlib import Path


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
    """Find a binary by name: bundled in package, then PATH.

    Raises:
        FileNotFoundError: If the binary cannot be located.
    """
    # 1. Bundled binary inside the Python package
    bundled = _find_bundled_binary(name)
    if bundled:
        return bundled

    # 2. Binary on PATH (e.g. installed via Homebrew or cargo)
    found = shutil.which(name)
    if found:
        return found

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
