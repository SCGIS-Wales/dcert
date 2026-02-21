"""CLI entry point for dcert-python."""

import argparse
import sys


def main() -> None:
    """Run the dcert MCP proxy server."""
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
