"""FastMCP client for connecting to the dcert-mcp Rust binary.

Provides a thin client wrapper that connects to the Rust binary via stdio
transport. All tool discovery is handled by the MCP protocol at runtime,
so new tools added to the binary are automatically available.
"""

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from dcert.server import _build_subprocess_env, _find_binary


def create_client(
    binary_path: str | None = None,
    env: dict[str, str] | None = None,
) -> Client:
    """Create a FastMCP client connected to the dcert-mcp Rust binary via stdio.

    Args:
        binary_path: Explicit path to the dcert-mcp binary. Auto-detected if ``None``.
        env: Additional environment variables to pass to the subprocess.

    Returns:
        A FastMCP ``Client`` instance. Use as an async context manager.

    Example::

        async with create_client() as client:
            tools = await client.list_tools()
            result = await client.call_tool(
                "analyze_certificate", {"target": "example.com"}
            )
    """
    binary = binary_path or _find_binary()
    subprocess_env = _build_subprocess_env(extra_env=env)
    transport = StdioTransport(
        command=binary,
        args=[],
        env=subprocess_env or None,
    )
    return Client(transport)
