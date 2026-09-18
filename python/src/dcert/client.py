"""FastMCP client connected to the ``dcert-mcp`` Rust binary over stdio."""

from __future__ import annotations

from collections.abc import Mapping

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from dcert.server import create_transport


def create_client(
    binary_path: str | None = None,
    env: Mapping[str, str] | None = None,
) -> Client[StdioTransport]:
    """Return a FastMCP client for the Rust binary; use it as an async context manager.

    Args:
        binary_path: Explicit path to ``dcert-mcp``; auto detected when ``None``.
        env: Extra environment variables for the subprocess.

    Example::

        async with create_client() as client:
            tools = await client.list_tools()
    """
    return Client(create_transport(binary_path, env))
