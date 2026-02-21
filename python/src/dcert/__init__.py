"""dcert: A Python MCP wrapper for the dcert TLS certificate MCP server.

This package provides a FastMCP proxy that wraps the dcert-mcp Rust binary,
automatically exposing all TLS certificate tools via the Model Context Protocol.

The proxy pattern means this package requires zero code changes when new
tools are added to the Rust binary — they are discovered and forwarded
automatically at runtime via the MCP protocol.

Usage as a server:
    from dcert import create_server
    server = create_server()
    server.run()

Usage as a client:
    from dcert import create_client
    async with create_client() as client:
        tools = await client.list_tools()
        result = await client.call_tool("analyze_certificate", {"target": "example.com"})
"""

__version__ = "3.0.14"

from dcert.client import create_client
from dcert.server import create_server

__all__ = ["create_server", "create_client", "__version__"]
