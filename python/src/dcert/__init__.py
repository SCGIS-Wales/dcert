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

Usage with typed async wrappers:
    from dcert.tools import DcertClient
    async with DcertClient() as dcert:
        result = await dcert.analyze_certificate(target="example.com")
"""

__version__ = "3.0.17"

from dcert.client import create_client
from dcert.server import create_server
from dcert.tools import (
    DcertClient,
    DcertConnectionError,
    DcertError,
    DcertTimeoutError,
    DcertToolError,
    analyze_certificate,
    check_expiry,
    check_revocation,
    compare_certificates,
    convert_pem_to_pfx,
    convert_pfx_to_pem,
    create_keystore,
    create_truststore,
    export_pem,
    tls_connection_info,
    verify_key_match,
)

__all__ = [
    # Core API
    "create_server",
    "create_client",
    "__version__",
    # Client
    "DcertClient",
    # Exceptions
    "DcertError",
    "DcertTimeoutError",
    "DcertConnectionError",
    "DcertToolError",
    # Tool wrappers
    "analyze_certificate",
    "check_expiry",
    "check_revocation",
    "compare_certificates",
    "tls_connection_info",
    "export_pem",
    "verify_key_match",
    "convert_pfx_to_pem",
    "convert_pem_to_pfx",
    "create_keystore",
    "create_truststore",
]
