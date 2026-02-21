# dcert (Python)

[![CI/CD Pipeline](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/dcert)](https://pypi.org/project/dcert/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python MCP wrapper for the [dcert](https://github.com/SCGIS-Wales/dcert) Rust server.

Uses [FastMCP](https://github.com/PrefectHQ/fastmcp) to create a transparent proxy around the dcert-mcp Rust binary, exposing all TLS certificate tools via the Model Context Protocol. **New tools added to the Rust binary are automatically available without any Python code changes.**

## Requirements

- Python 3.14+
- The `dcert-mcp` Rust binary is **automatically downloaded** on first use (with SHA256 checksum verification)

## Installation

```bash
pip install dcert
```

## Quick Start

### As a server

```python
from dcert import create_server

server = create_server()
server.run()  # stdio mode (default)
```

### As a client

```python
import asyncio
from dcert import create_client

async def main():
    async with create_client() as client:
        tools = await client.list_tools()
        print(f"Available tools: {len(tools)}")

        result = await client.call_tool(
            "analyze_certificate", {"target": "example.com"}
        )
        print(result)

asyncio.run(main())
```

### CLI

```bash
# stdio mode (default, for MCP clients like Claude Code)
dcert-python

# HTTP mode
dcert-python --transport http --host 0.0.0.0 --port 8080

# Pre-download binary
dcert-python --setup

# Explicit binary path
dcert-python --binary /usr/local/bin/dcert-mcp
```

## Binary Discovery

The package locates the `dcert-mcp` Rust binary in this order:

1. `DCERT_MCP_BINARY` environment variable
2. Bundled binary in the package `bin/` directory
3. Auto-download from GitHub Releases (with SHA256 checksum verification)
4. `dcert-mcp` on `PATH`

## Environment Variables

The proxy forwards these environment variables to the Rust binary:

| Category | Variables |
|----------|-----------|
| Proxy | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lowercase variants) |
| TLS | `SSL_CERT_FILE`, `SSL_CERT_DIR` |
| dcert | `DCERT_PATH`, `DCERT_MCP_TIMEOUT`, `DCERT_MCP_CONNECTION_TIMEOUT`, `DCERT_MCP_READ_TIMEOUT` |

## Scalability

This package uses the MCP proxy pattern: the Python layer never needs to know about individual dcert tools. All tool discovery, input schemas, and invocations are forwarded to the Rust binary via the MCP protocol at runtime. When new capabilities are added to the Rust server, they are immediately available through the Python wrapper.

## License

MIT
