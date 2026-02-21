# dcert (Python)

[![CI/CD Pipeline](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/dcert)](https://pypi.org/project/dcert/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python MCP wrapper for the [dcert](https://github.com/SCGIS-Wales/dcert) Rust server.

Uses [FastMCP](https://github.com/PrefectHQ/fastmcp) to create a transparent proxy around the dcert-mcp Rust binary, exposing all TLS certificate tools via the Model Context Protocol. **New tools added to the Rust binary are automatically available without any Python code changes.**

## Requirements

- Python 3.12+
- The `dcert-mcp` Rust binary is **bundled in platform-specific wheels** (no network access needed at runtime)

## Installation

```bash
pip install dcert
```

Platform-specific wheels are available for:
- **Linux** x86_64 (Ubuntu 22.04+, glibc 2.35+)
- **macOS** Intel (x86_64)
- **macOS** Apple Silicon (ARM64)

A universal fallback wheel auto-downloads the binary on first use if no platform wheel matches.

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

### Typed async tool wrappers

For production use with type safety, timeouts, and automatic reconnection:

```python
import asyncio
from dcert.tools import DcertClient

async def main():
    async with DcertClient(timeout=60.0) as dcert:
        # Analyze a certificate
        result = await dcert.analyze_certificate(target="example.com")

        # Check expiry with custom threshold
        expiry = await dcert.check_expiry(target="example.com", days=90)

        # Get TLS connection details
        info = await dcert.tls_connection_info(target="example.com")

        # Export PEM chain
        pem = await dcert.export_pem(target="example.com", output_path="chain.pem")

asyncio.run(main())
```

All 11 tools are available as typed async methods:

| Method | Description |
|--------|-------------|
| `analyze_certificate()` | Decode and analyze TLS certificates |
| `check_expiry()` | Check certificate expiry within N days |
| `check_revocation()` | Check OCSP revocation status |
| `compare_certificates()` | Compare certificates between two targets |
| `tls_connection_info()` | Get TLS connection details (cipher, protocol, latency) |
| `export_pem()` | Export certificate chain as PEM |
| `verify_key_match()` | Verify private key matches a certificate |
| `convert_pfx_to_pem()` | Convert PKCS12/PFX to PEM files |
| `convert_pem_to_pfx()` | Convert PEM cert+key to PKCS12/PFX |
| `create_keystore()` | Create PKCS12 keystore (Java-compatible) |
| `create_truststore()` | Create PKCS12 truststore from CA certs |

### Error handling

```python
from dcert.tools import (
    DcertClient,
    DcertError,          # Base exception
    DcertTimeoutError,   # Tool call timed out
    DcertConnectionError,# Subprocess died
    DcertToolError,      # MCP tool returned an error
)

async with DcertClient(timeout=30.0, max_reconnects=3) as dcert:
    try:
        result = await dcert.analyze_certificate(target="example.com")
    except DcertTimeoutError:
        print("Tool call timed out")
    except DcertToolError as e:
        print(f"Tool error: {e} (tool={e.tool})")
    except DcertConnectionError:
        print("Binary subprocess crashed")
```

### CLI

```bash
# stdio mode (default, for MCP clients like Claude Code)
dcert-python

# HTTP mode
dcert-python --transport http --host 0.0.0.0 --port 8080

# Pre-download binary (universal wheel only)
dcert-python --setup

# Explicit binary path
dcert-python --binary /usr/local/bin/dcert-mcp
```

## Binary Discovery

The package locates the `dcert-mcp` Rust binary in this order:

1. `DCERT_MCP_BINARY` environment variable
2. Bundled binary in the package `bin/` directory
3. `dcert-mcp` on `PATH` (platform wheels install the binary here)
4. Auto-download from GitHub Releases (universal wheel fallback, with SHA256 verification)

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
