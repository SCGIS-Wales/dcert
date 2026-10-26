# dcert (Python)

[![CI/CD Pipeline](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/dcert)](https://pypi.org/project/dcert/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python MCP wrapper for the [dcert](https://github.com/SCGIS-Wales/dcert) Rust server.

The package uses [FastMCP](https://github.com/PrefectHQ/fastmcp) to run a transparent proxy around the `dcert-mcp` Rust binary and exposes all TLS certificate tools over the Model Context Protocol. Tools added to the Rust binary are discovered at runtime, so the Python layer never needs to change.

## Requirements

- Python 3.12 or later
- The `dcert-mcp` Rust binary. Platform wheels bundle it; the universal wheel downloads it on first use after verifying its SHA256 checksum.

## Installation

```bash
pip install dcert
```

Platform wheels exist for Linux x86_64 (glibc 2.35 or later), macOS Intel, macOS Apple Silicon and Windows x86_64. The universal wheel works everywhere else that a release archive exists for.

## Quick start

### As a server

```python
from dcert import create_server

create_server().run()  # stdio transport
```

### As a client

```python
import asyncio
from dcert import create_client

async def main() -> None:
    async with create_client() as client:
        tools = await client.list_tools()
        result = await client.call_tool("analyze_certificate", {"target": "example.com"})
        print(len(tools), result)

asyncio.run(main())
```

### Typed async tool functions

The functional API opens a session (a subprocess plus its resilience stack) and passes it to plain async functions:

```python
import asyncio
from dcert import analyze_certificate, check_expiry, create_session, export_pem

async def main() -> None:
    async with create_session(timeout=60.0) as session:
        cert = await analyze_certificate(target="example.com", session=session)
        expiry = await check_expiry(target="example.com", days=90, session=session)
        pem = await export_pem(target="example.com", output_path="chain.pem", session=session)
        raw = await session.call("tls_connection_info", {"target": "example.com"})

asyncio.run(main())
```

Leaving out `session` uses a shared default session that is created on first use and reused afterwards; `close_default_session()` shuts it down. The shared session belongs to the event loop that created it: a later `asyncio.run()` gets a fresh one, and calling `close_default_session()` before a loop ends releases the subprocess cleanly.

| Function | Description |
|----------|-------------|
| `analyze_certificate()` | Decode and analyse TLS certificates |
| `check_expiry()` | Check certificate expiry within N days |
| `check_revocation()` | Check OCSP revocation status |
| `compare_certificates()` | Compare certificates between two targets |
| `tls_connection_info()` | TLS connection details (cipher, protocol, latency) |
| `export_pem()` | Export the certificate chain as PEM |
| `verify_key_match()` | Verify a private key matches a certificate |
| `convert_pfx_to_pem()` | Convert PKCS12/PFX to PEM files |
| `convert_pem_to_pfx()` | Convert PEM cert and key to PKCS12/PFX |
| `create_keystore()` | Create a PKCS12 keystore (Java compatible) |
| `create_truststore()` | Create a PKCS12 truststore from CA certs |
| `tls_scan()` | Enumerate the TLS versions, cipher suites and groups a server accepts |
| `list_cipher_suites()` | List TLS cipher suites from the IANA registry (offline) |
| `list_tls_policies()` | List the catalogued TLS security policies (offline) |
| `show_tls_policy()` | Show one catalogued TLS security policy (offline) |
| `tls_policy_test()` | Test an endpoint against a TLS security policy, or identify the closest one |
| `explain_cipher_suite()` | Explain one cipher suite in any notation (offline) |

The network facing functions accept the shared mTLS and connection options (`client_cert`, `client_key`, `pkcs12`, `cert_password`, `ca_cert`, `connect_to`, `resolve`, `proxy`, `noproxy`) as keyword arguments.

### Error handling

```python
from dcert import (
    DcertError,            # base class
    DcertTimeoutError,     # the call exceeded its timeout
    DcertConnectionError,  # the subprocess died or the circuit breaker is open
    DcertToolError,        # the tool returned an error result (has .tool)
)
```

Only transport failures are retried, with exponential backoff and full jitter, and only for tools whose MCP annotations mark them read-only or idempotent (the typed client reads the backend's tool list once per session to decide). `TypeError` and `ValueError` surface immediately and cancellation is never swallowed. A call that times out closes the subprocess (it is reconnected on the next call) and counts against the circuit breaker; concurrent calls that fail together share one reconnect and count as one failure.

### Command line

```bash
dcert-python                                   # stdio (for MCP clients such as Claude Code)
dcert-python --transport http --port 8080      # HTTP; needs DCERT_MCP_AUTH_TOKEN or OIDC
dcert-python --setup                           # download the binary and exit
dcert-python --binary /usr/local/bin/dcert-mcp # explicit binary
dcert-python --rate-limit 20 --bulkhead-max 4  # resilience flags
dcert-python --help                            # every option
```

HTTP and SSE mode refuse to start without authentication: a static bearer token of at least 32 characters (`--auth-token` or, better, `DCERT_MCP_AUTH_TOKEN`, compared in constant time) or an OIDC configuration (`--oidc-issuer`, `--oidc-audience`, `--oidc-jwks-uri` or `DCERT_MCP_OIDC_ISSUER`, `DCERT_MCP_OIDC_AUDIENCE`, `DCERT_MCP_OIDC_JWKS_URL`, all https). Requests whose `Host` header is not a loopback name, the bind address or an entry from `--allowed-hosts` are answered 400, which defeats DNS rebinding from a browser.

The proxy forwards only the environment variables listed under `subprocess.passthrough_env` in `config.yaml` to `dcert-mcp`: proxy and CA settings, `TMPDIR`, `XDG_CACHE_HOME`, `DCERT_PROXY`, `DCERT_NOPROXY`, `DCERT_KB_FILE`, every `DCERT_MCP_*` policy variable and the `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`, `VAULT_CAPATH` and `VAULT_SKIP_VERIFY` settings. An entry ending in `*` matches by prefix.

`dcert` and `dcert-mcp` are thin wrappers that exec the Rust binaries with all arguments. A wrapper refuses to run when the only `dcert-mcp` it can find is itself (for example the pip console script on `PATH`), instead of exec-ing in a loop.

## Configuration

Defaults live in the packaged `dcert/config.yaml`: the release URL, download limits, the install directory, the platform table, the environment variables forwarded to the subprocess, the server bind address, the transports and exporters offered by `dcert-python`, and every resilience value. `dcert.load_config()` returns them as an immutable record.

Resilience values can be overridden with `DCERT_MCP_*` environment variables (listed in `dcert/resilience.py`) and the `dcert-python` flags override those. A value outside its valid range (for example `DCERT_MCP_CB_THRESHOLD=0` or `DCERT_MCP_BULKHEAD_MAX=0`) is rejected with a message naming the variable rather than crashing or hanging later. `DCERT_MCP_NO_RETRY` disables retries in both the proxy and the typed client, and `DCERT_MCP_CONNECT_TIMEOUT` bounds how long starting the subprocess and reading its tool list may take.

The proxy reads each tool's MCP annotations before applying caching or retries:

- **Caching** (`--cache`) replays results only for tools marked read-only and idempotent. Tools that generate keys, issue or sign certificates, or change Vault state (`create_csr`, `vault_issue`, `vault_sign`, `vault_renew`, …) are always run.
- **Retry** after a transport failure applies only to read-only or idempotent tools. Any other call surfaces the error instead of running a second time, because the first attempt may already have issued a certificate.

## Binary discovery

1. `DCERT_MCP_BINARY` (or `DCERT_PATH` for the `dcert` CLI); a relative path is resolved against the working directory, never through `PATH`
2. The bundled binary in the package `bin/` directory
3. A compiled `dcert-mcp` on `PATH` (pip console script wrappers and the running launcher are skipped)
4. Download from GitHub Releases: https only, redirects restricted to GitHub hosts, size and time capped, SHA256 verified before extraction, installed atomically under a lock

An install record beside the binaries (`.install-record.json`: package version, archive digest and each binary's digest) makes a later run download again when the package version changes, the embedded checksum changes or an installed binary was modified. The install directory is created with mode `0700`.

Downloaded binaries are installed into a directory owned by dcert, never into pip's scripts directory, so a download can never replace a console script: `~/.local/share/dcert/bin` on Linux and macOS, `%LOCALAPPDATA%\dcert\bin` on Windows. Set `DCERT_INSTALL_DIR` to use another directory. `dcert-python --setup` downloads the binary ahead of time and prints where it was installed.

## Environment variables forwarded to the binary

| Category | Variables |
|----------|-----------|
| Proxy | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lowercase variants) |
| TLS | `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE` |
| dcert | `DCERT_PATH`, `DCERT_MCP_TIMEOUT`, `DCERT_MCP_CONNECTION_TIMEOUT`, `DCERT_MCP_READ_TIMEOUT` |

## Development

```bash
cd python
pip install -e ".[dev]"
ruff check src tests ../scripts
ruff format --check src tests ../scripts
mypy
pytest
```

## License

MIT
