# dcert-mcp

[![CI/CD Pipeline](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml)
[![dcert-mcp on PyPI](https://img.shields.io/pypi/v/dcert-mcp?label=dcert-mcp)](https://pypi.org/project/dcert-mcp/)
[![dcert on PyPI](https://img.shields.io/pypi/v/dcert?label=dcert)](https://pypi.org/project/dcert/)
[![Python versions](https://img.shields.io/pypi/pyversions/dcert-mcp)](https://pypi.org/project/dcert-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

dcert-mcp is a Model Context Protocol server that gives AI assistants the dcert certificate and TLS tools. The server is a prebuilt Rust executable (`dcert-mcp`), installed as a wheel script, so starting it runs no Python. The optional `proxy` extra adds a [FastMCP](https://github.com/PrefectHQ/fastmcp) proxy, typed async client and the `dcert-mcp-proxy` command. Tools added to the Rust server are discovered at runtime, so the Python layer never needs to change.

This package is separate from [`dcert`](https://pypi.org/project/dcert/), the command line tool. Installing `dcert-mcp` pulls in `dcert` at the same version and nothing else.

## Installation

| Command | Result | Third party Python packages |
|---------|--------|-----------------------------|
| `pip install dcert-mcp` | the `dcert-mcp` MCP server, and `dcert` through the dependency | 0 |
| `pip install "dcert-mcp[proxy]"` | plus the FastMCP proxy, typed client and `dcert-mcp-proxy` | the FastMCP stack |
| `pip install "dcert-mcp[proxy,otel]"` | plus OpenTelemetry export | the FastMCP stack and OpenTelemetry |

Requires Python 3.12 or later. Wheels exist for Linux x86_64 (glibc 2.34 or later: RHEL 9, Ubuntu 22.04, Debian 12 and later), macOS Intel, macOS Apple Silicon and Windows x86_64. Only these platform wheels are published, so an install from PyPI, a private mirror or a downloaded wheel never fetches anything from GitHub. On any other platform pip reports "no matching distribution"; build the binaries from source and point `DCERT_MCP_BINARY` at the server.

Without the extra, the Rust server works on its own (`dcert-mcp` speaks MCP over stdio, or HTTP with `--mode http`). The Python helpers below need the extra: importing one without it fails with a single line naming it, for example `dcert_mcp needs the optional package 'fastmcp'. Install it with: pip install "dcert-mcp[proxy]"`.

## Quick start

### As a server

```python
from dcert_mcp import create_server

create_server().run()  # stdio transport
```

### As a client

```python
import asyncio
from dcert_mcp import create_client

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
from dcert_mcp import analyze_certificate, check_expiry, create_session, export_pem

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
from dcert_mcp import (
    DcertError,            # base class
    DcertTimeoutError,     # the call exceeded its timeout
    DcertConnectionError,  # the subprocess died or the circuit breaker is open
    DcertToolError,        # the tool returned an error result (has .tool)
)
```

Only transport failures are retried, with exponential backoff and full jitter, and only for tools whose MCP annotations mark them read-only or idempotent (the typed client reads the backend's tool list once per session to decide). `TypeError` and `ValueError` surface immediately and cancellation is never swallowed. A call that times out closes the subprocess (it is reconnected on the next call) and counts against the circuit breaker; concurrent calls that fail together share one reconnect and count as one failure.

### Command line

```bash
dcert-mcp-proxy                                   # stdio (for MCP clients such as Claude Code)
dcert-mcp-proxy --transport http --port 8080      # HTTP; needs DCERT_MCP_AUTH_TOKEN or OIDC
dcert-mcp-proxy --binary /usr/local/bin/dcert-mcp # explicit binary
dcert-mcp-proxy --rate-limit 20 --bulkhead-max 4  # resilience flags
dcert-mcp-proxy --help                            # every option
```

HTTP and SSE mode refuse to start without authentication: a static bearer token of at least 32 characters (`--auth-token` or, better, `DCERT_MCP_AUTH_TOKEN`, compared in constant time) or an OIDC configuration (`--oidc-issuer`, `--oidc-audience`, `--oidc-jwks-uri` or `DCERT_MCP_OIDC_ISSUER`, `DCERT_MCP_OIDC_AUDIENCE`, `DCERT_MCP_OIDC_JWKS_URL`, all https). Requests whose `Host` header is not a loopback name, the bind address or an entry from `--allowed-hosts` are answered 400, which defeats DNS rebinding from a browser.

The proxy forwards only the environment variables listed under `subprocess.passthrough_env` in `config.yaml` to `dcert-mcp`: proxy and CA settings, `TMPDIR`, `XDG_CACHE_HOME`, `DCERT_PROXY`, `DCERT_NOPROXY`, `DCERT_KB_FILE`, every `DCERT_MCP_*` policy variable and the `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`, `VAULT_CAPATH` and `VAULT_SKIP_VERIFY` settings. An entry ending in `*` matches by prefix.

`dcert-mcp` and `dcert` are the Rust executables themselves, so no Python wrapper sits in front of them.

## Configuration

Defaults live in the packaged `dcert_mcp/config.yaml`: the environment variables forwarded to the subprocess, the server bind address, the transports and exporters offered by `dcert-mcp-proxy`, and every resilience value. `dcert_mcp.load_config()` returns them as an immutable record.

Resilience values can be overridden with `DCERT_MCP_*` environment variables (listed in `dcert_mcp/resilience.py`) and the `dcert-mcp-proxy` flags override those. A value outside its valid range (for example `DCERT_MCP_CB_THRESHOLD=0` or `DCERT_MCP_BULKHEAD_MAX=0`) is rejected with a message naming the variable rather than crashing or hanging later. `DCERT_MCP_NO_RETRY` disables retries in both the proxy and the typed client, and `DCERT_MCP_CONNECT_TIMEOUT` bounds how long starting the subprocess and reading its tool list may take.

The proxy reads each tool's MCP annotations before applying caching or retries:

- **Caching** (`--cache`) replays results only for tools marked read-only and idempotent. Tools that generate keys, issue or sign certificates, or change Vault state (`create_csr`, `vault_issue`, `vault_sign`, `vault_renew`, …) are always run.
- **Retry** after a transport failure applies only to read-only or idempotent tools. Any other call surfaces the error instead of running a second time, because the first attempt may already have issued a certificate.

## Binary discovery

1. `DCERT_MCP_BINARY`; a relative path is resolved against the working directory, never through `PATH`
2. A compiled `dcert-mcp` on `PATH`. The wheel installs it there; pip console script wrappers and the running launcher are skipped.

Nothing is downloaded at run time.

## Environment variables forwarded to the binary

The proxy starts `dcert-mcp` with only these variables from its own environment (`subprocess.passthrough_env` in `config.yaml`); everything else is dropped. An entry ending in `*` forwards every variable with that prefix.

<!-- env-table: generated from src/dcert_mcp/config.yaml; CI checks it -->
| Group | Variables |
|-------|-----------|
| Process | `HOME`, `USER`, `PATH`, `TMPDIR`, `XDG_CACHE_HOME` |
| Loader | `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `DYLD_FALLBACK_LIBRARY_PATH` |
| Proxy | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY`, `http_proxy`, `https_proxy`, `no_proxy`, `all_proxy` |
| Trust | `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE` |
| dcert | `DCERT_PATH`, `DCERT_PROXY`, `DCERT_NOPROXY`, `DCERT_KB_FILE`, `DCERT_MCP_*` |
| Vault | `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`, `VAULT_CAPATH`, `VAULT_SKIP_VERIFY` |
<!-- /env-table -->

`DCERT_MCP_*` covers the server's own settings, for example `DCERT_MCP_TIMEOUT`, `DCERT_MCP_CONNECTION_TIMEOUT`, `DCERT_MCP_READ_TIMEOUT` and `DCERT_MCP_ALLOWED_TARGETS`.

## Development

The package has no build backend of its own: CI builds the wheels with `scripts/build_wheels.py`, so `pip install -e` does not apply. Tests run from the source tree (`pythonpath = ["src"]` in the pytest configuration) with the extras' requirements installed:

```bash
# From the repository root, build the server the integration tests start
cargo build --release --bin dcert-mcp --features mcp
export DCERT_MCP_BINARY="$PWD/target/release/dcert-mcp"

cd python/dcert-mcp
# The requirements of the proxy, otel and dev extras, exactly as CI installs them
python ../../scripts/ci/extras_requirements.py proxy otel dev > extras.txt
pip install -r extras.txt          # or: uv venv && uv pip install -r extras.txt

# The same checks as CI
ruff check src tests ../../scripts
ruff format --check src tests ../../scripts
mypy
pytest -q
```

Without `DCERT_MCP_BINARY` (or a compiled `dcert-mcp` on `PATH`) the integration tests are skipped.

## License

MIT
