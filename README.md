# dcert - TLS Certificate Decoder & Validator

A Rust CLI and MCP server for X.509 certificate analysis, format conversion, and key verification. Reads certificates from PEM files or HTTPS endpoints. Validates TLS connections, checks revocation status, converts between PFX and PEM formats, and integrates with AI-powered IDEs via the Model Context Protocol (MCP).

[![CI/CD Pipeline](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg)](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml)

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Commands](#commands)
  - [dcert [check] -- Certificate Analysis](#dcert-check--certificate-analysis-default)
  - [dcert convert -- Format Conversion](#dcert-convert--format-conversion)
  - [dcert verify-key -- Key Matching](#dcert-verify-key--key-matching)
- [MCP Server (AI IDE Integration)](#mcp-server-ai-ide-integration)
- [Features by Topic](#features-by-topic)
- [Use Cases](#use-cases)
- [Development](#development)
- [License](#license)

## Quick Start

```bash
# Install via Homebrew
brew tap SCGIS-Wales/homebrew-tap https://github.com/SCGIS-Wales/homebrew-tap.git
brew install dcert

# Analyze a live HTTPS endpoint
dcert https://www.google.com

# Check certificate expiry (CI/CD gate)
dcert https://your-api.com --expiry-warn 30

# Convert PFX to PEM
dcert convert pfx-to-pem client.pfx --password secret --output-dir ./certs

# Verify a private key matches a certificate
dcert verify-key cert.pem --key private.key
```

## Installation

### Homebrew (recommended — macOS and Linux)

Homebrew is the recommended installation method. On Linux it builds from source, which avoids glibc compatibility issues and works on Ubuntu 22.04 and later.

```bash
brew tap SCGIS-Wales/homebrew-tap https://github.com/SCGIS-Wales/homebrew-tap.git
brew install dcert
```

> **Note:** If you don't have Homebrew on Linux, install it first:
> ```bash
> /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
> ```

### Prebuilt binaries

Download from the [Releases](https://github.com/SCGIS-Wales/dcert/releases) page. Each release includes `dcert` (CLI) and `dcert-mcp` (MCP server). Prebuilt Linux binaries require Ubuntu 22.04 (glibc 2.35) or later.

```bash
curl -L https://github.com/SCGIS-Wales/dcert/releases/latest/download/dcert-x86_64-unknown-linux-gnu.tar.gz | tar xz
chmod +x dcert dcert-mcp
sudo mv dcert dcert-mcp /usr/local/bin/
```

### Build from source

```bash
git clone https://github.com/SCGIS-Wales/dcert.git
cd dcert
cargo build --release
# Binaries: target/release/dcert and target/release/dcert-mcp
```

### Docker

```bash
docker pull ghcr.io/scgis-wales/dcert:main

# CLI
docker run --rm ghcr.io/scgis-wales/dcert:main https://www.google.com

# Local PEM file
docker run --rm -v "$PWD:/data" ghcr.io/scgis-wales/dcert:main /data/cert.pem

# MCP server
docker run --rm -i --entrypoint dcert-mcp ghcr.io/scgis-wales/dcert:main
```

---

## Commands

dcert uses subcommands to organize its features. The `check` subcommand is the default and can be omitted:

```
dcert <targets> [OPTIONS]              # Certificate analysis (default, same as 'dcert check')
dcert convert <MODE> [OPTIONS]         # Format conversion (PFX/PEM/keystore/truststore)
dcert verify-key <target> --key <KEY>  # Key-certificate matching
```

### dcert [check] -- Certificate Analysis (default)

Analyze TLS certificates from PEM files or HTTPS endpoints. The `check` keyword is optional -- `dcert https://example.com` and `dcert check https://example.com` are equivalent.

```bash
# Fetch and analyze certificates from HTTPS
dcert https://www.google.com

# Analyze a local PEM file
dcert certificate.pem

# Multiple targets
dcert https://www.google.com https://github.com cert.pem

# Pipe targets from stdin
echo -e "https://google.com\nhttps://github.com" | dcert -

# JSON or YAML output
dcert https://example.com --format json
dcert https://example.com --format yaml

# SHA-256 fingerprints and certificate extensions
dcert https://example.com --fingerprint --extensions

# Expiry warning (exit code 1 if expiring within 30 days)
dcert https://example.com --expiry-warn 30

# OCSP revocation check
dcert https://example.com --check-revocation

# Compare certificates between two targets
dcert --diff https://staging.example.com https://prod.example.com

# Monitor certificates every 60 seconds
dcert --watch 60 https://example.com

# Export certificate chain to PEM file
dcert https://www.google.com --export-pem chain.pem

# Export excluding expired certificates
dcert https://www.google.com --export-pem chain.pem --exclude-expired

# Sort by expiry date
dcert certificates.pem --sort-expiry asc

# Only show expired certificates
dcert certificates.pem --expired-only
```

#### TLS Options

```bash
# Require TLS 1.3
dcert --min-tls 1.3 https://example.com

# Force TLS 1.2 only
dcert --min-tls 1.2 --max-tls 1.2 https://example.com

# Specific TLS 1.2 ciphers
dcert --cipher-list "ECDHE+AESGCM:CHACHA20" --max-tls 1.2 https://example.com

# TLS 1.3 cipher suites
dcert --cipher-suites "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256" https://example.com

# HTTP/2 ALPN negotiation
dcert --http-protocol http2 https://example.com

# SNI override
dcert https://10.0.0.1 --sni api.example.com

# Skip TLS verification (self-signed certs)
dcert https://localhost:8443 --no-verify
```

#### mTLS (Mutual TLS)

```bash
# Client certificate with PEM files
dcert https://api.internal.com --client-cert client.pem --client-key client-key.pem

# Client certificate with PKCS12/PFX
dcert https://api.internal.com --pkcs12 client.pfx --cert-password secret

# Custom CA bundle (overrides system CAs)
dcert https://internal.server --ca-cert corporate-ca.pem

# Combine mTLS with custom CA
dcert https://api.internal.com --client-cert client.pem --client-key client-key.pem --ca-cert corporate-ca.pem
```

#### HTTP Options

```bash
# Custom headers and method
dcert https://api.example.com --method POST --header "Authorization:Bearer token"

# POST with inline data
dcert https://api.example.com -d '{"key":"value"}' --header "Content-Type:application/json"

# POST with data from file
dcert https://api.example.com --data-file body.json

# Custom timeout
dcert https://slow-server.example.com --timeout 30 --read-timeout 15
```

#### Full Options Reference

```
dcert [check] [OPTIONS] [TARGETS]...

Arguments:
  [TARGETS]...                         PEM file(s), HTTPS URL(s), or '-' for stdin

Options:
  -f, --format <FORMAT>                Output format [pretty, json, yaml] (default: pretty)
      --expired-only                   Show only expired certificates
      --export-pem <FILE>              Export fetched PEM chain to a file
      --exclude-expired                Exclude expired certs from export
      --sort-expiry <ORDER>            Sort by expiry [asc, desc]
      --method <METHOD>                HTTP method [get, post, head, options] (default: get)
      --header <KEY:VALUE>             Custom HTTP headers (repeatable)
  -d, --data <DATA>                    Request body (implies POST)
      --data-file <FILE>               Request body from file (implies POST)
      --http-protocol <PROTO>          HTTP protocol [http1-1, http2] (default: http1-1)
      --min-tls <VERSION>              Minimum TLS version [1.2, 1.3]
      --max-tls <VERSION>              Maximum TLS version [1.2, 1.3]
      --cipher-list <STRING>           Allowed TLS 1.2 ciphers (OpenSSL format)
      --cipher-suites <SUITES>         Allowed TLS 1.3 cipher suites (colon-separated)
      --no-verify                      Disable TLS verification (insecure)
      --timeout <SECONDS>              Connection timeout (default: 10)
      --read-timeout <SECONDS>         Read timeout (default: 5)
      --sni <HOSTNAME>                 Override SNI hostname
      --fingerprint                    Show SHA-256 fingerprints
      --extensions                     Show certificate extensions
      --expiry-warn <DAYS>             Warn if expiring within N days (exit code 1)
      --diff                           Compare certificates between two targets
      --watch <SECONDS>                Re-check at interval
      --check-revocation               Check OCSP revocation status
      --debug                          Verbose OSI-layer diagnostics on stderr
      --client-cert <PATH>             Client certificate PEM for mTLS
      --client-key <PATH>              Client private key PEM for mTLS
      --pkcs12 <PATH>                  PKCS12/PFX file for mTLS (alternative to --client-cert/--client-key)
      --cert-password <PASS>           PKCS12 password (env: DCERT_CERT_PASSWORD)
      --ca-cert <PATH>                 Custom CA bundle PEM (overrides system CAs)
  -h, --help                           Print help
  -V, --version                        Print version
```

#### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success -- all certificates valid |
| 1 | Expiry warning -- certificate(s) expiring within `--expiry-warn` threshold |
| 2 | Error -- connection failure, file not found, or processing error |
| 3 | TLS verification failed |
| 4 | Certificate expired |
| 5 | Certificate revoked (OCSP) |
| 6 | Client certificate error (invalid, unreadable, wrong password) |
| 7 | Key mismatch (private key doesn't match certificate) |

---

### dcert convert -- Format Conversion

Convert between certificate formats. Four modes are available:

#### pfx-to-pem

Extract certificate, key, and CA chain from a PKCS12/PFX file into separate PEM files.

```bash
dcert convert pfx-to-pem server.pfx --password secret --output-dir ./certs
# Produces: ./certs/cert.pem, ./certs/key.pem, ./certs/ca.pem (if CA certs present)
```

#### pem-to-pfx

Bundle PEM certificate and private key into a PKCS12/PFX file.

```bash
dcert convert pem-to-pfx --cert server.pem --key server-key.pem --output server.pfx --password secret

# Include CA chain
dcert convert pem-to-pfx --cert server.pem --key server-key.pem --ca ca-chain.pem --output server.pfx --password secret
```

#### create-keystore

Create a PKCS12 keystore from PEM certificate and key (Java-compatible since JDK 9, where PKCS12 is the default keystore type).

```bash
dcert convert create-keystore --cert server.pem --key server-key.pem --output keystore.p12 --password changeit --alias myserver
```

To convert to JKS format if needed:

```bash
keytool -importkeystore -srckeystore keystore.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS
```

#### create-truststore

Create a PKCS12 truststore from CA certificate PEM files.

```bash
dcert convert create-truststore ca1.pem ca2.pem --output truststore.p12 --password changeit
```

---

### dcert verify-key -- Key Matching

Verify that a private key matches a certificate. Works with PEM files and HTTPS endpoints.

```bash
# Verify against a PEM file
dcert verify-key cert.pem --key private.key

# Verify against an HTTPS endpoint
dcert verify-key https://example.com --key private.key

# JSON output
dcert verify-key cert.pem --key private.key --format json
```

Returns key type, key size, certificate subject, and whether the key matches. Exit code 7 on mismatch.

---

## MCP Server (AI IDE Integration)

`dcert-mcp` is a Model Context Protocol server that exposes dcert's capabilities as tools for AI-powered IDEs. It communicates over stdio using the MCP protocol.

### Tools

| Tool | Description |
|------|-------------|
| `analyze_certificate` | Decode and analyze TLS certificates. Returns subject, issuer, SANs, validity, fingerprints, extensions, TLS connection info, and OSI-layer diagnostics. Supports mTLS. |
| `check_expiry` | Check if certificates expire within N days. Returns `ALL_VALID`, `EXPIRING_SOON`, or `ALREADY_EXPIRED`. Supports mTLS. |
| `check_revocation` | Check OCSP revocation status via the certificate's OCSP responder. Supports mTLS. |
| `compare_certificates` | Compare certificates between two targets side-by-side. |
| `tls_connection_info` | Get TLS connection details: protocol, cipher, ALPN, latency, verification, diagnostics. Supports mTLS. |
| `export_pem` | Export TLS certificate chain from an HTTPS endpoint as PEM. Optionally saves to file and can exclude expired certs. Supports mTLS. |
| `verify_key_match` | Verify that a private key matches a certificate (PEM file or HTTPS endpoint). |
| `convert_pfx_to_pem` | Convert PKCS12/PFX to separate PEM files (cert, key, CA chain). |
| `convert_pem_to_pfx` | Convert PEM certificate + key to PKCS12/PFX file. |
| `create_keystore` | Create a PKCS12 keystore from PEM cert + key (Java-compatible). |
| `create_truststore` | Create a PKCS12 truststore from CA certificate PEM files. |

### Configuration

#### Claude Code / Kiro / Kiro CLI

These tools use the same `mcpServers` configuration format. Create the config file at the appropriate location:

| Tool | Project config | Global config |
|------|---------------|---------------|
| Claude Code | `.mcp.json` | `~/.claude/settings/mcp.json` |
| Kiro (IDE) | `.kiro/settings/mcp.json` | `~/.kiro/settings/mcp.json` |
| Kiro CLI | `.kiro/settings/mcp.json` | `~/.kiro/settings/mcp.json` |

```json
{
  "mcpServers": {
    "dcert": {
      "type": "stdio",
      "command": "dcert-mcp"
    }
  }
}
```

Or add via Claude Code CLI:

```bash
claude mcp add dcert -- dcert-mcp
```

#### VS Code (GitHub Copilot)

Create `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "dcert": {
      "type": "stdio",
      "command": "dcert-mcp"
    }
  }
}
```

#### JetBrains IDEs

For JetBrains IDEs **2025.2+**: Go to **Settings > Tools > AI Assistant > Model Context Protocol (MCP)**, click **+**, choose **"As JSON"**, and paste:

```json
{
  "mcpServers": {
    "dcert": {
      "type": "stdio",
      "command": "dcert-mcp"
    }
  }
}
```

For earlier versions, install the [MCP Server plugin](https://plugins.jetbrains.com/plugin/26071-mcp-server) first.

#### Docker-based MCP

Use the Docker image if `dcert-mcp` is not installed locally:

```json
{
  "mcpServers": {
    "dcert": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "--rm", "-i", "--entrypoint", "dcert-mcp", "ghcr.io/scgis-wales/dcert:main"]
    }
  }
}
```

#### Custom binary path

If `dcert-mcp` is not on your `PATH`, specify the full path. You can also set `DCERT_PATH` to tell the MCP server where to find the `dcert` CLI:

```json
{
  "mcpServers": {
    "dcert": {
      "type": "stdio",
      "command": "/usr/local/bin/dcert-mcp",
      "env": {
        "DCERT_PATH": "/usr/local/bin/dcert"
      }
    }
  }
}
```

---

## Features by Topic

### Certificate Analysis

Decode X.509 certificates from PEM files or HTTPS endpoints: subject, issuer, serial number, validity window, SANs, expiry status.

### Certificate Extensions and Fingerprints

SHA-256 fingerprints (`--fingerprint`), key usage, extended key usage, basic constraints, authority info access, signature algorithm, public key info, SCT count (`--extensions`).

### TLS Debugging

Protocol version, cipher suite, ALPN negotiation, certificate transparency, verification result, and per-certificate chain validation detail. Network latency measurements for DNS resolution, TCP connect (Layer 4), and TLS+HTTP (Layer 7). Enable `--debug` for full OSI-layer diagnostics.

### Mutual TLS (mTLS)

Client certificate authentication via PEM (`--client-cert` + `--client-key`) or PKCS12/PFX (`--pkcs12` + `--cert-password`). Custom CA bundle support (`--ca-cert`) for corporate/internal PKI.

### Key-Certificate Matching

Verify private key matches a certificate (`dcert verify-key`). Supports RSA and EC keys against PEM files or live HTTPS endpoints.

### PFX/PEM Conversion

Convert PKCS12/PFX to separate PEM files or bundle PEM cert + key into PFX (`dcert convert pfx-to-pem`, `dcert convert pem-to-pfx`).

### Java KeyStore and TrustStore

Create PKCS12 keystores and truststores compatible with Java JDK 9+ (`dcert convert create-keystore`, `dcert convert create-truststore`).

### OCSP Revocation Checking

Query the certificate's OCSP responder to verify revocation status (`--check-revocation`).

### Expiry Monitoring

Configurable threshold warnings (`--expiry-warn N`) with machine-readable exit codes. Continuous monitoring with `--watch`.

### Certificate Comparison

Side-by-side diff of certificates between two targets (`--diff`).

### Certificate Export

Save fetched certificate chains as PEM files (`--export-pem`), with optional filtering of expired certificates (`--exclude-expired`).

---

## Use Cases

### DevOps & CI/CD

```bash
# Gate deployments on certificate health
dcert https://your-api.com --expiry-warn 14

# Check multiple endpoints
dcert https://api.example.com https://www.example.com https://admin.example.com

# Continuous monitoring
dcert --watch 300 https://your-api.com
```

### Security Auditing

```bash
# Enforce TLS 1.3 only
dcert --min-tls 1.3 https://target.com

# Full audit with extensions, fingerprints, and revocation
dcert https://site.com --fingerprint --extensions --check-revocation

# Test specific cipher suites
dcert --cipher-list "ECDHE+AESGCM" --max-tls 1.2 https://target.com
```

### Certificate Management

```bash
# Convert PFX for web server deployment
dcert convert pfx-to-pem server.pfx --password secret --output-dir /etc/ssl

# Prepare Java keystore
dcert convert create-keystore --cert server.pem --key server-key.pem --output keystore.p12 --password changeit

# Verify key matches certificate before deployment
dcert verify-key server.pem --key server-key.pem

# Compare staging vs production certificates
dcert --diff https://staging.example.com https://prod.example.com

# Export and backup certificate chains
for domain in google.com github.com; do
  dcert "https://$domain" --export-pem "${domain}-chain.pem"
done
```

---

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgements

- X.509 parsing by [x509-parser]
- CLI framework by [clap]
- Terminal colors by [colored]
- TLS connections and OCSP by [openssl]
- YAML serialization by [serde_yml]
- Signal handling by [ctrlc]
- MCP server by [rmcp]

[x509-parser]: https://crates.io/crates/x509-parser
[clap]: https://crates.io/crates/clap
[colored]: https://crates.io/crates/colored
[openssl]: https://crates.io/crates/openssl
[serde_yml]: https://crates.io/crates/serde_yml
[ctrlc]: https://crates.io/crates/ctrlc
[rmcp]: https://crates.io/crates/rmcp
