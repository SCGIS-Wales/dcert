<div align="center">
  <img src="assets/logo.svg" alt="dcert logo" width="400">
  <h1>dcert</h1>
  <p><strong>TLS Certificate Decoder & Validator</strong></p>
  <p>A Rust CLI and MCP server for X.509 certificate analysis, format conversion, and key verification.<br>Reads certificates from PEM files or HTTPS endpoints. Validates TLS connections, checks revocation status,<br>converts between PFX and PEM formats, and integrates with AI-powered IDEs via the Model Context Protocol (MCP).</p>
  <p>
    <a href="https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml"><img src="https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI/CD Pipeline"></a>
    <a href="https://pypi.org/project/dcert/"><img src="https://img.shields.io/pypi/v/dcert" alt="PyPI version"></a>
    <a href="https://pypi.org/project/dcert/"><img src="https://img.shields.io/pypi/dm/dcert" alt="PyPI Downloads"></a>
    <a href="https://pypi.org/project/dcert/"><img src="https://img.shields.io/pypi/pyversions/dcert" alt="Python"></a>
    <a href="https://github.com/SCGIS-Wales/dcert"><img src="https://img.shields.io/badge/Rust-stable-000000?logo=rust&logoColor=white" alt="Rust"></a>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  </p>
</div>

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Commands](#commands)
  - [dcert [check] -- Certificate Analysis](#dcert-check--certificate-analysis-default)
  - [dcert csr -- CSR Creation & Validation](#dcert-csr--csr-creation--validation)
  - [dcert convert -- Format Conversion](#dcert-convert--format-conversion)
  - [dcert verify-key -- Key Matching](#dcert-verify-key--key-matching)
  - [dcert vault -- HashiCorp Vault PKI](#dcert-vault--hashicorp-vault-pki)
- [MCP Server (AI IDE Integration)](#mcp-server-ai-ide-integration)
  - [Proxy and Timeout Configuration](#proxy-and-timeout-configuration)
  - [Troubleshooting](#troubleshooting)
  - [HTTP Transport Mode](#http-transport-mode)
- [Features by Topic](#features-by-topic)
- [Use Cases](#use-cases)
- [Python Package](#python-package)
- [Development](#development)
- [License](#license)

## Quick Start

```bash
# Install via Homebrew
brew tap SCGIS-Wales/homebrew-tap https://github.com/SCGIS-Wales/homebrew-tap.git
brew install dcert

# Analyze a live HTTPS endpoint (bare hostname or full URL)
dcert api.example.com
dcert https://www.google.com

# Read PEM from a pipe
cat certificate.pem | dcert

# Check certificate expiry (CI/CD gate)
dcert https://your-api.com --expiry-warn 30

# Convert PFX to PEM
dcert convert pfx-to-pem client.pfx --password secret --output-dir ./certs

# Verify a private key matches a certificate
dcert verify-key cert.pem --key private.key

# Auto-discover and verify all cert/key pairs in a directory
dcert verify-key

# Create a new CSR with RSA 4096 key
dcert csr create --cn api.example.com --org "My Corp" --country GB

# Validate a CSR for compliance
dcert csr validate my-cert.csr

# Issue a TLS certificate from HashiCorp Vault PKI
dcert vault issue --cn www.example.com --role my-role

# Renew a certificate stored in Vault KV
dcert vault renew secret/certs/www-example-com --role my-role
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
dcert csr create [OPTIONS]             # Create a CSR and private key
dcert csr validate <CSR_FILE>          # Validate a CSR for compliance
dcert convert <MODE> [OPTIONS]         # Format conversion (PFX/PEM/keystore/truststore)
dcert verify-key <target> --key <KEY>  # Key-certificate matching (single pair)
dcert verify-key [--dir <DIR>]         # Auto-discover and verify all cert/key pairs
dcert vault issue [OPTIONS]            # Issue a TLS certificate from Vault PKI
dcert vault sign [OPTIONS]             # Sign a CSR using Vault PKI
dcert vault revoke [OPTIONS]           # Revoke a certificate in Vault PKI
dcert vault list [OPTIONS]             # List certificates issued by Vault PKI
dcert vault store [OPTIONS] <PATH>     # Store cert+key in Vault KV
dcert vault validate <PATH>            # Validate a certificate in Vault KV
dcert vault renew <PATH> [OPTIONS]     # Renew a certificate in Vault KV
```

### dcert [check] -- Certificate Analysis (default)

Analyze TLS certificates from PEM files or HTTPS endpoints. The `check` keyword is optional -- `dcert https://example.com` and `dcert check https://example.com` are equivalent.

```bash
# Fetch and analyze certificates from HTTPS
dcert https://www.google.com

# Bare hostname (auto-prepends https://)
dcert api.example.com

# Analyze a local PEM file
dcert certificate.pem

# Read PEM data from stdin (pipe)
cat certificate.pem | dcert
echo "<base64-pem>" | base64 --decode | dcert
cat certificate.pem | dcert -

# Multiple targets
dcert https://www.google.com https://github.com cert.pem

# Pipe target names from stdin (one per line)
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

# Compliance report (CA/B Forum Baseline Requirements)
dcert https://example.com --compliance
dcert certificate.pem --compliance

# Compliance report in JSON (for CI/CD)
dcert https://example.com --compliance --format json
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
  [TARGETS]...                         PEM file(s), HTTPS URL(s), bare hostnames, or '-' for stdin
                                       Omit targets to read PEM data from a pipe

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
      --compliance                      Run compliance checks (CA/B Forum, DigiCert, X9)
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

### dcert csr -- CSR Creation & Validation

Create PKCS#10 Certificate Signing Requests (CSRs) and validate existing CSRs for compliance with CA/B Forum Baseline Requirements, DigiCert, and X9 standards.

#### Create a CSR

```bash
# RSA 4096 (default) — guided interactive mode (omit --cn)
dcert csr create

# RSA 4096 with subject fields
dcert csr create --cn api.example.com --org "My Corp" --country GB

# ECDSA P-256 (recommended modern) with multiple SANs
dcert csr create --cn www.example.com --key-algo ecdsa-p256 \
  --san DNS:www.example.com --san DNS:example.com --san IP:10.0.0.1

# Encrypted private key
dcert csr create --cn secure.example.com --encrypt-key --key-password "$(read -sp 'Password: ' p && echo $p)"

# Custom output paths and JSON output
dcert csr create --cn api.example.com --csr-out api.csr --key-out api.key --format json

# OU metadata identifiers (for internal/private PKI)
dcert csr create --cn app.internal.corp --ou "AppId:my-service-123" --ou "Team:Platform"
```

#### Validate a CSR

```bash
# Pretty compliance report
dcert csr validate my-cert.csr

# JSON output (for CI/CD pipelines)
dcert csr validate my-cert.csr --format json

# Strict mode (warnings become errors)
dcert csr validate my-cert.csr --strict
```

#### Key Algorithm Options

| Algorithm | Flag | Description |
|-----------|------|-------------|
| RSA 4096 | `--key-algo rsa-4096` | Default. Strong, widely compatible. |
| RSA 2048 | `--key-algo rsa-2048` | Minimum accepted by CAs. |
| ECDSA P-256 | `--key-algo ecdsa-p256` | Recommended modern choice. Faster, equivalent to RSA 3072. |
| ECDSA P-384 | `--key-algo ecdsa-p384` | High-security requirements. |
| Ed25519 | `--key-algo ed25519` | Modern EdDSA. Compact signatures, high performance. Requires OpenSSL 3.x. |

#### Compliance Checks

The validator checks against CA/B Forum Baseline Requirements, DigiCert, and X9 standards:

- **Key size**: Minimum RSA 2048-bit / ECDSA P-256
- **Signature algorithm**: SHA-256+ required, SHA-1 rejected
- **Subject Alternative Names**: Required for all modern certificates
- **OU deprecation**: Warning for publicly-trusted CAs (CA/B Forum Ballot SC47v2, Sep 2022)
- **Country code**: ISO 3166-1 alpha-2 validation
- **CN in SAN**: CN should be included in SANs per RFC 6125

#### Full Options Reference

```
dcert csr create [OPTIONS]

Options:
      --cn <NAME>          Common Name (FQDN). Omit for interactive mode.
      --org <NAME>         Organization (O)
      --ou <NAME>          Organizational Unit (repeatable, supports metadata e.g., "AppId:xxx")
      --country <CODE>     Two-letter country code (e.g., GB, US)
      --state <NAME>       State or province (ST)
      --locality <NAME>    City or locality (L)
      --email <EMAIL>      Email address
      --san <TYPE:VALUE>   Subject Alternative Name (repeatable, e.g., DNS:www.example.com, IP:10.0.0.1)
      --key-algo <ALGO>    Key algorithm [rsa-4096, rsa-2048, ecdsa-p256, ecdsa-p384, ed25519] (default: rsa-4096)
      --encrypt-key        Encrypt the private key (AES-256-CBC, PKCS#8)
      --key-password <PW>  Password for key encryption (env: DCERT_KEY_PASSWORD)
      --csr-out <FILE>     Output CSR file path (default: <cn>.csr)
      --key-out <FILE>     Output key file path (default: <cn>.key)
  -f, --format <FORMAT>    Output format [pretty, json, yaml] (default: pretty)

dcert csr validate [OPTIONS] <CSR_FILE>

Arguments:
  <CSR_FILE>              PEM-encoded CSR file to validate

Options:
      --strict             Treat warnings as errors
  -f, --format <FORMAT>   Output format [pretty, json, yaml] (default: pretty)
```

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

Verify that a private key matches a certificate. Works with PEM files and HTTPS endpoints. When run without arguments, auto-discovers matching cert/key pairs in the current directory.

```bash
# Verify a specific pair
dcert verify-key cert.pem --key private.key

# Verify against an HTTPS endpoint
dcert verify-key https://example.com --key private.key

# Auto-discover all cert/key pairs in the current directory
dcert verify-key

# Auto-discover in a specific directory
dcert verify-key --dir /etc/ssl/certs

# JSON output
dcert verify-key cert.pem --key private.key --format json
dcert verify-key --format json
```

**Auto-discovery** scans for `.crt` and `.pem` files that have a matching `.key` file with the same base name (e.g. `server.crt` + `server.key`, `app.pem` + `app.key`). Files without a matching key are skipped.

Returns key type, key size, certificate subject, and whether the key matches. Exit code 7 on mismatch.

---

### dcert vault -- HashiCorp Vault PKI

Issue, sign, revoke, list, store, validate, and renew TLS certificates using HashiCorp Vault's PKI Secrets Engine. Supports interactive wizard mode (omit required args) or fully non-interactive CLI usage.

#### Prerequisites

Set these environment variables before using vault commands:

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_ADDR` | Yes | Vault server URL (e.g., `https://vault.example.com:8200`) |
| `VAULT_TOKEN` | No* | Vault authentication token |

\* Token is discovered in order: `VAULT_TOKEN` env var, then `~/.vault-token` file.

#### Issue a Certificate

Vault generates a new private key and certificate via the PKI engine.

```bash
# Interactive wizard (guided step-by-step)
dcert vault issue

# Non-interactive with all options
dcert vault issue --cn www.example.com --role my-role \
  --san "DNS:*.example.com" --ip-san 10.0.0.1 --ttl 8760h

# Output as PFX instead of PEM
dcert vault issue --cn www.example.com --role my-role --pfx-password secret

# Issue and store in Vault KV
dcert vault issue --cn www.example.com --role my-role \
  --store-path secret/company/project/certs/www-example-com

# Custom PKI mount point
dcert vault issue --cn www.example.com --role my-role --mount pki_intermediate
```

#### Sign a CSR

Submit an existing CSR to Vault PKI for signing (no private key is generated).

```bash
# Interactive wizard
dcert vault sign

# Non-interactive
dcert vault sign --csr-file server.csr --role my-role --ttl 8760h

# Override CN from CSR
dcert vault sign --csr-file server.csr --role my-role --cn override.example.com
```

#### Revoke a Certificate

```bash
# Revoke by serial number
dcert vault revoke --serial "1a:2b:3c:4d:5e"

# Revoke by PEM certificate file
dcert vault revoke --cert-file server.crt
```

#### List Certificates

```bash
# List all issued certificates (serial numbers only)
dcert vault list

# Fetch and display details for each certificate
dcert vault list --show-details

# Filter by status
dcert vault list --show-details --expired-only
dcert vault list --show-details --valid-only

# Export to JSON or CSV
dcert vault list --show-details --export certs.json
dcert vault list --show-details --export certs.csv

# JSON output
dcert vault list --show-details --format json
```

#### Store in Vault KV

Store a local certificate and private key in Vault KV v2.

```bash
dcert vault store --cert-file server.crt --key-file server.key \
  secret/company/project/certs/www-example-com

# Custom key names in KV
dcert vault store --cert-file server.crt --key-file server.key \
  --cert-key tls_cert --key-key tls_key \
  secret/company/project/certs/www-example-com
```

#### Validate from Vault KV

Read a certificate and key from Vault KV, validate them, and display certificate details (same output as `dcert check`). Also verifies the private key matches the certificate.

```bash
dcert vault validate secret/company/project/certs/www-example-com

# Custom key names
dcert vault validate secret/company/project/certs/www-example-com \
  --cert-key tls_cert --key-key tls_key

# JSON output
dcert vault validate secret/company/project/certs/www-example-com --format json
```

#### Renew a Certificate

Read an existing certificate from Vault KV, extract its CN and SANs, issue a new certificate with the same parameters, and overwrite the KV entry.

```bash
dcert vault renew secret/company/project/certs/www-example-com --role my-role

# Custom TTL and mount
dcert vault renew secret/company/project/certs/www-example-com \
  --role my-role --ttl 2160h --mount pki_intermediate
```

#### Permission Errors

All Vault API calls produce clear, actionable error messages on permission denial:

```
Error: Permission denied by Vault.

  Endpoint: POST vault_intermediate/issue/my-role
  Required: create capability on "vault_intermediate/issue/my-role"

  Ask your Vault administrator to add this policy to your token:
    path "vault_intermediate/issue/my-role" {
      capabilities = ["create"]
    }
```

#### Full Options Reference

```
dcert vault issue [OPTIONS]
      --cn <NAME>           Common Name. Omit for interactive wizard.
      --san <SAN>           Subject Alternative Names (repeatable)
      --ip-san <IP>         IP SANs (repeatable)
      --ttl <TTL>           Certificate TTL (default: 8760h)
      --role <ROLE>         Vault PKI role name
      --mount <MOUNT>       Vault PKI mount point (default: vault_intermediate)
      --output <NAME>       Output file base name (default: sanitised CN)
  -f, --format <FORMAT>     Output format [pretty, json, yaml]
      --pfx-password <PW>   Output as PFX instead of PEM (env: DCERT_CERT_PASSWORD)
      --store-path <PATH>   Store cert+key in Vault KV after issuance

dcert vault sign [OPTIONS]
      --csr-file <FILE>     CSR PEM file. Omit for interactive wizard.
      --cn <NAME>           Override CN from CSR
      --san <SAN>           Additional SANs (repeatable)
      --ttl <TTL>           Certificate TTL (default: 8760h)
      --role <ROLE>         Vault PKI role name
      --mount <MOUNT>       PKI mount point (default: vault_intermediate)
      --output <NAME>       Output file base name
  -f, --format <FORMAT>     Output format [pretty, json, yaml]
      --store-path <PATH>   Store certificate in Vault KV after signing

dcert vault revoke [OPTIONS]
      --serial <SERIAL>     Certificate serial number (hex, colon or hyphen-separated)
      --cert-file <FILE>    PEM certificate file to revoke
      --mount <MOUNT>       PKI mount point (default: vault_intermediate)

dcert vault list [OPTIONS]
      --mount <MOUNT>       PKI mount point (default: vault_intermediate)
  -f, --format <FORMAT>     Output format [pretty, json, yaml]
      --show-details        Fetch details for each certificate
      --expired-only        Show only expired certificates
      --valid-only          Show only valid certificates
      --export <FILE>       Export to JSON or CSV file

dcert vault store [OPTIONS] <PATH>
      --cert-file <FILE>    Local PEM certificate file (required)
      --key-file <FILE>     Local PEM private key file (required)
      --cert-key <NAME>     KV key name for certificate (default: cert)
      --key-key <NAME>      KV key name for private key (default: key)

dcert vault validate [OPTIONS] <PATH>
      --cert-key <NAME>     KV key name for certificate (default: cert)
      --key-key <NAME>      KV key name for private key (default: key)
  -f, --format <FORMAT>     Output format [pretty, json, yaml]

dcert vault renew [OPTIONS] <PATH>
      --role <ROLE>         PKI role name for issuing new certificate
      --mount <MOUNT>       PKI mount point (default: vault_intermediate)
      --ttl <TTL>           TTL for new certificate (default: 8760h)
      --cert-key <NAME>     KV key name for certificate (default: cert)
      --key-key <NAME>      KV key name for private key (default: key)
  -f, --format <FORMAT>     Output format [pretty, json, yaml]
```

---

## MCP Server (AI IDE Integration)

`dcert-mcp` is a Model Context Protocol server that exposes dcert's capabilities as tools for AI-powered IDEs. It supports two transport modes: **stdio** (default, for IDE integration) and **HTTP** (for remote deployment with optional OIDC/OAuth2 authentication).

### Tools

| Tool | Description |
|------|-------------|
| `analyze_certificate` | Decode and analyze TLS certificates. Returns subject, issuer, SANs, validity, fingerprints, extensions, TLS connection info, and OSI-layer diagnostics. Supports mTLS. |
| `check_expiry` | Check if certificates expire within N days. Returns `ALL_VALID`, `EXPIRING_SOON`, or `ALREADY_EXPIRED`. Supports mTLS. |
| `check_revocation` | Check OCSP revocation status via the certificate's OCSP responder. Supports mTLS. |
| `compare_certificates` | Compare certificates between two targets side-by-side. |
| `tls_connection_info` | Get TLS connection details: protocol, cipher, ALPN, latency, verification, diagnostics. Supports mTLS. |
| `export_pem` | Export TLS certificate chain from an HTTPS endpoint as PEM. Optionally saves to file and can exclude expired certs. Supports mTLS. |
| `create_csr` | Create a PKCS#10 CSR and private key. Supports RSA/ECDSA, OU metadata, and encrypted keys. Compliant with CA/B Forum, DigiCert, and X9 standards. |
| `validate_csr` | Validate a CSR for compliance with CA/B Forum Baseline Requirements, DigiCert, and X9 standards. Returns findings with severity levels. |
| `validate_certificate` | Run compliance checks on a certificate (PEM file or HTTPS endpoint). Checks key size, signature algorithm, validity period, SANs, CT, EKU, and Basic Constraints against CA/B Forum standards. |
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

### Proxy and Timeout Configuration

In corporate environments behind forward proxies, `dcert-mcp` inherits proxy settings from the environment. The subprocess (`dcert`) automatically receives all parent environment variables including proxy and SSL settings.

#### Proxy environment variables

| Variable | Description |
|----------|-------------|
| `HTTPS_PROXY` / `https_proxy` | Forward proxy URL for HTTPS connections |
| `HTTP_PROXY` / `http_proxy` | Forward proxy URL for HTTP connections (fallback for HTTPS) |
| `NO_PROXY` / `no_proxy` | Comma-separated list of hosts to bypass the proxy |
| `SSL_CERT_FILE` | Custom CA certificate file for proxy TLS interception |
| `SSL_CERT_DIR` | Custom CA certificate directory |

Example configuration with a corporate proxy:

```json
{
  "mcpServers": {
    "dcert": {
      "type": "stdio",
      "command": "dcert-mcp",
      "env": {
        "HTTPS_PROXY": "http://proxy.corp.com:8080",
        "NO_PROXY": "localhost,127.0.0.1,.internal.corp.com",
        "SSL_CERT_FILE": "/etc/ssl/certs/corporate-ca.pem"
      }
    }
  }
}
```

#### Timeout settings

`dcert-mcp` supports configurable timeouts via CLI flags or environment variables:

| Setting | CLI flag | Environment variable | Default | Description |
|---------|----------|---------------------|---------|-------------|
| Subprocess timeout | `--timeout` | `DCERT_MCP_TIMEOUT` | 60s | Max time for a single dcert invocation |
| Connection timeout | `--connection-timeout` | `DCERT_MCP_CONNECTION_TIMEOUT` | 10s | TCP connection timeout (passed to dcert) |
| Read timeout | `--read-timeout` | `DCERT_MCP_READ_TIMEOUT` | 5s | Response read timeout (passed to dcert) |

Example with extended timeouts for slow networks:

```json
{
  "mcpServers": {
    "dcert": {
      "type": "stdio",
      "command": "dcert-mcp",
      "env": {
        "DCERT_MCP_TIMEOUT": "120",
        "DCERT_MCP_CONNECTION_TIMEOUT": "30",
        "DCERT_MCP_READ_TIMEOUT": "15"
      }
    }
  }
}
```

### Troubleshooting

#### Startup diagnostics

`dcert-mcp` logs diagnostic information to stderr at startup. In MCP mode, stderr is separate from the protocol channel (which uses stdio), so these logs are visible in your IDE's MCP server output or logs:

```
[dcert-mcp] v3.0.12
[dcert-mcp] dcert binary: /usr/local/bin/dcert
[dcert-mcp] subprocess timeout: 60s
[dcert-mcp] connection timeout: 10s (--timeout)
[dcert-mcp] read timeout: 5s (--read-timeout)
[dcert-mcp] HTTPS proxy: http://proxy.corp.com:8080
[dcert-mcp] HTTP proxy: (none)
[dcert-mcp] NO_PROXY: localhost,127.0.0.1
```

Proxy URLs are logged with passwords masked (shown as `****`).

#### Common issues

**MCP server hangs or times out silently**

This often happens behind corporate proxies. Check:

1. Verify proxy settings are passed to `dcert-mcp` via the MCP config `env` block
2. Check the startup diagnostics show the expected proxy URL
3. Increase `DCERT_MCP_TIMEOUT` if the proxy is slow
4. If the target is internal, add it to `NO_PROXY`
5. If TLS interception is used, set `SSL_CERT_FILE` to the corporate CA bundle

**dcert binary not found**

If the startup log shows a warning about the dcert binary not being found:

1. Ensure `dcert` is on your `PATH`, or
2. Set `DCERT_PATH` to the full path in the MCP config `env` block

**Timeout errors with diagnostic hints**

When a subprocess times out, `dcert-mcp` produces actionable error messages that include:
- The timeout duration
- Detected proxy configuration
- Suggestions for adjusting timeout environment variables
- Hints about DNS, connectivity, or proxy issues

### HTTP Transport Mode

For remote or multi-user deployments, `dcert-mcp` can run as an HTTP server:

```bash
# Start in HTTP mode (no auth)
dcert-mcp --mode http --addr 0.0.0.0:3000

# With OIDC/OAuth2 authentication
DCERT_MCP_OIDC_ISSUER="https://login.example.com/v2.0" \
DCERT_MCP_OIDC_AUDIENCE="api://dcert-mcp" \
dcert-mcp --mode http --addr 0.0.0.0:3000

# With static bearer token (simpler deployments)
DCERT_MCP_AUTH_TOKEN="my-secret-token" \
dcert-mcp --mode http
```

The HTTP server exposes:
- `GET /health` — health check endpoint
- `POST /mcp` — JSON-RPC endpoint for MCP tool calls

#### Authentication (OIDC/OAuth2)

When running in HTTP mode, `dcert-mcp` supports OIDC/OAuth2 JWT authentication following [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2024-11-05/security). Authentication is resolved in priority order:

1. **OIDC/OAuth2** — if `DCERT_MCP_OIDC_ISSUER` is set (recommended for production)
2. **Static bearer token** — if only `DCERT_MCP_AUTH_TOKEN` is set
3. **No auth** — if neither is configured

OIDC tokens are validated against JWKS (JSON Web Key Sets) with automatic key rotation. Validated tokens are cached in-memory with a configurable sliding window TTL.

#### On-Behalf-Of (OBO) Token Exchange

For downstream API calls that require user context, `dcert-mcp` supports the OBO token exchange flow:

- User tokens are **never forwarded** to downstream APIs
- OBO exchange acquires a new token scoped to the downstream resource
- Classified error handling with actionable guidance for each failure mode

#### Authentication Environment Variables

| Variable | Description |
|----------|-------------|
| `DCERT_MCP_OIDC_ISSUER` | OIDC issuer URL (enables OIDC mode) |
| `DCERT_MCP_OIDC_AUDIENCE` | Expected audience claim (required with OIDC) |
| `DCERT_MCP_OIDC_JWKS_URL` | JWKS URL (auto-discovered from issuer if omitted) |
| `DCERT_MCP_REQUIRED_SCOPES` | Comma-separated required OAuth2 scopes |
| `DCERT_MCP_REQUIRED_ROLES` | Comma-separated required app roles |
| `DCERT_MCP_ALLOWED_CLIENTS` | Comma-separated allowed client app IDs |
| `DCERT_MCP_SESSION_TTL` | Session cache inactivity TTL in seconds (default: 300) |
| `DCERT_MCP_AUTH_TOKEN` | Static bearer token (lower priority than OIDC) |
| `DCERT_MCP_OBO_TOKEN_URL` | OBO token exchange endpoint |
| `DCERT_MCP_OBO_CLIENT_ID` | OBO client application ID |
| `DCERT_MCP_OBO_CLIENT_SECRET` | OBO client secret |

See [SECURITY.md](SECURITY.md) for full security architecture documentation.

---

## Features by Topic

### Certificate Analysis

Decode X.509 certificates from PEM files, HTTPS endpoints, bare hostnames, or piped stdin: subject, issuer, serial number, validity window, SANs, expiry status. Reads PEM data automatically when piped (e.g. `cat cert.pem | dcert`).

### Certificate Extensions and Fingerprints

SHA-256 fingerprints (`--fingerprint`), key usage, extended key usage, basic constraints, authority info access, signature algorithm, public key info, SCT count (`--extensions`).

### TLS Debugging

Protocol version, cipher suite, ALPN negotiation, certificate transparency, verification result, and per-certificate chain validation detail. Network latency measurements for DNS resolution, TCP connect (Layer 4), and TLS+HTTP (Layer 7). Enable `--debug` for full OSI-layer diagnostics.

### Mutual TLS (mTLS)

Client certificate authentication via PEM (`--client-cert` + `--client-key`) or PKCS12/PFX (`--pkcs12` + `--cert-password`). Custom CA bundle support (`--ca-cert`) for corporate/internal PKI.

### CSR Creation & Validation

Create PKCS#10 Certificate Signing Requests with guided interactive mode or CLI flags (`dcert csr create`). Supports RSA 4096 (default), RSA 2048, ECDSA P-256 (recommended), ECDSA P-384, and Ed25519 (modern EdDSA). Optional AES-256-CBC key encryption. Validate existing CSRs for compliance with CA/B Forum, DigiCert, and X9 standards (`dcert csr validate`). OU metadata identifiers (e.g., `AppId:my-service`) supported for internal PKI.

### Certificate Compliance

Run compliance checks against CA/B Forum Baseline Requirements, DigiCert, and X9 standards (`--compliance`). Checks key size, signature algorithm (SHA-256+ required), validity period (398-day maximum), Subject Alternative Names, Certificate Transparency (SCTs), Extended Key Usage, and Basic Constraints. Returns findings with severity levels (Error, Warning, Info) and an overall COMPLIANT/NON-COMPLIANT status. Available in pretty, JSON, and YAML formats.

### Key-Certificate Matching

Verify private key matches a certificate (`dcert verify-key`). Supports RSA and EC keys against PEM files or live HTTPS endpoints. Auto-discovers matching `.crt`/`.pem` + `.key` pairs in a directory when run without arguments.

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

### Vault PKI Integration

Issue, sign, revoke, list, and renew TLS certificates via HashiCorp Vault's PKI Secrets Engine (`dcert vault`). Store and validate certificates in Vault KV v2. Interactive wizard mode for guided certificate issuance. Full chain assembly from Vault root and intermediate CAs. Clear, actionable permission error messages with Vault policy hints.

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

# Compliance audit against CA/B Forum Baseline Requirements
dcert https://site.com --compliance

# Test specific cipher suites
dcert --cipher-list "ECDHE+AESGCM" --max-tls 1.2 https://target.com
```

### CSR Management

```bash
# Create a CSR for a new service
dcert csr create --cn api.example.com --org "My Corp" --country GB --san DNS:api.example.com

# Create with ECDSA P-256 for modern deployments
dcert csr create --cn api.example.com --key-algo ecdsa-p256

# Create with Ed25519 (modern EdDSA, compact signatures)
dcert csr create --cn api.example.com --key-algo ed25519

# Validate before submitting to CA
dcert csr validate api-example-com.csr --format json

# Internal PKI with metadata identifiers
dcert csr create --cn app.internal.corp --ou "AppId:svc-123" --ou "Env:prod"
```

### Vault PKI Automation

```bash
# Issue a certificate from Vault PKI and store in KV
dcert vault issue --cn www.example.com --role web-server \
  --san "DNS:*.example.com" --store-path secret/certs/www-example-com

# Renew a certificate stored in Vault KV
dcert vault renew secret/certs/www-example-com --role web-server

# Validate certificates stored in Vault KV
dcert vault validate secret/certs/www-example-com

# Audit all issued certificates
dcert vault list --show-details --export audit.csv

# Sign a CSR through Vault PKI
dcert vault sign --csr-file server.csr --role web-server --ttl 2160h
```

### Certificate Management

```bash
# Convert PFX for web server deployment
dcert convert pfx-to-pem server.pfx --password secret --output-dir /etc/ssl

# Prepare Java keystore
dcert convert create-keystore --cert server.pem --key server-key.pem --output keystore.p12 --password changeit

# Verify key matches certificate before deployment
dcert verify-key server.pem --key server-key.pem

# Verify all cert/key pairs in a directory
dcert verify-key --dir /etc/ssl/certs

# Compare staging vs production certificates
dcert --diff https://staging.example.com https://prod.example.com

# Export and backup certificate chains
for domain in google.com github.com; do
  dcert "https://$domain" --export-pem "${domain}-chain.pem"
done
```

---

## Python Package

A Python wrapper is available on PyPI, providing a FastMCP proxy around the `dcert-mcp` Rust binary. The Rust binary is **automatically downloaded** on first use with SHA256 checksum verification.

```bash
pip install dcert
```

### Quick Start

```python
from dcert import create_server

server = create_server()
server.run()  # stdio mode (default)
```

### CLI

```bash
# stdio mode (default, for MCP clients like Claude Code)
dcert-python

# HTTP mode
dcert-python --transport http --host 0.0.0.0 --port 8080

# Pre-download binary
dcert-python --setup
```

### Binary Discovery

The Python package locates the `dcert-mcp` binary in this order:

1. `DCERT_MCP_BINARY` environment variable
2. Bundled binary in the package `bin/` directory
3. Auto-download from GitHub Releases (with SHA256 checksum verification)
4. `dcert-mcp` on `PATH`

See the [Python package README](python/README.md) for full documentation.

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
