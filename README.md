# dcert · TLS Certificate Decoder & Validator

A powerful Rust CLI tool that reads X.509 certificates from PEM files or fetches them directly from HTTPS endpoints. It extracts key certificate information, validates TLS connections, checks revocation status, and provides detailed debugging output.

[![CI/CD Pipeline](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg)](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml)

## Features

- **Dual Mode Operation**: Parse certificates from PEM files OR fetch live certificates from HTTPS endpoints
- **Multiple Targets**: Process multiple PEM files and URLs in a single invocation, or pipe targets via stdin
- **Comprehensive Certificate Analysis**: Subject, issuer, serial number, validity window, expiry status, SANs, and fingerprints
- **Certificate Extensions**: Key usage, extended key usage, basic constraints, authority info access, signature algorithm, and public key info (algorithm & key size)
- **Certificate Transparency**: SCT presence detection and SCT count (with `--extensions`)
- **TLS Connection Debugging**: Protocol version, cipher suite, certificate transparency, chain validation detail, and verification result
- **OCSP Revocation Checking**: Verify certificate revocation status via OCSP responders
- **Expiry Warnings**: Alert when certificates are approaching expiry with configurable threshold and exit codes
- **Certificate Comparison**: Side-by-side diff of certificates between two targets
- **Monitoring Mode**: Periodically re-check targets and detect certificate changes
- **Network Performance Metrics**: Layer 4 (TCP) and Layer 7 (TLS+HTTP) latency measurements
- **Flexible Output**: Pretty console output, JSON, or YAML
- **Advanced Filtering**: Show only expired certificates
- **Certificate Sorting**: Sort certificates by expiry date (ascending or descending)
- **Certificate Export**: Save fetched certificate chains as PEM files with optional filtering of expired certificates
- **Custom HTTP Options**: Configure HTTP method, headers, protocol version, SNI override, and connection timeout
- **TLS Verification Control**: Disable verification with `--no-verify` for testing environments (with visible warning)
- **Machine-Readable Exit Codes**: Distinct exit codes for success, expiry warnings, errors, verification failures, expired certs, and revoked certs
- **Separate Read Timeout**: Configure read timeout independently from connection timeout with `--read-timeout`
- **Smart Watch Mode**: Automatically enables fingerprinting for change detection in `--watch` mode
- **Interactive Stdin Detection**: Prints a helpful prompt when reading from a terminal stdin

## Installation

### Prebuilt binaries

Download the latest release from the **Releases** page and place the `dcert` binary on your `PATH`.

```bash
# Example for x86_64 glibc
curl -L https://github.com/SCGIS-Wales/dcert/releases/latest/download/dcert-x86_64-unknown-linux-gnu.tar.gz | tar xz
chmod +x dcert
sudo mv dcert /usr/local/bin/
```

### Homebrew

Install via the SCGIS-Wales tap:

```bash
# Add the tap
brew tap SCGIS-Wales/homebrew-tap https://github.com/SCGIS-Wales/homebrew-tap.git

# Install dcert
brew install dcert

# Verify installation
dcert --version
```

To update to the latest version:

```bash
brew update
brew upgrade dcert
```

### Build from source

Prerequisites: Rust and Cargo.

```bash
git clone https://github.com/SCGIS-Wales/dcert.git
cd dcert
cargo build --release
# Optional install to ~/.cargo/bin
cargo install --path .
```

### Docker

```bash
# Pull
docker pull ghcr.io/scgis-wales/dcert:main

# Run with a local PEM file
docker run --rm -v "$PWD:/data" ghcr.io/scgis-wales/dcert:main /data/certificate.pem

# Fetch from HTTPS endpoint
docker run --rm ghcr.io/scgis-wales/dcert:main https://www.google.com
```

## Usage

### Basic Examples

```bash
# Analyze a local PEM file
dcert certificate.pem

# Fetch and analyze certificates from an HTTPS endpoint
dcert https://www.google.com

# Multiple targets in a single invocation
dcert https://www.google.com https://github.com cert.pem

# Pipe targets from stdin
echo -e "https://google.com\nhttps://github.com" | dcert -

# Only show expired certificates from a bundle
dcert certificates.pem --expired-only

# Output in JSON or YAML format
dcert https://example.com --format json
dcert https://example.com --format yaml

# Show SHA-256 fingerprints
dcert https://example.com --fingerprint

# Show certificate extensions (key usage, EKU, basic constraints, AIA)
dcert https://example.com --extensions

# Warn if certificates expire within 30 days (exits with code 1)
dcert https://example.com --expiry-warn 30

# Check OCSP revocation status
dcert https://example.com --check-revocation

# Compare certificates between two targets
dcert --diff https://www.google.com https://www.github.com

# Monitor certificates every 60 seconds
dcert --watch 60 https://example.com

# Override SNI hostname
dcert https://10.0.0.1 --sni example.com

# Skip TLS verification (e.g. self-signed certs)
dcert https://localhost:8443 --no-verify

# Custom connection timeout
dcert https://slow-server.example.com --timeout 30

# Export fetched certificate chain to a file
dcert https://www.google.com --export-pem google-certs.pem

# Export certificate chain excluding expired certificates
dcert https://www.google.com --export-pem google-certs.pem --exclude-expired

# Sort certificates by expiry date (ascending - soonest expiry first)
dcert certificates.pem --sort-expiry asc

# Use HTTP/2 protocol
dcert --http-protocol http2 https://www.google.com

# Custom HTTP headers and method
dcert https://api.example.com --method POST --header "Authorization:Bearer token" --header "Content-Type:application/json"
```

### Command Line Options

```
dcert [OPTIONS] [TARGETS]...

Arguments:
  [TARGETS]...  Path(s) to PEM file(s) or HTTPS URL(s). Use '-' to read targets from stdin (one per line)

Options:
  -f, --format <FORMAT>                Output format [default: pretty] [possible values: pretty, json, yaml]
      --expired-only                   Show only expired certificates
      --export-pem <EXPORT_PEM>        Export the fetched PEM chain to a file (only for HTTPS targets)
      --exclude-expired                Exclude expired or invalid certificates from export (only with --export-pem)
      --sort-expiry <SORT_EXPIRY>      Sort certificates by expiry date (asc = soonest first, desc = latest first) [possible values: asc, desc]
      --method <METHOD>                HTTP method to use for HTTPS requests [default: get] [possible values: get, post, head, options]
      --header [<HEADER>...]           Custom HTTP headers (key:value), can be repeated
      --http-protocol <HTTP_PROTOCOL>  HTTP protocol to use [default: http1-1] [possible values: http1-1, http2]
      --no-verify                      Disable TLS certificate verification (insecure)
      --timeout <TIMEOUT>              Connection timeout in seconds [default: 10]
      --read-timeout <READ_TIMEOUT>   Read timeout in seconds (time to wait for server response) [default: 5]
      --sni <SNI>                      Override SNI hostname for TLS handshake
      --fingerprint                    Show SHA-256 fingerprint for each certificate
      --extensions                     Show certificate extensions (key usage, basic constraints, etc.)
      --expiry-warn <DAYS>             Warn if any certificate expires within the given number of days (exit code 1)
      --diff                           Compare certificates between exactly two targets
      --watch <SECONDS>                Periodically re-check targets at the given interval in seconds
      --check-revocation               Check certificate revocation status via OCSP
  -h, --help                           Print help
  -V, --version                        Print version
```

### Input Formats

#### PEM File
A single file can contain multiple certificates:

```pem
-----BEGIN CERTIFICATE-----
...base64...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
...base64...
-----END CERTIFICATE-----
```

#### HTTPS URL
Any valid HTTPS URL:
- `https://www.google.com`
- `https://api.github.com:443`
- `https://example.com/path?query=value`

## Output Examples

### Pretty Format (Live HTTPS Endpoint)

```
dcert https://www.google.com

Debug
  HTTP protocol: HTTP/1.1
  HTTP response code: 200
  Hostname matches certificate SANs/CN: true
  TLS version used: TLSv1.3
  TLS ciphersuite agreed: TLS_AES_256_GCM_SHA384
  TLS verification result: ok
  Certificate transparency: true

  Network latency (layer 4/TCP connect): 27 ms
  Network latency (layer 7/TLS+HTTP):    125 ms

Note: Layer 4 and Layer 7 latencies are measured separately and should not be summed.

Certificate
  Index        : 0
  Subject      : CN=www.google.com
  Issuer       : C=US, O=Google Trust Services, CN=WR2
  Serial       : 00E7ABC9898ECE40981042627F3050E7BA
  Not Before   : 2025-08-25T08:41:50Z
  Not After    : 2025-11-17T08:41:49Z
  SANs         :
    - DNS:www.google.com
  Status       : valid

Certificate
  Index        : 1
  Subject      : C=US, O=Google Trust Services, CN=WR2
  Issuer       : C=US, O=Google Trust Services LLC, CN=GTS Root R1
  Serial       : 7FF005A07C4CDED100AD9D66A5107B98
  Not Before   : 2023-12-13T09:00:00Z
  Not After    : 2029-02-20T14:00:00Z
  Status       : valid

Certificate
  Index        : 2
  Subject      : C=US, O=Google Trust Services LLC, CN=GTS Root R1
  Issuer       : C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA
  Serial       : 77BD0D6CDB36F91AEA210FC4F058D30D
  Not Before   : 2020-06-19T00:00:42Z
  Not After    : 2028-01-28T00:00:42Z
  Status       : valid
```

### JSON Format

```bash
dcert --http-protocol http2 https://www.google.com --format json
```

```json
[
  {
    "index": 0,
    "subject": "CN=www.google.com",
    "issuer": "C=US, O=Google Trust Services, CN=WR2",
    "common_name": "www.google.com",
    "subject_alternative_names": [
      "DNS:www.google.com"
    ],
    "serial_number": "00E7ABC9898ECE40981042627F3050E7BA",
    "not_before": "2025-08-25T08:41:50Z",
    "not_after": "2025-11-17T08:41:49Z",
    "is_expired": false,
    "ct_present": true
  }
]
```

> **Note:** When `--fingerprint`, `--extensions`, or `--check-revocation` flags are used, additional fields appear in the output (e.g. `sha256_fingerprint`, `public_key_algorithm`, `public_key_size_bits`, `key_usage`, `extended_key_usage`, `basic_constraints`, `authority_info_access`, `signature_algorithm`, `sct_count`, `revocation_status`).

### Exit Codes

dcert uses distinct exit codes for scripting and CI/CD integration:

| Code | Meaning |
|------|---------|
| 0 | Success - all certificates are valid |
| 1 | Expiry warning - certificate(s) expiring within `--expiry-warn` threshold |
| 2 | Error - connection failure, file not found, or processing error |
| 3 | TLS verification failed - certificate chain could not be verified |
| 4 | Certificate expired - at least one certificate in the chain has expired |
| 5 | Certificate revoked - OCSP reports at least one certificate as revoked |

```bash
# Use in CI/CD scripts
dcert https://your-api.com --expiry-warn 30
case $? in
  0) echo "All good" ;;
  1) echo "Certificate expiring soon" ;;
  3) echo "TLS verification failed" ;;
  4) echo "Certificate expired!" ;;
  5) echo "Certificate revoked!" ;;
  *) echo "Error occurred" ;;
esac
```

## Advanced Usage

### TLS Debugging and Performance Analysis

The debug output provides valuable insights for TLS troubleshooting:

- **HTTP Protocol**: Shows whether HTTP/1.1 or HTTP/2 was used
- **HTTP Response Code**: Actual response code from the server
- **Hostname Validation**: Checks if the certificate matches the requested hostname
- **TLS Version & Cipher**: Shows negotiated TLS version and cipher suite
- **TLS Verification Result**: Shows the OpenSSL verification outcome with per-certificate detail on failure
- **Certificate Transparency**: Indicates if CT logs are present (with SCT count when `--extensions` is used)
- **Network Latency**: Separate measurements for TCP and TLS+HTTP layers

### Certificate Extensions and Fingerprints

Inspect detailed certificate metadata:

```bash
# Show SHA-256 fingerprints and all extensions together
dcert https://example.com --fingerprint --extensions

# Extensions include:
#   - Signature algorithm (e.g. SHA256-RSA)
#   - Public key algorithm and key size (e.g. RSA 2048 bits, EC 256 bits)
#   - Key usage (e.g. Digital Signature, Key Encipherment)
#   - Extended key usage (e.g. TLS Web Server Authentication)
#   - Basic constraints (CA status and path length)
#   - Authority info access (OCSP and CA issuer URLs)
#   - SCT count (number of Signed Certificate Timestamps)
```

### OCSP Revocation Checking

Verify that certificates have not been revoked:

```bash
# Check revocation status via OCSP
dcert https://example.com --check-revocation

# Combine with JSON for programmatic access
dcert https://example.com --check-revocation --format json | jq '.[0].revocation_status'
```

### Expiry Monitoring and Warnings

Use `--expiry-warn` in CI/CD pipelines or cron jobs:

```bash
# Exit code 1 if any cert expires within 30 days
dcert https://your-api.com --expiry-warn 30

# Use in a script
if ! dcert https://your-api.com --expiry-warn 14 > /dev/null 2>&1; then
  echo "Certificate expiring soon!"
fi
```

### Certificate Comparison

Compare certificate chains between two targets:

```bash
# Diff certificates from two endpoints
dcert --diff https://www.google.com https://www.github.com

# Diff a local PEM against a live endpoint
dcert --diff cert.pem https://example.com
```

### Continuous Monitoring

Watch mode re-checks targets at a fixed interval and reports changes:

```bash
# Re-check every 5 minutes
dcert --watch 300 https://example.com

# Monitor multiple targets
dcert --watch 60 https://api.example.com https://www.example.com
```

### SNI Override and Verification Control

Test specific backends behind load balancers or self-signed certs:

```bash
# Connect to an IP but send a specific SNI hostname
dcert https://10.0.0.1 --sni api.example.com

# Skip verification for self-signed or dev environments
dcert https://localhost:8443 --no-verify
```

### Certificate Chain Export

Export certificate chains for offline analysis or compliance:

```bash
# Export Google's certificate chain
dcert https://www.google.com --export-pem google-chain.pem

# Analyze the exported chain later
dcert google-chain.pem --format json
```

### Custom HTTP Requests

Test APIs and services with custom headers:

```bash
# API testing with authentication
dcert https://api.github.com --header "Authorization:token ghp_xxxx" --header "User-Agent:dcert/2.0"

# Test with different HTTP methods
dcert https://httpbin.org/post --method POST --header "Content-Type:application/json"

# Set a longer timeout for slow servers
dcert https://slow-server.example.com --timeout 30

# Set separate read timeout for slow responses
dcert https://slow-server.example.com --timeout 30 --read-timeout 15
```

## Use Cases

### DevOps & Site Reliability

```bash
# CI/CD gate: fail the build if certs expire within 14 days
dcert https://your-api.com --expiry-warn 14

# Check multiple endpoints at once
dcert https://api.example.com https://www.example.com https://admin.example.com

# Continuous monitoring with change detection
dcert --watch 300 https://your-api.com https://your-site.com

# Performance monitoring
dcert https://your-app.com --format json | jq '{l4: .debug.l4_latency_ms, l7: .debug.l7_latency_ms}'
```

### Security Auditing

```bash
# Check for weak TLS configurations
dcert https://target.com | grep -E "(TLS version|ciphersuite)"

# Verify revocation status
dcert https://example.com --check-revocation

# Full audit with extensions, fingerprints and revocation
dcert https://site.com --fingerprint --extensions --check-revocation

# Audit certificate chains as JSON
dcert https://site.com --format json --extensions | jq '.[] | {subject, key_usage, extended_key_usage}'
```

### Certificate Management

```bash
# Find expiring certificates in a bundle
dcert certificate-bundle.pem --expiry-warn 90

# Sort certificates by expiry to find those expiring soonest
dcert certificate-bundle.pem --sort-expiry asc

# Compare certificates across environments
dcert --diff https://staging.example.com https://prod.example.com

# Export and backup certificate chains
for domain in google.com github.com stackoverflow.com; do
  dcert "https://$domain" --export-pem "${domain}-chain.pem"
done

# Export only valid (non-expired) certificates from a bundle
dcert certificate-bundle.pem --export-pem valid-certs.pem --exclude-expired

# Pipe targets from a file
cat endpoints.txt | dcert - --format yaml
```

## Development

```bash
# Format and lint
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings

# Tests
cargo test

# Build release
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

[x509-parser]: https://crates.io/crates/x509-parser
[clap]: https://crates.io/crates/clap
[colored]: https://crates.io/crates/colored
[openssl]: https://crates.io/crates/openssl
[serde_yml]: https://crates.io/crates/serde_yml
[ctrlc]: https://crates.io/crates/ctrlc
