# dcert · TLS Certificate Decoder & Validator

A powerful Rust CLI tool that reads X.509 certificates from PEM files or fetches them directly from HTTPS endpoints. It extracts key certificate information, validates TLS connections, and provides detailed debugging output.

[![CI/CD Pipeline](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg)](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml)

## Features

- **Dual Mode Operation**: Parse certificates from PEM files OR fetch live certificates from HTTPS endpoints
- **Comprehensive Certificate Analysis**: Subject, issuer, serial number, validity window, expiry status, and SANs
- **TLS Connection Debugging**: Protocol version, cipher suite, certificate transparency, mTLS detection
- **Network Performance Metrics**: Layer 4 (TCP) and Layer 7 (TLS+HTTP) latency measurements
- **Flexible Output**: Pretty console output or machine-readable JSON
- **Advanced Filtering**: Show only expired certificates
- **Certificate Sorting**: Sort certificates by expiry date (ascending or descending)
- **Certificate Export**: Save fetched certificate chains as PEM files with optional filtering of expired certificates
- **Custom HTTP Options**: Configure HTTP method, headers, and protocol version

## Installation

### Prebuilt binaries

Download the latest release from the **Releases** page and place the `dcert` binary on your `PATH`.

```bash
# Example for x86_64 glibc
curl -L https://github.com/SCGIS-Wales/dcert/releases/latest/download/dcert-x86_64-unknown-linux-gnu.tar.gz | tar xz
chmod +x dcert
sudo mv dcert /usr/local/bin/
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

# Only show expired certificates from a bundle
dcert certificates.pem --expired-only

# Output in JSON format
dcert https://example.com --format json

# Export fetched certificate chain to a file
dcert https://www.google.com --export-pem google-certs.pem

# Export certificate chain excluding expired certificates
dcert https://www.google.com --export-pem google-certs.pem --exclude-expired

# Sort certificates by expiry date (ascending - soonest expiry first)
dcert certificates.pem --sort-expiry asc

# Sort certificates by expiry date (descending - latest expiry first)
dcert certificates.pem --sort-expiry desc

# Use HTTP/2 protocol
dcert --http-protocol http2 https://www.google.com

# Custom HTTP headers and method
dcert https://api.example.com --method POST --header "Authorization:Bearer token" --header "Content-Type:application/json"
```

### Command Line Options

```
dcert [OPTIONS] <TARGET>

Arguments:
  <TARGET>  Path to a PEM file or an HTTPS URL like https://example.com

Options:
  -f, --format <FORMAT>                Output format [default: pretty] [possible values: pretty, json]
      --expired-only                   Show only expired certificates
      --export-pem <EXPORT_PEM>        Export the fetched PEM chain to a file (only for HTTPS targets)
      --exclude-expired                Exclude expired or invalid certificates from export (only with --export-pem)
      --sort-expiry <SORT_EXPIRY>      Sort certificates by expiry date (asc = soonest first, desc = latest first) [possible values: asc, desc]
      --method <METHOD>                HTTP method to use for HTTPS requests [default: GET]
      --header [<HEADER>...]           Custom HTTP headers (key:value), can be repeated
      --http-protocol <HTTP_PROTOCOL>  HTTP protocol to use [default: http1-1] [possible values: http1-1, http2]
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
  Mutual TLS requested: unknown
  Hostname matches certificate SANs/CN: true
  TLS version used: TLSv1.3
  TLS ciphersuite agreed: TLS_AES_256_GCM_SHA384
  Certificate transparency: true

  Network latency (layer 4/TCP connect): 27 ms
  Network latency (layer 7/TLS+HTTP):    125 ms

Note: Layer 4 and Layer 7 latencies are measured separately and should not be summed. Layer 4 covers TCP connection only; Layer 7 covers TLS handshake and HTTP request. DNS resolution and other delays are not included in these timings.

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
    "subject_alternative_names": [
      "DNS:www.google.com"
    ],
    "serial_number": "00E7ABC9898ECE40981042627F3050E7BA",
    "not_before": "2025-08-25T08:41:50Z",
    "not_after": "2025-11-17T08:41:49Z",
    "is_expired": false,
    "ct_present": true
  },
  {
    "index": 1,
    "subject": "C=US, O=Google Trust Services, CN=WR2",
    "issuer": "C=US, O=Google Trust Services LLC, CN=GTS Root R1",
    "serial_number": "7FF005A07C4CDED100AD9D66A5107B98",
    "not_before": "2023-12-13T09:00:00Z",
    "not_after": "2029-02-20T14:00:00Z",
    "is_expired": false,
    "ct_present": false
  },
  {
    "index": 2,
    "subject": "C=US, O=Google Trust Services LLC, CN=GTS Root R1",
    "issuer": "C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA",
    "serial_number": "77BD0D6CDB36F91AEA210FC4F058D30D",
    "not_before": "2020-06-19T00:00:42Z",
    "not_after": "2028-01-28T00:00:42Z",
    "is_expired": false,
    "ct_present": false
  }
]
```

## Advanced Usage

### TLS Debugging and Performance Analysis

The debug output provides valuable insights for TLS troubleshooting:

- **HTTP Protocol**: Shows whether HTTP/1.1 or HTTP/2 was used
- **HTTP Response Code**: Actual response code from the server
- **Mutual TLS**: Indicates if the server requested client certificates
- **Hostname Validation**: Checks if the certificate matches the requested hostname
- **TLS Version & Cipher**: Shows negotiated TLS version and cipher suite
- **Certificate Transparency**: Indicates if CT logs are present
- **Network Latency**: Separate measurements for TCP and TLS+HTTP layers

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
dcert https://api.github.com --header "Authorization:token ghp_xxxx" --header "User-Agent:dcert/1.0"

# Test with different HTTP methods
dcert https://httpbin.org/post --method POST --header "Content-Type:application/json"
```

## Use Cases

### DevOps & Site Reliability

```bash
# Quick certificate expiry check
dcert https://your-api.com --format json | jq '.[0].not_after'

# Monitor certificate transparency compliance
dcert https://your-site.com | grep "Certificate transparency"

# Performance monitoring
dcert https://your-app.com | grep "Network latency"
```

### Security Auditing

```bash
# Check for weak TLS configurations
dcert https://target.com | grep -E "(TLS version|ciphersuite)"

# Verify proper hostname matching
dcert https://example.com | grep "Hostname matches"

# Audit certificate chains
dcert https://site.com --format json | jq '.[] | {subject, issuer, not_after}'
```

### Certificate Management

```bash
# Find expiring certificates in a bundle
dcert certificate-bundle.pem --format json | jq '.[] | select(.not_after < "2024-12-31")'

# Sort certificates by expiry to find those expiring soonest
dcert certificate-bundle.pem --sort-expiry asc

# Export and backup certificate chains
for domain in google.com github.com stackoverflow.com; do
  dcert "https://$domain" --export-pem "${domain}-chain.pem"
done

# Export only valid (non-expired) certificates from a bundle
dcert certificate-bundle.pem --export-pem valid-certs.pem --exclude-expired

# Combine sorting and filtering for certificate renewal planning
dcert certificate-bundle.pem --sort-expiry asc --format json | jq '.[] | select(.not_after < "2025-06-01")'
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
- TLS connections by [openssl]

[x509-parser]: https://crates.io/crates/x509-parser
[clap]: https://crates.io/crates/clap
[colored]: https://crates.io/crates/colored
[openssl]: https://crates.io/crates/openssl
