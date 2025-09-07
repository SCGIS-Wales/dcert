# dcert · TLS PEM base64 certificate decoder

A small Rust CLI that reads one or more PEM encoded X.509 certificates from a file, extracts key fields, and prints them in a friendly table or as JSON.

[![CI/CD Pipeline](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg)](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml)

## Features

- Parse one or many certificates from a single PEM file
- Show subject, issuer, serial number, validity window, and expiry status
- Pretty console output or JSON
- Filter to only expired certificates

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

# Run with a local PEM file (positional filename)
docker run --rm -v "$PWD:/data" ghcr.io/scgis-wales/dcert:main /data/certificate.pem
```

## Usage

### Basic

```bash
# Validate a single certificate file
dcert certificate.pem

# Only show expired certificates
dcert certificates.pem --expired-only

# Output in JSON format
dcert certificate.pem --format json
```

### Options

```
dcert [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to a PEM file with one or more certificates

Options:
  -F, --format <FORMAT>  Output format [default: pretty] [possible values: pretty, json]
      --expired-only     Show only expired certificates
  -h, --help             Print help
  -V, --version          Print version
```

### Input format

A single file can contain multiple certificates back to back:

```pem
-----BEGIN CERTIFICATE-----
...base64...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
...base64...
-----END CERTIFICATE-----
```

## Output examples

### Pretty

```
Certificate
  Index        : 0
  Subject      : C=US, ST=WA, L=Redmond, O=Microsoft Corporation, CN=portal.azure.com
  Issuer       : C=US, O=Microsoft Corporation, CN=Microsoft Azure RSA TLS Issuing CA 07
  Serial       : 3302491B72E6A86185CFC9711A000002491B72
  Not Before   : 2025-08-26T06:32:23Z
  Not After    : 2026-02-22T06:32:23Z
  SANs         :
    - DNS:portal.azure.com
    - DNS:*.portal.azure.com
    - DNS:*.portal.azure.net
    - DNS:devicemanagement.microsoft.com
    - DNS:endpoint.microsoft.com
    - DNS:canary-endpoint.microsoft.com
    - DNS:lighthouse.microsoft.com
    - DNS:shell.azure.com
    - DNS:*.reactblade.portal.azure.net
    - DNS:*.reactblade-rc.portal.azure.net
    - DNS:*.reactblade-ms.portal.azure.net
    - DNS:vlcentral.microsoft.com
  Status       : valid

Certificate
  Index        : 1
  Subject      : C=US, O=Microsoft Corporation, CN=Microsoft Azure RSA TLS Issuing CA 07
  Issuer       : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
  Serial       : 0A43A9509B01352F899579EC7208BA50
  Not Before   : 2023-06-08T00:00:00Z
  Not After    : 2026-08-25T23:59:59Z
  Status       : valid

Certificate
  Index        : 2
  Subject      : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
  Issuer       : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
  Serial       : 033AF1E6A711A9A0BB2864B11D09FAE5
  Not Before   : 2013-08-01T12:00:00Z
  Not After    : 2038-01-15T12:00:00Z
  Status       : valid
```

### JSON

```json
[
  {
    "index": 0,
    "subject": "C=US, ST=WA, L=Redmond, O=Microsoft Corporation, CN=portal.azure.com",
    "issuer": "C=US, O=Microsoft Corporation, CN=Microsoft Azure RSA TLS Issuing CA 07",
    "subject_alternative_names": [
      "DNS:portal.azure.com",
      "DNS:*.portal.azure.com",
      "DNS:*.portal.azure.net",
      "DNS:devicemanagement.microsoft.com",
      "DNS:endpoint.microsoft.com",
      "DNS:canary-endpoint.microsoft.com",
      "DNS:lighthouse.microsoft.com",
      "DNS:shell.azure.com",
      "DNS:*.reactblade.portal.azure.net",
      "DNS:*.reactblade-rc.portal.azure.net",
      "DNS:*.reactblade-ms.portal.azure.net",
      "DNS:vlcentral.microsoft.com"
    ],
    "serial_number": "3302491B72E6A86185CFC9711A000002491B72",
    "not_before": "2025-08-26T06:32:23Z",
    "not_after": "2026-02-22T06:32:23Z",
    "is_expired": false
  },
  {
    "index": 1,
    "subject": "C=US, O=Microsoft Corporation, CN=Microsoft Azure RSA TLS Issuing CA 07",
    "issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2",
    "serial_number": "0A43A9509B01352F899579EC7208BA50",
    "not_before": "2023-06-08T00:00:00Z",
    "not_after": "2026-08-25T23:59:59Z",
    "is_expired": false
  },
  {
    "index": 2,
    "subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2",
    "issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2",
    "serial_number": "033AF1E6A711A9A0BB2864B11D09FAE5",
    "not_before": "2013-08-01T12:00:00Z",
    "not_after": "2038-01-15T12:00:00Z",
    "is_expired": false
  }
]
```

## Tips

### Inspect a live site quickly

```bash
echo | openssl s_client -connect example.com:443 2>/dev/null   | openssl crl2pkcs7 -nocrl -certfile /dev/stdin | openssl pkcs7 -print_certs   | dcert --format json -
```

### Filter only expired from a bundle

```bash
dcert bundle.pem --expired-only
```

## Development

```bash
# Format and lint
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings

# Tests
cargo test
```

## Licence

MIT. See [LICENCE](LICENSE).

## Acknowledgements

- Parsing by [x509-parser]
- CLI by [clap]
- Terminal colours by [colored]

[x509-parser]: https://crates.io/crates/x509-parser
[clap]: https://crates.io/crates/clap
[colored]: https://crates.io/crates/colored
