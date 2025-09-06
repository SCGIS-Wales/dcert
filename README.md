# dcert - TLS Certificate Decoder

A robust command-line tool written in Rust for decoding and validating TLS certificates from PEM files. Supports single or multiple certificates in one file and provides comprehensive validation information with enhanced Subject Alternative Names (SANs) support for domain names, IPv4, and IPv6 addresses.

[![CI/CD Pipeline](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg)](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml)
[![Security Audit](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg)](https://github.com/SCGIS-Wales/dcert/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

- **Multi-certificate support**: Parse one or more PEM certificates from a single file
- **Comprehensive validation**: Extract and validate common name, SANs, expiry dates, serial numbers, and issuer details
- **Enhanced SAN support**: Full IPv4, IPv6, domain name, email, URI, and other name type parsing with proper formatting
- **Multiple output formats**: Pretty-printed console output, JSON, and CSV formats
- **Expiry checking**: Identify expired certificates and calculate days until expiry
- **Certificate type detection**: Distinguish between CA and end-entity certificates
- **Key usage analysis**: Display certificate key usage extensions
- **Cross-platform**: Linux binaries with ARM64 and x86_64 support
- **Easy installation**: Available via Homebrew for Linux
- **Container support**: Docker images available

## 📦 Installation

### Homebrew (Linux) - Recommended

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add the dcert tap and install
brew tap SCGIS-Wales/tap
brew install dcert

# Or use our setup script
curl -fsSL https://raw.githubusercontent.com/SCGIS-Wales/dcert/main/setup-homebrew-tap.sh | bash
```

### Pre-built Binaries

Download the latest release from the [releases page](https://github.com/SCGIS-Wales/dcert/releases):

```bash
# For x86_64 Linux (glibc)
curl -L https://github.com/SCGIS-Wales/dcert/releases/latest/download/dcert-x86_64-unknown-linux-gnu.tar.gz | tar xz

# For x86_64 Linux (musl - static binary)
curl -L https://github.com/SCGIS-Wales/dcert/releases/latest/download/dcert-x86_64-unknown-linux-musl.tar.gz | tar xz

# For ARM64 Linux
curl -L https://github.com/SCGIS-Wales/dcert/releases/latest/download/dcert-aarch64-unknown-linux-gnu.tar.gz | tar xz

# Make executable and move to PATH
chmod +x dcert
sudo mv dcert /usr/local/bin/
```

### Build from Source

#### Prerequisites

- Rust 1.70 or later
- Cargo package manager

#### Building

```bash
# Clone the repository
git clone https://github.com/SCGIS-Wales/dcert.git
cd dcert

# Build in release mode
cargo build --release

# Install to ~/.cargo/bin (ensure it's in your PATH)
cargo install --path .
```

### Docker

```bash
# Pull the image
docker pull ghcr.io/scgis-wales/dcert:latest

# Run with a local PEM file
docker run --rm -v /path/to/certs:/certs ghcr.io/scgis-wales/dcert:latest --file /certs/cert.pem
```

## 🔧 Usage

### Basic Usage

```bash
# Validate a single certificate file
dcert --file certificate.pem

# Show only expired certificates
dcert --file certificates.pem --expired-only

# Output in JSON format
dcert --file certificate.pem --format json

# Output in CSV format
dcert --file certificate.pem --format csv
```

### Command-line Options

```
dcert [OPTIONS] --file <FILE>

Options:
  -f, --file <FILE>           Path to the PEM file containing one or more certificates
  -F, --format <FORMAT>       Output format [default: pretty] [possible values: pretty, json, csv]
      --expired-only          Show only expired certificates
  -h, --help                  Print help
  -V, --version               Print version
```

### Input File Format

The tool accepts PEM files containing one or more certificates:

```pem
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAL3qgn0W6jQxMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
... (certificate data) ...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEFjCCAv6gAwIBAgIJANgz8rNsF5j9MA0GCSqGSIb3DQEBCwUAMIGYMQswCQYD
... (another certificate data) ...
-----END CERTIFICATE-----
```

## 📊 Output Examples

### Pretty Format (Default)

```
=== Certificate #1 ===
Status: VALID
Common Name: example.com
Subject Alternative Names:
  - DNS:example.com
  - DNS:www.example.com
  - IP:192.168.1.1
  - IP:2001:db8::1
Serial Number: BEDF2A827D16EA343
Issuer: CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
Valid From: 2023-01-15 12:00:00 UTC
Valid Until: 2024-04-15 12:00:00 UTC
Expires in: 45 days
Certificate Type: End Entity Certificate
Key Usage: Digital Signature, Key Encipherment
```

### JSON Format

```json
{
  "certificates": [
    {
      "common_name": "example.com",
      "subject_alternative_names": [
        "DNS:example.com",
        "DNS:www.example.com",
        "IP:192.168.1.1",
        "IP:2001:db8::1"
      ],
      "serial_number": "BEDF2A827D16EA343",
      "issuer": "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
      "not_before": "2023-01-15T12:00:00Z",
      "not_after": "2024-04-15T12:00:00Z",
      "is_expired": false,
      "is_ca": false,
      "key_usage": ["Digital Signature", "Key Encipherment"],
      "days_until_expiry": 45
    }
  ]
}
```

### CSV Format

```csv
common_name,sans,serial_number,issuer,not_before,not_after,is_expired,is_ca,key_usage,days_until_expiry
"example.com","DNS:example.com;DNS:www.example.com;IP:192.168.1.1","BEDF2A827D16EA343","CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US","2023-01-15T12:00:00Z","2024-04-15T12:00:00Z",false,false,"Digital Signature;Key Encipherment",45
```

## 🌟 Real-world Examples

### Check SSL certificate from a website

```bash
# Get certificate from a website and validate it
echo | openssl s_client -connect example.com:443 2>/dev/null | \
  openssl x509 | dcert --file -
```

### Validate a certificate bundle

```bash
# Check all certificates in a bundle and get JSON output
dcert --file /etc/ssl/certs/bundle.pem --format json | \
  jq '.certificates[] | select(.is_expired == true)'
```

### Monitor certificate expiry

```bash
# Get expiry dates for monitoring and alerting
dcert --file *.pem --format csv | \
  awk -F, '{print $1","$6}' | sort -t, -k2
```

### Batch processing with expired filter

```bash
# Find only expired certificates across multiple files
for cert in *.pem; do
  echo "=== $cert ==="
  dcert --file "$cert" --expired-only
done
```

## 🤖 Automated Features

dcert includes comprehensive automation for maintenance and security:

### Automated Dependency Updates

- **Every 2 weeks**: Automatic dependency updates and patch releases
- **Security patches**: Immediate updates for security vulnerabilities
- **Compatibility testing**: Full test suite runs before each automated release
- **Homebrew integration**: Automatic formula updates with new releases

### Continuous Integration

- **Multi-platform builds**: x86_64, ARM64, and musl targets
- **Security auditing**: Automated vulnerability scanning with `cargo audit`
- **Code quality**: Formatting, linting, and comprehensive testing
- **Release automation**: Automatic GitHub releases with binaries and checksums

### Health Monitoring

- **Daily health checks**: System status and dependency monitoring
- **Automatic issue creation**: Alerts when problems are detected
- **Performance tracking**: Build times and test execution monitoring

## 🛠️ Development

### Prerequisites

- Rust 1.70+
- Git

### Setting up Development Environment

```bash
# Clone the repository
git clone https://github.com/SCGIS-Wales/dcert.git
cd dcert

# Install development dependencies
cargo install cargo-audit cargo-outdated

# Run tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Check code formatting
cargo fmt --check

# Run clippy for linting
cargo clippy -- -D warnings

# Security audit
cargo audit
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with coverage (requires cargo-tarpaulin)
cargo install cargo-tarpaulin
cargo tarpaulin --out Html

# Run integration tests only
cargo test --test integration

# Run specific test
cargo test test_parse_pem_certificates
```

### Manual Dependency Updates

Use the provided script for manual dependency management:

```bash
# Standard update (patch release)
./scripts/update-dependencies.sh

# Preview changes without updating
./scripts/update-dependencies.sh --dry-run

# Allow major version updates
./scripts/update-dependencies.sh --major --release-type minor

# Force update even if no changes
./scripts/update-dependencies.sh --force
```

## 🏗️ Project Structure

```
├── src/
│   └── main.rs              # Main application logic
├── .github/
│   ├── workflows/
│   │   ├── ci.yml          # Main CI/CD pipeline
│   │   └── auto-update-dependencies.yml  # Automated updates
│   └── dependabot.yml     # Dependency update configuration
├── scripts/
│   ├── update-dependencies.sh  # Manual dependency updates
│   └── test-all-formats.sh    # Comprehensive testing
├── Dockerfile              # Container definition
├── Cargo.toml             # Dependencies and metadata
└── README.md              # This file
```

## 🔒 Security

### Security Features

- **Automated vulnerability scanning**: Daily security audits with `cargo audit`
- **Dependency updates**: Automatic security patches every 2 weeks
- **Safe defaults**: No unsafe code, comprehensive error handling
- **Container security**: Non-root user, minimal attack surface

### Reporting Security Issues

If you discover a security vulnerability, please send an email to api-py@users.noreply.github.com. All security vulnerabilities will be promptly addressed.

## 🚢 Deployment and Distribution

### Homebrew for Linux

dcert is distributed via Homebrew for easy installation and updates:

```bash
# Add tap and install
brew tap SCGIS-Wales/tap
brew install dcert

# Update to latest version
brew upgrade dcert
```

### GitHub Releases

Every release includes:
- Pre-built binaries for multiple Linux targets
- SHA256 checksums for verification
- Docker images published to GitHub Container Registry
- Automatic changelog generation

### Automated Release Process

1. **Dependency updates**: Automated every 2 weeks
2. **Version bumping**: Automatic semantic versioning
3. **Testing**: Complete test suite before release
4. **Binary building**: Cross-compilation for multiple targets
5. **Distribution**: Homebrew formula and Docker image updates

## 📈 Performance

- **Memory efficient**: Streams large PEM files without loading entirely into memory
- **Fast parsing**: Uses efficient Rust libraries for certificate validation
- **Small binary size**: Optimized release builds (~2-3MB)
- **Cross-platform**: Native performance on Linux x86_64 and ARM64

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`cargo test`)
6. Run formatting and linting (`cargo fmt && cargo clippy`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### Development Guidelines

- **Code quality**: All code must pass formatting, linting, and tests
- **Documentation**: Update documentation for new features
- **Testing**: Add tests for new functionality
- **Security**: Consider security implications of changes
- **Performance**: Avoid performance regressions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) for performance and safety
- Certificate parsing via [x509-parser](https://crates.io/crates/x509-parser)
- Command-line interface via [clap](https://crates.io/crates/clap)
- Enhanced terminal output via [colored](https://crates.io/crates/colored)

## 📞 Support

- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/SCGIS-Wales/dcert/issues)
- **Discussions**: Join the conversation in [GitHub Discussions](https://github.com/SCGIS-Wales/dcert/discussions)
- **Email**: Contact api-py@users.noreply.github.com for direct support

## 🔗 Links

- **Repository**: https://github.com/SCGIS-Wales/dcert
- **Releases**: https://github.com/SCGIS-Wales/dcert/releases
- **Container Images**: https://github.com/SCGIS-Wales/dcert/pkgs/container/dcert
- **CI/CD Pipeline**: https://github.com/SCGIS-Wales/dcert/actions

---

**dcert** - Decode TLS certificates with confidence. Built by SCGIS Wales with ❤️ and Rust.