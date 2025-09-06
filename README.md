# Homebrew Tap for dcert

This is the official Homebrew tap for [dcert](https://github.com/yourusername/dcert), a CLI tool to decode and validate TLS certificates from PEM files.

## Installation

```bash
# Add this tap
brew tap yourusername/tap

# Install dcert
brew install dcert
```

## Usage

```bash
# Basic certificate validation
dcert --file certificate.pem

# JSON output for scripting
dcert --file cert.pem --format json

# Check for expired certificates
dcert --file bundle.pem --expired-only

# CSV output for reports
dcert --file certs.pem --format csv
```

## About dcert

dcert is a fast, reliable TLS certificate decoder written in Rust that supports:

- **Multi-certificate PEM files** - Parse one or more certificates from a single file
- **Comprehensive validation** - Extract common name, SANs, expiry dates, serial numbers, issuer details
- **Enhanced SAN support** - Full IPv4, IPv6, domain name, email, and URI parsing
- **Multiple output formats** - Pretty console output, JSON, and CSV
- **Expiry checking** - Identify expired certificates and days until expiry
- **Certificate type detection** - Distinguish between CA and end-entity certificates

## Repository

Main project: [dcert](https://github.com/yourusername/dcert)

## Issues and Support

For issues, bug reports, or feature requests, please visit the [main repository](https://github.com/yourusername/dcert/issues).

## Updates

This tap is automatically updated when new versions of dcert are released. The formula is maintained via automated workflows.

## License

MIT License - see the [main repository](https://github.com/yourusername/dcert) for details.
