# dcert

[![dcert on PyPI](https://img.shields.io/pypi/v/dcert?label=dcert)](https://pypi.org/project/dcert/)
[![dcert-mcp on PyPI](https://img.shields.io/pypi/v/dcert-mcp?label=dcert-mcp)](https://pypi.org/project/dcert-mcp/)
[![CI](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SCGIS-Wales/dcert/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

dcert is a command line tool that decodes, validates and converts X.509
certificates and diagnoses TLS endpoints.

## Install

```bash
pip install dcert
uv tool install dcert      # on PATH, in its own environment
uvx dcert example.com      # run once without installing
```

## Examples

```bash
# Decode and validate the certificate chain of a live endpoint
dcert https://example.com

# Read a local certificate and print JSON
dcert cert.pem --format json

# Explain why an endpoint, mTLS handshake, gateway or proxy fails
dcert diagnose https://example.com

# Convert a PFX bundle to PEM files
dcert convert pfx-to-pem client.pfx --password secret --output-dir ./certs
```

## Platforms

| Platform | Wheel tag |
| --- | --- |
| Linux x86_64, glibc 2.34+ (RHEL 9, Ubuntu 22.04, Debian 12 and later) | `manylinux_2_34_x86_64` |
| macOS Intel 10.15+ | `macosx_10_15_x86_64` |
| macOS Apple Silicon 11+ | `macosx_11_0_arm64` |
| Windows x86_64 | `win_amd64` |

On any other platform (Linux aarch64, musl, Windows arm64) ask for `dcert>=4`:
pip then reports "No matching distribution found" instead of falling back to
the old platform independent 3.0.77 package. Use the Docker image
(`docker run --rm --entrypoint dcert ghcr.io/scgis-wales/dcert:latest example.com`)
or build from source:

```bash
cargo install --git https://github.com/SCGIS-Wales/dcert --locked --bin dcert dcert
```

## Security

The wheel contains one native executable, no Python code and no dependencies.
Nothing is downloaded at install or run time, so an install from PyPI or a
private mirror needs no access to GitHub. Releases carry build provenance
attestations and an SBOM; see the
[security policy](https://github.com/SCGIS-Wales/dcert/blob/main/SECURITY.md).

## MCP server

To give an AI assistant the same tools, install
[`dcert-mcp`](https://pypi.org/project/dcert-mcp/), which brings `dcert` with it:

```bash
pip install dcert-mcp
uv tool install dcert-mcp --with-executables-from dcert
```

## Documentation

The full documentation, the changelog and the security policy are in the
[repository](https://github.com/SCGIS-Wales/dcert#readme).
