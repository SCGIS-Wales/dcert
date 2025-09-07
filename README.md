# dcert – TLS Certificate Decoder and HTTPS Probe

A robust command line tool in Rust for decoding PEM certificates and probing HTTPS endpoints. It extracts Common Name and SANs, detects Certificate Transparency SCTs, prints TLS version and cipher suite, and measures Layer 4, Layer 6, and Layer 7 timings. It supports proxies, custom CA bundles, and optional chain export.

## Install from source

```bash
cargo build --release
```

## Usage

### File mode

```bash
dcert path/to/certs.pem [--format pretty|json|csv] [--expired-only]
```

### HTTPS mode

```bash
dcert https://example.com \
  --tls-version 1.3 \
  --http-version h2 \
  --method GET \
  --headers key=value,key2=value2 \
  --ca-file /path/to/ca.pem \
  --export-chain \
  --timeout-l4 15 --timeout-l6 15 --timeout-l7 15 \
  --format pretty
```

Notes:
- Default TLS version is 1.3.
- Default HTTP version is HTTP/2.
- Proxies: honours `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` patterns (e.g. `NO_PROXY=::1,.internal.net`).
- CA bundle: `--ca-file` overrides `SSL_CERT_FILE`. If verification fails, the handshake still completes and **Trusted with local TLS CAs** is set to `<not available>`.
- Chain export: `--export-chain` writes the certificate chain to a file in PEM format.

### Output example (HTTPS)

```
HTTPS session
  Connection on OSI layer 4 (TCP)     : OK
  Connection on OSI layer 6 (TLS)     : OK
  Connection on OSI layer 7 (HTTPS)   : OK
  TLS version agreed                  : 1.3
  TLS cipher suite                    : TLS13_AES_256_GCM_SHA384
  Negotiated ALPN                     : h2
  Network delay to layer 4 (ms)       : 23
  Network delay to layer 7 (ms)       : 118
  Trusted with local TLS CAs          : <not available>
  Client certificate requested        : false
```

The certificate chain is printed in the chosen format with fields such as `common_name`, `subject_alt_names`, and `has_embedded_sct`.

### Version info

```bash
dcert --version
```
Prints the tool version.

## Docker

A simple Alpine-based multi-stage build is included.

```bash
docker build -t dcert:local .
docker run --rm -v $PWD:/work -w /work dcert:local dcert https://example.com
```

## License

MIT
