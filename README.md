# dcert – TLS Certificate Decoder and HTTPS Probe

`dcert` is a Rust CLI tool for decoding PEM certificates and probing HTTPS endpoints. It extracts and displays certificate details (subject, issuer, serial, common name, SANs, CA status, Certificate Transparency SCTs), prints TLS version and cipher suite, and measures connection timings for TCP, TLS, and HTTPS layers. It supports proxies, custom CA bundles, and exporting certificate chains.

## Install from source

```bash
cargo build --release
```

## Usage

### File mode (PEM certificate decoding)

```bash
dcert path/to/certs.pem [--format pretty|json|csv] [--expired-only]
```

- **--format**: Output format (`pretty`, `json`, or `csv`). Default: `pretty`.
- **--expired-only**: Show only expired certificates.

### HTTPS mode (endpoint probe)

```bash
dcert https://example.com \
  --tls-version 1.3 \
  --http-version h2 \
  --method GET \
  --headers key=value,key2=value2 \
  --ca-file /path/to/ca.pem \
  --export-chain \
  --timeout-l4 3 --timeout-l6 3 --timeout-l7 3 \
  --format pretty
```

- **--tls-version**: TLS version (`1.2`, `1.3`, or `auto`). Default: `1.3`.
- **--http-version**: HTTP version (`HTTP/1.1` or `HTTP/2`). Default: `HTTP/2`.
- **--method**: HTTP method. Default: `GET`.
- **--headers**: Comma-separated HTTP headers.
- **--ca-file**: Custom CA bundle for verification. Overrides `SSL_CERT_FILE`.
- **--export-chain**: Export the certificate chain to PEM.
- **--timeout-l4**: TCP connect timeout (seconds). Default: `3`.
- **--timeout-l6**: TLS handshake timeout (seconds). Default: `3`.
- **--timeout-l7**: HTTPS request timeout (seconds). Default: `3`.
- **--format**: Output format (`pretty`, `json`, or `csv`). Default: `pretty`.

### Features

- **Certificate details**: Subject, issuer, serial number, common name, SANs (one per line), CA status, Certificate Transparency (SCTs), validity dates, and expiration status (colored).
- **Session info**: TLS version, cipher suite, negotiated ALPN, client certificate request status, and connection timings for each layer.
- **Proxy support**: Honors `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` environment variables.
- **Custom CA bundle**: Use `--ca-file` to specify a CA bundle.
- **Chain export**: Use `--export-chain` to write the certificate chain to PEM.
- **Output formats**: Pretty table (with colors), JSON, or CSV.

### Understanding the Timing Output

- **Network delay to layer 4 (ms):** Time to establish the TCP connection (includes DNS and network latency).
- **Network delay to layer 7 (ms):** Time to complete the HTTP(S) request after TLS handshake.
- Layer 4 (TCP) always occurs before Layer 7 (HTTPS). Layer 4 can be slower due to network conditions, DNS, or proxies. Layer 7 is typically faster because it only measures the HTTP request/response after the connection is ready.

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

Certificate details are shown in a table with fields such as `Common Name`, `Subject Alternative Names`, `Serial`, `Is CA`, `Certificate Transparency (SCTs)`, `Issued on`, `Expires on`, and colored `Expired` status.

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
