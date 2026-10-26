use anyhow::Result;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use pem_rfc7468::LineEnding;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::cli::{HttpProtocol, StarttlsProtocol, TlsVersionArg};
use crate::connect::{ConnectOverrides, ResolvedOverride};
use crate::debug::{dbg_section, debug_log, sanitize_header_value, sanitize_url};
use crate::keyex::{KeyExchangeClass, PqProbeResult, classify_group};
use crate::proxy::{ProxyConfig, connect_through_proxy};

pub const CONNECTION_TIMEOUT_SECS: u64 = 10;
pub const READ_TIMEOUT_SECS: u64 = 5;

/// Load CA certificates into the SSL connector builder.
///
/// Uses `openssl-probe` to discover system CA certificate locations and
/// configures the builder directly (via `set_ca_file` / `set_ca_path`),
/// avoiding `std::env::set_var()` which is unsound in multi-threaded
/// programs. Falls back to OpenSSL's `set_default_verify_paths()`.
///
/// This ensures dcert works on:
/// - macOS (Homebrew OpenSSL, which lacks Keychain access)
/// - Linux (distro-specific cert paths)
/// - Environments with custom CA bundles (SSL_CERT_FILE / SSL_CERT_DIR)
pub fn load_ca_certs(builder: &mut openssl::ssl::SslConnectorBuilder) -> Result<()> {
    // If the user has already set SSL_CERT_FILE / SSL_CERT_DIR, honour those
    // via OpenSSL's default verify paths (which reads those env vars).
    if openssl_probe::has_ssl_cert_env_vars() {
        builder
            .set_default_verify_paths()
            .map_err(|e| anyhow::anyhow!("Failed to load CA certificates: {e}"))?;
        return Ok(());
    }

    // Use openssl-probe to find system CA certs and configure the builder
    // directly instead of mutating environment variables (which is unsound
    // in multi-threaded programs since Rust 1.66).
    let probe = openssl_probe::probe();
    let mut loaded = false;

    if let Some(ref cert_file) = probe.cert_file
        && std::path::Path::new(cert_file).exists()
    {
        builder
            .set_ca_file(cert_file)
            .map_err(|e| anyhow::anyhow!("Failed to load CA file '{}': {}", cert_file.display(), e))?;
        loaded = true;
    }
    // If no cert file was loaded, fall back to OpenSSL's default verify paths.
    // This covers both the cert_dir case and systems where the cert file path
    // doesn't exist — OpenSSL will use SSL_CERT_DIR and its compiled-in defaults.
    if !loaded {
        builder
            .set_default_verify_paths()
            .map_err(|e| anyhow::anyhow!("Failed to load CA certificates: {e}"))?;
    }

    Ok(())
}

/// Establish a direct TCP connection: resolve within `timeout`, then try
/// every address in order (see [`crate::dns`]). Returns the stream, DNS
/// latency in milliseconds, and the address actually reached.
pub fn direct_tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<(TcpStream, u128, SocketAddr)> {
    let (addrs, dns_ms) = crate::dns::resolve_all(host, port, timeout)?;
    // The destination policy is enforced on the address actually dialled, so
    // a name that resolves somewhere else the second time is still refused.
    let (stream, addr) =
        crate::dns::connect_first(host, port, &addrs, timeout, |a| crate::netpolicy::enforce_addr(host, a))?;
    Ok((stream, dns_ms, addr))
}

/// Dial the target of a `--resolve` / `--connect-to` override.
///
/// Candidates are tried in order — `--resolve` may list several addresses for
/// one host — and each may be an IP literal (dialled directly) or a hostname
/// (resolved via DNS first). Returns the stream, the address actually reached,
/// and the DNS time spent, which is zero for IP literals.
///
/// Overrides deliberately bypass any forward proxy: the point of the flag is to
/// reach one specific endpoint, and routing that through a proxy would hand
/// destination selection back to the proxy.
pub fn connect_via_override(ov: &ResolvedOverride<'_>, timeout: Duration) -> Result<(TcpStream, SocketAddr, u128)> {
    let mut errors = Vec::new();

    for target in ov.targets {
        let attempt = match target.parse::<IpAddr>() {
            Ok(ip) => {
                let addr = SocketAddr::new(ip, ov.port);
                crate::netpolicy::enforce_addr(target, &addr).and_then(|()| {
                    TcpStream::connect_timeout(&addr, timeout)
                        .map(|s| (s, addr, 0))
                        .map_err(|e| anyhow::anyhow!("{e}"))
                })
            }
            Err(_) => direct_tcp_connect(target, ov.port, timeout).map(|(s, dns, addr)| (s, addr, dns)),
        };

        match attempt {
            Ok(result) => return Ok(result),
            Err(e) => errors.push(format!("{}:{}: {}", target, ov.port, e)),
        }
    }

    Err(anyhow::anyhow!(
        "{} could not reach any target ({})",
        ov.source,
        errors.join("; ")
    ))
}

/// One response header as sent by the server.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// Default number of body bytes captured for diagnostics.
pub use crate::limits::DEFAULT_BODY_LIMIT;
/// Upper bound accepted for `--body-limit`.
pub use crate::limits::MAX_BODY_LIMIT;

/// Parsed HTTP/1.x response head plus a bounded body excerpt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpResponseCapture {
    pub status: u16,
    pub reason: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
    pub body_truncated: bool,
}

impl HttpResponseCapture {
    /// First value of a header, case insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Parse raw response bytes. Tolerates a missing header terminator (the
    /// status line alone is enough to report a code) and never panics on
    /// malformed input.
    pub fn parse(raw: &[u8], body_limit: usize) -> Self {
        let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n");
        let (head, body) = match head_end {
            Some(i) => (&raw[..i], &raw[i + 4..]),
            None => (raw, &raw[raw.len()..]),
        };
        let head = String::from_utf8_lossy(head);
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let mut parts = status_line.splitn(3, ' ');
        let _version = parts.next();
        let status = parts.next().and_then(|c| c.parse::<u16>().ok()).unwrap_or(0);
        let reason = parts
            .next()
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .map(ToString::to_string);
        let headers = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                let name = name.trim();
                if name.is_empty() {
                    return None;
                }
                Some(HttpHeader {
                    name: name.to_ascii_lowercase(),
                    value: value.trim().to_string(),
                })
            })
            .collect();
        let body_truncated = body.len() > body_limit;
        Self {
            status,
            reason,
            headers,
            body: body[..body.len().min(body_limit)].to_vec(),
            body_truncated,
        }
    }

    /// Body as text, lossily decoded.
    pub fn body_text(&self) -> Option<String> {
        if self.body.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&self.body).into_owned())
        }
    }
}

/// Result of a TLS connection, containing the certificate chain and connection metadata.
#[derive(Debug, serde::Serialize, Clone, Default)]
pub struct TlsConnectionInfo {
    #[serde(skip)]
    pub pem_data: String,
    pub dns_latency: u128,
    pub l4_latency: u128,
    pub l7_latency: u128,
    pub tls_version: String,
    /// OpenSSL cipher name (e.g. "ECDHE-RSA-AES256-GCM-SHA384" for TLS 1.2)
    pub tls_cipher: String,
    /// IANA/RFC cipher name (e.g. "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
    pub tls_cipher_iana: Option<String>,
    /// ALPN negotiated protocol (e.g. "h2", "http/1.1")
    pub negotiated_protocol: Option<String>,
    /// Negotiated key exchange group, e.g. "X25519MLKEM768" or "X25519".
    /// `None` when the linked OpenSSL cannot report it (older than 3.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_exchange_group: Option<String>,
    /// Classification of that group: hybrid_pq, pure_pq, obsolete_pq,
    /// classical or unknown.
    pub key_exchange_class: KeyExchangeClass,
    /// Result of the opt in `--pq-probe` second handshake, when it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_quantum_probe: Option<PqProbeResult>,
    pub http_response_code: u16,
    /// Reason phrase from the status line, e.g. `Forbidden`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_reason: Option<String>,
    /// Response headers in wire order. Names are lower cased; values are
    /// trimmed. Empty when no response was read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_headers: Vec<HttpHeader>,
    /// Leading bytes of the response body (bounded by `--body-limit`),
    /// decoded lossily as UTF-8. Cleared before output unless `--show-body`
    /// is set or a diagnosis matched on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_body_excerpt: Option<String>,
    /// `true` when the body was cut at the limit.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub http_body_truncated: bool,
    pub verify_result: Option<String>,
    /// Per-certificate chain validation errors (depth, error, subject).
    pub chain_validation_errors: Vec<String>,
    /// `true` when the server requested a client certificate and the handshake
    /// failed because none was supplied (mTLS-required server). When set, the
    /// chain in `pem_data` was captured from the verify callback before the
    /// handshake aborted, so the user can still inspect the server identity.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub client_auth_required: bool,
    /// Whether the server sent a CertificateRequest and how the exchange
    /// ended: `not_requested`, `optional`, `required` or `presented`. Read
    /// from an OpenSSL callback, so it does not depend on alert wording and
    /// covers TLS 1.3 servers that reject the connection after the handshake.
    #[serde(default)]
    pub client_auth: crate::mtls::ClientAuthStatus,
    /// CA names the server listed in its CertificateRequest. Empty when it
    /// sent none, which many gateways do.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acceptable_client_cas: Vec<String>,
    /// `true` when `--no-verify` was set: the chain was accepted without
    /// validation and `verify_result` must not be read as a pass.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub verification_disabled: bool,
    /// Address actually dialled, e.g. "10.0.0.5:443". `None` when a forward
    /// proxy performed the connection on our behalf.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_address: Option<String>,
    /// Set when `--resolve` or `--connect-to` redirected the connection, e.g.
    /// "--resolve api.example.com:443 -> 10.0.0.5:443".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_override: Option<String>,
}

/// Detect whether an OpenSSL handshake failure is caused by the server
/// requiring client-certificate authentication that the client did not
/// supply.
///
/// Matches on the rendered error string against the well-known TLS alerts
/// for missing client cert: TLS 1.3 sends `tlsv13 alert certificate required`
/// (RFC 8446 §6.2 alert 116), TLS 1.2 typically sends a generic handshake
/// failure but the OpenSSL message includes `peer did not return a certificate`
/// when the local stack saw the CertificateRequest and we had nothing to
/// present.
pub fn is_client_auth_required(err_msg: &str) -> bool {
    let msg = err_msg.to_ascii_lowercase();
    msg.contains("certificate required")
        || msg.contains("peer did not return a certificate")
        || msg.contains("sslv3 alert certificate required")
        || msg.contains("tlsv13 alert certificate required")
        || msg.contains("tlsv1 alert handshake failure") && msg.contains("client_certificate")
}

/// Build a clear, actionable error message for a TLS handshake that failed
/// during certificate verification.
///
/// The common-but-confusing case is when the server presents an incomplete
/// chain (no intermediate) and the issuer's CA distribution endpoint (AIA /
/// CA-certificate / OCSP / CRL URL — e.g. `cacerts.digicert.com`,
/// `ocsp.digicert.com`) is blocked by a firewall. dcert (like OpenSSL) does
/// not fetch missing intermediates over AIA, so the result is an
/// `unable to get local issuer certificate` verify error. We detect that and
/// say so explicitly rather than blaming the local CA store.
///
/// `verify_details` are the per-cert verify errors captured during the
/// handshake (format: `depth N: <openssl error> (<subject>)`).
fn handshake_verify_error(err_str: &str, verify_details: &[String], custom_ca: bool) -> anyhow::Error {
    let lower = err_str.to_ascii_lowercase();
    let details_blob = verify_details.join("; ").to_ascii_lowercase();

    let missing_issuer =
        lower.contains("unable to get local issuer") || details_blob.contains("unable to get local issuer");
    let unknown_root = details_blob.contains("self signed certificate in certificate chain")
        || details_blob.contains("self-signed certificate in certificate chain")
        || lower.contains("self signed certificate in certificate chain");

    // Pull the subject of the deepest cert whose issuer could not be found —
    // that is the missing link in the chain.
    let missing_subject = verify_details
        .iter()
        .rfind(|d| d.to_ascii_lowercase().contains("unable to get local issuer"))
        .and_then(|d| d.split_once('(').map(|(_, s)| s.trim_end_matches(')').to_string()));

    let detail_lines = if verify_details.is_empty() {
        String::new()
    } else {
        format!("\n  Chain validation details: {}", verify_details.join("; "))
    };

    // A hostname mismatch is its own failure and has nothing to do with CA
    // trust, so say so rather than sending the user off to check SSL_CERT_FILE.
    // It is the expected outcome when --resolve/--connect-to point at a server
    // that does not serve a certificate for the target name.
    if lower.contains("hostname mismatch") {
        return anyhow::anyhow!(
            "TLS certificate does not match the hostname being validated. The server \
             presented a certificate whose SANs/CN do not cover the host in the target URL.\n  \
             - With --resolve/--connect-to, the target hostname is still what gets validated; \
             check that the address you redirected to serves a certificate for that name\n  \
             - Use --sni <name> to send a different SNI value\n  \
             - Or use --no-verify to inspect the certificate anyway (diagnostic only)\
             {detail_lines}\n  Underlying error: {err_str}"
        );
    }

    if missing_issuer && !unknown_root {
        let who = missing_subject.map(|s| format!(" for '{s}'")).unwrap_or_default();
        anyhow::anyhow!(
            "TLS chain incomplete: could not build a trusted path to a root CA. \
             The server did not send the intermediate CA certificate{who}, and dcert does \
             not fetch it from the issuer's AIA URL. This commonly happens when a firewall \
             blocks the CA's certificate/AIA/OCSP endpoint (e.g. cacerts.digicert.com, \
             ocsp.digicert.com). To resolve:\n  \
             - Supply the missing intermediate(s) with --ca-cert <chain.pem>\n  \
             - Or unblock outbound access to the CA's AIA/OCSP endpoints\n  \
             - Or use --no-verify to skip certificate verification (diagnostic only)\
             {detail_lines}\n  Underlying error: {err_str}"
        )
    } else if !custom_ca {
        anyhow::anyhow!(
            "TLS handshake failed: {err_str}\n\
             Hint: OpenSSL could not find the CA certificates needed to verify this chain. Try one of:\n  \
             - Set SSL_CERT_FILE to point to your CA bundle (e.g. /etc/ssl/certs/ca-certificates.crt)\n  \
             - Set SSL_CERT_DIR to your certificates directory\n  \
             - Supply the trust anchor with --ca-cert <ca.pem>\n  \
             - Use --no-verify to skip certificate verification\
             {detail_lines}"
        )
    } else {
        anyhow::anyhow!(
            "TLS handshake failed: {err_str}\n  \
             The provided --ca-cert bundle did not verify the server chain. Ensure it \
             contains the issuing intermediate(s) and root.{detail_lines}"
        )
    }
}

/// Encode a sequence of OpenSSL `X509` certificates as a single
/// concatenated PEM string. Used both on the success path (after a full
/// handshake) and on the mTLS-required failure path (chain captured during
/// verification).
fn chain_to_pem(certs: &[openssl::x509::X509]) -> Result<String> {
    let mut pem = String::new();
    for cert in certs {
        let der = cert
            .to_der()
            .map_err(|e| anyhow::anyhow!("DER conversion failed: {e}"))?;
        let pem_str = pem_rfc7468::encode_string("CERTIFICATE", LineEnding::LF, &der)
            .map_err(|e| anyhow::anyhow!("PEM encoding failed: {e}"))?;
        pem.push_str(&pem_str);
        if !pem.ends_with('\n') {
            pem.push('\n');
        }
    }
    Ok(pem)
}

/// Everything needed to build an [`SslConnector`] for a probe. Shared by the
/// HTTPS and STARTTLS paths so CA loading, client identity, protocol bounds,
/// cipher configuration and the verify callback are configured once.
struct ConnectorOptions<'a> {
    no_verify: bool,
    min_tls: Option<TlsVersionArg>,
    max_tls: Option<TlsVersionArg>,
    cipher_list: Option<&'a str>,
    cipher_suites: Option<&'a str>,
    /// OpenSSL group list (`--groups`); `None` keeps the library default,
    /// which on OpenSSL 3.5+ already offers `X25519MLKEM768`.
    groups: Option<&'a str>,
    ca_cert_path: Option<&'a str>,
    identity: ClientIdentity<'a>,
    /// ALPN to advertise. `None` sends no ALPN extension (STARTTLS).
    alpn: Option<HttpProtocol>,
    debug: bool,
}

/// Client certificate material for mutual TLS.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientIdentity<'a> {
    pub client_cert_path: Option<&'a str>,
    pub client_key_path: Option<&'a str>,
    pub pkcs12_path: Option<&'a str>,
    pub cert_password: Option<&'a str>,
}

impl<'a> ConnectorOptions<'a> {
    fn from_probe(probe: &TlsProbeOptions<'a>, identity: ClientIdentity<'a>, alpn: Option<HttpProtocol>) -> Self {
        Self {
            no_verify: probe.no_verify,
            min_tls: probe.min_tls,
            max_tls: probe.max_tls,
            cipher_list: probe.cipher_list,
            cipher_suites: probe.cipher_suites,
            groups: probe.groups,
            ca_cert_path: probe.ca_cert_path,
            identity,
            alpn,
            debug: probe.debug,
        }
    }
}

/// Server chain and per-depth verification errors captured inside the
/// OpenSSL verify callback. Mutex access is poison tolerant so a panic in an
/// earlier callback never turns into a second panic inside OpenSSL.
#[derive(Clone, Default)]
struct VerifyCapture {
    errors: Arc<std::sync::Mutex<Vec<String>>>,
    chain: Arc<std::sync::Mutex<Vec<openssl::x509::X509>>>,
    /// Filled when the server sends a CertificateRequest.
    cert_request: crate::mtls::CertRequestCapture,
}

impl VerifyCapture {
    fn errors(&self) -> Vec<String> {
        self.errors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn chain(&self) -> Vec<openssl::x509::X509> {
        self.chain
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Turn a failed `connect()` into the user facing error, enriching
    /// verification failures with the captured per-depth detail. When the
    /// server had asked for a client certificate the error carries that
    /// request, so diagnostics can attribute the failure to mTLS.
    fn handshake_error(&self, e: &dyn std::fmt::Display, custom_ca: bool) -> anyhow::Error {
        let err_str = e.to_string();
        let err = if err_str.contains("certificate verify failed") || err_str.contains("unable to get local issuer") {
            handshake_verify_error(&err_str, &self.errors(), custom_ca)
        } else {
            anyhow::anyhow!("TLS handshake failed: {e}")
        };
        self.with_cert_request(err)
    }

    /// Wrap `err` in [`crate::mtls::CertRequestedError`] when the server had
    /// sent a CertificateRequest; otherwise return it unchanged.
    fn with_cert_request(&self, err: anyhow::Error) -> anyhow::Error {
        let request = self.cert_request.get();
        if request.requested {
            anyhow::Error::new(crate::mtls::CertRequestedError {
                message: format!("{err:#}"),
                acceptable_cas: request.acceptable_cas,
            })
        } else {
            err
        }
    }
}

/// Build the connector and install the capturing verify callback.
fn build_connector(opts: &ConnectorOptions<'_>) -> Result<(SslConnector, VerifyCapture)> {
    let debug = opts.debug;
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| anyhow::anyhow!("OpenSSL builder failed: {e}"))?;

    // CA material: custom bundle or the system store.
    if let Some(ca_path) = opts.ca_cert_path {
        debug_log!(debug, "Using custom CA bundle: {}", ca_path);
        builder
            .set_ca_file(ca_path)
            .map_err(|e| anyhow::anyhow!("Failed to load custom CA certificate '{ca_path}': {e}"))?;
    } else {
        load_ca_certs(&mut builder)?;
    }

    // Client identity for mTLS.
    let identity = opts.identity;
    if let Some(cert_path) = identity.client_cert_path {
        debug_log!(debug, "Loading client certificate: {}", cert_path);
        builder
            .set_certificate_file(cert_path, openssl::ssl::SslFiletype::PEM)
            .map_err(|e| anyhow::anyhow!("Failed to load client certificate '{cert_path}': {e}"))?;
        if let Some(key_path) = identity.client_key_path {
            debug_log!(debug, "Loading client private key: {}", key_path);
            builder
                .set_private_key_file(key_path, openssl::ssl::SslFiletype::PEM)
                .map_err(|e| anyhow::anyhow!("Failed to load client private key '{key_path}': {e}"))?;
        }
        builder
            .check_private_key()
            .map_err(|e| anyhow::anyhow!("Client certificate and private key do not match: {e}"))?;
        debug_log!(debug, "Client certificate and key verified");
    } else if let Some(p12_path) = identity.pkcs12_path {
        debug_log!(debug, "Loading PKCS12 client identity: {}", p12_path);
        let p12_data =
            std::fs::read(p12_path).map_err(|e| anyhow::anyhow!("Failed to read PKCS12 file '{p12_path}': {e}"))?;
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(&p12_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse PKCS12 file '{p12_path}': {e}"))?;
        let parsed = pkcs12
            .parse2(identity.cert_password.unwrap_or(""))
            .map_err(|e| anyhow::anyhow!("Failed to decrypt PKCS12 '{p12_path}' (wrong password?): {e}"))?;
        if let Some(ref cert) = parsed.cert {
            builder
                .set_certificate(cert)
                .map_err(|e| anyhow::anyhow!("Failed to set PKCS12 certificate: {e}"))?;
        }
        if let Some(ref pkey) = parsed.pkey {
            builder
                .set_private_key(pkey)
                .map_err(|e| anyhow::anyhow!("Failed to set PKCS12 private key: {e}"))?;
        }
        if let Some(ref ca_chain) = parsed.ca {
            for ca_cert in ca_chain {
                builder
                    .add_extra_chain_cert(ca_cert.to_owned())
                    .map_err(|e| anyhow::anyhow!("Failed to add PKCS12 CA cert to chain: {e}"))?;
            }
        }
        builder
            .check_private_key()
            .map_err(|e| anyhow::anyhow!("PKCS12 certificate and private key do not match: {e}"))?;
        debug_log!(debug, "PKCS12 client identity loaded and verified");
    }

    // Protocol bounds. The floor defaults to TLS 1.2 so it is independent of
    // the linked OpenSSL version.
    let effective_min = opts.min_tls.unwrap_or(TlsVersionArg::Tls1_2);
    builder
        .set_min_proto_version(Some(effective_min.to_ssl_version()))
        .map_err(|e| anyhow::anyhow!("Failed to set minimum TLS version to {effective_min}: {e}"))?;
    if let Some(max) = opts.max_tls {
        builder
            .set_max_proto_version(Some(max.to_ssl_version()))
            .map_err(|e| anyhow::anyhow!("Failed to set maximum TLS version to {max}: {e}"))?;
    }

    if let Some(ciphers) = opts.cipher_list {
        builder
            .set_cipher_list(ciphers)
            .map_err(|e| anyhow::anyhow!("Invalid cipher list '{ciphers}': {e}"))?;
    }
    if let Some(suites) = opts.cipher_suites {
        builder
            .set_ciphersuites(suites)
            .map_err(|e| anyhow::anyhow!("Invalid TLS 1.3 cipher suites '{suites}': {e}"))?;
    }
    if let Some(groups) = opts.groups {
        debug_log!(debug, "Key exchange groups offered: {}", groups);
        builder.set_groups_list(groups).map_err(|e| {
            anyhow::anyhow!(
                "Invalid TLS groups list '{groups}': {e} (linked {}; ML-KEM groups need OpenSSL 3.5 or later)",
                openssl::version::version()
            )
        })?;
    }

    // ALPN. Only HTTP/1.1 framing is implemented on the wire; advertising h2
    // lets the server state its preference, and the caller warns if h2 wins.
    match opts.alpn {
        Some(HttpProtocol::Http2) => builder
            .set_alpn_protos(b"\x02h2\x08http/1.1")
            .map_err(|e| anyhow::anyhow!("Failed to set ALPN protocols: {e}"))?,
        Some(HttpProtocol::Http1_1) => builder
            .set_alpn_protos(b"\x08http/1.1")
            .map_err(|e| anyhow::anyhow!("Failed to set ALPN protocols: {e}"))?,
        None => {}
    }

    // Capture the chain and per-depth errors. The callback fires once per
    // certificate as the server's Certificate flight is processed, before the
    // client answers any CertificateRequest, so the chain is available even
    // when the handshake later aborts because the server requires mTLS.
    let capture = VerifyCapture {
        cert_request: crate::mtls::install(&mut builder),
        ..VerifyCapture::default()
    };
    let cb = capture.clone();
    let force_accept = opts.no_verify;
    builder.set_verify_callback(SslVerifyMode::PEER, move |preverify, ctx| {
        if let Some(cert) = ctx.current_cert() {
            let mut chain = cb.chain.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let owned: openssl::x509::X509 = cert.to_owned();
            if !chain.iter().any(|c| c == &owned) {
                chain.push(owned);
            }
        }
        if !preverify {
            let depth = ctx.error_depth();
            let err = ctx.error();
            let subject = ctx
                .current_cert()
                .map(|c| crate::cert::format_x509_name(c.subject_name()))
                .unwrap_or_else(|| "unknown".to_string());
            let mut errs = cb.errors.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            errs.push(format!("depth {depth}: {err} ({subject})"));
        }
        if force_accept { true } else { preverify }
    });

    Ok((builder.build(), capture))
}

/// Debug dump of the negotiated session (layers 5 and 6).
fn log_tls_session_debug(ssl: &openssl::ssl::SslRef, sni_host: &str, no_verify: bool, debug: bool) {
    if !debug {
        return;
    }
    dbg_section(true, "Layer 5/6 (Session/Presentation - TLS)");
    debug_log!(true, "TLS version: {}", ssl.version_str());
    if let Some(cipher) = ssl.current_cipher() {
        debug_log!(true, "Cipher (OpenSSL): {}", cipher.name());
        if let Some(std_name) = cipher.standard_name() {
            debug_log!(true, "Cipher (IANA): {}", std_name);
        }
    }
    match negotiated_group_name(ssl) {
        Some(group) => debug_log!(
            true,
            "Key exchange group: {} ({})",
            group,
            classify_group(&group).label()
        ),
        None => debug_log!(
            true,
            "Key exchange group: not reported by {}",
            openssl::version::version()
        ),
    }
    if let Some(proto) = ssl.selected_alpn_protocol()
        && let Ok(proto_str) = std::str::from_utf8(proto)
    {
        debug_log!(true, "ALPN negotiated: {}", proto_str);
    }
    debug_log!(true, "SNI sent: {}", sni_host);
    if no_verify {
        debug_log!(true, "Certificate verification: DISABLED (--no-verify)");
    }
    if let Some(chain) = ssl.peer_cert_chain() {
        debug_log!(true, "Certificate chain depth: {}", chain.len());
    }
}

/// Name of the negotiated key exchange group ("X25519MLKEM768", "X25519",
/// "secp384r1", ...). Uses `SSL_get0_group_name` on OpenSSL 3.2+ and falls
/// back to the server's ephemeral key type on older releases, which can name
/// classical groups only.
pub fn negotiated_group_name(ssl: &openssl::ssl::SslRef) -> Option<String> {
    #[cfg(dcert_ossl320)]
    {
        if let Some(name) = group_name_ffi(ssl) {
            return Some(name);
        }
    }
    #[cfg(all(unix, not(dcert_ossl320)))]
    {
        if let Some(name) = runtime_group_name(ssl) {
            return Some(name);
        }
    }
    group_name_from_tmp_key(ssl)
}

/// `SSL_get0_group_name` from the libssl loaded at run time.
///
/// The Linux release binary is built against OpenSSL 3.0 headers (the
/// ubuntu 22.04 glibc floor) but often runs on OpenSSL 3.5 or later, as in
/// the Docker image. The symbol is looked up once in the global symbol scope,
/// so that binary names ML-KEM groups whenever the loaded library can.
#[cfg(all(unix, not(dcert_ossl320)))]
#[allow(unsafe_code)] // dlsym and a call through the pointer it returns.
fn runtime_group_name_fn() -> Option<GroupNameFn> {
    use std::sync::OnceLock;
    static FUNC: OnceLock<Option<GroupNameFn>> = OnceLock::new();
    *FUNC.get_or_init(|| {
        let sym = lookup_global_symbol(c"SSL_get0_group_name");
        if sym.is_null() {
            None
        } else {
            // SAFETY: the symbol is OpenSSL's
            // `const char *SSL_get0_group_name(SSL *s)`, which matches
            // GroupNameFn.
            Some(unsafe { std::mem::transmute::<*mut std::ffi::c_void, GroupNameFn>(sym) })
        }
    })
}

/// Address of `name` in the process's global symbol scope, or null.
#[cfg(all(unix, not(dcert_ossl320)))]
#[allow(unsafe_code)] // dlsym.
fn lookup_global_symbol(name: &std::ffi::CStr) -> *mut std::ffi::c_void {
    unsafe extern "C" {
        fn dlsym(handle: *mut std::ffi::c_void, symbol: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    }
    // RTLD_DEFAULT: null on glibc and musl, (void *)-2 on Apple platforms.
    #[cfg(target_vendor = "apple")]
    let default_scope = std::ptr::null_mut::<std::ffi::c_void>().wrapping_sub(2);
    #[cfg(not(target_vendor = "apple"))]
    let default_scope = std::ptr::null_mut::<std::ffi::c_void>();
    // SAFETY: dlsym takes a valid handle (RTLD_DEFAULT) and a NUL terminated
    // name; it returns null or the symbol's address and has no other effect.
    unsafe { dlsym(default_scope, name.as_ptr()) }
}

#[cfg(all(unix, not(dcert_ossl320)))]
type GroupNameFn = unsafe extern "C" fn(*mut openssl_sys::SSL) -> *const std::ffi::c_char;

#[cfg(all(unix, not(dcert_ossl320)))]
#[allow(unsafe_code)] // Calls the symbol resolved by runtime_group_name_fn.
fn runtime_group_name(ssl: &openssl::ssl::SslRef) -> Option<String> {
    use foreign_types::ForeignTypeRef;
    let func = runtime_group_name_fn()?;
    // SAFETY: `ssl.as_ptr()` is a live SSL handle for this borrow; the result
    // is null or a NUL terminated string owned by the SSL object, copied
    // before the borrow ends.
    let ptr = unsafe { func(ssl.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non null and NUL terminated as documented.
    let name = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
    if name.is_empty() { None } else { Some(name) }
}

/// Whether the loaded libssl can name the negotiated group: compiled in
/// (OpenSSL 3.2 headers or later) or found at run time.
pub fn group_name_available() -> bool {
    #[cfg(all(unix, not(dcert_ossl320)))]
    {
        runtime_group_name_fn().is_some()
    }
    #[cfg(not(all(unix, not(dcert_ossl320))))]
    {
        cfg!(dcert_ossl320)
    }
}

#[cfg(dcert_ossl320)]
#[allow(unsafe_code)] // The openssl crate does not wrap SSL_get0_group_name yet.
fn group_name_ffi(ssl: &openssl::ssl::SslRef) -> Option<String> {
    use foreign_types::ForeignTypeRef;
    // SAFETY: `ssl.as_ptr()` is a live SSL handle for the duration of this
    // borrow. OpenSSL returns either null or a pointer to an internal,
    // NUL terminated string owned by the SSL object; it is copied into an owned
    // String before the borrow ends and never freed here.
    let ptr = unsafe { openssl_sys::SSL_get0_group_name(ssl.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non null and NUL terminated as documented for SSL_get0_group_name.
    let name = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
    if name.is_empty() { None } else { Some(name) }
}

/// Derive a classical group name from the server's ephemeral key. ML-KEM
/// hybrids cannot be named this way, which is fine: an OpenSSL too old to
/// report group names is also too old to negotiate them.
fn group_name_from_tmp_key(ssl: &openssl::ssl::SslRef) -> Option<String> {
    let key = ssl.peer_tmp_key().ok()?;
    match key.id() {
        openssl::pkey::Id::X25519 => Some("X25519".to_string()),
        openssl::pkey::Id::X448 => Some("X448".to_string()),
        openssl::pkey::Id::EC => key
            .ec_key()
            .ok()?
            .group()
            .curve_name()
            .and_then(|nid| nid.short_name().ok())
            .map(ToString::to_string),
        openssl::pkey::Id::DH => Some(format!("DHE-{}", key.bits())),
        _ => None,
    }
}

/// Negotiated session parameters, read once after the handshake.
struct TlsSessionSummary {
    tls_version: String,
    tls_cipher: String,
    tls_cipher_iana: Option<String>,
    negotiated_protocol: Option<String>,
    key_exchange_group: Option<String>,
    key_exchange_class: KeyExchangeClass,
    verify_result: Option<String>,
    chain_validation_errors: Vec<String>,
}

fn session_summary(ssl: &openssl::ssl::SslRef, capture: &VerifyCapture, debug: bool) -> TlsSessionSummary {
    let current_cipher = ssl.current_cipher();
    let verify_result = {
        let result = ssl.verify_result();
        if result == openssl::x509::X509VerifyResult::OK {
            None
        } else {
            Some(format!("{result}"))
        }
    };
    let chain_validation_errors = capture.errors();
    let key_exchange_group = negotiated_group_name(ssl);
    let key_exchange_class = key_exchange_group
        .as_deref()
        .map_or(KeyExchangeClass::Unknown, classify_group);
    if debug {
        if let Some(ref result) = verify_result {
            debug_log!(true, "Verification: {}", result);
            for err in &chain_validation_errors {
                debug_log!(true, "  Chain error: {}", err);
            }
        } else {
            debug_log!(true, "Verification: OK");
        }
    }
    TlsSessionSummary {
        tls_version: ssl.version_str().to_string(),
        tls_cipher: current_cipher
            .map(|c| c.name().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        tls_cipher_iana: current_cipher.and_then(|c| c.standard_name().map(ToString::to_string)),
        negotiated_protocol: ssl
            .selected_alpn_protocol()
            .and_then(|p| std::str::from_utf8(p).ok())
            .map(ToString::to_string),
        key_exchange_group,
        key_exchange_class,
        verify_result,
        chain_validation_errors,
    }
}

/// The peer's presented chain as concatenated PEM.
fn peer_chain_pem(ssl: &openssl::ssl::SslRef) -> Result<String> {
    let certs = ssl
        .peer_cert_chain()
        .ok_or_else(|| anyhow::anyhow!("No peer certificates presented"))?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("Empty certificate chain"));
    }
    let owned: Vec<openssl::x509::X509> = certs.iter().map(ToOwned::to_owned).collect();
    chain_to_pem(&owned)
}

/// Read an HTTP/1.x response head and a bounded body prefix from `stream`.
///
/// Stops at EOF, at the read deadline, when `Content-Length` bytes of body
/// have arrived, when `body_limit + 1` body bytes are buffered, or right
/// after the head when `body_limit` is zero. The result is raw bytes for
/// [`HttpResponseCapture::parse`]. Shared by the HTTPS probe, the proxy
/// CONNECT exchange and the OCSP client so every HTTP read has one deadline
/// and one size cap.
pub(crate) fn read_http_response<R: Read>(stream: &mut R, read_timeout_secs: u64, body_limit: usize) -> Vec<u8> {
    let (buf, err) = read_http_response_checked(stream, read_timeout_secs, body_limit);
    if let Some(e) = err
        && buf.is_empty()
    {
        eprintln!("Warning: Error reading HTTP response: {e}");
    }
    buf
}

/// [`read_http_response`] that hands back the read error instead of
/// printing it. A TLS 1.3 server that requires a client certificate sends
/// its `certificate_required` alert here, after the handshake, so the HTTPS
/// probe needs the error to tell an mTLS refusal from an empty reply.
/// Timeouts are not reported as errors: they end the read like EOF does.
pub(crate) fn read_http_response_checked<R: Read>(
    stream: &mut R,
    read_timeout_secs: u64,
    body_limit: usize,
) -> (Vec<u8>, Option<std::io::Error>) {
    const MAX_HEAD_SIZE: usize = 64 * 1024;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = std::time::Instant::now() + Duration::from_secs(read_timeout_secs.max(1));
    let mut head_len: Option<usize> = None;
    let mut content_length: Option<usize> = None;

    while std::time::Instant::now() < deadline {
        if let Some(hl) = head_len {
            let body_have = buf.len().saturating_sub(hl);
            // With no body wanted at all (proxy CONNECT answers, bare status
            // checks) stop as soon as the head is complete rather than
            // waiting for a body the peer may never send.
            if body_limit == 0 || body_have > body_limit || content_length.is_some_and(|cl| body_have >= cl) {
                break;
            }
        } else if buf.len() > MAX_HEAD_SIZE {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if head_len.is_none()
                    && let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                {
                    head_len = Some(i + 4);
                    let head = String::from_utf8_lossy(&buf[..i]);
                    content_length = head
                        .split("\r\n")
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse::<usize>().ok());
                }
            }
            Err(ref e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                break;
            }
            Err(e) => return (buf, Some(e)),
        }
    }
    (buf, None)
}

/// Settings shared by every TLS probe (HTTPS and STARTTLS): verification,
/// protocol bounds, cipher and group preferences, timeouts and where to dial.
#[derive(Debug, Clone, Copy)]
pub struct TlsProbeOptions<'a> {
    pub no_verify: bool,
    pub timeout_secs: u64,
    pub read_timeout_secs: u64,
    pub sni_override: Option<&'a str>,
    /// `--resolve` / `--connect-to` table. A match redirects where we dial; the
    /// hostname is still used for SNI, the `Host:` header and validation.
    pub connect_overrides: &'a ConnectOverrides,
    pub min_tls: Option<TlsVersionArg>,
    pub max_tls: Option<TlsVersionArg>,
    pub cipher_list: Option<&'a str>,
    pub cipher_suites: Option<&'a str>,
    /// OpenSSL group list (`--groups`), e.g. "X25519MLKEM768:X25519".
    /// `None` keeps the library default.
    pub groups: Option<&'a str>,
    pub ca_cert_path: Option<&'a str>,
    pub debug: bool,
}

/// Options for `fetch_tls_chain_openssl`.
#[derive(Debug)]
pub struct TlsFetchOptions<'a> {
    pub probe: TlsProbeOptions<'a>,
    pub endpoint: &'a str,
    pub method: &'a str,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
    pub http_protocol: HttpProtocol,
    pub proxy_config: &'a ProxyConfig,
    pub identity: ClientIdentity<'a>,
    /// Maximum number of response body bytes to keep for diagnostics.
    pub body_limit: usize,
}

/// How a probe reached its peer (layers 3 and 4).
#[derive(Debug)]
struct DialInfo {
    dns_latency: u128,
    l4_latency: u128,
    peer_address: Option<String>,
    connect_override: Option<String>,
    /// Wall clock bound on everything after the TCP connect.
    deadline: crate::deadline::DeadlineGuard,
}

/// Layers 3 and 4: reach `host:port` through a `--resolve`/`--connect-to`
/// override, directly, or through the forward proxy (HTTPS only, and never
/// for an override), then apply the read timeout. Shared by the HTTPS probe,
/// the STARTTLS probe and the post quantum probe so the dial logic, its
/// timeouts and its debug output exist once.
fn dial(
    host: &str,
    port: u16,
    probe: &TlsProbeOptions<'_>,
    proxy_config: Option<&ProxyConfig>,
) -> Result<(TcpStream, DialInfo)> {
    let debug = probe.debug;
    let connect_timeout = Duration::from_secs(probe.timeout_secs);
    let l4_start = std::time::Instant::now();

    let mut connect_override = None;
    let (stream, dns_latency, peer_address) = if let Some(ov) = probe.connect_overrides.lookup(host, port) {
        // --resolve / --connect-to: dial the override target, bypassing any
        // proxy. The hostname is still used for SNI and validation.
        let (s, addr, dns) = connect_via_override(&ov, connect_timeout)?;
        dbg_section(debug, "Layer 3 (Network)");
        let description = ov.describe(host, port);
        debug_log!(
            debug,
            "Connection override: {} (dialled {}, proxy bypassed)",
            description,
            addr
        );
        connect_override = Some(description);
        (s, dns, Some(addr))
    } else if let Some(proxy_url) = proxy_config
        .filter(|p| !p.should_bypass(host))
        .and_then(|p| p.get_proxy_url("https"))
    {
        debug_log!(debug, "Using proxy: {}", sanitize_url(proxy_url));
        // Proxy connections resolve the proxy host, not the target.
        let stream = connect_through_proxy(proxy_url, host, port, connect_timeout, probe.read_timeout_secs, debug)?;
        dbg_section(debug, "Layer 3 (Network)");
        debug_log!(debug, "DNS resolution handled by proxy");
        (stream, 0, None)
    } else {
        let (s, dns, addr) = direct_tcp_connect(host, port, connect_timeout)?;
        dbg_section(debug, "Layer 3 (Network)");
        debug_log!(debug, "Resolved {} -> {} ({} ms)", host, addr.ip(), dns);
        (s, dns, Some(addr))
    };

    let io_timeout = Some(Duration::from_secs(probe.read_timeout_secs.max(1)));
    stream
        .set_read_timeout(io_timeout)
        .and_then(|()| stream.set_write_timeout(io_timeout))
        .map_err(|e| anyhow::anyhow!("Failed to set socket timeouts: {e}"))?;
    // One budget for the whole probe: per read timeouts alone would let a
    // peer that drips a byte at a time hold the connection forever.
    let budget = crate::deadline::probe_budget(probe.timeout_secs, probe.read_timeout_secs);
    let deadline = crate::deadline::DeadlineGuard::arm(&stream, l4_start + budget, budget);

    let l4_latency = l4_start.elapsed().as_millis();
    dbg_section(debug, "Layer 4 (Transport)");
    debug_log!(debug, "TCP connection established ({} ms)", l4_latency);

    Ok((
        stream,
        DialInfo {
            dns_latency,
            l4_latency,
            peer_address: peer_address.map(|a| a.to_string()),
            connect_override,
            deadline,
        },
    ))
}

/// Assemble the result of a completed handshake.
fn connection_info(
    session: TlsSessionSummary,
    dialled: &DialInfo,
    l7_latency: u128,
    no_verify: bool,
    pem_data: String,
    http: Option<&HttpResponseCapture>,
) -> TlsConnectionInfo {
    TlsConnectionInfo {
        pem_data,
        dns_latency: dialled.dns_latency,
        l4_latency: dialled.l4_latency,
        l7_latency,
        tls_version: session.tls_version,
        tls_cipher: session.tls_cipher,
        tls_cipher_iana: session.tls_cipher_iana,
        negotiated_protocol: session.negotiated_protocol,
        tls_key_exchange_group: session.key_exchange_group,
        key_exchange_class: session.key_exchange_class,
        post_quantum_probe: None,
        http_response_code: http.map_or(0, |h| h.status),
        http_reason: http.and_then(|h| h.reason.clone()),
        http_headers: http.map(|h| h.headers.clone()).unwrap_or_default(),
        http_body_excerpt: http.and_then(HttpResponseCapture::body_text),
        http_body_truncated: http.is_some_and(|h| h.body_truncated),
        verify_result: session.verify_result,
        chain_validation_errors: session.chain_validation_errors,
        client_auth_required: false,
        client_auth: crate::mtls::ClientAuthStatus::NotRequested,
        acceptable_client_cas: Vec::new(),
        verification_disabled: no_verify,
        peer_address: dialled.peer_address.clone(),
        connect_override: dialled.connect_override.clone(),
    }
}

/// Record what the server's CertificateRequest (if any) means for a probe
/// whose request went through: optional mTLS without an identity, or a
/// certificate that was presented.
fn apply_cert_request(info: &mut TlsConnectionInfo, request: crate::mtls::CertRequest, identity_configured: bool) {
    use crate::mtls::ClientAuthStatus;
    if !request.requested {
        return;
    }
    info.client_auth = if identity_configured {
        ClientAuthStatus::Presented
    } else {
        ClientAuthStatus::Optional
    };
    info.acceptable_client_cas = request.acceptable_cas;
}

/// Mark `info` as an mTLS required refusal: the server asked for a client
/// certificate and closed the connection without one.
fn mark_client_auth_required(info: &mut TlsConnectionInfo, request: crate::mtls::CertRequest) {
    info.client_auth_required = true;
    info.client_auth = crate::mtls::ClientAuthStatus::Required;
    info.acceptable_client_cas = request.acceptable_cas;
    if info.verify_result.is_none() {
        info.verify_result = Some("client certificate required (mTLS)".to_string());
    }
}

impl ClientIdentity<'_> {
    /// `true` when a certificate (PEM or PKCS12) is configured.
    pub fn is_configured(&self) -> bool {
        self.client_cert_path.is_some() || self.pkcs12_path.is_some()
    }
}

/// Request target for the HTTP/1.1 request line: path plus query string, so
/// `https://host/v1/x?key=1` asks for `/v1/x?key=1` and not `/v1/x`.
fn request_target(url: &url::Url) -> String {
    let path = if url.path().is_empty() { "/" } else { url.path() };
    match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    }
}

/// `Host` header value: the port is included whenever it is not the HTTPS
/// default, as RFC 9112 requires and as virtual hosts and gateways expect.
fn host_header_value(host: &str, port: u16) -> String {
    if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// Build the HTTP/1.1 request head (and the headers that describe `body`).
fn build_http_request(
    url: &url::Url,
    host: &str,
    port: u16,
    method: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<String> {
    let mut req = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\n",
        request_target(url),
        host_header_value(host, port)
    );
    for (key, value) in headers {
        // Reject headers containing CR/LF to prevent header injection
        if key.contains('\r') || key.contains('\n') || value.contains('\r') || value.contains('\n') {
            return Err(anyhow::anyhow!(
                "HTTP header contains invalid characters (CR/LF): {key}:{value}"
            ));
        }
        req.push_str(&format!("{key}: {value}\r\n"));
    }
    // When a body is present, add Content-Length and default Content-Type
    if let Some(body_bytes) = body {
        req.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
        let has_content_type = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
        if !has_content_type {
            req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        }
    }
    req.push_str("Connection: close\r\n\r\n");
    Ok(req)
}

/// Fetch TLS certificate chain using OpenSSL, with proxy support, custom CA certificates, and mTLS.
pub fn fetch_tls_chain_openssl(opts: &TlsFetchOptions<'_>) -> Result<TlsConnectionInfo> {
    let probe = &opts.probe;
    let debug = probe.debug;
    let url = url::Url::parse(opts.endpoint).map_err(|e| anyhow::anyhow!("Invalid URL: {e}"))?;
    if url.scheme() != "https" {
        return Err(anyhow::anyhow!("Only HTTPS scheme is supported"));
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must include a host"))?;

    // Validate port range
    let port = url.port().unwrap_or(443);
    if port == 0 {
        return Err(anyhow::anyhow!("Invalid port number: {port}"));
    }

    // Rebuilt from the parsed components rather than echoing the argument,
    // so userinfo or anything else embedded in the input never reaches
    // the debug stream.
    debug_log!(
        debug,
        "Target URL: {}://{}:{}{}",
        url.scheme(),
        host,
        port,
        request_target(&url)
    );
    debug_log!(debug, "Host: {}, Port: {}", host, port);
    if let Some(sni) = probe.sni_override {
        debug_log!(debug, "SNI override: {}", sni);
    }

    let (stream, dialled) = dial(host, port, probe, Some(opts.proxy_config))?;

    // Layer 7: TLS handshake + HTTP request
    let l7_start = std::time::Instant::now();
    let (connector, verify) = build_connector(&ConnectorOptions::from_probe(
        probe,
        opts.identity,
        Some(opts.http_protocol),
    ))?;

    let sni_host = probe.sni_override.unwrap_or(host);
    let identity_configured = opts.identity.is_configured();
    let mut ssl_stream = match connector.connect(sni_host, stream) {
        Ok(s) => s,
        Err(e) => {
            if dialled.deadline.expired() {
                return Err(dialled.deadline.timeout_error("the TLS handshake"));
            }
            let err_str = e.to_string();
            let request = verify.cert_request.get();
            // Surface mTLS-required failures to the caller with the chain we
            // captured during verification, so the user gets the server
            // identity even though the handshake aborted. A server that sent
            // a CertificateRequest and then failed a handshake we entered
            // without a certificate is refusing us for that reason: the
            // CertificateRequest is only answered after the server's own
            // certificate has been verified, so nothing else is left to fail.
            if is_client_auth_required(&err_str) || (request.requested && !identity_configured) {
                let chain = verify.chain();
                if !chain.is_empty() {
                    let pem = chain_to_pem(&chain)?;
                    let l7_latency = l7_start.elapsed().as_millis();
                    let mut info = TlsConnectionInfo {
                        pem_data: pem,
                        dns_latency: dialled.dns_latency,
                        l4_latency: dialled.l4_latency,
                        l7_latency,
                        tls_version: "unknown (handshake aborted)".to_string(),
                        tls_cipher: "unknown".to_string(),
                        chain_validation_errors: verify.errors(),
                        verification_disabled: probe.no_verify,
                        peer_address: dialled.peer_address,
                        connect_override: dialled.connect_override,
                        ..Default::default()
                    };
                    mark_client_auth_required(&mut info, request);
                    return Ok(info);
                }
                // Fall through to the regular error path if no chain was captured.
            }
            return Err(verify.handshake_error(&e, probe.ca_cert_path.is_some()));
        }
    };

    log_tls_session_debug(ssl_stream.ssl(), sni_host, probe.no_verify, debug);

    // Warn if the server negotiated h2: only HTTP/1.1 framing is sent, so the
    // HTTP response parsing below may fail or produce incorrect results.
    if let Some(proto) = ssl_stream.ssl().selected_alpn_protocol()
        && proto == b"h2"
    {
        eprintln!(
            "Warning: Server negotiated HTTP/2 but dcert only implements HTTP/1.1 framing. \
                 The HTTP status code may be incorrect. Use --http-protocol http1-1 to force HTTP/1.1."
        );
    }

    let req = build_http_request(&url, host, port, opts.method, opts.headers, opts.body)?;

    // Debug: Layer 7 - HTTP request details
    if debug {
        dbg_section(true, "Layer 7 (Application - HTTP)");
        debug_log!(true, "> {} {} HTTP/1.1", opts.method, request_target(&url));
        debug_log!(true, "> Host: {}", host_header_value(host, port));
        for (key, value) in opts.headers {
            debug_log!(true, "> {}: {}", key, sanitize_header_value(key, value));
        }
        if let Some(body_bytes) = opts.body {
            debug_log!(true, "> Content-Length: {}", body_bytes.len());
            let has_content_type = opts.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
            if !has_content_type {
                debug_log!(true, "> Content-Type: application/x-www-form-urlencoded");
            }
        }
        debug_log!(true, "> Connection: close");
    }

    // Send the request head, then the body, then flush. A TLS 1.3 server
    // that requires a client certificate may already have sent its alert and
    // closed, so a write failure is classified rather than returned blindly.
    let sent = ssl_stream
        .write_all(req.as_bytes())
        .and_then(|()| opts.body.map_or(Ok(()), |b| ssl_stream.write_all(b)))
        .and_then(|()| ssl_stream.flush());

    // Read the HTTP response: the whole header block, then up to
    // `body_limit` bytes of body (plus one so truncation is detectable). Each
    // socket read is bounded by `--read-timeout` and the loop as a whole never
    // exceeds that deadline either, so a silent server costs one timeout.
    let write_failed = sent.is_err();
    let (response_buffer, io_error) = match sent {
        Ok(()) => read_http_response_checked(&mut ssl_stream, probe.read_timeout_secs, opts.body_limit),
        Err(e) => (Vec::new(), Some(e)),
    };
    if response_buffer.is_empty() && dialled.deadline.expired() {
        return Err(dialled.deadline.timeout_error("the HTTP exchange"));
    }
    let request = verify.cert_request.get();
    let l7_latency = l7_start.elapsed().as_millis();

    // TLS 1.3 mTLS refusals arrive here, after the handshake completed: the
    // server read our empty Certificate message and answered with an alert
    // (or simply closed) instead of an HTTP response.
    if response_buffer.is_empty()
        && let Some(e) = &io_error
    {
        let text = e.to_string();
        if is_client_auth_required(&text) || (request.requested && !identity_configured) {
            debug_log!(debug, "Server refused the connection after the handshake: {}", text);
            let pem = peer_chain_pem(ssl_stream.ssl())?;
            let session = session_summary(ssl_stream.ssl(), &verify, debug);
            let mut info = connection_info(session, &dialled, l7_latency, probe.no_verify, pem, None);
            mark_client_auth_required(&mut info, request);
            return Ok(info);
        }
        if request.requested {
            // A certificate was sent and the server rejected it with an alert
            // after the handshake (unknown CA, expired, revoked, ...).
            return Err(verify.with_cert_request(anyhow::anyhow!(
                "TLS alert after the handshake (client certificate rejected?): {text}"
            )));
        }
        if write_failed {
            return Err(anyhow::anyhow!("Failed to send HTTP request: {text}"));
        }
        eprintln!("Warning: Error reading HTTP response: {e}");
    }

    let capture = HttpResponseCapture::parse(&response_buffer, opts.body_limit);
    if response_buffer.is_empty() {
        eprintln!("Warning: No response data received");
    } else if capture.status == 0 {
        eprintln!(
            "Warning: Could not parse HTTP status line: {}",
            String::from_utf8_lossy(&response_buffer[..response_buffer.len().min(100)])
        );
    }

    debug_log!(debug, "< HTTP response: {}", capture.status);
    debug_log!(debug, "Layer 7 complete ({} ms)", l7_latency);

    let pem = peer_chain_pem(ssl_stream.ssl())?;
    let session = session_summary(ssl_stream.ssl(), &verify, debug);

    let mut info = connection_info(session, &dialled, l7_latency, probe.no_verify, pem, Some(&capture));
    apply_cert_request(&mut info, request, identity_configured);
    Ok(info)
}

/// Options for STARTTLS connections.
#[derive(Debug)]
pub struct StarttlsFetchOptions<'a> {
    pub probe: TlsProbeOptions<'a>,
    pub host: &'a str,
    pub port: u16,
    pub protocol: StarttlsProtocol,
    /// Client certificate for servers that require mTLS after STARTTLS.
    pub identity: ClientIdentity<'a>,
}

/// Read a line from a TCP stream (up to `\n`), with a size limit.
fn read_line_from_stream(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() > 4096 {
                    return Err(anyhow::anyhow!("STARTTLS: server response line too long"));
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Err(anyhow::anyhow!(
                    "STARTTLS: timed out waiting for the server's response (--read-timeout)"
                ));
            }
            Err(e) => return Err(anyhow::anyhow!("STARTTLS: read error: {e}")),
        }
    }
    String::from_utf8(buf).map_err(|e| anyhow::anyhow!("STARTTLS: invalid UTF-8 response: {e}"))
}

/// Most lines a multi line STARTTLS reply may have.
const MAX_RESPONSE_LINES: usize = 64;
/// Most bytes a multi line STARTTLS reply may have.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Read a full multi-line response (for SMTP which uses continuation lines like "250-...").
fn read_response(stream: &mut TcpStream) -> Result<String> {
    let mut full_response = String::new();
    for _ in 0..MAX_RESPONSE_LINES {
        let line = read_line_from_stream(stream)?;
        if line.is_empty() {
            return Err(anyhow::anyhow!("STARTTLS: server closed the connection mid reply"));
        }
        full_response.push_str(&line);
        if full_response.len() > MAX_RESPONSE_BYTES {
            return Err(anyhow::anyhow!(
                "STARTTLS: server reply exceeds {MAX_RESPONSE_BYTES} bytes"
            ));
        }
        // SMTP multi-line: lines with "-" after code continue, space after code ends
        // For other protocols, single line responses are expected
        if line.len() < 4 || line.as_bytes().get(3) != Some(&b'-') {
            return Ok(full_response);
        }
    }
    Err(anyhow::anyhow!(
        "STARTTLS: server reply exceeds {MAX_RESPONSE_LINES} lines"
    ))
}

/// Read IMAP lines until the one carrying `tag` (RFC 9051 section 2.2.2):
/// a server may send untagged `*` lines (capabilities, alerts) first. The
/// line count is bounded like other STARTTLS replies.
fn read_imap_tagged(stream: &mut TcpStream, tag: &str) -> Result<String> {
    let prefix = format!("{tag} ");
    for _ in 0..MAX_RESPONSE_LINES {
        let line = read_line_from_stream(stream)?;
        if line.is_empty() {
            return Err(anyhow::anyhow!(
                "IMAP: server closed the connection before answering {tag}"
            ));
        }
        if line.starts_with(&prefix) {
            return Ok(line);
        }
    }
    Err(anyhow::anyhow!(
        "IMAP: no tagged reply to {tag} within {MAX_RESPONSE_LINES} lines"
    ))
}

/// Whether a tagged IMAP reply is `OK` (case insensitive per RFC 9051).
fn imap_tagged_ok(line: &str, tag: &str) -> bool {
    line.strip_prefix(tag)
        .map(str::trim_start)
        .is_some_and(|rest| rest.get(..2).is_some_and(|s| s.eq_ignore_ascii_case("OK")))
}

/// Perform STARTTLS negotiation on a plain TCP stream.
fn negotiate_starttls(stream: &mut TcpStream, protocol: StarttlsProtocol, debug: bool) -> Result<()> {
    match protocol {
        StarttlsProtocol::Smtp => {
            // Read banner
            let banner = read_response(stream)?;
            debug_log!(debug, "SMTP banner: {}", banner.trim());
            if !banner.starts_with("220") {
                return Err(anyhow::anyhow!("SMTP: unexpected banner: {}", banner.trim()));
            }

            // Send EHLO
            stream.write_all(b"EHLO dcert\r\n")?;
            stream.flush()?;
            let ehlo_resp = read_response(stream)?;
            debug_log!(debug, "SMTP EHLO response: {}", ehlo_resp.trim());
            if !ehlo_resp.starts_with("250") {
                return Err(anyhow::anyhow!("SMTP: EHLO rejected: {}", ehlo_resp.trim()));
            }

            // Send STARTTLS
            stream.write_all(b"STARTTLS\r\n")?;
            stream.flush()?;
            let tls_resp = read_response(stream)?;
            debug_log!(debug, "SMTP STARTTLS response: {}", tls_resp.trim());
            if !tls_resp.starts_with("220") {
                return Err(anyhow::anyhow!("SMTP: STARTTLS rejected: {}", tls_resp.trim()));
            }
        }
        StarttlsProtocol::Imap => {
            // Read banner
            let banner = read_line_from_stream(stream)?;
            debug_log!(debug, "IMAP banner: {}", banner.trim());

            // Send STARTTLS
            stream.write_all(b"a001 STARTTLS\r\n")?;
            stream.flush()?;
            let resp = read_imap_tagged(stream, "a001")?;
            debug_log!(debug, "IMAP STARTTLS response: {}", resp.trim());
            if !imap_tagged_ok(&resp, "a001") {
                return Err(anyhow::anyhow!("IMAP: STARTTLS rejected: {}", resp.trim()));
            }
        }
        StarttlsProtocol::Pop3 => {
            // Read banner
            let banner = read_line_from_stream(stream)?;
            debug_log!(debug, "POP3 banner: {}", banner.trim());
            if !banner.starts_with("+OK") {
                return Err(anyhow::anyhow!("POP3: unexpected banner: {}", banner.trim()));
            }

            // Send STLS
            stream.write_all(b"STLS\r\n")?;
            stream.flush()?;
            let resp = read_line_from_stream(stream)?;
            debug_log!(debug, "POP3 STLS response: {}", resp.trim());
            if !resp.starts_with("+OK") {
                return Err(anyhow::anyhow!("POP3: STLS rejected: {}", resp.trim()));
            }
        }
        StarttlsProtocol::Ftp => {
            // Read banner
            let banner = read_response(stream)?;
            debug_log!(debug, "FTP banner: {}", banner.trim());

            // Send AUTH TLS
            stream.write_all(b"AUTH TLS\r\n")?;
            stream.flush()?;
            let resp = read_response(stream)?;
            debug_log!(debug, "FTP AUTH TLS response: {}", resp.trim());
            if !resp.starts_with("234") {
                return Err(anyhow::anyhow!("FTP: AUTH TLS rejected: {}", resp.trim()));
            }
        }
    }
    Ok(())
}

/// Fetch TLS certificate chain via STARTTLS negotiation.
pub fn fetch_tls_chain_starttls(opts: &StarttlsFetchOptions<'_>) -> Result<TlsConnectionInfo> {
    let probe = &opts.probe;
    let debug = probe.debug;
    debug_log!(
        debug,
        "STARTTLS target: {}:{} (protocol: {})",
        opts.host,
        opts.port,
        opts.protocol
    );

    // STARTTLS never goes through the forward proxy: CONNECT tunnels are an
    // HTTPS convention and mail/FTP proxies speak their own protocols.
    let (mut stream, dialled) = dial(opts.host, opts.port, probe, None)?;

    dbg_section(debug, "STARTTLS Negotiation");
    negotiate_starttls(&mut stream, opts.protocol, debug).map_err(|e| {
        if dialled.deadline.expired() {
            dialled.deadline.timeout_error("the STARTTLS exchange")
        } else {
            e
        }
    })?;

    // TLS handshake on the upgraded stream
    let l7_start = std::time::Instant::now();
    let (connector, capture) = build_connector(&ConnectorOptions::from_probe(probe, opts.identity, None))?;

    let sni_host = probe.sni_override.unwrap_or(opts.host);
    let ssl_stream = connector.connect(sni_host, stream).map_err(|e| {
        if dialled.deadline.expired() {
            dialled.deadline.timeout_error("the TLS handshake")
        } else {
            capture.handshake_error(&e, probe.ca_cert_path.is_some())
        }
    })?;

    log_tls_session_debug(ssl_stream.ssl(), sni_host, probe.no_verify, debug);

    let l7_latency = l7_start.elapsed().as_millis();
    let pem = peer_chain_pem(ssl_stream.ssl())?;
    let session = session_summary(ssl_stream.ssl(), &capture, debug);

    let mut info = connection_info(session, &dialled, l7_latency, probe.no_verify, pem, None);
    apply_cert_request(&mut info, capture.cert_request.get(), opts.identity.is_configured());
    Ok(info)
}

/// How the post quantum probe reaches the TLS layer.
#[derive(Debug, Clone, Copy)]
pub enum ProbeTransport {
    /// Plain TLS (HTTPS targets).
    Tls,
    /// Opportunistic TLS after the protocol's STARTTLS exchange.
    Starttls(StarttlsProtocol),
}

/// Everything the post quantum probe needs beyond the shared probe options.
#[derive(Debug, Clone, Copy)]
pub struct PqProbeRequest<'a> {
    pub host: &'a str,
    pub port: u16,
    pub transport: ProbeTransport,
    /// Forward proxy for HTTPS targets; ignored for STARTTLS.
    pub proxy_config: Option<&'a ProxyConfig>,
    /// Client identity, so an mTLS server completes the handshake.
    pub identity: ClientIdentity<'a>,
    pub alpn: Option<HttpProtocol>,
}

/// Opt in second handshake (`--pq-probe`) that offers only the RFC 10024
/// hybrid groups, answering "does this server support post quantum key
/// agreement?" independently of what the default handshake negotiated.
///
/// Verification is skipped for this handshake: the identity was already
/// checked on the main connection and a verification failure here would
/// masquerade as missing post quantum support.
pub fn probe_post_quantum(req: &PqProbeRequest<'_>, probe: &TlsProbeOptions<'_>) -> PqProbeResult {
    if !crate::keyex::openssl_supports_mlkem() {
        return PqProbeResult::not_testable();
    }
    if probe.max_tls == Some(TlsVersionArg::Tls1_2) {
        return PqProbeResult::not_testable_with(
            "hybrid groups exist in TLS 1.3 only, but --max-tls 1.2 was given".to_string(),
        );
    }
    let groups = crate::keyex::pq_probe_groups();
    let pq_probe = TlsProbeOptions {
        no_verify: true,
        min_tls: Some(TlsVersionArg::Tls1_3),
        cipher_list: None,
        cipher_suites: None,
        groups: Some(&groups),
        ..*probe
    };
    dbg_section(probe.debug, "Post quantum probe (RFC 10024 hybrid groups only)");
    match pq_handshake(req, &pq_probe) {
        Ok(Some(group)) if classify_group(&group).is_post_quantum() => PqProbeResult::supported(group),
        Ok(Some(group)) => PqProbeResult::not_supported(&format!("negotiated {group} instead")),
        Ok(None) => PqProbeResult::not_supported("group name not reported after the handshake"),
        Err(e) => PqProbeResult::not_supported(&e.to_string()),
    }
}

/// Run the probe handshake and return the negotiated group, if any. A server
/// that demands a client certificate still reveals its chosen group in the
/// ServerHello, so that failure is read as a result rather than an error.
fn pq_handshake(req: &PqProbeRequest<'_>, probe: &TlsProbeOptions<'_>) -> Result<Option<String>> {
    let proxy = match req.transport {
        ProbeTransport::Tls => req.proxy_config,
        ProbeTransport::Starttls(_) => None,
    };
    let (mut stream, _dialled) = dial(req.host, req.port, probe, proxy)?;
    if let ProbeTransport::Starttls(protocol) = req.transport {
        negotiate_starttls(&mut stream, protocol, probe.debug)?;
    }
    let (connector, _capture) = build_connector(&ConnectorOptions::from_probe(probe, req.identity, req.alpn))?;
    let sni_host = probe.sni_override.unwrap_or(req.host);
    match connector.connect(sni_host, stream) {
        Ok(ssl_stream) => Ok(negotiated_group_name(ssl_stream.ssl())),
        Err(openssl::ssl::HandshakeError::Failure(mid)) if is_client_auth_required(&mid.error().to_string()) => {
            Ok(negotiated_group_name(mid.ssl()))
        }
        Err(e) => Err(anyhow::anyhow!("{e}")),
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn imap_tagged_ok_matches_only_the_tagged_ok() {
        assert!(super::imap_tagged_ok("a001 OK Begin TLS negotiation now\r\n", "a001"));
        assert!(super::imap_tagged_ok("a001 ok go\r\n", "a001"));
        assert!(!super::imap_tagged_ok("a001 NO STARTTLS disabled\r\n", "a001"));
        assert!(!super::imap_tagged_ok("* OK still here\r\n", "a001"));
    }

    #[test]
    fn imap_reader_skips_untagged_lines_before_the_tagged_reply() {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s
                    .write_all(b"* CAPABILITY IMAP4rev2 STARTTLS\r\n* OK [ALERT] maintenance\r\na001 OK Begin TLS\r\n");
            }
        });
        let mut stream = std::net::TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        let line = super::read_imap_tagged(&mut stream, "a001").expect("tagged reply");
        assert!(line.starts_with("a001 OK"), "{line}");
    }

    /// The run time lookup finds libssl symbols the binary already links,
    /// which proves it will find SSL_get0_group_name where it exists.
    #[cfg(all(unix, not(dcert_ossl320)))]
    #[test]
    fn global_symbol_lookup_finds_linked_libssl_symbols() {
        assert!(!super::lookup_global_symbol(c"SSL_get_version").is_null());
        assert!(super::lookup_global_symbol(c"dcert_no_such_symbol").is_null());
    }
    use super::{connect_via_override, handshake_verify_error, is_client_auth_required};
    use crate::connect::{OverrideSource, ResolvedOverride};
    use std::time::Duration;

    /// Bind and immediately drop a loopback listener to obtain a port nothing is
    /// listening on, so connect attempts fail fast instead of timing out.
    fn closed_loopback_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.local_addr().expect("local addr").port()
    }

    #[test]
    fn connect_via_override_reports_every_failed_candidate() {
        let port = closed_loopback_port();
        let targets = vec!["127.0.0.1".to_string(), "127.0.0.2".to_string()];
        let ov = ResolvedOverride {
            targets: &targets,
            port,
            source: OverrideSource::Resolve,
        };

        let err = connect_via_override(&ov, Duration::from_secs(1))
            .expect_err("nothing is listening on the chosen port")
            .to_string();

        assert!(err.contains("--resolve"), "should name the flag: {err}");
        assert!(err.contains("127.0.0.1"), "should list the first candidate: {err}");
        assert!(err.contains("127.0.0.2"), "should list the second candidate: {err}");
    }

    #[test]
    fn missing_intermediate_error_names_aia_block() {
        let details =
            vec!["depth 1: unable to get local issuer certificate (CN=DigiCert TLS RSA SHA256 2020 CA1)".to_string()];
        let err = handshake_verify_error("certificate verify failed", &details, false);
        let msg = err.to_string();
        assert!(msg.contains("TLS chain incomplete"), "got: {msg}");
        assert!(msg.contains("AIA"), "should mention AIA: {msg}");
        assert!(
            msg.contains("DigiCert TLS RSA SHA256 2020 CA1"),
            "should name the missing intermediate: {msg}"
        );
        assert!(msg.contains("--ca-cert"), "should suggest --ca-cert: {msg}");
    }

    #[test]
    fn unknown_root_falls_back_to_trust_store_hint() {
        let details = vec!["depth 0: self signed certificate in certificate chain (CN=test)".to_string()];
        let err = handshake_verify_error("certificate verify failed", &details, false);
        let msg = err.to_string();
        assert!(!msg.contains("TLS chain incomplete"), "got: {msg}");
        assert!(msg.contains("SSL_CERT_FILE"), "got: {msg}");
    }

    #[test]
    fn detects_tls13_certificate_required_alert() {
        let msg = "TLS connect failed: tlsv13 alert certificate required";
        assert!(is_client_auth_required(msg));
    }

    #[test]
    fn detects_legacy_certificate_required_alert() {
        let msg = "TLS connect failed: sslv3 alert certificate required";
        assert!(is_client_auth_required(msg));
    }

    #[test]
    fn detects_peer_did_not_return_a_certificate() {
        let msg = "TLS read error: peer did not return a certificate";
        assert!(is_client_auth_required(msg));
    }

    #[test]
    fn does_not_match_unrelated_handshake_failures() {
        assert!(!is_client_auth_required(
            "TLS handshake failed: certificate verify failed: self-signed cert"
        ));
        assert!(!is_client_auth_required(
            "TLS handshake failed: unable to get local issuer certificate"
        ));
        assert!(!is_client_auth_required("TCP connection refused"));
    }
}
