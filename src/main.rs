use anyhow::{Context, Result};
use clap::CommandFactory;
use clap::{Parser, ValueEnum};
use colored::*;
use openssl::hash::MessageDigest;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use pem_rfc7468::LineEnding;
use std::env;
use std::fs;
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

lazy_static::lazy_static! {
    static ref OID_X509_SCT_LIST: x509_parser::asn1_rs::Oid<'static> =
        x509_parser::asn1_rs::Oid::from(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2]).unwrap();
}

/// Return the version string for `--version` output.
///
/// Prefers the git tag set by build.rs (e.g. "2.0.2" from tag "v2.0.2"),
/// falling back to CARGO_PKG_VERSION from Cargo.toml for non-git builds
/// (e.g. `cargo install` from crates.io) or shallow clones without tags.
fn dcert_version() -> &'static str {
    // DCERT_GIT_VERSION is set by build.rs from `git describe --tags --always`.
    // When no tags are reachable (shallow clone), git describe --always returns
    // just a commit hash (e.g. "42e938d") — fall back to CARGO_PKG_VERSION.
    match option_env!("DCERT_GIT_VERSION") {
        Some(git_ver) if git_ver.contains('.') => git_ver.strip_prefix('v').unwrap_or(git_ver),
        _ => env!("CARGO_PKG_VERSION"),
    }
}

static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
const MAX_CONNECTIONS: usize = 10;
const CONNECTION_TIMEOUT_SECS: u64 = 10;
const READ_TIMEOUT_SECS: u64 = 5;

/// Exit codes for machine-readable scripting.
mod exit_code {
    /// All certificates are valid and no warnings triggered.
    pub const SUCCESS: i32 = 0;
    /// At least one certificate is expiring soon (--expiry-warn threshold).
    pub const EXPIRY_WARNING: i32 = 1;
    /// A connection or processing error occurred.
    pub const ERROR: i32 = 2;
    /// TLS certificate verification failed.
    pub const VERIFY_FAILED: i32 = 3;
    /// At least one certificate in the chain is already expired.
    pub const CERT_EXPIRED: i32 = 4;
    /// At least one certificate has been revoked (OCSP).
    pub const CERT_REVOKED: i32 = 5;
}

struct ConnectionGuard;
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Check if a host should bypass proxy based on no_proxy environment variables
#[cfg(test)]
fn should_bypass_proxy(host: &str) -> bool {
    let no_proxy = env::var("no_proxy")
        .or_else(|_| env::var("NO_PROXY"))
        .unwrap_or_default();

    if no_proxy.is_empty() {
        return false;
    }

    let host = host.to_lowercase();

    for pattern in no_proxy.split(',') {
        let pattern = pattern.trim().to_lowercase();
        if pattern.is_empty() {
            continue;
        }

        // Exact match
        if pattern == host {
            return true;
        }

        // Domain suffix match (e.g., .example.com matches subdomain.example.com)
        if pattern.starts_with('.') && host.ends_with(&pattern) {
            return true;
        }

        // Subdomain match (e.g., example.com matches subdomain.example.com)
        if !pattern.starts_with('.') && host.ends_with(&format!(".{}", pattern)) {
            return true;
        }

        // Special case for localhost
        if pattern == "localhost" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
            return true;
        }
    }

    false
}

/// Cached proxy configuration, read once at startup.
struct ProxyConfig {
    https_proxy: Option<String>,
    http_proxy: Option<String>,
    no_proxy: String,
}

impl ProxyConfig {
    fn from_env() -> Self {
        let https_proxy = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
            .iter()
            .find_map(|var| env::var(var).ok().filter(|v| !v.is_empty()));
        let http_proxy = ["HTTP_PROXY", "http_proxy"]
            .iter()
            .find_map(|var| env::var(var).ok().filter(|v| !v.is_empty()));
        let no_proxy = env::var("no_proxy")
            .or_else(|_| env::var("NO_PROXY"))
            .unwrap_or_default();
        Self {
            https_proxy,
            http_proxy,
            no_proxy,
        }
    }

    fn get_proxy_url(&self, scheme: &str) -> Option<&str> {
        match scheme {
            "https" => self.https_proxy.as_deref(),
            "http" => self.http_proxy.as_deref(),
            _ => None,
        }
    }

    fn should_bypass(&self, host: &str) -> bool {
        if self.no_proxy.is_empty() {
            return false;
        }
        let host = host.to_lowercase();
        for pattern in self.no_proxy.split(',') {
            let pattern = pattern.trim().to_lowercase();
            if pattern.is_empty() {
                continue;
            }
            if pattern == host {
                return true;
            }
            if pattern.starts_with('.') && host.ends_with(&pattern) {
                return true;
            }
            if !pattern.starts_with('.') && host.ends_with(&format!(".{}", pattern)) {
                return true;
            }
            if pattern == "localhost" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
                return true;
            }
        }
        false
    }
}

/// Get proxy URL from environment variables (legacy, used by tests)
#[cfg(test)]
fn get_proxy_url(scheme: &str) -> Option<String> {
    let env_vars = match scheme {
        "https" => vec!["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"],
        "http" => vec!["HTTP_PROXY", "http_proxy"],
        _ => vec![],
    };

    for var in env_vars {
        if let Ok(proxy) = env::var(var) {
            if !proxy.is_empty() {
                return Some(proxy);
            }
        }
    }

    None
}

/// Connect through HTTP proxy using CONNECT method
fn connect_through_proxy(proxy_url: &str, target_host: &str, target_port: u16) -> Result<TcpStream> {
    let proxy = Url::parse(proxy_url).map_err(|e| anyhow::anyhow!("Invalid proxy URL {}: {}", proxy_url, e))?;

    let proxy_host = proxy
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Proxy URL must include a host"))?;
    let proxy_port = proxy.port().unwrap_or(8080);

    // Connect to proxy
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port)
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("Failed to resolve proxy {}: {}", proxy_host, e))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No valid address found for proxy {}", proxy_host))?;

    let mut stream = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .map_err(|e| anyhow::anyhow!("Failed to connect to proxy: {}", e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))
        .map_err(|e| anyhow::anyhow!("Failed to set proxy read timeout: {}", e))?;

    // Send CONNECT request
    let connect_request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: keep-alive\r\n\r\n",
        target_host, target_port, target_host, target_port
    );

    stream
        .write_all(connect_request.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to send CONNECT request: {}", e))?;

    // Read proxy response
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];

    // Read until we get the full HTTP response headers
    loop {
        let n = stream
            .read(&mut buffer)
            .map_err(|e| anyhow::anyhow!("Failed to read proxy response: {}", e))?;

        if n == 0 {
            break;
        }

        response.extend_from_slice(&buffer[..n]);

        // Check if we have the complete headers (ending with \r\n\r\n)
        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    let status_line = response_str
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty proxy response"))?;

    // Check if the CONNECT was successful (200 Connection established)
    if !status_line.contains("200") {
        return Err(anyhow::anyhow!("Proxy CONNECT failed: {}", status_line));
    }

    Ok(stream)
}

/// Load CA certificates into the SSL connector builder.
///
/// Uses `openssl-probe` to discover system CA certificate locations, then falls
/// back to OpenSSL's `set_default_verify_paths()`. This ensures dcert works on:
/// - macOS (Homebrew OpenSSL, which lacks Keychain access)
/// - Linux (distro-specific cert paths)
/// - Environments with custom CA bundles (SSL_CERT_FILE / SSL_CERT_DIR)
fn load_ca_certs(builder: &mut openssl::ssl::SslConnectorBuilder) -> Result<()> {
    // Use openssl-probe to find system CA certs and set the environment variables
    // that OpenSSL uses. This is critical on macOS where Homebrew OpenSSL's
    // compiled-in paths may not contain any certificates.
    if !openssl_probe::has_ssl_cert_env_vars() {
        let probe = openssl_probe::probe();
        if let Some(ref cert_file) = probe.cert_file {
            env::set_var("SSL_CERT_FILE", cert_file);
        }
        if let Some(cert_dir) = probe.cert_dir.first() {
            env::set_var("SSL_CERT_DIR", cert_dir);
        }
    }

    builder
        .set_default_verify_paths()
        .map_err(|e| anyhow::anyhow!("Failed to load CA certificates: {}", e))?;

    Ok(())
}

/// Establish a direct TCP connection with timeout and DNS resolution.
fn direct_tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let socket_addr = format!("{}:{}", host, port)
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("Failed to resolve host {}: {}", host, e))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No valid address found for host {}", host))?;

    TcpStream::connect_timeout(&socket_addr, timeout)
        .map_err(|e| anyhow::anyhow!("TCP connection to {}:{} failed: {e}", host, port))
}

/// Fetch TLS certificate chain using OpenSSL, with proxy support and custom CA certificates.
#[allow(clippy::too_many_arguments)]
fn fetch_tls_chain_openssl(
    endpoint: &str,
    method: &str,
    headers: &[(String, String)],
    _http_protocol: HttpProtocol,
    no_verify: bool,
    timeout_secs: u64,
    read_timeout_secs: u64,
    sni_override: Option<&str>,
    proxy_config: &ProxyConfig,
) -> Result<TlsConnectionInfo> {
    // Guard against too many concurrent connections
    let current = ACTIVE_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
    if current >= MAX_CONNECTIONS {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
        return Err(anyhow::anyhow!("Too many concurrent connections"));
    }

    // Ensure cleanup on all paths
    let _guard = ConnectionGuard;

    // Validate URL more thoroughly
    let url = url::Url::parse(endpoint).map_err(|e| anyhow::anyhow!("Invalid URL: {e}"))?;
    if url.scheme() != "https" {
        return Err(anyhow::anyhow!("Only HTTPS scheme is supported"));
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must include a host"))?;

    // Validate port range
    let port = url.port().unwrap_or(443);
    if port == 0 {
        return Err(anyhow::anyhow!("Invalid port number: {}", port));
    }

    // Layer 4: TCP connect with timeout (with proxy support)
    let connect_timeout = Duration::from_secs(timeout_secs);
    let l4_start = std::time::Instant::now();

    let stream = if proxy_config.should_bypass(host) {
        direct_tcp_connect(host, port, connect_timeout)?
    } else if let Some(proxy_url) = proxy_config.get_proxy_url("https") {
        eprintln!("Using proxy: {}", proxy_url);
        connect_through_proxy(proxy_url, host, port)?
    } else {
        direct_tcp_connect(host, port, connect_timeout)?
    };

    // Set read timeout
    stream
        .set_read_timeout(Some(Duration::from_secs(read_timeout_secs)))
        .map_err(|e| anyhow::anyhow!("Failed to set read timeout: {e}"))?;

    let l4_latency = l4_start.elapsed().as_millis();

    // Layer 7: TLS handshake + HTTP request
    let l7_start = std::time::Instant::now();
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| anyhow::anyhow!("OpenSSL builder failed: {e}"))?;

    // Load CA certificates (system defaults, or custom via SSL_CERT_FILE/SSL_CERT_DIR)
    load_ca_certs(&mut builder)?;

    // Collect per-certificate verification errors for chain validation detail
    let verify_errors: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let errors_clone = verify_errors.clone();

    if no_verify {
        // Collect chain but don't abort on verification failure; still record errors
        builder.set_verify_callback(SslVerifyMode::PEER, move |preverify, ctx| {
            if !preverify {
                let depth = ctx.error_depth();
                let err = ctx.error();
                let subject = ctx
                    .current_cert()
                    .map(|c| {
                        c.subject_name().entries().fold(String::new(), |mut acc, e| {
                            if !acc.is_empty() {
                                acc.push_str(", ");
                            }
                            if let Ok(data) = e.data().as_utf8() {
                                acc.push_str(data.as_ref());
                            }
                            acc
                        })
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                if let Ok(mut errs) = errors_clone.lock() {
                    errs.push(format!("depth {}: {} ({})", depth, err, subject));
                }
            }
            true // always continue
        });
    } else {
        builder.set_verify_callback(SslVerifyMode::PEER, move |preverify, ctx| {
            if !preverify {
                let depth = ctx.error_depth();
                let err = ctx.error();
                let subject = ctx
                    .current_cert()
                    .map(|c| {
                        c.subject_name().entries().fold(String::new(), |mut acc, e| {
                            if !acc.is_empty() {
                                acc.push_str(", ");
                            }
                            if let Ok(data) = e.data().as_utf8() {
                                acc.push_str(data.as_ref());
                            }
                            acc
                        })
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                if let Ok(mut errs) = errors_clone.lock() {
                    errs.push(format!("depth {}: {} ({})", depth, err, subject));
                }
            }
            preverify // respect the original verification result
        });
    }
    let connector = builder.build();

    let sni_host = sni_override.unwrap_or(host);
    let mut ssl_stream = connector.connect(sni_host, stream).map_err(|e| {
        let err_str = e.to_string();
        if err_str.contains("certificate verify failed") || err_str.contains("unable to get local issuer") {
            anyhow::anyhow!(
                "TLS handshake failed: {e}\n\
                 Hint: OpenSSL could not find CA certificates. Try one of:\n  \
                 - Set SSL_CERT_FILE to point to your CA bundle (e.g. /etc/ssl/certs/ca-certificates.crt)\n  \
                 - Set SSL_CERT_DIR to your certificates directory\n  \
                 - Use --no-verify to skip certificate verification"
            )
        } else {
            anyhow::anyhow!("TLS handshake failed: {e}")
        }
    })?;

    // Build HTTP request
    let path = if url.path().is_empty() { "/" } else { url.path() };

    // OpenSSL doesn't handle HTTP/2 framing; always use HTTP/1.1 on the wire.
    // The warning is printed in process_target() before calling this function.
    let req = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);

    let mut req = req;
    for (key, value) in headers {
        req.push_str(&format!("{}: {}\r\n", key, value));
    }
    req.push_str("Connection: close\r\n\r\n");

    // Send HTTP request
    ssl_stream
        .write_all(req.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to send HTTP request: {e}"))?;

    // Flush the stream to ensure the request is sent
    ssl_stream
        .flush()
        .map_err(|e| anyhow::anyhow!("Failed to flush stream: {e}"))?;

    // Read HTTP response to get status code
    // We need to read the response in a loop to handle partial reads
    let mut response_buffer = Vec::new();
    let mut temp_buffer = [0u8; 1024];
    let mut attempts = 0;
    const MAX_ATTEMPTS: usize = 10;

    // Keep reading until we have at least the status line
    while attempts < MAX_ATTEMPTS && response_buffer.len() < 4096 {
        match ssl_stream.read(&mut temp_buffer) {
            Ok(0) => break, // EOF
            Ok(n) => {
                response_buffer.extend_from_slice(&temp_buffer[..n]);

                // Check if we have a complete status line (HTTP/1.1 200 OK\r\n)
                if let Some(end_pos) = response_buffer.windows(2).position(|w| w == b"\r\n") {
                    // We found the end of the first line
                    if end_pos >= 12 {
                        // Minimum valid status line length
                        break;
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout, but we might have partial data
                if !response_buffer.is_empty() {
                    break;
                }
            }
            Err(e) => {
                // Log the error but continue if we have some data
                eprintln!("Warning: Error reading HTTP response: {}", e);
                break;
            }
        }
        attempts += 1;
    }

    // Parse HTTP status code
    let http_response_code = if !response_buffer.is_empty() {
        // Find the first line ending
        let line_end = response_buffer
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(response_buffer.len().min(100));

        let status_line = &response_buffer[..line_end];

        if let Ok(status_str) = std::str::from_utf8(status_line) {
            // Parse "HTTP/1.1 200 OK" format
            // Split by spaces and get the second element (status code)
            let parts: Vec<&str> = status_str.split_whitespace().collect();
            if parts.len() >= 2 {
                // The second part should be the status code
                if let Ok(code) = parts[1].parse::<u16>() {
                    code
                } else {
                    eprintln!("Warning: Could not parse status code from: {}", status_str);
                    0
                }
            } else {
                eprintln!("Warning: Invalid status line format: {}", status_str);
                0
            }
        } else {
            eprintln!("Warning: Status line is not valid UTF-8");
            0
        }
    } else {
        eprintln!("Warning: No response data received");
        0
    };

    let l7_latency = l7_start.elapsed().as_millis();

    // Get cert chain
    let certs = ssl_stream
        .ssl()
        .peer_cert_chain()
        .ok_or_else(|| anyhow::anyhow!("No peer certificates presented"))?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("Empty certificate chain"));
    }

    // Convert DER to concatenated PEM
    let mut pem = String::new();
    for cert in certs {
        let pem_str = pem_rfc7468::encode_string(
            "CERTIFICATE",
            LineEnding::LF,
            &cert
                .to_der()
                .map_err(|e| anyhow::anyhow!("DER conversion failed: {e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("PEM encoding failed: {e}"))?;
        pem.push_str(&pem_str);
        if !pem.ends_with('\n') {
            pem.push('\n');
        }
    }

    let ssl = ssl_stream.ssl();
    let tls_version = ssl.version_str().to_string();
    let current_cipher = ssl.current_cipher();
    let tls_cipher = current_cipher
        .map(|c| c.name().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let tls_cipher_iana = current_cipher.and_then(|c| c.standard_name().map(|s| s.to_string()));

    // Get verification result
    let verify_result = {
        let result = ssl_stream.ssl().verify_result();
        if result == openssl::x509::X509VerifyResult::OK {
            None
        } else {
            Some(format!("{}", result))
        }
    };

    // Collect chain validation errors
    let chain_validation_errors = verify_errors.lock().map(|errs| errs.clone()).unwrap_or_default();

    Ok(TlsConnectionInfo {
        pem_data: pem,
        l4_latency,
        l7_latency,
        tls_version,
        tls_cipher,
        tls_cipher_iana,
        http_response_code,
        verify_result,
        chain_validation_errors,
    })
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
    Yaml,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum HttpProtocol {
    Http1_1,
    Http2,
}

#[derive(ValueEnum, Clone, Debug)]
enum HttpMethod {
    Get,
    Post,
    Head,
    Options,
}

#[derive(ValueEnum, Clone, Debug, Copy)]
enum SortOrder {
    Asc,
    Desc,
}

#[derive(ValueEnum, Clone, Debug, Copy)]
enum CipherNotation {
    /// IANA/RFC standard names (e.g. TLS_AES_256_GCM_SHA384)
    Iana,
    /// OpenSSL names (e.g. TLS_AES_256_GCM_SHA384) — same for TLS 1.3, differs for TLS 1.2
    Openssl,
}

#[derive(Parser, Debug)]
#[command(name = "dcert")]
#[command(
    about = "Decode and validate TLS certificates from a PEM file or fetch the TLS certificate chain from an HTTPS endpoint.\n\
             If you specify an HTTPS URL, dcert will fetch and decode the server's TLS certificate chain.\n\
             Optionally, you can export the chain as a PEM file."
)]
#[command(version = dcert_version())]
struct Args {
    /// Path(s) to PEM file(s) or HTTPS URL(s). Use '-' to read targets from stdin (one per line)
    #[arg(value_parser = validate_target, num_args = 1..)]
    targets: Vec<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    format: OutputFormat,

    /// Show only expired certificates
    #[arg(long)]
    expired_only: bool,

    /// Export the fetched PEM chain to a file (only for HTTPS targets)
    #[arg(long)]
    export_pem: Option<String>,

    /// Exclude expired or invalid certificates from export (only with --export-pem)
    #[arg(long)]
    exclude_expired: bool,

    /// Sort certificates by expiry date (asc = soonest first, desc = latest first)
    #[arg(long, value_enum)]
    sort_expiry: Option<SortOrder>,

    /// HTTP method to use for HTTPS requests (default: GET)
    #[arg(long, value_enum, default_value_t = HttpMethod::Get)]
    method: HttpMethod,

    /// Custom HTTP headers (key:value), can be repeated
    #[arg(long, value_parser = parse_header, num_args = 0.., value_name = "HEADER")]
    header: Vec<(String, String)>,

    /// HTTP protocol to use (default: http1-1)
    #[arg(long, value_enum, default_value_t = HttpProtocol::Http1_1)]
    http_protocol: HttpProtocol,

    /// Disable TLS certificate verification (insecure)
    #[arg(long)]
    no_verify: bool,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Read timeout in seconds (time to wait for server response after connection)
    #[arg(long, default_value_t = 5)]
    read_timeout: u64,

    /// Override SNI hostname for TLS handshake
    #[arg(long)]
    sni: Option<String>,

    /// Show SHA-256 fingerprint for each certificate
    #[arg(long)]
    fingerprint: bool,

    /// Show certificate extensions (key usage, basic constraints, etc.)
    #[arg(long)]
    extensions: bool,

    /// Warn if any certificate expires within the given number of days (exit code 1)
    #[arg(long, value_name = "DAYS")]
    expiry_warn: Option<u64>,

    /// Compare certificates between exactly two targets
    #[arg(long)]
    diff: bool,

    /// Periodically re-check targets at the given interval in seconds
    #[arg(long, value_name = "SECONDS")]
    watch: Option<u64>,

    /// Check certificate revocation status via OCSP
    #[arg(long)]
    check_revocation: bool,

    /// Show the negotiated (agreed) TLS cipher suite in the given notation
    #[arg(long, value_enum, value_name = "NOTATION")]
    ciphers: Option<CipherNotation>,
}

#[derive(Debug, serde::Serialize, Clone)]
struct CertInfo {
    index: usize,
    subject: String,
    issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    common_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subject_alternative_names: Vec<String>,
    serial_number: String,
    not_before: String, // RFC 3339
    not_after: String,  // RFC 3339
    is_expired: bool,
    ct_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sct_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key_size_bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_usage: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extended_key_usage: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    basic_constraints: Option<BasicConstraintsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority_info_access: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_status: Option<String>,
}

#[derive(Debug, serde::Serialize, Clone)]
struct BasicConstraintsInfo {
    ca: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_len_constraint: Option<u32>,
}

/// Options controlling what extra information to extract from certificates.
struct CertProcessOpts {
    expired_only: bool,
    fingerprint: bool,
    extensions: bool,
}

/// Process a single certificate into CertInfo
fn process_certificate(
    cert: X509Certificate<'_>,
    der_bytes: &[u8],
    idx: usize,
    opts: &CertProcessOpts,
) -> Result<Option<CertInfo>> {
    // Build owned info
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    // Serial as uppercase hex
    let serial_bytes = cert.raw_serial();
    let serial_number = serial_bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>();

    // Validity converted to RFC3339 strings
    let nb: OffsetDateTime = cert.validity().not_before.to_datetime();
    let na: OffsetDateTime = cert.validity().not_after.to_datetime();
    let now = OffsetDateTime::now_utc();

    let not_before = nb.format(&Rfc3339).unwrap_or_else(|_| nb.to_string());
    let not_after = na.format(&Rfc3339).unwrap_or_else(|_| na.to_string());
    let is_expired = na < now;

    if opts.expired_only && !is_expired {
        return Ok(None);
    }

    let common_name = extract_common_name(&cert);
    let subject_alternative_names = extract_sans(&cert);

    let sct_ext = cert.extensions().iter().find(|ext| ext.oid == *OID_X509_SCT_LIST);
    let ct_present = sct_ext.is_some();

    // Try to count individual SCTs in the extension.
    // The SCT list is an ASN.1 OCTET STRING wrapping a TLS-encoded SignedCertificateTimestampList:
    //   - 2 bytes: total list length
    //   - each SCT: 2 bytes length + SCT data
    let sct_count: Option<usize> = if opts.extensions {
        sct_ext.and_then(|ext| {
            let data = ext.value;
            // The outer layer is an ASN.1 OCTET STRING; parse it to get inner bytes
            let inner = if data.len() > 2 && data[0] == 0x04 {
                // Simple DER OCTET STRING: tag=0x04, length, value
                let len_byte = data[1] as usize;
                if len_byte < 0x80 && data.len() >= 2 + len_byte {
                    &data[2..2 + len_byte]
                } else if len_byte == 0x81 && data.len() > 3 {
                    let len = data[2] as usize;
                    if data.len() >= 3 + len {
                        &data[3..3 + len]
                    } else {
                        data
                    }
                } else if len_byte == 0x82 && data.len() > 4 {
                    let len = ((data[2] as usize) << 8) | (data[3] as usize);
                    if data.len() >= 4 + len {
                        &data[4..4 + len]
                    } else {
                        data
                    }
                } else {
                    data
                }
            } else {
                data
            };
            // Now inner is the TLS-encoded list: 2-byte total length, then SCTs
            if inner.len() < 2 {
                return None;
            }
            let total_len = ((inner[0] as usize) << 8) | (inner[1] as usize);
            let mut offset = 2;
            let end = (2 + total_len).min(inner.len());
            let mut count = 0usize;
            while offset + 2 <= end {
                let sct_len = ((inner[offset] as usize) << 8) | (inner[offset + 1] as usize);
                offset += 2 + sct_len;
                count += 1;
            }
            Some(count)
        })
    } else {
        None
    };

    // SHA-256 fingerprint
    let sha256_fingerprint = if opts.fingerprint {
        let digest = openssl::hash::hash(MessageDigest::sha256(), der_bytes)
            .map_err(|e| anyhow::anyhow!("SHA-256 hash failed: {e}"))?;
        Some(
            digest
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":"),
        )
    } else {
        None
    };

    // Signature algorithm
    let signature_algorithm = if opts.extensions {
        Some(cert.signature_algorithm.algorithm.to_id_string())
    } else {
        None
    };

    // Public key info (always shown in extensions mode)
    let (public_key_algorithm, public_key_size_bits) = if opts.extensions {
        let spki = cert.public_key();
        let alg_oid = spki.algorithm.algorithm.to_id_string();
        let alg_name = match alg_oid.as_str() {
            "1.2.840.113549.1.1.1" => "RSA".to_string(),
            "1.2.840.10045.2.1" => "EC".to_string(),
            "1.3.101.110" => "X25519".to_string(),
            "1.3.101.112" => "Ed25519".to_string(),
            "1.3.101.113" => "Ed448".to_string(),
            other => other.to_string(),
        };
        let key_bits = (spki.subject_public_key.data.len() * 8) as u32;
        (Some(alg_name), Some(key_bits))
    } else {
        (None, None)
    };

    // Extensions
    let (key_usage, extended_key_usage, basic_constraints, authority_info_access) = if opts.extensions {
        let mut ku = None;
        let mut eku = None;
        let mut bc = None;
        let mut aia = None;

        for ext in cert.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::KeyUsage(usage) => {
                    let mut usages = Vec::new();
                    if usage.digital_signature() {
                        usages.push("digitalSignature".to_string());
                    }
                    if usage.non_repudiation() {
                        usages.push("nonRepudiation".to_string());
                    }
                    if usage.key_encipherment() {
                        usages.push("keyEncipherment".to_string());
                    }
                    if usage.data_encipherment() {
                        usages.push("dataEncipherment".to_string());
                    }
                    if usage.key_agreement() {
                        usages.push("keyAgreement".to_string());
                    }
                    if usage.key_cert_sign() {
                        usages.push("keyCertSign".to_string());
                    }
                    if usage.crl_sign() {
                        usages.push("cRLSign".to_string());
                    }
                    if usage.encipher_only() {
                        usages.push("encipherOnly".to_string());
                    }
                    if usage.decipher_only() {
                        usages.push("decipherOnly".to_string());
                    }
                    if !usages.is_empty() {
                        ku = Some(usages);
                    }
                }
                ParsedExtension::ExtendedKeyUsage(usage) => {
                    let mut usages = Vec::new();
                    if usage.server_auth {
                        usages.push("serverAuth".to_string());
                    }
                    if usage.client_auth {
                        usages.push("clientAuth".to_string());
                    }
                    if usage.code_signing {
                        usages.push("codeSigning".to_string());
                    }
                    if usage.email_protection {
                        usages.push("emailProtection".to_string());
                    }
                    if usage.time_stamping {
                        usages.push("timeStamping".to_string());
                    }
                    if usage.ocsp_signing {
                        usages.push("ocspSigning".to_string());
                    }
                    if !usages.is_empty() {
                        eku = Some(usages);
                    }
                }
                ParsedExtension::BasicConstraints(constraints) => {
                    bc = Some(BasicConstraintsInfo {
                        ca: constraints.ca,
                        path_len_constraint: constraints.path_len_constraint,
                    });
                }
                ParsedExtension::AuthorityInfoAccess(access) => {
                    let mut urls = Vec::new();
                    for desc in access.iter() {
                        let method_oid = desc.access_method.to_id_string();
                        let method = match method_oid.as_str() {
                            "1.3.6.1.5.5.7.48.1" => "OCSP",
                            "1.3.6.1.5.5.7.48.2" => "CA Issuers",
                            _ => &method_oid,
                        };
                        match &desc.access_location {
                            GeneralName::URI(uri) => {
                                urls.push(format!("{}: {}", method, uri));
                            }
                            _ => {
                                urls.push(format!("{}: (non-URI)", method));
                            }
                        }
                    }
                    if !urls.is_empty() {
                        aia = Some(urls);
                    }
                }
                _ => {}
            }
        }

        (ku, eku, bc, aia)
    } else {
        (None, None, None, None)
    };

    Ok(Some(CertInfo {
        index: idx,
        subject,
        issuer,
        common_name,
        subject_alternative_names,
        serial_number,
        not_before,
        not_after,
        is_expired,
        ct_present,
        sct_count,
        sha256_fingerprint,
        signature_algorithm,
        public_key_algorithm,
        public_key_size_bits,
        key_usage,
        extended_key_usage,
        basic_constraints,
        authority_info_access,
        revocation_status: None,
    }))
}

/// Parse all PEM certificate blocks from `pem_data` and return owned `CertInfo`
/// for each certificate. We do not store `X509Certificate` to avoid lifetime issues.
fn parse_cert_infos_from_pem(pem_data: &str, opts: &CertProcessOpts) -> Result<Vec<CertInfo>> {
    let blocks = pem::parse_many(pem_data).map_err(|e| anyhow::anyhow!("Failed to parse PEM: {e}"))?;

    let mut infos = Vec::new();
    let mut errors = Vec::new();

    for (idx, block) in blocks.iter().enumerate() {
        if block.tag() != "CERTIFICATE" {
            continue;
        }

        match X509Certificate::from_der(block.contents()) {
            Ok((_, cert)) => {
                match process_certificate(cert, block.contents(), idx, opts) {
                    Ok(Some(info)) => infos.push(info),
                    Ok(None) => {} // Filtered out (e.g., not expired when expired_only is true)
                    Err(e) => errors.push(format!("Certificate {}: {}", idx, e)),
                }
            }
            Err(e) => {
                errors.push(format!("Certificate {} parsing failed: {}", idx, e));
                continue;
            }
        }
    }

    // Return results even if some certs failed, but warn about errors
    if !errors.is_empty() {
        eprintln!("Warning: Some certificates had issues:");
        for error in &errors {
            eprintln!("  - {}", error);
        }
    }

    if infos.is_empty() && !errors.is_empty() {
        return Err(anyhow::anyhow!(
            "All certificates failed to parse:\n{}",
            errors.join("\n")
        ));
    }

    Ok(infos)
}

fn extract_common_name(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_attributes()
        .find(|attr| *attr.attr_type() == x509_parser::oid_registry::OID_X509_COMMON_NAME)
        .and_then(|attr| attr.attr_value().as_str().ok())
        .map(|s| s.to_string())
}

fn extract_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut out = Vec::new();

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                match gn {
                    GeneralName::DNSName(d) => out.push(format!("DNS:{}", d)),
                    GeneralName::RFC822Name(e) => out.push(format!("Email:{}", e)),
                    GeneralName::URI(u) => out.push(format!("URI:{}", u)),
                    GeneralName::IPAddress(bytes) => match bytes.len() {
                        4 => {
                            if let Ok(v4) = <[u8; 4]>::try_from(&bytes[..]) {
                                out.push(format!("IP:{}", IpAddr::from(v4)));
                            }
                        }
                        16 => {
                            if let Ok(v6) = <[u8; 16]>::try_from(&bytes[..]) {
                                out.push(format!("IP:{}", IpAddr::from(v6)));
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }

    out
}

/// Extract OCSP responder URL from a certificate's Authority Information Access extension.
fn extract_ocsp_url(cert: &X509Certificate<'_>) -> Option<String> {
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                // OID 1.3.6.1.5.5.7.48.1 = id-ad-ocsp
                if desc.access_method.to_id_string() == "1.3.6.1.5.5.7.48.1" {
                    if let GeneralName::URI(uri) = &desc.access_location {
                        return Some(uri.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Check OCSP revocation status for a certificate.
/// Returns "good", "revoked", "unknown", or an error description.
fn check_ocsp_status(cert_der: &[u8], issuer_der: Option<&[u8]>, ocsp_url: &str) -> String {
    let cert = match X509::from_der(cert_der) {
        Ok(c) => c,
        Err(e) => return format!("error: failed to parse cert: {}", e),
    };

    let issuer = match issuer_der {
        Some(der) => match X509::from_der(der) {
            Ok(c) => c,
            Err(e) => return format!("error: failed to parse issuer: {}", e),
        },
        None => return "unknown (no issuer certificate available)".to_string(),
    };

    // Build OCSP request
    let cert_id = match openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), &cert, &issuer) {
        Ok(id) => id,
        Err(e) => return format!("error: OCSP cert ID creation failed: {}", e),
    };

    let mut ocsp_req_builder = match openssl::ocsp::OcspRequest::new() {
        Ok(r) => r,
        Err(e) => return format!("error: OCSP request creation failed: {}", e),
    };

    if let Err(e) = ocsp_req_builder.add_id(cert_id) {
        return format!("error: failed to add cert ID: {}", e);
    }

    let request_bytes = match ocsp_req_builder.to_der() {
        Ok(b) => b,
        Err(e) => return format!("error: OCSP request serialization failed: {}", e),
    };

    // Send OCSP request via HTTP POST
    let url = match Url::parse(ocsp_url) {
        Ok(u) => u,
        Err(e) => return format!("error: invalid OCSP URL: {}", e),
    };

    let host = match url.host_str() {
        Some(h) => h.to_string(),
        None => return "error: OCSP URL has no host".to_string(),
    };
    let default_port = match url.scheme() {
        "https" => 443,
        _ => 80,
    };
    let port = url.port().unwrap_or(default_port);
    let path = if url.path().is_empty() { "/" } else { url.path() };

    let tcp_stream = match direct_tcp_connect(&host, port, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => return format!("error: connect to OCSP responder failed: {}", e),
    };
    let _ = tcp_stream.set_read_timeout(Some(Duration::from_secs(5)));

    let http_req = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/ocsp-request\r\nContent-Length: {}\r\n\r\n",
        path,
        host,
        request_bytes.len()
    );

    let mut buf_stream = std::io::BufWriter::new(tcp_stream);
    if buf_stream.write_all(http_req.as_bytes()).is_err()
        || buf_stream.write_all(&request_bytes).is_err()
        || buf_stream.flush().is_err()
    {
        return "error: failed to send OCSP request".to_string();
    }

    let mut tcp_stream = match buf_stream.into_inner() {
        Ok(s) => s,
        Err(_) => return "error: failed to flush stream".to_string(),
    };

    let mut response = Vec::new();
    if tcp_stream.read_to_end(&mut response).is_err() {
        return "error: failed to read OCSP response".to_string();
    }

    // Find end of HTTP headers
    let header_end = match response.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => pos + 4,
        None => return "error: malformed OCSP HTTP response".to_string(),
    };

    let ocsp_bytes = &response[header_end..];
    if ocsp_bytes.is_empty() {
        return "error: empty OCSP response body".to_string();
    }

    let ocsp_response = match openssl::ocsp::OcspResponse::from_der(ocsp_bytes) {
        Ok(r) => r,
        Err(e) => return format!("error: OCSP response parse failed: {}", e),
    };

    match ocsp_response.status() {
        openssl::ocsp::OcspResponseStatus::SUCCESSFUL => {}
        status => return format!("error: OCSP response status: {:?}", status),
    }

    // Parse the basic response to check cert status
    let basic = match ocsp_response.basic() {
        Ok(b) => b,
        Err(e) => return format!("error: OCSP basic response failed: {}", e),
    };

    // Re-create cert_id for status lookup
    let cert_id2 = match openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), &cert, &issuer) {
        Ok(id) => id,
        Err(_) => return "error: cert ID re-creation failed".to_string(),
    };

    match basic.find_status(&cert_id2) {
        Some(status) => {
            let revoked = status.revocation_time.is_some();
            if revoked {
                "revoked".to_string()
            } else {
                "good".to_string()
            }
        }
        None => "unknown (no status in response)".to_string(),
    }
}

/// Debug/connection info for pretty output.
struct PrettyDebugInfo<'a> {
    hostname: Option<&'a str>,
    conn: Option<&'a TlsConnectionInfo>,
    http_protocol: &'a HttpProtocol,
    cipher_notation: Option<CipherNotation>,
}

fn print_pretty(infos: &[CertInfo], debug: &PrettyDebugInfo<'_>) {
    if let (Some(host), Some(conn)) = (debug.hostname, debug.conn) {
        if let Some(leaf) = infos.first() {
            let matched = cert_matches_hostname(leaf, host);
            let status = if matched { "true".green() } else { "false".red() };
            println!();
            println!("{}", "Debug".bold());
            println!(
                "  HTTP protocol: {}",
                match debug.http_protocol {
                    HttpProtocol::Http2 => "HTTP/2",
                    HttpProtocol::Http1_1 => "HTTP/1.1",
                }
            );
            if conn.http_response_code > 0 {
                let code_color = match conn.http_response_code {
                    200..=299 => conn.http_response_code.to_string().green(),
                    300..=399 => conn.http_response_code.to_string().yellow(),
                    400..=499 => conn.http_response_code.to_string().red(),
                    500..=599 => conn.http_response_code.to_string().red().bold(),
                    _ => conn.http_response_code.to_string().normal(),
                };
                println!("  HTTP response code: {}", code_color);
            } else {
                println!("  HTTP response code: not available");
            }
            println!("  Hostname matches certificate SANs/CN: {}", status);
            println!("  TLS version used: {}", conn.tls_version);
            // Cipher display: always show OpenSSL name in the default line,
            // but when --ciphers is used, show the requested notation prominently
            match debug.cipher_notation {
                Some(CipherNotation::Iana) => {
                    let iana_name = conn
                        .tls_cipher_iana
                        .as_deref()
                        .unwrap_or("unknown (IANA name not available)");
                    println!("  TLS ciphersuite agreed (IANA): {}", iana_name);
                }
                Some(CipherNotation::Openssl) => {
                    println!("  TLS ciphersuite agreed (OpenSSL): {}", conn.tls_cipher);
                }
                None => {
                    println!("  TLS ciphersuite agreed: {}", conn.tls_cipher);
                }
            }
            let ct_str = if leaf.ct_present { "true".green() } else { "false".red() };
            println!("  Certificate transparency: {}", ct_str);

            // Verification result
            if let Some(ref err) = conn.verify_result {
                println!("  Chain verification: {}", err.red());
                for detail in &conn.chain_validation_errors {
                    println!("    {}", detail.red());
                }
            } else {
                println!("  Chain verification: {}", "ok".green());
            }

            println!();
            println!("  Network latency (layer 4/TCP connect): {} ms", conn.l4_latency);
            println!("  Network latency (layer 7/TLS+HTTP):    {} ms", conn.l7_latency);
            println!();
            println!(
                "Note: DNS, Layer 4, and Layer 7 latencies are measured separately and should not be summed. \
DNS covers name resolution only; Layer 4 covers TCP connection only; \
Layer 7 covers TLS handshake and HTTP request."
            );
            println!();
        }
    }
    for info in infos {
        println!("{}", "Certificate".bold());
        println!("  Index        : {}", info.index);
        if let Some(cn) = &info.common_name {
            println!("  Common Name  : {}", cn);
        }
        println!("  Subject      : {}", info.subject);
        println!("  Issuer       : {}", info.issuer);
        println!("  Serial       : {}", info.serial_number);
        println!("  Not Before   : {}", info.not_before);
        println!("  Not After    : {}", info.not_after);

        if !info.subject_alternative_names.is_empty() {
            println!("  SANs         :");
            for san in &info.subject_alternative_names {
                println!("    - {}", san);
            }
        }

        if let Some(ref fp) = info.sha256_fingerprint {
            println!("  SHA-256      : {}", fp);
        }

        if let Some(ref alg) = info.signature_algorithm {
            println!("  Sig Algorithm: {}", alg);
        }

        if let Some(ref alg) = info.public_key_algorithm {
            let size_str = info
                .public_key_size_bits
                .map(|s| format!(" ({} bits)", s))
                .unwrap_or_default();
            println!("  Public Key   : {}{}", alg, size_str);
        }

        if let Some(ref ku) = info.key_usage {
            println!("  Key Usage    : {}", ku.join(", "));
        }

        if let Some(ref eku) = info.extended_key_usage {
            println!("  Ext Key Usage: {}", eku.join(", "));
        }

        if let Some(ref bc) = info.basic_constraints {
            let ca_str = if bc.ca { "true" } else { "false" };
            let path_str = bc
                .path_len_constraint
                .map(|p| format!(", pathLen={}", p))
                .unwrap_or_default();
            println!("  Basic Constr : CA={}{}", ca_str, path_str);
        }

        if let Some(ref aia) = info.authority_info_access {
            println!("  Auth Info    :");
            for entry in aia {
                println!("    - {}", entry);
            }
        }

        if let Some(ref rev) = info.revocation_status {
            let colored_status = match rev.as_str() {
                "good" => rev.green(),
                "revoked" => rev.red(),
                _ => rev.yellow(),
            };
            println!("  Revocation   : {}", colored_status);
        }

        let status = if info.is_expired {
            "expired".red()
        } else {
            "valid".green()
        };
        println!("  Status       : {}", status);
        println!();
    }
}

fn cert_matches_hostname(cert: &CertInfo, host: &str) -> bool {
    let host = host.trim().to_lowercase();

    // Helper for wildcard matching
    fn matches_wildcard(pattern: &str, hostname: &str) -> bool {
        // Only allow wildcard at the start, e.g. *.example.com
        if let Some(stripped) = pattern.strip_prefix("*.") {
            // Host must have at least one subdomain
            if let Some(rest) = hostname.strip_prefix('.') {
                return rest.ends_with(stripped);
            }
            // Or, split and check
            let host_labels: Vec<&str> = hostname.split('.').collect();
            let pattern_labels: Vec<&str> = stripped.split('.').collect();
            if host_labels.len() < pattern_labels.len() + 1 {
                return false;
            }
            let host_suffix = host_labels[1..].join(".");
            return host_suffix == stripped;
        }
        false
    }

    // Check Common Name
    if let Some(cn) = &cert.common_name {
        let cn = cn.trim().to_lowercase();
        if cn == host {
            return true;
        }
        if cn.starts_with("*.") && matches_wildcard(&cn, &host) {
            return true;
        }
    }
    // Check SANs
    for san in &cert.subject_alternative_names {
        if let Some(san_host) = san.strip_prefix("DNS:") {
            let san_host = san_host.trim().to_lowercase();
            if san_host == host {
                return true;
            }
            if san_host.starts_with("*.") && matches_wildcard(&san_host, &host) {
                return true;
            }
        }
    }
    false
}

/// Result of a TLS connection, containing the certificate chain and connection metadata.
struct TlsConnectionInfo {
    pem_data: String,
    l4_latency: u128,
    l7_latency: u128,
    tls_version: String,
    /// OpenSSL cipher name (e.g. "ECDHE-RSA-AES256-GCM-SHA384" for TLS 1.2)
    tls_cipher: String,
    /// IANA/RFC cipher name (e.g. "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
    tls_cipher_iana: Option<String>,
    http_response_code: u16,
    verify_result: Option<String>,
    /// Per-certificate chain validation errors (depth, error, subject).
    chain_validation_errors: Vec<String>,
}

/// Result of processing a single target.
struct TargetResult {
    target: String,
    conn_info: Option<TlsConnectionInfo>,
    infos: Vec<CertInfo>,
    pem_data: String,
}

/// Process a single target (PEM file or HTTPS URL) and return results.
fn process_target(target: &str, args: &Args, proxy_config: &ProxyConfig) -> Result<TargetResult> {
    let opts = CertProcessOpts {
        expired_only: args.expired_only,
        fingerprint: args.fingerprint,
        extensions: args.extensions,
    };

    let (pem_data, conn_info) = if target.starts_with("https://") {
        if matches!(args.http_protocol, HttpProtocol::Http2) {
            eprintln!(
                "{} --http-protocol http2 has no effect; dcert always uses HTTP/1.1 on the wire \
                 (OpenSSL does not support HTTP/2 framing)",
                "Warning:".yellow().bold()
            );
        }
        if args.no_verify {
            eprintln!(
                "{} TLS certificate verification is disabled (--no-verify). \
                 Chain validation errors will be suppressed.",
                "Warning:".yellow().bold()
            );
        }
        let conn = fetch_tls_chain_openssl(
            target,
            &args.method.to_string(),
            &args.header,
            args.http_protocol,
            args.no_verify,
            args.timeout,
            args.read_timeout,
            args.sni.as_deref(),
            proxy_config,
        )
        .with_context(|| format!("Failed to fetch TLS chain from {}", target))?;
        let pem = conn.pem_data.clone();
        (pem, Some(conn))
    } else {
        let pem = fs::read_to_string(target).with_context(|| format!("Failed to read PEM file: {}", target))?;
        (pem, None)
    };

    let mut infos = parse_cert_infos_from_pem(&pem_data, &opts).with_context(|| "Failed to parse PEM certificates")?;

    // OCSP revocation checking
    if args.check_revocation {
        let blocks = pem::parse_many(&pem_data).unwrap_or_default();
        let cert_ders: Vec<&[u8]> = blocks
            .iter()
            .filter(|b| b.tag() == "CERTIFICATE")
            .map(|b| b.contents())
            .collect();

        for (i, info) in infos.iter_mut().enumerate() {
            // Parse the x509 cert to extract OCSP URL
            if let Some(der) = cert_ders.get(i) {
                if let Ok((_, cert)) = X509Certificate::from_der(der) {
                    if let Some(ocsp_url) = extract_ocsp_url(&cert) {
                        let issuer_der = cert_ders.get(i + 1).copied();
                        info.revocation_status = Some(check_ocsp_status(der, issuer_der, &ocsp_url));
                    } else {
                        info.revocation_status = Some("unknown (no OCSP responder)".to_string());
                    }
                }
            }
        }
    }

    // Sort certificates by expiry if requested
    if let Some(sort_order) = args.sort_expiry {
        sort_certs_by_expiry(&mut infos, sort_order);
    }

    Ok(TargetResult {
        target: target.to_string(),
        conn_info,
        infos,
        pem_data,
    })
}

/// Sort certificates by expiry date.
fn sort_certs_by_expiry(infos: &mut [CertInfo], sort_order: SortOrder) {
    infos.sort_by(|a, b| {
        let parse_date = |date_str: &str| -> Option<OffsetDateTime> { OffsetDateTime::parse(date_str, &Rfc3339).ok() };

        let ordering = match (parse_date(&a.not_after), parse_date(&b.not_after)) {
            (Some(date_a), Some(date_b)) => date_a.cmp(&date_b),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.not_after.cmp(&b.not_after),
        };

        match sort_order {
            SortOrder::Asc => ordering,
            SortOrder::Desc => ordering.reverse(),
        }
    });
}

/// Check expiry warning threshold and return exit code.
fn check_expiry_warnings(infos: &[CertInfo], warn_days: u64) -> i32 {
    let now = OffsetDateTime::now_utc();
    let threshold = now + time::Duration::days(warn_days as i64);
    let mut has_warning = false;

    for info in infos {
        if let Ok(not_after) = OffsetDateTime::parse(&info.not_after, &Rfc3339) {
            if info.is_expired {
                eprintln!(
                    "{} Certificate {} ({}) is EXPIRED (expired {})",
                    "WARNING:".yellow().bold(),
                    info.index,
                    info.common_name.as_deref().unwrap_or(&info.subject),
                    info.not_after,
                );
                has_warning = true;
            } else if not_after <= threshold {
                let days_left = (not_after - now).whole_days();
                eprintln!(
                    "{} Certificate {} ({}) expires in {} days ({})",
                    "WARNING:".yellow().bold(),
                    info.index,
                    info.common_name.as_deref().unwrap_or(&info.subject),
                    days_left,
                    info.not_after,
                );
                has_warning = true;
            }
        }
    }

    if has_warning {
        1
    } else {
        0
    }
}

/// Print diff between two sets of certificate infos.
fn print_diff(target_a: &str, infos_a: &[CertInfo], target_b: &str, infos_b: &[CertInfo]) {
    println!("{}", "Certificate Diff".bold());
    println!("  A: {}", target_a);
    println!("  B: {}", target_b);
    println!();

    let max_len = infos_a.len().max(infos_b.len());
    for i in 0..max_len {
        let a = infos_a.get(i);
        let b = infos_b.get(i);

        match (a, b) {
            (Some(ca), Some(cb)) => {
                println!("{}", format!("Certificate [{}]", i).bold());
                diff_field("Subject", &ca.subject, &cb.subject);
                diff_field("Issuer", &ca.issuer, &cb.issuer);
                diff_field(
                    "Common Name",
                    ca.common_name.as_deref().unwrap_or("(none)"),
                    cb.common_name.as_deref().unwrap_or("(none)"),
                );
                diff_field("Serial", &ca.serial_number, &cb.serial_number);
                diff_field("Not Before", &ca.not_before, &cb.not_before);
                diff_field("Not After", &ca.not_after, &cb.not_after);
                diff_field("Expired", &ca.is_expired.to_string(), &cb.is_expired.to_string());
                if let (Some(fa), Some(fb)) = (&ca.sha256_fingerprint, &cb.sha256_fingerprint) {
                    diff_field("SHA-256", fa, fb);
                }
                let sans_a = ca.subject_alternative_names.join(", ");
                let sans_b = cb.subject_alternative_names.join(", ");
                diff_field("SANs", &sans_a, &sans_b);
                println!();
            }
            (Some(ca), None) => {
                println!("{} Only in A: index={} subject={}", "+".green(), ca.index, ca.subject);
            }
            (None, Some(cb)) => {
                println!("{} Only in B: index={} subject={}", "+".green(), cb.index, cb.subject);
            }
            (None, None) => {}
        }
    }
}

fn diff_field(name: &str, a: &str, b: &str) {
    if a == b {
        println!("  {:<14}: {}", name, a);
    } else {
        println!("  {:<14}: {} → {}", name, a.to_string().red(), b.to_string().green());
    }
}

/// Export PEM chain to a file, optionally excluding expired certs.
fn export_pem_chain(pem_data: &str, export_path: &str, exclude_expired: bool) -> Result<()> {
    let export_data = if exclude_expired {
        let blocks = pem::parse_many(pem_data).map_err(|e| anyhow::anyhow!("Failed to parse PEM for export: {e}"))?;
        let now = OffsetDateTime::now_utc();
        let mut filtered_pem = String::new();

        for block in blocks {
            if block.tag() != "CERTIFICATE" {
                continue;
            }
            if let Ok((_, cert)) = X509Certificate::from_der(block.contents()) {
                let not_after: OffsetDateTime = cert.validity().not_after.to_datetime();
                if not_after >= now {
                    let pem_str = pem_rfc7468::encode_string("CERTIFICATE", LineEnding::LF, block.contents())
                        .map_err(|e| anyhow::anyhow!("PEM encoding failed: {e}"))?;
                    filtered_pem.push_str(&pem_str);
                    if !filtered_pem.ends_with('\n') {
                        filtered_pem.push('\n');
                    }
                }
            }
        }

        if filtered_pem.is_empty() {
            eprintln!(
                "Warning: All certificates were expired. No certificates exported to {}",
                export_path
            );
            return Ok(());
        }

        filtered_pem
    } else {
        pem_data.to_string()
    };

    fs::write(export_path, export_data).with_context(|| format!("Failed to write PEM file: {}", export_path))?;
    println!("PEM chain exported to {}", export_path);
    Ok(())
}

/// Output results for a target in the requested format.
fn output_results(
    result: &TargetResult,
    format: OutputFormat,
    http_protocol: &HttpProtocol,
    multi_target: bool,
    args: &Args,
) -> Result<()> {
    if multi_target {
        println!("{}", format!("--- {} ---", result.target).bold().cyan());
    }

    let hostname = if result.target.starts_with("https://") {
        Url::parse(&result.target)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_lowercase()))
    } else {
        None
    };

    match format {
        OutputFormat::Pretty => {
            let debug = PrettyDebugInfo {
                hostname: hostname.as_deref(),
                conn: result.conn_info.as_ref(),
                http_protocol,
                cipher_notation: args.ciphers,
            };
            print_pretty(&result.infos, &debug);
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result.infos)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(&result.infos)?);
        }
    }
    Ok(())
}

fn run() -> Result<i32> {
    let mut args: Args = Args::parse();

    // Cache proxy configuration from environment at startup
    let proxy_config = ProxyConfig::from_env();

    // Resolve targets (support stdin via '-')
    let mut targets: Vec<String> = Vec::new();
    for t in &args.targets {
        if t == "-" {
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() {
                eprintln!("Reading targets from stdin (one per line, Ctrl-D to finish)...");
            }
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let line = line.with_context(|| "Failed to read from stdin")?;
                let line = line.trim().to_string();
                if !line.is_empty() {
                    targets.push(line);
                }
            }
        } else {
            targets.push(t.clone());
        }
    }

    if targets.is_empty() {
        return Err(anyhow::anyhow!("No targets specified"));
    }

    // Validate diff mode
    if args.diff && targets.len() != 2 {
        return Err(anyhow::anyhow!("--diff requires exactly 2 targets"));
    }

    // Watch mode
    if let Some(interval) = args.watch {
        // Auto-enable fingerprint in watch mode so change detection works
        if !args.fingerprint {
            args.fingerprint = true;
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        // Handle Ctrl+C gracefully
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .ok();

        let mut iteration = 0u64;
        let mut prev_fingerprints: std::collections::HashMap<String, Vec<Option<String>>> =
            std::collections::HashMap::new();

        while running.load(Ordering::SeqCst) {
            iteration += 1;
            let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default();
            println!(
                "{}",
                format!("=== Watch iteration {} at {} ===", iteration, now)
                    .bold()
                    .cyan()
            );

            for target in &targets {
                match process_target(target, &args, &proxy_config) {
                    Ok(result) => {
                        // Check for changes
                        let current_fps: Vec<Option<String>> =
                            result.infos.iter().map(|c| c.sha256_fingerprint.clone()).collect();

                        if let Some(prev) = prev_fingerprints.get(target) {
                            if prev != &current_fps {
                                println!("{}", format!("CHANGE DETECTED for {}", target).red().bold());
                            }
                        }
                        prev_fingerprints.insert(target.clone(), current_fps);

                        output_results(&result, args.format, &args.http_protocol, targets.len() > 1, &args)?;
                    }
                    Err(e) => {
                        eprintln!("{} {}: {}", "Error:".red().bold(), target, e);
                    }
                }
            }

            if !running.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_secs(interval));
        }

        println!("\nWatch stopped.");
        return Ok(0);
    }

    // Normal (non-watch) mode
    let multi_target = targets.len() > 1;
    let mut exit_code = exit_code::SUCCESS;
    let mut all_results: Vec<TargetResult> = Vec::new();

    for target in &targets {
        match process_target(target, &args, &proxy_config) {
            Ok(result) => {
                // Check for verification failure
                if let Some(ref conn) = result.conn_info {
                    if conn.verify_result.is_some() && exit_code < exit_code::VERIFY_FAILED {
                        exit_code = exit_code::VERIFY_FAILED;
                    }
                }
                all_results.push(result);
            }
            Err(e) => {
                eprintln!("{} {}: {}", "Error:".red().bold(), target, e);
                exit_code = exit_code::ERROR;
            }
        }
    }

    // Diff mode
    if args.diff {
        if all_results.len() == 2 {
            // Enable fingerprint for diff comparison
            print_diff(
                &all_results[0].target,
                &all_results[0].infos,
                &all_results[1].target,
                &all_results[1].infos,
            );
        } else {
            return Err(anyhow::anyhow!("Failed to fetch both targets for diff comparison"));
        }
        return Ok(exit_code);
    }

    // JSON multi-target wrapping
    if multi_target && matches!(args.format, OutputFormat::Json) {
        let mut map = serde_json::Map::new();
        for result in &all_results {
            map.insert(result.target.clone(), serde_json::to_value(&result.infos)?);
        }
        println!("{}", serde_json::to_string_pretty(&map)?);
    } else if multi_target && matches!(args.format, OutputFormat::Yaml) {
        let mut map = std::collections::BTreeMap::new();
        for result in &all_results {
            map.insert(result.target.clone(), result.infos.clone());
        }
        println!("{}", serde_yml::to_string(&map)?);
    } else {
        for result in &all_results {
            output_results(result, args.format, &args.http_protocol, multi_target, &args)?;
        }
    }

    // Check for expired certificates
    for result in &all_results {
        if result.infos.iter().any(|c| c.is_expired) && exit_code < exit_code::CERT_EXPIRED {
            exit_code = exit_code::CERT_EXPIRED;
        }
        // Check for revoked certificates
        if result
            .infos
            .iter()
            .any(|c| c.revocation_status.as_deref() == Some("revoked"))
            && exit_code < exit_code::CERT_REVOKED
        {
            exit_code = exit_code::CERT_REVOKED;
        }
    }

    // Check expiry warnings (overrides lower exit codes)
    if let Some(warn_days) = args.expiry_warn {
        for result in &all_results {
            if multi_target {
                eprintln!("--- Expiry check: {} ---", result.target);
            }
            let warn_code = check_expiry_warnings(&result.infos, warn_days);
            if warn_code > 0 && exit_code < exit_code::EXPIRY_WARNING {
                exit_code = exit_code::EXPIRY_WARNING;
            }
        }
    }

    // Export PEM
    if let Some(ref export_path) = args.export_pem {
        if all_results.len() == 1 {
            export_pem_chain(&all_results[0].pem_data, export_path, args.exclude_expired)?;
        } else {
            eprintln!("Warning: --export-pem only supported for a single target");
        }
    }

    // Check for empty results
    if all_results.iter().all(|r| r.infos.is_empty()) && exit_code == exit_code::SUCCESS {
        eprintln!("{}", "No valid certificates found in the input".red());
        return Ok(exit_code::EXPIRY_WARNING);
    }

    Ok(exit_code)
}

fn main() {
    // Print help if no arguments (other than program name) are provided
    if std::env::args().len() == 1 {
        Args::command().print_help().unwrap();
        println!();
        std::process::exit(0);
    }

    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            std::process::exit(exit_code::ERROR);
        }
    }
}

fn validate_target(s: &str) -> Result<String, String> {
    if s == "-" || s.starts_with("https://") || std::path::Path::new(s).exists() {
        Ok(s.to_string())
    } else if let Some(rest) = s.strip_prefix("http://") {
        Err(format!("HTTP is not supported. Did you mean https://{rest}?"))
    } else if looks_like_hostname(s) {
        // Bare hostname like "www.google.com" or "10.0.0.1:8443"
        Ok(format!("https://{s}"))
    } else {
        Err(format!(
            "'{s}' is not a valid target. Provide an HTTPS URL, hostname, PEM file path, or '-' for stdin"
        ))
    }
}

/// Check if a string looks like a hostname (with optional port) rather than a file path.
fn looks_like_hostname(s: &str) -> bool {
    // Must not be empty
    if s.is_empty() {
        return false;
    }
    // Strip optional port suffix (e.g. "example.com:8443")
    let host_part = if let Some(idx) = s.rfind(':') {
        let port_part = &s[idx + 1..];
        // If what follows ':' is all digits, treat it as host:port
        if port_part.chars().all(|c| c.is_ascii_digit()) && !port_part.is_empty() {
            &s[..idx]
        } else {
            s
        }
    } else {
        s
    };
    // Must contain a dot (domain) or be a valid IP address
    if host_part.contains('.') {
        // Hostname chars: alphanumeric, hyphens, dots
        host_part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    } else {
        // Could be a single-label hostname like "localhost"
        host_part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && host_part.len() > 1
    }
}

fn parse_header(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("Header must be in key:value format".to_string());
    }
    Ok((parts[0].trim().to_string(), parts[1].trim().to_string()))
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // A self-signed test certificate with CN=test.example.com and SANs
    const VALID_PEM: &str = include_str!("../tests/data/valid.pem");

    // The multi-cert chain from tests/data/test.pem (Microsoft Azure)
    const CHAIN_PEM: &str = include_str!("../tests/data/test.pem");

    fn default_opts() -> CertProcessOpts {
        CertProcessOpts {
            expired_only: false,
            fingerprint: false,
            extensions: false,
        }
    }

    fn opts_expired_only() -> CertProcessOpts {
        CertProcessOpts {
            expired_only: true,
            fingerprint: false,
            extensions: false,
        }
    }

    fn opts_with_fingerprint() -> CertProcessOpts {
        CertProcessOpts {
            expired_only: false,
            fingerprint: true,
            extensions: false,
        }
    }

    fn opts_with_extensions() -> CertProcessOpts {
        CertProcessOpts {
            expired_only: false,
            fingerprint: false,
            extensions: true,
        }
    }

    fn make_test_cert(common_name: Option<&str>, sans: Vec<&str>) -> CertInfo {
        CertInfo {
            index: 0,
            subject: common_name.map(|cn| format!("CN={}", cn)).unwrap_or_default(),
            issuer: "CN=Test CA".to_string(),
            common_name: common_name.map(|s| s.to_string()),
            subject_alternative_names: sans.into_iter().map(|s| s.to_string()).collect(),
            serial_number: "AABB".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2027-01-01T00:00:00Z".to_string(),
            is_expired: false,
            ct_present: false,
            sct_count: None,
            sha256_fingerprint: None,
            signature_algorithm: None,
            public_key_algorithm: None,
            public_key_size_bits: None,
            key_usage: None,
            extended_key_usage: None,
            basic_constraints: None,
            authority_info_access: None,
            revocation_status: None,
        }
    }

    // ---------------------------------------------------------------
    // parse_cert_infos_from_pem tests
    // ---------------------------------------------------------------

    #[test]
    fn test_empty_pem() {
        let result = parse_cert_infos_from_pem("", &default_opts());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_invalid_pem() {
        let result = parse_cert_infos_from_pem("invalid pem data", &default_opts());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_valid_single_cert() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        assert_eq!(infos.len(), 1);
        let cert = &infos[0];
        assert!(cert.common_name.as_deref() == Some("test.example.com"));
        assert!(!cert.subject.is_empty());
        assert!(!cert.issuer.is_empty());
        assert!(!cert.serial_number.is_empty());
        assert!(!cert.not_before.is_empty());
        assert!(!cert.not_after.is_empty());
    }

    #[test]
    fn test_valid_cert_sans() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        let cert = &infos[0];
        assert!(
            cert.subject_alternative_names
                .iter()
                .any(|s| s == "DNS:test.example.com"),
            "expected DNS:test.example.com in SANs, got {:?}",
            cert.subject_alternative_names
        );
        assert!(
            cert.subject_alternative_names.iter().any(|s| s == "DNS:*.example.com"),
            "expected DNS:*.example.com in SANs"
        );
        assert!(
            cert.subject_alternative_names.iter().any(|s| s == "IP:127.0.0.1"),
            "expected IP:127.0.0.1 in SANs"
        );
    }

    #[test]
    fn test_valid_cert_not_expired() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        assert!(!infos[0].is_expired, "test cert should not be expired yet");
    }

    #[test]
    fn test_cert_chain_multiple_certs() {
        let infos = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        assert_eq!(infos.len(), 3, "test.pem should contain 3 certificates");
    }

    #[test]
    fn test_cert_chain_indices() {
        let infos = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        assert_eq!(infos[0].index, 0);
        assert_eq!(infos[1].index, 1);
        assert_eq!(infos[2].index, 2);
    }

    #[test]
    fn test_expired_only_filter() {
        let all = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        let expired = parse_cert_infos_from_pem(CHAIN_PEM, &opts_expired_only()).unwrap();
        let expired_count = all.iter().filter(|c| c.is_expired).count();
        assert_eq!(expired.len(), expired_count);
        for cert in &expired {
            assert!(cert.is_expired, "expired_only should only return expired certs");
        }
    }

    #[test]
    fn test_cert_serial_is_hex() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        let serial = &infos[0].serial_number;
        assert!(
            serial.chars().all(|c| c.is_ascii_hexdigit()),
            "serial should be hex, got: {}",
            serial
        );
    }

    #[test]
    fn test_cert_dates_are_rfc3339() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        let not_before = &infos[0].not_before;
        let not_after = &infos[0].not_after;
        assert!(
            OffsetDateTime::parse(not_before, &Rfc3339).is_ok(),
            "not_before should be RFC3339: {not_before}",
        );
        assert!(
            OffsetDateTime::parse(not_after, &Rfc3339).is_ok(),
            "not_after should be RFC3339: {not_after}",
        );
    }

    #[test]
    fn test_pem_with_non_certificate_blocks() {
        let mixed = format!(
            "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----\n{}",
            VALID_PEM
        );
        let infos = parse_cert_infos_from_pem(&mixed, &default_opts()).unwrap();
        assert_eq!(infos.len(), 1, "should skip non-CERTIFICATE blocks");
    }

    // ---------------------------------------------------------------
    // Fingerprint tests
    // ---------------------------------------------------------------

    #[test]
    fn test_fingerprint_computed_when_requested() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &opts_with_fingerprint()).unwrap();
        let cert = &infos[0];
        assert!(cert.sha256_fingerprint.is_some(), "fingerprint should be present");
        let fp = cert.sha256_fingerprint.as_ref().unwrap();
        // SHA-256 fingerprint is 32 bytes = 64 hex chars + 31 colons = 95 chars
        assert_eq!(fp.len(), 95, "fingerprint should be 95 chars (AA:BB:CC format)");
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':'),
            "fingerprint should be hex with colons"
        );
    }

    #[test]
    fn test_fingerprint_not_present_by_default() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        assert!(infos[0].sha256_fingerprint.is_none());
    }

    // ---------------------------------------------------------------
    // Extensions tests
    // ---------------------------------------------------------------

    #[test]
    fn test_extensions_parsed_when_requested() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &opts_with_extensions()).unwrap();
        let cert = &infos[0];
        assert!(
            cert.signature_algorithm.is_some(),
            "signature_algorithm should be present with --extensions"
        );
        // Self-signed cert should have basic constraints
        assert!(
            cert.basic_constraints.is_some(),
            "basic_constraints should be present for self-signed cert"
        );
    }

    #[test]
    fn test_extensions_not_present_by_default() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        assert!(infos[0].signature_algorithm.is_none());
        assert!(infos[0].key_usage.is_none());
        assert!(infos[0].extended_key_usage.is_none());
        assert!(infos[0].basic_constraints.is_none());
    }

    #[test]
    fn test_chain_extensions() {
        let infos = parse_cert_infos_from_pem(CHAIN_PEM, &opts_with_extensions()).unwrap();
        // At least the leaf cert should have extended key usage
        let has_eku = infos.iter().any(|c| c.extended_key_usage.is_some());
        assert!(has_eku, "at least one cert in chain should have EKU");
    }

    // ---------------------------------------------------------------
    // Expiry warning tests
    // ---------------------------------------------------------------

    #[test]
    fn test_expiry_warn_no_warning_for_distant_expiry() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        // cert expires in ~1 year, warning for 7 days should not trigger
        let code = check_expiry_warnings(&infos, 7);
        assert_eq!(code, 0, "no warning should be triggered for distant expiry");
    }

    #[test]
    fn test_expiry_warn_warning_for_large_horizon() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        // cert expires in ~1 year, warning for 400 days should trigger
        let code = check_expiry_warnings(&infos, 400);
        assert_eq!(code, 1, "warning should be triggered for large horizon");
    }

    #[test]
    fn test_expiry_warn_expired_certs() {
        let all = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        let has_expired = all.iter().any(|c| c.is_expired);
        if has_expired {
            let code = check_expiry_warnings(&all, 1);
            assert_eq!(code, 1, "expired certs should trigger warning");
        }
    }

    // ---------------------------------------------------------------
    // Sort expiry tests
    // ---------------------------------------------------------------

    #[test]
    fn test_sort_certs_by_expiry_asc() {
        let mut infos = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        sort_certs_by_expiry(&mut infos, SortOrder::Asc);
        for i in 1..infos.len() {
            assert!(infos[i - 1].not_after <= infos[i].not_after, "expected ascending order");
        }
    }

    #[test]
    fn test_sort_certs_by_expiry_desc() {
        let mut infos = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        sort_certs_by_expiry(&mut infos, SortOrder::Desc);
        for i in 1..infos.len() {
            assert!(
                infos[i - 1].not_after >= infos[i].not_after,
                "expected descending order"
            );
        }
    }

    // ---------------------------------------------------------------
    // parse_header tests
    // ---------------------------------------------------------------

    #[test]
    fn test_parse_header() {
        assert_eq!(
            parse_header("Content-Type: application/json").unwrap(),
            ("Content-Type".to_string(), "application/json".to_string())
        );
        assert_eq!(
            parse_header("Authorization: Bearer token:with:colons").unwrap(),
            ("Authorization".to_string(), "Bearer token:with:colons".to_string())
        );
        assert!(parse_header("InvalidHeader").is_err());
    }

    #[test]
    fn test_parse_header_whitespace_trimming() {
        let (key, value) = parse_header("  X-Custom  :  some value  ").unwrap();
        assert_eq!(key, "X-Custom");
        assert_eq!(value, "some value");
    }

    #[test]
    fn test_parse_header_empty_value() {
        let (key, value) = parse_header("X-Empty:").unwrap();
        assert_eq!(key, "X-Empty");
        assert_eq!(value, "");
    }

    // ---------------------------------------------------------------
    // validate_target tests
    // ---------------------------------------------------------------

    #[test]
    fn test_validate_target_https_url() {
        assert!(validate_target("https://example.com").is_ok());
        assert!(validate_target("https://example.com:8443/path").is_ok());
    }

    #[test]
    fn test_validate_target_invalid() {
        assert!(validate_target("http://example.com").is_err());
        assert!(validate_target("ftp://example.com").is_err());
        assert!(validate_target("/nonexistent/path.pem").is_err());
    }

    #[test]
    fn test_validate_target_existing_file() {
        let path = "tests/data/valid.pem";
        assert!(validate_target(path).is_ok());
    }

    #[test]
    fn test_validate_target_stdin() {
        assert!(validate_target("-").is_ok());
    }

    #[test]
    fn test_validate_target_bare_hostname() {
        // Bare hostnames should auto-prepend https://
        let result = validate_target("www.google.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://www.google.com");

        let result = validate_target("example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com");

        let result = validate_target("api.example.com:8443");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://api.example.com:8443");
    }

    #[test]
    fn test_validate_target_http_rejected_with_hint() {
        let result = validate_target("http://example.com");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("https://example.com"), "Should suggest HTTPS: {err}");
    }

    #[test]
    fn test_looks_like_hostname() {
        assert!(looks_like_hostname("www.google.com"));
        assert!(looks_like_hostname("example.com"));
        assert!(looks_like_hostname("example.com:443"));
        assert!(looks_like_hostname("10.0.0.1"));
        assert!(looks_like_hostname("sub-domain.example.co.uk"));
        assert!(looks_like_hostname("localhost"));

        // Should NOT look like hostnames
        assert!(!looks_like_hostname(""));
        assert!(!looks_like_hostname("a")); // too short single-label
        assert!(!looks_like_hostname("/etc/ssl/certs"));
        assert!(!looks_like_hostname("file with spaces.pem"));
    }

    // ---------------------------------------------------------------
    // cert_matches_hostname tests
    // ---------------------------------------------------------------

    #[test]
    fn test_hostname_exact_match_cn() {
        let cert = make_test_cert(Some("test.example.com"), vec![]);
        assert!(cert_matches_hostname(&cert, "test.example.com"));
        assert!(!cert_matches_hostname(&cert, "other.example.com"));
    }

    #[test]
    fn test_hostname_case_insensitive() {
        let cert = make_test_cert(Some("Test.Example.COM"), vec![]);
        assert!(cert_matches_hostname(&cert, "test.example.com"));
        assert!(cert_matches_hostname(&cert, "TEST.EXAMPLE.COM"));
    }

    #[test]
    fn test_hostname_wildcard_san() {
        let cert = make_test_cert(None, vec!["DNS:*.example.com"]);
        assert!(cert_matches_hostname(&cert, "www.example.com"));
        assert!(cert_matches_hostname(&cert, "mail.example.com"));
        assert!(!cert_matches_hostname(&cert, "example.com"));
        assert!(!cert_matches_hostname(&cert, "sub.sub.example.com"));
    }

    #[test]
    fn test_hostname_san_exact_match() {
        let cert = make_test_cert(None, vec!["DNS:api.example.com", "DNS:www.example.com"]);
        assert!(cert_matches_hostname(&cert, "api.example.com"));
        assert!(cert_matches_hostname(&cert, "www.example.com"));
        assert!(!cert_matches_hostname(&cert, "other.example.com"));
    }

    #[test]
    fn test_hostname_no_match() {
        let cert = make_test_cert(Some("other.example.com"), vec!["DNS:another.example.com"]);
        assert!(!cert_matches_hostname(&cert, "test.example.com"));
    }

    // ---------------------------------------------------------------
    // should_bypass_proxy tests (combined to avoid env var races)
    // ---------------------------------------------------------------

    #[test]
    fn test_bypass_proxy_logic() {
        let orig_no_proxy = env::var("no_proxy").ok();
        let orig_no_proxy_upper = env::var("NO_PROXY").ok();

        env::remove_var("no_proxy");
        env::remove_var("NO_PROXY");
        assert!(!should_bypass_proxy("example.com"), "empty no_proxy should not bypass");

        env::set_var("no_proxy", "example.com,other.com");
        assert!(should_bypass_proxy("example.com"), "exact match should bypass");
        assert!(should_bypass_proxy("other.com"), "exact match should bypass");
        assert!(!should_bypass_proxy("notmatched.com"), "non-matching should not bypass");

        env::set_var("no_proxy", ".example.com");
        assert!(should_bypass_proxy("sub.example.com"), "suffix should bypass subdomain");
        assert!(
            !should_bypass_proxy("example.com"),
            "suffix should not bypass exact domain"
        );

        env::set_var("no_proxy", "example.com");
        assert!(should_bypass_proxy("sub.example.com"), "subdomain should bypass");

        env::set_var("no_proxy", "localhost");
        assert!(should_bypass_proxy("localhost"), "localhost should bypass");
        assert!(
            should_bypass_proxy("127.0.0.1"),
            "127.0.0.1 should bypass for localhost"
        );
        assert!(should_bypass_proxy("::1"), "::1 should bypass for localhost");

        if let Some(v) = orig_no_proxy {
            env::set_var("no_proxy", v);
        } else {
            env::remove_var("no_proxy");
        }
        if let Some(v) = orig_no_proxy_upper {
            env::set_var("NO_PROXY", v);
        } else {
            env::remove_var("NO_PROXY");
        }
    }

    // ---------------------------------------------------------------
    // get_proxy_url tests (combined to avoid env var races)
    // ---------------------------------------------------------------

    #[test]
    fn test_get_proxy_url_logic() {
        let orig_https = env::var("HTTPS_PROXY").ok();
        let orig_http = env::var("HTTP_PROXY").ok();
        let orig_https_l = env::var("https_proxy").ok();
        let orig_http_l = env::var("http_proxy").ok();

        env::remove_var("HTTPS_PROXY");
        env::remove_var("HTTP_PROXY");
        env::remove_var("https_proxy");
        env::remove_var("http_proxy");

        assert_eq!(get_proxy_url("https"), None, "no proxy vars should return None");
        assert_eq!(get_proxy_url("http"), None, "no proxy vars should return None");
        assert_eq!(get_proxy_url("ftp"), None, "unknown scheme should return None");

        if let Some(v) = orig_https {
            env::set_var("HTTPS_PROXY", v);
        }
        if let Some(v) = orig_http {
            env::set_var("HTTP_PROXY", v);
        }
        if let Some(v) = orig_https_l {
            env::set_var("https_proxy", v);
        }
        if let Some(v) = orig_http_l {
            env::set_var("http_proxy", v);
        }
    }

    // ---------------------------------------------------------------
    // HttpMethod Display tests
    // ---------------------------------------------------------------

    #[test]
    fn test_http_method_display() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Post.to_string(), "POST");
        assert_eq!(HttpMethod::Head.to_string(), "HEAD");
        assert_eq!(HttpMethod::Options.to_string(), "OPTIONS");
    }

    // ---------------------------------------------------------------
    // CertInfo serialization tests
    // ---------------------------------------------------------------

    #[test]
    fn test_cert_info_json_serialization() {
        let mut info = make_test_cert(Some("test"), vec!["DNS:test.com"]);
        info.ct_present = true;
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"common_name\":\"test\""));
        assert!(json.contains("\"ct_present\":true"));
        assert!(json.contains("\"is_expired\":false"));
    }

    #[test]
    fn test_cert_info_json_omits_empty_fields() {
        let info = make_test_cert(None, vec![]);
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("common_name"), "None common_name should be omitted");
        assert!(
            !json.contains("subject_alternative_names"),
            "empty SANs should be omitted"
        );
        assert!(
            !json.contains("sha256_fingerprint"),
            "None fingerprint should be omitted"
        );
        assert!(!json.contains("key_usage"), "None key_usage should be omitted");
        assert!(!json.contains("extended_key_usage"), "None EKU should be omitted");
        assert!(!json.contains("basic_constraints"), "None BC should be omitted");
        assert!(!json.contains("revocation_status"), "None revocation should be omitted");
    }

    #[test]
    fn test_cert_info_json_includes_fingerprint() {
        let mut info = make_test_cert(Some("test"), vec![]);
        info.sha256_fingerprint = Some("AA:BB:CC".to_string());
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("sha256_fingerprint"));
        assert!(json.contains("AA:BB:CC"));
    }

    #[test]
    fn test_cert_info_yaml_serialization() {
        let info = make_test_cert(Some("test"), vec!["DNS:test.com"]);
        let yaml = serde_yml::to_string(&info).unwrap();
        assert!(yaml.contains("common_name"), "YAML should contain common_name");
        assert!(yaml.contains("test"), "YAML should contain the CN value");
    }

    // ---------------------------------------------------------------
    // diff_field tests
    // ---------------------------------------------------------------

    #[test]
    fn test_diff_field_same_values() {
        // diff_field prints to stdout; just verify it doesn't panic
        diff_field("Test", "value", "value");
    }

    #[test]
    fn test_diff_field_different_values() {
        diff_field("Test", "old", "new");
    }

    // ---------------------------------------------------------------
    // External file tests
    // ---------------------------------------------------------------

    #[test]
    fn test_valid_cert_from_file() -> Result<()> {
        let path = PathBuf::from("tests/data/valid.pem");
        assert!(path.exists(), "tests/data/valid.pem is missing");
        let pem = std::fs::read_to_string(&path)?;
        let infos = parse_cert_infos_from_pem(&pem, &default_opts())?;
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].common_name.as_deref(), Some("test.example.com"));
        Ok(())
    }

    #[test]
    fn test_chain_from_external_file() -> Result<()> {
        let path = PathBuf::from("tests/data/test.pem");
        assert!(path.exists(), "tests/data/test.pem is missing");
        let pem = std::fs::read_to_string(&path)?;
        let infos = parse_cert_infos_from_pem(&pem, &default_opts())?;
        assert!(infos.len() >= 2, "expected at least 2 certificates in chain");
        Ok(())
    }

    // ---------------------------------------------------------------
    // BasicConstraintsInfo serialization
    // ---------------------------------------------------------------

    #[test]
    fn test_basic_constraints_serialization() {
        let bc = BasicConstraintsInfo {
            ca: true,
            path_len_constraint: Some(1),
        };
        let json = serde_json::to_string(&bc).unwrap();
        assert!(json.contains("\"ca\":true"));
        assert!(json.contains("\"path_len_constraint\":1"));
    }

    #[test]
    fn test_basic_constraints_omits_none_path_len() {
        let bc = BasicConstraintsInfo {
            ca: false,
            path_len_constraint: None,
        };
        let json = serde_json::to_string(&bc).unwrap();
        assert!(!json.contains("path_len_constraint"));
    }
}
