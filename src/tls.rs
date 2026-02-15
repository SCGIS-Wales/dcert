use anyhow::Result;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use pem_rfc7468::LineEnding;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::cli::{HttpProtocol, TlsVersionArg};
use crate::debug::{dbg_section, debug_log, sanitize_header_value, sanitize_url};
use crate::proxy::{connect_through_proxy, ProxyConfig};

pub static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
pub const MAX_CONNECTIONS: usize = 10;
pub const CONNECTION_TIMEOUT_SECS: u64 = 10;
pub const READ_TIMEOUT_SECS: u64 = 5;

pub struct ConnectionGuard;
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Load CA certificates into the SSL connector builder.
///
/// Uses `openssl-probe` to discover system CA certificate locations, then falls
/// back to OpenSSL's `set_default_verify_paths()`. This ensures dcert works on:
/// - macOS (Homebrew OpenSSL, which lacks Keychain access)
/// - Linux (distro-specific cert paths)
/// - Environments with custom CA bundles (SSL_CERT_FILE / SSL_CERT_DIR)
pub fn load_ca_certs(builder: &mut openssl::ssl::SslConnectorBuilder) -> Result<()> {
    // Use openssl-probe to find system CA certs and set the environment variables
    // that OpenSSL uses. This is critical on macOS where Homebrew OpenSSL's
    // compiled-in paths may not contain any certificates.
    if !openssl_probe::has_ssl_cert_env_vars() {
        let probe = openssl_probe::probe();
        if let Some(ref cert_file) = probe.cert_file {
            std::env::set_var("SSL_CERT_FILE", cert_file);
        }
        if let Some(cert_dir) = probe.cert_dir.first() {
            std::env::set_var("SSL_CERT_DIR", cert_dir);
        }
    }

    builder
        .set_default_verify_paths()
        .map_err(|e| anyhow::anyhow!("Failed to load CA certificates: {}", e))?;

    Ok(())
}

/// Resolve a hostname to a socket address, returning the address and DNS resolution time.
pub fn resolve_host(host: &str, port: u16) -> Result<(SocketAddr, u128)> {
    let dns_start = std::time::Instant::now();
    let addr = format!("{}:{}", host, port)
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for '{}': {}", host, e))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("DNS resolution failed for '{}': no addresses returned", host))?;
    let dns_ms = dns_start.elapsed().as_millis();
    Ok((addr, dns_ms))
}

/// Establish a direct TCP connection with timeout and DNS resolution.
/// Returns the stream, DNS latency in milliseconds, and the resolved socket address.
pub fn direct_tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<(TcpStream, u128, SocketAddr)> {
    let (socket_addr, dns_ms) = resolve_host(host, port)?;

    let stream = TcpStream::connect_timeout(&socket_addr, timeout).map_err(|e| {
        let kind = e.kind();
        match kind {
            std::io::ErrorKind::TimedOut => {
                anyhow::anyhow!(
                    "TCP connection to {}:{} timed out after {}s",
                    host,
                    port,
                    timeout.as_secs()
                )
            }
            std::io::ErrorKind::ConnectionRefused => {
                anyhow::anyhow!("TCP connection refused by {}:{} (port may not be open)", host, port)
            }
            _ => {
                anyhow::anyhow!("TCP connection to {}:{} failed: {}", host, port, e)
            }
        }
    })?;
    Ok((stream, dns_ms, socket_addr))
}

/// Result of a TLS connection, containing the certificate chain and connection metadata.
#[derive(Debug, serde::Serialize, Clone)]
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
    pub http_response_code: u16,
    pub verify_result: Option<String>,
    /// Per-certificate chain validation errors (depth, error, subject).
    pub chain_validation_errors: Vec<String>,
}

/// Fetch TLS certificate chain using OpenSSL, with proxy support, custom CA certificates, and mTLS.
#[allow(clippy::too_many_arguments)]
pub fn fetch_tls_chain_openssl(
    endpoint: &str,
    method: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    http_protocol: HttpProtocol,
    no_verify: bool,
    timeout_secs: u64,
    read_timeout_secs: u64,
    sni_override: Option<&str>,
    proxy_config: &ProxyConfig,
    min_tls: Option<TlsVersionArg>,
    max_tls: Option<TlsVersionArg>,
    cipher_list: Option<&str>,
    cipher_suites: Option<&str>,
    debug: bool,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
    pkcs12_path: Option<&str>,
    cert_password: Option<&str>,
    ca_cert_path: Option<&str>,
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

    debug_log!(debug, "Target URL: {}", endpoint);
    debug_log!(debug, "Host: {}, Port: {}", host, port);
    if let Some(sni) = sni_override {
        debug_log!(debug, "SNI override: {}", sni);
    }

    // Layer 4: TCP connect with timeout (with proxy support)
    let connect_timeout = Duration::from_secs(timeout_secs);
    let l4_start = std::time::Instant::now();

    let (stream, dns_latency) = if proxy_config.should_bypass(host) {
        let (s, dns, addr) = direct_tcp_connect(host, port, connect_timeout)?;
        dbg_section(debug, "Layer 3 (Network)");
        debug_log!(debug, "Resolved {} -> {} ({} ms)", host, addr.ip(), dns);
        (s, dns)
    } else if let Some(proxy_url) = proxy_config.get_proxy_url("https") {
        debug_log!(debug, "Using proxy: {}", sanitize_url(proxy_url));
        // Proxy connections resolve the proxy host, not the target
        let stream = connect_through_proxy(proxy_url, host, port, debug)?;
        dbg_section(debug, "Layer 3 (Network)");
        debug_log!(debug, "DNS resolution handled by proxy");
        (stream, 0)
    } else {
        let (s, dns, addr) = direct_tcp_connect(host, port, connect_timeout)?;
        dbg_section(debug, "Layer 3 (Network)");
        debug_log!(debug, "Resolved {} -> {} ({} ms)", host, addr.ip(), dns);
        (s, dns)
    };

    // Set read timeout
    stream
        .set_read_timeout(Some(Duration::from_secs(read_timeout_secs)))
        .map_err(|e| anyhow::anyhow!("Failed to set read timeout: {e}"))?;

    let l4_latency = l4_start.elapsed().as_millis();

    dbg_section(debug, "Layer 4 (Transport)");
    debug_log!(debug, "TCP connection established ({} ms)", l4_latency);

    // Layer 7: TLS handshake + HTTP request
    let l7_start = std::time::Instant::now();
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| anyhow::anyhow!("OpenSSL builder failed: {e}"))?;

    // Load CA certificates: custom CA bundle or system defaults
    if let Some(ca_path) = ca_cert_path {
        debug_log!(debug, "Using custom CA bundle: {}", ca_path);
        builder
            .set_ca_file(ca_path)
            .map_err(|e| anyhow::anyhow!("Failed to load custom CA certificate '{}': {}", ca_path, e))?;
    } else {
        load_ca_certs(&mut builder)?;
    }

    // Load client certificate for mTLS
    if let Some(cert_path) = client_cert_path {
        debug_log!(debug, "Loading client certificate: {}", cert_path);
        builder
            .set_certificate_file(cert_path, openssl::ssl::SslFiletype::PEM)
            .map_err(|e| anyhow::anyhow!("Failed to load client certificate '{}': {}", cert_path, e))?;

        if let Some(key_path) = client_key_path {
            debug_log!(debug, "Loading client private key: {}", key_path);
            builder
                .set_private_key_file(key_path, openssl::ssl::SslFiletype::PEM)
                .map_err(|e| anyhow::anyhow!("Failed to load client private key '{}': {}", key_path, e))?;
        }

        builder
            .check_private_key()
            .map_err(|e| anyhow::anyhow!("Client certificate and private key do not match: {}", e))?;
        debug_log!(debug, "Client certificate and key verified");
    } else if let Some(p12_path) = pkcs12_path {
        debug_log!(debug, "Loading PKCS12 client identity: {}", p12_path);
        let p12_data =
            std::fs::read(p12_path).map_err(|e| anyhow::anyhow!("Failed to read PKCS12 file '{}': {}", p12_path, e))?;
        let password = cert_password.unwrap_or("");
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(&p12_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse PKCS12 file '{}': {}", p12_path, e))?;
        let parsed = pkcs12
            .parse2(password)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt PKCS12 '{}' (wrong password?): {}", p12_path, e))?;

        if let Some(ref cert) = parsed.cert {
            builder
                .set_certificate(cert)
                .map_err(|e| anyhow::anyhow!("Failed to set PKCS12 certificate: {}", e))?;
        }
        if let Some(ref pkey) = parsed.pkey {
            builder
                .set_private_key(pkey)
                .map_err(|e| anyhow::anyhow!("Failed to set PKCS12 private key: {}", e))?;
        }
        if let Some(ref ca_chain) = parsed.ca {
            for ca_cert in ca_chain {
                builder
                    .add_extra_chain_cert(ca_cert.to_owned())
                    .map_err(|e| anyhow::anyhow!("Failed to add PKCS12 CA cert to chain: {}", e))?;
            }
        }
        builder
            .check_private_key()
            .map_err(|e| anyhow::anyhow!("PKCS12 certificate and private key do not match: {}", e))?;
        debug_log!(debug, "PKCS12 client identity loaded and verified");
    }

    // Apply TLS version constraints
    if let Some(min) = min_tls {
        builder
            .set_min_proto_version(Some(min.to_ssl_version()))
            .map_err(|e| anyhow::anyhow!("Failed to set minimum TLS version to {}: {}", min, e))?;
    }
    if let Some(max) = max_tls {
        builder
            .set_max_proto_version(Some(max.to_ssl_version()))
            .map_err(|e| anyhow::anyhow!("Failed to set maximum TLS version to {}: {}", max, e))?;
    }

    // Apply cipher suite configuration
    if let Some(ciphers) = cipher_list {
        builder
            .set_cipher_list(ciphers)
            .map_err(|e| anyhow::anyhow!("Invalid cipher list '{}': {}", ciphers, e))?;
    }
    if let Some(suites) = cipher_suites {
        builder
            .set_ciphersuites(suites)
            .map_err(|e| anyhow::anyhow!("Invalid TLS 1.3 cipher suites '{}': {}", suites, e))?;
    }

    // Set ALPN protocols for HTTP/2 or HTTP/1.1 negotiation
    match http_protocol {
        HttpProtocol::Http2 => {
            // Prefer h2 but fall back to http/1.1
            builder
                .set_alpn_protos(b"\x02h2\x08http/1.1")
                .map_err(|e| anyhow::anyhow!("Failed to set ALPN protocols: {}", e))?;
        }
        HttpProtocol::Http1_1 => {
            builder
                .set_alpn_protos(b"\x08http/1.1")
                .map_err(|e| anyhow::anyhow!("Failed to set ALPN protocols: {}", e))?;
        }
    }

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

    // Debug: Layer 5/6 - TLS session details
    if debug {
        dbg_section(true, "Layer 5/6 (Session/Presentation - TLS)");
        let ssl_ref = ssl_stream.ssl();
        debug_log!(true, "TLS version: {}", ssl_ref.version_str());
        if let Some(cipher) = ssl_ref.current_cipher() {
            debug_log!(true, "Cipher (OpenSSL): {}", cipher.name());
            if let Some(std_name) = cipher.standard_name() {
                debug_log!(true, "Cipher (IANA): {}", std_name);
            }
        }
        if let Some(proto) = ssl_ref.selected_alpn_protocol() {
            if let Ok(proto_str) = std::str::from_utf8(proto) {
                debug_log!(true, "ALPN negotiated: {}", proto_str);
            }
        }
        debug_log!(true, "SNI sent: {}", sni_host);
        if no_verify {
            debug_log!(true, "Certificate verification: DISABLED (--no-verify)");
        }
        if let Some(chain) = ssl_ref.peer_cert_chain() {
            debug_log!(true, "Certificate chain depth: {}", chain.len());
        }
    }

    // Build HTTP request
    let path = if url.path().is_empty() { "/" } else { url.path() };

    // Always send HTTP/1.1 on the wire — we use ALPN to signal HTTP/2 preference
    // to the server, but the actual framing is HTTP/1.1 (full HTTP/2 binary
    // framing would require a dedicated library like h2 or hyper).
    let req = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);

    let mut req = req;
    for (key, value) in headers {
        // Reject headers containing CR/LF to prevent header injection
        if key.contains('\r') || key.contains('\n') || value.contains('\r') || value.contains('\n') {
            return Err(anyhow::anyhow!(
                "HTTP header contains invalid characters (CR/LF): {}:{}",
                key,
                value
            ));
        }
        req.push_str(&format!("{}: {}\r\n", key, value));
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

    // Debug: Layer 7 - HTTP request details
    if debug {
        dbg_section(true, "Layer 7 (Application - HTTP)");
        debug_log!(true, "> {} {} HTTP/1.1", method, path);
        debug_log!(true, "> Host: {}", host);
        for (key, value) in headers {
            debug_log!(true, "> {}: {}", key, sanitize_header_value(key, value));
        }
        if let Some(body_bytes) = body {
            debug_log!(true, "> Content-Length: {}", body_bytes.len());
            let has_content_type = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
            if !has_content_type {
                debug_log!(true, "> Content-Type: application/x-www-form-urlencoded");
            }
        }
        debug_log!(true, "> Connection: close");
    }

    // Send HTTP headers
    ssl_stream
        .write_all(req.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to send HTTP request: {e}"))?;

    // Send body after headers if present
    if let Some(body_bytes) = body {
        ssl_stream
            .write_all(body_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to send request body: {e}"))?;
    }

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

    debug_log!(debug, "< HTTP response: {}", http_response_code);
    debug_log!(debug, "Layer 7 complete ({} ms)", l7_latency);

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

    // Get ALPN negotiated protocol
    let negotiated_protocol = ssl
        .selected_alpn_protocol()
        .and_then(|p| std::str::from_utf8(p).ok())
        .map(|s| s.to_string());

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

    Ok(TlsConnectionInfo {
        pem_data: pem,
        dns_latency,
        l4_latency,
        l7_latency,
        tls_version,
        tls_cipher,
        tls_cipher_iana,
        negotiated_protocol,
        http_response_code,
        verify_result,
        chain_validation_errors,
    })
}
