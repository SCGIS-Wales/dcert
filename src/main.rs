use anyhow::{Context, Result};
use clap::CommandFactory;
use clap::{Parser, ValueEnum};
use colored::*;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use pem_rfc7468::LineEnding;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
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

static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
const MAX_CONNECTIONS: usize = 10;
const CONNECTION_TIMEOUT_SECS: u64 = 10;
const READ_TIMEOUT_SECS: u64 = 5;

struct ConnectionGuard;
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Fetch TLS certificate chain using OpenSSL, bypassing all validation.
fn fetch_tls_chain_openssl(
    endpoint: &str,
    method: &str,
    headers: &[(String, String)],
    _http_protocol: HttpProtocol,
) -> Result<TlsChainResult> {
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

    // Layer 4: TCP connect with timeout
    let l4_start = std::time::Instant::now();

    // Resolve address first
    let socket_addr = format!("{}:{}", host, port)
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("Failed to resolve host {}: {}", host, e))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No valid address found for host {}", host))?;

    let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .map_err(|e| anyhow::anyhow!("TCP connection failed: {e}"))?;

    // Set read timeout
    stream
        .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))
        .map_err(|e| anyhow::anyhow!("Failed to set read timeout: {e}"))?;

    let l4_latency = l4_start.elapsed().as_millis();

    // Layer 7: TLS handshake + HTTP request
    let l7_start = std::time::Instant::now();
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| anyhow::anyhow!("OpenSSL builder failed: {e}"))?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let mut ssl_stream = connector
        .connect(host, stream)
        .map_err(|e| anyhow::anyhow!("TLS handshake failed: {e}"))?;

    // Build HTTP request
    let path = if url.path().is_empty() { "/" } else { url.path() };

    // Both HTTP/1.1 and HTTP/2 will use HTTP/1.1 format here
    // OpenSSL doesn't handle HTTP/2 ALPN negotiation automatically
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
    let tls_cipher = ssl
        .current_cipher()
        .map(|c| c.name().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Check if server requested a client certificate (mTLS)
    // Note: OpenSSL crate doesn't directly expose this, using false as default
    let mtls_requested = false;

    let offered_ciphers: Vec<String> = Vec::new();
    Ok((
        pem,
        l4_latency,
        l7_latency,
        tls_version,
        tls_cipher,
        offered_ciphers,
        mtls_requested,
        http_response_code,
    ))
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
}

#[derive(ValueEnum, Clone, Debug)]
enum HttpProtocol {
    Http1_1,
    Http2,
}

#[derive(Parser, Debug)]
#[command(name = "dcert")]
#[command(
    about = "Decode and validate TLS certificates from a PEM file or fetch the TLS certificate chain from an HTTPS endpoint.\n\
             If you specify an HTTPS URL, dcert will fetch and decode the server's TLS certificate chain.\n\
             Optionally, you can export the chain as a PEM file."
)]
#[command(version = "0.1.2")]
struct Args {
    /// Path to a PEM file or an HTTPS URL like https://example.com
    target: String,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    format: OutputFormat,

    /// Show only expired certificates
    #[arg(long)]
    expired_only: bool,

    /// Export the fetched PEM chain to a file (only for HTTPS targets)
    #[arg(long)]
    export_pem: Option<String>,

    /// HTTP method to use for HTTPS requests (default: GET)
    #[arg(long, default_value = "GET")]
    method: String,

    /// Custom HTTP headers (key:value), can be repeated
    #[arg(long, value_parser = parse_header, num_args = 0.., value_name = "HEADER")]
    header: Vec<(String, String)>,

    /// HTTP protocol to use (default: http2)
    #[arg(long, value_enum, default_value_t = HttpProtocol::Http1_1)]
    http_protocol: HttpProtocol,
}

#[derive(Debug, serde::Serialize)]
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
}

/// Process a single certificate into CertInfo
fn process_certificate(cert: X509Certificate<'_>, idx: usize, expired_only: bool) -> Result<Option<CertInfo>> {
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

    if expired_only && !is_expired {
        return Ok(None);
    }

    let common_name = extract_common_name(&cert);
    let subject_alternative_names = extract_sans(&cert);

    let ct_present = cert.extensions().iter().any(|ext| ext.oid == *OID_X509_SCT_LIST);

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
    }))
}

/// Parse all PEM certificate blocks from `pem_data` and return owned `CertInfo`
/// for each certificate. We do not store `X509Certificate` to avoid lifetime issues.
fn parse_cert_infos_from_pem(pem_data: &str, expired_only: bool) -> Result<Vec<CertInfo>> {
    let blocks = pem::parse_many(pem_data).map_err(|e| anyhow::anyhow!("Failed to parse PEM: {e}"))?;

    let mut infos = Vec::new();
    let mut errors = Vec::new();

    for (idx, block) in blocks.iter().enumerate() {
        if block.tag != "CERTIFICATE" {
            continue;
        }

        match X509Certificate::from_der(&block.contents) {
            Ok((_, cert)) => {
                match process_certificate(cert, idx, expired_only) {
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

#[allow(clippy::too_many_arguments)]
fn print_pretty(
    infos: &[CertInfo],
    hostname: Option<&str>,
    l4_latency: u128,
    l7_latency: u128,
    tls_version: &str,
    tls_cipher: &str,
    http_protocol: &HttpProtocol,
    http_response_code: u16,
) {
    if let Some(host) = hostname {
        if let Some(leaf) = infos.first() {
            let matched = cert_matches_hostname(leaf, host);
            let status = if matched { "true".green() } else { "false".red() };
            println!();
            println!("{}", "Debug".bold());
            println!(
                "  HTTP protocol: {}",
                match http_protocol {
                    HttpProtocol::Http2 => "HTTP/2",
                    HttpProtocol::Http1_1 => "HTTP/1.1",
                }
            );
            if http_response_code > 0 {
                let code_color = match http_response_code {
                    200..=299 => http_response_code.to_string().green(),
                    300..=399 => http_response_code.to_string().yellow(),
                    400..=499 => http_response_code.to_string().red(),
                    500..=599 => http_response_code.to_string().red().bold(),
                    _ => http_response_code.to_string().normal(),
                };
                println!("  HTTP response code: {}", code_color);
            } else {
                println!("  HTTP response code: not available");
            }
            println!("  Mutual TLS requested: unknown");
            println!("  Hostname matches certificate SANs/CN: {}", status);
            println!("  TLS version used: {}", tls_version);
            println!("  TLS ciphersuite agreed: {}", tls_cipher);
            let ct_str = if leaf.ct_present { "true".green() } else { "false".red() };
            println!("  Certificate transparency: {}", ct_str);
            println!();
            println!("  Network latency (layer 4/TCP connect): {} ms", l4_latency);
            println!("  Network latency (layer 7/TLS+HTTP):    {} ms", l7_latency);
            println!();
            println!(
                "Note: Layer 4 and Layer 7 latencies are measured separately and should not be summed. \
Layer 4 covers TCP connection only; Layer 7 covers TLS handshake and HTTP request. \
DNS resolution and other delays are not included in these timings."
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

type TlsChainResult = (String, u128, u128, String, String, Vec<String>, bool, u16);

fn run() -> Result<i32> {
    let args: Args = Args::parse();

    let (pem_data, l4_latency, l7_latency, tls_version, tls_cipher, _mtls_requested, http_response_code) =
        if args.target.starts_with("https://") {
            let (pem, l4, l7, tls_version, tls_cipher, _, mtls_requested, http_response_code) =
                fetch_tls_chain_openssl(&args.target, &args.method, &args.header, args.http_protocol.clone())
                    .with_context(|| "Failed to fetch TLS chain")?;
            if let Some(export_path) = &args.export_pem {
                fs::write(export_path, &pem).with_context(|| format!("Failed to write PEM to {}", export_path))?;
            }
            (pem, l4, l7, tls_version, tls_cipher, mtls_requested, http_response_code)
        } else {
            (
                fs::read_to_string(&args.target)
                    .with_context(|| format!("Failed to read PEM file: {}", &args.target))?,
                0,
                0,
                String::new(),
                String::new(),
                false,
                0,
            )
        };

    let infos =
        parse_cert_infos_from_pem(&pem_data, args.expired_only).with_context(|| "Failed to parse PEM certificates")?;

    if infos.is_empty() {
        eprintln!("{}", "No valid certificates found in the input".red());
        return Ok(1);
    }

    match args.format {
        OutputFormat::Pretty => {
            let hostname = if args.target.starts_with("https://") {
                Url::parse(&args.target)
                    .ok()
                    .and_then(|u| u.host_str().map(|s| s.to_lowercase()))
            } else {
                None
            };
            print_pretty(
                &infos,
                hostname.as_deref(),
                l4_latency,
                l7_latency,
                &tls_version,
                &tls_cipher,
                &args.http_protocol,
                http_response_code,
            );
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&infos)?);
        }
    }

    // Optionally export the PEM chain to a file
    if let Some(export_path) = args.export_pem {
        fs::write(&export_path, pem_data).with_context(|| format!("Failed to write PEM file: {}", export_path))?;
        println!("PEM chain exported to {}", export_path);
    }

    Ok(0)
}

fn main() {
    // Print help if no arguments (other than program name) are provided
    if std::env::args().len() == 1 {
        Args::command().print_help().unwrap();
        println!();
        std::process::exit(0);
    }

    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("dcert {}", env!("CARGO_PKG_VERSION"));
        println!("Libraries:");
        println!("  openssl {}", openssl::version::version());
        println!("  x509-parser {}", env!("CARGO_PKG_VERSION"));
        println!("  clap {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            std::process::exit(2);
        }
    }
}

fn parse_header(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("Header must be in key:value format".to_string());
    }
    Ok((parts[0].trim().to_string(), parts[1].trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_empty_pem() {
        let result = parse_cert_infos_from_pem("", false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_invalid_pem() {
        // Not valid PEM headers, should yield zero certs not an error
        let result = parse_cert_infos_from_pem("invalid pem data", false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    /// Reads certificate data from tests/data/test.pem.
    /// Add a valid PEM there and run with `cargo test -- --ignored`
    #[test]
    #[ignore]
    fn test_valid_from_external_file() -> Result<()> {
        let path = PathBuf::from("tests/data/test.pem");
        assert!(path.exists(), "tests/data/test.pem is missing");
        let pem = std::fs::read_to_string(&path)?;
        let infos = parse_cert_infos_from_pem(&pem, false)?;
        assert!(!infos.is_empty(), "expected at least one certificate");
        let first = &infos[0];
        assert!(!first.subject.is_empty());
        assert!(!first.issuer.is_empty());
        assert!(!first.serial_number.is_empty());
        Ok(())
    }

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
}
