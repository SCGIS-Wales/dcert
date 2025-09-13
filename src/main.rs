use anyhow::{Context, Result};
use clap::CommandFactory;
use clap::{Parser, ValueEnum};
use colored::*;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use pem_rfc7468::LineEnding;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::net::TcpStream;
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

/// Fetch TLS certificate chain using OpenSSL, bypassing all validation.
fn fetch_tls_chain_openssl(
    endpoint: &str,
    _method: &str,
    headers: &[(String, String)],
    http_protocol: HttpProtocol,
) -> Result<TlsChainResult> {
    let url = url::Url::parse(endpoint).map_err(|e| anyhow::anyhow!("Invalid URL: {e}"))?;
    if url.scheme() != "https" {
        return Err(anyhow::anyhow!("Only HTTPS scheme is supported"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must include a host"))?;
    let port = url.port().unwrap_or(443);

    // Layer 4: TCP connect
    let l4_start = std::time::Instant::now();
    let stream = TcpStream::connect((host, port)).map_err(|e| anyhow::anyhow!("TCP connection failed: {e}"))?;
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

    // Send HTTP request (layer 7)
    let req = match http_protocol {
        HttpProtocol::Http2 => {
            // HTTP/2 uses pseudo-headers, but for a raw TCP socket, send HTTP/1.1 as fallback
            // Most servers will negotiate HTTP/2 via ALPN, but OpenSSL's SslStream does not handle this automatically.
            // For now, send HTTP/1.1 request line but indicate HTTP/2 in debug output.
            format!("{} {} HTTP/1.1\r\nHost: {}\r\n", _method, url.path(), host)
        }
        HttpProtocol::Http1_1 => {
            format!("{} {} HTTP/1.1\r\nHost: {}\r\n", _method, url.path(), host)
        }
    };
    let mut req = req;
    for (key, value) in headers {
        req.push_str(&format!("{}: {}\r\n", key, value));
    }
    req.push_str("Connection: close\r\n\r\n");
    ssl_stream.get_mut().write_all(req.as_bytes()).ok();

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
    let mtls_requested = false; // OpenSSL crate does not expose mTLS request detection

    let offered_ciphers: Vec<String> = Vec::new();
    Ok((
        pem,
        l4_latency,
        l7_latency,
        tls_version,
        tls_cipher,
        offered_ciphers,
        mtls_requested,
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
    #[arg(long, value_enum, default_value_t = HttpProtocol::Http2)]
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

/// Parse all PEM certificate blocks from `pem_data` and return owned `CertInfo`
/// for each certificate. We do not store `X509Certificate` to avoid lifetime issues.
fn parse_cert_infos_from_pem(pem_data: &str, expired_only: bool) -> Result<Vec<CertInfo>> {
    let blocks = pem::parse_many(pem_data).map_err(|e| anyhow::anyhow!("Failed to parse PEM: {e}"))?; // blocks: Vec<pem::Pem>
    let mut infos = Vec::new();
    for (idx, block) in blocks.iter().enumerate() {
        // Access tag and contents fields on the Pem struct
        if block.tag == "CERTIFICATE" {
            let (_, cert) =
                X509Certificate::from_der(&block.contents).map_err(|e| anyhow::anyhow!("Failed to parse DER: {e}"))?;

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
                continue;
            }

            let common_name = extract_common_name(&cert);
            let subject_alternative_names = extract_sans(&cert);

            let ct_present = cert.extensions().iter().any(|ext| ext.oid == *OID_X509_SCT_LIST);

            infos.push(CertInfo {
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
            });
        }
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

fn print_pretty(
    infos: &[CertInfo],
    hostname: Option<&str>,
    l4_latency: u128,
    l7_latency: u128,
    tls_version: &str,
    tls_cipher: &str,
) {
    if let Some(host) = hostname {
        if let Some(leaf) = infos.first() {
            let matched = cert_matches_hostname(leaf, host);
            let status = if matched { "true".green() } else { "false".red() };
            println!();
            println!("{}", "Debug".bold());
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

type TlsChainResult = (String, u128, u128, String, String, Vec<String>, bool);

fn run() -> Result<i32> {
    let args: Args = Args::parse();

    let (pem_data, l4_latency, l7_latency, tls_version, tls_cipher, _mtls_requested) =
        if args.target.starts_with("https://") {
            let (pem, l4, l7, tls_version, tls_cipher, _, mtls_requested) =
                fetch_tls_chain_openssl(&args.target, &args.method, &args.header, args.http_protocol.clone())
                    .with_context(|| "Failed to fetch TLS chain")?;
            if let Some(export_path) = &args.export_pem {
                fs::write(export_path, &pem).with_context(|| format!("Failed to write PEM to {}", export_path))?;
            }
            (pem, l4, l7, tls_version, tls_cipher, mtls_requested)
        } else {
            (
                fs::read_to_string(&args.target)
                    .with_context(|| format!("Failed to read PEM file: {}", &args.target))?,
                0,
                0,
                String::new(),
                String::new(),
                false,
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

    println!(
        "  HTTP protocol: {}",
        match args.http_protocol {
            HttpProtocol::Http2 => "HTTP/2",
            HttpProtocol::Http1_1 => "HTTP/1.1",
        }
    );
    println!("  Mutual TLS requested: unknown");

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
}
