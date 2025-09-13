use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use clap::CommandFactory; // filepath: /Users/ssddgreg/dcert/src/main.rs
use colored::*;
use pem_rfc7468::{encode_string as encode_pem, LineEnding};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_native_certs as native_certs;
use std::fs;
use std::io::Cursor;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
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
}

/// Parse all PEM certificate blocks from `pem_data` and return owned `CertInfo`
/// for each certificate. We do not store `X509Certificate` to avoid lifetime issues.
fn parse_cert_infos_from_pem(pem_data: &str, expired_only: bool) -> Result<Vec<CertInfo>> {
    let mut reader = Cursor::new(pem_data.as_bytes());
    let mut infos = Vec::new();

    // rustls-pemfile 2.x returns an iterator of Result<CertificateDer<'static>, Error>
    let iter = rustls_pemfile::certs(&mut reader);
    for (idx, der_res) in iter.enumerate() {
        let der = der_res.map_err(|e| anyhow::anyhow!("Failed reading PEM blocks: {e}"))?;
        let (_, cert) =
            X509Certificate::from_der(der.as_ref()).map_err(|e| anyhow::anyhow!("Failed to parse DER: {e}"))?;

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
        });
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

fn print_pretty(infos: &[CertInfo]) {
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

/// Fetch the peer TLS certificate chain from an HTTPS endpoint and return it as a single PEM string.
fn fetch_tls_chain_as_pem(endpoint: &str) -> Result<String> {
    let url = Url::parse(endpoint).map_err(|e| anyhow::anyhow!("Invalid URL: {e}"))?;
    if url.scheme() != "https" {
        return Err(anyhow::anyhow!("Only HTTPS scheme is supported"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must include a host"))?
        .to_owned();
    let port = url.port().unwrap_or(443);

    // Leak a clone for the TLS API, keep the original for other uses
    let host_static: &'static str = Box::leak(host.clone().into_boxed_str());
    let server_name = ServerName::try_from(host_static).map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?;

    let addr = format!("{}:{}", host, port);
    // Connect TCP with a sensible timeout
    let tcp = TcpStream::connect(addr).map_err(|e| anyhow::anyhow!("TCP connect failed: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(10))).ok();

    // Build rustls client with native roots
    let mut roots = RootCertStore::empty();
    let native = native_certs::load_native_certs();
    if !native.errors.is_empty() {
        return Err(anyhow::anyhow!("loading native certs failed: {:?}", native.errors));
    }
    for cert in native.certs {
        roots.add(cert).ok();
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| anyhow::anyhow!("TLS client setup failed: {e}"))?;
    let mut tls = StreamOwned::new(conn, tcp);

    // Perform handshake by doing a minimal HTTP request, which also ensures server sends the chain
    // We do not care about the response, only the handshake completion.
    // Write a HEAD request which is cheap.
    write!(
        tls,
        "HEAD {} HTTP/1.1
Host: {}
Connection: close

",
        url.path(),
        host
    )
    .map_err(|e| anyhow::anyhow!("TLS write failed: {e}"))?;
    let mut sink = Vec::new();
    let _ = tls.read_to_end(&mut sink); // ignore errors

    let conn_ref = tls.conn;
    let certs: Vec<CertificateDer<'static>> = conn_ref
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("No peer certificates presented"))?
        .to_vec();

    if certs.is_empty() {
        return Err(anyhow::anyhow!("Empty certificate chain"));
    }

    // Convert DER to concatenated PEM
    let mut pem = String::new();
    for der in certs {
        let one = encode_pem("CERTIFICATE", LineEnding::LF, der.as_ref())
            .map_err(|e| anyhow::anyhow!("PEM encoding failed: {e}"))?;
        pem.push_str(&one);
        if !pem.ends_with('\n') {
            pem.push('\n');
        }
    }
    Ok(pem)
}

fn run() -> Result<i32> {
    let args: Args = Args::parse();

    let pem_data = if args.target.starts_with("https://") {
        let pem = fetch_tls_chain_as_pem(&args.target).with_context(|| "Failed to fetch TLS chain")?;
        if let Some(export_path) = &args.export_pem {
            fs::write(export_path, &pem).with_context(|| format!("Failed to write PEM to {}", export_path))?;
        } else if args.export_pem.is_some() {
            // If --export-pem is present but empty, use default name
            let domain = args.target.trim_start_matches("https://").replace(['/', ':', '.'], "");
            let default_name = format!("{}-pem.txt", domain);
            fs::write(&default_name, &pem).with_context(|| format!("Failed to write PEM to {}", default_name))?;
        }
        pem
    } else {
        fs::read_to_string(&args.target).with_context(|| format!("Failed to read file: {}", args.target))?
    };

    let infos =
        parse_cert_infos_from_pem(&pem_data, args.expired_only).with_context(|| "Failed to parse PEM certificates")?;

    if infos.is_empty() {
        eprintln!("{}", "No valid certificates found in the input".red());
        return Ok(1);
    }

    match args.format {
        OutputFormat::Pretty => print_pretty(&infos),
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
        println!("  rustls {}", env!("CARGO_PKG_VERSION"));
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
