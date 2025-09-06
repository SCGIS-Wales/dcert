use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::*;
use oid_registry::OID_COMMON_NAME;
use std::fs;
use std::io::Cursor;
use std::net::IpAddr;
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
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
#[command(about = "Decode and validate TLS certificates from a PEM file")]
#[command(version = "0.1.0")]
struct Args {
    /// Path to the PEM file containing one or more certificates
    file: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    format: OutputFormat,

    /// Show only expired certificates
    #[arg(long)]
    expired_only: bool,
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

fn extract_common_name(cert: &X509Certificate<'_>) -> Option<String> {
    // Scan the subject RDNs for CN
    for attr in cert.subject().iter_attributes() {
        if attr.attr_type() == OID_COMMON_NAME {
            // Convert to UTF8 if possible
            if let Ok(s) = attr.attr_value().as_str() {
                return Some(s.to_string());
            } else {
                // Fallback to the raw printable form
                return Some(attr.attr_value().to_string());
            }
        }
    }
    None
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
                    GeneralName::IPAddress(bytes) => {
                        // Expect 4 or 16 bytes for v4 or v6
                        match bytes.len() {
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
                            _ => {
                                // Unknown length, skip to avoid noisy output
                            }
                        }
                    }
                    // OtherName, DirectoryName, RegisteredID etc are omitted for brevity
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

fn run() -> Result<i32> {
    let args = Args::parse();

    let pem_data =
        fs::read_to_string(&args.file).with_context(|| format!("Failed to read file: {}", args.file.display()))?;

    let infos =
        parse_cert_infos_from_pem(&pem_data, args.expired_only).with_context(|| "Failed to parse PEM certificates")?;

    if infos.is_empty() {
        eprintln!("{}", "No valid certificates found in the file".red());
        return Ok(1);
    }

    match args.format {
        OutputFormat::Pretty => print_pretty(&infos),
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&infos)?);
        }
    }

    Ok(0)
}

fn main() {
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
        // Basic sanity checks
        assert!(!first.subject.is_empty());
        assert!(!first.issuer.is_empty());
        assert!(!first.serial_number.is_empty());
        Ok(())
    }
}
