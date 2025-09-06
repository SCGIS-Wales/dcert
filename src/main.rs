use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::*;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::offset_date_time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;

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
    serial_number: String,
    not_before: String, // RFC 3339
    not_after: String,  // RFC 3339
    is_expired: bool,
}

fn parse_pem_certificates(pem_data: &str) -> Result<Vec<X509Certificate<'_>>> {
    let mut certs = Vec::new();

    // Read all CERTIFICATE blocks from the PEM file
    let mut reader = Cursor::new(pem_data.as_bytes());

    // In rustls-pemfile 2.2, `certs` returns an iterator of Result<CertificateDer<'static>, Error>
    let iter = rustls_pemfile::certs(&mut reader);
    for der_res in iter {
        let der = der_res.map_err(|e| anyhow::anyhow!("Failed reading PEM blocks: {e}"))?;
        let (_, parsed) =
            X509Certificate::from_der(der.as_ref()).map_err(|e| anyhow::anyhow!("Failed to parse DER: {e}"))?;
        certs.push(parsed);
    }

    Ok(certs)
}

fn extract_cert_info(cert: &X509Certificate<'_>, index: usize) -> Result<CertInfo> {
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    // Serial as uppercase hex
    let serial_bytes = cert.raw_serial();
    let serial_number = serial_bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>();

    // x509-parser exposes time as time::OffsetDateTime via to_datetime()
    let nb: OffsetDateTime = cert.validity().not_before.to_datetime();
    let na: OffsetDateTime = cert.validity().not_after.to_datetime();
    let now = OffsetDateTime::now_utc();

    let not_before = nb.format(&Rfc3339).unwrap_or_else(|_| nb.to_string());
    let not_after = na.format(&Rfc3339).unwrap_or_else(|_| na.to_string());
    let is_expired = na < now;

    Ok(CertInfo {
        index,
        subject,
        issuer,
        serial_number,
        not_before,
        not_after,
        is_expired,
    })
}

fn print_pretty(infos: &[CertInfo]) {
    for info in infos {
        println!("{}", "Certificate".bold());
        println!("  Index        : {}", info.index);
        println!("  Subject      : {}", info.subject);
        println!("  Issuer       : {}", info.issuer);
        println!("  Serial       : {}", info.serial_number);
        println!("  Not Before   : {}", info.not_before);
        println!("  Not After    : {}", info.not_after);
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

    let mut certificates = parse_pem_certificates(&pem_data).with_context(|| "Failed to parse PEM certificates")?;

    if certificates.is_empty() {
        eprintln!("{}", "No valid certificates found in the file".red());
        return Ok(1);
    }

    let mut infos: Vec<CertInfo> = Vec::new();
    for (idx, cert) in certificates.drain(..).enumerate() {
        let info = extract_cert_info(&cert, idx)?;
        if args.expired_only && !info.is_expired {
            continue;
        }
        infos.push(info);
    }

    if infos.is_empty() {
        println!("{}", "No certificates matched the filter".yellow());
        return Ok(0);
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
        let result = parse_pem_certificates("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_invalid_pem() {
        // Not valid PEM headers
        let result = parse_pem_certificates("invalid pem data");
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
        let certs = parse_pem_certificates(&pem)?;
        assert!(!certs.is_empty(), "expected at least one certificate");
        let info = super::extract_cert_info(&certs[0], 0)?;
        assert!(!info.subject.is_empty());
        assert!(!info.issuer.is_empty());
        assert!(!info.serial_number.is_empty());
        Ok(())
    }
}
