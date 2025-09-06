use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use colored::*;
use pem::parse_many;
use std::fs;
use std::path::PathBuf;
use x509_parser::prelude::*;

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
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    is_expired: bool,
}

fn parse_pem_certificates(pem_data: &str) -> Result<Vec<X509Certificate<'_>>> {
    let mut certs = Vec::new();
    for block in parse_many(pem_data.as_bytes()) {
        if block.tag != "CERTIFICATE" {
            continue;
        }
        let (_, parsed) = X509Certificate::from_der(&block.contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse DER: {e}"))?;
        certs.push(parsed);
    }
    Ok(certs)
}

fn extract_cert_info(cert: &X509Certificate<'_>, index: usize) -> Result<CertInfo> {
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let serial_number = cert.serial().to_bn().to_hex_str().to_string();

    let not_before = DateTime::<Utc>::from(cert.validity().not_before.to_datetime());
    let not_after = DateTime::<Utc>::from(cert.validity().not_after.to_datetime());
    let now = Utc::now();
    let is_expired = not_after < now;

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

    let pem_data = fs::read_to_string(&args.file)
        .with_context(|| format!("Failed to read file: {}", args.file.display()))?;

    let mut certificates =
        parse_pem_certificates(&pem_data).with_context(|| "Failed to parse PEM certificates")?;

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
        let result = parse_pem_certificates("invalid pem data");
        assert!(result.is_err());
    }

    /// Reads certificate data from tests/data/test.pem.
    /// To enable, place a valid PEM certificate file at that path.
    #[test]
    #[ignore]
    fn test_valid_from_external_file() -> Result<()> {
        let path = PathBuf::from("tests/data/test.pem");
        assert!(path.exists(), "tests/data/test.pem is missing");
        let pem = fs::read_to_string(&path)?;
        let certs = parse_pem_certificates(&pem)?;
        assert!(certs.len() > 0, "expected at least one certificate");
        let info = extract_cert_info(&certs[0], 0)?;
        assert!(!info.subject.is_empty());
        assert!(!info.issuer.is_empty());
        assert!(info.serial_number.len() > 0);
        Ok(())
    }
}
