use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use colored::*;
use std::fs;
use std::path::PathBuf;
use x509_parser::prelude::*;

#[derive(Parser)]
#[command(name = "tls-cert-validator")]
#[command(about = "A CLI tool to validate TLS certificates from PEM files")]
#[command(version = "0.1.0")]
struct Args {
    /// Path to the PEM file containing one or more certificates
    #[arg(short, long, value_name = "FILE")]
    file: PathBuf,
    
    /// Output format (default: pretty)
    #[arg(short, long, value_enum, default_value = "pretty")]
    format: OutputFormat,
    
    /// Show only expired certificates
    #[arg(long)]
    expired_only: bool,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
    Csv,
}

#[derive(Debug)]
struct CertInfo {
    common_name: Option<String>,
    sans: Vec<String>,
    serial_number: String,
    issuer: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    is_expired: bool,
    is_ca: bool,
    key_usage: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    let pem_data = fs::read_to_string(&args.file)
        .with_context(|| format!("Failed to read file: {}", args.file.display()))?;
    
    let certificates = parse_pem_certificates(&pem_data)
        .with_context(|| "Failed to parse PEM certificates")?;
    
    if certificates.is_empty() {
        eprintln!("{}", "No valid certificates found in the file".red());
        std::process::exit(1);
    }
    
    let cert_infos: Vec<CertInfo> = certificates
        .into_iter()
        .enumerate()
        .filter_map(|(index, cert)| {
            match extract_cert_info(&cert) {
                Ok(info) => {
                    if args.expired_only && !info.is_expired {
                        None
                    } else {
                        Some(info)
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to parse certificate {}: {}", index + 1, e);
                    None
                }
            }
        })
        .collect();
    
    if cert_infos.is_empty() {
        if args.expired_only {
            println!("{}", "No expired certificates found".green());
        } else {
            eprintln!("{}", "No valid certificates could be parsed".red());
            std::process::exit(1);
        }
        return Ok(());
    }
    
    match args.format {
        OutputFormat::Pretty => print_pretty(&cert_infos)?,
        OutputFormat::Json => print_json(&cert_infos)?,
        OutputFormat::Csv => print_csv(&cert_infos)?,
    }
    
    Ok(())
}

fn parse_pem_certificates(pem_data: &str) -> Result<Vec<X509Certificate>> {
    let pem_objects = pem::parse_many(pem_data)
        .with_context(|| "Failed to parse PEM data")?;
    
    let mut certificates = Vec::new();
    
    for (index, pem_obj) in pem_objects.iter().enumerate() {
        if pem_obj.tag == "CERTIFICATE" {
            match X509Certificate::from_der(&pem_obj.contents) {
                Ok((_, cert)) => certificates.push(cert),
                Err(e) => eprintln!("Warning: Failed to parse certificate {}: {}", index + 1, e),
            }
        }
    }
    
    Ok(certificates)
}

fn extract_cert_info(cert: &X509Certificate) -> Result<CertInfo> {
    let now = Utc::now();
    let not_before = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
        .unwrap_or(now);
    let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .unwrap_or(now);
    
    let is_expired = now > not_after || now < not_before;
    
    // Extract Common Name
    let common_name = cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());
    
    // Extract Subject Alternative Names with improved parsing
    let mut sans = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    sans.push(format!("DNS:{}", dns));
                },
                GeneralName::IPAddress(ip) => {
                    let ip_str = match ip.len() {
                        4 => {
                            // IPv4 address
                            format!("IP:{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                        },
                        16 => {
                            // IPv6 address - format as standard hex notation
                            let addr = format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                                ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
                            
                            // Compress consecutive zeros for readability (basic compression)
                            let compressed = addr.replace(":0000:", "::");
                            format!("IP:{}", compressed)
                        },
                        _ => {
                            // Unknown IP format, display as hex
                            let hex_ip = ip.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");
                            format!("IP:{}", hex_ip)
                        }
                    };
                    sans.push(ip_str);
                },
                GeneralName::RFC822Name(email) => {
                    sans.push(format!("EMAIL:{}", email));
                },
                GeneralName::URI(uri) => {
                    sans.push(format!("URI:{}", uri));
                },
                GeneralName::DirectoryName(dn) => {
                    sans.push(format!("DN:{}", dn.to_string()));
                },
                GeneralName::RegisteredID(oid) => {
                    sans.push(format!("OID:{}", oid.to_id_string()));
                },
                GeneralName::OtherName(other) => {
                    sans.push(format!("OTHER:{}", other.type_id.to_id_string()));
                },
            }
        }
    }
    
    // Extract serial number
    let serial_number = cert.serial.to_str_radix(16).to_uppercase();
    
    // Extract issuer
    let issuer = cert.issuer().to_string();
    
    // Check if it's a CA certificate
    let is_ca = cert.basic_constraints()
        .map(|bc| bc.map(|ext| ext.ca).unwrap_or(false))
        .unwrap_or(false);
    
    // Extract key usage
    let mut key_usage = Vec::new();
    if let Ok(Some(ku_ext)) = cert.key_usage() {
        let ku = ku_ext.flags;
        if ku.digital_signature() { key_usage.push("Digital Signature".to_string()); }
        if ku.content_commitment() { key_usage.push("Content Commitment".to_string()); }
        if ku.key_encipherment() { key_usage.push("Key Encipherment".to_string()); }
        if ku.data_encipherment() { key_usage.push("Data Encipherment".to_string()); }
        if ku.key_agreement() { key_usage.push("Key Agreement".to_string()); }
        if ku.key_cert_sign() { key_usage.push("Key Cert Sign".to_string()); }
        if ku.crl_sign() { key_usage.push("CRL Sign".to_string()); }
        if ku.encipher_only() { key_usage.push("Encipher Only".to_string()); }
        if ku.decipher_only() { key_usage.push("Decipher Only".to_string()); }
    }
    
    Ok(CertInfo {
        common_name,
        sans,
        serial_number,
        issuer,
        not_before,
        not_after,
        is_expired,
        is_ca,
        key_usage,
    })
}

fn print_pretty(cert_infos: &[CertInfo]) -> Result<()> {
    for (index, cert) in cert_infos.iter().enumerate() {
        println!("{}Certificate #{}{}", "=== ".blue(), (index + 1).to_string().blue(), " ===".blue());
        
        // Status
        let status = if cert.is_expired {
            "EXPIRED".red()
        } else {
            "VALID".green()
        };
        println!("Status: {}", status);
        
        // Common Name
        match &cert.common_name {
            Some(cn) => println!("Common Name: {}", cn.cyan()),
            None => println!("Common Name: {}", "Not specified".yellow()),
        }
        
        // Subject Alternative Names
        if !cert.sans.is_empty() {
            println!("Subject Alternative Names:");
            for san in &cert.sans {
                println!("  - {}", san);
            }
        } else {
            println!("Subject Alternative Names: {}", "None".yellow());
        }
        
        // Certificate details
        println!("Serial Number: {}", cert.serial_number.bright_white());
        println!("Issuer: {}", cert.issuer.bright_white());
        
        // Validity period
        let not_before_str = cert.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let not_after_str = cert.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        
        println!("Valid From: {}", not_before_str.green());
        println!("Valid Until: {}", if cert.is_expired { 
            not_after_str.red() 
        } else { 
            not_after_str.green() 
        });
        
        // Days until expiry
        let days_until_expiry = (cert.not_after - Utc::now()).num_days();
        if days_until_expiry < 0 {
            println!("Expired: {} days ago", (-days_until_expiry).to_string().red());
        } else if days_until_expiry < 30 {
            println!("Expires in: {} days", days_until_expiry.to_string().yellow());
        } else {
            println!("Expires in: {} days", days_until_expiry.to_string().green());
        }
        
        // Certificate type
        println!("Certificate Type: {}", if cert.is_ca { "CA Certificate".bright_magenta() } else { "End Entity Certificate".bright_cyan() });
        
        // Key usage
        if !cert.key_usage.is_empty() {
            println!("Key Usage: {}", cert.key_usage.join(", "));
        }
        
        println!(); // Empty line between certificates
    }
    Ok(())
}

fn print_json(cert_infos: &[CertInfo]) -> Result<()> {
    let json_output = serde_json::json!({
        "certificates": cert_infos.iter().map(|cert| {
            serde_json::json!({
                "common_name": cert.common_name,
                "subject_alternative_names": cert.sans,
                "serial_number": cert.serial_number,
                "issuer": cert.issuer,
                "not_before": cert.not_before.to_rfc3339(),
                "not_after": cert.not_after.to_rfc3339(),
                "is_expired": cert.is_expired,
                "is_ca": cert.is_ca,
                "key_usage": cert.key_usage,
                "days_until_expiry": (cert.not_after - Utc::now()).num_days()
            })
        }).collect::<Vec<_>>()
    });
    
    println!("{}", serde_json::to_string_pretty(&json_output)?);
    Ok(())
}

fn print_csv(cert_infos: &[CertInfo]) -> Result<()> {
    println!("common_name,sans,serial_number,issuer,not_before,not_after,is_expired,is_ca,key_usage,days_until_expiry");
    
    for cert in cert_infos {
        let cn = cert.common_name.as_deref().unwrap_or("");
        let sans = cert.sans.join(";");
        let key_usage = cert.key_usage.join(";");
        let days_until_expiry = (cert.not_after - Utc::now()).num_days();
        
        println!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},{},\"{}\",{}",
            cn,
            sans,
            cert.serial_number,
            cert.issuer,
            cert.not_before.to_rfc3339(),
            cert.not_after.to_rfc3339(),
            cert.is_expired,
            cert.is_ca,
            key_usage,
            days_until_expiry
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;
    
    const TEST_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAL3qgn0W6jQxMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjAwMTAxMTIwMDAwWhcNMzAwMTAxMTIwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA0f+bBhJ/9K9/W9E5q1OL1zI8fT9YR2R6x8vQK3rY3QN2x9Jl7JL1o7AJ
kS3s8c7+8JfZ9gAn0fJM4+4PnV5Qx2X7GZWJrZ7rK1M1Q2F6oP2W2M4M8NbZ3b0m
Z5g6vL7VQ3mL4d5wHmN+5k9XQKYgF0dJdN9I0qzB7yU1JtF0P9wH8A6B2k7QV5cO
BnSr8iZ8tQ5e1fgBmYk9Q0mZ3W4Rn8K9I5rZ8p4P6Y9J4cN4B7S1K8U7M9Ox9V7F
QW3f5E9t0s3V7MKqJX2nG8N0yF1Q0VlJ6MZ4vX2eJ1l0x0dZ2gG7Y6bC8qZ2L5l1
P6F2a0y1qZ5R0a1M6x7N7Z8F0X1sVwIDAQABo1AwTjAdBgNVHQ4EFgQUhGL9+5qx
SjZS9F6qoUkQQ0FO3VYwHwYDVR0jBBgwFoAUhGL9+5qxSjZS9F6qoUkQQ0FO3VYw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAJcDzZ8WFNfYBwGh9XKRR
3w2Bs8e4Nb0ZKWj1vgBt2T2x0yF3Qz0T6K8Y2jQ2W4q5pK7Vh8z0P9s3n7G7b6K2
9F8y4X1l0l3E1f8Q0s0vZ5qF8S7Q3vR0rU6p1M9K8q9nV6q3s3P4K1l9v1w7mX4r
2Y0q2sT5p9Q3t5K1n1c1q5t9q0s7Z4Y2F1n6L7R5X9T0f3d2p9K4a8G9S3V1H0E7
b5W9L7p2F3t0Y9P1R7g5s3k1t4q1N4Z2E8X5M3V2C7B9O0a9q8Q7m1T6A9L0k7e
1N7W9E5S2Z7M4r9K3z1P7t8c9N0q1m9R3B6N8Y0f4Q7d9S9T1e1Y2Z0G9M3T6c
-----END CERTIFICATE-----"#;
    
    #[test]
    fn test_parse_pem_certificates() {
        let certs = parse_pem_certificates(TEST_PEM).unwrap();
        assert_eq!(certs.len(), 1);
    }
    
    #[test]
    fn test_extract_cert_info() {
        let certs = parse_pem_certificates(TEST_PEM).unwrap();
        let cert_info = extract_cert_info(&certs[0]).unwrap();
        
        assert!(cert_info.serial_number.len() > 0);
        assert!(cert_info.issuer.len() > 0);
    }
    
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
}