use anyhow::{Context, Result};
use base64::Engine;
use rustls::pki_types::CertificateDer;
use rustls_pemfile as pemfile;
use serde::Serialize;
use std::io::Cursor;
use std::net::IpAddr;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Serialize, Clone)]
pub struct CertInfo {
    pub index: usize,
    pub subject: String,
    pub issuer: String,
    pub serial: String, // <-- Add this field
    pub not_before: String,
    pub not_after: String,
    pub common_name: Option<String>,
    pub subject_alt_names: Vec<String>,
    pub has_embedded_sct: bool,
    pub is_ca: Option<bool>,
}

/// Convert DER certificates to PEM base64 strings.
#[allow(dead_code)]
pub fn der_chain_to_pem_base64(ders: &[CertificateDer]) -> Vec<String> {
    ders.iter()
        .map(|der| {
            let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                b64.chars()
                    .collect::<Vec<_>>()
                    .chunks(64)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })
        .collect()
}

/// Parse a PEM blob into a vector of DER certificates.
pub fn parse_pem_to_der(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut ders = Vec::new();
    let mut rdr = Cursor::new(pem.as_bytes());
    for item in pemfile::certs(&mut rdr) {
        let der = item.context("Failed to read PEM block as certificate")?;
        ders.push(der);
    }
    Ok(ders)
}

/// Extract a displayable "CN=" value from the subject, if present.
#[allow(dead_code)]
fn get_cn(cert: &X509Certificate<'_>) -> Option<String> {
    let mut it = cert.subject().iter_common_name();
    it.next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
}

/// Extract SANs (DNS/IP) as strings.
#[allow(dead_code)]
fn get_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for gn in san_ext.value.general_names.iter() {
            match gn {
                GeneralName::DNSName(dns) => out.push(dns.to_string()),
                GeneralName::IPAddress(ip_bytes) => {
                    // Try IPv4/IPv6; otherwise hex-encode.
                    let s = match ip_bytes.len() {
                        4 => IpAddr::from([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]])
                            .to_string(),
                        16 => {
                            let mut a = [0u8; 16];
                            a.copy_from_slice(ip_bytes);
                            IpAddr::from(a).to_string()
                        }
                        _ => hex::encode(ip_bytes),
                    };
                    out.push(s);
                }
                _ => {}
            }
        }
    }
    out
}

/// Return true if the SCT list extension (1.3.6.1.4.1.11129.2.4.2) is present.
fn has_embedded_sct(cert: &X509Certificate<'_>) -> bool {
    let sct_oid =
        x509_parser::asn1_rs::Oid::from(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2]).expect("valid OID");
    cert.extensions().iter().any(|ext| ext.oid == sct_oid)
}

/// Minimal time string formatter; x509-parser's time types implement Display.
#[allow(dead_code)]
fn fmt_time<T: ToString>(t: T) -> String {
    t.to_string()
}

/// Interrogate DER certificates for display info.
pub fn infos_from_der_certs(ders: &[CertificateDer]) -> Vec<CertInfo> {
    ders.iter()
        .enumerate()
        .filter_map(|(index, der)| {
            let (_, cert) = X509Certificate::from_der(der.as_ref()).ok()?;
            let serial = cert.serial.to_str_radix(16);
            let common_name = cert
                .subject()
                .iter_common_name()
                .next()
                .map(|cn| cn.as_str().unwrap_or("").to_string());
            let subject_alt_names = cert
                .subject_alternative_name()
                .map(|san_ext| {
                    san_ext
                        .unwrap()
                        .value
                        .general_names
                        .iter()
                        .filter_map(|gn| match gn {
                            GeneralName::DNSName(dns) => Some(dns.to_string()),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            let has_embedded_sct = has_embedded_sct(&cert);
            let is_ca = cert
                .basic_constraints()
                .ok()
                .and_then(|ext| ext.map(|bc| bc.value.ca));
            Some(CertInfo {
                index,
                subject: cert.subject().to_string(),
                issuer: cert.issuer().to_string(),
                serial,
                not_before: cert
                    .validity()
                    .not_before
                    .to_rfc2822()
                    .unwrap_or_else(|e| format!("<invalid: {}>", e)),
                not_after: cert
                    .validity()
                    .not_after
                    .to_rfc2822()
                    .unwrap_or_else(|e| format!("<invalid: {}>", e)),
                common_name,
                subject_alt_names,
                has_embedded_sct,
                is_ca,
            })
        })
        .collect()
}
