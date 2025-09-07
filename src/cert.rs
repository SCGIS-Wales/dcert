use anyhow::{Context, Result};
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
    pub not_before: String,
    pub not_after: String,
    pub common_name: Option<String>,
    pub subject_alt_names: Vec<String>,
    pub has_embedded_sct: bool,
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
fn get_cn(cert: &X509Certificate<'_>) -> Option<String> {
    let mut it = cert.subject().iter_common_name();
    it.next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
}

/// Extract SANs (DNS/IP) as strings.
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
fn fmt_time<T: ToString>(t: T) -> String {
    t.to_string()
}

/// Convert parsed DER certs to high-level infos.
pub fn infos_from_der_certs(ders: &[CertificateDer<'_>]) -> Vec<CertInfo> {
    let mut out = Vec::new();
    for (idx, der) in ders.iter().enumerate() {
        if let Ok((_, cert)) = X509Certificate::from_der(der.as_ref()) {
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let nb = fmt_time(cert.validity().not_before);
            let na = fmt_time(cert.validity().not_after);
            let cn = get_cn(&cert);
            let sans = get_sans(&cert);
            let ct = has_embedded_sct(&cert);

            out.push(CertInfo {
                index: idx,
                subject,
                issuer,
                not_before: nb,
                not_after: na,
                common_name: cn,
                subject_alt_names: sans,
                has_embedded_sct: ct,
            });
        }
    }
    out
}
