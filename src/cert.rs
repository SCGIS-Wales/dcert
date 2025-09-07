use anyhow::{Context, Result};
use rustls::pki_types::CertificateDer;
use rustls_pemfile as pemfile;
use serde::Serialize;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::time::ASN1Time;

#[derive(Debug, Serialize, Clone)]
pub struct CertInfo {
    pub index: usize,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub is_expired: bool,
    pub common_name: Option<String>,
    pub subject_alternative_names: Vec<String>,
    pub ct_scts_embedded: bool,
    pub is_ca: bool,
}

fn fmt_time(t: ASN1Time) -> String {
    let odt = t.to_datetime();
    odt.format(&Rfc3339).unwrap_or_default()
}

fn ip_to_string(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            Some(IpAddr::from(a).to_string())
        }
        _ => None,
    }
}

fn get_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in ext.value.general_names.iter() {
            match gn {
                GeneralName::DNSName(d) => out.push(d.to_string()),
                GeneralName::IPAddress(ip) => {
                    if let Some(s) = ip_to_string(ip) {
                        out.push(s)
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn get_cn(cert: &X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
}

fn has_embedded_sct(cert: &X509Certificate<'_>) -> bool {
    // OID: 1.3.6.1.4.1.11129.2.4.2 (SCT list)
    let sct_oid = x509_parser::asn1_rs::Oid::from(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2])
        .expect("valid SCT OID");
    cert.extensions().iter().any(|ext| ext.oid == sct_oid)
}

/// Build `CertInfo` from parsed x509 certs (used by HTTPS path).
pub fn infos_from_x509(certs: &[X509Certificate<'_>]) -> Vec<CertInfo> {
    let now = time::OffsetDateTime::now_utc();
    certs
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let subject = c.subject().to_string();
            let issuer = c.issuer().to_string();
            let serial_hex = c
                .raw_serial()
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>();
            let nb = fmt_time(c.validity().not_before);
            let na = fmt_time(c.validity().not_after);
            let is_expired = c.validity().not_after.to_datetime() <= now;
            let cn = get_cn(c);
            let sans = get_sans(c);
            let ct = has_embedded_sct(c);
            let is_ca = c.tbs_certificate.is_ca();

            CertInfo {
                index: i,
                subject,
                issuer,
                serial_number: serial_hex,
                not_before: nb,
                not_after: na,
                is_expired,
                common_name: cn,
                subject_alternative_names: sans,
                ct_scts_embedded: ct,
                is_ca,
            }
        })
        .collect()
}

/// Parse a PEM string into a vector of certificate DERs (compatible with rustls 0.23).
pub fn parse_pem_to_der(pem_data: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut rdr = std::io::Cursor::new(pem_data.as_bytes());
    let ders: Vec<CertificateDer<'static>> = pemfile::certs(&mut rdr)
        .collect::<std::result::Result<_, std::io::Error>>()
        .context("Failed to parse PEM certificates")?;
    Ok(ders)
}

/// Convert a set of certificate DERs into `CertInfo` entries (used by file/PEM mode).
pub fn infos_from_der_certs(ders: &[CertificateDer<'_>]) -> Vec<CertInfo> {
    let now = time::OffsetDateTime::now_utc();
    let mut out = Vec::with_capacity(ders.len());
    for (i, der) in ders.iter().enumerate() {
        if let Ok((_, c)) = X509Certificate::from_der(der.as_ref()) {
            let subject = c.subject().to_string();
            let issuer = c.issuer().to_string();
            let serial_hex = c
                .raw_serial()
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>();
            let nb = fmt_time(c.validity().not_before);
            let na = fmt_time(c.validity().not_after);
            let is_expired = c.validity().not_after.to_datetime() <= now;
            let cn = get_cn(&c);
            let sans = get_sans(&c);
            let ct = has_embedded_sct(&c);
            let is_ca = c.tbs_certificate.is_ca();

            out.push(CertInfo {
                index: i,
                subject,
                issuer,
                serial_number: serial_hex,
                not_before: nb,
                not_after: na,
                is_expired,
                common_name: cn,
                subject_alternative_names: sans,
                ct_scts_embedded: ct,
                is_ca,
            });
        }
    }
    out
}
