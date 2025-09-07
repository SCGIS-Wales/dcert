use anyhow::{Context, Result};
use rustls::pki_types::CertificateDer;
use rustls_pemfile as pemfile;
use serde::Serialize;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

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

fn fmt_time(t: x509_parser::time::ASN1Time) -> String {
    t.to_datetime().format(&Rfc3339).unwrap_or_default()
}

fn get_cn(cert: &X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            // Fallback: search attributes for CN OID
            let oid = x509_parser::oid_registry::OID_X509_COMMON_NAME;
            cert.subject()
                .iter_attributes()
                .find(|attr| *attr.attr_type() == oid)
                .and_then(|attr| attr.as_str().ok().map(|s| s.to_string()))
        })
}

fn get_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut out = Vec::new();
    // x509-parser 0.18 returns Result<Option<_>>
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                GeneralName::DNSName(s) => out.push(s.to_string()),
                GeneralName::IPAddress(ip) => {
                    // ip is &[u8]; render as IPv4/IPv6 if sized, else hex
                    let s = match ip.len() {
                        4 => {
                            let v4 = [ip[0], ip[1], ip[2], ip[3]];
                            IpAddr::from(v4).to_string()
                        }
                        16 => {
                            let mut v6 = [0u8; 16];
                            v6.copy_from_slice(ip);
                            IpAddr::from(v6).to_string()
                        }
                        _ => format!("0x{}", hex::encode(ip)),
                    };
                    out.push(s);
                }
                _ => {}
            }
        }
    }
    out
}

fn has_embedded_sct(cert: &X509Certificate<'_>) -> bool {
    // 1.3.6.1.4.1.11129.2.4.2
    let sct_oid = x509_parser::asn1_rs::Oid::from(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2])
        .expect("constant SCT OID parses");
    cert.extensions().iter().any(|ext| ext.oid == sct_oid)
}

pub fn infos_from_der_certs<'a>(ders: &'a [CertificateDer<'a>]) -> Vec<CertInfo> {
    let now = time::OffsetDateTime::now_utc();
    ders.iter()
        .enumerate()
        .filter_map(|(i, der)| {
            let (_, cert) = X509Certificate::from_der(der.as_ref()).ok()?;
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let serial_hex = cert
                .raw_serial()
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>();
            let nb = fmt_time(cert.validity().not_before);
            let na = fmt_time(cert.validity().not_after);
            let is_expired = cert.validity().not_after.to_datetime() <= now;
            let cn = get_cn(&cert);
            let sans = get_sans(&cert);
            let ct = has_embedded_sct(&cert);
            let is_ca = cert.tbs_certificate.is_ca();
            Some(CertInfo {
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
            })
        })
        .collect()
}

/// Parse a PEM file into DER certs using rustls-pemfile (v2 iterator API).
pub fn parse_pem_to_der(pem_data: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut rdr = std::io::Cursor::new(pem_data.as_bytes());
    let mut ders = Vec::<CertificateDer<'static>>::new();
    for item in pemfile::certs(&mut rdr) {
        let der = item.context("Failed to parse PEM certificate block")?;
        ders.push(der);
    }
    Ok(ders)
}
