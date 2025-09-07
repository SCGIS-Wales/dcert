use anyhow::{Context, Result};
use rustls::pki_types::CertificateDer;
use rustls_pemfile as pemfile;
use serde::Serialize;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_X509_COMMON_NAME;
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
    let odt = t.to_datetime();
    odt.format(&Rfc3339).unwrap_or_default()
}

fn get_cn(cert: &X509Certificate<'_>) -> Option<String> {
    // Robust CN extraction: walk attributes and match the CN OID.
    cert.subject()
        .iter_attributes()
        .find(|attr| *attr.attr_type() == OID_X509_COMMON_NAME)
        .and_then(|attr| attr.as_str().ok().map(ToString::to_string))
}

fn get_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for gn in san_ext.value.general_names.iter() {
            match gn {
                GeneralName::DNSName(dns) => out.push(dns.to_string()),
                GeneralName::IPAddress(ip_bytes) => {
                    // Try to render IPv4/IPv6; otherwise hex-encode.
                    let s = match ip_bytes.len() {
                        4 => IpAddr::from([
                            ip_bytes[0],
                            ip_bytes[1],
                            ip_bytes[2],
                            ip_bytes[3],
                        ])
                        .to_string(),
                        16 => {
                            let mut a = [0u8; 16];
                            a.copy_from_slice(ip_bytes);
                            IpAddr::from(a).to_string()
                        }
                        _ => hex::encode_upper(ip_bytes),
                    };
                    out.push(s);
                }
                GeneralName::URI(uri) => out.push(uri.to_string()),
                GeneralName::RFC822Name(email) => out.push(email.to_string()),
                _ => {}
            }
        }
    }
    out
}

fn has_embedded_sct(cert: &X509Certificate<'_>) -> bool {
    // 1.3.6.1.4.1.11129.2.4.2 (embedded SCT extension)
    if let Ok(oid) = x509_parser::asn1_rs::Oid::from(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2]) {
        cert.extensions().iter().any(|ext| ext.oid == oid)
    } else {
        false
    }
}

/// Parse a PEM string into DER certificate blobs.
pub fn parse_pem_to_der(pem_data: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut rdr = std::io::Cursor::new(pem_data.as_bytes());
    let mut ders = Vec::<CertificateDer<'static>>::new();

    for item in pemfile::certs(&mut rdr) {
        match item {
            Ok(der) => ders.push(der),
            Err(e) => {
                // Keep scanning; but surface an error if we end with nothing.
                if ders.is_empty() {
                    return Err(anyhow::anyhow!(e)).context("Failed to parse PEM certificates");
                }
            }
        }
    }

    if ders.is_empty() {
        Err(anyhow::anyhow!("No certificates found in PEM input"))
            .context("Failed to parse PEM certificates")
    } else {
        Ok(ders)
    }
}

/// Build `CertInfo` list from parsed DERs.
pub fn infos_from_der_certs(ders: &[CertificateDer<'static>]) -> Vec<CertInfo> {
    let now = time::OffsetDateTime::now_utc();
    ders.iter()
        .enumerate()
        .filter_map(|(i, der)| {
            let bytes: &[u8] = der.as_ref();
            let Ok((_, cert)) = X509Certificate::from_der(bytes) else {
                return None;
            };

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

/// Build `CertInfo` list directly from parsed x509 structures (used for HTTPS probe).
pub fn infos_from_x509(certs: &[X509Certificate<'_>]) -> Vec<CertInfo> {
    let now = time::OffsetDateTime::now_utc();
    certs
        .iter()
        .enumerate()
        .map(|(i, cert)| {
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
            let cn = get_cn(cert);
            let sans = get_sans(cert);
            let ct = has_embedded_sct(cert);
            let is_ca = cert.tbs_certificate.is_ca();

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
