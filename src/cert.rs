use anyhow::{Context, Result};
use hex;
use rustls::pki_types::CertificateDer;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_X509_COMMON_NAME;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, serde::Serialize, Clone)]
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
    odt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn get_cn(cert: &X509Certificate<'_>) -> Option<String> {
    if let Some(attr) = cert.subject().iter_common_name().next() {
        if let Ok(s) = attr.as_str() {
            return Some(s.to_string());
        }
    }
    cert.subject()
        .iter_attributes()
        .find(|attr| *attr.attr_type() == OID_X509_COMMON_NAME)
        .and_then(|attr| attr.as_str().ok().map(|s| s.to_string()))
}

fn get_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        let san = ext.value;
        for gn in san.general_names.iter() {
            match gn {
                GeneralName::DNSName(d) => out.push(d.to_string()),
                GeneralName::RFC822Name(e) => out.push(e.to_string()),
                GeneralName::URI(u) => out.push(u.to_string()),
                GeneralName::IPAddress(ip) => {
                    let s = match ip.len() {
                        4 => {
                            let mut a = [0u8; 4];
                            a.copy_from_slice(ip);
                            std::net::IpAddr::from(a).to_string()
                        }
                        16 => {
                            let mut a = [0u8; 16];
                            a.copy_from_slice(ip);
                            std::net::IpAddr::from(a).to_string()
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
    let sct_oid =
        x509_parser::asn1_rs::Oid::from(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2]).expect("oid");
    cert.extensions().iter().any(|ext| ext.oid == sct_oid)
}

pub fn parse_pem_to_der(pem_text: &str) -> Result<Vec<CertificateDer<'static>>> {
    use rustls_pemfile as pemfile;

    let mut rdr = std::io::Cursor::new(pem_text.as_bytes());
    let mut ders: Vec<CertificateDer<'static>> = Vec::new();
    for item in pemfile::certs(&mut rdr) {
        let der = item.context("Error while decoding PEM certificate")?;
        ders.push(der);
    }
    Ok(ders)
}

pub fn infos_from_der_certs(ders: &[CertificateDer<'_>]) -> Vec<CertInfo> {
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
