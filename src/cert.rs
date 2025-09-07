use anyhow::{Context, Result};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::oid_registry::OID_X509_COMMON_NAME;
use x509_parser::extensions::GeneralName;
use pem::parse_many;

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

pub fn parse_pem_certificates(pem_data: &str) -> Result<Vec<X509Certificate<'_>>> {
    let mut certs = Vec::new();
    let blocks = parse_many(pem_data.as_bytes()).context("Failed to parse PEM")?;
    for b in blocks {
        if b.tag != "CERTIFICATE" {
            continue;
        }
        let (_, cert) = X509Certificate::from_der(&b.contents).context("DER parse failed")?;
        certs.push(cert);
    }
    Ok(certs)
}

fn fmt_time(t: x509_parser::time::ASN1Time) -> String {
    let odt = t.to_datetime();
    odt.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

fn get_cn(cert: &X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            cert.subject().iter_attributes().find(|attr| *attr.attr_type() == OID_X509_COMMON_NAME)
                .and_then(|attr| attr.as_str().ok().map(|s| s.to_string()))
        })
}

fn get_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(san) = cert.subject_alternative_name() {
        for gn in san.value.general_names.iter() {
            let s = match gn {
                GeneralName::DNSName(n) => format!("DNS:{n}"),
                GeneralName::IPAddress(ip) => {
                    if ip.len() == 4 {
                        format!("IP:{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                    } else if ip.len() == 16 {
                        use std::net::Ipv6Addr;
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(ip);
                        format!("IP:{}", Ipv6Addr::from(bytes))
                    } else {
                        "IP:<?>".to_string()
                    }
                }
                GeneralName::RFC822Name(e) => format!("EMAIL:{e}"),
                GeneralName::URI(u) => format!("URI:{u}"),
                GeneralName::DirectoryName(d) => format!("DIR:{d}"),
                other => format!("{other:?}"),
            };
            out.push(s);
        }
    }
    out
}

fn has_embedded_sct(cert: &X509Certificate<'_>) -> bool {
    let sct_oid = x509_parser::oid_registry::Oid::from(&[1,3,6,1,4,1,11129,2,4,2]);
    cert.extensions().iter().any(|ext| ext.oid == sct_oid)
}

pub fn infos_from_x509(certs: &[X509Certificate<'_>]) -> Vec<CertInfo> {
    let now = time::OffsetDateTime::now_utc();
    certs.iter().enumerate().map(|(i, c)| {
        let subject = c.subject().to_string();
        let issuer = c.issuer().to_string();
        let serial_hex = c.raw_serial().iter().map(|b| format!("{:02X}", b)).collect::<String>();
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
    }).collect()
}
