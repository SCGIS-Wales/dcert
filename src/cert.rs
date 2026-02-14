use anyhow::Result;
use openssl::hash::MessageDigest;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

lazy_static::lazy_static! {
    pub static ref OID_X509_SCT_LIST: x509_parser::asn1_rs::Oid<'static> =
        x509_parser::asn1_rs::Oid::from(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2])
            .expect("hardcoded SCT list OID is valid");
}

#[derive(Debug, serde::Serialize, Clone)]
pub struct CertInfo {
    pub index: usize,
    pub subject: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subject_alternative_names: Vec<String>,
    pub serial_number: String,
    pub not_before: String, // RFC 3339
    pub not_after: String,  // RFC 3339
    pub is_expired: bool,
    pub ct_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sct_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_size_bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usage: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_key_usage: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_constraints: Option<BasicConstraintsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_info_access: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_status: Option<String>,
}

#[derive(Debug, serde::Serialize, Clone)]
pub struct BasicConstraintsInfo {
    pub ca: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_len_constraint: Option<u32>,
}

/// Options controlling what extra information to extract from certificates.
pub struct CertProcessOpts {
    pub expired_only: bool,
    pub fingerprint: bool,
    pub extensions: bool,
}

/// Process a single certificate into CertInfo
pub fn process_certificate(
    cert: X509Certificate<'_>,
    der_bytes: &[u8],
    idx: usize,
    opts: &CertProcessOpts,
) -> Result<Option<CertInfo>> {
    // Build owned info
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    // Serial as uppercase hex
    let serial_bytes = cert.raw_serial();
    let serial_number = serial_bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>();

    // Validity converted to RFC3339 strings
    let nb: OffsetDateTime = cert.validity().not_before.to_datetime();
    let na: OffsetDateTime = cert.validity().not_after.to_datetime();
    let now = OffsetDateTime::now_utc();

    let not_before = nb.format(&Rfc3339).unwrap_or_else(|_| nb.to_string());
    let not_after = na.format(&Rfc3339).unwrap_or_else(|_| na.to_string());
    let is_expired = na < now;

    if opts.expired_only && !is_expired {
        return Ok(None);
    }

    let common_name = extract_common_name(&cert);
    let subject_alternative_names = extract_sans(&cert);

    let sct_ext = cert.extensions().iter().find(|ext| ext.oid == *OID_X509_SCT_LIST);
    let ct_present = sct_ext.is_some();

    // Try to count individual SCTs in the extension.
    // The SCT list is an ASN.1 OCTET STRING wrapping a TLS-encoded SignedCertificateTimestampList:
    //   - 2 bytes: total list length
    //   - each SCT: 2 bytes length + SCT data
    let sct_count: Option<usize> = if opts.extensions {
        sct_ext.and_then(|ext| {
            let data = ext.value;
            // The outer layer is an ASN.1 OCTET STRING; parse it to get inner bytes
            let inner = if data.len() > 2 && data[0] == 0x04 {
                // Simple DER OCTET STRING: tag=0x04, length, value
                let len_byte = data[1] as usize;
                if len_byte < 0x80 && data.len() >= 2 + len_byte {
                    &data[2..2 + len_byte]
                } else if len_byte == 0x81 && data.len() > 3 {
                    let len = data[2] as usize;
                    if data.len() >= 3 + len {
                        &data[3..3 + len]
                    } else {
                        data
                    }
                } else if len_byte == 0x82 && data.len() > 4 {
                    let len = ((data[2] as usize) << 8) | (data[3] as usize);
                    if data.len() >= 4 + len {
                        &data[4..4 + len]
                    } else {
                        data
                    }
                } else {
                    data
                }
            } else {
                data
            };
            // Now inner is the TLS-encoded list: 2-byte total length, then SCTs
            if inner.len() < 2 {
                return None;
            }
            let total_len = ((inner[0] as usize) << 8) | (inner[1] as usize);
            let mut offset = 2;
            let end = (2 + total_len).min(inner.len());
            let mut count = 0usize;
            while offset + 2 <= end {
                let sct_len = ((inner[offset] as usize) << 8) | (inner[offset + 1] as usize);
                offset += 2 + sct_len;
                count += 1;
            }
            Some(count)
        })
    } else {
        None
    };

    // SHA-256 fingerprint
    let sha256_fingerprint = if opts.fingerprint {
        let digest = openssl::hash::hash(MessageDigest::sha256(), der_bytes)
            .map_err(|e| anyhow::anyhow!("SHA-256 hash failed: {e}"))?;
        Some(
            digest
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":"),
        )
    } else {
        None
    };

    // Signature algorithm
    let signature_algorithm = if opts.extensions {
        Some(cert.signature_algorithm.algorithm.to_id_string())
    } else {
        None
    };

    // Public key info (always shown in extensions mode)
    let (public_key_algorithm, public_key_size_bits) = if opts.extensions {
        let spki = cert.public_key();
        let alg_oid = spki.algorithm.algorithm.to_id_string();
        let alg_name = match alg_oid.as_str() {
            "1.2.840.113549.1.1.1" => "RSA".to_string(),
            "1.2.840.10045.2.1" => "EC".to_string(),
            "1.3.101.110" => "X25519".to_string(),
            "1.3.101.112" => "Ed25519".to_string(),
            "1.3.101.113" => "Ed448".to_string(),
            other => other.to_string(),
        };
        let key_bits = (spki.subject_public_key.data.len() * 8) as u32;
        (Some(alg_name), Some(key_bits))
    } else {
        (None, None)
    };

    // Extensions
    let (key_usage, extended_key_usage, basic_constraints, authority_info_access) = if opts.extensions {
        let mut ku = None;
        let mut eku = None;
        let mut bc = None;
        let mut aia = None;

        for ext in cert.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::KeyUsage(usage) => {
                    let mut usages = Vec::new();
                    if usage.digital_signature() {
                        usages.push("digitalSignature".to_string());
                    }
                    if usage.non_repudiation() {
                        usages.push("nonRepudiation".to_string());
                    }
                    if usage.key_encipherment() {
                        usages.push("keyEncipherment".to_string());
                    }
                    if usage.data_encipherment() {
                        usages.push("dataEncipherment".to_string());
                    }
                    if usage.key_agreement() {
                        usages.push("keyAgreement".to_string());
                    }
                    if usage.key_cert_sign() {
                        usages.push("keyCertSign".to_string());
                    }
                    if usage.crl_sign() {
                        usages.push("cRLSign".to_string());
                    }
                    if usage.encipher_only() {
                        usages.push("encipherOnly".to_string());
                    }
                    if usage.decipher_only() {
                        usages.push("decipherOnly".to_string());
                    }
                    if !usages.is_empty() {
                        ku = Some(usages);
                    }
                }
                ParsedExtension::ExtendedKeyUsage(usage) => {
                    let mut usages = Vec::new();
                    if usage.server_auth {
                        usages.push("serverAuth".to_string());
                    }
                    if usage.client_auth {
                        usages.push("clientAuth".to_string());
                    }
                    if usage.code_signing {
                        usages.push("codeSigning".to_string());
                    }
                    if usage.email_protection {
                        usages.push("emailProtection".to_string());
                    }
                    if usage.time_stamping {
                        usages.push("timeStamping".to_string());
                    }
                    if usage.ocsp_signing {
                        usages.push("ocspSigning".to_string());
                    }
                    if !usages.is_empty() {
                        eku = Some(usages);
                    }
                }
                ParsedExtension::BasicConstraints(constraints) => {
                    bc = Some(BasicConstraintsInfo {
                        ca: constraints.ca,
                        path_len_constraint: constraints.path_len_constraint,
                    });
                }
                ParsedExtension::AuthorityInfoAccess(access) => {
                    let mut urls = Vec::new();
                    for desc in access.iter() {
                        let method_oid = desc.access_method.to_id_string();
                        let method = match method_oid.as_str() {
                            "1.3.6.1.5.5.7.48.1" => "OCSP",
                            "1.3.6.1.5.5.7.48.2" => "CA Issuers",
                            _ => &method_oid,
                        };
                        match &desc.access_location {
                            GeneralName::URI(uri) => {
                                urls.push(format!("{}: {}", method, uri));
                            }
                            _ => {
                                urls.push(format!("{}: (non-URI)", method));
                            }
                        }
                    }
                    if !urls.is_empty() {
                        aia = Some(urls);
                    }
                }
                _ => {}
            }
        }

        (ku, eku, bc, aia)
    } else {
        (None, None, None, None)
    };

    Ok(Some(CertInfo {
        index: idx,
        subject,
        issuer,
        common_name,
        subject_alternative_names,
        serial_number,
        not_before,
        not_after,
        is_expired,
        ct_present,
        sct_count,
        sha256_fingerprint,
        signature_algorithm,
        public_key_algorithm,
        public_key_size_bits,
        key_usage,
        extended_key_usage,
        basic_constraints,
        authority_info_access,
        revocation_status: None,
    }))
}

/// Parse all PEM certificate blocks from `pem_data` and return owned `CertInfo`
/// for each certificate. We do not store `X509Certificate` to avoid lifetime issues.
pub fn parse_cert_infos_from_pem(pem_data: &str, opts: &CertProcessOpts) -> Result<Vec<CertInfo>> {
    let blocks = pem::parse_many(pem_data).map_err(|e| anyhow::anyhow!("Failed to parse PEM: {e}"))?;

    let mut infos = Vec::new();
    let mut errors = Vec::new();

    for (idx, block) in blocks.iter().enumerate() {
        if block.tag() != "CERTIFICATE" {
            continue;
        }

        match X509Certificate::from_der(block.contents()) {
            Ok((_, cert)) => {
                match process_certificate(cert, block.contents(), idx, opts) {
                    Ok(Some(info)) => infos.push(info),
                    Ok(None) => {} // Filtered out (e.g., not expired when expired_only is true)
                    Err(e) => errors.push(format!("Certificate {}: {}", idx, e)),
                }
            }
            Err(e) => {
                errors.push(format!("Certificate {} parsing failed: {}", idx, e));
                continue;
            }
        }
    }

    // Return results even if some certs failed, but warn about errors
    if !errors.is_empty() {
        eprintln!("Warning: Some certificates had issues:");
        for error in &errors {
            eprintln!("  - {}", error);
        }
    }

    if infos.is_empty() && !errors.is_empty() {
        return Err(anyhow::anyhow!(
            "All certificates failed to parse:\n{}",
            errors.join("\n")
        ));
    }

    Ok(infos)
}

pub fn extract_common_name(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_attributes()
        .find(|attr| *attr.attr_type() == x509_parser::oid_registry::OID_X509_COMMON_NAME)
        .and_then(|attr| attr.attr_value().as_str().ok())
        .map(|s| s.to_string())
}

pub fn extract_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut out = Vec::new();

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                match gn {
                    GeneralName::DNSName(d) => out.push(format!("DNS:{}", d)),
                    GeneralName::RFC822Name(e) => out.push(format!("Email:{}", e)),
                    GeneralName::URI(u) => out.push(format!("URI:{}", u)),
                    GeneralName::IPAddress(bytes) => match bytes.len() {
                        4 => {
                            if let Ok(v4) = <[u8; 4]>::try_from(&bytes[..]) {
                                out.push(format!("IP:{}", IpAddr::from(v4)));
                            }
                        }
                        16 => {
                            if let Ok(v6) = <[u8; 16]>::try_from(&bytes[..]) {
                                out.push(format!("IP:{}", IpAddr::from(v6)));
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }

    out
}

/// Extract OCSP responder URL from a certificate's Authority Information Access extension.
pub fn extract_ocsp_url(cert: &X509Certificate<'_>) -> Option<String> {
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                // OID 1.3.6.1.5.5.7.48.1 = id-ad-ocsp
                if desc.access_method.to_id_string() == "1.3.6.1.5.5.7.48.1" {
                    if let GeneralName::URI(uri) = &desc.access_location {
                        return Some(uri.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::path::PathBuf;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    // A self-signed test certificate with CN=test.example.com and SANs
    const VALID_PEM: &str = include_str!("../tests/data/valid.pem");

    // The multi-cert chain from tests/data/test.pem (Microsoft Azure)
    const CHAIN_PEM: &str = include_str!("../tests/data/test.pem");

    fn default_opts() -> CertProcessOpts {
        CertProcessOpts {
            expired_only: false,
            fingerprint: false,
            extensions: false,
        }
    }

    fn opts_expired_only() -> CertProcessOpts {
        CertProcessOpts {
            expired_only: true,
            fingerprint: false,
            extensions: false,
        }
    }

    fn opts_with_fingerprint() -> CertProcessOpts {
        CertProcessOpts {
            expired_only: false,
            fingerprint: true,
            extensions: false,
        }
    }

    fn opts_with_extensions() -> CertProcessOpts {
        CertProcessOpts {
            expired_only: false,
            fingerprint: false,
            extensions: true,
        }
    }

    pub fn make_test_cert(common_name: Option<&str>, sans: Vec<&str>) -> CertInfo {
        CertInfo {
            index: 0,
            subject: common_name.map(|cn| format!("CN={}", cn)).unwrap_or_default(),
            issuer: "CN=Test CA".to_string(),
            common_name: common_name.map(|s| s.to_string()),
            subject_alternative_names: sans.into_iter().map(|s| s.to_string()).collect(),
            serial_number: "AABB".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2027-01-01T00:00:00Z".to_string(),
            is_expired: false,
            ct_present: false,
            sct_count: None,
            sha256_fingerprint: None,
            signature_algorithm: None,
            public_key_algorithm: None,
            public_key_size_bits: None,
            key_usage: None,
            extended_key_usage: None,
            basic_constraints: None,
            authority_info_access: None,
            revocation_status: None,
        }
    }

    // ---------------------------------------------------------------
    // parse_cert_infos_from_pem tests
    // ---------------------------------------------------------------

    #[test]
    fn test_empty_pem() {
        let result = parse_cert_infos_from_pem("", &default_opts());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_invalid_pem() {
        let result = parse_cert_infos_from_pem("invalid pem data", &default_opts());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_valid_single_cert() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        assert_eq!(infos.len(), 1);
        let cert = &infos[0];
        assert!(cert.common_name.as_deref() == Some("test.example.com"));
        assert!(!cert.subject.is_empty());
        assert!(!cert.issuer.is_empty());
        assert!(!cert.serial_number.is_empty());
        assert!(!cert.not_before.is_empty());
        assert!(!cert.not_after.is_empty());
    }

    #[test]
    fn test_valid_cert_sans() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        let cert = &infos[0];
        assert!(
            cert.subject_alternative_names
                .iter()
                .any(|s| s == "DNS:test.example.com"),
            "expected DNS:test.example.com in SANs, got {:?}",
            cert.subject_alternative_names
        );
        assert!(
            cert.subject_alternative_names.iter().any(|s| s == "DNS:*.example.com"),
            "expected DNS:*.example.com in SANs"
        );
        assert!(
            cert.subject_alternative_names.iter().any(|s| s == "IP:127.0.0.1"),
            "expected IP:127.0.0.1 in SANs"
        );
    }

    #[test]
    fn test_valid_cert_not_expired() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        assert!(!infos[0].is_expired, "test cert should not be expired yet");
    }

    #[test]
    fn test_cert_chain_multiple_certs() {
        let infos = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        assert_eq!(infos.len(), 3, "test.pem should contain 3 certificates");
    }

    #[test]
    fn test_cert_chain_indices() {
        let infos = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        assert_eq!(infos[0].index, 0);
        assert_eq!(infos[1].index, 1);
        assert_eq!(infos[2].index, 2);
    }

    #[test]
    fn test_expired_only_filter() {
        let all = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        let expired = parse_cert_infos_from_pem(CHAIN_PEM, &opts_expired_only()).unwrap();
        let expired_count = all.iter().filter(|c| c.is_expired).count();
        assert_eq!(expired.len(), expired_count);
        for cert in &expired {
            assert!(cert.is_expired, "expired_only should only return expired certs");
        }
    }

    #[test]
    fn test_cert_serial_is_hex() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        let serial = &infos[0].serial_number;
        assert!(
            serial.chars().all(|c| c.is_ascii_hexdigit()),
            "serial should be hex, got: {}",
            serial
        );
    }

    #[test]
    fn test_cert_dates_are_rfc3339() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        let not_before = &infos[0].not_before;
        let not_after = &infos[0].not_after;
        assert!(
            OffsetDateTime::parse(not_before, &Rfc3339).is_ok(),
            "not_before should be RFC3339: {not_before}",
        );
        assert!(
            OffsetDateTime::parse(not_after, &Rfc3339).is_ok(),
            "not_after should be RFC3339: {not_after}",
        );
    }

    #[test]
    fn test_pem_with_non_certificate_blocks() {
        let mixed = format!(
            "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----\n{}",
            VALID_PEM
        );
        let infos = parse_cert_infos_from_pem(&mixed, &default_opts()).unwrap();
        assert_eq!(infos.len(), 1, "should skip non-CERTIFICATE blocks");
    }

    // ---------------------------------------------------------------
    // Fingerprint tests
    // ---------------------------------------------------------------

    #[test]
    fn test_fingerprint_computed_when_requested() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &opts_with_fingerprint()).unwrap();
        let cert = &infos[0];
        assert!(cert.sha256_fingerprint.is_some(), "fingerprint should be present");
        let fp = cert.sha256_fingerprint.as_ref().unwrap();
        // SHA-256 fingerprint is 32 bytes = 64 hex chars + 31 colons = 95 chars
        assert_eq!(fp.len(), 95, "fingerprint should be 95 chars (AA:BB:CC format)");
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':'),
            "fingerprint should be hex with colons"
        );
    }

    #[test]
    fn test_fingerprint_not_present_by_default() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        assert!(infos[0].sha256_fingerprint.is_none());
    }

    // ---------------------------------------------------------------
    // Extensions tests
    // ---------------------------------------------------------------

    #[test]
    fn test_extensions_parsed_when_requested() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &opts_with_extensions()).unwrap();
        let cert = &infos[0];
        assert!(
            cert.signature_algorithm.is_some(),
            "signature_algorithm should be present with --extensions"
        );
        // Self-signed cert should have basic constraints
        assert!(
            cert.basic_constraints.is_some(),
            "basic_constraints should be present for self-signed cert"
        );
    }

    #[test]
    fn test_extensions_not_present_by_default() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        assert!(infos[0].signature_algorithm.is_none());
        assert!(infos[0].key_usage.is_none());
        assert!(infos[0].extended_key_usage.is_none());
        assert!(infos[0].basic_constraints.is_none());
    }

    #[test]
    fn test_chain_extensions() {
        let infos = parse_cert_infos_from_pem(CHAIN_PEM, &opts_with_extensions()).unwrap();
        // At least the leaf cert should have extended key usage
        let has_eku = infos.iter().any(|c| c.extended_key_usage.is_some());
        assert!(has_eku, "at least one cert in chain should have EKU");
    }

    // ---------------------------------------------------------------
    // External file tests
    // ---------------------------------------------------------------

    #[test]
    fn test_valid_cert_from_file() -> anyhow::Result<()> {
        let path = PathBuf::from("tests/data/valid.pem");
        assert!(path.exists(), "tests/data/valid.pem is missing");
        let pem = std::fs::read_to_string(&path)?;
        let infos = parse_cert_infos_from_pem(&pem, &default_opts())?;
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].common_name.as_deref(), Some("test.example.com"));
        Ok(())
    }

    #[test]
    fn test_chain_from_external_file() -> anyhow::Result<()> {
        let path = PathBuf::from("tests/data/test.pem");
        assert!(path.exists(), "tests/data/test.pem is missing");
        let pem = std::fs::read_to_string(&path)?;
        let infos = parse_cert_infos_from_pem(&pem, &default_opts())?;
        assert!(infos.len() >= 2, "expected at least 2 certificates in chain");
        Ok(())
    }

    // ---------------------------------------------------------------
    // BasicConstraintsInfo serialization
    // ---------------------------------------------------------------

    #[test]
    fn test_basic_constraints_serialization() {
        let bc = BasicConstraintsInfo {
            ca: true,
            path_len_constraint: Some(1),
        };
        let json = serde_json::to_string(&bc).unwrap();
        assert!(json.contains("\"ca\":true"));
        assert!(json.contains("\"path_len_constraint\":1"));
    }

    #[test]
    fn test_basic_constraints_omits_none_path_len() {
        let bc = BasicConstraintsInfo {
            ca: false,
            path_len_constraint: None,
        };
        let json = serde_json::to_string(&bc).unwrap();
        assert!(!json.contains("path_len_constraint"));
    }

    // ---------------------------------------------------------------
    // CertInfo serialization tests
    // ---------------------------------------------------------------

    #[test]
    fn test_cert_info_json_serialization() {
        let mut info = make_test_cert(Some("test"), vec!["DNS:test.com"]);
        info.ct_present = true;
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"common_name\":\"test\""));
        assert!(json.contains("\"ct_present\":true"));
        assert!(json.contains("\"is_expired\":false"));
    }

    #[test]
    fn test_cert_info_json_omits_empty_fields() {
        let info = make_test_cert(None, vec![]);
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("common_name"), "None common_name should be omitted");
        assert!(
            !json.contains("subject_alternative_names"),
            "empty SANs should be omitted"
        );
        assert!(
            !json.contains("sha256_fingerprint"),
            "None fingerprint should be omitted"
        );
        assert!(!json.contains("key_usage"), "None key_usage should be omitted");
        assert!(!json.contains("extended_key_usage"), "None EKU should be omitted");
        assert!(!json.contains("basic_constraints"), "None BC should be omitted");
        assert!(!json.contains("revocation_status"), "None revocation should be omitted");
    }

    #[test]
    fn test_cert_info_json_includes_fingerprint() {
        let mut info = make_test_cert(Some("test"), vec![]);
        info.sha256_fingerprint = Some("AA:BB:CC".to_string());
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("sha256_fingerprint"));
        assert!(json.contains("AA:BB:CC"));
    }

    #[test]
    fn test_cert_info_yaml_serialization() {
        let info = make_test_cert(Some("test"), vec!["DNS:test.com"]);
        let yaml = serde_yml::to_string(&info).unwrap();
        assert!(yaml.contains("common_name"), "YAML should contain common_name");
        assert!(yaml.contains("test"), "YAML should contain the CN value");
    }
}
