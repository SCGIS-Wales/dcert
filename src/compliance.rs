use crate::cert::CertInfo;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Severity of a compliance finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// A single compliance finding for a certificate.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertFinding {
    pub severity: Severity,
    pub category: String,
    pub message: String,
}

/// Full compliance report for a single certificate.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertComplianceReport {
    /// Certificate index in the chain
    pub index: usize,
    /// Subject of the certificate
    pub subject: String,
    /// Common name (if present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    /// Compliance findings
    pub findings: Vec<CertFinding>,
    /// Overall compliance status (true = no errors)
    pub compliant: bool,
}

/// Compliance report for a full certificate chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainComplianceReport {
    /// Per-certificate compliance reports
    pub certificates: Vec<CertComplianceReport>,
    /// Overall chain compliance (true = all certs compliant)
    pub chain_compliant: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run compliance checks on a slice of parsed certificates.
///
/// The certificates should have been parsed with `extensions: true` so that
/// key size, signature algorithm, key usage, and EKU information is available.
pub fn check_chain_compliance(infos: &[CertInfo]) -> ChainComplianceReport {
    let mut reports = Vec::with_capacity(infos.len());

    for info in infos {
        let is_leaf = info.index == 0;
        let findings = check_certificate_compliance(info, is_leaf);
        let compliant = !findings.iter().any(|f| f.severity == Severity::Error);
        reports.push(CertComplianceReport {
            index: info.index,
            subject: info.subject.clone(),
            common_name: info.common_name.clone(),
            findings,
            compliant,
        });
    }

    let chain_compliant = reports.iter().all(|r| r.compliant);
    ChainComplianceReport {
        certificates: reports,
        chain_compliant,
    }
}

/// Run all compliance checks for a single certificate.
fn check_certificate_compliance(info: &CertInfo, is_leaf: bool) -> Vec<CertFinding> {
    let mut findings = Vec::new();

    check_key_compliance(info, &mut findings);
    check_signature_algorithm(info, &mut findings);
    check_expiry_compliance(info, &mut findings);
    check_validity_period(info, &mut findings);
    check_certificate_transparency(info, &mut findings);

    if is_leaf {
        check_san_compliance(info, &mut findings);
        check_eku_compliance(info, &mut findings);
    } else {
        check_ca_compliance(info, &mut findings);
    }

    findings
}

// ---------------------------------------------------------------------------
// Individual compliance checks
// ---------------------------------------------------------------------------

/// Check public key algorithm and size against CA/B Forum requirements.
fn check_key_compliance(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    let (alg, bits) = match (&info.public_key_algorithm, info.public_key_size_bits) {
        (Some(alg), Some(bits)) => (alg.as_str(), bits),
        _ => {
            findings.push(CertFinding {
                severity: Severity::Info,
                category: "Key Size".to_string(),
                message: "Public key information not available (use --extensions to extract)"
                    .to_string(),
            });
            return;
        }
    };

    match alg {
        "RSA" => {
            if bits < 2048 {
                findings.push(CertFinding {
                    severity: Severity::Error,
                    category: "Key Size".to_string(),
                    message: format!(
                        "RSA key size {} bits is below the minimum 2048-bit requirement (CA/B Forum BR)",
                        bits
                    ),
                });
            } else if bits == 2048 {
                findings.push(CertFinding {
                    severity: Severity::Warning,
                    category: "Key Size".to_string(),
                    message: "RSA 2048-bit meets minimum requirements but 3072+ bits is recommended for long-lived certificates".to_string(),
                });
            } else {
                findings.push(CertFinding {
                    severity: Severity::Info,
                    category: "Key Size".to_string(),
                    message: format!("RSA {} bits meets requirements", bits),
                });
            }
        }
        "EC" => {
            if bits < 256 {
                findings.push(CertFinding {
                    severity: Severity::Error,
                    category: "Key Size".to_string(),
                    message: format!(
                        "EC key size {} bits is below the minimum 256-bit (P-256) requirement",
                        bits
                    ),
                });
            } else {
                findings.push(CertFinding {
                    severity: Severity::Info,
                    category: "Key Size".to_string(),
                    message: format!("EC {} bits meets requirements", bits),
                });
            }
        }
        _ => {
            findings.push(CertFinding {
                severity: Severity::Info,
                category: "Key Size".to_string(),
                message: format!("Key algorithm: {} ({} bits)", alg, bits),
            });
        }
    }
}

/// Check signature algorithm — SHA-1 and MD5 are rejected.
fn check_signature_algorithm(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    let sig_alg = match &info.signature_algorithm {
        Some(alg) => alg.as_str(),
        None => return, // not available
    };

    // OID-based detection
    let (name, severity, msg) = match sig_alg {
        // SHA-1 with RSA
        "1.2.840.113549.1.1.5" => (
            "SHA-1 with RSA",
            Severity::Error,
            "SHA-1 signatures are insecure and rejected by all major browsers since 2017",
        ),
        // MD5 with RSA
        "1.2.840.113549.1.1.4" => (
            "MD5 with RSA",
            Severity::Error,
            "MD5 signatures are cryptographically broken and must not be used",
        ),
        // MD2 with RSA
        "1.2.840.113549.1.1.2" => (
            "MD2 with RSA",
            Severity::Error,
            "MD2 signatures are cryptographically broken and must not be used",
        ),
        // SHA-256 with RSA
        "1.2.840.113549.1.1.11" => ("SHA-256 with RSA", Severity::Info, "Compliant signature algorithm"),
        // SHA-384 with RSA
        "1.2.840.113549.1.1.12" => ("SHA-384 with RSA", Severity::Info, "Compliant signature algorithm"),
        // SHA-512 with RSA
        "1.2.840.113549.1.1.13" => ("SHA-512 with RSA", Severity::Info, "Compliant signature algorithm"),
        // ECDSA with SHA-256
        "1.2.840.10045.4.3.2" => ("ECDSA with SHA-256", Severity::Info, "Compliant signature algorithm"),
        // ECDSA with SHA-384
        "1.2.840.10045.4.3.3" => ("ECDSA with SHA-384", Severity::Info, "Compliant signature algorithm"),
        // ECDSA with SHA-512
        "1.2.840.10045.4.3.4" => ("ECDSA with SHA-512", Severity::Info, "Compliant signature algorithm"),
        // RSA-PSS
        "1.2.840.113549.1.1.10" => ("RSA-PSS", Severity::Info, "Compliant signature algorithm"),
        // Ed25519
        "1.3.101.112" => ("Ed25519", Severity::Info, "Compliant signature algorithm"),
        // Ed448
        "1.3.101.113" => ("Ed448", Severity::Info, "Compliant signature algorithm"),
        _ => {
            findings.push(CertFinding {
                severity: Severity::Info,
                category: "Signature Algorithm".to_string(),
                message: format!("Signature algorithm OID: {}", sig_alg),
            });
            return;
        }
    };

    findings.push(CertFinding {
        severity,
        category: "Signature Algorithm".to_string(),
        message: format!("{}: {}", name, msg),
    });
}

/// Check certificate expiry and remaining validity.
fn check_expiry_compliance(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    if info.is_expired {
        findings.push(CertFinding {
            severity: Severity::Error,
            category: "Expiry".to_string(),
            message: format!("Certificate is EXPIRED (expired {})", info.not_after),
        });
        return;
    }

    let now = OffsetDateTime::now_utc();
    if let Ok(not_after) = OffsetDateTime::parse(&info.not_after, &Rfc3339) {
        let days_left = (not_after - now).whole_days();
        if days_left <= 30 {
            findings.push(CertFinding {
                severity: Severity::Warning,
                category: "Expiry".to_string(),
                message: format!(
                    "Certificate expires in {} days ({}). Renewal recommended.",
                    days_left, info.not_after
                ),
            });
        } else if days_left <= 90 {
            findings.push(CertFinding {
                severity: Severity::Info,
                category: "Expiry".to_string(),
                message: format!(
                    "Certificate expires in {} days ({})",
                    days_left, info.not_after
                ),
            });
        } else {
            findings.push(CertFinding {
                severity: Severity::Info,
                category: "Expiry".to_string(),
                message: format!("Certificate valid for {} more days", days_left),
            });
        }
    }
}

/// Check validity period does not exceed CA/B Forum maximum (398 days since Sep 2020).
fn check_validity_period(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    let not_before = match OffsetDateTime::parse(&info.not_before, &Rfc3339) {
        Ok(dt) => dt,
        Err(_) => return,
    };
    let not_after = match OffsetDateTime::parse(&info.not_after, &Rfc3339) {
        Ok(dt) => dt,
        Err(_) => return,
    };

    let validity_days = (not_after - not_before).whole_days();
    if validity_days > 398 {
        findings.push(CertFinding {
            severity: Severity::Warning,
            category: "Validity Period".to_string(),
            message: format!(
                "Certificate validity of {} days exceeds CA/B Forum maximum of 398 days (since Sep 2020). \
                 Publicly-trusted CAs must not issue certificates with longer validity.",
                validity_days
            ),
        });
    } else {
        findings.push(CertFinding {
            severity: Severity::Info,
            category: "Validity Period".to_string(),
            message: format!("Certificate validity period: {} days (within 398-day limit)", validity_days),
        });
    }
}

/// Check for Certificate Transparency SCTs (required by major browsers).
fn check_certificate_transparency(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    if info.ct_present {
        let sct_msg = match info.sct_count {
            Some(count) => format!(
                "Certificate Transparency: {} SCT(s) embedded (compliant with CT policy)",
                count
            ),
            None => "Certificate Transparency: SCTs present".to_string(),
        };
        findings.push(CertFinding {
            severity: Severity::Info,
            category: "Certificate Transparency".to_string(),
            message: sct_msg,
        });
    } else {
        findings.push(CertFinding {
            severity: Severity::Warning,
            category: "Certificate Transparency".to_string(),
            message: "No embedded SCTs found. Chrome and other browsers require Certificate Transparency \
                      for publicly-trusted certificates. SCTs may be delivered via TLS extension or OCSP stapling instead."
                .to_string(),
        });
    }
}

/// Check SAN presence and CN-in-SAN for leaf certificates.
fn check_san_compliance(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    if info.subject_alternative_names.is_empty() {
        findings.push(CertFinding {
            severity: Severity::Error,
            category: "SAN".to_string(),
            message: "No Subject Alternative Names found. SANs are required for all publicly-trusted \
                      certificates since 2018 (CA/B Forum BR). All major browsers reject certificates without SANs."
                .to_string(),
        });
    } else {
        findings.push(CertFinding {
            severity: Severity::Info,
            category: "SAN".to_string(),
            message: format!(
                "{} SAN(s) present",
                info.subject_alternative_names.len()
            ),
        });

        // Check CN is in SANs
        if let Some(ref cn) = info.common_name {
            let cn_lower = cn.to_lowercase();
            let cn_in_sans = info.subject_alternative_names.iter().any(|san| {
                san.strip_prefix("DNS:")
                    .map(|d| d.to_lowercase() == cn_lower)
                    .unwrap_or(false)
            });
            if !cn_in_sans {
                findings.push(CertFinding {
                    severity: Severity::Warning,
                    category: "SAN".to_string(),
                    message: format!(
                        "Common Name '{}' is not included in SANs. Per RFC 6125, CN should be present in SANs.",
                        cn
                    ),
                });
            }
        }

        // Check for wildcard validity
        for san in &info.subject_alternative_names {
            if let Some(dns) = san.strip_prefix("DNS:") {
                if dns.contains('*') && !dns.starts_with("*.") {
                    findings.push(CertFinding {
                        severity: Severity::Error,
                        category: "SAN".to_string(),
                        message: format!(
                            "Invalid wildcard '{}': wildcards must only appear as the leftmost label (e.g., *.example.com)",
                            dns
                        ),
                    });
                }
            }
        }
    }
}

/// Check Extended Key Usage for leaf certificates.
fn check_eku_compliance(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    match &info.extended_key_usage {
        Some(eku) => {
            if eku.iter().any(|u| u == "serverAuth") {
                findings.push(CertFinding {
                    severity: Severity::Info,
                    category: "Extended Key Usage".to_string(),
                    message: "serverAuth present (required for TLS server certificates)".to_string(),
                });
            } else {
                findings.push(CertFinding {
                    severity: Severity::Warning,
                    category: "Extended Key Usage".to_string(),
                    message: format!(
                        "serverAuth not found in EKU (found: {}). TLS server certificates should include serverAuth.",
                        eku.join(", ")
                    ),
                });
            }
        }
        None => {
            // EKU not present — only a warning since some older certs omit it
        }
    }
}

/// Check CA certificate constraints.
fn check_ca_compliance(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    match &info.basic_constraints {
        Some(bc) => {
            if !bc.ca {
                findings.push(CertFinding {
                    severity: Severity::Warning,
                    category: "Basic Constraints".to_string(),
                    message: "Intermediate certificate has basicConstraints with CA=false. \
                              CA certificates must have CA=true."
                        .to_string(),
                });
            } else {
                findings.push(CertFinding {
                    severity: Severity::Info,
                    category: "Basic Constraints".to_string(),
                    message: "CA certificate: basicConstraints CA=true".to_string(),
                });
            }
        }
        None => {
            // Basic constraints not available — info only if extensions were parsed
        }
    }

    // CA certs should have keyCertSign
    if let Some(ref ku) = info.key_usage {
        if !ku.iter().any(|u| u == "keyCertSign") {
            findings.push(CertFinding {
                severity: Severity::Warning,
                category: "Key Usage".to_string(),
                message: "CA certificate missing keyCertSign in Key Usage".to_string(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::tests::make_test_cert;
    use crate::cert::{BasicConstraintsInfo, CertInfo};

    fn make_leaf_cert_with_extensions() -> CertInfo {
        let mut cert = make_test_cert(Some("www.example.com"), vec!["DNS:www.example.com", "DNS:example.com"]);
        cert.signature_algorithm = Some("1.2.840.113549.1.1.11".to_string()); // SHA-256 with RSA
        cert.public_key_algorithm = Some("RSA".to_string());
        cert.public_key_size_bits = Some(2048);
        cert.ct_present = true;
        cert.sct_count = Some(2);
        cert.extended_key_usage = Some(vec!["serverAuth".to_string()]);
        cert
    }

    fn make_expired_cert() -> CertInfo {
        let mut cert = make_test_cert(Some("expired.example.com"), vec!["DNS:expired.example.com"]);
        cert.is_expired = true;
        cert.not_after = "2020-01-01T00:00:00Z".to_string();
        cert.not_before = "2019-01-01T00:00:00Z".to_string();
        cert
    }

    fn make_ca_cert() -> CertInfo {
        let mut cert = make_test_cert(Some("Test CA"), vec![]);
        cert.index = 1;
        cert.basic_constraints = Some(BasicConstraintsInfo {
            ca: true,
            path_len_constraint: None,
        });
        cert.key_usage = Some(vec!["keyCertSign".to_string(), "cRLSign".to_string()]);
        cert.signature_algorithm = Some("1.2.840.113549.1.1.11".to_string());
        cert.public_key_algorithm = Some("RSA".to_string());
        cert.public_key_size_bits = Some(4096);
        cert
    }

    // ---------------------------------------------------------------
    // Key compliance tests
    // ---------------------------------------------------------------

    #[test]
    fn test_key_rsa_below_minimum() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.public_key_size_bits = Some(1024);
        let mut findings = Vec::new();
        check_key_compliance(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Error));
        assert!(findings.iter().any(|f| f.message.contains("below the minimum")));
    }

    #[test]
    fn test_key_rsa_2048_warning() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.public_key_size_bits = Some(2048);
        let mut findings = Vec::new();
        check_key_compliance(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Warning));
    }

    #[test]
    fn test_key_rsa_4096_ok() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.public_key_size_bits = Some(4096);
        let mut findings = Vec::new();
        check_key_compliance(&cert, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Error));
        assert!(findings.iter().any(|f| f.severity == Severity::Info));
    }

    #[test]
    fn test_key_ec_256_ok() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.public_key_algorithm = Some("EC".to_string());
        cert.public_key_size_bits = Some(256);
        let mut findings = Vec::new();
        check_key_compliance(&cert, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Error));
    }

    // ---------------------------------------------------------------
    // Signature algorithm tests
    // ---------------------------------------------------------------

    #[test]
    fn test_sig_sha1_error() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.signature_algorithm = Some("1.2.840.113549.1.1.5".to_string());
        let mut findings = Vec::new();
        check_signature_algorithm(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Error));
        assert!(findings.iter().any(|f| f.message.contains("SHA-1")));
    }

    #[test]
    fn test_sig_md5_error() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.signature_algorithm = Some("1.2.840.113549.1.1.4".to_string());
        let mut findings = Vec::new();
        check_signature_algorithm(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Error));
        assert!(findings.iter().any(|f| f.message.contains("MD5")));
    }

    #[test]
    fn test_sig_sha256_ok() {
        let cert = make_leaf_cert_with_extensions();
        let mut findings = Vec::new();
        check_signature_algorithm(&cert, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Error));
    }

    // ---------------------------------------------------------------
    // Expiry compliance tests
    // ---------------------------------------------------------------

    #[test]
    fn test_expired_cert_error() {
        let cert = make_expired_cert();
        let mut findings = Vec::new();
        check_expiry_compliance(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Error));
        assert!(findings.iter().any(|f| f.message.contains("EXPIRED")));
    }

    #[test]
    fn test_valid_cert_ok() {
        let cert = make_leaf_cert_with_extensions();
        let mut findings = Vec::new();
        check_expiry_compliance(&cert, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Error));
    }

    // ---------------------------------------------------------------
    // Validity period tests
    // ---------------------------------------------------------------

    #[test]
    fn test_validity_period_within_limit() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.not_before = "2026-01-01T00:00:00Z".to_string();
        cert.not_after = "2026-12-31T00:00:00Z".to_string(); // ~365 days
        let mut findings = Vec::new();
        check_validity_period(&cert, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Warning || f.severity == Severity::Error));
    }

    #[test]
    fn test_validity_period_exceeds_limit() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.not_before = "2026-01-01T00:00:00Z".to_string();
        cert.not_after = "2028-01-01T00:00:00Z".to_string(); // ~730 days
        let mut findings = Vec::new();
        check_validity_period(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Warning));
        assert!(findings.iter().any(|f| f.message.contains("398")));
    }

    // ---------------------------------------------------------------
    // CT compliance tests
    // ---------------------------------------------------------------

    #[test]
    fn test_ct_present() {
        let cert = make_leaf_cert_with_extensions();
        let mut findings = Vec::new();
        check_certificate_transparency(&cert, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Warning || f.severity == Severity::Error));
    }

    #[test]
    fn test_ct_missing() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.ct_present = false;
        cert.sct_count = None;
        let mut findings = Vec::new();
        check_certificate_transparency(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Warning));
    }

    // ---------------------------------------------------------------
    // SAN compliance tests
    // ---------------------------------------------------------------

    #[test]
    fn test_san_present_and_cn_in_sans() {
        let cert = make_leaf_cert_with_extensions();
        let mut findings = Vec::new();
        check_san_compliance(&cert, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Error || f.severity == Severity::Warning));
    }

    #[test]
    fn test_san_missing_error() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.subject_alternative_names = vec![];
        let mut findings = Vec::new();
        check_san_compliance(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Error));
    }

    #[test]
    fn test_cn_not_in_sans() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.common_name = Some("other.example.com".to_string());
        let mut findings = Vec::new();
        check_san_compliance(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Warning && f.category == "SAN"));
    }

    // ---------------------------------------------------------------
    // EKU compliance tests
    // ---------------------------------------------------------------

    #[test]
    fn test_eku_server_auth_present() {
        let cert = make_leaf_cert_with_extensions();
        let mut findings = Vec::new();
        check_eku_compliance(&cert, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Warning));
    }

    #[test]
    fn test_eku_missing_server_auth() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.extended_key_usage = Some(vec!["clientAuth".to_string()]);
        let mut findings = Vec::new();
        check_eku_compliance(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Warning));
    }

    // ---------------------------------------------------------------
    // CA compliance tests
    // ---------------------------------------------------------------

    #[test]
    fn test_ca_cert_compliant() {
        let cert = make_ca_cert();
        let mut findings = Vec::new();
        check_ca_compliance(&cert, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Error || f.severity == Severity::Warning));
    }

    #[test]
    fn test_ca_cert_missing_key_cert_sign() {
        let mut cert = make_ca_cert();
        cert.key_usage = Some(vec!["digitalSignature".to_string()]);
        let mut findings = Vec::new();
        check_ca_compliance(&cert, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Warning && f.message.contains("keyCertSign")));
    }

    // ---------------------------------------------------------------
    // Chain compliance tests
    // ---------------------------------------------------------------

    #[test]
    fn test_chain_compliance_all_ok() {
        let leaf = make_leaf_cert_with_extensions();
        let ca = make_ca_cert();
        let report = check_chain_compliance(&[leaf, ca]);
        assert!(report.chain_compliant);
        assert_eq!(report.certificates.len(), 2);
    }

    #[test]
    fn test_chain_compliance_expired_leaf() {
        let leaf = make_expired_cert();
        let ca = make_ca_cert();
        let report = check_chain_compliance(&[leaf, ca]);
        assert!(!report.chain_compliant);
        assert!(!report.certificates[0].compliant);
    }

    // ---------------------------------------------------------------
    // Serialization tests
    // ---------------------------------------------------------------

    #[test]
    fn test_compliance_report_json_serialization() {
        let leaf = make_leaf_cert_with_extensions();
        let report = check_chain_compliance(&[leaf]);
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("chain_compliant"));
        assert!(json.contains("findings"));
        assert!(json.contains("severity"));
    }

    #[test]
    fn test_severity_serialization() {
        let finding = CertFinding {
            severity: Severity::Error,
            category: "Test".to_string(),
            message: "test message".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"error\""));
    }
}
