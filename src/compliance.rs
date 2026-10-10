use crate::cert::CertInfo;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

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

/// A single compliance finding for a certificate or CSR.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub message: String,
}

impl Finding {
    pub fn new(severity: Severity, category: &str, message: impl Into<String>) -> Self {
        Self {
            severity,
            category: category.to_string(),
            message: message.into(),
        }
    }
}

/// Name kept for the certificate report; identical to [`Finding`].
pub type CertFinding = Finding;

/// `true` when no finding is an error.
pub fn is_compliant(findings: &[Finding]) -> bool {
    !findings.iter().any(|f| f.severity == Severity::Error)
}

// ---------------------------------------------------------------------------
// Shared checks (used by certificate and CSR validation)
// ---------------------------------------------------------------------------

/// Midnight UTC on the given calendar day, or `None` for an impossible date.
fn utc_midnight(year: i32, month: u8, day: u8) -> Option<OffsetDateTime> {
    let month = time::Month::try_from(month).ok()?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    Some(date.midnight().assume_utc())
}

/// `true` when `when` falls on or after midnight UTC of the given day.
fn on_or_after(when: OffsetDateTime, year: i32, month: u8, day: u8) -> bool {
    utc_midnight(year, month, day).is_some_and(|t| when >= t)
}

/// Maximum validity, in days, of a subscriber (leaf) certificate whose
/// notBefore is `not_before`, under CA/Browser Forum ballot SC-081v3, together
/// with a description of the issuance window the limit belongs to.
///
/// The schedule is keyed on the issuance date: 398 days before 2026-03-15,
/// 200 days from 2026-03-15, 100 days from 2027-03-15 and 47 days from
/// 2029-03-15. CA certificates are not subscriber certificates and are exempt.
pub fn max_subscriber_validity_days(not_before: OffsetDateTime) -> (i64, &'static str) {
    if on_or_after(not_before, 2029, 3, 15) {
        (47, "issued on or after 2029-03-15")
    } else if on_or_after(not_before, 2027, 3, 15) {
        (100, "issued between 2027-03-15 and 2029-03-14")
    } else if on_or_after(not_before, 2026, 3, 15) {
        (200, "issued between 2026-03-15 and 2027-03-14")
    } else {
        (398, "issued before 2026-03-15")
    }
}

/// Maximum validity, in days, for a certificate to count as short lived under
/// CA/Browser Forum ballot SC-063v4: 10 days when issued before 2026-03-15,
/// 7 days from 2026-03-15. Short lived certificates need no OCSP or CRL.
pub fn short_lived_max_days(not_before: OffsetDateTime) -> i64 {
    if on_or_after(not_before, 2026, 3, 15) { 7 } else { 10 }
}

/// Whole days between a certificate's notBefore and notAfter, when both parse.
fn validity_days(info: &CertInfo) -> Option<(OffsetDateTime, i64)> {
    let not_before = OffsetDateTime::parse(&info.not_before, &Rfc3339).ok()?;
    let not_after = OffsetDateTime::parse(&info.not_after, &Rfc3339).ok()?;
    Some((not_before, (not_after - not_before).whole_days()))
}

/// Coarse family of a public key or signature algorithm name, used to pick
/// the right compliance rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlgFamily {
    Rsa,
    Ec,
    EdDsa,
    MlDsa,
    MlKem,
    SlhDsa,
    Other,
}

fn alg_family(alg: &str) -> AlgFamily {
    let upper = alg.to_ascii_uppercase();
    if upper.starts_with("ML-DSA") {
        AlgFamily::MlDsa
    } else if upper.starts_with("ML-KEM") {
        AlgFamily::MlKem
    } else if upper.starts_with("SLH-DSA") {
        AlgFamily::SlhDsa
    } else if upper.starts_with("ED25519") || upper.starts_with("ED448") {
        AlgFamily::EdDsa
    } else if upper.starts_with("RSA") {
        AlgFamily::Rsa
    } else if upper.contains("EC") {
        AlgFamily::Ec
    } else {
        AlgFamily::Other
    }
}

/// Post quantum migration note for a classical (RSA or ECDSA) key, per NIST
/// IR 8547 (draft). `None` for any other algorithm.
pub fn post_quantum_migration_finding(alg: &str) -> Option<Finding> {
    match alg_family(alg) {
        AlgFamily::Rsa | AlgFamily::Ec => Some(Finding::new(
            Severity::Info,
            "Key Algorithm",
            format!(
                "{alg} is a classical algorithm; NIST IR 8547 (draft) deprecates RSA and ECDSA after 2030 \
                 and disallows them after 2035; plan the post quantum migration"
            ),
        )),
        _ => None,
    }
}

/// Findings for a public key algorithm and size against the CA/Browser Forum
/// Baseline Requirements. `alg` is a free form name such as `RSA`, `EC`,
/// `ECDSA P-256`, `Ed25519` or `ML-DSA-65`.
pub fn key_size_findings(alg: &str, bits: u32) -> Vec<Finding> {
    let mut findings = Vec::new();
    match alg_family(alg) {
        AlgFamily::MlDsa => {
            findings.push(Finding::new(
                Severity::Info,
                "Key Algorithm",
                format!("{alg}: post quantum signature key (FIPS 204, RFC 9881); {bits} bit encoded public key"),
            ));
            return findings;
        }
        AlgFamily::SlhDsa => {
            findings.push(Finding::new(
                Severity::Info,
                "Key Algorithm",
                format!("{alg}: post quantum signature key (FIPS 205); {bits} bit encoded public key"),
            ));
            return findings;
        }
        AlgFamily::MlKem => {
            findings.push(Finding::new(
                Severity::Info,
                "Key Algorithm",
                format!(
                    "{alg}: post quantum key encapsulation key (FIPS 203); {bits} bit encoded public key. \
                     ML-KEM keys cannot sign and are unusual in a TLS certificate; verify CA and client support."
                ),
            ));
            return findings;
        }
        AlgFamily::EdDsa => {
            findings.push(Finding::new(
                Severity::Info,
                "Key Algorithm",
                format!("{alg} ({bits} bits) meets requirements (RFC 8410 EdDSA key)"),
            ));
            return findings;
        }
        AlgFamily::Rsa | AlgFamily::Ec | AlgFamily::Other => {}
    }
    let upper = alg.to_ascii_uppercase();
    if upper.starts_with("RSA") {
        if bits < 2048 {
            findings.push(Finding::new(
                Severity::Error,
                "Key Size",
                format!("RSA key size {bits} bits is below the minimum 2048 bits required by the CA/Browser Forum Baseline Requirements"),
            ));
        } else if bits == 2048 {
            findings.push(Finding::new(
                Severity::Warning,
                "Key Size",
                "RSA 2048 meets the minimum requirement; RSA 3072 or larger, or ECDSA P-256, is recommended for stronger security",
            ));
        } else {
            findings.push(Finding::new(
                Severity::Info,
                "Key Size",
                format!("RSA {bits} bits meets requirements"),
            ));
        }
        findings.push(Finding::new(
            Severity::Info,
            "Key Algorithm",
            "Consider ECDSA P-256 for better performance with security equivalent to RSA 3072",
        ));
    } else if upper.contains("EC") {
        if bits < 256 {
            findings.push(Finding::new(
                Severity::Error,
                "Key Size",
                format!("EC key size {bits} bits is below the minimum 256 bits (P-256)"),
            ));
        } else {
            findings.push(Finding::new(
                Severity::Info,
                "Key Size",
                format!("{alg} {bits} bits meets requirements"),
            ));
        }
    } else {
        findings.push(Finding::new(
            Severity::Info,
            "Key Size",
            format!("Key algorithm: {alg} ({bits} bits). Verify CA support."),
        ));
    }
    findings
}

/// Shared SHA-1 verdict text. SHA-1 was rejected by browsers from 2017 and
/// CA/Browser Forum ballot SC-097 (2026) sunsets every remaining use of SHA-1
/// in certificates and CRLs, so an ECDSA or DSA SHA-1 signature is no better
/// than an RSA one.
const SHA1_MESSAGE: &str = "SHA-1 signatures are insecure, rejected by all major browsers since 2017, and \
                            every remaining use of SHA-1 in certificates and CRLs is sunset by CA/Browser Forum \
                            ballot SC-097 (2026)";

/// Verdict for a signature algorithm given its human readable name (for
/// example `sha256WithRSAEncryption`, `ecdsa-with-SHA384` or `ML-DSA-65`).
pub fn signature_name_finding(sig_algo: &str) -> Option<Finding> {
    let lower = sig_algo.to_ascii_lowercase();
    if lower.contains("md5") || lower.contains("md2") {
        Some(Finding::new(
            Severity::Error,
            "Signature Algorithm",
            format!("{sig_algo}: MD5 and MD2 signatures are cryptographically broken and must not be used"),
        ))
    } else if lower.contains("sha1") || lower.contains("sha-1") {
        Some(Finding::new(
            Severity::Error,
            "Signature Algorithm",
            format!("{sig_algo}: {SHA1_MESSAGE}"),
        ))
    } else if lower.starts_with("ml-dsa") {
        Some(Finding::new(
            Severity::Info,
            "Signature Algorithm",
            format!("{sig_algo}: post quantum signature (FIPS 204, RFC 9881)"),
        ))
    } else if lower.starts_with("slh-dsa") {
        Some(Finding::new(
            Severity::Info,
            "Signature Algorithm",
            format!("{sig_algo}: post quantum signature (FIPS 205)"),
        ))
    } else if lower.contains("sha256")
        || lower.contains("sha384")
        || lower.contains("sha512")
        || lower.contains("ed25519")
        || lower.contains("ed448")
        || lower.contains("pss")
    {
        Some(Finding::new(
            Severity::Info,
            "Signature Algorithm",
            format!("Signature algorithm '{sig_algo}' is compliant"),
        ))
    } else {
        None
    }
}

/// Warn when the Common Name is not repeated as a DNS SAN (RFC 6125).
pub fn cn_in_sans_finding(cn: Option<&str>, sans: &[String]) -> Option<Finding> {
    let cn = cn?;
    let cn_lower = cn.to_lowercase();
    let present = sans
        .iter()
        .any(|san| san.strip_prefix("DNS:").is_some_and(|d| d.to_lowercase() == cn_lower));
    if present {
        None
    } else {
        Some(Finding::new(
            Severity::Warning,
            "SAN",
            format!(
                "Common Name '{cn}' is not included in SANs. Per RFC 6125, the CN should also be present as a SAN."
            ),
        ))
    }
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
    let issuer_private = chain_looks_private(infos);

    for info in infos {
        let is_leaf = info.index == 0;
        let findings = check_certificate_compliance(info, is_leaf, issuer_private);
        let compliant = is_compliant(&findings);
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

/// Best effort guess that the chain was issued by a private CA rather than a
/// publicly trusted one, from the information a [`CertInfo`] slice carries.
///
/// Root trust classification lives in `trust.rs` and is not reachable from
/// here, so the heuristic is: the top certificate is self issued (subject
/// equals issuer) and is not flagged as a recognised public root. That covers
/// a lone self signed leaf and a chain that ends in a private root. When the
/// server omits its root (the usual case for public chains) the top is an
/// intermediate and the chain is treated as public.
fn chain_looks_private(infos: &[CertInfo]) -> bool {
    infos
        .last()
        .is_some_and(|top| top.subject == top.issuer && top.is_public_root != Some(true))
}

/// Whether the certificate is a CA (basicConstraints CA=true, or a non leaf
/// position in the chain when the extension was not parsed).
fn is_ca_certificate(info: &CertInfo, is_leaf: bool) -> bool {
    match &info.basic_constraints {
        Some(bc) => bc.ca,
        None => !is_leaf,
    }
}

/// Run all compliance checks for a single certificate. `issuer_private` is
/// the chain level guess from [`chain_looks_private`]; it only softens the
/// validity period verdict, because the SC-081 limits bind publicly trusted
/// CAs and not private PKIs.
fn check_certificate_compliance(info: &CertInfo, is_leaf: bool, issuer_private: bool) -> Vec<CertFinding> {
    let mut findings = Vec::new();

    check_key_compliance(info, is_leaf, &mut findings);
    check_signature_algorithm(info, &mut findings);
    check_expiry_compliance(info, &mut findings);
    check_validity_period(info, is_leaf, issuer_private, &mut findings);
    check_certificate_transparency(info, &mut findings);

    if is_leaf {
        check_san_compliance(info, &mut findings);
        check_eku_compliance(info, &mut findings);
        check_revocation_pointers(info, &mut findings);
    } else {
        check_ca_compliance(info, &mut findings);
    }

    findings
}

// ---------------------------------------------------------------------------
// Individual compliance checks
// ---------------------------------------------------------------------------

/// Check public key algorithm and size against CA/B Forum requirements. For
/// a leaf with a classical key, one post quantum migration note is added.
fn check_key_compliance(info: &CertInfo, is_leaf: bool, findings: &mut Vec<CertFinding>) {
    match (&info.public_key_algorithm, info.public_key_size_bits) {
        (Some(alg), Some(bits)) => {
            findings.extend(key_size_findings(alg, bits));
            if is_leaf {
                findings.extend(post_quantum_migration_finding(alg));
            }
        }
        _ => findings.push(Finding::new(
            Severity::Info,
            "Key Size",
            "Public key information not available (use --extensions to extract)",
        )),
    }
}

/// Check signature algorithm: SHA-1, MD5 and MD2 are rejected (CA/Browser
/// Forum ballot SC-097 sunsets SHA-1 everywhere in certificates and CRLs),
/// SHA-2 families and EdDSA are compliant, and the NIST post quantum
/// signatures (ML-DSA, FIPS 204; SLH-DSA, FIPS 205) are reported by name.
fn check_signature_algorithm(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    let sig_alg = match &info.signature_algorithm {
        Some(alg) => alg.as_str(),
        None => return, // not available
    };

    if let Some(name) = crate::cert::slh_dsa_name(sig_alg) {
        findings.push(CertFinding {
            severity: Severity::Info,
            category: "Signature Algorithm".to_string(),
            message: format!("{name}: post quantum signature (FIPS 205)"),
        });
        return;
    }

    // OID-based detection
    let (name, severity, msg) = match sig_alg {
        // SHA-1 with RSA (PKCS #1 and the older OIW arc)
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => ("SHA-1 with RSA", Severity::Error, SHA1_MESSAGE),
        // ECDSA with SHA-1
        "1.2.840.10045.4.1" => ("ECDSA with SHA-1", Severity::Error, SHA1_MESSAGE),
        // DSA with SHA-1 (X9.57 and the older OIW arc)
        "1.2.840.10040.4.3" | "1.3.14.3.2.27" => ("DSA with SHA-1", Severity::Error, SHA1_MESSAGE),
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
        "1.3.101.112" => (
            "Ed25519",
            Severity::Info,
            "Compliant signature algorithm (RFC 8410 EdDSA)",
        ),
        // Ed448
        "1.3.101.113" => (
            "Ed448",
            Severity::Info,
            "Compliant signature algorithm (RFC 8410 EdDSA)",
        ),
        // ML-DSA (FIPS 204), pure variants
        "2.16.840.1.101.3.4.3.17" => (
            "ML-DSA-44",
            Severity::Info,
            "post quantum signature (FIPS 204, RFC 9881)",
        ),
        "2.16.840.1.101.3.4.3.18" => (
            "ML-DSA-65",
            Severity::Info,
            "post quantum signature (FIPS 204, RFC 9881)",
        ),
        "2.16.840.1.101.3.4.3.19" => (
            "ML-DSA-87",
            Severity::Info,
            "post quantum signature (FIPS 204, RFC 9881)",
        ),
        // HashML-DSA (FIPS 204 pre hash variants)
        "2.16.840.1.101.3.4.3.32" => (
            "HashML-DSA-44 with SHA-512",
            Severity::Info,
            "post quantum signature (FIPS 204 pre hash variant, RFC 9881)",
        ),
        "2.16.840.1.101.3.4.3.33" => (
            "HashML-DSA-65 with SHA-512",
            Severity::Info,
            "post quantum signature (FIPS 204 pre hash variant, RFC 9881)",
        ),
        "2.16.840.1.101.3.4.3.34" => (
            "HashML-DSA-87 with SHA-512",
            Severity::Info,
            "post quantum signature (FIPS 204 pre hash variant, RFC 9881)",
        ),
        _ => {
            findings.push(CertFinding {
                severity: Severity::Info,
                category: "Signature Algorithm".to_string(),
                message: format!("Signature algorithm OID: {sig_alg}"),
            });
            return;
        }
    };

    findings.push(CertFinding {
        severity,
        category: "Signature Algorithm".to_string(),
        message: format!("{name}: {msg}"),
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
                message: format!("Certificate expires in {} days ({})", days_left, info.not_after),
            });
        } else {
            findings.push(CertFinding {
                severity: Severity::Info,
                category: "Expiry".to_string(),
                message: format!("Certificate valid for {days_left} more days"),
            });
        }
    }
}

/// Check the validity period against the CA/Browser Forum ballot SC-081v3
/// schedule (see [`max_subscriber_validity_days`]).
///
/// The limit binds subscriber certificates issued by publicly trusted CAs.
/// CA certificates are exempt and get an Info finding only. A leaf over the
/// limit is an Error, downgraded to a Warning when the chain looks privately
/// issued (`issuer_private`, see [`chain_looks_private`]) because a private
/// PKI is not bound by the Baseline Requirements, though the same limits are
/// still good practice there.
fn check_validity_period(info: &CertInfo, is_leaf: bool, issuer_private: bool, findings: &mut Vec<CertFinding>) {
    let Some((not_before, validity_days)) = validity_days(info) else {
        return;
    };

    if is_ca_certificate(info, is_leaf) {
        findings.push(CertFinding {
            severity: Severity::Info,
            category: "Validity Period".to_string(),
            message: format!(
                "CA certificate validity period: {validity_days} days. The CA/Browser Forum ballot SC-081v3 \
                 limits apply to subscriber certificates, not CA certificates."
            ),
        });
        return;
    }

    let (limit, window) = max_subscriber_validity_days(not_before);
    if validity_days > limit {
        let (severity, suffix) = if issuer_private {
            (
                Severity::Warning,
                " This chain appears to be privately issued (self signed or anchored on a root outside the \
                 public root programs), so the limit is advisory and reported as a warning.",
            )
        } else {
            (Severity::Error, "")
        };
        findings.push(CertFinding {
            severity,
            category: "Validity Period".to_string(),
            message: format!(
                "Certificate validity of {validity_days} days exceeds the {limit} day maximum for subscriber \
                 certificates {window} (CA/Browser Forum ballot SC-081v3). The limit applies to publicly trusted \
                 certificates; browsers reject longer ones.{suffix}"
            ),
        });
    } else {
        findings.push(CertFinding {
            severity: Severity::Info,
            category: "Validity Period".to_string(),
            message: format!(
                "Certificate validity period: {validity_days} days, within the {limit} day limit for subscriber \
                 certificates {window} (CA/Browser Forum ballot SC-081v3; applies to publicly trusted certificates)"
            ),
        });
    }
}

/// Check the revocation pointers of a leaf certificate against CA/Browser
/// Forum ballot SC-063v4.
///
/// Short lived certificates (at most 10 days when issued before 2026-03-15,
/// at most 7 days from that date) are exempt from revocation checking and
/// need neither OCSP nor CRL. For every other subscriber certificate a CRL
/// distribution point has been mandatory since 2024-03-15, while OCSP became
/// optional on the same date, so a missing OCSP URL is not a warning when a
/// CRL is present. Nothing is reported when extensions were not parsed.
fn check_revocation_pointers(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    let (Some(ocsp), Some(crl)) = (&info.ocsp_urls, &info.crl_distribution_points) else {
        return; // extensions not extracted
    };
    if is_ca_certificate(info, true) {
        return;
    }
    let Some((not_before, validity_days)) = validity_days(info) else {
        return;
    };

    let short_lived_limit = short_lived_max_days(not_before);
    if validity_days <= short_lived_limit {
        findings.push(CertFinding {
            severity: Severity::Info,
            category: "Revocation".to_string(),
            message: format!(
                "Short lived certificate ({validity_days} days, at most {short_lived_limit} days for certificates \
                 {}): revocation checking not required, no OCSP responder or CRL distribution point is expected \
                 (CA/Browser Forum ballot SC-063v4)",
                if short_lived_limit == 7 {
                    "issued on or after 2026-03-15"
                } else {
                    "issued before 2026-03-15"
                }
            ),
        });
        return;
    }

    let (severity, message) = match (crl.is_empty(), ocsp.is_empty()) {
        (false, false) => (
            Severity::Info,
            format!(
                "Revocation pointers present: {} CRL distribution point(s) and {} OCSP responder URL(s) \
                 (CA/Browser Forum ballot SC-063v4)",
                crl.len(),
                ocsp.len()
            ),
        ),
        (false, true) => (
            Severity::Info,
            "No OCSP responder URL. OCSP has been optional for subscriber certificates since 2024-03-15 and a \
             CRL distribution point is present, which satisfies CA/Browser Forum ballot SC-063v4."
                .to_string(),
        ),
        (true, false) => (
            Severity::Warning,
            "No CRL distribution point. CRLs have been mandatory for subscriber certificates since 2024-03-15 \
             and an OCSP responder alone no longer satisfies the Baseline Requirements (CA/Browser Forum ballot \
             SC-063v4); only short lived certificates are exempt."
                .to_string(),
        ),
        (true, true) => (
            Severity::Warning,
            "No CRL distribution point and no OCSP responder URL. A subscriber certificate that is not short \
             lived must carry a CRL distribution point (CA/Browser Forum ballot SC-063v4, mandatory since \
             2024-03-15); relying parties cannot check revocation for this certificate."
                .to_string(),
        ),
    };
    findings.push(CertFinding {
        severity,
        category: "Revocation".to_string(),
        message,
    });
}

/// Check for Certificate Transparency SCTs (required by major browsers).
fn check_certificate_transparency(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    if info.ct_present {
        let sct_msg = match info.sct_count {
            Some(count) => format!("Certificate Transparency: {count} SCT(s) embedded (compliant with CT policy)"),
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
            message: format!("{} SAN(s) present", info.subject_alternative_names.len()),
        });

        // Check CN is in SANs
        findings.extend(cn_in_sans_finding(
            info.common_name.as_deref(),
            &info.subject_alternative_names,
        ));

        // Check for wildcard validity
        for san in &info.subject_alternative_names {
            if let Some(dns) = san.strip_prefix("DNS:")
                && dns.contains('*')
                && !dns.starts_with("*.")
            {
                findings.push(CertFinding {
                    severity: Severity::Error,
                    category: "SAN".to_string(),
                    message: format!(
                        "Invalid wildcard '{dns}': wildcards must only appear as the leftmost label (e.g., *.example.com)"
                    ),
                });
            }
        }
    }
}

/// Check Extended Key Usage for leaf certificates.
///
/// serverAuth is required. clientAuth alongside serverAuth is a Warning: the
/// Chrome Root Program policy requires publicly trusted CAs to issue
/// serverAuth only leaf certificates, and the large public CAs have stopped
/// adding clientAuth (Google Trust Services in April 2026, Let's Encrypt in
/// February 2026 with the tlsclient profile retired in July 2026).
fn check_eku_compliance(info: &CertInfo, findings: &mut Vec<CertFinding>) {
    match &info.extended_key_usage {
        Some(eku) => {
            let has_server_auth = eku.iter().any(|u| u == "serverAuth");
            let has_client_auth = eku.iter().any(|u| u == "clientAuth");
            if has_server_auth {
                findings.push(CertFinding {
                    severity: Severity::Info,
                    category: "Extended Key Usage".to_string(),
                    message: "serverAuth present (required for TLS server certificates)".to_string(),
                });
                if has_client_auth && !is_ca_certificate(info, true) {
                    findings.push(CertFinding {
                        severity: Severity::Warning,
                        category: "Extended Key Usage".to_string(),
                        message: "clientAuth present on a TLS server certificate. The Chrome Root Program policy \
                                  requires serverAuth only leaf certificates from publicly trusted CAs (Google \
                                  Trust Services stopped issuing clientAuth in April 2026, Let's Encrypt removed \
                                  it in February 2026 and retired the tlsclient profile in July 2026); mTLS client \
                                  identities should come from a private CA."
                            .to_string(),
                    });
                }
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
    if let Some(ref ku) = info.key_usage
        && !ku.iter().any(|u| u == "keyCertSign")
    {
        findings.push(CertFinding {
            severity: Severity::Warning,
            category: "Key Usage".to_string(),
            message: "CA certificate missing keyCertSign in Key Usage".to_string(),
        });
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
        check_key_compliance(&cert, true, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Error));
        assert!(findings.iter().any(|f| f.message.contains("below the minimum")));
    }

    #[test]
    fn test_key_rsa_2048_warning() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.public_key_size_bits = Some(2048);
        let mut findings = Vec::new();
        check_key_compliance(&cert, true, &mut findings);
        assert!(findings.iter().any(|f| f.severity == Severity::Warning));
    }

    #[test]
    fn test_key_rsa_4096_ok() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.public_key_size_bits = Some(4096);
        let mut findings = Vec::new();
        check_key_compliance(&cert, true, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Error));
        assert!(findings.iter().any(|f| f.severity == Severity::Info));
    }

    #[test]
    fn test_key_ec_256_ok() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.public_key_algorithm = Some("EC".to_string());
        cert.public_key_size_bits = Some(256);
        let mut findings = Vec::new();
        check_key_compliance(&cert, true, &mut findings);
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
        cert.not_after = "2026-12-31T00:00:00Z".to_string(); // ~365 days, 398 day window
        let mut findings = Vec::new();
        check_validity_period(&cert, true, false, &mut findings);
        assert!(
            !findings
                .iter()
                .any(|f| f.severity == Severity::Warning || f.severity == Severity::Error)
        );
        assert!(findings.iter().any(|f| f.message.contains("398 day limit")));
        assert!(findings.iter().any(|f| f.message.contains("SC-081v3")));
    }

    #[test]
    fn test_validity_period_exceeds_limit_is_error_for_public_leaf() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.not_before = "2026-01-01T00:00:00Z".to_string();
        cert.not_after = "2028-01-01T00:00:00Z".to_string(); // ~730 days
        let mut findings = Vec::new();
        check_validity_period(&cert, true, false, &mut findings);
        let f = findings
            .iter()
            .find(|f| f.category == "Validity Period")
            .expect("validity finding");
        assert_eq!(f.severity, Severity::Error);
        assert!(f.message.contains("398 day maximum"));
        assert!(f.message.contains("SC-081v3"));
        assert!(f.message.contains("publicly trusted"));
    }

    #[test]
    fn test_validity_period_exceeds_limit_is_warning_when_privately_issued() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.not_before = "2026-01-01T00:00:00Z".to_string();
        cert.not_after = "2028-01-01T00:00:00Z".to_string();
        let mut findings = Vec::new();
        check_validity_period(&cert, true, true, &mut findings);
        let f = findings
            .iter()
            .find(|f| f.category == "Validity Period")
            .expect("validity finding");
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.message.contains("privately issued"));
    }

    #[test]
    fn test_sc081_schedule_by_issuance_date() {
        let at = |s: &str| OffsetDateTime::parse(s, &Rfc3339).unwrap();
        assert_eq!(max_subscriber_validity_days(at("2025-12-31T23:59:59Z")).0, 398);
        assert_eq!(max_subscriber_validity_days(at("2026-03-14T23:59:59Z")).0, 398);
        assert_eq!(max_subscriber_validity_days(at("2026-03-15T00:00:00Z")).0, 200);
        assert_eq!(max_subscriber_validity_days(at("2027-03-14T23:59:59Z")).0, 200);
        assert_eq!(max_subscriber_validity_days(at("2027-03-15T00:00:00Z")).0, 100);
        assert_eq!(max_subscriber_validity_days(at("2029-03-14T23:59:59Z")).0, 100);
        assert_eq!(max_subscriber_validity_days(at("2029-03-15T00:00:00Z")).0, 47);
        assert_eq!(max_subscriber_validity_days(at("2031-01-01T00:00:00Z")).0, 47);
    }

    #[test]
    fn test_validity_200_day_window_flags_365_day_leaf() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.not_before = "2026-06-01T00:00:00Z".to_string();
        cert.not_after = "2027-06-01T00:00:00Z".to_string(); // 365 days, 200 day window
        let mut findings = Vec::new();
        check_validity_period(&cert, true, false, &mut findings);
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Error);
        assert!(f.message.contains("200 day maximum"), "{}", f.message);
        assert!(f.message.contains("2026-03-15"), "{}", f.message);
    }

    #[test]
    fn test_validity_100_and_47_day_windows() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.not_before = "2027-06-01T00:00:00Z".to_string();
        cert.not_after = "2027-09-30T00:00:00Z".to_string(); // 121 days, 100 day window
        let mut findings = Vec::new();
        check_validity_period(&cert, true, false, &mut findings);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("100 day maximum"));

        cert.not_before = "2029-06-01T00:00:00Z".to_string();
        cert.not_after = "2029-07-31T00:00:00Z".to_string(); // 60 days, 47 day window
        let mut findings = Vec::new();
        check_validity_period(&cert, true, false, &mut findings);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("47 day maximum"));

        cert.not_after = "2029-07-15T00:00:00Z".to_string(); // 44 days, fine
        let mut findings = Vec::new();
        check_validity_period(&cert, true, false, &mut findings);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("47 day limit"));
    }

    #[test]
    fn test_validity_period_ca_certificates_are_exempt() {
        let mut ca = make_ca_cert();
        ca.not_before = "2026-06-01T00:00:00Z".to_string();
        ca.not_after = "2046-06-01T00:00:00Z".to_string(); // 20 years
        let mut findings = Vec::new();
        check_validity_period(&ca, false, false, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("CA certificate"));

        // A CA=true certificate at index 0 (a lone root) is also exempt.
        ca.index = 0;
        let mut findings = Vec::new();
        check_validity_period(&ca, true, false, &mut findings);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_validity_period_unparseable_dates_are_skipped() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.not_before = "not a date".to_string();
        let mut findings = Vec::new();
        check_validity_period(&cert, true, false, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_chain_looks_private_heuristic() {
        // Self signed leaf: private.
        let mut leaf = make_leaf_cert_with_extensions();
        leaf.issuer = leaf.subject.clone();
        assert!(chain_looks_private(std::slice::from_ref(&leaf)));
        // Leaf plus intermediate, root not sent: treated as public. The
        // fixture CA is self issued, so give it an upstream issuer here.
        let leaf = make_leaf_cert_with_extensions();
        let mut ca = make_ca_cert();
        ca.issuer = "CN=Upstream Root".to_string();
        assert!(!chain_looks_private(&[leaf.clone(), ca.clone()]));
        // Chain ending in a self issued root that is not a known public root: private.
        let mut root = make_ca_cert();
        root.index = 2;
        root.subject = "CN=Private Root".to_string();
        root.issuer = root.subject.clone();
        assert!(chain_looks_private(&[leaf.clone(), ca.clone(), root.clone()]));
        // Same root flagged as a recognised public root: public.
        root.is_public_root = Some(true);
        assert!(!chain_looks_private(&[leaf, ca, root]));
        assert!(!chain_looks_private(&[]));
    }

    #[test]
    fn test_chain_report_private_self_signed_leaf_over_limit_is_warning() {
        let mut leaf = make_leaf_cert_with_extensions();
        leaf.issuer = leaf.subject.clone();
        leaf.not_before = "2026-06-01T00:00:00Z".to_string();
        leaf.not_after = "2028-06-01T00:00:00Z".to_string();
        let report = check_chain_compliance(std::slice::from_ref(&leaf));
        let f = report.certificates[0]
            .findings
            .iter()
            .find(|f| f.category == "Validity Period")
            .expect("validity finding");
        assert_eq!(f.severity, Severity::Warning);
        assert!(report.chain_compliant);
    }

    // ---------------------------------------------------------------
    // Revocation pointer tests (SC-063v4)
    // ---------------------------------------------------------------

    fn revocation_findings(cert: &CertInfo) -> Vec<CertFinding> {
        let mut findings = Vec::new();
        check_revocation_pointers(cert, &mut findings);
        findings.retain(|f| f.category == "Revocation");
        findings
    }

    #[test]
    fn test_revocation_skipped_when_extensions_not_parsed() {
        let cert = make_leaf_cert_with_extensions();
        assert!(cert.ocsp_urls.is_none());
        assert!(revocation_findings(&cert).is_empty());
    }

    #[test]
    fn test_revocation_short_lived_is_exempt() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.ocsp_urls = Some(vec![]);
        cert.crl_distribution_points = Some(vec![]);
        // 7 day certificate issued after 2026-03-15: short lived.
        cert.not_before = "2026-06-01T00:00:00Z".to_string();
        cert.not_after = "2026-06-07T23:59:59Z".to_string();
        let f = revocation_findings(&cert);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].message.contains("revocation checking not required"));
        assert!(f[0].message.contains("SC-063v4"));

        // 10 day certificate issued before 2026-03-15: short lived.
        cert.not_before = "2026-01-01T00:00:00Z".to_string();
        cert.not_after = "2026-01-10T23:59:59Z".to_string();
        let f = revocation_findings(&cert);
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].message.contains("Short lived"));

        // 10 day certificate issued after 2026-03-15: no longer short lived, and
        // it carries no pointers at all, so that is a warning.
        cert.not_before = "2026-06-01T00:00:00Z".to_string();
        cert.not_after = "2026-06-10T23:59:59Z".to_string();
        let f = revocation_findings(&cert);
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].message.contains("No CRL distribution point and no OCSP"));
    }

    #[test]
    fn test_revocation_missing_ocsp_with_crl_is_info() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.ocsp_urls = Some(vec![]);
        cert.crl_distribution_points = Some(vec!["http://crl.example.com/ca.crl".to_string()]);
        let f = revocation_findings(&cert);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].message.contains("OCSP has been optional"));
    }

    #[test]
    fn test_revocation_missing_crl_is_warning_even_with_ocsp() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.ocsp_urls = Some(vec!["http://ocsp.example.com".to_string()]);
        cert.crl_distribution_points = Some(vec![]);
        let f = revocation_findings(&cert);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].message.contains("No CRL distribution point"));
        assert!(f[0].message.contains("2024-03-15"));
    }

    #[test]
    fn test_revocation_both_present_is_info() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.ocsp_urls = Some(vec!["http://ocsp.example.com".to_string()]);
        cert.crl_distribution_points = Some(vec!["http://crl.example.com/ca.crl".to_string()]);
        let f = revocation_findings(&cert);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn test_revocation_not_checked_for_ca_certificates() {
        let mut ca = make_ca_cert();
        ca.ocsp_urls = Some(vec![]);
        ca.crl_distribution_points = Some(vec![]);
        assert!(revocation_findings(&ca).is_empty());
    }

    #[test]
    fn test_short_lived_threshold_dates() {
        let at = |s: &str| OffsetDateTime::parse(s, &Rfc3339).unwrap();
        assert_eq!(short_lived_max_days(at("2026-03-14T23:59:59Z")), 10);
        assert_eq!(short_lived_max_days(at("2026-03-15T00:00:00Z")), 7);
    }

    // ---------------------------------------------------------------
    // CT compliance tests
    // ---------------------------------------------------------------

    #[test]
    fn test_ct_present() {
        let cert = make_leaf_cert_with_extensions();
        let mut findings = Vec::new();
        check_certificate_transparency(&cert, &mut findings);
        assert!(
            !findings
                .iter()
                .any(|f| f.severity == Severity::Warning || f.severity == Severity::Error)
        );
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
        assert!(
            !findings
                .iter()
                .any(|f| f.severity == Severity::Error || f.severity == Severity::Warning)
        );
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
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Warning && f.category == "SAN")
        );
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
        assert!(
            !findings
                .iter()
                .any(|f| f.severity == Severity::Error || f.severity == Severity::Warning)
        );
    }

    #[test]
    fn test_ca_cert_missing_key_cert_sign() {
        let mut cert = make_ca_cert();
        cert.key_usage = Some(vec!["digitalSignature".to_string()]);
        let mut findings = Vec::new();
        check_ca_compliance(&cert, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Warning && f.message.contains("keyCertSign"))
        );
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

    // ---------------------------------------------------------------
    // SHA-1 variants (SC-097) and post quantum signature algorithms
    // ---------------------------------------------------------------

    #[test]
    fn test_sig_sha1_ecdsa_and_dsa_are_errors_citing_sc097() {
        for oid in [
            "1.2.840.10045.4.1",
            "1.2.840.10040.4.3",
            "1.2.840.113549.1.1.5",
            "1.3.14.3.2.29",
        ] {
            let mut cert = make_leaf_cert_with_extensions();
            cert.signature_algorithm = Some(oid.to_string());
            let mut findings = Vec::new();
            check_signature_algorithm(&cert, &mut findings);
            assert_eq!(findings.len(), 1, "{oid}");
            assert_eq!(findings[0].severity, Severity::Error, "{oid}");
            assert!(findings[0].message.contains("SHA-1"), "{oid}: {}", findings[0].message);
            assert!(findings[0].message.contains("SC-097"), "{oid}: {}", findings[0].message);
        }
        let mut cert = make_leaf_cert_with_extensions();
        cert.signature_algorithm = Some("1.2.840.10045.4.1".to_string());
        let mut findings = Vec::new();
        check_signature_algorithm(&cert, &mut findings);
        assert!(findings[0].message.starts_with("ECDSA with SHA-1"));
    }

    #[test]
    fn test_sig_name_sha1_cites_sc097() {
        let f = signature_name_finding("ecdsa-with-SHA1").expect("finding");
        assert_eq!(f.severity, Severity::Error);
        assert!(f.message.contains("SC-097"));
        let f = signature_name_finding("ML-DSA-65").expect("finding");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.message.contains("FIPS 204"));
        let f = signature_name_finding("SLH-DSA-SHA2-128s").expect("finding");
        assert!(f.message.contains("FIPS 205"));
    }

    #[test]
    fn test_sig_ml_dsa_is_post_quantum_info() {
        for (oid, name) in [
            ("2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
            ("2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
            ("2.16.840.1.101.3.4.3.19", "ML-DSA-87"),
        ] {
            let mut cert = make_leaf_cert_with_extensions();
            cert.signature_algorithm = Some(oid.to_string());
            let mut findings = Vec::new();
            check_signature_algorithm(&cert, &mut findings);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Info);
            assert!(findings[0].message.starts_with(name), "{}", findings[0].message);
            assert!(
                findings[0].message.contains("FIPS 204, RFC 9881"),
                "{}",
                findings[0].message
            );
        }
    }

    #[test]
    fn test_sig_slh_dsa_is_post_quantum_info() {
        for last in 20..=31 {
            let mut cert = make_leaf_cert_with_extensions();
            cert.signature_algorithm = Some(format!("2.16.840.1.101.3.4.3.{last}"));
            let mut findings = Vec::new();
            check_signature_algorithm(&cert, &mut findings);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Info);
            assert!(findings[0].message.starts_with("SLH-DSA-"), "{}", findings[0].message);
            assert!(findings[0].message.contains("FIPS 205"), "{}", findings[0].message);
        }
    }

    #[test]
    fn test_sig_eddsa_is_compliant_info() {
        for oid in ["1.3.101.112", "1.3.101.113"] {
            let mut cert = make_leaf_cert_with_extensions();
            cert.signature_algorithm = Some(oid.to_string());
            let mut findings = Vec::new();
            check_signature_algorithm(&cert, &mut findings);
            assert_eq!(findings[0].severity, Severity::Info);
            assert!(findings[0].message.contains("Compliant"));
        }
    }

    #[test]
    fn test_sig_unknown_oid_is_info() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.signature_algorithm = Some("1.2.3.4".to_string());
        let mut findings = Vec::new();
        check_signature_algorithm(&cert, &mut findings);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("1.2.3.4"));
    }

    // ---------------------------------------------------------------
    // Post quantum keys and the migration note
    // ---------------------------------------------------------------

    #[test]
    fn test_key_ml_dsa_is_info_without_migration_note() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.public_key_algorithm = Some("ML-DSA-65".to_string());
        cert.public_key_size_bits = Some(1952 * 8);
        let mut findings = Vec::new();
        check_key_compliance(&cert, true, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("ML-DSA-65"));
        assert!(findings[0].message.contains("FIPS 204"));
        assert!(!findings.iter().any(|f| f.message.contains("NIST IR 8547")));
    }

    #[test]
    fn test_key_slh_dsa_ml_kem_and_eddsa_are_info() {
        for (alg, needle) in [
            ("SLH-DSA-SHAKE-128s", "FIPS 205"),
            ("ML-KEM-768", "FIPS 203"),
            ("Ed25519", "meets requirements"),
            ("Ed448", "meets requirements"),
        ] {
            let findings = key_size_findings(alg, 256);
            assert_eq!(findings.len(), 1, "{alg}");
            assert_eq!(findings[0].severity, Severity::Info, "{alg}");
            assert!(findings[0].message.contains(needle), "{alg}: {}", findings[0].message);
        }
    }

    #[test]
    fn test_key_classical_leaf_gets_one_migration_note() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.public_key_algorithm = Some("RSA".to_string());
        cert.public_key_size_bits = Some(4096);
        let mut findings = Vec::new();
        check_key_compliance(&cert, true, &mut findings);
        let notes: Vec<_> = findings.iter().filter(|f| f.message.contains("NIST IR 8547")).collect();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].severity, Severity::Info);
        assert!(notes[0].message.contains("2030") && notes[0].message.contains("2035"));

        cert.public_key_algorithm = Some("EC".to_string());
        cert.public_key_size_bits = Some(256);
        let mut findings = Vec::new();
        check_key_compliance(&cert, true, &mut findings);
        assert_eq!(
            findings.iter().filter(|f| f.message.contains("NIST IR 8547")).count(),
            1
        );
    }

    #[test]
    fn test_key_classical_ca_gets_no_migration_note() {
        let ca = make_ca_cert();
        let mut findings = Vec::new();
        check_key_compliance(&ca, false, &mut findings);
        assert!(!findings.iter().any(|f| f.message.contains("NIST IR 8547")));
    }

    #[test]
    fn test_chain_report_has_single_migration_note_per_leaf() {
        let leaf = make_leaf_cert_with_extensions();
        let ca = make_ca_cert();
        let report = check_chain_compliance(&[leaf, ca]);
        let count = |i: usize| {
            report.certificates[i]
                .findings
                .iter()
                .filter(|f| f.message.contains("NIST IR 8547"))
                .count()
        };
        assert_eq!(count(0), 1);
        assert_eq!(count(1), 0);
    }

    // ---------------------------------------------------------------
    // clientAuth on a server leaf
    // ---------------------------------------------------------------

    #[test]
    fn test_eku_client_auth_with_server_auth_is_warning() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.extended_key_usage = Some(vec!["serverAuth".to_string(), "clientAuth".to_string()]);
        let mut findings = Vec::new();
        check_eku_compliance(&cert, &mut findings);
        let w = findings
            .iter()
            .find(|f| f.severity == Severity::Warning)
            .expect("clientAuth warning");
        assert!(w.message.contains("clientAuth"));
        assert!(w.message.contains("Chrome Root Program"));
        assert!(w.message.contains("private CA"));
    }

    #[test]
    fn test_eku_client_auth_alone_is_missing_server_auth_not_client_auth_warning() {
        let mut cert = make_leaf_cert_with_extensions();
        cert.extended_key_usage = Some(vec!["clientAuth".to_string()]);
        let mut findings = Vec::new();
        check_eku_compliance(&cert, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("serverAuth not found"));
    }

    #[test]
    fn test_eku_client_auth_on_ca_is_not_warned() {
        let mut ca = make_ca_cert();
        ca.extended_key_usage = Some(vec!["serverAuth".to_string(), "clientAuth".to_string()]);
        let mut findings = Vec::new();
        check_eku_compliance(&ca, &mut findings);
        assert!(!findings.iter().any(|f| f.severity == Severity::Warning));
    }
}
