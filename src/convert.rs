use anyhow::{Context, Result};
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::{X509, X509NameRef};
use std::fs;
use x509_parser::prelude::FromDer;

/// Role of a certificate within a chain — used to surface clear, beginner-friendly
/// guidance when building keystores and truststores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertRole {
    /// Self-signed CA (subject == issuer, BasicConstraints CA:TRUE).
    RootCa,
    /// CA that is not self-signed (BasicConstraints CA:TRUE, signed by another CA).
    IntermediateCa,
    /// Server / client / end-entity certificate (BasicConstraints CA:FALSE or absent).
    Leaf,
}

impl CertRole {
    /// Human-readable bracket label used in pre-flight summaries.
    pub fn label(self) -> &'static str {
        match self {
            Self::RootCa => "ROOT",
            Self::IntermediateCa => "INTERMEDIATE",
            Self::Leaf => "LEAF",
        }
    }

    pub fn is_ca(self) -> bool {
        matches!(self, Self::RootCa | Self::IntermediateCa)
    }
}

/// Classify an `X509` certificate as a root CA, intermediate CA, or leaf.
///
/// Reads the BasicConstraints extension via the parsed-cert path. If the
/// extension is absent we assume `CA:FALSE` (the legacy default for end-entity
/// certs). Self-signed is determined by structural subject == issuer match.
pub fn classify_cert(cert: &X509) -> CertRole {
    let der = match cert.to_der() {
        Ok(d) => d,
        Err(_) => return CertRole::Leaf,
    };
    let parsed = match x509_parser::certificate::X509Certificate::from_der(&der) {
        Ok((_, c)) => c,
        Err(_) => return CertRole::Leaf,
    };
    let mut is_ca = false;
    for ext in parsed.extensions() {
        if let x509_parser::extensions::ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
            is_ca = bc.ca;
            break;
        }
    }
    if !is_ca {
        return CertRole::Leaf;
    }
    if parsed.subject() == parsed.issuer() {
        CertRole::RootCa
    } else {
        CertRole::IntermediateCa
    }
}

/// Collect the entries of an `X509Name` into a comma-separated `KEY=value` string
/// (Subject CN, O, OU, …). Folds the four duplicate copies that previously
/// lived inline in convert.rs and tls.rs into a single helper.
pub fn format_x509_name(name: &X509NameRef) -> String {
    name.entries().fold(String::new(), |mut acc, e| {
        if !acc.is_empty() {
            acc.push_str(", ");
        }
        if let Ok(data) = e.data().as_utf8() {
            acc.push_str(data.as_ref());
        }
        acc
    })
}

/// Lightweight summary of a single certificate, used in pre-flight tables and
/// JSON `cert_roles` arrays.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertSummary {
    pub role: CertRole,
    pub subject: String,
    pub issuer: String,
    /// `not_after` formatted as `YYYY-MM-DD` for the table; empty if parse fails.
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub expired: bool,
}

fn cert_summary(cert: &X509) -> Result<CertSummary> {
    let role = classify_cert(cert);
    let subject = format_x509_name(cert.subject_name());
    let issuer = format_x509_name(cert.issuer_name());
    let der = cert
        .to_der()
        .map_err(|e| anyhow::anyhow!("DER conversion failed: {e}"))?;
    let digest =
        openssl::hash::hash(MessageDigest::sha256(), &der).map_err(|e| anyhow::anyhow!("SHA-256 hash failed: {e}"))?;
    let fingerprint_sha256 = digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    let (not_after, expired) = match x509_parser::certificate::X509Certificate::from_der(&der) {
        Ok((_, parsed)) => {
            let na = parsed.validity().not_after.to_datetime();
            let now = time::OffsetDateTime::now_utc();
            let formatted = format!("{:04}-{:02}-{:02}", na.year(), u8::from(na.month()), na.day());
            (formatted, na < now)
        }
        Err(_) => (String::new(), false),
    };

    Ok(CertSummary {
        role,
        subject,
        issuer,
        not_after,
        fingerprint_sha256,
        expired,
    })
}

#[derive(Debug, serde::Serialize)]
pub struct ConvertResult {
    pub input_format: String,
    pub output_format: String,
    pub output_files: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    pub ca_certs_count: usize,
    /// Pre-flight summary of each certificate in the operation. Always present
    /// for `create-truststore` and `create-keystore` so machine consumers
    /// (including the MCP layer) can surface role/expiry/fingerprint info
    /// without re-parsing PEM.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cert_roles: Vec<CertSummary>,
    /// Beginner-friendly warnings produced while validating the input — e.g.
    /// "leaf cert in truststore", "missing chain in keystore", "duplicate CA",
    /// "rotation: same CN, different fingerprint".
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

/// Convert a PKCS12/PFX file to PEM certificate + key files.
pub fn pfx_to_pem(input: &str, password: &str, output_dir: &str) -> Result<ConvertResult> {
    let p12_data = fs::read(input).with_context(|| format!("Failed to read PKCS12 file: {}", input))?;

    let pkcs12 = Pkcs12::from_der(&p12_data).with_context(|| format!("Failed to parse PKCS12 file: {}", input))?;

    let parsed = pkcs12
        .parse2(password)
        .with_context(|| format!("Failed to decrypt PKCS12 '{}' (wrong password?)", input))?;

    // Ensure output directory exists
    fs::create_dir_all(output_dir).with_context(|| format!("Failed to create output directory: {}", output_dir))?;

    let mut output_files = Vec::new();
    let mut cert_subject = None;
    let mut key_type = None;

    // Write certificate
    if let Some(ref cert) = parsed.cert {
        let cert_pem = cert.to_pem().with_context(|| "Failed to encode certificate as PEM")?;
        let cert_path = format!("{}/cert.pem", output_dir);
        fs::write(&cert_path, &cert_pem).with_context(|| format!("Failed to write certificate: {}", cert_path))?;
        output_files.push(cert_path);

        cert_subject = Some(format_x509_name(cert.subject_name()));
    }

    // Write private key
    if let Some(ref pkey) = parsed.pkey {
        let key_pem = pkey
            .private_key_to_pem_pkcs8()
            .with_context(|| "Failed to encode private key as PEM")?;
        let key_path = format!("{}/key.pem", output_dir);
        fs::write(&key_path, &key_pem).with_context(|| format!("Failed to write private key: {}", key_path))?;
        restrict_file_permissions(&key_path);
        output_files.push(key_path);

        key_type = Some(key_type_name(pkey));
    }

    // Write CA certificates
    let ca_count = parsed.ca.as_ref().map(|c| c.len()).unwrap_or(0);
    if let Some(ref ca_chain) = parsed.ca
        && !ca_chain.is_empty()
    {
        let mut ca_pem = String::new();
        for ca_cert in ca_chain {
            let pem_bytes = ca_cert
                .to_pem()
                .with_context(|| "Failed to encode CA certificate as PEM")?;
            ca_pem.push_str(&String::from_utf8_lossy(&pem_bytes));
        }
        let ca_path = format!("{}/ca.pem", output_dir);
        fs::write(&ca_path, &ca_pem).with_context(|| format!("Failed to write CA certificates: {}", ca_path))?;
        output_files.push(ca_path);
    }

    Ok(ConvertResult {
        input_format: "PKCS12/PFX".to_string(),
        output_format: "PEM".to_string(),
        output_files,
        cert_subject,
        key_type,
        ca_certs_count: ca_count,
        cert_roles: Vec::new(),
        warnings: Vec::new(),
    })
}

/// Convert PEM certificate + key to PKCS12/PFX file.
pub fn pem_to_pfx(
    cert_path: &str,
    key_path: &str,
    password: &str,
    output: &str,
    ca_path: Option<&str>,
) -> Result<ConvertResult> {
    let cert_pem = fs::read(cert_path).with_context(|| format!("Failed to read certificate file: {}", cert_path))?;
    let key_pem = fs::read(key_path).with_context(|| format!("Failed to read private key file: {}", key_path))?;

    let cert = X509::from_pem(&cert_pem).with_context(|| format!("Failed to parse PEM certificate: {}", cert_path))?;
    let pkey = PKey::private_key_from_pem(&key_pem)
        .with_context(|| format!("Failed to parse PEM private key: {}", key_path))?;

    let cert_subject = format_x509_name(cert.subject_name());

    let key_type = key_type_name(&pkey);

    let mut builder = Pkcs12::builder();
    builder.name("dcert-export");
    builder.pkey(&pkey);
    builder.cert(&cert);

    let mut ca_count = 0;
    if let Some(ca_file) = ca_path {
        let ca_pem = fs::read(ca_file).with_context(|| format!("Failed to read CA certificate file: {}", ca_file))?;
        let ca_certs =
            X509::stack_from_pem(&ca_pem).with_context(|| format!("Failed to parse CA certificates: {}", ca_file))?;
        ca_count = ca_certs.len();
        builder.ca(vec_to_stack(ca_certs)?);
    }

    let pkcs12 = builder.build2(password).with_context(|| "Failed to build PKCS12")?;
    let der = pkcs12.to_der().with_context(|| "Failed to serialize PKCS12 to DER")?;
    fs::write(output, &der).with_context(|| format!("Failed to write PKCS12 file: {}", output))?;
    // PFX contains private key material — restrict file permissions
    restrict_file_permissions(output);

    Ok(ConvertResult {
        input_format: "PEM".to_string(),
        output_format: "PKCS12/PFX".to_string(),
        output_files: vec![output.to_string()],
        cert_subject: Some(cert_subject),
        key_type: Some(key_type),
        ca_certs_count: ca_count,
        cert_roles: Vec::new(),
        warnings: Vec::new(),
    })
}

/// Create a PKCS12 keystore from a private key + certificate (Java-compatible since JDK 9).
///
/// Validates the input shape and returns beginner-friendly warnings (in
/// `ConvertResult.warnings`) when:
/// - Only a leaf cert is supplied without intermediates (Java clients usually
///   need the full issuer chain).
/// - The first cert in the PEM is a CA rather than the leaf (wrong order).
pub fn create_keystore(
    cert_path: &str,
    key_path: &str,
    password: &str,
    output: &str,
    alias: &str,
) -> Result<ConvertResult> {
    let cert_pem = fs::read(cert_path).with_context(|| format!("Failed to read certificate file: {}", cert_path))?;
    let key_pem = fs::read(key_path).with_context(|| format!("Failed to read private key file: {}", key_path))?;

    let certs =
        X509::stack_from_pem(&cert_pem).with_context(|| format!("Failed to parse PEM certificates: {}", cert_path))?;

    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in: {}", cert_path));
    }

    let pkey = PKey::private_key_from_pem(&key_pem)
        .with_context(|| format!("Failed to parse PEM private key: {}", key_path))?;

    let leaf_cert = &certs[0];
    let cert_subject = format_x509_name(leaf_cert.subject_name());
    let key_type = key_type_name(&pkey);

    // Build pre-flight summary of every cert in the input.
    let mut summaries: Vec<CertSummary> = Vec::with_capacity(certs.len());
    for cert in &certs {
        summaries.push(cert_summary(cert)?);
    }

    // Beginner-friendly warnings: surface common keystore mistakes.
    let mut warnings: Vec<String> = Vec::new();
    let leaf_role = summaries[0].role;
    if leaf_role.is_ca() {
        warnings.push(format!(
            "First certificate in --cert appears to be a {} (CA), not the server's leaf certificate. \
             The leaf cert must come first; CA certs follow. Re-export with the leaf at the top of the PEM.",
            leaf_role.label()
        ));
    }
    if certs.len() == 1 && leaf_role == CertRole::Leaf {
        warnings.push(
            "Only a leaf certificate was supplied. Java clients usually need the full issuer chain — \
             concatenate the issuing CA(s) into --cert (leaf first, then intermediates, optionally root)."
                .to_string(),
        );
    }
    for (idx, summary) in summaries.iter().enumerate() {
        if summary.expired {
            warnings.push(format!(
                "Certificate at position {} ({}) expired on {}. Java clients will reject the keystore identity.",
                idx, summary.subject, summary.not_after
            ));
        }
    }

    let mut builder = Pkcs12::builder();
    builder.name(alias);
    builder.pkey(&pkey);
    builder.cert(leaf_cert);

    // Add remaining certificates as CA chain
    let ca_count = if certs.len() > 1 {
        let ca_certs: Vec<X509> = certs[1..].to_vec();
        let count = ca_certs.len();
        builder.ca(vec_to_stack(ca_certs)?);
        count
    } else {
        0
    };

    let pkcs12 = builder
        .build2(password)
        .with_context(|| "Failed to build PKCS12 keystore")?;
    let der = pkcs12.to_der().with_context(|| "Failed to serialize keystore")?;
    fs::write(output, &der).with_context(|| format!("Failed to write keystore: {}", output))?;
    // Keystore contains private key material — restrict file permissions
    restrict_file_permissions(output);

    Ok(ConvertResult {
        input_format: "PEM".to_string(),
        output_format: "PKCS12 KeyStore".to_string(),
        output_files: vec![output.to_string()],
        cert_subject: Some(cert_subject),
        key_type: Some(key_type),
        ca_certs_count: ca_count,
        cert_roles: summaries,
        warnings,
    })
}

/// Create a PKCS12 truststore from CA certificates (Java-compatible since JDK 9).
///
/// By default, **rejects** any leaf (non-CA) certificate in the input with a
/// beginner-friendly error explaining why a server certificate doesn't belong
/// in a truststore. Pass `allow_non_ca = true` to override (the MCP layer
/// defaults to `true` to preserve its previous "build whatever you give me"
/// semantics; the CLI defaults to `false` so non-expert users get loud,
/// actionable feedback instead of a silently-wrong truststore).
///
/// Also dedupes by SHA-256 fingerprint and detects rotation cases (two CAs
/// with the same subject CN but different fingerprints).
pub fn create_truststore(
    cert_paths: &[String],
    password: &str,
    output: &str,
    allow_non_ca: bool,
) -> Result<ConvertResult> {
    let mut all_certs: Vec<X509> = Vec::new();

    for path in cert_paths {
        let pem_data = fs::read(path).with_context(|| format!("Failed to read certificate file: {}", path))?;
        let certs =
            X509::stack_from_pem(&pem_data).with_context(|| format!("Failed to parse PEM certificates: {}", path))?;
        all_certs.extend(certs);
    }

    if all_certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in the provided files"));
    }

    // Build per-cert summaries up-front (role, subject, fingerprint, expiry).
    let mut summaries: Vec<CertSummary> = Vec::with_capacity(all_certs.len());
    for cert in &all_certs {
        summaries.push(cert_summary(cert)?);
    }

    // Dedupe by fingerprint while preserving order — keep the first occurrence
    // of each unique cert and report duplicates in warnings.
    let mut seen_fps: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut deduped_certs: Vec<X509> = Vec::with_capacity(all_certs.len());
    let mut deduped_summaries: Vec<CertSummary> = Vec::with_capacity(summaries.len());
    let mut duplicate_count: usize = 0;
    for (cert, summary) in all_certs.iter().zip(summaries.iter()) {
        if seen_fps.insert(summary.fingerprint_sha256.clone()) {
            deduped_certs.push(cert.clone());
            deduped_summaries.push(summary.clone());
        } else {
            duplicate_count += 1;
        }
    }

    let mut warnings: Vec<String> = Vec::new();
    if duplicate_count > 0 {
        warnings.push(format!(
            "Skipped {} duplicate certificate(s) (matched by SHA-256 fingerprint). Kept {} unique cert(s).",
            duplicate_count,
            deduped_certs.len()
        ));
    }

    // Reject leaf certs unless explicitly allowed.
    let leaf_summaries: Vec<&CertSummary> = deduped_summaries.iter().filter(|s| s.role == CertRole::Leaf).collect();
    if !leaf_summaries.is_empty() && !allow_non_ca {
        let mut msg = format!(
            "{} leaf (server) certificate(s) found in the input.\n\
             A truststore should only contain CA certificates (root and/or intermediate),\n\
             never the server's own certificate. The trust anchor is the CA that ISSUED\n\
             the leaf — re-export with the issuing CA chain instead.\n\n\
             Leaf cert(s) detected:",
            leaf_summaries.len()
        );
        for s in &leaf_summaries {
            msg.push_str(&format!("\n  - {}  (issued by: {})", s.subject, s.issuer));
        }
        msg.push_str(
            "\n\n  Tip: use `dcert <host> --export-pem chain.pem` to capture the CA\n  \
             chain that issued it, then build the truststore from those CAs only.\n\n  \
             Override (not recommended): pass --allow-non-ca to include leaves anyway.",
        );
        return Err(anyhow::anyhow!("{}", msg));
    }
    if !leaf_summaries.is_empty() && allow_non_ca {
        warnings.push(format!(
            "{} leaf (non-CA) certificate(s) included via --allow-non-ca. Truststores normally hold CA certs only.",
            leaf_summaries.len()
        ));
    }

    // Detect rotation: two CAs with the same subject CN but different fingerprints.
    {
        use std::collections::HashMap;
        let mut subject_groups: HashMap<&str, Vec<&CertSummary>> = HashMap::new();
        for s in &deduped_summaries {
            if s.role.is_ca() {
                subject_groups.entry(s.subject.as_str()).or_default().push(s);
            }
        }
        for (subject, group) in &subject_groups {
            if group.len() > 1 {
                let fps: Vec<String> = group
                    .iter()
                    .map(|s| {
                        format!(
                            "fp:{}.. expires {}",
                            &s.fingerprint_sha256[..s.fingerprint_sha256.len().min(11)],
                            s.not_after
                        )
                    })
                    .collect();
                warnings.push(format!(
                    "{} CAs share subject \"{}\" (different fingerprints). \
                     This is normal during a CA rotation — both will be trusted until you remove the old one. {}",
                    group.len(),
                    subject,
                    fps.join("; ")
                ));
            }
        }
    }

    // Warn on (but accept) expired CAs.
    for summary in &deduped_summaries {
        if summary.expired {
            warnings.push(format!(
                "CA \"{}\" expired on {}. Java clients will not trust certificates that chain to it.",
                summary.subject, summary.not_after
            ));
        }
    }

    let all_certs = deduped_certs;
    let summaries_for_result = deduped_summaries;
    let ca_count = all_certs.len();

    // PKCS12 format requires a private key matching the main certificate.
    // For a truststore (CA certs only, no private key), we generate an
    // ephemeral self-signed certificate + key pair, then put all the user's
    // CA certs as the CA chain. Java can load this as a truststore.
    let rsa = openssl::rsa::Rsa::generate(2048).with_context(|| "Failed to generate ephemeral key for truststore")?;
    let pkey = PKey::from_rsa(rsa).with_context(|| "Failed to wrap ephemeral key")?;

    // Create a minimal self-signed cert for the ephemeral key. Each builder
    // call is `?`-propagated with context so a malformed placeholder produces
    // a precise OpenSSL error instead of a silently-corrupted truststore that
    // Java would later reject with a confusing message.
    let mut x509_builder = openssl::x509::X509::builder().with_context(|| "Failed to create X509 builder")?;
    x509_builder
        .set_version(2)
        .with_context(|| "Failed to set placeholder cert version")?;
    let serial = openssl::bn::BigNum::from_u32(1)
        .and_then(|bn| bn.to_asn1_integer())
        .with_context(|| "Failed to create serial number")?;
    x509_builder
        .set_serial_number(&serial)
        .with_context(|| "Failed to set placeholder cert serial number")?;
    let mut name_builder =
        openssl::x509::X509NameBuilder::new().with_context(|| "Failed to create X509 name builder")?;
    name_builder
        .append_entry_by_text("CN", "dcert-truststore-placeholder")
        .with_context(|| "Failed to set placeholder cert CN")?;
    let name = name_builder.build();
    x509_builder
        .set_subject_name(&name)
        .with_context(|| "Failed to set placeholder cert subject name")?;
    x509_builder
        .set_issuer_name(&name)
        .with_context(|| "Failed to set placeholder cert issuer name")?;
    let not_before = openssl::asn1::Asn1Time::days_from_now(0).with_context(|| "Failed to create not_before")?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(3650).with_context(|| "Failed to create not_after")?;
    x509_builder
        .set_not_before(&not_before)
        .with_context(|| "Failed to set placeholder cert not_before")?;
    x509_builder
        .set_not_after(&not_after)
        .with_context(|| "Failed to set placeholder cert not_after")?;
    x509_builder
        .set_pubkey(&pkey)
        .with_context(|| "Failed to set placeholder cert public key")?;
    x509_builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .with_context(|| "Failed to sign ephemeral certificate")?;
    let placeholder_cert = x509_builder.build();

    let mut builder = Pkcs12::builder();
    builder.name("truststore");
    builder.pkey(&pkey);
    builder.cert(&placeholder_cert);
    builder.ca(vec_to_stack(all_certs)?);

    let pkcs12 = builder
        .build2(password)
        .with_context(|| "Failed to build PKCS12 truststore")?;
    let der = pkcs12.to_der().with_context(|| "Failed to serialize truststore")?;
    fs::write(output, &der).with_context(|| format!("Failed to write truststore: {}", output))?;
    // Truststore contains ephemeral private key — restrict file permissions
    restrict_file_permissions(output);

    Ok(ConvertResult {
        input_format: "PEM".to_string(),
        output_format: "PKCS12 TrustStore".to_string(),
        output_files: vec![output.to_string()],
        cert_subject: None,
        key_type: None,
        ca_certs_count: ca_count,
        cert_roles: summaries_for_result,
        warnings,
    })
}

/// Convert a Vec<X509> to an openssl Stack<X509>.
fn vec_to_stack(certs: Vec<X509>) -> Result<Stack<X509>> {
    let mut stack = Stack::new().with_context(|| "Failed to create X509 stack")?;
    for cert in certs {
        stack.push(cert).with_context(|| "Failed to push cert onto stack")?;
    }
    Ok(stack)
}

/// Warn the user (to stderr) that a private-key file could not be locked down.
/// Restricting permissions is best-effort — we never abort key generation over it —
/// but the user must be told so they can fix the permissions themselves rather than
/// unknowingly leaving a private key world-readable.
#[cfg(any(unix, windows))]
fn warn_unrestricted(path: &str, detail: &str) {
    eprintln!(
        "warning: could not restrict permissions on '{path}' ({detail}). \
         This file may contain a private key — secure it manually."
    );
}

/// Set file permissions to owner-only (0600) on Unix.
/// Best-effort: on failure we warn rather than aborting, since the file is already
/// written and the caller may still want the output.
#[cfg(unix)]
pub(crate) fn restrict_file_permissions(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        warn_unrestricted(path, &e.to_string());
    }
}

/// On Windows, restrict file permissions using icacls.
/// Removes inherited ACLs and grants access only to the current user.
#[cfg(windows)]
pub(crate) fn restrict_file_permissions(path: &str) {
    use std::process::Command;
    let username = std::env::var("USERNAME").unwrap_or_default();
    if username.is_empty() {
        warn_unrestricted(path, "USERNAME environment variable is not set");
        return;
    }
    // Reject characters that are illegal in Windows account names and that would
    // otherwise corrupt the icacls grant argument (`user:perm`) if interpolated.
    if username.contains([':', '/', '\\', '"', '*', '?', '<', '>', '|']) || username.trim() != username {
        warn_unrestricted(path, "USERNAME contains unexpected characters");
        return;
    }
    // Remove inherited permissions, then grant full control only to the current user.
    // icacls is available on all modern Windows versions (Vista+).
    let stripped = Command::new("icacls").args([path, "/inheritance:r"]).output();
    let granted = Command::new("icacls")
        .args([path, "/grant:r", &format!("{username}:F")])
        .output();
    let ok = matches!((&stripped, &granted),
        (Ok(s), Ok(g)) if s.status.success() && g.status.success());
    if !ok {
        warn_unrestricted(path, "icacls did not complete successfully");
    }
}

/// No-op on platforms that are neither Unix nor Windows.
#[cfg(not(any(unix, windows)))]
pub(crate) fn restrict_file_permissions(_path: &str) {}

fn key_type_name(pkey: &PKey<openssl::pkey::Private>) -> String {
    format!("{} ({} bits)", crate::cert::pkey_algorithm(pkey), pkey.bits())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
    use openssl::x509::{X509, X509NameBuilder};
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn restrict_file_permissions_sets_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("key.pem");
        fs::write(&path, b"-----BEGIN PRIVATE KEY-----\n").unwrap();
        // Start permissive so we can prove the call actually tightens the mode.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        restrict_file_permissions(path.to_str().unwrap());

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "private key file should be owner-only");
    }

    /// Generate a self-signed test certificate and private key.
    fn generate_test_key_and_cert() -> (PKey<openssl::pkey::Private>, X509) {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "test.example.com").unwrap();
        name_builder.append_entry_by_text("O", "Test Org").unwrap();
        let name = name_builder.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();

        let serial = BigNum::from_u32(1).unwrap();
        builder.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();

        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        builder.set_pubkey(&pkey).unwrap();

        let bc = BasicConstraints::new().critical().ca().build().unwrap();
        builder.append_extension(bc).unwrap();

        let san = SubjectAlternativeName::new()
            .dns("test.example.com")
            .dns("*.example.com")
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        (pkey, builder.build())
    }

    /// Generate a second (different) test key and cert for mismatch tests.
    fn generate_other_key_and_cert() -> (PKey<openssl::pkey::Private>, X509) {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "other.example.com").unwrap();
        let name = name_builder.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(2).unwrap();
        builder.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        (pkey, builder.build())
    }

    fn write_pem_files(dir: &TempDir, pkey: &PKey<openssl::pkey::Private>, cert: &X509) -> (String, String) {
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
        fs::write(&key_path, pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();
        (
            cert_path.to_str().unwrap().to_string(),
            key_path.to_str().unwrap().to_string(),
        )
    }

    #[test]
    fn test_pem_to_pfx_roundtrip() {
        let (pkey, cert) = generate_test_key_and_cert();
        let dir = TempDir::new().unwrap();
        let (cert_path, key_path) = write_pem_files(&dir, &pkey, &cert);
        let pfx_path = dir.path().join("test.pfx").to_str().unwrap().to_string();

        let result = pem_to_pfx(&cert_path, &key_path, "testpass", &pfx_path, None).unwrap();
        assert_eq!(result.input_format, "PEM");
        assert_eq!(result.output_format, "PKCS12/PFX");
        assert!(result.cert_subject.is_some());
        assert!(result.key_type.as_ref().unwrap().starts_with("RSA"));
        assert_eq!(result.ca_certs_count, 0);

        // Now convert back
        let out_dir = dir.path().join("out");
        let out_dir_str = out_dir.to_str().unwrap().to_string();
        let result2 = pfx_to_pem(&pfx_path, "testpass", &out_dir_str).unwrap();
        assert_eq!(result2.input_format, "PKCS12/PFX");
        assert_eq!(result2.output_format, "PEM");
        assert!(result2.output_files.iter().any(|f| f.ends_with("cert.pem")));
        assert!(result2.output_files.iter().any(|f| f.ends_with("key.pem")));
    }

    #[test]
    fn test_pfx_wrong_password() {
        let (pkey, cert) = generate_test_key_and_cert();
        let dir = TempDir::new().unwrap();
        let (cert_path, key_path) = write_pem_files(&dir, &pkey, &cert);
        let pfx_path = dir.path().join("test.pfx").to_str().unwrap().to_string();

        pem_to_pfx(&cert_path, &key_path, "correctpass", &pfx_path, None).unwrap();

        let result = pfx_to_pem(&pfx_path, "wrongpass", "/tmp/out");
        assert!(result.is_err());
    }

    #[test]
    fn test_pem_to_pfx_with_ca() {
        let (pkey, cert) = generate_test_key_and_cert();
        let (_, ca_cert) = generate_other_key_and_cert();
        let dir = TempDir::new().unwrap();
        let (cert_path, key_path) = write_pem_files(&dir, &pkey, &cert);

        let ca_path = dir.path().join("ca.pem");
        fs::write(&ca_path, ca_cert.to_pem().unwrap()).unwrap();
        let ca_path_str = ca_path.to_str().unwrap();

        let pfx_path = dir.path().join("test.pfx").to_str().unwrap().to_string();
        let result = pem_to_pfx(&cert_path, &key_path, "pass", &pfx_path, Some(ca_path_str)).unwrap();
        assert_eq!(result.ca_certs_count, 1);
    }

    #[test]
    fn test_create_keystore() {
        let (pkey, cert) = generate_test_key_and_cert();
        let dir = TempDir::new().unwrap();
        let (cert_path, key_path) = write_pem_files(&dir, &pkey, &cert);
        let ks_path = dir.path().join("keystore.p12").to_str().unwrap().to_string();

        let result = create_keystore(&cert_path, &key_path, "changeit", &ks_path, "myalias").unwrap();
        assert_eq!(result.output_format, "PKCS12 KeyStore");
        assert!(result.cert_subject.is_some());

        // Verify we can read it back
        let data = fs::read(&ks_path).unwrap();
        let p12 = Pkcs12::from_der(&data).unwrap();
        let parsed = p12.parse2("changeit").unwrap();
        assert!(parsed.cert.is_some());
        assert!(parsed.pkey.is_some());
    }

    #[test]
    fn test_create_truststore() {
        let (_, cert1) = generate_test_key_and_cert();
        let (_, cert2) = generate_other_key_and_cert();
        let dir = TempDir::new().unwrap();

        let ca1_path = dir.path().join("ca1.pem");
        let ca2_path = dir.path().join("ca2.pem");
        fs::write(&ca1_path, cert1.to_pem().unwrap()).unwrap();
        fs::write(&ca2_path, cert2.to_pem().unwrap()).unwrap();

        let ts_path = dir.path().join("truststore.p12").to_str().unwrap().to_string();
        // generate_other_key_and_cert produces a cert without BasicConstraints
        // (so it classifies as a Leaf). Use allow_non_ca=true to bypass the
        // strict-mode rejection for this happy-path test; strict-mode tests
        // live in their own #[test] functions below.
        let result = create_truststore(
            &[
                ca1_path.to_str().unwrap().to_string(),
                ca2_path.to_str().unwrap().to_string(),
            ],
            "changeit",
            &ts_path,
            true,
        )
        .unwrap();

        assert_eq!(result.output_format, "PKCS12 TrustStore");
        assert_eq!(result.ca_certs_count, 2);

        // Verify we can read it back
        let data = fs::read(&ts_path).unwrap();
        let p12 = Pkcs12::from_der(&data).unwrap();
        let parsed = p12.parse2("changeit").unwrap();
        assert!(parsed.cert.is_some());
    }

    /// Generate a self-signed CA certificate (BasicConstraints CA:TRUE,
    /// subject == issuer). Used to exercise the role classifier.
    fn generate_root_ca() -> (PKey<openssl::pkey::Private>, X509) {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "Test Root CA").unwrap();
        let name = name_builder.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(100).unwrap();
        builder.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(3650).unwrap()).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        let bc = BasicConstraints::new().critical().ca().build().unwrap();
        builder.append_extension(bc).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        (pkey, builder.build())
    }

    /// Generate a leaf cert (BasicConstraints CA:FALSE, signed by an external
    /// authority — but for classifier testing we self-sign to simplify).
    /// Returns a leaf with explicit CA:FALSE so it classifies as Leaf even
    /// when subject == issuer (BasicConstraints takes precedence).
    fn generate_leaf_self_signed() -> (PKey<openssl::pkey::Private>, X509) {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "leaf.example.com").unwrap();
        let name = name_builder.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(101).unwrap();
        builder.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        let bc = BasicConstraints::new().critical().build().unwrap();
        builder.append_extension(bc).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        (pkey, builder.build())
    }

    #[test]
    fn test_classify_root_ca() {
        let (_, ca) = generate_root_ca();
        assert_eq!(classify_cert(&ca), CertRole::RootCa);
    }

    #[test]
    fn test_classify_leaf_with_ca_false() {
        let (_, leaf) = generate_leaf_self_signed();
        assert_eq!(classify_cert(&leaf), CertRole::Leaf);
    }

    #[test]
    fn test_classify_leaf_no_basic_constraints() {
        // generate_other_key_and_cert produces a cert with no BasicConstraints
        // extension at all — should default to Leaf.
        let (_, cert) = generate_other_key_and_cert();
        assert_eq!(classify_cert(&cert), CertRole::Leaf);
    }

    #[test]
    fn test_create_truststore_rejects_leaf_by_default() {
        let (_, leaf) = generate_leaf_self_signed();
        let dir = TempDir::new().unwrap();
        let leaf_path = dir.path().join("leaf.pem");
        fs::write(&leaf_path, leaf.to_pem().unwrap()).unwrap();
        let ts_path = dir.path().join("truststore.p12");

        let result = create_truststore(
            &[leaf_path.to_str().unwrap().to_string()],
            "changeit",
            ts_path.to_str().unwrap(),
            false, // strict mode
        );
        assert!(result.is_err(), "strict mode should reject leaf certs");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("leaf"), "error must mention leaf certs: {err}");
        assert!(
            err.contains("--allow-non-ca"),
            "error must point to the override flag: {err}"
        );
    }

    #[test]
    fn test_create_truststore_allow_non_ca_overrides() {
        let (_, leaf) = generate_leaf_self_signed();
        let dir = TempDir::new().unwrap();
        let leaf_path = dir.path().join("leaf.pem");
        fs::write(&leaf_path, leaf.to_pem().unwrap()).unwrap();
        let ts_path = dir.path().join("truststore.p12");

        let result = create_truststore(
            &[leaf_path.to_str().unwrap().to_string()],
            "changeit",
            ts_path.to_str().unwrap(),
            true, // allow_non_ca
        )
        .unwrap();
        assert_eq!(result.ca_certs_count, 1);
        assert!(
            result.warnings.iter().any(|w| w.contains("non-CA")),
            "expected a warning about non-CA inclusion: {:?}",
            result.warnings
        );
    }

    #[test]
    fn test_create_truststore_dedupes_duplicate_certs() {
        let (_, ca) = generate_root_ca();
        let dir = TempDir::new().unwrap();
        let ca_path = dir.path().join("ca.pem");
        fs::write(&ca_path, ca.to_pem().unwrap()).unwrap();
        let ts_path = dir.path().join("truststore.p12");
        let p = ca_path.to_str().unwrap().to_string();

        // Pass the same path twice — same fingerprint → dedupe to 1.
        let result = create_truststore(&[p.clone(), p], "changeit", ts_path.to_str().unwrap(), false).unwrap();
        assert_eq!(result.ca_certs_count, 1, "duplicates should be deduped");
        assert!(
            result.warnings.iter().any(|w| w.contains("duplicate")),
            "expected a duplicate-warning: {:?}",
            result.warnings
        );
    }

    #[test]
    fn test_create_keystore_warns_on_missing_chain() {
        // Single leaf, no intermediates → warn that Java needs the chain.
        // generate_test_key_and_cert produces a cert with CA:TRUE, so it
        // classifies as RootCa — exercises the "first cert is a CA" warning,
        // and (for the missing-chain warning) we use generate_leaf_self_signed.
        let (pkey, leaf) = generate_leaf_self_signed();
        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("leaf.pem");
        let key_path = dir.path().join("leaf.key");
        fs::write(&cert_path, leaf.to_pem().unwrap()).unwrap();
        fs::write(&key_path, pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();
        let ks_path = dir.path().join("keystore.p12");

        let result = create_keystore(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            "changeit",
            ks_path.to_str().unwrap(),
            "server",
        )
        .unwrap();
        assert!(
            result.warnings.iter().any(|w| w.contains("Only a leaf certificate")),
            "expected a missing-chain warning: {:?}",
            result.warnings
        );
        assert_eq!(result.cert_roles.len(), 1);
        assert_eq!(result.cert_roles[0].role, CertRole::Leaf);
    }

    #[test]
    fn test_create_keystore_warns_when_first_cert_is_ca() {
        // generate_test_key_and_cert sets BasicConstraints CA:TRUE — the
        // resulting cert would classify as RootCa, not Leaf, and we want
        // create_keystore to warn that the leaf must come first.
        let (pkey, ca) = generate_test_key_and_cert();
        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("ca.pem");
        let key_path = dir.path().join("ca.key");
        fs::write(&cert_path, ca.to_pem().unwrap()).unwrap();
        fs::write(&key_path, pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();
        let ks_path = dir.path().join("keystore.p12");

        let result = create_keystore(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            "changeit",
            ks_path.to_str().unwrap(),
            "server",
        )
        .unwrap();
        assert!(
            result.warnings.iter().any(|w| w.contains("appears to be a")),
            "expected a leaf-first-warning: {:?}",
            result.warnings
        );
    }

    #[test]
    fn test_pem_to_pfx_mismatched_key() {
        let (_, cert) = generate_test_key_and_cert();
        let (other_pkey, _) = generate_other_key_and_cert();
        let dir = TempDir::new().unwrap();

        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
        fs::write(&key_path, other_pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();

        let pfx_path = dir.path().join("test.pfx").to_str().unwrap().to_string();
        // OpenSSL may or may not reject mismatched key at build time depending on version
        // The test just verifies we don't panic
        let _ = pem_to_pfx(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            "pass",
            &pfx_path,
            None,
        );
    }
}
