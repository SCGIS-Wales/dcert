use anyhow::{Context, Result};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509Name, X509NameBuilder, X509NameRef, X509Req, X509ReqBuilder};
use std::fs;

use crate::convert::restrict_file_permissions;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Supported key algorithms for CSR generation.
#[derive(Debug, Clone, Copy)]
pub enum KeyAlgorithm {
    /// RSA 2048-bit — minimum accepted by CAs
    Rsa2048,
    /// RSA 4096-bit — strong, widely compatible (default)
    Rsa4096,
    /// ECDSA with NIST P-256 — modern, fast, recommended
    EcdsaP256,
    /// ECDSA with NIST P-384 — high-security, CNSA 2.0 compliant
    EcdsaP384,
    /// Ed25519 — modern EdDSA, compact signatures, high performance
    Ed25519,
}

impl KeyAlgorithm {
    pub fn label(&self) -> &'static str {
        match self {
            KeyAlgorithm::Rsa2048 => "RSA 2048",
            KeyAlgorithm::Rsa4096 => "RSA 4096",
            KeyAlgorithm::EcdsaP256 => "ECDSA P-256",
            KeyAlgorithm::EcdsaP384 => "ECDSA P-384",
            KeyAlgorithm::Ed25519 => "Ed25519",
        }
    }

    pub fn bits(&self) -> u32 {
        match self {
            KeyAlgorithm::Rsa2048 => 2048,
            KeyAlgorithm::Rsa4096 => 4096,
            KeyAlgorithm::EcdsaP256 => 256,
            KeyAlgorithm::EcdsaP384 => 384,
            KeyAlgorithm::Ed25519 => 256,
        }
    }
}

/// Subject fields for a CSR.
#[derive(Debug, Clone, Default)]
pub struct CsrSubject {
    pub common_name: String,
    pub organization: Option<String>,
    /// Multiple OUs are supported; can include metadata identifiers like "AppId:my-app-123".
    pub organizational_units: Vec<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub email: Option<String>,
}

/// Options for CSR creation.
#[derive(Debug, Clone)]
pub struct CsrCreateOptions {
    pub subject: CsrSubject,
    pub san: Vec<String>,
    pub key_algo: KeyAlgorithm,
    pub encrypt_key: bool,
    pub key_password: Option<String>,
}

/// Result of CSR creation.
#[derive(Debug, serde::Serialize)]
pub struct CsrCreateResult {
    pub csr_file: String,
    pub key_file: String,
    pub key_algorithm: String,
    pub key_size_bits: u32,
    pub signature_algorithm: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
    pub key_encrypted: bool,
}

// ---------------------------------------------------------------------------
// CSR Validation types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CsrFinding {
    pub severity: Severity,
    pub category: String,
    pub message: String,
}

#[derive(Debug, serde::Serialize)]
pub struct CsrSubjectInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub organizational_units: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct CsrValidationResult {
    pub subject: CsrSubjectInfo,
    pub public_key_algorithm: String,
    pub public_key_size_bits: u32,
    pub signature_algorithm: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subject_alternative_names: Vec<String>,
    pub findings: Vec<CsrFinding>,
    pub compliant: bool,
}

// ---------------------------------------------------------------------------
// CSR Creation
// ---------------------------------------------------------------------------

/// Generate a private key and CSR, writing them to the specified files.
pub fn create_csr(opts: &CsrCreateOptions, csr_path: &str, key_path: &str) -> Result<CsrCreateResult> {
    // Generate key pair
    let pkey = generate_key(opts.key_algo)?;

    // Build subject name
    let subject_name = build_subject_name(&opts.subject)?;

    // Build CSR
    let mut req_builder = X509ReqBuilder::new().with_context(|| "Failed to create X509 request builder")?;
    req_builder.set_version(0).ok(); // PKCS#10 v1
    req_builder
        .set_pubkey(&pkey)
        .with_context(|| "Failed to set public key on CSR")?;
    req_builder
        .set_subject_name(&subject_name)
        .with_context(|| "Failed to set subject name on CSR")?;

    // Add SANs as an extension request if provided
    if !opts.san.is_empty() {
        let mut extensions = openssl::stack::Stack::new().with_context(|| "Failed to create extensions stack")?;
        let mut san_builder = SubjectAlternativeName::new();
        for entry in &opts.san {
            if let Some(dns) = entry.strip_prefix("DNS:") {
                san_builder.dns(dns);
            } else if let Some(ip) = entry.strip_prefix("IP:") {
                san_builder.ip(ip);
            } else if let Some(email) = entry.strip_prefix("Email:") {
                san_builder.email(email);
            } else if let Some(uri) = entry.strip_prefix("URI:") {
                san_builder.uri(uri);
            } else {
                // Default to DNS if no prefix
                san_builder.dns(entry);
            }
        }
        let san_ext = san_builder
            .build(&req_builder.x509v3_context(None))
            .with_context(|| "Failed to build SAN extension")?;
        extensions
            .push(san_ext)
            .with_context(|| "Failed to push SAN extension")?;
        req_builder
            .add_extensions(&extensions)
            .with_context(|| "Failed to add extensions to CSR")?;
    }

    // Sign the CSR
    match select_digest(opts.key_algo) {
        Some(digest) => req_builder.sign(&pkey, digest).with_context(|| "Failed to sign CSR")?,
        None => {
            // For Ed25519/Ed448, OpenSSL expects a null digest
            req_builder
                .sign(&pkey, MessageDigest::null())
                .with_context(|| "Failed to sign CSR with Ed25519")?
        }
    };

    let req = req_builder.build();

    // Serialize CSR
    let csr_pem = req.to_pem().with_context(|| "Failed to encode CSR as PEM")?;
    fs::write(csr_path, &csr_pem).with_context(|| format!("Failed to write CSR to: {}", csr_path))?;

    // Serialize private key
    let key_pem = if opts.encrypt_key {
        let password = opts.key_password.as_deref().unwrap_or("").as_bytes();
        pkey.private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), password)
            .with_context(|| "Failed to encrypt private key")?
    } else {
        pkey.private_key_to_pem_pkcs8()
            .with_context(|| "Failed to encode private key as PEM")?
    };
    fs::write(key_path, &key_pem).with_context(|| format!("Failed to write private key to: {}", key_path))?;
    restrict_file_permissions(key_path);

    // Build subject string for display
    let subject_str = format_subject_name(&opts.subject);
    let sig_algo = match opts.key_algo {
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => "SHA-256 with RSA",
        KeyAlgorithm::EcdsaP256 => "ECDSA with SHA-256",
        KeyAlgorithm::EcdsaP384 => "ECDSA with SHA-384",
        KeyAlgorithm::Ed25519 => "Ed25519",
    };

    Ok(CsrCreateResult {
        csr_file: csr_path.to_string(),
        key_file: key_path.to_string(),
        key_algorithm: opts.key_algo.label().to_string(),
        key_size_bits: opts.key_algo.bits(),
        signature_algorithm: sig_algo.to_string(),
        subject: subject_str,
        sans: opts.san.clone(),
        key_encrypted: opts.encrypt_key,
    })
}

// ---------------------------------------------------------------------------
// CSR Validation
// ---------------------------------------------------------------------------

/// Parse and validate a CSR from PEM data.
pub fn validate_csr(pem_data: &str) -> Result<CsrValidationResult> {
    let req = X509Req::from_pem(pem_data.as_bytes()).with_context(
        || "Failed to parse CSR PEM data. Ensure the file contains a valid PKCS#10 certificate request.",
    )?;

    // Verify the CSR's self-signature
    let pubkey = req
        .public_key()
        .with_context(|| "Failed to extract public key from CSR")?;
    let sig_valid = req.verify(&pubkey).unwrap_or(false);

    // Extract subject fields
    let subject = extract_subject_info(req.subject_name());

    // Extract public key info
    let (pk_algo, pk_bits) = extract_pubkey_info(&pubkey);

    // Extract signature algorithm
    let sig_algo = extract_signature_algorithm(&req);

    // Extract SANs from extensions
    let sans = extract_csr_sans(&req);

    // Run compliance checks
    let mut findings = Vec::new();

    // Signature validity
    if !sig_valid {
        findings.push(CsrFinding {
            severity: Severity::Error,
            category: "Signature".to_string(),
            message: "CSR signature verification failed — the CSR may be corrupted or tampered with".to_string(),
        });
    } else {
        findings.push(CsrFinding {
            severity: Severity::Info,
            category: "Signature".to_string(),
            message: "CSR signature is valid".to_string(),
        });
    }

    // Key algorithm and size checks
    check_key_compliance(&pk_algo, pk_bits, &mut findings);

    // Subject checks
    check_subject_compliance(&subject, &mut findings);

    // SAN checks
    check_san_compliance(&sans, &subject.common_name, &mut findings);

    // Signature algorithm checks
    check_signature_algorithm_compliance(&sig_algo, &mut findings);

    let compliant = !findings.iter().any(|f| f.severity == Severity::Error);

    Ok(CsrValidationResult {
        subject,
        public_key_algorithm: pk_algo,
        public_key_size_bits: pk_bits,
        signature_algorithm: sig_algo,
        subject_alternative_names: sans,
        findings,
        compliant,
    })
}

// ---------------------------------------------------------------------------
// Interactive CLI helpers
// ---------------------------------------------------------------------------

/// Run interactive CSR creation wizard. Reads from stdin, writes prompts to stderr.
pub fn interactive_create() -> Result<(CsrCreateOptions, String, String)> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "Interactive mode requires a terminal. Use --cn and other flags for non-interactive mode."
        ));
    }

    eprintln!("=== CSR Creation Wizard ===\n");
    eprintln!("Enter certificate subject fields. Press Enter to skip optional fields.\n");

    let cn = prompt_required("Common Name (CN) [e.g., www.example.com]")?;
    let org = prompt_optional("Organization (O) [e.g., Example Inc]")?;
    let country = prompt_optional("Country (C) [2-letter code, e.g., GB]")?;
    let state = prompt_optional("State/Province (ST)")?;
    let locality = prompt_optional("Locality/City (L)")?;
    let email = prompt_optional("Email Address")?;

    // Organizational Units
    eprintln!("\n--- Organizational Units ---");
    eprintln!("You can add multiple OUs, including metadata identifiers (e.g., \"AppId:my-app-123\").");
    eprintln!("Note: OU is deprecated for public CA certificates (CA/B Forum, Sep 2022).");
    eprintln!("      For internal/private PKI, OU with metadata identifiers is widely supported.\n");

    let mut ous: Vec<String> = Vec::new();
    loop {
        let label = if ous.is_empty() {
            "Organizational Unit (OU) [press Enter to skip]"
        } else {
            "Additional OU [press Enter to finish]"
        };
        match prompt_optional(label)? {
            Some(ou) => ous.push(ou),
            None => break,
        }
    }

    // SANs
    eprintln!("\n--- Subject Alternative Names (SANs) ---");
    eprintln!("SANs are required by modern CAs. The CN will be added automatically.");
    eprintln!("Use prefixes: DNS:, IP:, Email: (DNS: is default)\n");

    let mut sans: Vec<String> = Vec::new();
    // Auto-add CN as a SAN
    let cn_san = format!("DNS:{}", cn);
    sans.push(cn_san);
    eprintln!("  Auto-added: DNS:{}", cn);

    loop {
        let label = "Additional SAN [press Enter to finish]";
        match prompt_optional(label)? {
            Some(san) => {
                let san = if san.contains(':') { san } else { format!("DNS:{}", san) };
                sans.push(san);
            }
            None => break,
        }
    }

    // Key algorithm
    eprintln!("\n--- Key Algorithm ---");
    eprintln!("  1. RSA 4096 (default) — strongest RSA, widely compatible");
    eprintln!("  2. ECDSA P-256 (recommended) — modern, fast, smaller keys, excellent security");
    eprintln!("  3. ECDSA P-384 — higher security margin, good for sensitive workloads");
    eprintln!("  4. RSA 2048 — minimum accepted, use only if compatibility requires it");
    let algo_choice = prompt_optional("Key algorithm [1-4, default: 1]")?;
    let key_algo = match algo_choice.as_deref() {
        Some("2") => KeyAlgorithm::EcdsaP256,
        Some("3") => KeyAlgorithm::EcdsaP384,
        Some("4") => KeyAlgorithm::Rsa2048,
        _ => KeyAlgorithm::Rsa4096,
    };
    eprintln!("  Selected: {}", key_algo.label());

    // Key encryption
    eprintln!("\n--- Private Key Protection ---");
    let encrypt_str = prompt_optional("Encrypt private key with passphrase? [y/N]")?;
    let encrypt_key = matches!(
        encrypt_str.as_deref(),
        Some("y") | Some("Y") | Some("yes") | Some("Yes")
    );
    let key_password = if encrypt_key {
        let pw = prompt_required("Enter passphrase for private key")?;
        Some(pw)
    } else {
        None
    };

    // Output paths
    eprintln!("\n--- Output Files ---");
    let default_base = cn.replace('*', "wildcard").replace('.', "-");
    let default_csr = format!("{}.csr", default_base);
    let default_key = format!("{}.key", default_base);
    let csr_path = prompt_with_default("CSR output file", &default_csr)?;
    let key_path = prompt_with_default("Key output file", &default_key)?;

    // Validate country code
    if let Some(ref c) = country
        && (c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_uppercase()))
    {
        eprintln!(
            "\nWARNING: Country code '{}' should be a 2-letter ISO 3166 code (e.g., GB, US)",
            c
        );
    }

    let subject = CsrSubject {
        common_name: cn,
        organization: org,
        organizational_units: ous,
        country,
        state,
        locality,
        email,
    };

    let opts = CsrCreateOptions {
        subject,
        san: sans,
        key_algo,
        encrypt_key,
        key_password,
    };

    Ok((opts, csr_path, key_path))
}

pub(crate) fn prompt_required(label: &str) -> Result<String> {
    use std::io::{self, Write};
    loop {
        eprint!("{}: ", label);
        io::stderr().flush().ok();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .with_context(|| "Failed to read input")?;
        let input = input.trim().to_string();
        if !input.is_empty() {
            return Ok(input);
        }
        eprintln!("  This field is required.");
    }
}

pub(crate) fn prompt_optional(label: &str) -> Result<Option<String>> {
    use std::io::{self, Write};
    eprint!("{}: ", label);
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .with_context(|| "Failed to read input")?;
    let input = input.trim().to_string();
    if input.is_empty() { Ok(None) } else { Ok(Some(input)) }
}

pub(crate) fn prompt_with_default(label: &str, default: &str) -> Result<String> {
    use std::io::{self, Write};
    eprint!("{} [{}]: ", label, default);
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .with_context(|| "Failed to read input")?;
    let input = input.trim().to_string();
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn generate_key(algo: KeyAlgorithm) -> Result<PKey<openssl::pkey::Private>> {
    match algo {
        KeyAlgorithm::Rsa2048 => {
            let rsa = Rsa::generate(2048).with_context(|| "Failed to generate RSA 2048 key")?;
            PKey::from_rsa(rsa).with_context(|| "Failed to wrap RSA key")
        }
        KeyAlgorithm::Rsa4096 => {
            let rsa = Rsa::generate(4096).with_context(|| "Failed to generate RSA 4096 key")?;
            PKey::from_rsa(rsa).with_context(|| "Failed to wrap RSA key")
        }
        KeyAlgorithm::EcdsaP256 => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).with_context(|| "Failed to get P-256 curve")?;
            let ec = EcKey::generate(&group).with_context(|| "Failed to generate ECDSA P-256 key")?;
            PKey::from_ec_key(ec).with_context(|| "Failed to wrap EC key")
        }
        KeyAlgorithm::EcdsaP384 => {
            let group = EcGroup::from_curve_name(Nid::SECP384R1).with_context(|| "Failed to get P-384 curve")?;
            let ec = EcKey::generate(&group).with_context(|| "Failed to generate ECDSA P-384 key")?;
            PKey::from_ec_key(ec).with_context(|| "Failed to wrap EC key")
        }
        KeyAlgorithm::Ed25519 => PKey::generate_ed25519().with_context(|| "Failed to generate Ed25519 key"),
    }
}

fn build_subject_name(subject: &CsrSubject) -> Result<X509Name> {
    let mut builder = X509NameBuilder::new().with_context(|| "Failed to create X509 name builder")?;

    if let Some(ref c) = subject.country {
        builder
            .append_entry_by_text("C", c)
            .with_context(|| "Failed to set Country")?;
    }
    if let Some(ref st) = subject.state {
        builder
            .append_entry_by_text("ST", st)
            .with_context(|| "Failed to set State")?;
    }
    if let Some(ref l) = subject.locality {
        builder
            .append_entry_by_text("L", l)
            .with_context(|| "Failed to set Locality")?;
    }
    if let Some(ref o) = subject.organization {
        builder
            .append_entry_by_text("O", o)
            .with_context(|| "Failed to set Organization")?;
    }
    for ou in &subject.organizational_units {
        builder
            .append_entry_by_text("OU", ou)
            .with_context(|| format!("Failed to set OU: {}", ou))?;
    }
    builder
        .append_entry_by_text("CN", &subject.common_name)
        .with_context(|| "Failed to set Common Name")?;
    if let Some(ref email) = subject.email {
        builder
            .append_entry_by_text("emailAddress", email)
            .with_context(|| "Failed to set Email")?;
    }

    Ok(builder.build())
}

fn select_digest(algo: KeyAlgorithm) -> Option<MessageDigest> {
    match algo {
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => Some(MessageDigest::sha256()),
        KeyAlgorithm::EcdsaP256 => Some(MessageDigest::sha256()),
        KeyAlgorithm::EcdsaP384 => Some(MessageDigest::sha384()),
        // Ed25519 uses its own built-in hash (SHA-512 internally); pass None to sign()
        KeyAlgorithm::Ed25519 => None,
    }
}

fn format_subject_name(subject: &CsrSubject) -> String {
    let mut parts = Vec::new();
    if let Some(ref c) = subject.country {
        parts.push(format!("C={}", c));
    }
    if let Some(ref st) = subject.state {
        parts.push(format!("ST={}", st));
    }
    if let Some(ref l) = subject.locality {
        parts.push(format!("L={}", l));
    }
    if let Some(ref o) = subject.organization {
        parts.push(format!("O={}", o));
    }
    for ou in &subject.organizational_units {
        parts.push(format!("OU={}", ou));
    }
    parts.push(format!("CN={}", subject.common_name));
    if let Some(ref email) = subject.email {
        parts.push(format!("emailAddress={}", email));
    }
    parts.join(", ")
}

// -- Validation helpers --

fn extract_subject_info(name: &X509NameRef) -> CsrSubjectInfo {
    let get_field = |nid: Nid| -> Option<String> {
        name.entries_by_nid(nid)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
    };

    let ous: Vec<String> = name
        .entries_by_nid(Nid::ORGANIZATIONALUNITNAME)
        .filter_map(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
        .collect();

    CsrSubjectInfo {
        common_name: get_field(Nid::COMMONNAME),
        organization: get_field(Nid::ORGANIZATIONNAME),
        organizational_units: ous,
        country: get_field(Nid::COUNTRYNAME),
        state: get_field(Nid::STATEORPROVINCENAME),
        locality: get_field(Nid::LOCALITYNAME),
        email: get_field(Nid::from_raw(48)), // emailAddress NID
    }
}

fn extract_pubkey_info(pkey: &PKey<openssl::pkey::Public>) -> (String, u32) {
    let algo = if pkey.rsa().is_ok() {
        "RSA".to_string()
    } else if pkey.ec_key().is_ok() {
        let ec = pkey.ec_key().unwrap();
        let nid = ec.group().curve_name();
        match nid {
            Some(Nid::X9_62_PRIME256V1) => "ECDSA P-256".to_string(),
            Some(Nid::SECP384R1) => "ECDSA P-384".to_string(),
            Some(Nid::SECP521R1) => "ECDSA P-521".to_string(),
            _ => "EC".to_string(),
        }
    } else {
        "Unknown".to_string()
    };
    let bits = pkey.bits();
    (algo, bits)
}

fn extract_signature_algorithm(req: &X509Req) -> String {
    // Convert CSR to PEM and inspect the signature algorithm via the DER structure.
    // The openssl crate doesn't directly expose signature_algorithm() on X509Req,
    // so we extract it from the PEM text which includes the algorithm info.
    if let Ok(pem_data) = req.to_pem() {
        let pem_str = String::from_utf8_lossy(&pem_data);
        // Re-parse to get the DER bytes and inspect
        if let Ok(parsed_req) = openssl::x509::X509Req::from_pem(pem_str.as_bytes()) {
            // Use the to_text() method if available, otherwise infer from key type
            if let Ok(text) = parsed_req.to_text() {
                let text_str = String::from_utf8_lossy(&text);
                // Look for "Signature Algorithm:" line in the text output
                for line in text_str.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("Signature Algorithm:") {
                        return trimmed
                            .strip_prefix("Signature Algorithm:")
                            .unwrap_or(trimmed)
                            .trim()
                            .to_string();
                    }
                }
            }
        }
    }
    // Fallback: infer from key type
    if let Ok(pubkey) = req.public_key() {
        if pubkey.rsa().is_ok() {
            return "sha256WithRSAEncryption".to_string();
        } else if pubkey.ec_key().is_ok() {
            return "ecdsa-with-SHA256".to_string();
        }
    }
    "unknown".to_string()
}

fn extract_csr_sans(req: &X509Req) -> Vec<String> {
    let mut sans = Vec::new();
    // Extract SANs from the CSR's text representation since the openssl crate
    // doesn't expose extension object/data accessors directly on X509ExtensionRef.
    if let Ok(text_bytes) = req.to_text() {
        let text = String::from_utf8_lossy(&text_bytes);
        let mut in_san_section = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.contains("X509v3 Subject Alternative Name") {
                in_san_section = true;
                continue;
            }
            if in_san_section {
                // SAN values are on the next line(s), comma-separated
                for part in trimmed.split(',') {
                    let part = part.trim();
                    if part.starts_with("DNS:")
                        || part.starts_with("IP Address:")
                        || part.starts_with("email:")
                        || part.starts_with("URI:")
                    {
                        // Normalize "IP Address:" to "IP:"
                        let normalized = part.replace("IP Address:", "IP:");
                        // Normalize "email:" to "Email:"
                        let normalized = normalized.replace("email:", "Email:");
                        sans.push(normalized);
                    }
                }
                // SANs are typically on one line after the extension header
                in_san_section = false;
            }
        }
    }
    sans
}

fn check_key_compliance(algo: &str, bits: u32, findings: &mut Vec<CsrFinding>) {
    if algo.contains("RSA") {
        if bits < 2048 {
            findings.push(CsrFinding {
                severity: Severity::Error,
                category: "Key Size".to_string(),
                message: format!(
                    "RSA key size {} bits is below the minimum 2048 bits required by CA/Browser Forum Baseline Requirements",
                    bits
                ),
            });
        } else if bits == 2048 {
            findings.push(CsrFinding {
                severity: Severity::Warning,
                category: "Key Size".to_string(),
                message: "RSA 2048 meets minimum requirements but RSA 4096 or ECDSA P-256 is recommended for stronger security".to_string(),
            });
        } else if bits >= 4096 {
            findings.push(CsrFinding {
                severity: Severity::Info,
                category: "Key Size".to_string(),
                message: format!("RSA {} bits — strong key size", bits),
            });
        }
        // Suggest ECDSA as modern alternative
        findings.push(CsrFinding {
            severity: Severity::Info,
            category: "Key Algorithm".to_string(),
            message: "Consider ECDSA P-256 for better performance with equivalent security to RSA 3072".to_string(),
        });
    } else if algo.contains("EC") || algo.contains("ECDSA") {
        if bits < 256 {
            findings.push(CsrFinding {
                severity: Severity::Error,
                category: "Key Size".to_string(),
                message: format!("EC key size {} bits is below the minimum 256 bits", bits),
            });
        } else {
            findings.push(CsrFinding {
                severity: Severity::Info,
                category: "Key Size".to_string(),
                message: format!("{} {} bits — excellent choice for modern deployments", algo, bits),
            });
        }
    } else {
        findings.push(CsrFinding {
            severity: Severity::Warning,
            category: "Key Algorithm".to_string(),
            message: format!("Unknown key algorithm: {}. Verify CA support.", algo),
        });
    }
}

fn check_subject_compliance(subject: &CsrSubjectInfo, findings: &mut Vec<CsrFinding>) {
    if subject.common_name.is_none() {
        findings.push(CsrFinding {
            severity: Severity::Warning,
            category: "Subject".to_string(),
            message: "Common Name (CN) is missing. While SANs are preferred, most CAs still expect a CN.".to_string(),
        });
    }

    if let Some(ref country) = subject.country
        && (country.len() != 2 || !country.chars().all(|c| c.is_ascii_uppercase()))
    {
        findings.push(CsrFinding {
            severity: Severity::Error,
            category: "Subject".to_string(),
            message: format!(
                "Country code '{}' is not a valid 2-letter ISO 3166 code (e.g., GB, US, DE)",
                country
            ),
        });
    }

    if !subject.organizational_units.is_empty() {
        findings.push(CsrFinding {
            severity: Severity::Warning,
            category: "Subject".to_string(),
            message: "OU (Organizational Unit) is deprecated for publicly-trusted certificates (CA/Browser Forum Ballot SC47v2, Sep 2022). Public CAs will strip or reject this field. For internal/private PKI, OU is still valid and commonly used for metadata identifiers.".to_string(),
        });
    }

    if subject.email.is_some() {
        findings.push(CsrFinding {
            severity: Severity::Info,
            category: "Subject".to_string(),
            message: "Email in subject DN is uncommon for TLS certificates. Consider using SAN Email instead."
                .to_string(),
        });
    }
}

fn check_san_compliance(sans: &[String], cn: &Option<String>, findings: &mut Vec<CsrFinding>) {
    if sans.is_empty() {
        findings.push(CsrFinding {
            severity: Severity::Error,
            category: "SAN".to_string(),
            message: "No Subject Alternative Names (SANs) found. SANs are required by CA/Browser Forum Baseline Requirements since 2018. Browsers will reject certificates without SANs.".to_string(),
        });
    } else {
        // Check if CN is included in SANs
        if let Some(cn_val) = cn {
            let cn_in_sans = sans
                .iter()
                .any(|s| s.strip_prefix("DNS:").map(|dns| dns == cn_val).unwrap_or(false));
            if !cn_in_sans {
                findings.push(CsrFinding {
                    severity: Severity::Warning,
                    category: "SAN".to_string(),
                    message: format!(
                        "CN '{}' is not included in SANs. Best practice is to include the CN as a SAN entry.",
                        cn_val
                    ),
                });
            }
        }

        findings.push(CsrFinding {
            severity: Severity::Info,
            category: "SAN".to_string(),
            message: format!("{} SAN entries found", sans.len()),
        });
    }
}

fn check_signature_algorithm_compliance(sig_algo: &str, findings: &mut Vec<CsrFinding>) {
    let sig_lower = sig_algo.to_lowercase();
    if sig_lower.contains("sha1") || sig_lower.contains("sha-1") || sig_lower.contains("sha1withrsa") {
        findings.push(CsrFinding {
            severity: Severity::Error,
            category: "Signature Algorithm".to_string(),
            message: "SHA-1 signatures are insecure and rejected by all major CAs and browsers since 2017".to_string(),
        });
    } else if sig_lower.contains("md5") {
        findings.push(CsrFinding {
            severity: Severity::Error,
            category: "Signature Algorithm".to_string(),
            message: "MD5 signatures are cryptographically broken and must not be used".to_string(),
        });
    } else if sig_lower.contains("sha256") || sig_lower.contains("sha384") || sig_lower.contains("sha512") {
        findings.push(CsrFinding {
            severity: Severity::Info,
            category: "Signature Algorithm".to_string(),
            message: format!("Signature algorithm '{}' is compliant", sig_algo),
        });
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_csr_rsa4096() {
        let dir = TempDir::new().unwrap();
        let csr_path = dir.path().join("test.csr").to_str().unwrap().to_string();
        let key_path = dir.path().join("test.key").to_str().unwrap().to_string();

        let opts = CsrCreateOptions {
            subject: CsrSubject {
                common_name: "test.example.com".to_string(),
                organization: Some("Test Org".to_string()),
                organizational_units: vec!["Engineering".to_string()],
                country: Some("GB".to_string()),
                state: None,
                locality: None,
                email: None,
            },
            san: vec!["DNS:test.example.com".to_string(), "DNS:www.example.com".to_string()],
            key_algo: KeyAlgorithm::Rsa4096,
            encrypt_key: false,
            key_password: None,
        };

        let result = create_csr(&opts, &csr_path, &key_path).unwrap();
        assert_eq!(result.key_algorithm, "RSA 4096");
        assert_eq!(result.key_size_bits, 4096);
        assert!(result.subject.contains("CN=test.example.com"));
        assert_eq!(result.sans.len(), 2);
        assert!(!result.key_encrypted);

        // Verify files exist and are valid PEM
        let csr_pem = fs::read_to_string(&csr_path).unwrap();
        assert!(csr_pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        let key_pem = fs::read_to_string(&key_path).unwrap();
        assert!(key_pem.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_create_csr_ecdsa_p256() {
        let dir = TempDir::new().unwrap();
        let csr_path = dir.path().join("test.csr").to_str().unwrap().to_string();
        let key_path = dir.path().join("test.key").to_str().unwrap().to_string();

        let opts = CsrCreateOptions {
            subject: CsrSubject {
                common_name: "ec.example.com".to_string(),
                organization: None,
                organizational_units: vec![],
                country: None,
                state: None,
                locality: None,
                email: None,
            },
            san: vec!["DNS:ec.example.com".to_string()],
            key_algo: KeyAlgorithm::EcdsaP256,
            encrypt_key: false,
            key_password: None,
        };

        let result = create_csr(&opts, &csr_path, &key_path).unwrap();
        assert_eq!(result.key_algorithm, "ECDSA P-256");
        assert_eq!(result.key_size_bits, 256);
    }

    #[test]
    fn test_create_csr_encrypted_key() {
        let dir = TempDir::new().unwrap();
        let csr_path = dir.path().join("test.csr").to_str().unwrap().to_string();
        let key_path = dir.path().join("test.key").to_str().unwrap().to_string();

        let opts = CsrCreateOptions {
            subject: CsrSubject {
                common_name: "encrypted.example.com".to_string(),
                ..Default::default()
            },
            san: vec!["DNS:encrypted.example.com".to_string()],
            key_algo: KeyAlgorithm::Rsa4096,
            encrypt_key: true,
            key_password: Some("test-password-123".to_string()),
        };

        let result = create_csr(&opts, &csr_path, &key_path).unwrap();
        assert!(result.key_encrypted);

        let key_pem = fs::read_to_string(&key_path).unwrap();
        assert!(key_pem.contains("ENCRYPTED"));
    }

    #[test]
    fn test_create_csr_with_metadata_ou() {
        let dir = TempDir::new().unwrap();
        let csr_path = dir.path().join("test.csr").to_str().unwrap().to_string();
        let key_path = dir.path().join("test.key").to_str().unwrap().to_string();

        let opts = CsrCreateOptions {
            subject: CsrSubject {
                common_name: "app.example.com".to_string(),
                organization: Some("Example Corp".to_string()),
                organizational_units: vec![
                    "Engineering".to_string(),
                    "AppId:my-app-123".to_string(),
                    "CostCenter:CC-456".to_string(),
                ],
                country: Some("US".to_string()),
                ..Default::default()
            },
            san: vec!["DNS:app.example.com".to_string()],
            key_algo: KeyAlgorithm::EcdsaP256,
            encrypt_key: false,
            key_password: None,
        };

        let result = create_csr(&opts, &csr_path, &key_path).unwrap();
        assert!(result.subject.contains("OU=AppId:my-app-123"));
        assert!(result.subject.contains("OU=CostCenter:CC-456"));
    }

    #[test]
    fn test_create_and_validate_roundtrip() {
        let dir = TempDir::new().unwrap();
        let csr_path = dir.path().join("test.csr").to_str().unwrap().to_string();
        let key_path = dir.path().join("test.key").to_str().unwrap().to_string();

        let opts = CsrCreateOptions {
            subject: CsrSubject {
                common_name: "roundtrip.example.com".to_string(),
                organization: Some("Test Org".to_string()),
                organizational_units: vec!["Dept A".to_string()],
                country: Some("GB".to_string()),
                state: Some("Wales".to_string()),
                locality: Some("Cardiff".to_string()),
                email: None,
            },
            san: vec![
                "DNS:roundtrip.example.com".to_string(),
                "DNS:*.example.com".to_string(),
                "IP:10.0.0.1".to_string(),
            ],
            key_algo: KeyAlgorithm::Rsa4096,
            encrypt_key: false,
            key_password: None,
        };

        create_csr(&opts, &csr_path, &key_path).unwrap();

        let csr_pem = fs::read_to_string(&csr_path).unwrap();
        let validation = validate_csr(&csr_pem).unwrap();

        assert_eq!(validation.subject.common_name.as_deref(), Some("roundtrip.example.com"));
        assert_eq!(validation.subject.organization.as_deref(), Some("Test Org"));
        assert_eq!(validation.subject.country.as_deref(), Some("GB"));
        assert_eq!(validation.subject.state.as_deref(), Some("Wales"));
        assert_eq!(validation.subject.locality.as_deref(), Some("Cardiff"));
        assert!(validation.public_key_algorithm.contains("RSA"));
        assert_eq!(validation.public_key_size_bits, 4096);
        assert!(!validation.subject_alternative_names.is_empty());

        // Signature should be valid
        assert!(
            validation
                .findings
                .iter()
                .any(|f| f.message.contains("signature is valid"))
        );
    }

    #[test]
    fn test_validate_csr_compliance_checks() {
        let dir = TempDir::new().unwrap();
        let csr_path = dir.path().join("test.csr").to_str().unwrap().to_string();
        let key_path = dir.path().join("test.key").to_str().unwrap().to_string();

        // Create a CSR with OU (triggers deprecation warning)
        let opts = CsrCreateOptions {
            subject: CsrSubject {
                common_name: "test.example.com".to_string(),
                organizational_units: vec!["AppId:test".to_string()],
                ..Default::default()
            },
            san: vec!["DNS:test.example.com".to_string()],
            key_algo: KeyAlgorithm::Rsa4096,
            encrypt_key: false,
            key_password: None,
        };
        create_csr(&opts, &csr_path, &key_path).unwrap();

        let csr_pem = fs::read_to_string(&csr_path).unwrap();
        let validation = validate_csr(&csr_pem).unwrap();

        // Should have OU deprecation warning
        assert!(
            validation
                .findings
                .iter()
                .any(|f| f.severity == Severity::Warning && f.message.contains("OU"))
        );

        // Should be compliant (warnings don't break compliance, only errors do)
        assert!(validation.compliant);
    }

    #[test]
    fn test_validate_invalid_pem() {
        let result = validate_csr("not a CSR");
        assert!(result.is_err());
    }

    #[test]
    fn test_key_algorithm_labels() {
        assert_eq!(KeyAlgorithm::Rsa2048.label(), "RSA 2048");
        assert_eq!(KeyAlgorithm::Rsa4096.label(), "RSA 4096");
        assert_eq!(KeyAlgorithm::EcdsaP256.label(), "ECDSA P-256");
        assert_eq!(KeyAlgorithm::EcdsaP384.label(), "ECDSA P-384");
    }

    #[test]
    fn test_format_subject_name() {
        let subject = CsrSubject {
            common_name: "test.example.com".to_string(),
            organization: Some("Org".to_string()),
            organizational_units: vec!["OU1".to_string(), "OU2".to_string()],
            country: Some("GB".to_string()),
            state: None,
            locality: None,
            email: None,
        };
        let formatted = format_subject_name(&subject);
        assert!(formatted.contains("CN=test.example.com"));
        assert!(formatted.contains("O=Org"));
        assert!(formatted.contains("OU=OU1"));
        assert!(formatted.contains("OU=OU2"));
        assert!(formatted.contains("C=GB"));
    }

    #[test]
    fn test_csr_create_result_serialization() {
        let result = CsrCreateResult {
            csr_file: "test.csr".to_string(),
            key_file: "test.key".to_string(),
            key_algorithm: "RSA 4096".to_string(),
            key_size_bits: 4096,
            signature_algorithm: "SHA-256 with RSA".to_string(),
            subject: "CN=test".to_string(),
            sans: vec!["DNS:test".to_string()],
            key_encrypted: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"key_algorithm\":\"RSA 4096\""));
        assert!(json.contains("\"key_encrypted\":false"));
    }

    #[test]
    fn test_validation_result_serialization() {
        let result = CsrValidationResult {
            subject: CsrSubjectInfo {
                common_name: Some("test".to_string()),
                organization: None,
                organizational_units: vec![],
                country: None,
                state: None,
                locality: None,
                email: None,
            },
            public_key_algorithm: "RSA".to_string(),
            public_key_size_bits: 4096,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            subject_alternative_names: vec!["DNS:test".to_string()],
            findings: vec![CsrFinding {
                severity: Severity::Info,
                category: "Test".to_string(),
                message: "test finding".to_string(),
            }],
            compliant: true,
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("\"compliant\": true"));
        assert!(json.contains("\"severity\": \"info\""));
    }

    #[test]
    fn test_create_csr_ecdsa_p384() {
        let dir = TempDir::new().unwrap();
        let csr_path = dir.path().join("test.csr").to_str().unwrap().to_string();
        let key_path = dir.path().join("test.key").to_str().unwrap().to_string();

        let opts = CsrCreateOptions {
            subject: CsrSubject {
                common_name: "p384.example.com".to_string(),
                ..Default::default()
            },
            san: vec!["DNS:p384.example.com".to_string()],
            key_algo: KeyAlgorithm::EcdsaP384,
            encrypt_key: false,
            key_password: None,
        };

        let result = create_csr(&opts, &csr_path, &key_path).unwrap();
        assert_eq!(result.key_algorithm, "ECDSA P-384");
        assert_eq!(result.key_size_bits, 384);
    }

    #[test]
    fn test_create_csr_no_sans() {
        let dir = TempDir::new().unwrap();
        let csr_path = dir.path().join("test.csr").to_str().unwrap().to_string();
        let key_path = dir.path().join("test.key").to_str().unwrap().to_string();

        let opts = CsrCreateOptions {
            subject: CsrSubject {
                common_name: "nosan.example.com".to_string(),
                ..Default::default()
            },
            san: vec![],
            key_algo: KeyAlgorithm::EcdsaP256,
            encrypt_key: false,
            key_password: None,
        };

        let result = create_csr(&opts, &csr_path, &key_path).unwrap();
        assert!(result.sans.is_empty());

        // Validate should flag missing SANs
        let csr_pem = fs::read_to_string(&csr_path).unwrap();
        let validation = validate_csr(&csr_pem).unwrap();
        assert!(
            validation
                .findings
                .iter()
                .any(|f| f.severity == Severity::Error && f.message.contains("SAN"))
        );
        assert!(!validation.compliant);
    }
}
