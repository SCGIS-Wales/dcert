use anyhow::Result;
use openssl::hash::MessageDigest;
use std::net::IpAddr;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

pub const OID_X509_SCT_LIST: x509_parser::asn1_rs::Oid<'static> =
    x509_parser::oid_registry::asn1_rs::oid!(1.3.6.1.4.1.11129.2.4.2);

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
    /// OCSP responder URLs from the AIA extension. `None` when extensions were
    /// not extracted; `Some(empty)` when they were and the certificate carries
    /// no OCSP URL, so compliance checks can tell "not parsed" from "absent".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocsp_urls: Option<Vec<String>>,
    /// URIs from the CRL Distribution Points extension (RFC 5280 4.2.1.13).
    /// Same `None` / `Some(empty)` convention as `ocsp_urls`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_distribution_points: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_status: Option<String>,
    /// Set when this certificate is itself present in the chain and is (or is
    /// not) a recognized publicly trusted root CA. Usually `None` because the
    /// root is not sent by the server; populated for full-chain PEM input or
    /// servers that include the root. See chain-level `root_trust` for the verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_public_root: Option<bool>,
}

#[derive(Debug, serde::Serialize, Clone)]
pub struct BasicConstraintsInfo {
    pub ca: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_len_constraint: Option<u32>,
}

/// Options controlling what extra information to extract from certificates.
#[derive(Debug, Clone, Copy, Default)]
pub struct CertProcessOpts {
    pub expired_only: bool,
    pub fingerprint: bool,
    pub extensions: bool,
}

/// Count individual SCTs (Signed Certificate Timestamps) inside the value of
/// an X.509 SCT-list extension (OID 1.3.6.1.4.1.11129.2.4.2).
///
/// The extension value is an ASN.1 OCTET STRING wrapping a TLS-encoded
/// `SignedCertificateTimestampList` (RFC 6962 §3.3): a 2-byte total length
/// followed by length-prefixed SCT entries (2-byte length each).
///
/// Returns `Some(count)` on success or `None` when the value is too short
/// or structurally invalid. Uses `checked_add` throughout so a malformed
/// list claiming a huge `sct_len` cannot wrap `usize` and trigger
/// out-of-bounds panics or denial-of-service via infinite loops.
fn count_scts(data: &[u8]) -> Option<usize> {
    // The outer layer is an ASN.1 OCTET STRING; parse it to get inner bytes.
    let inner = if data.len() > 2 && data[0] == 0x04 {
        // Simple DER OCTET STRING: tag=0x04, length, value
        let len_byte = data[1] as usize;
        if len_byte < 0x80 && data.len() >= 2 + len_byte {
            &data[2..2 + len_byte]
        } else if len_byte == 0x81 && data.len() > 3 {
            let len = data[2] as usize;
            if data.len() >= 3 + len { &data[3..3 + len] } else { data }
        } else if len_byte == 0x82 && data.len() > 4 {
            let len = ((data[2] as usize) << 8) | (data[3] as usize);
            if data.len() >= 4 + len { &data[4..4 + len] } else { data }
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
    let mut offset: usize = 2;
    let end = 2usize
        .checked_add(total_len)
        .map(|e| e.min(inner.len()))
        .unwrap_or(inner.len());
    let mut count = 0usize;
    // Guard against malformed SCT lists that claim huge lengths.
    // `checked_add` prevents wrap-around when `sct_len` is near `usize::MAX`
    // on a malicious input; on overflow we stop counting cleanly.
    while offset.checked_add(2).is_some_and(|o| o <= end) {
        let sct_len = ((inner[offset] as usize) << 8) | (inner[offset + 1] as usize);
        let Some(next) = offset.checked_add(2).and_then(|o| o.checked_add(sct_len)) else {
            break;
        };
        if next > end {
            break;
        }
        offset = next;
        count += 1;
    }
    Some(count)
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
    let serial_number = serial_bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();

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

    let sct_ext = cert.extensions().iter().find(|ext| ext.oid == OID_X509_SCT_LIST);
    let ct_present = sct_ext.is_some();

    let sct_count: Option<usize> = if opts.extensions {
        sct_ext.and_then(|ext| count_scts(ext.value))
    } else {
        None
    };

    // SHA-256 fingerprint
    let sha256_fingerprint = if opts.fingerprint {
        Some(fingerprint_sha256_hex(der_bytes)?)
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
        let alg_name = public_key_algorithm_name(&alg_oid);
        // Compute key size correctly based on algorithm type:
        // - RSA: parse the DER-encoded RSAPublicKey to get the modulus bit length
        // - EC: derive from the curve parameters OID or uncompressed point size
        // - Ed25519/Ed448/X25519: fixed key sizes
        // - ML-DSA, ML-KEM, SLH-DSA and anything else: the encoded public key
        //   length in bits (there is no modulus or curve to measure)
        let key_bits = match alg_oid.as_str() {
            "1.2.840.113549.1.1.1" => {
                // RSA: SubjectPublicKey contains DER-encoded RSAPublicKey (SEQUENCE { modulus, exponent })
                // Parse the modulus length from the DER encoding
                openssl::rsa::Rsa::public_key_from_der(&spki.subject_public_key.data)
                    .map(|rsa| rsa.size() * 8)
                    .unwrap_or_else(|_| u32::try_from(spki.subject_public_key.data.len() * 8).unwrap_or(u32::MAX))
            }
            "1.2.840.10045.2.1" => {
                // EC: uncompressed point is 1 + 2*field_size bytes; field_size = (key_bits + 7) / 8
                // For P-256: 65 bytes → 256 bits, P-384: 97 bytes → 384 bits, P-521: 133 bytes → 521 bits
                let point_len = spki.subject_public_key.data.len();
                if point_len > 1 {
                    u32::try_from(((point_len - 1) / 2) * 8).unwrap_or(u32::MAX)
                } else {
                    0
                }
            }
            "1.3.101.112" => 256, // Ed25519
            "1.3.101.113" => 448, // Ed448
            "1.3.101.110" => 256, // X25519
            _ => u32::try_from(spki.subject_public_key.data.len() * 8).unwrap_or(u32::MAX),
        };
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
                ParsedExtension::AuthorityInfoAccess(_) => {
                    let urls = aia_entries(&cert);
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

    // Revocation pointers, kept apart from the AIA listing so compliance can
    // distinguish "extensions not parsed" from "no OCSP / CRL URL present".
    let (ocsp_urls, crl_distribution_points) = if opts.extensions {
        (
            Some(aia_uris(&cert, AiaMethod::Ocsp)),
            Some(crl_distribution_point_uris(&cert)),
        )
    } else {
        (None, None)
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
        ocsp_urls,
        crl_distribution_points,
        revocation_status: None,
        is_public_root: None,
    }))
}

/// Human readable name for a SubjectPublicKeyInfo algorithm OID.
///
/// Covers the classical algorithms, the EdDSA and X25519/X448 curves and the
/// NIST post quantum algorithms (ML-DSA, FIPS 204; ML-KEM, FIPS 203; SLH-DSA,
/// FIPS 205) by their CSOR OIDs, so a post quantum key is reported by name
/// rather than as a bare OID. Unknown OIDs are returned unchanged.
pub fn public_key_algorithm_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.10040.4.1" => "DSA",
        "1.3.101.110" => "X25519",
        "1.3.101.111" => "X448",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        "2.16.840.1.101.3.4.3.17" => "ML-DSA-44",
        "2.16.840.1.101.3.4.3.18" => "ML-DSA-65",
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87",
        "2.16.840.1.101.3.4.4.1" => "ML-KEM-512",
        "2.16.840.1.101.3.4.4.2" => "ML-KEM-768",
        "2.16.840.1.101.3.4.4.3" => "ML-KEM-1024",
        other => return slh_dsa_name(other).map_or_else(|| other.to_string(), ToString::to_string),
    }
    .to_string()
}

/// Name of an SLH-DSA (FIPS 205) parameter set by its CSOR OID
/// (2.16.840.1.101.3.4.3.20 through .31), or `None`.
pub fn slh_dsa_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.16.840.1.101.3.4.3.20" => "SLH-DSA-SHA2-128s",
        "2.16.840.1.101.3.4.3.21" => "SLH-DSA-SHA2-128f",
        "2.16.840.1.101.3.4.3.22" => "SLH-DSA-SHA2-192s",
        "2.16.840.1.101.3.4.3.23" => "SLH-DSA-SHA2-192f",
        "2.16.840.1.101.3.4.3.24" => "SLH-DSA-SHA2-256s",
        "2.16.840.1.101.3.4.3.25" => "SLH-DSA-SHA2-256f",
        "2.16.840.1.101.3.4.3.26" => "SLH-DSA-SHAKE-128s",
        "2.16.840.1.101.3.4.3.27" => "SLH-DSA-SHAKE-128f",
        "2.16.840.1.101.3.4.3.28" => "SLH-DSA-SHAKE-192s",
        "2.16.840.1.101.3.4.3.29" => "SLH-DSA-SHAKE-192f",
        "2.16.840.1.101.3.4.3.30" => "SLH-DSA-SHAKE-256s",
        "2.16.840.1.101.3.4.3.31" => "SLH-DSA-SHAKE-256f",
        _ => return None,
    })
}

/// Every URI named by the CRL Distribution Points extension, in certificate
/// order. Only `fullName` URIs are returned; `nameRelativeToCRLIssuer` and
/// non-URI general names cannot be fetched and are skipped.
pub fn crl_distribution_point_uris(cert: &X509Certificate<'_>) -> Vec<String> {
    use x509_parser::extensions::DistributionPointName;
    let mut urls = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
            for point in points.iter() {
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            urls.push(uri.to_string());
                        }
                    }
                }
            }
        }
    }
    urls
}

/// Parse all PEM certificate blocks from `pem_data` and return owned `CertInfo`
/// for each certificate. We do not store `X509Certificate` to avoid lifetime issues.
pub fn parse_cert_infos_from_pem(pem_data: &str, opts: &CertProcessOpts) -> Result<Vec<CertInfo>> {
    let blocks = pem::parse_many(pem_data).map_err(|e| anyhow::anyhow!("Failed to parse PEM: {e}"))?;

    let mut infos = Vec::new();
    let mut errors = Vec::new();
    let mut cert_idx = 0usize;

    for block in &blocks {
        if block.tag() != "CERTIFICATE" {
            continue;
        }

        match X509Certificate::from_der(block.contents()) {
            Ok((_, cert)) => {
                match process_certificate(cert, block.contents(), cert_idx, opts) {
                    Ok(Some(info)) => infos.push(info),
                    Ok(None) => {} // Filtered out (e.g., not expired when expired_only is true)
                    Err(e) => errors.push(format!("Certificate {cert_idx}: {e}")),
                }
            }
            Err(e) => {
                errors.push(format!("Certificate {cert_idx} parsing failed: {e}"));
            }
        }
        cert_idx += 1;
    }

    // Return results even if some certs failed, but warn about errors
    if !errors.is_empty() {
        eprintln!("Warning: Some certificates had issues:");
        for error in &errors {
            eprintln!("  - {error}");
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

pub fn extract_common_name(cert: &X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_attributes()
        .find(|attr| *attr.attr_type() == x509_parser::oid_registry::OID_X509_COMMON_NAME)
        .and_then(|attr| attr.attr_value().as_str().ok())
        .map(ToString::to_string)
}

pub fn extract_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut out = Vec::new();

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                match gn {
                    GeneralName::DNSName(d) => out.push(format!("DNS:{d}")),
                    GeneralName::RFC822Name(e) => out.push(format!("Email:{e}")),
                    GeneralName::URI(u) => out.push(format!("URI:{u}")),
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

/// Result of verifying that a private key matches a certificate.
#[derive(Debug, serde::Serialize)]
pub struct KeyMatchResult {
    pub matches: bool,
    pub key_type: String,
    pub key_size_bits: u32,
    pub cert_subject: String,
    pub cert_public_key_algorithm: String,
    pub cert_public_key_size_bits: u32,
    pub details: String,
}

/// Report the public-key algorithm of an OpenSSL key by its key id.
///
/// Unlike probing `rsa()`/`ec_key()` and falling back to a bare `"Unknown"`,
/// `id()` always reflects the real algorithm, so EdDSA/DSA keys are named
/// instead of being silently bucketed as unknown.
pub fn pkey_algorithm<T>(pkey: &openssl::pkey::PKey<T>) -> String {
    use openssl::pkey::Id;
    match pkey.id() {
        Id::RSA => "RSA".to_string(),
        Id::RSA_PSS => "RSA-PSS".to_string(),
        Id::EC => "EC".to_string(),
        Id::ED25519 => "Ed25519".to_string(),
        Id::ED448 => "Ed448".to_string(),
        Id::DSA => "DSA".to_string(),
        other => format!("Unknown ({other:?})"),
    }
}

/// Fetch the presented chain of `target` as PEM, over HTTPS or, with
/// `--starttls`, over the mail or FTP protocol upgrade. Every setting comes
/// from `probe`, the same builder `check` uses.
fn fetch_chain_pem(target: &str, probe: &crate::tlsopts::ProbeOptions<'_>) -> Result<String> {
    if let Some(protocol) = probe.tls.starttls {
        let (host, port) = crate::output::starttls_host_port(target, protocol.default_port());
        let conn = crate::tls::fetch_tls_chain_starttls(&crate::tls::StarttlsFetchOptions {
            probe: probe.tls_probe(),
            host: &host,
            port,
            protocol,
            identity: probe.identity,
        })?;
        return Ok(conn.pem_data);
    }
    let conn = crate::tls::fetch_tls_chain_openssl(&crate::tls::TlsFetchOptions {
        probe: probe.tls_probe(),
        endpoint: target,
        method: "GET",
        headers: &[],
        body: None,
        http_protocol: crate::cli::HttpProtocol::Http1_1,
        proxy_config: &probe.proxy,
        identity: probe.identity,
        body_limit: 0,
    })?;
    Ok(conn.pem_data)
}

/// Verify that the private key in `key_path` matches the certificate in
/// `target`: a PEM file, an HTTPS URL, or with `--starttls` a host[:port].
/// Network targets are fetched with the TLS and connection settings in
/// `probe` (proxy, overrides, SNI, CA bundle, timeouts).
pub fn verify_key_matches_cert(
    key_path: &str,
    target: &str,
    probe: &crate::tlsopts::ProbeOptions<'_>,
) -> Result<KeyMatchResult> {
    use crate::debug::debug_log;
    use openssl::pkey::PKey;
    let debug = probe.debug;

    // Load private key
    debug_log!(debug, "Loading private key from: {}", key_path);
    // Zeroizing: the PEM bytes hold the private key and are wiped on drop.
    let key_data = std::fs::read(key_path)
        .map(zeroize::Zeroizing::new)
        .map_err(|e| anyhow::anyhow!("Failed to read private key '{key_path}': {e}"))?;
    let private_key = PKey::private_key_from_pem(&key_data)
        .map_err(|e| anyhow::anyhow!("Failed to parse private key '{key_path}': {e}"))?;

    let key_type = pkey_algorithm(&private_key);
    let key_size_bits = private_key.bits();
    debug_log!(debug, "Key type: {} ({} bits)", key_type, key_size_bits);

    // Load certificate PEM data
    let cert_pem = if target.starts_with("https://") || probe.tls.starttls.is_some() {
        debug_log!(debug, "Fetching certificate from: {}", target);
        fetch_chain_pem(target, probe)?
    } else {
        std::fs::read_to_string(target).map_err(|e| anyhow::anyhow!("Failed to read certificate '{target}': {e}"))?
    };

    // Parse the first certificate
    let cert = openssl::x509::X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM certificate: {e}"))?;

    let cert_subject = format_x509_name(cert.subject_name());
    debug_log!(debug, "Certificate subject: {}", cert_subject);

    let cert_pubkey = cert
        .public_key()
        .map_err(|e| anyhow::anyhow!("Failed to extract public key from certificate: {e}"))?;

    let cert_key_alg = pkey_algorithm(&cert_pubkey);
    let cert_key_size = cert_pubkey.bits();

    // Compare public keys
    let matches = private_key.public_eq(&cert_pubkey);

    let details = if matches {
        "Public key from private key matches certificate's public key".to_string()
    } else if key_type != cert_key_alg {
        format!("Key type mismatch: private key is {key_type} but certificate uses {cert_key_alg}")
    } else {
        "Public key from private key does not match certificate's public key".to_string()
    };

    debug_log!(debug, "Match result: {}", matches);

    Ok(KeyMatchResult {
        matches,
        key_type,
        key_size_bits,
        cert_subject,
        cert_public_key_algorithm: cert_key_alg,
        cert_public_key_size_bits: cert_key_size,
        details,
    })
}

/// Extract OCSP responder URL from a certificate's Authority Information Access extension.
pub fn extract_ocsp_url(cert: &X509Certificate<'_>) -> Option<String> {
    aia_uris(cert, AiaMethod::Ocsp).into_iter().next()
}

/// Access methods carried in the Authority Information Access extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiaMethod {
    /// `id-ad-ocsp` (1.3.6.1.5.5.7.48.1)
    Ocsp,
    /// `id-ad-caIssuers` (1.3.6.1.5.5.7.48.2)
    CaIssuers,
}

impl AiaMethod {
    fn oid(self) -> &'static str {
        match self {
            AiaMethod::Ocsp => "1.3.6.1.5.5.7.48.1",
            AiaMethod::CaIssuers => "1.3.6.1.5.5.7.48.2",
        }
    }

    /// Human readable label used in extension listings.
    pub fn label(self) -> &'static str {
        match self {
            AiaMethod::Ocsp => "OCSP",
            AiaMethod::CaIssuers => "CA Issuers",
        }
    }

    fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            "1.3.6.1.5.5.7.48.1" => Some(AiaMethod::Ocsp),
            "1.3.6.1.5.5.7.48.2" => Some(AiaMethod::CaIssuers),
            _ => None,
        }
    }
}

/// Every URI in the AIA extension for the given access method, in
/// certificate order. Non-URI access locations are skipped.
pub fn aia_uris(cert: &X509Certificate<'_>, method: AiaMethod) -> Vec<String> {
    let mut urls = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                if desc.access_method.to_id_string() == method.oid()
                    && let GeneralName::URI(uri) = &desc.access_location
                {
                    urls.push(uri.to_string());
                }
            }
        }
    }
    urls
}

/// Render every AIA entry as `"<method>: <location>"`, the shape shown in
/// the `--extensions` listing.
pub fn aia_entries(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut entries = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                let method_oid = desc.access_method.to_id_string();
                let method =
                    AiaMethod::from_oid(&method_oid).map_or_else(|| method_oid.clone(), |m| m.label().to_string());
                match &desc.access_location {
                    GeneralName::URI(uri) => entries.push(format!("{method}: {uri}")),
                    _ => entries.push(format!("{method}: (non-URI)")),
                }
            }
        }
    }
    entries
}

/// Collect the entries of an OpenSSL `X509Name` into a comma separated list of
/// values (`Example Ltd, GB, api.example.com`). Used wherever a compact
/// subject or issuer string is shown.
pub fn format_x509_name(name: &openssl::x509::X509NameRef) -> String {
    name.entries().fold(String::new(), |mut acc, e| {
        if !acc.is_empty() {
            acc.push_str(", ");
        }
        if let Ok(data) = e.data().to_string() {
            acc.push_str(&data);
        }
        acc
    })
}

/// Render an OpenSSL `X509Name` as `CN=..., O=..., C=...`.
pub fn format_x509_name_with_keys(name: &openssl::x509::X509NameRef) -> String {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let key = entry.object().nid().short_name().unwrap_or("?");
        if let Ok(value) = entry.data().to_string() {
            parts.push(format!("{key}={value}"));
        }
    }
    parts.join(", ")
}

/// Colon separated uppercase SHA-256 fingerprint of a DER encoded certificate.
pub fn fingerprint_sha256_hex(der: &[u8]) -> Result<String> {
    let digest =
        openssl::hash::hash(MessageDigest::sha256(), der).map_err(|e| anyhow::anyhow!("SHA-256 hash failed: {e}"))?;
    Ok(digest.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
}

/// Colon separated uppercase SHA-256 fingerprint of an OpenSSL certificate.
/// Returns an empty string if the digest cannot be computed.
pub fn fingerprint_hex(cert: &openssl::x509::X509Ref) -> String {
    cert.digest(MessageDigest::sha256())
        .map(|d| d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
        .unwrap_or_default()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::path::PathBuf;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

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
            subject: common_name.map(|cn| format!("CN={cn}")).unwrap_or_default(),
            issuer: "CN=Test CA".to_string(),
            common_name: common_name.map(ToString::to_string),
            subject_alternative_names: sans.into_iter().map(ToString::to_string).collect(),
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
            ocsp_urls: None,
            crl_distribution_points: None,
            revocation_status: None,
            is_public_root: None,
        }
    }

    // ---------------------------------------------------------------
    // Public key algorithm naming (classical and post quantum OIDs)
    // ---------------------------------------------------------------

    #[test]
    fn public_key_algorithm_name_covers_classical_and_post_quantum_oids() {
        assert_eq!(public_key_algorithm_name("1.2.840.113549.1.1.1"), "RSA");
        assert_eq!(public_key_algorithm_name("1.2.840.10045.2.1"), "EC");
        assert_eq!(public_key_algorithm_name("1.3.101.112"), "Ed25519");
        assert_eq!(public_key_algorithm_name("1.3.101.113"), "Ed448");
        assert_eq!(public_key_algorithm_name("2.16.840.1.101.3.4.3.17"), "ML-DSA-44");
        assert_eq!(public_key_algorithm_name("2.16.840.1.101.3.4.3.18"), "ML-DSA-65");
        assert_eq!(public_key_algorithm_name("2.16.840.1.101.3.4.3.19"), "ML-DSA-87");
        assert_eq!(public_key_algorithm_name("2.16.840.1.101.3.4.4.2"), "ML-KEM-768");
        assert_eq!(
            public_key_algorithm_name("2.16.840.1.101.3.4.3.20"),
            "SLH-DSA-SHA2-128s"
        );
        assert_eq!(
            public_key_algorithm_name("2.16.840.1.101.3.4.3.31"),
            "SLH-DSA-SHAKE-256f"
        );
        // Unknown OIDs pass through unchanged rather than becoming "unknown".
        assert_eq!(public_key_algorithm_name("1.2.3.4.5"), "1.2.3.4.5");
        assert_eq!(slh_dsa_name("2.16.840.1.101.3.4.3.32"), None);
    }

    // ---------------------------------------------------------------
    // Revocation pointers
    // ---------------------------------------------------------------

    #[test]
    fn revocation_pointers_are_none_without_extensions() {
        let infos = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        assert!(infos[0].ocsp_urls.is_none());
        assert!(infos[0].crl_distribution_points.is_none());
    }

    /// Minimal DER TLV encoder for the hand built extensions below.
    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = contents.len();
        if len < 0x80 {
            out.push(u8::try_from(len).unwrap());
        } else {
            out.push(0x82);
            out.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        }
        out.extend_from_slice(contents);
        out
    }

    /// A self-signed certificate carrying a CRL distribution point and an
    /// OCSP responder URL, built with raw DER extensions because the
    /// shipped test fixtures carry neither.
    fn cert_with_revocation_pointers() -> String {
        use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::x509::{X509, X509Extension, X509NameBuilder};

        let key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "revocation.example.com").unwrap();
        let name = name.build();

        // CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
        //   DistributionPoint ::= SEQUENCE { distributionPoint [0] EXPLICIT
        //   DistributionPointName } where fullName is [0] IMPLICIT GeneralNames
        //   and the URI is GeneralName [6] IMPLICIT IA5String.
        let uri = der(0x86, b"http://crl.example.com/ca.crl");
        let crl_dp = der(0x30, &der(0x30, &der(0xA0, &der(0xA0, &uri))));
        // AuthorityInfoAccess ::= SEQUENCE OF AccessDescription { OID, GeneralName }
        let ocsp_oid = der(0x06, &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]);
        let mut access = ocsp_oid;
        access.extend(der(0x86, b"http://ocsp.example.com"));
        let aia = der(0x30, &der(0x30, &access));

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(30).unwrap()).unwrap();
        for (oid, value) in [("2.5.29.31", crl_dp), ("1.3.6.1.5.5.7.1.1", aia)] {
            let ext = X509Extension::new_from_der(
                &Asn1Object::from_str(oid).unwrap(),
                false,
                &Asn1OctetString::new_from_bytes(&value).unwrap(),
            )
            .unwrap();
            builder.append_extension(ext).unwrap();
        }
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
    }

    #[test]
    fn revocation_pointers_are_extracted_with_extensions() {
        let pem = cert_with_revocation_pointers();
        let infos = parse_cert_infos_from_pem(&pem, &opts_with_extensions()).unwrap();
        let leaf = &infos[0];
        assert_eq!(
            leaf.crl_distribution_points.as_deref(),
            Some(&["http://crl.example.com/ca.crl".to_string()][..])
        );
        assert_eq!(
            leaf.ocsp_urls.as_deref(),
            Some(&["http://ocsp.example.com".to_string()][..])
        );
        // Parsed but absent: Some(empty) rather than None, so compliance can
        // tell "not extracted" from "the certificate has no pointer".
        let plain = parse_cert_infos_from_pem(VALID_PEM, &opts_with_extensions()).unwrap();
        assert_eq!(plain[0].ocsp_urls.as_deref(), Some(&[][..]));
        assert_eq!(plain[0].crl_distribution_points.as_deref(), Some(&[][..]));
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
            "serial should be hex, got: {serial}"
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
        let mixed = format!("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----\n{VALID_PEM}");
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
    fn test_valid_cert_from_file() -> Result<()> {
        let path = PathBuf::from("tests/data/valid.pem");
        assert!(path.exists(), "tests/data/valid.pem is missing");
        let pem = std::fs::read_to_string(&path)?;
        let infos = parse_cert_infos_from_pem(&pem, &default_opts())?;
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].common_name.as_deref(), Some("test.example.com"));
        Ok(())
    }

    #[test]
    fn test_chain_from_external_file() -> Result<()> {
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
        let yaml = serde_norway::to_string(&info).unwrap();
        assert!(yaml.contains("common_name"), "YAML should contain common_name");
        assert!(yaml.contains("test"), "YAML should contain the CN value");
    }

    // ---------------------------------------------------------------
    // count_scts: malformed input must not panic or hang
    // ---------------------------------------------------------------

    #[test]
    fn count_scts_handles_empty_input() {
        assert_eq!(count_scts(&[]), None);
    }

    #[test]
    fn count_scts_handles_too_short_for_total_length() {
        // OCTET STRING tag + length byte but no value: parser falls through to
        // treating the raw bytes as the TLS list, total_len exceeds the slice
        // so end clamps and the loop yields zero SCTs without panicking.
        assert_eq!(count_scts(&[0x04, 0x01]), Some(0));
    }

    #[test]
    fn count_scts_counts_simple_two_sct_list() {
        // OCTET STRING (0x04) of len 8: total_len=6, SCT1 len=1, SCT2 len=1
        let data = &[0x04, 0x08, 0x00, 0x06, 0x00, 0x01, b'A', 0x00, 0x01, b'B'];
        assert_eq!(count_scts(data), Some(2));
    }

    #[test]
    fn count_scts_does_not_panic_on_malicious_huge_sct_len() {
        // Synthetic SCT extension where sct_len claims 0xFFFF but only 1 byte
        // of payload is actually present. A naive `offset += 2 + sct_len`
        // would wrap on 32-bit hosts and could mis-index on any host;
        // `checked_add` + `next > end` makes us stop cleanly.
        let data = &[
            0x04, 0x05, // OCTET STRING, length 5
            0x00, 0x03, // total_len = 3 (claimed)
            0xff, 0xff, // sct_len = 0xFFFF (much larger than payload)
            b'X', // 1 byte of payload
        ];
        // Should return Some(0) — we couldn't fit the claimed SCT and bailed.
        let result = count_scts(data);
        assert!(result.is_some(), "must return Some, got {result:?}");
        assert!(result.unwrap() < 100, "must not loop into a huge count: {result:?}");
    }

    #[test]
    fn count_scts_handles_total_len_overflow_against_inner_slice() {
        // total_len far exceeds the inner slice — `end` clamps to inner.len()
        // and the loop terminates immediately.
        let data = &[0x04, 0x04, 0xff, 0xff, 0x00, 0x00];
        let result = count_scts(data);
        assert!(result.is_some());
    }
}
