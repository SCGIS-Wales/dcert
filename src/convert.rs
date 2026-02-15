use anyhow::{Context, Result};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::X509;
use std::fs;

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

        cert_subject = Some(cert.subject_name().entries().fold(String::new(), |mut acc, e| {
            if !acc.is_empty() {
                acc.push_str(", ");
            }
            if let Ok(data) = e.data().as_utf8() {
                acc.push_str(data.as_ref());
            }
            acc
        }));
    }

    // Write private key
    if let Some(ref pkey) = parsed.pkey {
        let key_pem = pkey
            .private_key_to_pem_pkcs8()
            .with_context(|| "Failed to encode private key as PEM")?;
        let key_path = format!("{}/key.pem", output_dir);
        fs::write(&key_path, &key_pem).with_context(|| format!("Failed to write private key: {}", key_path))?;
        output_files.push(key_path);

        key_type = Some(key_type_name(pkey));
    }

    // Write CA certificates
    let ca_count = parsed.ca.as_ref().map(|c| c.len()).unwrap_or(0);
    if let Some(ref ca_chain) = parsed.ca {
        if !ca_chain.is_empty() {
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
    }

    Ok(ConvertResult {
        input_format: "PKCS12/PFX".to_string(),
        output_format: "PEM".to_string(),
        output_files,
        cert_subject,
        key_type,
        ca_certs_count: ca_count,
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

    let cert_subject = cert.subject_name().entries().fold(String::new(), |mut acc, e| {
        if !acc.is_empty() {
            acc.push_str(", ");
        }
        if let Ok(data) = e.data().as_utf8() {
            acc.push_str(data.as_ref());
        }
        acc
    });

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

    Ok(ConvertResult {
        input_format: "PEM".to_string(),
        output_format: "PKCS12/PFX".to_string(),
        output_files: vec![output.to_string()],
        cert_subject: Some(cert_subject),
        key_type: Some(key_type),
        ca_certs_count: ca_count,
    })
}

/// Create a PKCS12 keystore from a private key + certificate (Java-compatible since JDK 9).
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
    let cert_subject = leaf_cert.subject_name().entries().fold(String::new(), |mut acc, e| {
        if !acc.is_empty() {
            acc.push_str(", ");
        }
        if let Ok(data) = e.data().as_utf8() {
            acc.push_str(data.as_ref());
        }
        acc
    });

    let key_type = key_type_name(&pkey);

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

    Ok(ConvertResult {
        input_format: "PEM".to_string(),
        output_format: "PKCS12 KeyStore".to_string(),
        output_files: vec![output.to_string()],
        cert_subject: Some(cert_subject),
        key_type: Some(key_type),
        ca_certs_count: ca_count,
    })
}

/// Create a PKCS12 truststore from CA certificates (Java-compatible since JDK 9).
pub fn create_truststore(cert_paths: &[String], password: &str, output: &str) -> Result<ConvertResult> {
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

    let ca_count = all_certs.len();

    // PKCS12 format requires a private key matching the main certificate.
    // For a truststore (CA certs only, no private key), we generate an
    // ephemeral self-signed certificate + key pair, then put all the user's
    // CA certs as the CA chain. Java can load this as a truststore.
    let rsa = openssl::rsa::Rsa::generate(2048).with_context(|| "Failed to generate ephemeral key for truststore")?;
    let pkey = PKey::from_rsa(rsa).with_context(|| "Failed to wrap ephemeral key")?;

    // Create a minimal self-signed cert for the ephemeral key
    let mut x509_builder = openssl::x509::X509::builder().with_context(|| "Failed to create X509 builder")?;
    x509_builder.set_version(2).ok();
    let serial = openssl::bn::BigNum::from_u32(1)
        .and_then(|bn| bn.to_asn1_integer())
        .with_context(|| "Failed to create serial number")?;
    x509_builder.set_serial_number(&serial).ok();
    let mut name_builder =
        openssl::x509::X509NameBuilder::new().with_context(|| "Failed to create X509 name builder")?;
    name_builder
        .append_entry_by_text("CN", "dcert-truststore-placeholder")
        .ok();
    let name = name_builder.build();
    x509_builder.set_subject_name(&name).ok();
    x509_builder.set_issuer_name(&name).ok();
    let not_before = openssl::asn1::Asn1Time::days_from_now(0).with_context(|| "Failed to create not_before")?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(3650).with_context(|| "Failed to create not_after")?;
    x509_builder.set_not_before(&not_before).ok();
    x509_builder.set_not_after(&not_after).ok();
    x509_builder.set_pubkey(&pkey).ok();
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

    Ok(ConvertResult {
        input_format: "PEM".to_string(),
        output_format: "PKCS12 TrustStore".to_string(),
        output_files: vec![output.to_string()],
        cert_subject: None,
        key_type: None,
        ca_certs_count: ca_count,
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

fn key_type_name(pkey: &PKey<openssl::pkey::Private>) -> String {
    if pkey.rsa().is_ok() {
        format!("RSA ({} bits)", pkey.bits())
    } else if pkey.ec_key().is_ok() {
        format!("EC ({} bits)", pkey.bits())
    } else {
        format!("Unknown ({} bits)", pkey.bits())
    }
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
    use openssl::x509::{X509NameBuilder, X509};
    use tempfile::TempDir;

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
        let result = create_truststore(
            &[
                ca1_path.to_str().unwrap().to_string(),
                ca2_path.to_str().unwrap().to_string(),
            ],
            "changeit",
            &ts_path,
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
