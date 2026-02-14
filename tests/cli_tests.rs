use std::path::PathBuf;
use std::process::Command;

fn dcert_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dcert"))
}

fn test_data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name)
}

// ---------------------------------------------------------------
// Help & version output
// ---------------------------------------------------------------

#[test]
fn test_no_args_shows_help() {
    let output = dcert_bin().output().expect("failed to run dcert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Decode and validate TLS certificates"),
        "no-args output should show help text"
    );
}

#[test]
fn test_version_flag() {
    let output = dcert_bin().arg("--version").output().expect("failed to run dcert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dcert"), "version output should contain 'dcert'");
    // Version comes from git tag (via build.rs) or Cargo.toml — just verify it's a semver-like string
    let version_line = stdout.lines().next().expect("should have a version line");
    let version_part = version_line.strip_prefix("dcert ").expect("should start with 'dcert '");
    assert!(
        version_part.contains('.'),
        "version should be a dotted version string, got: {version_part}"
    );
}

#[test]
fn test_help_flag() {
    let output = dcert_bin().arg("--help").output().expect("failed to run dcert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--export-pem"));
    assert!(stdout.contains("--expired-only"));
    // Check new flags are in help
    assert!(stdout.contains("--no-verify"));
    assert!(stdout.contains("--timeout"));
    assert!(stdout.contains("--fingerprint"));
    assert!(stdout.contains("--extensions"));
    assert!(stdout.contains("--expiry-warn"));
    assert!(stdout.contains("--diff"));
    assert!(stdout.contains("--watch"));
    assert!(stdout.contains("--sni"));
    assert!(stdout.contains("--check-revocation"));
}

// ---------------------------------------------------------------
// PEM file parsing (pretty output)
// ---------------------------------------------------------------

#[test]
fn test_parse_valid_pem_pretty() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success(), "dcert should succeed with valid PEM");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Certificate"),
        "output should contain Certificate header"
    );
    assert!(stdout.contains("test.example.com"), "output should contain the CN");
    assert!(stdout.contains("Subject"), "output should contain Subject field");
    assert!(stdout.contains("Issuer"), "output should contain Issuer field");
    assert!(stdout.contains("Serial"), "output should contain Serial field");
}

#[test]
fn test_parse_chain_pem_pretty() {
    let pem_path = test_data("test.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show multiple certificates
    let cert_count = stdout.matches("Certificate").count();
    assert!(
        cert_count >= 3,
        "expected at least 3 Certificate sections, got {}",
        cert_count
    );
}

// ---------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------

#[test]
fn test_parse_valid_pem_json() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert!(parsed.is_array(), "JSON output should be an array");
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["common_name"], "test.example.com");
    assert!(!arr[0]["serial_number"].as_str().unwrap().is_empty());
}

#[test]
fn test_parse_chain_json() {
    let pem_path = test_data("test.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 3, "chain should have 3 certs");
}

// ---------------------------------------------------------------
// YAML output
// ---------------------------------------------------------------

#[test]
fn test_parse_valid_pem_yaml() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--format")
        .arg("yaml")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("common_name"), "YAML output should contain common_name");
    assert!(stdout.contains("test.example.com"), "YAML output should contain the CN");
    assert!(stdout.contains("subject:"), "YAML output should contain subject");
}

// ---------------------------------------------------------------
// Export PEM
// ---------------------------------------------------------------

#[test]
fn test_export_pem() {
    let pem_path = test_data("valid.pem");
    let dir = tempfile::tempdir().unwrap();
    let export_path = dir.path().join("exported.pem");

    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--export-pem")
        .arg(export_path.to_str().unwrap())
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    assert!(export_path.exists(), "exported PEM file should exist");

    let exported = std::fs::read_to_string(&export_path).unwrap();
    assert!(
        exported.contains("-----BEGIN CERTIFICATE-----"),
        "exported file should contain PEM data"
    );
}

// ---------------------------------------------------------------
// Sort expiry
// ---------------------------------------------------------------

#[test]
fn test_sort_expiry_asc_json() {
    let pem_path = test_data("test.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .arg("--sort-expiry")
        .arg("asc")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = parsed.as_array().unwrap();
    // Verify ascending order
    for i in 1..arr.len() {
        let prev = arr[i - 1]["not_after"].as_str().unwrap();
        let curr = arr[i]["not_after"].as_str().unwrap();
        assert!(prev <= curr, "expected ascending order: {} <= {}", prev, curr);
    }
}

#[test]
fn test_sort_expiry_desc_json() {
    let pem_path = test_data("test.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .arg("--sort-expiry")
        .arg("desc")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = parsed.as_array().unwrap();
    // Verify descending order
    for i in 1..arr.len() {
        let prev = arr[i - 1]["not_after"].as_str().unwrap();
        let curr = arr[i]["not_after"].as_str().unwrap();
        assert!(prev >= curr, "expected descending order: {} >= {}", prev, curr);
    }
}

// ---------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------

#[test]
fn test_fingerprint_pretty() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--fingerprint")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SHA-256"), "pretty output should contain SHA-256 field");
    // Should have colon-separated hex
    assert!(stdout.contains(":"), "fingerprint should contain colons");
}

#[test]
fn test_fingerprint_json() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .arg("--fingerprint")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let fp = arr[0]["sha256_fingerprint"].as_str().unwrap();
    assert_eq!(fp.len(), 95, "fingerprint should be 95 chars (AA:BB:CC:... format)");
}

// ---------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------

#[test]
fn test_extensions_pretty() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--extensions")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Sig Algorithm"),
        "extensions should show signature algorithm"
    );
    assert!(
        stdout.contains("Basic Constr"),
        "extensions should show basic constraints for self-signed cert"
    );
}

#[test]
fn test_extensions_json() {
    let pem_path = test_data("test.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .arg("--extensions")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = parsed.as_array().unwrap();
    // At least one cert should have extended_key_usage
    let has_eku = arr.iter().any(|c| c.get("extended_key_usage").is_some());
    assert!(has_eku, "at least one cert in chain should have EKU in JSON");
}

// ---------------------------------------------------------------
// Expiry warning
// ---------------------------------------------------------------

#[test]
fn test_expiry_warn_no_warning() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--expiry-warn")
        .arg("7")
        .output()
        .expect("failed to run dcert");
    // Exit code 0 since cert doesn't expire within 7 days
    assert!(output.status.success(), "no warning for distant expiry");
}

#[test]
fn test_expiry_warn_triggers() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--expiry-warn")
        .arg("400")
        .output()
        .expect("failed to run dcert");
    // Exit code 1 since cert expires within 400 days
    assert_eq!(
        output.status.code(),
        Some(1),
        "should exit with 1 when cert expires within horizon"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("WARNING"), "should print warning to stderr");
}

// ---------------------------------------------------------------
// Multiple targets
// ---------------------------------------------------------------

#[test]
fn test_multiple_pem_targets_pretty() {
    let pem_path1 = test_data("valid.pem");
    let pem_path2 = test_data("test.pem");
    let output = dcert_bin()
        .arg(pem_path1.to_str().unwrap())
        .arg(pem_path2.to_str().unwrap())
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should contain headers for both targets
    assert!(stdout.contains("---"), "multi-target output should contain separators");
}

#[test]
fn test_multiple_pem_targets_json() {
    let pem_path1 = test_data("valid.pem");
    let pem_path2 = test_data("test.pem");
    let output = dcert_bin()
        .arg(pem_path1.to_str().unwrap())
        .arg(pem_path2.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert!(
        parsed.is_object(),
        "multi-target JSON should be an object keyed by target"
    );
    let obj = parsed.as_object().unwrap();
    assert_eq!(obj.len(), 2, "should have 2 target entries");
}

// ---------------------------------------------------------------
// Diff mode
// ---------------------------------------------------------------

#[test]
fn test_diff_same_file() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg(pem_path.to_str().unwrap())
        .arg("--diff")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Certificate Diff"), "diff output should contain header");
}

#[test]
fn test_diff_different_files() {
    let pem_path1 = test_data("valid.pem");
    let pem_path2 = test_data("test.pem");
    let output = dcert_bin()
        .arg(pem_path1.to_str().unwrap())
        .arg(pem_path2.to_str().unwrap())
        .arg("--diff")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Certificate Diff"), "diff output should contain header");
    // Subjects are different, so should show differences
    assert!(stdout.contains("→"), "diff should show changes with arrow");
}

#[test]
fn test_diff_requires_two_targets() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--diff")
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "diff with 1 target should fail");
}

// ---------------------------------------------------------------
// Combined flags
// ---------------------------------------------------------------

#[test]
fn test_fingerprint_and_extensions_together() {
    let pem_path = test_data("test.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--fingerprint")
        .arg("--extensions")
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = parsed.as_array().unwrap();
    // Every cert should have a fingerprint
    for cert in arr {
        assert!(
            cert.get("sha256_fingerprint").is_some(),
            "fingerprint should be present"
        );
        assert!(
            cert.get("signature_algorithm").is_some(),
            "signature_algorithm should be present"
        );
    }
}

// ---------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------

#[test]
fn test_nonexistent_file_fails() {
    let output = dcert_bin()
        .arg("/nonexistent/path/to/file.pem")
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "should fail with nonexistent file");
}

#[test]
fn test_invalid_url_scheme() {
    let output = dcert_bin()
        .arg("http://example.com")
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "should fail with http:// (not https://)");
}
