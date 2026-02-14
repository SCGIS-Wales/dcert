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
}

#[test]
fn test_help_flag() {
    let output = dcert_bin().arg("--help").output().expect("failed to run dcert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--export-pem"));
    assert!(stdout.contains("--expired-only"));
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
