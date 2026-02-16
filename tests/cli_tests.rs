use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
        stdout.contains("TLS certificate analysis"),
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
    // Top-level help shows subcommands
    let output = dcert_bin().arg("--help").output().expect("failed to run dcert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("check"), "top-level help should list check subcommand");
    assert!(
        stdout.contains("convert"),
        "top-level help should list convert subcommand"
    );
    assert!(
        stdout.contains("verify-key"),
        "top-level help should list verify-key subcommand"
    );

    // Check subcommand help shows all check-specific flags
    let output = dcert_bin()
        .args(["check", "--help"])
        .output()
        .expect("failed to run dcert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--export-pem"));
    assert!(stdout.contains("--expired-only"));
    assert!(stdout.contains("--no-verify"));
    assert!(stdout.contains("--timeout"));
    assert!(stdout.contains("--fingerprint"));
    assert!(stdout.contains("--extensions"));
    assert!(stdout.contains("--expiry-warn"));
    assert!(stdout.contains("--diff"));
    assert!(stdout.contains("--watch"));
    assert!(stdout.contains("--sni"));
    assert!(stdout.contains("--check-revocation"));
    assert!(stdout.contains("--read-timeout"));
    // New mTLS flags
    assert!(stdout.contains("--client-cert"));
    assert!(stdout.contains("--client-key"));
    assert!(stdout.contains("--pkcs12"));
    assert!(stdout.contains("--ca-cert"));
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
    assert!(parsed.is_object(), "JSON output should be an object");
    let arr = parsed["certificates"]
        .as_array()
        .expect("should have certificates array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["common_name"], "test.example.com");
    assert!(!arr[0]["serial_number"].as_str().unwrap().is_empty());
    // PEM files should not have connection info
    assert!(parsed.get("connection").is_none() || parsed["connection"].is_null());
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
    let arr = parsed["certificates"]
        .as_array()
        .expect("should have certificates array");
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
    let arr = parsed["certificates"].as_array().unwrap();
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
    let arr = parsed["certificates"].as_array().unwrap();
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
    let arr = parsed["certificates"].as_array().unwrap();
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
    assert!(stdout.contains("Public Key"), "extensions should show public key info");
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
    let arr = parsed["certificates"].as_array().unwrap();
    // At least one cert should have extended_key_usage
    let has_eku = arr.iter().any(|c| c.get("extended_key_usage").is_some());
    assert!(has_eku, "at least one cert in chain should have EKU in JSON");
    // Every cert should have public key info when extensions are enabled
    for cert in arr {
        assert!(
            cert.get("public_key_algorithm").is_some(),
            "public_key_algorithm should be present with --extensions"
        );
        assert!(
            cert.get("public_key_size_bits").is_some(),
            "public_key_size_bits should be present with --extensions"
        );
    }
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
    // Each entry should have a certificates array
    for (_key, val) in obj {
        assert!(
            val["certificates"].is_array(),
            "each target entry should have a certificates array"
        );
    }
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
    let arr = parsed["certificates"].as_array().unwrap();
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

// ---------------------------------------------------------------
// Request body flags (--data / --data-file)
// ---------------------------------------------------------------

#[test]
fn test_help_shows_data_flags() {
    let output = dcert_bin()
        .args(["check", "--help"])
        .output()
        .expect("failed to run dcert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--data"), "help should mention --data");
    assert!(stdout.contains("--data-file"), "help should mention --data-file");
    assert!(stdout.contains("-d"), "help should mention -d short flag");
}

#[test]
fn test_data_and_data_file_conflict() {
    let pem_path = test_data("test.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--data")
        .arg("foo=bar")
        .arg("--data-file")
        .arg("somefile.txt")
        .output()
        .expect("failed to run dcert");
    assert!(
        !output.status.success(),
        "should fail when both --data and --data-file are given"
    );
}

#[test]
fn test_data_file_nonexistent() {
    let output = dcert_bin()
        .arg("https://example.com")
        .arg("--data-file")
        .arg("/nonexistent/path/body.txt")
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "should fail with nonexistent data file");
}

// ---------------------------------------------------------------
// TLS version rejection (TLS 1.0 and 1.1 are insecure)
// ---------------------------------------------------------------

#[test]
fn test_min_tls_rejects_1_0() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--min-tls")
        .arg("1.0")
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "--min-tls 1.0 should be rejected as insecure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value '1.0'"),
        "error should indicate 1.0 is not a valid value: {stderr}"
    );
}

#[test]
fn test_min_tls_rejects_1_1() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--min-tls")
        .arg("1.1")
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "--min-tls 1.1 should be rejected as insecure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value '1.1'"),
        "error should indicate 1.1 is not a valid value: {stderr}"
    );
}

#[test]
fn test_max_tls_rejects_1_0() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--max-tls")
        .arg("1.0")
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "--max-tls 1.0 should be rejected as insecure");
}

#[test]
fn test_max_tls_rejects_1_1() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--max-tls")
        .arg("1.1")
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "--max-tls 1.1 should be rejected as insecure");
}

#[test]
fn test_min_tls_accepts_1_2() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--min-tls")
        .arg("1.2")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success(), "--min-tls 1.2 should be accepted");
}

#[test]
fn test_min_tls_accepts_1_3() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--min-tls")
        .arg("1.3")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success(), "--min-tls 1.3 should be accepted");
}

// ---------------------------------------------------------------
// TLS version ordering (min <= max)
// ---------------------------------------------------------------

#[test]
fn test_min_tls_greater_than_max_tls_rejected() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--min-tls")
        .arg("1.3")
        .arg("--max-tls")
        .arg("1.2")
        .output()
        .expect("failed to run dcert");
    assert!(
        !output.status.success(),
        "--min-tls 1.3 --max-tls 1.2 should be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must not be greater than"),
        "error should mention version ordering: {stderr}"
    );
}

#[test]
fn test_no_verify_shows_warning() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--no-verify")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("WARNING") && stderr.contains("--no-verify"),
        "should warn about --no-verify on stderr: {stderr}"
    );
}

// ---------------------------------------------------------------
// Debug flag
// ---------------------------------------------------------------

#[test]
fn test_help_shows_debug_flag() {
    let output = dcert_bin()
        .args(["check", "--help"])
        .output()
        .expect("failed to run dcert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--debug"), "help should mention --debug");
}

#[test]
fn test_debug_with_pem_file() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--debug")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success(), "dcert --debug should succeed with valid PEM");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Processing target"),
        "debug should show target processing on stderr"
    );
}

#[test]
fn test_debug_does_not_contaminate_json() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .arg("--debug")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // stdout must be valid JSON (no debug contamination)
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("JSON stdout must not be contaminated by debug output");
    assert!(parsed.is_object());
    assert!(parsed["certificates"].is_array());
}

#[test]
fn test_debug_does_not_contaminate_yaml() {
    let pem_path = test_data("valid.pem");
    let output = dcert_bin()
        .arg(pem_path.to_str().unwrap())
        .arg("--format")
        .arg("yaml")
        .arg("--debug")
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("common_name"),
        "YAML output should still work with --debug"
    );
    // No debug prefix in stdout
    assert!(!stdout.contains("* ---"), "debug markers should not appear in stdout");
}

// ---------------------------------------------------------------
// verify-key: explicit pair
// ---------------------------------------------------------------

#[test]
fn test_verify_key_explicit_pair_matches() {
    let cert_path = test_data("verify-key-discovery/server.crt");
    let key_path = test_data("verify-key-discovery/server.key");
    let output = dcert_bin()
        .args([
            "verify-key",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success(), "matching cert+key should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Key matches certificate"),
        "should show match: {stdout}"
    );
}

#[test]
fn test_verify_key_explicit_pair_mismatch() {
    // Use server.crt with app.key (different key pair)
    let cert_path = test_data("verify-key-discovery/server.crt");
    let key_path = test_data("verify-key-discovery/app.key");
    let output = dcert_bin()
        .args([
            "verify-key",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run dcert");
    assert_eq!(output.status.code(), Some(7), "mismatch should exit with code 7");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("does NOT match"), "should indicate mismatch: {stdout}");
}

#[test]
fn test_verify_key_explicit_pair_json() {
    let cert_path = test_data("verify-key-discovery/server.crt");
    let key_path = test_data("verify-key-discovery/server.key");
    let output = dcert_bin()
        .args([
            "verify-key",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert_eq!(parsed["matches"], true);
    assert_eq!(parsed["key_type"], "RSA");
}

// ---------------------------------------------------------------
// verify-key: auto-discovery
// ---------------------------------------------------------------

#[test]
fn test_verify_key_auto_discovery_pretty() {
    let dir_path = test_data("verify-key-discovery");
    let output = dcert_bin()
        .args(["verify-key", "--dir", dir_path.to_str().unwrap()])
        .output()
        .expect("failed to run dcert");
    assert!(
        output.status.success(),
        "auto-discovery with matching pairs should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should find both pairs
    assert!(stdout.contains("server.crt"), "should list server.crt: {stdout}");
    assert!(stdout.contains("app.pem"), "should list app.pem: {stdout}");
    // orphan.pem should NOT appear (no matching .key)
    assert!(!stdout.contains("orphan"), "orphan.pem should be skipped: {stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("2 cert/key pair(s)"),
        "should report found pairs: {stderr}"
    );
}

#[test]
fn test_verify_key_auto_discovery_json() {
    let dir_path = test_data("verify-key-discovery");
    let output = dcert_bin()
        .args(["verify-key", "--dir", dir_path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed.is_array(), "auto-discovery JSON should be an array");
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 2, "should find 2 cert/key pairs");
    // Each result should include cert_file and key_file
    for result in arr {
        assert!(result["cert_file"].is_string(), "should have cert_file");
        assert!(result["key_file"].is_string(), "should have key_file");
        assert_eq!(result["matches"], true, "all pairs should match");
    }
}

#[test]
fn test_verify_key_auto_discovery_empty_dir() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let output = dcert_bin()
        .args(["verify-key", "--dir", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run dcert");
    assert!(
        !output.status.success(),
        "empty directory should fail with no pairs found"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No matching cert/key pairs"),
        "should indicate no pairs found: {stderr}"
    );
}

#[test]
fn test_verify_key_requires_both_or_neither() {
    // Provide target but not --key
    let cert_path = test_data("verify-key-discovery/server.crt");
    let output = dcert_bin()
        .args(["verify-key", cert_path.to_str().unwrap()])
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "target without --key should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Both target and --key must be provided together"),
        "should explain both are needed: {stderr}"
    );
}

// ---------------------------------------------------------------
// stdin PEM piping
// ---------------------------------------------------------------

#[test]
fn test_stdin_pem_with_dash_arg() {
    // Pipe PEM data via stdin with explicit '-' target
    let pem_data = std::fs::read(test_data("valid.pem")).expect("failed to read valid.pem");
    let mut child = dcert_bin()
        .args(["check", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcert");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pem_data)
        .expect("failed to write stdin");
    let output = child.wait_with_output().expect("failed to wait");
    assert!(output.status.success(), "piped PEM via stdin should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test.example.com"),
        "should parse cert from stdin: {stdout}"
    );
}

#[test]
fn test_stdin_pem_no_args() {
    // Pipe PEM data via stdin with no arguments at all (auto-detect)
    let pem_data = std::fs::read(test_data("valid.pem")).expect("failed to read valid.pem");
    let mut child = dcert_bin()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcert");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pem_data)
        .expect("failed to write stdin");
    let output = child.wait_with_output().expect("failed to wait");
    assert!(
        output.status.success(),
        "piped PEM with no args should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test.example.com"),
        "should parse cert from stdin: {stdout}"
    );
}

#[test]
fn test_stdin_base64_decoded_pem() {
    // Simulate: echo "<base64 PEM>" | base64 --decode | dcert -
    // Read the PEM file, base64-encode it, then decode in the pipeline
    let pem_data = std::fs::read(test_data("valid.pem")).expect("failed to read valid.pem");
    // The pem_data is already in PEM text format, pipe it directly as if it came from base64 --decode
    let mut child = dcert_bin()
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcert");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pem_data)
        .expect("failed to write stdin");
    let output = child.wait_with_output().expect("failed to wait");
    assert!(output.status.success(), "base64-decoded PEM pipe should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test.example.com"),
        "should parse cert from decoded stdin: {stdout}"
    );
}

#[test]
fn test_stdin_pem_json_format() {
    // Pipe PEM via stdin and request JSON output
    let pem_data = std::fs::read(test_data("valid.pem")).expect("failed to read valid.pem");
    let mut child = dcert_bin()
        .args(["check", "-", "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcert");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pem_data)
        .expect("failed to write stdin");
    let output = child.wait_with_output().expect("failed to wait");
    assert!(output.status.success(), "stdin PEM with JSON format should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should produce valid JSON");
    assert!(parsed["certificates"].is_array(), "JSON should have certificates array");
    assert_eq!(
        parsed["certificates"][0]["common_name"], "test.example.com",
        "should contain the cert CN"
    );
}

#[test]
fn test_stdin_chain_pem() {
    // Pipe a multi-cert chain via stdin
    let pem_data = std::fs::read(test_data("test.pem")).expect("failed to read test.pem");
    let mut child = dcert_bin()
        .args(["check", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcert");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pem_data)
        .expect("failed to write stdin");
    let output = child.wait_with_output().expect("failed to wait");
    assert!(output.status.success(), "stdin chain PEM should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The chain should contain multiple certificates
    let cert_count = stdout.matches("Certificate").count();
    assert!(cert_count >= 2, "chain should parse multiple certs, found {cert_count}");
}
