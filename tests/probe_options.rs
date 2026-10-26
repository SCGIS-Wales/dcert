//! Shared probe options (plan PR 3.1): `verify-key` reaches its target with
//! the same TLS and connection settings as `check`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use std::path::{Path, PathBuf};
use support::{Identity, TlsServer, dcert_bin, json_output, test_data, test_pki};

/// Write the test CA and the RSA leaf key into `dir`.
fn write_pki(dir: &Path) -> (PathBuf, PathBuf) {
    let pki = test_pki();
    let ca = dir.join("ca.pem");
    let key = dir.join("leaf.key");
    std::fs::write(&ca, pki.ca_pem()).expect("write CA");
    std::fs::write(&key, pki.rsa.key.private_key_to_pem_pkcs8().expect("key PEM")).expect("write key");
    (ca, key)
}

#[test]
fn verify_key_over_https_honours_ca_cert_and_resolve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (ca, key) = write_pki(dir.path());
    let server = TlsServer::builder().identity(Identity::Rsa).spawn();
    let port = server.port();
    let output = dcert_bin()
        .args([
            "verify-key",
            &format!("https://localhost:{port}"),
            "--key",
            key.to_str().unwrap(),
            "--ca-cert",
            ca.to_str().unwrap(),
            "--resolve",
            &format!("localhost:{port}:127.0.0.1"),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    let parsed = json_output(&output);
    assert_eq!(parsed["matches"], true, "{parsed}");
}

#[test]
fn verify_key_without_the_ca_bundle_fails_verification() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, key) = write_pki(dir.path());
    let server = TlsServer::builder().identity(Identity::Rsa).spawn();
    let output = dcert_bin()
        .args(["verify-key", &server.url(), "--key", key.to_str().unwrap()])
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "a private CA is not trusted by default");
}

#[test]
fn verify_key_over_starttls() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (ca, key) = write_pki(dir.path());
    let server = TlsServer::builder().starttls_smtp().identity(Identity::Rsa).spawn();
    let output = dcert_bin()
        .args([
            "verify-key",
            &format!("127.0.0.1:{}", server.port()),
            "--starttls",
            "smtp",
            "--key",
            key.to_str().unwrap(),
            "--ca-cert",
            ca.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    let parsed = json_output(&output);
    assert_eq!(parsed["matches"], true, "{parsed}");
}

#[test]
fn verify_key_rejects_handshake_report_flags() {
    let output = dcert_bin()
        .args([
            "verify-key",
            test_data("verify-key-discovery/server.crt").to_str().unwrap(),
            "--key",
            test_data("verify-key-discovery/server.key").to_str().unwrap(),
            "--pq-probe",
        ])
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("apply to `dcert check` only"));
}

#[test]
fn starttls_still_conflicts_with_http_request_options() {
    for flag in [["--method", "post"], ["--header", "A: b"], ["--http-protocol", "http2"]] {
        let output = dcert_bin()
            .args(["check", "mail.example.com", "--starttls", "smtp", flag[0], flag[1]])
            .output()
            .expect("failed to run dcert");
        assert_eq!(output.status.code(), Some(2), "{flag:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
            "{flag:?}"
        );
    }
}

#[test]
fn ciphers_is_still_accepted_as_an_alias() {
    let output = dcert_bin()
        .args([
            "check",
            test_data("valid.pem").to_str().unwrap(),
            "--ciphers",
            "iana",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}
