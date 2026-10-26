//! TLS 1.0 and 1.1 probing is opt in (plan PR 4.3).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use openssl::ssl::SslVersion;
use support::{Identity, TlsServer, dcert_bin, json_output, test_data};

/// A server that speaks TLS 1.1 only. TLS 1.1 has no AEAD suites, so it
/// needs a CBC suite, and security level 0 lets the linked OpenSSL
/// negotiate it at all.
fn tls11_server() -> TlsServer {
    TlsServer::builder()
        .versions(Some(SslVersion::TLS1_1), Some(SslVersion::TLS1_1))
        .security_level(0)
        .cipher_list("ECDHE-RSA-AES128-SHA:@SECLEVEL=0")
        .identity(Identity::Rsa)
        .spawn()
}

#[test]
fn a_tls11_server_is_rejected_by_default() {
    let server = tls11_server();
    let output = dcert_bin()
        .args([server.url().as_str(), "--no-verify"])
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success(), "TLS 1.1 must not be offered by default");
}

#[test]
fn a_tls11_server_is_accepted_with_the_flag() {
    let server = tls11_server();
    let output = dcert_bin()
        .args([
            server.url().as_str(),
            "--no-verify",
            "--allow-legacy-tls",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    let parsed = json_output(&output);
    assert_eq!(parsed["connection"]["tls_version"], "TLSv1.1", "{parsed}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.matches("Warning: --allow-legacy-tls").count(),
        1,
        "one warning line: {stderr}"
    );
}

#[test]
fn an_explicit_legacy_minimum_is_honoured() {
    let server = tls11_server();
    let output = dcert_bin()
        .args([
            server.url().as_str(),
            "--no-verify",
            "--allow-legacy-tls",
            "--min-tls",
            "1.1",
            "--max-tls",
            "1.1",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    assert_eq!(json_output(&output)["connection"]["tls_version"], "TLSv1.1");
}

#[test]
fn legacy_versions_without_the_flag_are_a_clear_error() {
    for args in [["--min-tls", "1.0"], ["--max-tls", "1.1"]] {
        let output = dcert_bin()
            .arg(test_data("valid.pem").to_str().unwrap())
            .args(args)
            .output()
            .expect("failed to run dcert");
        assert!(!output.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("--allow-legacy-tls"), "{args:?}: {stderr}");
        assert!(stderr.contains("RFC 8996"), "{args:?}: {stderr}");
    }
}
