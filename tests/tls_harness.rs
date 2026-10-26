//! End to end checks that the hermetic TLS harness drives dcert as intended.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use openssl::ssl::SslVersion;
use std::time::Duration;
use support::{Identity, Observation, TEST_SERVER_CN, TlsServer, dcert_bin, json_output};

fn probe(server: &TlsServer) -> serde_json::Value {
    let output = dcert_bin()
        .args([&server.url(), "--no-verify", "--format", "json"])
        .output()
        .expect("failed to run dcert");
    json_output(&output)
}

#[test]
fn tls12_only_single_cipher_is_negotiated_exactly() {
    let server = TlsServer::builder()
        .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_2))
        .cipher_list("ECDHE-RSA-AES128-GCM-SHA256")
        .identity(Identity::Rsa)
        .spawn();
    let parsed = probe(&server);
    let conn = &parsed["connection"];
    assert_eq!(conn["tls_version"], "TLSv1.2", "{conn}");
    assert_eq!(conn["tls_cipher"]["openssl"], "ECDHE-RSA-AES128-GCM-SHA256", "{conn}");
    assert_eq!(parsed["certificates"][0]["common_name"], TEST_SERVER_CN);
    assert_eq!(
        server.observation(Duration::from_secs(5)),
        Some(Observation::Accepted {
            version: "TLSv1.2".into(),
            cipher: "ECDHE-RSA-AES128-GCM-SHA256".into(),
        })
    );
}

#[test]
fn tls13_single_suite_on_ecdsa_identity_is_negotiated_exactly() {
    let server = TlsServer::builder()
        .versions(Some(SslVersion::TLS1_3), Some(SslVersion::TLS1_3))
        .ciphersuites("TLS_CHACHA20_POLY1305_SHA256")
        .identity(Identity::Ecdsa)
        .spawn();
    let parsed = probe(&server);
    let conn = &parsed["connection"];
    assert_eq!(conn["tls_version"], "TLSv1.3", "{conn}");
    assert_eq!(conn["tls_cipher"]["openssl"], "TLS_CHACHA20_POLY1305_SHA256", "{conn}");
}

#[test]
fn version_mismatch_fails_and_the_server_records_the_rejection() {
    let server = TlsServer::builder()
        .versions(Some(SslVersion::TLS1_3), Some(SslVersion::TLS1_3))
        .spawn();
    let output = dcert_bin()
        .args([&server.url(), "--no-verify", "--max-tls", "1.2", "--format", "json"])
        .output()
        .expect("failed to run dcert");
    assert!(
        !output.status.success(),
        "a TLS 1.2 client must not reach a TLS 1.3 only server"
    );
    assert!(matches!(
        server.observation(Duration::from_secs(5)),
        Some(Observation::Rejected(_))
    ));
}
