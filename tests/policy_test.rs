//! `dcert policy test` against loopback servers configured like a policy
//! (plan PR 5.2). PR 5.3 adds the full set for the two required policies.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use openssl::ssl::SslVersion;
use support::{Identity, TlsServer, dcert_bin, json_output};

const RES_PQ: &str = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09";
const RES_PQ_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";

/// The policy groups the linked OpenSSL can serve, plus the classical ones.
fn groups() -> &'static str {
    if dcert::keyex::openssl_supports_mlkem() {
        "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519:prime256v1:secp384r1"
    } else {
        "X25519:prime256v1:secp384r1"
    }
}

fn res_pq_server(extra_cipher: Option<&str>) -> TlsServer {
    let ciphers = match extra_cipher {
        Some(extra) => format!("{RES_PQ_CIPHERS}:{extra}"),
        None => RES_PQ_CIPHERS.to_string(),
    };
    TlsServer::builder()
        .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_3))
        .cipher_list(&ciphers)
        .ciphersuites("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
        .groups(groups())
        .identity(Identity::Both)
        .connections(600)
        .spawn()
}

fn policy_test(server: &TlsServer, extra: &[&str]) -> std::process::Output {
    dcert_bin()
        .args([
            "policy",
            "test",
            &server.url(),
            "--policy",
            RES_PQ,
            "--provider",
            "aws_alb",
        ])
        .args(["--versions", "1.2,1.3"])
        .args(extra)
        .output()
        .expect("failed to run dcert")
}

#[test]
fn an_emulated_listener_conforms() {
    let server = res_pq_server(None);
    let output = policy_test(&server, &["--format", "json"]);
    let report = json_output(&output);
    assert_eq!(report["deviations"], serde_json::json!([]), "{report}");
    let expected = if dcert::keyex::openssl_supports_mlkem() {
        "conformant"
    } else {
        "inconclusive"
    };
    assert_eq!(report["verdict"], expected, "{report}");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report["key_types"], serde_json::json!(["rsa", "ecdsa"]));
    let passed = |subject: &str| {
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["subject"] == subject && c["outcome"] == "pass")
    };
    for subject in [
        "TLS 1.2",
        "TLS 1.3",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_AES_128_CCM_SHA256",
        "X25519",
    ] {
        assert!(passed(subject), "{subject} should pass: {report}");
    }
    if !dcert::keyex::openssl_supports_mlkem() {
        let strict = policy_test(&server_again(), &["--strict", "--format", "json"]);
        assert_eq!(strict.status.code(), Some(10));
    }
}

fn server_again() -> TlsServer {
    res_pq_server(None)
}

#[test]
fn an_extra_cbc_cipher_is_named_in_every_notation() {
    let server = res_pq_server(Some("ECDHE-RSA-AES128-SHA256"));
    let output = policy_test(&server, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(9));
    let report = json_output(&output);
    assert_eq!(report["verdict"], "non_conformant");
    let deviations = report["deviations"].as_array().unwrap();
    assert_eq!(deviations.len(), 1, "{report}");
    let line = deviations[0].as_str().unwrap();
    for notation in [
        "ECDHE-RSA-AES128-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "0xC027",
    ] {
        assert!(line.contains(notation), "{line}");
    }
}

#[test]
fn pretty_output_puts_the_verdict_and_deviations_first() {
    let server = res_pq_server(Some("ECDHE-RSA-AES128-SHA256"));
    let output = policy_test(&server, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.lines().next().unwrap().contains("NON CONFORMANT"), "{stdout}");
    assert!(stdout.contains("Deviations:"), "{stdout}");
    assert!(stdout.contains("FAIL ECDHE-RSA-AES128-SHA256"), "{stdout}");
}

#[test]
fn identify_names_the_emulated_policy() {
    let server = res_pq_server(None);
    let output = dcert_bin()
        .args([
            "policy",
            "test",
            &server.url(),
            "--identify",
            "--versions",
            "1.2,1.3",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    assert_eq!(output.status.code(), Some(0));
    let report = json_output(&output);
    let best: Vec<&str> = report["best_fit"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(best.contains(&format!("{RES_PQ} (aws_alb)").as_str()), "{report}");
}

#[test]
fn a_policy_test_needs_a_policy_or_identify() {
    let output = dcert_bin()
        .args(["policy", "test", "example.com"])
        .output()
        .expect("failed to run dcert");
    assert_eq!(output.status.code(), Some(2));
    let unknown = dcert_bin()
        .args(["policy", "test", "example.com", "--policy", "Nope"])
        .output()
        .expect("failed to run dcert");
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("dcert policy list"));
}
