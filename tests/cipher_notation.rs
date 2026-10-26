//! `--cipher` in any notation and the negotiated cipher in every output
//! format (plan PR 4.2), against loopback servers.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use openssl::ssl::SslVersion;
use std::time::Duration;
use support::{Identity, Observation, TlsServer, dcert_bin, json_output};

/// A TLS 1.2 server that accepts two suites, so the client's choice decides.
fn tls12_server() -> TlsServer {
    TlsServer::builder()
        .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_2))
        .cipher_list("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384")
        .identity(Identity::Rsa)
        .spawn()
}

fn check(server: &TlsServer, extra: &[&str]) -> std::process::Output {
    dcert_bin()
        .args([server.url().as_str(), "--no-verify"])
        .args(extra)
        .output()
        .expect("failed to run dcert")
}

#[test]
fn one_suite_is_negotiated_through_each_notation() {
    for notation in [
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ecdhe-rsa-aes256-gcm-sha384",
        "0xC030",
        "C030",
        "0xC0,0x30",
    ] {
        let server = tls12_server();
        let parsed = json_output(&check(&server, &["--cipher", notation, "--format", "json"]));
        let cipher = &parsed["connection"]["tls_cipher"];
        assert_eq!(cipher["openssl"], "ECDHE-RSA-AES256-GCM-SHA384", "{notation}: {cipher}");
        assert_eq!(cipher["code_point"], "0xC030", "{notation}");
        assert_eq!(
            server.observation(Duration::from_secs(5)),
            Some(Observation::Accepted {
                version: "TLSv1.2".into(),
                cipher: "ECDHE-RSA-AES256-GCM-SHA384".into(),
            }),
            "{notation}"
        );
    }
}

#[test]
fn mixed_families_configure_both_lists() {
    let server = TlsServer::builder()
        .ciphersuites("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")
        .identity(Identity::Rsa)
        .spawn();
    let parsed = json_output(&check(
        &server,
        &[
            "--cipher",
            "0xC02F",
            "--cipher",
            "TLS_AES_256_GCM_SHA384",
            "--format",
            "json",
        ],
    ));
    let conn = &parsed["connection"];
    assert_eq!(conn["tls_version"], "TLSv1.3", "{conn}");
    assert_eq!(conn["tls_cipher"]["iana"], "TLS_AES_256_GCM_SHA384", "{conn}");
    assert_eq!(conn["tls_cipher"]["protocol"], "tls13", "{conn}");
}

#[test]
fn a_suite_the_server_lacks_fails_the_handshake() {
    let server = tls12_server();
    let output = check(&server, &["--cipher", "ECDHE-ECDSA-AES128-GCM-SHA256"]);
    assert!(!output.status.success());
}

#[test]
fn the_record_is_the_default_and_names_follow_the_notation() {
    let server = tls12_server();
    let parsed = json_output(&check(&server, &["--cipher", "C02F", "--format", "json"]));
    let record = &parsed["connection"]["tls_cipher"];
    assert_eq!(
        *record,
        serde_json::json!({
            "openssl": "ECDHE-RSA-AES128-GCM-SHA256",
            "iana": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "code_point": "0xC02F",
            "protocol": "tls12",
            "forward_secrecy": true,
            "aead": true,
        })
    );

    for (notation, expected) in [
        ("iana", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        ("openssl", "ECDHE-RSA-AES128-GCM-SHA256"),
    ] {
        let server = tls12_server();
        let args = ["--cipher", "C02F", "--cipher-notation", notation];
        let json = json_output(&check(&server, &[&args[..], &["--format", "json"]].concat()));
        assert_eq!(json["connection"]["tls_cipher"], expected, "{notation}");

        let server = tls12_server();
        let yaml = check(&server, &[&args[..], &["--format", "yaml"]].concat());
        let stdout = String::from_utf8_lossy(&yaml.stdout);
        assert!(
            stdout.contains(&format!("tls_cipher: {expected}")),
            "{notation}: {stdout}"
        );

        let server = tls12_server();
        let pretty = check(&server, &args);
        let stdout = String::from_utf8_lossy(&pretty.stdout);
        assert!(stdout.contains(expected), "{notation}: {stdout}");
    }
}

#[test]
fn pretty_output_shows_every_notation_by_default() {
    let server = tls12_server();
    let output = check(&server, &["--cipher", "C02F"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(
            "TLS ciphersuite agreed: ECDHE-RSA-AES128-GCM-SHA256 (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0xC02F)"
        ),
        "{stdout}"
    );
}

#[test]
fn cipher_and_raw_lists_conflict() {
    let output = dcert_bin()
        .args(["check", "example.com", "--cipher", "C02F", "--cipher-list", "HIGH"])
        .output()
        .expect("failed to run dcert");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn ciphers_explain_prints_the_same_record_for_every_notation() {
    let records: Vec<serde_json::Value> = [
        "C02F",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
    ]
    .iter()
    .map(|s| {
        let output = dcert_bin()
            .args(["ciphers", "explain", s, "--format", "json"])
            .output()
            .expect("failed to run dcert");
        json_output(&output)
    })
    .collect();
    assert!(records.windows(2).all(|w| w[0] == w[1]), "{records:?}");
    assert_eq!(records[0]["code_point"], "0xC02F");
    assert_eq!(records[0]["offerable"], true);
}

#[test]
fn ciphers_explain_suggests_near_misses() {
    let output = dcert_bin()
        .args(["ciphers", "explain", "ECDHE-RSA-AES128-GCM-SHA265"])
        .output()
        .expect("failed to run dcert");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("did you mean ECDHE-RSA-AES128-GCM-SHA256"));
}

#[test]
fn ciphers_list_filters_by_protocol_and_offerability() {
    let list = |args: &[&str]| -> Vec<serde_json::Value> {
        let output = dcert_bin()
            .args(["ciphers", "list", "--format", "json"])
            .args(args)
            .output()
            .expect("failed to run dcert");
        json_output(&output).as_array().unwrap().clone()
    };
    let tls13 = list(&["--protocol", "1.3"]);
    assert!(tls13.iter().all(|c| c["protocol"] == "tls13"));
    assert!(tls13.iter().any(|c| c["iana"] == "TLS_AES_128_GCM_SHA256"));
    let offerable = list(&["--offerable"]);
    assert!(offerable.iter().all(|c| c["offerable"] == true));
    assert!(offerable.len() < list(&[]).len());
}
