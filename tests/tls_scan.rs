//! `dcert tls-scan` against loopback servers (plan PR 4.4): it lists exactly
//! the configured versions, suites and groups, and knows which suites need
//! which key type.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;

use openssl::ssl::SslVersion;
use serde_json::Value;
use support::{Identity, TlsServer, dcert_bin, json_output};

/// Enough connections for a full scan.
const CONNECTIONS: usize = 400;

fn scan(server: &TlsServer, extra: &[&str]) -> Value {
    let output = dcert_bin()
        .args(["tls-scan", &server.url(), "--format", "json"])
        .args(extra)
        .output()
        .expect("failed to run dcert");
    json_output(&output)
}

fn version<'a>(report: &'a Value, number: &str) -> &'a Value {
    report["versions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["version"] == number)
        .unwrap_or_else(|| panic!("no version {number} in {report}"))
}

/// Code points of the suites accepted at `number`.
fn accepted(report: &Value, number: &str) -> BTreeSet<String> {
    version(report, number)["ciphers"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|c| c["accepted"] == true)
                .map(|c| c["cipher"]["code_point"].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn set(codes: &[&str]) -> BTreeSet<String> {
    codes.iter().map(|c| (*c).to_string()).collect()
}

#[test]
fn a_tls12_server_lists_exactly_its_suites() {
    let server = TlsServer::builder()
        .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_2))
        .cipher_list("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384")
        .identity(Identity::Rsa)
        .connections(CONNECTIONS)
        .spawn();
    let report = scan(&server, &[]);
    assert_eq!(version(&report, "1.3")["accepted"], false, "{report}");
    assert_eq!(version(&report, "1.2")["accepted"], true, "{report}");
    assert_eq!(accepted(&report, "1.2"), set(&["0xC02F", "0xC030"]));
    let first = version(&report, "1.2")["ciphers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["accepted"] == true)
        .unwrap();
    assert!(first["leaf_key"].as_str().unwrap().starts_with("RSA "), "{first}");
    assert!(
        first["cipher"]["iana"]
            .as_str()
            .unwrap()
            .starts_with("TLS_ECDHE_RSA_WITH_AES_")
    );
    assert_eq!(report["truncated"], false);
    assert!(version(&report, "1.3")["alert"].is_string());
}

#[test]
fn a_tls13_server_lists_exactly_its_suites() {
    let server = TlsServer::builder()
        .versions(Some(SslVersion::TLS1_3), Some(SslVersion::TLS1_3))
        .ciphersuites("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
        .identity(Identity::Ecdsa)
        .connections(CONNECTIONS)
        .spawn();
    let report = scan(&server, &[]);
    assert_eq!(version(&report, "1.2")["accepted"], false);
    assert_eq!(accepted(&report, "1.3"), set(&["0x1302", "0x1303"]));
    assert_eq!(report["groups_version"], "1.3");
}

#[test]
fn enumeration_follows_the_key_type() {
    let tls12 = |identity| {
        TlsServer::builder()
            .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_2))
            .cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
            .identity(identity)
            .connections(CONNECTIONS)
            .spawn()
    };

    let rsa = scan(&tls12(Identity::Rsa), &[]);
    assert_eq!(accepted(&rsa, "1.2"), set(&["0xC02F"]));

    let ecdsa = scan(&tls12(Identity::Ecdsa), &[]);
    assert_eq!(accepted(&ecdsa, "1.2"), set(&["0xC02B"]));

    let both = scan(&tls12(Identity::Both), &[]);
    assert_eq!(accepted(&both, "1.2"), set(&["0xC02B", "0xC02F"]));
    for cipher in version(&both, "1.2")["ciphers"].as_array().unwrap() {
        if cipher["accepted"] != true {
            continue;
        }
        let key = cipher["leaf_key"].as_str().unwrap();
        match cipher["cipher"]["code_point"].as_str().unwrap() {
            "0xC02B" => assert!(key.starts_with("EC "), "{cipher}"),
            "0xC02F" => assert!(key.starts_with("RSA "), "{cipher}"),
            other => panic!("unexpected {other}"),
        }
    }
}

#[test]
fn groups_are_tried_one_at_a_time() {
    let server = TlsServer::builder()
        .versions(Some(SslVersion::TLS1_3), Some(SslVersion::TLS1_3))
        .groups("secp384r1")
        .identity(Identity::Rsa)
        .connections(CONNECTIONS)
        .spawn();
    let report = scan(&server, &[]);
    let status = |name: &str| {
        report["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["group"] == name)
            .map(|g| g["status"].as_str().unwrap().to_string())
            .unwrap_or_else(|| panic!("no group {name}: {report}"))
    };
    assert_eq!(status("secp384r1"), "accepted");
    assert_eq!(status("X25519"), "rejected");
    assert_eq!(status("secp256r1"), "rejected");
}

#[test]
fn the_budget_stops_the_scan_and_says_so() {
    let server = TlsServer::builder()
        .identity(Identity::Rsa)
        .connections(CONNECTIONS)
        .spawn();
    let report = scan(&server, &["--max-handshakes", "5"]);
    assert_eq!(report["truncated"], true, "{report}");
    assert_eq!(report["handshakes"], 5);
}

#[test]
fn legacy_versions_join_only_with_the_flag() {
    let server = TlsServer::builder()
        .versions(Some(SslVersion::TLS1_1), Some(SslVersion::TLS1_1))
        .security_level(0)
        .cipher_list("ECDHE-RSA-AES128-SHA:@SECLEVEL=0")
        .identity(Identity::Rsa)
        .connections(CONNECTIONS)
        .spawn();
    let plain = dcert_bin()
        .args(["tls-scan", &server.url(), "--format", "json"])
        .output()
        .expect("failed to run dcert");
    assert_eq!(plain.status.code(), Some(2), "no version accepted");
    let report = json_output(&plain);
    assert!(
        report["versions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["version"] != "1.1")
    );

    let legacy = scan(&server, &["--allow-legacy-tls"]);
    assert_eq!(version(&legacy, "1.1")["accepted"], true, "{legacy}");
    assert_eq!(accepted(&legacy, "1.1"), set(&["0xC013"]));
}

#[test]
fn pretty_output_lists_versions_suites_and_groups() {
    let server = TlsServer::builder()
        .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_2))
        .cipher_list("ECDHE-RSA-AES128-GCM-SHA256")
        .identity(Identity::Rsa)
        .connections(CONNECTIONS)
        .spawn();
    let output = dcert_bin()
        .args(["tls-scan", &server.url()])
        .output()
        .expect("failed to run dcert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TLS 1.2  accepted"), "{stdout}");
    assert!(stdout.contains("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"), "{stdout}");
    assert!(stdout.contains("Groups at TLS 1.2"), "{stdout}");
}
