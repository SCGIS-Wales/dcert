//! Hermetic conformance tests for the two required ALB post quantum policies
//! (plan PR 5.3): `ELBSecurityPolicy-TLS13-1-3-PQ-2025-09` and
//! `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`, against loopback servers
//! configured from the catalogue. Each test checks JSON and pretty output and
//! the exit code. ML-KEM group checks pass where the linked OpenSSL has
//! ML-KEM (3.5 and later, the vendored build) and are not testable on 3.0.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use dcert::tlspolicy::{PolicyCatalogue, PolicyProvider, TlsPolicy};
use openssl::ssl::SslVersion;
use serde_json::Value;
use support::{Identity, TlsServer, TlsServerBuilder, dcert_bin, json_output};

const TLS13_PQ: &str = "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09";
const RES_PQ: &str = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09";
const RES_FIPS_PQ: &str = "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09";
const CLASSICAL: &str = "X25519:prime256v1:secp384r1";

fn mlkem() -> bool {
    dcert::keyex::openssl_supports_mlkem()
}

fn policy(id: &str) -> &'static TlsPolicy {
    PolicyCatalogue::builtin()
        .unwrap()
        .get(id, PolicyProvider::AwsAlb)
        .unwrap()
}

fn ssl_version(number: &str) -> SslVersion {
    match number {
        "1.0" => SslVersion::TLS1,
        "1.1" => SslVersion::TLS1_1,
        "1.2" => SslVersion::TLS1_2,
        _ => SslVersion::TLS1_3,
    }
}

/// A server configured like policy `id`: its version range, TLS 1.2
/// ciphers and TLS 1.3 suites, the policy groups this OpenSSL implements
/// plus the classical ones, at security level 2.
fn emulate_policy(id: &str, identity: Identity) -> TlsServerBuilder {
    let p = policy(id);
    let oldest = p.protocols.iter().min().unwrap();
    let newest = p.protocols.iter().max().unwrap();
    let openssl = |name: &String| dcert::ciphers::Cipher::parse(name).unwrap().openssl.unwrap();
    let mut groups: Vec<&str> = if mlkem() {
        p.groups.iter().map(String::as_str).collect()
    } else {
        Vec::new()
    };
    groups.push(CLASSICAL);
    let mut builder = TlsServer::builder()
        .versions(Some(ssl_version(oldest)), Some(ssl_version(newest)))
        .ciphersuites(&p.tls13_suites.join(":"))
        .groups(&groups.join(":"))
        .security_level(2)
        .identity(identity)
        .connections(800);
    if !p.tls12_ciphers.is_empty() {
        builder = builder.cipher_list(&p.tls12_ciphers.iter().map(openssl).collect::<Vec<_>>().join(":"));
    }
    builder
}

/// Run `dcert policy test` in JSON and in pretty output; both must exit
/// with `code`. Returns the JSON report and the pretty text.
fn policy_test(server: &TlsServer, id: &str, extra: &[&str], code: i32) -> (Value, String) {
    let run = |format: &str| {
        dcert_bin()
            .args([
                "policy",
                "test",
                &server.url(),
                "--policy",
                id,
                "--provider",
                "aws_alb",
                "--format",
                format,
            ])
            .args(extra)
            .output()
            .expect("failed to run dcert")
    };
    let json = run("json");
    assert_eq!(
        json.status.code(),
        Some(code),
        "json: {}",
        String::from_utf8_lossy(&json.stderr)
    );
    let pretty = run("pretty");
    assert_eq!(pretty.status.code(), Some(code), "pretty");
    (json_output(&json), String::from_utf8_lossy(&pretty.stdout).into_owned())
}

fn check<'a>(report: &'a Value, subject: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["subject"] == subject)
        .unwrap_or_else(|| panic!("no check for {subject}: {report}"))
}

fn outcomes<'a>(report: &'a Value, kind: &str) -> Vec<&'a str> {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == kind)
        .map(|c| c["outcome"].as_str().unwrap())
        .collect()
}

/// The verdict a faithful emulation earns on this build.
fn faithful_verdict() -> &'static str {
    if mlkem() { "conformant" } else { "inconclusive" }
}

#[test]
fn tls13_1_3_pq_tls13_conformant() {
    let server = emulate_policy(TLS13_PQ, Identity::Rsa).spawn();
    let (report, pretty) = policy_test(&server, TLS13_PQ, &["--versions", "1.3"], 0);
    assert_eq!(report["verdict"], faithful_verdict(), "{report}");
    assert!(outcomes(&report, "tls13_suite").iter().all(|o| *o == "pass"));
    assert_eq!(outcomes(&report, "tls13_suite").len(), 3);
    let groups = outcomes(&report, "group");
    assert_eq!(groups.len(), 3);
    let expected = if mlkem() { "pass" } else { "not_testable" };
    assert!(groups.iter().all(|o| *o == expected), "{groups:?}");
    assert_eq!(check(&report, "X25519")["outcome"], "pass", "classical fallback");
    assert!(pretty.contains(if mlkem() { "CONFORMANT" } else { "INCONCLUSIVE" }));
}

#[test]
fn tls13_1_3_pq_tls12_rejected() {
    let server = emulate_policy(TLS13_PQ, Identity::Rsa).spawn();
    let client = dcert_bin()
        .args([server.url().as_str(), "--no-verify", "--max-tls", "1.2"])
        .output()
        .expect("failed to run dcert");
    assert!(!client.status.success());
    assert!(String::from_utf8_lossy(&client.stderr).contains("protocol version"));

    let (report, pretty) = policy_test(&server, TLS13_PQ, &["--versions", "1.2,1.3"], 0);
    let tls12 = check(&report, "TLS 1.2");
    assert_eq!(
        (tls12["expected"].as_str(), tls12["observed"].as_str()),
        (Some("reject"), Some("reject"))
    );
    assert_eq!(tls12["outcome"], "pass");
    assert!(pretty.contains("TLS 1.2: expected reject, observed reject"), "{pretty}");
}

#[test]
fn tls13_1_3_pq_detects_tls12_enabled() {
    let server = emulate_policy(TLS13_PQ, Identity::Rsa)
        .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_3))
        .cipher_list("ECDHE-RSA-AES128-GCM-SHA256")
        .spawn();
    let (report, pretty) = policy_test(&server, TLS13_PQ, &["--versions", "1.2,1.3"], 9);
    assert_eq!(report["verdict"], "non_conformant");
    assert_eq!(report["deviations"], serde_json::json!(["TLS 1.2 accepted"]));
    assert!(pretty.contains("FAIL TLS 1.2 accepted"), "{pretty}");
}

#[test]
fn tls13_1_2_res_pq_tls13_conformant() {
    let server = emulate_policy(RES_PQ, Identity::Both).spawn();
    let (report, _) = policy_test(&server, RES_PQ, &["--versions", "1.3"], 0);
    assert_eq!(report["verdict"], faithful_verdict(), "{report}");
    assert_eq!(outcomes(&report, "tls13_suite"), ["pass", "pass", "pass"]);
    // CCM_8 needs security level 0 on OpenSSL 3.2 and later; it is still
    // offered and rejected.
    assert!(
        outcomes(&report, "tls13_excluded").iter().all(|o| *o == "pass"),
        "{report}"
    );
    assert_eq!(check(&report, "TLS_AES_128_CCM_8_SHA256")["outcome"], "pass");
}

#[test]
fn tls13_1_2_res_pq_tls12_conformant() {
    let dual = emulate_policy(RES_PQ, Identity::Both).spawn();
    let (report, pretty) = policy_test(&dual, RES_PQ, &["--versions", "1.2"], 0);
    assert_eq!(report["verdict"], faithful_verdict(), "{report}");
    assert_eq!(report["key_types"], serde_json::json!(["rsa", "ecdsa"]));
    assert_eq!(outcomes(&report, "tls12_cipher"), ["pass", "pass", "pass", "pass"]);
    // Every excluded cipher is tested: those the linked OpenSSL cannot
    // offer (RC4, 3DES) are left out rather than made not testable.
    let excluded = outcomes(&report, "tls12_excluded");
    assert!(!excluded.is_empty());
    assert!(excluded.iter().all(|o| *o == "pass"), "{excluded:?}");
    assert!(!report.to_string().contains("RC4"), "{report}");
    assert!(pretty.contains("ECDHE-ECDSA-AES128-GCM-SHA256 (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0xC02B)"));

    let rsa_only = emulate_policy(RES_PQ, Identity::Rsa).spawn();
    let (report, _) = policy_test(&rsa_only, RES_PQ, &["--versions", "1.2"], 0);
    assert_eq!(report["key_types"], serde_json::json!(["rsa"]));
    for (subject, outcome) in [
        ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "not_applicable"),
        ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "not_applicable"),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "pass"),
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "pass"),
    ] {
        assert_eq!(check(&report, subject)["outcome"], outcome, "{subject}");
    }
}

#[test]
fn tls13_1_2_res_pq_detects_cbc_cipher() {
    let p = policy(RES_PQ);
    let mut ciphers: Vec<&str> = p
        .tls12_ciphers
        .iter()
        .map(|c| dcert::ciphers::Cipher::parse(c).unwrap().openssl.unwrap())
        .collect();
    ciphers.push("ECDHE-RSA-AES128-SHA256");
    let server = emulate_policy(RES_PQ, Identity::Both)
        .cipher_list(&ciphers.join(":"))
        .spawn();
    let (report, pretty) = policy_test(&server, RES_PQ, &["--versions", "1.2,1.3"], 9);
    assert_eq!(report["verdict"], "non_conformant");
    let deviations = report["deviations"].as_array().unwrap();
    assert_eq!(deviations.len(), 1, "{report}");
    for notation in [
        "ECDHE-RSA-AES128-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "0xC027",
    ] {
        assert!(deviations[0].as_str().unwrap().contains(notation), "{notation}");
        assert!(pretty.contains(notation), "{notation}");
    }
}

#[test]
fn tls13_1_2_res_pq_detects_tls11() {
    // TLS 1.1 needs a CBC cipher and security level 0. The run leaves TLS 1.2
    // out so the CBC cipher's TLS 1.2 deviation does not hide the point:
    // only --allow-legacy-tls can see the extra version.
    let p = policy(RES_PQ);
    let mut ciphers: Vec<&str> = p
        .tls12_ciphers
        .iter()
        .map(|c| dcert::ciphers::Cipher::parse(c).unwrap().openssl.unwrap())
        .collect();
    ciphers.push("ECDHE-RSA-AES128-SHA");
    let list = format!("{}:@SECLEVEL=0", ciphers.join(":"));
    let server = || {
        emulate_policy(RES_PQ, Identity::Both)
            .versions(Some(SslVersion::TLS1_1), Some(SslVersion::TLS1_3))
            .security_level(0)
            .cipher_list(&list)
            .spawn()
    };
    let (blind, _) = policy_test(&server(), RES_PQ, &["--versions", "1.3,1.1"], 0);
    assert_eq!(blind["verdict"], "inconclusive", "{blind}");
    assert_eq!(check(&blind, "TLS 1.1")["outcome"], "not_testable");

    let (seen, pretty) = policy_test(&server(), RES_PQ, &["--versions", "1.3,1.1", "--allow-legacy-tls"], 9);
    assert_eq!(seen["verdict"], "non_conformant");
    assert_eq!(seen["deviations"], serde_json::json!(["TLS 1.1 accepted"]));
    assert!(pretty.contains("FAIL TLS 1.1 accepted"));
}

#[test]
fn tls13_1_2_res_pq_identify() {
    let server = emulate_policy(RES_PQ, Identity::Both).spawn();
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
    let fips = report["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["policy"] == RES_FIPS_PQ && c["provider"] == "aws_alb")
        .unwrap_or_else(|| panic!("FIPS twin not among the candidates: {report}"));
    assert_eq!(
        fips["deviations"],
        serde_json::json!(["TLS_CHACHA20_POLY1305_SHA256 (0x1303) accepted"])
    );
    if mlkem() {
        assert_eq!(
            best[0],
            format!("{RES_PQ} (aws_alb)"),
            "with ML-KEM the stated groups decide"
        );
    }
    let pretty = dcert_bin()
        .args(["policy", "test", &server.url(), "--identify", "--versions", "1.2,1.3"])
        .output()
        .expect("failed to run dcert");
    assert!(String::from_utf8_lossy(&pretty.stdout).contains(RES_PQ));
}
