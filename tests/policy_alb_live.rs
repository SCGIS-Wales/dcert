//! Live conformance tests against real AWS Application Load Balancers
//! (plan PR 5.4). They run only when both URLs are set, for example by
//! `make live-alb` or the manual `live-alb` workflow, and are skipped with a
//! message otherwise:
//!
//! - `DCERT_LIVE_ALB_TLS13_1_3_PQ_URL`: a listener with
//!   `ELBSecurityPolicy-TLS13-1-3-PQ-2025-09`
//! - `DCERT_LIVE_ALB_TLS13_1_2_RES_PQ_URL`: a listener with
//!   `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use support::{dcert_bin, json_output};

/// The URL in `var`, or `None` after saying why the test is skipped.
fn live_url(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("skipped: set {var} to run the live ALB test (see docs/testing/aws-alb-policy-fixtures.md)");
            None
        }
    }
}

/// `dcert policy test` against a live listener: no deviation, and a
/// conformant verdict wherever the linked OpenSSL can test ML-KEM.
fn assert_live_conformant(var: &str, policy: &str) {
    let Some(url) = live_url(var) else { return };
    let output = dcert_bin()
        .args(["policy", "test", &url, "--policy", policy, "--provider", "aws_alb"])
        .args(["--versions", "1.2,1.3", "--format", "json"])
        .output()
        .expect("failed to run dcert");
    let report = json_output(&output);
    assert_eq!(
        report["deviations"],
        serde_json::json!([]),
        "{policy} at {url}: {report}"
    );
    let expected = if dcert::keyex::openssl_supports_mlkem() {
        "conformant"
    } else {
        "inconclusive"
    };
    assert_eq!(report["verdict"], expected, "{policy} at {url}: {report}");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn live_alb_tls13_1_3_pq_conforms() {
    assert_live_conformant(
        "DCERT_LIVE_ALB_TLS13_1_3_PQ_URL",
        "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
    );
}

#[test]
fn live_alb_tls13_1_2_res_pq_conforms() {
    assert_live_conformant(
        "DCERT_LIVE_ALB_TLS13_1_2_RES_PQ_URL",
        "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
    );
}

#[test]
fn live_alb_identify_names_each_policy() {
    for (var, policy) in [
        (
            "DCERT_LIVE_ALB_TLS13_1_3_PQ_URL",
            "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
        ),
        (
            "DCERT_LIVE_ALB_TLS13_1_2_RES_PQ_URL",
            "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
        ),
    ] {
        let Some(url) = live_url(var) else { continue };
        let output = dcert_bin()
            .args([
                "policy",
                "test",
                &url,
                "--identify",
                "--versions",
                "1.2,1.3",
                "--format",
                "json",
            ])
            .output()
            .expect("failed to run dcert");
        let report = json_output(&output);
        let best: Vec<&str> = report["best_fit"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            best.contains(&format!("{policy} (aws_alb)").as_str()),
            "{url}: {report}"
        );
    }
}
