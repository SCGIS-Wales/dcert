//! `dcert policy list|show|schema` (plan PR 5.1).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use support::{dcert_bin, json_output};

fn run(args: &[&str]) -> std::process::Output {
    dcert_bin().args(args).output().expect("failed to run dcert")
}

#[test]
fn list_filters_by_provider() {
    let all = json_output(&run(&["policy", "list", "-f", "json"]));
    let alb = json_output(&run(&["policy", "list", "--provider", "aws_alb", "-f", "json"]));
    let alb = alb.as_array().unwrap();
    assert!(alb.len() < all.as_array().unwrap().len());
    assert!(alb.iter().all(|p| p["provider"] == "aws_alb"));
    let dashed = json_output(&run(&["policy", "list", "--provider", "aws-alb", "-f", "json"]));
    assert_eq!(dashed.as_array().unwrap().len(), alb.len());
}

#[test]
fn show_prints_the_required_policy_in_every_notation() {
    let output = run(&[
        "policy",
        "show",
        "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
        "--provider",
        "aws_alb",
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "0xC02B",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "X25519MLKEM768",
        "Default for: console",
        "retrieved",
    ] {
        assert!(stdout.contains(expected), "{expected}: {stdout}");
    }
}

#[test]
fn show_returns_every_provider_with_the_id() {
    let both = json_output(&run(&["policy", "show", "elbsecuritypolicy-2016-08", "-f", "json"]));
    let providers: Vec<&str> = both
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["provider"].as_str().unwrap())
        .collect();
    assert_eq!(providers, ["aws_alb", "aws_nlb"]);
}

#[test]
fn unknown_policies_are_an_error() {
    let output = run(&["policy", "show", "ELBSecurityPolicy-Nope"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("dcert policy list"));
}

#[test]
fn schema_matches_the_committed_file() {
    let output = run(&["policy", "schema"]);
    let printed: serde_json::Value = serde_json::from_slice(&output.stdout).expect("schema JSON");
    let committed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/kb/tls_policies.schema.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(printed, committed);
}
