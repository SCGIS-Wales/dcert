//! One output path (plan PR 3.5): every structured result goes through
//! `print_structured`, so JSON and YAML carry the same shape everywhere.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use support::{dcert_bin, json_output, test_data};

fn stdout_of(args: &[&str]) -> String {
    let output = dcert_bin().args(args).output().expect("failed to run dcert");
    String::from_utf8(output.stdout).expect("utf-8 stdout")
}

#[test]
fn several_targets_are_one_document_keyed_by_target_in_json_and_yaml() {
    let a = test_data("valid.pem");
    let b = test_data("test.pem");
    let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());

    let json: serde_json::Value =
        serde_json::from_str(&stdout_of(&["check", a, b, "--format", "json"])).expect("one JSON document");
    let yaml: serde_json::Value =
        serde_norway::from_str(&stdout_of(&["check", a, b, "--format", "yaml"])).expect("one YAML document");
    for doc in [&json, &yaml] {
        let map = doc.as_object().expect("keyed by target");
        assert_eq!(map.len(), 2, "{doc}");
        assert!(
            map[a]["certificates"].is_array() && map[b]["certificates"].is_array(),
            "{doc}"
        );
    }
    assert_eq!(json, yaml, "JSON and YAML carry the same data");
}

#[test]
fn discovered_pairs_name_their_files_in_json() {
    let dir = test_data("verify-key-discovery");
    let output = dcert_bin()
        .args(["verify-key", "--dir", dir.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run dcert");
    let parsed = json_output(&output);
    let pairs = parsed.as_array().expect("an array of pairs");
    assert_eq!(pairs.len(), 2, "{parsed}");
    for pair in pairs {
        assert!(pair["cert_file"].is_string() && pair["key_file"].is_string(), "{pair}");
        assert!(pair["matches"].is_boolean(), "{pair}");
    }
}

#[test]
fn kb_show_pretty_is_its_yaml() {
    let id = "proxy.env.https-without-https-proxy";
    let pretty = stdout_of(&["kb", "show", id]);
    let yaml = stdout_of(&["kb", "show", id, "--format", "yaml"]);
    assert!(!pretty.is_empty());
    assert_eq!(pretty, yaml);
}

#[test]
fn kb_schema_is_json() {
    let schema: serde_json::Value = serde_json::from_str(&stdout_of(&["kb", "schema"])).expect("JSON schema");
    assert!(schema.is_object());
}
