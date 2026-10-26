//! Parity between the MCP probe tools and `dcert check` (plan PR 3.2).
//!
//! Every property a probe tool advertises must reach the CLI as a flag that
//! the CLI accepts, and every `check` flag must be reachable from some tool
//! or be listed in [`CLI_ONLY`] with the reason it is not.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;

use clap::{CommandFactory, Parser};
use dcert::cli::Cli;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use crate::params::*;

/// `check` flags no probe tool sends, and why.
const CLI_ONLY: &[(&str, &str)] = &[
    ("watch", "a long running loop; a tool call returns one result"),
    ("debug", "set server wide by DCERT_MCP_DEBUG"),
    ("header", "headers travel in a private file as --headers-file"),
    ("data", "the body travels in a private file as --data-file"),
    (
        "diff",
        "compare_certificates runs two checks; --diff parity arrives with plan PR 7.1",
    ),
    ("expired-only", "MCP parameter arrives with plan PR 7.1"),
    ("body-limit", "MCP parameter arrives with plan PR 7.1"),
    ("no-diagnose", "MCP parameter arrives with plan PR 7.1"),
    ("kb-file", "MCP parameter arrives with plan PR 7.1"),
    ("sort-expiry", "MCP parameter arrives with plan PR 7.1"),
];

const TARGET: &str = "https://api.example.com";

/// Properties to set so that `property` takes effect and the result still
/// parses (a client key needs its certificate).
fn sample(property: &str) -> Map<String, Value> {
    let value = match property {
        "fingerprint" | "extensions" => json!(false),
        "check_revocation"
        | "no_trust_check"
        | "resolve_issuers"
        | "refresh_public_roots"
        | "exclude_expired"
        | "show_body"
        | "no_verify"
        | "pq_probe" => json!(true),
        "issuer_timeout" => json!(3),
        "days" => json!(10),
        "timeout" => json!(7),
        "read_timeout" => json!(4),
        "min_tls" => json!("1.2"),
        "max_tls" => json!("1.3"),
        "cipher_list" => json!("ECDHE+AESGCM"),
        "cipher_suites" => json!("TLS_AES_128_GCM_SHA256"),
        "groups" => json!("X25519"),
        "tls_profile" => json!("modern"),
        "sni" => json!("api.example.com"),
        "connect_to" => json!("10.0.0.5"),
        "resolve" => json!("api.example.com:443:10.0.0.5"),
        "proxy" => json!("http://proxy.example:3128"),
        "noproxy" => json!("internal.example"),
        // Documented in upper case; the CLI takes lower case.
        "method" => json!("POST"),
        "data" => json!("{\"k\":1}"),
        "http_protocol" => json!("http2"),
        "ciphers_notation" => json!("iana"),
        "starttls" => json!("smtp"),
        "headers" => json!(["X-Test: 1"]),
        "client_cert" | "client_key" => {
            return Map::from_iter([
                ("client_cert".to_string(), json!("client.pem")),
                ("client_key".to_string(), json!("client.key")),
            ]);
        }
        "pkcs12" => json!("client.p12"),
        "cert_password" => json!("not-a-real-password"),
        "ca_cert" => json!("ca.pem"),
        "output_path" => json!("chain.pem"),
        other => panic!("no sample for probe tool property `{other}`; add one to keep the parity test complete"),
    };
    Map::from_iter([(property.to_string(), value)])
}

/// The top level properties of a parameter type's JSON schema.
fn properties<T: JsonSchema>() -> Vec<String> {
    let schema = serde_json::to_value(schemars::schema_for!(T)).expect("schema");
    schema["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .filter(|k| *k != "target")
        .cloned()
        .collect()
}

/// The long flag `check` reads from environment variable `var`.
fn flag_for_env(var: &str) -> String {
    let cmd = Cli::command();
    let check = cmd.find_subcommand("check").expect("check subcommand");
    let arg = check
        .get_arguments()
        .find(|a| a.get_env().is_some_and(|e| e == var))
        .unwrap_or_else(|| panic!("no check flag reads {var}"));
    format!("--{}", arg.get_long().expect("long flag"))
}

/// The argv a tool call with `props` produces, environment settings turned
/// into their flags, after checking that the CLI accepts it.
fn tool_argv<T: DeserializeOwned + ProbeParams>(props: &Map<String, Value>) -> Vec<String> {
    let mut object = props.clone();
    object.insert("target".to_string(), json!(TARGET));
    let mut params: T = serde_json::from_value(Value::Object(object)).expect("params deserialise");
    let (_, http_tls) = params.groups();
    let (file_args, _files) = match http_tls {
        Some(h) => h.secret_files().expect("secret files"),
        None => (Vec::new(), Vec::new()),
    };
    let (mut args, env) = params.cli_args();
    args.extend(file_args);
    args.extend(env.iter().map(|(var, value)| format!("{}={value}", flag_for_env(var))));

    let mut argv = vec!["dcert".to_string(), T::SUBCOMMAND.to_string()];
    argv.extend(args.iter().cloned());
    argv.extend(["--".to_string(), TARGET.to_string()]);
    if let Err(e) = Cli::try_parse_from(&argv) {
        panic!("{} rejects {argv:?}: {e}", T::SUBCOMMAND);
    }
    args
}

/// The long flag names in an argv, without values.
fn flag_names(args: &[String]) -> impl Iterator<Item = String> + '_ {
    args.iter()
        .filter_map(|a| a.strip_prefix("--"))
        .map(|a| a.split_once('=').map_or(a, |(name, _)| name).to_string())
}

/// Check every property of tool `T` and collect the flags it can send.
fn check_tool<T: DeserializeOwned + ProbeParams + JsonSchema>(sent: &mut BTreeSet<String>) {
    let base = tool_argv::<T>(&Map::new());
    sent.extend(flag_names(&base));
    for property in properties::<T>() {
        let args = tool_argv::<T>(&sample(&property));
        assert_ne!(
            args,
            base,
            "{}: property `{property}` does not reach the command line",
            std::any::type_name::<T>()
        );
        sent.extend(flag_names(&args));
    }
}

#[test]
fn every_probe_tool_property_maps_to_a_flag_the_cli_accepts() {
    let mut sent = BTreeSet::new();
    check_tool::<AnalyzeCertificateParams>(&mut sent);
    check_tool::<CheckExpiryParams>(&mut sent);
    check_tool::<CheckRevocationParams>(&mut sent);
    check_tool::<TlsConnectionInfoParams>(&mut sent);
    check_tool::<ExportPemParams>(&mut sent);
    check_tool::<DiagnoseEndpointParams>(&mut sent);
    check_tool::<ValidateCertificateParams>(&mut sent);

    let cmd = Cli::command();
    let check = cmd.find_subcommand("check").expect("check subcommand");
    let missing: Vec<String> = check
        .get_arguments()
        .filter_map(|a| a.get_long())
        .filter(|long| !matches!(*long, "help" | "version"))
        .filter(|long| !sent.contains(*long) && !CLI_ONLY.iter().any(|(name, _)| name == long))
        .map(str::to_string)
        .collect();
    assert!(
        missing.is_empty(),
        "check flags no probe tool sends and CLI_ONLY does not explain: {missing:?}"
    );
    for (name, _) in CLI_ONLY {
        assert!(
            check.get_arguments().any(|a| a.get_long() == Some(name)),
            "CLI_ONLY names `{name}`, which check no longer has"
        );
        assert!(!sent.contains(*name), "CLI_ONLY names `{name}`, which a tool now sends");
    }
}
