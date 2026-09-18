//! Unit and end to end tests for dcert-mcp.
//!
//! VaultParams implements Drop (to zeroize secrets), which forbids the
//! `..Default::default()` functional update syntax; tests build via
//! `VaultParams::default()` then assign fields, so the related lint is allowed.
#![allow(clippy::field_reassign_with_default, unsafe_code, unused_imports)]

use crate::config::*;
use crate::exec::*;
use crate::http::*;
use crate::params::*;
use crate::params_vault::*;
use crate::tools::*;
use crate::validate::*;
use rmcp::{ServerHandler, ServiceExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------
// CORS origin policy parsing
// ---------------------------------------------------------------

#[test]
fn test_parse_allowed_origins_empty_is_none() {
    assert_eq!(parse_allowed_origins(""), CorsOriginPolicy::None);
    assert_eq!(parse_allowed_origins("   "), CorsOriginPolicy::None);
    assert_eq!(parse_allowed_origins(" , , "), CorsOriginPolicy::None);
}

// ---------------------------------------------------------------
// MCP HTTP protocol version negotiation
// ---------------------------------------------------------------

#[test]
fn test_negotiate_protocol_version_echoes_supported() {
    assert_eq!(negotiate_protocol_version(Some("2025-06-18")), "2025-06-18");
    assert_eq!(negotiate_protocol_version(Some("2024-11-05")), "2024-11-05");
    assert_eq!(negotiate_protocol_version(Some("2025-11-25")), "2025-11-25");
}

#[test]
fn test_negotiate_protocol_version_falls_back_to_latest() {
    // Unknown or absent requested version → advertise the latest we support.
    assert_eq!(negotiate_protocol_version(None), "2025-11-25");
    assert_eq!(negotiate_protocol_version(Some("1999-01-01")), "2025-11-25");
    assert_eq!(negotiate_protocol_version(Some("")), "2025-11-25");
}

// ---------------------------------------------------------------
// Insecure-bind guard helper
// ---------------------------------------------------------------

#[test]
fn test_addr_is_loopback() {
    assert!(addr_is_loopback("127.0.0.1:3000"));
    assert!(addr_is_loopback("[::1]:3000"));
    assert!(!addr_is_loopback("0.0.0.0:3000"));
    assert!(!addr_is_loopback("192.168.1.10:3000"));
    // Unparseable → fail closed (treated as non-loopback).
    assert!(!addr_is_loopback("not-an-addr"));
}

// ---------------------------------------------------------------
// HTTP dispatch input validation
// ---------------------------------------------------------------

#[tokio::test]
async fn test_dispatch_tool_call_rejects_flag_target() {
    let config = test_config(PathBuf::from("/nonexistent/dcert"));
    let args = serde_json::json!({"target": "--no-verify"});
    let (out, is_error) = dispatch_tool_call(&config, "analyze_certificate", &args).await;
    assert!(is_error, "flag-like target must be rejected");
    assert!(
        out.contains("must not start with '-'") || out.contains("error:"),
        "got: {out}"
    );
}

#[tokio::test]
async fn test_dispatch_tool_call_unknown_tool_is_error() {
    let config = test_config(PathBuf::from("/nonexistent/dcert"));
    let (out, is_error) = dispatch_tool_call(&config, "no_such_tool", &serde_json::json!({})).await;
    assert!(is_error);
    assert!(out.contains("unknown tool"));
}

#[test]
fn test_parse_allowed_origins_wildcard_is_any() {
    assert_eq!(parse_allowed_origins("*"), CorsOriginPolicy::Any);
    // A wildcard anywhere in the list wins.
    assert_eq!(parse_allowed_origins("https://a.test, *"), CorsOriginPolicy::Any);
}

#[test]
fn test_parse_allowed_origins_list_is_trimmed() {
    assert_eq!(
        parse_allowed_origins("https://a.test, https://b.test ,,"),
        CorsOriginPolicy::List(vec!["https://a.test".to_string(), "https://b.test".to_string()])
    );
}

// ---------------------------------------------------------------
// Upstream error truncation
// ---------------------------------------------------------------

#[test]
fn test_truncate_upstream_error_short_passthrough() {
    assert_eq!(truncate_upstream_error("  permission denied  "), "permission denied");
}

#[test]
fn test_truncate_upstream_error_caps_long_body() {
    let long = "x".repeat(1000);
    let out = truncate_upstream_error(&long);
    assert!(out.ends_with("… (truncated)"));
    assert!(out.chars().count() < 1000);
}

// ---------------------------------------------------------------
// validate_target unit tests
// ---------------------------------------------------------------

#[test]
fn test_validate_target_accepts_hostname() {
    assert!(validate_target("example.com").is_ok());
    assert!(validate_target("www.google.com").is_ok());
}

#[test]
fn test_validate_target_accepts_https_url() {
    assert!(validate_target("https://example.com").is_ok());
    assert!(validate_target("https://example.com:8443/path").is_ok());
}

#[test]
fn test_validate_target_accepts_file_path() {
    assert!(validate_target("tests/data/valid.pem").is_ok());
    assert!(validate_target("/tmp/cert.pem").is_ok());
}

#[test]
fn test_validate_target_rejects_empty() {
    let result = validate_target("");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("must not be empty"));
}

#[test]
fn test_validate_target_rejects_dash_prefix() {
    let result = validate_target("--no-verify");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("must not start with '-'"));
}

#[test]
fn test_validate_target_rejects_flag_like_inputs() {
    assert!(validate_target("-f").is_err());
    assert!(validate_target("--format").is_err());
    assert!(validate_target("--check-revocation").is_err());
    assert!(validate_target("-").is_err()); // stdin not supported in MCP
}

#[test]
fn test_validate_target_rejects_null_bytes() {
    let result = validate_target("example\0.com");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("null bytes"));
}

// ---------------------------------------------------------------
// validate_path unit tests
// ---------------------------------------------------------------

#[test]
fn test_validate_path_accepts_valid() {
    assert!(validate_path("/tmp/cert.pem", "cert").is_ok());
    assert!(validate_path("relative/path.pem", "cert").is_ok());
}

#[test]
fn test_validate_path_rejects_empty() {
    assert!(validate_path("", "cert").is_err());
}

#[test]
fn test_validate_path_rejects_dash_prefix() {
    assert!(validate_path("--flag", "cert").is_err());
}

#[test]
fn test_validate_path_rejects_traversal() {
    assert!(validate_path("../etc/passwd", "cert").is_err());
    assert!(validate_path("/tmp/../etc/passwd", "cert").is_err());
    assert!(validate_path("foo/../../bar", "cert").is_err());
    assert!(validate_path("..", "cert").is_err());
}

#[test]
fn test_validate_path_accepts_filename_with_dots() {
    // The previous substring-based check false-positived on filenames
    // that happened to contain '..' as part of the name (e.g. backup
    // files or chained extensions). The component-based check accepts
    // these; only an actual `..` path segment is rejected.
    assert!(validate_path("/tmp/my..config.pem", "cert").is_ok());
    assert!(validate_path("backup..2025.pem", "cert").is_ok());
    assert!(validate_path("foo./bar", "cert").is_ok());
    assert!(validate_path("foo/./bar", "cert").is_ok());
}

// ---------------------------------------------------------------
// MtlsParams validation tests
// ---------------------------------------------------------------

#[test]
fn test_mtls_params_empty_valid() {
    let params = MtlsParams::default();
    assert!(params.validate().is_ok());
}

#[test]
fn test_mtls_params_cert_without_key() {
    let params = MtlsParams {
        client_cert: Some("/tmp/cert.pem".to_string()),
        client_key: None,
        ..Default::default()
    };
    assert!(params.validate().is_err());
}

#[test]
fn test_mtls_params_cert_and_pkcs12_conflict() {
    let params = MtlsParams {
        client_cert: Some("/tmp/cert.pem".to_string()),
        client_key: Some("/tmp/key.pem".to_string()),
        pkcs12: Some("/tmp/client.pfx".to_string()),
        ..Default::default()
    };
    assert!(params.validate().is_err());
}

#[test]
fn test_mtls_params_to_args() {
    let params = MtlsParams {
        client_cert: Some("/tmp/cert.pem".to_string()),
        client_key: Some("/tmp/key.pem".to_string()),
        ca_cert: Some("/tmp/ca.pem".to_string()),
        ..Default::default()
    };
    let args = params.to_args();
    assert!(args.contains(&"--client-cert".to_string()));
    assert!(args.contains(&"--client-key".to_string()));
    assert!(args.contains(&"--ca-cert".to_string()));
}

// ---------------------------------------------------------------
// HttpTlsParams connection-override unit tests
// ---------------------------------------------------------------

/// Index of the value that follows `flag` in an argv vector.
fn value_after(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .zip(args.iter().skip(1))
        .filter(|(f, _)| f.as_str() == flag)
        .map(|(_, v)| v.clone())
        .collect()
}

#[test]
fn test_http_tls_params_connect_to_accepts_single_string() {
    let params = HttpTlsParams {
        connect_to: Some(OneOrMany::One("10.0.0.5".to_string())),
        ..Default::default()
    };
    assert_eq!(value_after(&params.to_args(), "--connect-to"), vec!["10.0.0.5"]);
}

#[test]
fn test_http_tls_params_connect_to_accepts_list() {
    let params = HttpTlsParams {
        connect_to: Some(OneOrMany::Many(vec![
            "api.example.com:443:origin.internal:8443".to_string(),
            "10.0.0.5".to_string(),
        ])),
        ..Default::default()
    };
    assert_eq!(
        value_after(&params.to_args(), "--connect-to"),
        vec!["api.example.com:443:origin.internal:8443", "10.0.0.5"]
    );
}

#[test]
fn test_http_tls_params_resolve_to_args() {
    let params = HttpTlsParams {
        resolve: Some(OneOrMany::Many(vec![
            "api.example.com:443:10.0.0.5".to_string(),
            "*:8443:10.0.0.6".to_string(),
        ])),
        ..Default::default()
    };
    assert_eq!(
        value_after(&params.to_args(), "--resolve"),
        vec!["api.example.com:443:10.0.0.5", "*:8443:10.0.0.6"]
    );
}

#[test]
fn test_http_tls_params_deserializes_string_or_list() {
    let one: HttpTlsParams = serde_json::from_value(serde_json::json!({"connect_to": "10.0.0.5"})).unwrap();
    assert_eq!(value_after(&one.to_args(), "--connect-to"), vec!["10.0.0.5"]);

    let many: HttpTlsParams =
        serde_json::from_value(serde_json::json!({"resolve": ["a.example.com:443:10.0.0.5"]})).unwrap();
    assert_eq!(
        value_after(&many.to_args(), "--resolve"),
        vec!["a.example.com:443:10.0.0.5"]
    );
}

#[test]
fn test_http_tls_params_proxy_goes_via_env_not_argv() {
    let params = HttpTlsParams {
        proxy: Some("http://user:pass@proxy.corp:3128".to_string()),
        noproxy: Some("*".to_string()),
        ..Default::default()
    };
    let args = params.to_args();
    assert!(
        !args.iter().any(|a| a.contains("proxy.corp")),
        "proxy credentials must not reach argv: {args:?}"
    );
    assert_eq!(
        params.env_vars(),
        vec![
            ("DCERT_PROXY", "http://user:pass@proxy.corp:3128"),
            ("DCERT_NOPROXY", "*"),
        ]
    );
}

/// The HTTP transport builds subprocess argv from the raw JSON arguments
/// rather than from a typed `Parameters<T>`, so it can silently drop
/// parameters that `tools/list` advertises. Deserializing the shared struct
/// is what keeps the two transports honest — this pins that behaviour.
#[test]
fn test_http_transport_deserializes_the_same_params_as_stdio() {
    let arguments = serde_json::json!({
        "target": "https://api.example.com",
        "fingerprint": true,
        "connect_to": "api.example.com:443:origin.internal:8443",
        "resolve": ["api.example.com:443:10.0.0.5"],
        "sni": "api.example.com",
        "proxy": "http://proxy.corp:3128",
        "noproxy": "*",
    });

    let http_tls: HttpTlsParams = serde_json::from_value(arguments).expect("unknown keys are ignored");
    assert!(http_tls.validate().is_ok());

    let args = http_tls.to_args();
    assert_eq!(
        value_after(&args, "--connect-to"),
        vec!["api.example.com:443:origin.internal:8443"]
    );
    assert_eq!(value_after(&args, "--resolve"), vec!["api.example.com:443:10.0.0.5"]);
    assert_eq!(value_after(&args, "--sni"), vec!["api.example.com"]);
    assert_eq!(
        http_tls.env_vars(),
        vec![("DCERT_PROXY", "http://proxy.corp:3128"), ("DCERT_NOPROXY", "*")]
    );
}

#[test]
fn test_http_tls_params_validate_accepts_normal_values() {
    let params = HttpTlsParams {
        connect_to: Some(OneOrMany::One("10.0.0.5".to_string())),
        resolve: Some(OneOrMany::One("api.example.com:443:10.0.0.5".to_string())),
        proxy: Some("http://proxy.corp:3128".to_string()),
        noproxy: Some("internal.corp,*".to_string()),
        ..Default::default()
    };
    assert!(params.validate().is_ok());
}

#[test]
fn test_http_tls_params_validate_rejects_flag_injection() {
    let params = HttpTlsParams {
        connect_to: Some(OneOrMany::One("--no-verify".to_string())),
        ..Default::default()
    };
    assert!(params.validate().unwrap_err().contains("must not start with '-'"));

    let params = HttpTlsParams {
        resolve: Some(OneOrMany::One("--export-pem".to_string())),
        ..Default::default()
    };
    assert!(params.validate().unwrap_err().contains("must not start with '-'"));

    let params = HttpTlsParams {
        proxy: Some("--ca-cert".to_string()),
        ..Default::default()
    };
    assert!(params.validate().is_err());

    let params = HttpTlsParams {
        noproxy: Some("--debug".to_string()),
        ..Default::default()
    };
    assert!(params.validate().is_err());
}

#[test]
fn test_http_tls_params_validate_rejects_null_bytes_and_empty() {
    let params = HttpTlsParams {
        resolve: Some(OneOrMany::One("a.example.com:443:10.0.0.5\0".to_string())),
        ..Default::default()
    };
    assert!(params.validate().unwrap_err().contains("null bytes"));

    let params = HttpTlsParams {
        connect_to: Some(OneOrMany::One("  ".to_string())),
        ..Default::default()
    };
    assert!(params.validate().unwrap_err().contains("must not be empty"));
}

// ---------------------------------------------------------------
// validate_tls_version unit tests
// ---------------------------------------------------------------

#[test]
fn test_validate_tls_version_accepts_valid() {
    assert!(validate_tls_version("1.2").is_ok());
    assert!(validate_tls_version("1.3").is_ok());
}

#[test]
fn test_validate_tls_version_rejects_invalid() {
    assert!(validate_tls_version("1.0").is_err());
    assert!(validate_tls_version("1.1").is_err());
    assert!(validate_tls_version("2.0").is_err());
    assert!(validate_tls_version("tls1.3").is_err());
    assert!(validate_tls_version("").is_err());
}

// ---------------------------------------------------------------
// find_dcert_binary unit tests
// ---------------------------------------------------------------

/// Mutex to serialize tests that modify environment variables.
/// SAFETY: `set_var`/`remove_var` are unsafe because they are not
/// thread-safe. This mutex ensures only one test mutates env vars
/// at a time, and `--test-threads=1` (or the mutex) prevents
/// concurrent reads from other tests. Tests always restore the
/// original value before releasing the lock.
static DCERT_PATH_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_find_dcert_binary_respects_env() {
    let _guard = DCERT_PATH_MUTEX.lock().unwrap();
    // Save and restore existing env
    let original = std::env::var("DCERT_PATH").ok();
    unsafe { std::env::set_var("DCERT_PATH", "/custom/path/dcert") };
    let path = find_dcert_binary();
    assert_eq!(path, PathBuf::from("/custom/path/dcert"));
    // Restore
    if let Some(orig) = original {
        unsafe { std::env::set_var("DCERT_PATH", orig) };
    } else {
        unsafe { std::env::remove_var("DCERT_PATH") };
    }
}

#[test]
fn test_find_dcert_binary_fallback() {
    let _guard = DCERT_PATH_MUTEX.lock().unwrap();
    // Save and restore existing env
    let original = std::env::var("DCERT_PATH").ok();
    unsafe { std::env::remove_var("DCERT_PATH") };
    let path = find_dcert_binary();
    // Should either find a sibling binary or fall back to "dcert"
    assert!(path.file_name().unwrap().to_str().unwrap().starts_with("dcert"));
    // Restore
    if let Some(orig) = original {
        unsafe { std::env::set_var("DCERT_PATH", orig) };
    }
}

// ---------------------------------------------------------------
// DcertMcpServer construction tests
// ---------------------------------------------------------------

/// Create a test McpConfig with default values and optional dcert binary path.
fn test_config(dcert_binary: PathBuf) -> McpConfig {
    McpConfig {
        subprocess_timeout: Duration::from_secs(DEFAULT_SUBPROCESS_TIMEOUT),
        connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
        read_timeout: DEFAULT_READ_TIMEOUT,
        dcert_binary,
        proxy_config: McpProxyInfo {
            https_proxy: None,
            http_proxy: None,
            no_proxy: None,
        },
    }
}

#[test]
fn test_server_construction() {
    let server = DcertMcpServer::new(test_config(PathBuf::from("dcert")));
    let info = server.get_info();
    assert_eq!(info.server_info.name, "dcert-mcp");
    assert!(!info.server_info.version.is_empty());
    assert_eq!(info.server_info.title.as_deref(), Some("dcert MCP Server"));
    assert_eq!(info.server_info.description.as_deref(), Some(MCP_DESCRIPTION));
}

#[test]
fn test_server_default() {
    let server = DcertMcpServer::default();
    let info = server.get_info();
    assert_eq!(info.server_info.name, "dcert-mcp");
}

// ---------------------------------------------------------------
// run_dcert integration tests (requires built binary)
// ---------------------------------------------------------------

#[tokio::test]
async fn test_run_dcert_with_pem_file() {
    let dcert_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("dcert");
    if !dcert_path.exists() {
        eprintln!("Skipping test: dcert binary not found at {dcert_path:?}");
        return;
    }

    let config = test_config(dcert_path);
    let result = run_dcert(&["tests/data/valid.pem", "--format", "json"], &config).await;

    assert!(result.is_ok(), "run_dcert should succeed: {result:?}");
    let (stdout, _stderr, code) = result.unwrap();
    assert_eq!(code, 0, "exit code should be 0");
    assert!(stdout.contains("certificates"), "should contain JSON output");
}

#[tokio::test]
async fn test_run_dcert_with_invalid_file() {
    let dcert_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("dcert");
    if !dcert_path.exists() {
        eprintln!("Skipping test: dcert binary not found at {dcert_path:?}");
        return;
    }

    let config = test_config(dcert_path);
    let result = run_dcert(&["nonexistent_file.pem", "--format", "json"], &config).await;

    assert!(result.is_ok(), "run_dcert should not fail on spawn");
    let (_stdout, stderr, code) = result.unwrap();
    assert_ne!(code, 0, "exit code should be non-zero for invalid file");
    assert!(!stderr.is_empty(), "stderr should contain error message");
}

// ---------------------------------------------------------------
// MCP tool integration tests (via duplex transport)
// ---------------------------------------------------------------

#[tokio::test]
async fn test_mcp_analyze_certificate_with_pem() {
    use rmcp::model::CallToolRequestParams;
    use rmcp::{ClientHandler, ServiceExt};

    let dcert_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("dcert");
    if !dcert_path.exists() {
        eprintln!("Skipping test: dcert binary not found at {dcert_path:?}");
        return;
    }

    let (server_transport, client_transport) = tokio::io::duplex(65536);

    let server = DcertMcpServer::new(test_config(dcert_path));
    let server_handle = tokio::spawn(async move {
        let svc = server.serve(server_transport).await.unwrap();
        svc.waiting().await.unwrap();
    });

    #[derive(Clone, Default)]
    struct TestClient;
    impl ClientHandler for TestClient {}

    let client = TestClient.serve(client_transport).await.unwrap();

    let result = client
        .call_tool(
            CallToolRequestParams::new("analyze_certificate").with_arguments(
                serde_json::json!({
                    "target": "tests/data/valid.pem",
                    "fingerprint": true,
                    "extensions": false,
                    "check_revocation": false
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await;

    assert!(result.is_ok(), "Tool call should succeed: {result:?}");
    let response = result.unwrap();
    let text = response
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .unwrap_or("");
    assert!(
        text.contains("certificates"),
        "Response should contain JSON with certificates: {}",
        &text[..text.len().min(200)]
    );
    // Root-CA trust classification flows through the MCP path by default.
    // valid.pem is a self-signed certificate.
    assert!(
        text.contains("root_trust") && text.contains("self_signed"),
        "Response should classify the self-signed root: {}",
        &text[..text.len().min(400)]
    );

    client.cancel().await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn test_mcp_analyze_rejects_flag_injection() {
    use rmcp::model::CallToolRequestParams;
    use rmcp::{ClientHandler, ServiceExt};

    let (server_transport, client_transport) = tokio::io::duplex(65536);

    let server = DcertMcpServer::default();
    let server_handle = tokio::spawn(async move {
        let svc = server.serve(server_transport).await.unwrap();
        svc.waiting().await.unwrap();
    });

    #[derive(Clone, Default)]
    struct TestClient;
    impl ClientHandler for TestClient {}

    let client = TestClient.serve(client_transport).await.unwrap();

    let result = client
        .call_tool(
            CallToolRequestParams::new("analyze_certificate").with_arguments(
                serde_json::json!({
                    "target": "--no-verify"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await;

    assert!(result.is_ok(), "Tool call should return error result, not fail");
    let response = result.unwrap();
    // Should be marked as error (is_error = true)
    assert!(
        response.is_error.unwrap_or(false),
        "Response should be an error for flag-like target"
    );
    let text = response
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .unwrap_or("");
    assert!(
        text.contains("must not start with '-'"),
        "Error should mention flag rejection: {text}"
    );

    client.cancel().await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn test_mcp_tls_connection_rejects_invalid_tls_version() {
    use rmcp::model::CallToolRequestParams;
    use rmcp::{ClientHandler, ServiceExt};

    let (server_transport, client_transport) = tokio::io::duplex(65536);

    let server = DcertMcpServer::default();
    let server_handle = tokio::spawn(async move {
        let svc = server.serve(server_transport).await.unwrap();
        svc.waiting().await.unwrap();
    });

    #[derive(Clone, Default)]
    struct TestClient;
    impl ClientHandler for TestClient {}

    let client = TestClient.serve(client_transport).await.unwrap();

    let result = client
        .call_tool(
            CallToolRequestParams::new("tls_connection_info").with_arguments(
                serde_json::json!({
                    "target": "example.com",
                    "min_tls": "1.0"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.is_error.unwrap_or(false));
    let text = response
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .unwrap_or("");
    assert!(
        text.contains("Invalid TLS version"),
        "Error should mention invalid TLS version: {text}"
    );

    client.cancel().await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn test_mcp_check_expiry_with_pem() {
    use rmcp::model::CallToolRequestParams;
    use rmcp::{ClientHandler, ServiceExt};

    let dcert_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("dcert");
    if !dcert_path.exists() {
        eprintln!("Skipping test: dcert binary not found at {dcert_path:?}");
        return;
    }

    let (server_transport, client_transport) = tokio::io::duplex(65536);

    let server = DcertMcpServer::new(test_config(dcert_path));
    let server_handle = tokio::spawn(async move {
        let svc = server.serve(server_transport).await.unwrap();
        svc.waiting().await.unwrap();
    });

    #[derive(Clone, Default)]
    struct TestClient;
    impl ClientHandler for TestClient {}

    let client = TestClient.serve(client_transport).await.unwrap();

    let result = client
        .call_tool(
            CallToolRequestParams::new("check_expiry").with_arguments(
                serde_json::json!({
                    "target": "tests/data/valid.pem",
                    "days": 30
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await;

    assert!(result.is_ok(), "Tool call should succeed: {result:?}");
    let response = result.unwrap();
    let text = response
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .unwrap_or("");
    assert!(
        text.contains("expiry_status:"),
        "Response should contain expiry status: {}",
        &text[..text.len().min(200)]
    );

    client.cancel().await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn test_mcp_compare_rejects_empty_target() {
    use rmcp::model::CallToolRequestParams;
    use rmcp::{ClientHandler, ServiceExt};

    let (server_transport, client_transport) = tokio::io::duplex(65536);

    let server = DcertMcpServer::default();
    let server_handle = tokio::spawn(async move {
        let svc = server.serve(server_transport).await.unwrap();
        svc.waiting().await.unwrap();
    });

    #[derive(Clone, Default)]
    struct TestClient;
    impl ClientHandler for TestClient {}

    let client = TestClient.serve(client_transport).await.unwrap();

    let result = client
        .call_tool(
            CallToolRequestParams::new("compare_certificates").with_arguments(
                serde_json::json!({
                    "target_a": "",
                    "target_b": "example.com"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.is_error.unwrap_or(false));
    let text = response
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .unwrap_or("");
    assert!(
        text.contains("must not be empty"),
        "Error should mention empty target: {text}"
    );

    client.cancel().await.unwrap();
    server_handle.abort();
}

// ---------------------------------------------------------------
// validate_password unit tests
// ---------------------------------------------------------------

#[test]
fn test_validate_password_accepts_normal() {
    assert!(validate_password("secret123").is_ok());
    assert!(validate_password("").is_ok()); // empty is valid (some tools allow it)
    assert!(validate_password("a".repeat(1024).as_str()).is_ok()); // at the limit
}

#[test]
fn test_validate_password_rejects_too_long() {
    let long = "a".repeat(1025);
    assert!(validate_password(&long).is_err());
}

#[test]
fn test_validate_password_rejects_null_bytes() {
    assert!(validate_password("pass\0word").is_err());
}

// ---------------------------------------------------------------
// validate_alias unit tests
// ---------------------------------------------------------------

#[test]
fn test_validate_alias_accepts_valid() {
    assert!(validate_alias("server").is_ok());
    assert!(validate_alias("my-key_entry.1").is_ok());
    assert!(validate_alias("a").is_ok());
}

#[test]
fn test_validate_alias_rejects_empty() {
    assert!(validate_alias("").is_err());
}

#[test]
fn test_validate_alias_rejects_too_long() {
    let long = "a".repeat(257);
    assert!(validate_alias(&long).is_err());
}

#[test]
fn test_validate_alias_rejects_special_chars() {
    assert!(validate_alias("my alias").is_err()); // space
    assert!(validate_alias("my/alias").is_err()); // slash
    assert!(validate_alias("alias;rm").is_err()); // semicolon
}

// ---------------------------------------------------------------
// truncate_output unit tests
// ---------------------------------------------------------------

#[test]
fn test_truncate_output_passes_small() {
    let small = "hello world".to_string();
    let result = truncate_output(small.clone());
    assert_eq!(result, small);
}

#[test]
fn test_truncate_output_truncates_large() {
    let large = "x".repeat(MAX_OUTPUT_SIZE + 1000);
    let result = truncate_output(large);
    assert!(result.len() < MAX_OUTPUT_SIZE + 200); // truncated + message
    assert!(result.contains("output truncated"));
}

#[test]
fn test_truncate_output_multibyte_utf8() {
    // Build a string where MAX_OUTPUT_SIZE falls in the middle of a multi-byte char.
    // '€' is 3 bytes in UTF-8. Fill up to just before MAX_OUTPUT_SIZE, then add '€'.
    let padding = "a".repeat(MAX_OUTPUT_SIZE - 1);
    let input = format!("{padding}€extra"); // '€' starts at MAX_OUTPUT_SIZE-1
    let result = truncate_output(input);
    assert!(result.contains("output truncated"));
    // Must not panic — the key property being tested
    assert!(result.is_char_boundary(0)); // valid UTF-8
}

// ---------------------------------------------------------------
// MCP tool: TLS version ordering rejection
// ---------------------------------------------------------------

#[tokio::test]
async fn test_mcp_tls_connection_rejects_inverted_tls_range() {
    use rmcp::model::CallToolRequestParams;
    use rmcp::{ClientHandler, ServiceExt};

    let (server_transport, client_transport) = tokio::io::duplex(65536);

    let server = DcertMcpServer::default();
    let server_handle = tokio::spawn(async move {
        let svc = server.serve(server_transport).await.unwrap();
        svc.waiting().await.unwrap();
    });

    #[derive(Clone, Default)]
    struct TestClient;
    impl ClientHandler for TestClient {}

    let client = TestClient.serve(client_transport).await.unwrap();

    let result = client
        .call_tool(
            CallToolRequestParams::new("tls_connection_info").with_arguments(
                serde_json::json!({
                    "target": "example.com",
                    "min_tls": "1.3",
                    "max_tls": "1.2"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.is_error.unwrap_or(false));
    let text = response
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .unwrap_or("");
    assert!(
        text.contains("must not be greater than"),
        "Error should mention TLS version ordering: {text}"
    );

    client.cancel().await.unwrap();
    server_handle.abort();
}

// ---------------------------------------------------------------
// MCP tool: check_expiry days bounds
// ---------------------------------------------------------------

#[tokio::test]
async fn test_mcp_check_expiry_rejects_excessive_days() {
    use rmcp::model::CallToolRequestParams;
    use rmcp::{ClientHandler, ServiceExt};

    let (server_transport, client_transport) = tokio::io::duplex(65536);

    let server = DcertMcpServer::default();
    let server_handle = tokio::spawn(async move {
        let svc = server.serve(server_transport).await.unwrap();
        svc.waiting().await.unwrap();
    });

    #[derive(Clone, Default)]
    struct TestClient;
    impl ClientHandler for TestClient {}

    let client = TestClient.serve(client_transport).await.unwrap();

    let result = client
        .call_tool(
            CallToolRequestParams::new("check_expiry").with_arguments(
                serde_json::json!({
                    "target": "example.com",
                    "days": 9999
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.is_error.unwrap_or(false));
    let text = response
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .unwrap_or("");
    assert!(text.contains("at most 3650"), "Error should mention days limit: {text}");

    client.cancel().await.unwrap();
    server_handle.abort();
}

// ---------------------------------------------------------------
// McpConfig and McpProxyInfo tests
// ---------------------------------------------------------------

#[test]
fn test_mcp_proxy_info_from_env_empty() {
    let _guard = DCERT_PATH_MUTEX.lock().unwrap();
    // Clear all proxy env vars
    for var in &[
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        unsafe { std::env::remove_var(var) };
    }
    let info = McpProxyInfo::from_env();
    assert!(info.https_proxy.is_none());
    assert!(info.http_proxy.is_none());
    assert!(info.no_proxy.is_none());
}

#[test]
fn test_mcp_proxy_info_from_env_with_proxy() {
    let _guard = DCERT_PATH_MUTEX.lock().unwrap();
    // Clear then set
    for var in &[
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        unsafe { std::env::remove_var(var) };
    }
    unsafe {
        std::env::set_var("HTTPS_PROXY", "http://proxy.corp:8080");
        std::env::set_var("NO_PROXY", "localhost,127.0.0.1");
    }
    let info = McpProxyInfo::from_env();
    assert_eq!(info.https_proxy.as_deref(), Some("http://proxy.corp:8080"));
    assert_eq!(info.no_proxy.as_deref(), Some("localhost,127.0.0.1"));
    // Restore
    unsafe {
        std::env::remove_var("HTTPS_PROXY");
        std::env::remove_var("NO_PROXY");
    }
}

// ---------------------------------------------------------------
// sanitize_proxy_url tests
// ---------------------------------------------------------------

#[test]
fn test_sanitize_proxy_url_masks_password() {
    let result = dcert::debug::sanitize_url("http://user:secret@proxy.example.com:8080");
    assert!(result.contains("****"), "password should be masked");
    assert!(!result.contains("secret"), "original password should not appear");
}

#[test]
fn test_sanitize_proxy_url_no_password() {
    let result = dcert::debug::sanitize_url("http://proxy.example.com:8080");
    assert!(!result.contains("****"));
}

#[test]
fn test_sanitize_proxy_url_invalid() {
    let result = dcert::debug::sanitize_url("not-a-url");
    assert_eq!(result, "not-a-url");
}

// ---------------------------------------------------------------
// format_timeout_error tests
// ---------------------------------------------------------------

#[test]
fn test_format_timeout_error_with_proxy() {
    let config = McpConfig {
        subprocess_timeout: Duration::from_secs(120),
        connection_timeout: 30,
        read_timeout: 15,
        dcert_binary: PathBuf::from("dcert"),
        proxy_config: McpProxyInfo {
            https_proxy: Some("http://proxy.corp.com:8080".to_string()),
            http_proxy: None,
            no_proxy: Some("localhost,127.0.0.1".to_string()),
        },
    };
    let msg = format_timeout_error(&config);
    assert!(msg.contains("120s"), "should mention timeout duration");
    assert!(msg.contains("proxy"), "should mention proxy: {msg}");
    assert!(msg.contains("DCERT_MCP_TIMEOUT"), "should mention env var");
    assert!(msg.contains("NO_PROXY"), "should mention NO_PROXY");
}

#[test]
fn test_format_timeout_error_without_proxy() {
    let config = McpConfig {
        subprocess_timeout: Duration::from_secs(60),
        connection_timeout: 10,
        read_timeout: 5,
        dcert_binary: PathBuf::from("dcert"),
        proxy_config: McpProxyInfo {
            https_proxy: None,
            http_proxy: None,
            no_proxy: None,
        },
    };
    let msg = format_timeout_error(&config);
    assert!(msg.contains("60s"));
    assert!(
        msg.contains("No proxy configured"),
        "should hint to set HTTPS_PROXY: {msg}"
    );
    assert!(msg.contains("HTTPS_PROXY"));
}

// ---------------------------------------------------------------
// VaultParams validation tests
// ---------------------------------------------------------------

#[test]
fn test_vault_params_token_default_valid() {
    let params = VaultParams::default();
    // Token method with no explicit token is valid (falls back to env/file)
    assert!(params.validate().is_ok());
}

#[test]
fn test_vault_params_ldap_missing_username() {
    let mut params = VaultParams::default();
    params.auth_method = Some("ldap".to_string());
    params.ldap_password = Some("pass".to_string());
    params.vault_addr = Some("https://vault.example.com:8200".to_string());
    let err = params.validate().unwrap_err();
    assert!(
        err.contains("ldap_username"),
        "Error should mention ldap_username: {err}"
    );
}

#[test]
fn test_vault_params_ldap_missing_password() {
    let mut params = VaultParams::default();
    params.auth_method = Some("ldap".to_string());
    params.ldap_username = Some("user".to_string());
    params.vault_addr = Some("https://vault.example.com:8200".to_string());
    let err = params.validate().unwrap_err();
    assert!(
        err.contains("ldap_password"),
        "Error should mention ldap_password: {err}"
    );
}

#[test]
fn test_vault_params_ldap_valid() {
    let mut params = VaultParams::default();
    params.auth_method = Some("ldap".to_string());
    params.ldap_username = Some("user".to_string());
    params.ldap_password = Some("pass".to_string());
    params.vault_addr = Some("https://vault.example.com:8200".to_string());
    assert!(params.validate().is_ok());
}

#[test]
fn test_vault_params_approle_missing_role_id() {
    let mut params = VaultParams::default();
    params.auth_method = Some("approle".to_string());
    params.approle_secret_id = Some("secret".to_string());
    params.vault_addr = Some("https://vault.example.com:8200".to_string());
    let err = params.validate().unwrap_err();
    assert!(
        err.contains("approle_role_id"),
        "Error should mention approle_role_id: {err}"
    );
}

#[test]
fn test_vault_params_approle_missing_secret_id() {
    let mut params = VaultParams::default();
    params.auth_method = Some("approle".to_string());
    params.approle_role_id = Some("role-id".to_string());
    params.vault_addr = Some("https://vault.example.com:8200".to_string());
    let err = params.validate().unwrap_err();
    assert!(
        err.contains("approle_secret_id"),
        "Error should mention approle_secret_id: {err}"
    );
}

#[test]
fn test_vault_params_approle_valid() {
    let mut params = VaultParams::default();
    params.auth_method = Some("approle".to_string());
    params.approle_role_id = Some("role-id".to_string());
    params.approle_secret_id = Some("secret-id".to_string());
    params.vault_addr = Some("https://vault.example.com:8200".to_string());
    assert!(params.validate().is_ok());
}

#[test]
fn test_vault_params_invalid_method() {
    let mut params = VaultParams::default();
    params.auth_method = Some("invalid".to_string());
    let err = params.validate().unwrap_err();
    assert!(err.contains("Invalid auth_method"), "Error: {err}");
}

#[test]
fn test_vault_params_resolve_addr() {
    let mut params = VaultParams::default();
    params.vault_addr = Some("https://vault.example.com:8200/".to_string());
    assert_eq!(
        params.resolve_addr(),
        Some("https://vault.example.com:8200".to_string())
    );
}

#[test]
fn test_vault_params_resolve_addr_no_trailing_slash() {
    let mut params = VaultParams::default();
    params.vault_addr = Some("https://vault.example.com:8200".to_string());
    assert_eq!(
        params.resolve_addr(),
        Some("https://vault.example.com:8200".to_string())
    );
}
