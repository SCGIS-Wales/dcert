use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;

/// Maximum time allowed for a single dcert subprocess invocation.
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(60);

/// Locate the dcert binary. Checks DCERT_PATH env, then sibling directory
/// of the current executable, then falls back to "dcert" on $PATH.
fn find_dcert_binary() -> PathBuf {
    if let Ok(path) = std::env::var("DCERT_PATH") {
        return PathBuf::from(path);
    }

    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("dcert");
        if sibling.exists() {
            return sibling;
        }
    }

    PathBuf::from("dcert")
}

/// Validate a target string to prevent argument injection.
///
/// Targets starting with `-` could be misinterpreted as CLI flags by the
/// dcert subprocess. We reject them unless they look like a valid stdin
/// indicator (bare `-`) which the MCP server doesn't support.
fn validate_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("Target must not be empty".to_string());
    }
    if target.starts_with('-') {
        return Err(format!(
            "Invalid target '{}': targets must not start with '-' (looks like a CLI flag)",
            target
        ));
    }
    // Reject targets with embedded null bytes
    if target.contains('\0') {
        return Err("Target must not contain null bytes".to_string());
    }
    Ok(())
}

/// Run dcert with given arguments and return (stdout, stderr, exit_code).
///
/// Enforces a timeout to prevent indefinite hangs from slow or unreachable targets.
async fn run_dcert(args: &[&str]) -> Result<(String, String, i32), String> {
    let dcert = find_dcert_binary();
    let child = Command::new(&dcert)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run dcert at {}: {}", dcert.display(), e))?;

    let output = tokio::time::timeout(SUBPROCESS_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| format!("dcert subprocess timed out after {}s", SUBPROCESS_TIMEOUT.as_secs()))?
        .map_err(|e| format!("Failed to run dcert at {}: {}", dcert.display(), e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(2);

    Ok((stdout, stderr, code))
}

// -- Parameter types --

/// Parameters for the analyze_certificate tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct AnalyzeCertificateParams {
    /// HTTPS URL, hostname, or local path to a PEM file. Bare hostnames are auto-converted to https://
    target: String,
    /// Include SHA-256 fingerprints (default: true)
    #[serde(default = "default_true")]
    fingerprint: bool,
    /// Include certificate extensions such as key usage, basic constraints, etc. (default: true)
    #[serde(default = "default_true")]
    extensions: bool,
    /// Check OCSP revocation status (default: false)
    #[serde(default)]
    check_revocation: bool,
}

/// Parameters for the check_expiry tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct CheckExpiryParams {
    /// HTTPS URL, hostname, or local path to a PEM file. Bare hostnames are auto-converted to https://
    target: String,
    /// Warning threshold in days (default: 30)
    #[serde(default = "default_30")]
    days: u64,
}

/// Parameters for the check_revocation tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct CheckRevocationParams {
    /// HTTPS URL, hostname, or local path to a PEM file. Bare hostnames are auto-converted to https://
    target: String,
}

/// Parameters for the compare_certificates tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct CompareCertificatesParams {
    /// First HTTPS URL, hostname, or PEM file path
    target_a: String,
    /// Second HTTPS URL, hostname, or PEM file path
    target_b: String,
}

/// Parameters for the tls_connection_info tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct TlsConnectionInfoParams {
    /// HTTPS URL or hostname to inspect TLS connection details
    target: String,
    /// Minimum TLS version: "1.2" or "1.3"
    min_tls: Option<String>,
    /// Maximum TLS version: "1.2" or "1.3"
    max_tls: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_30() -> u64 {
    30
}

/// Validate that a TLS version string is one of the accepted values.
fn validate_tls_version(version: &str) -> Result<(), String> {
    match version {
        "1.2" | "1.3" => Ok(()),
        _ => Err(format!("Invalid TLS version '{}': must be \"1.2\" or \"1.3\"", version)),
    }
}

fn ok_text(text: String) -> Result<CallToolResult, rmcp::ErrorData> {
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

fn ok_error(msg: String) -> Result<CallToolResult, rmcp::ErrorData> {
    Ok(CallToolResult::error(vec![Content::text(msg)]))
}

// -- MCP Server Handler --

/// dcert MCP server handler.
#[derive(Debug, Clone)]
pub struct DcertMcpServer {
    tool_router: ToolRouter<Self>,
}

impl DcertMcpServer {
    /// Create a new dcert MCP server.
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

impl Default for DcertMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl DcertMcpServer {
    /// Decode and analyze TLS certificates from an HTTPS endpoint or PEM file.
    #[tool(
        description = "Decode and analyze TLS certificates from an HTTPS endpoint or PEM file. Returns certificate details including subject, issuer, SANs, validity dates, fingerprints, extensions, and TLS connection information."
    )]
    pub async fn analyze_certificate(
        &self,
        Parameters(params): Parameters<AnalyzeCertificateParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }

        let mut args = vec![params.target.as_str(), "--format", "json"];
        if params.fingerprint {
            args.push("--fingerprint");
        }
        if params.extensions {
            args.push("--extensions");
        }
        if params.check_revocation {
            args.push("--check-revocation");
        }

        match run_dcert(&args).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- stderr ---\n");
                    output.push_str(&stderr);
                }
                if code != 0 {
                    output.push_str(&format!("\n--- exit code: {} ---", code));
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }

    /// Check if TLS certificates for a target expire within a specified number of days.
    #[tool(
        description = "Check if TLS certificates for a target expire within a specified number of days. Returns expiry status and warnings. Exit codes: 0=ok, 1=expiring soon, 4=already expired."
    )]
    pub async fn check_expiry(
        &self,
        Parameters(params): Parameters<CheckExpiryParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }

        let days_str = params.days.to_string();
        let args = vec![
            params.target.as_str(),
            "--format",
            "json",
            "--fingerprint",
            "--expiry-warn",
            &days_str,
        ];

        match run_dcert(&args).await {
            Ok((stdout, stderr, code)) => {
                let status = match code {
                    0 => "ALL_VALID",
                    1 => "EXPIRING_SOON",
                    4 => "ALREADY_EXPIRED",
                    _ => "ERROR",
                };
                let mut output = format!("expiry_status: {}\n\n", status);
                output.push_str(&stdout);
                if !stderr.is_empty() {
                    output.push_str("\n--- warnings ---\n");
                    output.push_str(&stderr);
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }

    /// Check the OCSP revocation status of TLS certificates.
    #[tool(
        description = "Check the OCSP revocation status of TLS certificates. Queries the certificate's OCSP responder to determine if it has been revoked."
    )]
    pub async fn check_revocation(
        &self,
        Parameters(params): Parameters<CheckRevocationParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }

        let args = vec![
            params.target.as_str(),
            "--format",
            "json",
            "--check-revocation",
            "--extensions",
        ];

        match run_dcert(&args).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if code == 5 {
                    output.insert_str(0, "revocation_status: REVOKED\n\n");
                }
                if !stderr.is_empty() {
                    output.push_str("\n--- stderr ---\n");
                    output.push_str(&stderr);
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }

    /// Compare TLS certificates between two targets and show differences.
    #[tool(
        description = "Compare TLS certificates between two targets and show differences. Useful for verifying certificate rotations, comparing staging vs production, or detecting changes."
    )]
    pub async fn compare_certificates(
        &self,
        Parameters(params): Parameters<CompareCertificatesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target_a) {
            return ok_error(e);
        }
        if let Err(e) = validate_target(&params.target_b) {
            return ok_error(e);
        }

        let args_a = vec![params.target_a.as_str(), "--format", "json", "--fingerprint"];
        let args_b = vec![params.target_b.as_str(), "--format", "json", "--fingerprint"];

        let (result_a, result_b) = tokio::join!(run_dcert(&args_a), run_dcert(&args_b));

        match (result_a, result_b) {
            (Ok((stdout_a, _, _)), Ok((stdout_b, _, _))) => {
                let json_a: serde_json::Value = match serde_json::from_str(&stdout_a) {
                    Ok(v) => v,
                    Err(e) => return ok_error(format!("Failed to parse target_a output: {}", e)),
                };
                let json_b: serde_json::Value = match serde_json::from_str(&stdout_b) {
                    Ok(v) => v,
                    Err(e) => return ok_error(format!("Failed to parse target_b output: {}", e)),
                };

                let diff = serde_json::json!({
                    "target_a": {
                        "target": params.target_a,
                        "result": json_a,
                    },
                    "target_b": {
                        "target": params.target_b,
                        "result": json_b,
                    }
                });

                match serde_json::to_string_pretty(&diff) {
                    Ok(output) => ok_text(output),
                    Err(e) => ok_error(format!("Failed to serialize diff: {}", e)),
                }
            }
            (Err(e), _) => ok_error(format!("Failed to fetch target_a: {}", e)),
            (_, Err(e)) => ok_error(format!("Failed to fetch target_b: {}", e)),
        }
    }

    /// Get TLS connection details for an HTTPS endpoint.
    #[tool(
        description = "Get TLS connection details for an HTTPS endpoint including protocol version, cipher suite, ALPN negotiation, DNS/TCP/TLS latency, and verification status."
    )]
    pub async fn tls_connection_info(
        &self,
        Parameters(params): Parameters<TlsConnectionInfoParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }

        let mut args = vec![
            params.target.as_str(),
            "--format",
            "json",
            "--fingerprint",
            "--extensions",
        ];

        let min_tls_owned;
        let max_tls_owned;

        if let Some(ref min) = params.min_tls {
            if let Err(e) = validate_tls_version(min) {
                return ok_error(e);
            }
            min_tls_owned = min.clone();
            args.push("--min-tls");
            args.push(&min_tls_owned);
        }
        if let Some(ref max) = params.max_tls {
            if let Err(e) = validate_tls_version(max) {
                return ok_error(e);
            }
            max_tls_owned = max.clone();
            args.push("--max-tls");
            args.push(&max_tls_owned);
        }

        match run_dcert(&args).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- stderr ---\n");
                    output.push_str(&stderr);
                }
                if code != 0 {
                    output.push_str(&format!("\n--- exit code: {} ---", code));
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for DcertMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "dcert-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                title: Some("dcert MCP Server".to_string()),
                description: Some("TLS certificate analysis and validation tools for AI-powered IDEs".to_string()),
                icons: None,
                website_url: Some("https://github.com/SCGIS-Wales/dcert".to_string()),
            },
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = DcertMcpServer::new();
    let service = server.serve(rmcp::transport::io::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_find_dcert_binary_respects_env() {
        // Save and restore existing env
        let original = std::env::var("DCERT_PATH").ok();
        std::env::set_var("DCERT_PATH", "/custom/path/dcert");
        let path = find_dcert_binary();
        assert_eq!(path, PathBuf::from("/custom/path/dcert"));
        // Restore
        if let Some(orig) = original {
            std::env::set_var("DCERT_PATH", orig);
        } else {
            std::env::remove_var("DCERT_PATH");
        }
    }

    #[test]
    fn test_find_dcert_binary_fallback() {
        // Save and restore existing env
        let original = std::env::var("DCERT_PATH").ok();
        std::env::remove_var("DCERT_PATH");
        let path = find_dcert_binary();
        // Should either find a sibling binary or fall back to "dcert"
        assert!(path.file_name().unwrap().to_str().unwrap().starts_with("dcert"));
        // Restore
        if let Some(orig) = original {
            std::env::set_var("DCERT_PATH", orig);
        }
    }

    // ---------------------------------------------------------------
    // DcertMcpServer construction tests
    // ---------------------------------------------------------------

    #[test]
    fn test_server_construction() {
        let server = DcertMcpServer::new();
        let info = server.get_info();
        assert_eq!(info.server_info.name, "dcert-mcp");
        assert!(!info.server_info.version.is_empty());
        assert_eq!(info.server_info.title.as_deref(), Some("dcert MCP Server"));
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
        // Point DCERT_PATH to the debug binary
        let dcert_path = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("dcert");
        if !dcert_path.exists() {
            eprintln!("Skipping test: dcert binary not found at {:?}", dcert_path);
            return;
        }
        std::env::set_var("DCERT_PATH", &dcert_path);

        let result = run_dcert(&["tests/data/valid.pem", "--format", "json"]).await;
        std::env::remove_var("DCERT_PATH");

        assert!(result.is_ok(), "run_dcert should succeed: {:?}", result);
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
            eprintln!("Skipping test: dcert binary not found at {:?}", dcert_path);
            return;
        }
        std::env::set_var("DCERT_PATH", &dcert_path);

        let result = run_dcert(&["nonexistent_file.pem", "--format", "json"]).await;
        std::env::remove_var("DCERT_PATH");

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

        // Build the dcert binary path
        let dcert_path = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("dcert");
        if !dcert_path.exists() {
            eprintln!("Skipping test: dcert binary not found at {:?}", dcert_path);
            return;
        }
        std::env::set_var("DCERT_PATH", &dcert_path);

        let (server_transport, client_transport) = tokio::io::duplex(65536);

        let server = DcertMcpServer::new();
        let server_handle = tokio::spawn(async move {
            let svc = server.serve(server_transport).await.unwrap();
            svc.waiting().await.unwrap();
        });

        #[derive(Clone, Default)]
        struct TestClient;
        impl ClientHandler for TestClient {}

        let client = TestClient.serve(client_transport).await.unwrap();

        let result = client
            .call_tool(CallToolRequestParams {
                meta: None,
                name: "analyze_certificate".into(),
                arguments: Some(
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
                task: None,
            })
            .await;

        std::env::remove_var("DCERT_PATH");

        assert!(result.is_ok(), "Tool call should succeed: {:?}", result);
        let response = result.unwrap();
        let text = response
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.as_str())
            .unwrap_or("");
        assert!(
            text.contains("certificates"),
            "Response should contain JSON with certificates: {}",
            &text[..text.len().min(200)]
        );

        client.cancel().await.unwrap();
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_mcp_analyze_rejects_flag_injection() {
        use rmcp::model::CallToolRequestParams;
        use rmcp::{ClientHandler, ServiceExt};

        let (server_transport, client_transport) = tokio::io::duplex(65536);

        let server = DcertMcpServer::new();
        let server_handle = tokio::spawn(async move {
            let svc = server.serve(server_transport).await.unwrap();
            svc.waiting().await.unwrap();
        });

        #[derive(Clone, Default)]
        struct TestClient;
        impl ClientHandler for TestClient {}

        let client = TestClient.serve(client_transport).await.unwrap();

        let result = client
            .call_tool(CallToolRequestParams {
                meta: None,
                name: "analyze_certificate".into(),
                arguments: Some(
                    serde_json::json!({
                        "target": "--no-verify"
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
                task: None,
            })
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
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.as_str())
            .unwrap_or("");
        assert!(
            text.contains("must not start with '-'"),
            "Error should mention flag rejection: {}",
            text
        );

        client.cancel().await.unwrap();
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_mcp_tls_connection_rejects_invalid_tls_version() {
        use rmcp::model::CallToolRequestParams;
        use rmcp::{ClientHandler, ServiceExt};

        let (server_transport, client_transport) = tokio::io::duplex(65536);

        let server = DcertMcpServer::new();
        let server_handle = tokio::spawn(async move {
            let svc = server.serve(server_transport).await.unwrap();
            svc.waiting().await.unwrap();
        });

        #[derive(Clone, Default)]
        struct TestClient;
        impl ClientHandler for TestClient {}

        let client = TestClient.serve(client_transport).await.unwrap();

        let result = client
            .call_tool(CallToolRequestParams {
                meta: None,
                name: "tls_connection_info".into(),
                arguments: Some(
                    serde_json::json!({
                        "target": "example.com",
                        "min_tls": "1.0"
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
                task: None,
            })
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_error.unwrap_or(false));
        let text = response
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.as_str())
            .unwrap_or("");
        assert!(
            text.contains("Invalid TLS version"),
            "Error should mention invalid TLS version: {}",
            text
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
            eprintln!("Skipping test: dcert binary not found at {:?}", dcert_path);
            return;
        }
        std::env::set_var("DCERT_PATH", &dcert_path);

        let (server_transport, client_transport) = tokio::io::duplex(65536);

        let server = DcertMcpServer::new();
        let server_handle = tokio::spawn(async move {
            let svc = server.serve(server_transport).await.unwrap();
            svc.waiting().await.unwrap();
        });

        #[derive(Clone, Default)]
        struct TestClient;
        impl ClientHandler for TestClient {}

        let client = TestClient.serve(client_transport).await.unwrap();

        let result = client
            .call_tool(CallToolRequestParams {
                meta: None,
                name: "check_expiry".into(),
                arguments: Some(
                    serde_json::json!({
                        "target": "tests/data/valid.pem",
                        "days": 30
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
                task: None,
            })
            .await;

        std::env::remove_var("DCERT_PATH");

        assert!(result.is_ok(), "Tool call should succeed: {:?}", result);
        let response = result.unwrap();
        let text = response
            .content
            .first()
            .and_then(|c| c.raw.as_text())
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

        let server = DcertMcpServer::new();
        let server_handle = tokio::spawn(async move {
            let svc = server.serve(server_transport).await.unwrap();
            svc.waiting().await.unwrap();
        });

        #[derive(Clone, Default)]
        struct TestClient;
        impl ClientHandler for TestClient {}

        let client = TestClient.serve(client_transport).await.unwrap();

        let result = client
            .call_tool(CallToolRequestParams {
                meta: None,
                name: "compare_certificates".into(),
                arguments: Some(
                    serde_json::json!({
                        "target_a": "",
                        "target_b": "example.com"
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
                task: None,
            })
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_error.unwrap_or(false));
        let text = response
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.as_str())
            .unwrap_or("");
        assert!(
            text.contains("must not be empty"),
            "Error should mention empty target: {}",
            text
        );

        client.cancel().await.unwrap();
        server_handle.abort();
    }
}
