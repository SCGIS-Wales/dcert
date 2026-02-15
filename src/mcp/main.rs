use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::PathBuf;
use tokio::process::Command;

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

/// Run dcert with given arguments and return (stdout, stderr, exit_code).
async fn run_dcert(args: &[&str]) -> Result<(String, String, i32), String> {
    let dcert = find_dcert_binary();
    let output = Command::new(&dcert)
        .args(args)
        .output()
        .await
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
            min_tls_owned = min.clone();
            args.push("--min-tls");
            args.push(&min_tls_owned);
        }
        if let Some(ref max) = params.max_tls {
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
impl ServerHandler for DcertMcpServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = DcertMcpServer::new();
    let service = server.serve(rmcp::transport::io::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
