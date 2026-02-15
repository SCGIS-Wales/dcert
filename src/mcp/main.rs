use clap::Parser;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Semaphore;

/// Canonical description for dcert-mcp, consistent with the CLI.
const MCP_DESCRIPTION: &str =
    "MCP server for TLS certificate analysis, format conversion, and key verification — for AI-powered IDEs";

/// Return the version string, preferring the git tag set by build.rs.
fn dcert_mcp_version() -> &'static str {
    match option_env!("DCERT_GIT_VERSION") {
        Some(git_ver) if git_ver.contains('.') => git_ver.strip_prefix('v').unwrap_or(git_ver),
        _ => env!("CARGO_PKG_VERSION"),
    }
}

/// Long version string: version + description, for `dcert-mcp --version`.
fn dcert_mcp_long_version() -> &'static str {
    use std::sync::OnceLock;
    static LONG_VER: OnceLock<String> = OnceLock::new();
    let s = LONG_VER.get_or_init(|| format!("{}\n{}", dcert_mcp_version(), MCP_DESCRIPTION));
    s.as_str()
}

/// dcert-mcp: MCP server for TLS certificate analysis.
#[derive(Parser, Debug)]
#[command(name = "dcert-mcp")]
#[command(about = MCP_DESCRIPTION)]
#[command(version = dcert_mcp_version())]
#[command(long_version = dcert_mcp_long_version())]
struct McpCli {}

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

/// Validate a file path parameter to prevent argument injection.
fn validate_path(path: &str, param_name: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{} must not be empty", param_name));
    }
    if path.starts_with('-') {
        return Err(format!("Invalid {}: '{}' must not start with '-'", param_name, path));
    }
    if path.contains('\0') {
        return Err(format!("{} must not contain null bytes", param_name));
    }
    Ok(())
}

/// Maximum number of certificate paths in a single truststore creation request.
const MAX_CERT_PATHS: usize = 100;

/// Maximum password length to prevent memory-based attacks.
const MAX_PASSWORD_LEN: usize = 1024;

/// Maximum subprocess output size (10 MB) to prevent memory exhaustion.
const MAX_OUTPUT_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of concurrent subprocess invocations.
/// Prevents resource exhaustion when many MCP tool calls arrive simultaneously.
const MAX_CONCURRENT_SUBPROCESSES: usize = 10;

/// Global semaphore for subprocess concurrency limiting.
static SUBPROCESS_SEMAPHORE: std::sync::LazyLock<Arc<Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_SUBPROCESSES)));

/// Validate a password parameter for reasonable length.
fn validate_password(password: &str) -> Result<(), String> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(format!(
            "Password too long ({} bytes, maximum is {})",
            password.len(),
            MAX_PASSWORD_LEN
        ));
    }
    if password.contains('\0') {
        return Err("Password must not contain null bytes".to_string());
    }
    Ok(())
}

/// Validate a keystore alias (alphanumeric, hyphens, underscores, dots; max 256 chars).
fn validate_alias(alias: &str) -> Result<(), String> {
    if alias.is_empty() {
        return Err("Alias must not be empty".to_string());
    }
    if alias.len() > 256 {
        return Err(format!("Alias too long ({} chars, maximum is 256)", alias.len()));
    }
    if !alias
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "Invalid alias '{}': must contain only alphanumeric characters, hyphens, underscores, or dots",
            alias
        ));
    }
    Ok(())
}

/// Truncate subprocess output if it exceeds the maximum allowed size.
fn truncate_output(output: String) -> String {
    if output.len() > MAX_OUTPUT_SIZE {
        let mut truncated = output[..MAX_OUTPUT_SIZE].to_string();
        truncated.push_str("\n--- output truncated (exceeded 10 MB limit) ---");
        truncated
    } else {
        output
    }
}

/// Run dcert with given arguments and return (stdout, stderr, exit_code).
///
/// Always passes `--debug` so MCP tool responses include diagnostic info.
/// Enforces a timeout to prevent indefinite hangs from slow or unreachable targets.
/// Acquires a semaphore permit to limit concurrent subprocess invocations.
async fn run_dcert(args: &[&str]) -> Result<(String, String, i32), String> {
    let _permit = SUBPROCESS_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| "Subprocess semaphore closed".to_string())?;

    let dcert = find_dcert_binary();

    // Always include --debug for richer diagnostic output
    let mut full_args: Vec<&str> = Vec::with_capacity(args.len() + 1);
    full_args.extend_from_slice(args);
    if !full_args.contains(&"--debug") {
        full_args.push("--debug");
    }

    let child = Command::new(&dcert)
        .args(&full_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run dcert at {}: {}", dcert.display(), e))?;

    let output = tokio::time::timeout(SUBPROCESS_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| format!("dcert subprocess timed out after {}s", SUBPROCESS_TIMEOUT.as_secs()))?
        .map_err(|e| format!("Failed to run dcert at {}: {}", dcert.display(), e))?;

    let stdout = truncate_output(String::from_utf8_lossy(&output.stdout).to_string());
    let stderr = truncate_output(String::from_utf8_lossy(&output.stderr).to_string());
    let code = output.status.code().unwrap_or(2);

    Ok((stdout, stderr, code))
}

/// Run dcert without --debug (for subcommands that don't support it).
/// Acquires a semaphore permit to limit concurrent subprocess invocations.
async fn run_dcert_raw(args: &[&str]) -> Result<(String, String, i32), String> {
    let _permit = SUBPROCESS_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| "Subprocess semaphore closed".to_string())?;

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

    let stdout = truncate_output(String::from_utf8_lossy(&output.stdout).to_string());
    let stderr = truncate_output(String::from_utf8_lossy(&output.stderr).to_string());
    let code = output.status.code().unwrap_or(2);

    Ok((stdout, stderr, code))
}

// -- Parameter types --

/// mTLS parameters shared across check-based tools.
#[derive(Debug, Deserialize, JsonSchema, Default)]
struct MtlsParams {
    /// Client certificate PEM file path for mutual TLS authentication
    #[serde(default)]
    client_cert: Option<String>,
    /// Client private key PEM file path for mutual TLS (must be used with client_cert)
    #[serde(default)]
    client_key: Option<String>,
    /// PKCS12/PFX file containing client cert + key (alternative to client_cert/client_key)
    #[serde(default)]
    pkcs12: Option<String>,
    /// Password for the PKCS12 file
    #[serde(default)]
    cert_password: Option<String>,
    /// Custom CA certificate bundle PEM file (overrides system CAs)
    #[serde(default)]
    ca_cert: Option<String>,
}

impl MtlsParams {
    fn validate(&self) -> Result<(), String> {
        // client_cert and client_key must both be set or both absent
        match (&self.client_cert, &self.client_key) {
            (Some(_), None) => return Err("client_cert requires client_key".to_string()),
            (None, Some(_)) => return Err("client_key requires client_cert".to_string()),
            _ => {}
        }
        // client_cert/client_key and pkcs12 are mutually exclusive
        if self.client_cert.is_some() && self.pkcs12.is_some() {
            return Err("client_cert/client_key and pkcs12 are mutually exclusive".to_string());
        }
        // Validate paths
        if let Some(ref p) = self.client_cert {
            validate_path(p, "client_cert")?;
        }
        if let Some(ref p) = self.client_key {
            validate_path(p, "client_key")?;
        }
        if let Some(ref p) = self.pkcs12 {
            validate_path(p, "pkcs12")?;
        }
        if let Some(ref p) = self.ca_cert {
            validate_path(p, "ca_cert")?;
        }
        Ok(())
    }

    fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(ref p) = self.client_cert {
            args.push("--client-cert".to_string());
            args.push(p.clone());
        }
        if let Some(ref p) = self.client_key {
            args.push("--client-key".to_string());
            args.push(p.clone());
        }
        if let Some(ref p) = self.pkcs12 {
            args.push("--pkcs12".to_string());
            args.push(p.clone());
        }
        if let Some(ref p) = self.cert_password {
            args.push("--cert-password".to_string());
            args.push(p.clone());
        }
        if let Some(ref p) = self.ca_cert {
            args.push("--ca-cert".to_string());
            args.push(p.clone());
        }
        args
    }
}

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
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    mtls: MtlsParams,
}

/// Parameters for the check_expiry tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct CheckExpiryParams {
    /// HTTPS URL, hostname, or local path to a PEM file. Bare hostnames are auto-converted to https://
    target: String,
    /// Warning threshold in days (default: 30)
    #[serde(default = "default_30")]
    days: u64,
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    mtls: MtlsParams,
}

/// Parameters for the check_revocation tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct CheckRevocationParams {
    /// HTTPS URL, hostname, or local path to a PEM file. Bare hostnames are auto-converted to https://
    target: String,
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    mtls: MtlsParams,
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
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    mtls: MtlsParams,
}

/// Parameters for the export_pem tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct ExportPemParams {
    /// HTTPS URL or hostname to fetch the TLS certificate chain from
    target: String,
    /// Output file path to write the PEM chain (default: writes to stdout in response)
    #[serde(default)]
    output_path: Option<String>,
    /// Exclude expired certificates from the exported chain (default: false)
    #[serde(default)]
    exclude_expired: bool,
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    mtls: MtlsParams,
}

/// Parameters for the verify_key_match tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct VerifyKeyMatchParams {
    /// PEM certificate file or HTTPS URL to verify against
    target: String,
    /// Private key PEM file path
    key_path: String,
}

/// Parameters for the convert_pfx_to_pem tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct ConvertPfxToPemParams {
    /// Input PKCS12/PFX file path
    pkcs12_path: String,
    /// Password for the PKCS12 file
    password: String,
    /// Output directory for PEM files (default: current directory)
    #[serde(default = "default_dot")]
    output_dir: String,
}

/// Parameters for the convert_pem_to_pfx tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct ConvertPemToPfxParams {
    /// PEM certificate file path
    cert_path: String,
    /// PEM private key file path
    key_path: String,
    /// Password for the output PKCS12 file
    password: String,
    /// Output PFX file path
    output_path: String,
    /// Optional CA certificate PEM file to include in the chain
    #[serde(default)]
    ca_path: Option<String>,
}

/// Parameters for the create_keystore tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct CreateKeystoreParams {
    /// PEM certificate file path (or chain)
    cert_path: String,
    /// PEM private key file path
    key_path: String,
    /// Password for the keystore
    password: String,
    /// Output PKCS12 keystore file path
    output_path: String,
    /// Alias for the key entry (default: "server")
    #[serde(default = "default_server")]
    alias: String,
}

/// Parameters for the create_truststore tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct CreateTruststoreParams {
    /// PEM file path(s) containing CA certificates to trust
    cert_paths: Vec<String>,
    /// Password for the truststore (default: "changeit")
    #[serde(default = "default_changeit")]
    password: String,
    /// Output PKCS12 truststore file path
    output_path: String,
}

fn default_true() -> bool {
    true
}
fn default_30() -> u64 {
    30
}
fn default_dot() -> String {
    ".".to_string()
}
fn default_server() -> String {
    "server".to_string()
}
fn default_changeit() -> String {
    "changeit".to_string()
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
        description = "Decode and analyze TLS certificates from an HTTPS endpoint or PEM file. Returns certificate details including subject, issuer, SANs, validity dates, fingerprints, extensions, TLS connection information, and OSI-layer diagnostics. Supports mTLS with client certificates and custom CA bundles."
    )]
    pub async fn analyze_certificate(
        &self,
        Parameters(params): Parameters<AnalyzeCertificateParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }
        if let Err(e) = params.mtls.validate() {
            return ok_error(e);
        }

        let mut args = vec![params.target.clone(), "--format".to_string(), "json".to_string()];
        if params.fingerprint {
            args.push("--fingerprint".to_string());
        }
        if params.extensions {
            args.push("--extensions".to_string());
        }
        if params.check_revocation {
            args.push("--check-revocation".to_string());
        }
        args.extend(params.mtls.to_args());

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert(&args_refs).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- debug/stderr ---\n");
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
        description = "Check if TLS certificates for a target expire within a specified number of days. Returns expiry status and warnings. Exit codes: 0=ok, 1=expiring soon, 4=already expired. Supports mTLS."
    )]
    pub async fn check_expiry(
        &self,
        Parameters(params): Parameters<CheckExpiryParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }
        if let Err(e) = params.mtls.validate() {
            return ok_error(e);
        }
        if params.days > 3650 {
            return ok_error(format!("days must be at most 3650 (10 years), got {}", params.days));
        }

        let days_str = params.days.to_string();
        let mut args = vec![
            params.target.clone(),
            "--format".to_string(),
            "json".to_string(),
            "--fingerprint".to_string(),
            "--expiry-warn".to_string(),
            days_str,
        ];
        args.extend(params.mtls.to_args());

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert(&args_refs).await {
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
        description = "Check the OCSP revocation status of TLS certificates. Queries the certificate's OCSP responder to determine if it has been revoked. Supports mTLS."
    )]
    pub async fn check_revocation(
        &self,
        Parameters(params): Parameters<CheckRevocationParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }
        if let Err(e) = params.mtls.validate() {
            return ok_error(e);
        }

        let mut args = vec![
            params.target.clone(),
            "--format".to_string(),
            "json".to_string(),
            "--check-revocation".to_string(),
            "--extensions".to_string(),
        ];
        args.extend(params.mtls.to_args());

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert(&args_refs).await {
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
        description = "Get TLS connection details for an HTTPS endpoint including protocol version, cipher suite, ALPN negotiation, DNS/TCP/TLS latency, verification status, and full OSI-layer diagnostics. Supports mTLS and custom CA bundles."
    )]
    pub async fn tls_connection_info(
        &self,
        Parameters(params): Parameters<TlsConnectionInfoParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }
        if let Err(e) = params.mtls.validate() {
            return ok_error(e);
        }

        let mut args = vec![
            params.target.clone(),
            "--format".to_string(),
            "json".to_string(),
            "--fingerprint".to_string(),
            "--extensions".to_string(),
        ];

        if let Some(ref min) = params.min_tls {
            if let Err(e) = validate_tls_version(min) {
                return ok_error(e);
            }
            args.push("--min-tls".to_string());
            args.push(min.clone());
        }
        if let Some(ref max) = params.max_tls {
            if let Err(e) = validate_tls_version(max) {
                return ok_error(e);
            }
            args.push("--max-tls".to_string());
            args.push(max.clone());
        }
        // Validate min_tls <= max_tls ordering
        if let (Some(ref min), Some(ref max)) = (&params.min_tls, &params.max_tls) {
            if min == "1.3" && max == "1.2" {
                return ok_error("min_tls (1.3) must not be greater than max_tls (1.2)".to_string());
            }
        }
        args.extend(params.mtls.to_args());

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert(&args_refs).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- debug/stderr ---\n");
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

    /// Export the PEM certificate chain from an HTTPS endpoint.
    #[tool(
        description = "Export the TLS certificate chain from an HTTPS endpoint as PEM text. Optionally saves to a file and can exclude expired certificates. Returns the PEM chain text. Supports mTLS and custom CA bundles."
    )]
    pub async fn export_pem(
        &self,
        Parameters(params): Parameters<ExportPemParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }
        if let Err(e) = params.mtls.validate() {
            return ok_error(e);
        }
        if let Some(ref p) = params.output_path {
            if let Err(e) = validate_path(p, "output_path") {
                return ok_error(e);
            }
        }

        let mut args = vec![params.target.clone(), "--format".to_string(), "json".to_string()];
        if let Some(ref output) = params.output_path {
            args.push("--export-pem".to_string());
            args.push(output.clone());
        }
        if params.exclude_expired {
            args.push("--exclude-expired".to_string());
        }
        args.extend(params.mtls.to_args());

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert(&args_refs).await {
            Ok((stdout, stderr, code)) => {
                let mut output = String::new();

                // If no output_path, extract PEM data from stderr debug output
                // or just return JSON with cert info. The user can also specify
                // an output_path to write to file.
                if params.output_path.is_some() {
                    output.push_str(&format!(
                        "PEM chain exported to: {}\n\n",
                        params.output_path.as_ref().unwrap()
                    ));
                }
                output.push_str(&stdout);
                if !stderr.is_empty() {
                    output.push_str("\n--- debug/stderr ---\n");
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

    /// Verify that a private key matches a certificate.
    #[tool(
        description = "Verify that a private key PEM file matches a certificate (PEM file or HTTPS endpoint). Returns match status, key type/size, and certificate subject. Useful for validating key-cert pairs before deployment."
    )]
    pub async fn verify_key_match(
        &self,
        Parameters(params): Parameters<VerifyKeyMatchParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.key_path, "key_path") {
            return ok_error(e);
        }

        let args = vec![
            "verify-key",
            params.target.as_str(),
            "--key",
            params.key_path.as_str(),
            "--format",
            "json",
        ];

        match run_dcert_raw(&args).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- stderr ---\n");
                    output.push_str(&stderr);
                }
                if code != 0 && code != 7 {
                    output.push_str(&format!("\n--- exit code: {} ---", code));
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }

    /// Convert a PKCS12/PFX file to PEM certificate and key files.
    #[tool(
        description = "Convert a PKCS12/PFX file to separate PEM files (cert.pem, key.pem, ca.pem). Extracts the certificate, private key, and any CA chain certificates."
    )]
    pub async fn convert_pfx_to_pem(
        &self,
        Parameters(params): Parameters<ConvertPfxToPemParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_path(&params.pkcs12_path, "pkcs12_path") {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.output_dir, "output_dir") {
            return ok_error(e);
        }
        if let Err(e) = validate_password(&params.password) {
            return ok_error(e);
        }

        let args = vec![
            "convert",
            "pfx-to-pem",
            params.pkcs12_path.as_str(),
            "--password",
            params.password.as_str(),
            "--output-dir",
            params.output_dir.as_str(),
        ];

        match run_dcert_raw(&args).await {
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

    /// Convert PEM certificate and key to a PKCS12/PFX file.
    #[tool(
        description = "Convert PEM certificate and private key files to a PKCS12/PFX file. Optionally includes CA chain certificates."
    )]
    pub async fn convert_pem_to_pfx(
        &self,
        Parameters(params): Parameters<ConvertPemToPfxParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_path(&params.cert_path, "cert_path") {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.key_path, "key_path") {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.output_path, "output_path") {
            return ok_error(e);
        }
        if let Err(e) = validate_password(&params.password) {
            return ok_error(e);
        }
        if let Some(ref ca) = params.ca_path {
            if let Err(e) = validate_path(ca, "ca_path") {
                return ok_error(e);
            }
        }

        let mut args = vec![
            "convert".to_string(),
            "pem-to-pfx".to_string(),
            "--cert".to_string(),
            params.cert_path,
            "--key".to_string(),
            params.key_path,
            "--output".to_string(),
            params.output_path,
            "--password".to_string(),
            params.password,
        ];
        if let Some(ca) = params.ca_path {
            args.push("--ca".to_string());
            args.push(ca);
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_raw(&args_refs).await {
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

    /// Create a PKCS12 keystore from a private key and certificate.
    #[tool(
        description = "Create a PKCS12 keystore from PEM certificate and private key files. Java-compatible since JDK 9 (PKCS12 is the default keystore type). Sets the key entry alias."
    )]
    pub async fn create_keystore(
        &self,
        Parameters(params): Parameters<CreateKeystoreParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_path(&params.cert_path, "cert_path") {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.key_path, "key_path") {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.output_path, "output_path") {
            return ok_error(e);
        }
        if let Err(e) = validate_password(&params.password) {
            return ok_error(e);
        }
        if let Err(e) = validate_alias(&params.alias) {
            return ok_error(e);
        }

        let args = vec![
            "convert",
            "create-keystore",
            "--cert",
            params.cert_path.as_str(),
            "--key",
            params.key_path.as_str(),
            "--output",
            params.output_path.as_str(),
            "--password",
            params.password.as_str(),
            "--alias",
            params.alias.as_str(),
        ];

        match run_dcert_raw(&args).await {
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

    /// Create a PKCS12 truststore from CA certificates.
    #[tool(
        description = "Create a PKCS12 truststore from CA certificate PEM files. Java-compatible since JDK 9. Bundles multiple CA certificates into a single truststore file."
    )]
    pub async fn create_truststore(
        &self,
        Parameters(params): Parameters<CreateTruststoreParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if params.cert_paths.is_empty() {
            return ok_error("cert_paths must contain at least one certificate file".to_string());
        }
        if params.cert_paths.len() > MAX_CERT_PATHS {
            return ok_error(format!(
                "cert_paths contains {} entries, maximum is {}",
                params.cert_paths.len(),
                MAX_CERT_PATHS
            ));
        }
        for path in &params.cert_paths {
            if let Err(e) = validate_path(path, "cert_paths") {
                return ok_error(e);
            }
        }
        if let Err(e) = validate_path(&params.output_path, "output_path") {
            return ok_error(e);
        }
        if let Err(e) = validate_password(&params.password) {
            return ok_error(e);
        }

        let mut args: Vec<String> = vec!["convert".to_string(), "create-truststore".to_string()];
        for path in &params.cert_paths {
            args.push(path.clone());
        }
        args.push("--output".to_string());
        args.push(params.output_path);
        args.push("--password".to_string());
        args.push(params.password);

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_raw(&args_refs).await {
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
                version: dcert_mcp_version().to_string(),
                title: Some("dcert MCP Server".to_string()),
                description: Some(MCP_DESCRIPTION.to_string()),
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
    // Parse CLI args so --version and --help work
    let _cli = McpCli::parse();

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

    /// Mutex to serialize tests that modify the DCERT_PATH env var,
    /// preventing race conditions when tests run in parallel.
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

    #[test]
    fn test_server_construction() {
        let server = DcertMcpServer::new();
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

    // ---------------------------------------------------------------
    // MCP tool: TLS version ordering rejection
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_mcp_tls_connection_rejects_inverted_tls_range() {
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
                        "min_tls": "1.3",
                        "max_tls": "1.2"
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
            text.contains("must not be greater than"),
            "Error should mention TLS version ordering: {}",
            text
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
                        "target": "example.com",
                        "days": 9999
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
            text.contains("at most 3650"),
            "Error should mention days limit: {}",
            text
        );

        client.cancel().await.unwrap();
        server_handle.abort();
    }
}
