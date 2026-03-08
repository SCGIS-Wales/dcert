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

mod security;

/// Canonical description for dcert-mcp, consistent with the CLI.
const MCP_DESCRIPTION: &str =
    "MCP server for TLS certificate analysis, format conversion, and key verification — for AI-powered IDEs";

/// Return the version string from Cargo.toml.
fn dcert_mcp_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
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
struct McpCli {
    /// Subprocess timeout in seconds (max time for a single dcert invocation)
    #[arg(long, env = "DCERT_MCP_TIMEOUT", default_value_t = DEFAULT_SUBPROCESS_TIMEOUT)]
    timeout: u64,

    /// Connection timeout in seconds passed to the dcert subprocess (TCP connect timeout)
    #[arg(long, env = "DCERT_MCP_CONNECTION_TIMEOUT", default_value_t = DEFAULT_CONNECTION_TIMEOUT)]
    connection_timeout: u64,

    /// Read timeout in seconds passed to the dcert subprocess (time to wait for server response)
    #[arg(long, env = "DCERT_MCP_READ_TIMEOUT", default_value_t = DEFAULT_READ_TIMEOUT)]
    read_timeout: u64,

    /// Transport mode: "stdio" (default) or "http"
    #[arg(long, env = "DCERT_MCP_MODE", default_value = "stdio")]
    mode: String,

    /// HTTP bind address (only used in http mode)
    #[arg(long, env = "DCERT_MCP_ADDR", default_value = "0.0.0.0:3000")]
    addr: String,
}

/// Default maximum time allowed for a single dcert subprocess invocation.
const DEFAULT_SUBPROCESS_TIMEOUT: u64 = 60;

/// Default TCP connection timeout (seconds) passed to the dcert subprocess via --timeout.
const DEFAULT_CONNECTION_TIMEOUT: u64 = 10;

/// Default read timeout (seconds) passed to the dcert subprocess via --read-timeout.
const DEFAULT_READ_TIMEOUT: u64 = 5;

/// Proxy environment info detected at MCP startup (for diagnostic logging).
#[derive(Debug)]
struct McpProxyInfo {
    https_proxy: Option<String>,
    http_proxy: Option<String>,
    no_proxy: Option<String>,
}

impl McpProxyInfo {
    /// Read proxy environment variables using the same precedence as the main dcert binary.
    fn from_env() -> Self {
        let https_proxy = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
            .iter()
            .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()));
        let http_proxy = ["HTTP_PROXY", "http_proxy"]
            .iter()
            .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()));
        let no_proxy = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .ok()
            .filter(|v| !v.is_empty());
        Self {
            https_proxy,
            http_proxy,
            no_proxy,
        }
    }
}

/// Runtime configuration for the dcert MCP server, resolved at startup.
#[derive(Debug)]
struct McpConfig {
    /// Subprocess timeout (default 60s, overridable via DCERT_MCP_TIMEOUT or --timeout).
    subprocess_timeout: Duration,
    /// TCP connection timeout in seconds passed to dcert subprocess via --timeout.
    connection_timeout: u64,
    /// Read timeout in seconds passed to dcert subprocess via --read-timeout.
    read_timeout: u64,
    /// Resolved path to the dcert binary.
    dcert_binary: PathBuf,
    /// Detected proxy configuration (for logging; env vars are inherited by subprocesses).
    proxy_config: McpProxyInfo,
}

/// Mask password in proxy URL for safe logging.
/// Note: This is identical to `debug::sanitize_url` in the main dcert binary.
/// The two binaries don't share a library crate, so the logic is duplicated here.
fn sanitize_proxy_url(url_str: &str) -> String {
    match url::Url::parse(url_str) {
        Ok(mut u) => {
            if u.password().is_some() {
                let _ = u.set_password(Some("****"));
            }
            u.to_string()
        }
        Err(_) => url_str.to_string(),
    }
}

/// Log MCP server startup diagnostics to stderr.
/// MCP servers communicate over stdio, so diagnostics go to stderr.
fn log_startup_diagnostics(config: &McpConfig) {
    eprintln!("[dcert-mcp] v{}", dcert_mcp_version());
    eprintln!("[dcert-mcp] dcert binary: {}", config.dcert_binary.display());
    eprintln!(
        "[dcert-mcp] subprocess timeout: {}s",
        config.subprocess_timeout.as_secs()
    );
    eprintln!(
        "[dcert-mcp] connection timeout: {}s (--timeout)",
        config.connection_timeout
    );
    eprintln!("[dcert-mcp] read timeout: {}s (--read-timeout)", config.read_timeout);

    match &config.proxy_config.https_proxy {
        Some(proxy) => eprintln!("[dcert-mcp] HTTPS proxy: {}", sanitize_proxy_url(proxy)),
        None => eprintln!("[dcert-mcp] HTTPS proxy: (none)"),
    }
    match &config.proxy_config.http_proxy {
        Some(proxy) => eprintln!("[dcert-mcp] HTTP proxy: {}", sanitize_proxy_url(proxy)),
        None => eprintln!("[dcert-mcp] HTTP proxy: (none)"),
    }
    match &config.proxy_config.no_proxy {
        Some(no_proxy) => eprintln!("[dcert-mcp] NO_PROXY: {}", no_proxy),
        None => eprintln!("[dcert-mcp] NO_PROXY: (none)"),
    }

    // Warn if dcert binary not found at resolved path
    if config.dcert_binary != std::path::Path::new("dcert") && !config.dcert_binary.exists() {
        eprintln!(
            "[dcert-mcp] WARNING: dcert binary not found at {}",
            config.dcert_binary.display()
        );
    }
}

/// Build a detailed timeout error message with diagnostic hints for corporate environments.
fn format_timeout_error(config: &McpConfig) -> String {
    let mut msg = format!(
        "dcert subprocess timed out after {}s.",
        config.subprocess_timeout.as_secs()
    );

    msg.push_str("\n\nPossible causes:");

    if config.proxy_config.https_proxy.is_some() {
        msg.push_str(&format!(
            "\n  - Forward proxy detected ({}). The proxy may be blocking or slow to respond.",
            sanitize_proxy_url(config.proxy_config.https_proxy.as_deref().unwrap_or(""))
        ));
        msg.push_str("\n  - Check that the target host is allowed through your proxy.");
        if let Some(ref no_proxy) = config.proxy_config.no_proxy {
            msg.push_str(&format!(
                "\n  - NO_PROXY is set to '{}'. Verify the target isn't incorrectly bypassed.",
                no_proxy
            ));
        }
    } else {
        msg.push_str("\n  - No proxy configured. If behind a corporate proxy, set HTTPS_PROXY.");
    }

    msg.push_str("\n  - DNS resolution may be slow or failing for the target host.");
    msg.push_str("\n  - The target host may be unreachable or its port may be filtered.");
    msg.push_str(&format!(
        "\n  - The connection timeout is {}s and read timeout is {}s.",
        config.connection_timeout, config.read_timeout
    ));

    msg.push_str("\n\nTo adjust timeouts:");
    msg.push_str(&format!(
        "\n  - Set DCERT_MCP_TIMEOUT to increase the subprocess timeout (current: {}s).",
        config.subprocess_timeout.as_secs()
    ));
    msg.push_str("\n  - Set DCERT_MCP_CONNECTION_TIMEOUT to increase the TCP connection timeout.");
    msg.push_str("\n  - Set DCERT_MCP_READ_TIMEOUT to increase the response read timeout.");

    msg
}

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
/// Passes `--timeout` and `--read-timeout` from the MCP config to the subprocess.
/// Enforces a subprocess timeout to prevent indefinite hangs from slow or unreachable targets.
/// Acquires a semaphore permit to limit concurrent subprocess invocations.
///
/// Note: The subprocess inherits all parent environment variables (we do NOT call
/// `.env_clear()` or `.env()` on the Command). This is required for proxy support —
/// HTTPS_PROXY, HTTP_PROXY, NO_PROXY, SSL_CERT_FILE, and SSL_CERT_DIR are forwarded
/// automatically to the dcert CLI subprocess.
async fn run_dcert(args: &[&str], config: &McpConfig) -> Result<(String, String, i32), String> {
    run_dcert_with_env(args, config, None).await
}

/// Run dcert with optional environment variables for passing secrets securely.
/// Secrets like cert_password are passed via env vars instead of CLI args to avoid
/// exposing them in process listings (ps aux, /proc/<pid>/cmdline).
async fn run_dcert_with_env(
    args: &[&str],
    config: &McpConfig,
    env_vars: Option<&[(&str, &str)]>,
) -> Result<(String, String, i32), String> {
    let _permit = SUBPROCESS_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| "Subprocess semaphore closed".to_string())?;

    // Only include --debug when explicitly enabled via DCERT_MCP_DEBUG env var
    let mut full_args: Vec<&str> = Vec::with_capacity(args.len() + 5);
    full_args.extend_from_slice(args);
    if std::env::var("DCERT_MCP_DEBUG").is_ok() && !full_args.contains(&"--debug") {
        full_args.push("--debug");
    }

    // Pass connection and read timeouts to the dcert subprocess
    let timeout_str = config.connection_timeout.to_string();
    let read_timeout_str = config.read_timeout.to_string();
    if !full_args.contains(&"--timeout") {
        full_args.push("--timeout");
        full_args.push(&timeout_str);
    }
    if !full_args.contains(&"--read-timeout") {
        full_args.push("--read-timeout");
        full_args.push(&read_timeout_str);
    }

    let mut cmd = Command::new(&config.dcert_binary);
    cmd.args(&full_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Set additional env vars (e.g., DCERT_CERT_PASSWORD for mTLS)
    if let Some(vars) = env_vars {
        for (key, value) in vars {
            cmd.env(key, value);
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to run dcert at {}: {}", config.dcert_binary.display(), e))?;

    run_child_with_timeout(&mut child, config).await
}

/// Run dcert without --debug and without --timeout/--read-timeout flags.
/// Used for subcommands (convert, verify-key) that don't support connection timeouts.
/// Acquires a semaphore permit to limit concurrent subprocess invocations.
///
/// Note: The subprocess inherits all parent environment variables including proxy
/// settings. See `run_dcert()` for details.
async fn run_dcert_raw(args: &[&str], config: &McpConfig) -> Result<(String, String, i32), String> {
    let _permit = SUBPROCESS_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| "Subprocess semaphore closed".to_string())?;

    let mut child = Command::new(&config.dcert_binary)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run dcert at {}: {}", config.dcert_binary.display(), e))?;

    run_child_with_timeout(&mut child, config).await
}

/// Wait for a child process with timeout, explicitly killing it on timeout
/// to prevent orphaned processes.
async fn run_child_with_timeout(
    child: &mut tokio::process::Child,
    config: &McpConfig,
) -> Result<(String, String, i32), String> {
    // Take the pipes so we can read them separately from waiting
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    // Wait for the child with a timeout
    match tokio::time::timeout(config.subprocess_timeout, child.wait()).await {
        Ok(result) => {
            let status = result.map_err(|e| format!("Failed waiting for dcert: {}", e))?;

            // Read pipes after the process has exited
            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();
            if let Some(ref mut pipe) = stdout_pipe {
                let _ = tokio::io::AsyncReadExt::read_to_end(pipe, &mut stdout_buf).await;
            }
            if let Some(ref mut pipe) = stderr_pipe {
                let _ = tokio::io::AsyncReadExt::read_to_end(pipe, &mut stderr_buf).await;
            }

            let stdout = truncate_output(String::from_utf8_lossy(&stdout_buf).to_string());
            let stderr = truncate_output(String::from_utf8_lossy(&stderr_buf).to_string());
            let code = status.code().unwrap_or(2);
            Ok((stdout, stderr, code))
        }
        Err(_) => {
            // Explicitly kill the child process on timeout to prevent orphaned processes
            let _ = child.kill().await;
            Err(format_timeout_error(config))
        }
    }
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
        // cert_password is passed via DCERT_CERT_PASSWORD env var (see run_dcert_with_env)
        // to avoid exposing it in process listings.
        if let Some(ref p) = self.ca_cert {
            args.push("--ca-cert".to_string());
            args.push(p.clone());
        }
        args
    }

    /// Returns env vars to set on the subprocess for secret parameters.
    fn env_vars(&self) -> Vec<(&str, &str)> {
        let mut vars = Vec::new();
        if let Some(ref p) = self.cert_password {
            vars.push(("DCERT_CERT_PASSWORD", p.as_str()));
        }
        vars
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

/// Parameters for the create_csr tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct CreateCsrParams {
    /// Common Name (CN) — typically the FQDN (e.g., "api.example.com")
    common_name: String,
    /// Organization name (O)
    #[serde(default)]
    organization: Option<String>,
    /// Organizational Unit(s) (OU) — supports metadata identifiers (e.g., "AppId:my-app-123").
    /// Note: OU is deprecated for publicly-trusted certificates since CA/B Forum Ballot SC47v2 (Sep 2022),
    /// but remains valid for internal/private PKI.
    #[serde(default)]
    organizational_units: Vec<String>,
    /// Two-letter ISO 3166-1 country code (e.g., "GB", "US")
    #[serde(default)]
    country: Option<String>,
    /// State or province name (ST)
    #[serde(default)]
    state: Option<String>,
    /// Locality or city name (L)
    #[serde(default)]
    locality: Option<String>,
    /// Email address for the certificate (rarely used in modern TLS)
    #[serde(default)]
    email: Option<String>,
    /// Subject Alternative Names in TYPE:VALUE format (e.g., "DNS:www.example.com", "IP:10.0.0.1").
    /// If empty, the CN is automatically added as a DNS SAN.
    #[serde(default)]
    subject_alternative_names: Vec<String>,
    /// Key algorithm: "rsa-4096" (default, strong), "rsa-2048" (minimum), "ecdsa-p256" (recommended, modern), "ecdsa-p384" (high-security), "ed25519" (modern EdDSA, compact signatures, requires OpenSSL 3.x)
    #[serde(default = "default_rsa_4096")]
    key_algorithm: String,
    /// Whether to encrypt the private key with AES-256-CBC (PKCS#8)
    #[serde(default)]
    encrypt_key: bool,
    /// Password for key encryption (required when encrypt_key is true)
    #[serde(default)]
    key_password: Option<String>,
    /// Output path for the CSR file
    csr_output_path: String,
    /// Output path for the private key file
    key_output_path: String,
}

/// Parameters for the validate_csr tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct ValidateCsrParams {
    /// Path to the PEM-encoded CSR file to validate
    csr_file: String,
    /// Strict mode: treat warnings as errors (e.g., OU deprecation, RSA 2048 key size)
    #[serde(default)]
    strict: bool,
}

/// Parameters for the validate_certificate tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct ValidateCertificateParams {
    /// HTTPS URL, hostname, or local path to a PEM file. Bare hostnames are auto-converted to https://
    target: String,
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    mtls: MtlsParams,
}

fn default_rsa_4096() -> String {
    "rsa-4096".to_string()
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
fn default_vault_mount() -> String {
    "vault_intermediate".to_string()
}
fn default_ttl() -> String {
    "8760h".to_string()
}
fn default_kv_version() -> u8 {
    1
}
fn default_cert_key_name() -> String {
    "cert".to_string()
}
fn default_key_key_name() -> String {
    "key".to_string()
}

// ---------------------------------------------------------------------------
// Vault MCP Parameters
// ---------------------------------------------------------------------------

/// Authentication and connection parameters shared across all Vault MCP tools.
///
/// ## Architecture: MCP client → dcert-mcp (MCP server) → Vault
///
/// The MCP server handles Vault authentication so that MCP clients (AI-powered IDEs)
/// don't need to manage Vault tokens. Three auth methods are supported:
///
/// 1. **Token** (default): Uses `vault_token` parameter, or inherits `VAULT_TOKEN`
///    env var / `~/.vault-token` file from the MCP server process.
///
/// 2. **LDAP**: The MCP server authenticates with Vault via
///    `POST /v1/auth/{ldap_mount}/login/{username}` and extracts a short-lived token.
///
/// 3. **AppRole**: The MCP server authenticates with Vault via
///    `POST /v1/auth/{approle_mount}/login` with `role_id` + `secret_id`.
///
/// The resulting token is passed to the `dcert vault` subprocess via the `VAULT_TOKEN`
/// env var. The `vault_addr` parameter is passed via `VAULT_ADDR`.
///
/// This design keeps the dcert CLI stateless (token-based only) while the MCP server
/// handles the auth handshake, which is the appropriate separation of concerns.
#[derive(Debug, Deserialize, JsonSchema, Default)]
struct VaultParams {
    /// Vault server address (e.g., "https://vault.example.com:8200").
    /// If omitted, inherits VAULT_ADDR from the MCP server environment.
    #[serde(default)]
    vault_addr: Option<String>,

    /// Vault token for authentication. If omitted, inherits from VAULT_TOKEN env var
    /// or ~/.vault-token file. Ignored when auth_method is "ldap" or "approle".
    #[serde(default)]
    vault_token: Option<String>,

    /// Authentication method: "token" (default), "ldap", or "approle"
    #[serde(default)]
    auth_method: Option<String>,

    /// LDAP username (required when auth_method is "ldap")
    #[serde(default)]
    ldap_username: Option<String>,

    /// LDAP password (required when auth_method is "ldap")
    #[serde(default)]
    ldap_password: Option<String>,

    /// LDAP auth mount point (default: "ldap")
    #[serde(default)]
    ldap_mount: Option<String>,

    /// AppRole role_id (required when auth_method is "approle")
    #[serde(default)]
    approle_role_id: Option<String>,

    /// AppRole secret_id (required when auth_method is "approle")
    #[serde(default)]
    approle_secret_id: Option<String>,

    /// AppRole auth mount point (default: "approle")
    #[serde(default)]
    approle_mount: Option<String>,

    /// Custom CA certificate PEM file for Vault TLS verification.
    /// Also reads VAULT_CACERT env var from the MCP server environment.
    #[serde(default)]
    vault_cacert: Option<String>,

    /// Skip TLS certificate verification for Vault (insecure).
    /// Also reads VAULT_SKIP_VERIFY env var from the MCP server environment.
    #[serde(default)]
    skip_verify: Option<bool>,
}

impl VaultParams {
    fn validate(&self) -> Result<(), String> {
        let method = self.auth_method.as_deref().unwrap_or("token");
        match method {
            "token" => {} // token is optional (falls back to env/file)
            "ldap" => {
                if self.ldap_username.is_none() {
                    return Err("ldap_username is required when auth_method is \"ldap\"".to_string());
                }
                if self.ldap_password.is_none() {
                    return Err("ldap_password is required when auth_method is \"ldap\"".to_string());
                }
                // vault_addr is required for LDAP auth (can't auth without knowing Vault URL)
                if self.vault_addr.is_none() && std::env::var("VAULT_ADDR").is_err() {
                    return Err(
                        "vault_addr is required for LDAP auth (or set VAULT_ADDR env var on the MCP server)"
                            .to_string(),
                    );
                }
            }
            "approle" => {
                if self.approle_role_id.is_none() {
                    return Err("approle_role_id is required when auth_method is \"approle\"".to_string());
                }
                if self.approle_secret_id.is_none() {
                    return Err("approle_secret_id is required when auth_method is \"approle\"".to_string());
                }
                if self.vault_addr.is_none() && std::env::var("VAULT_ADDR").is_err() {
                    return Err(
                        "vault_addr is required for AppRole auth (or set VAULT_ADDR env var on the MCP server)"
                            .to_string(),
                    );
                }
            }
            _ => {
                return Err(format!(
                    "Invalid auth_method '{}': must be \"token\", \"ldap\", or \"approle\"",
                    method
                ))
            }
        }
        if let Some(ref p) = self.vault_cacert {
            validate_path(p, "vault_cacert")?;
        }
        Ok(())
    }

    /// Resolve the Vault address from params or environment.
    fn resolve_addr(&self) -> Option<String> {
        self.vault_addr
            .clone()
            .or_else(|| std::env::var("VAULT_ADDR").ok())
            .map(|s| s.trim_end_matches('/').to_string())
    }
}

/// Authenticate with Vault using LDAP or AppRole and return a client token.
/// The MCP server performs the auth handshake so the dcert subprocess only needs a token.
async fn vault_authenticate(vault_params: &VaultParams) -> Result<String, String> {
    let method = vault_params.auth_method.as_deref().unwrap_or("token");
    let vault_addr = vault_params
        .resolve_addr()
        .ok_or_else(|| "vault_addr is required for authentication".to_string())?;

    let skip_verify = vault_params.skip_verify.unwrap_or(false)
        || std::env::var("VAULT_SKIP_VERIFY")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(skip_verify)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    match method {
        "ldap" => {
            use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
            let username = vault_params.ldap_username.as_deref().unwrap();
            let password = vault_params.ldap_password.as_deref().unwrap();
            let mount = vault_params.ldap_mount.as_deref().unwrap_or("ldap");
            let encoded_mount = utf8_percent_encode(mount, NON_ALPHANUMERIC).to_string();
            let encoded_username = utf8_percent_encode(username, NON_ALPHANUMERIC).to_string();
            let url = format!("{}/v1/auth/{}/login/{}", vault_addr, encoded_mount, encoded_username);

            let resp = client
                .post(&url)
                .json(&serde_json::json!({"password": password}))
                .send()
                .await
                .map_err(|e| format!("LDAP auth request failed: {}", e))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("LDAP auth failed (HTTP {}): {}", status, body));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse LDAP auth response: {}", e))?;

            json["auth"]["client_token"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| "LDAP auth response did not contain a client_token".to_string())
        }
        "approle" => {
            let role_id = vault_params.approle_role_id.as_deref().unwrap();
            let secret_id = vault_params.approle_secret_id.as_deref().unwrap();
            let mount = vault_params.approle_mount.as_deref().unwrap_or("approle");
            let url = format!("{}/v1/auth/{}/login", vault_addr, mount);

            let resp = client
                .post(&url)
                .json(&serde_json::json!({"role_id": role_id, "secret_id": secret_id}))
                .send()
                .await
                .map_err(|e| format!("AppRole auth request failed: {}", e))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("AppRole auth failed (HTTP {}): {}", status, body));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse AppRole auth response: {}", e))?;

            json["auth"]["client_token"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| "AppRole auth response did not contain a client_token".to_string())
        }
        _ => Err(format!("Unsupported auth method for authentication: {}", method)),
    }
}

/// Run dcert vault with vault-specific environment variables.
/// Resolves vault_addr, handles auth (LDAP/AppRole → token), and passes
/// configuration to the subprocess via env vars and CLI flags.
async fn run_dcert_vault(
    vault_args: &[&str],
    vault_params: &VaultParams,
    config: &McpConfig,
) -> Result<(String, String, i32), String> {
    let _permit = SUBPROCESS_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| "Subprocess semaphore closed".to_string())?;

    // Resolve vault token: explicit param → LDAP/AppRole auth → inherited from env
    let method = vault_params.auth_method.as_deref().unwrap_or("token");
    let resolved_token: Option<String> = match method {
        "ldap" | "approle" => Some(vault_authenticate(vault_params).await?),
        _ => vault_params.vault_token.clone(),
    };

    // Build CLI args: "vault" <subcommand> [flags] --format json
    let mut full_args: Vec<String> = vec!["vault".to_string()];
    // Add vault global flags before subcommand
    if vault_params.skip_verify == Some(true) {
        full_args.push("--skip-verify".to_string());
    }
    if let Some(ref cacert) = vault_params.vault_cacert {
        full_args.push("--vault-cacert".to_string());
        full_args.push(cacert.clone());
    }
    full_args.push("--debug".to_string());
    // Add subcommand-specific args
    for arg in vault_args {
        full_args.push(arg.to_string());
    }

    let mut cmd = Command::new(&config.dcert_binary);
    let args_refs: Vec<&str> = full_args.iter().map(|s| s.as_str()).collect();
    cmd.args(&args_refs);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    // Set vault env vars on the subprocess
    if let Some(ref addr) = vault_params.resolve_addr() {
        cmd.env("VAULT_ADDR", addr);
    }
    if let Some(ref token) = resolved_token {
        cmd.env("VAULT_TOKEN", token);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to run dcert at {}: {}", config.dcert_binary.display(), e))?;

    run_child_with_timeout(&mut child, config).await
}

// ---------------------------------------------------------------------------
// Vault MCP Tool Parameter Types
// ---------------------------------------------------------------------------

/// Parameters for the vault_issue tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct VaultIssueParams {
    /// Common Name (CN) for the certificate (e.g., "api.example.com")
    common_name: String,
    /// Subject Alternative Names (e.g., ["DNS:*.example.com", "DNS:api.example.com"])
    #[serde(default)]
    sans: Vec<String>,
    /// IP Subject Alternative Names (e.g., ["10.0.0.1", "192.168.1.1"])
    #[serde(default)]
    ip_sans: Vec<String>,
    /// Certificate TTL (e.g., "8760h" for 1 year, "720h" for 30 days)
    #[serde(default = "default_ttl")]
    ttl: String,
    /// Vault PKI role name. If omitted, dcert infers from token policies.
    #[serde(default)]
    role: Option<String>,
    /// Vault PKI mount point (default: "vault_intermediate")
    #[serde(default = "default_vault_mount")]
    mount: String,
    /// Output file base name (without extension). Defaults to sanitised CN.
    #[serde(default)]
    output: Option<String>,
    /// PFX password — if provided, output is PKCS12/PFX instead of PEM
    #[serde(default)]
    pfx_password: Option<String>,
    /// Store cert and key in Vault KV at this path after issuance
    #[serde(default)]
    store_path: Option<String>,
    /// Vault KV version (1 or 2) for --store-path
    #[serde(default = "default_kv_version")]
    kv_version: u8,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    vault: VaultParams,
}

/// Parameters for the vault_sign tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct VaultSignParams {
    /// Path to CSR PEM file to sign
    csr_file: String,
    /// Common Name override (defaults to CN from CSR)
    #[serde(default)]
    common_name: Option<String>,
    /// Subject Alternative Names
    #[serde(default)]
    sans: Vec<String>,
    /// IP Subject Alternative Names
    #[serde(default)]
    ip_sans: Vec<String>,
    /// Certificate TTL
    #[serde(default = "default_ttl")]
    ttl: String,
    /// Vault PKI role name
    #[serde(default)]
    role: Option<String>,
    /// Vault PKI mount point
    #[serde(default = "default_vault_mount")]
    mount: String,
    /// Output file base name
    #[serde(default)]
    output: Option<String>,
    /// Store cert in Vault KV at this path after signing
    #[serde(default)]
    store_path: Option<String>,
    /// Vault KV version (1 or 2) for --store-path
    #[serde(default = "default_kv_version")]
    kv_version: u8,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    vault: VaultParams,
}

/// Parameters for the vault_revoke tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct VaultRevokeParams {
    /// Certificate serial number (colon or hyphen-separated hex)
    #[serde(default)]
    serial: Option<String>,
    /// PEM certificate file path to revoke (alternative to serial)
    #[serde(default)]
    cert_file: Option<String>,
    /// Vault PKI mount point
    #[serde(default = "default_vault_mount")]
    mount: String,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    vault: VaultParams,
}

/// Parameters for the vault_list tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct VaultListParams {
    /// Vault PKI mount point
    #[serde(default = "default_vault_mount")]
    mount: String,
    /// Fetch and display details for each certificate (slower for large lists)
    #[serde(default)]
    show_details: bool,
    /// Show only expired certificates
    #[serde(default)]
    expired_only: bool,
    /// Show only valid (non-expired) certificates
    #[serde(default)]
    valid_only: bool,
    /// Export results to a file (JSON, CSV, or XLSX based on extension)
    #[serde(default)]
    export: Option<String>,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    vault: VaultParams,
}

/// Parameters for the vault_store tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct VaultStoreParams {
    /// Local PEM certificate file to store
    cert_file: String,
    /// Local PEM private key file to store
    key_file: String,
    /// Vault KV path (e.g., "secret/certs/my-cert")
    path: String,
    /// Key name for the certificate in Vault KV
    #[serde(default = "default_cert_key_name")]
    cert_key: String,
    /// Key name for the private key in Vault KV
    #[serde(default = "default_key_key_name")]
    key_key: String,
    /// Vault KV version (1 or 2)
    #[serde(default = "default_kv_version")]
    kv_version: u8,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    vault: VaultParams,
}

/// Parameters for the vault_validate tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct VaultValidateParams {
    /// Vault KV path to read certificate from
    path: String,
    /// Key name for the certificate in Vault KV
    #[serde(default = "default_cert_key_name")]
    cert_key: String,
    /// Key name for the private key in Vault KV
    #[serde(default = "default_key_key_name")]
    key_key: String,
    /// Vault KV version (1 or 2)
    #[serde(default = "default_kv_version")]
    kv_version: u8,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    vault: VaultParams,
}

/// Parameters for the vault_renew tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct VaultRenewParams {
    /// Vault KV path containing the existing certificate to renew
    path: String,
    /// Vault PKI role name for issuing the new certificate
    #[serde(default)]
    role: Option<String>,
    /// Vault PKI mount point
    #[serde(default = "default_vault_mount")]
    mount: String,
    /// TTL for the new certificate
    #[serde(default = "default_ttl")]
    ttl: String,
    /// Key name for the certificate in Vault KV
    #[serde(default = "default_cert_key_name")]
    cert_key: String,
    /// Key name for the private key in Vault KV
    #[serde(default = "default_key_key_name")]
    key_key: String,
    /// Vault KV version (1 or 2)
    #[serde(default = "default_kv_version")]
    kv_version: u8,
    /// Additional Subject Alternative Names (override existing SANs if provided)
    #[serde(default)]
    sans: Vec<String>,
    /// Additional IP Subject Alternative Names
    #[serde(default)]
    ip_sans: Vec<String>,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    vault: VaultParams,
}

/// Validate that a key algorithm string is one of the accepted values.
fn validate_key_algorithm(algo: &str) -> Result<(), String> {
    match algo {
        "rsa-4096" | "rsa-2048" | "ecdsa-p256" | "ecdsa-p384" | "ed25519" => Ok(()),
        _ => Err(format!(
            "Invalid key algorithm '{}': must be one of \"rsa-4096\", \"rsa-2048\", \"ecdsa-p256\", \"ecdsa-p384\", \"ed25519\"",
            algo
        )),
    }
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
    config: Arc<McpConfig>,
}

impl DcertMcpServer {
    /// Create a new dcert MCP server with the given configuration.
    fn new(config: McpConfig) -> Self {
        Self {
            tool_router: Self::tool_router(),
            config: Arc::new(config),
        }
    }
}

impl Default for DcertMcpServer {
    fn default() -> Self {
        Self::new(McpConfig {
            subprocess_timeout: Duration::from_secs(DEFAULT_SUBPROCESS_TIMEOUT),
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            dcert_binary: find_dcert_binary(),
            proxy_config: McpProxyInfo::from_env(),
        })
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
        let mtls_env = params.mtls.env_vars();
        let env_refs = mtls_env.to_vec();

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
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
        let mtls_env = params.mtls.env_vars();
        let env_refs = mtls_env.to_vec();

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
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
        let mtls_env = params.mtls.env_vars();
        let env_refs = mtls_env.to_vec();

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
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

        let (result_a, result_b) = tokio::join!(run_dcert(&args_a, &self.config), run_dcert(&args_b, &self.config));

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
        let mtls_env = params.mtls.env_vars();
        let env_refs = mtls_env.to_vec();

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
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
        let mtls_env = params.mtls.env_vars();
        let env_refs = mtls_env.to_vec();

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
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

        match run_dcert_raw(&args, &self.config).await {
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

        match run_dcert_raw(&args, &self.config).await {
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
        match run_dcert_raw(&args_refs, &self.config).await {
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

        match run_dcert_raw(&args, &self.config).await {
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

    /// Create a new Certificate Signing Request (CSR) with a private key.
    #[tool(
        description = "Create a PKCS#10 Certificate Signing Request (CSR) and private key. Supports RSA 4096 (default), RSA 2048, ECDSA P-256 (recommended modern), ECDSA P-384, and Ed25519 (modern EdDSA). Compliant with CA/B Forum Baseline Requirements, DigiCert, and X9 standards. OU fields can encode metadata identifiers (e.g., AppId:my-app-123) for internal PKI. Returns JSON with CSR details, key info, and file paths."
    )]
    pub async fn create_csr(
        &self,
        Parameters(params): Parameters<CreateCsrParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Validate inputs
        if params.common_name.trim().is_empty() {
            return ok_error("common_name must not be empty".to_string());
        }
        if params.common_name.len() > 64 {
            return ok_error("common_name must not exceed 64 characters (X.520 limit)".to_string());
        }
        if let Err(e) = validate_key_algorithm(&params.key_algorithm) {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.csr_output_path, "csr_output_path") {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.key_output_path, "key_output_path") {
            return ok_error(e);
        }
        if params.encrypt_key && params.key_password.is_none() {
            return ok_error("key_password is required when encrypt_key is true".to_string());
        }
        if let Some(ref pw) = params.key_password {
            if let Err(e) = validate_password(pw) {
                return ok_error(e);
            }
        }
        if let Some(ref country) = params.country {
            if country.len() != 2 || !country.chars().all(|c| c.is_ascii_uppercase()) {
                return ok_error(format!(
                    "country must be a 2-letter ISO 3166-1 alpha-2 code (e.g., 'GB', 'US'), got '{}'",
                    country
                ));
            }
        }
        if params.subject_alternative_names.len() > 100 {
            return ok_error("subject_alternative_names must not exceed 100 entries".to_string());
        }

        let mut args: Vec<String> = vec![
            "csr".to_string(),
            "create".to_string(),
            "--cn".to_string(),
            params.common_name.clone(),
            "--key-algo".to_string(),
            params.key_algorithm,
            "--csr-out".to_string(),
            params.csr_output_path,
            "--key-out".to_string(),
            params.key_output_path,
            "--format".to_string(),
            "json".to_string(),
        ];
        if let Some(org) = params.organization {
            args.push("--org".to_string());
            args.push(org);
        }
        for ou in params.organizational_units {
            args.push("--ou".to_string());
            args.push(ou);
        }
        if let Some(country) = params.country {
            args.push("--country".to_string());
            args.push(country);
        }
        if let Some(state) = params.state {
            args.push("--state".to_string());
            args.push(state);
        }
        if let Some(locality) = params.locality {
            args.push("--locality".to_string());
            args.push(locality);
        }
        if let Some(email) = params.email {
            args.push("--email".to_string());
            args.push(email);
        }
        for san in params.subject_alternative_names {
            args.push("--san".to_string());
            args.push(san);
        }
        if params.encrypt_key {
            args.push("--encrypt-key".to_string());
            if let Some(pw) = params.key_password {
                args.push("--key-password".to_string());
                args.push(pw);
            }
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_raw(&args_refs, &self.config).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- notes ---\n");
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

    /// Validate a PEM-encoded CSR for compliance with industry standards.
    #[tool(
        description = "Validate a PEM-encoded Certificate Signing Request (CSR) for compliance with CA/B Forum Baseline Requirements, DigiCert, and X9 standards. Checks key algorithm/size, signature algorithm, SAN presence, OU deprecation, country code format, and more. Returns JSON with subject info, key details, SANs, compliance findings (error/warning/info), and overall compliant/non-compliant status."
    )]
    pub async fn validate_csr(
        &self,
        Parameters(params): Parameters<ValidateCsrParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_path(&params.csr_file, "csr_file") {
            return ok_error(e);
        }

        let mut args: Vec<String> = vec![
            "csr".to_string(),
            "validate".to_string(),
            params.csr_file,
            "--format".to_string(),
            "json".to_string(),
        ];
        if params.strict {
            args.push("--strict".to_string());
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_raw(&args_refs, &self.config).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- notes ---\n");
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

    /// Validate TLS certificates against industry standards and report compliance status.
    #[tool(
        description = "Validate TLS certificates from an HTTPS endpoint or PEM file against CA/B Forum Baseline Requirements, DigiCert, and X9 standards. Checks key size, signature algorithm (SHA-1/MD5 rejection), SAN presence, certificate validity period (398-day max), Certificate Transparency (SCT presence), Extended Key Usage, and CA constraints. Returns JSON with per-certificate findings (error/warning/info) and overall COMPLIANT/NON-COMPLIANT status. Supports mTLS."
    )]
    pub async fn validate_certificate(
        &self,
        Parameters(params): Parameters<ValidateCertificateParams>,
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
            "--compliance".to_string(),
        ];
        args.extend(params.mtls.to_args());
        let mtls_env = params.mtls.env_vars();
        let env_refs = mtls_env.to_vec();

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
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
        match run_dcert_raw(&args_refs, &self.config).await {
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

    // ===================================================================
    // Vault PKI Tools
    // ===================================================================

    /// Issue a new TLS certificate from HashiCorp Vault PKI.
    #[tool(
        description = "Issue a new TLS certificate from HashiCorp Vault PKI. Generates a private key and certificate signed by the Vault PKI CA. Supports DNS and IP SANs, configurable TTL, PEM or PFX output, and optional KV storage. Requires Vault connectivity (vault_addr + authentication). Supports token, LDAP, and AppRole auth methods."
    )]
    pub async fn vault_issue(
        &self,
        Parameters(params): Parameters<VaultIssueParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if params.common_name.trim().is_empty() {
            return ok_error("common_name must not be empty".to_string());
        }

        let mut args: Vec<String> = vec![
            "issue".to_string(),
            "--cn".to_string(),
            params.common_name.clone(),
            "--mount".to_string(),
            params.mount,
            "--ttl".to_string(),
            params.ttl,
            "--format".to_string(),
            "json".to_string(),
        ];
        if let Some(ref role) = params.role {
            args.push("--role".to_string());
            args.push(role.clone());
        }
        for san in &params.sans {
            args.push("--san".to_string());
            args.push(san.clone());
        }
        for ip in &params.ip_sans {
            args.push("--ip-san".to_string());
            args.push(ip.clone());
        }
        if let Some(ref output) = params.output {
            args.push("--output".to_string());
            args.push(output.clone());
        }
        if let Some(ref pfx_pw) = params.pfx_password {
            args.push("--pfx-password".to_string());
            args.push(pfx_pw.clone());
        }
        if let Some(ref store_path) = params.store_path {
            args.push("--store-path".to_string());
            args.push(store_path.clone());
            args.push("--kv-version".to_string());
            args.push(params.kv_version.to_string());
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_vault(&args_refs, &params.vault, &self.config).await {
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

    /// Sign a Certificate Signing Request (CSR) using Vault PKI.
    #[tool(
        description = "Sign a Certificate Signing Request (CSR) using HashiCorp Vault PKI. Takes a PEM-encoded CSR file and returns a signed certificate with the full CA chain. Supports CN override, SANs, and optional KV storage. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods."
    )]
    pub async fn vault_sign(
        &self,
        Parameters(params): Parameters<VaultSignParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.csr_file, "csr_file") {
            return ok_error(e);
        }

        let mut args: Vec<String> = vec![
            "sign".to_string(),
            "--csr-file".to_string(),
            params.csr_file,
            "--mount".to_string(),
            params.mount,
            "--ttl".to_string(),
            params.ttl,
            "--format".to_string(),
            "json".to_string(),
        ];
        if let Some(ref role) = params.role {
            args.push("--role".to_string());
            args.push(role.clone());
        }
        if let Some(ref cn) = params.common_name {
            args.push("--cn".to_string());
            args.push(cn.clone());
        }
        for san in &params.sans {
            args.push("--san".to_string());
            args.push(san.clone());
        }
        for ip in &params.ip_sans {
            args.push("--ip-san".to_string());
            args.push(ip.clone());
        }
        if let Some(ref output) = params.output {
            args.push("--output".to_string());
            args.push(output.clone());
        }
        if let Some(ref store_path) = params.store_path {
            args.push("--store-path".to_string());
            args.push(store_path.clone());
            args.push("--kv-version".to_string());
            args.push(params.kv_version.to_string());
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_vault(&args_refs, &params.vault, &self.config).await {
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

    /// Revoke a certificate in Vault PKI by serial number or PEM file.
    #[tool(
        description = "Revoke a TLS certificate in HashiCorp Vault PKI. Specify either the serial number (hex) or a PEM certificate file path. The certificate is added to the CRL. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods."
    )]
    pub async fn vault_revoke(
        &self,
        Parameters(params): Parameters<VaultRevokeParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if params.serial.is_none() && params.cert_file.is_none() {
            return ok_error("Either serial or cert_file must be provided".to_string());
        }

        let mut args: Vec<String> = vec!["revoke".to_string(), "--mount".to_string(), params.mount];
        if let Some(ref serial) = params.serial {
            args.push("--serial".to_string());
            args.push(serial.clone());
        }
        if let Some(ref cert) = params.cert_file {
            if let Err(e) = validate_path(cert, "cert_file") {
                return ok_error(e);
            }
            args.push("--cert-file".to_string());
            args.push(cert.clone());
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_vault(&args_refs, &params.vault, &self.config).await {
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

    /// List all certificates issued by Vault PKI.
    #[tool(
        description = "List all certificates issued by HashiCorp Vault PKI with optional filtering by expired/valid status. Supports export to JSON, CSV, or XLSX files. Returns serial numbers, common names, expiry dates, and status. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods."
    )]
    pub async fn vault_list(
        &self,
        Parameters(params): Parameters<VaultListParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }

        let mut args: Vec<String> = vec![
            "list".to_string(),
            "--mount".to_string(),
            params.mount,
            "--format".to_string(),
            "json".to_string(),
        ];
        if params.show_details {
            args.push("--show-details".to_string());
        }
        if params.expired_only {
            args.push("--expired-only".to_string());
        }
        if params.valid_only {
            args.push("--valid-only".to_string());
        }
        if let Some(ref export) = params.export {
            if let Err(e) = validate_path(export, "export") {
                return ok_error(e);
            }
            args.push("--export".to_string());
            args.push(export.clone());
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_vault(&args_refs, &params.vault, &self.config).await {
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

    /// Store a local certificate and private key in Vault KV.
    #[tool(
        description = "Store a local PEM certificate and private key in HashiCorp Vault KV secret store. Supports KV v1 and v2. Configurable key names for the certificate and private key within the secret. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods."
    )]
    pub async fn vault_store(
        &self,
        Parameters(params): Parameters<VaultStoreParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.cert_file, "cert_file") {
            return ok_error(e);
        }
        if let Err(e) = validate_path(&params.key_file, "key_file") {
            return ok_error(e);
        }

        let kv_version_str = params.kv_version.to_string();
        let args: Vec<&str> = vec![
            "store",
            "--cert-file",
            &params.cert_file,
            "--key-file",
            &params.key_file,
            &params.path,
            "--cert-key",
            &params.cert_key,
            "--key-key",
            &params.key_key,
            "--kv-version",
            &kv_version_str,
        ];

        match run_dcert_vault(&args, &params.vault, &self.config).await {
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

    /// Read and validate a certificate stored in Vault KV.
    #[tool(
        description = "Read and validate a TLS certificate stored in HashiCorp Vault KV. Checks expiry, key match, and displays certificate details. Supports KV v1 and v2. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods."
    )]
    pub async fn vault_validate(
        &self,
        Parameters(params): Parameters<VaultValidateParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }

        let kv_version_str = params.kv_version.to_string();
        let args: Vec<&str> = vec![
            "validate",
            &params.path,
            "--cert-key",
            &params.cert_key,
            "--key-key",
            &params.key_key,
            "--kv-version",
            &kv_version_str,
        ];

        match run_dcert_vault(&args, &params.vault, &self.config).await {
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

    /// Renew an existing certificate in Vault KV by re-issuing from Vault PKI.
    #[tool(
        description = "Renew a TLS certificate stored in HashiCorp Vault KV by re-issuing from Vault PKI. Reads the existing cert to preserve CN and SANs, issues a new cert with a fresh TTL, and updates the KV secret. Optionally override SANs. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods."
    )]
    pub async fn vault_renew(
        &self,
        Parameters(params): Parameters<VaultRenewParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }

        let kv_version_str = params.kv_version.to_string();
        let mut args: Vec<String> = vec![
            "renew".to_string(),
            params.path,
            "--mount".to_string(),
            params.mount,
            "--ttl".to_string(),
            params.ttl,
            "--cert-key".to_string(),
            params.cert_key,
            "--key-key".to_string(),
            params.key_key,
            "--kv-version".to_string(),
            kv_version_str,
        ];
        if let Some(ref role) = params.role {
            args.push("--role".to_string());
            args.push(role.clone());
        }
        for san in &params.sans {
            args.push("--san".to_string());
            args.push(san.clone());
        }
        for ip in &params.ip_sans {
            args.push("--ip-san".to_string());
            args.push(ip.clone());
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match run_dcert_vault(&args_refs, &params.vault, &self.config).await {
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
    let cli = McpCli::parse();

    let config = McpConfig {
        subprocess_timeout: Duration::from_secs(cli.timeout),
        connection_timeout: cli.connection_timeout,
        read_timeout: cli.read_timeout,
        dcert_binary: find_dcert_binary(),
        proxy_config: McpProxyInfo::from_env(),
    };

    match cli.mode.as_str() {
        "http" => run_http_mode(config, &cli.addr).await,
        _ => run_stdio_mode(config).await,
    }
}

/// Run in stdio mode (default, unchanged behavior).
async fn run_stdio_mode(config: McpConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Log startup diagnostics to stderr (MCP protocol uses stdio)
    log_startup_diagnostics(&config);

    let server = DcertMcpServer::new(config);
    let service = server.serve(rmcp::transport::io::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// Shared state for HTTP mode handlers.
struct HttpAppState {
    mcp_server: DcertMcpServer,
}

/// Run in HTTP mode with OIDC/OAuth2 authentication.
async fn run_http_mode(config: McpConfig, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    use axum::routing::{get, post};
    use security::audit::AuditLogger;
    use security::middleware::{auth_middleware, AuthState};
    use security::session::{SessionCache, SessionConfig};
    use tower_http::cors::CorsLayer;

    // Initialize structured logging for HTTP mode.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .json()
        .init();

    log_startup_diagnostics(&config);

    // Build auth state from environment variables.
    let oidc_validator = build_oidc_validator();
    let static_token = std::env::var("DCERT_MCP_AUTH_TOKEN").ok().filter(|s| !s.is_empty());

    // Log auth status.
    if oidc_validator.is_some() {
        tracing::info!("authentication: OIDC/OAuth2 enabled");
    } else if static_token.is_some() {
        tracing::info!("authentication: static bearer token enabled");
    } else {
        tracing::warn!("authentication: DISABLED — no OIDC issuer or static token configured");
    }

    // Session cache.
    let session_ttl = std::env::var("DCERT_MCP_SESSION_TTL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);
    let session_cache = Arc::new(SessionCache::new(SessionConfig {
        inactivity_ttl: Duration::from_secs(session_ttl),
        ..SessionConfig::default()
    }));

    let audit_logger = Arc::new(AuditLogger::new());

    let auth_state = Arc::new(AuthState {
        oidc_validator: oidc_validator.map(Arc::new),
        static_token,
        session_cache: Some(session_cache),
        audit_logger: Some(audit_logger),
    });

    let mcp_server = DcertMcpServer::new(config);

    let app_state = Arc::new(HttpAppState { mcp_server });

    // Create axum router with auth middleware.
    let app = axum::Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", post(mcp_handler))
        .layer(CorsLayer::permissive())
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_middleware))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = addr, "dcert-mcp HTTP server listening");

    axum::serve(listener, app).await?;
    Ok(())
}

/// Build OIDC validator from environment variables (if configured).
fn build_oidc_validator() -> Option<security::oidc::OidcValidator> {
    let issuer = std::env::var("DCERT_MCP_OIDC_ISSUER").ok().filter(|s| !s.is_empty())?;
    let audience = std::env::var("DCERT_MCP_OIDC_AUDIENCE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    if audience.is_empty() {
        eprintln!("[dcert-mcp] WARNING: DCERT_MCP_OIDC_ISSUER set but DCERT_MCP_OIDC_AUDIENCE missing");
        return None;
    }

    let config = security::oidc::OidcConfig {
        issuer_url: issuer,
        audience,
        jwks_url: std::env::var("DCERT_MCP_OIDC_JWKS_URL").ok().filter(|s| !s.is_empty()),
        required_scopes: std::env::var("DCERT_MCP_REQUIRED_SCOPES")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        required_roles: std::env::var("DCERT_MCP_REQUIRED_ROLES")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        allowed_client_ids: std::env::var("DCERT_MCP_ALLOWED_CLIENTS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
    };

    match security::oidc::OidcValidator::new(config) {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("[dcert-mcp] ERROR: failed to create OIDC validator: {e}");
            None
        }
    }
}

/// Health check endpoint.
async fn health_handler() -> &'static str {
    "ok"
}

/// MCP JSON-RPC handler for HTTP mode.
async fn mcp_handler(
    axum::extract::State(state): axum::extract::State<Arc<HttpAppState>>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> axum::response::Json<serde_json::Value> {
    let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = body.get("params").cloned().unwrap_or(serde_json::Value::Null);
    let id = body.get("id").cloned().unwrap_or(serde_json::Value::Null);

    match method {
        "tools/list" => {
            let tools = state.mcp_server.tool_router.list_all();
            let tool_list: Vec<serde_json::Value> = tools
                .into_iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema
                    })
                })
                .collect();
            axum::response::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": tool_list }
            }))
        }
        "tools/call" => {
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Object(Default::default()));

            // Run the dcert binary directly for tool calls.
            let result = dispatch_tool_call(&state.mcp_server.config, &tool_name, &arguments).await;

            axum::response::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{"type": "text", "text": result}],
                    "isError": false
                }
            }))
        }
        "initialize" => axum::response::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "dcert-mcp",
                    "version": dcert_mcp_version()
                }
            }
        })),
        _ => axum::response::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("method not found: {method}")
            }
        })),
    }
}

/// Dispatch a tool call by running the dcert binary with appropriate arguments.
async fn dispatch_tool_call(config: &McpConfig, tool_name: &str, arguments: &serde_json::Value) -> String {
    // Map tool names to dcert CLI arguments.
    let mut args: Vec<String> = Vec::new();

    match tool_name {
        "analyze_certificate" => {
            if let Some(target) = arguments.get("target").and_then(|v| v.as_str()) {
                args.push(target.to_string());
            }
            args.extend(["--format".to_string(), "json".to_string()]);
            if arguments.get("fingerprint").and_then(|v| v.as_bool()) == Some(true) {
                args.push("--fingerprint".to_string());
            }
            if arguments.get("extensions").and_then(|v| v.as_bool()) == Some(true) {
                args.push("--extensions".to_string());
            }
            if arguments.get("check_revocation").and_then(|v| v.as_bool()) == Some(true) {
                args.push("--check-revocation".to_string());
            }
        }
        "validate_certificate" => {
            if let Some(target) = arguments.get("target").and_then(|v| v.as_str()) {
                args.push(target.to_string());
            }
            args.push("--compliance".to_string());
            args.extend(["--format".to_string(), "json".to_string()]);
        }
        _ => {
            return format!("unknown tool: {tool_name}");
        }
    }

    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match run_dcert(&args_refs, config).await {
        Ok((stdout, stderr, code)) => {
            let mut output = stdout;
            if !stderr.is_empty() {
                output.push_str("\n--- stderr ---\n");
                output.push_str(&stderr);
            }
            if code != 0 {
                output.push_str(&format!("\n--- exit code: {code} ---"));
            }
            output
        }
        Err(e) => format!("error: {e}"),
    }
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
            eprintln!("Skipping test: dcert binary not found at {:?}", dcert_path);
            return;
        }

        let config = test_config(dcert_path);
        let result = run_dcert(&["tests/data/valid.pem", "--format", "json"], &config).await;

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
            eprintln!("Skipping test: dcert binary not found at {:?}", dcert_path);
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
        let result = sanitize_proxy_url("http://user:secret@proxy.example.com:8080");
        assert!(result.contains("****"), "password should be masked");
        assert!(!result.contains("secret"), "original password should not appear");
    }

    #[test]
    fn test_sanitize_proxy_url_no_password() {
        let result = sanitize_proxy_url("http://proxy.example.com:8080");
        assert!(!result.contains("****"));
    }

    #[test]
    fn test_sanitize_proxy_url_invalid() {
        let result = sanitize_proxy_url("not-a-url");
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
        assert!(msg.contains("proxy"), "should mention proxy: {}", msg);
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
            "should hint to set HTTPS_PROXY: {}",
            msg
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
        let params = VaultParams {
            auth_method: Some("ldap".to_string()),
            ldap_password: Some("pass".to_string()),
            vault_addr: Some("https://vault.example.com:8200".to_string()),
            ..Default::default()
        };
        let err = params.validate().unwrap_err();
        assert!(
            err.contains("ldap_username"),
            "Error should mention ldap_username: {}",
            err
        );
    }

    #[test]
    fn test_vault_params_ldap_missing_password() {
        let params = VaultParams {
            auth_method: Some("ldap".to_string()),
            ldap_username: Some("user".to_string()),
            vault_addr: Some("https://vault.example.com:8200".to_string()),
            ..Default::default()
        };
        let err = params.validate().unwrap_err();
        assert!(
            err.contains("ldap_password"),
            "Error should mention ldap_password: {}",
            err
        );
    }

    #[test]
    fn test_vault_params_ldap_valid() {
        let params = VaultParams {
            auth_method: Some("ldap".to_string()),
            ldap_username: Some("user".to_string()),
            ldap_password: Some("pass".to_string()),
            vault_addr: Some("https://vault.example.com:8200".to_string()),
            ..Default::default()
        };
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_vault_params_approle_missing_role_id() {
        let params = VaultParams {
            auth_method: Some("approle".to_string()),
            approle_secret_id: Some("secret".to_string()),
            vault_addr: Some("https://vault.example.com:8200".to_string()),
            ..Default::default()
        };
        let err = params.validate().unwrap_err();
        assert!(
            err.contains("approle_role_id"),
            "Error should mention approle_role_id: {}",
            err
        );
    }

    #[test]
    fn test_vault_params_approle_missing_secret_id() {
        let params = VaultParams {
            auth_method: Some("approle".to_string()),
            approle_role_id: Some("role-id".to_string()),
            vault_addr: Some("https://vault.example.com:8200".to_string()),
            ..Default::default()
        };
        let err = params.validate().unwrap_err();
        assert!(
            err.contains("approle_secret_id"),
            "Error should mention approle_secret_id: {}",
            err
        );
    }

    #[test]
    fn test_vault_params_approle_valid() {
        let params = VaultParams {
            auth_method: Some("approle".to_string()),
            approle_role_id: Some("role-id".to_string()),
            approle_secret_id: Some("secret-id".to_string()),
            vault_addr: Some("https://vault.example.com:8200".to_string()),
            ..Default::default()
        };
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_vault_params_invalid_method() {
        let params = VaultParams {
            auth_method: Some("invalid".to_string()),
            ..Default::default()
        };
        let err = params.validate().unwrap_err();
        assert!(err.contains("Invalid auth_method"), "Error: {}", err);
    }

    #[test]
    fn test_vault_params_resolve_addr() {
        let params = VaultParams {
            vault_addr: Some("https://vault.example.com:8200/".to_string()),
            ..Default::default()
        };
        assert_eq!(
            params.resolve_addr(),
            Some("https://vault.example.com:8200".to_string())
        );
    }

    #[test]
    fn test_vault_params_resolve_addr_no_trailing_slash() {
        let params = VaultParams {
            vault_addr: Some("https://vault.example.com:8200".to_string()),
            ..Default::default()
        };
        assert_eq!(
            params.resolve_addr(),
            Some("https://vault.example.com:8200".to_string())
        );
    }
}
