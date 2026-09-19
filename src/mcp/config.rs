//! Runtime configuration, binary discovery and startup diagnostics.

use std::path::PathBuf;
use std::time::Duration;

use dcert::debug::sanitize_url;

/// Canonical description for dcert-mcp, consistent with the CLI.
pub(crate) const MCP_DESCRIPTION: &str =
    "MCP server for TLS certificate analysis, format conversion, and key verification — for AI-powered IDEs";

/// Return the version string from Cargo.toml.
pub(crate) fn dcert_mcp_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Long version string: version + description, for `dcert-mcp --version`.
pub(crate) fn dcert_mcp_long_version() -> &'static str {
    use std::sync::OnceLock;
    static LONG_VER: OnceLock<String> = OnceLock::new();
    let s = LONG_VER.get_or_init(|| format!("{}\n{}", dcert_mcp_version(), MCP_DESCRIPTION));
    s.as_str()
}

/// Default maximum time allowed for a single dcert subprocess invocation.
pub(crate) const DEFAULT_SUBPROCESS_TIMEOUT: u64 = 60;

/// Default TCP connection timeout (seconds) passed to the dcert subprocess via --timeout.
pub(crate) const DEFAULT_CONNECTION_TIMEOUT: u64 = 10;

/// Default read timeout (seconds) passed to the dcert subprocess via --read-timeout.
pub(crate) const DEFAULT_READ_TIMEOUT: u64 = 5;

/// Proxy environment info detected at MCP startup (for diagnostic logging).
#[derive(Debug)]
pub(crate) struct McpProxyInfo {
    pub(crate) https_proxy: Option<String>,
    pub(crate) http_proxy: Option<String>,
    pub(crate) no_proxy: Option<String>,
}

impl McpProxyInfo {
    /// Read proxy environment variables using the same precedence as the main dcert binary.
    pub(crate) fn from_env() -> Self {
        // DCERT_PROXY/DCERT_NOPROXY come first: they are what the per-tool
        // `proxy`/`noproxy` parameters set on the subprocess, and dcert itself
        // gives them precedence over the standard variables.
        let https_proxy = ["DCERT_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
            .iter()
            .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()));
        let http_proxy = ["DCERT_PROXY", "HTTP_PROXY", "http_proxy"]
            .iter()
            .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()));
        let no_proxy = std::env::var("DCERT_NOPROXY")
            .or_else(|_| std::env::var("NO_PROXY"))
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
pub(crate) struct McpConfig {
    /// Subprocess timeout (default 60s, overridable via DCERT_MCP_TIMEOUT or --timeout).
    pub(crate) subprocess_timeout: Duration,
    /// TCP connection timeout in seconds passed to dcert subprocess via --timeout.
    pub(crate) connection_timeout: u64,
    /// Read timeout in seconds passed to dcert subprocess via --read-timeout.
    pub(crate) read_timeout: u64,
    /// Resolved path to the dcert binary.
    pub(crate) dcert_binary: PathBuf,
    /// Detected proxy configuration (for logging; env vars are inherited by subprocesses).
    pub(crate) proxy_config: McpProxyInfo,
}

/// Log MCP server startup diagnostics to stderr.
/// MCP servers communicate over stdio, so diagnostics go to stderr.
pub(crate) fn log_startup_diagnostics(config: &McpConfig) {
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
        Some(proxy) => eprintln!("[dcert-mcp] HTTPS proxy: {}", sanitize_url(proxy)),
        None => eprintln!("[dcert-mcp] HTTPS proxy: (none)"),
    }
    match &config.proxy_config.http_proxy {
        Some(proxy) => eprintln!("[dcert-mcp] HTTP proxy: {}", sanitize_url(proxy)),
        None => eprintln!("[dcert-mcp] HTTP proxy: (none)"),
    }
    match &config.proxy_config.no_proxy {
        Some(no_proxy) => eprintln!("[dcert-mcp] NO_PROXY: {no_proxy}"),
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
pub(crate) fn format_timeout_error(config: &McpConfig) -> String {
    let mut msg = format!(
        "dcert subprocess timed out after {}s.",
        config.subprocess_timeout.as_secs()
    );

    msg.push_str("\n\nPossible causes:");

    if config.proxy_config.https_proxy.is_some() {
        msg.push_str(&format!(
            "\n  - Forward proxy detected ({}). The proxy may be blocking or slow to respond.",
            sanitize_url(config.proxy_config.https_proxy.as_deref().unwrap_or(""))
        ));
        msg.push_str("\n  - Check that the target host is allowed through your proxy.");
        if let Some(ref no_proxy) = config.proxy_config.no_proxy {
            msg.push_str(&format!(
                "\n  - NO_PROXY is set to '{no_proxy}'. Verify the target isn't incorrectly bypassed."
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
pub(crate) fn find_dcert_binary() -> PathBuf {
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
