//! Runtime configuration, binary discovery and startup diagnostics.

use std::path::PathBuf;
use std::time::Duration;

use dcert::debug::sanitize_url;

/// Canonical description for dcert-mcp, consistent with the CLI.
pub(crate) const MCP_DESCRIPTION: &str =
    "MCP server for TLS certificate analysis, format conversion, and key verification — for AI-powered IDEs";

/// Guidance sent to clients in the `initialize` result. MCP clients typically
/// add it to the model's context, so it says which tool fits which question
/// rather than repeating the per-tool descriptions.
pub(crate) const MCP_INSTRUCTIONS: &str = "dcert inspects and manages TLS certificates.\n\
- Start with `analyze_certificate` for a certificate or endpoint, `check_expiry` for a quick expiry check, \
and `diagnose_endpoint` when an HTTPS endpoint fails or misbehaves (any server: Apigee, Envoy/Istio, nginx, \
CloudFront, API Gateway and others). Its `platforms` field names the products it fingerprinted; vendor specific \
findings appear only for those, so do not suggest AWS fixes when `platforms` lists no AWS service.\n\
- mTLS: the `client_auth` connection field says whether the server sent a CertificateRequest (`not_requested`, \
`optional`, `required`, `presented`) and `acceptable_client_cas` lists the CAs it accepts. `required` with no \
HTTP status means supply `client_cert`/`client_key` (or `pkcs12`) and probe again.\n\
- Use `explain_edge_term` only for Amazon CloudFront or API Gateway terms, without contacting the network.\n\
- `target` accepts an HTTPS URL, a hostname, or a local PEM file path. To test a specific backend IP while \
validating the hostname, keep the hostname in `target` and set `connect_to` or `resolve`.\n\
- Tools marked openWorld contact remote hosts (the target, OCSP responders, or HashiCorp Vault); the others work \
only on local files.\n\
- `create_csr`, `vault_issue`, `vault_sign` and `vault_renew` create new keys or certificates on every call, and \
`vault_revoke` is irreversible: confirm with the user before calling them, and do not retry them blindly.\n\
- Results are JSON text. A tool error result explains what failed and usually how to fix the input.";

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
pub(crate) const DEFAULT_CONNECTION_TIMEOUT: u64 = dcert::limits::DEFAULT_TIMEOUT_SECS;

/// Default read timeout (seconds) passed to the dcert subprocess via --read-timeout.
pub(crate) const DEFAULT_READ_TIMEOUT: u64 = dcert::limits::DEFAULT_READ_TIMEOUT_SECS;

/// Default number of failed authentication attempts one client address may
/// make within the failure window before it is answered with `429`.
pub(crate) const DEFAULT_AUTH_FAILURE_LIMIT: u32 = 10;

/// Default length of the authentication failure window, in seconds.
pub(crate) const DEFAULT_AUTH_FAILURE_WINDOW_SECS: u64 = 60;

/// Longest failure window accepted: a day. Beyond that a typo would lock a
/// client out for longer than any operator intends.
const MAX_AUTH_FAILURE_WINDOW_SECS: u64 = 86_400;

/// How many authentication failures a client address may make, and over what
/// window, before the HTTP transport refuses it. Read from
/// `DCERT_MCP_AUTH_FAILURE_LIMIT` and `DCERT_MCP_AUTH_FAILURE_WINDOW`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthFailureLimitConfig {
    /// Failures allowed per window; zero disables the limiter.
    pub(crate) limit: u32,
    /// Length of the window.
    pub(crate) window: Duration,
}

impl Default for AuthFailureLimitConfig {
    fn default() -> Self {
        Self {
            limit: DEFAULT_AUTH_FAILURE_LIMIT,
            window: Duration::from_secs(DEFAULT_AUTH_FAILURE_WINDOW_SECS),
        }
    }
}

impl AuthFailureLimitConfig {
    /// Read the configuration from the environment. A value that cannot be
    /// used is an error, so a misconfigured limiter stops the server from
    /// starting rather than silently running with a different setting.
    pub(crate) fn from_env() -> Result<Self, String> {
        Self::from_values(
            std::env::var("DCERT_MCP_AUTH_FAILURE_LIMIT").ok().as_deref(),
            std::env::var("DCERT_MCP_AUTH_FAILURE_WINDOW").ok().as_deref(),
        )
    }

    /// Build the configuration from the raw variable values, so validation
    /// can be unit tested without touching the process environment.
    pub(crate) fn from_values(limit: Option<&str>, window: Option<&str>) -> Result<Self, String> {
        let defaults = Self::default();

        let limit = match limit.map(str::trim).filter(|v| !v.is_empty()) {
            None => defaults.limit,
            Some(raw) => raw.parse::<u32>().map_err(|_| {
                format!(
                    "DCERT_MCP_AUTH_FAILURE_LIMIT must be a whole number of attempts \
                     (0 disables the limiter), got {raw:?}"
                )
            })?,
        };

        let window_secs = match window.map(str::trim).filter(|v| !v.is_empty()) {
            None => defaults.window.as_secs(),
            Some(raw) => {
                let secs = raw.parse::<u64>().map_err(|_| {
                    format!("DCERT_MCP_AUTH_FAILURE_WINDOW must be a whole number of seconds, got {raw:?}")
                })?;
                if !(1..=MAX_AUTH_FAILURE_WINDOW_SECS).contains(&secs) {
                    return Err(format!(
                        "DCERT_MCP_AUTH_FAILURE_WINDOW must be between 1 and \
                         {MAX_AUTH_FAILURE_WINDOW_SECS} seconds, got {secs}"
                    ));
                }
                secs
            }
        };

        Ok(Self {
            limit,
            window: Duration::from_secs(window_secs),
        })
    }

    /// `true` when failures are counted at all.
    pub(crate) fn is_enabled(&self) -> bool {
        self.limit > 0
    }
}

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
    /// Which destinations tool calls may reach (`DCERT_MCP_ALLOWED_TARGETS`,
    /// `DCERT_MCP_DENY_PRIVATE_TARGETS`), also handed to every child.
    pub(crate) destinations: dcert::netpolicy::DestinationPolicy,
}

/// Operator variables for the destination policy.
pub(crate) const ALLOWED_TARGETS_VAR: &str = "DCERT_MCP_ALLOWED_TARGETS";
/// See [`ALLOWED_TARGETS_VAR`].
pub(crate) const DENY_PRIVATE_TARGETS_VAR: &str = "DCERT_MCP_DENY_PRIVATE_TARGETS";

/// The destination policy from the environment. Private ranges are denied by
/// default in HTTP mode, where callers are remote, and allowed in stdio mode,
/// where the caller is the local user.
pub(crate) fn destination_policy_from_env(http_mode: bool) -> Result<dcert::netpolicy::DestinationPolicy, String> {
    dcert::netpolicy::DestinationPolicy::parse(
        std::env::var(ALLOWED_TARGETS_VAR).ok().as_deref(),
        std::env::var(DENY_PRIVATE_TARGETS_VAR).ok().as_deref(),
        http_mode,
        ALLOWED_TARGETS_VAR,
        DENY_PRIVATE_TARGETS_VAR,
    )
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

    if config.destinations.is_open() {
        eprintln!("[dcert-mcp] destinations: unrestricted");
    } else {
        let allow = config.destinations.allow_list_env();
        eprintln!(
            "[dcert-mcp] destinations: private ranges {}; allow list: {}",
            if config.destinations.denies_private() {
                "denied"
            } else {
                "allowed"
            },
            if allow.is_empty() { "(none)" } else { allow.as_str() }
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failure_limit_defaults_when_unset_or_blank() {
        let cfg = AuthFailureLimitConfig::from_values(None, None).expect("defaults");
        assert_eq!(cfg, AuthFailureLimitConfig::default());
        assert_eq!(cfg.limit, 10);
        assert_eq!(cfg.window, Duration::from_secs(60));
        assert!(cfg.is_enabled());

        let blank = AuthFailureLimitConfig::from_values(Some("  "), Some("")).expect("blank is unset");
        assert_eq!(blank, cfg);
    }

    #[test]
    fn auth_failure_limit_reads_both_values() {
        let cfg = AuthFailureLimitConfig::from_values(Some(" 3 "), Some("120")).expect("valid");
        assert_eq!(cfg.limit, 3);
        assert_eq!(cfg.window, Duration::from_secs(120));
    }

    #[test]
    fn auth_failure_limit_zero_disables() {
        let cfg = AuthFailureLimitConfig::from_values(Some("0"), None).expect("valid");
        assert!(!cfg.is_enabled());
    }

    #[test]
    fn auth_failure_limit_rejects_bad_values() {
        let err = AuthFailureLimitConfig::from_values(Some("ten"), None).unwrap_err();
        assert!(err.contains("DCERT_MCP_AUTH_FAILURE_LIMIT"), "{err}");
        let err = AuthFailureLimitConfig::from_values(Some("-1"), None).unwrap_err();
        assert!(err.contains("DCERT_MCP_AUTH_FAILURE_LIMIT"), "{err}");

        let err = AuthFailureLimitConfig::from_values(None, Some("0")).unwrap_err();
        assert!(err.contains("DCERT_MCP_AUTH_FAILURE_WINDOW"), "{err}");
        let err = AuthFailureLimitConfig::from_values(None, Some("90000")).unwrap_err();
        assert!(err.contains("DCERT_MCP_AUTH_FAILURE_WINDOW"), "{err}");
        let err = AuthFailureLimitConfig::from_values(None, Some("1m")).unwrap_err();
        assert!(err.contains("DCERT_MCP_AUTH_FAILURE_WINDOW"), "{err}");
    }
}
