//! Vault tool parameters, authentication and the Vault subprocess runner.

use schemars::JsonSchema;
use serde::Deserialize;
use std::time::Duration;
use tokio::process::Command;

use crate::config::McpConfig;
use crate::exec::{SUBPROCESS_SEMAPHORE, run_child_with_timeout};
use crate::params::{
    default_cert_key_name, default_key_key_name, default_kv_version, default_ttl, default_vault_mount,
};
use crate::validate::validate_path;

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
pub(crate) struct VaultParams {
    /// Vault server address (e.g., "https://vault.example.com:8200").
    /// If omitted, inherits VAULT_ADDR from the MCP server environment.
    #[serde(default)]
    pub(crate) vault_addr: Option<String>,

    /// Vault token for authentication. If omitted, inherits from VAULT_TOKEN env var
    /// or ~/.vault-token file. Ignored when auth_method is "ldap" or "approle".
    #[serde(default)]
    pub(crate) vault_token: Option<String>,

    /// Authentication method: "token" (default), "ldap", or "approle"
    #[serde(default)]
    pub(crate) auth_method: Option<String>,

    /// LDAP username (required when auth_method is "ldap")
    #[serde(default)]
    pub(crate) ldap_username: Option<String>,

    /// LDAP password (required when auth_method is "ldap")
    #[serde(default)]
    pub(crate) ldap_password: Option<String>,

    /// LDAP auth mount point (default: "ldap")
    #[serde(default)]
    pub(crate) ldap_mount: Option<String>,

    /// AppRole role_id (required when auth_method is "approle")
    #[serde(default)]
    pub(crate) approle_role_id: Option<String>,

    /// AppRole secret_id (required when auth_method is "approle")
    #[serde(default)]
    pub(crate) approle_secret_id: Option<String>,

    /// AppRole auth mount point (default: "approle")
    #[serde(default)]
    pub(crate) approle_mount: Option<String>,

    /// Custom CA certificate PEM file for Vault TLS verification.
    /// Also reads VAULT_CACERT env var from the MCP server environment.
    #[serde(default)]
    pub(crate) vault_cacert: Option<String>,

    /// Skip TLS certificate verification for Vault (insecure).
    /// Also reads VAULT_SKIP_VERIFY env var from the MCP server environment.
    #[serde(default)]
    pub(crate) skip_verify: Option<bool>,
}

impl Drop for VaultParams {
    /// Wipe Vault secrets received in tool arguments (token, LDAP password,
    /// AppRole secret_id) from memory once the request is done.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(s) = self.vault_token.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.ldap_password.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.approle_secret_id.as_mut() {
            s.zeroize();
        }
    }
}

impl VaultParams {
    pub(crate) fn validate(&self) -> Result<(), String> {
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
                    "Invalid auth_method '{method}': must be \"token\", \"ldap\", or \"approle\""
                ));
            }
        }
        if let Some(ref p) = self.vault_cacert {
            validate_path(p, "vault_cacert")?;
        }
        Ok(())
    }

    /// Resolve the Vault address from params or environment.
    pub(crate) fn resolve_addr(&self) -> Option<String> {
        self.vault_addr
            .clone()
            .or_else(|| std::env::var("VAULT_ADDR").ok())
            .map(|s| s.trim_end_matches('/').to_string())
    }
}

/// Cap untrusted upstream text before echoing it into an error message, so a
/// large or sensitive Vault response body isn't returned verbatim to the MCP
/// client or written to logs.
pub(crate) fn truncate_upstream_error(s: &str) -> String {
    const MAX_CHARS: usize = 512;
    let trimmed = s.trim();
    if trimmed.chars().count() > MAX_CHARS {
        let head: String = trimmed.chars().take(MAX_CHARS).collect();
        format!("{head}… (truncated)")
    } else {
        trimmed.to_string()
    }
}

/// Authenticate with Vault using LDAP or AppRole and return a client token.
/// The MCP server performs the auth handshake so the dcert subprocess only needs a token.
pub(crate) async fn vault_authenticate(vault_params: &VaultParams) -> Result<String, String> {
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
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    match method {
        "ldap" => {
            use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
            let username = vault_params
                .ldap_username
                .as_deref()
                .ok_or_else(|| "ldap_username is required for LDAP auth".to_string())?;
            let password = vault_params
                .ldap_password
                .as_deref()
                .ok_or_else(|| "ldap_password is required for LDAP auth".to_string())?;
            let mount = vault_params.ldap_mount.as_deref().unwrap_or("ldap");
            let encoded_mount = utf8_percent_encode(mount, NON_ALPHANUMERIC).to_string();
            let encoded_username = utf8_percent_encode(username, NON_ALPHANUMERIC).to_string();
            let url = format!("{vault_addr}/v1/auth/{encoded_mount}/login/{encoded_username}");

            let resp = client
                .post(&url)
                .json(&serde_json::json!({"password": password}))
                .send()
                .await
                .map_err(|e| format!("LDAP auth request failed: {e}"))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = truncate_upstream_error(&resp.text().await.unwrap_or_default());
                return Err(format!("LDAP auth failed (HTTP {status}): {body}"));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse LDAP auth response: {e}"))?;

            json["auth"]["client_token"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| "LDAP auth response did not contain a client_token".to_string())
        }
        "approle" => {
            use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
            let role_id = vault_params
                .approle_role_id
                .as_deref()
                .ok_or_else(|| "approle_role_id is required for AppRole auth".to_string())?;
            let secret_id = vault_params
                .approle_secret_id
                .as_deref()
                .ok_or_else(|| "approle_secret_id is required for AppRole auth".to_string())?;
            let mount = vault_params.approle_mount.as_deref().unwrap_or("approle");
            let encoded_mount = utf8_percent_encode(mount, NON_ALPHANUMERIC).to_string();
            let url = format!("{vault_addr}/v1/auth/{encoded_mount}/login");

            let resp = client
                .post(&url)
                .json(&serde_json::json!({"role_id": role_id, "secret_id": secret_id}))
                .send()
                .await
                .map_err(|e| format!("AppRole auth request failed: {e}"))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = truncate_upstream_error(&resp.text().await.unwrap_or_default());
                return Err(format!("AppRole auth failed (HTTP {status}): {body}"));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse AppRole auth response: {e}"))?;

            json["auth"]["client_token"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| "AppRole auth response did not contain a client_token".to_string())
        }
        _ => Err(format!("Unsupported auth method for authentication: {method}")),
    }
}

/// Run dcert vault with vault-specific environment variables.
/// Resolves vault_addr, handles auth (LDAP/AppRole → token), and passes
/// configuration to the subprocess via env vars and CLI flags.
pub(crate) async fn run_dcert_vault(
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
    // Wrapped in `Zeroizing` so the token buffer is wiped once it has been
    // handed to the subprocess environment below.
    let resolved_token: Option<zeroize::Zeroizing<String>> = match method {
        "ldap" | "approle" => Some(zeroize::Zeroizing::new(vault_authenticate(vault_params).await?)),
        _ => vault_params.vault_token.clone().map(zeroize::Zeroizing::new),
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
    let args_refs: Vec<&str> = full_args.iter().map(String::as_str).collect();
    cmd.args(&args_refs);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    // Set vault env vars on the subprocess
    if let Some(ref addr) = vault_params.resolve_addr() {
        cmd.env("VAULT_ADDR", addr);
    }
    if let Some(ref token) = resolved_token {
        cmd.env("VAULT_TOKEN", token.as_str());
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
pub(crate) struct VaultIssueParams {
    /// Common Name (CN) for the certificate (e.g., "api.example.com")
    pub(crate) common_name: String,
    /// Subject Alternative Names (e.g., ["DNS:*.example.com", "DNS:api.example.com"])
    #[serde(default)]
    pub(crate) sans: Vec<String>,
    /// IP Subject Alternative Names (e.g., ["10.0.0.1", "192.168.1.1"])
    #[serde(default)]
    pub(crate) ip_sans: Vec<String>,
    /// Certificate TTL (e.g., "8760h" for 1 year, "720h" for 30 days)
    #[serde(default = "default_ttl")]
    pub(crate) ttl: String,
    /// Vault PKI role name. If omitted, dcert infers from token policies.
    #[serde(default)]
    pub(crate) role: Option<String>,
    /// Vault PKI mount point (default: "vault_intermediate")
    #[serde(default = "default_vault_mount")]
    pub(crate) mount: String,
    /// Output file base name (without extension). Defaults to sanitised CN.
    #[serde(default)]
    pub(crate) output: Option<String>,
    /// PFX password — if provided, output is PKCS12/PFX instead of PEM
    #[serde(default)]
    pub(crate) pfx_password: Option<String>,
    /// Store cert and key in Vault KV at this path after issuance
    #[serde(default)]
    pub(crate) store_path: Option<String>,
    /// Vault KV version (1 or 2) for --store-path
    #[serde(default = "default_kv_version")]
    pub(crate) kv_version: u8,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    pub(crate) vault: VaultParams,
}

/// Parameters for the vault_sign tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct VaultSignParams {
    /// Path to CSR PEM file to sign
    pub(crate) csr_file: String,
    /// Common Name override (defaults to CN from CSR)
    #[serde(default)]
    pub(crate) common_name: Option<String>,
    /// Subject Alternative Names
    #[serde(default)]
    pub(crate) sans: Vec<String>,
    /// IP Subject Alternative Names
    #[serde(default)]
    pub(crate) ip_sans: Vec<String>,
    /// Certificate TTL
    #[serde(default = "default_ttl")]
    pub(crate) ttl: String,
    /// Vault PKI role name
    #[serde(default)]
    pub(crate) role: Option<String>,
    /// Vault PKI mount point
    #[serde(default = "default_vault_mount")]
    pub(crate) mount: String,
    /// Output file base name
    #[serde(default)]
    pub(crate) output: Option<String>,
    /// Store cert in Vault KV at this path after signing
    #[serde(default)]
    pub(crate) store_path: Option<String>,
    /// Vault KV version (1 or 2) for --store-path
    #[serde(default = "default_kv_version")]
    pub(crate) kv_version: u8,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    pub(crate) vault: VaultParams,
}

/// Parameters for the vault_revoke tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct VaultRevokeParams {
    /// Certificate serial number (colon or hyphen-separated hex)
    #[serde(default)]
    pub(crate) serial: Option<String>,
    /// PEM certificate file path to revoke (alternative to serial)
    #[serde(default)]
    pub(crate) cert_file: Option<String>,
    /// Vault PKI mount point
    #[serde(default = "default_vault_mount")]
    pub(crate) mount: String,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    pub(crate) vault: VaultParams,
}

/// Parameters for the vault_list tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct VaultListParams {
    /// Vault PKI mount point
    #[serde(default = "default_vault_mount")]
    pub(crate) mount: String,
    /// Fetch and display details for each certificate (slower for large lists)
    #[serde(default)]
    pub(crate) show_details: bool,
    /// Show only expired certificates
    #[serde(default)]
    pub(crate) expired_only: bool,
    /// Show only valid (non-expired) certificates
    #[serde(default)]
    pub(crate) valid_only: bool,
    /// Export results to a file (JSON, CSV, or XLSX based on extension)
    #[serde(default)]
    pub(crate) export: Option<String>,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    pub(crate) vault: VaultParams,
}

/// Parameters for the vault_store tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct VaultStoreParams {
    /// Local PEM certificate file to store
    pub(crate) cert_file: String,
    /// Local PEM private key file to store
    pub(crate) key_file: String,
    /// Vault KV path (e.g., "secret/certs/my-cert")
    pub(crate) path: String,
    /// Key name for the certificate in Vault KV
    #[serde(default = "default_cert_key_name")]
    pub(crate) cert_key: String,
    /// Key name for the private key in Vault KV
    #[serde(default = "default_key_key_name")]
    pub(crate) key_key: String,
    /// Vault KV version (1 or 2)
    #[serde(default = "default_kv_version")]
    pub(crate) kv_version: u8,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    pub(crate) vault: VaultParams,
}

/// Parameters for the vault_validate tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct VaultValidateParams {
    /// Vault KV path to read certificate from
    pub(crate) path: String,
    /// Key name for the certificate in Vault KV
    #[serde(default = "default_cert_key_name")]
    pub(crate) cert_key: String,
    /// Key name for the private key in Vault KV
    #[serde(default = "default_key_key_name")]
    pub(crate) key_key: String,
    /// Vault KV version (1 or 2)
    #[serde(default = "default_kv_version")]
    pub(crate) kv_version: u8,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    pub(crate) vault: VaultParams,
}

/// Parameters for the vault_renew tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct VaultRenewParams {
    /// Vault KV path containing the existing certificate to renew
    pub(crate) path: String,
    /// Vault PKI role name for issuing the new certificate
    #[serde(default)]
    pub(crate) role: Option<String>,
    /// Vault PKI mount point
    #[serde(default = "default_vault_mount")]
    pub(crate) mount: String,
    /// TTL for the new certificate
    #[serde(default = "default_ttl")]
    pub(crate) ttl: String,
    /// Key name for the certificate in Vault KV
    #[serde(default = "default_cert_key_name")]
    pub(crate) cert_key: String,
    /// Key name for the private key in Vault KV
    #[serde(default = "default_key_key_name")]
    pub(crate) key_key: String,
    /// Vault KV version (1 or 2)
    #[serde(default = "default_kv_version")]
    pub(crate) kv_version: u8,
    /// Additional Subject Alternative Names (override existing SANs if provided)
    #[serde(default)]
    pub(crate) sans: Vec<String>,
    /// Additional IP Subject Alternative Names
    #[serde(default)]
    pub(crate) ip_sans: Vec<String>,
    /// Vault connection and authentication parameters
    #[serde(flatten, default)]
    pub(crate) vault: VaultParams,
}
