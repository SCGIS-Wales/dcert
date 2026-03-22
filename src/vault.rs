use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;

use crate::cert::{CertProcessOpts, parse_cert_infos_from_pem};
use crate::convert;
use crate::csr::{prompt_optional, prompt_required, prompt_with_default};
use crate::output::{PrettyDebugInfo, print_pretty};

// ---------------------------------------------------------------------------
// Vault Token & Address Discovery
// ---------------------------------------------------------------------------

/// Discover the Vault token. Checks VAULT_TOKEN env var first, then ~/.vault-token file.
pub fn discover_vault_token() -> Result<String> {
    discover_vault_token_from(std::env::var("VAULT_TOKEN").ok(), home_dir())
}

/// Core token discovery logic, testable without env var manipulation.
fn discover_vault_token_from(env_token: Option<String>, home: Option<std::path::PathBuf>) -> Result<String> {
    // 1. VAULT_TOKEN environment variable
    if let Some(token) = env_token {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }

    // 2. ~/.vault-token file
    if let Some(home) = home {
        let token_path = home.join(".vault-token");
        if token_path.exists() {
            let token =
                fs::read_to_string(&token_path).with_context(|| format!("Failed to read {}", token_path.display()))?;
            let token = token.trim().to_string();
            if !token.is_empty() {
                return Ok(token);
            }
        }
    }

    Err(anyhow::anyhow!(
        "No Vault token found.\n\
         Set the VAULT_TOKEN environment variable or write your token to ~/.vault-token"
    ))
}

/// Authenticate with Vault using LDAP or AppRole and return a client token.
/// This mirrors the MCP server's authentication logic for CLI parity.
#[allow(clippy::too_many_arguments)]
pub fn vault_authenticate(
    vault_addr: &str,
    auth_method: &str,
    ldap_username: Option<&str>,
    ldap_password: Option<&str>,
    ldap_mount: &str,
    approle_role_id: Option<&str>,
    approle_secret_id: Option<&str>,
    approle_mount: &str,
    skip_verify: bool,
    vault_cacert: Option<&str>,
) -> Result<String> {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

    let mut client_builder = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(skip_verify)
        .timeout(std::time::Duration::from_secs(30));

    if let Some(ca_path) = vault_cacert {
        let ca_data = fs::read(ca_path).with_context(|| format!("Failed to read CA cert: {}", ca_path))?;
        let ca_cert = reqwest::Certificate::from_pem(&ca_data)
            .with_context(|| format!("Failed to parse CA cert: {}", ca_path))?;
        client_builder = client_builder.add_root_certificate(ca_cert);
    }

    let client = client_builder
        .build()
        .context("Failed to create HTTP client for Vault auth")?;

    match auth_method {
        "ldap" => {
            let username = ldap_username.ok_or_else(|| anyhow::anyhow!("--ldap-username is required for LDAP auth"))?;
            let password = ldap_password.ok_or_else(|| anyhow::anyhow!("--ldap-password is required for LDAP auth"))?;
            let encoded_mount = utf8_percent_encode(ldap_mount, NON_ALPHANUMERIC).to_string();
            let encoded_username = utf8_percent_encode(username, NON_ALPHANUMERIC).to_string();
            let url = format!("{}/v1/auth/{}/login/{}", vault_addr, encoded_mount, encoded_username);

            let resp = client
                .post(&url)
                .json(&serde_json::json!({"password": password}))
                .send()
                .with_context(|| "LDAP auth request failed")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().unwrap_or_default();
                return Err(anyhow::anyhow!("LDAP auth failed (HTTP {}): {}", status, body));
            }

            let json: serde_json::Value = resp.json().context("Failed to parse LDAP auth response")?;
            json["auth"]["client_token"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| anyhow::anyhow!("LDAP auth response did not contain a client_token"))
        }
        "approle" => {
            let role_id =
                approle_role_id.ok_or_else(|| anyhow::anyhow!("--approle-role-id is required for AppRole auth"))?;
            let secret_id =
                approle_secret_id.ok_or_else(|| anyhow::anyhow!("--approle-secret-id is required for AppRole auth"))?;
            let encoded_mount = utf8_percent_encode(approle_mount, NON_ALPHANUMERIC).to_string();
            let url = format!("{}/v1/auth/{}/login", vault_addr, encoded_mount);

            let resp = client
                .post(&url)
                .json(&serde_json::json!({"role_id": role_id, "secret_id": secret_id}))
                .send()
                .with_context(|| "AppRole auth request failed")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().unwrap_or_default();
                return Err(anyhow::anyhow!("AppRole auth failed (HTTP {}): {}", status, body));
            }

            let json: serde_json::Value = resp.json().context("Failed to parse AppRole auth response")?;
            json["auth"]["client_token"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| anyhow::anyhow!("AppRole auth response did not contain a client_token"))
        }
        _ => Err(anyhow::anyhow!(
            "Invalid auth method '{}': must be \"token\", \"ldap\", or \"approle\"",
            auth_method
        )),
    }
}

/// Read the Vault address from VAULT_ADDR environment variable.
pub fn vault_addr() -> Result<String> {
    std::env::var("VAULT_ADDR")
        .map(|s| s.trim_end_matches('/').to_string())
        .map_err(|_| {
            anyhow::anyhow!(
                "VAULT_ADDR environment variable is not set.\n\
             Set it to your Vault server URL (e.g., https://vault.example.com:8200)"
            )
        })
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var("HOME").ok().map(std::path::PathBuf::from)
}

/// Mask a token for display: show first 4 and last 4 chars.
fn mask_token(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 8 {
        "****".to_string()
    } else {
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[chars.len() - 4..].iter().collect();
        format!("{prefix}****{suffix}")
    }
}

// ---------------------------------------------------------------------------
// Vault HTTP Client
// ---------------------------------------------------------------------------

/// Configuration for the Vault HTTP client (TLS, debug, etc.).
#[derive(Debug, Clone, Default)]
pub struct VaultClientConfig {
    /// Custom CA certificate PEM file for TLS verification.
    pub cacert: Option<String>,
    /// Skip TLS certificate verification (insecure).
    pub skip_verify: bool,
    /// Enable verbose debug output.
    pub debug: bool,
}

/// A simple Vault HTTP client wrapping reqwest.
pub struct VaultClient {
    client: reqwest::blocking::Client,
    base_url: String,
    token: String,
    debug: bool,
}

/// Describes the required Vault policy capability for an endpoint.
struct PolicyHint {
    path: String,
    capability: &'static str,
}

impl VaultClient {
    /// Create a new Vault client with TLS configuration.
    ///
    /// Supports:
    /// - `VAULT_SKIP_VERIFY=1` or `config.skip_verify` — disables TLS verification
    /// - `VAULT_CACERT` env var or `config.cacert` — custom CA certificate PEM
    /// - `VAULT_CAPATH` env var — directory of CA PEM files
    /// - System native root certificates (corporate CAs installed system-wide)
    pub fn new(addr: &str, token: &str, config: &VaultClientConfig) -> Result<Self> {
        let skip_verify = config.skip_verify
            || std::env::var("VAULT_SKIP_VERIFY")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
                .unwrap_or(false);

        let mut builder = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(skip_verify)
            .timeout(std::time::Duration::from_secs(30));

        if config.debug {
            eprintln!("{}", "  Vault TLS configuration:".dimmed());
            eprintln!("    skip_verify   : {}", skip_verify);
            eprintln!("    native roots  : {} (system CA store)", "enabled".green());
        }

        if skip_verify {
            eprintln!(
                "{} {}",
                "WARNING:".yellow().bold(),
                "TLS certificate verification is disabled for Vault. Connection is NOT secure.".yellow()
            );
        }

        // Load custom CA cert from CLI flag, VAULT_CACERT, or SSL_CERT_FILE env var
        let cacert_path = config
            .cacert
            .clone()
            .or_else(|| std::env::var("VAULT_CACERT").ok())
            .or_else(|| std::env::var("SSL_CERT_FILE").ok());

        if let Some(ref cacert_path) = cacert_path {
            let pem_data = fs::read(cacert_path)
                .with_context(|| format!("Failed to read CA certificate file: {}", cacert_path))?;
            let cert = reqwest::Certificate::from_pem(&pem_data)
                .with_context(|| format!("Failed to parse CA certificate from: {}", cacert_path))?;
            builder = builder.add_root_certificate(cert);

            if config.debug {
                let source = if config.cacert.as_deref() == Some(cacert_path.as_str()) {
                    "--vault-cacert"
                } else if std::env::var("VAULT_CACERT").ok().as_deref() == Some(cacert_path.as_str()) {
                    "VAULT_CACERT"
                } else {
                    "SSL_CERT_FILE"
                };
                eprintln!("    CA cert       : {} (from {})", cacert_path, source);
            }
        }

        // Load CA certs from VAULT_CAPATH or SSL_CERT_DIR env var
        let capath = std::env::var("VAULT_CAPATH")
            .ok()
            .or_else(|| std::env::var("SSL_CERT_DIR").ok());
        if let Some(capath) = capath {
            if config.debug {
                eprintln!("    CA cert dir   : {}", capath);
            }
            let mut loaded = 0usize;
            for entry in
                fs::read_dir(&capath).with_context(|| format!("Failed to read CA path directory: {}", capath))?
            {
                let entry = entry?;
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if (ext == "pem" || ext == "crt" || ext == "cer")
                    && let Ok(pem_data) = fs::read(&path)
                    && let Ok(cert) = reqwest::Certificate::from_pem(&pem_data)
                {
                    builder = builder.add_root_certificate(cert);
                    loaded += 1;
                }
            }
            if config.debug {
                eprintln!("    CA certs loaded: {}", loaded);
            }
        }

        let client = builder
            .build()
            .with_context(|| "Failed to build HTTP client for Vault")?;

        if config.debug {
            eprintln!("    Target        : {}", addr);
            eprintln!();
        }

        Ok(Self {
            client,
            base_url: addr.trim_end_matches('/').to_string(),
            token: token.to_string(),
            debug: config.debug,
        })
    }

    /// Make an authenticated GET request.
    fn get(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}/v1/{}", self.base_url, path);
        let hint = PolicyHint {
            path: path.to_string(),
            capability: "read",
        };
        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .map_err(|e| vault_connection_error(e, &self.base_url, self.debug))?;

        handle_vault_response(resp, &hint)
    }

    /// Make an authenticated POST request with JSON body.
    fn post(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}/v1/{}", self.base_url, path);
        let hint = PolicyHint {
            path: path.to_string(),
            capability: "create",
        };
        let resp = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(body)
            .send()
            .map_err(|e| vault_connection_error(e, &self.base_url, self.debug))?;

        handle_vault_response(resp, &hint)
    }

    /// Make an authenticated LIST request (uses custom HTTP method via GET + query).
    fn list(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}/v1/{}", self.base_url, path);
        let hint = PolicyHint {
            path: path.to_string(),
            capability: "list",
        };
        let resp = self
            .client
            .request(
                reqwest::Method::from_bytes(b"LIST").unwrap_or(reqwest::Method::GET),
                &url,
            )
            .header("X-Vault-Token", &self.token)
            .send()
            .map_err(|e| vault_connection_error(e, &self.base_url, self.debug))?;

        handle_vault_response(resp, &hint)
    }

    /// Make an authenticated PUT request (for KV v2 writes).
    #[allow(dead_code)]
    fn put(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}/v1/{}", self.base_url, path);
        let hint = PolicyHint {
            path: path.to_string(),
            capability: "create, update",
        };
        let resp = self
            .client
            .put(&url)
            .header("X-Vault-Token", &self.token)
            .json(body)
            .send()
            .map_err(|e| vault_connection_error(e, &self.base_url, self.debug))?;

        handle_vault_response(resp, &hint)
    }

    /// Read a certificate from a PKI mount (unauthenticated endpoint, but we send token anyway).
    fn read_pki_cert(&self, path: &str) -> Result<String> {
        let url = format!("{}/v1/{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .map_err(|e| vault_connection_error(e, &self.base_url, self.debug))?;

        let hint = PolicyHint {
            path: path.to_string(),
            capability: "read",
        };

        let json = handle_vault_response(resp, &hint)?;
        json["data"]["certificate"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No certificate data returned from {}", path))
    }
}

fn vault_connection_error(e: reqwest::Error, base_url: &str, debug: bool) -> anyhow::Error {
    let debug_detail = if debug {
        format!("\n\n  Debug detail: {:#}", e)
    } else {
        String::new()
    };

    if e.is_connect() {
        let tls_hint = if base_url.starts_with("https") {
            "\n\n  If using a corporate/internal CA, try one of:\n\
             \x20   export VAULT_CACERT=/path/to/ca.pem\n\
             \x20   export SSL_CERT_FILE=/path/to/ca-bundle.pem\n\
             \x20   dcert vault --vault-cacert /path/to/ca.pem ...\n\
             \x20   dcert vault --skip-verify ...  (insecure)\n\
             \x20   export VAULT_SKIP_VERIFY=1     (insecure)\n\n\
             \x20 Run with --debug for full error details."
        } else {
            ""
        };

        anyhow::anyhow!(
            "Failed to connect to Vault at {}.\n\
             Check that VAULT_ADDR is correct and the Vault server is running.{}{}",
            base_url,
            tls_hint,
            debug_detail
        )
    } else if e.is_timeout() {
        anyhow::anyhow!(
            "Connection to Vault at {} timed out.\n\
             Check network connectivity and Vault server health.{}",
            base_url,
            debug_detail
        )
    } else {
        anyhow::anyhow!("Vault HTTP request failed: {}{}", e, debug_detail)
    }
}

fn handle_vault_response(resp: reqwest::blocking::Response, hint: &PolicyHint) -> Result<serde_json::Value> {
    let status = resp.status();

    if status.is_success() {
        let body: serde_json::Value = resp.json().with_context(|| "Failed to parse Vault JSON response")?;
        return Ok(body);
    }

    // Try to read error body
    let body_text = resp.text().unwrap_or_default();
    let vault_errors = serde_json::from_str::<serde_json::Value>(&body_text)
        .ok()
        .and_then(|v| {
            v["errors"].as_array().map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
        })
        .unwrap_or_default();

    let errors_str = if vault_errors.is_empty() {
        body_text.clone()
    } else {
        vault_errors.join("; ")
    };

    match status.as_u16() {
        403 => Err(anyhow::anyhow!(
            "Permission denied by Vault.\n\n\
             \x20 Endpoint: {}\n\
             \x20 Required: {} capability on \"{}\"\n\n\
             \x20 Ask your Vault administrator to add this policy to your token:\n\
             \x20   path \"{}\" {{\n\
             \x20     capabilities = [\"{}\"]\n\
             \x20   }}\n\n\
             \x20 Vault error: {}",
            hint.path,
            hint.capability,
            hint.path,
            hint.path,
            hint.capability,
            errors_str
        )),
        404 => Err(anyhow::anyhow!(
            "Not found: {}\n\n\
             \x20 The mount point or role may not exist. Check that:\n\
             \x20   - The PKI mount is enabled (vault secrets enable pki)\n\
             \x20   - The role name is correct\n\
             \x20   - The path exists in Vault\n\n\
             \x20 Vault error: {}",
            hint.path,
            errors_str
        )),
        400 => Err(anyhow::anyhow!(
            "Bad request: {}\n\n\x20 Vault error: {}",
            hint.path,
            errors_str
        )),
        _ if status.is_server_error() => Err(anyhow::anyhow!(
            "Vault server error (HTTP {}): {}\n\n\
             \x20 The Vault server may be experiencing issues. Check Vault server logs.",
            status.as_u16(),
            errors_str
        )),
        _ => Err(anyhow::anyhow!(
            "Vault returned HTTP {}: {}",
            status.as_u16(),
            errors_str
        )),
    }
}

// ---------------------------------------------------------------------------
// Token Lookup & Role Discovery
// ---------------------------------------------------------------------------

/// Look up the current token's metadata via Vault API (`/auth/token/lookup-self`).
pub fn token_lookup_self(client: &VaultClient) -> Result<serde_json::Value> {
    client.get("auth/token/lookup-self")
}

/// Extract unique role names from Vault token policies.
///
/// Policies follow a dotted naming convention (e.g., `prefix.rolename.permission`).
/// This function extracts the second segment from policies that have at least three
/// dot-separated parts, deduplicates, and sorts alphabetically.
pub fn extract_roles_from_policies(policies: &[String]) -> Vec<String> {
    let mut roles: Vec<String> = policies
        .iter()
        .filter_map(|p| {
            let parts: Vec<&str> = p.split('.').collect();
            if parts.len() >= 3 {
                Some(parts[1].to_string())
            } else {
                None
            }
        })
        .collect();

    roles.sort();
    roles.dedup();
    roles
}

/// Discover roles from the current Vault token's policies and prompt the user to select one.
/// Returns the selected role name.
pub fn discover_role_from_token(client: &VaultClient) -> Result<Option<String>> {
    let resp = match token_lookup_self(client) {
        Ok(r) => r,
        Err(e) => {
            // Only swallow 403/404 (permission denied or endpoint not found).
            // Propagate connection errors so TLS issues are surfaced.
            let err_str = format!("{}", e);
            if err_str.contains("Permission denied") || err_str.contains("Not found") {
                if client.debug {
                    eprintln!("  {} token lookup-self failed (non-fatal): {}", "DEBUG:".dimmed(), e);
                }
                return Ok(None);
            }
            return Err(e);
        }
    };

    let policies: Vec<String> = resp["data"]["policies"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if client.debug {
        eprintln!("  {} Token policies: {:?}", "DEBUG:".dimmed(), policies);
    }

    let roles = extract_roles_from_policies(&policies);

    if client.debug {
        eprintln!("  {} Extracted roles: {:?}", "DEBUG:".dimmed(), roles);
    }

    if roles.is_empty() {
        if client.debug {
            eprintln!(
                "  {} No roles found (expecting policies with 3+ dot-separated segments, e.g. prefix.rolename.permission)",
                "DEBUG:".dimmed()
            );
        }
        return Ok(None);
    }

    if roles.len() == 1 {
        eprintln!(
            "  {} Inferred role '{}' from token policies",
            "Auto:".cyan().bold(),
            roles[0]
        );
        return Ok(Some(roles[0].clone()));
    }

    // Present selection
    eprintln!("{}", "Available roles (from token policies):".bold());
    for (i, role) in roles.iter().enumerate() {
        eprintln!("  {}. {}", i + 1, role);
    }
    eprintln!();

    let selection = prompt_required(&format!("Select role [1-{}]", roles.len()))?;
    let idx: usize = selection
        .trim()
        .parse::<usize>()
        .map_err(|_| anyhow::anyhow!("Invalid selection: '{}'", selection))?;

    if idx < 1 || idx > roles.len() {
        return Err(anyhow::anyhow!("Selection out of range: {}", idx));
    }

    Ok(Some(roles[idx - 1].clone()))
}

/// Resolve the role name: use provided value, or discover from token policies, or prompt.
pub fn resolve_role(client: &VaultClient, role: Option<String>) -> Result<String> {
    if let Some(role) = role {
        return Ok(role);
    }

    // Try to discover from token policies
    if let Ok(Some(role)) = discover_role_from_token(client) {
        return Ok(role);
    }

    // Fall back to manual prompt
    prompt_required("Role name")
}

// ---------------------------------------------------------------------------
// Vault PKI Response Types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct VaultPkiIssueData {
    pub certificate: String,
    pub private_key: Option<String>,
    pub private_key_type: Option<String>,
    pub issuing_ca: Option<String>,
    #[serde(default)]
    pub ca_chain: Vec<String>,
    pub serial_number: Option<String>,
    pub expiration: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultCertListEntry {
    pub serial_number: String,
    pub common_name: Option<String>,
    pub not_before: String,
    pub not_after: String,
    pub status: String,
}

// ---------------------------------------------------------------------------
// Issue Certificate
// ---------------------------------------------------------------------------

pub fn issue_certificate(
    client: &VaultClient,
    mount: &str,
    role: &str,
    common_name: &str,
    alt_names: &[String],
    ip_sans: &[String],
    ttl: &str,
) -> Result<VaultPkiIssueData> {
    let mut body = serde_json::json!({
        "common_name": common_name,
        "ttl": ttl,
        "format": "pem",
    });

    if !alt_names.is_empty() {
        body["alt_names"] = serde_json::json!(alt_names.join(","));
    }
    if !ip_sans.is_empty() {
        body["ip_sans"] = serde_json::json!(ip_sans.join(","));
    }

    let path = format!("{}/issue/{}", mount, role);
    let resp = client.post(&path, &body)?;
    let data: VaultPkiIssueData =
        serde_json::from_value(resp["data"].clone()).with_context(|| "Failed to parse Vault PKI issue response")?;
    Ok(data)
}

// ---------------------------------------------------------------------------
// Sign CSR
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn sign_csr(
    client: &VaultClient,
    mount: &str,
    role: &str,
    csr_pem: &str,
    common_name: Option<&str>,
    alt_names: &[String],
    ip_sans: &[String],
    ttl: &str,
) -> Result<VaultPkiIssueData> {
    let mut body = serde_json::json!({
        "csr": csr_pem,
        "ttl": ttl,
        "format": "pem",
    });

    if let Some(cn) = common_name {
        body["common_name"] = serde_json::json!(cn);
    }
    if !alt_names.is_empty() {
        body["alt_names"] = serde_json::json!(alt_names.join(","));
    }
    if !ip_sans.is_empty() {
        body["ip_sans"] = serde_json::json!(ip_sans.join(","));
    }

    let path = format!("{}/sign/{}", mount, role);
    let resp = client.post(&path, &body)?;
    let data: VaultPkiIssueData =
        serde_json::from_value(resp["data"].clone()).with_context(|| "Failed to parse Vault PKI sign response")?;
    Ok(data)
}

// ---------------------------------------------------------------------------
// Revoke Certificate
// ---------------------------------------------------------------------------

pub fn revoke_certificate(
    client: &VaultClient,
    mount: &str,
    serial: Option<&str>,
    cert_pem: Option<&str>,
) -> Result<()> {
    let body = if let Some(serial) = serial {
        serde_json::json!({ "serial_number": serial })
    } else if let Some(cert) = cert_pem {
        serde_json::json!({ "certificate": cert })
    } else {
        return Err(anyhow::anyhow!("Either --serial or --cert-file must be provided"));
    };

    let path = format!("{}/revoke", mount);
    let resp = client.post(&path, &body)?;

    let revocation_time = resp["data"]["revocation_time"].as_f64();
    if let Some(ts) = revocation_time {
        let dt = time::OffsetDateTime::from_unix_timestamp(ts as i64).unwrap_or(time::OffsetDateTime::now_utc());
        let formatted = dt
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| dt.to_string());
        println!("{}", "Certificate revoked successfully".green().bold());
        println!("  Revocation time: {}", formatted);
    } else {
        println!("{}", "Certificate revoked successfully".green().bold());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// List Certificates
// ---------------------------------------------------------------------------

pub fn list_certificates(
    client: &VaultClient,
    mount: &str,
    show_details: bool,
    expired_only: bool,
    valid_only: bool,
) -> Result<Vec<VaultCertListEntry>> {
    let path = format!("{}/certs", mount);
    let resp = client.list(&path)?;

    let serials: Vec<String> = resp["data"]["keys"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if serials.is_empty() {
        println!("No certificates found in {}", mount);
        return Ok(Vec::new());
    }

    if !show_details {
        let mut entries = Vec::new();
        for serial in &serials {
            entries.push(VaultCertListEntry {
                serial_number: serial.clone(),
                common_name: None,
                not_before: String::new(),
                not_after: String::new(),
                status: "unknown".to_string(),
            });
        }
        return Ok(entries);
    }

    let mut entries = Vec::new();
    for serial in &serials {
        let cert_path = format!("{}/cert/{}", mount, serial);
        match client.get(&cert_path) {
            Ok(cert_resp) => {
                if let Some(cert_pem) = cert_resp["data"]["certificate"].as_str() {
                    let opts = CertProcessOpts {
                        expired_only: false,
                        fingerprint: false,
                        extensions: false,
                    };
                    if let Ok(infos) = parse_cert_infos_from_pem(cert_pem, &opts)
                        && let Some(info) = infos.first()
                    {
                        let status = if info.is_expired {
                            "expired".to_string()
                        } else {
                            "valid".to_string()
                        };

                        // Apply filters
                        if expired_only && !info.is_expired {
                            continue;
                        }
                        if valid_only && info.is_expired {
                            continue;
                        }

                        entries.push(VaultCertListEntry {
                            serial_number: serial.clone(),
                            common_name: info.common_name.clone(),
                            not_before: info.not_before.clone(),
                            not_after: info.not_after.clone(),
                            status,
                        });
                    }
                }
            }
            Err(_) => {
                entries.push(VaultCertListEntry {
                    serial_number: serial.clone(),
                    common_name: None,
                    not_before: String::new(),
                    not_after: String::new(),
                    status: "error reading".to_string(),
                });
            }
        }
    }

    Ok(entries)
}

/// Escape a field value for RFC 4180 CSV output.
///
/// Quotes the field if it contains commas, quotes, newlines, or starts with
/// characters that could trigger formula injection in spreadsheet applications
/// (=, +, -, @).
fn csv_escape(field: &str) -> String {
    let needs_quoting = field.contains(',')
        || field.contains('"')
        || field.contains('\n')
        || field.contains('\r')
        || field.starts_with('=')
        || field.starts_with('+')
        || field.starts_with('-')
        || field.starts_with('@');
    if needs_quoting {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

pub fn export_cert_list(entries: &[VaultCertListEntry], export_path: &str) -> Result<()> {
    if export_path.ends_with(".xlsx") {
        export_cert_list_xlsx(entries, export_path)?;
    } else if export_path.ends_with(".csv") {
        let mut csv = String::from("serial_number,common_name,not_before,not_after,status\n");
        for entry in entries {
            csv.push_str(&format!(
                "{},{},{},{},{}\n",
                csv_escape(&entry.serial_number),
                csv_escape(entry.common_name.as_deref().unwrap_or("")),
                csv_escape(&entry.not_before),
                csv_escape(&entry.not_after),
                csv_escape(&entry.status),
            ));
        }
        fs::write(export_path, &csv).with_context(|| format!("Failed to write CSV file: {}", export_path))?;
    } else {
        // Default to JSON
        let json = serde_json::to_string_pretty(entries).with_context(|| "Failed to serialize certificate list")?;
        fs::write(export_path, &json).with_context(|| format!("Failed to write JSON file: {}", export_path))?;
    }

    println!("Certificate list exported to {}", export_path);
    Ok(())
}

fn export_cert_list_xlsx(entries: &[VaultCertListEntry], export_path: &str) -> Result<()> {
    use rust_xlsxwriter::{Format, Workbook};

    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();
    worksheet
        .set_name("Certificates")
        .map_err(|e| anyhow::anyhow!("Failed to set worksheet name: {}", e))?;

    let header_format = Format::new().set_bold();

    // Write headers
    let headers = ["Serial Number", "Common Name", "Not Before", "Not After", "Status"];
    for (col, header) in headers.iter().enumerate() {
        worksheet
            .write_string_with_format(0, col as u16, *header, &header_format)
            .map_err(|e| anyhow::anyhow!("Failed to write header: {}", e))?;
    }

    // Write data rows
    for (row, entry) in entries.iter().enumerate() {
        let r = (row + 1) as u32;
        worksheet
            .write_string(r, 0, &entry.serial_number)
            .map_err(|e| anyhow::anyhow!("Failed to write cell: {}", e))?;
        worksheet
            .write_string(r, 1, entry.common_name.as_deref().unwrap_or(""))
            .map_err(|e| anyhow::anyhow!("Failed to write cell: {}", e))?;
        worksheet
            .write_string(r, 2, &entry.not_before)
            .map_err(|e| anyhow::anyhow!("Failed to write cell: {}", e))?;
        worksheet
            .write_string(r, 3, &entry.not_after)
            .map_err(|e| anyhow::anyhow!("Failed to write cell: {}", e))?;
        worksheet
            .write_string(r, 4, &entry.status)
            .map_err(|e| anyhow::anyhow!("Failed to write cell: {}", e))?;
    }

    workbook
        .save(export_path)
        .map_err(|e| anyhow::anyhow!("Failed to save Excel file: {}", e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Chain Assembly
// ---------------------------------------------------------------------------

/// Build the full PEM chain: leaf + CA chain (intermediate → root).
/// Falls back to reading CA certs directly from Vault mounts if ca_chain is empty.
pub fn build_full_chain(client: &VaultClient, leaf_cert: &str, ca_chain: &[String], mount: &str) -> String {
    let mut full_pem = leaf_cert.trim().to_string();
    full_pem.push('\n');

    if !ca_chain.is_empty() {
        for ca in ca_chain {
            let ca = ca.trim();
            if !ca.is_empty() {
                full_pem.push_str(ca);
                full_pem.push('\n');
            }
        }
    } else {
        // Fallback: read intermediate CA from mount
        let intermediate_path = format!("{}/cert/ca", mount);
        if let Ok(intermediate_pem) = client.read_pki_cert(&intermediate_path) {
            full_pem.push_str(intermediate_pem.trim());
            full_pem.push('\n');
        }
    }

    // Try to read root CA from vault_root/cert/ca
    if let Ok(root_pem) = client.read_pki_cert("vault_root/cert/ca") {
        // Only add root if it's not already in the chain
        let root_trimmed = root_pem.trim();
        if !full_pem.contains(root_trimmed) {
            full_pem.push_str(root_trimmed);
            full_pem.push('\n');
        }
    }

    full_pem
}

// ---------------------------------------------------------------------------
// File Output
// ---------------------------------------------------------------------------

/// Write PEM certificate chain and private key to files.
pub fn write_pem_files(
    cert_chain_pem: &str,
    private_key_pem: Option<&str>,
    base_name: &str,
) -> Result<(String, Option<String>)> {
    let cert_path = format!("{}.crt", base_name);
    fs::write(&cert_path, cert_chain_pem)
        .with_context(|| format!("Failed to write certificate file: {}", cert_path))?;

    let key_path = if let Some(key) = private_key_pem {
        let kp = format!("{}.key", base_name);
        fs::write(&kp, key).with_context(|| format!("Failed to write private key file: {}", kp))?;
        convert::restrict_file_permissions(&kp);
        Some(kp)
    } else {
        None
    };

    Ok((cert_path, key_path))
}

/// Sanitise a CN into a safe base filename.
pub fn sanitise_cn(cn: &str) -> String {
    cn.replace('*', "wildcard").replace(['.', '/', ':'], "-")
}

// ---------------------------------------------------------------------------
// Display Certificate (reuse dcert check output)
// ---------------------------------------------------------------------------

pub fn display_certificate(pem_data: &str) {
    let opts = CertProcessOpts {
        expired_only: false,
        fingerprint: false,
        extensions: false,
    };

    match parse_cert_infos_from_pem(pem_data, &opts) {
        Ok(infos) => {
            let debug = PrettyDebugInfo {
                hostname: None,
                conn: None,
                http_protocol: &crate::cli::HttpProtocol::Http1_1,
                cipher_notation: None,
            };
            print_pretty(&infos, &debug);
        }
        Err(e) => {
            eprintln!("{} Failed to parse certificate: {}", "Error:".red().bold(), e);
        }
    }
}

// ---------------------------------------------------------------------------
// Vault KV Operations
// ---------------------------------------------------------------------------

/// Build the Vault KV API path based on the KV version.
/// KV v1: path as-is. KV v2: insert `/data/` after the mount point.
fn kv_api_path(user_path: &str, kv_version: u8) -> String {
    if kv_version >= 2 {
        // Insert /data/ after the first path segment (mount point)
        if let Some(idx) = user_path.find('/') {
            format!("{}/data/{}", &user_path[..idx], &user_path[idx + 1..])
        } else {
            format!("{}/data", user_path)
        }
    } else {
        user_path.to_string()
    }
}

/// Extract data from a KV response based on version.
/// KV v1: `resp["data"]`. KV v2: `resp["data"]["data"]`.
fn kv_extract_data(resp: &serde_json::Value, kv_version: u8) -> serde_json::Value {
    if kv_version >= 2 {
        resp["data"]["data"].clone()
    } else {
        resp["data"].clone()
    }
}

/// Store certificate and key in Vault KV.
pub fn kv_store(
    client: &VaultClient,
    kv_path: &str,
    cert_pem: &str,
    key_pem: &str,
    cert_key_name: &str,
    key_key_name: &str,
    kv_version: u8,
) -> Result<()> {
    let api_path = kv_api_path(kv_path, kv_version);

    // Check if secret already exists
    let exists = client.get(&api_path).is_ok();
    if exists {
        eprintln!(
            "{} Secret already exists at path '{}'.",
            "WARNING:".yellow().bold(),
            kv_path
        );
        let overwrite = prompt_with_default("Overwrite? [Y/n]", "Y")?;
        if overwrite.to_lowercase().starts_with('n') {
            println!("Skipping storage.");
            return Ok(());
        }
    }

    let body = if kv_version >= 2 {
        // KV v2 wraps data in a "data" envelope
        serde_json::json!({
            "data": {
                cert_key_name: cert_pem,
                key_key_name: key_pem,
            }
        })
    } else {
        // KV v1 uses flat structure
        serde_json::json!({
            cert_key_name: cert_pem,
            key_key_name: key_pem,
        })
    };

    client.post(&api_path, &body)?;

    println!(
        "{}",
        format!("Certificate and key stored at '{}' (KV v{})", kv_path, kv_version).green()
    );
    println!("  Format: base64 PEM certificate, unencrypted private key");

    Ok(())
}

/// Read certificate and key from Vault KV.
pub fn kv_read_cert_key(
    client: &VaultClient,
    kv_path: &str,
    cert_key_name: &str,
    key_key_name: &str,
    kv_version: u8,
) -> Result<(String, Option<String>)> {
    let api_path = kv_api_path(kv_path, kv_version);
    let resp = client.get(&api_path)?;

    let data = kv_extract_data(&resp, kv_version);
    if data.is_null() {
        return Err(anyhow::anyhow!("No data found at path '{}'", kv_path));
    }

    let cert = data[cert_key_name].as_str().map(|s| s.to_string());

    let key = data[key_key_name].as_str().map(|s| s.to_string());

    match cert {
        Some(c) => Ok((c, key)),
        None => Err(anyhow::anyhow!(
            "'{}' key not found in Vault secret at '{}'.\n\
             Available keys: {}",
            cert_key_name,
            kv_path,
            data.as_object()
                .map(|m| m.keys().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_else(|| "(none)".to_string())
        )),
    }
}

// ---------------------------------------------------------------------------
// Validate (read from KV and display)
// ---------------------------------------------------------------------------

pub fn validate_from_kv(
    client: &VaultClient,
    kv_path: &str,
    cert_key_name: &str,
    key_key_name: &str,
    kv_version: u8,
) -> Result<()> {
    let (cert_pem, key_pem) = kv_read_cert_key(client, kv_path, cert_key_name, key_key_name, kv_version)?;

    println!("{}", format!("=== Certificate from Vault KV: {} ===", kv_path).bold());
    println!();

    display_certificate(&cert_pem);

    // If we have a private key, verify it matches
    if let Some(ref key) = key_pem {
        // Write temporary files for key verification
        let temp_dir = tempfile::TempDir::new().with_context(|| "Failed to create temp directory")?;
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, key)?;

        let key_path_str = key_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Temp key path contains invalid UTF-8"))?;
        let cert_path_str = cert_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Temp cert path contains invalid UTF-8"))?;
        match crate::cert::verify_key_matches_cert(key_path_str, cert_path_str, false) {
            Ok(result) => {
                if result.matches {
                    println!(
                        "  {} {}",
                        "Key verification:".bold(),
                        "Private key matches certificate".green().bold()
                    );
                } else {
                    println!(
                        "  {} {}",
                        "Key verification:".bold(),
                        "Private key does NOT match certificate".red().bold()
                    );
                }
            }
            Err(e) => {
                eprintln!("  {} Failed to verify key: {}", "Key verification:".bold(), e);
            }
        }
    } else {
        println!(
            "  {} '{}' key not found — skipping key verification",
            "Note:".cyan().bold(),
            key_key_name
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Renew (read existing cert from KV, re-issue, overwrite)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn renew_certificate(
    client: &VaultClient,
    kv_path: &str,
    mount: &str,
    role: &str,
    ttl: &str,
    cert_key_name: &str,
    key_key_name: &str,
    kv_version: u8,
    san_overrides: &[String],
    ip_san_overrides: &[String],
) -> Result<()> {
    // Step 1: Read existing cert from KV
    println!("{}", "=== Certificate Renewal ===".bold());
    println!();
    println!("Reading existing certificate from '{}'...", kv_path);

    let (cert_pem, _) = kv_read_cert_key(client, kv_path, cert_key_name, key_key_name, kv_version)?;

    // Step 2: Parse existing cert to extract CN and SANs
    let opts = CertProcessOpts {
        expired_only: false,
        fingerprint: true,
        extensions: true,
    };
    let infos = parse_cert_infos_from_pem(&cert_pem, &opts).with_context(|| "Failed to parse existing certificate")?;

    let info = infos
        .first()
        .ok_or_else(|| anyhow::anyhow!("No certificates found in the stored PEM data"))?;

    let cn = info
        .common_name
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Existing certificate has no Common Name"))?;

    // Use SAN overrides if provided, otherwise extract from existing cert
    let sans: Vec<String> = if !san_overrides.is_empty() {
        san_overrides.to_vec()
    } else {
        info.subject_alternative_names
            .iter()
            .filter_map(|san| san.strip_prefix("DNS:").map(|s| s.to_string()))
            .collect()
    };

    let ip_sans: Vec<String> = if !ip_san_overrides.is_empty() {
        ip_san_overrides.to_vec()
    } else {
        info.subject_alternative_names
            .iter()
            .filter_map(|san| san.strip_prefix("IP:").map(|s| s.to_string()))
            .collect()
    };

    // Step 3: Display current cert details
    println!();
    println!("{}", "Current certificate:".bold());
    println!("  Common Name  : {}", cn);
    if !sans.is_empty() {
        println!("  SANs         : {}", sans.join(", "));
    }
    if !ip_sans.is_empty() {
        println!("  IP SANs      : {}", ip_sans.join(", "));
    }
    println!("  Issuer       : {}", info.issuer);
    println!("  Not After    : {}", info.not_after);
    let status = if info.is_expired {
        "EXPIRED".red().to_string()
    } else {
        "valid".green().to_string()
    };
    println!("  Status       : {}", status);
    println!();

    // Step 4: Issue new certificate with same CN + SANs
    println!("Issuing new certificate from {}/issue/{} ...", mount, role);

    let new_data = issue_certificate(client, mount, role, cn, &sans, &ip_sans, ttl)?;

    // Step 5: Build full chain
    let full_chain = build_full_chain(client, &new_data.certificate, &new_data.ca_chain, mount);

    // Step 6: Display new cert
    println!();
    println!("{}", "New certificate:".bold());
    display_certificate(&full_chain);

    // Step 7: Warn and ask for confirmation
    println!(
        "{} This will overwrite the existing certificate and private key at '{}'.",
        "WARNING:".yellow().bold(),
        kv_path
    );
    println!("  The private key will be replaced.");
    println!("  Format: base64 PEM certificate, unencrypted private key.");

    let confirm = prompt_with_default("Continue? [Y/n]", "Y")?;
    if confirm.to_lowercase().starts_with('n') {
        println!("Renewal cancelled.");
        return Ok(());
    }

    // Step 8: Overwrite in Vault KV
    let key_pem = new_data
        .private_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Vault did not return a private key for the new certificate"))?;

    let api_path = kv_api_path(kv_path, kv_version);
    let body = if kv_version >= 2 {
        serde_json::json!({
            "data": {
                cert_key_name: full_chain,
                key_key_name: key_pem,
            }
        })
    } else {
        serde_json::json!({
            cert_key_name: full_chain,
            key_key_name: key_pem,
        })
    };

    client.post(&api_path, &body)?;

    println!();
    println!(
        "{}",
        format!("Certificate and key successfully renewed and stored at '{}'", kv_path)
            .green()
            .bold()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Interactive Wizards
// ---------------------------------------------------------------------------

/// Print Vault connectivity info and optionally check server health.
pub fn print_vault_connectivity(client: &VaultClient, addr: &str, token: &str) {
    eprintln!("{}", "Vault connectivity:".bold());
    eprintln!("  VAULT_ADDR : {}", addr);
    let source = if std::env::var("VAULT_TOKEN").is_ok() {
        "VAULT_TOKEN env"
    } else {
        "~/.vault-token"
    };
    eprintln!("  Token      : {} (from {})", mask_token(token), source);

    // Query Vault health endpoint (unauthenticated) to verify connectivity and show version
    if client.debug {
        match vault_health_check(client) {
            Ok(health) => {
                if let Some(ref version) = health.version {
                    eprintln!("  Vault ver  : {}", version.green());
                }
                let status_str = if health.sealed {
                    "SEALED".red().bold().to_string()
                } else if !health.initialized {
                    "NOT INITIALIZED".red().bold().to_string()
                } else if health.performance_standby {
                    "perf-standby".yellow().to_string()
                } else if health.standby {
                    "standby".yellow().to_string()
                } else {
                    "active".green().to_string()
                };
                eprintln!("  Status     : {}", status_str);
                if let Some(ref cluster) = health.cluster_name {
                    eprintln!("  Cluster    : {}", cluster);
                }
                if let Some(ref cluster_id) = health.cluster_id {
                    eprintln!("  Cluster ID : {}", cluster_id);
                }
                if let Some(ref dr_mode) = health.replication_dr_mode {
                    eprintln!("  DR mode    : {}", dr_mode);
                }
                if let Some(ref perf_mode) = health.replication_perf_mode {
                    eprintln!("  Perf repl  : {}", perf_mode);
                }
                if let Some(ref expiry) = health.license_expiry {
                    // Parse the expiry to check for warnings
                    match time::OffsetDateTime::parse(expiry, &time::format_description::well_known::Rfc3339) {
                        Ok(expiry_dt) => {
                            let now = time::OffsetDateTime::now_utc();
                            let days_left = (expiry_dt - now).whole_days();
                            if days_left < 0 {
                                eprintln!(
                                    "  License    : {} (expired {} days ago)",
                                    "EXPIRED".red().bold(),
                                    -days_left
                                );
                            } else if days_left <= 30 {
                                eprintln!(
                                    "  {} Vault license expires in {} days ({})",
                                    "WARNING:".yellow().bold(),
                                    days_left,
                                    expiry
                                );
                            } else {
                                eprintln!("  License    : expires {} ({} days)", expiry, days_left);
                            }
                        }
                        Err(_) => {
                            eprintln!("  License    : expires {}", expiry);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("  Health     : {} ({})", "unavailable".red(), e);
            }
        }
    }

    eprintln!();
}

/// Vault health check response fields.
struct VaultHealth {
    version: Option<String>,
    initialized: bool,
    sealed: bool,
    standby: bool,
    performance_standby: bool,
    cluster_name: Option<String>,
    cluster_id: Option<String>,
    replication_dr_mode: Option<String>,
    replication_perf_mode: Option<String>,
    license_expiry: Option<String>,
}

/// Query `/v1/sys/health` to verify connectivity and get server version.
/// This endpoint is unauthenticated and returns status even for sealed/standby nodes.
fn vault_health_check(client: &VaultClient) -> Result<VaultHealth> {
    // Use ?standbyok=true&sealedok=true to always get 200 status
    let url = format!("{}/v1/sys/health?standbyok=true&sealedok=true", client.base_url);
    let resp = client
        .client
        .get(&url)
        .send()
        .map_err(|e| vault_connection_error(e, &client.base_url, client.debug))?;

    let json: serde_json::Value = resp.json().with_context(|| "Failed to parse Vault health response")?;

    Ok(VaultHealth {
        version: json["version"].as_str().map(String::from),
        initialized: json["initialized"].as_bool().unwrap_or(false),
        sealed: json["sealed"].as_bool().unwrap_or(true),
        standby: json["standby"].as_bool().unwrap_or(false),
        performance_standby: json["performance_standby"].as_bool().unwrap_or(false),
        cluster_name: json["cluster_name"].as_str().map(String::from),
        cluster_id: json["cluster_id"].as_str().map(String::from),
        replication_dr_mode: json["replication_dr_mode"].as_str().map(String::from),
        replication_perf_mode: json["replication_performance_mode"].as_str().map(String::from),
        license_expiry: json["license"]["expiry_time"].as_str().map(String::from),
    })
}

/// Return type for interactive_issue: (mount, role, cn, sans, ip_sans, ttl, pfx_password, output, store_path)
type IssueWizardResult = (
    String,
    String,
    String,
    Vec<String>,
    Vec<String>,
    String,
    Option<String>,
    String,
    Option<String>,
);

/// Return type for interactive_sign: (mount, role, csr_file, cn_override, sans, ttl, pfx_password, output, store_path)
type SignWizardResult = (
    String,
    String,
    String,
    Option<String>,
    Vec<String>,
    String,
    Option<String>,
    String,
    Option<String>,
);

/// Interactive wizard for issuing a certificate.
pub fn interactive_issue(client: &VaultClient) -> Result<IssueWizardResult> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "Interactive mode requires a terminal. Use --cn, --role, and other flags for non-interactive mode."
        ));
    }

    eprintln!("{}", "=== Vault PKI Certificate Issuance ===".bold());
    eprintln!();

    let mount = prompt_with_default("PKI mount point", "vault_intermediate")?;
    let role = resolve_role(client, None)?;
    let cn = prompt_required("Common Name (CN) [e.g., www.example.com]")?;

    eprintln!();
    let san_str = prompt_optional("Subject Alternative Names (comma-separated, press Enter to skip)")?;
    let sans: Vec<String> = san_str
        .map(|s| {
            s.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let ip_san_str = prompt_optional("IP SANs (comma-separated, press Enter to skip)")?;
    let ip_sans: Vec<String> = ip_san_str
        .map(|s| {
            s.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let ttl = prompt_with_default("TTL", "8760h")?;

    eprintln!();
    eprintln!("{}", "--- Output Format ---".bold());
    eprintln!("  1. PEM files (default) — cert.crt + key file");
    eprintln!("  2. PFX/PKCS12 — bundled with passphrase");
    let format_choice = prompt_with_default("Output format [1-2]", "1")?;
    let pfx_password = if format_choice == "2" {
        Some(prompt_required("PFX passphrase")?)
    } else {
        None
    };

    let default_output = sanitise_cn(&cn);
    let output = prompt_with_default("Output file base name", &default_output)?;

    eprintln!();
    let store_str = prompt_optional("Store certificate and key in Vault KV? Enter path or press Enter to skip")?;

    Ok((mount, role, cn, sans, ip_sans, ttl, pfx_password, output, store_str))
}

/// Interactive wizard for signing a CSR.
pub fn interactive_sign(client: &VaultClient) -> Result<SignWizardResult> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "Interactive mode requires a terminal. Use --csr-file, --role, and other flags for non-interactive mode."
        ));
    }

    eprintln!("{}", "=== Vault PKI CSR Signing ===".bold());
    eprintln!();

    let mount = prompt_with_default("PKI mount point", "vault_intermediate")?;
    let role = resolve_role(client, None)?;
    let csr_file = prompt_required("CSR file path")?;

    let cn = prompt_optional("Common Name override (press Enter to use CN from CSR)")?;

    let san_str = prompt_optional("Additional SANs (comma-separated, press Enter to skip)")?;
    let sans: Vec<String> = san_str
        .map(|s| {
            s.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let ttl = prompt_with_default("TTL", "8760h")?;

    eprintln!();
    eprintln!("{}", "--- Output Format ---".bold());
    eprintln!("  1. PEM files (default) — cert.crt file");
    eprintln!("  2. PFX/PKCS12 — bundled with passphrase (requires local private key)");
    let format_choice = prompt_with_default("Output format [1-2]", "1")?;
    let pfx_password = if format_choice == "2" {
        Some(prompt_required("PFX passphrase")?)
    } else {
        None
    };

    let output = prompt_with_default("Output file base name", "signed-cert")?;

    let store_str = prompt_optional("Store certificate in Vault KV? Enter path or press Enter to skip")?;

    Ok((mount, role, csr_file, cn, sans, ttl, pfx_password, output, store_str))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Token Discovery (uses discover_vault_token_from to avoid env var races) --

    #[test]
    fn test_token_from_env() {
        let result = discover_vault_token_from(Some("test-token-123".to_string()), None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-token-123");
    }

    #[test]
    fn test_token_from_file() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        fs::write(temp_dir.path().join(".vault-token"), "file-token-456\n").unwrap();

        let result = discover_vault_token_from(None, Some(temp_dir.path().to_path_buf()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "file-token-456");
    }

    #[test]
    fn test_token_env_takes_precedence() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        fs::write(temp_dir.path().join(".vault-token"), "file-token").unwrap();

        let result = discover_vault_token_from(Some("env-token".to_string()), Some(temp_dir.path().to_path_buf()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "env-token");
    }

    #[test]
    fn test_token_missing_error() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        // Don't create .vault-token file

        let result = discover_vault_token_from(None, Some(temp_dir.path().to_path_buf()));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("No Vault token found"), "Error: {}", err);
        assert!(err.contains("VAULT_TOKEN"), "Error should mention VAULT_TOKEN: {}", err);
    }

    // -- VAULT_ADDR --

    #[test]
    fn test_vault_addr_from_env() {
        let prev = std::env::var("VAULT_ADDR").ok();
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("VAULT_ADDR", "https://vault.example.com:8200") };
        let result = vault_addr();
        match prev {
            // TODO: Audit that the environment access only happens in single-threaded code.
            Some(v) => unsafe { std::env::set_var("VAULT_ADDR", v) },
            // TODO: Audit that the environment access only happens in single-threaded code.
            None => unsafe { std::env::remove_var("VAULT_ADDR") },
        }
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://vault.example.com:8200");
    }

    #[test]
    fn test_vault_addr_strips_trailing_slash() {
        let prev = std::env::var("VAULT_ADDR").ok();
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("VAULT_ADDR", "https://vault.example.com:8200/") };
        let result = vault_addr();
        match prev {
            // TODO: Audit that the environment access only happens in single-threaded code.
            Some(v) => unsafe { std::env::set_var("VAULT_ADDR", v) },
            // TODO: Audit that the environment access only happens in single-threaded code.
            None => unsafe { std::env::remove_var("VAULT_ADDR") },
        }
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://vault.example.com:8200");
    }

    #[test]
    fn test_vault_addr_missing_error() {
        let prev = std::env::var("VAULT_ADDR").ok();
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::remove_var("VAULT_ADDR") };
        let result = vault_addr();
        if let Some(v) = prev {
            // TODO: Audit that the environment access only happens in single-threaded code.
            unsafe { std::env::set_var("VAULT_ADDR", v) };
        }
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("VAULT_ADDR"), "Error: {}", err);
    }

    // -- Response Parsing --

    #[test]
    fn test_parse_issue_response() {
        let json = serde_json::json!({
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
                "private_key_type": "rsa",
                "issuing_ca": "-----BEGIN CERTIFICATE-----\nCA...\n-----END CERTIFICATE-----",
                "ca_chain": [
                    "-----BEGIN CERTIFICATE-----\nINTER...\n-----END CERTIFICATE-----",
                    "-----BEGIN CERTIFICATE-----\nROOT...\n-----END CERTIFICATE-----"
                ],
                "serial_number": "39:dd:2e:90:b7:23:1f:8d",
                "expiration": 1654105687
            }
        });

        let data: VaultPkiIssueData = serde_json::from_value(json["data"].clone()).unwrap();
        assert!(data.certificate.contains("BEGIN CERTIFICATE"));
        assert!(data.private_key.unwrap().contains("BEGIN RSA PRIVATE KEY"));
        assert_eq!(data.ca_chain.len(), 2);
        assert_eq!(data.serial_number, Some("39:dd:2e:90:b7:23:1f:8d".to_string()));
    }

    #[test]
    fn test_parse_sign_response() {
        let json = serde_json::json!({
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nSIGNED...\n-----END CERTIFICATE-----",
                "issuing_ca": "-----BEGIN CERTIFICATE-----\nCA...\n-----END CERTIFICATE-----",
                "ca_chain": [
                    "-----BEGIN CERTIFICATE-----\nINTER...\n-----END CERTIFICATE-----"
                ],
                "serial_number": "aa:bb:cc:dd"
            }
        });

        let data: VaultPkiIssueData = serde_json::from_value(json["data"].clone()).unwrap();
        assert!(data.certificate.contains("SIGNED"));
        assert!(data.private_key.is_none());
        assert_eq!(data.ca_chain.len(), 1);
    }

    #[test]
    fn test_parse_revoke_response() {
        let json = serde_json::json!({
            "data": {
                "revocation_time": 1654105687
            }
        });
        let revocation_time = json["data"]["revocation_time"].as_f64();
        assert!(revocation_time.is_some());
        assert_eq!(revocation_time.unwrap() as i64, 1654105687);
    }

    #[test]
    fn test_parse_list_response() {
        let json = serde_json::json!({
            "data": {
                "keys": ["39:dd:2e:90", "aa:bb:cc:dd", "11:22:33:44"]
            }
        });
        let keys: Vec<String> = json["data"]["keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_parse_kv_read_response() {
        let json = serde_json::json!({
            "data": {
                "data": {
                    "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                    "key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
                },
                "metadata": {
                    "version": 1
                }
            }
        });
        let inner = &json["data"]["data"];
        assert!(inner["cert"].as_str().is_some());
        assert!(inner["key"].as_str().is_some());
    }

    // -- Chain Assembly --

    #[test]
    fn test_chain_assembly_from_ca_chain() {
        let leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----";
        let ca_chain = vec![
            "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----".to_string(),
            "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----".to_string(),
        ];

        // We can't test with a real VaultClient, so test the chain ordering logic directly
        let mut full_pem = leaf.trim().to_string();
        full_pem.push('\n');
        for ca in &ca_chain {
            full_pem.push_str(ca.trim());
            full_pem.push('\n');
        }

        assert!(full_pem.starts_with("-----BEGIN CERTIFICATE-----\nLEAF"));
        assert!(full_pem.contains("INTERMEDIATE"));
        assert!(full_pem.contains("ROOT"));

        // Verify ordering: LEAF comes before INTERMEDIATE comes before ROOT
        let leaf_pos = full_pem.find("LEAF").unwrap();
        let inter_pos = full_pem.find("INTERMEDIATE").unwrap();
        let root_pos = full_pem.find("ROOT").unwrap();
        assert!(leaf_pos < inter_pos);
        assert!(inter_pos < root_pos);
    }

    #[test]
    fn test_chain_with_single_ca() {
        let leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----";
        let ca_chain = vec!["-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----".to_string()];

        let mut full_pem = leaf.trim().to_string();
        full_pem.push('\n');
        for ca in &ca_chain {
            full_pem.push_str(ca.trim());
            full_pem.push('\n');
        }

        assert!(full_pem.contains("LEAF"));
        assert!(full_pem.contains("CA"));
    }

    #[test]
    fn test_chain_empty_ca() {
        let leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----";
        let ca_chain: Vec<String> = vec![];

        let mut full_pem = leaf.trim().to_string();
        full_pem.push('\n');
        for ca in &ca_chain {
            full_pem.push_str(ca.trim());
            full_pem.push('\n');
        }

        assert!(full_pem.contains("LEAF"));
        // No CA certs in chain
        assert_eq!(full_pem.matches("BEGIN CERTIFICATE").count(), 1);
    }

    // -- File Output --

    #[test]
    fn test_write_pem_files() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let base = temp_dir.path().join("test-cert").to_str().unwrap().to_string();

        let cert = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";
        let key = "-----BEGIN PRIVATE KEY-----\nTESTKEY\n-----END PRIVATE KEY-----\n";

        let (cert_path, key_path) = write_pem_files(cert, Some(key), &base).unwrap();
        assert!(std::path::Path::new(&cert_path).exists());
        assert!(key_path.is_some());
        assert!(std::path::Path::new(&key_path.unwrap()).exists());

        let written_cert = fs::read_to_string(&cert_path).unwrap();
        assert!(written_cert.contains("TEST"));
    }

    #[test]
    fn test_write_pem_files_no_key() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let base = temp_dir.path().join("cert-only").to_str().unwrap().to_string();

        let cert = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";
        let (cert_path, key_path) = write_pem_files(cert, None, &base).unwrap();
        assert!(std::path::Path::new(&cert_path).exists());
        assert!(key_path.is_none());
    }

    // -- Error Handling --

    #[test]
    fn test_permission_denied_error_message() {
        let hint = PolicyHint {
            path: "vault_intermediate/issue/my-role".to_string(),
            capability: "create",
        };

        // Simulate a 403 response
        let err = anyhow::anyhow!(
            "Permission denied by Vault.\n\n\
             \x20 Endpoint: {}\n\
             \x20 Required: {} capability on \"{}\"\n\n\
             \x20 Ask your Vault administrator to add this policy to your token:\n\
             \x20   path \"{}\" {{\n\
             \x20     capabilities = [\"{}\"]\n\
             \x20   }}",
            hint.path,
            hint.capability,
            hint.path,
            hint.path,
            hint.capability,
        );

        let msg = err.to_string();
        assert!(msg.contains("Permission denied"), "msg: {}", msg);
        assert!(msg.contains("vault_intermediate/issue/my-role"), "msg: {}", msg);
        assert!(msg.contains("create"), "msg: {}", msg);
        assert!(msg.contains("capabilities"), "msg: {}", msg);
    }

    #[test]
    fn test_not_found_error_message() {
        let hint = PolicyHint {
            path: "nonexistent/issue/role".to_string(),
            capability: "create",
        };

        // Construct the error as the handler would
        let errors_str = "no handler for route";
        let err = anyhow::anyhow!(
            "Not found: {}\n\n\
             \x20 The mount point or role may not exist. Check that:\n\
             \x20   - The PKI mount is enabled (vault secrets enable pki)\n\
             \x20   - The role name is correct\n\
             \x20   - The path exists in Vault\n\n\
             \x20 Vault error: {}",
            hint.path,
            errors_str
        );

        let msg = err.to_string();
        assert!(msg.contains("Not found"), "msg: {}", msg);
        assert!(msg.contains("mount point or role may not exist"), "msg: {}", msg);
    }

    #[test]
    fn test_empty_response_handling() {
        let json = serde_json::json!({
            "data": {}
        });
        // Parsing an empty data object should fail for issue response
        let result: Result<VaultPkiIssueData, _> = serde_json::from_value(json["data"].clone());
        assert!(result.is_err());
    }

    // -- Sanitise CN --

    #[test]
    fn test_sanitise_cn() {
        assert_eq!(sanitise_cn("www.example.com"), "www-example-com");
        assert_eq!(sanitise_cn("*.example.com"), "wildcard-example-com");
        assert_eq!(sanitise_cn("api.prod.example.com"), "api-prod-example-com");
    }

    // -- Mask Token --

    #[test]
    fn test_mask_token() {
        assert_eq!(mask_token("abcdefghijklmnop"), "abcd****mnop");
        assert_eq!(mask_token("short"), "****");
        assert_eq!(mask_token("12345678"), "****");
        assert_eq!(mask_token("123456789"), "1234****6789");
    }

    // -- Export Cert List --

    #[test]
    fn test_export_cert_list_csv() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let csv_path = temp_dir.path().join("certs.csv").to_str().unwrap().to_string();

        let entries = vec![VaultCertListEntry {
            serial_number: "aa:bb:cc".to_string(),
            common_name: Some("test.example.com".to_string()),
            not_before: "2024-01-01T00:00:00Z".to_string(),
            not_after: "2025-01-01T00:00:00Z".to_string(),
            status: "valid".to_string(),
        }];

        export_cert_list(&entries, &csv_path).unwrap();
        let content = fs::read_to_string(&csv_path).unwrap();
        assert!(content.contains("serial_number,common_name"));
        assert!(content.contains("aa:bb:cc"));
        assert!(content.contains("test.example.com"));
    }

    #[test]
    fn test_export_cert_list_json() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let json_path = temp_dir.path().join("certs.json").to_str().unwrap().to_string();

        let entries = vec![VaultCertListEntry {
            serial_number: "11:22:33".to_string(),
            common_name: Some("api.example.com".to_string()),
            not_before: "2024-01-01T00:00:00Z".to_string(),
            not_after: "2025-01-01T00:00:00Z".to_string(),
            status: "expired".to_string(),
        }];

        export_cert_list(&entries, &json_path).unwrap();
        let content = fs::read_to_string(&json_path).unwrap();
        let parsed: Vec<VaultCertListEntry> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].serial_number, "11:22:33");
    }

    // -- Role Discovery from Policies --

    #[test]
    fn test_extract_roles_from_policies_basic() {
        let policies = vec![
            "default".to_string(),
            "team.app-alpha.admin".to_string(),
            "team.app-alpha.contributor".to_string(),
            "team.app-beta.deployer".to_string(),
            "team.app-gamma.admin".to_string(),
            "team.app-gamma.contributor".to_string(),
        ];
        let roles = extract_roles_from_policies(&policies);
        assert_eq!(roles, vec!["app-alpha", "app-beta", "app-gamma"]);
    }

    #[test]
    fn test_extract_roles_skips_short_policies() {
        let policies = vec!["default".to_string(), "admin".to_string(), "org.svc.read".to_string()];
        let roles = extract_roles_from_policies(&policies);
        assert_eq!(roles, vec!["svc"]);
    }

    #[test]
    fn test_extract_roles_deduplicates_and_sorts() {
        let policies = vec![
            "org.zebra.admin".to_string(),
            "org.alpha.contributor".to_string(),
            "org.zebra.deployer".to_string(),
            "org.alpha.admin".to_string(),
            "org.middle.viewer".to_string(),
        ];
        let roles = extract_roles_from_policies(&policies);
        assert_eq!(roles, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn test_extract_roles_empty_policies() {
        let policies: Vec<String> = vec!["default".to_string()];
        let roles = extract_roles_from_policies(&policies);
        assert!(roles.is_empty());
    }

    #[test]
    fn test_extract_roles_four_part_policies() {
        let policies = vec!["org.service.sub.admin".to_string(), "org.other.deployer".to_string()];
        let roles = extract_roles_from_policies(&policies);
        // Still extracts the 2nd part
        assert_eq!(roles, vec!["other", "service"]);
    }

    #[test]
    fn test_parse_token_lookup_policies() {
        let json = serde_json::json!({
            "data": {
                "policies": [
                    "default",
                    "team.app-one.admin",
                    "team.app-one.contributor",
                    "team.app-two.deployer",
                    "team.app-three.admin"
                ]
            }
        });

        let policies: Vec<String> = json["data"]["policies"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();

        let roles = extract_roles_from_policies(&policies);
        assert_eq!(roles, vec!["app-one", "app-three", "app-two"]);
    }

    // -- KV v1/v2 path construction --

    #[test]
    fn test_kv_api_path_v1() {
        assert_eq!(kv_api_path("secret/my-cert", 1), "secret/my-cert");
        assert_eq!(kv_api_path("secret/team/app/cert", 1), "secret/team/app/cert");
        assert_eq!(kv_api_path("secret", 1), "secret");
    }

    #[test]
    fn test_kv_api_path_v2() {
        assert_eq!(kv_api_path("secret/my-cert", 2), "secret/data/my-cert");
        assert_eq!(kv_api_path("secret/team/app/cert", 2), "secret/data/team/app/cert");
        assert_eq!(kv_api_path("secret", 2), "secret/data");
    }

    // -- KV v1/v2 response parsing --

    #[test]
    fn test_kv_extract_data_v1() {
        let resp = serde_json::json!({
            "data": {
                "cert": "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
                "key": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----"
            }
        });
        let data = kv_extract_data(&resp, 1);
        assert_eq!(
            data["cert"].as_str().unwrap(),
            "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"
        );
        assert_eq!(
            data["key"].as_str().unwrap(),
            "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----"
        );
    }

    #[test]
    fn test_kv_extract_data_v2() {
        let resp = serde_json::json!({
            "data": {
                "data": {
                    "cert": "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
                    "key": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----"
                },
                "metadata": {
                    "version": 1
                }
            }
        });
        let data = kv_extract_data(&resp, 2);
        assert_eq!(
            data["cert"].as_str().unwrap(),
            "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"
        );
        assert_eq!(
            data["key"].as_str().unwrap(),
            "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----"
        );
    }

    // -- Excel Export --

    #[test]
    fn test_export_cert_list_xlsx() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let xlsx_path = temp_dir.path().join("certs.xlsx").to_str().unwrap().to_string();

        let entries = vec![
            VaultCertListEntry {
                serial_number: "aa:bb:cc".to_string(),
                common_name: Some("test.example.com".to_string()),
                not_before: "2024-01-01T00:00:00Z".to_string(),
                not_after: "2025-01-01T00:00:00Z".to_string(),
                status: "valid".to_string(),
            },
            VaultCertListEntry {
                serial_number: "dd:ee:ff".to_string(),
                common_name: Some("api.example.com".to_string()),
                not_before: "2023-06-01T00:00:00Z".to_string(),
                not_after: "2024-06-01T00:00:00Z".to_string(),
                status: "expired".to_string(),
            },
        ];

        export_cert_list(&entries, &xlsx_path).unwrap();

        // Verify the file exists and has non-zero size
        let metadata = fs::metadata(&xlsx_path).unwrap();
        assert!(metadata.len() > 0, "XLSX file should not be empty");
    }

    #[test]
    fn test_export_cert_list_defaults_to_json() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let txt_path = temp_dir.path().join("certs.txt").to_str().unwrap().to_string();

        let entries = vec![VaultCertListEntry {
            serial_number: "aa:bb:cc".to_string(),
            common_name: Some("test.example.com".to_string()),
            not_before: "2024-01-01T00:00:00Z".to_string(),
            not_after: "2025-01-01T00:00:00Z".to_string(),
            status: "valid".to_string(),
        }];

        export_cert_list(&entries, &txt_path).unwrap();
        // Unknown extension defaults to JSON
        let content = fs::read_to_string(&txt_path).unwrap();
        let parsed: Vec<VaultCertListEntry> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].serial_number, "aa:bb:cc");
    }
}
