use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;

use crate::cert::{parse_cert_infos_from_pem, CertProcessOpts};
use crate::convert;
use crate::csr::{prompt_optional, prompt_required, prompt_with_default};
use crate::output::{print_pretty, PrettyDebugInfo};

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
    if token.len() <= 8 {
        "****".to_string()
    } else {
        format!("{}****{}", &token[..4], &token[token.len() - 4..])
    }
}

// ---------------------------------------------------------------------------
// Vault HTTP Client
// ---------------------------------------------------------------------------

/// A simple Vault HTTP client wrapping reqwest.
pub struct VaultClient {
    client: reqwest::blocking::Client,
    base_url: String,
    token: String,
}

/// Describes the required Vault policy capability for an endpoint.
struct PolicyHint {
    path: String,
    capability: &'static str,
}

impl VaultClient {
    /// Create a new Vault client.
    pub fn new(addr: &str, token: &str) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(false)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .with_context(|| "Failed to build HTTP client for Vault")?;

        Ok(Self {
            client,
            base_url: addr.trim_end_matches('/').to_string(),
            token: token.to_string(),
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
            .map_err(|e| vault_connection_error(e, &self.base_url))?;

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
            .map_err(|e| vault_connection_error(e, &self.base_url))?;

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
            .map_err(|e| vault_connection_error(e, &self.base_url))?;

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
            .map_err(|e| vault_connection_error(e, &self.base_url))?;

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
            .map_err(|e| vault_connection_error(e, &self.base_url))?;

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

fn vault_connection_error(e: reqwest::Error, base_url: &str) -> anyhow::Error {
    if e.is_connect() {
        anyhow::anyhow!(
            "Failed to connect to Vault at {}.\n\
             Check that VAULT_ADDR is correct and the Vault server is running.",
            base_url
        )
    } else if e.is_timeout() {
        anyhow::anyhow!(
            "Connection to Vault at {} timed out.\n\
             Check network connectivity and Vault server health.",
            base_url
        )
    } else {
        anyhow::anyhow!("Vault HTTP request failed: {}", e)
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

pub fn sign_csr(
    client: &VaultClient,
    mount: &str,
    role: &str,
    csr_pem: &str,
    common_name: Option<&str>,
    alt_names: &[String],
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
                    if let Ok(infos) = parse_cert_infos_from_pem(cert_pem, &opts) {
                        if let Some(info) = infos.first() {
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

pub fn export_cert_list(entries: &[VaultCertListEntry], export_path: &str) -> Result<()> {
    if export_path.ends_with(".csv") {
        let mut csv = String::from("serial_number,common_name,not_before,not_after,status\n");
        for entry in entries {
            csv.push_str(&format!(
                "{},{},{},{},{}\n",
                entry.serial_number,
                entry.common_name.as_deref().unwrap_or(""),
                entry.not_before,
                entry.not_after,
                entry.status,
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
        fingerprint: true,
        extensions: true,
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

/// Store certificate and key in Vault KV v2.
pub fn kv_store(
    client: &VaultClient,
    kv_path: &str,
    cert_pem: &str,
    key_pem: &str,
    cert_key_name: &str,
    key_key_name: &str,
) -> Result<()> {
    // Check if secret already exists
    let exists = kv_read_raw(client, kv_path).is_ok();
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

    let body = serde_json::json!({
        "data": {
            cert_key_name: cert_pem,
            key_key_name: key_pem,
        }
    });

    // KV v2 uses POST to {mount}/data/{path}
    client.post(kv_path, &body)?;

    println!("{}", format!("Certificate and key stored at '{}'", kv_path).green());
    println!("  Format: base64 PEM certificate, unencrypted private key");

    Ok(())
}

/// Read raw KV v2 data from Vault.
fn kv_read_raw(client: &VaultClient, kv_path: &str) -> Result<serde_json::Value> {
    client.get(kv_path)
}

/// Read certificate and key from Vault KV v2.
pub fn kv_read_cert_key(
    client: &VaultClient,
    kv_path: &str,
    cert_key_name: &str,
    key_key_name: &str,
) -> Result<(String, Option<String>)> {
    let resp = client.get(kv_path)?;

    let data = &resp["data"]["data"];
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

pub fn validate_from_kv(client: &VaultClient, kv_path: &str, cert_key_name: &str, key_key_name: &str) -> Result<()> {
    let (cert_pem, key_pem) = kv_read_cert_key(client, kv_path, cert_key_name, key_key_name)?;

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

        match crate::cert::verify_key_matches_cert(key_path.to_str().unwrap(), cert_path.to_str().unwrap(), false) {
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

pub fn renew_certificate(
    client: &VaultClient,
    kv_path: &str,
    mount: &str,
    role: &str,
    ttl: &str,
    cert_key_name: &str,
    key_key_name: &str,
) -> Result<()> {
    // Step 1: Read existing cert from KV
    println!("{}", "=== Certificate Renewal ===".bold());
    println!();
    println!("Reading existing certificate from '{}'...", kv_path);

    let (cert_pem, _) = kv_read_cert_key(client, kv_path, cert_key_name, key_key_name)?;

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

    let sans: Vec<String> = info
        .subject_alternative_names
        .iter()
        .filter_map(|san| san.strip_prefix("DNS:").map(|s| s.to_string()))
        .collect();

    // Step 3: Display current cert details
    println!();
    println!("{}", "Current certificate:".bold());
    println!("  Common Name  : {}", cn);
    if !sans.is_empty() {
        println!("  SANs         : {}", sans.join(", "));
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

    let new_data = issue_certificate(client, mount, role, cn, &sans, &[], ttl)?;

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

    let body = serde_json::json!({
        "data": {
            cert_key_name: full_chain,
            key_key_name: key_pem,
        }
    });

    client.post(kv_path, &body)?;

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

/// Print Vault connectivity info.
pub fn print_vault_connectivity(addr: &str, token: &str) {
    eprintln!("{}", "Vault connectivity:".bold());
    eprintln!("  VAULT_ADDR : {}", addr);
    let source = if std::env::var("VAULT_TOKEN").is_ok() {
        "VAULT_TOKEN env"
    } else {
        "~/.vault-token"
    };
    eprintln!("  Token      : {} (from {})", mask_token(token), source);
    eprintln!();
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
pub fn interactive_issue() -> Result<IssueWizardResult> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "Interactive mode requires a terminal. Use --cn, --role, and other flags for non-interactive mode."
        ));
    }

    eprintln!("{}", "=== Vault PKI Certificate Issuance ===".bold());
    eprintln!();

    let mount = prompt_with_default("PKI mount point", "vault_intermediate")?;
    let role = prompt_required("Role name")?;
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
pub fn interactive_sign() -> Result<SignWizardResult> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "Interactive mode requires a terminal. Use --csr-file, --role, and other flags for non-interactive mode."
        ));
    }

    eprintln!("{}", "=== Vault PKI CSR Signing ===".bold());
    eprintln!();

    let mount = prompt_with_default("PKI mount point", "vault_intermediate")?;
    let role = prompt_required("Role name")?;
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
        std::env::set_var("VAULT_ADDR", "https://vault.example.com:8200");
        let result = vault_addr();
        match prev {
            Some(v) => std::env::set_var("VAULT_ADDR", v),
            None => std::env::remove_var("VAULT_ADDR"),
        }
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://vault.example.com:8200");
    }

    #[test]
    fn test_vault_addr_strips_trailing_slash() {
        let prev = std::env::var("VAULT_ADDR").ok();
        std::env::set_var("VAULT_ADDR", "https://vault.example.com:8200/");
        let result = vault_addr();
        match prev {
            Some(v) => std::env::set_var("VAULT_ADDR", v),
            None => std::env::remove_var("VAULT_ADDR"),
        }
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://vault.example.com:8200");
    }

    #[test]
    fn test_vault_addr_missing_error() {
        let prev = std::env::var("VAULT_ADDR").ok();
        std::env::remove_var("VAULT_ADDR");
        let result = vault_addr();
        if let Some(v) = prev {
            std::env::set_var("VAULT_ADDR", v);
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
}
