//! HashiCorp Vault PKI tools.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use super::{DcertMcpServer, ok_error, ok_text};
use crate::exec::format_tool_output;
use crate::params_vault::*;
use crate::validate::*;

/// Reply to a Vault tool call with the subprocess output, or with the reason
/// it could not run.
fn vault_reply(outcome: Result<(String, String, i32), String>) -> Result<CallToolResult, rmcp::ErrorData> {
    match outcome {
        Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "debug/stderr", &[0])),
        Err(e) => ok_error(e),
    }
}

/// Check a Vault KV path parameter with the same rules the CLI applies, so a
/// path such as `secret/../sys/policies/acl/root` is refused here rather than
/// reaching an arbitrary Vault endpoint with the server's token.
fn validate_kv_path_param(path: &str, param_name: &str) -> Result<(), String> {
    dcert::vault::validate_kv_path(path)
        .map(|_| ())
        .map_err(|e| format!("Invalid {param_name}: {e}"))
}

/// `output` is a base name: dcert appends `.crt`, `.key` or `.pfx` to it. Each
/// file that can result must lie inside the allowed roots, like every other
/// file parameter.
///
/// Returns the canonical base to pass to the child.
fn validate_output_base(output: &str) -> Result<String, String> {
    let base = validate_path(output, "output")?;
    for ext in ["crt", "key", "pfx"] {
        validate_path(&format!("{base}.{ext}"), "output")?;
    }
    Ok(base)
}

/// Replace an optional output base with its canonical form.
fn resolve_output_base(output: &mut Option<String>) -> Result<(), String> {
    if let Some(base) = output.as_mut() {
        *base = validate_output_base(base)?;
    }
    Ok(())
}

/// The PKI issuance flags shared by `vault_issue`, `vault_sign` and
/// `vault_renew`.
struct PkiArgs<'a> {
    role: Option<&'a str>,
    sans: &'a [String],
    ip_sans: &'a [String],
    output: Option<&'a str>,
    store_path: Option<&'a str>,
    kv_version: u8,
}

/// Append `--role`, `--san`, `--ip-san`, `--output` and, when a store path
/// is given, `--store-path` with its `--kv-version`.
fn push_pki_args(args: &mut Vec<String>, pki: &PkiArgs<'_>) {
    if let Some(role) = pki.role {
        args.push("--role".to_string());
        args.push(role.to_string());
    }
    for san in pki.sans {
        args.push("--san".to_string());
        args.push(san.clone());
    }
    for ip in pki.ip_sans {
        args.push("--ip-san".to_string());
        args.push(ip.clone());
    }
    if let Some(output) = pki.output {
        args.push("--output".to_string());
        args.push(output.to_string());
    }
    if let Some(store_path) = pki.store_path {
        args.push("--store-path".to_string());
        args.push(store_path.to_string());
        args.push("--kv-version".to_string());
        args.push(pki.kv_version.to_string());
    }
}

#[tool_router(router = vault_tool_router, vis = "pub(crate)")]
impl DcertMcpServer {
    // ===================================================================
    // Vault PKI Tools
    // ===================================================================

    /// Issue a new TLS certificate from HashiCorp Vault PKI.
    #[tool(
        title = "Vault: Issue Certificate",
        description = "Issue a new TLS certificate from HashiCorp Vault PKI. Generates a private key and certificate signed by the Vault PKI CA. Supports DNS and IP SANs, configurable TTL, PEM or PFX output, and optional KV storage. Requires Vault connectivity (vault_addr + authentication). Supports token, LDAP, and AppRole auth methods.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn vault_issue(
        &self,
        Parameters(mut params): Parameters<VaultIssueParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if let Err(e) = validate_args(&[
            ("common_name", Some(params.common_name.as_str())),
            ("mount", Some(params.mount.as_str())),
            ("ttl", Some(params.ttl.as_str())),
            ("role", params.role.as_deref()),
            ("output", params.output.as_deref()),
            ("store_path", params.store_path.as_deref()),
        ])
        .and_then(|()| validate_list(&params.sans, "sans", 100))
        .and_then(|()| validate_list(&params.ip_sans, "ip_sans", 100))
        .and_then(|()| validate_kv_version(params.kv_version))
        .and_then(|()| resolve_output_base(&mut params.output))
        .and_then(|()| {
            params
                .store_path
                .as_deref()
                .map_or(Ok(()), |p| validate_kv_path_param(p, "store_path"))
        }) {
            return ok_error(e);
        }

        let mut args: Vec<String> = vec![
            "issue".to_string(),
            "--cn".to_string(),
            params.common_name.clone(),
            "--mount".to_string(),
            params.mount.clone(),
            "--ttl".to_string(),
            params.ttl.clone(),
            "--format".to_string(),
            "json".to_string(),
        ];
        push_pki_args(
            &mut args,
            &PkiArgs {
                role: params.role.as_deref(),
                sans: &params.sans,
                ip_sans: &params.ip_sans,
                output: params.output.as_deref(),
                store_path: params.store_path.as_deref(),
                kv_version: params.kv_version,
            },
        );
        // The PFX passphrase travels in the environment, never in argv.
        let mut extra_env: Vec<(&str, &str)> = Vec::new();
        if let Some(ref pfx_pw) = params.pfx_password {
            extra_env.push(("DCERT_CERT_PASSWORD", pfx_pw.as_str()));
        }

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        vault_reply(run_dcert_vault(&args_refs, &params.vault, &self.config, &extra_env).await)
    }

    /// Sign a Certificate Signing Request (CSR) using Vault PKI.
    #[tool(
        title = "Vault: Sign CSR",
        description = "Sign a Certificate Signing Request (CSR) using HashiCorp Vault PKI. Takes a PEM-encoded CSR file and returns a signed certificate with the full CA chain. Supports CN override, SANs, and optional KV storage. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn vault_sign(
        &self,
        Parameters(mut params): Parameters<VaultSignParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if let Err(e) = validate_args(&[
            ("mount", Some(params.mount.as_str())),
            ("ttl", Some(params.ttl.as_str())),
            ("role", params.role.as_deref()),
            ("common_name", params.common_name.as_deref()),
            ("output", params.output.as_deref()),
            ("store_path", params.store_path.as_deref()),
        ])
        .and_then(|()| validate_list(&params.sans, "sans", 100))
        .and_then(|()| validate_list(&params.ip_sans, "ip_sans", 100))
        .and_then(|()| validate_kv_version(params.kv_version))
        .and_then(|()| validate_path(&params.csr_file, "csr_file"))
        .map(|p| params.csr_file = p)
        .and_then(|()| resolve_output_base(&mut params.output))
        .and_then(|()| {
            params
                .store_path
                .as_deref()
                .map_or(Ok(()), |p| validate_kv_path_param(p, "store_path"))
        }) {
            return ok_error(e);
        }

        let mut args: Vec<String> = vec![
            "sign".to_string(),
            "--csr-file".to_string(),
            params.csr_file.clone(),
            "--mount".to_string(),
            params.mount.clone(),
            "--ttl".to_string(),
            params.ttl.clone(),
            "--format".to_string(),
            "json".to_string(),
        ];
        if let Some(ref cn) = params.common_name {
            args.push("--cn".to_string());
            args.push(cn.clone());
        }
        push_pki_args(
            &mut args,
            &PkiArgs {
                role: params.role.as_deref(),
                sans: &params.sans,
                ip_sans: &params.ip_sans,
                output: params.output.as_deref(),
                store_path: params.store_path.as_deref(),
                kv_version: params.kv_version,
            },
        );

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        vault_reply(run_dcert_vault(&args_refs, &params.vault, &self.config, &[]).await)
    }

    /// Revoke a certificate in Vault PKI by serial number or PEM file.
    #[tool(
        title = "Vault: Revoke Certificate",
        description = "Revoke a TLS certificate in HashiCorp Vault PKI. Specify either the serial number (hex) or a PEM certificate file path. The certificate is added to the CRL. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn vault_revoke(
        &self,
        Parameters(mut params): Parameters<VaultRevokeParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if let Err(e) = validate_args(&[
            ("mount", Some(params.mount.as_str())),
            ("serial", params.serial.as_deref()),
        ]) {
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
            match validate_path(cert, "cert_file") {
                Ok(cert) => {
                    args.push("--cert-file".to_string());
                    args.push(cert);
                }
                Err(e) => return ok_error(e),
            }
        }

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        vault_reply(run_dcert_vault(&args_refs, &params.vault, &self.config, &[]).await)
    }

    /// List all certificates issued by Vault PKI.
    #[tool(
        title = "Vault: List Certificates",
        description = "List all certificates issued by HashiCorp Vault PKI with optional filtering by expired/valid status. Supports export to JSON, CSV, or XLSX files. Returns serial numbers, common names, expiry dates, and status. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn vault_list(
        &self,
        Parameters(mut params): Parameters<VaultListParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if let Err(e) = validate_args(&[("mount", Some(params.mount.as_str()))]) {
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
            match validate_path(export, "export") {
                Ok(export) => {
                    args.push("--export".to_string());
                    args.push(export);
                }
                Err(e) => return ok_error(e),
            }
        }

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        vault_reply(run_dcert_vault(&args_refs, &params.vault, &self.config, &[]).await)
    }

    /// Store a local certificate and private key in Vault KV.
    #[tool(
        title = "Vault: Store Certificate",
        description = "Store a local PEM certificate and private key in HashiCorp Vault KV secret store. Supports KV v1 and v2. Configurable key names for the certificate and private key within the secret. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn vault_store(
        &self,
        Parameters(mut params): Parameters<VaultStoreParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if let Err(e) = validate_args(&[
            ("path", Some(params.path.as_str())),
            ("cert_key", Some(params.cert_key.as_str())),
            ("key_key", Some(params.key_key.as_str())),
        ])
        .and_then(|()| validate_kv_path_param(&params.path, "path"))
        .and_then(|()| validate_kv_version(params.kv_version))
        .and_then(|()| validate_path(&params.cert_file, "cert_file"))
        .map(|p| params.cert_file = p)
        .and_then(|()| validate_path(&params.key_file, "key_file"))
        .map(|p| params.key_file = p)
        {
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

        vault_reply(run_dcert_vault(&args, &params.vault, &self.config, &[]).await)
    }

    /// Read and validate a certificate stored in Vault KV.
    #[tool(
        title = "Vault: Validate Stored Certificate",
        description = "Read and validate a TLS certificate stored in HashiCorp Vault KV. Checks expiry, key match, and displays certificate details. Supports KV v1 and v2. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn vault_validate(
        &self,
        Parameters(mut params): Parameters<VaultValidateParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if let Err(e) = validate_args(&[
            ("path", Some(params.path.as_str())),
            ("cert_key", Some(params.cert_key.as_str())),
            ("key_key", Some(params.key_key.as_str())),
        ])
        .and_then(|()| validate_kv_path_param(&params.path, "path"))
        .and_then(|()| validate_kv_version(params.kv_version))
        {
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

        vault_reply(run_dcert_vault(&args, &params.vault, &self.config, &[]).await)
    }

    /// Renew an existing certificate in Vault KV by re-issuing from Vault PKI.
    #[tool(
        title = "Vault: Renew Certificate",
        description = "Renew a TLS certificate stored in HashiCorp Vault KV by re-issuing from Vault PKI. Reads the existing cert to preserve CN and SANs, issues a new cert with a fresh TTL, and updates the KV secret. Optionally override SANs. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn vault_renew(
        &self,
        Parameters(mut params): Parameters<VaultRenewParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = params.vault.validate() {
            return ok_error(e);
        }
        if let Err(e) = validate_args(&[
            ("path", Some(params.path.as_str())),
            ("mount", Some(params.mount.as_str())),
            ("ttl", Some(params.ttl.as_str())),
            ("role", params.role.as_deref()),
            ("cert_key", Some(params.cert_key.as_str())),
            ("key_key", Some(params.key_key.as_str())),
        ])
        .and_then(|()| validate_list(&params.sans, "sans", 100))
        .and_then(|()| validate_list(&params.ip_sans, "ip_sans", 100))
        .and_then(|()| validate_kv_path_param(&params.path, "path"))
        .and_then(|()| validate_kv_version(params.kv_version))
        {
            return ok_error(e);
        }

        let mut args: Vec<String> = vec![
            "renew".to_string(),
            params.path.clone(),
            "--mount".to_string(),
            params.mount.clone(),
            "--ttl".to_string(),
            params.ttl.clone(),
            "--cert-key".to_string(),
            params.cert_key.clone(),
            "--key-key".to_string(),
            params.key_key.clone(),
            "--kv-version".to_string(),
            params.kv_version.to_string(),
        ];
        push_pki_args(
            &mut args,
            &PkiArgs {
                role: params.role.as_deref(),
                sans: &params.sans,
                ip_sans: &params.ip_sans,
                output: None,
                store_path: None,
                kv_version: params.kv_version,
            },
        );

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        vault_reply(run_dcert_vault(&args_refs, &params.vault, &self.config, &[]).await)
    }
}
