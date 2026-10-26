//! HashiCorp Vault PKI tools.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use super::{DcertMcpServer, ok_error, reply};
use crate::cliargs::{ArgBuilder, ToCliArgs};
use crate::params_vault::*;
use crate::validate::*;

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

/// `--role`, `--san`, `--ip-san`, `--output` and, when a store path is
/// given, `--store-path` with its `--kv-version`.
impl ToCliArgs for PkiArgs<'_> {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
        out.value("role", self.role)
            .repeat("san", self.sans)
            .repeat("ip-san", self.ip_sans)
            .value("output", self.output)
            .value("store-path", self.store_path)
            .value("kv-version", self.store_path.map(|_| self.kv_version));
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

        let pki = PkiArgs {
            role: params.role.as_deref(),
            sans: &params.sans,
            ip_sans: &params.ip_sans,
            output: params.output.as_deref(),
            store_path: params.store_path.as_deref(),
            kv_version: params.kv_version,
        };
        let mut b = ArgBuilder::new();
        b.positional(["issue"])
            .value("cn", Some(&params.common_name))
            .value("mount", Some(&params.mount))
            .value("ttl", Some(&params.ttl))
            .value("format", Some("json"))
            .extend(&pki)
            // The PFX passphrase travels in the environment, never in argv.
            .env("DCERT_CERT_PASSWORD", params.pfx_password.as_deref());
        let (args, env) = b.into_parts();
        reply(
            run_dcert_vault(args, &params.vault, &self.config, &env).await,
            "debug/stderr",
            &[0],
        )
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

        let pki = PkiArgs {
            role: params.role.as_deref(),
            sans: &params.sans,
            ip_sans: &params.ip_sans,
            output: params.output.as_deref(),
            store_path: params.store_path.as_deref(),
            kv_version: params.kv_version,
        };
        let mut b = ArgBuilder::new();
        b.positional(["sign"])
            .value("csr-file", Some(&params.csr_file))
            .value("mount", Some(&params.mount))
            .value("ttl", Some(&params.ttl))
            .value("format", Some("json"))
            .value("cn", params.common_name.as_deref())
            .extend(&pki);
        let (args, _) = b.into_parts();
        reply(
            run_dcert_vault(args, &params.vault, &self.config, &[]).await,
            "debug/stderr",
            &[0],
        )
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

        if let Some(cert) = params.cert_file.as_mut() {
            match validate_path(cert, "cert_file") {
                Ok(canonical) => *cert = canonical,
                Err(e) => return ok_error(e),
            }
        }
        let mut b = ArgBuilder::new();
        b.positional(["revoke"])
            .value("mount", Some(&params.mount))
            .value("serial", params.serial.as_deref())
            .value("cert-file", params.cert_file.as_deref());
        let (args, _) = b.into_parts();
        reply(
            run_dcert_vault(args, &params.vault, &self.config, &[]).await,
            "debug/stderr",
            &[0],
        )
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

        if let Some(export) = params.export.as_mut() {
            match validate_path(export, "export") {
                Ok(canonical) => *export = canonical,
                Err(e) => return ok_error(e),
            }
        }
        let mut b = ArgBuilder::new();
        b.positional(["list"])
            .value("mount", Some(&params.mount))
            .value("format", Some("json"))
            .flag("show-details", params.show_details)
            .flag("expired-only", params.expired_only)
            .flag("valid-only", params.valid_only)
            .value("export", params.export.as_deref());
        let (args, _) = b.into_parts();
        reply(
            run_dcert_vault(args, &params.vault, &self.config, &[]).await,
            "debug/stderr",
            &[0],
        )
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

        let mut b = ArgBuilder::new();
        b.positional(["store"])
            .value("cert-file", Some(&params.cert_file))
            .value("key-file", Some(&params.key_file))
            .positional([&params.path])
            .value("cert-key", Some(&params.cert_key))
            .value("key-key", Some(&params.key_key))
            .value("kv-version", Some(params.kv_version));
        let (args, _) = b.into_parts();

        reply(
            run_dcert_vault(args, &params.vault, &self.config, &[]).await,
            "debug/stderr",
            &[0],
        )
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

        let mut b = ArgBuilder::new();
        b.positional(["validate", params.path.as_str()])
            .value("cert-key", Some(&params.cert_key))
            .value("key-key", Some(&params.key_key))
            .value("kv-version", Some(params.kv_version));
        let (args, _) = b.into_parts();

        reply(
            run_dcert_vault(args, &params.vault, &self.config, &[]).await,
            "debug/stderr",
            &[0],
        )
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

        let pki = PkiArgs {
            role: params.role.as_deref(),
            sans: &params.sans,
            ip_sans: &params.ip_sans,
            output: None,
            store_path: None,
            kv_version: params.kv_version,
        };
        let mut b = ArgBuilder::new();
        b.positional(["renew", params.path.as_str()])
            .value("mount", Some(&params.mount))
            .value("ttl", Some(&params.ttl))
            .value("cert-key", Some(&params.cert_key))
            .value("key-key", Some(&params.key_key))
            .value("kv-version", Some(params.kv_version))
            .extend(&pki);
        let (args, _) = b.into_parts();
        reply(
            run_dcert_vault(args, &params.vault, &self.config, &[]).await,
            "debug/stderr",
            &[0],
        )
    }
}
