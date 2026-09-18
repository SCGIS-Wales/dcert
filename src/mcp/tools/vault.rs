//! HashiCorp Vault PKI tools.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use super::{DcertMcpServer, ok_error, ok_text};
use crate::params_vault::*;
use crate::validate::*;

#[tool_router(router = vault_tool_router, vis = "pub(crate)")]
impl DcertMcpServer {
    // ===================================================================
    // Vault PKI Tools
    // ===================================================================

    /// Issue a new TLS certificate from HashiCorp Vault PKI.
    #[tool(
        description = "Issue a new TLS certificate from HashiCorp Vault PKI. Generates a private key and certificate signed by the Vault PKI CA. Supports DNS and IP SANs, configurable TTL, PEM or PFX output, and optional KV storage. Requires Vault connectivity (vault_addr + authentication). Supports token, LDAP, and AppRole auth methods.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = false)
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

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_vault(&args_refs, &params.vault, &self.config).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- debug/stderr ---\n");
                    output.push_str(&stderr);
                }
                if code != 0 {
                    output.push_str(&format!("\n--- exit code: {code} ---"));
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }

    /// Sign a Certificate Signing Request (CSR) using Vault PKI.
    #[tool(
        description = "Sign a Certificate Signing Request (CSR) using HashiCorp Vault PKI. Takes a PEM-encoded CSR file and returns a signed certificate with the full CA chain. Supports CN override, SANs, and optional KV storage. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = false)
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

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_vault(&args_refs, &params.vault, &self.config).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- debug/stderr ---\n");
                    output.push_str(&stderr);
                }
                if code != 0 {
                    output.push_str(&format!("\n--- exit code: {code} ---"));
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }

    /// Revoke a certificate in Vault PKI by serial number or PEM file.
    #[tool(
        description = "Revoke a TLS certificate in HashiCorp Vault PKI. Specify either the serial number (hex) or a PEM certificate file path. The certificate is added to the CRL. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = true)
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

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_vault(&args_refs, &params.vault, &self.config).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- debug/stderr ---\n");
                    output.push_str(&stderr);
                }
                if code != 0 {
                    output.push_str(&format!("\n--- exit code: {code} ---"));
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }

    /// List all certificates issued by Vault PKI.
    #[tool(
        description = "List all certificates issued by HashiCorp Vault PKI with optional filtering by expired/valid status. Supports export to JSON, CSV, or XLSX files. Returns serial numbers, common names, expiry dates, and status. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true)
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

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_vault(&args_refs, &params.vault, &self.config).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- debug/stderr ---\n");
                    output.push_str(&stderr);
                }
                if code != 0 {
                    output.push_str(&format!("\n--- exit code: {code} ---"));
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }

    /// Store a local certificate and private key in Vault KV.
    #[tool(
        description = "Store a local PEM certificate and private key in HashiCorp Vault KV secret store. Supports KV v1 and v2. Configurable key names for the certificate and private key within the secret. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = true)
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
                    output.push_str(&format!("\n--- exit code: {code} ---"));
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }

    /// Read and validate a certificate stored in Vault KV.
    #[tool(
        description = "Read and validate a TLS certificate stored in HashiCorp Vault KV. Checks expiry, key match, and displays certificate details. Supports KV v1 and v2. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true)
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
                    output.push_str(&format!("\n--- exit code: {code} ---"));
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }

    /// Renew an existing certificate in Vault KV by re-issuing from Vault PKI.
    #[tool(
        description = "Renew a TLS certificate stored in HashiCorp Vault KV by re-issuing from Vault PKI. Reads the existing cert to preserve CN and SANs, issues a new cert with a fresh TTL, and updates the KV secret. Optionally override SANs. Requires Vault connectivity. Supports token, LDAP, and AppRole auth methods.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = false)
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

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_vault(&args_refs, &params.vault, &self.config).await {
            Ok((stdout, stderr, code)) => {
                let mut output = stdout;
                if !stderr.is_empty() {
                    output.push_str("\n--- debug/stderr ---\n");
                    output.push_str(&stderr);
                }
                if code != 0 {
                    output.push_str(&format!("\n--- exit code: {code} ---"));
                }
                ok_text(output)
            }
            Err(e) => ok_error(e),
        }
    }
}
