//! Certificate analysis, conversion, key and CSR tools.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use super::{DcertMcpServer, ok_error, ok_text};
use crate::exec::{format_tool_output, run_dcert, run_dcert_raw, run_dcert_with_env};
use crate::params::*;
use crate::validate::*;

#[tool_router(router = cert_tool_router, vis = "pub(crate)")]
impl DcertMcpServer {
    /// Decode and analyze TLS certificates from an HTTPS endpoint or PEM file.
    #[tool(
        description = "Decode and analyze TLS certificates from an HTTPS endpoint or PEM file. Returns certificate details including subject, issuer, SANs, validity dates, fingerprints, extensions, TLS connection information, and OSI-layer diagnostics. Also classifies the chain's root CA (the `root_trust` object): whether it anchors to a publicly trusted CA (Mozilla/CCADB root program — DigiCert, Amazon, Google, Microsoft, Apple, Let's Encrypt, etc.), a private PKI, or is self-signed. This runs offline by default; set `resolve_issuers` to follow AIA 'CA Issuers' URLs over the network to complete an incomplete chain or probe a private CA backend. Supports mTLS with client certificates and custom CA bundles. To analyze a specific IP/backend while validating a hostname (e.g. behind a load balancer, or when DNS does not resolve), keep the hostname in `target` and use `connect_to` (an IP, or 'HOST1:PORT1:HOST2:PORT2' to redirect to another hostname/port) or `resolve` ('HOST:PORT:IP'). Set `proxy`/`noproxy` to override the forward proxy for this request.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true)
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
        if params.no_trust_check {
            args.push("--no-trust-check".to_string());
        }
        if params.resolve_issuers {
            args.push("--resolve-issuers".to_string());
        }
        if let Some(t) = params.issuer_timeout {
            args.push("--issuer-timeout".to_string());
            args.push(t.to_string());
        }
        if params.refresh_public_roots {
            args.push("--refresh-public-roots".to_string());
        }
        if let Err(e) = params.http_tls.validate() {
            return ok_error(e);
        }
        args.extend(params.mtls.to_args());
        args.extend(params.http_tls.to_args());
        let mut env_refs = params.mtls.env_vars();
        env_refs.extend(params.http_tls.env_vars());

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "debug/stderr", &[0])),
            Err(e) => ok_error(e),
        }
    }

    /// Check if TLS certificates for a target expire within a specified number of days.
    #[tool(
        description = "Check if TLS certificates for a target expire within a specified number of days. Returns expiry status and warnings. Exit codes: 0=ok, 1=expiring soon, 4=already expired. Supports mTLS.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true)
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
        if let Err(e) = params.http_tls.validate() {
            return ok_error(e);
        }
        args.extend(params.mtls.to_args());
        args.extend(params.http_tls.to_args());
        let mut env_refs = params.mtls.env_vars();
        env_refs.extend(params.http_tls.env_vars());

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
            Ok((stdout, stderr, code)) => {
                let status = match code {
                    0 => "ALL_VALID",
                    1 => "EXPIRING_SOON",
                    4 => "ALREADY_EXPIRED",
                    _ => "ERROR",
                };
                let prefixed = format!("expiry_status: {status}\n\n{stdout}");
                ok_text(format_tool_output(prefixed, &stderr, code, "warnings", &[0, 1, 4]))
            }
            Err(e) => ok_error(e),
        }
    }

    /// Check the OCSP revocation status of TLS certificates.
    #[tool(
        description = "Check the OCSP revocation status of TLS certificates. Queries the certificate's OCSP responder to determine if it has been revoked. Supports mTLS.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = false)
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
        if let Err(e) = params.http_tls.validate() {
            return ok_error(e);
        }
        args.extend(params.mtls.to_args());
        args.extend(params.http_tls.to_args());
        let mut env_refs = params.mtls.env_vars();
        env_refs.extend(params.http_tls.env_vars());

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
            Ok((stdout, stderr, code)) => {
                let prefixed = match code {
                    5 => format!("revocation_status: REVOKED\n\n{stdout}"),
                    8 => format!("revocation_status: CHECK_FAILED\n\n{stdout}"),
                    _ => stdout,
                };
                ok_text(format_tool_output(prefixed, &stderr, code, "stderr", &[0, 5, 8]))
            }
            Err(e) => ok_error(e),
        }
    }

    /// Compare TLS certificates between two targets and show differences.
    #[tool(
        description = "Compare TLS certificates between two targets and show differences. Useful for verifying certificate rotations, comparing staging vs production, or detecting changes.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true)
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
                    Err(e) => return ok_error(format!("Failed to parse target_a output: {e}")),
                };
                let json_b: serde_json::Value = match serde_json::from_str(&stdout_b) {
                    Ok(v) => v,
                    Err(e) => return ok_error(format!("Failed to parse target_b output: {e}")),
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
                    Err(e) => ok_error(format!("Failed to serialize diff: {e}")),
                }
            }
            (Err(e), _) => ok_error(format!("Failed to fetch target_a: {e}")),
            (_, Err(e)) => ok_error(format!("Failed to fetch target_b: {e}")),
        }
    }

    /// Get TLS connection details for an HTTPS endpoint.
    #[tool(
        description = "Get TLS connection details for an HTTPS endpoint including protocol version, cipher suite, ALPN negotiation, DNS/TCP/TLS latency, verification status, full OSI-layer diagnostics, and (when applicable) a `client_auth_required` flag plus the captured server chain when the server demands mTLS. Supports mTLS and custom CA bundles. To probe a specific IP/backend while validating a hostname (e.g. behind a load balancer, or when DNS does not resolve), keep the hostname in `target` and use `connect_to` (an IP, or 'HOST1:PORT1:HOST2:PORT2' to redirect to another hostname/port) or `resolve` ('HOST:PORT:IP'). Set `proxy`/`noproxy` to override the forward proxy for this request.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = false)
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
        if let (Some(min), Some(max)) = (&params.min_tls, &params.max_tls)
            && min == "1.3"
            && max == "1.2"
        {
            return ok_error("min_tls (1.3) must not be greater than max_tls (1.2)".to_string());
        }
        if let Err(e) = params.http_tls.validate() {
            return ok_error(e);
        }
        args.extend(params.mtls.to_args());
        args.extend(params.http_tls.to_args());
        let mut env_refs = params.mtls.env_vars();
        env_refs.extend(params.http_tls.env_vars());

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "debug/stderr", &[0])),
            Err(e) => ok_error(e),
        }
    }

    /// Export the PEM certificate chain from an HTTPS endpoint.
    #[tool(
        description = "Export the TLS certificate chain from an HTTPS endpoint as PEM text. Optionally saves to a file and can exclude expired certificates. Returns the PEM chain text. Supports mTLS and custom CA bundles.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = true)
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
        if let Some(ref p) = params.output_path
            && let Err(e) = validate_path(p, "output_path")
        {
            return ok_error(e);
        }

        let mut args = vec![params.target.clone(), "--format".to_string(), "json".to_string()];
        if let Some(ref output) = params.output_path {
            args.push("--export-pem".to_string());
            args.push(output.clone());
        }
        if params.exclude_expired {
            args.push("--exclude-expired".to_string());
        }
        if let Err(e) = params.http_tls.validate() {
            return ok_error(e);
        }
        args.extend(params.mtls.to_args());
        args.extend(params.http_tls.to_args());
        let mut env_refs = params.mtls.env_vars();
        env_refs.extend(params.http_tls.env_vars());

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
            Ok((stdout, stderr, code)) => {
                let prefixed = match &params.output_path {
                    Some(path) => format!("PEM chain exported to: {path}\n\n{stdout}"),
                    None => stdout,
                };
                ok_text(format_tool_output(prefixed, &stderr, code, "debug/stderr", &[0]))
            }
            Err(e) => ok_error(e),
        }
    }

    /// Verify that a private key matches a certificate.
    #[tool(
        description = "Verify that a private key PEM file matches a certificate (PEM file or HTTPS endpoint). Returns match status, key type/size, and certificate subject. Useful for validating key-cert pairs before deployment.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true)
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

        match run_dcert_raw(&args, &self.config, None).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "stderr", &[0, 7])),
            Err(e) => ok_error(e),
        }
    }

    /// Scan a directory for matching certificate/key pairs and verify they match.
    #[tool(
        description = "Scan a directory for matching certificate and private key file pairs (.pem/.crt + .key) and verify they match. Returns match status, key type/size, and certificate subject for each discovered pair. Useful for auditing certificate deployments.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true)
    )]
    pub async fn verify_key_auto_discover(
        &self,
        Parameters(params): Parameters<VerifyKeyAutoDiscoverParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_path(&params.dir, "dir") {
            return ok_error(e);
        }

        let args = vec!["verify-key", "--dir", params.dir.as_str(), "--format", "json"];

        match run_dcert_raw(&args, &self.config, None).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "stderr", &[0, 7])),
            Err(e) => ok_error(e),
        }
    }

    /// Convert a PKCS12/PFX file to PEM certificate and key files.
    #[tool(
        description = "Convert a PKCS12/PFX file to separate PEM files (cert.pem, key.pem, ca.pem). Extracts the certificate, private key, and any CA chain certificates.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = true)
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
            "--format",
            "json",
            "pfx-to-pem",
            params.pkcs12_path.as_str(),
            "--output-dir",
            params.output_dir.as_str(),
        ];
        // Pass password via env var to avoid exposure in process listings
        let env_vars = [("DCERT_CERT_PASSWORD", params.password.as_str())];

        match run_dcert_raw(&args, &self.config, Some(&env_vars)).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "stderr", &[0])),
            Err(e) => ok_error(e),
        }
    }

    /// Convert PEM certificate and key to a PKCS12/PFX file.
    #[tool(
        description = "Convert PEM certificate and private key files to a PKCS12/PFX file. Optionally includes CA chain certificates.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = true)
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
        if let Some(ref ca) = params.ca_path
            && let Err(e) = validate_path(ca, "ca_path")
        {
            return ok_error(e);
        }

        let mut args = vec![
            "convert".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "pem-to-pfx".to_string(),
            "--cert".to_string(),
            params.cert_path.clone(),
            "--key".to_string(),
            params.key_path.clone(),
            "--output".to_string(),
            params.output_path.clone(),
        ];
        if let Some(ref ca) = params.ca_path {
            args.push("--ca".to_string());
            args.push(ca.clone());
        }
        // Pass password via env var to avoid exposure in process listings
        let env_vars = [("DCERT_CERT_PASSWORD", params.password.as_str())];

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_raw(&args_refs, &self.config, Some(&env_vars)).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "stderr", &[0])),
            Err(e) => ok_error(e),
        }
    }

    /// Create a PKCS12 keystore from a private key and certificate.
    #[tool(
        description = "Create a PKCS12 keystore from PEM certificate and private key files. Java-compatible since JDK 9. Returns warnings when the cert PEM is missing the issuer chain or when the leaf cert is not first.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = true)
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
            "--format",
            "json",
            "create-keystore",
            "--cert",
            params.cert_path.as_str(),
            "--key",
            params.key_path.as_str(),
            "--output",
            params.output_path.as_str(),
            "--alias",
            params.alias.as_str(),
        ];
        // Pass password via env var to avoid exposure in process listings
        let env_vars = [("DCERT_KEYSTORE_PASSWORD", params.password.as_str())];

        match run_dcert_raw(&args, &self.config, Some(&env_vars)).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "stderr", &[0])),
            Err(e) => ok_error(e),
        }
    }

    /// Create a new Certificate Signing Request (CSR) with a private key.
    #[tool(
        description = "Create a PKCS#10 Certificate Signing Request (CSR) and private key. Supports RSA 4096 (default), RSA 2048, ECDSA P-256 (recommended modern), ECDSA P-384, and Ed25519 (modern EdDSA). Compliant with CA/B Forum Baseline Requirements, DigiCert, and X9 standards. OU fields can encode metadata identifiers (e.g., AppId:my-app-123) for internal PKI. Returns JSON with CSR details, key info, and file paths.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = false)
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
        if let Some(ref pw) = params.key_password
            && let Err(e) = validate_password(pw)
        {
            return ok_error(e);
        }
        if let Some(ref country) = params.country
            && (country.len() != 2 || !country.chars().all(|c| c.is_ascii_uppercase()))
        {
            return ok_error(format!(
                "country must be a 2-letter ISO 3166-1 alpha-2 code (e.g., 'GB', 'US'), got '{country}'"
            ));
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
            params.key_algorithm.clone(),
            "--csr-out".to_string(),
            params.csr_output_path.clone(),
            "--key-out".to_string(),
            params.key_output_path.clone(),
            "--format".to_string(),
            "json".to_string(),
        ];
        if let Some(ref org) = params.organization {
            args.push("--org".to_string());
            args.push(org.clone());
        }
        for ou in &params.organizational_units {
            args.push("--ou".to_string());
            args.push(ou.clone());
        }
        if let Some(ref country) = params.country {
            args.push("--country".to_string());
            args.push(country.clone());
        }
        if let Some(ref state) = params.state {
            args.push("--state".to_string());
            args.push(state.clone());
        }
        if let Some(ref locality) = params.locality {
            args.push("--locality".to_string());
            args.push(locality.clone());
        }
        if let Some(ref email) = params.email {
            args.push("--email".to_string());
            args.push(email.clone());
        }
        for san in &params.subject_alternative_names {
            args.push("--san".to_string());
            args.push(san.clone());
        }
        // The passphrase travels in the environment, never in argv.
        let mut env_refs: Vec<(&str, &str)> = Vec::new();
        if params.encrypt_key {
            args.push("--encrypt-key".to_string());
            if let Some(ref pw) = params.key_password {
                env_refs.push(("DCERT_KEY_PASSWORD", pw.as_str()));
            }
        }

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_raw(&args_refs, &self.config, Some(&env_refs)).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "notes", &[0])),
            Err(e) => ok_error(e),
        }
    }

    /// Validate a PEM-encoded CSR for compliance with industry standards.
    #[tool(
        description = "Validate a PEM-encoded Certificate Signing Request (CSR) for compliance with CA/B Forum Baseline Requirements, DigiCert, and X9 standards. Checks key algorithm/size, signature algorithm, SAN presence, OU deprecation, country code format, and more. Returns JSON with subject info, key details, SANs, compliance findings (error/warning/info), and overall compliant/non-compliant status.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true)
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
            args.push("--warnings-as-errors".to_string());
        }

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_raw(&args_refs, &self.config, None).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "notes", &[0])),
            Err(e) => ok_error(e),
        }
    }

    /// Diagnose CloudFront, mTLS and forward proxy failures for an endpoint.
    #[tool(
        description = "Diagnose why an HTTPS endpoint fails or misbehaves, with a focus on Amazon CloudFront (edge generated 4xx/5xx pages, origin errors forwarded by the edge, viewer mTLS in verify, optional and passthrough modes, origin mTLS gaps), forward web proxies (CONNECT 407/403/5xx, wrong proxy scheme, HTTP_PROXY only environments) and TLS inspection (chains re signed by Zscaler, Netskope and similar gateways). Probes the target, captures the TLS handshake, certificate chain, HTTP status, headers and a bounded body excerpt, and scores them against the diagnostics knowledge base. Returns JSON findings ordered earliest layer first, each with a confidence figure, the evidence that matched, a root cause and remediation steps. Supports mTLS, connection overrides and per request proxy settings like analyze_certificate.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true)
    )]
    pub async fn diagnose_endpoint(
        &self,
        Parameters(params): Parameters<DiagnoseEndpointParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }
        if let Err(e) = params.mtls.validate() {
            return ok_error(e);
        }
        if let Err(e) = params.http_tls.validate() {
            return ok_error(e);
        }

        let mut args = vec![
            "diagnose".to_string(),
            params.target.clone(),
            "--format".to_string(),
            "json".to_string(),
        ];
        if params.show_body {
            args.push("--show-body".to_string());
        }
        if params.no_verify {
            args.push("--no-verify".to_string());
        }
        args.extend(params.mtls.to_args());
        args.extend(params.http_tls.to_args());
        let mut env_refs = params.mtls.env_vars();
        env_refs.extend(params.http_tls.env_vars());

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
            // A failed probe is the expected input for a diagnosis, so exit
            // codes are reported inline rather than treated as tool errors.
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "stderr", &[0])),
            Err(e) => ok_error(e),
        }
    }

    /// Validate TLS certificates against industry standards and report compliance status.
    #[tool(
        description = "Validate TLS certificates from an HTTPS endpoint or PEM file against CA/B Forum Baseline Requirements, DigiCert, and X9 standards. Checks key size, signature algorithm (SHA-1/MD5 rejection), SAN presence, certificate validity period (398-day max), Certificate Transparency (SCT presence), Extended Key Usage, and CA constraints. Returns JSON with per-certificate findings (error/warning/info) and overall COMPLIANT/NON-COMPLIANT status. Supports mTLS.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true)
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

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "debug/stderr", &[0])),
            Err(e) => ok_error(e),
        }
    }

    /// Create a PKCS12 truststore from CA certificates.
    #[tool(
        description = "Create a PKCS12 truststore from CA certificate PEM files. Java-compatible since JDK 9. Bundles multiple CA certificates into a single truststore file. Returns warnings about leaf certs, duplicates, expired CAs, and CA-rotation cases (same subject, different fingerprint). Set `allow_non_ca: false` to refuse leaves with a beginner-friendly explanation; the default `true` preserves prior MCP behaviour.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = true)
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

        // Force --format json so the subprocess output is parseable, regardless
        // of the CLI default (which is `pretty` for human users).
        let mut args: Vec<String> = vec![
            "convert".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "create-truststore".to_string(),
        ];
        for path in &params.cert_paths {
            args.push(path.clone());
        }
        args.push("--output".to_string());
        args.push(params.output_path.clone());
        if params.allow_non_ca {
            args.push("--allow-non-ca".to_string());
        }
        // The password travels in the environment, never in argv.
        let env_refs: Vec<(&str, &str)> = vec![("DCERT_TRUSTSTORE_PASSWORD", params.password.as_str())];

        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_dcert_raw(&args_refs, &self.config, Some(&env_refs)).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "stderr", &[0])),
            Err(e) => ok_error(e),
        }
    }
}
