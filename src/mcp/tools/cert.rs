//! Certificate analysis, conversion, key and CSR tools.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use super::{DcertMcpServer, ok_error, ok_text};
use crate::exec::{format_tool_output, run_dcert, run_dcert_raw, run_dcert_with_env, target_args};
use crate::params::*;
use crate::validate::*;

/// What a dcert run produced: stdout, stderr and the exit code, or why it
/// could not run at all.
type RunOutcome = Result<(String, String, i32), String>;

/// Turn a run outcome into the tool reply: the formatted output on success,
/// an error result when the subprocess could not be run.
fn tool_reply(outcome: RunOutcome, banner: &str, ok_codes: &[i32]) -> Result<CallToolResult, rmcp::ErrorData> {
    match outcome {
        Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, banner, ok_codes)),
        Err(e) => ok_error(e),
    }
}

impl DcertMcpServer {
    /// The prologue every network probe shares: validate the target and the
    /// mTLS and HTTP/TLS options, append their argv and environment to the
    /// tool specific `args`, and run dcert.
    ///
    /// Tools with no HTTP/TLS options (`validate_certificate`) pass `None`.
    async fn run_probe(
        &self,
        subcommand: &str,
        target: &str,
        options: Vec<String>,
        mtls: &mut MtlsParams,
        http_tls: Option<&HttpTlsParams>,
    ) -> RunOutcome {
        let target = resolve_target(target)?;
        mtls.validate()?;
        if let Some(http_tls) = http_tls {
            http_tls.validate()?;
        }
        check_destinations(&self.config.destinations, probe_destinations(&target, http_tls)?).await?;
        let mut options = options;
        options.extend(mtls.to_args());
        let mut env_refs = mtls.env_vars();
        if let Some(http_tls) = http_tls {
            options.extend(http_tls.to_args());
            env_refs.extend(http_tls.env_vars());
        }
        let args = target_args(subcommand, options, &target);
        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_dcert_with_env(&args_refs, &self.config, Some(&env_refs)).await
    }
}

/// Exit codes `kb explain` returns that are answers rather than failures.
///
/// The CLI exits 2 both when nothing matched (with an empty JSON list on
/// stdout) and on a real error such as an unknown service (no stdout), so
/// 2 only counts as an answer when the empty list is there.
pub(crate) fn explain_ok_codes(code: i32, stdout: &str) -> &'static [i32] {
    let empty_list = serde_json::from_str::<Vec<serde_json::Value>>(stdout.trim()).is_ok_and(|v| v.is_empty());
    if code == 2 && empty_list { &[0, 2] } else { &[0] }
}

#[tool_router(router = cert_tool_router, vis = "pub(crate)")]
impl DcertMcpServer {
    /// Decode and analyze TLS certificates from an HTTPS endpoint or PEM file.
    #[tool(
        title = "Analyze TLS Certificate",
        description = "Decode and analyze TLS certificates from an HTTPS endpoint or PEM file. Returns certificate details including subject, issuer, SANs, validity dates, fingerprints, extensions, TLS connection information, and OSI-layer diagnostics. Also classifies the chain's root CA (the `root_trust` object): whether it anchors to a publicly trusted CA (Mozilla/CCADB root program — DigiCert, Amazon, Google, Microsoft, Apple, Let's Encrypt, etc.), a private PKI, or is self-signed. This runs offline by default; set `resolve_issuers` to follow AIA 'CA Issuers' URLs over the network to complete an incomplete chain or probe a private CA backend. Supports mTLS with client certificates and custom CA bundles. To analyze a specific IP/backend while validating a hostname (e.g. behind a load balancer, or when DNS does not resolve), keep the hostname in `target` and use `connect_to` (an IP, or 'HOST1:PORT1:HOST2:PORT2' to redirect to another hostname/port) or `resolve` ('HOST:PORT:IP'). Set `proxy`/`noproxy` to override the forward proxy for this request.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn analyze_certificate(
        &self,
        Parameters(mut params): Parameters<AnalyzeCertificateParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut args = vec!["--format".to_string(), "json".to_string()];
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
        let outcome = self
            .run_probe("check", &params.target, args, &mut params.mtls, Some(&params.http_tls))
            .await;
        tool_reply(outcome, "debug/stderr", &[0])
    }

    /// Check if TLS certificates for a target expire within a specified number of days.
    #[tool(
        title = "Check Certificate Expiry",
        description = "Check if TLS certificates for a target expire within a specified number of days. Returns expiry status and warnings. Exit codes: 0=ok, 1=expiring soon, 4=already expired. Supports mTLS.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn check_expiry(
        &self,
        Parameters(mut params): Parameters<CheckExpiryParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if params.days > 3650 {
            return ok_error(format!("days must be at most 3650 (10 years), got {}", params.days));
        }

        let args = vec![
            "--format".to_string(),
            "json".to_string(),
            "--fingerprint".to_string(),
            "--expiry-warn".to_string(),
            params.days.to_string(),
        ];
        let outcome = self
            .run_probe("check", &params.target, args, &mut params.mtls, Some(&params.http_tls))
            .await
            .map(|(stdout, stderr, code)| {
                let status = match code {
                    0 => "ALL_VALID",
                    1 => "EXPIRING_SOON",
                    4 => "ALREADY_EXPIRED",
                    _ => "ERROR",
                };
                (format!("expiry_status: {status}\n\n{stdout}"), stderr, code)
            });
        tool_reply(outcome, "warnings", &[0, 1, 4])
    }

    /// Check the OCSP revocation status of TLS certificates.
    #[tool(
        title = "Check OCSP Revocation",
        description = "Check the OCSP revocation status of TLS certificates. Queries the certificate's OCSP responder to determine if it has been revoked. Supports mTLS.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn check_revocation(
        &self,
        Parameters(mut params): Parameters<CheckRevocationParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args = vec![
            "--format".to_string(),
            "json".to_string(),
            "--check-revocation".to_string(),
            "--extensions".to_string(),
        ];
        let outcome = self
            .run_probe("check", &params.target, args, &mut params.mtls, Some(&params.http_tls))
            .await
            .map(|(stdout, stderr, code)| {
                let prefixed = match code {
                    5 => format!("revocation_status: REVOKED\n\n{stdout}"),
                    8 => format!("revocation_status: CHECK_FAILED\n\n{stdout}"),
                    _ => stdout,
                };
                (prefixed, stderr, code)
            });
        tool_reply(outcome, "stderr", &[0, 5, 8])
    }

    /// Compare TLS certificates between two targets and show differences.
    #[tool(
        title = "Compare Certificates",
        description = "Compare TLS certificates between two targets and show differences. Useful for verifying certificate rotations, comparing staging vs production, or detecting changes.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
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

        let destinations = probe_destinations(&params.target_a, None).and_then(|mut a| {
            probe_destinations(&params.target_b, None).map(|b| {
                a.extend(b);
                a
            })
        });
        if let Err(e) = match destinations {
            Ok(d) => check_destinations(&self.config.destinations, d).await,
            Err(e) => Err(e),
        } {
            return ok_error(e);
        }

        let options = || vec!["--format".to_string(), "json".to_string(), "--fingerprint".to_string()];
        let args_a = target_args("check", options(), &params.target_a);
        let args_b = target_args("check", options(), &params.target_b);
        let refs_a: Vec<&str> = args_a.iter().map(String::as_str).collect();
        let refs_b: Vec<&str> = args_b.iter().map(String::as_str).collect();

        let (result_a, result_b) = tokio::join!(run_dcert(&refs_a, &self.config), run_dcert(&refs_b, &self.config));

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
        title = "TLS Connection Info",
        description = "Get TLS connection details for an HTTPS endpoint including protocol version, cipher suite, ALPN negotiation, DNS/TCP/TLS latency, verification status, full OSI-layer diagnostics, the mTLS state (`client_auth`: not_requested, optional, required or presented, detected from the server's CertificateRequest on TLS 1.2 and 1.3, `acceptable_client_cas` with the CA names the server accepts, and `client_auth_required` plus the captured server chain when the server refuses the connection without a client certificate). Supports mTLS and custom CA bundles. To probe a specific IP/backend while validating a hostname (e.g. behind a load balancer, or when DNS does not resolve), keep the hostname in `target` and use `connect_to` (an IP, or 'HOST1:PORT1:HOST2:PORT2' to redirect to another hostname/port) or `resolve` ('HOST:PORT:IP'). Set `proxy`/`noproxy` to override the forward proxy for this request.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn tls_connection_info(
        &self,
        Parameters(mut params): Parameters<TlsConnectionInfoParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut args = vec![
            "--format".to_string(),
            "json".to_string(),
            "--fingerprint".to_string(),
            "--extensions".to_string(),
        ];

        // Parse both bounds into the CLI's own enum so the ordering check
        // compares versions, not strings.
        let mut bounds = (None, None);
        for (flag, value, slot) in [
            ("--min-tls", &params.min_tls, &mut bounds.0),
            ("--max-tls", &params.max_tls, &mut bounds.1),
        ] {
            if let Some(v) = value {
                match validate_tls_version(v) {
                    Ok(parsed) => *slot = Some(parsed),
                    Err(e) => return ok_error(e),
                }
                args.push(flag.to_string());
                args.push(v.clone());
            }
        }
        if let (Some(min), Some(max)) = bounds
            && min > max
        {
            return ok_error(format!("min_tls ({min}) must not be greater than max_tls ({max})"));
        }
        let outcome = self
            .run_probe("check", &params.target, args, &mut params.mtls, Some(&params.http_tls))
            .await;
        tool_reply(outcome, "debug/stderr", &[0])
    }

    /// Export the PEM certificate chain from an HTTPS endpoint.
    #[tool(
        title = "Export PEM Chain",
        description = "Export the TLS certificate chain from an HTTPS endpoint as PEM text. Optionally saves to a file and can exclude expired certificates. Returns the PEM chain text. Supports mTLS and custom CA bundles.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn export_pem(
        &self,
        Parameters(mut params): Parameters<ExportPemParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Some(p) = params.output_path.as_mut() {
            match validate_path(p, "output_path") {
                Ok(v) => *p = v,
                Err(e) => return ok_error(e),
            }
        }

        // Without an output file the chain comes back in the JSON as
        // `pem_data` (`--export-pem -`).
        let mut args = vec![
            "--format".to_string(),
            "json".to_string(),
            "--export-pem".to_string(),
            params.output_path.clone().unwrap_or_else(|| "-".to_string()),
        ];
        if params.exclude_expired {
            args.push("--exclude-expired".to_string());
        }
        let outcome = self
            .run_probe("check", &params.target, args, &mut params.mtls, Some(&params.http_tls))
            .await
            .map(|(stdout, stderr, code)| {
                let prefixed = match &params.output_path {
                    Some(path) => format!("PEM chain exported to: {path}\n\n{stdout}"),
                    None => stdout,
                };
                (prefixed, stderr, code)
            });
        tool_reply(outcome, "debug/stderr", &[0])
    }

    /// Verify that a private key matches a certificate.
    #[tool(
        title = "Verify Key Matches Certificate",
        description = "Verify that a private key PEM file matches a certificate (PEM file or HTTPS endpoint). Returns match status, key type/size, and certificate subject. Useful for validating key-cert pairs before deployment.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn verify_key_match(
        &self,
        Parameters(mut params): Parameters<VerifyKeyMatchParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_target(&params.target) {
            return ok_error(e);
        }
        match validate_path(&params.key_path, "key_path") {
            Ok(p) => params.key_path = p,
            Err(e) => return ok_error(e),
        }

        let args = target_args(
            "verify-key",
            vec![
                "--key".to_string(),
                params.key_path.clone(),
                "--format".to_string(),
                "json".to_string(),
            ],
            &params.target,
        );
        let args: Vec<&str> = args.iter().map(String::as_str).collect();

        match run_dcert_raw(&args, &self.config, None).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "stderr", &[0, 7])),
            Err(e) => ok_error(e),
        }
    }

    /// Scan a directory for matching certificate/key pairs and verify they match.
    #[tool(
        title = "Discover and Verify Key Pairs",
        description = "Scan a directory for matching certificate and private key file pairs (.pem/.crt + .key) and verify they match. Returns match status, key type/size, and certificate subject for each discovered pair. Useful for auditing certificate deployments.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn verify_key_auto_discover(
        &self,
        Parameters(mut params): Parameters<VerifyKeyAutoDiscoverParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match validate_path(&params.dir, "dir") {
            Ok(p) => params.dir = p,
            Err(e) => return ok_error(e),
        }

        let args = vec!["verify-key", "--dir", params.dir.as_str(), "--format", "json"];

        match run_dcert_raw(&args, &self.config, None).await {
            Ok((stdout, stderr, code)) => ok_text(format_tool_output(stdout, &stderr, code, "stderr", &[0, 7])),
            Err(e) => ok_error(e),
        }
    }

    /// Convert a PKCS12/PFX file to PEM certificate and key files.
    #[tool(
        title = "Convert PFX to PEM",
        description = "Convert a PKCS12/PFX file to separate PEM files (cert.pem, key.pem, ca.pem). Extracts the certificate, private key, and any CA chain certificates.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn convert_pfx_to_pem(
        &self,
        Parameters(mut params): Parameters<ConvertPfxToPemParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_path(&params.pkcs12_path, "pkcs12_path") {
            return ok_error(e);
        }
        match validate_path(&params.output_dir, "output_dir") {
            Ok(p) => params.output_dir = p,
            Err(e) => return ok_error(e),
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
        title = "Convert PEM to PFX",
        description = "Convert PEM certificate and private key files to a PKCS12/PFX file. Optionally includes CA chain certificates.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn convert_pem_to_pfx(
        &self,
        Parameters(mut params): Parameters<ConvertPemToPfxParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match validate_path(&params.cert_path, "cert_path") {
            Ok(p) => params.cert_path = p,
            Err(e) => return ok_error(e),
        }
        match validate_path(&params.key_path, "key_path") {
            Ok(p) => params.key_path = p,
            Err(e) => return ok_error(e),
        }
        match validate_path(&params.output_path, "output_path") {
            Ok(p) => params.output_path = p,
            Err(e) => return ok_error(e),
        }
        if let Err(e) = validate_password(&params.password) {
            return ok_error(e);
        }
        if let Some(p) = params.ca_path.as_mut() {
            match validate_path(p, "ca_path") {
                Ok(v) => *p = v,
                Err(e) => return ok_error(e),
            }
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
        title = "Create PKCS12 Keystore",
        description = "Create a PKCS12 keystore from PEM certificate and private key files. Java-compatible since JDK 9. Returns warnings when the cert PEM is missing the issuer chain or when the leaf cert is not first.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn create_keystore(
        &self,
        Parameters(mut params): Parameters<CreateKeystoreParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match validate_path(&params.cert_path, "cert_path") {
            Ok(p) => params.cert_path = p,
            Err(e) => return ok_error(e),
        }
        match validate_path(&params.key_path, "key_path") {
            Ok(p) => params.key_path = p,
            Err(e) => return ok_error(e),
        }
        match validate_path(&params.output_path, "output_path") {
            Ok(p) => params.output_path = p,
            Err(e) => return ok_error(e),
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
        title = "Create CSR and Private Key",
        description = "Create a PKCS#10 Certificate Signing Request (CSR) and private key. Supports RSA 4096 (default), RSA 2048, ECDSA P-256 (recommended modern), ECDSA P-384, and Ed25519 (modern EdDSA). Compliant with CA/B Forum Baseline Requirements, DigiCert, and X9 standards. OU fields can encode metadata identifiers (e.g., AppId:my-app-123) for internal PKI. Returns JSON with CSR details, key info, and file paths.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    pub async fn create_csr(
        &self,
        Parameters(mut params): Parameters<CreateCsrParams>,
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
        match validate_path(&params.csr_output_path, "csr_output_path") {
            Ok(p) => params.csr_output_path = p,
            Err(e) => return ok_error(e),
        }
        match validate_path(&params.key_output_path, "key_output_path") {
            Ok(p) => params.key_output_path = p,
            Err(e) => return ok_error(e),
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
        // Every subject field and SAN lands in argv, so each one gets the
        // same flag, control character and length checks as any other
        // free form argument.
        if let Err(e) = validate_args(&[
            ("common_name", Some(params.common_name.as_str())),
            ("organization", params.organization.as_deref()),
            ("state", params.state.as_deref()),
            ("locality", params.locality.as_deref()),
            ("email", params.email.as_deref()),
        ])
        .and_then(|()| validate_list(&params.organizational_units, "organizational_units", 100))
        .and_then(|()| validate_list(&params.subject_alternative_names, "subject_alternative_names", 100))
        {
            return ok_error(e);
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
        title = "Validate CSR",
        description = "Validate a PEM-encoded Certificate Signing Request (CSR) for compliance with CA/B Forum Baseline Requirements, DigiCert, and X9 standards. Checks key algorithm/size, signature algorithm, SAN presence, OU deprecation, country code format, and more. Returns JSON with subject info, key details, SANs, compliance findings (error/warning/info), and overall compliant/non-compliant status.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn validate_csr(
        &self,
        Parameters(mut params): Parameters<ValidateCsrParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match validate_path(&params.csr_file, "csr_file") {
            Ok(p) => params.csr_file = p,
            Err(e) => return ok_error(e),
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

    /// Diagnose TLS, mTLS, gateway, CDN and forward proxy failures for an endpoint.
    #[tool(
        title = "Diagnose HTTPS Endpoint",
        description = "Diagnose why an HTTPS endpoint fails or misbehaves: TLS handshake failures, mutual TLS on any server (client certificate required, optional or rejected, detected from the server's CertificateRequest on TLS 1.2 and 1.3), Apigee runtime faults (target TLS handshake failures, unreachable or slow targets, policy faults), Envoy and Istio upstream errors, nginx client certificate errors, Amazon CloudFront (edge generated 4xx/5xx pages, origin errors forwarded by the edge, viewer mTLS, origin mTLS gaps, security policy mismatches), Amazon API Gateway (gateway responses such as Missing Authentication Token, Forbidden, throttling, integration timeouts and 5xx, mutual TLS custom domains, private API endpoints), forward web proxies (CONNECT 407/403/5xx, wrong proxy scheme, HTTP_PROXY only environments) and TLS inspection (chains re signed by Zscaler, Netskope and similar gateways). Probes the target, captures the TLS handshake, certificate chain, HTTP status, headers and a bounded body excerpt, and scores them against the diagnostics knowledge base. Returns JSON findings ordered earliest layer first, each with a confidence figure, the evidence that matched, a root cause and remediation steps, plus `platforms` (the products fingerprinted from headers, body, host and chain; vendor specific findings require one, so a non AWS endpoint never gets CloudFront or API Gateway advice) and `context` notes explaining what the status, headers and body sentences of a CloudFront or API Gateway response mean. Supports mTLS, connection overrides and per request proxy settings like analyze_certificate.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn diagnose_endpoint(
        &self,
        Parameters(mut params): Parameters<DiagnoseEndpointParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut args = vec!["--format".to_string(), "json".to_string()];
        if params.show_body {
            args.push("--show-body".to_string());
        }
        if params.no_verify {
            args.push("--no-verify".to_string());
        }
        // A failed probe is the expected input for a diagnosis, so exit
        // codes are reported inline rather than treated as tool errors.
        let outcome = self
            .run_probe(
                "diagnose",
                &params.target,
                args,
                &mut params.mtls,
                Some(&params.http_tls),
            )
            .await;
        tool_reply(outcome, "stderr", &[0])
    }

    /// Explain a CloudFront or API Gateway status code, header, error name or topic.
    #[tool(
        title = "Explain CloudFront/API Gateway Term",
        description = "Look up what an Amazon CloudFront or Amazon API Gateway response means, from dcert's built in reference knowledge base compiled from the AWS documentation and Knowledge Center. Accepts an HTTP status code (403, 502, 504), a response header (x-cache, x-amz-cf-pop, x-amzn-errortype, cloudfront-viewer-cert-present), a control plane exception name (NoSuchDistribution, InvalidViewerCertificate, TooManyRequestsException), a gateway response type (MISSING_AUTHENTICATION_TOKEN, INTEGRATION_TIMEOUT) or a topic keyword (viewer-mtls, passthrough, origin-mtls, truststore, security policy, signed url, error caching, limits). Returns JSON answers with a summary, causes and checks, and documentation references. Use it to interpret the `context` notes and diagnosis ids returned by diagnose_endpoint, or to answer questions about CloudFront and API Gateway behaviour without probing anything. AWS only: do not use it to explain responses from Apigee, Envoy, nginx or other non AWS endpoints.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn explain_edge_term(
        &self,
        Parameters(params): Parameters<ExplainEdgeTermParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = validate_arg(&params.query, "query") {
            return ok_error(e);
        }
        if let Some(service) = params.service.as_deref()
            && let Err(e) = validate_arg(service, "service")
        {
            return ok_error(e);
        }
        let mut args = vec!["kb", "explain", params.query.as_str(), "--format", "json"];
        if let Some(service) = params.service.as_deref() {
            args.push("--service");
            args.push(service);
        }
        match run_dcert_raw(&args, &self.config, None).await {
            Ok((stdout, stderr, code)) => {
                let ok_codes = explain_ok_codes(code, &stdout);
                ok_text(format_tool_output(stdout, &stderr, code, "stderr", ok_codes))
            }
            Err(e) => ok_error(e),
        }
    }

    /// Validate TLS certificates against industry standards and report compliance status.
    #[tool(
        title = "Validate Certificate Compliance",
        description = "Validate TLS certificates from an HTTPS endpoint or PEM file against CA/B Forum Baseline Requirements, DigiCert, and X9 standards. Checks key size, signature algorithm (SHA-1/MD5 rejection), SAN presence, certificate validity period (398-day max), Certificate Transparency (SCT presence), Extended Key Usage, and CA constraints. Returns JSON with per-certificate findings (error/warning/info) and overall COMPLIANT/NON-COMPLIANT status. Supports mTLS.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn validate_certificate(
        &self,
        Parameters(mut params): Parameters<ValidateCertificateParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args = vec!["--format".to_string(), "json".to_string(), "--compliance".to_string()];
        let outcome = self
            .run_probe("check", &params.target, args, &mut params.mtls, None)
            .await;
        tool_reply(outcome, "debug/stderr", &[0])
    }

    /// Create a PKCS12 truststore from CA certificates.
    #[tool(
        title = "Create PKCS12 Truststore",
        description = "Create a PKCS12 truststore from CA certificate PEM files. Java-compatible since JDK 9. Bundles multiple CA certificates into a single truststore file. Returns warnings about leaf certs, duplicates, expired CAs, and CA-rotation cases (same subject, different fingerprint). Leaf (non CA) certificates are refused with a beginner friendly explanation, as in the CLI; set `allow_non_ca: true` to include them anyway.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn create_truststore(
        &self,
        Parameters(mut params): Parameters<CreateTruststoreParams>,
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
        for path in &mut params.cert_paths {
            match validate_path(path, "cert_paths") {
                Ok(p) => *path = p,
                Err(e) => return ok_error(e),
            }
        }
        match validate_path(&params.output_path, "output_path") {
            Ok(p) => params.output_path = p,
            Err(e) => return ok_error(e),
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
