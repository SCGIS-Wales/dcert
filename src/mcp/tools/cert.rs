//! Certificate analysis, conversion, key and CSR tools.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use super::{DcertMcpServer, ok_error, ok_text, reply};
use crate::cliargs::ArgBuilder;
use crate::exec::{Invocation, RunOutcome, run_dcert, target_args};
use crate::params::*;
use crate::validate::*;

impl DcertMcpServer {
    /// The prologue every network probe shares: validate the target and the
    /// mTLS and HTTP/TLS options, check the destination policy, serialise the
    /// parameters with [`ToCliArgs`] and run dcert.
    pub(crate) async fn run_probe<P: ProbeParams>(&self, params: &mut P) -> RunOutcome {
        let target = resolve_target(params.target())?;
        let (mtls, http_tls) = params.groups();
        mtls.validate()?;
        if let Some(http_tls) = http_tls {
            http_tls.validate()?;
        }
        check_destinations(&self.config.destinations, probe_destinations(&target, http_tls)?).await?;
        // The files are kept alive until the child has finished reading them.
        let (file_args, _secret_files) = match http_tls {
            Some(http_tls) => http_tls.secret_files()?,
            None => (Vec::new(), Vec::new()),
        };
        let (mut options, env_refs) = params.cli_args();
        options.extend(file_args);
        let args = target_args(P::SUBCOMMAND, options, &target);
        run_dcert(Invocation::new(args).env(&env_refs), &self.config).await
    }
}

/// A tool answer computed in process, as pretty JSON.
fn json_reply<T: serde::Serialize>(value: &T) -> Result<CallToolResult, rmcp::ErrorData> {
    match serde_json::to_string_pretty(value) {
        Ok(text) => ok_text(text),
        Err(e) => ok_error(format!("cannot serialise the answer: {e}")),
    }
}

/// Whether the operator lets tool calls disable certificate verification
/// (`DCERT_MCP_ALLOW_NO_VERIFY=1`). The caller is not the party who should
/// decide that the server may talk to an unverified peer.
pub(crate) fn no_verify_allowed() -> bool {
    std::env::var("DCERT_MCP_ALLOW_NO_VERIFY").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
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
        if let Some(t) = params.issuer_timeout
            && let Err(e) = dcert::limits::check_range("issuer_timeout", t, &dcert::limits::ISSUER_TIMEOUT_RANGE)
        {
            return ok_error(e);
        }
        let outcome = self.run_probe(&mut params).await;
        reply(outcome, "debug/stderr", &[0])
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
        if let Err(e) = dcert::limits::check_range("days", params.days, &dcert::limits::EXPIRY_WARN_RANGE) {
            return ok_error(e);
        }

        let outcome = self.run_probe(&mut params).await.map(|(stdout, stderr, code)| {
            let status = match code {
                0 => "ALL_VALID",
                1 => "EXPIRING_SOON",
                4 => "ALREADY_EXPIRED",
                _ => "ERROR",
            };
            (format!("expiry_status: {status}\n\n{stdout}"), stderr, code)
        });
        reply(outcome, "warnings", &[0, 1, 4])
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
        let outcome = self.run_probe(&mut params).await.map(|(stdout, stderr, code)| {
            let prefixed = match code {
                5 => format!("revocation_status: REVOKED\n\n{stdout}"),
                8 => format!("revocation_status: CHECK_FAILED\n\n{stdout}"),
                _ => stdout,
            };
            (prefixed, stderr, code)
        });
        reply(outcome, "stderr", &[0, 5, 8])
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
        let (result_a, result_b) = tokio::join!(
            run_dcert(Invocation::new(args_a), &self.config),
            run_dcert(Invocation::new(args_b), &self.config)
        );

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
        description = "Get TLS connection details for an HTTPS endpoint including protocol version, the negotiated cipher suite (`tls_cipher`: by default a record with the OpenSSL and IANA names, code point, protocol, forward secrecy and AEAD; set `ciphers_notation` to \"iana\" or \"openssl\" for that name alone), ALPN negotiation, DNS/TCP/TLS latency, verification status, full OSI-layer diagnostics, the mTLS state (`client_auth`: not_requested, optional, required or presented, detected from the server's CertificateRequest on TLS 1.2 and 1.3, `acceptable_client_cas` with the CA names the server accepts, and `client_auth_required` plus the captured server chain when the server refuses the connection without a client certificate). Supports mTLS and custom CA bundles. To probe a specific IP/backend while validating a hostname (e.g. behind a load balancer, or when DNS does not resolve), keep the hostname in `target` and use `connect_to` (an IP, or 'HOST1:PORT1:HOST2:PORT2' to redirect to another hostname/port) or `resolve` ('HOST:PORT:IP'). Set `proxy`/`noproxy` to override the forward proxy for this request. Set `cipher` to offer specific suites in any notation.",
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
        // Parse both bounds into the CLI's own enum so the ordering check
        // compares versions, not strings.
        let mut bounds = (None, None);
        for (value, slot) in [(&params.min_tls, &mut bounds.0), (&params.max_tls, &mut bounds.1)] {
            if let Some(v) = value {
                match validate_tls_version(v) {
                    Ok(parsed) => *slot = Some(parsed),
                    Err(e) => return ok_error(e),
                }
            }
        }
        if let (Some(min), Some(max)) = bounds
            && min > max
        {
            return ok_error(format!("min_tls ({min}) must not be greater than max_tls ({max})"));
        }
        let legacy = [bounds.0, bounds.1]
            .into_iter()
            .flatten()
            .any(dcert::cli::TlsVersionArg::is_legacy);
        if legacy && params.http_tls.allow_legacy_tls != Some(true) {
            return ok_error(
                "TLS 1.0 and 1.1 are deprecated (RFC 8996); set allow_legacy_tls to true to probe them".to_string(),
            );
        }
        let outcome = self.run_probe(&mut params).await;
        reply(outcome, "debug/stderr", &[0])
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

        let outcome = self.run_probe(&mut params).await.map(|(stdout, stderr, code)| {
            let prefixed = match &params.output_path {
                Some(path) => format!("PEM chain exported to: {path}\n\n{stdout}"),
                None => stdout,
            };
            (prefixed, stderr, code)
        });
        reply(outcome, "debug/stderr", &[0])
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
        reply(run_dcert(Invocation::new(args), &self.config).await, "stderr", &[0, 7])
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

        reply(run_dcert(Invocation::new(args), &self.config).await, "stderr", &[0, 7])
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

        reply(
            run_dcert(Invocation::new(args).env(&env_vars), &self.config).await,
            "stderr",
            &[0],
        )
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

        let mut b = ArgBuilder::new();
        b.positional(["convert", "--format=json", "pem-to-pfx"])
            .value("cert", Some(&params.cert_path))
            .value("key", Some(&params.key_path))
            .value("output", Some(&params.output_path))
            .value("ca", params.ca_path.as_deref())
            // The password travels in the environment, never in argv.
            .env("DCERT_CERT_PASSWORD", Some(params.password.as_str()));
        let (args, env) = b.into_parts();
        reply(
            run_dcert(Invocation::new(args).env(&env), &self.config).await,
            "stderr",
            &[0],
        )
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

        reply(
            run_dcert(Invocation::new(args).env(&env_vars), &self.config).await,
            "stderr",
            &[0],
        )
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

        let mut b = ArgBuilder::new();
        b.positional(["csr", "create"])
            .value("cn", Some(&params.common_name))
            .value("key-algo", Some(&params.key_algorithm))
            .value("csr-out", Some(&params.csr_output_path))
            .value("key-out", Some(&params.key_output_path))
            .value("format", Some("json"))
            .value("org", params.organization.as_deref())
            .repeat("ou", &params.organizational_units)
            .value("country", params.country.as_deref())
            .value("state", params.state.as_deref())
            .value("locality", params.locality.as_deref())
            .value("email", params.email.as_deref())
            .repeat("san", &params.subject_alternative_names)
            .flag("encrypt-key", params.encrypt_key)
            // The passphrase travels in the environment, never in argv.
            .env(
                "DCERT_KEY_PASSWORD",
                params.key_password.as_deref().filter(|_| params.encrypt_key),
            );
        let (args, env_refs) = b.into_parts();
        reply(
            run_dcert(Invocation::new(args).env(&env_refs), &self.config).await,
            "notes",
            &[0],
        )
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

        let mut b = ArgBuilder::new();
        b.positional(["csr", "validate", params.csr_file.as_str()])
            .value("format", Some("json"))
            .flag("warnings-as-errors", params.strict);
        let (args, _) = b.into_parts();
        reply(run_dcert(Invocation::new(args), &self.config).await, "notes", &[0])
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
        if params.no_verify && !no_verify_allowed() {
            return ok_error(
                "no_verify is not permitted by the server policy (set DCERT_MCP_ALLOW_NO_VERIFY=1 on the server to allow it)"
                    .to_string(),
            );
        }
        // A failed probe is the expected input for a diagnosis, so exit
        // codes are reported inline rather than treated as tool errors.
        let outcome = self.run_probe(&mut params).await;
        reply(outcome, "stderr", &[0])
    }

    /// List TLS cipher suites from the IANA registry.
    #[tool(
        title = "List TLS Cipher Suites",
        description = "List TLS cipher suites from dcert's table of the IANA TLS Cipher Suites registry, without any network access. Each entry has the code point, IANA name, OpenSSL name (null when OpenSSL does not implement the suite), protocol family (tls12 or tls13), key exchange, authentication, encryption, MAC, the AEAD, forward secrecy, export, NULL, anonymous and FIPS flags, the IANA recommended or discouraged status, and whether this server's linked OpenSSL can offer it. Filter with `protocol` (\"1.2\" or \"1.3\") and `offerable`. Use explain_cipher_suite for one suite.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn list_cipher_suites(
        &self,
        Parameters(params): Parameters<ListCipherSuitesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let protocol = match params.protocol.as_deref() {
            None => None,
            Some(v) => match parse_enum::<dcert::cli::CipherFamilyArg>("protocol", v, false) {
                Ok(version) => Some(version.into()),
                Err(e) => return ok_error(e),
            },
        };
        json_reply(&dcert::ciphers::list(protocol, params.offerable))
    }

    /// Show one TLS cipher suite in every notation.
    #[tool(
        title = "Explain TLS Cipher Suite",
        description = "Explain one TLS cipher suite given in any notation: IANA name (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256), OpenSSL name (ECDHE-RSA-AES128-GCM-SHA256) or code point (0xC02F, C02F, 0xC0,0x2F), case insensitive. Returns JSON with every notation, the protocol family, key exchange, authentication, encryption, MAC, the AEAD, forward secrecy, export, NULL, anonymous and FIPS flags, the IANA recommended or discouraged status, and whether this server's linked OpenSSL can offer it. An unknown name returns an error with the nearest known names. No network access. Use it to translate between notations, for example the OpenSSL names in an AWS load balancer security policy and the IANA names in a scanner report.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn explain_cipher_suite(
        &self,
        Parameters(params): Parameters<ExplainCipherSuiteParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match dcert::ciphers::Cipher::parse(&params.suite) {
            Ok(cipher) => json_reply(&dcert::ciphers::CipherDetails::from(cipher)),
            Err(e) => ok_error(e.to_string()),
        }
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
        let mut b = ArgBuilder::new();
        b.positional(["kb", "explain", params.query.as_str()])
            .value("format", Some("json"))
            .value("service", params.service.as_deref());
        let (args, _) = b.into_parts();
        let outcome = run_dcert(Invocation::new(args), &self.config).await;
        let ok_codes = match &outcome {
            Ok((stdout, _, code)) => explain_ok_codes(*code, stdout),
            Err(_) => &[0],
        };
        reply(outcome, "stderr", ok_codes)
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
        let outcome = self.run_probe(&mut params).await;
        reply(outcome, "debug/stderr", &[0])
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
        let mut b = ArgBuilder::new();
        b.positional(["convert", "--format=json", "create-truststore"])
            .positional(&params.cert_paths)
            .value("output", Some(&params.output_path))
            .flag("allow-non-ca", params.allow_non_ca)
            // The password travels in the environment, never in argv.
            .env("DCERT_TRUSTSTORE_PASSWORD", Some(params.password.as_str()));
        let (args, env_refs) = b.into_parts();
        reply(
            run_dcert(Invocation::new(args).env(&env_refs), &self.config).await,
            "stderr",
            &[0],
        )
    }
}
