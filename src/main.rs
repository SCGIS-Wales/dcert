use anyhow::{Context, Result};
use clap::CommandFactory;
use clap::Parser;
use colored::*;
use dcert::{cert, cli, connect, convert, csr, diagnose, output, proxy, trust, vault};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use cli::{CheckArgs, Cli, Command, HttpMethod, KNOWN_SUBCOMMANDS, OutputFormat, exit_code};
use connect::ConnectOverrides;
use output::{
    StructuredOutput, TargetResult, check_expiry_warnings, export_pem_chain, output_results, print_diff,
    print_structured, process_target,
};
use proxy::ProxyConfig;

/// Maximum size for stdin input (10 MB). Prevents OOM from accidentally
/// piping huge files. 10 MB is generous enough for large PEM bundles
/// containing 50+ certificates.
const MAX_STDIN_SIZE: usize = 10 * 1024 * 1024;

/// Conventional Unix exit code for SIGINT-terminated processes (128 + SIGINT(2)).
const EXIT_INTERRUPTED: i32 = 130;

/// Warn when a secret was supplied on the command line rather than through
/// its environment variable, since argv is visible to every local user.
fn warn_secret_on_argv(flag: &str, env_var: &str, provided: bool) {
    if provided && std::env::var_os(env_var).is_none() {
        eprintln!(
            "{} {}",
            "WARNING:".yellow().bold(),
            format!("Secret passed via {flag} is visible in process listings. Set {env_var} instead.").yellow()
        );
    }
}

/// Register a single, process-wide Ctrl+C handler that prints a friendly
/// message and exits with code 130. Returns an `AtomicBool` that long-running
/// loops (e.g. `--watch`) can poll for graceful shutdown — the handler also
/// flips this bool to false before exiting, so cooperative loops still work.
///
/// Most dcert flows are blocked inside OpenSSL `connect()` or TCP I/O when
/// SIGINT arrives — they cannot poll the bool until the syscall returns.
/// Calling `process::exit()` from the handler is the only way to make Ctrl+C
/// feel responsive there. Watch mode owns its own polling loop and benefits
/// from the bool too: see `run_check_with_stdin` watch branch.
fn register_sigint_handler() -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        eprintln!("\n{} Interrupted (Ctrl+C). Exiting cleanly.", "^C".yellow().bold());
        std::process::exit(EXIT_INTERRUPTED);
    }) {
        eprintln!(
            "{} Failed to register Ctrl+C handler: {}. Ctrl+C may not exit cleanly.",
            "WARNING:".yellow().bold(),
            e
        );
    }
    running
}

fn run_check(args: CheckArgs) -> Result<i32> {
    run_check_with_stdin(args, None)
}

fn run_check_with_stdin(mut args: CheckArgs, pre_read_stdin: Option<String>) -> Result<i32> {
    // Warn prominently when certificate verification is disabled
    if args.no_verify {
        eprintln!(
            "{} {}",
            "WARNING:".yellow().bold(),
            "TLS certificate verification is disabled (--no-verify). Connection is NOT secure.".yellow()
        );
    }

    // Validate min_tls <= max_tls ordering if both are set
    if let (Some(min), Some(max)) = (&args.min_tls, &args.max_tls) {
        let min_ord = match min {
            cli::TlsVersionArg::Tls1_2 => 0,
            cli::TlsVersionArg::Tls1_3 => 1,
        };
        let max_ord = match max {
            cli::TlsVersionArg::Tls1_2 => 0,
            cli::TlsVersionArg::Tls1_3 => 1,
        };
        if min_ord > max_ord {
            return Err(anyhow::anyhow!(
                "--min-tls ({min}) must not be greater than --max-tls ({max})"
            ));
        }
    }

    warn_secret_on_argv("--cert-password", "DCERT_CERT_PASSWORD", args.cert_password.is_some());

    // Resolve request body from --data or --data-file
    let body_data: Option<Vec<u8>> = if let Some(ref data) = args.data {
        Some(data.as_bytes().to_vec())
    } else if let Some(ref path) = args.data_file {
        Some(std::fs::read(path).with_context(|| format!("Failed to read data file: {path}"))?)
    } else {
        None
    };

    // Auto-promote method to POST when body is provided and method is at default (GET)
    if body_data.is_some() && matches!(args.method, HttpMethod::Get) {
        args.method = HttpMethod::Post;
    }

    // Cache proxy configuration at startup: --proxy/--noproxy layered over the
    // standard environment variables.
    let proxy_config = ProxyConfig::resolve(args.proxy.as_deref(), args.noproxy.as_deref())?;

    // --resolve and --connect-to share one lookup table, built once per run.
    let connect_overrides = ConnectOverrides::new(&args.resolve, &args.connect_to);

    // Build the public root set once per invocation (offline by default;
    // optionally refreshed from the upstream Mozilla/CCADB bundle). Reused
    // across every target so classifying 50+ certs stays fast.
    let public_roots = trust::PublicRoots::load(
        args.refresh_public_roots,
        &proxy_config,
        Duration::from_secs(args.issuer_timeout),
        args.debug,
    )?;

    // Resolve targets (support stdin via '-')
    let mut targets: Vec<String> = Vec::new();
    let mut stdin_pem: Option<String> = None;
    for t in &args.targets {
        if t == "-" {
            // Use pre-read stdin data if available, otherwise read now
            let content = if let Some(ref data) = pre_read_stdin {
                data.clone()
            } else {
                use std::io::Read as _;
                let mut buf = Vec::new();
                std::io::stdin()
                    .lock()
                    .take(MAX_STDIN_SIZE as u64 + 1)
                    .read_to_end(&mut buf)
                    .with_context(|| "Failed to read from stdin")?;
                if buf.len() > MAX_STDIN_SIZE {
                    return Err(anyhow::anyhow!(
                        "Stdin input exceeds {} MB limit",
                        MAX_STDIN_SIZE / (1024 * 1024)
                    ));
                }
                String::from_utf8_lossy(&buf).to_string()
            };

            let trimmed = content.trim();

            if trimmed.starts_with("-----BEGIN ") {
                // Stdin contains PEM data — process it directly
                stdin_pem = Some(content);
                targets.push("-".to_string());
            } else {
                // Stdin contains target names (one per line)
                for line in trimmed.lines() {
                    let line = line.trim();
                    if !line.is_empty() {
                        targets.push(line.to_string());
                    }
                }
            }
        } else {
            targets.push(t.clone());
        }
    }

    if targets.is_empty() {
        return Err(anyhow::anyhow!("No targets specified"));
    }

    // Validate diff mode
    if args.diff && targets.len() != 2 {
        return Err(anyhow::anyhow!("--diff requires exactly 2 targets"));
    }

    // Auto-enable fingerprint in diff mode so comparisons include fingerprints
    if args.diff && !args.fingerprint {
        args.fingerprint = true;
    }

    // Watch mode
    if let Some(interval) = args.watch {
        // Auto-enable fingerprint in watch mode so change detection works
        if !args.fingerprint {
            args.fingerprint = true;
        }

        // The global SIGINT handler (registered in `main()`) flips this bool to
        // false before exiting, but we re-register here for the rare case where
        // run() wasn't entered (e.g. tests calling run_check_with_stdin directly).
        // ctrlc::set_handler() returns an error on second registration, which is
        // fine — the global handler is already in place.
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let _ = ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        });

        let mut iteration = 0u64;
        let mut prev_fingerprints: std::collections::HashMap<String, Vec<Option<String>>> =
            std::collections::HashMap::new();

        while running.load(Ordering::SeqCst) {
            iteration += 1;
            let now = OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "unknown time".to_string());
            println!(
                "{}",
                format!("=== Watch iteration {iteration} at {now} ===").bold().cyan()
            );

            for target in &targets {
                match process_target(
                    target,
                    &args,
                    &proxy_config,
                    &connect_overrides,
                    &public_roots,
                    body_data.as_deref(),
                    stdin_pem.as_deref(),
                ) {
                    Ok(result) => {
                        // Check for changes
                        let current_fps: Vec<Option<String>> =
                            result.infos.iter().map(|c| c.sha256_fingerprint.clone()).collect();

                        if let Some(prev) = prev_fingerprints.get(target)
                            && prev != &current_fps
                        {
                            println!("{}", format!("CHANGE DETECTED for {target}").red().bold());
                        }
                        prev_fingerprints.insert(target.clone(), current_fps);

                        output_results(&result, args.format, &args.http_protocol, targets.len() > 1, &args)?;
                    }
                    Err(e) => {
                        eprintln!("{} {}: {}", "Error:".red().bold(), target, e);
                    }
                }
            }

            if !running.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_secs(interval));
        }

        println!("\nWatch stopped.");
        return Ok(0);
    }

    // Normal (non-watch) mode
    let multi_target = targets.len() > 1;
    let mut exit_code = exit_code::SUCCESS;
    let mut all_results: Vec<TargetResult> = Vec::new();

    // Diagnostics: load the knowledge base once, and describe the probe so
    // signals about the proxy and client identity can be evaluated.
    let kb = if args.no_diagnose {
        None
    } else {
        Some(diagnose::KnowledgeBase::load(
            args.kb_file.as_deref().map(std::path::Path::new),
        )?)
    };
    let probe = diagnose::ProbeContext {
        proxy: Some(&proxy_config),
        client_cert_supplied: args.client_cert.is_some() || args.pkcs12.is_some(),
        sni_overridden: args.sni.is_some(),
    };
    let mut diagnose_outputs: Vec<DiagnoseOutput> = Vec::new();

    for target in &targets {
        match process_target(
            target,
            &args,
            &proxy_config,
            &connect_overrides,
            &public_roots,
            body_data.as_deref(),
            stdin_pem.as_deref(),
        ) {
            Ok(mut result) => {
                let mut keep_body = args.show_body;
                if let Some(kb) = &kb {
                    let evidence = diagnose::Evidence::from_result(
                        target,
                        &probe,
                        result.conn_info.as_ref(),
                        &result.infos,
                        result.root_trust.as_ref(),
                    );
                    let report = diagnose::diagnose(kb, &evidence);
                    keep_body |= report.body_matched;
                    result.diagnosis = report.findings;
                }
                // The body excerpt is evidence, not output: keep it only when
                // asked for or when a finding cites it.
                if !keep_body && let Some(conn) = result.conn_info.as_mut() {
                    conn.http_body_excerpt = None;
                    conn.http_body_truncated = false;
                }
                if args.diagnose_only {
                    diagnose_outputs.push(DiagnoseOutput {
                        target: target.clone(),
                        error: None,
                        http_status: result
                            .conn_info
                            .as_ref()
                            .map(|c| c.http_response_code)
                            .filter(|c| *c > 0),
                        diagnosis: result.diagnosis.clone(),
                        body_excerpt: result.conn_info.as_ref().and_then(|c| c.http_body_excerpt.clone()),
                        body_truncated: result.conn_info.as_ref().is_some_and(|c| c.http_body_truncated),
                    });
                }
                // Promote to CLIENT_CERT_ERROR when the server demanded an mTLS
                // client cert we didn't supply. This is more specific than the
                // generic VERIFY_FAILED and tells callers what to fix.
                if let Some(ref conn) = result.conn_info
                    && conn.client_auth_required
                    && exit_code < exit_code::CLIENT_CERT_ERROR
                {
                    exit_code = exit_code::CLIENT_CERT_ERROR;
                } else if let Some(ref conn) = result.conn_info
                    && conn.verify_result.is_some()
                    && exit_code < exit_code::VERIFY_FAILED
                {
                    exit_code = exit_code::VERIFY_FAILED;
                }
                all_results.push(result);
            }
            Err(e) => {
                eprintln!("{} {}: {}", "Error:".red().bold(), target, e);
                if exit_code < exit_code::ERROR {
                    exit_code = exit_code::ERROR;
                }
                if let Some(kb) = &kb {
                    let evidence = diagnose::Evidence::from_error(target, &probe, &e);
                    let report = diagnose::diagnose(kb, &evidence);
                    if args.diagnose_only {
                        diagnose_outputs.push(DiagnoseOutput {
                            target: target.clone(),
                            error: Some(format!("{e:#}")),
                            http_status: None,
                            diagnosis: report.findings,
                            // A probe that failed outright never read a body.
                            body_excerpt: None,
                            body_truncated: false,
                        });
                    } else if !report.findings.is_empty() && matches!(args.format, OutputFormat::Pretty) {
                        // Failed probes have no stdout record; keep the
                        // diagnosis next to the error on stderr.
                        let _ = output::write_diagnosis(&mut std::io::stderr().lock(), &report.findings);
                    }
                }
            }
        }
    }

    if args.diagnose_only {
        print_structured(args.format, &diagnose_outputs, || {
            print_diagnose_output_pretty(&diagnose_outputs);
        })?;
        return Ok(exit_code);
    }

    // Diff mode
    if args.diff {
        if all_results.len() == 2 {
            // Enable fingerprint for diff comparison
            print_diff(
                &all_results[0].target,
                &all_results[0].infos,
                &all_results[1].target,
                &all_results[1].infos,
            );
        } else {
            return Err(anyhow::anyhow!("Failed to fetch both targets for diff comparison"));
        }
        return Ok(exit_code);
    }

    // JSON multi-target wrapping
    if multi_target && matches!(args.format, OutputFormat::Json) {
        let mut map = serde_json::Map::new();
        for result in &all_results {
            map.insert(
                result.target.clone(),
                serde_json::to_value(StructuredOutput::from(result))?,
            );
        }
        println!("{}", serde_json::to_string_pretty(&map)?);
    } else if multi_target && matches!(args.format, OutputFormat::Yaml) {
        let map: std::collections::BTreeMap<&str, StructuredOutput> = all_results
            .iter()
            .map(|r| (r.target.as_str(), StructuredOutput::from(r)))
            .collect();
        println!("{}", serde_yaml_ng::to_string(&map)?);
    } else {
        for result in &all_results {
            output_results(result, args.format, &args.http_protocol, multi_target, &args)?;
        }
    }

    // Check for expired certificates
    for result in &all_results {
        if result.infos.iter().any(|c| c.is_expired) && exit_code < exit_code::CERT_EXPIRED {
            exit_code = exit_code::CERT_EXPIRED;
        }
        // Check for revoked certificates
        if result
            .infos
            .iter()
            .any(|c| c.revocation_status.as_deref() == Some("revoked"))
            && exit_code < exit_code::CERT_REVOKED
        {
            exit_code = exit_code::CERT_REVOKED;
        }
        // A revocation check that could not complete is not a clean result.
        if result
            .infos
            .iter()
            .any(|c| c.revocation_status.as_deref().is_some_and(|s| s.starts_with("error")))
            && exit_code < exit_code::REVOCATION_CHECK_FAILED
        {
            exit_code = exit_code::REVOCATION_CHECK_FAILED;
        }
    }

    // Check expiry warnings (overrides lower exit codes)
    if let Some(warn_days) = args.expiry_warn {
        for result in &all_results {
            if multi_target {
                eprintln!("--- Expiry check: {} ---", result.target);
            }
            let warn_code = check_expiry_warnings(&result.infos, warn_days);
            if warn_code > 0 && exit_code < exit_code::EXPIRY_WARNING {
                exit_code = exit_code::EXPIRY_WARNING;
            }
        }
    }

    // Export PEM
    if let Some(ref export_path) = args.export_pem {
        if all_results.len() == 1 {
            export_pem_chain(&all_results[0].pem_data, export_path, args.exclude_expired)?;
        } else {
            eprintln!("Warning: --export-pem only supported for a single target");
        }
    }

    // Check for empty results
    if all_results.iter().all(|r| r.infos.is_empty()) && exit_code < exit_code::ERROR {
        eprintln!("{}", "No valid certificates found in the input".red());
        return Ok(exit_code::ERROR);
    }

    Ok(exit_code)
}

/// Beginner primer printed by `--explain` on `create-truststore`.
const TRUSTSTORE_EXPLAIN: &str = "About truststores\n  \
- A truststore holds the CA certificates you trust (root + intermediates).\n  \
- It does NOT contain the website's own (leaf) certificate, and it never\n    \
  contains a private key.\n  \
- Java picks server identity from the keystore, and decides whether to\n    \
  trust a server's CA chain by checking against the truststore.\n  \
- To rotate CAs: add the new CA, deploy, verify, then remove the old one.\n";

/// Beginner primer printed by `--explain` on `create-keystore`.
const KEYSTORE_EXPLAIN: &str = "About keystores\n  \
- A keystore holds an identity: a private key plus the matching certificate\n    \
  (and its issuer chain).\n  \
- The leaf certificate must be FIRST in the cert PEM, followed by the\n    \
  intermediate CAs that issued it. Java needs the chain to present to\n    \
  remote clients.\n  \
- The keystore password protects the private key — keep it private.\n  \
- A keystore is NOT a truststore: that's a separate file that lists which\n    \
  CAs you trust.\n";

fn run_convert(args: cli::ConvertArgs) -> Result<i32> {
    // Warn when passwords are passed via CLI args (visible in process listing)
    match &args.mode {
        cli::ConvertMode::PfxToPem { .. } | cli::ConvertMode::PemToPfx { .. } => {
            warn_secret_on_argv("--password", "DCERT_CERT_PASSWORD", true);
        }
        cli::ConvertMode::CreateKeystore { .. } => {
            warn_secret_on_argv("--password", "DCERT_KEYSTORE_PASSWORD", true);
        }
        cli::ConvertMode::CreateTruststore { .. } => {} // truststore password is low-sensitivity
    }

    let format = args.format;
    match args.mode {
        cli::ConvertMode::PfxToPem {
            input,
            password,
            output_dir,
        } => {
            let result = convert::pfx_to_pem(&input, &password, &output_dir)?;
            output::render_convert_result(&result, format)?;
            Ok(exit_code::SUCCESS)
        }
        cli::ConvertMode::PemToPfx {
            cert,
            key,
            output,
            password,
            ca,
        } => {
            let result = convert::pem_to_pfx(&cert, &key, &password, &output, ca.as_deref())?;
            output::render_convert_result(&result, format)?;
            Ok(exit_code::SUCCESS)
        }
        cli::ConvertMode::CreateKeystore {
            cert,
            key,
            output,
            password,
            alias,
            explain,
        } => {
            if explain && matches!(format, OutputFormat::Pretty) {
                eprintln!("{KEYSTORE_EXPLAIN}");
            }
            let result = convert::create_keystore(&cert, &key, &password, &output, &alias)?;
            output::render_convert_result(&result, format)?;
            Ok(exit_code::SUCCESS)
        }
        cli::ConvertMode::CreateTruststore {
            certs,
            output,
            password,
            allow_non_ca,
            explain,
        } => {
            if explain && matches!(format, OutputFormat::Pretty) {
                eprintln!("{TRUSTSTORE_EXPLAIN}");
            }
            let result = convert::create_truststore(&certs, &password, &output, allow_non_ca)?;
            output::render_convert_result(&result, format)?;
            Ok(exit_code::SUCCESS)
        }
    }
}

/// Discover matching certificate/key pairs in a directory.
///
/// Scans for files with `.crt` or `.pem` extensions that have a corresponding `.key`
/// file with the same base name (e.g. `server.crt` + `server.key`, `app.pem` + `app.key`).
fn discover_cert_key_pairs(dir: &str) -> Result<Vec<(String, String)>> {
    let dir_path = std::path::Path::new(dir);
    if !dir_path.is_dir() {
        return Err(anyhow::anyhow!("'{dir}' is not a directory"));
    }

    let entries = std::fs::read_dir(dir_path).with_context(|| format!("Failed to read directory '{dir}'"))?;

    let mut pairs: Vec<(String, String)> = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Skip symlinks to prevent symlink-based attacks in shared directories
        if path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            continue;
        }

        // Only consider .crt and .pem files as certificate candidates
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "crt" && ext != "pem" {
            continue;
        }

        // Build the expected key path: same base name with .key extension
        let key_path = path.with_extension("key");
        // Also skip symlinked key files
        if key_path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            continue;
        }
        if key_path.exists() {
            pairs.push((
                path.to_string_lossy().to_string(),
                key_path.to_string_lossy().to_string(),
            ));
        }
    }

    // Sort for deterministic output
    pairs.sort();
    Ok(pairs)
}

fn print_single_result(result: &cert::KeyMatchResult, cert_path: Option<&str>, key_path: Option<&str>) {
    if let (Some(cert), Some(key)) = (cert_path, key_path) {
        println!("  Cert file      : {cert}");
        println!("  Key file       : {key}");
    }
    if result.matches {
        println!("{}", "  Key matches certificate".green().bold());
    } else {
        println!("{}", "  Key does NOT match certificate".red().bold());
    }
    println!("  Key type       : {}", result.key_type);
    println!("  Key size       : {} bits", result.key_size_bits);
    println!("  Cert subject   : {}", result.cert_subject);
    println!("  Cert key algo  : {}", result.cert_public_key_algorithm);
    println!("  Cert key size  : {} bits", result.cert_public_key_size_bits);
    if !result.details.is_empty() {
        println!("  Details        : {}", result.details);
    }
}

fn run_verify_key(args: cli::VerifyKeyArgs) -> Result<i32> {
    // If both target and key are provided, run single-pair verification
    if let (Some(target), Some(key)) = (&args.target, &args.key) {
        let result = cert::verify_key_matches_cert(key, target, args.debug)?;

        print_structured(args.format, &result, || print_single_result(&result, None, None))?;

        return if result.matches {
            Ok(exit_code::SUCCESS)
        } else {
            Ok(exit_code::KEY_MISMATCH)
        };
    }

    // If only one of target/key is provided, that's an error
    if args.target.is_some() || args.key.is_some() {
        return Err(anyhow::anyhow!(
            "Both target and --key must be provided together, or omit both to auto-discover cert/key pairs in the directory"
        ));
    }

    // Auto-discovery mode: scan directory for matching cert/key pairs
    let pairs = discover_cert_key_pairs(&args.dir)?;
    if pairs.is_empty() {
        return Err(anyhow::anyhow!(
            "No matching cert/key pairs found in '{}'. \
             Looking for .crt/.pem files with a matching .key file (same base name, e.g. server.crt + server.key)",
            args.dir
        ));
    }

    eprintln!("Found {} cert/key pair(s) in '{}'", pairs.len(), args.dir);

    let mut exit_code = exit_code::SUCCESS;
    let mut all_results: Vec<serde_json::Value> = Vec::new();

    for (cert_path, key_path) in &pairs {
        match cert::verify_key_matches_cert(key_path, cert_path, args.debug) {
            Ok(result) => {
                match args.format {
                    OutputFormat::Json | OutputFormat::Yaml => {
                        let mut val = serde_json::to_value(&result)?;
                        if let Some(obj) = val.as_object_mut() {
                            obj.insert("cert_file".to_string(), serde_json::json!(cert_path));
                            obj.insert("key_file".to_string(), serde_json::json!(key_path));
                        }
                        all_results.push(val);
                    }
                    OutputFormat::Pretty => {
                        if pairs.len() > 1 {
                            println!("---");
                        }
                        print_single_result(&result, Some(cert_path), Some(key_path));
                    }
                }
                if !result.matches && exit_code < exit_code::KEY_MISMATCH {
                    exit_code = exit_code::KEY_MISMATCH;
                }
            }
            Err(e) => {
                eprintln!("{} {} + {}: {}", "Error:".red().bold(), cert_path, key_path, e);
                if exit_code < exit_code::ERROR {
                    exit_code = exit_code::ERROR;
                }
            }
        }
    }

    // Output collected JSON/YAML results
    // Pretty output was printed per pair above.
    print_structured(args.format, &all_results, || {})?;

    Ok(exit_code)
}

fn run_csr(args: cli::CsrArgs) -> Result<i32> {
    match args.mode {
        cli::CsrMode::Create(create_args) => run_csr_create(*create_args),
        cli::CsrMode::Validate(validate_args) => run_csr_validate(validate_args),
    }
}

fn run_csr_create(args: cli::CsrCreateArgs) -> Result<i32> {
    use csr::{CsrCreateOptions, CsrSubject, KeyAlgorithm};

    let key_algo = match args.key_algo {
        cli::KeyAlgorithmArg::Rsa4096 => KeyAlgorithm::Rsa4096,
        cli::KeyAlgorithmArg::Rsa2048 => KeyAlgorithm::Rsa2048,
        cli::KeyAlgorithmArg::EcdsaP256 => KeyAlgorithm::EcdsaP256,
        cli::KeyAlgorithmArg::EcdsaP384 => KeyAlgorithm::EcdsaP384,
        cli::KeyAlgorithmArg::Ed25519 => KeyAlgorithm::Ed25519,
    };

    // If no CN is provided, enter interactive mode
    let (opts, csr_path, key_path) = if let Some(cn) = args.cn {
        // Build SANs — auto-add CN as DNS SAN if no SANs provided
        let mut sans = args.san;
        if sans.is_empty() {
            sans.push(format!("DNS:{cn}"));
        }

        // Validate key password requirement
        if args.encrypt_key && args.key_password.is_none() {
            return Err(anyhow::anyhow!("--key-password is required when --encrypt-key is set"));
        }

        // Determine output paths
        let base = csr::sanitise_cn(&cn);
        let csr_path = args.csr_out.unwrap_or_else(|| format!("{base}.csr"));
        let key_path = args.key_out.unwrap_or_else(|| format!("{base}.key"));

        let subject = CsrSubject {
            common_name: cn,
            organization: args.org,
            organizational_units: args.ou,
            country: args.country,
            state: args.state,
            locality: args.locality,
            email: args.email,
        };

        let opts = CsrCreateOptions {
            subject,
            san: sans,
            key_algo,
            encrypt_key: args.encrypt_key,
            key_password: args.key_password,
        };

        (opts, csr_path, key_path)
    } else {
        csr::interactive_create()?
    };

    // Warn about OU deprecation for public CAs
    if !opts.subject.organizational_units.is_empty() {
        eprintln!(
            "{} {}",
            "NOTE:".cyan().bold(),
            "OU fields are deprecated for publicly-trusted certificates (CA/B Forum, Sep 2022). \
             For internal/private PKI, OU with metadata identifiers (e.g., AppId:xxx) is valid."
                .cyan()
        );
    }

    warn_secret_on_argv(
        "--key-password",
        "DCERT_KEY_PASSWORD",
        opts.encrypt_key && opts.key_password.is_some(),
    );

    let result = csr::create_csr(&opts, &csr_path, &key_path)?;

    print_structured(args.format, &result, || {
        println!("{}", "CSR created successfully".green().bold());
        println!("  CSR file          : {}", result.csr_file);
        println!("  Key file          : {}", result.key_file);
        println!("  Key algorithm     : {}", result.key_algorithm);
        println!("  Key size          : {} bits", result.key_size_bits);
        println!("  Signature algo    : {}", result.signature_algorithm);
        println!("  Subject           : {}", result.subject);
        if !result.sans.is_empty() {
            println!("  SANs              : {}", result.sans.join(", "));
        }
        println!(
            "  Key encrypted     : {}",
            if result.key_encrypted { "yes" } else { "no" }
        );
    })?;

    Ok(exit_code::SUCCESS)
}

fn run_csr_validate(args: cli::CsrValidateArgs) -> Result<i32> {
    let pem_data = std::fs::read_to_string(&args.csr_file)
        .with_context(|| format!("Failed to read CSR file: {}", args.csr_file))?;

    let result = csr::validate_csr(&pem_data)?;

    print_structured(args.format, &result, || print_csr_validation_pretty(&result))?;

    if !result.compliant {
        return Ok(exit_code::ERROR);
    }

    if args.warnings_as_errors && result.findings.iter().any(|f| f.severity == csr::Severity::Warning) {
        eprintln!(
            "{} {}",
            "WARNING:".yellow().bold(),
            "Strict mode: warnings treated as errors".yellow()
        );
        return Ok(exit_code::EXPIRY_WARNING);
    }

    Ok(exit_code::SUCCESS)
}

fn print_csr_validation_pretty(result: &csr::CsrValidationResult) {
    println!("{}", "=== CSR Validation Report ===".bold());
    println!();

    println!("{}", "Subject:".bold());
    let subject = &result.subject;
    let rows: [(&str, Option<&str>); 6] = [
        ("Common Name   ", subject.common_name.as_deref()),
        ("Organization  ", subject.organization.as_deref()),
        ("Country       ", subject.country.as_deref()),
        ("State         ", subject.state.as_deref()),
        ("Locality      ", subject.locality.as_deref()),
        ("Email         ", subject.email.as_deref()),
    ];
    for (label, value) in rows {
        if let Some(v) = value {
            println!("  {label} : {v}");
        }
    }
    for ou in &subject.organizational_units {
        println!("  Org Unit       : {ou}");
    }
    println!();

    println!("{}", "Public Key:".bold());
    println!("  Algorithm      : {}", result.public_key_algorithm);
    println!("  Size           : {} bits", result.public_key_size_bits);
    println!("  Signature algo : {}", result.signature_algorithm);
    println!();

    if !result.subject_alternative_names.is_empty() {
        println!("{}", "Subject Alternative Names:".bold());
        for san in &result.subject_alternative_names {
            println!("  {san}");
        }
        println!();
    }

    println!("{}", "Compliance Findings:".bold());
    output::print_findings(&result.findings, "  ");
    println!();

    if result.compliant {
        println!("{}", "Result: COMPLIANT".green().bold());
    } else {
        println!("{}", "Result: NON-COMPLIANT".red().bold());
    }
}

fn run_vault(args: cli::VaultArgs) -> Result<i32> {
    warn_secret_on_argv("--ldap-password", "DCERT_LDAP_PASSWORD", args.ldap_password.is_some());
    warn_secret_on_argv(
        "--approle-secret-id",
        "DCERT_APPROLE_SECRET_ID",
        args.approle_secret_id.is_some(),
    );
    let pfx_on_argv = match &args.mode {
        cli::VaultMode::Issue(a) => a.pfx_password.is_some(),
        cli::VaultMode::Sign(a) => a.pfx_password.is_some(),
        _ => false,
    };
    warn_secret_on_argv("--pfx-password", "DCERT_CERT_PASSWORD", pfx_on_argv);

    // Discover Vault token and address
    let addr = vault::vault_addr()?;
    let auth_method: vault::VaultAuthMethod = args.auth_method.parse()?;
    let tls = vault::VaultTlsSettings::resolve(args.vault_cacert.as_deref(), args.skip_verify);
    let token = match auth_method {
        vault::VaultAuthMethod::Ldap | vault::VaultAuthMethod::AppRole => vault::vault_authenticate(
            &addr,
            auth_method,
            &vault::VaultLogin {
                ldap_username: args.ldap_username.as_deref(),
                ldap_password: args.ldap_password.as_deref(),
                ldap_mount: &args.ldap_mount,
                approle_role_id: args.approle_role_id.as_deref(),
                approle_secret_id: args.approle_secret_id.as_deref(),
                approle_mount: &args.approle_mount,
            },
            &tls,
        )?,
        vault::VaultAuthMethod::Token => zeroize::Zeroizing::new(vault::discover_vault_token()?),
    };

    let config = vault::VaultClientConfig {
        cacert: args.vault_cacert.clone(),
        skip_verify: args.skip_verify,
        debug: args.debug,
    };

    let client = vault::VaultClient::new(&addr, &token, &config)?;

    vault::print_vault_connectivity(&client, &addr, &token);

    match args.mode {
        cli::VaultMode::Issue(args) => run_vault_issue(&client, *args),
        cli::VaultMode::Sign(args) => run_vault_sign(&client, args),
        cli::VaultMode::Revoke(args) => run_vault_revoke(&client, args),
        cli::VaultMode::List(args) => run_vault_list(&client, args),
        cli::VaultMode::Store(args) => run_vault_store(&client, args),
        cli::VaultMode::Validate(args) => run_vault_validate(&client, args),
        cli::VaultMode::Renew(args) => run_vault_renew(&client, args),
    }
}

fn run_vault_issue(client: &vault::VaultClient, args: cli::VaultIssueArgs) -> Result<i32> {
    let kv_version = args.kv_version;
    let wizard = if let Some(cn) = args.cn {
        let role = vault::resolve_role(client, args.role)?;
        let output = args.output.unwrap_or_else(|| vault::sanitise_cn(&cn));
        vault::IssueWizardResult {
            mount: args.mount,
            role,
            cn,
            sans: args.san,
            ip_sans: args.ip_san,
            ttl: args.ttl,
            pfx_password: args.pfx_password,
            output,
            store_path: args.store_path,
        }
    } else {
        vault::interactive_issue(client)?
    };
    let vault::IssueWizardResult {
        mount,
        role,
        cn,
        sans,
        ip_sans,
        ttl,
        pfx_password,
        output: output_base,
        store_path,
    } = wizard;

    let data = vault::issue_certificate(client, &mount, &role, &cn, &sans, &ip_sans, &ttl)?;

    // Build full chain
    let full_chain = vault::build_full_chain(client, &data.certificate, &data.ca_chain, &mount);

    // Display certificate
    vault::display_certificate(&full_chain);

    // Write output files
    if let Some(ref pfx_pw) = pfx_password {
        let key_pem = data
            .private_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Vault did not return a private key"))?;
        let pfx_path = format!("{output_base}.pfx");
        // Write temp files for PFX conversion
        let temp_dir = tempfile::TempDir::new()?;
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        std::fs::write(&cert_path, &full_chain)
            .with_context(|| format!("Failed to write temp certificate file: {}", cert_path.display()))?;
        std::fs::write(&key_path, key_pem)
            .with_context(|| format!("Failed to write temp key file: {}", key_path.display()))?;
        convert::pem_to_pfx(
            cert_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Temp cert path contains invalid UTF-8"))?,
            key_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Temp key path contains invalid UTF-8"))?,
            pfx_pw,
            &pfx_path,
            None,
        )?;
        println!("{}", format!("PFX written to {pfx_path}").green());
    } else {
        let key_pem = data.private_key.as_deref();
        vault::write_pem_files(&full_chain, key_pem, &output_base)?;
    }

    // Store in Vault KV if requested
    if let Some(ref kv_path) = store_path {
        let key_pem = data.private_key.as_deref().unwrap_or("");
        vault::kv_store(client, kv_path, &full_chain, key_pem, "cert", "key", kv_version)?;
    }

    Ok(exit_code::SUCCESS)
}

fn run_vault_sign(client: &vault::VaultClient, args: cli::VaultSignArgs) -> Result<i32> {
    let kv_version = args.kv_version;
    let (wizard, ip_sans) = if let Some(csr_file) = args.csr_file {
        let role = vault::resolve_role(client, args.role)?;
        let output = args.output.unwrap_or_else(|| "signed-cert".to_string());
        (
            vault::SignWizardResult {
                mount: args.mount,
                role,
                csr_file,
                cn_override: args.cn,
                sans: args.san,
                ttl: args.ttl,
                pfx_password: args.pfx_password,
                output,
                store_path: args.store_path,
            },
            args.ip_san,
        )
    } else {
        (vault::interactive_sign(client)?, Vec::new())
    };
    let vault::SignWizardResult {
        mount,
        role,
        csr_file,
        cn_override,
        sans,
        ttl,
        pfx_password,
        output: output_base,
        store_path,
    } = wizard;

    let csr_pem = std::fs::read_to_string(&csr_file).with_context(|| format!("Failed to read CSR file: {csr_file}"))?;

    let data = vault::sign_csr(
        client,
        &vault::SignRequest {
            mount: &mount,
            role: &role,
            csr_pem: &csr_pem,
            common_name: cn_override.as_deref(),
            alt_names: &sans,
            ip_sans: &ip_sans,
            ttl: &ttl,
        },
    )?;

    // Build full chain
    let full_chain = vault::build_full_chain(client, &data.certificate, &data.ca_chain, &mount);

    // Display certificate
    vault::display_certificate(&full_chain);

    // Write output (no private key from sign operation)
    if pfx_password.is_some() {
        eprintln!(
            "{} PFX output requires a private key. The sign operation does not return a key.",
            "WARNING:".yellow().bold()
        );
        eprintln!("Use PFX output with 'vault issue' instead, or bundle manually with 'dcert convert pem-to-pfx'.");
    }

    vault::write_pem_files(&full_chain, None, &output_base)?;

    // Store in Vault KV if requested
    if let Some(ref kv_path) = store_path {
        vault::kv_store(client, kv_path, &full_chain, "", "cert", "key", kv_version)?;
    }

    Ok(exit_code::SUCCESS)
}

fn run_vault_revoke(client: &vault::VaultClient, args: cli::VaultRevokeArgs) -> Result<i32> {
    let cert_pem = if let Some(ref path) = args.cert_file {
        Some(std::fs::read_to_string(path).with_context(|| format!("Failed to read certificate file: {path}"))?)
    } else {
        None
    };

    vault::revoke_certificate(client, &args.mount, args.serial.as_deref(), cert_pem.as_deref())?;

    Ok(exit_code::SUCCESS)
}

fn run_vault_list(client: &vault::VaultClient, args: cli::VaultListArgs) -> Result<i32> {
    let entries = vault::list_certificates(
        client,
        &args.mount,
        args.show_details,
        args.expired_only,
        args.valid_only,
    )?;

    // Export to file if requested
    if let Some(ref export_path) = args.export {
        vault::export_cert_list(&entries, export_path)?;
        return Ok(exit_code::SUCCESS);
    }

    print_structured(args.format, &entries, || {
        println!("{} {} certificates", "Vault PKI:".bold(), entries.len());
        for entry in &entries {
            let status = if entry.status == "expired" {
                "EXPIRED".red().to_string()
            } else {
                entry.status.green().to_string()
            };
            let cn = entry.common_name.as_deref().unwrap_or("(unknown)");
            println!("  {} [{}] {}", entry.serial_number, status, cn);
            if !entry.not_after.is_empty() {
                println!("    Not After: {}", entry.not_after);
            }
        }
    })?;

    Ok(exit_code::SUCCESS)
}

fn run_vault_store(client: &vault::VaultClient, args: cli::VaultStoreArgs) -> Result<i32> {
    let cert_pem = std::fs::read_to_string(&args.cert_file)
        .with_context(|| format!("Failed to read certificate file: {}", args.cert_file))?;
    let key_pem = std::fs::read_to_string(&args.key_file)
        .with_context(|| format!("Failed to read key file: {}", args.key_file))?;

    vault::kv_store(
        client,
        &args.path,
        &cert_pem,
        &key_pem,
        &args.cert_key,
        &args.key_key,
        args.kv_version,
    )?;

    Ok(exit_code::SUCCESS)
}

fn run_vault_validate(client: &vault::VaultClient, args: cli::VaultValidateArgs) -> Result<i32> {
    vault::validate_from_kv(client, &args.path, &args.cert_key, &args.key_key, args.kv_version)?;
    Ok(exit_code::SUCCESS)
}

fn run_vault_renew(client: &vault::VaultClient, args: cli::VaultRenewArgs) -> Result<i32> {
    let role = vault::resolve_role(client, args.role)?;

    vault::renew_certificate(
        client,
        &vault::RenewRequest {
            kv_path: &args.path,
            mount: &args.mount,
            role: &role,
            ttl: &args.ttl,
            cert_key_name: &args.cert_key,
            key_key_name: &args.key_key,
            kv_version: args.kv_version,
            san_overrides: &args.san,
            ip_san_overrides: &args.ip_san,
        },
    )?;

    Ok(exit_code::SUCCESS)
}

fn run() -> Result<i32> {
    let os_args: Vec<String> = std::env::args().collect();

    // Backward-compatible default: inject "check" when first arg isn't a known subcommand
    let cli = if os_args.len() > 1 {
        let first_arg = &os_args[1];
        if KNOWN_SUBCOMMANDS.contains(&first_arg.as_str()) {
            Cli::parse()
        } else {
            // Insert "check" after program name
            let mut new_args = vec![os_args[0].clone(), "check".to_string()];
            new_args.extend(os_args[1..].iter().cloned());
            Cli::parse_from(new_args)
        }
    } else {
        Cli::parse()
    };

    match cli.command {
        Command::Check(args) => run_check(*args),
        Command::Convert(args) => run_convert(args),
        Command::VerifyKey(args) => run_verify_key(args),
        Command::Csr(args) => run_csr(args),
        Command::Vault(args) => run_vault(*args),
        Command::Diagnose(mut args) => {
            args.diagnose_only = true;
            run_check(*args)
        }
        Command::Kb(args) => run_kb(args),
    }
}

/// One target's diagnosis, the shape printed by `dcert diagnose`.
#[derive(Debug, serde::Serialize)]
struct DiagnoseOutput {
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
    diagnosis: Vec<diagnose::Diagnosis>,
    /// The response body the findings were matched against. Carried here
    /// because several entries tell the reader to look at it, so `--show-body`
    /// has to mean something on this subcommand and not only on `check`.
    #[serde(skip_serializing_if = "Option::is_none")]
    body_excerpt: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    body_truncated: bool,
}

fn print_diagnose_output_pretty(items: &[DiagnoseOutput]) {
    for item in items {
        println!("{}", format!("--- {} ---", item.target).bold().cyan());
        if let Some(e) = &item.error {
            println!("{} {e}", "Probe failed:".red().bold());
        } else if let Some(s) = item.http_status {
            println!("Probe completed: HTTP {s}");
        } else {
            println!("Probe completed");
        }
        if item.diagnosis.is_empty() {
            println!("No knowledge base entry matched. Re-run with --debug for the raw exchange.");
            println!();
        } else {
            output::print_diagnosis_pretty(&item.diagnosis);
        }
        if let Some(body) = &item.body_excerpt {
            println!("{}", "Response body:".bold());
            for line in body.lines() {
                println!("  {line}");
            }
            if item.body_truncated {
                println!("  {}", "[truncated at --body-limit]".dimmed());
            }
            println!();
        }
    }
}

fn run_kb(args: cli::KbArgs) -> Result<i32> {
    use cli::KbMode;
    match args.mode {
        KbMode::List { format, kb_file } => {
            let kb = diagnose::KnowledgeBase::load(kb_file.as_deref().map(std::path::Path::new))?;
            #[derive(serde::Serialize)]
            struct Row<'a> {
                id: &'a str,
                layer: diagnose::Layer,
                category: diagnose::Category,
                title: &'a str,
            }
            let rows: Vec<Row<'_>> = kb
                .entries
                .iter()
                .map(|e| Row {
                    id: &e.id,
                    layer: e.layer,
                    category: e.category,
                    title: &e.title,
                })
                .collect();
            print_structured(format, &rows, || {
                println!("{} entries (knowledge base version {})", kb.entries.len(), kb.version);
                for e in &kb.entries {
                    println!("  {:<46} {:<24} {}", e.id, e.layer.label(), e.title);
                }
            })?;
            Ok(exit_code::SUCCESS)
        }
        KbMode::Show { id, format, kb_file } => {
            let kb = diagnose::KnowledgeBase::load(kb_file.as_deref().map(std::path::Path::new))?;
            let entry = kb
                .get(&id)
                .ok_or_else(|| anyhow::anyhow!("no knowledge base entry with id '{id}'"))?;
            print_structured(format, entry, || {
                println!("{}", serde_yaml_ng::to_string(entry).unwrap_or_default());
            })?;
            Ok(exit_code::SUCCESS)
        }
        KbMode::Validate { file } => {
            let text = std::fs::read_to_string(&file).with_context(|| format!("Failed to read {file}"))?;
            let kb = diagnose::KnowledgeBase::parse(&text)
                .with_context(|| format!("{file} is not a valid knowledge base"))?;
            let mut merged = diagnose::KnowledgeBase::builtin()?;
            let builtin_count = merged.entries.len();
            let file_count = kb.entries.len();
            merged.merge(kb);
            let replaced = builtin_count + file_count - merged.entries.len();
            println!(
                "{} {file}: {file_count} entries ({replaced} override built in entries, {} new)",
                "OK".green().bold(),
                file_count - replaced
            );
            Ok(exit_code::SUCCESS)
        }
        KbMode::Schema => {
            println!(
                "{}",
                serde_json::to_string_pretty(&diagnose::KnowledgeBase::json_schema())?
            );
            Ok(exit_code::SUCCESS)
        }
    }
}

fn main() {
    // Register process-wide SIGINT handler for the stdin-pipe path too —
    // run() registers it for everything else, but stdin-pipe never enters run().
    let _running = register_sigint_handler();

    // When no arguments are provided and stdin has piped data, treat it as PEM input
    if std::env::args().len() == 1 {
        use std::io::{IsTerminal, Read as _};

        if !std::io::stdin().is_terminal() {
            // Try to read piped data — if non-empty, process as PEM content
            let mut buf = Vec::new();
            if std::io::stdin()
                .lock()
                .take(MAX_STDIN_SIZE as u64 + 1)
                .read_to_end(&mut buf)
                .is_ok()
                && !buf.is_empty()
                && buf.len() <= MAX_STDIN_SIZE
            {
                // Re-parse with "check -" injected so clap builds the default CheckArgs
                let new_args = vec![
                    std::env::args().next().unwrap_or_else(|| "dcert".to_string()),
                    "check".to_string(),
                    "-".to_string(),
                ];
                let cli = Cli::parse_from(new_args);
                let content = String::from_utf8_lossy(&buf).to_string();
                match cli.command {
                    Command::Check(args) => match run_check_with_stdin(*args, Some(content)) {
                        Ok(code) => std::process::exit(code),
                        Err(e) => {
                            eprintln!("{} {}", "Error:".red().bold(), e);
                            std::process::exit(exit_code::ERROR);
                        }
                    },
                    // The stdin-pipe path injects `check -` above, so any other
                    // variant here would mean a clap mis-parse. Surface that
                    // as a friendly error rather than an `unreachable!()` panic
                    // so future subcommand additions don't crash users.
                    other => {
                        eprintln!(
                            "{} stdin pipe is only supported for `dcert check ...`; got: {:?}",
                            "Error:".red().bold(),
                            other
                        );
                        std::process::exit(exit_code::ERROR);
                    }
                }
            }
        }

        if let Err(e) = Cli::command().print_help() {
            eprintln!("{} failed to render help: {}", "Error:".red().bold(), e);
            std::process::exit(exit_code::ERROR);
        }
        println!();
        std::process::exit(0);
    }

    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            std::process::exit(exit_code::ERROR);
        }
    }
}
