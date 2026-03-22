mod cert;
mod cli;
mod compliance;
mod convert;
mod csr;
mod debug;
mod ocsp;
mod output;
mod proxy;
mod tls;
mod vault;

use anyhow::{Context, Result};
use clap::CommandFactory;
use clap::Parser;
use colored::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use cli::{CheckArgs, Cli, Command, HttpMethod, KNOWN_SUBCOMMANDS, OutputFormat, exit_code};
use output::{
    StructuredOutput, TargetResult, check_expiry_warnings, export_pem_chain, output_results, print_diff, process_target,
};
use proxy::ProxyConfig;

/// Maximum size for stdin input (10 MB). Prevents OOM from accidentally
/// piping huge files. 10 MB is generous enough for large PEM bundles
/// containing 50+ certificates.
const MAX_STDIN_SIZE: usize = 10 * 1024 * 1024;

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
                "--min-tls ({}) must not be greater than --max-tls ({})",
                min,
                max
            ));
        }
    }

    // Warn when passwords are passed via CLI args (visible in process listing)
    if args.cert_password.is_some() && std::env::var("DCERT_CERT_PASSWORD").is_err() {
        eprintln!(
            "{} {}",
            "WARNING:".yellow().bold(),
            "Password passed via --cert-password is visible in process listings. Consider using DCERT_CERT_PASSWORD env var instead."
                .yellow()
        );
    }

    // Resolve request body from --data or --data-file
    let body_data: Option<Vec<u8>> = if let Some(ref data) = args.data {
        Some(data.as_bytes().to_vec())
    } else if let Some(ref path) = args.data_file {
        Some(std::fs::read(path).with_context(|| format!("Failed to read data file: {}", path))?)
    } else {
        None
    };

    // Auto-promote method to POST when body is provided and method is at default (GET)
    if body_data.is_some() && matches!(args.method, HttpMethod::Get) {
        args.method = HttpMethod::Post;
    }

    // Cache proxy configuration from environment at startup
    let proxy_config = ProxyConfig::from_env();

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

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        // Handle Ctrl+C gracefully
        if let Err(e) = ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }) {
            eprintln!(
                "{} Failed to register Ctrl+C handler: {}. Watch mode may not stop gracefully.",
                "WARNING:".yellow().bold(),
                e
            );
        }

        let mut iteration = 0u64;
        let mut prev_fingerprints: std::collections::HashMap<String, Vec<Option<String>>> =
            std::collections::HashMap::new();

        while running.load(Ordering::SeqCst) {
            iteration += 1;
            let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default();
            println!(
                "{}",
                format!("=== Watch iteration {} at {} ===", iteration, now)
                    .bold()
                    .cyan()
            );

            for target in &targets {
                match process_target(target, &args, &proxy_config, body_data.as_deref(), stdin_pem.as_deref()) {
                    Ok(result) => {
                        // Check for changes
                        let current_fps: Vec<Option<String>> =
                            result.infos.iter().map(|c| c.sha256_fingerprint.clone()).collect();

                        if let Some(prev) = prev_fingerprints.get(target)
                            && prev != &current_fps
                        {
                            println!("{}", format!("CHANGE DETECTED for {}", target).red().bold());
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

    for target in &targets {
        match process_target(target, &args, &proxy_config, body_data.as_deref(), stdin_pem.as_deref()) {
            Ok(result) => {
                // Check for verification failure
                if let Some(ref conn) = result.conn_info
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
            }
        }
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
            let output = StructuredOutput {
                certificates: result.infos.clone(),
                connection: result.conn_info.clone(),
                compliance: result.compliance_report.clone(),
            };
            map.insert(result.target.clone(), serde_json::to_value(&output)?);
        }
        println!("{}", serde_json::to_string_pretty(&map)?);
    } else if multi_target && matches!(args.format, OutputFormat::Yaml) {
        let mut map = std::collections::BTreeMap::new();
        for result in &all_results {
            let output = StructuredOutput {
                certificates: result.infos.clone(),
                connection: result.conn_info.clone(),
                compliance: result.compliance_report.clone(),
            };
            map.insert(result.target.clone(), output);
        }
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

fn run_convert(args: cli::ConvertArgs) -> Result<i32> {
    // Warn when passwords are passed via CLI args (visible in process listing)
    let password_via_cli = match &args.mode {
        cli::ConvertMode::PfxToPem { .. } => std::env::var("DCERT_CERT_PASSWORD").is_err(),
        cli::ConvertMode::PemToPfx { .. } => std::env::var("DCERT_CERT_PASSWORD").is_err(),
        cli::ConvertMode::CreateKeystore { .. } => std::env::var("DCERT_KEYSTORE_PASSWORD").is_err(),
        cli::ConvertMode::CreateTruststore { .. } => false, // truststore password is low-sensitivity
    };
    if password_via_cli {
        eprintln!(
            "{} {}",
            "WARNING:".yellow().bold(),
            "Password passed via CLI argument is visible in process listings. Consider using the corresponding env var instead."
                .yellow()
        );
    }

    match args.mode {
        cli::ConvertMode::PfxToPem {
            input,
            password,
            output_dir,
        } => {
            let result = convert::pfx_to_pem(&input, &password, &output_dir)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
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
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(exit_code::SUCCESS)
        }
        cli::ConvertMode::CreateKeystore {
            cert,
            key,
            output,
            password,
            alias,
        } => {
            let result = convert::create_keystore(&cert, &key, &password, &output, &alias)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(exit_code::SUCCESS)
        }
        cli::ConvertMode::CreateTruststore {
            certs,
            output,
            password,
        } => {
            let result = convert::create_truststore(&certs, &password, &output)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
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
        return Err(anyhow::anyhow!("'{}' is not a directory", dir));
    }

    let entries = std::fs::read_dir(dir_path).with_context(|| format!("Failed to read directory '{}'", dir))?;

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
        println!("  Cert file      : {}", cert);
        println!("  Key file       : {}", key);
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

        match args.format {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            OutputFormat::Yaml => {
                println!("{}", serde_yaml_ng::to_string(&result)?);
            }
            OutputFormat::Pretty => {
                print_single_result(&result, None, None);
            }
        }

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
    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&all_results)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml_ng::to_string(&all_results)?);
        }
        OutputFormat::Pretty => {} // already printed
    }

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
            sans.push(format!("DNS:{}", cn));
        }

        // Validate key password requirement
        if args.encrypt_key && args.key_password.is_none() {
            return Err(anyhow::anyhow!("--key-password is required when --encrypt-key is set"));
        }

        // Determine output paths
        let base = cn.replace('*', "wildcard").replace('.', "-");
        let csr_path = args.csr_out.unwrap_or_else(|| format!("{}.csr", base));
        let key_path = args.key_out.unwrap_or_else(|| format!("{}.key", base));

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

    // Warn about key password on CLI
    if opts.encrypt_key && opts.key_password.is_some() && std::env::var("DCERT_KEY_PASSWORD").is_err() {
        eprintln!(
            "{} {}",
            "WARNING:".yellow().bold(),
            "Password passed via --key-password is visible in process listings. Consider using DCERT_KEY_PASSWORD env var."
                .yellow()
        );
    }

    let result = csr::create_csr(&opts, &csr_path, &key_path)?;

    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml_ng::to_string(&result)?);
        }
        OutputFormat::Pretty => {
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
        }
    }

    Ok(exit_code::SUCCESS)
}

fn run_csr_validate(args: cli::CsrValidateArgs) -> Result<i32> {
    let pem_data = std::fs::read_to_string(&args.csr_file)
        .with_context(|| format!("Failed to read CSR file: {}", args.csr_file))?;

    let result = csr::validate_csr(&pem_data)?;

    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml_ng::to_string(&result)?);
        }
        OutputFormat::Pretty => {
            println!("{}", "=== CSR Validation Report ===".bold());
            println!();

            // Subject
            println!("{}", "Subject:".bold());
            if let Some(ref cn) = result.subject.common_name {
                println!("  Common Name    : {}", cn);
            }
            if let Some(ref org) = result.subject.organization {
                println!("  Organization   : {}", org);
            }
            for ou in &result.subject.organizational_units {
                println!("  Org Unit       : {}", ou);
            }
            if let Some(ref c) = result.subject.country {
                println!("  Country        : {}", c);
            }
            if let Some(ref st) = result.subject.state {
                println!("  State          : {}", st);
            }
            if let Some(ref l) = result.subject.locality {
                println!("  Locality       : {}", l);
            }
            if let Some(ref email) = result.subject.email {
                println!("  Email          : {}", email);
            }
            println!();

            // Key info
            println!("{}", "Public Key:".bold());
            println!("  Algorithm      : {}", result.public_key_algorithm);
            println!("  Size           : {} bits", result.public_key_size_bits);
            println!("  Signature algo : {}", result.signature_algorithm);
            println!();

            // SANs
            if !result.subject_alternative_names.is_empty() {
                println!("{}", "Subject Alternative Names:".bold());
                for san in &result.subject_alternative_names {
                    println!("  {}", san);
                }
                println!();
            }

            // Findings
            println!("{}", "Compliance Findings:".bold());
            for finding in &result.findings {
                let (icon, color_fn): (&str, fn(&str) -> colored::ColoredString) = match finding.severity {
                    csr::Severity::Error => ("ERROR", |s: &str| s.red().bold()),
                    csr::Severity::Warning => ("WARN ", |s: &str| s.yellow()),
                    csr::Severity::Info => ("INFO ", |s: &str| s.cyan()),
                };
                println!("  {} [{}] {}", color_fn(icon), finding.category, finding.message);
            }
            println!();

            // Overall result
            if result.compliant {
                println!("{}", "Result: COMPLIANT".green().bold());
            } else {
                println!("{}", "Result: NON-COMPLIANT".red().bold());
            }
        }
    }

    if !result.compliant {
        return Ok(exit_code::ERROR);
    }

    if args.strict && result.findings.iter().any(|f| f.severity == csr::Severity::Warning) {
        eprintln!(
            "{} {}",
            "WARNING:".yellow().bold(),
            "Strict mode: warnings treated as errors".yellow()
        );
        return Ok(exit_code::EXPIRY_WARNING);
    }

    Ok(exit_code::SUCCESS)
}

fn run_vault(args: cli::VaultArgs) -> Result<i32> {
    // Discover Vault token and address
    let token = vault::discover_vault_token()?;
    let addr = vault::vault_addr()?;

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
    let (mount, role, cn, sans, ip_sans, ttl, pfx_password, output_base, store_path) = if let Some(cn) = args.cn {
        let role = vault::resolve_role(client, args.role)?;
        let output_base = args.output.unwrap_or_else(|| vault::sanitise_cn(&cn));
        (
            args.mount,
            role,
            cn,
            args.san,
            args.ip_san,
            args.ttl,
            args.pfx_password,
            output_base,
            args.store_path,
        )
    } else {
        // Interactive wizard
        vault::interactive_issue(client)?
    };

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
        let pfx_path = format!("{}.pfx", output_base);
        // Write temp files for PFX conversion
        let temp_dir = tempfile::TempDir::new()?;
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        std::fs::write(&cert_path, &full_chain)?;
        std::fs::write(&key_path, key_pem)?;
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
        println!("{}", format!("PFX written to {}", pfx_path).green());
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
    let (mount, role, csr_file, cn_override, sans, ip_sans, ttl, pfx_password, output_base, store_path) =
        if let Some(csr_file) = args.csr_file {
            let role = vault::resolve_role(client, args.role)?;
            let output_base = args.output.unwrap_or_else(|| "signed-cert".to_string());
            (
                args.mount,
                role,
                csr_file,
                args.cn,
                args.san,
                args.ip_san,
                args.ttl,
                args.pfx_password,
                output_base,
                args.store_path,
            )
        } else {
            // Interactive wizard
            let (mount, role, csr_file, cn_override, sans, ttl, pfx_password, output_base, store_path) =
                vault::interactive_sign(client)?;
            (
                mount,
                role,
                csr_file,
                cn_override,
                sans,
                vec![],
                ttl,
                pfx_password,
                output_base,
                store_path,
            )
        };

    let csr_pem =
        std::fs::read_to_string(&csr_file).with_context(|| format!("Failed to read CSR file: {}", csr_file))?;

    let data = vault::sign_csr(
        client,
        &mount,
        &role,
        &csr_pem,
        cn_override.as_deref(),
        &sans,
        &ip_sans,
        &ttl,
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
        Some(std::fs::read_to_string(path).with_context(|| format!("Failed to read certificate file: {}", path))?)
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

    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml_ng::to_string(&entries)?);
        }
        OutputFormat::Pretty => {
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
        }
    }

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
        &args.path,
        &args.mount,
        &role,
        &args.ttl,
        &args.cert_key,
        &args.key_key,
        args.kv_version,
        &args.san,
        &args.ip_san,
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
        Command::Vault(args) => run_vault(args),
    }
}

fn main() {
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
                    _ => unreachable!(),
                }
            }
        }

        Cli::command().print_help().unwrap();
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
