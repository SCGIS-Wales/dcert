mod cert;
mod cli;
mod debug;
mod ocsp;
mod output;
mod proxy;
mod tls;

use anyhow::{Context, Result};
use clap::CommandFactory;
use clap::Parser;
use colored::*;
use std::io::BufRead;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use cli::{exit_code, Args, HttpMethod, OutputFormat};
use output::{
    check_expiry_warnings, export_pem_chain, output_results, print_diff, process_target, StructuredOutput, TargetResult,
};
use proxy::ProxyConfig;

fn run() -> Result<i32> {
    let mut args: Args = Args::parse();

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
    for t in &args.targets {
        if t == "-" {
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() {
                eprintln!("Reading targets from stdin (one per line, Ctrl-D to finish)...");
            }
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let line = line.with_context(|| "Failed to read from stdin")?;
                let line = line.trim().to_string();
                if !line.is_empty() {
                    targets.push(line);
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
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .ok();

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
                match process_target(target, &args, &proxy_config, body_data.as_deref()) {
                    Ok(result) => {
                        // Check for changes
                        let current_fps: Vec<Option<String>> =
                            result.infos.iter().map(|c| c.sha256_fingerprint.clone()).collect();

                        if let Some(prev) = prev_fingerprints.get(target) {
                            if prev != &current_fps {
                                println!("{}", format!("CHANGE DETECTED for {}", target).red().bold());
                            }
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
        match process_target(target, &args, &proxy_config, body_data.as_deref()) {
            Ok(result) => {
                // Check for verification failure
                if let Some(ref conn) = result.conn_info {
                    if conn.verify_result.is_some() && exit_code < exit_code::VERIFY_FAILED {
                        exit_code = exit_code::VERIFY_FAILED;
                    }
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
            };
            map.insert(result.target.clone(), output);
        }
        println!("{}", serde_yml::to_string(&map)?);
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

fn main() {
    // Print help if no arguments (other than program name) are provided
    if std::env::args().len() == 1 {
        Args::command().print_help().unwrap();
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
