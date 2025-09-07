mod args;
mod cert;
mod https;
mod proxy;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use serde::Serialize;
use std::fs;

use crate::args::{Cli, OutputFormat};

#[derive(Serialize)]
struct JsonOutput<'a> {
    session: Option<&'a https::HttpsSession>,
    certificates: &'a [cert::CertInfo],
}

fn to_csv(infos: &[cert::CertInfo]) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record([
        "index",
        "subject",
        "issuer",
        "serial_number",
        "not_before",
        "not_after",
        "is_expired",
        "common_name",
        "sans",
        "is_ca",
        "ct_scts_embedded",
    ])?;
    for i in infos {
        let sans_join = i.subject_alternative_names.join(";");
        wtr.write_record([
            i.index.to_string(),
            i.subject.clone(),
            i.issuer.clone(),
            i.serial_number.clone(),
            i.not_before.clone(),
            i.not_after.clone(),
            i.is_expired.to_string(),
            i.common_name.clone().unwrap_or_default(),
            sans_join,
            i.is_ca.to_string(),
            i.ct_scts_embedded.to_string(),
        ])?;
    }
    let data = String::from_utf8(wtr.into_inner()?)?;
    Ok(data)
}

/// Print extended version information, including dependency versions if provided by build.rs.
fn print_version_and_exit() {
    println!("dcert {}", env!("CARGO_PKG_VERSION"));

    // These come from build.rs if you add it; otherwise they show "unknown".
    macro_rules! dep {
        ($env:literal) => {
            option_env!($env).unwrap_or("unknown")
        };
    }

    println!("  rustls           : {}", dep!("DEP_DCERT_RUSTLS_VERSION"));
    println!("  rustls-webpki    : {}", dep!("DEP_DCERT_RUSTLS_WEBPKI_VERSION"));
    println!("  webpki-roots     : {}", dep!("DEP_DCERT_WEBPKI_ROOTS_VERSION"));
    println!("  x509-parser      : {}", dep!("DEP_DCERT_X509_PARSER_VERSION"));
    println!("  rustls-pemfile   : {}", dep!("DEP_DCERT_RUSTLS_PEMFILE_VERSION"));
    println!("  url              : {}", dep!("DEP_DCERT_URL_VERSION"));
    println!("  clap             : {}", dep!("DEP_DCERT_CLAP_VERSION"));
    println!("  colored          : {}", dep!("DEP_DCERT_COLORED_VERSION"));
    println!("  time             : {}", dep!("DEP_DCERT_TIME_VERSION"));
    println!("  serde/serde_json : {}/{}", dep!("DEP_DCERT_SERDE_VERSION"), dep!("DEP_DCERT_SERDE_JSON_VERSION"));
    println!("  csv              : {}", dep!("DEP_DCERT_CSV_VERSION"));
    println!("  base64           : {}", dep!("DEP_DCERT_BASE64_VERSION"));
    println!("  httparse         : {}", dep!("DEP_DCERT_HTTPARSE_VERSION"));
}

fn main() -> Result<()> {
    let args = Cli::parse();

    if args.version_only {
        print_version_and_exit();
        return Ok(());
    }

    // HTTPS mode
    if args.input.starts_with("https://") {
        // Parse headers "k=v,k2=v2"
        let headers_kv: Vec<(String, String)> = args
            .headers
            .as_deref()
            .map(|s| {
                s.split(',')
                    .filter_map(|kv| {
                        let mut it = kv.splitn(2, '=');
                        let k = it.next()?.trim().to_string();
                        let v = it.next().unwrap_or("").trim().to_string();
                        if k.is_empty() {
                            None
                        } else {
                            Some((k, v))
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let (session, chain_der) = https::probe_https(
            &args.input,
            args.tls_version,
            args.http_version,
            &args.method,
            &headers_kv,
            args.ca_file.as_deref(),
            args.timeout_l4,
            args.timeout_l6,
            args.timeout_l7,
            args.export_chain,
        )
        .with_context(|| "HTTPS probe failed")?;

        // Convert peer chain to printable infos
        let mut infos = cert::infos_from_der_certs(&chain_der);
        if args.expired_only {
            infos.retain(|i| i.is_expired);
        }

        match args.format {
            OutputFormat::Pretty => {
                println!("{}", "HTTPS session".bold());
                println!(
                    "  Connection on OSI layer 4 (TCP)     : {}",
                    if session.l4_ok { "OK".green() } else { "NOT OK".red() }
                );
                println!(
                    "  Connection on OSI layer 6 (TLS)     : {}",
                    if session.l6_ok { "OK".green() } else { "NOT OK".red() }
                );
                println!(
                    "  Connection on OSI layer 7 (HTTPS)   : {}",
                    if session.l7_ok { "OK".green() } else { "NOT OK".red() }
                );
                if let Some(tv) = &session.tls_version {
                    println!("  TLS version agreed                  : {}", tv);
                }
                if let Some(cs) = &session.cipher_suite {
                    println!("  TLS cipher suite                    : {}", cs);
                }
                if let Some(alpn) = &session.alpn {
                    println!("  Negotiated ALPN                     : {}", alpn);
                }
                println!("  Network delay to layer 4 (ms)       : {}", session.t_l4_ms);
                println!("  Network delay to layer 7 (ms)       : {}", session.t_l7_ms);
                println!(
                    "  Trusted with local TLS CAs          : {}",
                    session.trusted_with_local_cas
                );
                println!(
                    "  Client certificate requested        : {}",
                    session.client_cert_requested
                );

                // Certificates
                for info in &infos {
                    println!();
                    println!("{}", "Certificate".bold());
                    println!("  Index        : {}", info.index);
                    println!("  Subject      : {}", info.subject);
                    println!("  Issuer       : {}", info.issuer);
                    println!("  Serial       : {}", info.serial_number);
                    println!("  Not Before   : {}", info.not_before);
                    println!("  Not After    : {}", info.not_after);
                    println!(
                        "  Status       : {}",
                        if info.is_expired {
                            "expired".red()
                        } else {
                            "valid".green()
                        }
                    );
                    if let Some(cn) = &info.common_name {
                        println!("  Common Name  : {}", cn);
                    }
                    if !info.subject_alternative_names.is_empty() {
                        println!(
                            "  SANs         : {}",
                            info.subject_alternative_names.join(", ")
                        );
                    }
                    println!("  Is CA        : {}", info.is_ca);
                    println!("  CT (embedded SCTs) : {}", info.ct_scts_embedded);
                }
            }
            OutputFormat::Json => {
                // For HTTPS we include the session as well.
                let payload = JsonOutput {
                    session: Some(&session),
                    certificates: &infos,
                };
                println!("{}", serde_json::to_string_pretty(&payload)?);
            }
            OutputFormat::Csv => {
                let csv = to_csv(&infos)?;
                print!("{csv}");
            }
        }

        return Ok(());
    }

    // File/PEM mode
    let pem_data =
        fs::read_to_string(&args.input).with_context(|| format!("Failed to read file: {}", args.input))?;
    let ders = cert::parse_pem_to_der(&pem_data).with_context(|| "Failed to parse PEM certificates")?;

    let mut infos = cert::infos_from_der_certs(&ders);
    if args.expired_only {
        infos.retain(|i| i.is_expired);
    }

    match args.format {
        OutputFormat::Pretty => {
            for info in &infos {
                println!("{}", "Certificate".bold());
                println!("  Index        : {}", info.index);
                println!("  Subject      : {}", info.subject);
                println!("  Issuer       : {}", info.issuer);
                println!("  Serial       : {}", info.serial_number);
                println!("  Not Before   : {}", info.not_before);
                println!("  Not After    : {}", info.not_after);
                println!(
                    "  Status       : {}",
                    if info.is_expired {
                        "expired".red()
                    } else {
                        "valid".green()
                    }
                );
                if let Some(cn) = &info.common_name {
                    println!("  Common Name  : {}", cn);
                }
                if !info.subject_alternative_names.is_empty() {
                    println!(
                        "  SANs         : {}",
                        info.subject_alternative_names.join(", ")
                    );
                }
                println!("  Is CA        : {}", info.is_ca);
                println!("  CT (embedded SCTs) : {}", info.ct_scts_embedded);
                println!();
            }
        }
        OutputFormat::Json => {
            // File mode matches your prior behavior: just the certificates array.
            println!("{}", serde_json::to_string_pretty(&infos)?);
        }
        OutputFormat::Csv => {
            let csv = to_csv(&infos)?;
            print!("{csv}");
        }
    }

    Ok(())
}
