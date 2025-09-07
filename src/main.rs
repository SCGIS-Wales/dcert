mod args;
mod cert;
mod https;
mod proxy;

use anyhow::{Context, Result};
use args::Cli;
use clap::Parser;
use colored::Colorize;
use std::fs;

fn main() -> Result<()> {
    let args = Cli::parse();

    if args.input.starts_with("https://") {
        // Build headers
        let headers_kv: Vec<(String, String)> = args
            .headers
            .as_deref()
            .map(|s| {
                s.split(',')
                    .filter_map(|kv| {
                        let mut it = kv.splitn(2, '=');
                        let k = it.next()?.trim().to_string();
                        let v = it.next().unwrap_or("").trim().to_string();
                        if k.is_empty() { None } else { Some((k, v)) }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let ca_file_path = args.ca_file.as_deref().map(std::path::Path::new);

        let (session, chain) = https::probe_https(
            &args.input,
            args.tls_version,
            args.http_version,
            &args.method,
            &headers_kv,
            ca_file_path,
            args.timeout_l4,
            args.timeout_l6,
            args.timeout_l7,
            args.export_chain,
        )
        .with_context(|| "HTTPS probe failed")?;

        if args.json {
            let infos = cert::infos_from_x509(&chain);
            let payload = serde_json::json!({
                "session": session,
                "certs": infos,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
            return Ok(());
        }

        println!("{}", "HTTPS session".bold());
        println!(
            "  Connection on OSI layer 4 (TCP)     : {}",
            if session.l4_ok {
                "OK".green()
            } else {
                "NOT OK".red()
            }
        );
        println!(
            "  Connection on OSI layer 6 (TLS)     : {}",
            if session.l6_ok {
                "OK".green()
            } else {
                "NOT OK".red()
            }
        );
        println!(
            "  Connection on OSI layer 7 (HTTPS)   : {}",
            if session.l7_ok {
                "OK".green()
            } else {
                "NOT OK".red()
            }
        );
        if let Some(tv) = &session.tls_version {
            println!("  TLS version agreed                  : {}", tv);
        }
        if let Some(cs) = &session.cipher_suite {
            println!("  TLS cipher suite                    : {}", cs);
        }
        if let Some(alpn) = &session.negotiated_alpn {
            println!("  ALPN negotiated                     : {}", alpn);
        }
        println!(
            "  Network delay to layer 4 (ms)       : {}",
            session.t_l4_ms
        );
        println!(
            "  Network delay to layer 7 (ms)       : {}",
            session.t_l7_ms
        );
        println!(
            "  Trusted with local TLS CAs          : {}",
            session.trusted_with_local_cas
        );
        println!(
            "  Client certificate requested        : {}",
            session.client_cert_requested
        );

        let infos = cert::infos_from_x509(&chain);
        println!();
        println!("{}", "Certificate Chain".bold());
        for info in infos {
            println!("  [{}]", info.index);
            println!("    Subject     : {}", info.subject);
            println!("    Issuer      : {}", info.issuer);
            println!("    Serial      : {}", info.serial_number);
            println!("    Not Before  : {}", info.not_before);
            println!("    Not After   : {}", info.not_after);
            println!(
                "    Status      : {}",
                if info.is_expired {
                    "expired".red()
                } else {
                    "valid".green()
                }
            );
            if let Some(cn) = &info.common_name {
                println!("    Common Name : {}", cn);
            }
            if !info.subject_alternative_names.is_empty() {
                println!(
                    "    SANs        : {}",
                    info.subject_alternative_names.join(", ")
                );
            }
            println!("    Is CA       : {}", info.is_ca);
            println!("    CT (SCTs)   : {}", info.ct_scts_embedded);
            println!();
        }
        return Ok(());
    }

    // File/PEM mode
    let pem_data = fs::read_to_string(&args.input)
        .with_context(|| format!("Failed to read file: {}", args.input))?;
    let ders =
        cert::parse_pem_to_der(&pem_data).with_context(|| "Failed to parse PEM certificates")?;

    let mut infos = cert::infos_from_der_certs(&ders);
    if args.expired_only {
        infos.retain(|i| i.is_expired);
    }

    if args.csv {
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
        for i in &infos {
            wtr.write_record([
                i.index.to_string(),
                i.subject.clone(),
                i.issuer.clone(),
                i.serial_number.clone(),
                i.not_before.clone(),
                i.not_after.clone(),
                i.is_expired.to_string(),
                i.common_name.clone().unwrap_or_default(),
                i.subject_alternative_names.join(";"),
                i.is_ca.to_string(),
                i.ct_scts_embedded.to_string(),
            ])?;
        }
        let data = String::from_utf8(wtr.into_inner()?)?;
        println!("{data}");
        return Ok(());
    }

    println!("{}", "Certificates".bold());
    for info in infos {
        println!("  [{}]", info.index);
        println!("    Subject     : {}", info.subject);
        println!("    Issuer      : {}", info.issuer);
        println!("    Serial      : {}", info.serial_number);
        println!("    Not Before  : {}", info.not_before);
        println!("    Not After   : {}", info.not_after);
        println!(
            "    Status      : {}",
            if info.is_expired {
                "expired".red()
            } else {
                "valid".green()
            }
        );
        if let Some(cn) = &info.common_name {
            println!("    Common Name : {}", cn);
        }
        if !info.subject_alternative_names.is_empty() {
            println!(
                "    SANs        : {}",
                info.subject_alternative_names.join(", ")
            );
        }
        println!("    Is CA       : {}", info.is_ca);
        println!("    CT (SCTs)   : {}", info.ct_scts_embedded);
        println!();
    }

    Ok(())
}
