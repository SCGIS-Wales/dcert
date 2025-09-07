mod args;
mod cert;
mod https;
mod proxy;

use anyhow::{Context, Result};
use args::Cli;
use clap::Parser;
use colored::Colorize;
use rustls::pki_types::CertificateDer; // Add this import at the top of main.rs
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

        let (session, chain_x509) = https::probe_https(
            &args.input,
            args.tls_version,
            args.http_version,
            &args.method,
            &headers_kv,
            args.timeout_l4,
            args.timeout_l6,
            args.timeout_l7,
            ca_file_path,
            args.export_chain,
        )
        .with_context(|| "HTTPS probe failed")?;

        if args.json {
            let chain_der: Vec<CertificateDer<'_>> = chain_x509
                .iter()
                .map(|cert| CertificateDer::from(cert.as_ref()))
                .collect();
            let infos = cert::infos_from_der_certs(&chain_der);
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
        println!("  Trusted with local TLS CAs          : <not available>");
        println!(
            "  Client certificate requested        : {}",
            session.client_cert_requested
        );

        for (idx, cert) in chain_x509.iter().enumerate() {
            println!("  [{}]", idx);
            println!("    Subject     : {}", cert.subject().to_string());
            println!("    Issuer      : {}", cert.issuer().to_string());
            println!("    Serial      : <not available>");
            let now = chrono::Utc::now().to_string();
            let not_after = cert.validity().not_after.to_string();
            if not_after < now {
                println!("    Expired     : Yes");
            } else {
                println!("    Expired     : No");
            }
            // You can extract SANs and other info similarly if needed
            println!("    Is CA       : <not available>");
            println!("    CT (SCTs)   : <not available>");
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
        let now = chrono::Utc::now().to_string();
        infos.retain(|i| i.not_after < now);
    }
    if infos.is_empty() {
        println!("No certificates found");
        return Ok(());
    }
    if args.csv {
        let mut wtr = csv::Writer::from_writer(vec![]);
        wtr.write_record([
            "index",
            "subject",
            "issuer",
            "not_before",
            "not_after",
            "is_expired",
            "common_name",
            "sans",
            "is_ca",
            "ct_scts_embedded",
        ])?;
        let now = chrono::Utc::now().to_string(); // <-- Add this line
        for i in &infos {
            wtr.write_record([
                i.index.to_string(),
                i.subject.clone(),
                i.issuer.clone(),
                i.not_before.clone(),
                i.not_after.clone(),
                (i.not_after < now).to_string(), // Expired check
                i.common_name.clone().unwrap_or_default(),
                i.subject_alt_names.join(";"),
                "<not available>".to_string(),
                i.has_embedded_sct.to_string(),
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
        println!("    Serial      : <not available>");
        let now = chrono::Utc::now().to_string();
        if info.not_after < now {
            println!("    Expired     : Yes");
        } else {
            println!("    Expired     : No");
        }
        if !info.subject_alt_names.is_empty() {
            println!("    SAN         : {}", info.subject_alt_names.join(", "));
        }
        println!("    Is CA       : <not available>");
        println!("    CT (SCTs)   : {}", info.has_embedded_sct);
        println!();
    }

    Ok(())
}
