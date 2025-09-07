mod args;
mod cert;
mod https;
mod proxy;

use anyhow::{Context, Result};
use args::Cli;
use clap::Parser;
use colored::Colorize;
use comfy_table::{Cell, Color, ContentArrangement, Row, Table, presets::UTF8_FULL};
use rustls::pki_types::CertificateDer;
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

        let probe_result = https::probe_https(
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
        );

        let (session, chain_x509) = match probe_result {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Error: HTTPS probe failed\n");
                if let Some(session) = e.downcast_ref::<https::HttpsSession>() {
                    if !session.l4_ok {
                        eprintln!("Layer 4 (TCP) failed");
                    } else if !session.l6_ok {
                        eprintln!("Layer 6 (TLS) failed");
                    } else if !session.l7_ok {
                        eprintln!("Layer 7 (HTTPS) failed");
                    }
                }
                eprintln!("\nCaused by:\n    {}", e);
                return Ok(());
            }
        };

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

        let mut session_table = Table::new();
        session_table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["Check", "Status"]);

        session_table.add_row(vec![
            Cell::new("Connection on OSI layer 4 (TCP)"),
            Cell::new(if session.l4_ok {
                "OK".green()
            } else {
                "NOT OK".red()
            }),
        ]);
        session_table.add_row(vec![
            Cell::new("Connection on OSI layer 6 (TLS)"),
            Cell::new(if session.l6_ok {
                "OK".green()
            } else {
                "NOT OK".red()
            }),
        ]);
        session_table.add_row(vec![
            Cell::new("Connection on OSI layer 7 (HTTPS)"),
            Cell::new(if session.l7_ok {
                "OK".green()
            } else {
                "NOT OK".red()
            }),
        ]);
        if let Some(tv) = &session.tls_version {
            session_table.add_row(vec![Cell::new("TLS version agreed"), Cell::new(tv)]);
        }
        if let Some(cs) = &session.cipher_suite {
            session_table.add_row(vec![Cell::new("TLS cipher suite"), Cell::new(cs)]);
        }
        if let Some(alpn) = &session.negotiated_alpn {
            session_table.add_row(vec![Cell::new("ALPN negotiated"), Cell::new(alpn)]);
        }
        session_table.add_row(vec![
            Cell::new("Network delay to layer 4 (ms)"),
            Cell::new(session.t_l4_ms.to_string()),
        ]);
        session_table.add_row(vec![
            Cell::new("Network delay to layer 7 (ms)"),
            Cell::new(session.t_l7_ms.to_string()),
        ]);
        session_table.add_row(vec![
            Cell::new("Trusted with local TLS CAs"),
            Cell::new("<not available>"),
        ]);
        session_table.add_row(vec![
            Cell::new("Client certificate requested"),
            Cell::new(session.client_cert_requested.to_string()),
        ]);

        println!("{session_table}");

        for (idx, cert) in chain_x509.iter().enumerate() {
            println!("  [{}]", idx);
            println!("    Subject     : {}", cert.subject());
            println!("    Issuer      : {}", cert.issuer());
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

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "Index",
            "Subject",
            "Issuer",
            "Serial",
            "Common Name",
            "SANs",
            "Is CA",
            "Certificate Transparency (SCTs)",
            "Issued on",
            "Expires on",
            "Expired",
        ]);

    let now = chrono::Utc::now().to_string();

    for (idx, _cert_der) in ders.iter().enumerate() {
        let info = &infos[idx];
        let subject = info.subject.clone();
        let issuer = info.issuer.clone();
        let serial = "<not available>"; // Replace with actual serial extraction if possible
        let common_name = info.common_name.clone().unwrap_or_default();
        let sans = info.subject_alt_names.join(";");
        let is_ca_cell = Cell::new("<not available>");
        let ct_cell = Cell::new(if info.has_embedded_sct {
            "true"
        } else {
            "false"
        });
        let not_before = info.not_before.clone();
        let not_after = info.not_after.clone();
        let expired = not_after < now;
        let expired_cell = if expired {
            Cell::new("true").fg(Color::Red)
        } else {
            Cell::new("false").fg(Color::Green)
        };

        table.add_row(Row::from(vec![
            Cell::new(idx),
            Cell::new(subject),
            Cell::new(issuer),
            Cell::new(serial),
            Cell::new(common_name),
            Cell::new(sans),
            is_ca_cell,
            ct_cell,
            Cell::new(not_before),
            Cell::new(not_after),
            expired_cell,
        ]));
    }

    println!("{table}");

    Ok(())
}
