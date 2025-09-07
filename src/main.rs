mod args;
mod cert;
mod https;
mod proxy;

use anyhow::{Context, Result};
use args::{Args, OutputFormat};
use clap::Parser;
use colored::Colorize;
use std::fs;

include!(concat!(env!("OUT_DIR"), "/deps.rs"));

fn print_version() {
    println!("dcert {}", PKG_VERSION);
    println!("Dependencies:");
    for line in DEP_VERSIONS.lines() {
        println!("  {line}");
    }
}

fn print_pretty(infos: &[cert::CertInfo]) {
    for info in infos {
        println!("{}", "Certificate".bold());
        println!("  Index        : {}", info.index);
        println!("  Subject      : {}", info.subject);
        println!("  Issuer       : {}", info.issuer);
        println!("  Serial       : {}", info.serial_number);
        println!("  Not Before   : {}", info.not_before);
        println!("  Not After    : {}", info.not_after);
        println!("  Status       : {}", if info.is_expired { "expired".red() } else { "valid".green() });
        if let Some(cn) = &info.common_name {
            println!("  Common Name  : {}", cn);
        }
        if !info.subject_alternative_names.is_empty() {
            println!("  SANs         : {}", info.subject_alternative_names.join(", "));
        }
        println!("  Is CA        : {}", info.is_ca);
        println!("  CT embedded  : {}", info.ct_scts_embedded);
        println!();
    }
}

fn to_csv(infos: &[cert::CertInfo]) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record([
        "index","subject","issuer","serial_number","not_before","not_after","is_expired","common_name","sans","is_ca","ct_scts_embedded"
    ])?;
    for i in infos {
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
    Ok(data)
}

fn main() -> Result<()> {
    // Custom --version that prints dependencies too
    if std::env::args().any(|a| a == "--version" || a == "-V") && std::env::args().count() == 2 {
        print_version();
        return Ok(());
    }

    let args = Args::parse();

    if args.input.starts_with("https://") {
        // HTTPS probe
        let headers_kv: Vec<(String,String)> = args.headers.as_deref()
            .map(|s| s.split(',')
                .filter_map(|kv| {
                    let mut it = kv.splitn(2,'=');
                    let k = it.next()?.trim().to_string();
                    let v = it.next().unwrap_or("").trim().to_string();
                    if k.is_empty() { None } else { Some((k,v)) }
                })
                .collect()
            ).unwrap_or_default();

        let (session, chain) = https::probe_https(
            &args.input,
            args.tls_version,
            args.http_version,
            &args.method,
            &headers_kv,
            args.ca_file.as_ref().map(|p| p.as_path()),
            args.timeout_l4,
            args.timeout_l6,
            args.timeout_l7,
            args.export_chain,
        ).with_context(|| "HTTPS probe failed")?;

        println!("{}", "HTTPS session".bold());
        println!("  Connection on OSI layer 4 (TCP)     : {}", if session.l4_ok { "OK".green() } else { "NOT OK".red() });
        println!("  Connection on OSI layer 6 (TLS)     : {}", if session.l6_ok { "OK".green() } else { "NOT OK".red() });
        println!("  Connection on OSI layer 7 (HTTPS)   : {}", if session.l7_ok { "OK".green() } else { "NOT OK".red() });
        if let Some(tv) = &session.tls_version {
            println!("  TLS version agreed                  : {}", tv);
        }
        if let Some(cs) = &session.tls_cipher_suite {
            println!("  TLS cipher suite                    : {}", cs);
        }
        if let Some(alpn) = &session.negotiated_alpn {
            println!("  Negotiated ALPN                     : {}", alpn);
        }
        println!("  Network delay to layer 4 (ms)       : {}", session.t_l4_ms);
        println!("  Network delay to layer 7 (ms)       : {}", session.t_l7_ms);
        println!("  Trusted with local TLS CAs          : {}", session.trusted_with_local_cas);
        println!("  Client certificate requested        : {}", session.client_cert_requested);

        // Print certificates
        let infos = cert::infos_from_x509(&chain);
        match args.format {
            OutputFormat::Pretty => {
                println!();
                print_pretty(&infos);
            }
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&infos)?);
            }
            OutputFormat::Csv => {
                println!("{}", to_csv(&infos)?);
            }
        }
        return Ok(());
    }

    // File mode
    let pem_data = fs::read_to_string(&args.input)
        .with_context(|| format!("Failed to read file: {}", args.input))?;

    let certs = cert::parse_pem_certificates(&pem_data)
        .with_context(|| "Failed to parse PEM certificates")?;

    let mut infos = cert::infos_from_x509(&certs);
    if args.expired_only {
        infos.retain(|i| i.is_expired);
    }

    match args.format {
        OutputFormat::Pretty => print_pretty(&infos),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&infos)?),
        OutputFormat::Csv => println!("{}", to_csv(&infos)?),
    }

    Ok(())
}
