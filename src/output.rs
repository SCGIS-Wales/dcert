use anyhow::{Context, Result};
use colored::*;
use pem_rfc7468::LineEnding;
use std::fs;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::cert::{extract_ocsp_url, parse_cert_infos_from_pem, CertInfo, CertProcessOpts};
use crate::cli::{Args, CipherNotation, HttpProtocol, OutputFormat, SortOrder};
use crate::debug::debug_log;
use crate::ocsp::check_ocsp_status;
use crate::proxy::ProxyConfig;
use crate::tls::{fetch_tls_chain_openssl, TlsConnectionInfo};

/// Debug/connection info for pretty output.
pub struct PrettyDebugInfo<'a> {
    pub hostname: Option<&'a str>,
    pub conn: Option<&'a TlsConnectionInfo>,
    pub http_protocol: &'a HttpProtocol,
    pub cipher_notation: Option<CipherNotation>,
}

pub fn print_pretty(infos: &[CertInfo], debug: &PrettyDebugInfo<'_>) {
    if let (Some(host), Some(conn)) = (debug.hostname, debug.conn) {
        if let Some(leaf) = infos.first() {
            let matched = cert_matches_hostname(leaf, host);
            let status = if matched { "true".green() } else { "false".red() };
            println!();
            println!("{}", "Debug".bold());
            // Show the negotiated ALPN protocol if available, otherwise the requested protocol
            let proto_display = match &conn.negotiated_protocol {
                Some(proto) => match proto.as_str() {
                    "h2" => "HTTP/2 (h2)".to_string(),
                    "http/1.1" => "HTTP/1.1".to_string(),
                    other => other.to_string(),
                },
                None => match debug.http_protocol {
                    HttpProtocol::Http2 => "HTTP/2 (requested, ALPN not supported by server)".to_string(),
                    HttpProtocol::Http1_1 => "HTTP/1.1".to_string(),
                },
            };
            println!("  HTTP protocol: {}", proto_display);
            if conn.http_response_code > 0 {
                let code_color = match conn.http_response_code {
                    200..=299 => conn.http_response_code.to_string().green(),
                    300..=399 => conn.http_response_code.to_string().yellow(),
                    400..=499 => conn.http_response_code.to_string().red(),
                    500..=599 => conn.http_response_code.to_string().red().bold(),
                    _ => conn.http_response_code.to_string().normal(),
                };
                println!("  HTTP response code: {}", code_color);
            } else {
                println!("  HTTP response code: not available");
            }
            println!("  Hostname matches certificate SANs/CN: {}", status);
            println!("  TLS version used: {}", conn.tls_version);
            // Cipher display: always show OpenSSL name in the default line,
            // but when --ciphers is used, show the requested notation prominently
            match debug.cipher_notation {
                Some(CipherNotation::Iana) => {
                    let iana_name = conn
                        .tls_cipher_iana
                        .as_deref()
                        .unwrap_or("unknown (IANA name not available)");
                    println!("  TLS ciphersuite agreed (IANA): {}", iana_name);
                }
                Some(CipherNotation::Openssl) => {
                    println!("  TLS ciphersuite agreed (OpenSSL): {}", conn.tls_cipher);
                }
                None => {
                    println!("  TLS ciphersuite agreed: {}", conn.tls_cipher);
                }
            }
            let ct_str = if leaf.ct_present { "true".green() } else { "false".red() };
            println!("  Certificate transparency: {}", ct_str);

            // Verification result
            if let Some(ref err) = conn.verify_result {
                println!("  Chain verification: {}", err.red());
                for detail in &conn.chain_validation_errors {
                    println!("    {}", detail.red());
                }
            } else {
                println!("  Chain verification: {}", "ok".green());
            }

            println!();
            println!("  Network latency (DNS resolution):      {} ms", conn.dns_latency);
            println!("  Network latency (layer 4/TCP connect): {} ms", conn.l4_latency);
            println!("  Network latency (layer 7/TLS+HTTP):    {} ms", conn.l7_latency);
            println!();
            println!(
                "Note: DNS, Layer 4, and Layer 7 latencies are measured separately and should not be summed. \
DNS covers name resolution only; Layer 4 covers DNS + TCP connection; \
Layer 7 covers TLS handshake, sending the HTTP request, and reading the \
HTTP status line (not the full response body)."
            );
            println!();
        }
    }
    for info in infos {
        println!("{}", "Certificate".bold());
        println!("  Index        : {}", info.index);
        if let Some(cn) = &info.common_name {
            println!("  Common Name  : {}", cn);
        }
        println!("  Subject      : {}", info.subject);
        println!("  Issuer       : {}", info.issuer);
        println!("  Serial       : {}", info.serial_number);
        println!("  Not Before   : {}", info.not_before);
        println!("  Not After    : {}", info.not_after);

        if !info.subject_alternative_names.is_empty() {
            println!("  SANs         :");
            for san in &info.subject_alternative_names {
                println!("    - {}", san);
            }
        }

        if let Some(ref fp) = info.sha256_fingerprint {
            println!("  SHA-256      : {}", fp);
        }

        if let Some(ref alg) = info.signature_algorithm {
            println!("  Sig Algorithm: {}", alg);
        }

        if let Some(ref alg) = info.public_key_algorithm {
            let size_str = info
                .public_key_size_bits
                .map(|s| format!(" ({} bits)", s))
                .unwrap_or_default();
            println!("  Public Key   : {}{}", alg, size_str);
        }

        if let Some(ref ku) = info.key_usage {
            println!("  Key Usage    : {}", ku.join(", "));
        }

        if let Some(ref eku) = info.extended_key_usage {
            println!("  Ext Key Usage: {}", eku.join(", "));
        }

        if let Some(ref bc) = info.basic_constraints {
            let ca_str = if bc.ca { "true" } else { "false" };
            let path_str = bc
                .path_len_constraint
                .map(|p| format!(", pathLen={}", p))
                .unwrap_or_default();
            println!("  Basic Constr : CA={}{}", ca_str, path_str);
        }

        if let Some(ref aia) = info.authority_info_access {
            println!("  Auth Info    :");
            for entry in aia {
                println!("    - {}", entry);
            }
        }

        if let Some(ref rev) = info.revocation_status {
            let colored_status = match rev.as_str() {
                "good" => rev.green(),
                "revoked" => rev.red(),
                _ => rev.yellow(),
            };
            println!("  Revocation   : {}", colored_status);
        }

        let status = if info.is_expired {
            "expired".red()
        } else {
            "valid".green()
        };
        println!("  Status       : {}", status);
        println!();
    }
}

pub fn cert_matches_hostname(cert: &CertInfo, host: &str) -> bool {
    let host = host.trim().to_lowercase();

    // Helper for wildcard matching
    fn matches_wildcard(pattern: &str, hostname: &str) -> bool {
        // Only allow wildcard at the start, e.g. *.example.com
        if let Some(stripped) = pattern.strip_prefix("*.") {
            let host_labels: Vec<&str> = hostname.split('.').collect();
            let pattern_labels: Vec<&str> = stripped.split('.').collect();
            if host_labels.len() < pattern_labels.len() + 1 {
                return false;
            }
            let host_suffix = host_labels[1..].join(".");
            return host_suffix == stripped;
        }
        false
    }

    // Check Common Name
    if let Some(cn) = &cert.common_name {
        let cn = cn.trim().to_lowercase();
        if cn == host {
            return true;
        }
        if cn.starts_with("*.") && matches_wildcard(&cn, &host) {
            return true;
        }
    }
    // Check SANs
    for san in &cert.subject_alternative_names {
        if let Some(san_host) = san.strip_prefix("DNS:") {
            let san_host = san_host.trim().to_lowercase();
            if san_host == host {
                return true;
            }
            if san_host.starts_with("*.") && matches_wildcard(&san_host, &host) {
                return true;
            }
        }
    }
    false
}

/// Result of processing a single target.
pub struct TargetResult {
    pub target: String,
    pub conn_info: Option<TlsConnectionInfo>,
    pub infos: Vec<CertInfo>,
    pub pem_data: String,
}

/// Process a single target (PEM file or HTTPS URL) and return results.
#[allow(clippy::too_many_arguments)]
pub fn process_target(
    target: &str,
    args: &Args,
    proxy_config: &ProxyConfig,
    body: Option<&[u8]>,
) -> Result<TargetResult> {
    debug_log!(args.debug, "Processing target: {}", target);

    let opts = CertProcessOpts {
        expired_only: args.expired_only,
        fingerprint: args.fingerprint,
        extensions: args.extensions,
    };

    let (pem_data, conn_info) = if target.starts_with("https://") {
        if args.no_verify {
            eprintln!(
                "{} TLS certificate verification is disabled (--no-verify). \
                 Chain validation errors will be suppressed.",
                "Warning:".yellow().bold()
            );
        }
        let conn = fetch_tls_chain_openssl(
            target,
            &args.method.to_string(),
            &args.header,
            body,
            args.http_protocol,
            args.no_verify,
            args.timeout,
            args.read_timeout,
            args.sni.as_deref(),
            proxy_config,
            args.min_tls,
            args.max_tls,
            args.cipher_list.as_deref(),
            args.cipher_suites.as_deref(),
            args.debug,
        )?;
        let pem = conn.pem_data.clone();
        (pem, Some(conn))
    } else {
        let pem = fs::read_to_string(target).with_context(|| format!("Failed to read PEM file: {}", target))?;
        (pem, None)
    };

    let mut infos = parse_cert_infos_from_pem(&pem_data, &opts).with_context(|| "Failed to parse PEM certificates")?;

    // OCSP revocation checking
    if args.check_revocation {
        let blocks = pem::parse_many(&pem_data).unwrap_or_default();
        let cert_ders: Vec<&[u8]> = blocks
            .iter()
            .filter(|b| b.tag() == "CERTIFICATE")
            .map(|b| b.contents())
            .collect();

        for (i, info) in infos.iter_mut().enumerate() {
            // Parse the x509 cert to extract OCSP URL
            if let Some(der) = cert_ders.get(i) {
                if let Ok((_, cert)) = X509Certificate::from_der(der) {
                    if let Some(ocsp_url) = extract_ocsp_url(&cert) {
                        let issuer_der = cert_ders.get(i + 1).copied();
                        info.revocation_status = Some(check_ocsp_status(der, issuer_der, &ocsp_url, args.debug));
                    } else {
                        info.revocation_status = Some("unknown (no OCSP responder)".to_string());
                    }
                }
            }
        }
    }

    // Sort certificates by expiry if requested
    if let Some(sort_order) = args.sort_expiry {
        sort_certs_by_expiry(&mut infos, sort_order);
    }

    Ok(TargetResult {
        target: target.to_string(),
        conn_info,
        infos,
        pem_data,
    })
}

/// Sort certificates by expiry date.
pub fn sort_certs_by_expiry(infos: &mut [CertInfo], sort_order: SortOrder) {
    infos.sort_by(|a, b| {
        let parse_date = |date_str: &str| -> Option<OffsetDateTime> { OffsetDateTime::parse(date_str, &Rfc3339).ok() };

        let ordering = match (parse_date(&a.not_after), parse_date(&b.not_after)) {
            (Some(date_a), Some(date_b)) => date_a.cmp(&date_b),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.not_after.cmp(&b.not_after),
        };

        match sort_order {
            SortOrder::Asc => ordering,
            SortOrder::Desc => ordering.reverse(),
        }
    });
}

/// Check expiry warning threshold and return exit code.
pub fn check_expiry_warnings(infos: &[CertInfo], warn_days: u64) -> i32 {
    let now = OffsetDateTime::now_utc();
    let threshold = now + time::Duration::days(warn_days as i64);
    let mut has_warning = false;

    for info in infos {
        if let Ok(not_after) = OffsetDateTime::parse(&info.not_after, &Rfc3339) {
            if info.is_expired {
                eprintln!(
                    "{} Certificate {} ({}) is EXPIRED (expired {})",
                    "WARNING:".yellow().bold(),
                    info.index,
                    info.common_name.as_deref().unwrap_or(&info.subject),
                    info.not_after,
                );
                has_warning = true;
            } else if not_after <= threshold {
                let days_left = (not_after - now).whole_days();
                eprintln!(
                    "{} Certificate {} ({}) expires in {} days ({})",
                    "WARNING:".yellow().bold(),
                    info.index,
                    info.common_name.as_deref().unwrap_or(&info.subject),
                    days_left,
                    info.not_after,
                );
                has_warning = true;
            }
        }
    }

    if has_warning {
        1
    } else {
        0
    }
}

/// Print diff between two sets of certificate infos.
pub fn print_diff(target_a: &str, infos_a: &[CertInfo], target_b: &str, infos_b: &[CertInfo]) {
    println!("{}", "Certificate Diff".bold());
    println!("  A: {}", target_a);
    println!("  B: {}", target_b);
    println!();

    let max_len = infos_a.len().max(infos_b.len());
    for i in 0..max_len {
        let a = infos_a.get(i);
        let b = infos_b.get(i);

        match (a, b) {
            (Some(ca), Some(cb)) => {
                println!("{}", format!("Certificate [{}]", i).bold());
                diff_field("Subject", &ca.subject, &cb.subject);
                diff_field("Issuer", &ca.issuer, &cb.issuer);
                diff_field(
                    "Common Name",
                    ca.common_name.as_deref().unwrap_or("(none)"),
                    cb.common_name.as_deref().unwrap_or("(none)"),
                );
                diff_field("Serial", &ca.serial_number, &cb.serial_number);
                diff_field("Not Before", &ca.not_before, &cb.not_before);
                diff_field("Not After", &ca.not_after, &cb.not_after);
                diff_field("Expired", &ca.is_expired.to_string(), &cb.is_expired.to_string());
                if let (Some(fa), Some(fb)) = (&ca.sha256_fingerprint, &cb.sha256_fingerprint) {
                    diff_field("SHA-256", fa, fb);
                }
                let sans_a = ca.subject_alternative_names.join(", ");
                let sans_b = cb.subject_alternative_names.join(", ");
                diff_field("SANs", &sans_a, &sans_b);
                println!();
            }
            (Some(ca), None) => {
                println!("{} Only in A: index={} subject={}", "-".red(), ca.index, ca.subject);
            }
            (None, Some(cb)) => {
                println!("{} Only in B: index={} subject={}", "+".green(), cb.index, cb.subject);
            }
            (None, None) => {}
        }
    }
}

pub fn diff_field(name: &str, a: &str, b: &str) {
    if a == b {
        println!("  {:<14}: {}", name, a);
    } else {
        println!("  {:<14}: {} → {}", name, a.to_string().red(), b.to_string().green());
    }
}

/// Export PEM chain to a file, optionally excluding expired certs.
pub fn export_pem_chain(pem_data: &str, export_path: &str, exclude_expired: bool) -> Result<()> {
    let export_data = if exclude_expired {
        let blocks = pem::parse_many(pem_data).map_err(|e| anyhow::anyhow!("Failed to parse PEM for export: {e}"))?;
        let now = OffsetDateTime::now_utc();
        let mut filtered_pem = String::new();

        for block in blocks {
            if block.tag() != "CERTIFICATE" {
                continue;
            }
            if let Ok((_, cert)) = X509Certificate::from_der(block.contents()) {
                let not_after: OffsetDateTime = cert.validity().not_after.to_datetime();
                if not_after >= now {
                    let pem_str = pem_rfc7468::encode_string("CERTIFICATE", LineEnding::LF, block.contents())
                        .map_err(|e| anyhow::anyhow!("PEM encoding failed: {e}"))?;
                    filtered_pem.push_str(&pem_str);
                    if !filtered_pem.ends_with('\n') {
                        filtered_pem.push('\n');
                    }
                }
            }
        }

        if filtered_pem.is_empty() {
            eprintln!(
                "Warning: All certificates were expired. No certificates exported to {}",
                export_path
            );
            return Ok(());
        }

        filtered_pem
    } else {
        pem_data.to_string()
    };

    fs::write(export_path, export_data).with_context(|| format!("Failed to write PEM file: {}", export_path))?;
    println!("PEM chain exported to {}", export_path);
    Ok(())
}

/// Output results for a target in the requested format.
pub fn output_results(
    result: &TargetResult,
    format: OutputFormat,
    http_protocol: &HttpProtocol,
    multi_target: bool,
    args: &Args,
) -> Result<()> {
    if multi_target {
        println!("{}", format!("--- {} ---", result.target).bold().cyan());
    }

    let hostname = if result.target.starts_with("https://") {
        Url::parse(&result.target)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_lowercase()))
    } else {
        None
    };

    match format {
        OutputFormat::Pretty => {
            let debug = PrettyDebugInfo {
                hostname: hostname.as_deref(),
                conn: result.conn_info.as_ref(),
                http_protocol,
                cipher_notation: args.ciphers,
            };
            print_pretty(&result.infos, &debug);
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result.infos)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(&result.infos)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::tests::make_test_cert;
    use crate::cert::{parse_cert_infos_from_pem, CertProcessOpts};
    use crate::cli::SortOrder;

    // The multi-cert chain from tests/data/test.pem (Microsoft Azure)
    const CHAIN_PEM: &str = include_str!("../tests/data/test.pem");

    // A self-signed test certificate with CN=test.example.com and SANs
    const VALID_PEM: &str = include_str!("../tests/data/valid.pem");

    fn default_opts() -> CertProcessOpts {
        CertProcessOpts {
            expired_only: false,
            fingerprint: false,
            extensions: false,
        }
    }

    // ---------------------------------------------------------------
    // cert_matches_hostname tests
    // ---------------------------------------------------------------

    #[test]
    fn test_hostname_exact_match_cn() {
        let cert = make_test_cert(Some("test.example.com"), vec![]);
        assert!(cert_matches_hostname(&cert, "test.example.com"));
        assert!(!cert_matches_hostname(&cert, "other.example.com"));
    }

    #[test]
    fn test_hostname_case_insensitive() {
        let cert = make_test_cert(Some("Test.Example.COM"), vec![]);
        assert!(cert_matches_hostname(&cert, "test.example.com"));
        assert!(cert_matches_hostname(&cert, "TEST.EXAMPLE.COM"));
    }

    #[test]
    fn test_hostname_wildcard_san() {
        let cert = make_test_cert(None, vec!["DNS:*.example.com"]);
        assert!(cert_matches_hostname(&cert, "www.example.com"));
        assert!(cert_matches_hostname(&cert, "mail.example.com"));
        assert!(!cert_matches_hostname(&cert, "example.com"));
        assert!(!cert_matches_hostname(&cert, "sub.sub.example.com"));
    }

    #[test]
    fn test_hostname_san_exact_match() {
        let cert = make_test_cert(None, vec!["DNS:api.example.com", "DNS:www.example.com"]);
        assert!(cert_matches_hostname(&cert, "api.example.com"));
        assert!(cert_matches_hostname(&cert, "www.example.com"));
        assert!(!cert_matches_hostname(&cert, "other.example.com"));
    }

    #[test]
    fn test_hostname_no_match() {
        let cert = make_test_cert(Some("other.example.com"), vec!["DNS:another.example.com"]);
        assert!(!cert_matches_hostname(&cert, "test.example.com"));
    }

    // ---------------------------------------------------------------
    // Expiry warning tests
    // ---------------------------------------------------------------

    #[test]
    fn test_expiry_warn_no_warning_for_distant_expiry() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        // cert expires in ~1 year, warning for 7 days should not trigger
        let code = check_expiry_warnings(&infos, 7);
        assert_eq!(code, 0, "no warning should be triggered for distant expiry");
    }

    #[test]
    fn test_expiry_warn_warning_for_large_horizon() {
        let infos = parse_cert_infos_from_pem(VALID_PEM, &default_opts()).unwrap();
        // cert expires in ~1 year, warning for 400 days should trigger
        let code = check_expiry_warnings(&infos, 400);
        assert_eq!(code, 1, "warning should be triggered for large horizon");
    }

    #[test]
    fn test_expiry_warn_expired_certs() {
        let all = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        let has_expired = all.iter().any(|c| c.is_expired);
        if has_expired {
            let code = check_expiry_warnings(&all, 1);
            assert_eq!(code, 1, "expired certs should trigger warning");
        }
    }

    // ---------------------------------------------------------------
    // Sort expiry tests
    // ---------------------------------------------------------------

    #[test]
    fn test_sort_certs_by_expiry_asc() {
        let mut infos = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        sort_certs_by_expiry(&mut infos, SortOrder::Asc);
        for i in 1..infos.len() {
            assert!(infos[i - 1].not_after <= infos[i].not_after, "expected ascending order");
        }
    }

    #[test]
    fn test_sort_certs_by_expiry_desc() {
        let mut infos = parse_cert_infos_from_pem(CHAIN_PEM, &default_opts()).unwrap();
        sort_certs_by_expiry(&mut infos, SortOrder::Desc);
        for i in 1..infos.len() {
            assert!(
                infos[i - 1].not_after >= infos[i].not_after,
                "expected descending order"
            );
        }
    }

    // ---------------------------------------------------------------
    // diff_field tests
    // ---------------------------------------------------------------

    #[test]
    fn test_diff_field_same_values() {
        // diff_field prints to stdout; just verify it doesn't panic
        diff_field("Test", "value", "value");
    }

    #[test]
    fn test_diff_field_different_values() {
        diff_field("Test", "old", "new");
    }
}
