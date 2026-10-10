use openssl::hash::MessageDigest;
use openssl::x509::X509;
use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;
use url::Url;

use crate::debug::debug_log;
use crate::tls::{read_http_response, resolve_host};

/// Determine whether an OCSP responder host is safe to contact.
///
/// The OCSP URL comes from the certificate's AIA extension and is therefore
/// **attacker-controlled** when we're checking a certificate from an untrusted
/// source. Without a guard, a malicious cert can specify
/// `http://169.254.169.254/...` (cloud metadata), `http://127.0.0.1:8200/...`
/// (local Vault/services), or any RFC 1918 address — turning `dcert` into an
/// SSRF probe. We reject IP literals that target loopback, link-local,
/// private (RFC 1918), or unique-local-IPv6 ranges.
///
/// Hostnames are accepted at parse time (we cannot prevent DNS rebinding here
/// without a full resolver dance); the destination IP appears in the debug
/// output of `direct_tcp_connect` and an external SSRF allow-list at the
/// network layer remains the strongest defence.
pub fn is_safe_ocsp_host(host: &str) -> bool {
    // Strip optional surrounding `[` `]` for IPv6 literals.
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    match trimmed.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => !is_internal_v4(v4),
        Ok(IpAddr::V6(v6)) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return false;
            }
            // Link-local: fe80::/10
            let segs = v6.segments();
            if (segs[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            // Unique local addresses (ULA): fc00::/7
            if (segs[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            // Multicast ff00::/8 is never a responder.
            if v6.is_multicast() {
                return false;
            }
            // IPv4-mapped IPv6 (::ffff:0:0/96): apply the full v4 policy.
            if let Some(v4) = v6.to_ipv4_mapped()
                && is_internal_v4(v4)
            {
                return false;
            }
            true
        }
        // Hostnames are accepted; resolution (and the resulting safety check
        // at the network layer) is logged via debug output.
        Err(_) => true,
    }
}

/// IPv4 ranges an OCSP responder must never live in: loopback, RFC 1918,
/// link local (including the cloud metadata address), carrier grade NAT
/// (100.64.0.0/10), the IETF protocol block 192.0.0.0/24, documentation
/// networks, multicast, the reserved 240.0.0.0/4, broadcast and unspecified.
fn is_internal_v4(v4: std::net::Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || v4.is_documentation()
        || v4.is_multicast()
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && v4.octets()[2] == 0)
        || a >= 240
}

/// Maximum accepted OCSP response size (DER plus HTTP head).
const MAX_OCSP_RESPONSE_SIZE: usize = 1024 * 1024;

/// Socket connect and read bound for the responder exchange.
const OCSP_TIMEOUT: Duration = Duration::from_secs(5);

/// Clock skew tolerated when checking `thisUpdate` / `nextUpdate`.
const OCSP_MAX_SKEW_SECS: i64 = 300;

/// Check OCSP revocation status for a certificate.
/// Returns "good", "revoked", "unknown", or an error description.
pub fn check_ocsp_status(cert_der: &[u8], issuer_der: Option<&[u8]>, ocsp_url: &str, debug: bool) -> String {
    let cert = match X509::from_der(cert_der) {
        Ok(c) => c,
        Err(e) => return format!("error: failed to parse cert: {e}"),
    };

    let issuer = match issuer_der {
        Some(der) => match X509::from_der(der) {
            Ok(c) => c,
            Err(e) => return format!("error: failed to parse issuer: {e}"),
        },
        None => return "unknown (no issuer certificate available)".to_string(),
    };

    // Build OCSP request
    let cert_id = match openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), &cert, &issuer) {
        Ok(id) => id,
        Err(e) => return format!("error: OCSP cert ID creation failed: {e}"),
    };

    let mut ocsp_req_builder = match openssl::ocsp::OcspRequest::new() {
        Ok(r) => r,
        Err(e) => return format!("error: OCSP request creation failed: {e}"),
    };

    if let Err(e) = ocsp_req_builder.add_id(cert_id) {
        return format!("error: failed to add cert ID: {e}");
    }

    let request_bytes = match ocsp_req_builder.to_der() {
        Ok(b) => b,
        Err(e) => return format!("error: OCSP request serialization failed: {e}"),
    };

    // Send OCSP request via HTTP POST
    let url = match Url::parse(ocsp_url) {
        Ok(u) => u,
        Err(e) => return format!("error: invalid OCSP URL: {e}"),
    };

    // Defence-in-depth against SSRF via attacker-controlled AIA extension:
    // refuse non-HTTP schemes and refuse private/loopback/link-local IPs.
    // OCSP responders are public services by definition; an OCSP URL
    // pointing at `127.0.0.1` or `169.254.169.254` is suspicious by itself.
    // RFC 6960 responders are plain HTTP (the response is signed); an
    // `https://` URL is rejected explicitly rather than spoken to in
    // cleartext on port 443, which can only ever fail.
    if url.scheme() != "http" {
        return format!(
            "unknown (OCSP responder rejected: unsupported scheme '{}'; RFC 6960 responders use http://)",
            url.scheme()
        );
    }

    let host = match url.host_str() {
        Some(h) => h.to_string(),
        None => return "error: OCSP URL has no host".to_string(),
    };
    if !is_safe_ocsp_host(&host) {
        return "unknown (OCSP responder rejected: private/loopback address)".to_string();
    }
    let port = url.port().unwrap_or(80);
    let path = if url.path().is_empty() { "/" } else { url.path() };

    debug_log!(debug, "OCSP check: {}:{}{}", host, port, path);

    // Resolve first and check the answer before any packet goes out, so a
    // name pointing at an internal service is refused without connecting
    // (connecting first would turn dcert into a port scan oracle).
    let addr = match resolve_host(&host, port) {
        Ok((addr, _dns_ms)) => addr,
        Err(e) => return format!("unknown (could not resolve OCSP responder {host}: {e})"),
    };
    if !is_safe_ocsp_host(&addr.ip().to_string()) {
        return "unknown (OCSP responder rejected: address is private, loopback or otherwise internal)".to_string();
    }
    let tcp_stream = match std::net::TcpStream::connect_timeout(&addr, OCSP_TIMEOUT) {
        Ok(s) => {
            debug_log!(debug, "OCSP responder connected: {}:{}", host, port);
            s
        }
        Err(e) => {
            // The CA's OCSP endpoint (e.g. ocsp.digicert.com) is unreachable.
            // This is frequently a firewall blocking outbound access to the CA
            // rather than a problem with the certificate itself; say so clearly.
            return format!(
                "unknown (could not reach OCSP responder at {host}:{port}; CA endpoint unreachable, possibly firewall blocked: {e})"
            );
        }
    };
    if let Err(e) = tcp_stream.set_read_timeout(Some(OCSP_TIMEOUT)) {
        eprintln!("Warning: failed to set OCSP read timeout: {e}");
    }

    let http_req = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/ocsp-request\r\nContent-Length: {}\r\n\r\n",
        path,
        host,
        request_bytes.len()
    );

    let mut buf_stream = std::io::BufWriter::new(tcp_stream);
    if buf_stream.write_all(http_req.as_bytes()).is_err()
        || buf_stream.write_all(&request_bytes).is_err()
        || buf_stream.flush().is_err()
    {
        return "error: failed to send OCSP request".to_string();
    }

    let Ok(mut tcp_stream) = buf_stream.into_inner() else {
        return "error: failed to flush stream".to_string();
    };

    // Read the response through the shared bounded HTTP reader: one deadline,
    // a 64 KiB head cap and a body cap, then parse status and body.
    let response = read_http_response(&mut tcp_stream, OCSP_TIMEOUT.as_secs(), MAX_OCSP_RESPONSE_SIZE);
    if response.is_empty() {
        return "error: failed to read OCSP response".to_string();
    }
    let capture = crate::tls::HttpResponseCapture::parse(&response, MAX_OCSP_RESPONSE_SIZE);
    if capture.status == 0 {
        return "error: malformed OCSP HTTP response".to_string();
    }
    if capture.status != 200 {
        return format!(
            "error: OCSP responder returned non-200: {} {}",
            capture.status,
            capture.reason.as_deref().unwrap_or("")
        );
    }
    if capture.body_truncated {
        return "error: OCSP response too large (>1 MB)".to_string();
    }
    let ocsp_bytes: &[u8] = &capture.body;
    if ocsp_bytes.is_empty() {
        return "error: empty OCSP response body".to_string();
    }

    let ocsp_response = match openssl::ocsp::OcspResponse::from_der(ocsp_bytes) {
        Ok(r) => r,
        Err(e) => return format!("error: OCSP response parse failed: {e}"),
    };

    match ocsp_response.status() {
        openssl::ocsp::OcspResponseStatus::SUCCESSFUL => {}
        status => return format!("error: OCSP response status: {status:?}"),
    }

    // Parse the basic response to check cert status
    let basic = match ocsp_response.basic() {
        Ok(b) => b,
        Err(e) => return format!("error: OCSP basic response failed: {e}"),
    };

    // Verify the OCSP response signature against the issuer certificate.
    // This prevents MITM attacks from injecting forged "good" statuses.
    {
        let mut store_builder = match openssl::x509::store::X509StoreBuilder::new() {
            Ok(b) => b,
            Err(e) => return format!("error: failed to create X509 store: {e}"),
        };
        if let Err(e) = store_builder.add_cert(issuer.clone()) {
            return format!("error: failed to add issuer to store: {e}");
        }
        let store = store_builder.build();
        let mut certs = match openssl::stack::Stack::new() {
            Ok(s) => s,
            Err(e) => return format!("error: failed to create cert stack: {e}"),
        };
        if let Err(e) = certs.push(issuer.clone()) {
            return format!("error: failed to push issuer to stack: {e}");
        }
        if let Err(e) = basic.verify(&certs, &store, openssl::ocsp::OcspFlag::empty()) {
            return format!("error: OCSP response signature verification failed: {e}");
        }
        debug_log!(debug, "OCSP response signature verified");
    }

    // Re-create cert_id for status lookup
    let Ok(cert_id2) = openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), &cert, &issuer) else {
        return "error: cert ID re-creation failed".to_string();
    };

    let result = match basic.find_status(&cert_id2) {
        Some(status) => {
            // A signed but stale answer (captured before a revocation and
            // replayed) must not pass as "good": thisUpdate must not be in
            // the future and nextUpdate, when present, must not have passed.
            if let Err(e) = status.check_validity(OCSP_MAX_SKEW_SECS as u32, None) {
                return format!(
                    "error: OCSP response is stale or not yet valid (thisUpdate/nextUpdate check failed: {e})"
                );
            }
            let revoked = status.revocation_time.is_some();
            if revoked {
                "revoked".to_string()
            } else {
                "good".to_string()
            }
        }
        None => "unknown (no status in response)".to_string(),
    };

    debug_log!(debug, "OCSP status: {}", result);
    result
}

#[cfg(test)]
mod tests {
    use super::is_safe_ocsp_host;

    #[test]
    fn rejects_ipv4_loopback() {
        assert!(!is_safe_ocsp_host("127.0.0.1"));
        assert!(!is_safe_ocsp_host("127.255.255.254"));
    }

    #[test]
    fn rejects_ipv4_private() {
        assert!(!is_safe_ocsp_host("10.0.0.1"));
        assert!(!is_safe_ocsp_host("172.16.0.1"));
        assert!(!is_safe_ocsp_host("172.31.255.255"));
        assert!(!is_safe_ocsp_host("192.168.1.1"));
    }

    #[test]
    fn rejects_link_local_metadata_endpoint() {
        // The classic cloud-metadata SSRF target.
        assert!(!is_safe_ocsp_host("169.254.169.254"));
    }

    #[test]
    fn rejects_ipv6_loopback_and_link_local() {
        assert!(!is_safe_ocsp_host("::1"));
        assert!(!is_safe_ocsp_host("[::1]"));
        assert!(!is_safe_ocsp_host("fe80::1"));
        // Unique-local IPv6
        assert!(!is_safe_ocsp_host("fd00::1"));
    }

    #[test]
    fn rejects_ipv4_mapped_loopback_in_ipv6() {
        // ::ffff:127.0.0.1 — IPv6 wrapper around a loopback IPv4.
        assert!(!is_safe_ocsp_host("::ffff:127.0.0.1"));
    }

    #[test]
    fn rejects_cgnat_ietf_block_multicast_and_reserved() {
        assert!(!is_safe_ocsp_host("100.64.0.1"));
        assert!(!is_safe_ocsp_host("100.127.255.254"));
        assert!(is_safe_ocsp_host("100.128.0.1"));
        assert!(!is_safe_ocsp_host("192.0.0.8"));
        assert!(!is_safe_ocsp_host("224.0.0.1"));
        assert!(!is_safe_ocsp_host("240.0.0.1"));
        assert!(!is_safe_ocsp_host("255.255.255.255"));
        assert!(!is_safe_ocsp_host("0.0.0.0"));
        assert!(!is_safe_ocsp_host("ff02::1"));
        assert!(!is_safe_ocsp_host("::"));
    }

    #[test]
    fn rejects_ipv4_mapped_internal_ranges() {
        assert!(!is_safe_ocsp_host("::ffff:169.254.169.254"));
        assert!(!is_safe_ocsp_host("::ffff:100.64.0.1"));
        assert!(!is_safe_ocsp_host("::ffff:0.0.0.0"));
        assert!(is_safe_ocsp_host("::ffff:8.8.8.8"));
    }

    #[test]
    fn rejects_https_responder_url_without_connecting() {
        // Any https:// AIA URL is refused up front: RFC 6960 responders are
        // plain HTTP and cleartext on port 443 could only ever fail.
        let pem = include_str!("../tests/data/valid.pem");
        let der = ::pem::parse(pem).expect("pem").into_contents();
        let result = super::check_ocsp_status(&der, None, "https://127.0.0.1:1/ocsp", false);
        assert!(result.contains("unsupported scheme 'https'"), "{result}");
    }

    #[test]
    fn accepts_public_ipv4() {
        assert!(is_safe_ocsp_host("8.8.8.8"));
        assert!(is_safe_ocsp_host("1.1.1.1"));
    }

    #[test]
    fn accepts_hostnames() {
        // We cannot resolve here without DNS, so hostnames are accepted at
        // parse time. The defence relies on the IP literal check above for
        // attacker-controlled OCSP URLs that point directly at private IPs.
        assert!(is_safe_ocsp_host("ocsp.digicert.com"));
        assert!(is_safe_ocsp_host("ocsp.example.com"));
    }
}
