use openssl::hash::MessageDigest;
use openssl::x509::X509;
use std::io::Write;
use std::time::Duration;
use url::Url;

use crate::debug::debug_log;
use crate::tls::read_http_response;

/// Determine whether an OCSP responder host is safe to contact.
///
/// The OCSP URL comes from the certificate's AIA extension and is therefore
/// **attacker controlled** when we're checking a certificate from an untrusted
/// source. Without a guard, a malicious cert can specify
/// `http://169.254.169.254/...` (cloud metadata), `http://127.0.0.1:8200/...`
/// (local Vault/services), or any RFC 1918 address, turning `dcert` into an
/// SSRF probe. The ranges live in [`crate::netpolicy::is_internal_ip`].
pub fn is_safe_ocsp_host(host: &str) -> bool {
    crate::netpolicy::is_safe_host_literal(host)
}

/// Maximum accepted OCSP response size (DER plus HTTP head).
const MAX_OCSP_RESPONSE_SIZE: usize = 1024 * 1024;

/// Clock skew tolerated when checking `thisUpdate` / `nextUpdate`.
const OCSP_MAX_SKEW_SECS: u32 = 300;

/// Check OCSP revocation status for a certificate.
/// Returns "good", "revoked", "unknown", or an error description.
/// How the OCSP request reaches the responder.
#[derive(Debug, Clone, Copy)]
pub struct OcspNetwork<'a> {
    /// The run's proxy settings; an `http://` proxy that does not bypass the
    /// responder carries the request (absolute URI form).
    pub proxy: Option<&'a crate::proxy::ProxyConfig>,
    /// Connect timeout, and the bound on each read and on the whole reply
    /// (from `--timeout`).
    pub timeout: Duration,
    pub debug: bool,
}

pub fn check_ocsp_status(cert_der: &[u8], issuer_der: Option<&[u8]>, ocsp_url: &str, net: &OcspNetwork<'_>) -> String {
    let debug = net.debug;
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

    let timeout = net.timeout.max(Duration::from_secs(1));
    let via_proxy = net
        .proxy
        .filter(|p| !p.should_bypass(&host))
        .and_then(|p| p.get_proxy_url("http"));
    let (tcp_stream, request_target, proxy_auth) = match via_proxy {
        Some(proxy_url) => match connect_proxy(proxy_url, timeout) {
            Ok((stream, auth)) => {
                debug_log!(debug, "OCSP via proxy {}", crate::debug::sanitize_url(proxy_url));
                (stream, format!("http://{host}:{port}{path}"), auth)
            }
            Err(e) => return format!("unknown (could not reach the proxy for OCSP: {e})"),
        },
        None => match connect_direct(&host, port, timeout, debug) {
            Ok(stream) => (stream, path.to_string(), String::new()),
            Err(status) => return status,
        },
    };
    if let Err(e) = tcp_stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| tcp_stream.set_write_timeout(Some(timeout)))
    {
        return format!("error: failed to set OCSP socket timeouts: {e}");
    }

    let http_req = format!(
        "POST {request_target} HTTP/1.0\r\nHost: {host}\r\n{proxy_auth}Content-Type: application/ocsp-request\r\nContent-Length: {}\r\n\r\n",
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
    let response = read_http_response(&mut tcp_stream, timeout.as_secs(), MAX_OCSP_RESPONSE_SIZE);
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
            if let Err(e) = status.check_validity(OCSP_MAX_SKEW_SECS, None) {
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

/// Dial the responder directly. Every resolved address must be public
/// before any packet goes out, so a name pointing at an internal service is
/// refused without connecting (connecting first would make dcert a port
/// scan oracle). The `Err` is the status string to report.
fn connect_direct(host: &str, port: u16, timeout: Duration, debug: bool) -> Result<std::net::TcpStream, String> {
    let addrs = match crate::dns::resolve_all(host, port, timeout) {
        Ok((addrs, _dns_ms)) => addrs,
        Err(e) => return Err(format!("unknown (could not resolve OCSP responder {host}: {e})")),
    };
    if addrs.iter().any(|a| !is_safe_ocsp_host(&a.ip().to_string())) {
        return Err(
            "unknown (OCSP responder rejected: address is private, loopback or otherwise internal)".to_string(),
        );
    }
    match crate::dns::connect_first(host, port, &addrs, timeout, |a| crate::netpolicy::enforce_addr(host, a)) {
        Ok((s, _)) => {
            debug_log!(debug, "OCSP responder connected: {}:{}", host, port);
            Ok(s)
        }
        // The CA's OCSP endpoint is unreachable. This is frequently a
        // firewall blocking outbound access to the CA rather than a problem
        // with the certificate itself; say so clearly.
        Err(e) => Err(format!(
            "unknown (could not reach OCSP responder at {host}:{port}; CA endpoint unreachable, possibly firewall blocked: {e})"
        )),
    }
}

/// Dial an `http://` forward proxy for a plain HTTP OCSP request. Returns
/// the stream and the `Proxy-Authorization` header line, if any.
fn connect_proxy(proxy_url: &str, timeout: Duration) -> anyhow::Result<(std::net::TcpStream, String)> {
    let proxy = Url::parse(proxy_url)
        .map_err(|e| anyhow::anyhow!("invalid proxy URL {}: {e}", crate::debug::sanitize_url(proxy_url)))?;
    if proxy.scheme() != "http" {
        anyhow::bail!("{}", crate::proxy::HTTPS_PROXY_UNSUPPORTED);
    }
    let host = proxy
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("proxy URL must include a host"))?;
    let (stream, _, _) = crate::tls::direct_tcp_connect(host, proxy.port().unwrap_or(8080), timeout)?;
    Ok((stream, crate::proxy::proxy_authorization_header(&proxy)))
}

#[cfg(test)]
mod tests {

    #[test]
    fn ocsp_goes_through_an_http_proxy_with_an_absolute_uri() {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = stream.write_all(b"HTTP/1.0 503 Busy\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let proxy = crate::proxy::ProxyConfig::resolve(Some(&format!("http://u:p@127.0.0.1:{port}")), None)
            .expect("proxy config");
        let pki = crate::testutil::test_pki();
        let leaf = pki.rsa.cert.to_der().expect("der");
        let ca = pki.ca.cert.to_der().expect("der");
        let net = super::OcspNetwork {
            proxy: Some(&proxy),
            timeout: std::time::Duration::from_secs(2),
            debug: false,
        };
        let status = super::check_ocsp_status(&leaf, Some(&ca), "http://ocsp.test.invalid/status", &net);
        assert!(status.contains("non-200: 503"), "{status}");
        let request = rx.recv_timeout(std::time::Duration::from_secs(2)).expect("request");
        assert!(
            request.starts_with("POST http://ocsp.test.invalid:80/status HTTP/1.0\r\n"),
            "{request}"
        );
        assert!(request.contains("Proxy-Authorization: Basic "), "{request}");
        assert!(request.contains("Host: ocsp.test.invalid\r\n"), "{request}");
    }
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
        // The fixture is self signed, so it serves as its own issuer.
        let net = super::OcspNetwork {
            proxy: None,
            timeout: std::time::Duration::from_secs(1),
            debug: false,
        };
        let result = super::check_ocsp_status(&der, Some(&der), "https://127.0.0.1:1/ocsp", &net);
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
