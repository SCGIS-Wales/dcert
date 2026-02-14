use openssl::hash::MessageDigest;
use openssl::x509::X509;
use std::io::{Read, Write};
use std::time::Duration;
use url::Url;

use crate::debug::debug_log;
use crate::tls::direct_tcp_connect;

/// Check OCSP revocation status for a certificate.
/// Returns "good", "revoked", "unknown", or an error description.
pub fn check_ocsp_status(cert_der: &[u8], issuer_der: Option<&[u8]>, ocsp_url: &str, debug: bool) -> String {
    let cert = match X509::from_der(cert_der) {
        Ok(c) => c,
        Err(e) => return format!("error: failed to parse cert: {}", e),
    };

    let issuer = match issuer_der {
        Some(der) => match X509::from_der(der) {
            Ok(c) => c,
            Err(e) => return format!("error: failed to parse issuer: {}", e),
        },
        None => return "unknown (no issuer certificate available)".to_string(),
    };

    // Build OCSP request
    let cert_id = match openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), &cert, &issuer) {
        Ok(id) => id,
        Err(e) => return format!("error: OCSP cert ID creation failed: {}", e),
    };

    let mut ocsp_req_builder = match openssl::ocsp::OcspRequest::new() {
        Ok(r) => r,
        Err(e) => return format!("error: OCSP request creation failed: {}", e),
    };

    if let Err(e) = ocsp_req_builder.add_id(cert_id) {
        return format!("error: failed to add cert ID: {}", e);
    }

    let request_bytes = match ocsp_req_builder.to_der() {
        Ok(b) => b,
        Err(e) => return format!("error: OCSP request serialization failed: {}", e),
    };

    // Send OCSP request via HTTP POST
    let url = match Url::parse(ocsp_url) {
        Ok(u) => u,
        Err(e) => return format!("error: invalid OCSP URL: {}", e),
    };

    let host = match url.host_str() {
        Some(h) => h.to_string(),
        None => return "error: OCSP URL has no host".to_string(),
    };
    let default_port = match url.scheme() {
        "https" => 443,
        _ => 80,
    };
    let port = url.port().unwrap_or(default_port);
    let path = if url.path().is_empty() { "/" } else { url.path() };

    debug_log!(debug, "OCSP check: {}:{}{}", host, port, path);

    let tcp_stream = match direct_tcp_connect(&host, port, Duration::from_secs(5)) {
        Ok((s, _dns_ms, _addr)) => {
            debug_log!(debug, "OCSP responder connected: {}:{}", host, port);
            s
        }
        Err(e) => return format!("error: connect to OCSP responder failed: {}", e),
    };
    if let Err(e) = tcp_stream.set_read_timeout(Some(Duration::from_secs(5))) {
        eprintln!("Warning: failed to set OCSP read timeout: {}", e);
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

    let mut tcp_stream = match buf_stream.into_inner() {
        Ok(s) => s,
        Err(_) => return "error: failed to flush stream".to_string(),
    };

    // Read response with a size limit to prevent OOM from malicious responders
    const MAX_OCSP_RESPONSE_SIZE: usize = 1024 * 1024; // 1 MB
    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match tcp_stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                if response.len() > MAX_OCSP_RESPONSE_SIZE {
                    return "error: OCSP response too large (>1 MB)".to_string();
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => return "error: failed to read OCSP response".to_string(),
        }
    }

    // Find end of HTTP headers
    let header_end = match response.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => pos + 4,
        None => return "error: malformed OCSP HTTP response".to_string(),
    };

    // Validate HTTP status code before parsing body
    let header_bytes = &response[..header_end];
    let status_ok = String::from_utf8_lossy(header_bytes)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|code| code == "200")
        .unwrap_or(false);
    if !status_ok {
        let status_line = String::from_utf8_lossy(header_bytes)
            .lines()
            .next()
            .unwrap_or("(empty)")
            .to_string();
        return format!("error: OCSP responder returned non-200: {}", status_line);
    }

    let ocsp_bytes = &response[header_end..];
    if ocsp_bytes.is_empty() {
        return "error: empty OCSP response body".to_string();
    }

    let ocsp_response = match openssl::ocsp::OcspResponse::from_der(ocsp_bytes) {
        Ok(r) => r,
        Err(e) => return format!("error: OCSP response parse failed: {}", e),
    };

    match ocsp_response.status() {
        openssl::ocsp::OcspResponseStatus::SUCCESSFUL => {}
        status => return format!("error: OCSP response status: {:?}", status),
    }

    // Parse the basic response to check cert status
    let basic = match ocsp_response.basic() {
        Ok(b) => b,
        Err(e) => return format!("error: OCSP basic response failed: {}", e),
    };

    // Re-create cert_id for status lookup
    let cert_id2 = match openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), &cert, &issuer) {
        Ok(id) => id,
        Err(_) => return "error: cert ID re-creation failed".to_string(),
    };

    let result = match basic.find_status(&cert_id2) {
        Some(status) => {
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
