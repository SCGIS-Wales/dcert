use crate::args::{HttpVersion, TlsVersion};
use crate::proxy::choose_https_proxy;
use anyhow::{Context, Result};
use base64::Engine;
use colored::Colorize;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConnection, SignatureScheme, StreamOwned};
use serde::Serialize;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;
use x509_parser::prelude::FromDer;

#[derive(Debug)]
struct NoClientAuthResolver;

impl std::fmt::Display for NoClientAuthResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoClientAuthResolver")
    }
}

impl ResolvesClientCert for NoClientAuthResolver {
    fn resolve(
        &self,
        _offered: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<rustls::sign::CertifiedKey> {
        None
    }
}

#[derive(Debug)]
struct AcceptAllVerifier;

impl std::fmt::Display for AcceptAllVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AcceptAllVerifier")
    }
}

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // We accept anything here; real trust checking is out of scope for the probe.
        Ok(ServerCertVerified::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct HttpsSession {
    pub l4_ok: bool,
    pub l6_ok: bool,
    pub l7_ok: bool,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub negotiated_alpn: Option<String>,
    pub t_l4_ms: u128,
    pub t_l7_ms: u128,
    pub trusted_with_local_cas: bool,
    pub client_cert_requested: bool,
}

/// Read CA bundle DERs from --ca-file or SSL_CERT_FILE. Returns None if neither is present.
fn load_ca_bundle_der(
    ca_file: Option<&std::path::Path>,
) -> Result<Option<Vec<CertificateDer<'static>>>> {
    let Some(path) = ca_file
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::var_os("SSL_CERT_FILE").map(Into::into))
    else {
        return Ok(None);
    };

    let data = std::fs::read(&path)
        .with_context(|| format!("Failed to read CA file {}", path.display()))?;
    let mut cursor = std::io::Cursor::new(&data);
    let mut ders = Vec::<CertificateDer<'static>>::new();
    for item in rustls_pemfile::certs(&mut cursor) {
        ders.push(item?);
    }
    Ok(Some(ders))
}

fn connect_direct(host: &str, port: u16, timeout: u64) -> Result<TcpStream> {
    let addrs = (host, port).to_socket_addrs().context("DNS resolution failed")?;
    let mut last_err: Option<std::io::Error> = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout)) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(anyhow::anyhow!(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")
    })))
}

fn connect_via_proxy(mut stream: TcpStream, host: &str, port: u16, _timeout: u64) -> Result<TcpStream> {
    // Basic HTTP CONNECT
    let req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");
    if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
        anyhow::bail!("Proxy CONNECT failed: {resp}");
    }
    Ok(stream)
}

/// Build ALPN list based on requested HTTP version.
fn alpn_for(http_version: HttpVersion) -> Vec<Vec<u8>> {
    match http_version {
        HttpVersion::H2 => vec![b"h2".to_vec()],
        HttpVersion::H1_1 => vec![b"http/1.1".to_vec()],
        // This TLS/TCP probe doesn't do QUIC; send no ALPN for H3 (placeholder).
        HttpVersion::H3 => Vec::new(),
    }
}

/// Perform a minimal HTTP/1.1 request to mark L7 reachability.
fn l7_http11_request(
    tls: &mut StreamOwned<ClientConnection, TcpStream>,
    method: &str,
    host: &str,
    path_query: &str,
    headers_kv: &[(String, String)],
    timeout: u64,
) -> Result<()> {
    let req_line = format!("{method} {path_query} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    tls.write_all(req_line.as_bytes())?;
    for (k, v) in headers_kv {
        if !k.is_empty() {
            tls.write_all(format!("{k}: {v}\r\n").as_bytes())?;
        }
    }
    tls.write_all(b"\r\n")?;
    tls.flush()?;

    // Read a little bit to ensure server responded
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut buf = [0u8; 1024];
    loop {
        if Instant::now() > deadline {
            anyhow::bail!("L7 read timeout");
        }
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => break,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn probe_https(
    url_s: &str,
    tls_version: TlsVersion,
    http_version: HttpVersion,
    method: &str,
    headers_kv: &[(String, String)],
    timeout_l4: u64,
    timeout_l6: u64,
    timeout_l7: u64,
    ca_file: Option<&std::path::Path>,
    _export_chain: bool,
) -> Result<(HttpsSession, Vec<x509_parser::prelude::X509Certificate<'static>>)> {
    let url = Url::parse(url_s).context("Invalid URL")?;
    if url.scheme() != "https" {
        anyhow::bail!("Only https:// is supported for probing");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Host missing in URL"))?
        .to_string();
    let port = url.port().unwrap_or(443);
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let path_query = if let Some(q) = url.query() {
        format!("{path}?{q}")
    } else {
        path.to_string()
    };

    // L4 connect (direct or proxy)
    let t0 = Instant::now();
    let tcp = if let Some(proxy) = choose_https_proxy(&host) {
        let proxy_addr = proxy
            .to_socket_addrs()
            .context("Proxy DNS resolution failed")?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Proxy resolved to no addresses"))?;
        let stream = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(timeout_l4))
            .context("TCP connect to proxy failed")?;
        connect_via_proxy(stream, &host, port, timeout_l4)?
    } else {
        connect_direct(&host, port, timeout_l4)?
    };
    let t_l4_ms = t0.elapsed().as_millis();

    // TLS config
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ders) = load_ca_bundle_der(ca_file)? {
        let _ = roots.add_parsable_certificates(ders);
    } else {
        roots
            .roots
            .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let versions = match tls_version {
        TlsVersion::Tls12 => &[&rustls::version::TLS12][..],
        TlsVersion::Tls13 => &[&rustls::version::TLS13][..],
        TlsVersion::Auto => &[&rustls::version::TLS13, &rustls::version::TLS12][..],
    };

    let verifier = Arc::new(AcceptAllVerifier);
    let mut cfg = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    cfg.alpn_protocols = alpn_for(http_version);

    let server_name =
        ServerName::try_from(host.as_str()).context("Invalid SNI")?;
    let mut conn = ClientConnection::new(Arc::new(cfg), server_name).context("TLS client build failed")?;
    conn.set_buffer_limit(Some(64 * 1024));

    let mut tls = StreamOwned::new(conn, tcp);
    tls.sock()
        .set_read_timeout(Some(Duration::from_secs(timeout_l6)))?;
    tls.sock()
        .set_write_timeout(Some(Duration::from_secs(timeout_l6)))?;

    // TLS handshake (L6)
    let t1 = Instant::now();
    tls.conn.complete_io(&mut tls.sock())?; // drive handshake
    let t_l6_ms = t1.elapsed().as_millis();

    // L7 probe
    let t2 = Instant::now();
    let l7_ok = l7_http11_request(&mut tls, method, &host, &path_query, headers_kv, timeout_l7).is_ok();
    let t_l7_ms = t2.elapsed().as_millis();

    // Negotiated info
    let tls_version = tls.conn.protocol_version().map(|v| match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLS1.3".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS1.2".to_string(),
        other => format!("{other:?}"),
    });

    let cipher_suite = tls
        .conn
        .negotiated_cipher_suite()
        .map(|cs| cs.suite().as_str().unwrap_or("unknown").to_string());

    let negotiated_alpn = tls.conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).to_string());

    // Gather peer certificates (DER) and decode to X509 for the caller
    let peer_certs: Vec<CertificateDer<'static>> = tls
        .conn
        .peer_certificates()
        .unwrap_or(&[])
        .iter()
        .cloned()
        .collect();

    let mut chain = Vec::new();
    for der in &peer_certs {
        if let Ok((_, c)) = x509_parser::certificate::X509Certificate::from_der(der.as_ref()) {
            chain.push(c.to_owned());
        }
    }

    // Placeholder trust signal (set to false; add real validation if desired)
    let trusted_with_local_cas = false;

    let session = HttpsSession {
        l4_ok: true,
        l6_ok: true,
        l7_ok,
        tls_version,
        cipher_suite,
        negotiated_alpn,
        t_l4_ms,
        t_l7_ms,
        trusted_with_local_cas,
        client_cert_requested: false,
    };

    Ok((session, chain))
}
