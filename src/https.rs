use crate::args::{HttpVersion, TlsVersion};
use crate::proxy::choose_https_proxy;
use anyhow::{Context, Result};
use colored::Colorize;
use rustls::{ClientConfig, RootCertStore, ClientConnection, StreamOwned, ProtocolVersion};
use rustls::client::{ServerName, ResolvesClientCert, ServerCertVerifier, HandshakeSignatureValid};
use rustls::SignatureScheme;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::{FromDer, X509Certificate};

struct NoClientAuthResolver {
    was_requested: Arc<AtomicBool>,
}
impl ResolvesClientCert for NoClientAuthResolver {
    fn resolve(&self, _offered: &[rustls::client::ClientCertType], _sigschemes: &[SignatureScheme]) -> Option<rustls::sign::CertifiedKey> {
        self.was_requested.store(true, Ordering::SeqCst);
        None
    }
    fn has_certs(&self) -> bool { false }
}

struct PermissiveVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    trusted: Arc<AtomicBool>,
}
impl ServerCertVerifier for PermissiveVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item=&[u8]>,
        ocsp: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(end_entity, intermediates, server_name, scts, ocsp, now) {
            Ok(v) => {
                self.trusted.store(true, Ordering::SeqCst);
                Ok(v)
            }
            Err(_e) => {
                self.trusted.store(false, Ordering::SeqCst);
                Ok(rustls::client::ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &rustls::DigitallySignedStruct
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &rustls::DigitallySignedStruct
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
}

fn load_roots(ca_file: Option<&std::path::Path>) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    if let Some(fp) = ca_file {
        let data = std::fs::read(fp).with_context(|| format!("Failed to read CA file {}", fp.display()))?;
        let mut added = 0usize;
        for block in pem::parse_many(&data)? {
            if block.tag == "CERTIFICATE" {
                store.add(&rustls::Certificate(block.contents)).ok();
                added += 1;
            }
        }
        if added == 0 {
            anyhow::bail!("No certificates found in {}", fp.display());
        }
        return Ok(store);
    }
    if let Ok(env_path) = std::env::var("SSL_CERT_FILE") {
        let p = std::path::Path::new(&env_path);
        if p.exists() {
            return load_roots(Some(p));
        }
    }
    store.add_trust_anchors(TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject, ta.spki, ta.name_constraints
        )
    }));
    Ok(store)
}

fn do_connect(addr: &str, timeout_secs: u64) -> Result<TcpStream> {
    let addrs = addr.to_socket_addrs()
        .with_context(|| format!("DNS resolution failed for {addr}"))?;
    let start = Instant::now();
    let mut last_err = None;
    for sa in addrs {
        match TcpStream::connect_timeout(&sa, Duration::from_secs(timeout_secs)) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(Duration::from_secs(timeout_secs)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(timeout_secs)));
                return Ok(s);
            }
            Err(e) => { last_err = Some(e); }
        }
        if start.elapsed() > Duration::from_secs(timeout_secs) {
            break;
        }
    }
    Err(anyhow::anyhow!(last_err.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))))
}

fn connect_via_proxy(mut stream: TcpStream, host: &str, port: u16, timeout: u64) -> Result<TcpStream> {
    let connect_req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream.write_all(connect_req.as_bytes())?;
    stream.flush()?;
    let mut buf = [0u8; 1024];
    stream.set_read_timeout(Some(Duration::from_secs(timeout)))?;
    let n = stream.read(&mut buf)?;
    let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");
    if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
        Ok(stream)
    } else {
        Err(anyhow::anyhow!("Proxy CONNECT failed: {}", resp.lines().next().unwrap_or(resp)))
    }
}

fn l7_http11_request(stream: &mut StreamOwned<ClientConnection, TcpStream>, method: &str, host: &str, path: &str, headers: &[(String,String)], timeout: u64) -> Result<()> {
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dcert/{}\r\nConnection: close\r\n", env!("CARGO_PKG_VERSION"));
    for (k,v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut buf = [0u8; 1024];
    stream.get_ref().set_read_timeout(Some(Duration::from_secs(timeout)))?;
    let _ = stream.read(&mut buf)?;
    Ok(())
}

#[derive(Debug, serde::Serialize)]
pub struct HttpsSession {
    pub l4_ok: bool,
    pub l6_ok: bool,
    pub l7_ok: bool,
    pub tls_version: Option<String>,
    pub tls_cipher_suite: Option<String>,
    pub t_l4_ms: u128,
    pub t_l7_ms: u128,
    pub trusted_with_local_cas: bool,
    pub client_cert_requested: bool,
    pub negotiated_alpn: Option<String>,
}

pub fn probe_https(
    url_str: &str,
    tls_version: TlsVersion,
    http_version: HttpVersion,
    method: &str,
    headers_kv: &[(String,String)],
    ca_file: Option<&std::path::Path>,
    timeout_l4: u64,
    timeout_l6: u64,
    timeout_l7: u64,
    export_chain: bool,
) -> Result<(HttpsSession, Vec<X509Certificate<'static>>)> {
    let url = Url::parse(url_str).context("Invalid URL")?;
    if url.scheme() != "https" {
        anyhow::bail!("Only https:// is supported for probing");
    }
    let host = url.host_str().ok_or_else(|| anyhow::anyhow!("Host missing in URL"))?.to_string();
    let port = url.port().unwrap_or(443);
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let path_query = if let Some(q) = url.query() {
        format!("{path}?{q}")
    } else {
        path.to_string()
    };

    // L4 connect (direct or proxy)
    let l4_start = Instant::now();
    let mut tcp = if let Some(proxy) = choose_https_proxy(&host) {
        let proxy_host = proxy.host_str().ok_or_else(|| anyhow::anyhow!("Invalid proxy host"))?.to_string();
        let proxy_port = proxy.port_or_known_default().ok_or_else(|| anyhow::anyhow!("Invalid proxy port"))?;
        let s = do_connect(&format!("{proxy_host}:{proxy_port}"), timeout_l4)?;
        let s = connect_via_proxy(s, &host, port, timeout_l4)?;
        s
    } else {
        do_connect(&format!("{host}:{port}"), timeout_l4)?
    };
    let t_l4 = l4_start.elapsed().as_millis();

    if matches!(http_version, HttpVersion::H3) {
        eprintln!("{}", "HTTP/3 requested but not enabled in this build".yellow());
    }

    let roots = load_roots(ca_file)?;
    let mut cfg = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(match tls_version {
            TlsVersion::V13 => &["TLS13"],
            TlsVersion::V12 => &["TLS12"],
        }).map_err(|_| anyhow::anyhow!("Failed to set protocol versions"))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    // record if client cert requested
    let requested = Arc::new(AtomicBool::new(false));
    cfg.client_auth_cert_resolver = Arc::new(NoClientAuthResolver { was_requested: requested.clone() });

    // ALPN
    match http_version {
        HttpVersion::H2 => cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        HttpVersion::H1_1 => cfg.alpn_protocols = vec![b"http/1.1".to_vec()],
        HttpVersion::H3 => { /* negotiated later if enabled */ }
    }

    // trust, even if invalid
    let trusted_flag = Arc::new(AtomicBool::new(false));
    let webpki = rustls::client::WebPkiVerifier::new(cfg.root_store.clone(), None);
    cfg.dangerous().set_certificate_verifier(Arc::new(PermissiveVerifier { inner: webpki, trusted: trusted_flag.clone() }));

    let server_name = ServerName::try_from(host.as_str()).context("Invalid SNI")?;
    let mut conn = ClientConnection::new(Arc::new(cfg), server_name).context("TLS client build failed")?;
    let mut tls = StreamOwned::new(conn, tcp);

    let l6_start = Instant::now();
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).map_err(|e| anyhow::anyhow!("TLS handshake error: {e}"))?;
        if l6_start.elapsed() > Duration::from_secs(timeout_l6) {
            anyhow::bail!("TLS handshake timeout");
        }
    }
    let l6_ok = true;

    let tls_vers = tls.conn.protocol_version().map(|v| match v {
        ProtocolVersion::TLSv1_3 => "1.3".to_string(),
        ProtocolVersion::TLSv1_2 => "1.2".to_string(),
        other => format!("{other:?}"),
    });
    let cipher = tls.conn.negotiated_cipher_suite().map(|cs| format!("{:?}", cs.suite()));
    let alpn = tls.conn.alpn_protocol().map(|v| String::from_utf8_lossy(v).to_string());
    let client_cert_requested = requested.load(Ordering::SeqCst);
    let trusted = trusted_flag.load(Ordering::SeqCst);

    // Collect chain
    let mut chain_der: Vec<Vec<u8>> = Vec::new();
    if let Some(certs) = tls.conn.peer_certificates() {
        for c in certs {
            chain_der.push(c.0.clone());
        }
    }

    // Export chain if requested
    if export_chain && !chain_der.is_empty() {
        let fname = format!("{}-base64-pem.txt", host.replace('.', ""));
        let mut out = String::new();
        for der in &chain_der {
            out.push_str("-----BEGIN CERTIFICATE-----\n");
            out.push_str(&base64::engine::general_purpose::STANDARD.encode(der));
            out.push_str("\n-----END CERTIFICATE-----\n");
        }
        std::fs::write(&fname, out).with_context(|| format!("Failed to write {fname}"))?;
        eprintln!("{}", format!("Exported chain to {fname}").green());
    }

    // L7 check over the same stream using HTTP/1.1
    let l7_start = Instant::now();
    let l7_ok = l7_http11_request(&mut tls, method, &host, &path_query, headers_kv, timeout_l7).is_ok();
    let t_l7 = l7_start.elapsed().as_millis();

    // Parse chain for reporting
    let mut xcs: Vec<X509Certificate<'static>> = Vec::new();
    for der in chain_der {
        if let Ok((_, cert)) = X509Certificate::from_der(&der) {
            xcs.push(cert);
        }
    }

    let session = HttpsSession {
        l4_ok: true,
        l6_ok,
        l7_ok,
        tls_version: tls_vers,
        tls_cipher_suite: cipher,
        t_l4_ms: t_l4,
        t_l7_ms: t_l7,
        trusted_with_local_cas: trusted,
        client_cert_requested,
        negotiated_alpn: alpn,
    };
    Ok((session, xcs))
}
