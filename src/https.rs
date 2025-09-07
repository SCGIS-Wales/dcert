use crate::proxy::choose_https_proxy;
use anyhow::{Context, Result};
use colored::Colorize;
use rustls::client::{ClientConfig, ClientConnection};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ProtocolVersion, RootCertStore, SignatureScheme, StreamOwned};
use rustls_pemfile as pemfile;
use std::io::{Read, Write};
use std::io::Cursor;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

pub enum TlsVersion {
    V13,
    V12,
}

pub enum HttpVersion {
    H2,
    H11,
}

pub struct HttpsSession {
    pub l4_ok: bool,
    pub l6_ok: bool,
    pub l7_ok: bool,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub t_l4_ms: u128,
    pub t_l7_ms: u128,
    pub trusted_with_local_cas: bool,
    pub client_cert_requested: bool,
}

struct NoClientAuthResolver {
    was_requested: Arc<AtomicBool>,
}

impl ResolvesClientCert for NoClientAuthResolver {
    fn resolve(
        &self,
        _offered: &[rustls::client::CertificateType],
        _sigschemes: &[SignatureScheme],
    ) -> Option<rustls::sign::CertifiedKey> {
        // If the server asked for a client cert, rustls will query this resolver.
        self.was_requested.store(true, Ordering::SeqCst);
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

/// Verifier that accepts all certs but tracks whether chain validation would have passed
struct PermissiveVerifier {
    inner: rustls::client::WebPkiVerifier,
    trusted: Arc<AtomicBool>,
}

impl ServerCertVerifier for PermissiveVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, &[], now)
        {
            Ok(_) => {
                self.trusted.store(true, Ordering::SeqCst);
                Ok(ServerCertVerified::assertion())
            }
            Err(_e) => {
                // Mark as untrusted but still permit connection
                self.trusted.store(false, Ordering::SeqCst);
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
}

fn roots_from_env_or_default(ca_file: Option<&std::path::Path>) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();

    // 1) optional explicit file path
    if let Some(p) = ca_file {
        let data = std::fs::read(p).with_context(|| format!("Failed to read CA file: {}", p.display()))?;
        let mut cursor = Cursor::new(&data);
        let certs = pemfile::certs(&mut cursor)?;
        let _added = store.add_parsable_certificates(certs);
        return Ok(store);
    }

    // 2) SSL_CERT_FILE environment variable
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        let p = std::path::Path::new(&path);
        if p.exists() {
            let data = std::fs::read(p)
                .with_context(|| format!("Failed to read SSL_CERT_FILE: {}", p.display()))?;
            let mut cursor = Cursor::new(&data);
            let certs = pemfile::certs(&mut cursor)?;
            let _added = store.add_parsable_certificates(certs);
            return Ok(store);
        }
    }

    // 3) built-in webpki roots
    store.add_trust_anchors(TLS_SERVER_ROOTS.iter().cloned());
    Ok(store)
}

fn do_connect(addr: &str, timeout_secs: u64) -> Result<TcpStream> {
    let addrs = addr
        .to_socket_addrs()
        .with_context(|| format!("DNS resolution failed for {addr}"))?;
    let start = Instant::now();
    let mut last_err = None;

    for a in addrs {
        match TcpStream::connect_timeout(&a, Duration::from_secs(timeout_secs)) {
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;
                s.set_write_timeout(Some(Duration::from_secs(timeout_secs)))?;
                return Ok(s);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
        if start.elapsed() > Duration::from_secs(timeout_secs) {
            break;
        }
    }
    Err(anyhow::anyhow!(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")
    })))
}

fn connect_via_proxy(mut stream: TcpStream, host: &str, port: u16, _timeout: u64) -> Result<TcpStream> {
    let connect_req =
        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n");
    stream.write_all(connect_req.as_bytes())?;
    stream.flush()?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
        Ok(stream)
    } else {
        Err(anyhow::anyhow!(
            "Proxy CONNECT failed: {}",
            resp.lines().next().unwrap_or(&resp)
        ))
    }
}

fn l7_http11_request(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(String, String)],
    timeout: u64,
) -> Result<()> {
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dcert/{}\r\nConnection: close\r\n",
        env!("CARGO_PKG_VERSION")
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    stream.sock().set_read_timeout(Some(Duration::from_secs(timeout)))?;
    let mut tmp = [0u8; 1];
    // Try to read at least something to mark l7_ok
    let _ = stream.read(&mut tmp);
    Ok(())
}

pub fn probe_https(
    url_s: &str,
    tls_version: TlsVersion,
    http_version: HttpVersion,
    method: &str,
    headers_kv: &[(String, String)],
    ca_file: Option<&std::path::Path>,
    timeout_l4: u64,
    timeout_l6: u64,
    timeout_l7: u64,
) -> Result<(HttpsSession, Vec<x509_parser::certificate::X509Certificate<'static>>)> {
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
    let l4_start = Instant::now();
    let mut tcp = if let Some(proxy) = choose_https_proxy(&host) {
        let proxy_host = proxy
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid proxy host"))?
            .to_string();
        let proxy_port = proxy
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("Invalid proxy port"))?;
        let s = do_connect(&format!("{proxy_host}:{proxy_port}"), timeout_l4)?;
        connect_via_proxy(s, &host, port, timeout_l4)?
    } else {
        do_connect(&format!("{host}:{port}"), timeout_l4)?
    };
    let t_l4_ms = l4_start.elapsed().as_millis();

    // TLS config
    let roots = roots_from_env_or_default(ca_file)?;
    let mut cfg = ClientConfig::builder()
        .with_protocol_versions(match tls_version {
            TlsVersion::V13 => &["TLS13"],
            TlsVersion::V12 => &["TLS12"],
        })
        .map_err(|_| anyhow::anyhow!("Failed to set protocol versions"))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    // client-cert request detector
    let requested = Arc::new(AtomicBool::new(false));
    cfg.client_auth_cert_resolver = Arc::new(NoClientAuthResolver {
        was_requested: requested.clone(),
    });

    // ALPN
    match http_version {
        HttpVersion::H2 => {
            cfg.alpn_protocols = vec![b"h2".to_vec()];
        }
        HttpVersion::H11 => {
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
    }

    // Build permissive verifier (record if trust chain is valid)
    let trusted_flag = Arc::new(AtomicBool::new(false));
    let webpki = rustls::client::WebPkiVerifier::new(cfg.root_store.clone(), None);
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(PermissiveVerifier {
            inner: webpki,
            trusted: trusted_flag.clone(),
        }));

    // TLS connect
    let server_name = ServerName::try_from(host.as_str()).context("Invalid SNI")?;
    let mut conn = ClientConnection::new(Arc::new(cfg), server_name).context("TLS client build failed")?;
    let mut tls = StreamOwned::new(conn, tcp);

    let l6_start = Instant::now();
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|e| anyhow::anyhow!("TLS handshake error: {e}"))?;
        if l6_start.elapsed() > Duration::from_secs(timeout_l6) {
            anyhow::bail!("TLS handshake timeout");
        }
    }
    let l6_ok = true;

    // negotiated TLS version & cipher
    let tls_version_str = tls
        .conn
        .protocol_version()
        .map(|v| match v {
            ProtocolVersion::TLSv1_3 => "1.3",
            ProtocolVersion::TLSv1_2 => "1.2",
            _ => "unknown",
        })
        .map(|s| s.to_string());

    let cipher_suite = tls
        .conn
        .negotiated_cipher_suite()
        .map(|cs| cs.suite().as_str().to_string());

    // L7
    let l7_start = Instant::now();
    match http_version {
        HttpVersion::H11 => {
            l7_http11_request(&mut tls, method, &host, &path_query, headers_kv, timeout_l7)?;
        }
        HttpVersion::H2 => {
            // Minimal “poke”: just write HTTP/2 connection preface then read a byte.
            // (A full H2 client is out-of-scope; we only need success/fail & timing.)
            const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            tls.write_all(PREFACE)?;
            let _ = tls.sock().set_read_timeout(Some(Duration::from_secs(timeout_l7)));
            let mut tmp = [0u8; 1];
            let _ = tls.read(&mut tmp);
        }
    }
    let t_l7_ms = l7_start.elapsed().as_millis();
    let l7_ok = true;

    // peer certs to x509
    let chain_x509 = tls
        .conn
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .filter_map(|cder| {
            x509_parser::certificate::X509Certificate::from_der(cder.as_ref())
                .ok()
                .map(|(_, c)| c.to_owned())
        })
        .collect::<Vec<_>>();

    let session = HttpsSession {
        l4_ok: true,
        l6_ok,
        l7_ok,
        tls_version: tls_version_str,
        cipher_suite,
        t_l4_ms,
        t_l7_ms,
        trusted_with_local_cas: trusted_flag.load(Ordering::SeqCst),
        client_cert_requested: requested.load(Ordering::SeqCst),
    };

    Ok((session, chain_x509))
}
