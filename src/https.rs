use crate::args::{HttpVersion, TlsVersion};
use crate::proxy::choose_https_proxy;
use anyhow::{Context, Result};
use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConnection, SignatureScheme, StreamOwned};
use serde::Serialize;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use url::Url;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug)]
struct NoClientAuthResolver {
    was_requested: Arc<AtomicBool>,
}

impl ResolvesClientCert for NoClientAuthResolver {
    fn resolve(
        &self,
        _offered: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.was_requested.store(true, Ordering::SeqCst);
        None
    }
    fn has_certs(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
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

    // In rustls 0.23 these are not required; handshakes use the scheme list above.
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

#[derive(Debug, Serialize)]
pub struct HttpsSession {
    pub l4_ok: bool,
    pub l6_ok: bool,
    pub l7_ok: bool,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub negotiated_alpn: Option<String>,
    pub t_l4_ms: u64,
    pub t_l7_ms: u64,
    pub trusted_with_local_cas: bool,
    pub client_cert_requested: bool,
}

fn load_ca_bundle_der(ca_file: Option<&std::path::Path>) -> Result<Option<Vec<CertificateDer<'static>>>> {
    // pick explicit --ca-file or SSL_CERT_FILE; otherwise None
    let Some(path) = ca_file
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::var_os("SSL_CERT_FILE").map(Into::into))
        .map(std::path::PathBuf::from)
    else {
        return Ok(None);
    };

    let data = std::fs::read(&path)
        .with_context(|| format!("Failed to read CA file {}", path.display()))?;

    let mut cursor = std::io::Cursor::new(&data);
    let mut ders = Vec::<CertificateDer<'static>>::new();

    for item in rustls_pemfile::certs(&mut cursor) {
        if let Ok(der) = item {
            ders.push(der);
        }
    }

    if ders.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ders))
    }
}

fn do_connect(addr: &str, timeout_secs: u64) -> Result<TcpStream> {
    let addrs = addr
        .to_socket_addrs()
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

fn connect_via_proxy(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    timeout: u64,
) -> Result<TcpStream> {
    let connect_req =
        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n");
    stream.write_all(connect_req.as_bytes())?;
    stream.flush()?;
    let mut buf = [0u8; 1024];
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout)))
        .ok();
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
    stream.flush()?;

    // read a small response head to assert L7 ok
    stream
        .sock
        .set_read_timeout(Some(Duration::from_secs(timeout)))
        .ok();
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf)?; // ignore content, only care about success
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
    _export_chain: bool,
) -> Result<(HttpsSession, Vec<X509Certificate<'static>>)> {
    // Parse URL
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
    let tcp = if let Some(proxy) = choose_https_proxy(&host) {
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

    // Roots (either explicit CA file or built-ins)
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ders) = load_ca_bundle_der(ca_file)? {
        // NOTE: pass by value (not &ders) to satisfy IntoIterator<CertificateDer<'a>>
        let _ = roots.add_parsable_certificates(ders);
    } else {
        // Use built-in Mozilla root set from webpki-roots v1.0.2
        roots.roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    // Protocol versions
    use rustls::version::{TLS12, TLS13};
    let versions: &[&rustls::SupportedProtocolVersion] = match tls_version {
        TlsVersion::V13 => &[&TLS13],
        TlsVersion::V12 => &[&TLS12],
    };

    // Build TLS client config with roots, then override verifier to accept all (we still keep roots).
    let mut cfg = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(roots.clone())
        .with_no_client_auth();

    // Record if server requested client cert
    let requested = Arc::new(AtomicBool::new(false));
    cfg.client_auth_cert_resolver = Arc::new(NoClientAuthResolver {
        was_requested: requested.clone(),
    });

    // Accept-all verifier to complete handshake even for untrusted targets.
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(AcceptAllVerifier));

    // ALPN setup
    cfg.alpn_protocols = match http_version {
        HttpVersion::H2 => vec![b"h2".to_vec()],
        HttpVersion::H1_1 => vec![b"http/1.1".to_vec()],
    };

    let server_name = ServerName::try_from(host.as_str()).context("Invalid SNI")?;
    let mut conn =
        ClientConnection::new(Arc::new(cfg), server_name).context("TLS client build failed")?;
    let mut tls = StreamOwned::new(conn, tcp);

    // TLS handshake with timeout
    let l6_start = Instant::now();
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|e| anyhow::anyhow!("TLS handshake error: {e}"))?;
        if l6_start.elapsed() > Duration::from_secs(timeout_l6) {
            anyhow::bail!("TLS handshake timeout");
        }
    }

    let mut l7_ok = false;
    // Simple layer 7 probe (HTTP/1.1 request) — good enough for a reachability check.
    // Works for H1.1; many H2 servers will still accept it if they support both.
    if let Err(e) = l7_http11_request(
        &mut tls,
        method,
        &host,
        &path_query,
        headers_kv,
        timeout_l7,
    ) {
        // keep l7_ok = false
        let _ = e; // silence lint if unused
    } else {
        l7_ok = true;
    }

    // Gather negotiated info
    let tls_version_str = tls
        .conn
        .protocol_version()
        .map(|v| match v {
            rustls::ProtocolVersion::TLSv1_3 => "TLS1.3".to_string(),
            rustls::ProtocolVersion::TLSv1_2 => "TLS1.2".to_string(),
            _ => format!("{:?}", v),
        });

    let cipher_suite = tls
        .conn
        .negotiated_cipher_suite()
        .and_then(|cs| cs.suite().as_str().map(|s| s.to_string()));

    let negotiated_alpn = tls
        .conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());

    // Peer chain
    let peer_chain_der: Vec<CertificateDer<'static>> = tls
        .conn
        .peer_certificates()
        .map(|v| v.iter().cloned().collect())
        .unwrap_or_default();

    let mut x509_chain = Vec::<X509Certificate<'static>>::new();
    for der in &peer_chain_der {
        if let Ok((_, c)) = X509Certificate::from_der(der.as_ref()) {
            // Re-serialize to owned buffer for 'static certificate (safe for display)
            let der_b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
            let der_bytes = base64::engine::general_purpose::STANDARD
                .decode(der_b64.as_bytes())
                .unwrap_or_default();
            if let Ok((_, owned)) = X509Certificate::from_der(&der_bytes) {
                x509_chain.push(owned);
            }
        }
    }

    let t_l7_ms = l6_start.elapsed().as_millis();

    // We don’t run a secondary trust check, so keep this false.
    let trusted_with_local_cas = false;

    let session = HttpsSession {
        l4_ok: true,
        l6_ok: true,
        l7_ok,
        tls_version: tls_version_str,
        cipher_suite,
        negotiated_alpn,
        t_l4_ms: t_l4_ms as u64,
        t_l7_ms: t_l7_ms as u64,
        trusted_with_local_cas,
        client_cert_requested: requested.load(Ordering::SeqCst),
    };

    Ok((session, x509_chain))
}

// Make StreamOwned.sock field visible via a short Display impl if needed elsewhere.
impl fmt::Display for HttpsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "L4:{} L6:{} L7:{} TLS:{:?} ALPN:{:?}",
            self.l4_ok, self.l6_ok, self.l7_ok, self.tls_version, self.negotiated_alpn
        )
    }
}
