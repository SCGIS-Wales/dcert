use crate::args::{HttpVersion, TlsVersion};
use crate::proxy::choose_https_proxy;
use anyhow::{Context, Result};
use base64::Engine;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, RootCertStore, SignatureScheme, StreamOwned};
use serde::Serialize;
use std::fmt::Debug;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

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
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
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

fn load_root_store(ca_file: Option<&std::path::Path>) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();

    // 1) Explicit --ca-file has highest precedence
    if let Some(path) = ca_file {
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read CA file {}", path.display()))?;
        let mut cursor = std::io::Cursor::new(&data);
        let mut v = Vec::<CertificateDer<'static>>::new();
        for item in rustls_pemfile::certs(&mut cursor) {
            v.push(item?);
        }
        let _ = store.add_parsable_certificates(v.into_iter());
        return Ok(store);
    }

    // 2) SSL_CERT_FILE environment variable
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        let p = std::path::Path::new(&path);
        if p.exists() {
            let data = std::fs::read(p)
                .with_context(|| format!("Failed to read SSL_CERT_FILE {}", p.display()))?;
            let mut cursor = std::io::Cursor::new(&data);
            let mut v = Vec::<CertificateDer<'static>>::new();
            for item in rustls_pemfile::certs(&mut cursor) {
                v.push(item?);
            }
            let _ = store.add_parsable_certificates(v.into_iter());
            return Ok(store);
        }
    }

    // 3) Fallback: bundled Mozilla roots from webpki-roots
    let _ = store.add_parsable_certificates(TLS_SERVER_ROOTS.iter().cloned());
    Ok(store)
}

fn do_connect(addr: &str, timeout_secs: u64) -> Result<TcpStream> {
    let addrs = addr
        .to_socket_addrs()
        .with_context(|| format!("DNS resolution failed for {addr}"))?;
    let start = Instant::now();
    let mut last_err: Option<std::io::Error> = None;

    for sockaddr in addrs {
        match TcpStream::connect_timeout(&sockaddr, Duration::from_secs(timeout_secs)) {
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

fn connect_via_proxy(mut stream: TcpStream, host: &str, port: u16, timeout: u64) -> Result<TcpStream> {
    let connect_req =
        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n");
    stream.write_all(connect_req.as_bytes())?;
    stream.flush()?;
    let mut buf = [0u8; 1024];
    let start = Instant::now();
    let mut total = 0usize;
    loop {
        let n = stream.read(&mut buf[total..])?;
        total += n;
        if total >= 12 {
            let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
            if s.starts_with("HTTP/1.1 200") || s.starts_with("HTTP/1.0 200") {
                return Ok(stream);
            }
            if s.starts_with("HTTP/1.1 ") || s.starts_with("HTTP/1.0 ") {
                let first = s.lines().next().unwrap_or(s);
                return Err(anyhow::anyhow!("Proxy CONNECT failed: {first}"));
            }
        }
        if start.elapsed() > Duration::from_secs(timeout) {
            return Err(anyhow::anyhow!("Proxy CONNECT timeout"));
        }
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

    // Read a tiny bit to be sure L7 is reachable
    let start = Instant::now();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Err(anyhow::anyhow!("EOF before HTTP response")),
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        if start.elapsed() > Duration::from_secs(timeout) {
            return Err(anyhow::anyhow!("HTTP read timeout"));
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct HttpsSession {
    pub l4_ok: bool,
    pub l6_ok: bool,
    pub l7_ok: bool,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn: Option<String>,
    pub t_l4_ms: u128,
    pub t_l7_ms: u128,
    pub trusted_with_local_cas: bool,
    pub client_cert_requested: bool,
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
    export_chain: bool,
) -> Result<(HttpsSession, Vec<CertificateDer<'static>>)> {
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
        let s = connect_via_proxy(s, &host, port, timeout_l4)?;
        s
    } else {
        do_connect(&format!("{host}:{port}"), timeout_l4)?
    };
    let t_l4_ms = l4_start.elapsed().as_millis();

    // TLS config
    let mut roots = load_root_store(ca_file)?;
    // Accept all during the handshake so we can still collect chain even if invalid
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(AcceptAllVerifier);

    use rustls::versions::{TLS12, TLS13};
    let versions = match tls_version {
        TlsVersion::V13 => &[&TLS13[..]][..],
        TlsVersion::V12 => &[&TLS12[..]][..],
    };

    let mut cfg = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_root_certificates(roots.clone()) // still set roots for ALPN selection etc.
        .with_no_client_auth();

    // Detect if server requests client certificate
    let requested = Arc::new(AtomicBool::new(false));
    cfg.client_auth_cert_resolver = Arc::new(NoClientAuthResolver {
        was_requested: requested.clone(),
    });

    // ALPN
    cfg.alpn_protocols = match http_version {
        HttpVersion::H1_1 => vec![b"http/1.1".to_vec()],
        HttpVersion::H2 => vec![b"h2".to_vec()],
        HttpVersion::H3 => vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()],
    };

    let server_name = ServerName::try_from(host.as_str()).context("Invalid SNI")?;
    let mut conn = ClientConnection::new(Arc::new(cfg), server_name).context("TLS client build failed")?;
    let mut tls = StreamOwned::new(conn, tcp);

    // L6 handshake
    let l6_start = Instant::now();
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|e| anyhow::anyhow!("TLS handshake error: {e}"))?;
        if l6_start.elapsed() > Duration::from_secs(timeout_l6) {
            anyhow::bail!("TLS handshake timeout");
        }
    }

    // Collect negotiated parameters
    let tls_version_str = tls
        .conn
        .protocol_version()
        .map(|v| match v.version {
            rustls::ProtocolVersion::TLSv1_3 => "1.3".to_string(),
            rustls::ProtocolVersion::TLSv1_2 => "1.2".to_string(),
            _ => format!("{:?}", v.version),
        });

    let cipher_suite = tls
        .conn
        .negotiated_cipher_suite()
        .and_then(|cs| cs.suite().as_str().map(|s| s.to_string()));

    let alpn = tls
        .conn
        .alpn_protocol()
        .map(|b| String::from_utf8_lossy(b).to_string());

    // L7 (only perform an HTTP/1.1 request when HTTP/1.1 is selected)
    let l7_start = Instant::now();
    let mut l7_ok = false;
    if http_version == HttpVersion::H1_1 {
        if let Err(e) = l7_http11_request(&mut tls, method, &host, &path_query, headers_kv, timeout_l7) {
            // We still proceed; certs are available already
            eprintln!("Note: HTTP/1.1 request failed: {e}");
        } else {
            l7_ok = true;
        }
    } else {
        // For H2/H3 we consider Layer 7 reachable after handshake (ALPN negotiated)
        l7_ok = true;
    }
    let t_l7_ms = l7_start.elapsed().as_millis();

    // Peer chain
    let chain: Vec<CertificateDer<'static>> = tls
        .conn
        .peer_certificates()
        .map(|v| v.iter().cloned().collect())
        .unwrap_or_default();

    // Optional export
    if export_chain {
        if let Some(host_only) = url.host_str() {
            let fname = format!("{}-base64-pem.txt", host_only.replace('.', ""));
            let mut out = String::new();
            for der in &chain {
                let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
                out.push_str("-----BEGIN CERTIFICATE-----\n");
                for chunk in b64.as_bytes().chunks(64) {
                    out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
                    out.push('\n');
                }
                out.push_str("-----END CERTIFICATE-----\n");
            }
            std::fs::write(&fname, out)?;
        }
    }

    // Separate trust verification (using webpki) against our chosen roots
    let trusted_with_local_cas = verify_chain_with_roots(&host, &chain, &roots);

    let session = HttpsSession {
        l4_ok: true,
        l6_ok: true,
        l7_ok,
        tls_version: tls_version_str,
        cipher_suite,
        alpn,
        t_l4_ms,
        t_l7_ms,
        trusted_with_local_cas,
        client_cert_requested: requested.load(Ordering::SeqCst),
    };

    Ok((session, chain))
}

/// Validate the server chain using rustls-webpki + the given RootCertStore.
fn verify_chain_with_roots(host: &str, chain: &[CertificateDer<'_>], roots: &RootCertStore) -> bool {
    use rustls_webpki::{EndEntityCert, Time, TlsServerTrustAnchors};
    // Convert roots into TrustAnchors expected by webpki.
    let anchors_vec: Vec<rustls_webpki::TrustAnchor<'_>> = roots
        .roots
        .iter()
        .filter_map(|ta| rustls_webpki::TrustAnchor::try_from_cert_der(ta.der().as_ref()).ok())
        .collect();

    if chain.is_empty() || anchors_vec.is_empty() {
        return false;
    }

    let end_entity = match EndEntityCert::try_from(chain[0].as_ref()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let intermediates: Vec<&[u8]> = chain.iter().skip(1).map(|c| c.as_ref()).collect();
    let now = Time::try_from(std::time::SystemTime::now()).unwrap_or(Time::from_seconds_since_unix_epoch(0));

    // Supported signature algorithms list (webpki expects this)
    let supported = [
        &rustls_webpki::ECDSA_P256_SHA256,
        &rustls_webpki::ECDSA_P384_SHA384,
        &rustls_webpki::ED25519,
        &rustls_webpki::RSA_PKCS1_2048_8192_SHA256,
        &rustls_webpki::RSA_PKCS1_2048_8192_SHA384,
        &rustls_webpki::RSA_PKCS1_2048_8192_SHA512,
        &rustls_webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        &rustls_webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        &rustls_webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    ];

    let dns_name = match rustls_webpki::DnsNameRef::try_from_ascii_str(host) {
        Ok(d) => d,
        Err(_) => return false,
    };

    end_entity
        .verify_is_valid_tls_server_cert(
            &supported,
            &TlsServerTrustAnchors(&anchors_vec),
            &intermediates,
            now,
        )
        .is_ok()
        &&
    // Name checks (SAN/CN)
    end_entity.verify_is_valid_for_dns_name(dns_name).is_ok()
}
