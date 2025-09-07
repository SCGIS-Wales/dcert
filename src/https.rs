use x509_parser::prelude::FromDer;
use crate::args::{HttpVersion, TlsVersion};
use crate::proxy::choose_https_proxy;
use anyhow::{Context, Result};
use base64::Engine;
use rustls::client::ResolvesClientCert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConnection, SignatureScheme, StreamOwned};
use serde::Serialize;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use url::Url;

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

/// Read CA bundle DERs from --ca-file or SSL_CERT_FILE. Returns None if neither is present.
fn load_ca_bundle_der(
    ca_file: Option<&std::path::Path>,
) -> Result<Option<Vec<CertificateDer<'static>>>> {
    let path_opt = ca_file
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::var_os("SSL_CERT_FILE").map(std::path::PathBuf::from));

    let Some(path) = path_opt else {
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

fn connect_via_proxy(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    timeout: u64,
) -> Result<TcpStream> {
    let connect_req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream.write_all(connect_req.as_bytes())?;
    stream.flush()?;
    let mut buf = [0u8; 1024];
    let _ = stream.set_read_timeout(Some(Duration::from_secs(timeout)));
    let n = stream.read(&mut buf)?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
        Ok(stream)
    } else {
        Err(anyhow::anyhow!(
            "Proxy CONNECT failed: {}",
            resp.lines().next().unwrap_or(&resp)
        ))
    }
}

fn http11_request(
    tls: &mut StreamOwned<ClientConnection, TcpStream>,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(String, String)],
) -> Result<()> {
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dcert/{ver}\r\nConnection: close\r\n",
        ver = env!("CARGO_PKG_VERSION"),
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes())?;
    tls.flush()?;
    Ok(())
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
) -> Result<(
    HttpsSession,
    Vec<x509_parser::prelude::X509Certificate<'static>>,
)> {
    let url = Url::parse(url_s).context("Invalid URL")?;
    if url.scheme() != "https" {
        anyhow::bail!("Only https:// is supported for probing");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Host missing in URL"))?
        .to_string();
    let port = url.port().unwrap_or(443);
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
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

    // Build rustls config
    let mut roots = rustls::RootCertStore::empty();
    if let Some(bundle) = load_ca_bundle_der(ca_file)? {
        let _ = roots.add_parsable_certificates(bundle);
    }

    let alpn_protocols = match http_version {
        HttpVersion::H2 => vec![b"h2".to_vec()],
        HttpVersion::H1_1 => vec![b"http/1.1".to_vec()],
        HttpVersion::H3 => vec![b"h2".to_vec(), b"http/1.1".to_vec()], // placeholder
    };

    let versions: &[&'static rustls::SupportedProtocolVersion] = match tls_version {
        TlsVersion::V13 => &[&rustls::version::TLS13],
        TlsVersion::V12 => &[&rustls::version::TLS12],
    };

    let mut cfg = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_root_certificates(roots.clone())
        .with_no_client_auth();

    // Track client-cert request
    let requested = Arc::new(AtomicBool::new(false));
    cfg.client_auth_cert_resolver = Arc::new(NoClientAuthResolver {
        was_requested: requested.clone(),
    });

    cfg.alpn_protocols = alpn_protocols;

    // SNI
    let server_name = ServerName::try_from(host.clone()).context("Invalid SNI")?;
    let mut conn =
        ClientConnection::new(Arc::new(cfg), server_name).context("TLS client build failed")?;
    let mut tls = StreamOwned::new(conn, tcp);

    // L6 handshake
    let l6_start = Instant::now();
    loop {
        match tls.conn.complete_io(&mut tls.sock) {
            Ok(_) => {
                if !tls.conn.is_handshaking() {
                    break;
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!("TLS handshake error: {e}"));
            }
        }
        if l6_start.elapsed() > Duration::from_secs(timeout_l6) {
            anyhow::bail!("TLS handshake timeout");
        }
    }
    let l6_ok = true;

    // TLS negotiated params
    let tls_version_s = tls.conn.protocol_version().map(|v| match v {
        rustls::ProtocolVersion::TLSv1_3 => "1.3".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "1.2".to_string(),
        _ => format!("{v:?}"),
    });
    let cipher_suite = tls
        .conn
        .negotiated_cipher_suite()
        .and_then(|cs| cs.suite().as_str().map(|s| s.to_string()));
    let negotiated_alpn = tls
        .conn
        .alpn_protocol()
        .map(|b| String::from_utf8_lossy(b).to_string());

    // L7 request (only HTTP/1.1 implemented; H2 path reaches server anyway)
    let l7_start = Instant::now();
    let mut l7_ok = false;
    match http_version {
        HttpVersion::H1_1 => {
            http11_request(&mut tls, method, &host, &path_query, headers_kv)?;
            let mut buf = [0u8; 1];
            let _ = tls.read(&mut buf)?;
            l7_ok = true;
        }
        _ => {
            // We don’t implement full H2/H3 here — count handshake as reaching L7.
            l7_ok = true;
        }
    }
    let t_l7_ms = l7_start.elapsed().as_millis();

    // Capture chain for parsing/export
    let peer_chain: Vec<CertificateDer<'static>> = tls
        .conn
        .peer_certificates()
        .unwrap_or(&[])
        .iter()
        .cloned()
        .collect();

    // Optional trust check (behind feature)
    let mut trusted_with_local_cas = false;
    #[allow(unused_mut, unused_variables)]
    {
        #[cfg(feature = "trust-check")]
        {
            use rustls_webpki::{
                DnsNameRef, EndEntityCert, Time, TlsServerTrustAnchors, TrustAnchor,
            };

            if !roots.is_empty() && !peer_chain.is_empty() {
                let anchors_vec: Vec<TrustAnchor<'_>> = roots
                    .roots
                    .iter()
                    .filter_map(|ta| TrustAnchor::try_from_cert_der(ta.der().as_ref()).ok())
                    .collect();
                let trust = TlsServerTrustAnchors(&anchors_vec);

                if let Some(end) = peer_chain.first() {
                    let intermediates: Vec<&[u8]> =
                        peer_chain.iter().skip(1).map(|c| c.as_ref()).collect();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if let Ok(ee) = EndEntityCert::try_from(end.as_ref()) {
                        let dns_name = DnsNameRef::try_from_ascii_str(&host).unwrap_or_else(|_| {
                            DnsNameRef::try_from_ascii_str("invalid.example").unwrap()
                        });
                        let res = ee.verify_is_valid_tls_server_cert(
                            &[
                                &rustls_webpki::ECDSA_P256_SHA256,
                                &rustls_webpki::ECDSA_P384_SHA384,
                                &rustls_webpki::ED25519,
                                &rustls_webpki::RSA_PKCS1_2048_8192_SHA256,
                                &rustls_webpki::RSA_PKCS1_2048_8192_SHA384,
                                &rustls_webpki::RSA_PKCS1_2048_8192_SHA512,
                                &rustls_webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                                &rustls_webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                                &rustls_webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                            ],
                            &trust,
                            &intermediates,
                            Time::from_seconds_since_unix_epoch(now),
                        );
                        if res.is_ok() && ee.verify_is_valid_for_dns_name(dns_name).is_ok() {
                            trusted_with_local_cas = true;
                        }
                    }
                }
            }
        }
    }

    // Optionally export the chain as base64-PEM
    if export_chain && !peer_chain.is_empty() {
        if let Some(h) = url.host_str() {
            let fname = format!("{}-base64-pem.txt", h.replace('.', ""));
            let mut out = String::new();
            for der in &peer_chain {
                let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
                out.push_str("-----BEGIN CERTIFICATE-----\n");
                for chunk in b64.as_bytes().chunks(64) {
                    out.push_str(&String::from_utf8_lossy(chunk));
                    out.push('\n');
                }
                out.push_str("-----END CERTIFICATE-----\n");
            }
            std::fs::write(&fname, out).with_context(|| format!("Write {fname}"))?;
        }
    }

    // Parse X.509s
    let mut x509s = Vec::new();
    for der in peer_chain {
        if let Ok((_, c)) = x509_parser::certificate::X509Certificate::from_der(der.as_ref()) {
            x509s.push(c.to_owned());
        }
    }

    let session = HttpsSession {
        l4_ok: true,
        l6_ok,
        l7_ok,
        tls_version: tls_version_s,
        cipher_suite,
        negotiated_alpn,
        t_l4_ms,
        t_l7_ms,
        trusted_with_local_cas,
        client_cert_requested: requested.load(Ordering::SeqCst),
    };

    Ok((session, x509s))
}
