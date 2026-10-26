//! Hermetic TLS test harness shared by unit and integration tests.
//!
//! The same file is compiled into the library under `#[cfg(test)]` and into
//! every integration test crate through `tests/support/mod.rs`, so there is
//! exactly one loopback server implementation. It depends on `openssl` and
//! `std` only, never on other modules of this crate.
//!
//! Test identities (a test CA plus RSA 2048 and ECDSA P-256 leaves issued to
//! `test-server`) are generated in memory on first use instead of being
//! committed as fixtures.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{AlpnError, SslAcceptor, SslMethod, SslRef, SslVerifyMode, SslVersion};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509, X509Name, X509NameBuilder, X509NameRef};

/// Common name of every generated leaf certificate and of the committed
/// fixture, so tests can assert on it regardless of the identity in use.
pub const TEST_SERVER_CN: &str = "test-server";

/// A minimal HTTP response that completes the exchange dcert expects.
pub const HTTP_200: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Path of a file under `tests/data`.
pub fn test_data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name)
}

/// A private key with the certificate issued for it.
#[derive(Clone)]
pub struct KeyPair {
    pub key: PKey<Private>,
    pub cert: X509,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("subject", &self.cert.subject_name())
            .finish_non_exhaustive()
    }
}

/// The generated test PKI: one CA and one RSA and one ECDSA leaf it issued.
#[derive(Debug)]
pub struct TestPki {
    pub ca: KeyPair,
    pub rsa: KeyPair,
    pub ecdsa: KeyPair,
}

impl TestPki {
    /// The CA certificate as PEM, for `--ca-cert` style arguments.
    pub fn ca_pem(&self) -> Vec<u8> {
        self.ca.cert.to_pem().expect("CA to PEM")
    }
}

/// The process wide test PKI, generated once on first use.
pub fn test_pki() -> &'static TestPki {
    static PKI: OnceLock<TestPki> = OnceLock::new();
    PKI.get_or_init(generate_pki)
}

fn name(common_name: &str) -> X509Name {
    let mut builder = X509NameBuilder::new().expect("name builder");
    builder.append_entry_by_text("O", "dcert test").expect("O");
    builder.append_entry_by_text("CN", common_name).expect("CN");
    builder.build()
}

fn serial() -> openssl::asn1::Asn1Integer {
    let mut bn = BigNum::new().expect("bignum");
    bn.rand(127, MsbOption::MAYBE_ZERO, false).expect("random serial");
    bn.to_asn1_integer().expect("serial")
}

fn rsa_key() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).expect("RSA key")).expect("RSA pkey")
}

fn ecdsa_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
    PKey::from_ec_key(EcKey::generate(&group).expect("EC key")).expect("EC pkey")
}

fn generate_pki() -> TestPki {
    let ca_key = ecdsa_key();
    let ca_name = name("dcert test CA");
    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("version");
    builder.set_serial_number(&serial()).expect("serial");
    builder.set_subject_name(&ca_name).expect("subject");
    builder.set_issuer_name(&ca_name).expect("issuer");
    builder.set_pubkey(&ca_key).expect("pubkey");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("now"))
        .expect("not before");
    builder
        .set_not_after(&Asn1Time::days_from_now(365).expect("later"))
        .expect("not after");
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().expect("bc"))
        .expect("bc ext");
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .expect("ku"),
        )
        .expect("ku ext");
    builder.sign(&ca_key, MessageDigest::sha256()).expect("sign CA");
    let ca = KeyPair {
        key: ca_key,
        cert: builder.build(),
    };
    let rsa = issue_leaf(&ca, rsa_key());
    let ecdsa = issue_leaf(&ca, ecdsa_key());
    TestPki { ca, rsa, ecdsa }
}

fn issue_leaf(ca: &KeyPair, key: PKey<Private>) -> KeyPair {
    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("version");
    builder.set_serial_number(&serial()).expect("serial");
    builder.set_subject_name(&name(TEST_SERVER_CN)).expect("subject");
    builder.set_issuer_name(ca.cert.subject_name()).expect("issuer");
    builder.set_pubkey(&key).expect("pubkey");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("now"))
        .expect("not before");
    builder
        .set_not_after(&Asn1Time::days_from_now(90).expect("later"))
        .expect("not after");
    builder
        .append_extension(BasicConstraints::new().build().expect("bc"))
        .expect("bc ext");
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()
                .expect("ku"),
        )
        .expect("ku ext");
    builder
        .append_extension(ExtendedKeyUsage::new().server_auth().build().expect("eku"))
        .expect("eku ext");
    let san = SubjectAlternativeName::new()
        .dns(TEST_SERVER_CN)
        .dns("localhost")
        .ip("127.0.0.1")
        .build(&builder.x509v3_context(Some(&ca.cert), None))
        .expect("san");
    builder.append_extension(san).expect("san ext");
    builder.sign(&ca.key, MessageDigest::sha256()).expect("sign leaf");
    KeyPair {
        key,
        cert: builder.build(),
    }
}

/// The server certificate and key a harness server presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// The committed `tests/data/verify-key-discovery` fixture (self signed RSA).
    Fixture,
    /// Generated RSA 2048 leaf issued by the test CA.
    Rsa,
    /// Generated ECDSA P-256 leaf issued by the test CA.
    Ecdsa,
    /// Both generated leaves, so the server picks by the client's offer.
    Both,
}

/// How the server treats client certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMode {
    /// No CertificateRequest is sent.
    None,
    /// A CertificateRequest is sent; a missing certificate is tolerated.
    Optional,
    /// A CertificateRequest is sent; a missing certificate fails the handshake.
    Required,
}

/// What the server saw on one connection, for assertions on the server side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// The handshake completed with this protocol version and cipher.
    Accepted { version: String, cipher: String },
    /// The handshake failed with this error text.
    Rejected(String),
}

/// Plaintext exchange before the TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preamble {
    /// TLS from the first byte.
    None,
    /// SMTP banner, EHLO and STARTTLS, then TLS (RFC 3207).
    Smtp,
}

type Responder = Box<dyn Fn(&[u8]) -> Vec<u8> + Send + 'static>;

/// Builder for a loopback TLS server. Every knob is optional; the defaults
/// match `SslAcceptor::mozilla_intermediate_v5` with the fixture identity.
pub struct TlsServerBuilder {
    min: Option<SslVersion>,
    max: Option<SslVersion>,
    cipher_list: Option<String>,
    ciphersuites: Option<String>,
    groups: Option<String>,
    security_level: Option<u32>,
    client_auth: ClientAuthMode,
    client_ca_names: Vec<X509Name>,
    alpn: Vec<Vec<u8>>,
    identity: Identity,
    connections: usize,
    preamble: Preamble,
    drip: Option<Duration>,
    respond: Responder,
}

impl std::fmt::Debug for TlsServerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServerBuilder")
            .field("cipher_list", &self.cipher_list)
            .field("ciphersuites", &self.ciphersuites)
            .field("groups", &self.groups)
            .field("identity", &self.identity)
            .field("connections", &self.connections)
            .finish_non_exhaustive()
    }
}

/// A running loopback TLS server.
#[derive(Debug)]
pub struct TlsServer {
    port: u16,
    observations: Receiver<Observation>,
}

impl TlsServer {
    /// Start configuring a server.
    pub fn builder() -> TlsServerBuilder {
        TlsServerBuilder {
            min: None,
            max: None,
            cipher_list: None,
            ciphersuites: None,
            groups: None,
            security_level: None,
            client_auth: ClientAuthMode::None,
            client_ca_names: Vec::new(),
            alpn: Vec::new(),
            identity: Identity::Fixture,
            connections: 1,
            preamble: Preamble::None,
            drip: None,
            respond: Box::new(|_| HTTP_200.to_vec()),
        }
    }

    /// The bound loopback port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `https://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    /// The next connection outcome, waiting at most `timeout`.
    pub fn observation(&self, timeout: Duration) -> Option<Observation> {
        self.observations.recv_timeout(timeout).ok()
    }
}

impl TlsServerBuilder {
    /// Pin the protocol range; `None` leaves that bound at the library default.
    pub fn versions(mut self, min: Option<SslVersion>, max: Option<SslVersion>) -> Self {
        self.min = min;
        self.max = max;
        self
    }

    /// TLS 1.2 and below cipher list (OpenSSL syntax).
    pub fn cipher_list(mut self, list: &str) -> Self {
        self.cipher_list = Some(list.to_string());
        self
    }

    /// TLS 1.3 cipher suites (OpenSSL syntax, colon separated).
    pub fn ciphersuites(mut self, suites: &str) -> Self {
        self.ciphersuites = Some(suites.to_string());
        self
    }

    /// Key exchange groups (OpenSSL group list syntax).
    pub fn groups(mut self, groups: &str) -> Self {
        self.groups = Some(groups.to_string());
        self
    }

    /// OpenSSL security level for the server context.
    pub fn security_level(mut self, level: u32) -> Self {
        self.security_level = Some(level);
        self
    }

    /// Client certificate policy.
    pub fn client_auth(mut self, mode: ClientAuthMode) -> Self {
        self.client_auth = mode;
        self
    }

    /// CA names advertised in the CertificateRequest.
    pub fn client_ca_names(mut self, names: Vec<X509Name>) -> Self {
        self.client_ca_names = names;
        self
    }

    /// ALPN protocols the server accepts, in preference order. A client that
    /// offers none of them gets a `no_application_protocol` alert.
    pub fn alpn(mut self, protocols: &[&str]) -> Self {
        self.alpn = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
        self
    }

    /// Server certificate and key.
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = identity;
        self
    }

    /// Number of connections to serve before the thread exits.
    pub fn connections(mut self, n: usize) -> Self {
        self.connections = n;
        self
    }

    /// Speak an SMTP STARTTLS exchange before the handshake.
    pub fn starttls_smtp(mut self) -> Self {
        self.preamble = Preamble::Smtp;
        self
    }

    /// Send the reply one byte at a time, `interval` apart, as a slow or
    /// hostile peer would.
    pub fn drip(mut self, interval: Duration) -> Self {
        self.drip = Some(interval);
        self
    }

    /// Reply produced from the request head of each accepted connection.
    pub fn respond(mut self, respond: impl Fn(&[u8]) -> Vec<u8> + Send + 'static) -> Self {
        self.respond = Box::new(respond);
        self
    }

    /// Build the acceptor, bind `127.0.0.1:0` and serve in a thread.
    pub fn spawn(self) -> TlsServer {
        let acceptor = self.acceptor();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let (tx, rx) = channel();
        let connections = self.connections;
        let preamble = self.preamble;
        let drip = self.drip;
        let respond = self.respond;
        std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept() else {
                    continue;
                };
                if preamble == Preamble::Smtp && smtp_starttls(&mut stream).is_err() {
                    let _ = tx.send(Observation::Rejected("SMTP STARTTLS exchange failed".into()));
                    continue;
                }
                serve_one(&acceptor, stream, &respond, drip, &tx);
            }
        });
        TlsServer { port, observations: rx }
    }

    fn acceptor(&self) -> SslAcceptor {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("acceptor builder");
        match self.identity {
            Identity::Fixture => {
                let key = PKey::private_key_from_pem(
                    &std::fs::read(test_data("verify-key-discovery/server.key")).expect("read fixture key"),
                )
                .expect("parse fixture key");
                let cert = X509::from_pem(
                    &std::fs::read(test_data("verify-key-discovery/server.crt")).expect("read fixture cert"),
                )
                .expect("parse fixture cert");
                builder.set_certificate(&cert).expect("fixture cert");
                builder.set_private_key(&key).expect("fixture key");
            }
            Identity::Rsa => use_pair(&mut builder, &test_pki().rsa),
            Identity::Ecdsa => use_pair(&mut builder, &test_pki().ecdsa),
            Identity::Both => {
                use_pair(&mut builder, &test_pki().rsa);
                use_pair(&mut builder, &test_pki().ecdsa);
            }
        }
        if let Some(level) = self.security_level {
            builder.set_security_level(level);
        }
        if self.min.is_some() || self.max.is_some() {
            builder.set_min_proto_version(self.min).expect("min version");
            builder.set_max_proto_version(self.max).expect("max version");
        }
        if let Some(list) = &self.cipher_list {
            builder.set_cipher_list(list).expect("server cipher list");
        }
        if let Some(suites) = &self.ciphersuites {
            builder.set_ciphersuites(suites).expect("server ciphersuites");
        }
        if let Some(groups) = &self.groups {
            builder.set_groups_list(groups).expect("server groups");
        }
        match self.client_auth {
            ClientAuthMode::None => {}
            ClientAuthMode::Optional => {
                builder.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
            }
            ClientAuthMode::Required => {
                builder.set_verify_callback(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT, |_, _| true);
            }
        }
        if !self.client_ca_names.is_empty() {
            let mut names = openssl::stack::Stack::new().expect("name stack");
            for n in &self.client_ca_names {
                let n: &X509NameRef = n;
                names.push(n.to_owned().expect("copy name")).expect("push name");
            }
            builder.set_client_ca_list(names);
        }
        if !self.alpn.is_empty() {
            let accepted = self.alpn.clone();
            builder.set_alpn_select_callback(move |_, offered| select_alpn(&accepted, offered));
        }
        builder.build()
    }
}

fn use_pair(builder: &mut openssl::ssl::SslAcceptorBuilder, pair: &KeyPair) {
    builder.set_certificate(&pair.cert).expect("server cert");
    builder.set_private_key(&pair.key).expect("server key");
    builder.check_private_key().expect("key matches cert");
}

/// Pick the first server protocol the client offered. The returned slice must
/// borrow from `offered`, so it is located there rather than in `accepted`.
fn select_alpn<'a>(accepted: &[Vec<u8>], offered: &'a [u8]) -> Result<&'a [u8], AlpnError> {
    let mut client = Vec::new();
    let mut rest = offered;
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len);
        if tail.len() < len {
            break;
        }
        client.push(&tail[..len]);
        rest = &tail[len..];
    }
    accepted
        .iter()
        .find_map(|want| client.iter().copied().find(|c| *c == want.as_slice()))
        .ok_or(AlpnError::ALERT_FATAL)
}

fn describe(ssl: &SslRef) -> Observation {
    Observation::Accepted {
        version: ssl.version_str().to_string(),
        cipher: ssl.current_cipher().map(|c| c.name().to_string()).unwrap_or_default(),
    }
}

/// Read one CRLF terminated line, byte by byte so nothing past it is consumed.
fn read_line(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < 1024 {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Server side of the RFC 3207 exchange up to the TLS handshake.
fn smtp_starttls(stream: &mut TcpStream) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    stream.write_all(b"220 test-server ESMTP ready\r\n")?;
    let ehlo = read_line(stream)?;
    if !ehlo.to_ascii_uppercase().starts_with("EHLO") {
        return Err(std::io::Error::other(format!("expected EHLO, got {ehlo:?}")));
    }
    stream.write_all(b"250-test-server\r\n250 STARTTLS\r\n")?;
    let starttls = read_line(stream)?;
    if !starttls.to_ascii_uppercase().starts_with("STARTTLS") {
        return Err(std::io::Error::other(format!("expected STARTTLS, got {starttls:?}")));
    }
    stream.write_all(b"220 ready to start TLS\r\n")
}

fn serve_one(
    acceptor: &SslAcceptor,
    stream: TcpStream,
    respond: &Responder,
    drip: Option<Duration>,
    tx: &Sender<Observation>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    match acceptor.accept(stream) {
        Ok(mut tls) => {
            let _ = tx.send(describe(tls.ssl()));
            let mut req = [0u8; 4096];
            let n = tls.read(&mut req).unwrap_or(0);
            let reply = respond(&req[..n]);
            match drip {
                None => {
                    let _ = tls.write_all(&reply);
                }
                Some(interval) => {
                    for byte in reply {
                        if tls.write_all(&[byte]).and_then(|()| tls.flush()).is_err() {
                            return;
                        }
                        std::thread::sleep(interval);
                    }
                }
            }
            let _ = tls.shutdown();
        }
        Err(e) => {
            let _ = tx.send(Observation::Rejected(e.to_string()));
        }
    }
}

/// A forward proxy that answers the first request with `response` verbatim.
pub fn spawn_fake_proxy(response: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut req = [0u8; 4096];
            let _ = stream.read(&mut req);
            let _ = stream.write_all(response);
        }
    });
    port
}

/// A raw TCP server for one connection that writes `prefix` and then one
/// `filler` byte every `interval` until the peer goes away (at most 60
/// seconds), so every individual read succeeds but the exchange never ends.
pub fn spawn_drip_server(prefix: &'static [u8], filler: u8, interval: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        if stream.write_all(prefix).is_err() {
            return;
        }
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            if stream.write_all(&[filler]).and_then(|()| stream.flush()).is_err() {
                return;
            }
            std::thread::sleep(interval);
        }
    });
    port
}

/// A loopback port with nothing listening on it, so connects fail fast.
pub fn closed_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.local_addr().expect("local addr").port()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ssl::{SslConnector, SslVerifyMode};

    fn client(server: &TlsServer, configure: impl FnOnce(&mut openssl::ssl::SslConnectorBuilder)) -> Observation {
        let mut builder = SslConnector::builder(SslMethod::tls()).expect("connector");
        builder.set_verify(SslVerifyMode::NONE);
        configure(&mut builder);
        let stream = TcpStream::connect(("127.0.0.1", server.port())).expect("connect");
        match builder.build().connect("test-server", stream) {
            Ok(mut tls) => {
                let seen = describe(tls.ssl());
                let _ = tls.write_all(b"GET / HTTP/1.1\r\n\r\n");
                seen
            }
            Err(e) => Observation::Rejected(e.to_string()),
        }
    }

    #[test]
    fn pinned_tls12_single_cipher_is_negotiated() {
        let server = TlsServer::builder()
            .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_2))
            .cipher_list("ECDHE-RSA-AES256-GCM-SHA384")
            .identity(Identity::Rsa)
            .spawn();
        let seen = client(&server, |_| {});
        assert_eq!(
            seen,
            Observation::Accepted {
                version: "TLSv1.2".into(),
                cipher: "ECDHE-RSA-AES256-GCM-SHA384".into()
            }
        );
        assert_eq!(server.observation(Duration::from_secs(5)), Some(seen));
    }

    #[test]
    fn dual_identity_serves_ecdsa_to_an_ecdsa_only_client() {
        let server = TlsServer::builder()
            .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_2))
            .identity(Identity::Both)
            .spawn();
        let seen = client(&server, |b| {
            b.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256")
                .expect("client ciphers");
        });
        assert!(
            matches!(&seen, Observation::Accepted { cipher, .. } if cipher == "ECDHE-ECDSA-AES128-GCM-SHA256"),
            "{seen:?}"
        );
    }

    #[test]
    fn rsa_only_server_rejects_ecdsa_only_client() {
        let server = TlsServer::builder()
            .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_2))
            .identity(Identity::Rsa)
            .spawn();
        let seen = client(&server, |b| {
            b.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256")
                .expect("client ciphers");
        });
        assert!(matches!(seen, Observation::Rejected(_)), "{seen:?}");
        assert!(matches!(
            server.observation(Duration::from_secs(5)),
            Some(Observation::Rejected(_))
        ));
    }

    #[test]
    fn alpn_mismatch_is_rejected() {
        let server = TlsServer::builder().alpn(&["h2"]).spawn();
        let seen = client(&server, |b| {
            b.set_alpn_protos(b"\x08http/1.1").expect("client alpn");
        });
        assert!(matches!(seen, Observation::Rejected(_)), "{seen:?}");
    }

    #[test]
    fn generated_leaves_chain_to_the_test_ca() {
        let pki = test_pki();
        for leaf in [&pki.rsa, &pki.ecdsa] {
            let ca_key = pki.ca.cert.public_key().expect("CA public key");
            assert!(
                leaf.cert.verify(&ca_key).expect("verify"),
                "leaf must be signed by the CA"
            );
        }
        assert!(!pki.ca_pem().is_empty());
    }
}
