//! Shared construction of blocking HTTP clients.
//!
//! Every outbound HTTP call that is not the TLS probe itself (AIA issuer
//! fetches, public root refreshes, Vault) goes through [`blocking_client`],
//! so proxy handling, timeouts, custom CA material and the user agent are
//! configured in exactly one place.
//!
//! The client is `ureq` over the OpenSSL the probe already links: TLS is
//! negotiated by [`OpensslConnector`], so the binary carries one TLS
//! implementation, not two. Trust is OpenSSL's (the same defaults as the
//! probe, see [`crate::tls::load_ca_certs`]), plus the platform store on macOS
//! and Windows, plus any `ca_file` or `ca_dir` the caller names. Redirects are
//! followed here rather than by `ureq`, so a same-origin rule can stop a
//! credential from leaving the server it was meant for.

use anyhow::{Context, Result};
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::X509;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use ureq::http::{HeaderName, HeaderValue, Method, StatusCode, Uri};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{
    Buffers, ConnectProxyConnector, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout, TcpConnector,
    Transport, TransportAdapter,
};

use crate::proxy::ProxyConfig;

/// User agent sent by every client built here.
pub const USER_AGENT: &str = concat!("dcert/", env!("CARGO_PKG_VERSION"));

/// Options for [`blocking_client`].
#[derive(Debug, Clone, Default)]
pub struct HttpClientOptions<'a> {
    /// Overall request timeout. `None` means no overall timeout.
    pub timeout: Option<Duration>,
    /// TCP connect timeout. Defaults to `timeout` when unset.
    pub connect_timeout: Option<Duration>,
    /// Forward proxy configuration. `None` disables proxy support entirely:
    /// no proxy environment variable is read here, so behaviour is identical
    /// to dcert's TLS path.
    pub proxy: Option<&'a ProxyConfig>,
    /// Disable server certificate verification. Callers must warn the user.
    pub accept_invalid_certs: bool,
    /// Extra root certificate bundle (PEM, may contain several certificates).
    pub ca_file: Option<&'a str>,
    /// Directory of `.pem`, `.crt` or `.cer` files to add as roots.
    pub ca_dir: Option<&'a str>,
    /// Maximum redirects to follow. `None` keeps the default (10);
    /// `Some(0)` refuses to follow any redirect.
    pub max_redirects: Option<usize>,
    /// Follow redirects only within the origin (scheme, host and port) of
    /// the original request. Clients that send credentials (Vault) set this,
    /// so a redirect can never carry a token to another server.
    pub same_origin_redirects: bool,
    /// Connect to these addresses for this host instead of resolving it
    /// again, so the addresses a destination policy checked are the ones
    /// dialled (see [`crate::netpolicy::enforce_url_pinned`]).
    pub pinned: Option<&'a crate::netpolicy::PinnedHost>,
}

/// Default redirect limit.
const DEFAULT_MAX_REDIRECTS: usize = 10;

/// Whether a redirect from a chain that started at `first` may go to `next`
/// after `hops` redirects already followed: same scheme, host and port, and
/// fewer than `limit` hops.
pub fn same_origin_redirect_allowed(first: &url::Url, next: &url::Url, hops: usize, limit: usize) -> bool {
    hops < limit && first.origin() == next.origin()
}

/// How a client treats a redirect response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectRule {
    /// Follow up to this many redirects to any origin; one more is an error.
    Limited(usize),
    /// Follow up to this many redirects on the original origin; any other
    /// redirect is handed back to the caller as the response.
    SameOrigin(usize),
}

/// Number of CA certificates loaded from a directory by [`blocking_client`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaDirSummary {
    pub loaded: usize,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// What went wrong with a request, for callers that explain failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    /// Name resolution, TCP connect, proxy CONNECT or the TLS handshake failed.
    Connect,
    /// A timeout expired.
    Timeout,
    /// The redirect limit was exceeded or a redirect was malformed.
    Redirect,
    /// The request could not be built (bad URL, unserialisable body).
    Builder,
    /// Anything else while sending the request or reading the response head.
    Request,
}

/// An error from [`HttpClient`].
#[derive(Debug)]
pub struct HttpError {
    kind: ErrorKind,
    message: String,
}

impl HttpError {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn from_ureq(err: ureq::Error) -> Self {
        let kind = match &err {
            ureq::Error::Timeout(_) => ErrorKind::Timeout,
            ureq::Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => ErrorKind::Timeout,
            ureq::Error::HostNotFound
            | ureq::Error::ConnectionFailed
            | ureq::Error::ConnectProxyFailed(_)
            | ureq::Error::Io(_)
            | ureq::Error::Tls(_) => ErrorKind::Connect,
            ureq::Error::Other(e) if e.is::<TlsHandshakeError>() => ErrorKind::Connect,
            ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => ErrorKind::Redirect,
            ureq::Error::BadUri(_) | ureq::Error::Http(_) | ureq::Error::InvalidProxyUrl => ErrorKind::Builder,
            _ => ErrorKind::Request,
        };
        Self::new(kind, err.to_string())
    }

    /// The connection could not be established (DNS, TCP, proxy or TLS).
    pub fn is_connect(&self) -> bool {
        self.kind == ErrorKind::Connect
    }

    /// A timeout expired.
    pub fn is_timeout(&self) -> bool {
        self.kind == ErrorKind::Timeout
    }

    /// The redirect limit was exceeded.
    pub fn is_redirect(&self) -> bool {
        self.kind == ErrorKind::Redirect
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            ErrorKind::Connect => "error connecting",
            ErrorKind::Timeout => "operation timed out",
            ErrorKind::Redirect => "error following redirect",
            ErrorKind::Builder => "invalid request",
            ErrorKind::Request => "error sending request",
        };
        write!(f, "{what}: {}", self.message)
    }
}

impl std::error::Error for HttpError {}

/// A TLS handshake failure, with OpenSSL's verification result when there is one.
#[derive(Debug)]
struct TlsHandshakeError(String);

impl fmt::Display for TlsHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS handshake failed: {}", self.0)
    }
}

impl std::error::Error for TlsHandshakeError {}

// ---------------------------------------------------------------------------
// Client, requests and responses
// ---------------------------------------------------------------------------

/// A blocking HTTP client. Cheap to clone.
#[derive(Clone)]
pub struct HttpClient {
    direct: ureq::Agent,
    https_proxy: Option<ureq::Agent>,
    http_proxy: Option<ureq::Agent>,
    proxy: Option<ProxyConfig>,
    redirects: RedirectRule,
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient")
            .field("https_proxy", &self.https_proxy.is_some())
            .field("http_proxy", &self.http_proxy.is_some())
            .field("redirects", &self.redirects)
            .finish_non_exhaustive()
    }
}

impl HttpClient {
    /// Start a GET request.
    pub fn get(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::GET, url)
    }

    /// Start a POST request.
    pub fn post(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::POST, url)
    }

    /// Start a request with any method, including extension methods such as
    /// Vault's `LIST`.
    pub fn request(&self, method: Method, url: &str) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            method,
            url: url.to_string(),
            headers: Vec::new(),
            body: None,
            error: None,
        }
    }

    /// The agent for `url`: through the proxy configured for its scheme
    /// unless `NO_PROXY` excludes its host, direct otherwise.
    fn agent_for(&self, url: &url::Url) -> &ureq::Agent {
        let Some(proxy) = &self.proxy else {
            return &self.direct;
        };
        let host = url
            .host_str()
            .unwrap_or_default()
            .trim_start_matches('[')
            .trim_end_matches(']');
        if proxy.should_bypass(host) {
            return &self.direct;
        }
        let agent = match url.scheme() {
            "https" => self.https_proxy.as_ref(),
            "http" => self.http_proxy.as_ref(),
            _ => None,
        };
        agent.unwrap_or(&self.direct)
    }

    fn execute(
        &self,
        method: &Method,
        url: &url::Url,
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&[u8]>,
    ) -> Result<Response, HttpError> {
        let mut builder = ureq::http::Request::builder().method(method.clone()).uri(url.as_str());
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(body.unwrap_or_default().to_vec())
            .map_err(|e| HttpError::new(ErrorKind::Builder, e.to_string()))?;
        let response = self.agent_for(url).run(request).map_err(HttpError::from_ureq)?;
        let (parts, body) = response.into_parts();
        Ok(Response {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }
}

/// A request being built; see [`HttpClient::get`].
pub struct RequestBuilder<'c> {
    client: &'c HttpClient,
    method: Method,
    url: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Option<Vec<u8>>,
    error: Option<HttpError>,
}

impl fmt::Debug for RequestBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Header values and the body may carry credentials: not printed.
        f.debug_struct("RequestBuilder")
            .field("method", &self.method)
            .field("url", &crate::debug::sanitize_url(&self.url))
            .finish_non_exhaustive()
    }
}

impl RequestBuilder<'_> {
    /// Add a request header. An invalid name or value fails the request at
    /// [`send`](Self::send).
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        match (HeaderName::try_from(name), HeaderValue::try_from(value)) {
            (Ok(n), Ok(mut v)) => {
                v.set_sensitive(n.as_str().eq_ignore_ascii_case("x-vault-token"));
                self.headers.push((n, v));
            }
            _ => {
                self.error
                    .get_or_insert_with(|| HttpError::new(ErrorKind::Builder, format!("invalid header '{name}'")));
            }
        }
        self
    }

    /// Send `value` as a JSON body.
    #[must_use]
    pub fn json<T: serde::Serialize + ?Sized>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(bytes) => {
                self.body = Some(bytes);
                self.headers.push((
                    ureq::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ));
            }
            Err(e) => {
                self.error
                    .get_or_insert_with(|| HttpError::new(ErrorKind::Builder, format!("invalid JSON body: {e}")));
            }
        }
        self
    }

    /// Send the request, following redirects under the client's rule.
    pub fn send(self) -> Result<Response, HttpError> {
        if let Some(err) = self.error {
            return Err(err);
        }
        let first = url::Url::parse(&self.url)
            .map_err(|e| HttpError::new(ErrorKind::Builder, format!("invalid URL '{}': {e}", self.url)))?;
        let mut url = first.clone();
        let mut method = self.method;
        let mut body = self.body;
        let mut headers = self.headers;
        let mut hops = 0;
        loop {
            let response = self.client.execute(&method, &url, &headers, body.as_deref())?;
            if !response.status.is_redirection() {
                return Ok(response);
            }
            let Some(location) = response.header("location") else {
                return Ok(response);
            };
            let next = url
                .join(location)
                .map_err(|e| HttpError::new(ErrorKind::Redirect, format!("invalid redirect location: {e}")))?;
            match self.client.redirects {
                RedirectRule::Limited(limit) => {
                    if hops >= limit {
                        return Err(HttpError::new(
                            ErrorKind::Redirect,
                            format!("too many redirects (limit {limit}) at {url}"),
                        ));
                    }
                }
                RedirectRule::SameOrigin(limit) => {
                    if !same_origin_redirect_allowed(&first, &next, hops, limit) {
                        return Ok(response);
                    }
                }
            }
            // 307 and 308 repeat the request as it was; the others turn a
            // request with a body into a GET without one, as browsers do.
            let keep_method = matches!(
                response.status,
                StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT
            );
            if !keep_method && method != Method::GET && method != Method::HEAD {
                method = Method::GET;
                body = None;
                headers.retain(|(n, _)| n != ureq::http::header::CONTENT_TYPE);
            }
            if next.origin() != first.origin() {
                // Credentials never follow a redirect to another origin.
                headers.retain(|(n, _)| {
                    !n.as_str().eq_ignore_ascii_case("x-vault-token") && n != ureq::http::header::AUTHORIZATION
                });
            }
            url = next;
            hops += 1;
        }
    }
}

/// A response: status, headers and a body read at most once.
pub struct Response {
    status: StatusCode,
    headers: ureq::http::HeaderMap,
    body: ureq::Body,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl Response {
    /// The HTTP status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// A response header as text, if present and valid.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The declared body length, if the server sent one.
    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length").and_then(|v| v.trim().parse().ok())
    }

    /// The body as a reader.
    pub fn into_reader(self) -> impl Read {
        self.body.into_reader()
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Build a blocking client from `opts`.
pub fn blocking_client(opts: &HttpClientOptions<'_>) -> Result<HttpClient> {
    let (client, _) = blocking_client_with_summary(opts)?;
    Ok(client)
}

/// Same as [`blocking_client`] but also reports how many CA files were loaded
/// from `ca_dir`, for debug output.
pub fn blocking_client_with_summary(opts: &HttpClientOptions<'_>) -> Result<(HttpClient, CaDirSummary)> {
    let (tls, summary) = tls_connector(opts)?;
    let tls = Arc::new(tls);
    let pinned = opts.pinned.map(|(host, addrs)| (normalise_host(host), addrs.clone()));
    let connect = opts.connect_timeout.or(opts.timeout);
    let config = |proxy: Option<ureq::Proxy>, pool: bool| {
        let builder = ureq::Agent::config_builder()
            .user_agent(USER_AGENT)
            .http_status_as_error(false)
            // Vault's LIST.
            .allow_non_standard_methods(true)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_global(opts.timeout)
            .timeout_connect(connect)
            .proxy(proxy);
        if pool { builder } else { builder.max_idle_connections(0) }.build()
    };
    let tls_chain = || OpensslConnector {
        connector: Arc::clone(&tls),
        verify: !opts.accept_invalid_certs,
    };
    // Direct, and https through a proxy: ureq dials (or CONNECTs through the
    // proxy) and OpenSSL negotiates TLS end to end with the server.
    let agent = |proxy: Option<ureq::Proxy>| -> ureq::Agent {
        let connector = ().chain(ConnectProxyConnector::default()).chain(TcpConnector::default()).chain(tls_chain());
        let resolver = PinnedResolver {
            pinned: pinned.clone(),
            fallback: DefaultResolver::default(),
        };
        ureq::Agent::with_parts(config(proxy, true), connector, resolver)
    };
    // Plain http through a proxy: dial the proxy and send the request in
    // absolute form (`GET http://host/path`), as HTTP proxies expect and as
    // the previous client did. ureq itself would tunnel with CONNECT, which
    // many proxies only allow to port 443.
    let forward_agent = |proxy_url: &str| -> Result<ureq::Agent> {
        let parsed = url::Url::parse(proxy_url)
            .map_err(|e| anyhow::anyhow!("invalid http proxy '{}': {e}", crate::debug::sanitize_url(proxy_url)))?;
        let host = parsed.host_str().unwrap_or_default().to_string();
        let port = parsed.port_or_known_default().unwrap_or(80);
        let authorization = proxy_authorization(&parsed);
        let connector = ().chain(TcpConnector::default()).chain(AbsoluteFormConnector { authorization });
        let resolver = ProxyResolver {
            proxy: format!("http://{}:{port}/", url_host(&host))
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid http proxy '{}': {e}", crate::debug::sanitize_url(proxy_url)))?,
            fallback: DefaultResolver::default(),
        };
        // One request per connection: the request line rewrite applies to the
        // first request a connection carries.
        Ok(ureq::Agent::with_parts(config(None, false), connector, resolver))
    };

    let mut client = HttpClient {
        direct: agent(None),
        https_proxy: None,
        http_proxy: None,
        proxy: opts.proxy.cloned(),
        redirects: if opts.same_origin_redirects {
            RedirectRule::SameOrigin(opts.max_redirects.unwrap_or(DEFAULT_MAX_REDIRECTS))
        } else {
            RedirectRule::Limited(opts.max_redirects.unwrap_or(DEFAULT_MAX_REDIRECTS))
        },
    };
    if let Some(proxy) = opts.proxy {
        if let Some(p) = &proxy.https_proxy {
            client.https_proxy = Some(agent(Some(parse_proxy(p, "https")?)));
        }
        if let Some(p) = &proxy.http_proxy {
            parse_proxy(p, "http")?;
            client.http_proxy = Some(forward_agent(p)?);
        }
    }
    Ok((client, summary))
}

fn parse_proxy(url: &str, scheme: &str) -> Result<ureq::Proxy> {
    let parsed = url::Url::parse(url)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some_and(|h| !h.is_empty()));
    if parsed.is_none() {
        anyhow::bail!("invalid {scheme} proxy '{}'", crate::debug::sanitize_url(url));
    }
    ureq::Proxy::new(url)
        .map_err(|e| anyhow::anyhow!("invalid {scheme} proxy '{}': {e}", crate::debug::sanitize_url(url)))
}

/// The OpenSSL client context shared by every connection of a client.
fn tls_connector(opts: &HttpClientOptions<'_>) -> Result<(SslConnector, CaDirSummary)> {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).context("failed to build HTTP client")?;
    if opts.accept_invalid_certs {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        crate::tls::load_ca_certs(&mut builder)?;
        add_platform_roots(&mut builder);
    }
    if let Some(path) = opts.ca_file {
        for cert in load_ca_file(path)? {
            add_root(&mut builder, cert);
        }
    }
    let mut summary = CaDirSummary::default();
    if let Some(dir) = opts.ca_dir {
        for cert in load_ca_dir(dir)? {
            add_root(&mut builder, cert);
            summary.loaded += 1;
        }
    }
    // ureq speaks HTTP/1.1 only.
    builder
        .set_alpn_protos(b"\x08http/1.1")
        .context("failed to build HTTP client")?;
    Ok((builder.build(), summary))
}

fn add_root(builder: &mut openssl::ssl::SslConnectorBuilder, cert: X509) {
    // A certificate already in the store is reported as an error; it is
    // trusted either way.
    let _ = builder.cert_store_mut().add_cert(cert);
}

/// Add the operating system's trusted roots on platforms where OpenSSL has
/// no access to them: the Windows certificate store and the macOS keychain.
/// On Linux OpenSSL already reads the system bundle.
#[cfg(any(windows, target_os = "macos"))]
fn add_platform_roots(builder: &mut openssl::ssl::SslConnectorBuilder) {
    let found = rustls_native_certs::load_native_certs();
    for cert in found.certs {
        if let Ok(x509) = X509::from_der(cert.as_ref()) {
            add_root(builder, x509);
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn add_platform_roots(_builder: &mut openssl::ssl::SslConnectorBuilder) {}

/// Read a response body without ever buffering more than `cap` bytes. The
/// declared `Content-Length` is checked first, then the stream is cut off
/// one byte past the cap so an oversized body is rejected before it lands
/// in memory.
pub fn read_capped(resp: Response, cap: usize, what: &str) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length()
        && len > cap as u64
    {
        anyhow::bail!("{what} too large ({len} bytes, limit {cap})");
    }
    let mut buf = Vec::with_capacity(cap.min(64 * 1024));
    resp.into_reader()
        .take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("read failed: {e}"))?;
    if buf.len() > cap {
        anyhow::bail!("{what} too large (more than {cap} bytes)");
    }
    Ok(buf)
}

/// Parse every certificate in a PEM bundle.
pub fn load_ca_file(path: &str) -> Result<Vec<X509>> {
    let pem = fs::read(path).with_context(|| format!("Failed to read CA certificate file: {path}"))?;
    let certs = X509::stack_from_pem(&pem).with_context(|| format!("Failed to parse CA certificate from: {path}"))?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in CA file: {path}");
    }
    Ok(certs)
}

/// Load every `.pem`, `.crt` or `.cer` file in `dir` as a root certificate.
/// Files that fail to parse are skipped so one stray file does not disable
/// the whole directory.
pub fn load_ca_dir(dir: &str) -> Result<Vec<X509>> {
    let mut certs = Vec::new();
    let entries = fs::read_dir(dir).with_context(|| format!("Failed to read CA path directory: {dir}"))?;
    for entry in entries {
        let path = entry?.path();
        if !is_ca_file(&path) {
            continue;
        }
        if let Ok(pem) = fs::read(&path)
            && let Ok(parsed) = X509::stack_from_pem(&pem)
        {
            certs.extend(parsed);
        }
    }
    Ok(certs)
}

fn is_ca_file(path: &Path) -> bool {
    matches!(path.extension().and_then(|e| e.to_str()), Some("pem" | "crt" | "cer"))
}

// ---------------------------------------------------------------------------
// Resolver: pinned addresses for one host
// ---------------------------------------------------------------------------

fn normalise_host(host: &str) -> String {
    host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase()
}

/// Resolves the pinned host to the addresses the destination policy checked,
/// with the URL's port, and every other host normally.
#[derive(Debug)]
struct PinnedResolver {
    pinned: Option<(String, Vec<SocketAddr>)>,
    fallback: DefaultResolver,
}

impl Resolver for PinnedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        if let Some((host, addrs)) = &self.pinned
            && uri.host().is_some_and(|h| normalise_host(h) == *host)
        {
            let port = uri
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
            let mut out = self.empty();
            for addr in addrs {
                if out.try_push(SocketAddr::new(addr.ip(), port)).is_err() {
                    break;
                }
            }
            if out.is_empty() {
                return Err(ureq::Error::HostNotFound);
            }
            return Ok(out);
        }
        self.fallback.resolve(uri, config, timeout)
    }
}

/// `[::1]` for an IPv6 literal, the name otherwise.
fn url_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// `Basic` credentials for a proxy URL with a user name, as `reqwest` sent them.
fn proxy_authorization(proxy: &url::Url) -> Option<Vec<u8>> {
    use base64::Engine;
    if proxy.username().is_empty() {
        return None;
    }
    let decode = |s: &str| percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned();
    let user = decode(proxy.username());
    let pass = decode(proxy.password().unwrap_or_default());
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    Some(format!("Proxy-Authorization: Basic {token}\r\n").into_bytes())
}

/// Resolves every host to the forward proxy, which resolves the target itself.
#[derive(Debug)]
struct ProxyResolver {
    proxy: Uri,
    fallback: DefaultResolver,
}

impl Resolver for ProxyResolver {
    fn resolve(
        &self,
        _uri: &Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        self.fallback.resolve(&self.proxy, config, timeout)
    }
}

/// Wraps the TCP connection to a forward proxy so the request goes out in
/// absolute form.
#[derive(Debug)]
struct AbsoluteFormConnector {
    authorization: Option<Vec<u8>>,
}

impl<In: Transport> Connector<In> for AbsoluteFormConnector {
    type Out = AbsoluteFormTransport;

    fn connect(&self, details: &ConnectionDetails, chained: Option<In>) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            return Ok(None);
        };
        if details.needs_tls() {
            return Err(ureq::Error::Tls("https is not sent through the forward proxy agent"));
        }
        let authority = details
            .uri
            .authority()
            .ok_or_else(|| ureq::Error::BadUri("http URL without a host".into()))?;
        Ok(Some(AbsoluteFormTransport {
            inner: transport.boxed(),
            buffers: LazyBuffers::new(details.config.input_buffer_size(), details.config.output_buffer_size()),
            origin: format!("http://{authority}").into_bytes(),
            authorization: self.authorization.clone(),
            rewritten: false,
        }))
    }
}

/// A connection to a forward proxy that rewrites the first request line.
struct AbsoluteFormTransport {
    inner: Box<dyn Transport>,
    buffers: LazyBuffers,
    origin: Vec<u8>,
    authorization: Option<Vec<u8>>,
    rewritten: bool,
}

impl fmt::Debug for AbsoluteFormTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbsoluteFormTransport").finish_non_exhaustive()
    }
}

/// `GET /path HTTP/1.1\r\n...` becomes `GET http://host/path HTTP/1.1\r\n`,
/// with the proxy credentials after the request line when there are any.
fn absolute_form(prelude: &[u8], origin: &[u8], authorization: Option<&[u8]>) -> Option<Vec<u8>> {
    let space = prelude.iter().position(|&b| b == b' ')?;
    if prelude.get(space + 1) != Some(&b'/') {
        return None;
    }
    let line_end = prelude.windows(2).position(|w| w == b"\r\n")? + 2;
    let mut out = Vec::with_capacity(prelude.len() + origin.len() + 64);
    out.extend_from_slice(&prelude[..=space]);
    out.extend_from_slice(origin);
    out.extend_from_slice(&prelude[space + 1..line_end]);
    if let Some(auth) = authorization {
        out.extend_from_slice(auth);
    }
    out.extend_from_slice(&prelude[line_end..]);
    Some(out)
}

impl Transport for AbsoluteFormTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        let mut data = self.buffers.output()[..amount].to_vec();
        if !self.rewritten {
            data = absolute_form(&data, &self.origin, self.authorization.as_deref()).ok_or_else(|| {
                ureq::Error::Other(Box::new(std::io::Error::other(
                    "unexpected request line for the forward proxy",
                )))
            })?;
            self.rewritten = true;
        }
        let mut rest = data.as_slice();
        while !rest.is_empty() {
            let out = self.inner.buffers().output();
            let n = out.len().min(rest.len());
            out[..n].copy_from_slice(&rest[..n]);
            self.inner.transmit_output(n, timeout)?;
            rest = &rest[n..];
        }
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        if self.inner.buffers().input().is_empty() && !self.inner.await_input(timeout)? {
            return Ok(false);
        }
        let available = self.inner.buffers().input();
        let target = self.buffers.input_append_buf();
        let n = target.len().min(available.len());
        target[..n].copy_from_slice(&available[..n]);
        self.inner.buffers().input_consume(n);
        self.buffers.input_appended(n);
        Ok(n > 0)
    }

    fn is_open(&mut self) -> bool {
        self.inner.is_open()
    }

    fn is_tls(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// TLS over OpenSSL
// ---------------------------------------------------------------------------

/// Negotiates TLS for `https` URLs with OpenSSL.
struct OpensslConnector {
    connector: Arc<SslConnector>,
    verify: bool,
}

impl fmt::Debug for OpensslConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpensslConnector")
            .field("verify", &self.verify)
            .finish()
    }
}

impl<In: Transport> Connector<In> for OpensslConnector {
    type Out = Either<In, OpensslTransport>;

    fn connect(&self, details: &ConnectionDetails, chained: Option<In>) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            return Ok(None);
        };
        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }
        let host = details
            .uri
            .host()
            .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())
            .ok_or_else(|| ureq::Error::BadUri("https URL without a host".into()))?;

        let mut config = self
            .connector
            .configure()
            .map_err(|e| ureq::Error::Other(Box::new(TlsHandshakeError(e.to_string()))))?;
        config.set_verify_hostname(self.verify);
        if !self.verify {
            config.set_verify(SslVerifyMode::NONE);
        }

        let mut adapter = TransportAdapter::new(transport.boxed(), details.current_time.clone());
        adapter.set_timeout(details.timeout);

        let stream = config.connect(&host, adapter).map_err(|e| match e {
            openssl::ssl::HandshakeError::Failure(mid) | openssl::ssl::HandshakeError::WouldBlock(mid) => {
                let verify = mid.ssl().verify_result();
                let error = mid.into_error();
                if let Some(io) = error.io_error()
                    && io.get_ref().is_some()
                {
                    // A transport error (such as a timeout) surfaced through OpenSSL.
                    return ureq::Error::from(std::io::Error::new(io.kind(), io.to_string()));
                }
                let detail = if verify == openssl::x509::X509VerifyResult::OK {
                    error.to_string()
                } else {
                    format!("certificate verify failed: {}", verify.error_string())
                };
                ureq::Error::Other(Box::new(TlsHandshakeError(detail)))
            }
            openssl::ssl::HandshakeError::SetupFailure(e) => {
                ureq::Error::Other(Box::new(TlsHandshakeError(e.to_string())))
            }
        })?;

        let buffers = LazyBuffers::new(details.config.input_buffer_size(), details.config.output_buffer_size());
        Ok(Some(Either::B(OpensslTransport { buffers, stream })))
    }
}

/// An established TLS connection.
pub struct OpensslTransport {
    buffers: LazyBuffers,
    stream: SslStream<TransportAdapter>,
}

impl fmt::Debug for OpensslTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpensslTransport").finish_non_exhaustive()
    }
}

impl Transport for OpensslTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = match self.stream.read(input) {
            Ok(n) => n,
            // A peer that closes without close_notify ends the body here, as
            // with a plain TCP connection.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e.into()),
        };
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_redirects_stay_on_scheme_host_and_port() {
        let first = url::Url::parse("https://vault.corp:8200/v1/a").unwrap();
        let ok = url::Url::parse("https://vault.corp:8200/v1/b").unwrap();
        assert!(same_origin_redirect_allowed(&first, &ok, 0, 10));
        assert!(!same_origin_redirect_allowed(&first, &ok, 10, 10), "hop limit");
        for other in [
            "http://vault.corp:8200/v1/b",
            "https://evil.example:8200/v1/b",
            "https://vault.corp:8201/v1/b",
        ] {
            let next = url::Url::parse(other).unwrap();
            assert!(!same_origin_redirect_allowed(&first, &next, 0, 10), "{other}");
        }
    }

    #[test]
    fn client_builds_without_proxy() {
        let opts = HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        };
        assert!(blocking_client(&opts).is_ok());
    }

    /// Serve `responses` in order on a local port, one per connection, and
    /// return the port and a handle yielding each raw request received.
    fn serve(responses: Vec<String>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else { break };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                seen.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = stream.write_all(response.as_bytes());
            }
            seen
        });
        (port, handle)
    }

    fn redirect(location: &str, status: &str) -> String {
        format!("HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn redirect_limit_is_enforced() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let (port2, _h) = serve(vec![redirect(&format!("http://127.0.0.1:{port}/next"), "302 Found")]);
        let opts = HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            max_redirects: Some(0),
            ..Default::default()
        };
        let client = blocking_client(&opts).unwrap();
        let err = client
            .get(&format!("http://127.0.0.1:{port2}/"))
            .send()
            .expect_err("a redirect must be refused when the limit is zero");
        assert!(err.is_redirect(), "{err}");
    }

    #[test]
    fn redirects_are_followed_within_the_limit() {
        let (port, handle) = serve(vec![redirect("/b", "302 Found"), ok("done")]);
        let client = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            max_redirects: Some(2),
            ..Default::default()
        })
        .unwrap();
        let resp = client.get(&format!("http://127.0.0.1:{port}/a")).send().unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(read_capped(resp, 100, "body").unwrap(), b"done");
        let seen = handle.join().unwrap();
        assert!(seen[1].starts_with("GET /b "), "{}", seen[1]);
    }

    #[test]
    fn same_origin_rule_returns_a_foreign_redirect_and_keeps_307_bodies() {
        let (port, handle) = serve(vec![
            redirect("/v1/next", "307 Temporary Redirect"),
            redirect("http://evil.example/steal", "302 Found"),
        ]);
        let client = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            same_origin_redirects: true,
            ..Default::default()
        })
        .unwrap();
        let resp = client
            .post(&format!("http://127.0.0.1:{port}/v1/start"))
            .header("X-Vault-Token", "s.secret")
            .json(&serde_json::json!({"a": 1}))
            .send()
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND, "the foreign redirect is not followed");
        let seen = handle.join().unwrap();
        assert!(
            seen[1].starts_with("POST /v1/next "),
            "307 keeps the method: {}",
            seen[1]
        );
        assert!(seen[1].contains("{\"a\":1}"), "307 keeps the body: {}", seen[1]);
        assert!(seen[1].to_ascii_lowercase().contains("x-vault-token: s.secret"));
    }

    #[test]
    fn extension_methods_and_error_statuses_are_returned() {
        let (port, handle) = serve(vec![
            "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_string(),
        ]);
        let client = blocking_client(&HttpClientOptions::default()).unwrap();
        let resp = client
            .request(
                Method::from_bytes(b"LIST").unwrap(),
                &format!("http://127.0.0.1:{port}/v1/x"),
            )
            .send()
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(handle.join().unwrap()[0].starts_with("LIST /v1/x "));
    }

    #[test]
    fn read_capped_rejects_oversized_bodies() {
        let (port, _h) = serve(vec![ok("0123456789")]);
        let client = blocking_client(&HttpClientOptions::default()).unwrap();
        let resp = client.get(&format!("http://127.0.0.1:{port}/")).send().unwrap();
        let err = read_capped(resp, 4, "thing").unwrap_err().to_string();
        assert!(err.contains("thing too large"), "{err}");
    }

    #[test]
    fn connection_refused_is_a_connect_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let client = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        })
        .unwrap();
        let err = client.get(&format!("http://127.0.0.1:{port}/")).send().unwrap_err();
        assert!(err.is_connect(), "{err}");
    }

    #[test]
    fn pinned_host_is_dialled_at_the_checked_address() {
        let (port, handle) = serve(vec![ok("pinned")]);
        let pinned: crate::netpolicy::PinnedHost = ("issuer.invalid".to_string(), vec!["127.0.0.1:1".parse().unwrap()]);
        let client = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            pinned: Some(&pinned),
            ..Default::default()
        })
        .unwrap();
        let resp = client
            .get(&format!("http://issuer.invalid:{port}/ca.crt"))
            .send()
            .unwrap();
        assert_eq!(read_capped(resp, 100, "body").unwrap(), b"pinned");
        assert!(
            handle.join().unwrap()[0]
                .to_ascii_lowercase()
                .contains("host: issuer.invalid")
        );
    }

    #[test]
    fn https_to_a_plain_server_fails_as_a_connect_error() {
        let (port, _h) = serve(vec![ok("not tls")]);
        let client = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        })
        .unwrap();
        let err = client.get(&format!("https://127.0.0.1:{port}/")).send().unwrap_err();
        assert!(err.is_connect(), "{err}");
    }

    #[test]
    fn client_rejects_invalid_proxy_url() {
        let proxy = ProxyConfig {
            https_proxy: Some("not a url".to_string()),
            http_proxy: None,
            no_proxy: String::new(),
        };
        let opts = HttpClientOptions {
            proxy: Some(&proxy),
            ..Default::default()
        };
        let err = blocking_client(&opts).unwrap_err().to_string();
        assert!(err.contains("invalid https proxy"), "{err}");
    }

    #[test]
    fn proxy_is_used_unless_no_proxy_matches() {
        let (port, handle) = serve(vec![ok("via proxy")]);
        let proxy = ProxyConfig {
            https_proxy: None,
            http_proxy: Some(format!("http://127.0.0.1:{port}")),
            no_proxy: "skip.example".to_string(),
        };
        let client = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            proxy: Some(&proxy),
            ..Default::default()
        })
        .unwrap();
        let resp = client.get("http://upstream.example/x").send().unwrap();
        assert_eq!(read_capped(resp, 100, "body").unwrap(), b"via proxy");
        let seen = handle.join().unwrap();
        assert!(
            seen[0].starts_with("GET http://upstream.example/x HTTP/1.1\r\n"),
            "{}",
            seen[0]
        );
        assert!(std::ptr::eq(
            client.agent_for(&url::Url::parse("http://skip.example/").unwrap()),
            &client.direct
        ));
    }

    #[test]
    fn forward_proxy_credentials_are_sent() {
        let (port, handle) = serve(vec![ok("ok")]);
        let proxy = ProxyConfig {
            https_proxy: None,
            http_proxy: Some(format!("http://user:p%40ss@127.0.0.1:{port}")),
            no_proxy: String::new(),
        };
        let client = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            proxy: Some(&proxy),
            ..Default::default()
        })
        .unwrap();
        client.get("http://upstream.example:8080/a?b=1").send().unwrap();
        let seen = handle.join().unwrap();
        assert!(
            seen[0].starts_with("GET http://upstream.example:8080/a?b=1 HTTP/1.1\r\n"),
            "{}",
            seen[0]
        );
        // base64("user:p@ss")
        assert!(
            seen[0].contains("Proxy-Authorization: Basic dXNlcjpwQHNz\r\n"),
            "{}",
            seen[0]
        );
    }

    #[test]
    fn absolute_form_rewrites_only_origin_form_request_lines() {
        let out = absolute_form(b"GET /p HTTP/1.1\r\nhost: h\r\n\r\n", b"http://h", None).unwrap();
        assert_eq!(out, b"GET http://h/p HTTP/1.1\r\nhost: h\r\n\r\n");
        assert!(absolute_form(b"GET http://h/p HTTP/1.1\r\n", b"http://h", None).is_none());
        assert!(
            absolute_form(b"GET /p HTTP/1.1", b"http://h", None).is_none(),
            "no CRLF"
        );
    }

    /// A self-signed certificate for `localhost` and 127.0.0.1, and its key.
    fn self_signed() -> (X509, openssl::pkey::PKey<openssl::pkey::Private>) {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::x509::extension::SubjectAlternativeName;
        let key = openssl::pkey::PKey::from_ec_key(
            openssl::ec::EcKey::generate(
                &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .ip("127.0.0.1")
            .build(&b.x509v3_context(None, None))
            .unwrap();
        b.append_extension(san).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

    /// Serve one HTTPS request per entry of `count` with the given certificate.
    fn serve_tls(cert: X509, key: openssl::pkey::PKey<openssl::pkey::Private>, count: usize) -> u16 {
        let mut acceptor = openssl::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        acceptor.set_private_key(&key).unwrap();
        let acceptor = acceptor.build();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for _ in 0..count {
                let Ok((tcp, _)) = listener.accept() else { break };
                if let Ok(mut tls) = acceptor.accept(tcp) {
                    let mut buf = [0u8; 4096];
                    let _ = tls.read(&mut buf);
                    let _ = tls.write_all(ok("secure").as_bytes());
                    let _ = tls.shutdown();
                }
            }
        });
        port
    }

    #[test]
    fn tls_verifies_against_openssl_trust_and_the_extra_ca_file() {
        let (cert, key) = self_signed();
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        fs::write(&ca, cert.to_pem().unwrap()).unwrap();
        let port = serve_tls(cert, key, 3);
        let url = format!("https://localhost:{port}/");

        let untrusted = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        })
        .unwrap();
        let err = untrusted.get(&url).send().unwrap_err();
        assert!(err.is_connect(), "{err}");
        assert!(err.to_string().contains("certificate verify failed"), "{err}");

        let trusted = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            ca_file: ca.to_str(),
            ..Default::default()
        })
        .unwrap();
        let resp = trusted.get(&url).send().unwrap();
        assert_eq!(read_capped(resp, 100, "body").unwrap(), b"secure");

        let insecure = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            accept_invalid_certs: true,
            ..Default::default()
        })
        .unwrap();
        let resp = insecure.get(&url).send().unwrap();
        assert_eq!(read_capped(resp, 100, "body").unwrap(), b"secure");
    }

    #[test]
    fn tls_checks_the_host_name() {
        let (cert, key) = self_signed();
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        fs::write(&ca, cert.to_pem().unwrap()).unwrap();
        let port = serve_tls(cert, key, 1);
        let pinned: crate::netpolicy::PinnedHost = ("wrong.example".to_string(), vec!["127.0.0.1:1".parse().unwrap()]);
        let client = blocking_client(&HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            ca_file: ca.to_str(),
            pinned: Some(&pinned),
            ..Default::default()
        })
        .unwrap();
        let err = client
            .get(&format!("https://wrong.example:{port}/"))
            .send()
            .unwrap_err();
        assert!(err.is_connect(), "{err}");
    }

    #[test]
    fn ca_dir_skips_unparseable_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("junk.pem"), "not a certificate").unwrap();
        fs::write(dir.path().join("ignored.txt"), "x").unwrap();
        let certs = load_ca_dir(dir.path().to_str().unwrap()).unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn ca_file_reports_missing_file() {
        let err = load_ca_file("/definitely/missing.pem").unwrap_err().to_string();
        assert!(err.contains("Failed to read CA certificate file"), "{err}");
    }

    #[test]
    fn ca_file_reports_empty_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.pem");
        fs::write(&p, "").unwrap();
        let err = load_ca_file(p.to_str().unwrap()).unwrap_err().to_string();
        assert!(err.contains("No certificates found"), "{err}");
    }
}
