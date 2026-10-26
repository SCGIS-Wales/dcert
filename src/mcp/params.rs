//! Tool parameter types for the certificate, conversion and CSR tools.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::cliargs::{ArgBuilder, ToCliArgs};
use crate::validate::{parse_enum, reject_flag_like, validate_arg, validate_path};
use dcert::limits::{self, READ_TIMEOUT_RANGE, TIMEOUT_RANGE, check_range};

// -- Parameter types --

/// mTLS parameters shared across check-based tools.
#[derive(Debug, Deserialize, JsonSchema, Default)]
pub(crate) struct MtlsParams {
    /// Client certificate PEM file path for mutual TLS authentication
    #[serde(default)]
    pub(crate) client_cert: Option<String>,
    /// Client private key PEM file path for mutual TLS (must be used with client_cert)
    #[serde(default)]
    pub(crate) client_key: Option<String>,
    /// PKCS12/PFX file containing client cert + key (alternative to client_cert/client_key)
    #[serde(default)]
    pub(crate) pkcs12: Option<String>,
    /// Password for the PKCS12 file
    #[serde(default)]
    pub(crate) cert_password: Option<String>,
    /// Custom CA certificate bundle PEM file (overrides system CAs)
    #[serde(default)]
    pub(crate) ca_cert: Option<String>,
}

impl MtlsParams {
    pub(crate) fn validate(&mut self) -> Result<(), String> {
        // client_cert and client_key must both be set or both absent
        match (&self.client_cert, &self.client_key) {
            (Some(_), None) => return Err("client_cert requires client_key".to_string()),
            (None, Some(_)) => return Err("client_key requires client_cert".to_string()),
            _ => {}
        }
        // client_cert/client_key and pkcs12 are mutually exclusive
        if self.client_cert.is_some() && self.pkcs12.is_some() {
            return Err("client_cert/client_key and pkcs12 are mutually exclusive".to_string());
        }
        // Confine every path and replace it with the canonical form the
        // child is given.
        for (value, name) in [
            (&mut self.client_cert, "client_cert"),
            (&mut self.client_key, "client_key"),
            (&mut self.pkcs12, "pkcs12"),
            (&mut self.ca_cert, "ca_cert"),
        ] {
            if let Some(p) = value.as_mut() {
                *p = validate_path(p, name)?;
            }
        }
        Ok(())
    }
}

impl ToCliArgs for MtlsParams {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
        out.value("client-cert", self.client_cert.as_deref())
            .value("client-key", self.client_key.as_deref())
            .value("pkcs12", self.pkcs12.as_deref())
            .value("ca-cert", self.ca_cert.as_deref())
            // The password travels in the environment, never in argv.
            .env("DCERT_CERT_PASSWORD", self.cert_password.as_deref());
    }
}

/// A parameter that accepts either one value or a list of them.
///
/// The repeatable connection-override flags are far more often used once than
/// many times, so requiring an array for the common case would be needless
/// ceremony for callers.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
pub(crate) enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub(crate) fn values(&self) -> Vec<&str> {
        match self {
            OneOrMany::One(v) => vec![v.as_str()],
            OneOrMany::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

/// Optional HTTP/TLS parameters shared across check-related MCP tools.
/// These mirror the CLI flags that were previously only available on the command line.
#[derive(Debug, Deserialize, JsonSchema, Default)]
pub(crate) struct HttpTlsParams {
    /// Custom HTTP headers as "Key:Value" strings (repeatable)
    #[serde(default)]
    pub(crate) headers: Option<Vec<String>>,
    /// Cipher suites to offer, each in any notation: IANA name
    /// ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"), OpenSSL name
    /// ("ECDHE-RSA-AES128-GCM-SHA256") or code point ("0xC02F", "C02F",
    /// "0xC0,0x2F"). A single string or a list; TLS 1.2 and 1.3 suites may be
    /// mixed. Naming one family only limits the handshake to that version.
    /// Cannot be combined with `cipher_list` or `cipher_suites`.
    #[serde(default)]
    pub(crate) cipher: Option<OneOrMany>,
    /// OpenSSL cipher string for TLS 1.2 and below (e.g. "ECDHE+AESGCM:CHACHA20"), passed as is
    #[serde(default)]
    pub(crate) cipher_list: Option<String>,
    /// Colon-separated IANA cipher names for TLS 1.3 (e.g. "TLS_AES_256_GCM_SHA384")
    #[serde(default)]
    pub(crate) cipher_suites: Option<String>,
    /// Key exchange groups to offer, as an OpenSSL group list
    /// (e.g. "X25519MLKEM768:X25519:secp384r1"). RFC 10024 post quantum
    /// hybrids need OpenSSL 3.5 or later on the dcert host.
    #[serde(default)]
    pub(crate) groups: Option<String>,
    /// Named TLS client profile: "modern" (TLS 1.3 only) or "intermediate"
    /// (TLS 1.2 and 1.3, forward secret AEAD suites), following the Mozilla
    /// configurator v6. Explicit cipher, suite and group values win.
    #[serde(default)]
    pub(crate) tls_profile: Option<String>,
    /// Run a second handshake offering only the RFC 10024 hybrid post quantum
    /// groups and report whether the server supports post quantum key
    /// agreement (`post_quantum_probe` in the connection block).
    #[serde(default)]
    pub(crate) pq_probe: Option<bool>,
    /// Override the SNI (Server Name Indication) hostname sent in the TLS
    /// handshake. Most callers do NOT need this. To connect to an IP while
    /// validating a hostname, prefer `connect_to` (keep the hostname in
    /// `target`); use `sni` only to send a SNI value that differs from the
    /// validated hostname. Example: target='https://10.0.0.5', sni='api.example.com'.
    #[serde(default)]
    pub(crate) sni: Option<String>,
    /// Redirect the connection to another host or IP while `target`'s hostname
    /// is still used for SNI, the Host header and certificate validation. Use
    /// this to analyze a specific server/backend behind a load balancer or DNS
    /// round-robin, or when the hostname does not resolve from here. Accepts a
    /// bare IP address, or curl's "HOST1:PORT1:HOST2:PORT2" form (empty fields
    /// mean any/unchanged) when the destination is a hostname or a different
    /// port. A single string or a list of strings. Like curl's --connect-to.
    /// Examples: target='https://api.example.com' with connect_to='10.0.0.5',
    /// or connect_to='api.example.com:443:origin.internal:8443'.
    #[serde(default)]
    pub(crate) connect_to: Option<OneOrMany>,
    /// Pin "HOST:PORT" to specific IP addresses instead of using DNS, like
    /// curl's --resolve. The hostname is still used for SNI, the Host header
    /// and certificate validation. Format "HOST:PORT:ADDRESS", where HOST may
    /// be "*" and ADDRESS may be several comma-separated IPs tried in order.
    /// Only IP addresses are accepted here — use `connect_to` for a hostname.
    /// A single string or a list of strings.
    /// Example: 'api.example.com:443:10.0.0.5'.
    #[serde(default)]
    pub(crate) resolve: Option<OneOrMany>,
    /// Forward proxy URL for this request, overriding the HTTPS_PROXY/HTTP_PROXY
    /// environment variables the server inherited. Must be http:// (https://
    /// proxies are refused until TLS to the proxy is implemented);
    /// credentials may be embedded (http://user:pass@proxy.corp:3128). Pass an
    /// empty string to force a direct connection. Note that `connect_to` and
    /// `resolve` always bypass the proxy.
    #[serde(default)]
    pub(crate) proxy: Option<String>,
    /// Comma-separated hosts that must bypass the proxy, overriding NO_PROXY.
    /// "*" bypasses the proxy entirely; an empty string clears an inherited
    /// NO_PROXY. Like curl's --noproxy.
    #[serde(default)]
    pub(crate) noproxy: Option<String>,
    /// Connection timeout in seconds (default: 10)
    #[serde(default)]
    pub(crate) timeout: Option<u64>,
    /// Read timeout in seconds (default: 5)
    #[serde(default)]
    pub(crate) read_timeout: Option<u64>,
    /// HTTP method: "GET", "POST", "HEAD", "OPTIONS" (default: GET)
    #[serde(default)]
    pub(crate) method: Option<String>,
    /// Request body data string (implies POST if method is GET)
    #[serde(default)]
    pub(crate) data: Option<String>,
    /// HTTP protocol version: "http1-1" or "http2" (default: http1-1)
    #[serde(default)]
    pub(crate) http_protocol: Option<String>,
    /// How the negotiated cipher is reported: "all" (default; a record with
    /// the OpenSSL and IANA names, code point, protocol, forward secrecy and
    /// AEAD), or "iana" or "openssl" for that name alone
    #[serde(default)]
    pub(crate) ciphers_notation: Option<String>,
    /// STARTTLS protocol: "smtp", "imap", "pop3", "ftp". When set, target is treated as host[:port]
    #[serde(default)]
    pub(crate) starttls: Option<String>,
    /// Allow TLS 1.0 and 1.1 (deprecated by RFC 8996) at OpenSSL security
    /// level 0 for this probe. With no minimum version given, the probe
    /// then also offers TLS 1.0 and 1.1 (default: false)
    #[serde(default)]
    pub(crate) allow_legacy_tls: Option<bool>,
}

/// Upper bound on the request body a tool call may send (1 MiB), so a client
/// cannot make the server allocate or write without bound. The body reaches
/// the subprocess through a private file, not argv.
pub(crate) const MAX_DATA_LEN: usize = 1024 * 1024;

/// Write `contents` to a new temporary file readable only by this user.
fn private_file(kind: &str, contents: &[u8]) -> Result<tempfile::NamedTempFile, String> {
    use std::io::Write as _;
    let mut file = tempfile::Builder::new()
        .prefix(&format!("dcert-mcp-{kind}-"))
        .tempfile()
        .map_err(|e| format!("cannot create the {kind} file: {e}"))?;
    file.write_all(contents)
        .and_then(|()| file.flush())
        .map_err(|e| format!("cannot write the {kind} file: {e}"))?;
    Ok(file)
}

/// The file's path as an argument.
fn path_arg(file: &tempfile::NamedTempFile) -> Result<String, String> {
    file.path()
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| "temporary file path is not valid UTF-8".to_string())
}

impl ToCliArgs for HttpTlsParams {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
        out.repeat("cipher", self.cipher.iter().flat_map(OneOrMany::values))
            .value("cipher-list", self.cipher_list.as_deref())
            .value("cipher-suites", self.cipher_suites.as_deref())
            .value("groups", self.groups.as_deref())
            .value("tls-profile", self.tls_profile.as_deref())
            .flag("pq-probe", self.pq_probe == Some(true))
            .flag("allow-legacy-tls", self.allow_legacy_tls == Some(true))
            .value("sni", self.sni.as_deref())
            .repeat("connect-to", self.connect_to.iter().flat_map(OneOrMany::values))
            .repeat("resolve", self.resolve.iter().flat_map(OneOrMany::values))
            .value("timeout", self.timeout)
            .value("read-timeout", self.read_timeout)
            .value("method", self.method.as_deref())
            .value("http-protocol", self.http_protocol.as_deref())
            .value("cipher-notation", self.ciphers_notation.as_deref())
            .value("starttls", self.starttls.as_deref())
            // A proxy URL may carry credentials, so proxy settings travel in
            // the environment like DCERT_CERT_PASSWORD.
            .env(dcert::proxy::DCERT_PROXY_ENV, self.proxy.as_deref())
            .env(dcert::proxy::DCERT_NOPROXY_ENV, self.noproxy.as_deref());
    }
}

impl HttpTlsParams {
    /// Headers and the request body travel in private temporary files
    /// (mode 0600 on Unix) passed as `--headers-file` and `--data-file`,
    /// never in argv: argv is readable by every local user through `ps` and
    /// `/proc`, and a single argument is capped at 128 KiB on Linux. The
    /// returned files must outlive the child, so the caller keeps them.
    pub(crate) fn secret_files(&self) -> Result<(Vec<String>, Vec<tempfile::NamedTempFile>), String> {
        let mut args = Vec::new();
        let mut files = Vec::new();
        let headers = self.headers.as_deref().unwrap_or_default();
        if !headers.is_empty() {
            let mut text = headers.join("\n");
            text.push('\n');
            let file = private_file("headers", text.as_bytes())?;
            args.extend(["--headers-file".to_string(), path_arg(&file)?]);
            files.push(file);
        }
        if let Some(ref data) = self.data {
            let file = private_file("data", data.as_bytes())?;
            args.extend(["--data-file".to_string(), path_arg(&file)?]);
            files.push(file);
        }
        Ok((args, files))
    }

    /// Reject values that could smuggle extra flags into the dcert subprocess.
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (label, spec) in self
            .connect_to
            .iter()
            .flat_map(OneOrMany::values)
            .map(|s| ("connect_to", s))
            .chain(self.resolve.iter().flat_map(OneOrMany::values).map(|s| ("resolve", s)))
        {
            reject_flag_like(spec, label)?;
        }
        if let Some(ref proxy) = self.proxy
            && !proxy.is_empty()
        {
            validate_arg(proxy, "proxy")?;
        }
        if let Some(ref noproxy) = self.noproxy
            && !noproxy.is_empty()
        {
            validate_arg(noproxy, "noproxy")?;
        }
        for h in self.headers.iter().flatten() {
            validate_arg(h, "headers")?;
            if !h.contains(':') {
                return Err(format!("headers entry '{h}' must be in Key:Value form"));
            }
        }
        if let Some(ref groups) = self.groups {
            dcert::keyex::validate_groups_list(groups).map_err(|e| e.replace("--groups", "groups"))?;
        }
        // Enumerated values are checked against the CLI's own enums, with
        // the same case rule as the matching flag.
        if let Some(ref v) = self.tls_profile {
            parse_enum::<dcert::keyex::TlsProfile>("tls_profile", v, false)?;
        }
        if let Some(ref v) = self.starttls {
            parse_enum::<dcert::cli::StarttlsProtocol>("starttls", v, false)?;
        }
        if let Some(ref v) = self.method {
            parse_enum::<dcert::cli::HttpMethod>("method", v, true)?;
        }
        if let Some(ref v) = self.http_protocol {
            parse_enum::<dcert::cli::HttpProtocol>("http_protocol", v, false)?;
        }
        if let Some(ref v) = self.ciphers_notation {
            parse_enum::<dcert::cli::CipherNotation>("ciphers_notation", v, false)?;
        }
        if let Some(ref ciphers) = self.cipher {
            if self.cipher_list.is_some() || self.cipher_suites.is_some() {
                return Err("cipher cannot be combined with cipher_list or cipher_suites".to_string());
            }
            for value in ciphers.values() {
                dcert::ciphers::parse_cipher_arg(value).map_err(|e| format!("cipher: {e}"))?;
            }
        }
        for (name, value) in [
            ("cipher_list", &self.cipher_list),
            ("cipher_suites", &self.cipher_suites),
            ("sni", &self.sni),
            ("method", &self.method),
            ("http_protocol", &self.http_protocol),
            ("ciphers_notation", &self.ciphers_notation),
            ("starttls", &self.starttls),
        ] {
            if let Some(v) = value {
                validate_arg(v, name)?;
            }
        }
        // The body travels in a file, so any content is safe; only its size
        // is bounded.
        if let Some(ref data) = self.data
            && data.len() > MAX_DATA_LEN
        {
            return Err(format!(
                "data is too large ({} bytes, maximum {MAX_DATA_LEN})",
                data.len()
            ));
        }
        if let Some(t) = self.timeout {
            check_range("timeout", t, &TIMEOUT_RANGE)?;
        }
        if let Some(t) = self.read_timeout {
            check_range("read_timeout", t, &READ_TIMEOUT_RANGE)?;
        }
        Ok(())
    }
}

/// Parameters for the diagnose_endpoint tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct DiagnoseEndpointParams {
    /// HTTPS URL or hostname to probe (a gateway, CDN, origin or any TLS endpoint)
    pub(crate) target: String,
    /// Include the captured response body excerpt in the output even when no finding cites it (default: false)
    #[serde(default)]
    pub(crate) show_body: bool,
    /// Accept the server certificate without verification so the HTTP layer can still be probed
    /// (default: false). Refused unless the server sets DCERT_MCP_ALLOW_NO_VERIFY=1.
    #[serde(default)]
    pub(crate) no_verify: bool,
    /// mTLS client identity and custom CA
    #[serde(flatten, default)]
    pub(crate) mtls: MtlsParams,
    /// Connection, proxy and HTTP request options
    #[serde(flatten, default)]
    pub(crate) http_tls: HttpTlsParams,
}

/// Parameters for the explain_edge_term tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ExplainEdgeTermParams {
    /// What to look up: an HTTP status code (502), a response header (x-cache, x-amzn-errortype), a CloudFront or API Gateway API exception (NoSuchDistribution, ForbiddenException), a gateway response type (INTEGRATION_TIMEOUT), or a topic keyword (viewer-mtls, passthrough, truststore, origin-mtls, signed url)
    pub(crate) query: String,
    /// Restrict the answer to one service: "cloudfront" or "api_gateway" (default: both)
    #[serde(default)]
    pub(crate) service: Option<String>,
}

/// Parameters for the list_cipher_suites tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ListCipherSuitesParams {
    /// Only suites of this protocol family: "1.2" (TLS 1.2 and earlier) or "1.3"
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    /// Only suites the server's linked OpenSSL can offer (default: false)
    #[serde(default)]
    pub(crate) offerable: bool,
}

/// Parameters for the explain_cipher_suite tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ExplainCipherSuiteParams {
    /// The suite in any notation: IANA name (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256), OpenSSL name (ECDHE-RSA-AES128-GCM-SHA256) or code point (0xC02F, C02F, 0xC0,0x2F); case insensitive
    pub(crate) suite: String,
}

/// Parameters for the analyze_certificate tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct AnalyzeCertificateParams {
    /// HTTPS URL, hostname, or local path to a PEM file. Bare hostnames are auto-converted to https://
    pub(crate) target: String,
    /// Include SHA-256 fingerprints (default: true)
    #[serde(default = "default_true")]
    pub(crate) fingerprint: bool,
    /// Include certificate extensions such as key usage, basic constraints, etc. (default: true)
    #[serde(default = "default_true")]
    pub(crate) extensions: bool,
    /// Check OCSP revocation status (default: false)
    #[serde(default)]
    pub(crate) check_revocation: bool,
    /// Skip the root-CA trust classification (publicly trusted vs private PKI
    /// vs self-signed). Classification is on by default and runs fully offline;
    /// set true to omit the `root_trust` object. (default: false)
    #[serde(default)]
    pub(crate) no_trust_check: bool,
    /// For chains that do not anchor to a publicly trusted root, follow the
    /// Authority Information Access "CA Issuers" URLs over the network to fetch
    /// missing issuer certificates — completing the chain and probing whether a
    /// private CA backend is reachable. Off by default. Honours forward-proxy
    /// environment variables (http_proxy/https_proxy/no_proxy). (default: false)
    #[serde(default)]
    pub(crate) resolve_issuers: bool,
    /// Short connect/read timeout in seconds for issuer (`resolve_issuers`) and
    /// public-root refresh fetches. Kept low so batches fail fast. (default: 2)
    #[serde(default)]
    pub(crate) issuer_timeout: Option<u64>,
    /// Refresh the embedded Mozilla/CCADB public root set from the upstream
    /// bundle (https://curl.se/ca/cacert.pem) and union it in for this run.
    /// Honours forward-proxy environment variables. (default: false)
    #[serde(default)]
    pub(crate) refresh_public_roots: bool,
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    pub(crate) mtls: MtlsParams,
    /// HTTP/TLS connection options
    #[serde(flatten, default)]
    pub(crate) http_tls: HttpTlsParams,
}

/// Parameters for the check_expiry tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct CheckExpiryParams {
    /// HTTPS URL, hostname, or local path to a PEM file. Bare hostnames are auto-converted to https://
    pub(crate) target: String,
    /// Warning threshold in days (default: 30)
    #[serde(default = "default_30")]
    pub(crate) days: u64,
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    pub(crate) mtls: MtlsParams,
    /// HTTP/TLS connection options
    #[serde(flatten, default)]
    pub(crate) http_tls: HttpTlsParams,
}

/// Parameters for the check_revocation tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct CheckRevocationParams {
    /// HTTPS URL, hostname, or local path to a PEM file. Bare hostnames are auto-converted to https://
    pub(crate) target: String,
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    pub(crate) mtls: MtlsParams,
    /// HTTP/TLS connection options
    #[serde(flatten, default)]
    pub(crate) http_tls: HttpTlsParams,
}

/// Parameters for the compare_certificates tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct CompareCertificatesParams {
    /// First HTTPS URL, hostname, or PEM file path
    pub(crate) target_a: String,
    /// Second HTTPS URL, hostname, or PEM file path
    pub(crate) target_b: String,
}

/// Parameters for the tls_connection_info tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct TlsConnectionInfoParams {
    /// HTTPS URL or hostname to inspect TLS connection details
    pub(crate) target: String,
    /// Minimum TLS version: "1.2" or "1.3"; "1.0" and "1.1" need `allow_legacy_tls`
    pub(crate) min_tls: Option<String>,
    /// Maximum TLS version: "1.2" or "1.3"; "1.0" and "1.1" need `allow_legacy_tls`
    pub(crate) max_tls: Option<String>,
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    pub(crate) mtls: MtlsParams,
    /// HTTP/TLS connection options
    #[serde(flatten, default)]
    pub(crate) http_tls: HttpTlsParams,
}

/// Parameters for the export_pem tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ExportPemParams {
    /// HTTPS URL or hostname to fetch the TLS certificate chain from
    pub(crate) target: String,
    /// Output file path to write the PEM chain (default: writes to stdout in response)
    #[serde(default)]
    pub(crate) output_path: Option<String>,
    /// Exclude expired certificates from the exported chain (default: false)
    #[serde(default)]
    pub(crate) exclude_expired: bool,
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    pub(crate) mtls: MtlsParams,
    /// HTTP/TLS connection options
    #[serde(flatten, default)]
    pub(crate) http_tls: HttpTlsParams,
}

/// Parameters for the verify_key_match tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct VerifyKeyMatchParams {
    /// PEM certificate file or HTTPS URL to verify against
    pub(crate) target: String,
    /// Private key PEM file path
    pub(crate) key_path: String,
}

/// Parameters for the verify_key_auto_discover tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct VerifyKeyAutoDiscoverParams {
    /// Directory to scan for matching cert/key pairs (default: current directory)
    #[serde(default = "default_dot")]
    pub(crate) dir: String,
}

/// Parameters for the convert_pfx_to_pem tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ConvertPfxToPemParams {
    /// Input PKCS12/PFX file path
    pub(crate) pkcs12_path: String,
    /// Password for the PKCS12 file
    pub(crate) password: String,
    /// Output directory for PEM files (default: current directory)
    #[serde(default = "default_dot")]
    pub(crate) output_dir: String,
}

/// Parameters for the convert_pem_to_pfx tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ConvertPemToPfxParams {
    /// PEM certificate file path
    pub(crate) cert_path: String,
    /// PEM private key file path
    pub(crate) key_path: String,
    /// Password for the output PKCS12 file
    pub(crate) password: String,
    /// Output PFX file path
    pub(crate) output_path: String,
    /// Optional CA certificate PEM file to include in the chain
    #[serde(default)]
    pub(crate) ca_path: Option<String>,
}

/// Parameters for the create_keystore tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct CreateKeystoreParams {
    /// PEM certificate file path (or chain)
    pub(crate) cert_path: String,
    /// PEM private key file path
    pub(crate) key_path: String,
    /// Password for the keystore
    pub(crate) password: String,
    /// Output PKCS12 keystore file path
    pub(crate) output_path: String,
    /// Alias for the key entry (default: "server")
    #[serde(default = "default_server")]
    pub(crate) alias: String,
}

/// Parameters for the create_truststore tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct CreateTruststoreParams {
    /// PEM file path(s) containing CA certificates to trust
    pub(crate) cert_paths: Vec<String>,
    /// Password for the truststore (default: "changeit")
    #[serde(default = "default_changeit")]
    pub(crate) password: String,
    /// Output PKCS12 truststore file path
    pub(crate) output_path: String,
    /// Allow non CA (leaf or server) certificates in the truststore. Defaults
    /// to `false`, matching the CLI, so a leaf is refused with actionable
    /// guidance instead of silently producing a truststore that trusts it.
    #[serde(default)]
    pub(crate) allow_non_ca: bool,
}

/// Parameters for the create_csr tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct CreateCsrParams {
    /// Common Name (CN) — typically the FQDN (e.g., "api.example.com")
    pub(crate) common_name: String,
    /// Organization name (O)
    #[serde(default)]
    pub(crate) organization: Option<String>,
    /// Organizational Unit(s) (OU) — supports metadata identifiers (e.g., "AppId:my-app-123").
    /// Note: OU is deprecated for publicly-trusted certificates since CA/B Forum Ballot SC47v2 (Sep 2022),
    /// but remains valid for internal/private PKI.
    #[serde(default)]
    pub(crate) organizational_units: Vec<String>,
    /// Two-letter ISO 3166-1 country code (e.g., "GB", "US")
    #[serde(default)]
    pub(crate) country: Option<String>,
    /// State or province name (ST)
    #[serde(default)]
    pub(crate) state: Option<String>,
    /// Locality or city name (L)
    #[serde(default)]
    pub(crate) locality: Option<String>,
    /// Email address for the certificate (rarely used in modern TLS)
    #[serde(default)]
    pub(crate) email: Option<String>,
    /// Subject Alternative Names in TYPE:VALUE format (e.g., "DNS:www.example.com", "IP:10.0.0.1").
    /// If empty, the CN is automatically added as a DNS SAN.
    #[serde(default)]
    pub(crate) subject_alternative_names: Vec<String>,
    /// Key algorithm: "rsa-4096" (default, strong), "rsa-2048" (minimum), "ecdsa-p256" (recommended, modern), "ecdsa-p384" (high-security), "ed25519" (modern EdDSA, compact signatures, requires OpenSSL 3.x)
    #[serde(default = "default_rsa_4096")]
    pub(crate) key_algorithm: String,
    /// Whether to encrypt the private key with AES-256-CBC (PKCS#8)
    #[serde(default)]
    pub(crate) encrypt_key: bool,
    /// Password for key encryption (required when encrypt_key is true)
    #[serde(default)]
    pub(crate) key_password: Option<String>,
    /// Output path for the CSR file
    pub(crate) csr_output_path: String,
    /// Output path for the private key file
    pub(crate) key_output_path: String,
}

/// Parameters for the validate_csr tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ValidateCsrParams {
    /// Path to the PEM-encoded CSR file to validate
    pub(crate) csr_file: String,
    /// Strict mode: treat warnings as errors (e.g., OU deprecation, RSA 2048 key size)
    #[serde(default)]
    pub(crate) strict: bool,
}

/// Parameters for the validate_certificate tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ValidateCertificateParams {
    /// HTTPS URL, hostname, or local path to a PEM file. Bare hostnames are auto-converted to https://
    pub(crate) target: String,
    /// mTLS and CA configuration
    #[serde(flatten, default)]
    pub(crate) mtls: MtlsParams,
}

// -- Probe tools: what each one sends to `dcert check` or `dcert diagnose` --

/// A tool that probes a target through `dcert check` (or `dcert diagnose`).
pub(crate) trait ProbeParams: ToCliArgs {
    /// The subcommand the tool runs.
    const SUBCOMMAND: &'static str = "check";

    fn target(&self) -> &str;

    /// The shared option groups, validated before the argv is built.
    fn groups(&mut self) -> (&mut MtlsParams, Option<&HttpTlsParams>);
}

/// Implement [`ProbeParams`] for a tool whose `mtls` and `http_tls` groups
/// are both flattened into its parameters.
macro_rules! probe_params {
    ($ty:ty $(, $sub:literal)?) => {
        impl ProbeParams for $ty {
            $(const SUBCOMMAND: &'static str = $sub;)?

            fn target(&self) -> &str {
                &self.target
            }

            fn groups(&mut self) -> (&mut MtlsParams, Option<&HttpTlsParams>) {
                (&mut self.mtls, Some(&self.http_tls))
            }
        }
    };
}
probe_params!(AnalyzeCertificateParams);
probe_params!(CheckExpiryParams);
probe_params!(CheckRevocationParams);
probe_params!(TlsConnectionInfoParams);
probe_params!(ExportPemParams);
probe_params!(DiagnoseEndpointParams, "diagnose");

impl ProbeParams for ValidateCertificateParams {
    fn target(&self) -> &str {
        &self.target
    }

    fn groups(&mut self) -> (&mut MtlsParams, Option<&HttpTlsParams>) {
        (&mut self.mtls, None)
    }
}

impl ToCliArgs for AnalyzeCertificateParams {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
        out.value("format", Some("json"))
            .flag("fingerprint", self.fingerprint)
            .flag("extensions", self.extensions)
            .flag("check-revocation", self.check_revocation)
            .flag("no-trust-check", self.no_trust_check)
            .flag("resolve-issuers", self.resolve_issuers)
            .value("issuer-timeout", self.issuer_timeout)
            .flag("refresh-public-roots", self.refresh_public_roots)
            .extend(&self.mtls)
            .extend(&self.http_tls);
    }
}

impl ToCliArgs for CheckExpiryParams {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
        out.value("format", Some("json"))
            .flag("fingerprint", true)
            .value("expiry-warn", Some(self.days))
            .extend(&self.mtls)
            .extend(&self.http_tls);
    }
}

impl ToCliArgs for CheckRevocationParams {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
        out.value("format", Some("json"))
            .flag("check-revocation", true)
            .flag("extensions", true)
            .extend(&self.mtls)
            .extend(&self.http_tls);
    }
}

impl ToCliArgs for TlsConnectionInfoParams {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
        out.value("format", Some("json"))
            .flag("fingerprint", true)
            .flag("extensions", true)
            .value("min-tls", self.min_tls.as_deref())
            .value("max-tls", self.max_tls.as_deref())
            .extend(&self.mtls)
            .extend(&self.http_tls);
    }
}

impl ToCliArgs for ExportPemParams {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
        // Without an output file the chain comes back in the JSON as
        // `pem_data` (`--export-pem=-`).
        out.value("format", Some("json"))
            .value("export-pem", Some(self.output_path.as_deref().unwrap_or("-")))
            .flag("exclude-expired", self.exclude_expired)
            .extend(&self.mtls)
            .extend(&self.http_tls);
    }
}

impl ToCliArgs for DiagnoseEndpointParams {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
        out.value("format", Some("json"))
            .flag("show-body", self.show_body)
            .flag("no-verify", self.no_verify)
            .extend(&self.mtls)
            .extend(&self.http_tls);
    }
}

impl ToCliArgs for ValidateCertificateParams {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
        out.value("format", Some("json"))
            .flag("compliance", true)
            .extend(&self.mtls);
    }
}

// Serde defaults. Each reads the one definition in `dcert::limits` that the
// CLI's clap defaults also use.

pub(crate) fn default_rsa_4096() -> String {
    "rsa-4096".to_string()
}

pub(crate) fn default_true() -> bool {
    true
}
pub(crate) fn default_30() -> u64 {
    limits::DEFAULT_EXPIRY_WARN_DAYS
}
pub(crate) fn default_dot() -> String {
    limits::DEFAULT_OUTPUT_DIR.to_string()
}
pub(crate) fn default_server() -> String {
    limits::DEFAULT_KEYSTORE_ALIAS.to_string()
}
pub(crate) fn default_changeit() -> String {
    limits::DEFAULT_TRUSTSTORE_PASSWORD.to_string()
}
pub(crate) fn default_vault_mount() -> String {
    limits::DEFAULT_VAULT_PKI_MOUNT.to_string()
}
pub(crate) fn default_ttl() -> String {
    limits::DEFAULT_VAULT_TTL.to_string()
}
pub(crate) fn default_kv_version() -> u8 {
    limits::DEFAULT_KV_VERSION
}
pub(crate) fn default_cert_key_name() -> String {
    limits::DEFAULT_KV_CERT_KEY.to_string()
}
pub(crate) fn default_key_key_name() -> String {
    limits::DEFAULT_KV_KEY_KEY.to_string()
}

/// Wipe secrets received as tool arguments once the request is done.
macro_rules! zeroize_on_drop {
    ($ty:ident, [$($field:ident),*], [$($opt:ident),*]) => {
        impl Drop for $ty {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                $( self.$field.zeroize(); )*
                $( if let Some(v) = self.$opt.as_mut() { v.zeroize(); } )*
            }
        }
    };
}
zeroize_on_drop!(ConvertPfxToPemParams, [password], []);
zeroize_on_drop!(ConvertPemToPfxParams, [password], []);
zeroize_on_drop!(CreateKeystoreParams, [password], []);
zeroize_on_drop!(CreateTruststoreParams, [password], []);
zeroize_on_drop!(CreateCsrParams, [], [key_password]);
zeroize_on_drop!(MtlsParams, [], [cert_password]);
