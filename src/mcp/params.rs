//! Tool parameter types for the certificate, conversion and CSR tools.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::validate::validate_path;

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
    pub(crate) fn validate(&self) -> Result<(), String> {
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
        // Validate paths
        if let Some(ref p) = self.client_cert {
            validate_path(p, "client_cert")?;
        }
        if let Some(ref p) = self.client_key {
            validate_path(p, "client_key")?;
        }
        if let Some(ref p) = self.pkcs12 {
            validate_path(p, "pkcs12")?;
        }
        if let Some(ref p) = self.ca_cert {
            validate_path(p, "ca_cert")?;
        }
        Ok(())
    }

    pub(crate) fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(ref p) = self.client_cert {
            args.push("--client-cert".to_string());
            args.push(p.clone());
        }
        if let Some(ref p) = self.client_key {
            args.push("--client-key".to_string());
            args.push(p.clone());
        }
        if let Some(ref p) = self.pkcs12 {
            args.push("--pkcs12".to_string());
            args.push(p.clone());
        }
        // cert_password is passed via DCERT_CERT_PASSWORD env var (see run_dcert_with_env)
        // to avoid exposing it in process listings.
        if let Some(ref p) = self.ca_cert {
            args.push("--ca-cert".to_string());
            args.push(p.clone());
        }
        args
    }

    /// Returns env vars to set on the subprocess for secret parameters.
    pub(crate) fn env_vars(&self) -> Vec<(&str, &str)> {
        let mut vars = Vec::new();
        if let Some(ref p) = self.cert_password {
            vars.push(("DCERT_CERT_PASSWORD", p.as_str()));
        }
        vars
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
    /// OpenSSL cipher string for TLS 1.2 and below (e.g. "ECDHE+AESGCM:CHACHA20")
    #[serde(default)]
    pub(crate) cipher_list: Option<String>,
    /// Colon-separated IANA cipher names for TLS 1.3 (e.g. "TLS_AES_256_GCM_SHA384")
    #[serde(default)]
    pub(crate) cipher_suites: Option<String>,
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
    /// environment variables the server inherited. Must be http:// or https://;
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
    /// Show negotiated cipher in "iana" or "openssl" notation
    #[serde(default)]
    pub(crate) ciphers_notation: Option<String>,
    /// STARTTLS protocol: "smtp", "imap", "pop3", "ftp". When set, target is treated as host[:port]
    #[serde(default)]
    pub(crate) starttls: Option<String>,
}

impl HttpTlsParams {
    pub(crate) fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(ref headers) = self.headers {
            for h in headers {
                args.push("--header".to_string());
                args.push(h.clone());
            }
        }
        if let Some(ref v) = self.cipher_list {
            args.push("--cipher-list".to_string());
            args.push(v.clone());
        }
        if let Some(ref v) = self.cipher_suites {
            args.push("--cipher-suites".to_string());
            args.push(v.clone());
        }
        if let Some(ref v) = self.sni {
            args.push("--sni".to_string());
            args.push(v.clone());
        }
        for spec in self.connect_to.iter().flat_map(OneOrMany::values) {
            args.push("--connect-to".to_string());
            args.push(spec.to_string());
        }
        for spec in self.resolve.iter().flat_map(OneOrMany::values) {
            args.push("--resolve".to_string());
            args.push(spec.to_string());
        }
        if let Some(v) = self.timeout {
            args.push("--timeout".to_string());
            args.push(v.to_string());
        }
        if let Some(v) = self.read_timeout {
            args.push("--read-timeout".to_string());
            args.push(v.to_string());
        }
        if let Some(ref v) = self.method {
            args.push("--method".to_string());
            args.push(v.clone());
        }
        if let Some(ref v) = self.data {
            args.push("--data".to_string());
            args.push(v.clone());
        }
        if let Some(ref v) = self.http_protocol {
            args.push("--http-protocol".to_string());
            args.push(v.clone());
        }
        if let Some(ref v) = self.ciphers_notation {
            args.push("--ciphers".to_string());
            args.push(v.clone());
        }
        if let Some(ref v) = self.starttls {
            args.push("--starttls".to_string());
            args.push(v.clone());
        }
        args
    }

    /// Proxy settings travel as environment variables rather than argv: a proxy
    /// URL may carry credentials, and argv is world-readable via `ps`. This is
    /// the same treatment `MtlsParams` gives `DCERT_CERT_PASSWORD`.
    pub(crate) fn env_vars(&self) -> Vec<(&str, &str)> {
        let mut vars = Vec::new();
        if let Some(ref p) = self.proxy {
            vars.push(("DCERT_PROXY", p.as_str()));
        }
        if let Some(ref n) = self.noproxy {
            vars.push(("DCERT_NOPROXY", n.as_str()));
        }
        vars
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
            if spec.trim().is_empty() {
                return Err(format!("{label} entries must not be empty"));
            }
            if spec.starts_with('-') {
                return Err(format!("{label} value '{spec}' must not start with '-'"));
            }
            if spec.contains('\0') {
                return Err(format!("{label} value must not contain null bytes"));
            }
        }
        if let Some(ref proxy) = self.proxy
            && (proxy.starts_with('-') || proxy.contains('\0'))
        {
            return Err("proxy must not start with '-' or contain null bytes".to_string());
        }
        if let Some(ref noproxy) = self.noproxy
            && (noproxy.starts_with('-') || noproxy.contains('\0'))
        {
            return Err("noproxy must not start with '-' or contain null bytes".to_string());
        }
        Ok(())
    }
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
    /// Minimum TLS version: "1.2" or "1.3"
    pub(crate) min_tls: Option<String>,
    /// Maximum TLS version: "1.2" or "1.3"
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
    /// Allow non-CA (leaf/server) certificates in the truststore. Defaults to
    /// `true` here to preserve the prior MCP behaviour of accepting any
    /// parseable PEM. The CLI defaults to `false` (strict) so human users get
    /// loud, actionable feedback. Agents can pass `false` to opt into strict
    /// mode and surface the same guidance to their callers.
    #[serde(default = "default_true")]
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

pub(crate) fn default_rsa_4096() -> String {
    "rsa-4096".to_string()
}

pub(crate) fn default_true() -> bool {
    true
}
pub(crate) fn default_30() -> u64 {
    30
}
pub(crate) fn default_dot() -> String {
    ".".to_string()
}
pub(crate) fn default_server() -> String {
    "server".to_string()
}
pub(crate) fn default_changeit() -> String {
    "changeit".to_string()
}
pub(crate) fn default_vault_mount() -> String {
    "vault_intermediate".to_string()
}
pub(crate) fn default_ttl() -> String {
    "8760h".to_string()
}
pub(crate) fn default_kv_version() -> u8 {
    1
}
pub(crate) fn default_cert_key_name() -> String {
    "cert".to_string()
}
pub(crate) fn default_key_key_name() -> String {
    "key".to_string()
}
