use clap::{Args, Parser, Subcommand, ValueEnum};
use openssl::ssl::SslVersion;

/// Return the version string for `--version` output.
///
/// Uses CARGO_PKG_VERSION from Cargo.toml, which is set to the correct
/// semver by the CI auto-tag job before building.
pub fn dcert_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Exit codes for machine-readable scripting.
pub mod exit_code {
    /// All certificates are valid and no warnings triggered.
    pub const SUCCESS: i32 = 0;
    /// At least one certificate is expiring soon (--expiry-warn threshold).
    pub const EXPIRY_WARNING: i32 = 1;
    /// A connection or processing error occurred.
    pub const ERROR: i32 = 2;
    /// TLS certificate verification failed.
    pub const VERIFY_FAILED: i32 = 3;
    /// At least one certificate in the chain is already expired.
    pub const CERT_EXPIRED: i32 = 4;
    /// At least one certificate has been revoked (OCSP).
    pub const CERT_REVOKED: i32 = 5;
    /// Client certificate error (invalid, unreadable, wrong password).
    #[allow(dead_code)]
    pub const CLIENT_CERT_ERROR: i32 = 6;
    /// Private key does not match the certificate.
    pub const KEY_MISMATCH: i32 = 7;
}

// -- Value enums --

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum StarttlsProtocol {
    /// SMTP STARTTLS (default port: 587)
    #[value(name = "smtp")]
    Smtp,
    /// IMAP STARTTLS (default port: 143)
    #[value(name = "imap")]
    Imap,
    /// POP3 STLS (default port: 110)
    #[value(name = "pop3")]
    Pop3,
    /// FTP AUTH TLS (default port: 21)
    #[value(name = "ftp")]
    Ftp,
}

impl StarttlsProtocol {
    /// Default port for each STARTTLS protocol.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Smtp => 587,
            Self::Imap => 143,
            Self::Pop3 => 110,
            Self::Ftp => 21,
        }
    }
}

impl std::fmt::Display for StarttlsProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Smtp => write!(f, "smtp"),
            Self::Imap => write!(f, "imap"),
            Self::Pop3 => write!(f, "pop3"),
            Self::Ftp => write!(f, "ftp"),
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum KeyAlgorithmArg {
    /// RSA 4096-bit — strong, widely compatible (default)
    #[value(name = "rsa-4096")]
    Rsa4096,
    /// RSA 2048-bit — minimum accepted by CAs
    #[value(name = "rsa-2048")]
    Rsa2048,
    /// ECDSA P-256 — modern, fast, recommended for new deployments
    #[value(name = "ecdsa-p256")]
    EcdsaP256,
    /// ECDSA P-384 — high-security, CNSA 2.0 compliant
    #[value(name = "ecdsa-p384")]
    EcdsaP384,
    /// Ed25519 — modern EdDSA, compact signatures, high performance (requires OpenSSL 3.x)
    #[value(name = "ed25519")]
    Ed25519,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
    Yaml,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum HttpProtocol {
    Http1_1,
    Http2,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum TlsVersionArg {
    #[value(name = "1.2")]
    Tls1_2,
    #[value(name = "1.3")]
    Tls1_3,
}

impl TlsVersionArg {
    pub fn to_ssl_version(self) -> SslVersion {
        match self {
            TlsVersionArg::Tls1_2 => SslVersion::TLS1_2,
            TlsVersionArg::Tls1_3 => SslVersion::TLS1_3,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TlsVersionArg::Tls1_2 => "TLS 1.2",
            TlsVersionArg::Tls1_3 => "TLS 1.3",
        }
    }
}

impl std::fmt::Display for TlsVersionArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(ValueEnum, Clone, Debug)]
pub enum HttpMethod {
    Get,
    Post,
    Head,
    Options,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
        }
    }
}

#[derive(ValueEnum, Clone, Debug, Copy)]
pub enum SortOrder {
    Asc,
    Desc,
}

#[derive(ValueEnum, Clone, Debug, Copy)]
pub enum CipherNotation {
    /// IANA/RFC standard names (e.g. TLS_AES_256_GCM_SHA384)
    Iana,
    /// OpenSSL names (e.g. TLS_AES_256_GCM_SHA384) — same for TLS 1.3, differs for TLS 1.2
    Openssl,
}

/// Canonical one-liner description used by CLI, MCP, and Cargo.toml.
pub const DCERT_DESCRIPTION: &str =
    "TLS certificate analysis, format conversion, and key verification — CLI and MCP server";

/// Long version string: version + description, for `dcert --version`.
pub fn dcert_long_version() -> &'static str {
    use std::sync::OnceLock;
    static LONG_VER: OnceLock<String> = OnceLock::new();
    let s = LONG_VER.get_or_init(|| format!("{}\n{}", dcert_version(), DCERT_DESCRIPTION));
    s.as_str()
}

// -- Top-level CLI --

#[derive(Parser, Debug)]
#[command(name = "dcert")]
#[command(about = DCERT_DESCRIPTION)]
#[command(
    long_about = "TLS certificate analysis, format conversion, and key verification — CLI and MCP server.\n\n\
    The 'check' command is the default and can be omitted:\n  \
    dcert example.com  ≡  dcert check example.com"
)]
#[command(version = dcert_version())]
#[command(long_version = dcert_long_version())]
#[command(after_help = "\x1b[1mExamples:\x1b[0m
  dcert example.com                          Check TLS certificate for a domain
  dcert check cert.pem                       Analyze a local PEM file
  dcert check example.com -f json            Output as JSON
  dcert check example.com --compliance       Run CA/B Forum compliance checks
  dcert convert pfx-to-pem cert.pfx --password secret
  dcert csr create --cn www.example.com      Generate CSR + private key
  dcert verify-key cert.pem --key key.pem    Verify key matches certificate
  dcert vault issue --cn app.example.com     Issue cert from Vault PKI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Analyze TLS certificates from PEM files or HTTPS endpoints (default command)
    #[command(name = "check", alias = "c")]
    Check(Box<CheckArgs>),

    /// Convert certificate formats (PFX/PEM/PKCS12 keystore/truststore)
    #[command(name = "convert")]
    Convert(ConvertArgs),

    /// Verify that a private key matches a certificate
    #[command(name = "verify-key", alias = "vk")]
    VerifyKey(VerifyKeyArgs),

    /// Create or validate Certificate Signing Requests (CSRs)
    #[command(name = "csr")]
    Csr(CsrArgs),

    /// HashiCorp Vault PKI operations (issue, sign, revoke, list, store, validate, renew)
    #[command(name = "vault")]
    Vault(Box<VaultArgs>),
}

/// Known subcommand names for backward-compatible default routing.
pub const KNOWN_SUBCOMMANDS: &[&str] = &[
    "check",
    "c",
    "convert",
    "verify-key",
    "vk",
    "csr",
    "vault",
    "help",
    "--help",
    "-h",
    "--version",
    "-V",
];

// -- Check subcommand (default) --

#[derive(Args, Debug)]
#[command(after_help = "\x1b[1mExamples:\x1b[0m
  dcert check example.com                       Basic TLS certificate check
  dcert check example.com -f json               JSON output
  dcert check cert.pem --fingerprint             Show SHA-256 fingerprints
  dcert check example.com --expiry-warn 30       Warn if expiring within 30 days
  dcert check a.com b.com --diff                 Compare two certificate chains
  dcert check example.com --watch 60             Re-check every 60 seconds
  dcert check example.com --check-revocation     OCSP revocation check
  dcert check smtp.gmail.com --starttls smtp     Inspect mail server certificate
  cat cert.pem | dcert check -                   Read PEM from stdin")]
pub struct CheckArgs {
    /// Path(s) to PEM file(s) or HTTPS URL(s). Use '-' to read targets from stdin (one per line)
    #[arg(value_parser = validate_target, num_args = 1..)]
    pub targets: Vec<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    /// Show only expired certificates
    #[arg(long)]
    pub expired_only: bool,

    /// Export the fetched PEM chain to a file (only for HTTPS targets)
    #[arg(long)]
    pub export_pem: Option<String>,

    /// Exclude expired or invalid certificates from export (only with --export-pem)
    #[arg(long)]
    pub exclude_expired: bool,

    /// Sort certificates by expiry date (asc = soonest first, desc = latest first)
    #[arg(long, value_enum)]
    pub sort_expiry: Option<SortOrder>,

    /// HTTP method to use for HTTPS requests (default: GET)
    #[arg(long, value_enum, default_value_t = HttpMethod::Get)]
    pub method: HttpMethod,

    /// Custom HTTP headers (key:value), can be repeated
    #[arg(long, value_parser = parse_header, num_args = 0.., value_name = "HEADER")]
    pub header: Vec<(String, String)>,

    /// Send data as the request body (implies POST if --method is not explicitly set).
    /// Similar to curl's -d flag.
    #[arg(short = 'd', long = "data", value_name = "DATA")]
    pub data: Option<String>,

    /// Read request body from a file (implies POST if --method is not explicitly set).
    /// Similar to curl's --data-binary @file.
    #[arg(long = "data-file", value_name = "FILE", conflicts_with = "data")]
    pub data_file: Option<String>,

    /// HTTP protocol to use (default: http1-1)
    #[arg(long, value_enum, default_value_t = HttpProtocol::Http1_1)]
    pub http_protocol: HttpProtocol,

    /// Minimum TLS version to accept [possible values: 1.2, 1.3]
    #[arg(long, value_enum, value_name = "VERSION")]
    pub min_tls: Option<TlsVersionArg>,

    /// Maximum TLS version to accept [possible values: 1.2, 1.3]
    #[arg(long, value_enum, value_name = "VERSION")]
    pub max_tls: Option<TlsVersionArg>,

    /// Set allowed TLS cipher suites using an OpenSSL cipher string (e.g. "ECDHE+AESGCM:CHACHA20")
    ///
    /// Controls TLS 1.2 and below ciphers. Uses OpenSSL cipher string format.
    /// See: https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
    #[arg(long, value_name = "CIPHER_STRING")]
    pub cipher_list: Option<String>,

    /// Set allowed TLS 1.3 cipher suites (e.g. "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
    ///
    /// Controls TLS 1.3 ciphers only. Uses colon-separated IANA cipher names.
    #[arg(long, value_name = "CIPHERSUITES")]
    pub cipher_suites: Option<String>,

    /// Disable TLS certificate verification (insecure)
    #[arg(long)]
    pub no_verify: bool,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    /// Read timeout in seconds (time to wait for server response after connection)
    #[arg(long, default_value_t = 5)]
    pub read_timeout: u64,

    /// Override SNI hostname for TLS handshake
    #[arg(long)]
    pub sni: Option<String>,

    /// Show SHA-256 fingerprint for each certificate
    #[arg(long)]
    pub fingerprint: bool,

    /// Show certificate extensions (key usage, basic constraints, etc.)
    #[arg(long)]
    pub extensions: bool,

    /// Warn if any certificate expires within the given number of days (exit code 1)
    #[arg(long, value_name = "DAYS")]
    pub expiry_warn: Option<u64>,

    /// Compare certificates between exactly two targets
    #[arg(long)]
    pub diff: bool,

    /// Periodically re-check targets at the given interval in seconds
    #[arg(long, value_name = "SECONDS")]
    pub watch: Option<u64>,

    /// Check certificate revocation status via OCSP
    #[arg(long)]
    pub check_revocation: bool,

    /// Show the negotiated (agreed) TLS cipher suite in the given notation
    #[arg(long, value_enum, value_name = "NOTATION")]
    pub ciphers: Option<CipherNotation>,

    /// Run compliance checks against CA/B Forum Baseline Requirements, DigiCert, and X9 standards.
    /// Reports findings (error/warning/info) and overall COMPLIANT/NON-COMPLIANT status.
    #[arg(long)]
    pub compliance: bool,

    /// Show verbose debug output with OSI layer diagnostics on stderr
    #[arg(long)]
    pub debug: bool,

    // -- mTLS options --
    /// Client certificate PEM file for mutual TLS authentication
    #[arg(long, value_name = "PATH", requires = "client_key")]
    pub client_cert: Option<String>,

    /// Client private key PEM file for mutual TLS (unencrypted RSA/EC key)
    #[arg(long, value_name = "PATH", requires = "client_cert", conflicts_with = "pkcs12")]
    pub client_key: Option<String>,

    /// PKCS12/PFX file containing client certificate and private key for mTLS
    #[arg(long, value_name = "PATH", conflicts_with_all = ["client_cert", "client_key"])]
    pub pkcs12: Option<String>,

    /// Password for the PKCS12/PFX file (or set DCERT_CERT_PASSWORD env var)
    #[arg(long, value_name = "PASS", env = "DCERT_CERT_PASSWORD")]
    pub cert_password: Option<String>,

    /// Custom CA certificate bundle PEM file for server verification (overrides system CAs)
    #[arg(long, value_name = "PATH")]
    pub ca_cert: Option<String>,

    // -- STARTTLS --
    /// Perform STARTTLS negotiation before TLS handshake (for mail/FTP servers).
    /// Target is treated as host[:port] instead of an HTTPS URL.
    #[arg(long, value_enum, value_name = "PROTOCOL", conflicts_with_all = ["method", "header", "data", "data_file", "http_protocol"])]
    pub starttls: Option<StarttlsProtocol>,
}

// -- Convert subcommand --

#[derive(Args, Debug)]
#[command(after_help = "\x1b[1mExamples:\x1b[0m
  dcert convert pfx-to-pem cert.pfx --password secret
  dcert convert pem-to-pfx --cert cert.pem --key key.pem -o out.pfx --password secret
  dcert convert create-keystore --cert cert.pem --key key.pem -o keystore.p12 --password secret
  dcert convert create-truststore ca.pem -o truststore.p12")]
pub struct ConvertArgs {
    #[command(subcommand)]
    pub mode: ConvertMode,
}

#[derive(Subcommand, Debug)]
pub enum ConvertMode {
    /// Convert PKCS12/PFX file to PEM certificate + key files
    #[command(name = "pfx-to-pem")]
    PfxToPem {
        /// Input PKCS12/PFX file
        input: String,
        /// Password for PKCS12 file (or set DCERT_CERT_PASSWORD env var)
        #[arg(long, env = "DCERT_CERT_PASSWORD")]
        password: String,
        /// Output directory for PEM files (cert.pem, key.pem, ca.pem)
        #[arg(short, long, default_value = ".")]
        output_dir: String,
    },

    /// Convert PEM certificate + key to PKCS12/PFX file
    #[command(name = "pem-to-pfx")]
    PemToPfx {
        /// PEM certificate file
        #[arg(long)]
        cert: String,
        /// PEM private key file (unencrypted)
        #[arg(long)]
        key: String,
        /// Output PFX file path
        #[arg(short, long)]
        output: String,
        /// Password for the output PKCS12 file
        #[arg(long, env = "DCERT_CERT_PASSWORD")]
        password: String,
        /// Additional CA certificate PEM file to include in the chain
        #[arg(long)]
        ca: Option<String>,
    },

    /// Create a PKCS12 keystore from a private key + certificate (Java-compatible since JDK 9)
    #[command(name = "create-keystore")]
    CreateKeystore {
        /// PEM certificate file (or chain)
        #[arg(long)]
        cert: String,
        /// PEM private key file
        #[arg(long)]
        key: String,
        /// Output PKCS12 keystore file path
        #[arg(short, long)]
        output: String,
        /// KeyStore password
        #[arg(long, env = "DCERT_KEYSTORE_PASSWORD")]
        password: String,
        /// Alias for the key entry
        #[arg(long, default_value = "server")]
        alias: String,
    },

    /// Create a PKCS12 truststore from CA certificates (Java-compatible since JDK 9)
    #[command(name = "create-truststore")]
    CreateTruststore {
        /// PEM file(s) containing CA certificates to trust
        #[arg(num_args = 1..)]
        certs: Vec<String>,
        /// Output PKCS12 truststore file path
        #[arg(short, long)]
        output: String,
        /// TrustStore password
        #[arg(long, default_value = "changeit")]
        password: String,
    },
}

// -- Verify-key subcommand --

#[derive(Args, Debug)]
#[command(after_help = "\x1b[1mExamples:\x1b[0m
  dcert verify-key cert.pem --key key.pem    Verify a specific cert/key pair
  dcert verify-key https://example.com --key key.pem
  dcert verify-key                           Auto-discover pairs in current directory
  dcert verify-key --dir /etc/ssl            Auto-discover pairs in a directory")]
pub struct VerifyKeyArgs {
    /// PEM certificate file or HTTPS URL to verify against.
    /// If omitted (along with --key), scans the current directory for matching cert/key pairs.
    #[arg(value_parser = validate_target)]
    pub target: Option<String>,

    /// Private key PEM file to verify against the certificate.
    /// If omitted (along with target), scans the current directory for matching cert/key pairs.
    #[arg(long)]
    pub key: Option<String>,

    /// Directory to scan for matching cert/key pairs (default: current directory).
    /// Only used when target and --key are omitted.
    #[arg(long, default_value = ".")]
    pub dir: String,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    /// Show verbose debug output
    #[arg(long)]
    pub debug: bool,
}

// -- CSR subcommand --

#[derive(Args, Debug)]
#[command(after_help = "\x1b[1mExamples:\x1b[0m
  dcert csr create                               Interactive wizard
  dcert csr create --cn www.example.com --san DNS:*.example.com
  dcert csr create --cn app.local --key-algo ecdsa-p256
  dcert csr validate request.csr                 Validate against CA/B Forum standards
  dcert csr validate request.csr --strict        Treat warnings as errors")]
pub struct CsrArgs {
    #[command(subcommand)]
    pub mode: CsrMode,
}

#[derive(Subcommand, Debug)]
pub enum CsrMode {
    /// Create a new Certificate Signing Request (CSR) with private key generation.
    /// Run without --cn for an interactive guided wizard.
    #[command(name = "create")]
    Create(Box<CsrCreateArgs>),

    /// Validate a CSR file against industry standards (CA/Browser Forum Baseline Requirements)
    #[command(name = "validate")]
    Validate(CsrValidateArgs),
}

#[derive(Args, Debug)]
pub struct CsrCreateArgs {
    /// Common Name (e.g., www.example.com). If omitted, enters interactive wizard mode.
    #[arg(long)]
    pub cn: Option<String>,

    /// Organization name (e.g., "Example Inc")
    #[arg(long)]
    pub org: Option<String>,

    /// Organizational Unit — can be repeated. Supports metadata identifiers (e.g., "AppId:my-app-123").
    /// Note: OU is deprecated for public CA certificates but valid for internal/private PKI.
    #[arg(long, num_args = 0..)]
    pub ou: Vec<String>,

    /// Country code (2-letter ISO 3166, e.g., GB, US)
    #[arg(long)]
    pub country: Option<String>,

    /// State or Province name
    #[arg(long)]
    pub state: Option<String>,

    /// Locality or City name
    #[arg(long)]
    pub locality: Option<String>,

    /// Email address (uncommon for TLS certs; prefer SAN Email)
    #[arg(long)]
    pub email: Option<String>,

    /// Subject Alternative Names — can be repeated. Use prefix DNS:, IP:, Email:, URI: (DNS: is default)
    #[arg(long, num_args = 0..)]
    pub san: Vec<String>,

    /// Key algorithm [default: rsa-4096]
    #[arg(long, value_enum, default_value_t = KeyAlgorithmArg::Rsa4096)]
    pub key_algo: KeyAlgorithmArg,

    /// Encrypt the private key with a passphrase (AES-256-CBC)
    #[arg(long)]
    pub encrypt_key: bool,

    /// Passphrase for private key encryption (or set DCERT_KEY_PASSWORD env var).
    /// Required when --encrypt-key is set.
    #[arg(long, env = "DCERT_KEY_PASSWORD", requires = "encrypt_key")]
    pub key_password: Option<String>,

    /// Output CSR file path [default: <cn>.csr]
    #[arg(long)]
    pub csr_out: Option<String>,

    /// Output private key file path [default: <cn>.key]
    #[arg(long)]
    pub key_out: Option<String>,

    /// Output format for result summary
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,
}

#[derive(Args, Debug)]
pub struct CsrValidateArgs {
    /// Path to CSR PEM file to validate
    pub csr_file: String,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    /// Treat warnings as errors (exit code 1 if any warnings)
    #[arg(long)]
    pub strict: bool,
}

// -- Vault subcommand --

#[derive(Args, Debug)]
#[command(after_help = "\x1b[1mExamples:\x1b[0m
  dcert vault issue --cn app.example.com         Issue cert from Vault PKI
  dcert vault issue                              Interactive wizard
  dcert vault sign --csr-file request.csr        Sign a CSR via Vault
  dcert vault list                               List all PKI certificates
  dcert vault list --show-details --valid-only   List valid certs with details
  dcert vault revoke --serial 01:23:AB           Revoke by serial number
  dcert vault store --cert-file c.pem --key-file k.pem secret/certs/app
  dcert vault validate secret/certs/app          Validate cert stored in KV
  dcert vault renew secret/certs/app             Re-issue expiring cert")]
pub struct VaultArgs {
    /// Skip TLS certificate verification for Vault (insecure). Also: VAULT_SKIP_VERIFY=1
    #[arg(long, global = true)]
    pub skip_verify: bool,

    /// Custom CA certificate PEM file for Vault TLS verification. Also: VAULT_CACERT env var
    #[arg(long, value_name = "PATH", global = true)]
    pub vault_cacert: Option<String>,

    /// Show verbose debug output for Vault connectivity and API diagnostics
    #[arg(long, global = true)]
    pub debug: bool,

    /// Authentication method: "token" (default), "ldap", or "approle"
    #[arg(long, global = true, value_name = "METHOD", default_value = "token")]
    pub auth_method: String,

    /// LDAP username (required when auth_method is "ldap"). Also: DCERT_LDAP_USERNAME
    #[arg(long, global = true, value_name = "USERNAME", env = "DCERT_LDAP_USERNAME")]
    pub ldap_username: Option<String>,

    /// LDAP password (required when auth_method is "ldap"). Also: DCERT_LDAP_PASSWORD
    #[arg(long, global = true, value_name = "PASSWORD", env = "DCERT_LDAP_PASSWORD")]
    pub ldap_password: Option<String>,

    /// LDAP auth mount point (default: "ldap")
    #[arg(long, global = true, value_name = "PATH", default_value = "ldap")]
    pub ldap_mount: String,

    /// AppRole role_id (required when auth_method is "approle"). Also: DCERT_APPROLE_ROLE_ID
    #[arg(long, global = true, value_name = "ID", env = "DCERT_APPROLE_ROLE_ID")]
    pub approle_role_id: Option<String>,

    /// AppRole secret_id (required when auth_method is "approle"). Also: DCERT_APPROLE_SECRET_ID
    #[arg(long, global = true, value_name = "ID", env = "DCERT_APPROLE_SECRET_ID")]
    pub approle_secret_id: Option<String>,

    /// AppRole auth mount point (default: "approle")
    #[arg(long, global = true, value_name = "PATH", default_value = "approle")]
    pub approle_mount: String,

    #[command(subcommand)]
    pub mode: VaultMode,
}

#[derive(Subcommand, Debug)]
pub enum VaultMode {
    /// Issue a new TLS certificate from Vault PKI (generates private key).
    /// Run without --cn for an interactive guided wizard.
    #[command(name = "issue")]
    Issue(Box<VaultIssueArgs>),

    /// Sign a Certificate Signing Request (CSR) using Vault PKI
    #[command(name = "sign")]
    Sign(VaultSignArgs),

    /// Revoke a certificate in Vault PKI by serial number or PEM file
    #[command(name = "revoke")]
    Revoke(VaultRevokeArgs),

    /// List all certificates issued by Vault PKI (with optional filtering)
    #[command(name = "list")]
    List(VaultListArgs),

    /// Store a local certificate and private key in Vault KV
    #[command(name = "store")]
    Store(VaultStoreArgs),

    /// Read and validate a certificate stored in Vault KV
    #[command(name = "validate")]
    Validate(VaultValidateArgs),

    /// Renew an existing certificate in Vault KV by re-issuing from Vault PKI
    #[command(name = "renew")]
    Renew(VaultRenewArgs),
}

#[derive(Args, Debug)]
pub struct VaultIssueArgs {
    /// Common Name (e.g., www.example.com). If omitted, enters interactive wizard mode.
    #[arg(long)]
    pub cn: Option<String>,

    /// Subject Alternative Names (can be repeated, e.g., --san DNS:*.example.com)
    #[arg(long, num_args = 0..)]
    pub san: Vec<String>,

    /// IP Subject Alternative Names (can be repeated, e.g., --ip-san 10.0.0.1)
    #[arg(long, num_args = 0..)]
    pub ip_san: Vec<String>,

    /// Certificate TTL (e.g., 8760h for 1 year)
    #[arg(long, default_value = "8760h")]
    pub ttl: String,

    /// Vault PKI role name
    #[arg(long)]
    pub role: Option<String>,

    /// Vault PKI mount point
    #[arg(long, default_value = "vault_intermediate")]
    pub mount: String,

    /// Output file base name (without extension). Defaults to sanitised CN.
    #[arg(long)]
    pub output: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    /// PFX password — if provided, output will be PKCS12/PFX instead of PEM
    #[arg(long, env = "DCERT_CERT_PASSWORD")]
    pub pfx_password: Option<String>,

    /// Store certificate and key in Vault KV at this path after issuance
    #[arg(long)]
    pub store_path: Option<String>,

    /// Vault KV version (1 or 2) for --store-path
    #[arg(long, default_value_t = 1)]
    pub kv_version: u8,
}

#[derive(Args, Debug)]
pub struct VaultSignArgs {
    /// Path to CSR PEM file to sign. If omitted, enters interactive wizard mode.
    #[arg(long)]
    pub csr_file: Option<String>,

    /// Common Name override (defaults to CN from CSR)
    #[arg(long)]
    pub cn: Option<String>,

    /// Subject Alternative Names (can be repeated)
    #[arg(long, num_args = 0..)]
    pub san: Vec<String>,

    /// IP Subject Alternative Names (can be repeated, e.g., --ip-san 10.0.0.1)
    #[arg(long, num_args = 0..)]
    pub ip_san: Vec<String>,

    /// Certificate TTL
    #[arg(long, default_value = "8760h")]
    pub ttl: String,

    /// Vault PKI role name
    #[arg(long)]
    pub role: Option<String>,

    /// Vault PKI mount point
    #[arg(long, default_value = "vault_intermediate")]
    pub mount: String,

    /// Output file base name
    #[arg(long)]
    pub output: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    /// PFX password — if provided, output will be PKCS12/PFX instead of PEM
    #[arg(long, env = "DCERT_CERT_PASSWORD")]
    pub pfx_password: Option<String>,

    /// Store certificate in Vault KV at this path after signing
    #[arg(long)]
    pub store_path: Option<String>,

    /// Vault KV version (1 or 2) for --store-path
    #[arg(long, default_value_t = 1)]
    pub kv_version: u8,
}

#[derive(Args, Debug)]
pub struct VaultRevokeArgs {
    /// Certificate serial number (colon or hyphen-separated hex)
    #[arg(long, conflicts_with = "cert_file")]
    pub serial: Option<String>,

    /// PEM certificate file to revoke
    #[arg(long, conflicts_with = "serial")]
    pub cert_file: Option<String>,

    /// Vault PKI mount point
    #[arg(long, default_value = "vault_intermediate")]
    pub mount: String,
}

#[derive(Args, Debug)]
pub struct VaultListArgs {
    /// Vault PKI mount point
    #[arg(long, default_value = "vault_intermediate")]
    pub mount: String,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    /// Fetch and display details for each certificate (slower for large lists)
    #[arg(long)]
    pub show_details: bool,

    /// Show only expired certificates
    #[arg(long)]
    pub expired_only: bool,

    /// Show only valid (non-expired) certificates
    #[arg(long, conflicts_with = "expired_only")]
    pub valid_only: bool,

    /// Export results to a file (JSON, CSV, or XLSX based on extension)
    #[arg(long, value_name = "FILE")]
    pub export: Option<String>,
}

#[derive(Args, Debug)]
pub struct VaultStoreArgs {
    /// Local PEM certificate file to store
    #[arg(long)]
    pub cert_file: String,

    /// Local PEM private key file to store
    #[arg(long)]
    pub key_file: String,

    /// Vault KV path (e.g., secret/company/project/certs/my-cert)
    pub path: String,

    /// Key name for the certificate in Vault KV
    #[arg(long, default_value = "cert")]
    pub cert_key: String,

    /// Key name for the private key in Vault KV
    #[arg(long, default_value = "key")]
    pub key_key: String,

    /// Vault KV version (1 or 2). KV v1 uses flat paths; v2 uses /data/ prefix.
    #[arg(long, default_value_t = 1)]
    pub kv_version: u8,
}

#[derive(Args, Debug)]
pub struct VaultValidateArgs {
    /// Vault KV path to read certificate from (e.g., secret/company/project/certs/my-cert)
    pub path: String,

    /// Key name for the certificate in Vault KV
    #[arg(long, default_value = "cert")]
    pub cert_key: String,

    /// Key name for the private key in Vault KV
    #[arg(long, default_value = "key")]
    pub key_key: String,

    /// Vault KV version (1 or 2)
    #[arg(long, default_value_t = 1)]
    pub kv_version: u8,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,
}

#[derive(Args, Debug)]
pub struct VaultRenewArgs {
    /// Vault KV path containing the existing certificate to renew
    pub path: String,

    /// Vault PKI role name for issuing the new certificate
    #[arg(long)]
    pub role: Option<String>,

    /// Vault PKI mount point
    #[arg(long, default_value = "vault_intermediate")]
    pub mount: String,

    /// TTL for the new certificate
    #[arg(long, default_value = "8760h")]
    pub ttl: String,

    /// Key name for the certificate in Vault KV
    #[arg(long, default_value = "cert")]
    pub cert_key: String,

    /// Key name for the private key in Vault KV
    #[arg(long, default_value = "key")]
    pub key_key: String,

    /// Vault KV version (1 or 2)
    #[arg(long, default_value_t = 1)]
    pub kv_version: u8,

    /// Additional Subject Alternative Names (override existing SANs if provided)
    #[arg(long, num_args = 0..)]
    pub san: Vec<String>,

    /// Additional IP Subject Alternative Names
    #[arg(long, num_args = 0..)]
    pub ip_san: Vec<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,
}

// -- Helper functions --

pub fn validate_target(s: &str) -> Result<String, String> {
    if s == "-" || s.starts_with("https://") || std::path::Path::new(s).exists() {
        Ok(s.to_string())
    } else if let Some(rest) = s.strip_prefix("http://") {
        Err(format!("HTTP is not supported. Did you mean https://{rest}?"))
    } else if looks_like_hostname(s) {
        // Bare hostname like "www.google.com" or "10.0.0.1:8443"
        Ok(format!("https://{s}"))
    } else {
        Err(format!(
            "'{s}' is not a valid target. Provide an HTTPS URL, hostname, PEM file path, or '-' for stdin"
        ))
    }
}

/// Check if a string looks like a hostname (with optional port) rather than a file path.
pub fn looks_like_hostname(s: &str) -> bool {
    // Must not be empty
    if s.is_empty() {
        return false;
    }
    // Strip optional port suffix (e.g. "example.com:8443")
    let host_part = if let Some(idx) = s.rfind(':') {
        let port_part = &s[idx + 1..];
        // If what follows ':' is all digits, treat it as host:port
        if port_part.chars().all(|c| c.is_ascii_digit()) && !port_part.is_empty() {
            &s[..idx]
        } else {
            s
        }
    } else {
        s
    };
    // Must contain a dot (domain) or be a valid IP address
    if host_part.contains('.') {
        // Hostname chars: alphanumeric, hyphens, dots
        host_part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    } else {
        // Could be a single-label hostname like "localhost"
        host_part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && host_part.len() > 1
    }
}

pub fn parse_header(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("Header must be in key:value format".to_string());
    }
    let key = parts[0].trim();
    if key.is_empty() {
        return Err("Header key must not be empty".to_string());
    }
    Ok((key.to_string(), parts[1].trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // parse_header tests
    // ---------------------------------------------------------------

    #[test]
    fn test_parse_header() {
        assert_eq!(
            parse_header("Content-Type: application/json").unwrap(),
            ("Content-Type".to_string(), "application/json".to_string())
        );
        assert_eq!(
            parse_header("Authorization: Bearer token:with:colons").unwrap(),
            ("Authorization".to_string(), "Bearer token:with:colons".to_string())
        );
        assert!(parse_header("InvalidHeader").is_err());
    }

    #[test]
    fn test_parse_header_whitespace_trimming() {
        let (key, value) = parse_header("  X-Custom  :  some value  ").unwrap();
        assert_eq!(key, "X-Custom");
        assert_eq!(value, "some value");
    }

    #[test]
    fn test_parse_header_empty_value() {
        let (key, value) = parse_header("X-Empty:").unwrap();
        assert_eq!(key, "X-Empty");
        assert_eq!(value, "");
    }

    #[test]
    fn test_parse_header_empty_key_rejected() {
        assert!(parse_header(":value").is_err());
        assert!(parse_header("  :value").is_err());
    }

    // ---------------------------------------------------------------
    // validate_target tests
    // ---------------------------------------------------------------

    #[test]
    fn test_validate_target_https_url() {
        assert!(validate_target("https://example.com").is_ok());
        assert!(validate_target("https://example.com:8443/path").is_ok());
    }

    #[test]
    fn test_validate_target_invalid() {
        assert!(validate_target("http://example.com").is_err());
        assert!(validate_target("ftp://example.com").is_err());
        assert!(validate_target("/nonexistent/path.pem").is_err());
    }

    #[test]
    fn test_validate_target_existing_file() {
        let path = "tests/data/valid.pem";
        assert!(validate_target(path).is_ok());
    }

    #[test]
    fn test_validate_target_stdin() {
        assert!(validate_target("-").is_ok());
    }

    #[test]
    fn test_validate_target_bare_hostname() {
        // Bare hostnames should auto-prepend https://
        let result = validate_target("www.google.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://www.google.com");

        let result = validate_target("example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com");

        let result = validate_target("api.example.com:8443");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://api.example.com:8443");
    }

    #[test]
    fn test_validate_target_http_rejected_with_hint() {
        let result = validate_target("http://example.com");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("https://example.com"), "Should suggest HTTPS: {err}");
    }

    #[test]
    fn test_looks_like_hostname() {
        assert!(looks_like_hostname("www.google.com"));
        assert!(looks_like_hostname("example.com"));
        assert!(looks_like_hostname("example.com:443"));
        assert!(looks_like_hostname("10.0.0.1"));
        assert!(looks_like_hostname("sub-domain.example.co.uk"));
        assert!(looks_like_hostname("localhost"));

        // Should NOT look like hostnames
        assert!(!looks_like_hostname(""));
        assert!(!looks_like_hostname("a")); // too short single-label
        assert!(!looks_like_hostname("/etc/ssl/certs"));
        assert!(!looks_like_hostname("file with spaces.pem"));
    }

    // ---------------------------------------------------------------
    // HttpMethod Display tests
    // ---------------------------------------------------------------

    #[test]
    fn test_http_method_display() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Post.to_string(), "POST");
        assert_eq!(HttpMethod::Head.to_string(), "HEAD");
        assert_eq!(HttpMethod::Options.to_string(), "OPTIONS");
    }

    // ---------------------------------------------------------------
    // Subcommand backward-compat tests
    // ---------------------------------------------------------------

    #[test]
    fn test_known_subcommands_list() {
        assert!(KNOWN_SUBCOMMANDS.contains(&"check"));
        assert!(KNOWN_SUBCOMMANDS.contains(&"convert"));
        assert!(KNOWN_SUBCOMMANDS.contains(&"verify-key"));
        assert!(KNOWN_SUBCOMMANDS.contains(&"vk"));
        assert!(KNOWN_SUBCOMMANDS.contains(&"csr"));
        assert!(KNOWN_SUBCOMMANDS.contains(&"help"));
    }

    #[test]
    fn test_check_subcommand_parse() {
        let cli = Cli::parse_from(["dcert", "check", "tests/data/valid.pem"]);
        assert!(matches!(cli.command, Command::Check(_)));
        if let Command::Check(args) = cli.command {
            assert_eq!(args.targets.len(), 1);
        }
    }

    #[test]
    fn test_verify_key_subcommand_parse() {
        let cli = Cli::parse_from([
            "dcert",
            "verify-key",
            "tests/data/valid.pem",
            "--key",
            "tests/data/valid.pem",
        ]);
        assert!(matches!(cli.command, Command::VerifyKey(_)));
    }
}
