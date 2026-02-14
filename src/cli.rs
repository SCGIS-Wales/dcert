use clap::{Parser, ValueEnum};
use openssl::ssl::SslVersion;

/// Return the version string for `--version` output.
///
/// Prefers the git tag set by build.rs (e.g. "2.0.2" from tag "v2.0.2"),
/// falling back to CARGO_PKG_VERSION from Cargo.toml for non-git builds
/// (e.g. `cargo install` from crates.io) or shallow clones without tags.
pub fn dcert_version() -> &'static str {
    // DCERT_GIT_VERSION is set by build.rs from `git describe --tags --always`.
    // When no tags are reachable (shallow clone), git describe --always returns
    // just a commit hash (e.g. "42e938d") — fall back to CARGO_PKG_VERSION.
    match option_env!("DCERT_GIT_VERSION") {
        Some(git_ver) if git_ver.contains('.') => git_ver.strip_prefix('v').unwrap_or(git_ver),
        _ => env!("CARGO_PKG_VERSION"),
    }
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

#[derive(Parser, Debug)]
#[command(name = "dcert")]
#[command(
    about = "Decode and validate TLS certificates from a PEM file or fetch the TLS certificate chain from an HTTPS endpoint.\n\
             If you specify an HTTPS URL, dcert will fetch and decode the server's TLS certificate chain.\n\
             Optionally, you can export the chain as a PEM file."
)]
#[command(version = dcert_version())]
pub struct Args {
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

    /// Show verbose debug output with OSI layer diagnostics on stderr
    #[arg(long)]
    pub debug: bool,
}

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
}
