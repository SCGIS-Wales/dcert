use clap::{Parser, ValueEnum};

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2
    #[clap(name = "1.2")]
    V12,
    /// TLS 1.3 (default)
    #[clap(name = "1.3")]
    V13,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum HttpVersion {
    /// HTTP/1.1
    #[clap(name = "HTTP/1.1")]
    H1_1,
    /// HTTP/2 (default)
    #[clap(name = "HTTP/2")]
    H2,
    /// HTTP/3 (experimental flag only)
    #[clap(name = "HTTP/3")]
    H3,
}

#[derive(Parser, Debug)]
#[command(
    name = "dcert",
    about = "Decode PEM TLS certificates from files or HTTPS endpoints"
)]
pub struct Cli {
    /// File path (.pem) or https:// URL
    pub input: String,

    /// TLS version to use (default: 1.3)
    #[arg(long = "tls-version", value_enum, default_value = "1.3")]
    pub tls_version: TlsVersion,

    /// HTTP protocol version to request (default: HTTP/2)
    #[arg(long = "http-version", value_enum, default_value = "HTTP/2")]
    pub http_version: HttpVersion,

    /// HTTP method (default: GET)
    #[arg(long = "method", default_value = "GET")]
    pub method: String,

    /// Optional extra headers: key=value,key2=value2
    #[arg(long = "headers")]
    pub headers: Option<String>,

    /// Path to a CA bundle file to prefer over SSL_CERT_FILE
    #[arg(long = "ca-file")]
    pub ca_file: Option<String>,

    /// TCP connect timeout (seconds) – L4
    #[arg(long = "timeout-l4", default_value_t = 15)]
    pub timeout_l4: u64,

    /// TLS handshake timeout (seconds) – L6
    #[arg(long = "timeout-l6", default_value_t = 15)]
    pub timeout_l6: u64,

    /// First-byte HTTP timeout (seconds) – L7
    #[arg(long = "timeout-l7", default_value_t = 15)]
    pub timeout_l7: u64,

    /// Export full TLS chain (PEM, base64) to file
    #[arg(long = "export-chain", default_value_t = false)]
    pub export_chain: bool,

    /// Show only expired certs (file input mode)
    #[arg(long = "expired-only", default_value_t = false)]
    pub expired_only: bool,

    /// Output JSON instead of text (endpoint mode)
    #[arg(long = "json", default_value_t = false)]
    pub json: bool,

    /// Output CSV instead of text (file mode)
    #[arg(long = "csv", default_value_t = false)]
    pub csv: bool,
}
