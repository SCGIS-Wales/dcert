use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
    Csv,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum TlsVersion {
    V13,
    V12,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum HttpVersion {
    H3,
    H2,
    H1_1,
}

#[derive(Parser, Debug)]
#[command(name = "dcert", about = "Decode PEM TLS certificates from files or HTTPS endpoints")]
pub struct Cli {
    /// File path (.pem) or https:// URL
    pub input: String,

    /// Output format
    #[arg(long, default_value = "pretty", value_enum)]
    pub format: OutputFormat,

    /// Only print expired certificates
    #[arg(long, default_value_t = false)]
    pub expired_only: bool,

    /// Show extended version info and exit
    #[arg(long = "version-only", default_value_t = false)]
    pub version_only: bool,

    /// Preferred TLS version (default TLS 1.3)
    #[arg(long = "tls-version", value_enum, default_value = "v13")]
    pub tls_version: TlsVersion,

    /// HTTP protocol version to negotiate (default H2)
    #[arg(long = "http-version", value_enum, default_value = "h2")]
    pub http_version: HttpVersion,

    /// HTTP method for HTTPS probe (default GET)
    #[arg(long, default_value = "GET")]
    pub method: String,

    /// Optional request headers: "k=v,k2=v2"
    #[arg(long)]
    pub headers: Option<String>,

    /// Override CA bundle file path (PEM). If not set, respects SSL_CERT_FILE.
    #[arg(long = "ca-file")]
    pub ca_file: Option<PathBuf>,

    /// Timeout for layer 4 connect (seconds)
    #[arg(long = "timeout-l4", default_value_t = 15)]
    pub timeout_l4: u64,

    /// Timeout for TLS handshake (seconds)
    #[arg(long = "timeout-l6", default_value_t = 15)]
    pub timeout_l6: u64,

    /// Timeout for HTTP request (seconds)
    #[arg(long = "timeout-l7", default_value_t = 15)]
    pub timeout_l7: u64,

    /// Export full server chain as base64-PEM to <host>-base64-pem.txt
    #[arg(long = "export-chain", default_value_t = false)]
    pub export_chain: bool,
}
