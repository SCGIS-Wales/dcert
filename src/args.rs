use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
    Csv,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TlsVersion {
    V12,
    V13,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum HttpVersion {
    H1_1,
    H2,
    H3,
}

#[derive(Parser, Debug)]
#[command(name = "dcert", version)]
#[command(about = "Decode PEM TLS certificates from file or HTTPS URL")]
pub struct Args {
    /// Input source: a PEM file path or an https:// URL
    pub input: String,

    /// Output format
    #[arg(short='F', long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    /// Only show expired certificates (file mode)
    #[arg(long)]
    pub expired_only: bool,

    /// TLS version to use when probing HTTPS (default 1.3)
    #[arg(long, value_enum, default_value_t = TlsVersion::V13)]
    pub tls_version: TlsVersion,

    /// HTTP version preference when probing HTTPS (default h2). h3 requires a special build.
    #[arg(long, value_enum, default_value_t = HttpVersion::H2)]
    pub http_version: HttpVersion,

    /// Optional request method for HTTPS probe (GET, POST, PUT, DELETE, OPTIONS, etc.)
    #[arg(long, default_value = "GET")]
    pub method: String,

    /// Optional request headers, comma separated key=value pairs
    #[arg(long)]
    pub headers: Option<String>,

    /// Optional CA bundle file path (overrides SSL_CERT_FILE)
    #[arg(long)]
    pub ca_file: Option<PathBuf>,

    /// Export fetched TLS chain to a single PEM file (URL mode only)
    #[arg(long)]
    pub export_chain: bool,

    /// Timeout for OSI layer 4 connect, seconds (default 15)
    #[arg(long, default_value_t = 15)]
    pub timeout_l4: u64,

    /// Timeout for OSI layer 6 TLS handshake, seconds (default 15)
    #[arg(long, default_value_t = 15)]
    pub timeout_l6: u64,

    /// Timeout for OSI layer 7 first-byte, seconds (default 15)
    #[arg(long, default_value_t = 15)]
    pub timeout_l7: u64,
}
