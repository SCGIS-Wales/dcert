//! dcert-mcp: Model Context Protocol server exposing the dcert CLI.
//!
//! The binary is a thin supervisor around the `dcert` CLI: every tool call
//! validates its parameters, runs `dcert` as a bounded subprocess and returns
//! its output. Two transports are supported: stdio (default) and streamable
//! HTTP with OIDC or static token authentication.

use clap::Parser;
use rmcp::ServiceExt;
use std::time::Duration;

/// dcert-mcp: MCP server for TLS certificate analysis.
#[derive(Parser, Debug)]
#[command(name = "dcert-mcp")]
#[command(about = MCP_DESCRIPTION)]
#[command(version = dcert_mcp_version())]
#[command(long_version = dcert_mcp_long_version())]
struct McpCli {
    /// Subprocess timeout in seconds (max time for a single dcert invocation)
    #[arg(long, env = "DCERT_MCP_TIMEOUT", default_value_t = DEFAULT_SUBPROCESS_TIMEOUT)]
    timeout: u64,

    /// Connection timeout in seconds passed to the dcert subprocess (TCP connect timeout)
    #[arg(long, env = "DCERT_MCP_CONNECTION_TIMEOUT", default_value_t = DEFAULT_CONNECTION_TIMEOUT)]
    connection_timeout: u64,

    /// Read timeout in seconds passed to the dcert subprocess (time to wait for server response)
    #[arg(long, env = "DCERT_MCP_READ_TIMEOUT", default_value_t = DEFAULT_READ_TIMEOUT)]
    read_timeout: u64,

    /// Transport mode: "stdio" (default) or "http"
    #[arg(long, env = "DCERT_MCP_MODE", default_value = "stdio")]
    mode: String,

    /// HTTP bind address (only used in http mode)
    #[arg(long, env = "DCERT_MCP_ADDR", default_value = "0.0.0.0:3000")]
    addr: String,
}

mod config;
mod exec;
mod http;
mod params;
mod params_vault;
mod security;
#[cfg(test)]
mod tests;
mod tools;
mod validate;

use crate::config::{
    DEFAULT_CONNECTION_TIMEOUT, DEFAULT_READ_TIMEOUT, DEFAULT_SUBPROCESS_TIMEOUT, MCP_DESCRIPTION, McpConfig,
    McpProxyInfo, dcert_mcp_long_version, dcert_mcp_version, find_dcert_binary, log_startup_diagnostics,
};
use crate::tools::DcertMcpServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = McpCli::parse();

    let config = McpConfig {
        subprocess_timeout: Duration::from_secs(cli.timeout),
        connection_timeout: cli.connection_timeout,
        read_timeout: cli.read_timeout,
        dcert_binary: find_dcert_binary(),
        proxy_config: McpProxyInfo::from_env(),
    };

    match cli.mode.as_str() {
        "http" => http::run_http_mode(config, &cli.addr).await,
        _ => run_stdio_mode(config).await,
    }
}

/// Run in stdio mode (default, unchanged behavior).
async fn run_stdio_mode(config: McpConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Log startup diagnostics to stderr (MCP protocol uses stdio)
    log_startup_diagnostics(&config);

    let server = DcertMcpServer::new(config);
    let service = server.serve(rmcp::transport::io::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
