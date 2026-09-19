//! The MCP server handler and its tool routers.

use rmcp::ServerHandler;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{
    DEFAULT_CONNECTION_TIMEOUT, DEFAULT_READ_TIMEOUT, DEFAULT_SUBPROCESS_TIMEOUT, MCP_DESCRIPTION, McpConfig,
    McpProxyInfo, dcert_mcp_version, find_dcert_binary,
};

pub(crate) mod cert;
pub(crate) mod vault;

pub(crate) fn ok_text(text: String) -> Result<CallToolResult, rmcp::ErrorData> {
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

pub(crate) fn ok_error(msg: String) -> Result<CallToolResult, rmcp::ErrorData> {
    Ok(CallToolResult::error(vec![ContentBlock::text(msg)]))
}

// -- MCP Server Handler --

/// dcert MCP server handler.
#[derive(Debug, Clone)]
pub struct DcertMcpServer {
    pub(crate) tool_router: ToolRouter<Self>,
    pub(crate) config: Arc<McpConfig>,
}

impl DcertMcpServer {
    /// Create a new dcert MCP server with the given configuration.
    pub(crate) fn new(config: McpConfig) -> Self {
        Self::with_shared_config(Arc::new(config))
    }

    /// Build a handler that shares one configuration with other instances.
    /// The HTTP transport constructs a handler per session, so the resolved
    /// binary path and timeouts are read once at startup rather than per
    /// connection.
    pub(crate) fn with_shared_config(config: Arc<McpConfig>) -> Self {
        Self {
            tool_router: Self::cert_tool_router() + Self::vault_tool_router(),
            config,
        }
    }
}

impl Default for DcertMcpServer {
    fn default() -> Self {
        Self::new(McpConfig {
            subprocess_timeout: Duration::from_secs(DEFAULT_SUBPROCESS_TIMEOUT),
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            dcert_binary: find_dcert_binary(),
            proxy_config: McpProxyInfo::from_env(),
        })
    }
}

#[rmcp::tool_handler(router = self.tool_router)]
impl ServerHandler for DcertMcpServer {
    fn get_info(&self) -> ServerConfig {
        let impl_info = Implementation::new("dcert-mcp", dcert_mcp_version())
            .with_title("dcert MCP Server")
            .with_description(MCP_DESCRIPTION)
            .with_website_url("https://github.com/SCGIS-Wales/dcert");

        let mut info = ServerConfig::default().with_server_info(impl_info);
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}
