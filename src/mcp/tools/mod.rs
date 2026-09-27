//! The MCP server handler and its tool routers.

use rmcp::ServerHandler;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{
    CacheScope, CallToolResult, ContentBlock, Implementation, ListPromptsResult, ListResourceTemplatesResult,
    ListResourcesResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{
    DEFAULT_CONNECTION_TIMEOUT, DEFAULT_READ_TIMEOUT, DEFAULT_SUBPROCESS_TIMEOUT, MCP_DESCRIPTION, MCP_INSTRUCTIONS,
    McpConfig, McpProxyInfo, dcert_mcp_version, find_dcert_binary,
};

pub(crate) mod cert;
pub(crate) mod vault;

pub(crate) fn ok_text(text: String) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

pub(crate) fn ok_error(msg: String) -> Result<CallToolResult, ErrorData> {
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

        let mut info = ServerConfig::default()
            .with_server_info(impl_info)
            .with_instructions(MCP_INSTRUCTIONS);
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    // dcert has no prompts or resources, but proxies such as FastMCP's list them
    // regardless of the advertised capabilities. rmcp's default empty listings
    // omit `ttlMs`/`cacheScope`, which protocol 2026-07-28 makes mandatory, so
    // those clients reject the reply. Answer with the same cache hints rmcp's
    // generated `list_tools` sends.

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let result = ListPromptsResult::default();
        Ok(match cache_hints(&context) {
            Some((ttl, scope)) => result.with_ttl_ms(ttl).with_cache_scope(scope),
            None => result,
        })
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let result = ListResourcesResult::default();
        Ok(match cache_hints(&context) {
            Some((ttl, scope)) => result.with_ttl_ms(ttl).with_cache_scope(scope),
            None => result,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        let result = ListResourceTemplatesResult::default();
        Ok(match cache_hints(&context) {
            Some((ttl, scope)) => result.with_ttl_ms(ttl).with_cache_scope(scope),
            None => result,
        })
    }
}

/// Cache hints for a list result, when the negotiated protocol has them.
fn cache_hints(context: &RequestContext<RoleServer>) -> Option<(u64, CacheScope)> {
    context
        .protocol_version()
        .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
        .then_some((0, CacheScope::Public))
}
