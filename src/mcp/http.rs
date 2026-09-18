//! HTTP transport: rmcp streamable HTTP behind authentication, rate limiting,
//! timeouts and body limits.

use std::sync::Arc;
use std::time::Duration;

use crate::config::{McpConfig, dcert_mcp_version, log_startup_diagnostics};
use crate::exec::run_dcert_with_env;
use crate::params::HttpTlsParams;
use crate::security;
use crate::tools::DcertMcpServer;
use crate::validate::validate_target;

/// Shared state for HTTP mode handlers.
pub(crate) struct HttpAppState {
    mcp_server: DcertMcpServer,
}

/// Build the CORS layer for the HTTP MCP server.
///
/// Allowed origins are read from `DCERT_MCP_ALLOWED_ORIGINS` (comma-separated).
/// When unset/empty, cross-origin browser requests are denied (no
/// `Access-Control-Allow-Origin` header is emitted) — the server is meant to be
/// reached same-origin or via a trusted reverse proxy. A literal `*` enables
/// any-origin access (logged as a warning); we never pair it with credentials,
/// and only `authorization`/`content-type` request headers are allowed.
/// Parsed CORS origin policy derived from `DCERT_MCP_ALLOWED_ORIGINS`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CorsOriginPolicy {
    /// No cross-origin access (env unset/empty).
    None,
    /// Any origin (env contained a literal `*`).
    Any,
    /// Explicit allowlist of origins.
    List(Vec<String>),
}

/// Parse the `DCERT_MCP_ALLOWED_ORIGINS` value into a policy. Pure function so
/// the precedence rules (empty → None, any `*` → Any, else trimmed list) are
/// unit-testable without constructing an HTTP layer.
pub(crate) fn parse_allowed_origins(raw: &str) -> CorsOriginPolicy {
    let entries: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if entries.is_empty() {
        CorsOriginPolicy::None
    } else if entries.iter().any(|e| e == "*") {
        CorsOriginPolicy::Any
    } else {
        CorsOriginPolicy::List(entries)
    }
}

pub(crate) fn build_cors_layer() -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderName, HeaderValue, Method};
    use tower_http::cors::{AllowOrigin, CorsLayer};

    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
        ]);

    match parse_allowed_origins(&std::env::var("DCERT_MCP_ALLOWED_ORIGINS").unwrap_or_default()) {
        CorsOriginPolicy::Any => {
            tracing::warn!(
                "CORS: DCERT_MCP_ALLOWED_ORIGINS=* — allowing ANY origin; do not expose this server publicly"
            );
            layer.allow_origin(AllowOrigin::any())
        }
        CorsOriginPolicy::None => {
            tracing::info!("CORS: no cross-origin access (set DCERT_MCP_ALLOWED_ORIGINS to allow specific origins)");
            layer.allow_origin(AllowOrigin::list(Vec::<HeaderValue>::new()))
        }
        CorsOriginPolicy::List(entries) => {
            let origins: Vec<HeaderValue> = entries
                .iter()
                .filter_map(|o| match HeaderValue::from_str(o) {
                    Ok(v) => Some(v),
                    Err(_) => {
                        tracing::warn!(origin = %o, "CORS: ignoring invalid origin in DCERT_MCP_ALLOWED_ORIGINS");
                        None
                    }
                })
                .collect();
            tracing::info!(origins = ?entries, "CORS: cross-origin access restricted to allowlist");
            layer.allow_origin(AllowOrigin::list(origins))
        }
    }
}

/// Run in HTTP mode with OIDC/OAuth2 authentication.
pub(crate) async fn run_http_mode(config: McpConfig, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    use axum::routing::{get, post};
    use security::audit::AuditLogger;
    use security::middleware::{AuthState, auth_middleware};
    use security::session::{SessionCache, SessionConfig};

    // Initialize structured logging for HTTP mode.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .json()
        .init();

    log_startup_diagnostics(&config);

    // Build auth state from environment variables.
    let oidc_validator = build_oidc_validator();
    let static_token = std::env::var("DCERT_MCP_AUTH_TOKEN").ok().filter(|s| !s.is_empty());

    // Log auth status.
    let auth_configured = oidc_validator.is_some() || static_token.is_some();
    if oidc_validator.is_some() {
        tracing::info!("authentication: OIDC/OAuth2 enabled");
    } else if static_token.is_some() {
        tracing::info!("authentication: static bearer token enabled");
    } else {
        tracing::warn!("authentication: DISABLED — no OIDC issuer or static token configured");
    }

    // Refuse to expose an unauthenticated endpoint on a non-loopback interface.
    // Binding to a public/LAN address with no OIDC issuer or static token lets
    // any host on the network drive the cert-tooling/subprocess-spawning API.
    // The operator can opt in explicitly with DCERT_MCP_ALLOW_INSECURE=1.
    if !auth_configured && !addr_is_loopback(addr) {
        let allow_insecure = std::env::var("DCERT_MCP_ALLOW_INSECURE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !allow_insecure {
            return Err(format!(
                "refusing to start: HTTP mode has no authentication configured and would \
                 bind to a non-loopback address ({addr}). Configure DCERT_MCP_OIDC_ISSUER or \
                 DCERT_MCP_AUTH_TOKEN, bind to 127.0.0.1, or set DCERT_MCP_ALLOW_INSECURE=1 to \
                 override."
            )
            .into());
        }
        tracing::warn!(
            addr = addr,
            "starting UNAUTHENTICATED HTTP server on a non-loopback address (DCERT_MCP_ALLOW_INSECURE=1)"
        );
    }

    // Session cache.
    let session_ttl = std::env::var("DCERT_MCP_SESSION_TTL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);
    let session_cache = Arc::new(SessionCache::new(SessionConfig {
        inactivity_ttl: Duration::from_secs(session_ttl),
        ..SessionConfig::default()
    }));

    let audit_logger = Arc::new(AuditLogger::new());

    let auth_state = Arc::new(AuthState {
        oidc_validator: oidc_validator.map(Arc::new),
        static_token,
        session_cache: Some(session_cache),
        audit_logger: Some(audit_logger),
    });

    let mcp_server = DcertMcpServer::new(config);

    let app_state = Arc::new(HttpAppState { mcp_server });

    // Create axum router with auth middleware.
    let app = axum::Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", post(mcp_handler))
        .layer(build_cors_layer())
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_middleware))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = addr, "dcert-mcp HTTP server listening");

    // Wire ConnectInfo so the auth middleware can record the real client IP in
    // audit logs (otherwise `remote_addr` is always "unknown").
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Return true when `addr` binds to a loopback interface (safe to run without
/// authentication). Unparseable or non-loopback addresses are treated as
/// non-loopback so the insecure-bind guard fails closed.
pub(crate) fn addr_is_loopback(addr: &str) -> bool {
    use std::net::ToSocketAddrs;
    match addr.to_socket_addrs() {
        Ok(iter) => {
            let resolved: Vec<_> = iter.collect();
            !resolved.is_empty() && resolved.iter().all(|sa| sa.ip().is_loopback())
        }
        Err(_) => false,
    }
}

/// Build OIDC validator from environment variables (if configured).
pub(crate) fn build_oidc_validator() -> Option<security::oidc::OidcValidator> {
    let issuer = std::env::var("DCERT_MCP_OIDC_ISSUER").ok().filter(|s| !s.is_empty())?;
    let audience = std::env::var("DCERT_MCP_OIDC_AUDIENCE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    if audience.is_empty() {
        eprintln!("[dcert-mcp] WARNING: DCERT_MCP_OIDC_ISSUER set but DCERT_MCP_OIDC_AUDIENCE missing");
        return None;
    }

    let config = security::oidc::OidcConfig {
        issuer_url: issuer,
        audience,
        jwks_url: std::env::var("DCERT_MCP_OIDC_JWKS_URL").ok().filter(|s| !s.is_empty()),
        required_scopes: std::env::var("DCERT_MCP_REQUIRED_SCOPES")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        required_roles: std::env::var("DCERT_MCP_REQUIRED_ROLES")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        allowed_client_ids: std::env::var("DCERT_MCP_ALLOWED_CLIENTS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
    };

    match security::oidc::OidcValidator::new(config) {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("[dcert-mcp] ERROR: failed to create OIDC validator: {e}");
            None
        }
    }
}

/// Health check endpoint.
async fn health_handler() -> &'static str {
    "ok"
}

/// MCP JSON-RPC handler for HTTP mode.
async fn mcp_handler(
    axum::extract::State(state): axum::extract::State<Arc<HttpAppState>>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> axum::response::Json<serde_json::Value> {
    let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = body.get("params").cloned().unwrap_or(serde_json::Value::Null);
    let id = body.get("id").cloned().unwrap_or(serde_json::Value::Null);

    match method {
        "tools/list" => {
            let tools = state.mcp_server.tool_router.list_all();
            let tool_list: Vec<serde_json::Value> = tools
                .into_iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema
                    })
                })
                .collect();
            axum::response::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": tool_list }
            }))
        }
        "tools/call" => {
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Object(Default::default()));

            // Run the dcert binary directly for tool calls.
            let (result, is_error) = dispatch_tool_call(&state.mcp_server.config, &tool_name, &arguments).await;

            axum::response::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{"type": "text", "text": result}],
                    "isError": is_error
                }
            }))
        }
        "initialize" => {
            // Negotiate the protocol version instead of pinning the oldest
            // revision: echo the client's requested version when we support it,
            // otherwise advertise the latest version the rmcp SDK implements.
            let requested = params.get("protocolVersion").and_then(|v| v.as_str());
            axum::response::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": negotiate_protocol_version(requested),
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "dcert-mcp",
                        "version": dcert_mcp_version()
                    }
                }
            }))
        }
        _ => axum::response::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("method not found: {method}")
            }
        })),
    }
}

/// Negotiate the MCP protocol version for the HTTP transport.
///
/// Echoes the client's requested version when the rmcp SDK supports it,
/// otherwise falls back to the latest version rmcp implements. This keeps the
/// hand-rolled HTTP handler in lockstep with the stdio transport (which
/// negotiates through rmcp directly) instead of pinning the oldest revision.
pub(crate) fn negotiate_protocol_version(requested: Option<&str>) -> String {
    use rmcp::model::ProtocolVersion;
    match requested {
        Some(v) if ProtocolVersion::KNOWN_VERSIONS.iter().any(|k| k.as_str() == v) => v.to_string(),
        _ => ProtocolVersion::LATEST.as_str().to_string(),
    }
}

/// Dispatch a tool call by running the dcert binary with appropriate arguments.
///
/// Returns `(output, is_error)` so the HTTP transport can set the JSON-RPC
/// `isError` flag correctly instead of always reporting success.
pub(crate) async fn dispatch_tool_call(
    config: &McpConfig,
    tool_name: &str,
    arguments: &serde_json::Value,
) -> (String, bool) {
    // Map tool names to dcert CLI arguments.
    let mut args: Vec<String> = Vec::new();
    // Kept alive past the match so `env_vars()` can borrow from it below.
    let mut http_tls = HttpTlsParams::default();

    // The HTTP dispatch path reaches the subprocess argv directly, so it must
    // apply the same target hardening as the stdio `#[tool]` handlers: reject
    // empty, flag-like (`-`-prefixed), and null-byte-bearing targets before
    // they can be interpreted as CLI flags.
    if let Some(target) = arguments.get("target").and_then(|v| v.as_str())
        && let Err(e) = validate_target(target)
    {
        return (format!("error: {e}"), true);
    }

    match tool_name {
        "analyze_certificate" => {
            if let Some(target) = arguments.get("target").and_then(|v| v.as_str()) {
                args.push(target.to_string());
            }
            args.extend(["--format".to_string(), "json".to_string()]);
            if arguments.get("fingerprint").and_then(serde_json::Value::as_bool) == Some(true) {
                args.push("--fingerprint".to_string());
            }
            if arguments.get("extensions").and_then(serde_json::Value::as_bool) == Some(true) {
                args.push("--extensions".to_string());
            }
            if arguments.get("check_revocation").and_then(serde_json::Value::as_bool) == Some(true) {
                args.push("--check-revocation".to_string());
            }
            // HTTP/TLS params, including the connection and proxy overrides.
            // Deserializing the shared struct rather than re-reading each key by
            // hand keeps this path from drifting away from the stdio handlers —
            // `tools/list` advertises one schema for both transports.
            http_tls = serde_json::from_value(arguments.clone()).unwrap_or_default();
            if let Err(e) = http_tls.validate() {
                return (format!("error: {e}"), true);
            }
            args.extend(http_tls.to_args());
        }
        "validate_certificate" => {
            if let Some(target) = arguments.get("target").and_then(|v| v.as_str()) {
                args.push(target.to_string());
            }
            args.push("--compliance".to_string());
            args.extend(["--format".to_string(), "json".to_string()]);
        }
        _ => {
            return (format!("unknown tool: {tool_name}"), true);
        }
    }

    let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let env_refs = http_tls.env_vars();
    match run_dcert_with_env(&args_refs, config, Some(&env_refs)).await {
        Ok((stdout, stderr, code)) => {
            let mut output = stdout;
            if !stderr.is_empty() {
                output.push_str("\n--- stderr ---\n");
                output.push_str(&stderr);
            }
            if code != 0 {
                output.push_str(&format!("\n--- exit code: {code} ---"));
            }
            (output, code != 0)
        }
        Err(e) => (format!("error: {e}"), true),
    }
}
