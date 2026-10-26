//! HTTP transport.
//!
//! The MCP protocol itself is served by rmcp's streamable HTTP transport, so
//! every tool the stdio transport exposes is reachable over HTTP with the same
//! schema, session handling and protocol negotiation. This module owns only
//! what sits around it: Host and Origin validation, authentication, rate
//! limiting, request timeouts, body limits and graceful shutdown.

use std::sync::Arc;
use std::time::Duration;

use crate::config::{AuthFailureLimitConfig, McpConfig, log_startup_diagnostics};
use crate::security;
use crate::tools::DcertMcpServer;

/// Default limit on concurrent in-flight HTTP requests.
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 64;

/// Default wall-clock limit for a single HTTP request.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 120;

/// Default maximum request body size (1 MiB). MCP requests are small; a large
/// body is either a mistake or an attempt to exhaust memory.
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Read a positive integer from the environment, falling back to `default`.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

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

/// Build the CORS layer for the HTTP MCP server.
///
/// Allowed origins are read from `DCERT_MCP_ALLOWED_ORIGINS` (comma separated).
/// When unset or empty, cross-origin browser requests are denied: no
/// `Access-Control-Allow-Origin` header is emitted, and the transport's own
/// Origin check rejects any request that carries an `Origin` header. A literal
/// `*` enables any-origin access and is logged as a warning; it is never
/// paired with credentials, and only `authorization`, `content-type` and the
/// MCP session and protocol headers are allowed.
pub(crate) fn build_cors_layer() -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderName, HeaderValue, Method};
    use tower_http::cors::{AllowOrigin, CorsLayer};

    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("mcp-session-id"),
            HeaderName::from_static("mcp-protocol-version"),
            HeaderName::from_static("last-event-id"),
        ])
        .expose_headers([HeaderName::from_static("mcp-session-id")]);

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

/// Hostnames the transport accepts in the `Host` header, guarding against DNS
/// rebinding. Defaults to loopback names plus the bind address; operators
/// widen it with `DCERT_MCP_ALLOWED_HOSTS` when the server sits behind a
/// reverse proxy or a public name.
pub(crate) fn allowed_hosts(addr: &str) -> Vec<String> {
    if let Ok(raw) = std::env::var("DCERT_MCP_ALLOWED_HOSTS") {
        let entries: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if !entries.is_empty() {
            return entries;
        }
    }
    let mut hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "[::1]".to_string(),
    ];
    hosts.push(addr.to_ascii_lowercase());
    if let Some((host, port)) = addr.rsplit_once(':') {
        hosts.push(format!("localhost:{port}"));
        hosts.push(format!("127.0.0.1:{port}"));
        hosts.push(format!("[::1]:{port}"));
        let host = host.trim_matches(['[', ']']);
        if !host.is_empty() && host != "0.0.0.0" && host != "::" {
            hosts.push(host.to_ascii_lowercase());
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Return true when `addr` binds to a loopback interface (safe to run without
/// authentication). Unparseable or non-loopback addresses are treated as
/// non-loopback so the insecure-bind guard fails closed.
///
/// A literal IP address is decided without touching the resolver. A host
/// name is resolved with a blocking lookup, so callers on an async runtime
/// go through [`addr_is_loopback_async`].
pub(crate) fn addr_is_loopback(addr: &str) -> bool {
    use std::net::{SocketAddr, ToSocketAddrs};
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return sa.ip().is_loopback();
    }
    match addr.to_socket_addrs() {
        Ok(iter) => {
            let resolved: Vec<_> = iter.collect();
            !resolved.is_empty() && resolved.iter().all(|sa| sa.ip().is_loopback())
        }
        Err(_) => false,
    }
}

/// [`addr_is_loopback`] for async callers: a host name lookup runs on the
/// blocking pool rather than stalling the runtime. A lookup that cannot be
/// run at all counts as non-loopback, so the guard still fails closed.
pub(crate) async fn addr_is_loopback_async(addr: &str) -> bool {
    let addr = addr.to_string();
    tokio::task::spawn_blocking(move || addr_is_loopback(&addr))
        .await
        .unwrap_or(false)
}

/// Build OIDC validator from environment variables (if configured).
pub(crate) fn build_oidc_validator() -> Option<security::oidc::OidcValidator> {
    let issuer = std::env::var("DCERT_MCP_OIDC_ISSUER").ok().filter(|s| !s.is_empty())?;
    let audience = std::env::var("DCERT_MCP_OIDC_AUDIENCE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    if audience.is_empty() {
        tracing::error!("DCERT_MCP_OIDC_ISSUER is set but DCERT_MCP_OIDC_AUDIENCE is missing; OIDC is disabled");
        return None;
    }

    let csv = |name: &str| -> Vec<String> {
        std::env::var(name)
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };

    let config = security::oidc::OidcConfig {
        issuer_url: issuer,
        audience,
        jwks_url: std::env::var("DCERT_MCP_OIDC_JWKS_URL").ok().filter(|s| !s.is_empty()),
        required_scopes: csv("DCERT_MCP_REQUIRED_SCOPES"),
        required_roles: csv("DCERT_MCP_REQUIRED_ROLES"),
        allowed_client_ids: csv("DCERT_MCP_ALLOWED_CLIENTS"),
    };

    match security::oidc::OidcValidator::new(config) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!(error = %e, "failed to create OIDC validator; OIDC is disabled");
            None
        }
    }
}

/// Health check endpoint. Deliberately outside the authentication layer so
/// liveness and readiness probes do not need a bearer token.
pub(crate) async fn health_handler() -> &'static str {
    "ok"
}

/// Run in HTTP mode: rmcp's streamable HTTP transport behind Host and Origin
/// validation, authentication, rate limiting, a request timeout and a body
/// size limit, with graceful shutdown on SIGINT and SIGTERM.
pub(crate) async fn run_http_mode(config: McpConfig, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    use axum::routing::get;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpService, session::local::LocalSessionManager, tower::StreamableHttpServerConfig,
    };
    use security::audit::AuditLogger;
    use security::middleware::{
        AuthFailureLimitState, AuthFailureLimiter, AuthState, auth_failure_limit_middleware, auth_middleware,
    };
    use security::scope::ToolScopePolicy;
    use security::session::{SessionCache, SessionConfig};

    // Initialize structured logging for HTTP mode. A subscriber that is
    // already installed is kept rather than treated as fatal.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .json()
        .try_init();

    log_startup_diagnostics(&config);

    // Build auth state from environment variables.
    let oidc_validator = build_oidc_validator();
    let static_token = std::env::var("DCERT_MCP_AUTH_TOKEN").ok().filter(|s| !s.is_empty());

    let auth_configured = oidc_validator.is_some() || static_token.is_some();
    if oidc_validator.is_some() {
        tracing::info!("authentication: OIDC/OAuth2 enabled");
    } else if static_token.is_some() {
        tracing::info!("authentication: static bearer token enabled");
    } else {
        tracing::warn!("authentication: DISABLED — no OIDC issuer or static token configured");
    }

    // Bearer tokens on a non loopback bind travel in plaintext unless TLS is
    // terminated in front of this server; the operator confirms that with
    // DCERT_MCP_BEHIND_TLS=1.
    if bearer_needs_tls_warning(
        auth_configured,
        addr_is_loopback_async(addr).await,
        std::env::var("DCERT_MCP_BEHIND_TLS").ok().as_deref(),
    ) {
        tracing::warn!(
            addr = addr,
            "bearer authentication on a non-loopback address: tokens travel in plaintext unless TLS is \
             terminated in front of this server. Terminate TLS and set DCERT_MCP_BEHIND_TLS=1 to confirm."
        );
    }

    // Refuse to expose an unauthenticated endpoint on a non-loopback interface.
    // Binding to a public or LAN address with no OIDC issuer and no static
    // token lets any host on the network drive an API that spawns subprocesses.
    if !auth_configured && !addr_is_loopback_async(addr).await {
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

    // Session cache for validated tokens. A zero TTL would expire every entry
    // on its first read, so it falls back to the default like any other
    // unusable value.
    let session_ttl = std::env::var("DCERT_MCP_SESSION_TTL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(300);
    let session_cache = Arc::new(SessionCache::new(SessionConfig {
        inactivity_ttl: Duration::from_secs(session_ttl),
        ..SessionConfig::default()
    }));

    // Per tool authorization is decided from the token's scopes and roles, so
    // it can only be enforced when tokens are validated. A static token
    // carries no claims and would satisfy no rule. Refusing to start is the
    // honest outcome: silently ignoring the policy, or silently denying every
    // guarded tool, would both leave the operator with a server that does not
    // behave as configured.
    let tool_scopes = ToolScopePolicy::from_env();
    if tool_scopes.is_empty() {
        tracing::info!(
            "per tool authorization: not configured (set DCERT_MCP_SCOPE_WRITE, DCERT_MCP_SCOPE_READ \
             or DCERT_MCP_SCOPE_<TOOL> to require scopes per tool)"
        );
    } else if oidc_validator.is_none() {
        return Err(
            "refusing to start: DCERT_MCP_SCOPE_* requires OIDC. Per tool scopes are read \
             from a validated token, which a static bearer token does not carry. Configure \
             DCERT_MCP_OIDC_ISSUER, or unset the DCERT_MCP_SCOPE_* variables."
                .into(),
        );
    } else {
        tracing::info!("per tool authorization: enabled");
    }

    // One limit for the body, shared by the transport and by the middleware
    // that peeks at the tool name, so the two cannot disagree.
    let max_body_bytes = env_usize("DCERT_MCP_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES);

    let audit_logger = Arc::new(AuditLogger::new());
    let auth_state = Arc::new(AuthState {
        oidc_validator: oidc_validator.map(Arc::new),
        static_token,
        session_cache: Some(session_cache),
        audit_logger: Some(audit_logger.clone()),
        tool_scopes,
        max_body_bytes,
    });

    // Failed authentication attempts are limited per client address ahead of
    // authentication, so a bearer token cannot be guessed online at line
    // rate. With no authentication there are no failures to count, and a
    // limit of zero makes the layer a no-op, so it is always installed.
    let failure_limit = AuthFailureLimitConfig::from_env().map_err(|e| format!("refusing to start: {e}"))?;
    if !auth_configured {
        tracing::info!("authentication failure limiter: idle (no authentication configured)");
    } else if failure_limit.is_enabled() {
        tracing::info!(
            limit = failure_limit.limit,
            window_secs = failure_limit.window.as_secs(),
            "authentication failure limiter: enabled per client address (requests from behind a shared \
             proxy address count together)"
        );
    } else {
        tracing::warn!("authentication failure limiter: DISABLED (DCERT_MCP_AUTH_FAILURE_LIMIT=0)");
    }
    let failure_limit_state = Arc::new(AuthFailureLimitState {
        limiter: AuthFailureLimiter::new(failure_limit.limit, failure_limit.window),
        audit_logger: Some(audit_logger),
    });

    // One cancellation token drives both the transport's session teardown and
    // axum's graceful shutdown, so a signal closes in-flight work in order.
    let shutdown = tokio_util::sync::CancellationToken::new();

    let hosts = allowed_hosts(addr);
    tracing::info!(hosts = ?hosts, "Host header allowlist (set DCERT_MCP_ALLOWED_HOSTS to change)");
    let mut transport_config = StreamableHttpServerConfig::default()
        .with_cancellation_token(shutdown.clone())
        .with_allowed_hosts(hosts)
        .with_max_request_body_bytes(max_body_bytes);

    // Origin validation: an allowlist is enforced as given; with no allowlist
    // every request carrying an Origin header is rejected, which is what stops
    // a browser page on another origin from driving the tool API.
    transport_config = match parse_allowed_origins(&std::env::var("DCERT_MCP_ALLOWED_ORIGINS").unwrap_or_default()) {
        CorsOriginPolicy::List(entries) => transport_config.with_allowed_origins(entries),
        CorsOriginPolicy::Any => transport_config,
        CorsOriginPolicy::None => transport_config.enforce_origin_validation(),
    };

    let server_config = Arc::new(config);
    let mcp_service = StreamableHttpService::new(
        {
            let server_config = server_config.clone();
            move || Ok(DcertMcpServer::with_shared_config(server_config.clone()))
        },
        Arc::new(LocalSessionManager::default()),
        transport_config,
    );

    let max_concurrent = env_usize("DCERT_MCP_MAX_CONCURRENT_REQUESTS", DEFAULT_MAX_CONCURRENT_REQUESTS);
    let request_timeout = Duration::from_secs(
        std::env::var("DCERT_MCP_REQUEST_TIMEOUT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
    );

    // Layer order matters, and the two wrappers order in opposite directions.
    //
    // `ServiceBuilder::layer` wraps outermost-FIRST, so on the MCP route the
    // failure limiter runs first, then authentication, and only then is a
    // concurrency permit taken: a request from a locked out address or with
    // a bad token is rejected without occupying a slot, which is what stops
    // an unauthenticated flood from filling the limit. The limit is scoped to
    // `/mcp` so `/health` still answers a liveness probe while the tool API is
    // saturated.
    //
    // `Router::layer` wraps outermost-LAST, so the listed order runs bottom-up
    // and the timeout ends up OUTSIDE the concurrency limit. That is the point
    // of the split: tower's concurrency queue is unbounded, so a timeout
    // nested inside it would only start once a permit was granted and a queued
    // request would wait indefinitely instead of receiving the 504. CORS sits
    // below the timeout so preflights are answered before authentication can
    // reject them.
    let app = axum::Router::new()
        .route("/health", get(health_handler))
        .nest_service(
            "/mcp",
            axum::routing::any_service(
                tower::ServiceBuilder::new()
                    .layer(axum::middleware::from_fn_with_state(
                        failure_limit_state,
                        auth_failure_limit_middleware,
                    ))
                    .layer(axum::middleware::from_fn_with_state(auth_state, auth_middleware))
                    .layer(tower::limit::GlobalConcurrencyLimitLayer::new(max_concurrent))
                    .service(mcp_service),
            ),
        )
        .layer(build_cors_layer())
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::GATEWAY_TIMEOUT,
            request_timeout,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        addr = addr,
        max_concurrent_requests = max_concurrent,
        request_timeout_secs = request_timeout.as_secs(),
        "dcert-mcp HTTP server listening"
    );

    let shutdown_signal = {
        let shutdown = shutdown.clone();
        async move {
            wait_for_shutdown_signal().await;
            tracing::info!("shutdown signal received; draining in-flight requests");
            shutdown.cancel();
        }
    };

    // ConnectInfo gives the middleware the TCP peer address, which keys the
    // failure limiter and is what the audit log records as the client.
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal)
    .into_future();
    tokio::pin!(server);
    // In-flight requests get DRAIN_DEADLINE to finish after a signal; a
    // request stuck on a slow peer must not keep the process alive forever.
    let drain_expired = async {
        shutdown.cancelled().await;
        tokio::time::sleep(DRAIN_DEADLINE).await;
    };
    tokio::select! {
        result = &mut server => result?,
        () = drain_expired => {
            tracing::warn!(
                deadline_secs = DRAIN_DEADLINE.as_secs(),
                "drain deadline passed; exiting with requests still in flight"
            );
        }
    }

    tracing::info!("dcert-mcp HTTP server stopped");
    Ok(())
}

/// How long in-flight requests may run after a shutdown signal.
pub(crate) const DRAIN_DEADLINE: Duration = Duration::from_secs(10);

/// Resolve when the process is asked to stop: Ctrl+C on any platform, or
/// SIGTERM on Unix (how a container runtime asks a process to exit).
pub(crate) async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "failed to listen for Ctrl+C");
            // Never resolve: without a working handler, let the other branch win.
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    // Windows has no SIGTERM: Ctrl+Break and closing the console window (or
    // the service host ending the session) are its termination requests.
    #[cfg(windows)]
    let terminate = async {
        use tokio::signal::windows;
        match (windows::ctrl_break(), windows::ctrl_close(), windows::ctrl_shutdown()) {
            (Ok(mut brk), Ok(mut close), Ok(mut shutdown)) => {
                tokio::select! {
                    _ = brk.recv() => {},
                    _ = close.recv() => {},
                    _ = shutdown.recv() => {},
                }
            }
            _ => {
                tracing::error!("failed to listen for Ctrl+Break or console close");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(any(unix, windows)))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

/// Whether to warn that bearer tokens would cross the network in plaintext:
/// authentication is on, the bind is not loopback and the operator has not
/// confirmed TLS termination in front of the server.
pub(crate) fn bearer_needs_tls_warning(auth_configured: bool, loopback: bool, behind_tls: Option<&str>) -> bool {
    let confirmed = behind_tls.is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    auth_configured && !loopback && !confirmed
}
