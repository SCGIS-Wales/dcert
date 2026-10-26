//! Axum authentication middleware for HTTP transport mode.
//!
//! Authentication modes (in priority order):
//! 1. OIDC JWT validation (if an OIDC validator is configured)
//! 2. Static bearer token (if `DCERT_MCP_AUTH_TOKEN` is configured)
//! 3. No auth (if neither is configured): requests pass through
//!
//! Ahead of authentication sits [`auth_failure_limit_middleware`]. It counts
//! `401` responses per client address and answers `429` once a client has
//! used up its allowance for the window, so a bearer token cannot be guessed
//! online at line rate.

use super::audit::AuditLogger;
use super::oidc::{OidcValidator, TokenClaims};
use super::scope::{ToolRequest, ToolScopePolicy, classify_request};
use super::session::SessionCache;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Shared authentication state for the middleware.
pub struct AuthState {
    /// OIDC token validator. If None, OIDC auth is disabled.
    pub oidc_validator: Option<Arc<OidcValidator>>,
    /// Static bearer token, for deployments without an identity provider.
    /// Used only when no OIDC validator is configured.
    pub static_token: Option<String>,
    /// Optional session cache for validated tokens.
    pub session_cache: Option<Arc<SessionCache>>,
    /// Audit logger for security events.
    pub audit_logger: Option<Arc<AuditLogger>>,
    /// Per tool scope requirements, applied to every `tools/call`.
    pub tool_scopes: ToolScopePolicy,
    /// Largest request body the middleware will buffer to read the tool name.
    /// Set from the same limit the transport enforces, so a body the transport
    /// would accept is never rejected here.
    pub max_body_bytes: usize,
}

/// Axum middleware function for bearer token authentication.
pub async fn auth_middleware(State(state): State<Arc<AuthState>>, request: Request<Body>, next: Next) -> Response {
    // No auth configured: pass through.
    if state.oidc_validator.is_none() && state.static_token.is_none() {
        return next.run(request).await;
    }

    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // The TCP peer address is the canonical remote address. There is no
    // notion of a trusted proxy here, so `X-Forwarded-For` is never consulted:
    // it is client supplied and would let a caller choose its own identity in
    // the audit log and in the failure limiter.
    let remote_addr = client_ip(&request).map_or_else(|| "unknown".to_string(), |ip| ip.to_string());

    // OIDC mode.
    if let Some(ref validator) = state.oidc_validator {
        let token = extract_bearer_token(auth_header);
        if token.is_empty() {
            if let Some(ref logger) = state.audit_logger {
                logger.log_auth_failure("missing bearer token", &remote_addr);
            }
            return unauthorized();
        }

        // Check session cache first.
        // Use a hash of the raw token as cache key so get/put use the same key,
        // while avoiding storing the sensitive bearer token as a map key.
        let cache_key = token_cache_key(token);
        let mut claims: Option<TokenClaims> = None;
        if let (Some(cache), Some(key)) = (state.session_cache.as_ref(), cache_key.as_ref()) {
            claims = cache.get(key).await;
        }

        if claims.is_none() {
            // Validate the token.
            match validator.validate_token(token).await {
                Ok(validated) => {
                    // Cache the validated claims (only when we have a real hash
                    // key; a hashing failure skips caching rather than falling
                    // back to a collision-prone key).
                    if let (Some(cache), Some(key)) = (state.session_cache.as_ref(), cache_key.as_ref()) {
                        cache.put(key.clone(), validated.clone()).await;
                    }
                    claims = Some(validated);
                }
                Err(e) => {
                    if let Some(ref logger) = state.audit_logger {
                        logger.log_auth_failure(&e, &remote_addr);
                    }
                    // The reason is logged, never returned: issuer, audience,
                    // kid and JWKS details must not reach an unauthenticated
                    // caller.
                    warn!(
                        error = e.as_str(),
                        remote_addr = remote_addr.as_str(),
                        "OIDC token validation failed"
                    );
                    return unauthorized();
                }
            }
        }

        // Every authenticated request carries a session id, so audit records
        // can be correlated and a session revoked. It is derived from the
        // token hash, which is stable for the life of the token and reveals
        // nothing about it.
        let session_id = cache_key.clone().unwrap_or_default();

        let Some(claims) = claims else {
            return unauthorized();
        };

        // Per tool authorization: a token that passes the global scope check
        // is not automatically allowed to call a destructive tool.
        let (request, tool_request) = match read_tool_request(request, state.max_body_bytes).await {
            Ok(read) => read,
            Err(response) => return *response,
        };
        if let Err(reason) = state.tool_scopes.authorize_request(&tool_request, &claims) {
            let action = match &tool_request {
                ToolRequest::Call { tool, .. } => tool.as_str(),
                _ => "<undetermined>",
            };
            if let Some(ref logger) = state.audit_logger {
                logger.log_authz_denied(&claims, action, &reason);
            }
            warn!(
                tool = action,
                reason = reason.as_str(),
                "tool call denied by scope policy"
            );
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }

        if let Some(ref logger) = state.audit_logger {
            logger.log_auth_success(&claims, &session_id, &remote_addr);
            log_tool_call(logger, Some(&claims), &tool_request, &remote_addr);
        }

        // Inject claims into request extensions.
        let mut request = request;
        request.extensions_mut().insert(claims);

        return next.run(request).await;
    }

    // Static token mode.
    if let Some(ref expected) = state.static_token {
        // Parse the header the same way as the OIDC path (any case of the
        // `Bearer` prefix), then compare the token itself in constant time
        // over a fixed-width digest so neither its length nor its content
        // leaks through timing.
        let presented = extract_bearer_token(auth_header);
        if !constant_time_eq_hashed(presented, expected) {
            if let Some(ref logger) = state.audit_logger {
                logger.log_auth_failure("invalid static token", &remote_addr);
            }
            return unauthorized();
        }

        if let Some(ref logger) = state.audit_logger {
            let (request, tool_request) = match read_tool_request(request, state.max_body_bytes).await {
                Ok(read) => read,
                Err(response) => return *response,
            };
            log_tool_call(logger, None, &tool_request, &remote_addr);
            return next.run(request).await;
        }
        return next.run(request).await;
    }

    next.run(request).await
}

/// One audit record per tool call.
fn log_tool_call(logger: &AuditLogger, claims: Option<&TokenClaims>, request: &ToolRequest, remote_addr: &str) {
    if let ToolRequest::Call { tool, target } = request {
        logger.log_tool_call(claims, tool, target.as_deref(), remote_addr);
    }
}

// --- Authentication failure limiter ---

/// Upper bound on the number of client addresses the limiter tracks. When it
/// is reached, expired windows are dropped first and then the oldest window,
/// so a flood from many source addresses cannot grow the map without bound.
const AUTH_FAILURE_MAX_TRACKED_ADDRS: usize = 10_000;

/// Recent authentication failures from one client address.
#[derive(Debug, Clone, Copy)]
struct FailureWindow {
    started: Instant,
    failures: u32,
}

/// In process limiter for failed authentication attempts, keyed by client IP.
///
/// A fixed window opens at a client's first failure. Once the client has
/// failed `limit` times inside it, every request from that address is refused
/// with `429` until the window closes. Refused requests do not extend the
/// window, so a locked out client recovers after at most `window`. A limit of
/// zero disables the limiter.
#[derive(Debug)]
pub struct AuthFailureLimiter {
    limit: u32,
    window: Duration,
    max_tracked: usize,
    windows: Mutex<HashMap<IpAddr, FailureWindow>>,
}

impl AuthFailureLimiter {
    /// Limiter allowing `limit` failures per `window` from one address.
    pub fn new(limit: u32, window: Duration) -> Self {
        Self::with_capacity(limit, window, AUTH_FAILURE_MAX_TRACKED_ADDRS)
    }

    /// As [`AuthFailureLimiter::new`], tracking at most `max_tracked` addresses.
    pub fn with_capacity(limit: u32, window: Duration, max_tracked: usize) -> Self {
        Self {
            limit,
            window,
            max_tracked: max_tracked.max(1),
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Failures allowed per window; zero means the limiter is disabled.
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Length of the failure window.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// The map is only ever mutated under this lock in short, panic free
    /// sections, so a poisoned lock still holds a usable map.
    fn lock(&self) -> MutexGuard<'_, HashMap<IpAddr, FailureWindow>> {
        self.windows.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How long `ip` must wait before it may try again, or `None` when the
    /// request may proceed to authentication.
    pub fn check(&self, ip: IpAddr) -> Option<Duration> {
        if self.limit == 0 {
            return None;
        }
        let now = Instant::now();
        let mut windows = self.lock();
        let entry = windows.get(&ip).copied()?;
        let elapsed = now.saturating_duration_since(entry.started);
        if elapsed >= self.window {
            windows.remove(&ip);
            return None;
        }
        if entry.failures >= self.limit {
            Some(self.window.saturating_sub(elapsed))
        } else {
            None
        }
    }

    /// Record one failed attempt from `ip` and return its failure count in
    /// the current window.
    pub fn record_failure(&self, ip: IpAddr) -> u32 {
        if self.limit == 0 {
            return 0;
        }
        let now = Instant::now();
        let mut windows = self.lock();

        if let Some(entry) = windows.get_mut(&ip)
            && now.saturating_duration_since(entry.started) < self.window
        {
            entry.failures = entry.failures.saturating_add(1);
            return entry.failures;
        }

        // A new window for an address not yet tracked must not push the map
        // past its cap: drop closed windows first, then the oldest open one.
        if !windows.contains_key(&ip) && windows.len() >= self.max_tracked {
            windows.retain(|_, w| now.saturating_duration_since(w.started) < self.window);
            if windows.len() >= self.max_tracked
                && let Some(oldest) = windows.iter().min_by_key(|(_, w)| w.started).map(|(ip, _)| *ip)
            {
                windows.remove(&oldest);
            }
        }

        windows.insert(
            ip,
            FailureWindow {
                started: now,
                failures: 1,
            },
        );
        1
    }

    /// Number of addresses currently tracked.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.lock().len()
    }
}

/// Shared state for [`auth_failure_limit_middleware`].
#[derive(Debug)]
pub struct AuthFailureLimitState {
    /// The limiter itself.
    pub limiter: AuthFailureLimiter,
    /// Audit logger for `auth_rate_limited` events.
    pub audit_logger: Option<Arc<AuditLogger>>,
}

/// Axum middleware that refuses requests from a client address that has
/// exceeded the authentication failure limit. It runs outside
/// [`auth_middleware`] and counts the `401` responses that come back from it.
pub async fn auth_failure_limit_middleware(
    State(state): State<Arc<AuthFailureLimitState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(ip) = client_ip(&request) else {
        // Without a peer address there is nothing to key on. The request is
        // still authenticated by the layer below.
        return next.run(request).await;
    };

    if let Some(retry_after) = state.limiter.check(ip) {
        let retry_after_secs = whole_seconds(retry_after);
        if let Some(ref logger) = state.audit_logger {
            logger.log_auth_rate_limited(&ip.to_string(), retry_after_secs);
        }
        return too_many_requests(retry_after_secs);
    }

    let response = next.run(request).await;
    if response.status() == StatusCode::UNAUTHORIZED {
        let failures = state.limiter.record_failure(ip);
        if failures == state.limiter.limit() {
            warn!(
                remote_addr = %ip,
                failures,
                window_secs = state.limiter.window().as_secs(),
                "client reached the authentication failure limit; refusing further attempts for the window"
            );
        }
    }
    response
}

/// Round a duration up to whole seconds, never below one, for `Retry-After`.
fn whole_seconds(d: Duration) -> u64 {
    let secs = if d.subsec_nanos() > 0 {
        d.as_secs().saturating_add(1)
    } else {
        d.as_secs()
    };
    secs.max(1)
}

/// A bare `429` carrying only the time to wait.
fn too_many_requests(retry_after_secs: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after_secs.to_string())],
        "Too Many Requests",
    )
        .into_response()
}

/// The TCP peer address recorded by `into_make_service_with_connect_info`.
fn client_ip(request: &Request<Body>) -> Option<IpAddr> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

// --- Helpers ---

/// Extracts the token from a "Bearer <token>" Authorization header.
fn extract_bearer_token(auth_header: &str) -> &str {
    if auth_header.is_empty() {
        return "";
    }
    let parts: Vec<&str> = auth_header.splitn(2, ' ').collect();
    if parts.len() != 2 || !parts[0].eq_ignore_ascii_case("Bearer") {
        return "";
    }
    parts[1].trim()
}

/// A uniform 401 for every authentication failure. The reason is written to
/// the audit log, never to the response body.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "Unauthorized",
    )
        .into_response()
}

/// A bare `413` for a body over the configured limit.
fn payload_too_large() -> Response {
    (StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large").into_response()
}

/// Buffer the request body far enough to classify the MCP request,
/// returning a request that still carries the original body.
///
/// `max_body_bytes` is the transport's own request limit, so this never
/// rejects a body the transport would have accepted. A body over the limit is
/// answered with `413` here rather than handed on empty, which the transport
/// would otherwise report as a parse error. A body that cannot be read at all
/// is answered with `400`. The response is boxed so the `Ok` path, which is
/// the common one, does not carry its size.
async fn read_tool_request(
    request: Request<Body>,
    max_body_bytes: usize,
) -> Result<(Request<Body>, ToolRequest), Box<Response>> {
    // A declared length over the limit is refused before any of it is read.
    let limit = u64::try_from(max_body_bytes).unwrap_or(u64::MAX);
    if let Some(declared) = declared_content_length(request.headers())
        && declared > limit
    {
        return Err(Box::new(payload_too_large()));
    }

    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(e) if is_length_limit_error(&e) => return Err(Box::new(payload_too_large())),
        Err(e) => {
            debug!(error = %e, "failed to read request body");
            return Err(Box::new((StatusCode::BAD_REQUEST, "Bad Request").into_response()));
        }
    };
    let tool_request = classify_request(&bytes);
    Ok((Request::from_parts(parts, Body::from(bytes)), tool_request))
}

/// The `Content-Length` header as a number, if present and well formed.
fn declared_content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// `true` when `axum::body::to_bytes` failed because the body exceeded the
/// limit rather than because it could not be read. The underlying
/// `LengthLimitError` type is not re-exported by axum, so the check is on its
/// message, which is covered by a test here.
fn is_length_limit_error(e: &axum::Error) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = current {
        if err.to_string() == "length limit exceeded" {
            return true;
        }
        current = err.source();
    }
    false
}

/// Derives a cache key from a bearer token by hashing it with SHA-256.
/// This avoids storing the raw token in the cache while ensuring consistent keys.
///
/// Returns `None` if hashing fails so the caller skips the cache entirely. A
/// length-based fallback would collide all tokens of equal length, which could
/// let an unvalidated token receive claims cached for a validated one.
fn token_cache_key(token: &str) -> Option<String> {
    use openssl::hash::{MessageDigest, hash};
    hash(MessageDigest::sha256(), token.as_bytes())
        .ok()
        .map(|digest| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

/// Constant-time byte comparison. `subtle`'s slice implementation short
/// circuits when the lengths differ, so callers that compare secrets of
/// unknown length must use [`constant_time_eq_hashed`] instead.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Compare two secrets in constant time regardless of their lengths, by
/// comparing fixed-width SHA-256 digests. A hashing failure compares as false
/// so the request is rejected rather than accepted.
fn constant_time_eq_hashed(presented: &str, expected: &str) -> bool {
    use openssl::hash::{MessageDigest, hash};
    match (
        hash(MessageDigest::sha256(), presented.as_bytes()),
        hash(MessageDigest::sha256(), expected.as_bytes()),
    ) {
        (Ok(a), Ok(b)) => constant_time_eq(&a, &b),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::any;
    use tower::ServiceExt as _;

    #[test]
    fn test_extract_bearer_token_valid() {
        assert_eq!(extract_bearer_token("Bearer abc123"), "abc123");
        assert_eq!(extract_bearer_token("bearer ABC"), "ABC");
        assert_eq!(extract_bearer_token("BEARER token"), "token");
    }

    #[test]
    fn test_extract_bearer_token_empty() {
        assert_eq!(extract_bearer_token(""), "");
    }

    #[test]
    fn test_extract_bearer_token_no_bearer_prefix() {
        assert_eq!(extract_bearer_token("Basic abc123"), "");
        assert_eq!(extract_bearer_token("Token abc123"), "");
    }

    #[test]
    fn test_extract_bearer_token_no_value() {
        assert_eq!(extract_bearer_token("Bearer"), "");
    }

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    // --- read_tool_name (L2) ---

    fn tools_call(tool: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}
        })
        .to_string()
    }

    #[tokio::test]
    async fn read_tool_name_returns_the_tool_and_the_original_body() {
        let body = tools_call("vault_revoke");
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .body(Body::from(body.clone()))
            .expect("request");
        let (request, tool) = read_tool_request(request, 1024).await.expect("under the limit");
        assert!(
            matches!(tool, ToolRequest::Call { ref tool, .. } if tool == "vault_revoke"),
            "{tool:?}"
        );
        let replayed = axum::body::to_bytes(request.into_body(), 1024).await.expect("body");
        assert_eq!(replayed, body.as_bytes());
    }

    #[tokio::test]
    async fn read_tool_name_answers_413_for_a_body_over_the_limit() {
        let body = tools_call("vault_revoke");
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .body(Body::from(body.clone()))
            .expect("request");
        let response = read_tool_request(request, 16)
            .await
            .expect_err("a body over the limit is rejected");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn read_tool_name_answers_413_from_the_declared_length_without_reading() {
        // The declared length is over the limit even though the body sent is
        // not, so the rejection must come from the header alone.
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::CONTENT_LENGTH, "4096")
            .body(Body::from("{}"))
            .expect("request");
        let response = read_tool_request(request, 1024).await.expect_err("rejected");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn length_limit_error_is_recognised() {
        let err = axum::body::to_bytes(Body::from(vec![0u8; 64]), 8)
            .await
            .expect_err("over the limit");
        assert!(is_length_limit_error(&err));
    }

    // --- AuthFailureLimiter (M8) ---

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn limiter_allows_until_the_limit_then_refuses_for_the_window() {
        let limiter = AuthFailureLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check(ip(1)).is_none());
        assert_eq!(limiter.record_failure(ip(1)), 1);
        assert_eq!(limiter.record_failure(ip(1)), 2);
        assert!(limiter.check(ip(1)).is_none(), "two failures are under the limit");
        assert_eq!(limiter.record_failure(ip(1)), 3);
        let wait = limiter.check(ip(1)).expect("the third failure locks the address out");
        assert!(wait <= Duration::from_secs(60));
        assert!(wait > Duration::from_secs(55));
        assert!(limiter.check(ip(2)).is_none(), "other addresses are unaffected");
    }

    #[tokio::test]
    async fn limiter_forgets_an_address_once_its_window_has_closed() {
        let limiter = AuthFailureLimiter::new(1, Duration::from_millis(20));
        limiter.record_failure(ip(1));
        assert!(limiter.check(ip(1)).is_some());
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(limiter.check(ip(1)).is_none());
        assert_eq!(limiter.tracked(), 0, "a closed window is dropped on the next check");
        assert_eq!(limiter.record_failure(ip(1)), 1, "a new window starts from one");
    }

    #[test]
    fn limiter_caps_the_number_of_tracked_addresses() {
        let limiter = AuthFailureLimiter::with_capacity(5, Duration::from_secs(60), 3);
        for last in 1..=50 {
            limiter.record_failure(ip(last));
            assert!(limiter.tracked() <= 3, "the map must never exceed its cap");
        }
        // The most recent addresses survive; the oldest were evicted.
        assert!(limiter.check(ip(50)).is_none());
        assert_eq!(limiter.record_failure(ip(50)), 2);
        assert_eq!(limiter.record_failure(ip(1)), 1, "an evicted address starts afresh");
    }

    #[test]
    fn a_zero_limit_disables_the_limiter() {
        let limiter = AuthFailureLimiter::new(0, Duration::from_secs(60));
        for _ in 0..100 {
            assert_eq!(limiter.record_failure(ip(1)), 0);
        }
        assert!(limiter.check(ip(1)).is_none());
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        assert_eq!(whole_seconds(Duration::from_millis(1)), 1);
        assert_eq!(whole_seconds(Duration::from_millis(1500)), 2);
        assert_eq!(whole_seconds(Duration::from_secs(3)), 3);
        assert_eq!(whole_seconds(Duration::ZERO), 1);
    }

    // --- Middleware stack ---

    /// `/` behind the failure limiter and static token authentication, as the
    /// transport wires them.
    fn app(limit: u32, window: Duration) -> Router {
        let auth = Arc::new(AuthState {
            oidc_validator: None,
            static_token: Some("correct-horse".to_string()),
            session_cache: None,
            audit_logger: Some(Arc::new(AuditLogger::new())),
            tool_scopes: ToolScopePolicy::default(),
            max_body_bytes: 1024,
        });
        let limiter = Arc::new(AuthFailureLimitState {
            limiter: AuthFailureLimiter::new(limit, window),
            audit_logger: Some(Arc::new(AuditLogger::new())),
        });
        // `Router::layer` wraps outermost last, so the limiter sits outside
        // authentication and sees its 401s.
        Router::new()
            .route("/", any(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(auth, auth_middleware))
            .layer(axum::middleware::from_fn_with_state(
                limiter,
                auth_failure_limit_middleware,
            ))
    }

    fn request_from(peer: IpAddr, token: &str) -> Request<Body> {
        let mut request = Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer, 40_000)));
        request
    }

    #[tokio::test]
    async fn repeated_bad_tokens_are_answered_429_with_retry_after() {
        let app = app(2, Duration::from_secs(60));

        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(request_from(ip(1), "wrong"))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // The limit is reached: even the correct token is refused now, so a
        // guessed token cannot be confirmed from the locked out address.
        for token in ["wrong", "correct-horse"] {
            let response = app.clone().oneshot(request_from(ip(1), token)).await.expect("response");
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            let retry_after = response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .expect("Retry-After in whole seconds");
            assert!((1..=60).contains(&retry_after), "{retry_after}");
        }

        // Another address is unaffected and the correct token still works.
        let response = app
            .clone()
            .oneshot(request_from(ip(2), "correct-horse"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_successful_request_does_not_count_as_a_failure() {
        let app = app(1, Duration::from_secs(60));
        for _ in 0..5 {
            let response = app
                .clone()
                .oneshot(request_from(ip(1), "correct-horse"))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn a_request_without_a_peer_address_is_still_authenticated() {
        let app = app(1, Duration::from_secs(60));
        let request = Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, "Bearer wrong")
            .body(Body::empty())
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
