//! Axum authentication middleware for HTTP transport mode.
//!
//! Authentication modes (in priority order):
//! 1. OIDC JWT validation (if OIDCValidator is configured)
//! 2. Static bearer token (if StaticToken is configured)
//! 3. No auth (if neither is configured) — requests pass through

use super::audit::AuditLogger;
use super::oidc::{OidcValidator, TokenClaims};
use super::scope::{ToolScopePolicy, tool_name_from_request};
use super::session::SessionCache;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use std::sync::Arc;
use tracing::warn;

/// Shared authentication state for the middleware.
pub struct AuthState {
    /// OIDC token validator. If None, OIDC auth is disabled.
    pub oidc_validator: Option<Arc<OidcValidator>>,
    /// Static bearer token for simple authentication (legacy mode).
    pub static_token: Option<String>,
    /// Optional session cache for validated tokens.
    pub session_cache: Option<Arc<SessionCache>>,
    /// Audit logger for security events.
    pub audit_logger: Option<Arc<AuditLogger>>,
    /// Per tool scope requirements, applied to every `tools/call`.
    pub tool_scopes: ToolScopePolicy,
    /// Largest request body the middleware will buffer to read the tool name.
    /// Set from the same limit the transport enforces, so a body the transport
    /// would accept is never emptied here and reported as a parse error.
    pub max_body_bytes: usize,
}

/// Axum middleware function for bearer token authentication.
pub async fn auth_middleware(
    axum::extract::State(state): axum::extract::State<Arc<AuthState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // No auth configured — pass through.
    if state.oidc_validator.is_none() && state.static_token.is_none() {
        return next.run(request).await;
    }

    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Use the real TCP peer address as the canonical remote_addr.
    // X-Forwarded-For is logged separately as supplementary info only.
    let remote_addr = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

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
        let (request, tool) = read_tool_name(request, state.max_body_bytes).await;
        if let Some(tool) = tool.as_deref()
            && let Err(reason) = state.tool_scopes.authorize(tool, &claims)
        {
            if let Some(ref logger) = state.audit_logger {
                logger.log_authz_denied(&claims, tool, &reason);
            }
            warn!(
                tool = tool,
                reason = reason.as_str(),
                "tool call denied by scope policy"
            );
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }

        if let Some(ref logger) = state.audit_logger {
            logger.log_auth_success(&claims, &session_id, &remote_addr);
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

        return next.run(request).await;
    }

    next.run(request).await
}

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
        [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
        "Unauthorized",
    )
        .into_response()
}

/// Buffer the request body far enough to read the MCP method and tool name,
/// returning a request that still carries the original body.
///
/// `max_body_bytes` is the transport's own request limit, so this cannot
/// buffer an unbounded amount and never rejects a body the transport
/// would have accepted.
async fn read_tool_name(request: Request<Body>, max_body_bytes: usize) -> (Request<Body>, Option<String>) {
    let (parts, body) = request.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, max_body_bytes).await else {
        // Leave the body empty; the transport reports the real error.
        return (Request::from_parts(parts, Body::empty()), None);
    };
    let tool = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .as_ref()
        .and_then(tool_name_from_request)
        .map(str::to_string);
    (Request::from_parts(parts, Body::from(bytes)), tool)
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

/// Extracts token claims from axum request extensions.
pub fn claims_from_request(extensions: &axum::http::Extensions) -> Option<&TokenClaims> {
    extensions.get::<TokenClaims>()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
