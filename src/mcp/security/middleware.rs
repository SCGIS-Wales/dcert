//! Axum authentication middleware for HTTP transport mode.
//!
//! Authentication modes (in priority order):
//! 1. OIDC JWT validation (if OIDCValidator is configured)
//! 2. Static bearer token (if StaticToken is configured)
//! 3. No auth (if neither is configured) — requests pass through

use super::audit::AuditLogger;
use super::oidc::{OidcValidator, TokenClaims};
use super::session::SessionCache;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
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

    let remote_addr = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // OIDC mode.
    if let Some(ref validator) = state.oidc_validator {
        let token = extract_bearer_token(auth_header);
        if token.is_empty() {
            if let Some(ref logger) = state.audit_logger {
                logger.log_auth_failure("missing bearer token", &remote_addr);
            }
            return (StatusCode::UNAUTHORIZED, "Unauthorized: missing bearer token").into_response();
        }

        // Check session cache first.
        let mut claims: Option<TokenClaims> = None;
        if let Some(ref cache) = state.session_cache {
            claims = cache.get(token).await;
        }

        if claims.is_none() {
            // Validate the token.
            match validator.validate_token(token).await {
                Ok(validated) => {
                    // Cache the validated claims.
                    if let Some(ref cache) = state.session_cache {
                        let key = SessionCache::cache_key(&validated.object_id, &validated.subject);
                        cache.put(key, validated.clone()).await;
                    }
                    claims = Some(validated);
                }
                Err(e) => {
                    if let Some(ref logger) = state.audit_logger {
                        logger.log_auth_failure(&e, &remote_addr);
                    }
                    warn!(
                        error = e.as_str(),
                        remote_addr = remote_addr.as_str(),
                        "OIDC token validation failed"
                    );
                    return (StatusCode::UNAUTHORIZED, format!("Unauthorized: {e}")).into_response();
                }
            }
        }

        if let Some(ref claims) = claims {
            if let Some(ref logger) = state.audit_logger {
                logger.log_auth_success(claims, "", &remote_addr);
            }
        }

        // Inject claims into request extensions.
        let mut request = request;
        if let Some(claims) = claims {
            request.extensions_mut().insert(claims);
        }

        return next.run(request).await;
    }

    // Static token mode (legacy).
    if let Some(ref expected) = state.static_token {
        let expected_header = format!("Bearer {expected}");
        if !constant_time_eq(auth_header.as_bytes(), expected_header.as_bytes()) {
            if let Some(ref logger) = state.audit_logger {
                logger.log_auth_failure("invalid static token", &remote_addr);
            }
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
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

/// Constant-time byte comparison to prevent timing attacks on token comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
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
