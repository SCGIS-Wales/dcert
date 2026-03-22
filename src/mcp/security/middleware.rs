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
            return (StatusCode::UNAUTHORIZED, "Unauthorized: missing bearer token").into_response();
        }

        // Check session cache first.
        // Use a hash of the raw token as cache key so get/put use the same key,
        // while avoiding storing the sensitive bearer token as a map key.
        let cache_key = token_cache_key(token);
        let mut claims: Option<TokenClaims> = None;
        if let Some(ref cache) = state.session_cache {
            claims = cache.get(&cache_key).await;
        }

        if claims.is_none() {
            // Validate the token.
            match validator.validate_token(token).await {
                Ok(validated) => {
                    // Cache the validated claims.
                    if let Some(ref cache) = state.session_cache {
                        cache.put(cache_key.clone(), validated.clone()).await;
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

        if let Some(ref claims) = claims
            && let Some(ref logger) = state.audit_logger
        {
            logger.log_auth_success(claims, "", &remote_addr);
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

/// Derives a cache key from a bearer token by hashing it with SHA-256.
/// This avoids storing the raw token in the cache while ensuring consistent keys.
fn token_cache_key(token: &str) -> String {
    use openssl::hash::{MessageDigest, hash};
    match hash(MessageDigest::sha256(), token.as_bytes()) {
        Ok(digest) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
        Err(_) => token.len().to_string(), // fallback — effectively disables caching
    }
}

/// Constant-time byte comparison to prevent timing attacks on token comparison.
/// Uses the `subtle` crate to avoid leaking length or content via timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
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
