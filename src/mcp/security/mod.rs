//! OIDC/OAuth2 authentication for dcert-mcp.
//!
//! This module provides MCP Security Best Practices compliant authentication:
//! - JWT validation with JWKS (signature, issuer, audience, expiry)
//! - In-memory session cache with sliding window TTL
//! - Structured audit logging for security events
//! - Axum middleware for HTTP transport authentication

// These modules expose public APIs for extensibility; not all items are
// used internally but are available for consumers and downstream integration.
#[allow(dead_code)]
pub mod audit;
#[allow(dead_code)]
pub mod middleware;
#[allow(dead_code)]
pub mod oidc;
#[allow(dead_code)]
pub mod session;
