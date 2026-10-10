//! OIDC/OAuth2 authentication for dcert-mcp.
//!
//! This module provides MCP Security Best Practices compliant authentication:
//! - JWT validation with JWKS (signature, issuer, audience, expiry)
//! - In-memory session cache with sliding window TTL
//! - Structured audit logging for security events
//! - Per tool authorization scopes
//! - Axum middleware for HTTP transport authentication

pub mod audit;
pub mod middleware;
pub mod oidc;
pub mod scope;
pub mod session;
