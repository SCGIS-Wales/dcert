//! Structured audit logging for security events.
//!
//! Each application in the chain must log:
//! - Timestamp (UTC)
//! - Caller app ID (azp claim)
//! - Caller user OID/UPN
//! - Caller tenant ID
//! - Received scopes (scp claim)
//! - Resource accessed / action performed
//! - Result status
//! - OBO token source (cache/provider)
//! - OBO latency

use super::oidc::TokenClaims;
use tracing::info;

/// Structured audit logger for security events.
pub struct AuditLogger;

impl AuditLogger {
    /// Creates a new audit logger.
    pub fn new() -> Self {
        Self
    }

    /// Logs a successful authentication event.
    pub fn log_auth_success(&self, claims: &TokenClaims, session_id: &str, remote_addr: &str) {
        info!(
            audit.event_type = "auth_success",
            audit.result = "success",
            audit.principal_id = claims.object_id.as_str(),
            audit.principal_name = claims.preferred_username.as_str(),
            audit.tenant_id = claims.tenant_id.as_str(),
            audit.client_app_id = claims.authorized_party.as_str(),
            audit.token_id = claims.token_id.as_str(),
            audit.session_id = session_id,
            audit.scopes = claims.scopes.join(" ").as_str(),
            audit.remote_addr = remote_addr,
            "security_audit"
        );
    }

    /// Logs a failed authentication attempt.
    pub fn log_auth_failure(&self, reason: &str, remote_addr: &str) {
        info!(
            audit.event_type = "auth_failure",
            audit.result = "denied",
            audit.error = reason,
            audit.remote_addr = remote_addr,
            "security_audit"
        );
    }

    /// Logs an authorization denial.
    pub fn log_authz_denied(&self, claims: &TokenClaims, action: &str, reason: &str) {
        info!(
            audit.event_type = "authz_denied",
            audit.result = "denied",
            audit.principal_id = claims.object_id.as_str(),
            audit.principal_name = claims.preferred_username.as_str(),
            audit.tenant_id = claims.tenant_id.as_str(),
            audit.client_app_id = claims.authorized_party.as_str(),
            audit.scopes = claims.scopes.join(" ").as_str(),
            audit.action = action,
            audit.error = reason,
            "security_audit"
        );
    }

    /// Logs an OBO token exchange event.
    pub fn log_obo_exchange(
        &self,
        claims: &TokenClaims,
        target: &str,
        token_source: &str,
        duration_ms: u64,
        error: Option<&str>,
    ) {
        let result = if error.is_some() { "error" } else { "success" };
        info!(
            audit.event_type = "obo_exchange",
            audit.result = result,
            audit.principal_id = claims.object_id.as_str(),
            audit.principal_name = claims.preferred_username.as_str(),
            audit.tenant_id = claims.tenant_id.as_str(),
            audit.client_app_id = claims.authorized_party.as_str(),
            audit.obo_target = target,
            audit.obo_token_source = token_source,
            audit.duration_ms = duration_ms,
            audit.error = error.unwrap_or(""),
            "security_audit"
        );
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_claims() -> TokenClaims {
        TokenClaims {
            subject: "user123".to_string(),
            issuer: "https://issuer.example.com".to_string(),
            audience: vec!["api://test".to_string()],
            expires_at: 1700000000,
            issued_at: 1699999000,
            authorized_party: "client-app-id".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            roles: vec!["Admin".to_string()],
            object_id: "obj-123".to_string(),
            tenant_id: "tenant-456".to_string(),
            preferred_username: "user@example.com".to_string(),
            token_id: "token-789".to_string(),
        }
    }

    #[test]
    fn test_log_auth_success_does_not_panic() {
        let logger = AuditLogger::new();
        let claims = make_test_claims();
        logger.log_auth_success(&claims, "session-1", "127.0.0.1");
    }

    #[test]
    fn test_log_auth_failure_does_not_panic() {
        let logger = AuditLogger::new();
        logger.log_auth_failure("invalid token", "127.0.0.1");
    }

    #[test]
    fn test_log_authz_denied_does_not_panic() {
        let logger = AuditLogger::new();
        let claims = make_test_claims();
        logger.log_authz_denied(&claims, "cert_analysis", "insufficient scope");
    }

    #[test]
    fn test_log_obo_exchange_success_does_not_panic() {
        let logger = AuditLogger::new();
        let claims = make_test_claims();
        logger.log_obo_exchange(&claims, "https://downstream.api", "provider", 150, None);
    }

    #[test]
    fn test_log_obo_exchange_error_does_not_panic() {
        let logger = AuditLogger::new();
        let claims = make_test_claims();
        logger.log_obo_exchange(
            &claims,
            "https://downstream.api",
            "provider",
            150,
            Some("consent_required"),
        );
    }

    #[test]
    fn test_default_logger() {
        let _logger = AuditLogger;
    }
}
