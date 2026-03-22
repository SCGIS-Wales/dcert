//! On-Behalf-Of (OBO) token exchange for downstream API calls.
//!
//! Per MCP Security Best Practices:
//! - MCP servers must NOT forward user tokens to downstream APIs (no passthrough).
//! - When user context is needed downstream, OBO token exchange acquires a new
//!   access token with aud = downstream API.
//! - Tokens must be scoped only for the target downstream resource.

use reqwest::Client;
use serde::Deserialize;
use std::fmt;
use std::time::Duration;
use tracing::{debug, error};

/// Configuration for On-Behalf-Of token exchange.
#[derive(Debug, Clone)]
pub struct OboConfig {
    /// Token endpoint URL.
    pub token_url: String,
    /// This MCP server's registered application (client) ID.
    pub client_id: String,
    /// This MCP server's client secret.
    pub client_secret: String,
}

impl OboConfig {
    /// Validates that required fields are set.
    pub fn validate(&self) -> Result<(), String> {
        if self.token_url.is_empty() {
            return Err("OBO token URL is required".to_string());
        }
        if self.client_id.is_empty() {
            return Err("OBO client ID is required".to_string());
        }
        if self.client_secret.is_empty() {
            return Err("OBO client secret is required".to_string());
        }
        Ok(())
    }
}

/// Successful OBO token exchange response.
#[derive(Debug, Deserialize)]
pub struct OboTokenResponse {
    /// New token scoped for the downstream API.
    pub access_token: String,
    /// Typically "Bearer".
    pub token_type: String,
    /// Token lifetime in seconds.
    pub expires_in: i64,
    /// Granted scopes.
    #[serde(default)]
    pub scope: String,
}

/// Performs On-Behalf-Of token exchanges.
pub struct OboExchanger {
    config: OboConfig,
    http_client: Client,
}

impl OboExchanger {
    /// Creates a new OBO token exchanger.
    pub fn new(config: OboConfig) -> Result<Self, String> {
        config.validate()?;
        let http_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to create HTTP client: {e}"))?;

        Ok(Self { config, http_client })
    }

    /// Performs an OBO token exchange, acquiring a new token for the specified
    /// downstream resource on behalf of the user identified by the incoming assertion.
    pub async fn exchange(&self, assertion: &str, downstream_scopes: &[String]) -> Result<OboTokenResponse, OboError> {
        if assertion.is_empty() {
            return Err(OboError {
                code: "invalid_request".to_string(),
                description: "assertion token is required for OBO exchange".to_string(),
                retryable: false,
                guidance: "provide a valid assertion token".to_string(),
            });
        }
        if downstream_scopes.is_empty() {
            return Err(OboError {
                code: "invalid_request".to_string(),
                description: "at least one downstream scope is required".to_string(),
                retryable: false,
                guidance: "specify the target API scopes".to_string(),
            });
        }

        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("assertion", assertion),
            ("scope", &downstream_scopes.join(" ")),
            ("requested_token_use", "on_behalf_of"),
        ];

        let start = std::time::Instant::now();
        let resp = self
            .http_client
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                let duration = start.elapsed();
                let scrubbed = scrub_error(&e.to_string());
                error!(
                    duration_ms = duration.as_millis() as u64,
                    error = scrubbed.as_str(),
                    "OBO token exchange failed"
                );
                OboError {
                    code: "request_failed".to_string(),
                    description: scrubbed,
                    retryable: true,
                    guidance: "check network connectivity and token endpoint URL".to_string(),
                }
            })?;

        let duration = start.elapsed();
        let status = resp.status().as_u16();

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();

            #[derive(Deserialize, Default)]
            struct ErrorResp {
                #[serde(default)]
                error: String,
                #[serde(default)]
                error_description: String,
                #[serde(default)]
                error_codes: Vec<i64>,
                #[serde(default)]
                correlation_id: String,
                #[serde(default)]
                trace_id: String,
            }

            let err_resp: ErrorResp = serde_json::from_str(&body).unwrap_or_default();

            error!(
                status = status,
                error = err_resp.error.as_str(),
                error_codes = ?err_resp.error_codes,
                correlation_id = err_resp.correlation_id.as_str(),
                trace_id = err_resp.trace_id.as_str(),
                duration_ms = duration.as_millis() as u64,
                "OBO token exchange error"
            );

            return Err(classify_obo_error(status, &err_resp.error, &err_resp.error_description));
        }

        let token_resp: OboTokenResponse = resp.json().await.map_err(|e| OboError {
            code: "parse_error".to_string(),
            description: format!("parsing OBO token response: {e}"),
            retryable: false,
            guidance: "unexpected response format from token endpoint".to_string(),
        })?;

        debug!(
            scope = token_resp.scope.as_str(),
            expires_in = token_resp.expires_in,
            duration_ms = duration.as_millis() as u64,
            "OBO token exchange successful"
        );

        Ok(token_resp)
    }
}

/// Classified OBO token exchange error with actionable guidance.
#[derive(Debug)]
pub struct OboError {
    pub code: String,
    pub description: String,
    pub retryable: bool,
    pub guidance: String,
}

impl fmt::Display for OboError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OBO exchange error [{}]: {} (hint: {})",
            self.code, self.description, self.guidance
        )
    }
}

impl std::error::Error for OboError {}

/// Maps error codes to actionable error messages.
fn classify_obo_error(status: u16, err_code: &str, description: &str) -> OboError {
    match err_code {
        "interaction_required" => OboError {
            code: err_code.to_string(),
            description: description.to_string(),
            retryable: false,
            guidance: "user must re-authenticate; propagate claims challenge to the client".to_string(),
        },
        "consent_required" => OboError {
            code: err_code.to_string(),
            description: description.to_string(),
            retryable: false,
            guidance: "admin consent required for the downstream API scope; run admin consent flow".to_string(),
        },
        "invalid_grant" => OboError {
            code: err_code.to_string(),
            description: description.to_string(),
            retryable: false,
            guidance: "assertion token is invalid or expired; the user may need to sign in again".to_string(),
        },
        "invalid_scope" => OboError {
            code: err_code.to_string(),
            description: description.to_string(),
            retryable: false,
            guidance: "check that the downstream scope is registered in the app registration's 'API permissions'"
                .to_string(),
        },
        "invalid_client" => OboError {
            code: err_code.to_string(),
            description: description.to_string(),
            retryable: false,
            guidance: "verify DCERT_MCP_OBO_CLIENT_ID and DCERT_MCP_OBO_CLIENT_SECRET are correct".to_string(),
        },
        "temporarily_unavailable" => OboError {
            code: err_code.to_string(),
            description: description.to_string(),
            retryable: true,
            guidance: "identity provider is temporarily unavailable; retry with exponential backoff".to_string(),
        },
        _ => OboError {
            code: err_code.to_string(),
            description: format!("OBO exchange failed (HTTP {status}): {err_code} — {description}"),
            retryable: false,
            guidance: "check token endpoint configuration and error details".to_string(),
        },
    }
}

/// Removes potentially sensitive information (tokens, passwords) from error messages.
fn scrub_error(msg: &str) -> String {
    // Scrub bearer tokens.
    let result = regex_lite::Regex::new(r"(?i)(bearer\s+)\S+")
        .map(|re| re.replace_all(msg, "${1}***REDACTED***").to_string())
        .unwrap_or_else(|_| msg.to_string());

    // Scrub URL credentials (user:pass@host).

    regex_lite::Regex::new(r"://[^@\s]+@")
        .map(|re| re.replace_all(&result, "://***:***@").to_string())
        .unwrap_or(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obo_config_validate_requires_token_url() {
        let config = OboConfig {
            token_url: String::new(),
            client_id: "id".to_string(),
            client_secret: "secret".to_string(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_obo_config_validate_requires_client_id() {
        let config = OboConfig {
            token_url: "https://token.example.com".to_string(),
            client_id: String::new(),
            client_secret: "secret".to_string(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_obo_config_validate_requires_client_secret() {
        let config = OboConfig {
            token_url: "https://token.example.com".to_string(),
            client_id: "id".to_string(),
            client_secret: String::new(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_obo_config_validate_success() {
        let config = OboConfig {
            token_url: "https://token.example.com".to_string(),
            client_id: "id".to_string(),
            client_secret: "secret".to_string(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_classify_obo_error_interaction_required() {
        let err = classify_obo_error(400, "interaction_required", "MFA needed");
        assert_eq!(err.code, "interaction_required");
        assert!(!err.retryable);
    }

    #[test]
    fn test_classify_obo_error_temporarily_unavailable() {
        let err = classify_obo_error(503, "temporarily_unavailable", "try later");
        assert!(err.retryable);
    }

    #[test]
    fn test_classify_obo_error_invalid_client() {
        let err = classify_obo_error(401, "invalid_client", "bad credentials");
        assert_eq!(err.code, "invalid_client");
        assert!(!err.retryable);
        assert!(err.guidance.contains("DCERT_MCP_OBO_CLIENT_ID"));
    }

    #[test]
    fn test_classify_obo_error_unknown() {
        let err = classify_obo_error(500, "server_error", "internal failure");
        assert_eq!(err.code, "server_error");
        assert!(!err.retryable);
    }

    #[test]
    fn test_scrub_error_bearer_token() {
        let msg = "request failed: Bearer eyJ0eXAiOiJKV1Q... was rejected";
        let scrubbed = scrub_error(msg);
        assert!(!scrubbed.contains("eyJ0eXAiOiJKV1Q"));
        assert!(scrubbed.contains("***REDACTED***"));
    }

    #[test]
    fn test_scrub_error_url_credentials() {
        let msg = "failed to connect to https://user:secret@host.com/api";
        let scrubbed = scrub_error(msg);
        assert!(!scrubbed.contains("secret"));
        assert!(scrubbed.contains("***:***@"));
    }

    #[test]
    fn test_scrub_error_clean_message() {
        let msg = "connection timeout after 10s";
        assert_eq!(scrub_error(msg), msg);
    }

    #[test]
    fn test_obo_error_display() {
        let err = OboError {
            code: "test_code".to_string(),
            description: "test description".to_string(),
            retryable: false,
            guidance: "test guidance".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("test_code"));
        assert!(display.contains("test description"));
        assert!(display.contains("test guidance"));
    }
}
