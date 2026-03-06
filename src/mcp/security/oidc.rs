//! OIDC/OAuth2 JWT token validation with JWKS.
//!
//! Implements MCP authorization requirements:
//! - JWT validation with JWKS (signature, issuer, audience, expiry, azp)
//! - No acceptance of tokens issued for other resources
//! - Configurable via environment variables

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Configuration for OIDC/OAuth2 token validation.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Expected token issuer (iss claim).
    pub issuer_url: String,
    /// Expected audience (aud claim) — must match this MCP server's app ID.
    pub audience: String,
    /// URL to fetch JSON Web Key Sets for signature verification.
    /// If empty, auto-discovered from issuer_url.
    pub jwks_url: Option<String>,
    /// OAuth2 scopes that must be present in the token's scp claim.
    pub required_scopes: Vec<String>,
    /// App roles that must be present in the token's roles claim.
    pub required_roles: Vec<String>,
    /// Restricts which client applications (azp/appid) may call this server.
    pub allowed_client_ids: Vec<String>,
}

impl OidcConfig {
    /// Validates that required configuration fields are set.
    pub fn validate(&self) -> Result<(), String> {
        if self.issuer_url.is_empty() {
            return Err("OIDC issuer URL is required".to_string());
        }
        if self.audience.is_empty() {
            return Err("OIDC audience is required".to_string());
        }
        Ok(())
    }
}

/// Validated claims extracted from an OIDC token.
#[derive(Debug, Clone, Serialize)]
pub struct TokenClaims {
    /// User principal (sub claim).
    pub subject: String,
    /// Token issuer (iss claim).
    pub issuer: String,
    /// Audience(s) the token was issued for.
    pub audience: Vec<String>,
    /// Token expiration time (Unix timestamp).
    pub expires_at: i64,
    /// Token issuance time (Unix timestamp).
    pub issued_at: i64,
    /// Client application that requested the token (azp/appid).
    pub authorized_party: String,
    /// Delegated permission scopes (scp claim).
    pub scopes: Vec<String>,
    /// App roles assigned to the user (roles claim).
    pub roles: Vec<String>,
    /// Object identifier (oid claim).
    pub object_id: String,
    /// Tenant identifier (tid claim).
    pub tenant_id: String,
    /// User's display name / UPN.
    pub preferred_username: String,
    /// Unique token identifier (jti/uti claim).
    pub token_id: String,
}

/// OIDC JWT token validator using JWKS.
pub struct OidcValidator {
    config: OidcConfig,
    http_client: Client,
    jwks_cache: Arc<RwLock<JwksCache>>,
}

impl OidcValidator {
    /// Creates a new OIDC token validator.
    pub fn new(config: OidcConfig) -> Result<Self, String> {
        config.validate()?;
        let http_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to create HTTP client: {e}"))?;

        Ok(Self {
            config,
            http_client,
            jwks_cache: Arc::new(RwLock::new(JwksCache::new())),
        })
    }

    /// Validates a JWT bearer token and returns the extracted claims.
    pub async fn validate_token(&self, token_string: &str) -> Result<TokenClaims, String> {
        let jwks_url = match &self.config.jwks_url {
            Some(url) if !url.is_empty() => url.clone(),
            _ => self.discover_jwks().await?,
        };

        // Get header to find the kid.
        let header = decode_header(token_string).map_err(|e| format!("failed to decode JWT header: {e}"))?;

        let kid = header.kid.ok_or_else(|| "token missing kid header".to_string())?;

        // Try to get the key from cache.
        let key = self.get_signing_key(&jwks_url, &kid).await?;

        // Set up validation.
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer_url]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.algorithms = vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];

        // Decode and validate the token.
        let token_data = decode::<HashMap<String, serde_json::Value>>(token_string, &key, &validation)
            .map_err(|e| format!("token validation failed: {e}"))?;

        let claims = extract_claims(&token_data.claims);

        // Validate authorized party.
        if !self.config.allowed_client_ids.is_empty() {
            if claims.authorized_party.is_empty() {
                return Err("token missing azp/appid claim".to_string());
            }
            if !self.config.allowed_client_ids.contains(&claims.authorized_party) {
                return Err(format!(
                    "client {:?} is not in the allowed list",
                    claims.authorized_party
                ));
            }
        }

        // Validate required scopes.
        if !self.config.required_scopes.is_empty() {
            validate_required_strings("scope", &claims.scopes, &self.config.required_scopes)?;
        }

        // Validate required roles.
        if !self.config.required_roles.is_empty() {
            validate_required_strings("role", &claims.roles, &self.config.required_roles)?;
        }

        Ok(claims)
    }

    /// Gets a signing key from JWKS, refreshing if the kid is not found.
    async fn get_signing_key(&self, jwks_url: &str, kid: &str) -> Result<DecodingKey, String> {
        // Try cached keys first.
        {
            let cache = self.jwks_cache.read().await;
            if !cache.is_expired() {
                if let Some(key) = cache.get_key(kid) {
                    return Ok(key);
                }
            }
        }

        // Fetch fresh keys.
        self.refresh_jwks(jwks_url).await?;

        let cache = self.jwks_cache.read().await;
        cache
            .get_key(kid)
            .ok_or_else(|| format!("signing key {kid:?} not found in JWKS"))
    }

    /// Refreshes the JWKS cache.
    async fn refresh_jwks(&self, jwks_url: &str) -> Result<(), String> {
        let keys = fetch_jwks(&self.http_client, jwks_url).await?;
        let mut cache = self.jwks_cache.write().await;
        cache.update(keys);
        debug!(url = jwks_url, keys = cache.keys.len(), "JWKS keys refreshed");
        Ok(())
    }

    /// Discovers the JWKS URL from the OIDC discovery endpoint.
    async fn discover_jwks(&self) -> Result<String, String> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer_url.trim_end_matches('/')
        );

        let resp = self
            .http_client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| format!("fetching discovery document: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("discovery endpoint returned {}", resp.status().as_u16()));
        }

        #[derive(Deserialize)]
        struct DiscoveryDoc {
            jwks_uri: String,
        }

        let doc: DiscoveryDoc = resp
            .json()
            .await
            .map_err(|e| format!("parsing discovery document: {e}"))?;

        if doc.jwks_uri.is_empty() {
            return Err("discovery document missing jwks_uri".to_string());
        }

        Ok(doc.jwks_uri)
    }
}

/// Extracts typed claims from a JWT claims map.
fn extract_claims(m: &HashMap<String, serde_json::Value>) -> TokenClaims {
    let get_str = |key: &str| -> String { m.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string() };

    let get_i64 = |key: &str| -> i64 { m.get(key).and_then(|v| v.as_i64()).unwrap_or(0) };

    // aud can be string or array.
    let audience = match m.get("aud") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => vec![],
    };

    // azp (OIDC) or appid (v1 tokens).
    let authorized_party = {
        let azp = get_str("azp");
        if azp.is_empty() {
            get_str("appid")
        } else {
            azp
        }
    };

    // scp: space-separated scopes.
    let scopes = m
        .get("scp")
        .and_then(|v| v.as_str())
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    // roles: array of app roles.
    let roles = match m.get("roles") {
        Some(serde_json::Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => vec![],
    };

    // jti or uti (unique token identifier).
    let token_id = {
        let jti = get_str("jti");
        if jti.is_empty() {
            get_str("uti")
        } else {
            jti
        }
    };

    TokenClaims {
        subject: get_str("sub"),
        issuer: get_str("iss"),
        audience,
        expires_at: get_i64("exp"),
        issued_at: get_i64("iat"),
        authorized_party,
        scopes,
        roles,
        object_id: get_str("oid"),
        tenant_id: get_str("tid"),
        preferred_username: get_str("preferred_username"),
        token_id,
    }
}

/// Validates that all required values are present in the actual set.
fn validate_required_strings(kind: &str, actual: &[String], required: &[String]) -> Result<(), String> {
    let missing: Vec<&String> = required.iter().filter(|r| !actual.contains(r)).collect();
    if !missing.is_empty() {
        let names: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
        return Err(format!("missing required {kind}(s): {}", names.join(", ")));
    }
    Ok(())
}

// --- JWKS Cache ---

/// Cached JWKS key data.
struct JwksCachedKey {
    /// The RSA modulus (n parameter, base64url-decoded).
    n: Vec<u8>,
    /// The RSA exponent (e parameter, base64url-decoded).
    e: Vec<u8>,
}

/// Thread-safe JWKS key cache with TTL.
struct JwksCache {
    keys: HashMap<String, JwksCachedKey>,
    fetched: Option<Instant>,
    ttl: Duration,
}

impl JwksCache {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            fetched: None,
            ttl: Duration::from_secs(3600), // 1 hour
        }
    }

    fn is_expired(&self) -> bool {
        match self.fetched {
            Some(t) => t.elapsed() >= self.ttl,
            None => true,
        }
    }

    fn get_key(&self, kid: &str) -> Option<DecodingKey> {
        self.keys
            .get(kid)
            .map(|k| DecodingKey::from_rsa_raw_components(&k.n, &k.e))
    }

    fn update(&mut self, keys: HashMap<String, JwksCachedKey>) {
        self.keys = keys;
        self.fetched = Some(Instant::now());
    }
}

/// JWKS response structure.
#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKeyEntry>,
}

#[derive(Deserialize)]
struct JwkKeyEntry {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

/// Fetches and parses JWKS from the given URL.
async fn fetch_jwks(client: &Client, jwks_url: &str) -> Result<HashMap<String, JwksCachedKey>, String> {
    let resp = client
        .get(jwks_url)
        .send()
        .await
        .map_err(|e| format!("fetching JWKS: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("JWKS endpoint returned {}", resp.status().as_u16()));
    }

    let jwks: JwksResponse = resp.json().await.map_err(|e| format!("parsing JWKS: {e}"))?;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let mut keys = HashMap::new();
    for k in jwks.keys {
        if k.kty != "RSA" {
            continue;
        }
        if k.use_.as_deref() != Some("sig") {
            continue;
        }
        let kid = match &k.kid {
            Some(kid) => kid.clone(),
            None => continue,
        };
        let n_str = match &k.n {
            Some(n) => n,
            None => continue,
        };
        let e_str = match &k.e {
            Some(e) => e,
            None => continue,
        };

        let n_bytes = URL_SAFE_NO_PAD.decode(n_str).or_else(|_| {
            // Some JWKS endpoints use standard base64 with padding.
            use base64::engine::general_purpose::URL_SAFE;
            URL_SAFE.decode(n_str)
        });
        let e_bytes = URL_SAFE_NO_PAD.decode(e_str).or_else(|_| {
            use base64::engine::general_purpose::URL_SAFE;
            URL_SAFE.decode(e_str)
        });

        match (n_bytes, e_bytes) {
            (Ok(n), Ok(e)) => {
                keys.insert(kid, JwksCachedKey { n, e });
            }
            _ => {
                warn!(kid = kid.as_str(), "skipping malformed JWKS key");
            }
        }
    }

    if keys.is_empty() {
        return Err("no valid RSA signing keys found in JWKS".to_string());
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_config_validate_requires_issuer() {
        let config = OidcConfig {
            issuer_url: String::new(),
            audience: "api://test".to_string(),
            jwks_url: None,
            required_scopes: vec![],
            required_roles: vec![],
            allowed_client_ids: vec![],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_oidc_config_validate_requires_audience() {
        let config = OidcConfig {
            issuer_url: "https://issuer.example.com".to_string(),
            audience: String::new(),
            jwks_url: None,
            required_scopes: vec![],
            required_roles: vec![],
            allowed_client_ids: vec![],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_oidc_config_validate_success() {
        let config = OidcConfig {
            issuer_url: "https://issuer.example.com".to_string(),
            audience: "api://test".to_string(),
            jwks_url: None,
            required_scopes: vec![],
            required_roles: vec![],
            allowed_client_ids: vec![],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_required_strings_ok() {
        let actual = vec!["read".to_string(), "write".to_string()];
        let required = vec!["read".to_string()];
        assert!(validate_required_strings("scope", &actual, &required).is_ok());
    }

    #[test]
    fn test_validate_required_strings_missing() {
        let actual = vec!["read".to_string()];
        let required = vec!["read".to_string(), "admin".to_string()];
        let err = validate_required_strings("scope", &actual, &required).unwrap_err();
        assert!(err.contains("admin"));
    }

    #[test]
    fn test_extract_claims_basic() {
        let mut m = HashMap::new();
        m.insert("sub".to_string(), serde_json::json!("user123"));
        m.insert("iss".to_string(), serde_json::json!("https://issuer.example.com"));
        m.insert("aud".to_string(), serde_json::json!("api://test"));
        m.insert("exp".to_string(), serde_json::json!(1700000000));
        m.insert("iat".to_string(), serde_json::json!(1699999000));
        m.insert("azp".to_string(), serde_json::json!("client-app-id"));
        m.insert("scp".to_string(), serde_json::json!("read write"));
        m.insert("oid".to_string(), serde_json::json!("obj-123"));
        m.insert("tid".to_string(), serde_json::json!("tenant-456"));
        m.insert("preferred_username".to_string(), serde_json::json!("user@example.com"));
        m.insert("jti".to_string(), serde_json::json!("token-id-789"));

        let claims = extract_claims(&m);
        assert_eq!(claims.subject, "user123");
        assert_eq!(claims.issuer, "https://issuer.example.com");
        assert_eq!(claims.audience, vec!["api://test"]);
        assert_eq!(claims.expires_at, 1700000000);
        assert_eq!(claims.authorized_party, "client-app-id");
        assert_eq!(claims.scopes, vec!["read", "write"]);
        assert_eq!(claims.object_id, "obj-123");
        assert_eq!(claims.tenant_id, "tenant-456");
        assert_eq!(claims.preferred_username, "user@example.com");
        assert_eq!(claims.token_id, "token-id-789");
    }

    #[test]
    fn test_extract_claims_aud_array() {
        let mut m = HashMap::new();
        m.insert("aud".to_string(), serde_json::json!(["api://test", "api://other"]));
        let claims = extract_claims(&m);
        assert_eq!(claims.audience, vec!["api://test", "api://other"]);
    }

    #[test]
    fn test_extract_claims_appid_fallback() {
        let mut m = HashMap::new();
        m.insert("appid".to_string(), serde_json::json!("v1-client-id"));
        let claims = extract_claims(&m);
        assert_eq!(claims.authorized_party, "v1-client-id");
    }

    #[test]
    fn test_extract_claims_uti_fallback() {
        let mut m = HashMap::new();
        m.insert("uti".to_string(), serde_json::json!("unique-token-id"));
        let claims = extract_claims(&m);
        assert_eq!(claims.token_id, "unique-token-id");
    }

    #[test]
    fn test_extract_claims_roles() {
        let mut m = HashMap::new();
        m.insert("roles".to_string(), serde_json::json!(["Admin", "Reader"]));
        let claims = extract_claims(&m);
        assert_eq!(claims.roles, vec!["Admin", "Reader"]);
    }

    #[test]
    fn test_jwks_cache_expired_when_empty() {
        let cache = JwksCache::new();
        assert!(cache.is_expired());
    }

    #[test]
    fn test_jwks_cache_not_expired_after_update() {
        let mut cache = JwksCache::new();
        cache.update(HashMap::new());
        assert!(!cache.is_expired());
    }
}
