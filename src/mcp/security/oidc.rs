//! OIDC/OAuth2 JWT token validation with JWKS.
//!
//! Implements MCP authorization requirements:
//! - JWT validation with JWKS (signature, issuer, audience, expiry, azp)
//! - No acceptance of tokens issued for other resources
//! - Configurable via environment variables

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
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

/// Signature algorithms accepted for bearer tokens. `none` and the HMAC
/// family are absent by construction, so a token cannot be signed with the
/// public key it ships with (algorithm confusion).
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

/// Allowance for clock differences between this server and the issuer, in
/// seconds. Applied to `exp`, `nbf` and `iat`.
const CLOCK_SKEW_LEEWAY_SECS: u64 = 60;

/// Minimum interval between JWKS refreshes triggered by an unknown key id.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Largest discovery document or JWKS the validator will read from the
/// identity provider. Both are a few kilobytes in practice; the cap keeps a
/// misbehaving or impersonated provider from exhausting memory.
const MAX_IDP_RESPONSE_BYTES: usize = 1024 * 1024;

/// How long fetched JWKS keys stay cached, from `DCERT_MCP_JWKS_TTL`
/// (seconds, default one hour).
fn jwks_ttl() -> Duration {
    Duration::from_secs(
        std::env::var("DCERT_MCP_JWKS_TTL")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(3600),
    )
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
        require_https(&self.issuer_url, "DCERT_MCP_OIDC_ISSUER")?;
        if let Some(jwks) = self.jwks_url.as_deref().filter(|u| !u.is_empty()) {
            require_https(jwks, "DCERT_MCP_OIDC_JWKS_URL")?;
        }
        Ok(())
    }
}

/// Require an `https://` URL. Plain `http://` is accepted only for a
/// loopback host, for a local test identity provider.
fn require_https(raw: &str, what: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(raw).map_err(|e| format!("{what} is not a valid URL ({raw}): {e}"))?;
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err(format!("{what} must be an https:// URL, got {raw}")),
    }
}

/// Whether two URLs share scheme, host and port.
fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

/// Longest a cached signing key may be served past its TTL while the
/// identity provider cannot be reached, from `DCERT_MCP_JWKS_MAX_STALE`
/// (seconds, default 24 hours). Beyond it every token fails, so a key the
/// provider has withdrawn cannot be honoured indefinitely during an outage.
fn jwks_max_stale() -> Duration {
    Duration::from_secs(
        std::env::var("DCERT_MCP_JWKS_MAX_STALE")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(24 * 3600),
    )
}

/// Token types that mark an OAuth 2.0 access token (RFC 9068).
const ACCESS_TOKEN_TYPES: &[&str] = &["at+jwt", "application/at+jwt"];

/// Check the header `typ`. An RFC 9068 access token type is accepted as is.
/// A plain `JWT` or a missing `typ` (common for Entra ID and older
/// providers) is accepted only when the token carries `scp`, `scope` or
/// `roles`, which ID tokens do not. Any other type (an ID token, a logout
/// token, a DPoP proof) is refused.
fn check_token_type(typ: Option<&str>, claims: &HashMap<String, serde_json::Value>) -> Result<(), String> {
    let typ = typ.map(str::to_ascii_lowercase);
    match typ.as_deref() {
        Some(t) if ACCESS_TOKEN_TYPES.contains(&t) => Ok(()),
        None | Some("jwt" | "application/jwt") => {
            if ["scp", "scope", "roles"].iter().any(|k| claims.contains_key(*k)) {
                Ok(())
            } else {
                Err("token is not an access token: no at+jwt typ and no scp, scope or roles claim".to_string())
            }
        }
        Some(other) => Err(format!("token type {other:?} is not an access token")),
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
            // Discovery and JWKS answers decide which keys are trusted, so a
            // redirect may not move them to another origin.
            .redirect(dcert::http::same_origin_redirect_policy(5))
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
        // Parse the header before any network work, so a malformed token
        // cannot make the server call the identity provider.
        let header = decode_header(token_string).map_err(|e| format!("failed to decode JWT header: {e}"))?;
        let kid = header.kid.ok_or_else(|| "token missing kid header".to_string())?;

        // Reject a token whose header names an algorithm outside the
        // allow-list before fetching keys for it.
        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return Err(format!("unsupported token algorithm {:?}", header.alg));
        }

        // Serve from the cached keys when possible; discovery and JWKS fetches
        // only happen on a cache miss, and are throttled, so an unauthenticated
        // caller cannot make the server hammer the identity provider with one
        // request per token.
        let key = match self.cached_signing_key(&kid, header.alg).await {
            Some(key) => key,
            None => self.fetch_signing_key(&kid, header.alg).await?,
        };

        // Set up validation — supports both RSA and ECDSA algorithms.
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.config.issuer_url]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        // Reject a token that is not valid yet, and state the clock skew
        // allowance explicitly rather than inheriting a default.
        validation.validate_nbf = true;
        validation.leeway = CLOCK_SKEW_LEEWAY_SECS;
        validation.algorithms = ALLOWED_ALGORITHMS.to_vec();

        // Decode and validate the token.
        let token_data = decode::<HashMap<String, serde_json::Value>>(token_string, &key, &validation)
            .map_err(|e| format!("token validation failed: {e}"))?;

        check_token_type(header.typ.as_deref(), &token_data.claims)?;
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

    /// Look up a key in the cache without any network access. An entry past
    /// its TTL is not served here, so a refresh is attempted first; see
    /// [`OidcValidator::stale_signing_key`] for what happens when it cannot be.
    async fn cached_signing_key(&self, kid: &str, alg: Algorithm) -> Option<DecodingKey> {
        let cache = self.jwks_cache.read().await;
        if cache.is_expired() {
            None
        } else {
            cache.get_key(kid, alg)
        }
    }

    /// Look up a key in the cache even when the entry has passed its TTL.
    ///
    /// Used when the keys cannot be refreshed right now, because a refresh
    /// was attempted too recently or the identity provider did not answer.
    /// A key the provider published an hour ago is still the provider's key:
    /// serving it is strictly better than failing every token for the
    /// throttle interval, and a rotated out key is withdrawn as soon as a
    /// refresh succeeds. The fallback is logged at warn level once per
    /// interval so an outage is visible without flooding the log.
    async fn stale_signing_key(&self, kid: &str, alg: Algorithm, reason: &str) -> Option<DecodingKey> {
        let mut cache = self.jwks_cache.write().await;
        if cache
            .fetched
            .is_none_or(|t| t.elapsed() >= cache.ttl + jwks_max_stale())
        {
            warn!(
                kid = kid,
                reason = reason,
                "JWKS keys are older than DCERT_MCP_JWKS_MAX_STALE allows; refusing to serve them"
            );
            return None;
        }
        let key = cache.get_key(kid, alg)?;
        if cache.should_warn_stale() {
            let age_secs = cache.fetched.map(|t| t.elapsed().as_secs());
            warn!(
                kid = kid,
                reason = reason,
                key_age_secs = age_secs,
                "JWKS refresh unavailable; serving a cached signing key past its TTL"
            );
        }
        Some(key)
    }

    /// Fetch a signing key the cache does not hold, discovering the JWKS URL
    /// first when one is not configured.
    ///
    /// Every network path out of this function is behind one throttle, claimed
    /// before the first request is sent. Discovery and the JWKS fetch are
    /// therefore rate limited together: a flood of tokens bearing invented key
    /// ids cannot be amplified into a flood of requests to the identity
    /// provider, whether or not any keys have ever been loaded. A failed
    /// fetch is not retried for [`MIN_REFRESH_INTERVAL`], which is the correct
    /// trade when the provider is already failing.
    ///
    /// While a refresh is throttled or failing, a key the cache already holds
    /// is served even past its TTL, so a provider outage does not take the
    /// server down with it. Only a key id the cache has never seen fails.
    async fn fetch_signing_key(&self, kid: &str, alg: Algorithm) -> Result<DecodingKey, String> {
        if !self.claim_refresh_slot().await {
            return match self.stale_signing_key(kid, alg, "refresh throttled").await {
                Some(key) => Ok(key),
                None => Err(format!("signing key {kid:?} not found in JWKS (refresh throttled)")),
            };
        }

        // Re-check under the claim: a concurrent caller may have just filled
        // the cache between the miss and the claim.
        if let Some(key) = self.cached_signing_key(kid, alg).await {
            return Ok(key);
        }

        let refreshed = match &self.config.jwks_url {
            Some(url) if !url.is_empty() => self.refresh_jwks(url).await,
            _ => match self.discover_jwks().await {
                Ok(url) => self.refresh_jwks(&url).await,
                Err(e) => Err(e),
            },
        };
        if let Err(e) = refreshed {
            return match self.stale_signing_key(kid, alg, &e).await {
                Some(key) => Ok(key),
                None => Err(e),
            };
        }

        let cache = self.jwks_cache.read().await;
        cache
            .get_key(kid, alg)
            .ok_or_else(|| format!("signing key {kid:?} for {alg:?} not found in JWKS"))
    }

    /// Take the single refresh slot for this interval, returning `false` when
    /// another attempt was made too recently. The attempt is recorded before
    /// any request is sent, so concurrent callers are throttled too rather
    /// than all passing a check that only the first would have failed.
    async fn claim_refresh_slot(&self) -> bool {
        let mut cache = self.jwks_cache.write().await;
        // A cache TTL shorter than the throttle is a deliberate request for
        // frequent refreshes, so the shorter of the two wins and the throttle
        // can never starve a cache that has already expired.
        let interval = MIN_REFRESH_INTERVAL.min(cache.ttl);
        if let Some(last) = cache.last_attempt
            && last.elapsed() < interval
        {
            return false;
        }
        cache.last_attempt = Some(Instant::now());
        true
    }

    /// Refreshes the JWKS cache. The caller holds the refresh slot.
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
            #[serde(default)]
            issuer: String,
            jwks_uri: String,
        }

        let body = read_body_limited(resp, "discovery document").await?;
        let doc: DiscoveryDoc =
            serde_json::from_slice(&body).map_err(|e| format!("parsing discovery document: {e}"))?;
        validate_discovery(&self.config.issuer_url, &doc.issuer, &doc.jwks_uri)?;
        Ok(doc.jwks_uri)
    }
}

/// Check a discovery document against the configured issuer (OpenID Connect
/// Discovery 1.0 section 4.3): its `issuer` must equal the configured one,
/// and the discovered `jwks_uri` must be https and on the issuer's origin.
/// Keys from anywhere else need an explicit `DCERT_MCP_OIDC_JWKS_URL`.
fn validate_discovery(configured_issuer: &str, issuer: &str, jwks_uri: &str) -> Result<(), String> {
    let trim = |s: &str| s.trim_end_matches('/').to_string();
    if trim(issuer) != trim(configured_issuer) {
        return Err(format!(
            "discovery document issuer {issuer:?} does not match the configured issuer {configured_issuer:?}"
        ));
    }
    if jwks_uri.is_empty() {
        return Err("discovery document missing jwks_uri".to_string());
    }
    require_https(jwks_uri, "discovered jwks_uri")?;
    if !same_origin(jwks_uri, configured_issuer) {
        return Err(format!(
            "discovered jwks_uri {jwks_uri:?} is not on the issuer's origin; set DCERT_MCP_OIDC_JWKS_URL to trust it explicitly"
        ));
    }
    Ok(())
}

/// Extracts typed claims from a JWT claims map.
fn extract_claims(m: &HashMap<String, serde_json::Value>) -> TokenClaims {
    let get_str = |key: &str| -> String { m.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string() };

    let get_i64 = |key: &str| -> i64 { m.get(key).and_then(serde_json::Value::as_i64).unwrap_or(0) };

    // aud can be string or array.
    let audience = match m.get("aud") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => vec![],
    };

    // azp (OIDC) or appid (v1 tokens).
    let authorized_party = {
        let azp = get_str("azp");
        if azp.is_empty() { get_str("appid") } else { azp }
    };

    // Scopes from `scp` (Entra ID, Okta) and `scope` (RFC 9068), each a
    // space separated string or an array, merged without duplicates.
    let mut scopes: Vec<String> = Vec::new();
    for key in ["scp", "scope"] {
        let values: Vec<String> = match m.get(key) {
            Some(serde_json::Value::String(s)) => s.split_whitespace().map(String::from).collect(),
            Some(serde_json::Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
            _ => Vec::new(),
        };
        for v in values {
            if !scopes.contains(&v) {
                scopes.push(v);
            }
        }
    }

    // roles: array of app roles.
    let roles = match m.get("roles") {
        Some(serde_json::Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => vec![],
    };

    // jti or uti (unique token identifier).
    let token_id = {
        let jti = get_str("jti");
        if jti.is_empty() { get_str("uti") } else { jti }
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

/// Cached JWKS key data — supports both RSA and EC keys. These are public
/// key components, so deriving `Debug` exposes nothing secret.
#[derive(Debug)]
enum JwksCachedKey {
    Rsa {
        /// The RSA modulus (n parameter, base64url-decoded).
        n: Vec<u8>,
        /// The RSA exponent (e parameter, base64url-decoded).
        e: Vec<u8>,
    },
    Ec {
        /// The EC x coordinate (base64url string, as expected by jsonwebtoken).
        x: String,
        /// The EC y coordinate (base64url string, as expected by jsonwebtoken).
        y: String,
        /// The curve, `P-256` or `P-384`.
        crv: String,
    },
}

impl JwksCachedKey {
    /// Whether this key may verify a token signed with `alg`: RSA keys for
    /// RS*, P-256 for ES256 and P-384 for ES384. A token cannot pick a key of
    /// another type or curve than its header claims.
    fn fits(&self, alg: Algorithm) -> bool {
        match (self, alg) {
            (Self::Rsa { .. }, Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512) => true,
            (Self::Ec { crv, .. }, Algorithm::ES256) => crv == "P-256",
            (Self::Ec { crv, .. }, Algorithm::ES384) => crv == "P-384",
            _ => false,
        }
    }
}

/// Thread-safe JWKS key cache with TTL.
struct JwksCache {
    keys: HashMap<String, JwksCachedKey>,
    fetched: Option<Instant>,
    /// When a refresh was last attempted, successful or not. Used to rate
    /// limit refreshes triggered by unknown key ids.
    last_attempt: Option<Instant>,
    /// When a key past its TTL was last reported as served, so the warning
    /// is written once per interval rather than once per token.
    stale_warned: Option<Instant>,
    ttl: Duration,
}

impl JwksCache {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            fetched: None,
            last_attempt: None,
            stale_warned: None,
            ttl: jwks_ttl(),
        }
    }

    /// `true` once per refresh interval, on the first call after it opens.
    fn should_warn_stale(&mut self) -> bool {
        let interval = MIN_REFRESH_INTERVAL.min(self.ttl);
        if let Some(last) = self.stale_warned
            && last.elapsed() < interval
        {
            return false;
        }
        self.stale_warned = Some(Instant::now());
        true
    }

    fn is_expired(&self) -> bool {
        match self.fetched {
            Some(t) => t.elapsed() >= self.ttl,
            None => true,
        }
    }

    fn get_key(&self, kid: &str, alg: Algorithm) -> Option<DecodingKey> {
        self.keys.get(kid).filter(|k| k.fits(alg)).and_then(|k| match k {
            JwksCachedKey::Rsa { n, e } => Some(DecodingKey::from_rsa_raw_components(n, e)),
            JwksCachedKey::Ec { x, y, .. } => DecodingKey::from_ec_components(x, y).ok(),
        })
    }

    fn update(&mut self, keys: HashMap<String, JwksCachedKey>) {
        self.keys = keys;
        self.fetched = Some(Instant::now());
        // A fresh set of keys ends the outage, so the next one warns again.
        self.stale_warned = None;
    }
}

/// JWKS response structure.
#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKeyEntry>,
}

#[derive(Deserialize)]
struct JwkKeyEntry {
    /// Key type. Required by RFC 7517, but a malformed entry must only skip
    /// itself rather than fail the whole document.
    kty: Option<String>,
    kid: Option<String>,
    /// Public key use. Optional in RFC 7517; when absent the key may be used
    /// for signatures, so only an explicit other value excludes it.
    #[serde(rename = "use")]
    use_: Option<String>,
    /// RSA modulus
    n: Option<String>,
    /// RSA exponent
    e: Option<String>,
    /// EC x coordinate
    x: Option<String>,
    /// EC y coordinate
    y: Option<String>,
    /// EC curve name (e.g. "P-256", "P-384")
    crv: Option<String>,
}

/// Read a response body, refusing one larger than [`MAX_IDP_RESPONSE_BYTES`]
/// whether or not its length was declared.
async fn read_body_limited(mut resp: reqwest::Response, what: &str) -> Result<Vec<u8>, String> {
    let limit = u64::try_from(MAX_IDP_RESPONSE_BYTES).unwrap_or(u64::MAX);
    if let Some(declared) = resp.content_length()
        && declared > limit
    {
        return Err(format!("{what} response too large ({declared} bytes)"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| format!("reading {what}: {e}"))? {
        if body.len().saturating_add(chunk.len()) > MAX_IDP_RESPONSE_BYTES {
            return Err(format!(
                "{what} response too large (over {MAX_IDP_RESPONSE_BYTES} bytes)"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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

    let body = read_body_limited(resp, "JWKS").await?;
    parse_jwks(&body)
}

/// Parse a JWKS document into the keys this server can verify with.
///
/// Per RFC 7517 `use` is optional: a key without it is accepted, a key
/// marked for anything other than `sig` is skipped. Entries that are
/// malformed or of an unsupported type skip themselves without failing the
/// document.
fn parse_jwks(body: &[u8]) -> Result<HashMap<String, JwksCachedKey>, String> {
    let jwks: JwksResponse = serde_json::from_slice(body).map_err(|e| format!("parsing JWKS: {e}"))?;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let decode_b64 = |s: &str| -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(s).or_else(|_| {
            use base64::engine::general_purpose::URL_SAFE;
            URL_SAFE.decode(s)
        })
    };

    let mut keys = HashMap::new();
    for k in jwks.keys {
        if !matches!(k.use_.as_deref(), None | Some("sig")) {
            continue;
        }
        let kid = match &k.kid {
            Some(kid) => kid.clone(),
            None => continue,
        };

        let cached_key = match k.kty.as_deref().unwrap_or("") {
            "RSA" => {
                let (Some(n_str), Some(e_str)) = (&k.n, &k.e) else {
                    continue;
                };
                match (decode_b64(n_str), decode_b64(e_str)) {
                    (Ok(n), Ok(e)) => JwksCachedKey::Rsa { n, e },
                    _ => {
                        warn!(kid = kid.as_str(), "skipping malformed RSA JWKS key");
                        continue;
                    }
                }
            }
            "EC" => {
                let (x_str, y_str) = match (&k.x, &k.y) {
                    (Some(x), Some(y)) => (x.clone(), y.clone()),
                    _ => continue,
                };
                let crv = k.crv.as_deref().unwrap_or("");
                if crv != "P-256" && crv != "P-384" {
                    if !crv.is_empty() {
                        warn!(kid = kid.as_str(), crv = crv, "unsupported EC curve");
                    }
                    continue;
                }
                // Validate that x and y are valid base64url before caching
                if decode_b64(&x_str).is_err() || decode_b64(&y_str).is_err() {
                    warn!(kid = kid.as_str(), "skipping malformed EC JWKS key");
                    continue;
                }
                JwksCachedKey::Ec {
                    x: x_str,
                    y: y_str,
                    crv: crv.to_string(),
                }
            }
            _ => continue,
        };

        keys.insert(kid, cached_key);
    }

    if keys.is_empty() {
        return Err("no valid signing keys found in JWKS".to_string());
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_validator() -> OidcValidator {
        OidcValidator::new(OidcConfig {
            issuer_url: "https://issuer.example.com".to_string(),
            audience: "api://test".to_string(),
            jwks_url: None,
            required_scopes: vec![],
            required_roles: vec![],
            allowed_client_ids: vec![],
        })
        .expect("validator")
    }

    /// A validator whose JWKS URL is fixed and whose client ignores any proxy
    /// in the test environment, so it talks to a loopback mock directly.
    fn validator_with_jwks_url(jwks_url: &str) -> OidcValidator {
        OidcValidator {
            config: OidcConfig {
                issuer_url: "https://issuer.example.com".to_string(),
                audience: "api://test".to_string(),
                jwks_url: Some(jwks_url.to_string()),
                required_scopes: vec![],
                required_roles: vec![],
                allowed_client_ids: vec![],
            },
            http_client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("client"),
            jwks_cache: Arc::new(RwLock::new(JwksCache::new())),
        }
    }

    /// RFC 7515 appendix A.2 modulus, as a base64url string.
    const RSA_N: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";

    fn rsa_jwk(kid: &str, use_: Option<&str>) -> serde_json::Value {
        let mut key = serde_json::json!({"kty": "RSA", "kid": kid, "alg": "RS256", "n": RSA_N, "e": "AQAB"});
        if let Some(u) = use_ {
            key["use"] = serde_json::json!(u);
        }
        key
    }

    fn rsa_cached_key() -> JwksCachedKey {
        JwksCachedKey::Rsa {
            n: vec![1, 2, 3],
            e: vec![1, 0, 1],
        }
    }

    /// Put one key in the cache, already past its TTL, so the next lookup
    /// must try a refresh.
    async fn prime_expired_cache(v: &OidcValidator, kid: &str) {
        let mut cache = v.jwks_cache.write().await;
        cache.update(HashMap::from([(kid.to_string(), rsa_cached_key())]));
        cache.ttl = Duration::from_secs(1);
        cache.fetched = Instant::now().checked_sub(Duration::from_secs(2));
        assert!(cache.is_expired());
    }

    // --- M7: `use` is optional, stale keys survive a failed refresh ---

    #[test]
    fn parse_jwks_accepts_a_key_without_use_and_skips_other_uses() {
        let doc = serde_json::json!({"keys": [
            rsa_jwk("no-use", None),
            rsa_jwk("sig", Some("sig")),
            rsa_jwk("enc", Some("enc")),
            {"kid": "no-kty", "n": RSA_N, "e": "AQAB"},
            {"kty": "oct", "kid": "symmetric", "k": "AQAB"},
        ]});
        let keys = parse_jwks(doc.to_string().as_bytes()).expect("parses");
        let mut kids: Vec<&String> = keys.keys().collect();
        kids.sort();
        assert_eq!(kids, ["no-use", "sig"]);
    }

    #[test]
    fn parse_jwks_fails_when_no_key_is_usable() {
        let doc = serde_json::json!({"keys": [rsa_jwk("enc", Some("enc"))]});
        let err = parse_jwks(doc.to_string().as_bytes()).unwrap_err();
        assert!(err.contains("no valid signing keys"), "{err}");
    }

    #[tokio::test]
    async fn a_key_without_use_is_served_end_to_end() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [rsa_jwk("k1", None)]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let v = validator_with_jwks_url(&format!("{}/jwks", server.uri()));
        assert!(v.fetch_signing_key("k1", Algorithm::RS256).await.is_ok());
        assert!(v.cached_signing_key("k1", Algorithm::RS256).await.is_some());
    }

    #[tokio::test]
    async fn a_throttled_refresh_serves_the_stale_cached_key() {
        // The URL is never contacted: the throttle refuses the refresh first.
        let v = validator_with_jwks_url("http://127.0.0.1:9/jwks");
        prime_expired_cache(&v, "k1").await;
        v.jwks_cache.write().await.last_attempt = Some(Instant::now());

        assert!(
            v.cached_signing_key("k1", Algorithm::RS256).await.is_none(),
            "an expired entry is not served on the fast path"
        );
        assert!(
            v.fetch_signing_key("k1", Algorithm::RS256).await.is_ok(),
            "while the refresh is throttled the stale key is still the provider's key"
        );
        let err = v.fetch_signing_key("k2", Algorithm::RS256).await.unwrap_err();
        assert!(err.contains("throttled"), "{err}");
    }

    #[tokio::test]
    async fn a_failed_refresh_serves_the_stale_cached_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let v = validator_with_jwks_url(&format!("{}/jwks", server.uri()));
        prime_expired_cache(&v, "k1").await;

        assert!(
            v.fetch_signing_key("k1", Algorithm::RS256).await.is_ok(),
            "a provider outage must not fail tokens signed with a key the cache holds"
        );
        // A key id the cache has never seen cannot be served from anywhere;
        // this attempt is throttled by the failed one just before it.
        assert!(v.fetch_signing_key("k2", Algorithm::RS256).await.is_err());
        assert!(
            v.jwks_cache.read().await.is_expired(),
            "a failed refresh leaves the TTL untouched so the next interval retries"
        );
    }

    #[tokio::test]
    async fn the_stale_key_warning_is_written_once_per_interval() {
        let mut cache = JwksCache::new();
        cache.ttl = Duration::from_millis(20);
        assert!(cache.should_warn_stale());
        assert!(!cache.should_warn_stale());
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(cache.should_warn_stale());
        // A successful refresh resets it so the next outage is reported.
        cache.update(HashMap::new());
        assert!(cache.should_warn_stale());
    }

    #[tokio::test]
    async fn an_oversized_jwks_response_is_refused() {
        let server = MockServer::start().await;
        let body = format!(
            "{{\"keys\": [], \"padding\": \"{}\"}}",
            "x".repeat(MAX_IDP_RESPONSE_BYTES)
        );
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let v = validator_with_jwks_url(&format!("{}/jwks", server.uri()));
        let err = fetch_jwks(&v.http_client, &format!("{}/jwks", server.uri()))
            .await
            .unwrap_err();
        assert!(err.contains("too large"), "{err}");
    }

    #[tokio::test]
    async fn refresh_slot_is_claimed_before_any_network_work() {
        let v = test_validator();

        // The first caller takes the slot. Taking it up front, rather than
        // after a successful fetch, is what stops a burst of concurrent
        // callers from all passing the check and each issuing a request.
        assert!(v.claim_refresh_slot().await);
        assert!(
            !v.claim_refresh_slot().await,
            "a second claim in the same interval must be refused"
        );
    }

    #[tokio::test]
    async fn refresh_slot_is_throttled_even_with_an_empty_cache() {
        let v = test_validator();
        assert!(v.jwks_cache.read().await.keys.is_empty());

        // The throttle must not depend on keys having been loaded: an identity
        // provider that is down is exactly when unbounded retries hurt most,
        // and discovery runs behind this slot too, so a flood of tokens with
        // invented key ids cannot be amplified into a flood of requests.
        assert!(v.claim_refresh_slot().await);
        assert!(!v.claim_refresh_slot().await);
        assert!(v.jwks_cache.read().await.keys.is_empty());
    }

    #[tokio::test]
    async fn a_cache_ttl_shorter_than_the_throttle_wins() {
        let v = test_validator();
        {
            let mut cache = v.jwks_cache.write().await;
            cache.ttl = Duration::from_millis(10);
        }
        assert!(v.claim_refresh_slot().await);
        assert!(!v.claim_refresh_slot().await);
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            v.claim_refresh_slot().await,
            "a short TTL asks for frequent refreshes and must not be starved by the throttle"
        );
    }

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

    // --- Plan PR 1.7: OIDC hardening ---

    fn config(issuer: &str, jwks: Option<&str>) -> OidcConfig {
        OidcConfig {
            issuer_url: issuer.to_string(),
            audience: "api://test".to_string(),
            jwks_url: jwks.map(str::to_string),
            required_scopes: vec![],
            required_roles: vec![],
            allowed_client_ids: vec![],
        }
    }

    #[test]
    fn issuer_and_jwks_url_must_be_https_except_on_loopback() {
        assert!(config("http://idp.example.com", None).validate().is_err());
        assert!(
            config("https://idp.example.com", Some("http://keys.example.com"))
                .validate()
                .is_err()
        );
        assert!(
            config("https://idp.example.com", Some("https://keys.example.com"))
                .validate()
                .is_ok()
        );
        assert!(config("http://127.0.0.1:8080", None).validate().is_ok());
        assert!(config("http://localhost:8080", None).validate().is_ok());
    }

    fn loopback_validator(issuer: &str) -> OidcValidator {
        OidcValidator {
            config: config(issuer, None),
            http_client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("client"),
            jwks_cache: Arc::new(RwLock::new(JwksCache::new())),
        }
    }

    async fn discovery_server(doc: impl Fn(&str) -> serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        let body = doc(&server.uri());
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn discovery_accepts_a_matching_issuer_and_same_origin_jwks() {
        let server =
            discovery_server(|uri| serde_json::json!({"issuer": uri, "jwks_uri": format!("{uri}/keys")})).await;
        let v = loopback_validator(&server.uri());
        assert_eq!(v.discover_jwks().await, Ok(format!("{}/keys", server.uri())));
    }

    #[tokio::test]
    async fn discovery_refuses_a_different_issuer() {
        let server = discovery_server(
            |uri| serde_json::json!({"issuer": "https://evil.example", "jwks_uri": format!("{uri}/keys")}),
        )
        .await;
        let err = loopback_validator(&server.uri())
            .discover_jwks()
            .await
            .expect_err("issuer mismatch");
        assert!(err.contains("does not match"), "{err}");
    }

    #[tokio::test]
    async fn discovery_refuses_jwks_on_another_origin() {
        let server = discovery_server(
            |uri| serde_json::json!({"issuer": uri, "jwks_uri": "https://keys.elsewhere.example/keys"}),
        )
        .await;
        let err = loopback_validator(&server.uri())
            .discover_jwks()
            .await
            .expect_err("other origin");
        assert!(err.contains("DCERT_MCP_OIDC_JWKS_URL"), "{err}");
    }

    #[tokio::test]
    async fn discovery_refuses_plain_http_jwks() {
        let server =
            discovery_server(|uri| serde_json::json!({"issuer": uri, "jwks_uri": "http://keys.example.com/keys"}))
                .await;
        let err = loopback_validator(&server.uri())
            .discover_jwks()
            .await
            .expect_err("http jwks");
        assert!(err.contains("https"), "{err}");
    }

    #[tokio::test]
    async fn keys_older_than_the_staleness_cap_are_not_served() {
        let v = test_validator();
        let Some(long_ago) = Instant::now().checked_sub(Duration::from_secs(3600 + 25 * 3600)) else {
            return;
        };
        {
            let mut cache = v.jwks_cache.write().await;
            cache.update(HashMap::from([("k1".to_string(), rsa_cached_key())]));
            cache.ttl = Duration::from_secs(3600);
            cache.fetched = Some(long_ago);
        }
        assert!(v.stale_signing_key("k1", Algorithm::RS256, "test").await.is_none());
    }

    #[test]
    fn token_type_rules() {
        let with = |k: &str| HashMap::from([(k.to_string(), serde_json::json!("x"))]);
        assert!(check_token_type(Some("at+jwt"), &HashMap::new()).is_ok());
        assert!(check_token_type(Some("application/at+JWT"), &HashMap::new()).is_ok());
        for claim in ["scp", "scope", "roles"] {
            assert!(check_token_type(Some("JWT"), &with(claim)).is_ok(), "{claim}");
            assert!(check_token_type(None, &with(claim)).is_ok(), "{claim}");
        }
        assert!(check_token_type(None, &with("sub")).is_err(), "an ID token shape");
        assert!(check_token_type(Some("dpop+jwt"), &with("scope")).is_err());
    }

    #[test]
    fn scopes_are_read_from_scp_and_scope() {
        let mut m = HashMap::new();
        m.insert("scp".to_string(), serde_json::json!("read write"));
        m.insert("scope".to_string(), serde_json::json!(["write", "admin"]));
        assert_eq!(extract_claims(&m).scopes, vec!["read", "write", "admin"]);
    }

    #[test]
    fn a_key_only_verifies_its_own_algorithm_family() {
        let rsa = rsa_cached_key();
        assert!(rsa.fits(Algorithm::RS256) && rsa.fits(Algorithm::RS512));
        assert!(!rsa.fits(Algorithm::ES256));
        let p256 = JwksCachedKey::Ec {
            x: String::new(),
            y: String::new(),
            crv: "P-256".to_string(),
        };
        assert!(p256.fits(Algorithm::ES256));
        assert!(!p256.fits(Algorithm::ES384) && !p256.fits(Algorithm::RS256));
        let mut cache = JwksCache::new();
        cache.update(HashMap::from([("k".to_string(), rsa_cached_key())]));
        assert!(cache.get_key("k", Algorithm::ES256).is_none());
        assert!(cache.get_key("k", Algorithm::RS256).is_some());
    }
}
