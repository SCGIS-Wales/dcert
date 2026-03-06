//! In-memory session cache for validated OIDC tokens.
//!
//! Design:
//! - Tokens are never used beyond their exp
//! - Preferred store: in-memory
//! - Cache keys include principal ID + session ID (pattern: <principal_id>:<session_id>)
//! - Sliding window inactivity TTL
//! - Background cleanup task

use super::oidc::TokenClaims;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;

/// Session cache configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum time a cached entry survives without access (default: 5 minutes).
    pub inactivity_ttl: Duration,
    /// How often expired entries are purged (default: 1 minute).
    pub cleanup_interval: Duration,
    /// Maximum number of cached entries (default: 10,000).
    pub max_entries: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            inactivity_ttl: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(60),
            max_entries: 10_000,
        }
    }
}

/// A cached session entry with access tracking.
struct SessionEntry {
    claims: TokenClaims,
    last_access: Instant,
    #[allow(dead_code)]
    created_at: Instant,
}

/// In-memory cache for validated OIDC tokens.
/// Cache keys follow the pattern: `<principal_id>:<session_id>`.
pub struct SessionCache {
    entries: Arc<RwLock<HashMap<String, SessionEntry>>>,
    config: SessionConfig,
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl SessionCache {
    /// Creates a new session cache with background cleanup.
    pub fn new(config: SessionConfig) -> Self {
        let entries = Arc::new(RwLock::new(HashMap::new()));
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        // Spawn background cleanup task.
        let cleanup_entries = entries.clone();
        let cleanup_config = config.clone();
        tokio::spawn(async move {
            cleanup_loop(cleanup_entries, cleanup_config, stop_rx).await;
        });

        Self {
            entries,
            config,
            stop_tx: Some(stop_tx),
        }
    }

    /// Generates a cache key from principal ID and session ID.
    pub fn cache_key(principal_id: &str, session_id: &str) -> String {
        format!("{principal_id}:{session_id}")
    }

    /// Retrieves cached claims if the entry exists, is not expired by inactivity,
    /// and the token has not passed its expiration time.
    pub async fn get(&self, key: &str) -> Option<TokenClaims> {
        // Read check first.
        {
            let entries = self.entries.read().await;
            let entry = entries.get(key)?;

            let now = Instant::now();
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            // Never use tokens beyond their exp.
            if now_unix >= entry.claims.expires_at {
                drop(entries);
                self.delete(key).await;
                return None;
            }

            // Check inactivity TTL.
            if now.duration_since(entry.last_access) > self.config.inactivity_ttl {
                drop(entries);
                self.delete(key).await;
                return None;
            }
        }

        // Update last access time (sliding window).
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(key) {
            entry.last_access = Instant::now();
            Some(entry.claims.clone())
        } else {
            None
        }
    }

    /// Stores validated token claims in the cache.
    pub async fn put(&self, key: String, claims: TokenClaims) {
        let mut entries = self.entries.write().await;

        // Enforce max entries.
        if entries.len() >= self.config.max_entries {
            evict_oldest(&mut entries);
        }

        let now = Instant::now();
        entries.insert(
            key,
            SessionEntry {
                claims,
                last_access: now,
                created_at: now,
            },
        );
    }

    /// Removes an entry from the cache.
    pub async fn delete(&self, key: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(key);
    }

    /// Returns the number of entries in the cache.
    pub async fn size(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Stops the background cleanup task.
    pub fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
    }
}

impl Drop for SessionCache {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Background cleanup loop.
async fn cleanup_loop(
    entries: Arc<RwLock<HashMap<String, SessionEntry>>>,
    config: SessionConfig,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(config.cleanup_interval);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                cleanup(&entries, &config).await;
            }
            _ = stop_rx.changed() => {
                return;
            }
        }
    }
}

/// Removes entries that have exceeded inactivity TTL or token expiry.
async fn cleanup(entries: &Arc<RwLock<HashMap<String, SessionEntry>>>, config: &SessionConfig) {
    let mut entries = entries.write().await;
    let now = Instant::now();
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let before = entries.len();
    entries.retain(|_, entry| {
        let token_valid = now_unix < entry.claims.expires_at;
        let active = now.duration_since(entry.last_access) <= config.inactivity_ttl;
        token_valid && active
    });

    let expired = before - entries.len();
    if expired > 0 {
        debug!(expired, remaining = entries.len(), "session cache cleanup");
    }
}

/// Evicts the entry with the oldest last access time.
fn evict_oldest(entries: &mut HashMap<String, SessionEntry>) {
    let oldest_key = entries
        .iter()
        .min_by_key(|(_, entry)| entry.last_access)
        .map(|(key, _)| key.clone());

    if let Some(key) = oldest_key {
        entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims(expires_at: i64) -> TokenClaims {
        TokenClaims {
            subject: "user123".to_string(),
            issuer: "https://issuer.example.com".to_string(),
            audience: vec!["api://test".to_string()],
            expires_at,
            issued_at: 0,
            authorized_party: "client-app".to_string(),
            scopes: vec!["read".to_string()],
            roles: vec![],
            object_id: "obj-123".to_string(),
            tenant_id: "tenant-456".to_string(),
            preferred_username: "user@example.com".to_string(),
            token_id: "token-789".to_string(),
        }
    }

    fn future_expiry() -> i64 {
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600) as i64
    }

    fn past_expiry() -> i64 {
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60) as i64
    }

    #[test]
    fn test_cache_key() {
        assert_eq!(
            SessionCache::cache_key("principal-1", "session-2"),
            "principal-1:session-2"
        );
    }

    #[tokio::test]
    async fn test_put_and_get() {
        let cache = SessionCache::new(SessionConfig::default());
        let claims = make_claims(future_expiry());
        cache.put("key1".to_string(), claims.clone()).await;

        let result = cache.get("key1").await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().subject, "user123");
    }

    #[tokio::test]
    async fn test_get_missing_key() {
        let cache = SessionCache::new(SessionConfig::default());
        assert!(cache.get("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_expired_token_removed() {
        let cache = SessionCache::new(SessionConfig::default());
        let claims = make_claims(past_expiry());
        cache.put("key1".to_string(), claims).await;

        assert!(cache.get("key1").await.is_none());
        assert_eq!(cache.size().await, 0);
    }

    #[tokio::test]
    async fn test_delete() {
        let cache = SessionCache::new(SessionConfig::default());
        let claims = make_claims(future_expiry());
        cache.put("key1".to_string(), claims).await;
        cache.delete("key1").await;
        assert!(cache.get("key1").await.is_none());
    }

    #[tokio::test]
    async fn test_inactivity_ttl() {
        let config = SessionConfig {
            inactivity_ttl: Duration::from_millis(50),
            cleanup_interval: Duration::from_secs(60),
            max_entries: 100,
        };
        let cache = SessionCache::new(config);
        let claims = make_claims(future_expiry());
        cache.put("key1".to_string(), claims).await;

        // Wait for inactivity TTL to expire.
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(cache.get("key1").await.is_none());
    }

    #[tokio::test]
    async fn test_max_entries_eviction() {
        let config = SessionConfig {
            inactivity_ttl: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(60),
            max_entries: 3,
        };
        let cache = SessionCache::new(config);

        for i in 0..4 {
            let claims = make_claims(future_expiry());
            cache.put(format!("key{i}"), claims).await;
        }

        // Should have evicted one entry.
        assert!(cache.size().await <= 3);
    }

    #[tokio::test]
    async fn test_size() {
        let cache = SessionCache::new(SessionConfig::default());
        assert_eq!(cache.size().await, 0);

        let claims = make_claims(future_expiry());
        cache.put("key1".to_string(), claims.clone()).await;
        assert_eq!(cache.size().await, 1);

        cache.put("key2".to_string(), claims).await;
        assert_eq!(cache.size().await, 2);
    }
}
