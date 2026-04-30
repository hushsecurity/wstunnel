use crate::restrictions::auth::extract_bearer;
use crate::restrictions::types::JwtMatchConfig;
use anyhow::Context;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use parking_lot::Mutex;
use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Connection settings for the Redis instance that holds JWT public keys.
/// Built from CLI args at server startup; not deserialised from YAML.
#[derive(Clone)]
pub struct JwtRuntimeConfig {
    /// Full Redis connection URL, including credentials when required by the server.
    /// e.g. `redis://default:<password>@my-redis.example.com:6379/0` or `rediss://...`.
    pub redis_url: String,
    /// Name of the Redis hash that maps JWT `kid` (field) to the public PEM (value).
    /// Looked up via `HGET <redis_keys_hash> <kid>`.
    pub redis_keys_hash: String,
    /// Absolute upper bound on how long a cached public key may live, regardless of usage.
    /// Caps the revocation lag: once this elapses, the next request for that kid forces
    /// a fresh Redis lookup and an admin-removed key stops being honoured.
    pub key_cache_max_lifetime_sec: u64,
}

impl std::fmt::Debug for JwtRuntimeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // redis_url may carry credentials (redis://user:password@host...). Mask the
        // password so a stray dbg!() or error context can't leak the secret.
        let redacted_url = match url::Url::parse(&self.redis_url) {
            Ok(mut u) if u.password().is_some() => {
                let _ = u.set_password(Some("***"));
                u.to_string()
            }
            _ => self.redis_url.clone(),
        };
        f.debug_struct("JwtRuntimeConfig")
            .field("redis_url", &redacted_url)
            .field("redis_keys_hash", &self.redis_keys_hash)
            .field("key_cache_max_lifetime_sec", &self.key_cache_max_lifetime_sec)
            .finish()
    }
}

#[derive(Clone)]
struct CachedKey {
    decoding_key: DecodingKey,
    cached_at: Instant,
}

enum KeyFetcher {
    Redis {
        conn: MultiplexedConnection,
        keys_hash: String,
    },
    #[cfg(test)]
    Static(HashMap<String, String>),
}

impl KeyFetcher {
    async fn fetch(&self, kid: &str) -> Option<String> {
        match self {
            Self::Redis { conn, keys_hash } => {
                let mut conn = conn.clone();
                match conn.hget::<_, _, Option<String>>(keys_hash, kid).await {
                    Ok(Some(pem)) => Some(pem),
                    Ok(None) => {
                        debug!("No public key in Redis for kid {}", kid);
                        None
                    }
                    Err(err) => {
                        warn!("Redis HGET failed for kid {}: {}", kid, err);
                        None
                    }
                }
            }
            #[cfg(test)]
            Self::Static(keys) => keys.get(kid).cloned(),
        }
    }
}

pub struct JwtVerifier {
    fetcher: KeyFetcher,
    cache: Arc<Mutex<HashMap<String, CachedKey>>>,
    max_lifetime: Duration,
}

impl std::fmt::Debug for JwtVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtVerifier")
            .field("max_lifetime", &self.max_lifetime)
            .finish_non_exhaustive()
    }
}

impl JwtVerifier {
    pub async fn from_config(cfg: &JwtRuntimeConfig) -> anyhow::Result<Self> {
        let client = redis::Client::open(cfg.redis_url.as_str()).context("Invalid redis_url")?;
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to open Redis connection")?;
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .context("Redis PING failed")?;
        Ok(Self {
            fetcher: KeyFetcher::Redis {
                conn,
                keys_hash: cfg.redis_keys_hash.clone(),
            },
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_lifetime: Duration::from_secs(cfg.key_cache_max_lifetime_sec),
        })
    }

    pub async fn matches(&self, authorization_header: &str, cfg: &JwtMatchConfig) -> bool {
        let Some(token) = extract_bearer(authorization_header) else {
            return false;
        };

        let header = match decode_header(token) {
            Ok(h) => h,
            Err(err) => {
                debug!("JWT header decode failed: {}", err);
                return false;
            }
        };

        let Some(kid) = header.kid.as_deref() else {
            debug!("JWT missing 'kid' header");
            return false;
        };

        let Some(decoding_key) = self.get_or_fetch_key(kid).await else {
            return false;
        };

        let mut validation = Validation::new(Algorithm::RS256);
        // 'nbf' validation is disabled by default, explicitly enable it
        validation.validate_nbf = true;

        // If the operator listed 'aud' in required_claims, delegate audience validation to
        // jsonwebtoken so the RFC 7519 semantics are honoured: 'aud' may be a string or an
        // array of strings, and the token matches if any of its audiences is in the allow-list.
        // Otherwise skip aud validation entirely.
        match cfg.required_claims.get("aud") {
            Some(allowed) => validation.set_audience(allowed),
            None => validation.validate_aud = false,
        }

        let claims = match decode::<HashMap<String, serde_json::Value>>(token, &decoding_key, &validation) {
            Ok(td) => td.claims,
            Err(err) => {
                debug!("JWT verification failed: {}", err);
                return false;
            }
        };

        for (claim_name, allowed) in &cfg.required_claims {
            // 'aud' was already validated by jsonwebtoken above.
            if claim_name == "aud" {
                continue;
            }
            let Some(actual) = claims.get(claim_name).and_then(|v| v.as_str()) else {
                debug!("JWT missing or non-string required claim: {}", claim_name);
                return false;
            };
            if !allowed.iter().any(|a| a == actual) {
                debug!("JWT claim '{}' value not allowed: {}", claim_name, actual);
                return false;
            }
        }

        true
    }

    /// Cache lookup that avoids holding the lock across the underlying fetch:
    /// the miss path drops the lock before the (potentially slow) fetch and
    /// re-acquires only to insert. Two concurrent misses for the same kid
    /// resolve to the same key -- the later insert simply overwrites the
    /// earlier with an equivalent value.
    ///
    /// Entries are evicted strictly on absolute age: an entry past
    /// `max_lifetime` since its `cached_at` is treated as a miss and re-fetched
    /// from Redis. Cache hits do not extend lifetime, so an admin who removes a
    /// kid from Redis is guaranteed to stop honouring it within `max_lifetime`
    /// even against an adversary that keeps the entry warm with constant use.
    async fn get_or_fetch_key(&self, kid: &str) -> Option<DecodingKey> {
        let now = Instant::now();

        // Single lock: live hit returns; miss (or expired-on-hit) sweeps before we release.
        {
            let mut cache = self.cache.lock();
            if let Some(entry) = cache.get(kid) {
                if now.saturating_duration_since(entry.cached_at) < self.max_lifetime {
                    return Some(entry.decoding_key.clone());
                }
                info!("Purging public key {} (max lifetime reached)", kid);
                cache.remove(kid);
            }
            // Sweep other expired entries while the lock is briefly held.
            cache.retain(|k, e| {
                let keep = now.saturating_duration_since(e.cached_at) < self.max_lifetime;
                if !keep {
                    info!("Purging public key {}", k);
                }
                keep
            });
        }

        let pem = self.fetcher.fetch(kid).await?;

        let decoding_key = match DecodingKey::from_rsa_pem(pem.as_bytes()) {
            Ok(k) => k,
            Err(err) => {
                warn!("Failed to parse PEM for kid {}: {}", kid, err);
                return None;
            }
        };

        let mut cache = self.cache.lock();
        cache.insert(
            kid.to_string(),
            CachedKey {
                decoding_key: decoding_key.clone(),
                cached_at: Instant::now(),
            },
        );

        info!("Cached a new public key: {}", kid);

        Some(decoding_key)
    }
}

#[cfg(test)]
impl JwtVerifier {
    /// Test-only constructor. `static_keys` maps kid -> PEM-encoded SPKI public key.
    /// Bypasses Redis entirely.
    pub fn with_static_keys(static_keys: HashMap<String, String>, max_lifetime: Duration) -> Self {
        Self {
            fetcher: KeyFetcher::Static(static_keys),
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_lifetime,
        }
    }
}

// Test-only RSA-2048 keypair. Generated with openssl; never deployed. Exposed at
// `pub(crate)` so other modules' tests can sign tokens with the matching key.
#[cfg(test)]
pub(crate) const TEST_PRIVATE_PEM: &str = "
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCYhYFGt0LaJwyE
/BaCKa8h/7glyXipXEYnquryl53Q4akYqKIfIfup7+CtrAhQedLgIurmbQ1axLSY
GUFTIu7x3OzjQsaIia/U/I90YuMcflfnY8l3hnuKLD4m74on9gsd4C2L2XDzhBH2
1i2RgY9kYOQv1gpsNRfHdG1UCL794icTHoPW32/2gzyobL8KGYolJAypnzN36kml
fDTzrlb9aP5AiY/I5uEjZ2XZUqQzwkj3UDltJ5TR7NVQooWWYjjzRoA3w2hXKwip
5peD/fOYBVOz7PyGS9PK9sLtLy2atk4uVqEkLwWfbZBUAAzBcwO6Lr7DTiUGpneg
N4tJJ0pVAgMBAAECggEADPtmGMkN+2gR+HrFhrA6HCx6NdsrdkzomsVBSMNPd0FR
5Yuq+vfnRhxpFRc8wO7RnGrUcCcNmTF/hqe1p/gj+vm5PxHGuMXxbbFOm5M0Lg9x
93vGoPIVL1pbMvC2I3cdlJ4peksYgl22Mrqht84dkKdvnMO88N9nBf7atGmnKhBV
Xp7302PYo5BhJGOGKdvV2KDEcjwwYgOsxNHq8p0/rj6jWOfb3n6b288JlNZTQ4EF
DL7LufjDRM+RKWj5R/k3YW/D/6shoS+PSXszkwtmYhQWIYEHlLM/9Rby+JmOiHWc
yT95o4+bVIZqdL6PGWrMjAVG+54mc2GOC/FKN9KEgQKBgQDRBDjYgMXiTQdJ4uD0
FJu3KfQRRFsFqGRQKx1DimZ0b2gYoY0mpUwQ3jUrnIHspBJRhxSxzPjsFz2aggbe
YXjC1XfjQ9csUeEFmPNEQlUlefzFFkVzyma89OGacfDXNF3ILpyqVzMBi3oj7HqY
Nya7wue2w19zNkxYNyyEHPvp1QKBgQC6zkykoYz7tHl+vjf0y51XyM2+4ttDYdxJ
Dk7v6xQsa0Vr+CssjmLdptlK9ay4n+iqEBszJfKwgTBNwBC6SfccEXptHOYbCEZg
UWVGGNPj3CIWMI9+d2h196VWlAYxgF8kxUJCM1Mxm9a90mSRpg5frX2HSZhj+ozK
lu5/mdGegQKBgCgILvsIbt4Q8rxr/7m/2LMUDfLgrK5AujXAjDJLZ6QVUlKlXmtw
bUktxfE8YIX6Rqfmv0fugh51tQ7KqJYfBQoL6JJWg/exFvADg1QngDdVTdxRj6vF
sDewjyUNfZs6JFwa0VaurM428IXA3RoaNgjwI4EVmkpus+CRcK08/+KhAoGBAIY2
nl5SK6bUXc4wAKgCesONZDVXbE2XS9u5SgGaFl5rm+8c2HgkvOefbtMqe7QSP+mf
tMsk4p7p0rip29rcNYyXCizG7JRTd6zQDkE0qVg22s6yiQZF6GmJSeNQarq6DqGu
kBJcKdOksb6kINl8Qyt+zIec2r5KT0lm82f+LdsBAoGACyD6g524S+Pj7aC02C6Z
58fG0nwGgoJ7AAQwC58j8+0BOb454w5CKOfVUYnX8qEteAQRBnP5vnaydGsKqfGe
gmIm9VXZTd8aUUdHFY2JE95jz/uC9n6REz4c4ub08zJ/0ewcBlPhoae1Da/WGsVU
NJJvczee0T6SqhQuyusGGsY=
-----END PRIVATE KEY-----
";

#[cfg(test)]
pub(crate) const TEST_PUBLIC_PEM: &str = "
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmIWBRrdC2icMhPwWgimv
If+4Jcl4qVxGJ6rq8ped0OGpGKiiHyH7qe/grawIUHnS4CLq5m0NWsS0mBlBUyLu
8dzs40LGiImv1PyPdGLjHH5X52PJd4Z7iiw+Ju+KJ/YLHeAti9lw84QR9tYtkYGP
ZGDkL9YKbDUXx3RtVAi+/eInEx6D1t9v9oM8qGy/ChmKJSQMqZ8zd+pJpXw0865W
/Wj+QImPyObhI2dl2VKkM8JI91A5bSeU0ezVUKKFlmI480aAN8NoVysIqeaXg/3z
mAVTs+z8hkvTyvbC7S8tmrZOLlahJC8Fn22QVAAMwXMDui6+w04lBqZ3oDeLSSdK
VQIDAQAB
-----END PUBLIC KEY-----
";

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use std::time::SystemTime;

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn make_token(kid: Option<&str>, alg: Algorithm, claims: serde_json::Value) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(String::from);
        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    fn match_cfg(claim: &str, allowed: &[&str]) -> JwtMatchConfig {
        let mut required = HashMap::new();
        required.insert(claim.to_string(), allowed.iter().map(|s| s.to_string()).collect());
        JwtMatchConfig {
            required_claims: required,
        }
    }

    fn verifier_with_kid(kid: &str, max_lifetime: Duration) -> JwtVerifier {
        let mut keys = HashMap::new();
        keys.insert(kid.to_string(), TEST_PUBLIC_PEM.to_string());
        JwtVerifier::with_static_keys(keys, max_lifetime)
    }

    #[tokio::test]
    async fn matches_valid_token() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "exp": now_unix() + 60 }),
        );
        let cfg = match_cfg("sub", &["alice"]);
        assert!(verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn rejects_wrong_claim_value() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "bob", "exp": now_unix() + 60 }),
        );
        let cfg = match_cfg("sub", &["alice"]);
        assert!(!verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn matches_any_value_in_allowed_list() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let cfg = match_cfg("sub", &["alice", "bob"]);
        for sub in ["alice", "bob"] {
            let token = make_token(
                Some("test-kid"),
                Algorithm::RS256,
                serde_json::json!({ "sub": sub, "exp": now_unix() + 60 }),
            );
            assert!(
                verifier.matches(&format!("Bearer {}", token), &cfg).await,
                "sub={sub} should match"
            );
        }
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "carol", "exp": now_unix() + 60 }),
        );
        assert!(!verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn rejects_unknown_kid() {
        let verifier = verifier_with_kid("known-kid", Duration::from_secs(3600));
        let token = make_token(
            Some("unknown-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "exp": now_unix() + 60 }),
        );
        let cfg = match_cfg("sub", &["alice"]);
        assert!(!verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn rejects_missing_kid() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let token = make_token(
            None,
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "exp": now_unix() + 60 }),
        );
        let cfg = match_cfg("sub", &["alice"]);
        assert!(!verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn rejects_expired_token() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        // Past the default 60s leeway in jsonwebtoken's Validation.
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "exp": now_unix() - 7200 }),
        );
        let cfg = match_cfg("sub", &["alice"]);
        assert!(!verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn rejects_not_yet_valid_token() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        // 'nbf' far enough in the future to clear the default 60s leeway.
        // 'exp' is also pushed out so the failure is isolated to 'nbf'.
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "exp": now_unix() + 7200, "nbf": now_unix() + 7200 }),
        );
        let cfg = match_cfg("sub", &["alice"]);
        assert!(!verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn rejects_disallowed_algorithm() {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-kid".to_string());
        let claims = serde_json::json!({ "sub": "alice", "exp": now_unix() + 60 });
        let token = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(b"shared")).unwrap();
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let cfg = match_cfg("sub", &["alice"]);
        assert!(!verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn rejects_missing_authorization_header() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let cfg = match_cfg("sub", &["alice"]);
        assert!(!verifier.matches("not-a-bearer-token", &cfg).await);
    }

    #[tokio::test]
    async fn matches_string_aud() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "aud": "svc-a", "exp": now_unix() + 60 }),
        );
        let cfg = match_cfg("aud", &["svc-a"]);
        assert!(verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn matches_array_aud_per_rfc7519() {
        // Regression guard for the as_str()-based check that silently failed on array aud.
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({
                "sub": "alice",
                "aud": ["svc-a", "svc-b"],
                "exp": now_unix() + 60
            }),
        );
        let cfg = match_cfg("aud", &["svc-b"]);
        assert!(verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn rejects_aud_mismatch() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "aud": "svc-a", "exp": now_unix() + 60 }),
        );
        let cfg = match_cfg("aud", &["svc-b"]);
        assert!(!verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[test]
    fn debug_redacts_redis_password() {
        let cfg = JwtRuntimeConfig {
            redis_url: "redis://default:hunter2@redis.example.com:6379/0".to_string(),
            redis_keys_hash: "jwt_keys".to_string(),
            key_cache_max_lifetime_sec: 3600,
        };
        let dbg = format!("{:?}", cfg);
        assert!(!dbg.contains("hunter2"), "password leaked: {dbg}");
        assert!(dbg.contains("***"), "password not masked: {dbg}");
        assert!(dbg.contains("redis.example.com"), "host should still be visible: {dbg}");
    }

    #[tokio::test]
    async fn rejects_array_aud_mismatch() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({
                "sub": "alice",
                "aud": ["svc-a", "svc-b"],
                "exp": now_unix() + 60
            }),
        );
        let cfg = match_cfg("aud", &["svc-c"]);
        assert!(!verifier.matches(&format!("Bearer {}", token), &cfg).await);
    }

    #[tokio::test]
    async fn cache_evicts_expired_keys_on_miss() {
        let verifier = verifier_with_kid("test-kid", Duration::from_millis(50));
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "exp": now_unix() + 60 }),
        );
        let cfg = match_cfg("sub", &["alice"]);
        assert!(verifier.matches(&format!("Bearer {}", token), &cfg).await);
        assert_eq!(verifier.cache.lock().len(), 1);

        tokio::time::sleep(Duration::from_millis(80)).await;

        // Cache miss for an unknown kid; the sweep should evict the now-expired test-kid entry.
        let token2 = make_token(
            Some("other-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "exp": now_unix() + 60 }),
        );
        let _ = verifier.matches(&format!("Bearer {}", token2), &cfg).await;

        assert!(
            !verifier.cache.lock().contains_key("test-kid"),
            "expired entry should be evicted"
        );
    }

    #[tokio::test]
    async fn cache_evicts_expired_keys_on_hit() {
        // Regression guard: an entry past `max_lifetime` must not be served even if it is
        // hit repeatedly. This is the property that bounds revocation lag against an
        // adversary who keeps a stolen-key entry warm with constant requests.
        let verifier = verifier_with_kid("test-kid", Duration::from_millis(50));
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "exp": now_unix() + 60 }),
        );
        let cfg = match_cfg("sub", &["alice"]);
        assert!(verifier.matches(&format!("Bearer {}", token), &cfg).await);
        let cached_at_first = verifier.cache.lock().get("test-kid").unwrap().cached_at;

        tokio::time::sleep(Duration::from_millis(80)).await;

        // Same kid, well past max_lifetime: must trigger a refetch and re-stamp cached_at.
        assert!(verifier.matches(&format!("Bearer {}", token), &cfg).await);
        let cached_at_second = verifier.cache.lock().get("test-kid").unwrap().cached_at;

        assert!(
            cached_at_second > cached_at_first,
            "expired-on-hit entry should be replaced, not extended"
        );
    }

    #[tokio::test]
    async fn cache_keeps_fresh_keys_on_miss() {
        let verifier = verifier_with_kid("test-kid", Duration::from_secs(3600));
        let token = make_token(
            Some("test-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "exp": now_unix() + 60 }),
        );
        let cfg = match_cfg("sub", &["alice"]);
        assert!(verifier.matches(&format!("Bearer {}", token), &cfg).await);

        let token2 = make_token(
            Some("other-kid"),
            Algorithm::RS256,
            serde_json::json!({ "sub": "alice", "exp": now_unix() + 60 }),
        );
        let _ = verifier.matches(&format!("Bearer {}", token2), &cfg).await;

        assert!(
            verifier.cache.lock().contains_key("test-kid"),
            "recent entry should survive sweep"
        );
    }
}
