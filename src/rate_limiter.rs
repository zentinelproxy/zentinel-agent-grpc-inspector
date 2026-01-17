//! Token bucket rate limiter.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limiter using token bucket algorithm.
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<RateLimitKey, TokenBucket>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        let limiter = Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
        };
        limiter.spawn_cleanup_task();
        limiter
    }

    /// Check if a request is allowed under rate limits.
    pub async fn check(
        &self,
        key: RateLimitKey,
        limit: u32,
        window_seconds: u32,
        burst: u32,
    ) -> RateLimitResult {
        let mut buckets = self.buckets.write().await;
        let bucket = buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(limit, window_seconds, burst));

        bucket.try_consume()
    }

    /// Spawn a background task to clean up stale buckets.
    fn spawn_cleanup_task(&self) {
        let buckets = Arc::clone(&self.buckets);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mut buckets = buckets.write().await;
                let now = Instant::now();
                // Remove buckets that haven't been used in 5 minutes
                buckets.retain(|_, bucket| now.duration_since(bucket.last_update) < Duration::from_secs(300));
            }
        });
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Key for rate limiting - identifies a unique rate limit bucket.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RateLimitKey {
    pub service: String,
    pub method: String,
    pub client_key: String,
}

impl RateLimitKey {
    pub fn new(service: &str, method: &str, client_key: &str) -> Self {
        Self {
            service: service.to_string(),
            method: method.to_string(),
            client_key: client_key.to_string(),
        }
    }
}

/// Token bucket for rate limiting.
struct TokenBucket {
    /// Current number of tokens
    tokens: f64,
    /// Maximum tokens (capacity)
    capacity: u32,
    /// Tokens refilled per second
    refill_rate: f64,
    /// Burst allowance (extra tokens above capacity)
    burst: u32,
    /// Last time tokens were updated
    last_update: Instant,
}

impl TokenBucket {
    fn new(limit: u32, window_seconds: u32, burst: u32) -> Self {
        let capacity = limit;
        let refill_rate = limit as f64 / window_seconds as f64;

        Self {
            tokens: (capacity + burst) as f64, // Start full with burst
            capacity,
            refill_rate,
            burst,
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> RateLimitResult {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            RateLimitResult::Allowed {
                remaining: self.tokens as u32,
            }
        } else {
            // Calculate when a token will be available
            let tokens_needed = 1.0 - self.tokens;
            let seconds_to_wait = (tokens_needed / self.refill_rate).ceil() as u32;

            RateLimitResult::Exceeded {
                retry_after_secs: seconds_to_wait.max(1),
            }
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        // Add tokens based on elapsed time
        self.tokens += elapsed * self.refill_rate;

        // Cap at capacity + burst
        let max_tokens = (self.capacity + self.burst) as f64;
        if self.tokens > max_tokens {
            self.tokens = max_tokens;
        }
    }
}

/// Result of a rate limit check.
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed {
        /// Remaining requests in current window
        remaining: u32,
    },
    /// Request is rate limited
    Exceeded {
        /// Seconds until rate limit resets
        retry_after_secs: u32,
    },
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_allows_within_limit() {
        let mut bucket = TokenBucket::new(10, 60, 0);

        // Should allow 10 requests
        for i in 0..10 {
            let result = bucket.try_consume();
            assert!(
                result.is_allowed(),
                "Request {} should be allowed",
                i + 1
            );
        }

        // 11th request should be denied
        let result = bucket.try_consume();
        assert!(!result.is_allowed(), "11th request should be denied");
    }

    #[test]
    fn test_token_bucket_with_burst() {
        let mut bucket = TokenBucket::new(10, 60, 5);

        // Should allow 15 requests (10 + 5 burst)
        for i in 0..15 {
            let result = bucket.try_consume();
            assert!(
                result.is_allowed(),
                "Request {} should be allowed with burst",
                i + 1
            );
        }

        // 16th request should be denied
        let result = bucket.try_consume();
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_retry_after_calculation() {
        let mut bucket = TokenBucket::new(10, 60, 0);

        // Exhaust all tokens
        for _ in 0..10 {
            bucket.try_consume();
        }

        // Check retry_after
        if let RateLimitResult::Exceeded { retry_after_secs } = bucket.try_consume() {
            // At 10 tokens per 60 seconds = 1 token every 6 seconds
            assert!(
                (1..=7).contains(&retry_after_secs),
                "retry_after should be around 6 seconds, got {}",
                retry_after_secs
            );
        } else {
            panic!("Expected Exceeded result");
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new();
        let key = RateLimitKey::new("myapp.UserService", "GetUser", "127.0.0.1");

        // Allow 5 requests per 60 seconds
        for i in 0..5 {
            let result = limiter.check(key.clone(), 5, 60, 0).await;
            assert!(result.is_allowed(), "Request {} should be allowed", i + 1);
        }

        // 6th request should be denied
        let result = limiter.check(key.clone(), 5, 60, 0).await;
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_rate_limiter_different_keys() {
        let limiter = RateLimiter::new();

        let key1 = RateLimitKey::new("myapp.UserService", "GetUser", "127.0.0.1");
        let key2 = RateLimitKey::new("myapp.UserService", "GetUser", "192.168.1.1");

        // Both should get their own limit
        for _ in 0..5 {
            let r1 = limiter.check(key1.clone(), 5, 60, 0).await;
            let r2 = limiter.check(key2.clone(), 5, 60, 0).await;
            assert!(r1.is_allowed());
            assert!(r2.is_allowed());
        }

        // Both should now be exhausted
        assert!(!limiter.check(key1.clone(), 5, 60, 0).await.is_allowed());
        assert!(!limiter.check(key2.clone(), 5, 60, 0).await.is_allowed());
    }
}
