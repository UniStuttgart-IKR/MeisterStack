// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What to do about a VM whose phase is Failed: nothing, a bounded number of
//! retries, or Kubernetes' answer — retry forever, ever more slowly.
//!
//! The retry itself is cheap and safe: the reconciler re-sends Start, the
//! agent's `set_desired` clears its failure backoff and provisions afresh.
//! The policy only decides WHEN that kick is due, from bookkeeping the
//! reconciler keeps in `VmStatus` (`requeue_attempts`, `last_requeue`).
//! Failed is the one phase this touches — Quarantined stays manual by design.

use std::time::Duration;

pub trait RequeuePolicy: Send + Sync {
    /// Delay before attempt number `attempts + 1`; None = leave it Failed.
    fn next_delay(&self, attempts: u32) -> Option<Duration>;
}

/// 10s, 20s, 40s … capped at 5 minutes — the CrashLoopBackOff curve. Slow
/// enough that a genuinely broken spec ticks instead of thrashing, fast
/// enough that a transient host problem heals within a tick or two.
fn backoff(attempts: u32) -> Duration {
    Duration::from_secs(10)
        .saturating_mul(2u32.saturating_pow(attempts.min(5)))
        .min(Duration::from_secs(300))
}

/// `retry = "none"` — Failed is final, exactly the behaviour before this
/// module existed.
pub struct NoRequeue;

/// `retry = <n>` — up to n kicks on the backoff curve, then Failed is final.
pub struct RetryCount(pub u32);

/// `retry = "crash-loop-backoff"` — never final, always slower.
pub struct CrashLoopBackoff;

impl RequeuePolicy for NoRequeue {
    fn next_delay(&self, _attempts: u32) -> Option<Duration> {
        None
    }
}

impl RequeuePolicy for RetryCount {
    fn next_delay(&self, attempts: u32) -> Option<Duration> {
        (attempts < self.0).then(|| backoff(attempts))
    }
}

impl RequeuePolicy for CrashLoopBackoff {
    fn next_delay(&self, attempts: u32) -> Option<Duration> {
        Some(backoff(attempts))
    }
}

/// The TOML spelling: `retry = "none" | 5 | "crash-loop-backoff"`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum RequeueConfig {
    Count(u32),
    Named(String),
}

impl RequeueConfig {
    /// Default when the config says nothing: CrashLoopBackOff — a transient
    /// failure healing itself is the behaviour a K8s-shaped stack owes its
    /// operator; `retry = "none"` is the opt-out.
    pub fn into_policy(this: Option<Self>) -> anyhow::Result<std::sync::Arc<dyn RequeuePolicy>> {
        Ok(match this {
            None => std::sync::Arc::new(CrashLoopBackoff),
            Some(RequeueConfig::Count(n)) => std::sync::Arc::new(RetryCount(n)),
            Some(RequeueConfig::Named(s)) => match s.as_str() {
                "crash-loop-backoff" => std::sync::Arc::new(CrashLoopBackoff),
                "none" => std::sync::Arc::new(NoRequeue),
                other => anyhow::bail!(
                    "retry = {other:?}; expected \"none\", \"crash-loop-backoff\" or a number"
                ),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_curve_doubles_and_caps() {
        assert_eq!(backoff(0), Duration::from_secs(10));
        assert_eq!(backoff(1), Duration::from_secs(20));
        assert_eq!(backoff(4), Duration::from_secs(160));
        assert_eq!(backoff(5), Duration::from_secs(300));
        assert_eq!(backoff(50), Duration::from_secs(300));
    }

    #[test]
    fn none_never_retries_and_count_stops_at_its_limit() {
        assert_eq!(NoRequeue.next_delay(0), None);
        assert!(RetryCount(2).next_delay(1).is_some());
        assert_eq!(RetryCount(2).next_delay(2), None);
        assert!(CrashLoopBackoff.next_delay(1000).is_some());
    }

    /// The three TOML spellings parse into the three policies; nonsense is an
    /// error at startup, not a silent NoRequeue.
    #[test]
    fn the_toml_spellings_resolve() {
        #[derive(serde::Deserialize)]
        struct F {
            retry: Option<RequeueConfig>,
        }
        let parse = |s: &str| toml::from_str::<F>(s).unwrap().retry;
        assert!(RequeueConfig::into_policy(parse("retry = 3")).is_ok());
        assert!(RequeueConfig::into_policy(parse(r#"retry = "none""#)).is_ok());
        assert!(RequeueConfig::into_policy(parse(r#"retry = "crash-loop-backoff""#)).is_ok());
        assert!(RequeueConfig::into_policy(parse("")).is_ok());
        assert!(RequeueConfig::into_policy(parse(r#"retry = "sometimes""#)).is_err());
    }
}
