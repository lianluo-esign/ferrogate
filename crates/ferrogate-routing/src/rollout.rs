// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Canary + shadow/mirror rollout selection (issue #276).
//!
//! Pure, deterministic selection primitives shared by the gateway's
//! request path. Canary picks a sticky percentage of traffic for a new
//! provider/model (evaluated fully, like the primary route); shadow picks
//! a sampled, budget-capped fraction of traffic to *mirror* to a secondary
//! provider without affecting the client response.
//!
//! Both decisions hash a caller-stable *sticky key* (api key / tenant) so a
//! given caller lands consistently on (or off) the split, and so tests can
//! assert an exact distribution from a fixed set of keys.

use std::{collections::HashMap, sync::Mutex};

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Deterministic 0..=99 bucket for `sticky_key` under a named split.
///
/// The `salt` decorrelates independent splits: a caller can be inside the
/// canary bucket yet outside the shadow bucket (and vice versa) even at the
/// same percentage, so enabling one rollout never forces the other onto the
/// same subset of callers.
pub fn rollout_bucket(salt: &str, sticky_key: &str) -> u8 {
    let mut input = Vec::with_capacity(salt.len() + 1 + sticky_key.len());
    input.extend_from_slice(salt.as_bytes());
    input.push(0);
    input.extend_from_slice(sticky_key.as_bytes());
    (fnv1a64(&input) % 100) as u8
}

/// True when a request with `sticky_key` falls in the canary bucket for the
/// given percentage. `0` never selects, `>= 100` always selects, and every
/// value in between is sticky per key (same key -> same answer).
pub fn canary_selected(sticky_key: &str, percent: u8) -> bool {
    if percent == 0 {
        return false;
    }
    if percent >= 100 {
        return true;
    }
    rollout_bucket("canary", sticky_key) < percent
}

/// True when a request with `sticky_key` is sampled for shadow mirroring.
/// Uses a distinct salt from [`canary_selected`] so the two rollouts sample
/// independent subsets of callers.
pub fn shadow_sampled(sticky_key: &str, sample_percent: u8) -> bool {
    if sample_percent == 0 {
        return false;
    }
    if sample_percent >= 100 {
        return true;
    }
    rollout_bucket("shadow", sticky_key) < sample_percent
}

/// Process-lifetime budget cap for shadow-mirror dispatches, keyed by an
/// arbitrary budget scope (the gateway keys it by logical model). Caps the
/// mirror's cost: once `limit` shadow requests have been admitted for a key,
/// further requests are refused until the process restarts. `limit == 0`
/// means uncapped.
#[derive(Debug, Default)]
pub struct ShadowBudgetLedger {
    used: Mutex<HashMap<String, u64>>,
}

impl ShadowBudgetLedger {
    /// Admits one shadow dispatch against `key`, returning `true` when it is
    /// within budget (and charging it), or `false` when the cap is reached.
    /// A poisoned lock is recovered rather than panicking, so a shadow path
    /// can never take down the primary request.
    pub fn try_consume(&self, key: &str, limit: u64) -> bool {
        if limit == 0 {
            return true;
        }
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = used.entry(key.to_string()).or_insert(0);
        if *entry >= limit {
            return false;
        }
        *entry += 1;
        true
    }

    /// Number of shadow dispatches charged so far against `key`.
    pub fn consumed(&self, key: &str) -> u64 {
        self.used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_percent_zero_never_selects_and_hundred_always_selects() {
        for key in ["k0", "tenant-a", "api-key-42", ""] {
            assert!(!canary_selected(key, 0));
            assert!(canary_selected(key, 100));
            assert!(canary_selected(key, 200)); // saturating: >=100 always
        }
    }

    #[test]
    fn canary_is_sticky_per_key() {
        // Same key + percent always yields the same decision.
        for _ in 0..1000 {
            assert_eq!(
                canary_selected("sticky-key", 37),
                canary_selected("sticky-key", 37)
            );
        }
    }

    #[test]
    fn canary_ten_percent_split_is_within_tolerance() {
        // Deterministic "seed": a fixed, enumerated key space. A 10% canary
        // should land within a tight tolerance of 10% of the keys.
        let total = 10_000;
        let selected = (0..total)
            .filter(|index| canary_selected(&format!("key-{index}"), 10))
            .count();
        let ratio = selected as f64 / total as f64;
        assert!(
            (ratio - 0.10).abs() < 0.015,
            "canary ratio {ratio} not within tolerance of 0.10 ({selected}/{total})"
        );
    }

    #[test]
    fn canary_bucket_is_monotonic_in_percent() {
        // A key selected at percent P is still selected at every percent > P,
        // so raising the canary percentage only ever adds callers.
        let key = "monotonic-key";
        let mut previously_selected = false;
        for percent in 0..=100 {
            let selected = canary_selected(key, percent);
            if previously_selected {
                assert!(selected, "canary flipped back off at percent {percent}");
            }
            previously_selected = selected;
        }
    }

    #[test]
    fn shadow_and_canary_sample_independently() {
        // At the same percentage the two salted splits must not be identical
        // for every key, otherwise enabling one forces the other onto the
        // same callers.
        let differ = (0..1000).any(|index| {
            let key = format!("key-{index}");
            canary_selected(&key, 50) != shadow_sampled(&key, 50)
        });
        assert!(differ, "canary and shadow splits are perfectly correlated");
    }

    #[test]
    fn shadow_budget_caps_dispatch_count() {
        let ledger = ShadowBudgetLedger::default();
        assert!(ledger.try_consume("gpt-4o", 2));
        assert!(ledger.try_consume("gpt-4o", 2));
        assert!(
            !ledger.try_consume("gpt-4o", 2),
            "third dispatch must be refused"
        );
        assert_eq!(ledger.consumed("gpt-4o"), 2);
        // A different key has its own independent budget.
        assert!(ledger.try_consume("gpt-4o-mini", 2));
        assert_eq!(ledger.consumed("gpt-4o-mini"), 1);
    }

    #[test]
    fn shadow_budget_zero_limit_is_uncapped() {
        let ledger = ShadowBudgetLedger::default();
        for _ in 0..1000 {
            assert!(ledger.try_consume("model", 0));
        }
        // Uncapped never records usage.
        assert_eq!(ledger.consumed("model"), 0);
    }
}
