// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Tests for the Cloudflare Secrets Store beta-cap guardrail
// policy — value-size fail-fast, secret-count budget, env thresholds (#418).

//! Tests for [`crate::CfSecretsCapacityPolicy`] (issue #418) — pure policy
//! logic, no transport involved. Resolver-level enforcement (the guardrails
//! wired into the `create_secret` write path) is covered in
//! `cloudflare_test.rs` with the scripted mock transport.

use crate::{
    CfSecretsCapacityPolicy, CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT,
    CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES, DEFAULT_CF_SECRETS_WARN_AT,
};

#[test]
fn default_policy_mirrors_beta_caps() {
    let policy = CfSecretsCapacityPolicy::default();
    assert_eq!(
        policy.max_secrets,
        CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT
    );
    assert_eq!(policy.warn_at_secrets, DEFAULT_CF_SECRETS_WARN_AT);
    assert_eq!(
        policy.max_value_bytes,
        CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES
    );
}

// --- value-size guardrail ---------------------------------------------------

#[test]
fn value_at_cap_is_accepted_and_one_byte_over_is_rejected() {
    let policy = CfSecretsCapacityPolicy::default();
    let at_cap = "x".repeat(CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES);
    assert!(policy
        .check_value_size("provider-keys", "fits", &at_cap)
        .is_ok());

    let over = "x".repeat(CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES + 1);
    let error = policy
        .check_value_size("provider-keys", "too-big", &over)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("1025 bytes") && error.contains("beta cap of 1024 bytes"),
        "error must state the exact size and the cap: {error}"
    );
    assert!(
        error.contains("cloudflare-secrets-tenancy"),
        "error must point at the tenancy decision doc: {error}"
    );
}

#[test]
fn value_size_counts_utf8_bytes_not_chars() {
    // 400 four-byte scalars = 400 chars but 1600 bytes — must be rejected.
    let policy = CfSecretsCapacityPolicy::default();
    let wide = "\u{1F510}".repeat(400);
    assert_eq!(wide.chars().count(), 400);
    let error = policy
        .check_value_size("provider-keys", "wide", &wide)
        .unwrap_err()
        .to_string();
    assert!(error.contains("1600 bytes"), "unexpected error: {error}");
}

#[test]
fn overridden_value_cap_is_labelled_configured() {
    let policy = CfSecretsCapacityPolicy {
        max_value_bytes: 8,
        ..CfSecretsCapacityPolicy::default()
    };
    let error = policy
        .check_value_size("provider-keys", "n", "123456789")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("configured cap of 8 bytes"),
        "a non-beta cap must not be called a beta cap: {error}"
    );
}

// --- secret-count budget guardrail ------------------------------------------

#[test]
fn budget_allows_new_secret_below_warn_threshold_silently() {
    let policy = CfSecretsCapacityPolicy::default();
    assert_eq!(
        policy
            .check_secret_budget("provider-keys", "new", 25, false)
            .unwrap(),
        None
    );
}

#[test]
fn budget_warns_when_write_lands_at_or_above_soft_threshold() {
    let policy = CfSecretsCapacityPolicy::default();
    // 89 existing + 1 new = 90 → exactly the default soft threshold.
    let warning = policy
        .check_secret_budget("provider-keys", "ninetieth", 89, false)
        .unwrap()
        .expect("crossing the soft threshold must warn");
    assert_eq!(warning.used_after_write, 90);
    assert_eq!(warning.max_secrets, 100);
    assert_eq!(warning.warn_at_secrets, 90);
    let text = warning.to_string();
    assert!(
        text.contains("90 of 100"),
        "warning must show usage vs budget: {text}"
    );

    // 89 existing, overwrite → still 89 used → below the threshold, silent.
    assert_eq!(
        policy
            .check_secret_budget("provider-keys", "existing", 89, true)
            .unwrap(),
        None
    );
}

#[test]
fn budget_rejects_new_secret_at_hard_cap_but_allows_overwrite() {
    let policy = CfSecretsCapacityPolicy::default();
    let error = policy
        .check_secret_budget("provider-keys", "one-too-many", 100, false)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("100 secrets") && error.contains("beta budget of 100"),
        "hard-cap error must state usage and budget: {error}"
    );
    assert!(
        error.contains("cloudflare-secrets-tenancy"),
        "hard-cap error must point at the tenancy decision doc: {error}"
    );

    // Overwriting an existing name consumes no slot: allowed even at the cap
    // (with the soft warning, since usage stays >= the threshold).
    let warning = policy
        .check_secret_budget("provider-keys", "existing", 100, true)
        .unwrap()
        .expect("a full store must keep warning");
    assert_eq!(warning.used_after_write, 100);
}

#[test]
fn lowered_hard_budget_is_enforced() {
    let policy = CfSecretsCapacityPolicy {
        max_secrets: 10,
        warn_at_secrets: 8,
        ..CfSecretsCapacityPolicy::default()
    };
    let error = policy
        .check_secret_budget("provider-keys", "new", 10, false)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("configured budget of 10"),
        "a non-beta budget must not be called a beta budget: {error}"
    );
}

// --- environment overrides ---------------------------------------------------

// One test (not several) touches the fixed FERROGATE_CF_SECRETS_* variables,
// so the parallel test harness can never race two writers on them. No other
// test in the crate calls from_env (resolver tests build via from_client).
#[test]
fn from_env_applies_valid_overrides_clamps_warn_and_ignores_invalid() {
    // Valid overrides, with a soft threshold above the hard budget.
    std::env::set_var("FERROGATE_CF_SECRETS_MAX_SECRETS", "40");
    std::env::set_var("FERROGATE_CF_SECRETS_WARN_AT", "95");
    std::env::set_var("FERROGATE_CF_SECRETS_MAX_VALUE_BYTES", "2048");
    let policy = CfSecretsCapacityPolicy::from_env();
    assert_eq!(policy.max_secrets, 40);
    // 95 > the hard budget of 40 → clamped so the warning stays reachable.
    assert_eq!(policy.warn_at_secrets, 40);
    assert_eq!(policy.max_value_bytes, 2048);

    // Invalid overrides (non-numeric / zero) fall back to the defaults.
    std::env::set_var("FERROGATE_CF_SECRETS_MAX_SECRETS", "not-a-number");
    std::env::set_var("FERROGATE_CF_SECRETS_WARN_AT", "0");
    std::env::remove_var("FERROGATE_CF_SECRETS_MAX_VALUE_BYTES");
    let policy = CfSecretsCapacityPolicy::from_env();
    assert_eq!(policy, CfSecretsCapacityPolicy::default());

    std::env::remove_var("FERROGATE_CF_SECRETS_MAX_SECRETS");
    std::env::remove_var("FERROGATE_CF_SECRETS_WARN_AT");
}
