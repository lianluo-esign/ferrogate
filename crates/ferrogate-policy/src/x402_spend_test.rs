// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Unit + property tests for the typed Solana x402 spend policy and
// the immutable payment-authorization decision (issue #351). Sibling test file
// per AGENTS.md testing architecture (no inline `mod tests {}`).

use super::*;
use ferrogate_payments::{SelectedPayment, SolanaNetwork};
use proptest::prelude::*;

// Canonical, wire-validated base58 addresses used across the tests.
const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const USDC_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const RECIPIENT_A: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const RECIPIENT_B: &str = "GDDMwNyyx8uB6zrqwBFHjLLG3TBYk2F8Az4yrQC5RzMp";
const FEE_PAYER: &str = "So11111111111111111111111111111111111111112";

const RESOURCE_URL: &str = "https://api.example.com/paid/report";

fn selected(
    network: SolanaNetwork,
    mint: &str,
    atomic_amount: u64,
    recipient: &str,
    resource_url: &str,
) -> SelectedPayment {
    SelectedPayment {
        network,
        mint: mint.to_string(),
        atomic_amount,
        recipient: recipient.to_string(),
        fee_payer: FEE_PAYER.to_string(),
        memo: None,
        resource_url: resource_url.to_string(),
        max_timeout_seconds: 300,
        challenge_hash: [0xab; 32],
        raw_requirement: serde_json::Value::Null,
    }
}

/// A devnet USDC payment for `atomic` units to `RECIPIENT_A`, unlocking
/// `RESOURCE_URL`.
fn devnet_payment(atomic: u64) -> SelectedPayment {
    selected(
        SolanaNetwork::Devnet,
        USDC_DEVNET,
        atomic,
        RECIPIENT_A,
        RESOURCE_URL,
    )
}

/// The canonical enabled devnet policy: 1 credit per 1000 atomic units
/// (round-up), per-payment cap 1000 credits, run cap 5000, window cap 10000,
/// approval above 500 credits, atomic band [10, 2_000_000].
fn base_policy() -> X402SpendPolicy {
    X402SpendPolicy {
        enabled: true,
        revision: 7,
        allowed_networks: vec![PolicyNetwork::DEVNET],
        allowed_assets: vec![AllowedAsset {
            network: PolicyNetwork::DEVNET,
            mint: USDC_DEVNET.to_string(),
        }],
        allowed_recipients: vec![RECIPIENT_A.to_string()],
        allowed_resources: vec![ResourceRule {
            origin: "https://api.example.com".to_string(),
            path_prefix: "/paid".to_string(),
        }],
        caps: X402SpendCaps {
            max_credits_per_payment: Some(1_000),
            max_credits_per_run: Some(5_000),
            max_credits_per_window: Some(10_000),
            window_seconds: Some(3_600),
            max_atomic_per_payment: Some(2_000_000),
            min_atomic_per_payment: Some(10),
        },
        conversion: ConversionRule {
            numerator: 1,
            denominator: 1_000,
            rounding: Rounding::Up,
            version: "usdc-devnet-v1".to_string(),
        },
        approval: ApprovalPolicy {
            threshold_credits: Some(500),
        },
        allow_insecure_local_resources: false,
    }
}

fn validated(policy: X402SpendPolicy) -> ValidatedX402SpendPolicy {
    policy.validate().expect("policy should validate")
}

fn request<'a>(
    selected: &'a SelectedPayment,
    authorized: &'a str,
) -> PaymentAuthorizationRequest<'a> {
    PaymentAuthorizationRequest {
        selected,
        authorized_resource_url: authorized,
        scope: SpendScope {
            tenant_id: "tenant-1",
            project_id: Some("proj-1"),
            workspace_id: None,
            key_id: Some("key-1"),
            run_id: Some("run-1"),
        },
    }
}

fn decide(
    policy: &ValidatedX402SpendPolicy,
    payment: &SelectedPayment,
    authorized: &str,
    spent: SpendSnapshot,
) -> PaymentAuthorization {
    authorize_x402_payment(policy, &request(payment, authorized), &spent)
}

fn no_spend() -> SpendSnapshot {
    SpendSnapshot::default()
}

// ---------------------------------------------------------------------------
// Decision: allow / deny / approval
// ---------------------------------------------------------------------------

#[test]
fn allows_a_payment_within_every_cap() {
    let policy = validated(base_policy());
    // 100_000 atomic -> ceil(100_000/1000) = 100 credits, below the 500
    // approval threshold and every cap.
    let payment = devnet_payment(100_000);
    let auth = decide(&policy, &payment, RESOURCE_URL, no_spend());
    assert_eq!(auth.decision, PaymentDecision::Allow);
    assert_eq!(auth.reason_code, REASON_ALLOWED);
    // Evidence is fully populated.
    assert_eq!(auth.policy_revision, 7);
    assert_eq!(auth.computed_credits(), Some(Credits(100)));
    assert_eq!(auth.conversion.atomic_amount, AtomicAmount(100_000));
    assert_eq!(auth.network_caip2, SolanaNetwork::Devnet.caip2());
    assert_eq!(auth.mint, USDC_DEVNET);
    assert_eq!(auth.recipient, RECIPIENT_A);
    assert_eq!(auth.challenge_hash_hex, "ab".repeat(32));
    assert!(auth.matched_resource.is_some());
}

#[test]
fn disabled_policy_denies_every_payment() {
    let policy = validated(X402SpendPolicy::disabled());
    let payment = devnet_payment(100_000);
    let auth = decide(&policy, &payment, RESOURCE_URL, no_spend());
    assert_eq!(auth.decision, PaymentDecision::Deny);
    assert_eq!(auth.reason_code, REASON_DISABLED);
}

#[test]
fn denies_a_network_that_is_not_allowlisted() {
    let policy = validated(base_policy());
    // Mainnet payment against a devnet-only policy.
    let payment = selected(
        SolanaNetwork::Mainnet,
        USDC_MAINNET,
        100_000,
        RECIPIENT_A,
        RESOURCE_URL,
    );
    let auth = decide(&policy, &payment, RESOURCE_URL, no_spend());
    assert_eq!(auth.decision, PaymentDecision::Deny);
    assert_eq!(auth.reason_code, REASON_NETWORK_NOT_ALLOWED);
}

#[test]
fn denies_a_mint_that_is_not_allowlisted() {
    let policy = validated(base_policy());
    // A different (valid) mint on the allowed network.
    let payment = selected(
        SolanaNetwork::Devnet,
        FEE_PAYER, // valid base58 32-byte, but not the allowlisted mint
        100_000,
        RECIPIENT_A,
        RESOURCE_URL,
    );
    let auth = decide(&policy, &payment, RESOURCE_URL, no_spend());
    assert_eq!(auth.decision, PaymentDecision::Deny);
    assert_eq!(auth.reason_code, REASON_MINT_NOT_ALLOWED);
}

#[test]
fn denies_a_recipient_that_is_not_allowlisted() {
    let policy = validated(base_policy());
    let payment = devnet_payment(100_000);
    let payment = SelectedPayment {
        recipient: RECIPIENT_B.to_string(),
        ..payment
    };
    let auth = decide(&policy, &payment, RESOURCE_URL, no_spend());
    assert_eq!(auth.decision, PaymentDecision::Deny);
    assert_eq!(auth.reason_code, REASON_RECIPIENT_NOT_ALLOWED);
}

#[test]
fn denies_a_challenge_that_redirects_to_a_different_resource() {
    let policy = validated(base_policy());
    // The challenge claims RESOURCE_URL, but the gateway authorized a DIFFERENT
    // origin -- a payment redirect attempt.
    let payment = devnet_payment(100_000);
    let auth = decide(
        &policy,
        &payment,
        "https://evil.example.net/paid/report",
        no_spend(),
    );
    assert_eq!(auth.decision, PaymentDecision::Deny);
    assert_eq!(auth.reason_code, REASON_RESOURCE_MISMATCH);
}

#[test]
fn denies_a_resource_not_covered_by_any_rule() {
    let policy = validated(base_policy());
    // Challenge and authorized URL agree, but the path is outside /paid.
    let url = "https://api.example.com/free/report";
    let payment = selected(
        SolanaNetwork::Devnet,
        USDC_DEVNET,
        100_000,
        RECIPIENT_A,
        url,
    );
    let auth = decide(&policy, &payment, url, no_spend());
    assert_eq!(auth.decision, PaymentDecision::Deny);
    assert_eq!(auth.reason_code, REASON_RESOURCE_NOT_ALLOWED);
}

#[test]
fn binding_ignores_query_and_trailing_slash_but_not_path() {
    let policy = validated(base_policy());
    // Same origin+path, differing only by trailing slash + query string, must
    // still bind.
    let payment = selected(
        SolanaNetwork::Devnet,
        USDC_DEVNET,
        100_000,
        RECIPIENT_A,
        "https://api.example.com/paid/report/?ref=1",
    );
    let auth = decide(
        &policy,
        &payment,
        "https://api.example.com/paid/report#frag",
        no_spend(),
    );
    assert_eq!(auth.decision, PaymentDecision::Allow);
}

#[test]
fn denies_an_atomic_amount_below_the_minimum() {
    let policy = validated(base_policy());
    let payment = devnet_payment(5); // below min 10
    let auth = decide(&policy, &payment, RESOURCE_URL, no_spend());
    assert_eq!(auth.decision, PaymentDecision::Deny);
    assert_eq!(auth.reason_code, REASON_AMOUNT_BELOW_MIN);
}

#[test]
fn denies_an_atomic_amount_over_the_hard_atomic_cap() {
    let policy = validated(base_policy());
    let payment = devnet_payment(2_000_001); // above atomic cap 2_000_000
    let auth = decide(&policy, &payment, RESOURCE_URL, no_spend());
    assert_eq!(auth.decision, PaymentDecision::Deny);
    assert_eq!(auth.reason_code, REASON_ATOMIC_CAP_EXCEEDED);
}

#[test]
fn per_payment_credit_cap_is_a_boundary_at_the_cap_value() {
    // Isolate the per-payment cap: no approval threshold, generous atomic band.
    let mut policy = base_policy();
    policy.approval = ApprovalPolicy::default();
    policy.caps.min_atomic_per_payment = None;
    policy.caps.max_atomic_per_payment = None;
    let policy = validated(policy);

    // ceil(1_000_000 / 1000) = 1000 credits == cap -> allowed.
    let at_cap = decide(
        &policy,
        &devnet_payment(1_000_000),
        RESOURCE_URL,
        no_spend(),
    );
    assert_eq!(at_cap.decision, PaymentDecision::Allow);
    assert_eq!(at_cap.computed_credits(), Some(Credits(1_000)));

    // ceil(1_000_001 / 1000) = 1001 credits > cap -> denied.
    let over_cap = decide(
        &policy,
        &devnet_payment(1_000_001),
        RESOURCE_URL,
        no_spend(),
    );
    assert_eq!(over_cap.decision, PaymentDecision::Deny);
    assert_eq!(over_cap.reason_code, REASON_OVER_PER_PAYMENT_CAP);
}

#[test]
fn per_run_cap_counts_already_spent_credits() {
    let policy = validated(base_policy());
    // Payment is 100 credits (atomic 100_000). Run cap is 5000.
    // Already spent 4900 -> 4900 + 100 = 5000 == cap -> allowed.
    let at_cap = decide(
        &policy,
        &devnet_payment(100_000),
        RESOURCE_URL,
        SpendSnapshot {
            run_spent_credits: 4_900,
            window_spent_credits: 0,
        },
    );
    assert_eq!(at_cap.decision, PaymentDecision::Allow);

    // Already spent 4901 -> 5001 > 5000 -> denied on the run dimension.
    let over = decide(
        &policy,
        &devnet_payment(100_000),
        RESOURCE_URL,
        SpendSnapshot {
            run_spent_credits: 4_901,
            window_spent_credits: 0,
        },
    );
    assert_eq!(over.decision, PaymentDecision::Deny);
    assert_eq!(over.reason_code, REASON_OVER_RUN_CAP);
}

#[test]
fn per_window_cap_counts_already_spent_credits() {
    let policy = validated(base_policy());
    let over = decide(
        &policy,
        &devnet_payment(100_000), // 100 credits
        RESOURCE_URL,
        SpendSnapshot {
            run_spent_credits: 0,
            window_spent_credits: 9_950, // + 100 = 10_050 > 10_000
        },
    );
    assert_eq!(over.decision, PaymentDecision::Deny);
    assert_eq!(over.reason_code, REASON_OVER_WINDOW_CAP);
}

#[test]
fn a_checked_add_overflow_on_a_cap_denies() {
    let policy = validated(base_policy());
    // run_spent near u64::MAX so run_spent + credits overflows -> deny, never
    // wraps to a small total that would spuriously pass the cap.
    let auth = decide(
        &policy,
        &devnet_payment(100_000),
        RESOURCE_URL,
        SpendSnapshot {
            run_spent_credits: u64::MAX,
            window_spent_credits: 0,
        },
    );
    assert_eq!(auth.decision, PaymentDecision::Deny);
    assert_eq!(auth.reason_code, REASON_CONVERSION_UNAVAILABLE);
}

#[test]
fn a_conversion_overflow_denies_rather_than_coercing_to_zero() {
    let mut policy = base_policy();
    policy.caps.min_atomic_per_payment = None;
    policy.caps.max_atomic_per_payment = None;
    policy.caps.max_credits_per_payment = None;
    policy.caps.max_credits_per_run = None;
    policy.caps.max_credits_per_window = None;
    policy.conversion = ConversionRule {
        numerator: 1_000,
        denominator: 1,
        rounding: Rounding::Up,
        version: "overflow-v1".to_string(),
    };
    let policy = validated(policy);
    // u64::MAX * 1000 overflows u64 credits.
    let auth = decide(&policy, &devnet_payment(u64::MAX), RESOURCE_URL, no_spend());
    assert_eq!(auth.decision, PaymentDecision::Deny);
    assert_eq!(auth.reason_code, REASON_CONVERSION_UNAVAILABLE);
    assert_eq!(auth.computed_credits(), None);
}

#[test]
fn a_payment_above_the_approval_threshold_but_within_caps_needs_approval() {
    let policy = validated(base_policy());
    // 600_000 atomic -> 600 credits: above threshold 500, below per-payment cap
    // 1000 -> ApprovalRequired.
    let auth = decide(&policy, &devnet_payment(600_000), RESOURCE_URL, no_spend());
    assert_eq!(
        auth.decision,
        PaymentDecision::ApprovalRequired {
            threshold_credits: 500,
        }
    );
    assert_eq!(auth.reason_code, REASON_APPROVAL_REQUIRED);
    assert_eq!(auth.computed_credits(), Some(Credits(600)));
}

#[test]
fn rounding_up_and_down_produce_the_expected_credits() {
    let mut up = base_policy();
    up.conversion.rounding = Rounding::Up;
    let up = validated(up);
    // ceil(100_001 / 1000) = 101.
    let a = decide(&up, &devnet_payment(100_001), RESOURCE_URL, no_spend());
    assert_eq!(a.computed_credits(), Some(Credits(101)));

    let mut down = base_policy();
    down.conversion.rounding = Rounding::Down;
    let down = validated(down);
    // floor(100_999 / 1000) = 100.
    let b = decide(&down, &devnet_payment(100_999), RESOURCE_URL, no_spend());
    assert_eq!(b.computed_credits(), Some(Credits(100)));
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[test]
fn wildcard_mainnet_without_an_explicit_mint_is_rejected() {
    let mut policy = base_policy();
    policy.allowed_networks = vec![PolicyNetwork::MAINNET];
    // No mainnet asset pins the mint.
    policy.allowed_assets = vec![AllowedAsset {
        network: PolicyNetwork::DEVNET,
        mint: USDC_DEVNET.to_string(),
    }];
    // Give it a devnet network too so the asset-network check passes first is
    // avoided; keep only mainnet allowed so the asset network check fires...
    // Instead: allow both networks so the devnet asset is legal, then mainnet
    // has no mint -> WildcardMainnet.
    policy.allowed_networks = vec![PolicyNetwork::MAINNET, PolicyNetwork::DEVNET];
    let err = policy.validate().unwrap_err();
    assert_eq!(err, X402PolicyConfigError::WildcardMainnet);
}

#[test]
fn a_token_symbol_used_as_a_mint_is_rejected() {
    let mut policy = base_policy();
    policy.allowed_assets = vec![AllowedAsset {
        network: PolicyNetwork::DEVNET,
        mint: "USDC".to_string(),
    }];
    let err = policy.validate().unwrap_err();
    assert_eq!(
        err,
        X402PolicyConfigError::TokenSymbolMint {
            value: "USDC".to_string()
        }
    );
}

#[test]
fn an_http_resource_is_rejected_unless_local_test_mode_is_enabled() {
    let mut policy = base_policy();
    policy.allowed_resources = vec![ResourceRule {
        origin: "http://api.example.com".to_string(),
        path_prefix: "/paid".to_string(),
    }];
    let err = policy.clone().validate().unwrap_err();
    assert_eq!(
        err,
        X402PolicyConfigError::InsecureResource {
            origin: "http://api.example.com".to_string()
        }
    );

    // With the explicit local-test escape hatch, the same http origin validates.
    policy.allow_insecure_local_resources = true;
    assert!(policy.validate().is_ok());
}

#[test]
fn a_zero_cap_is_rejected() {
    let mut policy = base_policy();
    policy.caps.max_credits_per_payment = Some(0);
    let err = policy.validate().unwrap_err();
    assert_eq!(
        err,
        X402PolicyConfigError::ZeroCap {
            field: "caps.max_credits_per_payment"
        }
    );
}

#[test]
fn a_duplicate_recipient_rule_is_rejected() {
    let mut policy = base_policy();
    policy.allowed_recipients = vec![RECIPIENT_A.to_string(), RECIPIENT_A.to_string()];
    let err = policy.validate().unwrap_err();
    assert_eq!(
        err,
        X402PolicyConfigError::DuplicateRule {
            kind: "recipient",
            value: RECIPIENT_A.to_string(),
        }
    );
}

#[test]
fn a_duplicate_asset_rule_is_rejected() {
    let mut policy = base_policy();
    policy.allowed_assets = vec![
        AllowedAsset {
            network: PolicyNetwork::DEVNET,
            mint: USDC_DEVNET.to_string(),
        },
        AllowedAsset {
            network: PolicyNetwork::DEVNET,
            mint: USDC_DEVNET.to_string(),
        },
    ];
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        X402PolicyConfigError::DuplicateRule { kind: "asset", .. }
    ));
}

#[test]
fn an_impossible_conversion_ratio_is_rejected_even_when_disabled() {
    let mut policy = X402SpendPolicy::disabled();
    policy.conversion.denominator = 0;
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        X402PolicyConfigError::ImpossibleConversion { .. }
    ));
}

#[test]
fn an_enabled_policy_with_an_empty_allowlist_is_rejected() {
    let mut policy = base_policy();
    policy.allowed_recipients = vec![];
    let err = policy.validate().unwrap_err();
    assert_eq!(
        err,
        X402PolicyConfigError::EmptyAllowlist {
            field: "recipients"
        }
    );
}

#[test]
fn an_asset_on_a_non_allowed_network_is_rejected() {
    let mut policy = base_policy();
    // Devnet network allowed, but the asset names mainnet.
    policy.allowed_assets = vec![AllowedAsset {
        network: PolicyNetwork::MAINNET,
        mint: USDC_MAINNET.to_string(),
    }];
    let err = policy.validate().unwrap_err();
    assert!(matches!(
        err,
        X402PolicyConfigError::AssetNetworkNotAllowed { .. }
    ));
}

#[test]
fn an_inverted_atomic_band_is_rejected() {
    let mut policy = base_policy();
    policy.caps.min_atomic_per_payment = Some(100);
    policy.caps.max_atomic_per_payment = Some(10);
    let err = policy.validate().unwrap_err();
    assert_eq!(
        err,
        X402PolicyConfigError::InvertedAtomicBand { min: 100, max: 10 }
    );
}

#[test]
fn a_disabled_policy_with_empty_allowlists_still_validates() {
    // The disabled default has empty allowlists; it must validate (only the
    // conversion ratio is checked when disabled) so it can be stored/read back.
    assert!(X402SpendPolicy::disabled().validate().is_ok());
}

// ---------------------------------------------------------------------------
// Serialization: no f64, lossless atomic amounts
// ---------------------------------------------------------------------------

#[test]
fn atomic_amounts_round_trip_losslessly_through_json() {
    for value in [0u64, 1, 1_000_000, u64::MAX] {
        let json = serde_json::to_string(&AtomicAmount(value)).unwrap();
        // Serialized as a bare integer (no float, no string).
        assert_eq!(json, value.to_string());
        let back: AtomicAmount = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AtomicAmount(value));
    }
}

#[test]
fn the_decision_serializes_with_its_full_evidence() {
    let policy = validated(base_policy());
    let auth = decide(&policy, &devnet_payment(100_000), RESOURCE_URL, no_spend());
    let json = serde_json::to_value(&auth).unwrap();
    assert_eq!(json["reason_code"], REASON_ALLOWED);
    assert_eq!(json["policy_revision"], 7);
    assert_eq!(json["conversion"]["atomic_amount"], 100_000);
    assert_eq!(json["conversion"]["computed_credits"], 100);
    // Evidence fields are present and typed as bare integers (no float).
    assert!(json["conversion"]["computed_credits"].is_u64());
    assert_eq!(json["network_caip2"], SolanaNetwork::Devnet.caip2());
    assert_eq!(json["matched_resource"]["path_prefix"], "/paid");
}

#[test]
fn the_policy_config_round_trips_through_json_with_caip2_networks() {
    let policy = base_policy();
    let json = serde_json::to_value(&policy).unwrap();
    // Networks serialize as canonical CAIP-2 strings, not variant names.
    assert_eq!(json["allowed_networks"][0], SolanaNetwork::Devnet.caip2());
    let back: X402SpendPolicy = serde_json::from_value(json).unwrap();
    assert_eq!(back, policy);
}

// ---------------------------------------------------------------------------
// URL canonicalisation (security-load-bearing helpers)
// ---------------------------------------------------------------------------

#[test]
fn path_prefix_matching_respects_segment_boundaries() {
    let url = canonical_url("https://api.example.com/payment").unwrap();
    // "/pay" must NOT cover "/payment".
    assert!(!resource_rule_matches(
        &ResourceRule {
            origin: "https://api.example.com".to_string(),
            path_prefix: "/pay".to_string(),
        },
        &url,
    ));
    // "/payment" covers itself and descendants.
    assert!(resource_rule_matches(
        &ResourceRule {
            origin: "https://api.example.com".to_string(),
            path_prefix: "/payment".to_string(),
        },
        &url,
    ));
}

#[test]
fn default_https_port_is_canonicalised_away() {
    let a = canonical_url("https://api.example.com:443/paid").unwrap();
    let b = canonical_url("https://API.example.com/paid").unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Property tests: invariants over generated inputs
// ---------------------------------------------------------------------------

/// A policy with NO minimum atomic bound so that amount-based denials come only
/// from the (monotone) upper caps -- the domain the monotonicity invariant is
/// stated over.
fn monotone_policy() -> ValidatedX402SpendPolicy {
    let mut policy = base_policy();
    policy.caps.min_atomic_per_payment = None;
    validated(policy)
}

proptest! {
    /// Raising the quoted amount can never turn a Deny into an Allow.
    #[test]
    fn raising_the_quoted_amount_never_turns_deny_into_allow(a in 0u64..5_000_000, b in 0u64..5_000_000) {
        let policy = monotone_policy();
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let low = decide(&policy, &devnet_payment(lo), RESOURCE_URL, no_spend());
        let high = decide(&policy, &devnet_payment(hi), RESOURCE_URL, no_spend());
        if low.decision == PaymentDecision::Deny {
            prop_assert_ne!(high.decision, PaymentDecision::Allow);
        }
    }

    /// A payment whose computed credits exceed the per-payment cap is never
    /// allowed (with no min bound so identity/resource always match here).
    #[test]
    fn a_spend_over_the_per_payment_cap_is_never_allowed(atomic in 1u64..u64::MAX) {
        let mut policy = base_policy();
        policy.approval = ApprovalPolicy::default();
        policy.caps.min_atomic_per_payment = None;
        policy.caps.max_atomic_per_payment = None;
        policy.caps.max_credits_per_run = None;
        policy.caps.max_credits_per_window = None;
        let cap = policy.caps.max_credits_per_payment.unwrap();
        let policy = validated(policy);
        let auth = decide(&policy, &devnet_payment(atomic), RESOURCE_URL, no_spend());
        if let Some(Credits(credits)) = auth.computed_credits() {
            if credits > cap {
                prop_assert_ne!(auth.decision, PaymentDecision::Allow);
            }
        } else {
            // Conversion overflow must also never be an Allow.
            prop_assert_ne!(auth.decision, PaymentDecision::Allow);
        }
    }

    /// Conversion is monotone non-decreasing in the atomic amount.
    #[test]
    fn conversion_is_monotone_in_the_atomic_amount(a in 0u64..10_000_000, b in 0u64..10_000_000) {
        let rule = ConversionRule {
            numerator: 3,
            denominator: 7,
            rounding: Rounding::Up,
            version: "p".to_string(),
        };
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let cl = rule.convert(AtomicAmount(lo)).unwrap();
        let ch = rule.convert(AtomicAmount(hi)).unwrap();
        prop_assert!(cl <= ch);
    }

    /// Round-up credits are always >= round-down credits for the same input.
    #[test]
    fn round_up_is_never_less_than_round_down(atomic in 0u64..10_000_000, num in 1u64..1000, den in 1u64..1000) {
        let up = ConversionRule { numerator: num, denominator: den, rounding: Rounding::Up, version: "u".into() };
        let down = ConversionRule { numerator: num, denominator: den, rounding: Rounding::Down, version: "d".into() };
        let cu = up.convert(AtomicAmount(atomic)).unwrap();
        let cd = down.convert(AtomicAmount(atomic)).unwrap();
        prop_assert!(cu >= cd);
        // They differ by at most one credit.
        prop_assert!(cu.0 - cd.0 <= 1);
    }

    /// Atomic amounts survive a JSON round-trip losslessly for every u64.
    #[test]
    fn atomic_amount_json_round_trip_is_lossless(value in any::<u64>()) {
        let json = serde_json::to_string(&AtomicAmount(value)).unwrap();
        let back: AtomicAmount = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back, AtomicAmount(value));
    }
}
