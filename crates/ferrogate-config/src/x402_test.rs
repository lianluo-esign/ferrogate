// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Tests for the typed x402 spend-policy config surface (issue #351):
// valid config -> ValidatedX402SpendPolicy, structured rejection of invalid
// documents, disabled-by-default when absent, and serde/round-trip stability.

use super::*;

const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const RECIPIENT_A: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const CAIP2_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/// A realistic, fully-specified enabled devnet policy document. Individual
/// negative tests start from this and corrupt exactly one field.
fn valid_toml() -> String {
    format!(
        r#"
enabled = true
revision = 7
allowed_networks = ["{CAIP2_DEVNET}"]
allowed_recipients = ["{RECIPIENT_A}"]
allow_insecure_local_resources = false

[[allowed_assets]]
network = "{CAIP2_DEVNET}"
mint = "{USDC_DEVNET}"

[[allowed_resources]]
origin = "https://api.example.com"
path_prefix = "/paid"

[caps]
max_credits_per_payment = 1000
max_credits_per_run = 5000
max_credits_per_window = 10000
window_seconds = 3600
max_atomic_per_payment = 2000000
min_atomic_per_payment = 10

[conversion]
numerator = 1
denominator = 1000
rounding = "up"
version = "usdc-devnet-v1"

[approval]
threshold_credits = 500
"#
    )
}

#[test]
fn valid_config_parses_and_validates_into_a_typed_policy() {
    let validated =
        load_x402_spend_policy_toml(&valid_toml()).expect("a well-formed policy should validate");

    let policy = validated.policy();
    assert!(policy.enabled);
    assert_eq!(policy.revision, 7);
    assert_eq!(policy.allowed_networks, vec![PolicyNetwork::DEVNET]);
    assert_eq!(
        policy.allowed_assets,
        vec![AllowedAsset {
            network: PolicyNetwork::DEVNET,
            mint: USDC_DEVNET.to_string(),
        }]
    );
    assert_eq!(policy.allowed_recipients, vec![RECIPIENT_A.to_string()]);
    assert_eq!(
        policy.allowed_resources,
        vec![ResourceRule {
            origin: "https://api.example.com".to_string(),
            path_prefix: "/paid".to_string(),
        }]
    );
    assert_eq!(policy.caps.max_credits_per_payment, Some(1_000));
    assert_eq!(policy.caps.min_atomic_per_payment, Some(10));
    assert_eq!(policy.conversion.denominator, 1_000);
    assert_eq!(policy.conversion.rounding, Rounding::Up);
    assert_eq!(policy.approval.threshold_credits, Some(500));
}

#[test]
fn the_section_wrapper_validates_the_same_way_as_the_loader() {
    // The wrapper's `validate()` must delegate to the policy crate, so a document
    // routed through the typed section produces the identical validated policy.
    let section: X402SpendPolicyConfig =
        toml::from_str(&valid_toml()).expect("valid_toml should deserialize");
    let via_wrapper = section.validate().expect("wrapper should validate");
    let via_loader = load_x402_spend_policy_toml(&valid_toml()).expect("loader should validate");
    assert_eq!(via_wrapper, via_loader);
}

#[test]
fn an_unknown_network_string_is_a_parse_error() {
    let raw = valid_toml().replace(CAIP2_DEVNET, "solana:not-a-real-network");
    let error = load_x402_spend_policy_toml(&raw).expect_err("unknown network must be rejected");
    assert!(
        matches!(error, X402ConfigError::Parse(_)),
        "unknown CAIP-2 network should fail at deserialization, got {error:?}"
    );
}

#[test]
fn an_impossible_conversion_ratio_is_a_structured_validation_error() {
    let raw = valid_toml().replace("denominator = 1000", "denominator = 0");
    let error = load_x402_spend_policy_toml(&raw).expect_err("zero denominator must be rejected");
    assert!(
        matches!(
            error,
            X402ConfigError::Invalid(X402PolicyConfigError::ImpossibleConversion { .. })
        ),
        "got {error:?}"
    );
}

#[test]
fn an_inverted_atomic_band_is_rejected_as_over_under_bounds() {
    // min above max: the payment amount can never fall inside the band.
    let raw = valid_toml()
        .replace(
            "max_atomic_per_payment = 2000000",
            "max_atomic_per_payment = 5",
        )
        .replace(
            "min_atomic_per_payment = 10",
            "min_atomic_per_payment = 100",
        );
    let error = load_x402_spend_policy_toml(&raw).expect_err("inverted band must be rejected");
    assert!(
        matches!(
            error,
            X402ConfigError::Invalid(X402PolicyConfigError::InvertedAtomicBand {
                min: 100,
                max: 5
            })
        ),
        "got {error:?}"
    );
}

#[test]
fn a_zero_cap_is_rejected() {
    let raw = valid_toml().replace(
        "max_credits_per_payment = 1000",
        "max_credits_per_payment = 0",
    );
    let error = load_x402_spend_policy_toml(&raw).expect_err("a zero cap must be rejected");
    assert!(
        matches!(
            error,
            X402ConfigError::Invalid(X402PolicyConfigError::ZeroCap {
                field: "caps.max_credits_per_payment"
            })
        ),
        "got {error:?}"
    );
}

#[test]
fn an_enabled_policy_with_an_empty_allowlist_is_rejected() {
    let raw = valid_toml().replace(
        &format!("allowed_recipients = [\"{RECIPIENT_A}\"]"),
        "allowed_recipients = []",
    );
    let error = load_x402_spend_policy_toml(&raw).expect_err("empty allowlist must be rejected");
    assert!(
        matches!(
            error,
            X402ConfigError::Invalid(X402PolicyConfigError::EmptyAllowlist {
                field: "recipients"
            })
        ),
        "got {error:?}"
    );
}

#[test]
fn a_token_symbol_mint_is_rejected() {
    let raw = valid_toml().replace(USDC_DEVNET, "USDC");
    let error =
        load_x402_spend_policy_toml(&raw).expect_err("a token symbol mint must be rejected");
    assert!(
        matches!(
            error,
            X402ConfigError::Invalid(X402PolicyConfigError::TokenSymbolMint { .. })
        ),
        "got {error:?}"
    );
}

#[test]
fn the_default_section_is_disabled_and_validates() {
    // "No x402 config present" degrades to a fully-off, deny-everything policy.
    let section = X402SpendPolicyConfig::default();
    assert!(!section.policy().enabled);
    assert!(section.policy().allowed_assets.is_empty());

    let validated = section
        .validate()
        .expect("the disabled default must validate");
    assert!(!validated.policy().enabled);

    // The convenience accessor returns the same disabled, validated policy.
    assert_eq!(default_x402_spend_policy(), validated);
}

#[test]
fn a_disabled_policy_is_validated_leniently() {
    // A disabled policy keeps its empty allowlists (they can never authorize a
    // payment) and still validates, so an operator can stage config while off.
    let raw = valid_toml().replace("enabled = true", "enabled = false");
    let validated =
        load_x402_spend_policy_toml(&raw).expect("a disabled policy should always validate");
    assert!(!validated.policy().enabled);
}

#[test]
fn networks_round_trip_as_canonical_caip2_strings() {
    let validated = load_x402_spend_policy_toml(&valid_toml()).expect("valid");
    let json = serde_json::to_value(validated.policy()).expect("serialize policy to json");
    assert_eq!(json["allowed_networks"][0], CAIP2_DEVNET);
    assert_eq!(json["allowed_assets"][0]["network"], CAIP2_DEVNET);
}

#[test]
fn policy_is_serde_round_trip_stable() {
    let validated = load_x402_spend_policy_toml(&valid_toml()).expect("valid");
    let original = validated.policy().clone();

    // JSON round-trip: serialize -> deserialize yields an identical policy.
    let json = serde_json::to_string(&original).expect("json serialize");
    let from_json: X402SpendPolicy = serde_json::from_str(&json).expect("json deserialize");
    assert_eq!(from_json, original);

    // TOML round-trip through the config section: re-serializing the parsed
    // section and reloading it produces the same validated policy.
    let section = X402SpendPolicyConfig(original.clone());
    let toml_text = toml::to_string(&section).expect("toml serialize");
    let reloaded = load_x402_spend_policy_toml(&toml_text).expect("reload from re-serialized toml");
    assert_eq!(reloaded, validated);
}

#[test]
fn malformed_toml_is_a_parse_error() {
    let error =
        load_x402_spend_policy_toml("enabled = true\nrevision = ").expect_err("malformed toml");
    assert!(matches!(error, X402ConfigError::Parse(_)), "got {error:?}");
}
