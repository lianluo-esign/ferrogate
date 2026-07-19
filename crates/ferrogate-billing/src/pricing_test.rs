// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit coverage for the billing rate card: wildcard precedence and JSON parsing.

use super::*;

fn book() -> PriceBook {
    PriceBook::new(vec![
        PriceEntry::new("openai", "gpt-5.5", ModelPrice::usd(5.0, 15.0)),
        PriceEntry::new("openai", "*", ModelPrice::usd(1.0, 2.0)),
        PriceEntry::new("*", "*", ModelPrice::usd(10.0, 10.0)),
    ])
}

#[test]
fn exact_match_wins_over_wildcards() {
    let price = book().price_for("openai", "gpt-5.5").cloned().unwrap();
    assert_eq!(price, ModelPrice::usd(5.0, 15.0));
}

#[test]
fn provider_wildcard_matches_unknown_model() {
    let price = book().price_for("openai", "gpt-4o").cloned().unwrap();
    assert_eq!(price, ModelPrice::usd(1.0, 2.0));
}

#[test]
fn global_wildcard_is_last_resort() {
    let price = book().price_for("mystery", "model-x").cloned().unwrap();
    assert_eq!(price, ModelPrice::usd(10.0, 10.0));
}

#[test]
fn missing_price_is_none_when_no_wildcard() {
    let book = PriceBook::new(vec![PriceEntry::new(
        "openai",
        "gpt-5.5",
        ModelPrice::usd(5.0, 15.0),
    )]);
    assert!(book.price_for("anthropic", "claude").is_none());
}

#[test]
fn credits_scale_with_configured_rate() {
    let book = PriceBook::default().with_credits_per_usd(1_000.0);
    assert!((book.credits_for_usd(0.5) - 500.0).abs() < f64::EPSILON);
}

#[test]
fn egress_cost_is_none_when_unpriced_and_priced_per_gb_otherwise() {
    // #262: an unpriced book fails closed (no fabricated zero cost), exactly
    // like an unmatched model price.
    assert!(PriceBook::default()
        .egress_cost_usd(1_000_000_000)
        .is_none());

    // 1 GB (10^9 bytes) at $0.09/GB settles to exactly $0.09.
    let book = PriceBook::default().with_egress_price_per_gb(0.09);
    let cost = book.egress_cost_usd(1_000_000_000).unwrap();
    assert!((cost - 0.09).abs() < 1e-9, "1GB @ $0.09/GB should be $0.09");

    // Half a GB is half the charge; the free helper agrees with the method.
    let half = book.egress_cost_usd(500_000_000).unwrap();
    assert!((half - 0.045).abs() < 1e-9);
    assert!((half - egress_cost_usd(0.09, 500_000_000)).abs() < f64::EPSILON);
}

#[test]
fn default_rate_card_seeds_an_egress_rate() {
    // #262: the default rate card is no longer token-only.
    let book = PriceBook::with_default_rate_card();
    assert_eq!(book.egress_price_per_gb, Some(DEFAULT_EGRESS_PRICE_PER_GB));
    assert!(book.egress_cost_usd(2_000_000_000).unwrap() > 0.0);
}

#[test]
fn egress_price_survives_json_round_trip() {
    // #262: the egress dimension serializes alongside the token entries so a
    // configured rate card carries it to the standalone billing service.
    let book = PriceBook::with_default_rate_card();
    let json = serde_json::to_vec(&book).unwrap();
    let parsed = PriceBook::from_json_slice(&json).unwrap();
    assert_eq!(
        parsed.egress_price_per_gb,
        Some(DEFAULT_EGRESS_PRICE_PER_GB)
    );
    // A legacy rate card without the field still parses (serde default None).
    let legacy = br#"[{"provider":"*","model":"*","price":{"input_price_per_1m":1.0,"output_price_per_1m":1.0,"currency":"USD"}}]"#;
    assert!(PriceBook::from_json_slice(legacy)
        .unwrap()
        .egress_price_per_gb
        .is_none());
}

#[test]
fn parses_bare_array_and_full_object() {
    let array = br#"[{"provider":"openai","model":"gpt-5.5","price":{"input_price_per_1m":5.0,"output_price_per_1m":15.0,"currency":"USD"}}]"#;
    let from_array = PriceBook::from_json_slice(array).unwrap();
    assert_eq!(from_array.len(), 1);
    assert_eq!(from_array.credits_per_usd, DEFAULT_CREDITS_PER_USD);

    let object = br#"{"credits_per_usd":1000.0,"entries":[{"provider":"*","model":"*","price":{"input_price_per_1m":1.0,"output_price_per_1m":1.0,"currency":"USD"}}]}"#;
    let from_object = PriceBook::from_json_slice(object).unwrap();
    assert_eq!(from_object.credits_per_usd, 1000.0);
    assert_eq!(from_object.len(), 1);
}
