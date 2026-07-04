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
