// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for provider compliance projections and case coverage (#210).

use super::*;

#[test]
fn provider_contract_cases_cover_success_fallback_and_reported_usage_error() {
    assert_eq!(PROVIDER_CASES.len(), 5);
    let fallback = PROVIDER_CASES
        .iter()
        .find(|case| case.name == "fallback-success")
        .unwrap();
    assert_eq!(fallback.expected_upstream_models.len(), 2);
    assert_eq!(fallback.name, PROVIDER_CASES.last().unwrap().name);

    for name in [
        "terminal-error-with-usage",
        "terminal-stream-error-with-usage",
    ] {
        let case = PROVIDER_CASES
            .iter()
            .find(|case| case.name == name)
            .unwrap();
        assert_eq!(case.expected_status, 400);
        assert_eq!(case.expected_error_code, Some("bad_provider_request"));
        assert_eq!(case.total_tokens, 5);
        assert!(case.content.contains("with usage"));
    }
    assert!(
        PROVIDER_CASES
            .iter()
            .find(|case| case.name == "terminal-stream-error-with-usage")
            .unwrap()
            .stream
    );
}

#[test]
fn provider_contract_cases_cover_non_billable_errors_without_usage() {
    assert_eq!(PROVIDER_NO_SETTLEMENT_CASES.len(), 2);
    for case in PROVIDER_NO_SETTLEMENT_CASES {
        assert!(case.content.contains("without usage"));
        assert_eq!(case.expected_upstream_model, "gpt-4o-mini");
    }
    assert!(!PROVIDER_NO_SETTLEMENT_CASES[0].stream);
    assert!(PROVIDER_NO_SETTLEMENT_CASES[1].stream);
}

#[test]
fn provider_contract_costs_are_compared_as_integer_picodollars() {
    assert_eq!(
        cost_picousd(&serde_json::json!(0.000_003), "cost").unwrap(),
        3_000_000
    );
    assert_eq!(
        cost_picousd(&serde_json::json!(0.000_016), "cost").unwrap(),
        16_000_000
    );
}
