// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for provider compliance projections and case coverage (#210).

use super::*;

#[test]
fn provider_contract_matrix_exactly_matches_runtime_adapter_families() {
    validate_provider_case_matrix(&PROVIDER_CASES).unwrap();
}

#[test]
fn provider_contract_matrix_rejects_a_missing_runtime_family() {
    let mut cases = PROVIDER_CASES.to_vec();
    cases.retain(|case| case.adapter_family != "vertex");

    let error = validate_provider_case_matrix(&cases).unwrap_err();
    assert!(error.to_string().contains("missing compliance cases"));
    assert!(error.to_string().contains("vertex"));
}

#[test]
fn provider_contract_matrix_rejects_an_unsupported_family() {
    let mut cases = PROVIDER_CASES.to_vec();
    cases[0].adapter_family = "unsupported-test-adapter";

    let error = validate_provider_case_matrix(&cases).unwrap_err();
    assert!(error.to_string().contains("unsupported adapter families"));
    assert!(error.to_string().contains("unsupported-test-adapter"));
}

#[test]
fn provider_contract_matrix_rejects_a_new_runtime_family_without_a_case() {
    let mut runtime = runtime_provider_adapter_families();
    runtime.insert("future-test-adapter");

    let error = validate_provider_case_matrix_against(&PROVIDER_CASES, &runtime).unwrap_err();
    assert!(error.to_string().contains("missing compliance cases"));
    assert!(error.to_string().contains("future-test-adapter"));
}

#[test]
fn provider_contract_cases_cover_success_and_reported_usage_error() {
    assert_eq!(PROVIDER_CASES.len(), 18);
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
fn provider_contract_reserves_two_dispatches_for_multi_attempt_settlement() {
    assert_eq!(
        expected_provider_requests(),
        PROVIDER_CASES.len() + PROVIDER_NO_SETTLEMENT_CASES.len() + 2
    );
    assert!(MULTI_ATTEMPT_CONTENT.contains("multi attempt"));
}

#[test]
fn provider_contract_covers_reported_usage_streaming_families() {
    let streaming = PROVIDER_CASES
        .iter()
        .filter(|case| case.stream && case.expected_error_code.is_none())
        .map(|case| case.adapter_family)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        streaming,
        BTreeSet::from([
            "anthropic",
            "azure-openai",
            "gemini",
            "grok",
            "openai-compatible",
            "openrouter",
            "vertex",
        ])
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
