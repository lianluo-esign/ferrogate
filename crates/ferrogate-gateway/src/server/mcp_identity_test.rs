// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for MCP identity APIs, kept outside business logic.

use super::*;

#[test]
fn callback_parser_decodes_values_without_accepting_missing_fields() {
    assert_eq!(
        oauth_callback_params(Some("code=a%2Fb&state=s%2B1")),
        Some(("a/b".into(), "s+1".into()))
    );
    assert!(oauth_callback_params(Some("code=only")).is_none());
    assert!(oauth_callback_params(None).is_none());
}
