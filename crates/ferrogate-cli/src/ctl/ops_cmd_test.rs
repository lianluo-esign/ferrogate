// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit coverage for the `ops status` projection (issue #360). The network path
//! is exercised end-to-end in `tests/control_cli_e2e.rs`; here we prove the
//! pure body → table projection in isolation.

use super::*;
use serde_json::json;

fn sample_status() -> Value {
    json!({
        "service": "ferrogate",
        "version": "2026.7.9",
        "runtime": "pingora",
        "snapshot": "snap-1",
        "providers": 5, "enabled_providers": 3,
        "models": 10, "enabled_models": 8,
        "routes": 4, "enabled_routes": 4,
        "upstreams": 2, "enabled_upstreams": 1,
        "api_keys": 7, "tools": 12, "auth_required": true
    })
}

#[test]
fn status_table_projects_expected_rows() {
    let rendered = status_table(&sample_status()).unwrap().render();
    assert!(rendered.contains("FIELD"));
    assert!(rendered.contains("VALUE"));
    assert!(rendered.contains("service"));
    assert!(rendered.contains("ferrogate"));
    assert!(rendered.contains("pingora"));
    assert!(rendered.contains("2026.7.9"));
    assert!(
        rendered.contains("3/5"),
        "providers enabled/total: {rendered}"
    );
    assert!(
        rendered.contains("8/10"),
        "models enabled/total: {rendered}"
    );
    assert!(rendered.contains("true"), "auth_required: {rendered}");
}

#[test]
fn missing_fields_render_as_dash() {
    let rendered = status_table(&json!({ "service": "x" })).unwrap().render();
    assert!(
        rendered
            .lines()
            .any(|line| line.starts_with("version") && line.contains('-')),
        "absent fields render as '-': {rendered}"
    );
}

#[test]
fn render_scalar_strips_string_quotes() {
    assert_eq!(render_scalar(&json!("hello")), "hello");
    assert_eq!(render_scalar(&json!(42)), "42");
    assert_eq!(render_scalar(&json!(true)), "true");
    assert_eq!(render_scalar(&Value::Null), "-");
}

#[test]
fn enabled_of_total_formats_pair() {
    assert_eq!(
        enabled_of_total(&sample_status(), "enabled_models", "models"),
        "8/10"
    );
    assert_eq!(enabled_of_total(&json!({}), "a", "b"), "-");
    assert_eq!(enabled_of_total(&json!({ "b": 4 }), "a", "b"), "-/4");
}
