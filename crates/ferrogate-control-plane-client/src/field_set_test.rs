// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for per-field request-document assembly (#361). Pure logic only.

use super::*;
use crate::error::ExitClass;
use serde_json::json;

fn document(set: &[&str], set_json: &[&str]) -> CliResult<Option<Value>> {
    let set: Vec<String> = set.iter().map(|value| (*value).to_string()).collect();
    let set_json: Vec<String> = set_json.iter().map(|value| (*value).to_string()).collect();
    document_from_flags(&set, &set_json)
}

#[test]
fn set_always_produces_a_json_string() {
    let built = document(&["name=prod", "count=007", "flag=true"], &[])
        .unwrap()
        .unwrap();
    // The whole point of splitting the flags: a zero-padded id and the word
    // `true` survive as the operator typed them instead of being inferred into
    // a number and a boolean.
    assert_eq!(
        built,
        json!({"name": "prod", "count": "007", "flag": "true"})
    );
}

#[test]
fn set_json_parses_scalars_arrays_and_objects() {
    let built = document(
        &[],
        &[
            "limit=25",
            "enabled=true",
            "note=null",
            "tags=[\"a\",\"b\"]",
            "meta={\"k\":1}",
        ],
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        built,
        json!({
            "limit": 25,
            "enabled": true,
            "note": null,
            "tags": ["a", "b"],
            "meta": {"k": 1}
        })
    );
}

#[test]
fn a_dotted_key_builds_a_nested_object() {
    let built = document(&["quota.assets.max_bytes=1024"], &[])
        .unwrap()
        .unwrap();
    assert_eq!(built, json!({"quota": {"assets": {"max_bytes": "1024"}}}));
}

#[test]
fn an_escaped_dot_is_a_literal_field_name() {
    let built = document(&["labels.app\\.kubernetes\\.io/name=ferrogate"], &[])
        .unwrap()
        .unwrap();
    assert_eq!(
        built,
        json!({"labels": {"app.kubernetes.io/name": "ferrogate"}})
    );
}

#[test]
fn only_the_first_equals_separates_key_from_value() {
    let built = document(&["dsn=postgres://h/db?a=1&b=2"], &[])
        .unwrap()
        .unwrap();
    assert_eq!(built, json!({"dsn": "postgres://h/db?a=1&b=2"}));
}

#[test]
fn no_flags_yields_no_document() {
    assert_eq!(document(&[], &[]).unwrap(), None);
}

#[test]
fn a_pair_without_an_equals_is_a_usage_error() {
    let error = document(&["name"], &[]).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("--set must be KEY=VALUE"));
}

#[test]
fn an_empty_field_name_is_a_usage_error() {
    for key in ["=v", "a..b=v", ".a=v", "a.=v"] {
        let error = document(&[key], &[]).unwrap_err();
        assert_eq!(error.exit_class(), ExitClass::Usage, "{key}");
        assert!(error.to_string().contains("empty field name"), "{key}");
    }
}

#[test]
fn malformed_set_json_names_the_plain_string_alternative() {
    let error = document(&[], &["meta={oops"]).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    let message = error.to_string();
    assert!(message.contains("not valid JSON"), "{message}");
    assert!(message.contains("--set"), "{message}");
}

#[test]
fn a_duplicate_path_is_refused_rather_than_last_wins() {
    // Clap surfaces --set and --set-json as two independent lists, so their
    // interleaving is already lost; silently picking one would pick by an
    // order this layer cannot observe.
    let error = document(&["name=a"], &["name=\"b\""]).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("assign 'name' twice"));
}

#[test]
fn a_scalar_and_a_nested_field_on_one_path_collide_both_ways() {
    let scalar_first = document(&["a=1", "a.b=2"], &[]).unwrap_err();
    assert!(
        scalar_first.to_string().contains("assign 'a' twice"),
        "{scalar_first}"
    );
    let nested_first = document(&["a.b=2", "a=1"], &[]).unwrap_err();
    assert!(
        nested_first.to_string().contains("assign 'a' twice"),
        "{nested_first}"
    );
}

#[test]
fn a_trailing_backslash_is_a_usage_error() {
    let error = document(&["name\\=v"], &[]).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("trailing backslash"));
}

#[test]
fn argv_warning_fires_on_credential_keys_including_nested_and_declared_ones() {
    let warning = argv_credential_warning(
        &json!({"upstream": {"api_key": "sk-live"}, "name": "prod"}),
        &[],
    )
    .expect("nested api_key must warn");
    assert!(warning.contains("api_key"), "{warning}");
    assert!(warning.contains("--file"), "{warning}");

    // A group's declared one-time secret field warns even when its name
    // matches none of the generic markers.
    let declared = argv_credential_warning(&json!({"key": "vk_live"}), &["key"])
        .expect("declared secret field must warn");
    assert!(declared.contains("'key'"), "{declared}");
}

#[test]
fn argv_warning_stays_silent_on_documents_with_no_key_material() {
    // `token` is deliberately not a marker: in this codebase it means metered
    // LLM tokens far more often than a credential.
    assert_eq!(
        argv_credential_warning(
            &json!({"name": "prod", "token_usage": 10, "tokens_per_minute": 5}),
            &[]
        ),
        None
    );
    // A declared secret field present but null carries nothing to leak.
    assert_eq!(
        argv_credential_warning(&json!({"key": null}), &["key"]),
        None
    );
}
