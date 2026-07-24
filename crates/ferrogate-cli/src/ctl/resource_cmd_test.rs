// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the generic resource command wiring: the clap tree the
//! registry drives is internally valid, the resource args fold into the right
//! request input, and the generic table renderer projects the three response
//! shapes.

use super::*;
use ferrogate_cli_core::register_resource_families;
use serde_json::json;

fn registry() -> Registry {
    let mut registry = Registry::new();
    register_resource_families(&mut registry).expect("families register");
    registry
}

/// The generated `ctl` subtree is a valid clap command tree (the builder-side
/// analogue of the derive `debug_assert`). Exercises every registered group and
/// verb plus the shared global + resource args on each leaf.
#[test]
fn generated_ctl_tree_is_valid() {
    build_ctl_command(&registry()).debug_assert();
}

/// The `ctl` tree offers one subcommand per registered group, each with one
/// subcommand per declared verb — proving the tree is metadata-driven, not
/// hand-enumerated.
#[test]
fn ctl_tree_mirrors_the_registry() {
    let registry = registry();
    let ctl = build_ctl_command(&registry);
    for group in registry.groups() {
        let group_cmd = ctl
            .get_subcommands()
            .find(|command| command.get_name() == group.name)
            .unwrap_or_else(|| panic!("group '{}' missing from ctl tree", group.name));
        for verb in &group.verbs {
            assert!(
                group_cmd
                    .get_subcommands()
                    .any(|command| command.get_name() == verb.name),
                "verb '{} {}' missing from ctl tree",
                group.name,
                verb.name
            );
        }
    }
}

/// A representative invocation parses through the generated tree into the group
/// / verb / args a dispatch would consume.
#[test]
fn parses_a_get_with_output_flag() {
    let registry = registry();
    let command = build_ctl_command(&registry);
    let matches = command
        .try_get_matches_from(["ctl", "virtual-keys", "get", "vk-1", "--output", "json"])
        .expect("valid invocation parses");
    let (group, group_matches) = matches.subcommand().unwrap();
    assert_eq!(group, "virtual-keys");
    let (verb, verb_matches) = group_matches.subcommand().unwrap();
    assert_eq!(verb, "get");

    let resource = ResourceArgs::from_arg_matches(verb_matches).unwrap();
    assert_eq!(resource.segments, vec!["vk-1".to_string()]);
    let global = GlobalArgs::from_arg_matches(verb_matches).unwrap();
    assert_eq!(global.output.as_deref(), Some("json"));
}

#[test]
fn resource_args_fold_segments_body_and_list() {
    let registry = registry();
    let command = build_ctl_command(&registry);
    let matches = command
        .try_get_matches_from([
            "ctl",
            "quota-policies",
            "update",
            "tenant",
            "acme",
            "--data",
            r#"{"limit":5}"#,
            "--limit",
            "20",
            "--offset",
            "40",
            "--filter",
            "status=active",
        ])
        .expect("valid invocation parses");
    let verb_matches = matches
        .subcommand()
        .unwrap()
        .1
        .subcommand()
        .unwrap()
        .1
        .clone();
    let resource = ResourceArgs::from_arg_matches(&verb_matches).unwrap();
    let input = resource.to_input().unwrap();
    assert_eq!(
        input.segments,
        vec!["tenant".to_string(), "acme".to_string()]
    );
    assert_eq!(input.body, Some(json!({"limit": 5})));
    // The list params fold pagination + the server-side filter.
    let spec = build_request("quota-policies", "update", &input).unwrap();
    assert_eq!(spec.method.as_str(), "PATCH");
    assert_eq!(spec.path, "/admin/v1/quota-policies/tenant/acme");
    assert_eq!(spec.body, Some(json!({"limit": 5})));
}

#[test]
fn malformed_filter_is_a_usage_error() {
    let args = ResourceArgs {
        segments: vec![],
        data: None,
        file: None,
        limit: None,
        offset: None,
        filters: vec!["missing-equals".to_string()],
    };
    let error = args.to_input().unwrap_err();
    assert!(error.to_string().contains("KEY=VALUE"));
}

#[test]
fn malformed_body_is_a_usage_error() {
    let args = ResourceArgs {
        segments: vec![],
        data: Some("not json".to_string()),
        file: None,
        limit: None,
        offset: None,
        filters: vec![],
    };
    let error = args.to_input().unwrap_err();
    assert!(error.to_string().contains("not valid JSON"));
}

#[test]
fn render_table_projects_an_array_of_objects() {
    let body = json!([
        {"id": "a", "name": "Alpha"},
        {"id": "b", "name": "Beta", "extra": 1},
    ]);
    let table = render_table(&body).unwrap();
    assert!(table.contains("ID") && table.contains("NAME") && table.contains("EXTRA"));
    assert!(table.contains("Alpha") && table.contains("Beta"));
    // A row missing a union column renders a placeholder, never a ragged table.
    assert!(table.contains('-'));
}

#[test]
fn render_table_unwraps_a_list_envelope() {
    let body = json!({"items": [{"id": "x"}], "total": 1});
    let table = render_table(&body).unwrap();
    assert!(table.contains("ID"));
    assert!(table.contains('x'));
}

#[test]
fn render_table_projects_a_single_object() {
    let body = json!({"service": "ferrogate", "runtime": "pingora"});
    let table = render_table(&body).unwrap();
    assert!(table.contains("FIELD") && table.contains("VALUE"));
    assert!(table.contains("service") && table.contains("ferrogate"));
}

#[test]
fn render_table_handles_empty_and_scalar() {
    assert_eq!(render_table(&json!([])).unwrap(), "(no results)");
    assert_eq!(render_table(&Value::Null).unwrap(), "(empty)");
    assert_eq!(render_table(&json!("hello")).unwrap(), "hello");
}
