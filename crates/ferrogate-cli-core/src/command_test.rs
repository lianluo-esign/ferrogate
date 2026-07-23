// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the command registry and dispatch skeleton (#360).

use super::*;
use crate::error::ExitClass;

/// A representative resource family, the shape #361–#365 will follow: a
/// zero-sized type returning static metadata with OpenAPI operation ids.
struct TenantsGroup;

impl CommandGroup for TenantsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "tenants",
            "Manage tenants",
            vec![
                VerbDescriptor::api("list", "List tenants", "listTenants"),
                VerbDescriptor::api("get", "Show a tenant", "getTenant"),
                VerbDescriptor::api("create", "Create a tenant", "createTenant"),
            ],
        )
    }
}

/// A local-only family (the foundation's own `context` verbs) with no API ops.
struct ContextGroup;

impl CommandGroup for ContextGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "context",
            "Manage local contexts",
            vec![
                VerbDescriptor::local("list", "List contexts"),
                VerbDescriptor::local("use", "Select the current context"),
            ],
        )
    }
}

fn registry() -> Registry {
    let mut registry = Registry::new();
    registry.register(&TenantsGroup).unwrap();
    registry.register(&ContextGroup).unwrap();
    registry
}

#[test]
fn groups_register_and_are_listed_in_order() {
    let registry = registry();
    let names: Vec<&str> = registry
        .groups()
        .iter()
        .map(|group| group.name.as_str())
        .collect();
    assert_eq!(names, vec!["tenants", "context"]);
}

#[test]
fn resolve_routes_group_and_verb() {
    let registry = registry();
    let verb = registry.resolve("tenants", "get").unwrap();
    assert_eq!(verb.name, "get");
    assert_eq!(verb.operation_id.as_deref(), Some("getTenant"));
}

#[test]
fn resolve_unknown_group_is_usage_error() {
    let registry = registry();
    let error = registry.resolve("widgets", "list").unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("unknown command 'widgets'"));
}

#[test]
fn resolve_unknown_verb_is_usage_error() {
    let registry = registry();
    let error = registry.resolve("tenants", "frobnicate").unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("unknown verb 'frobnicate'"));
}

#[test]
fn duplicate_group_registration_is_rejected() {
    let mut registry = registry();
    let error = registry.register(&TenantsGroup).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("duplicate command group"));
}

#[test]
fn duplicate_verb_within_group_is_rejected() {
    struct BrokenGroup;
    impl CommandGroup for BrokenGroup {
        fn descriptor(&self) -> GroupDescriptor {
            GroupDescriptor::new(
                "broken",
                "Broken group",
                vec![
                    VerbDescriptor::local("list", "List"),
                    VerbDescriptor::local("list", "List again"),
                ],
            )
        }
    }
    let mut registry = Registry::new();
    let error = registry.register(&BrokenGroup).unwrap_err();
    assert!(error.to_string().contains("duplicate verb"));
}

#[test]
fn coverage_manifest_collects_only_api_operations() {
    let registry = registry();
    let manifest = registry.coverage_manifest();
    // Local `context` verbs contribute no operation ids.
    assert_eq!(manifest.len(), 3);
    assert!(manifest.contains("listTenants"));
    assert!(manifest.contains("getTenant"));
    assert!(manifest.contains("createTenant"));
    // Sorted/stable for diffing against the OpenAPI contract.
    let ordered: Vec<&String> = manifest.iter().collect();
    assert_eq!(ordered, vec!["createTenant", "getTenant", "listTenants"]);
}

#[test]
fn help_summary_lists_every_group_verb() {
    let registry = registry();
    let summary = registry.help_summary();
    assert!(summary.contains("tenants list"));
    assert!(summary.contains("context use"));
    assert_eq!(summary.lines().count(), 5);
}
