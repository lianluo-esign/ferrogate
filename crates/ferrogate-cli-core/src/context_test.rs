// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for context storage and precedence resolution (#360).

use super::*;
use crate::auth::AuthSource;
use crate::output::OutputFormat;

fn store_with_prod() -> ContextStore {
    let mut store = ContextStore::default();
    let mut prod = Context::new("production", "https://prod.example.com");
    prod.tenant = Some("acme".to_string());
    prod.project = Some("payments".to_string());
    prod.auth = AuthSource::Env {
        var: "PROD_TOKEN".to_string(),
    };
    store.upsert(prod);
    let mut staging = Context::new("staging", "https://staging.example.com");
    staging.tenant = Some("acme-staging".to_string());
    store.upsert(staging);
    store.set_current("production").unwrap();
    store
}

#[test]
fn default_resolution_uses_current_context() {
    let store = store_with_prod();
    let effective = resolve(
        &store,
        &EnvOverrides::default(),
        &GlobalOverrides::default(),
    )
    .unwrap();
    assert_eq!(effective.context_name.as_deref(), Some("production"));
    assert_eq!(effective.endpoint, "https://prod.example.com");
    assert_eq!(effective.tenant.as_deref(), Some("acme"));
    assert_eq!(effective.project.as_deref(), Some("payments"));
    assert_eq!(effective.timeout_millis, DEFAULT_TIMEOUT_MILLIS);
}

#[test]
fn flag_beats_env_beats_context() {
    let store = store_with_prod();
    let env = EnvOverrides {
        endpoint: Some("https://env.example.com".to_string()),
        tenant: Some("env-tenant".to_string()),
        ..EnvOverrides::default()
    };
    let overrides = GlobalOverrides {
        endpoint: Some("https://flag.example.com".to_string()),
        ..GlobalOverrides::default()
    };
    let effective = resolve(&store, &env, &overrides).unwrap();
    // endpoint: flag wins over env and context.
    assert_eq!(effective.endpoint, "https://flag.example.com");
    // tenant: no flag, so env wins over context.
    assert_eq!(effective.tenant.as_deref(), Some("env-tenant"));
}

#[test]
fn env_context_selection_overrides_current() {
    let store = store_with_prod();
    let env = EnvOverrides {
        context: Some("staging".to_string()),
        ..EnvOverrides::default()
    };
    let effective = resolve(&store, &env, &GlobalOverrides::default()).unwrap();
    assert_eq!(effective.context_name.as_deref(), Some("staging"));
    assert_eq!(effective.endpoint, "https://staging.example.com");
    assert_eq!(effective.tenant.as_deref(), Some("acme-staging"));
}

#[test]
fn flag_context_selection_overrides_env_context() {
    let store = store_with_prod();
    let env = EnvOverrides {
        context: Some("staging".to_string()),
        ..EnvOverrides::default()
    };
    let overrides = GlobalOverrides {
        context: Some("production".to_string()),
        ..GlobalOverrides::default()
    };
    let effective = resolve(&store, &env, &overrides).unwrap();
    assert_eq!(effective.context_name.as_deref(), Some("production"));
}

#[test]
fn no_context_falls_back_to_builtin_defaults() {
    let store = ContextStore::default();
    let effective = resolve(
        &store,
        &EnvOverrides::default(),
        &GlobalOverrides::default(),
    )
    .unwrap();
    assert_eq!(effective.context_name, None);
    assert_eq!(effective.endpoint, DEFAULT_ENDPOINT);
    assert_eq!(effective.tenant, None);
    assert_eq!(effective.auth, AuthSource::None);
}

#[test]
fn unknown_selected_context_is_a_usage_error() {
    let store = store_with_prod();
    let overrides = GlobalOverrides {
        context: Some("does-not-exist".to_string()),
        ..GlobalOverrides::default()
    };
    let error = resolve(&store, &EnvOverrides::default(), &overrides).unwrap_err();
    assert_eq!(error.exit_class(), crate::error::ExitClass::Usage);
}

#[test]
fn timeout_precedence_and_env_parsing() {
    let store = store_with_prod();
    let env = EnvOverrides::from_lookup(|name| match name {
        EnvOverrides::TIMEOUT_VAR => Some("5000".to_string()),
        _ => None,
    })
    .unwrap();
    // env only.
    let effective = resolve(&store, &env, &GlobalOverrides::default()).unwrap();
    assert_eq!(effective.timeout_millis, 5000);
    // flag beats env.
    let overrides = GlobalOverrides {
        timeout_millis: Some(1000),
        ..GlobalOverrides::default()
    };
    let effective = resolve(&store, &env, &overrides).unwrap();
    assert_eq!(effective.timeout_millis, 1000);
}

#[test]
fn invalid_timeout_env_is_usage_error() {
    let error = EnvOverrides::from_lookup(|name| match name {
        EnvOverrides::TIMEOUT_VAR => Some("soon".to_string()),
        _ => None,
    })
    .unwrap_err();
    assert_eq!(error.exit_class(), crate::error::ExitClass::Usage);
}

#[test]
fn empty_env_values_are_ignored() {
    let env = EnvOverrides::from_lookup(|name| match name {
        EnvOverrides::ENDPOINT_VAR => Some("   ".to_string()),
        _ => None,
    })
    .unwrap();
    assert_eq!(env.endpoint, None);
}

#[test]
fn output_override_applies_and_defaults_to_table() {
    let store = ContextStore::default();
    let effective = resolve(
        &store,
        &EnvOverrides::default(),
        &GlobalOverrides::default(),
    )
    .unwrap();
    assert_eq!(effective.output, OutputFormat::Table);
    let overrides = GlobalOverrides {
        output: Some(OutputFormat::Json),
        non_interactive: true,
        ..GlobalOverrides::default()
    };
    let effective = resolve(&store, &EnvOverrides::default(), &overrides).unwrap();
    assert_eq!(effective.output, OutputFormat::Json);
    assert!(effective.non_interactive);
}

#[test]
fn store_upsert_remove_and_set_current() {
    let mut store = store_with_prod();
    // upsert replaces in place.
    let mut prod = Context::new("production", "https://prod2.example.com");
    prod.tenant = Some("acme2".to_string());
    store.upsert(prod);
    assert_eq!(store.contexts.len(), 2);
    assert_eq!(
        store.get("production").unwrap().endpoint,
        "https://prod2.example.com"
    );

    // removing the current context clears the pointer.
    assert!(store.remove("production"));
    assert_eq!(store.current, None);
    assert!(!store.remove("production"));

    // set_current fails for an unknown name.
    assert_eq!(
        store.set_current("ghost").unwrap_err().exit_class(),
        crate::error::ExitClass::Usage
    );
    store.set_current("staging").unwrap();
    assert_eq!(store.current.as_deref(), Some("staging"));
}

#[test]
fn serialized_context_never_contains_a_token() {
    // A context references a credential source but must never carry the
    // secret itself. Serializing must not leak a token field.
    let mut context = Context::new("production", "https://prod.example.com");
    context.auth = AuthSource::Env {
        var: "PROD_TOKEN".to_string(),
    };
    let json = serde_json::to_string(&context).unwrap();
    assert!(json.contains("PROD_TOKEN"));
    assert!(!json.to_lowercase().contains("bearer"));
    // The only auth material is the variable *name*, not a value.
    assert!(!json.contains("secret-token-value"));
}

// ----- scope fields the server does not act on -------------------------------

/// A resolved tenant is announced, because sending it changes nothing: the
/// `x-ferrogate-tenant` header it becomes is declared by no operation in the
/// contract, so `--tenant acme` with an admin token returns whatever the
/// token's scope is. Silence there is a wrong-tenant read presented as a scoped
/// one.
#[test]
fn a_resolved_tenant_is_announced_as_unhonored() {
    let store = store_with_prod();
    let mut staging_only = ContextStore::default();
    staging_only.upsert(Context::new("plain", "https://prod.example.com"));
    staging_only.set_current("plain").unwrap();

    let scoped = resolve(
        &store,
        &EnvOverrides::default(),
        &GlobalOverrides::default(),
    )
    .unwrap();
    let notice = unhonored_scope_notice(&scoped).expect("a set tenant must be announced");
    assert!(
        notice.contains("x-ferrogate-tenant") && notice.contains("bearer token"),
        "the note must say what is sent and why it does not scope: {notice}"
    );
    // It also points at the one tenant selection that DOES work.
    assert!(notice.contains("--filter tenant="), "{notice}");

    // The negative twin: no scope set, no nagging. A note that fires
    // unconditionally is one operators learn to ignore.
    let unscoped = resolve(
        &staging_only,
        &EnvOverrides::default(),
        &GlobalOverrides::default(),
    )
    .unwrap();
    assert_eq!(unhonored_scope_notice(&unscoped), None);
}

/// `project`/`workspace` never reach a request in any form — not a header, not
/// a query parameter — so they are announced separately from the tenant, and
/// only when actually set.
#[test]
fn project_and_workspace_are_announced_as_never_sent() {
    let mut store = ContextStore::default();
    let mut context = Context::new("local", "https://prod.example.com");
    context.project = Some("payments".to_string());
    context.workspace = Some("ws-1".to_string());
    store.upsert(context);
    store.set_current("local").unwrap();

    let effective = resolve(
        &store,
        &EnvOverrides::default(),
        &GlobalOverrides::default(),
    )
    .unwrap();
    let notice = unhonored_scope_notice(&effective).expect("set fields must be announced");
    assert!(
        notice.contains("project and workspace") && notice.contains("not sent with any request"),
        "both unsent fields must be named: {notice}"
    );
    // No tenant is set here, so the tenant half must not fire.
    assert!(
        !notice.contains("x-ferrogate-tenant"),
        "only the fields actually set may be reported: {notice}"
    );

    // One field alone reads correctly rather than as a mangled plural.
    let mut single = ContextStore::default();
    let mut only_project = Context::new("local", "https://prod.example.com");
    only_project.project = Some("payments".to_string());
    single.upsert(only_project);
    single.set_current("local").unwrap();
    let effective = resolve(
        &single,
        &EnvOverrides::default(),
        &GlobalOverrides::default(),
    )
    .unwrap();
    let notice = unhonored_scope_notice(&effective).unwrap();
    assert!(notice.contains("project is recorded locally"), "{notice}");
}

/// The note follows the *resolved* value, not the flag, so an inherited
/// `FERROGATE_TENANT` — the path an operator is least likely to have in mind —
/// is announced exactly like an explicit `--tenant`.
#[test]
fn an_env_supplied_tenant_is_announced_too() {
    let mut store = ContextStore::default();
    store.upsert(Context::new("plain", "https://prod.example.com"));
    store.set_current("plain").unwrap();
    let env = EnvOverrides {
        tenant: Some("from-the-shell".to_string()),
        ..EnvOverrides::default()
    };

    let effective = resolve(&store, &env, &GlobalOverrides::default()).unwrap();
    assert_eq!(effective.tenant.as_deref(), Some("from-the-shell"));
    assert!(unhonored_scope_notice(&effective).is_some());
}
