// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for guardrail policy APIs, kept outside business logic.

use super::*;
use std::collections::HashSet;

fn tenant_auth(tenant_id: &str) -> AuthContext {
    AuthContext {
        api_key_id: Some("key-1".into()),
        scopes: HashSet::new(),
        allowed_models: HashSet::new(),
        denied_models: HashSet::new(),
        allowed_providers: HashSet::new(),
        denied_providers: HashSet::new(),
        region_allowlist: HashSet::new(),
        monthly_token_budget: None,
        request_limit_per_minute: None,
        organization_id: Some(tenant_id.into()),
        team_id: None,
        project_id: None,
        workspace_id: None,
        user_id: None,
        log_bodies: false,
        rbac_subject: None,
        effective_quota: ferrogate_policy::EffectiveQuota::default(),
    }
}

fn revision_with_scope(organization_ids: Vec<&str>) -> PolicyRevision {
    serde_json::from_value(serde_json::json!({
        "policy_id": "policy-1",
        "revision": 1,
        "name": "policy",
        "scope": {"organization_ids": organization_ids},
        "checks": [{
            "id": "check",
            "stage": "request",
            "detector": {"kind": "local", "keywords": ["secret"]}
        }],
        "on_pass": [{"kind": "allow"}],
        "on_fail": [{"kind": "block", "code": "blocked", "message": "blocked"}],
        "on_error": [{"kind": "block", "code": "error", "message": "error"}],
        "created_at_unix": 1,
        "created_by": "key-1"
    }))
    .expect("test policy must deserialize")
}

#[test]
fn tenant_guardrail_scope_requires_explicit_single_tenant_boundary() {
    let auth = tenant_auth("tenant-a");
    assert!(authorize_guardrail_scope(&auth, &revision_with_scope(vec!["tenant-a"])).is_ok());
    assert!(authorize_guardrail_scope(&auth, &revision_with_scope(Vec::new())).is_err());
    assert!(
        authorize_guardrail_scope(&auth, &revision_with_scope(vec!["tenant-a", "tenant-b"]))
            .is_err()
    );
}

fn operator_auth() -> AuthContext {
    let mut auth = tenant_auth("ignored");
    auth.organization_id = None;
    auth
}

fn revision_with_detector(detector: serde_json::Value) -> PolicyRevision {
    serde_json::from_value(serde_json::json!({
        "policy_id": "policy-1",
        "revision": 1,
        "name": "policy",
        "scope": {"organization_ids": ["tenant-a"]},
        "checks": [{
            "id": "check",
            "stage": "request",
            "detector": detector
        }],
        "on_pass": [{"kind": "allow"}],
        "on_fail": [{"kind": "block", "code": "blocked", "message": "blocked"}],
        "on_error": [{"kind": "block", "code": "error", "message": "error"}],
        "created_at_unix": 1,
        "created_by": "key-1"
    }))
    .expect("test policy must deserialize")
}

#[test]
fn tenant_authors_cannot_reference_host_secrets_but_operators_can() {
    let custom_http_secret = revision_with_detector(serde_json::json!({
        "kind": "custom_http",
        "endpoint": "https://detector.example/scan",
        "secret_ref": "env://VAULT_TOKEN"
    }));
    let local_fingerprint_secret = revision_with_detector(serde_json::json!({
        "kind": "local",
        "keywords": ["secret"],
        "fingerprint_secret_ref": "env://VAULT_TOKEN"
    }));
    let no_secret = revision_with_detector(serde_json::json!({
        "kind": "custom_http",
        "endpoint": "https://detector.example/scan"
    }));

    // A tenant-scoped author cannot dereference a host secret from any detector.
    let tenant = tenant_auth("tenant-a");
    assert!(authorize_guardrail_secret_refs(&tenant, &custom_http_secret).is_err());
    assert!(authorize_guardrail_secret_refs(&tenant, &local_fingerprint_secret).is_err());
    // ...but a secret-free detector is fine.
    assert!(authorize_guardrail_secret_refs(&tenant, &no_secret).is_ok());

    // A platform operator retains the ability to reference host secrets.
    let operator = operator_auth();
    assert!(authorize_guardrail_secret_refs(&operator, &custom_http_secret).is_ok());
    assert!(authorize_guardrail_secret_refs(&operator, &local_fingerprint_secret).is_ok());
}
