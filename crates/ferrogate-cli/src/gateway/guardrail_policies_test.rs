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
        platform_operator: false,
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

/// A DECLARED platform operator (#515): `platform_operator = true`, which is
/// what `resolve_platform_operator` produces for a key that opted in or that
/// inherited the deprecated `[tenancy] implicit_platform_operator` default.
fn operator_auth() -> AuthContext {
    let mut auth = tenant_auth("ignored");
    auth.organization_id = None;
    auth.platform_operator = true;
    auth
}

/// The shape #515 exists to separate from the one above: a hand-built context
/// that names no tenant and never declared platform root. `finalize_auth`
/// refuses it at the door, so this is the defence-in-depth case -- it must land
/// in `CallerScope::Tenant("")`, never in the operator branch.
fn unclassified_auth() -> AuthContext {
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

/// #515 finding 2. Both guardrail chokepoints used to ask
/// `organization_id.is_none()`, so a credential that declared NEITHER a tenant
/// nor platform root inherited the operator branch of each: unrestricted policy
/// visibility, and permission to point a `CustomHttp` detector at the gateway's
/// own `VAULT_TOKEN` and ship it to a caller-controlled endpoint. Asking
/// `caller_scope()` instead puts it in `Tenant("")`, which no policy scope can
/// match and which is not the operator.
#[test]
fn an_unclassified_credential_gets_neither_guardrail_operator_branch() {
    let unclassified = unclassified_auth();

    // Host-secret exfiltration guard: refused, exactly like any tenant author.
    let custom_http_secret = revision_with_detector(serde_json::json!({
        "kind": "custom_http",
        "endpoint": "https://detector.example/scan",
        "secret_ref": "env://VAULT_TOKEN"
    }));
    assert_eq!(
        authorize_guardrail_secret_refs(&unclassified, &custom_http_secret)
            .expect_err("a credential with no declared identity is not a platform operator")
            .code,
        "guardrail_secret_ref_forbidden",
    );

    // Tenant-isolation chokepoint: it sees no policy, not every policy. An
    // unscoped revision (the one an operator reads) and a tenant-scoped one are
    // both denied, because `Tenant("")` equals no tenant id that can be written.
    assert!(authorize_guardrail_scope(&unclassified, &revision_with_scope(Vec::new())).is_err());
    assert!(
        authorize_guardrail_scope(&unclassified, &revision_with_scope(vec!["tenant-a"])).is_err()
    );
    assert!(!guardrail_view_is_visible(
        &unclassified,
        &PolicyRevisionView {
            revision: revision_with_scope(vec!["tenant-a"]),
            status: Default::default(),
        }
    ));

    // The declared operator is unaffected: this is a narrowing of who counts as
    // root, not a removal of root.
    let operator = operator_auth();
    assert!(authorize_guardrail_secret_refs(&operator, &custom_http_secret).is_ok());
    assert!(authorize_guardrail_scope(&operator, &revision_with_scope(vec!["tenant-a"])).is_ok());
}
