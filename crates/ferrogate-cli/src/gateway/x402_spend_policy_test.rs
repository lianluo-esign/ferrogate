// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Unit tests for the admin x402 effective-policy diagnostics
// (issue #351): scope resolution + inheritance evidence, the allow / deny /
// approval-required dry-run decisions with their full evidence chain, the
// fail-closed defaults for an unconfigured scope and an unparseable challenge,
// and the invariant that no response field is secret- or signer-shaped.
// Sibling test file per AGENTS.md (no inline `mod tests {}`).

use super::*;

use base64::Engine as _;
use ferrogate_config::X402SpendPolicyConfig;
use ferrogate_policy::{
    AllowedAsset, ApprovalPolicy, ConversionRule, PolicyNetwork, X402SpendCaps, REASON_ALLOWED,
    REASON_APPROVAL_REQUIRED, REASON_DISABLED, REASON_OVER_PER_PAYMENT_CAP,
    REASON_RECIPIENT_NOT_ALLOWED, REASON_RESOURCE_MISMATCH,
};
use serde_json::{json, Value};

const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const CAIP2_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const MERCHANT: &str = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4";
const OTHER_MERCHANT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const FEE_PAYER: &str = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";
const RESOURCE: &str = "https://pay.example.com/weather";

/// The canonical devnet USDC policy: 1 credit per 1000 atomic units (round up),
/// 1000 credits per payment, approval above 500 credits.
fn policy(revision: u64) -> X402SpendPolicy {
    X402SpendPolicy {
        enabled: true,
        revision,
        allowed_networks: vec![PolicyNetwork::DEVNET],
        allowed_assets: vec![AllowedAsset {
            network: PolicyNetwork::DEVNET,
            mint: USDC_DEVNET.to_string(),
        }],
        allowed_recipients: vec![MERCHANT.to_string()],
        allowed_resources: vec![ResourceRule {
            origin: "https://pay.example.com".to_string(),
            path_prefix: "/weather".to_string(),
        }],
        caps: X402SpendCaps {
            max_credits_per_payment: Some(1_000),
            max_credits_per_run: Some(5_000),
            max_credits_per_window: Some(10_000),
            window_seconds: Some(3_600),
            max_atomic_per_payment: Some(2_000_000),
            min_atomic_per_payment: Some(10),
        },
        conversion: ConversionRule {
            numerator: 1,
            denominator: 1_000,
            rounding: Rounding::Up,
            version: "usdc-devnet-v1".to_string(),
        },
        approval: ApprovalPolicy {
            threshold_credits: Some(500),
        },
        allow_insecure_local_resources: false,
    }
}

fn declaration(
    scope_type: X402PolicyScopeKind,
    scope_id: &str,
    policy: X402SpendPolicy,
) -> X402ScopedSpendPolicy {
    X402ScopedSpendPolicy {
        scope_type,
        scope_id: scope_id.to_string(),
        policy: X402SpendPolicyConfig::from(policy),
    }
}

/// A tenant declaration at revision 7 plus a tighter project override at
/// revision 11 (2-credit per-payment cap), so precedence is observable.
fn declarations() -> Vec<X402ScopedSpendPolicy> {
    let mut tight = policy(11);
    tight.caps.max_credits_per_payment = Some(2);
    vec![
        declaration(X402PolicyScopeKind::Tenant, "tenant-1", policy(7)),
        declaration(X402PolicyScopeKind::Project, "project-1", tight),
    ]
}

fn scope(project: Option<&str>) -> X402ScopeRequest {
    X402ScopeRequest {
        tenant_id: "tenant-1".to_string(),
        project_id: project.map(str::to_string),
        workspace_id: None,
        key_id: None,
        run_id: None,
    }
}

/// Base64 `PAYMENT-REQUIRED` header for a devnet USDC challenge, exactly as an
/// untrusted merchant would send it.
fn challenge(atomic: u64, recipient: &str, resource: &str) -> String {
    let body = json!({
        "x402Version": 2,
        "resource": {"url": resource, "mimeType": "application/json"},
        "accepts": [{
            "scheme": "exact",
            "network": CAIP2_DEVNET,
            "amount": atomic.to_string(),
            "asset": USDC_DEVNET,
            "payTo": recipient,
            "maxTimeoutSeconds": 120,
            "extra": {"feePayer": FEE_PAYER}
        }]
    });
    base64::engine::general_purpose::STANDARD.encode(body.to_string())
}

fn evaluation_request(
    scope: X402ScopeRequest,
    atomic: u64,
    recipient: &str,
    challenge_resource: &str,
    authorized: &str,
) -> X402EvaluationRequest {
    X402EvaluationRequest {
        scope,
        payment_required: challenge(atomic, recipient, challenge_resource),
        authorized_resource_url: authorized.to_string(),
        spent: X402SpentRequest::default(),
    }
}

fn evaluate(request: &X402EvaluationRequest) -> X402EvaluationView {
    evaluate_x402_payment_request(&declarations(), request).expect("evaluation should succeed")
}

/// Every JSON key in a serialized value, recursively.
fn json_keys(value: &Value, into: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                into.push(key.clone());
                json_keys(nested, into);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| json_keys(item, into)),
        _ => {}
    }
}

#[test]
fn the_effective_view_reports_the_narrowest_declaration_and_why_it_won() {
    let view = build_effective_policy_view(&declarations(), &scope(Some("project-1")));

    assert!(view.declared);
    assert_eq!(view.policy_revision, 11);
    assert_eq!(
        view.resolved_scope,
        Some(X402PolicyScopeRef {
            scope_type: X402PolicyScopeKind::Project,
            scope_id: "project-1".to_string(),
        })
    );
    // Inheritance evidence: both levels present, tenant declared but overridden.
    assert_eq!(view.inheritance.len(), 2);
    assert_eq!(view.inheritance[0].scope_type, X402PolicyScopeKind::Tenant);
    assert!(view.inheritance[0].declared);
    assert!(!view.inheritance[0].effective);
    assert_eq!(view.inheritance[1].scope_type, X402PolicyScopeKind::Project);
    assert!(view.inheritance[1].declared);
    assert!(view.inheritance[1].effective);
}

#[test]
fn the_effective_view_falls_back_to_the_nearest_declared_parent() {
    let view = build_effective_policy_view(&declarations(), &scope(None));

    assert!(view.declared);
    assert_eq!(view.policy_revision, 7);
    assert_eq!(
        view.resolved_scope.as_ref().map(|scope| scope.scope_type),
        Some(X402PolicyScopeKind::Tenant)
    );
}

#[test]
fn an_unconfigured_scope_reports_the_disabled_deny_all_default_not_an_absence() {
    let view = build_effective_policy_view(
        &declarations(),
        &X402ScopeRequest {
            tenant_id: "tenant-unknown".to_string(),
            ..X402ScopeRequest::default()
        },
    );

    assert!(!view.declared);
    assert!(view.resolved_scope.is_none());
    assert_eq!(view.policy_revision, 0);
    assert!(!view.policy.enabled);
    assert!(view.policy.allowed_recipients.is_empty());
}

#[test]
fn what_the_operator_declared_is_exactly_what_the_effective_view_reads_back() {
    let declared = declarations();
    let view = build_effective_policy_view(&declared, &scope(Some("project-1")));

    // #188 guard at the projection layer: the surface must not reshape,
    // truncate, or default any field of the declaration in force.
    assert_eq!(&view.policy, declared[1].policy.policy());
    assert_eq!(
        declared_policy_view(&declared[1]).policy,
        view.policy,
        "the list projection and the effective projection must agree"
    );
}

#[test]
fn a_payment_within_every_cap_is_allowed_with_the_full_evidence_chain() {
    // 2500 atomic / 1000 = 3 credits (round up), below the 500-credit approval
    // threshold and every cap.
    let view = evaluate(&evaluation_request(
        scope(None),
        2_500,
        MERCHANT,
        RESOURCE,
        RESOURCE,
    ));

    assert_eq!(view.decision.decision, "allow");
    assert_eq!(view.decision.reason_code, REASON_ALLOWED);
    assert_eq!(view.policy_revision, 7);
    assert_eq!(view.decision.policy_revision, 7);
    assert_eq!(view.decision.atomic_amount, 2_500);
    assert_eq!(view.decision.computed_credits, Some(3));
    assert_eq!(view.decision.conversion.numerator, 1);
    assert_eq!(view.decision.conversion.denominator, 1_000);
    assert_eq!(view.decision.conversion.version, "usdc-devnet-v1");
    assert_eq!(view.decision.mint, USDC_DEVNET);
    assert_eq!(view.decision.recipient, MERCHANT);
    assert_eq!(view.decision.network_caip2, CAIP2_DEVNET);
    assert_eq!(
        view.decision.matched_resource,
        Some(ResourceRule {
            origin: "https://pay.example.com".to_string(),
            path_prefix: "/weather".to_string(),
        })
    );
    assert_eq!(view.decision.challenge_hash_hex.len(), 64);
    assert!(view
        .decision
        .challenge_hash_hex
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));
    assert!(view.decision.approval_threshold_credits.is_none());
}

#[test]
fn a_payment_above_the_approval_threshold_requires_approval_instead_of_allowing() {
    // 600_000 atomic = 600 credits: above the 500 threshold, under the 1000 cap.
    let view = evaluate(&evaluation_request(
        scope(None),
        600_000,
        MERCHANT,
        RESOURCE,
        RESOURCE,
    ));

    assert_eq!(view.decision.decision, "approval_required");
    assert_eq!(view.decision.reason_code, REASON_APPROVAL_REQUIRED);
    assert_eq!(view.decision.approval_threshold_credits, Some(500));
    assert_eq!(view.decision.computed_credits, Some(600));
    assert_eq!(view.decision.atomic_amount, 600_000);
}

#[test]
fn a_payment_over_the_per_payment_cap_is_denied() {
    // 1_500_000 atomic = 1500 credits, over the 1000-credit per-payment cap.
    let view = evaluate(&evaluation_request(
        scope(None),
        1_500_000,
        MERCHANT,
        RESOURCE,
        RESOURCE,
    ));

    assert_eq!(view.decision.decision, "deny");
    assert_eq!(view.decision.reason_code, REASON_OVER_PER_PAYMENT_CAP);
    assert_eq!(view.decision.computed_credits, Some(1_500));
}

#[test]
fn the_project_override_is_what_the_runtime_decision_actually_reads() {
    // Identical payment; only the scope chain differs. Under the tenant policy
    // 3 credits is allowed, under the project override (2-credit cap) it denies.
    let allowed = evaluate(&evaluation_request(
        scope(None),
        2_500,
        MERCHANT,
        RESOURCE,
        RESOURCE,
    ));
    let denied = evaluate(&evaluation_request(
        scope(Some("project-1")),
        2_500,
        MERCHANT,
        RESOURCE,
        RESOURCE,
    ));

    assert_eq!(allowed.decision.decision, "allow");
    assert_eq!(allowed.decision.policy_revision, 7);
    assert_eq!(denied.decision.decision, "deny");
    assert_eq!(denied.decision.reason_code, REASON_OVER_PER_PAYMENT_CAP);
    assert_eq!(denied.decision.policy_revision, 11);
    assert_eq!(
        denied.resolved_scope.as_ref().map(|scope| scope.scope_type),
        Some(X402PolicyScopeKind::Project)
    );
}

#[test]
fn a_challenge_that_redirects_payment_to_another_resource_is_denied() {
    let view = evaluate(&evaluation_request(
        scope(None),
        2_500,
        MERCHANT,
        "https://evil.example.com/drain",
        RESOURCE,
    ));

    assert_eq!(view.decision.decision, "deny");
    assert_eq!(view.decision.reason_code, REASON_RESOURCE_MISMATCH);
    assert_eq!(view.decision.authorized_resource_url, RESOURCE);
    assert_eq!(view.decision.resource_url, "https://evil.example.com/drain");
}

#[test]
fn an_unallowlisted_recipient_is_denied() {
    let view = evaluate(&evaluation_request(
        scope(None),
        2_500,
        OTHER_MERCHANT,
        RESOURCE,
        RESOURCE,
    ));

    assert_eq!(view.decision.decision, "deny");
    assert_eq!(view.decision.reason_code, REASON_RECIPIENT_NOT_ALLOWED);
}

#[test]
fn an_unconfigured_tenant_denies_every_payment() {
    let request = evaluation_request(
        X402ScopeRequest {
            tenant_id: "tenant-unknown".to_string(),
            ..X402ScopeRequest::default()
        },
        2_500,
        MERCHANT,
        RESOURCE,
        RESOURCE,
    );

    let view = evaluate(&request);

    assert!(!view.declared);
    assert_eq!(view.decision.decision, "deny");
    assert_eq!(view.decision.reason_code, REASON_DISABLED);
    assert_eq!(view.policy_revision, 0);
}

#[test]
fn an_unparseable_challenge_is_a_client_error_not_a_decision() {
    let request = X402EvaluationRequest {
        scope: scope(None),
        payment_required: "not-base64!!".to_string(),
        authorized_resource_url: RESOURCE.to_string(),
        spent: X402SpentRequest::default(),
    };

    let error = evaluate_x402_payment_request(&declarations(), &request)
        .expect_err("a malformed challenge must not produce a decision");
    assert!(matches!(error, X402EvaluationError::InvalidChallenge(_)));
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.code(), "invalid_x402_challenge");
}

#[test]
fn a_challenge_with_an_unsupported_scheme_is_rejected_rather_than_evaluated() {
    let body = json!({
        "x402Version": 2,
        "resource": {"url": RESOURCE},
        "accepts": [{
            "scheme": "upto",
            "network": CAIP2_DEVNET,
            "amount": "2500",
            "asset": USDC_DEVNET,
            "payTo": MERCHANT,
            "maxTimeoutSeconds": 120,
            "extra": {"feePayer": FEE_PAYER}
        }]
    });
    let request = X402EvaluationRequest {
        scope: scope(None),
        payment_required: base64::engine::general_purpose::STANDARD.encode(body.to_string()),
        authorized_resource_url: RESOURCE.to_string(),
        spent: X402SpentRequest::default(),
    };

    let error = evaluate_x402_payment_request(&declarations(), &request)
        .expect_err("an unsupported scheme must not be evaluated as a payment");
    assert!(matches!(error, X402EvaluationError::InvalidChallenge(_)));
}

#[test]
fn a_blank_authorized_resource_is_refused_so_a_challenge_cannot_bind_to_nothing() {
    let mut request = evaluation_request(scope(None), 2_500, MERCHANT, RESOURCE, RESOURCE);
    request.authorized_resource_url = "   ".to_string();

    let error = evaluate_x402_payment_request(&declarations(), &request)
        .expect_err("an empty binding target must be refused");
    assert_eq!(error, X402EvaluationError::MissingAuthorizedResource);
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn already_spent_credits_are_accounted_against_the_run_cap() {
    let mut request = evaluation_request(scope(None), 2_500, MERCHANT, RESOURCE, RESOURCE);
    request.spent = X402SpentRequest {
        run_spent_credits: 4_999,
        window_spent_credits: 0,
    };

    let view = evaluate_x402_payment_request(&declarations(), &request).expect("evaluation");

    // 4999 committed + 3 proposed = 5002 > the 5000-credit run cap.
    assert_eq!(view.decision.decision, "deny");
    assert_eq!(view.decision.reason_code, "x402_over_run_cap");
}

#[test]
fn no_diagnostics_response_exposes_a_secret_or_signer_shaped_field() {
    let effective = serde_json::to_value(build_effective_policy_view(
        &declarations(),
        &scope(Some("project-1")),
    ))
    .expect("effective policy view serializes");
    let evaluation = serde_json::to_value(evaluate(&evaluation_request(
        scope(None),
        2_500,
        MERCHANT,
        RESOURCE,
        RESOURCE,
    )))
    .expect("evaluation view serializes");
    let listed = serde_json::to_value(declared_policy_view(&declarations()[0]))
        .expect("declaration view serializes");

    let mut keys = Vec::new();
    for document in [&effective, &evaluation, &listed] {
        json_keys(document, &mut keys);
    }
    assert!(!keys.is_empty());
    for key in &keys {
        let lowered = key.to_ascii_lowercase();
        for forbidden in [
            "secret",
            "signer",
            "signature",
            "private",
            "keypair",
            "mnemonic",
            "seed",
            "credential",
            "password",
            "token",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "diagnostics response exposes a {forbidden}-shaped field: {key}"
            );
        }
    }
    // The serialized money path must stay integral: no float ever appears.
    let mut floats = Vec::new();
    collect_floats(&evaluation, &mut floats);
    assert!(
        floats.is_empty(),
        "the money path must be integer-only, found floats: {floats:?}"
    );
}

/// Every JSON number in `value` that is not an integer.
fn collect_floats(value: &Value, into: &mut Vec<f64>) {
    match value {
        Value::Object(map) => map.values().for_each(|nested| collect_floats(nested, into)),
        Value::Array(items) => items.iter().for_each(|item| collect_floats(item, into)),
        Value::Number(number) if number.as_i64().is_none() && number.as_u64().is_none() => {
            if let Some(float) = number.as_f64() {
                into.push(float);
            }
        }
        _ => {}
    }
}

#[test]
fn a_scope_chain_is_read_from_the_query_string_and_requires_a_tenant() {
    let scope =
        X402ScopeRequest::from_query(Some("tenant_id=tenant-1&project_id=project-1&run_id=run-9"))
            .expect("a query with tenant_id parses");
    assert_eq!(scope.tenant_id, "tenant-1");
    assert_eq!(scope.project_id.as_deref(), Some("project-1"));
    assert_eq!(scope.run_id.as_deref(), Some("run-9"));
    assert!(scope.workspace_id.is_none());

    assert!(X402ScopeRequest::from_query(Some("project_id=project-1")).is_none());
    assert!(X402ScopeRequest::from_query(None).is_none());
    // A blank value is absent, never an empty-id scope that matches nothing.
    let blank = X402ScopeRequest::from_query(Some("tenant_id=tenant-1&project_id="))
        .expect("blank optional value still parses");
    assert!(blank.project_id.is_none());
}

#[test]
fn run_scope_has_no_tenancy_equivalent_so_it_fails_closed_for_tenant_callers() {
    assert_eq!(
        tenancy_scope_kind(X402PolicyScopeKind::Tenant),
        Some(QuotaScopeKind::Tenant)
    );
    assert_eq!(
        tenancy_scope_kind(X402PolicyScopeKind::Key),
        Some(QuotaScopeKind::Key)
    );
    assert_eq!(tenancy_scope_kind(X402PolicyScopeKind::Run), None);
}

#[test]
fn every_path_under_the_diagnostics_prefix_routes_to_this_group() {
    use crate::gateway::{api_contract::match_route_group, route_groups::RouteGroup};

    for path in [
        "/admin/v1/x402-spend-policies",
        "/admin/v1/x402-spend-policies/effective",
        "/admin/v1/x402-spend-policies/evaluate",
        // A typo'd subpath must still land in this group so the handler answers
        // an explicit 404 instead of falling through to dynamic proxy routing.
        "/admin/v1/x402-spend-policies/effectiv",
        "/admin/v1/x402-spend-policies/anything/else",
    ] {
        assert_eq!(
            match_route_group(path),
            Some(RouteGroup::X402SpendPolicy),
            "{path} must route to the x402 spend policy group"
        );
    }
}

#[test]
fn only_the_documented_methods_are_contract_operations() {
    use crate::gateway::api_contract::{operation, path_is_documented};

    assert!(path_is_documented("/admin/v1/x402-spend-policies"));
    assert_eq!(
        operation(&Method::GET, "/admin/v1/x402-spend-policies").map(|op| op.operation_id.as_str()),
        Some("listX402SpendPolicies")
    );
    assert_eq!(
        operation(&Method::GET, "/admin/v1/x402-spend-policies/effective")
            .map(|op| op.operation_id.as_str()),
        Some("getEffectiveX402SpendPolicy")
    );
    assert_eq!(
        operation(&Method::POST, "/admin/v1/x402-spend-policies/evaluate")
            .map(|op| op.operation_id.as_str()),
        Some("evaluateX402SpendPolicy")
    );
    // The diagnostics surface is read-only: no mutating operation is documented,
    // so the shared contract layer answers 405 before any handler runs.
    assert!(operation(&Method::POST, "/admin/v1/x402-spend-policies").is_none());
    assert!(operation(&Method::PUT, "/admin/v1/x402-spend-policies/effective").is_none());
    assert!(operation(&Method::GET, "/admin/v1/x402-spend-policies/evaluate").is_none());
    // Every documented operation requires an admin.read bearer scope.
    for (method, path) in [
        (Method::GET, "/admin/v1/x402-spend-policies"),
        (Method::GET, "/admin/v1/x402-spend-policies/effective"),
        (Method::POST, "/admin/v1/x402-spend-policies/evaluate"),
    ] {
        let operation = operation(&method, path).expect("documented operation");
        assert_eq!(operation.visibility, "admin");
        assert_eq!(operation.auth.kind, "bearer");
        assert_eq!(operation.auth.scope.as_deref(), Some("admin.read"));
    }
}
