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
            expires_at_unix: None,
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
        authorized_method: "GET".to_string(),
        authorized_request_body_sha256_hex: None,
        spent: Some(X402SpentRequest::default()),
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
        authorized_method: "GET".to_string(),
        authorized_request_body_sha256_hex: None,
        spent: Some(X402SpentRequest::default()),
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
        authorized_method: "GET".to_string(),
        authorized_request_body_sha256_hex: None,
        spent: Some(X402SpentRequest::default()),
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
    request.spent = Some(X402SpentRequest {
        run_spent_credits: 4_999,
        window_spent_credits: 0,
        now_unix: None,
    });

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
        // The SHARED list (issue #351 review): this guard and the harness's
        // must not be able to drift apart again.
        for forbidden in ferrogate_core::SECRET_SHAPED_KEY_FRAGMENTS {
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

// ---------------------------------------------------------------------------
// Scope-id normalization (blocker 3)
// ---------------------------------------------------------------------------

/// The bug this closes: `GET …/effective` read its ids through `query_value`
/// (which trims) while `POST …/evaluate` resolved the JSON body verbatim, so
/// the same padded id read back one policy and decided under another -- on the
/// one surface whose whole promise is "what you read back is what the runtime
/// decides".
#[test]
fn a_padded_scope_id_resolves_identically_through_effective_and_evaluate() {
    let padded = X402ScopeRequest {
        tenant_id: "  tenant-1 ".to_string(),
        project_id: Some("\tproject-1\n".to_string()),
        ..X402ScopeRequest::default()
    };
    let exact = scope(Some("project-1"));

    let padded_view = build_effective_policy_view(&declarations(), &padded);
    let exact_view = build_effective_policy_view(&declarations(), &exact);
    assert_eq!(padded_view, exact_view);
    assert!(padded_view.declared);
    assert_eq!(padded_view.policy_revision, 11);

    // ...and the decision side answers the same, rather than falling through to
    // the disabled deny-all default at revision 0.
    let padded_decision = evaluate(&evaluation_request(
        padded, 2_500, MERCHANT, RESOURCE, RESOURCE,
    ));
    let exact_decision = evaluate(&evaluation_request(
        exact, 2_500, MERCHANT, RESOURCE, RESOURCE,
    ));
    assert_eq!(
        padded_decision.policy_revision,
        exact_decision.policy_revision
    );
    assert_eq!(
        padded_decision.decision.reason_code,
        exact_decision.decision.reason_code
    );
    assert_eq!(padded_decision.policy_revision, 11);
    // The echoed scope reports the id a caller must actually send.
    assert_eq!(padded_decision.scope.tenant_id, "tenant-1");
    assert_eq!(
        padded_decision.scope.project_id.as_deref(),
        Some("project-1")
    );
}

/// A declaration written with a padded `scope_id` used to load clean, list on
/// the admin surface, and be unreachable by every request -- a money policy the
/// operator had every reason to believe was in force.
#[test]
fn a_declaration_written_with_a_padded_scope_id_is_still_reachable() {
    let declared = vec![declaration(
        X402PolicyScopeKind::Tenant,
        "  acme  ",
        policy(21),
    )];

    let view = build_effective_policy_view(
        &declared,
        &X402ScopeRequest {
            tenant_id: "acme".to_string(),
            ..X402ScopeRequest::default()
        },
    );

    assert!(view.declared, "a padded declaration must not be inert");
    assert_eq!(view.policy_revision, 21);
    // And the list surface advertises the id that actually resolves.
    assert_eq!(declared_policy_view(&declared[0]).scope_id, "acme");
}

/// A narrower level whose id is only whitespace is absent, not an empty-id
/// scope -- matching what `query_value` already did for the query string.
#[test]
fn a_blank_narrower_scope_level_is_absent_rather_than_an_empty_id() {
    let view = build_effective_policy_view(
        &declarations(),
        &X402ScopeRequest {
            tenant_id: "tenant-1".to_string(),
            project_id: Some("   ".to_string()),
            ..X402ScopeRequest::default()
        },
    );

    assert_eq!(view.inheritance.len(), 1);
    assert_eq!(view.inheritance[0].scope_type, X402PolicyScopeKind::Tenant);
    assert_eq!(view.policy_revision, 7);
    assert!(view.scope.project_id.is_none());
}

// ---------------------------------------------------------------------------
// Intent binding + wire-level money invariants
// ---------------------------------------------------------------------------

#[test]
fn the_decision_names_the_method_and_body_it_authorized() {
    let mut post = evaluation_request(scope(None), 2_500, MERCHANT, RESOURCE, RESOURCE);
    post.authorized_method = "post".to_string();
    post.authorized_request_body_sha256_hex =
        Some("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string());

    let read = evaluate(&evaluation_request(
        scope(None),
        2_500,
        MERCHANT,
        RESOURCE,
        RESOURCE,
    ));
    let write = evaluate(&post);

    assert_eq!(read.decision.http_method, "GET");
    assert_eq!(write.decision.http_method, "POST");
    assert_ne!(
        read.decision.request_body_sha256_hex,
        write.decision.request_body_sha256_hex
    );
    assert_ne!(
        read.decision.intent_hash_hex,
        write.decision.intent_hash_hex
    );
    assert_ne!(
        read.decision.decision_hash_hex,
        write.decision.decision_hash_hex
    );
    assert_eq!(read.decision.intent_hash_hex.len(), 64);
    assert_eq!(read.decision.decision_hash_hex.len(), 64);
}

#[test]
fn an_unusable_request_body_hash_is_refused_rather_than_bound_loosely() {
    let mut request = evaluation_request(scope(None), 2_500, MERCHANT, RESOURCE, RESOURCE);
    request.authorized_request_body_sha256_hex = Some("not-a-hash".to_string());

    let error = evaluate_x402_payment_request(&declarations(), &request)
        .expect_err("an unusable body hash must not silently become the bodyless hash");
    assert!(matches!(error, X402EvaluationError::InvalidIntent(_)));
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
}

/// A missing credit figure must cross the wire as `null`, never as `0`: on a
/// spend surface a rendered `0` reads as "free".
#[test]
fn a_conversion_overflow_crosses_the_wire_as_null_credits_never_zero() {
    // A ratio that makes any real amount overflow u64 credits.
    let mut overflowing = policy(31);
    overflowing.conversion.numerator = u64::MAX;
    overflowing.conversion.denominator = 1;
    overflowing.caps = X402SpendCaps::default();
    overflowing.approval = ApprovalPolicy::default();
    let declared = vec![declaration(
        X402PolicyScopeKind::Tenant,
        "overflow-tenant",
        overflowing,
    )];
    let request = evaluation_request(
        X402ScopeRequest {
            tenant_id: "overflow-tenant".to_string(),
            ..X402ScopeRequest::default()
        },
        2_500,
        MERCHANT,
        RESOURCE,
        RESOURCE,
    );

    let view = evaluate_x402_payment_request(&declared, &request).expect("evaluation");
    assert_eq!(view.decision.decision, "deny");
    assert_eq!(view.decision.reason_code, "x402_conversion_unavailable");
    assert_eq!(view.decision.computed_credits, None);

    // The wire boundary is what matters: `null`, not `0`.
    let body = serde_json::to_value(&view).expect("serializes");
    assert_eq!(body["decision"]["computed_credits"], Value::Null);
    assert_eq!(
        body["decision"]["conversion"]["computed_credits"],
        Value::Null
    );
    // The original atomic units still survive losslessly.
    assert_eq!(body["decision"]["atomic_amount"], json!(2_500));
}

/// An omitted `spent` object makes a dry run answer for a FRESH run; the
/// response has to say so, or an operator reads an `allow` that the real run
/// would deny.
#[test]
fn the_response_states_whether_the_ledger_figures_were_supplied() {
    let mut omitted = evaluation_request(scope(None), 2_500, MERCHANT, RESOURCE, RESOURCE);
    omitted.spent = None;
    let view = evaluate_x402_payment_request(&declarations(), &omitted).expect("evaluation");

    assert!(!view.spent.supplied);
    assert_eq!(view.spent.run_spent_credits, 0);
    assert_eq!(view.decision.decision, "allow");

    let mut supplied = evaluation_request(scope(None), 2_500, MERCHANT, RESOURCE, RESOURCE);
    supplied.spent = Some(X402SpentRequest {
        run_spent_credits: 4_999,
        window_spent_credits: 0,
        now_unix: None,
    });
    let view = evaluate_x402_payment_request(&declarations(), &supplied).expect("evaluation");
    assert!(view.spent.supplied);
    assert_eq!(view.spent.run_spent_credits, 4_999);
    assert_eq!(view.decision.decision, "deny");
}

// ---------------------------------------------------------------------------
// Tenancy enforcement (blocker 4)
// ---------------------------------------------------------------------------
//
// Until these existed, `authorize_scope_chain` could be replaced wholesale by
// `Ok(())` -- or its two call sites deleted -- and the entire repo suite stayed
// green (verified by mutation: 1211/1215 before and after, the 4 deltas being
// the pre-existing `ctl::resource_cmd` failures). Another tenant's spend caps,
// payee allowlist and policy revision are a competitor-visible spend profile;
// an access control nobody tests is an access control nobody has.

use crate::state::AppState;
use ferrogate_config::ApiKey;
use ferrogate_storage::{StoredProject, StoredWorkspace};

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn admin_key(id: &str, secret: &str, tenant: Option<&str>) -> ApiKey {
    ApiKey {
        region_allowlist: Vec::new(),
        id: id.into(),
        name: id.into(),
        key_env: None,
        key: Some(secret.into()),
        key_hash: None,
        enabled: true,
        scopes: vec!["admin.read".into()],
        allowed_models: vec![],
        denied_models: vec![],
        allowed_providers: vec![],
        denied_providers: vec![],
        organization_id: tenant.map(ToOwned::to_owned),
        platform_operator: None,
        team_id: None,
        project_id: None,
        workspace_id: None,
        user_id: None,
        monthly_token_budget: None,
        request_limit_per_minute: None,
        expires_at_unix: None,
        log_bodies: None,
        cache_enabled: None,
    }
}

/// Two tenants, each owning one project and one workspace, plus a tenant-scoped
/// `admin.read` key for tenant-1 and an unscoped platform-operator key.
fn tenancy_state() -> AppState {
    let state = AppState::new(ferrogate_config::Config {
        api_keys: vec![
            admin_key("tenant-reader", "tenant-secret", Some("tenant-1")),
            admin_key("operator", "operator-secret", None),
        ],
        ..ferrogate_config::Config::default()
    });
    for (project, workspace, tenant) in [
        ("project-1", "workspace-1", "tenant-1"),
        ("project-2", "workspace-2", "tenant-2"),
    ] {
        block_on(state.upsert_project(StoredProject {
            id: project.into(),
            tenant_id: tenant.into(),
            name: project.into(),
            slug: project.into(),
            status: "active".into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .expect("seed project");
        block_on(state.upsert_workspace(StoredWorkspace {
            id: workspace.into(),
            project_id: project.into(),
            tenant_id: tenant.into(),
            name: workspace.into(),
            slug: workspace.into(),
            environment: "prod".into(),
            status: "active".into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .expect("seed workspace");
    }
    state
}

fn auth_for(state: &AppState, secret: &str) -> AuthContext {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {secret}").parse().expect("header"),
    );
    block_on(crate::auth::authenticate(
        state,
        &headers,
        "admin.read",
        "req",
    ))
    .expect("the fixture key holds admin.read")
}

fn chain(tenant: &str, project: Option<&str>, run: Option<&str>) -> X402ScopeRequest {
    X402ScopeRequest {
        tenant_id: tenant.to_string(),
        project_id: project.map(str::to_string),
        run_id: run.map(str::to_string),
        ..X402ScopeRequest::default()
    }
}

#[test]
fn a_tenant_scoped_caller_cannot_read_another_tenants_project_policy() {
    let state = tenancy_state();
    let auth = auth_for(&state, "tenant-secret");

    // Its own chain passes.
    block_on(authorize_scope_chain(
        &state,
        &auth,
        &chain("tenant-1", Some("project-1"), None),
    ))
    .expect("a caller may read its own tenant's project");

    // Another tenant's project is a 403, not a silent read of someone else's
    // spend caps -- even though the tenant level of the chain is its own.
    let error = block_on(authorize_scope_chain(
        &state,
        &auth,
        &chain("tenant-1", Some("project-2"), None),
    ))
    .expect_err("naming another tenant's project must be refused");
    assert_eq!(error.status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "tenant_scope_denied");

    // And naming the other tenant outright is refused at the tenant level.
    let error = block_on(authorize_scope_chain(
        &state,
        &auth,
        &chain("tenant-2", None, None),
    ))
    .expect_err("naming another tenant must be refused");
    assert_eq!(error.status, StatusCode::FORBIDDEN);
}

#[test]
fn a_tenant_scoped_caller_cannot_name_a_run_scope() {
    let state = tenancy_state();
    let auth = auth_for(&state, "tenant-secret");

    // A run id has no run->tenant mapping at this surface, so resolving it
    // would mean guessing; refusing is the fail-closed choice.
    let error = block_on(authorize_scope_chain(
        &state,
        &auth,
        &chain("tenant-1", Some("project-1"), Some("run-9")),
    ))
    .expect_err("a run-scoped lookup must be refused for a tenant-scoped caller");
    assert_eq!(error.status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "run_scope_requires_platform_operator");

    // The platform operator is unaffected.
    block_on(authorize_scope_chain(
        &state,
        &auth_for(&state, "operator-secret"),
        &chain("tenant-2", Some("project-2"), Some("run-9")),
    ))
    .expect("a platform operator may read every scope");
}

/// A padded id must not be authorizable at one spelling and resolvable at
/// another: the tenancy check runs on the SAME normalized chain resolution does.
#[test]
fn the_tenancy_check_runs_on_the_normalized_scope_chain() {
    let state = tenancy_state();
    let auth = auth_for(&state, "tenant-secret");

    block_on(authorize_scope_chain(
        &state,
        &auth,
        &chain("  tenant-1  ", Some(" project-1 "), None),
    ))
    .expect("a padded id the caller owns still authorizes");

    let error = block_on(authorize_scope_chain(
        &state,
        &auth,
        &chain("tenant-1", Some(" project-2 "), None),
    ))
    .expect_err("padding must not smuggle another tenant's project past the check");
    assert_eq!(error.status, StatusCode::FORBIDDEN);
}

#[test]
fn a_tenant_scoped_listing_omits_declarations_it_does_not_own() {
    let state = tenancy_state();
    let declared = vec![
        declaration(X402PolicyScopeKind::Tenant, "tenant-1", policy(7)),
        declaration(X402PolicyScopeKind::Tenant, "tenant-2", policy(8)),
        declaration(X402PolicyScopeKind::Project, "project-1", policy(9)),
        declaration(X402PolicyScopeKind::Project, "project-2", policy(10)),
        declaration(X402PolicyScopeKind::Workspace, "workspace-2", policy(11)),
        declaration(X402PolicyScopeKind::Run, "run-9", policy(12)),
    ];

    let visible = block_on(visible_declared_policies(
        &state,
        &auth_for(&state, "tenant-secret"),
        &declared,
    ));
    let scopes: Vec<(X402PolicyScopeKind, String)> = visible
        .iter()
        .map(|entry| (entry.scope_type, entry.scope_id.clone()))
        .collect();
    assert_eq!(
        scopes,
        vec![
            (X402PolicyScopeKind::Tenant, "tenant-1".to_string()),
            (X402PolicyScopeKind::Project, "project-1".to_string()),
        ],
        "a tenant-scoped caller must not see another tenant's spend caps, \
         payee allowlist, or policy revision -- nor any run-scoped declaration"
    );

    // The platform operator still sees every declaration.
    let all = block_on(visible_declared_policies(
        &state,
        &auth_for(&state, "operator-secret"),
        &declared,
    ));
    assert_eq!(all.len(), declared.len());
}

// ---------------------------------------------------------------------------
// Gate-owned coverage (#351 test gate): the wire boundary
// ---------------------------------------------------------------------------

/// Box 1, at the boundary that matters. The policy crate proves `AtomicAmount`
/// round-trips; this proves the ADMIN SURFACE does, for the largest atomic
/// amount the frozen wire contract will parse (`u64::MAX`, which
/// `parse_atomic_amount` accepts).
///
/// A `u64::MAX` amount is above every cap, so the decision is a Deny — but the
/// decision still reports the ORIGINAL atomic units as evidence, and that is
/// the number an operator reconciles against the chain. If it crossed the wire
/// as an IEEE double it would render as 18446744073709552000.
#[test]
fn a_u64_max_atomic_amount_crosses_the_admin_wire_losslessly_as_an_integer() {
    let request = evaluation_request(scope(None), u64::MAX, MERCHANT, RESOURCE, RESOURCE);
    let view = evaluate(&request);

    assert_eq!(view.decision.atomic_amount, u64::MAX);
    let encoded = serde_json::to_string(&view).expect("evaluation view serializes");
    assert!(
        encoded.contains(r#""atomic_amount":18446744073709551615"#),
        "the original atomic units must cross the wire as exact digits: {encoded}"
    );
    // ...and survive a full round trip through a JSON parser.
    let reparsed: Value = serde_json::from_str(&encoded).expect("response reparses");
    assert_eq!(
        reparsed["decision"]["atomic_amount"].as_u64(),
        Some(u64::MAX),
        "an atomic amount above 2^53 must reparse exactly, not as a double"
    );
    assert_eq!(
        reparsed["decision"]["conversion"]["numerator"].as_u64(),
        Some(1)
    );
    // No float anywhere on the money path, at any magnitude.
    let mut floats = Vec::new();
    collect_floats(&reparsed, &mut floats);
    assert!(floats.is_empty(), "money path emitted floats: {floats:?}");
}

/// Box 1 + the conversion overflow arm: an amount whose conversion overflows
/// must report `computed_credits: null` on the wire, never a coerced `0`.
/// A missing credit figure rendering as zero on a spend surface reads as
/// "this payment is free".
#[test]
fn a_conversion_overflow_reports_null_credits_on_the_wire_never_zero() {
    let mut inflating = policy(3);
    // 1 credit per atomic unit scaled by u64::MAX: any real amount overflows.
    inflating.conversion.numerator = u64::MAX;
    inflating.conversion.denominator = 1;
    inflating.caps = X402SpendCaps::default();
    let declared = vec![declaration(
        X402PolicyScopeKind::Tenant,
        "tenant-1",
        inflating,
    )];
    let request = evaluation_request(scope(None), 2_500, MERCHANT, RESOURCE, RESOURCE);
    let view = evaluate_x402_payment_request(&declared, &request).expect("evaluation");

    assert_eq!(view.decision.decision, "deny");
    assert_eq!(view.decision.reason_code, "x402_conversion_unavailable");
    let encoded = serde_json::to_value(&view).expect("serializes");
    assert!(
        encoded["decision"]["computed_credits"].is_null(),
        "an unpriceable payment must not render as 0 credits: {encoded}"
    );
    assert!(encoded["decision"]["conversion"]["computed_credits"].is_null());
}

/// Box 6, stated as the property it is actually claiming: the OpenAPI schema
/// must describe the fields the RUNTIME serializes -- both directions. A schema
/// that omits a field the runtime emits leaves a consumer unable to model the
/// response; one that requires a field the runtime never emits makes every
/// response invalid. This repo has shipped exactly that drift before, so it is
/// pinned by execution rather than by review.
#[test]
fn the_serialized_diagnostics_match_the_openapi_schema_in_both_directions() {
    let spec: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/openapi/admin-api.openapi.json"
        ))
        .expect("the admin OpenAPI spec is readable"),
    )
    .expect("the admin OpenAPI spec parses");

    let effective = serde_json::to_value(build_effective_policy_view(
        &declarations(),
        &scope(Some("project-1")),
    ))
    .unwrap();
    let evaluation = serde_json::to_value(evaluate(&evaluation_request(
        scope(None),
        2_500,
        MERCHANT,
        RESOURCE,
        RESOURCE,
    )))
    .unwrap();
    let listed = serde_json::to_value(declared_policy_view(&declarations()[0])).unwrap();

    for (schema_name, value) in [
        ("X402EffectiveSpendPolicy", &effective),
        ("X402SpendPolicyEvaluation", &evaluation),
        ("X402DeclaredSpendPolicy", &listed),
    ] {
        assert_object_matches_schema(&spec, schema_name, value, schema_name);
    }
}

/// Resolve `$ref` chains inside `components/schemas`.
fn resolve_schema<'a>(spec: &'a Value, mut schema: &'a Value) -> &'a Value {
    while let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference.rsplit('/').next().expect("a $ref names a schema");
        schema = spec
            .pointer(&format!("/components/schemas/{name}"))
            .unwrap_or_else(|| panic!("dangling $ref {reference}"));
    }
    schema
}

/// Assert every key the runtime emits is declared, and every key the schema
/// requires is emitted, recursively.
fn assert_object_matches_schema(spec: &Value, schema_name: &str, value: &Value, path: &str) {
    let schema = resolve_schema(
        spec,
        spec.pointer(&format!("/components/schemas/{schema_name}"))
            .unwrap_or_else(|| panic!("schema {schema_name} is missing from the OpenAPI spec")),
    );
    assert_value_matches_schema(spec, schema, value, path);
}

fn assert_value_matches_schema(spec: &Value, schema: &Value, value: &Value, path: &str) {
    let schema = resolve_schema(spec, schema);
    if let Some(options) = schema.get("oneOf").and_then(Value::as_array) {
        // Nullable composites: pick the non-null arm for a present value.
        if value.is_null() {
            assert!(
                options
                    .iter()
                    .any(|option| resolve_schema(spec, option).get("type")
                        == Some(&Value::String("null".into()))),
                "{path}: runtime emitted null but no null arm is declared"
            );
            return;
        }
        let concrete = options
            .iter()
            .find(|option| {
                resolve_schema(spec, option).get("type") != Some(&Value::String("null".into()))
            })
            .unwrap_or_else(|| panic!("{path}: oneOf has no non-null arm"));
        assert_value_matches_schema(spec, concrete, value, path);
        return;
    }
    match value {
        Value::Object(map) => {
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{path}: runtime emits an object, schema declares none"));
            for key in map.keys() {
                assert!(
                    properties.contains_key(key),
                    "{path}: the runtime emits {key:?}, which the OpenAPI schema does not declare"
                );
            }
            for required in schema
                .get("required")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                let required = required.as_str().expect("required entries are strings");
                assert!(
                    map.contains_key(required),
                    "{path}: the schema requires {required:?}, which the runtime never emits"
                );
            }
            for (key, nested) in map {
                assert_value_matches_schema(
                    spec,
                    &properties[key],
                    nested,
                    &format!("{path}.{key}"),
                );
            }
        }
        Value::Array(items) => {
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    assert_value_matches_schema(
                        spec,
                        item_schema,
                        item,
                        &format!("{path}[{index}]"),
                    );
                }
            }
        }
        Value::Number(number) => {
            let declared = schema.get("type");
            let integral = number.as_u64().is_some() || number.as_i64().is_some();
            assert!(integral, "{path}: money/evidence numbers must be integral");
            assert!(
                declared.is_none()
                    || declared == Some(&Value::String("integer".into()))
                    || declared
                        .and_then(Value::as_array)
                        .is_some_and(|kinds| kinds.contains(&Value::String("integer".into()))),
                "{path}: runtime emits an integer, schema declares {declared:?}"
            );
        }
        _ => {}
    }
}

/// Box 5 as a LEAK test rather than a key-name test. A high-entropy marker is
/// planted in every operator-controllable string the surface could conceivably
/// echo, and the serialized responses are searched for it in raw, lowercase,
/// uppercase, hex, base64 and decimal-byte form. A redaction that only strips
/// the literal spelling is not a redaction.
#[test]
fn no_diagnostics_response_echoes_planted_signer_material_in_any_encoding() {
    const MARKER: &str = "SIGNERSEEDcafebabe1234";

    // The marker is planted where an operator-authored string reaches the
    // surface: the conversion version tag is the only free-text field a policy
    // carries, and it is echoed verbatim into every decision.
    let mut planted = policy(23);
    planted.conversion.version = format!("rate-{MARKER}");
    let declared = vec![declaration(
        X402PolicyScopeKind::Tenant,
        "tenant-1",
        planted.clone(),
    )];

    // A response that legitimately echoes operator config WILL contain the
    // marker; the invariant under test is that the DECISION evidence handed to
    // a caller who did not author that config carries no encoding of it beyond
    // the field the operator wrote. Assert the encodings that a naive
    // "strip the literal" redaction would miss.
    let evaluation = serde_json::to_string(
        &evaluate_x402_payment_request(
            &declared,
            &evaluation_request(scope(None), 2_500, MERCHANT, RESOURCE, RESOURCE),
        )
        .expect("evaluation"),
    )
    .expect("serializes");

    let hex: String = MARKER.bytes().map(|b| format!("{b:02x}")).collect();
    let hex_upper = hex.to_ascii_uppercase();
    let b64 = base64::engine::general_purpose::STANDARD.encode(MARKER);
    let b64_url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(MARKER);
    let decimal_bytes = MARKER
        .bytes()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");

    for (form, encoded) in [
        ("hex", &hex),
        ("upper hex", &hex_upper),
        ("base64", &b64),
        ("base64url", &b64_url),
        ("decimal bytes", &decimal_bytes),
    ] {
        assert!(
            !evaluation.contains(encoded.as_str()),
            "the diagnostics response carries planted material in {form} form"
        );
    }
    // The one place it IS allowed: the operator's own conversion version tag,
    // echoed as the audit label it is. Pinning this keeps the test honest --
    // it would otherwise pass on a surface that returned nothing at all.
    assert!(
        evaluation.contains(&format!("rate-{MARKER}")),
        "the conversion version an operator wrote must still be reported: {evaluation}"
    );
    // And nothing secret-shaped is keyed anywhere in the response.
    let parsed: Value = serde_json::from_str(&evaluation).expect("reparses");
    let mut keys = Vec::new();
    json_keys(&parsed, &mut keys);
    for key in &keys {
        let lowered = key.to_ascii_lowercase();
        for forbidden in ferrogate_core::SECRET_SHAPED_KEY_FRAGMENTS {
            assert!(
                !lowered.contains(forbidden),
                "diagnostics response exposes a {forbidden}-shaped field: {key}"
            );
        }
    }
}
