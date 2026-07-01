// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Scenario + property coverage for the policy decision boundary (#104).

use ferrogate_core::{RequestContext, TenantContext};
use ferrogate_policy::{
    BasicPolicyEngine, PolicyDecision, PolicyEngine, PolicyRule, PolicySubject,
};
use proptest::prelude::*;

fn request(org: &str, project: &str, key: &str) -> RequestContext {
    RequestContext {
        tenant: TenantContext {
            organization_id: Some(org.to_string()),
            team_id: None,
            project_id: Some(project.to_string()),
            user_id: None,
            api_key_id: Some(key.to_string()),
        },
        ..RequestContext::default()
    }
}

fn deny_rule(subject: PolicySubject, models: Vec<&str>, providers: Vec<&str>) -> PolicyRule {
    PolicyRule::deny(
        subject,
        models.into_iter().map(String::from).collect(),
        providers.into_iter().map(String::from).collect(),
        "policy_denied",
        "blocked by policy",
    )
}

#[test]
fn empty_engine_allows_everything() {
    let engine = BasicPolicyEngine::default();
    assert_eq!(
        engine.evaluate(&request("o", "p", "k"), Some("m"), Some("prov")),
        PolicyDecision::Allow
    );
    assert_eq!(
        engine.evaluate(&request("o", "p", "k"), None, None),
        PolicyDecision::Allow
    );
}

#[test]
fn first_matching_deny_rule_wins() {
    let engine = BasicPolicyEngine::new(vec![
        deny_rule(
            PolicySubject {
                organization_id: Some("org".into()),
                project_id: None,
                api_key_id: None,
            },
            vec![],
            vec![],
        ),
        PolicyRule::deny(
            PolicySubject::default(),
            vec![],
            vec![],
            "second_rule",
            "second",
        ),
    ]);
    // The first rule matches org and denies; its code must be the one returned.
    match engine.evaluate(&request("org", "p", "k"), Some("m"), Some("prov")) {
        PolicyDecision::Deny { code, .. } => assert_eq!(code, "policy_denied"),
        other => panic!("expected deny, got {other:?}"),
    }
}

#[test]
fn subject_scoping_matches_only_the_named_tenant() {
    let engine = BasicPolicyEngine::new(vec![deny_rule(
        PolicySubject {
            organization_id: Some("org".into()),
            project_id: Some("project".into()),
            api_key_id: Some("key".into()),
        },
        vec![],
        vec![],
    )]);
    // Exact subject -> denied.
    assert!(matches!(
        engine.evaluate(&request("org", "project", "key"), Some("m"), Some("p")),
        PolicyDecision::Deny { .. }
    ));
    // Different org -> rule does not apply -> allowed.
    assert_eq!(
        engine.evaluate(&request("other", "project", "key"), Some("m"), Some("p")),
        PolicyDecision::Allow
    );
}

#[test]
fn model_and_provider_lists_scope_the_rule() {
    let engine = BasicPolicyEngine::new(vec![deny_rule(
        PolicySubject::default(),
        vec!["gpt-4o", "fast-chat"],
        vec!["openai"],
    )]);
    // Listed model + provider -> denied.
    assert!(matches!(
        engine.evaluate(&request("o", "p", "k"), Some("fast-chat"), Some("openai")),
        PolicyDecision::Deny { .. }
    ));
    // Listed model, other provider -> not matched -> allowed.
    assert_eq!(
        engine.evaluate(
            &request("o", "p", "k"),
            Some("fast-chat"),
            Some("anthropic")
        ),
        PolicyDecision::Allow
    );
    // A rule that constrains model must not match a request with no model.
    assert_eq!(
        engine.evaluate(&request("o", "p", "k"), None, Some("openai")),
        PolicyDecision::Allow
    );
}

proptest! {
    // Invariant: a deny rule whose subject/model/provider constraints all match
    // the request always denies, regardless of the concrete values.
    #[test]
    fn matching_deny_rule_always_denies(
        org in "[a-z]{1,8}",
        model in "[a-z0-9-]{1,10}",
        provider in "[a-z]{1,8}",
    ) {
        let engine = BasicPolicyEngine::new(vec![deny_rule(
            PolicySubject { organization_id: Some(org.clone()), project_id: None, api_key_id: None },
            vec![model.as_str()],
            vec![provider.as_str()],
        )]);
        let denied = matches!(
            engine.evaluate(&request(&org, "proj", "key"), Some(&model), Some(&provider)),
            PolicyDecision::Deny { .. }
        );
        prop_assert!(denied);
    }

    // Invariant: with no rules, every request is allowed.
    #[test]
    fn no_rules_always_allows(
        org in "[a-z]{1,8}",
        model in prop::option::of("[a-z0-9-]{1,10}"),
    ) {
        let engine = BasicPolicyEngine::default();
        prop_assert_eq!(
            engine.evaluate(&request(&org, "p", "k"), model.as_deref(), None),
            PolicyDecision::Allow
        );
    }

    // Invariant: a deny rule scoped to one org never denies a different org.
    #[test]
    fn deny_rule_never_affects_other_orgs(
        rule_org in "[a-z]{1,8}",
        req_org in "[a-z]{1,8}",
    ) {
        prop_assume!(rule_org != req_org);
        let engine = BasicPolicyEngine::new(vec![deny_rule(
            PolicySubject { organization_id: Some(rule_org), project_id: None, api_key_id: None },
            vec![],
            vec![],
        )]);
        prop_assert_eq!(
            engine.evaluate(&request(&req_org, "p", "k"), Some("m"), Some("prov")),
            PolicyDecision::Allow
        );
    }
}
