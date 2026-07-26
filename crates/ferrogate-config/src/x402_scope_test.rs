// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Tests for scoped x402 spend-policy precedence/inheritance
// (issue #351): narrowest declared scope wins across tenant/project/workspace/
// key/agent-run, unconfigured chains fall back to the disabled deny-all default,
// and a declaration set with duplicates/empty ids/invalid policies is rejected
// at load. Sibling test file per AGENTS.md (no inline `mod tests {}`).

use super::*;

const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const RECIPIENT_A: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

use ferrogate_policy::{
    AllowedAsset, ApprovalPolicy, ConversionRule, PolicyNetwork, ResourceRule, Rounding,
    X402SpendCaps,
};

/// An enabled devnet policy carrying `revision` so a resolution result can be
/// identified by which declaration produced it.
fn policy(revision: u64) -> X402SpendPolicy {
    X402SpendPolicy {
        enabled: true,
        revision,
        allowed_networks: vec![PolicyNetwork::DEVNET],
        allowed_assets: vec![AllowedAsset {
            network: PolicyNetwork::DEVNET,
            mint: USDC_DEVNET.to_string(),
        }],
        allowed_recipients: vec![RECIPIENT_A.to_string()],
        allowed_resources: vec![ResourceRule {
            origin: "https://api.example.com".to_string(),
            path_prefix: "/paid".to_string(),
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
    revision: u64,
) -> X402ScopedSpendPolicy {
    X402ScopedSpendPolicy {
        scope_type,
        scope_id: scope_id.to_string(),
        policy: X402SpendPolicyConfig::from(policy(revision)),
    }
}

/// One declaration at every level, each with a distinct revision so the winner
/// is unambiguous.
fn full_chain_declarations() -> Vec<X402ScopedSpendPolicy> {
    vec![
        declaration(X402PolicyScopeKind::Tenant, "tenant-1", 1),
        declaration(X402PolicyScopeKind::Project, "project-1", 2),
        declaration(X402PolicyScopeKind::Workspace, "workspace-1", 3),
        declaration(X402PolicyScopeKind::Key, "key-1", 4),
        declaration(X402PolicyScopeKind::Run, "run-1", 5),
    ]
}

fn chain<'a>(
    project: Option<&'a str>,
    workspace: Option<&'a str>,
    key: Option<&'a str>,
    run: Option<&'a str>,
) -> X402ScopeChain<'a> {
    X402ScopeChain {
        tenant_id: "tenant-1",
        project_id: project,
        workspace_id: workspace,
        key_id: key,
        run_id: run,
    }
}

#[test]
fn the_narrowest_declared_scope_wins_at_every_level() {
    let declared = full_chain_declarations();
    let cases = [
        (
            chain(None, None, None, None),
            1,
            X402PolicyScopeKind::Tenant,
        ),
        (
            chain(Some("project-1"), None, None, None),
            2,
            X402PolicyScopeKind::Project,
        ),
        (
            chain(Some("project-1"), Some("workspace-1"), None, None),
            3,
            X402PolicyScopeKind::Workspace,
        ),
        (
            chain(Some("project-1"), Some("workspace-1"), Some("key-1"), None),
            4,
            X402PolicyScopeKind::Key,
        ),
        (
            chain(
                Some("project-1"),
                Some("workspace-1"),
                Some("key-1"),
                Some("run-1"),
            ),
            5,
            X402PolicyScopeKind::Run,
        ),
    ];

    for (chain, expected_revision, expected_scope) in cases {
        let effective = resolve_effective_x402_spend_policy(&declared, &chain);
        assert_eq!(
            effective.revision(),
            expected_revision,
            "chain {chain:?} resolved to the wrong declaration"
        );
        assert_eq!(
            effective.source.as_ref().map(|source| source.scope_type),
            Some(expected_scope)
        );
    }
}

#[test]
fn a_narrower_scope_without_a_declaration_inherits_the_nearest_declared_parent() {
    let declared = vec![declaration(X402PolicyScopeKind::Tenant, "tenant-1", 1)];

    let effective = resolve_effective_x402_spend_policy(
        &declared,
        &chain(
            Some("project-1"),
            Some("workspace-1"),
            Some("key-1"),
            Some("run-1"),
        ),
    );

    assert_eq!(effective.revision(), 1);
    assert_eq!(
        effective.source,
        Some(X402PolicyScopeRef {
            scope_type: X402PolicyScopeKind::Tenant,
            scope_id: "tenant-1".to_string(),
        })
    );
}

#[test]
fn an_id_declared_at_a_different_scope_kind_never_matches() {
    // Same id string, wrong scope kind: a project declaration must not satisfy
    // a workspace lookup.
    let declared = vec![declaration(X402PolicyScopeKind::Project, "shared-id", 9)];

    let effective = resolve_effective_x402_spend_policy(
        &declared,
        &X402ScopeChain {
            tenant_id: "tenant-1",
            project_id: None,
            workspace_id: Some("shared-id"),
            key_id: None,
            run_id: None,
        },
    );

    assert!(!effective.is_declared());
    assert!(!effective.policy.enabled);
}

#[test]
fn an_unconfigured_chain_resolves_to_the_disabled_deny_all_default() {
    let effective = resolve_effective_x402_spend_policy(&[], &X402ScopeChain::tenant("tenant-1"));

    assert!(!effective.is_declared());
    assert!(!effective.policy.enabled);
    assert_eq!(effective.revision(), 0);
    assert!(effective.policy.allowed_networks.is_empty());
    assert!(effective.policy.allowed_assets.is_empty());
    assert!(effective.policy.allowed_recipients.is_empty());
    // The disabled default must still validate, so the runtime always has a
    // policy object to evaluate (and always denies).
    effective
        .validate()
        .expect("the disabled default must always validate");
}

#[test]
fn resolution_is_deterministic_regardless_of_declaration_order() {
    let mut reversed = full_chain_declarations();
    reversed.reverse();

    let chain = chain(
        Some("project-1"),
        Some("workspace-1"),
        Some("key-1"),
        Some("run-1"),
    );
    let forward = resolve_effective_x402_spend_policy(&full_chain_declarations(), &chain);
    let backward = resolve_effective_x402_spend_policy(&reversed, &chain);

    assert_eq!(forward, backward);
    assert_eq!(forward.revision(), 5);
}

#[test]
fn the_effective_policy_validates_into_the_type_the_decision_function_accepts() {
    let declared = full_chain_declarations();
    let effective =
        resolve_effective_x402_spend_policy(&declared, &chain(Some("project-1"), None, None, None));

    let validated = effective.validate().expect("declared policy must validate");
    assert_eq!(validated.policy().revision, 2);
}

#[test]
fn duplicate_scope_declarations_are_rejected_at_load() {
    let declared = vec![
        declaration(X402PolicyScopeKind::Tenant, "tenant-1", 1),
        declaration(X402PolicyScopeKind::Tenant, "tenant-1", 2),
    ];

    let error = validate_scoped_x402_spend_policies(&declared)
        .expect_err("a duplicate scope declaration must be rejected");
    assert_eq!(
        error,
        X402ScopedPolicyError::DuplicateScope {
            scope_type: X402PolicyScopeKind::Tenant,
            scope_id: "tenant-1".to_string(),
        }
    );
}

#[test]
fn an_empty_scope_id_is_rejected_at_load() {
    let declared = vec![declaration(X402PolicyScopeKind::Project, "   ", 1)];

    let error = validate_scoped_x402_spend_policies(&declared)
        .expect_err("an empty scope id must be rejected");
    assert_eq!(
        error,
        X402ScopedPolicyError::EmptyScopeId {
            scope_type: X402PolicyScopeKind::Project,
        }
    );
}

#[test]
fn an_invalid_declared_policy_is_rejected_at_load_with_the_policy_crates_own_error() {
    let mut broken = policy(3);
    // A token symbol where a canonical base58 mint is required.
    broken.allowed_assets[0].mint = "USDC".to_string();
    let declared = vec![X402ScopedSpendPolicy {
        scope_type: X402PolicyScopeKind::Workspace,
        scope_id: "workspace-1".to_string(),
        policy: X402SpendPolicyConfig::from(broken),
    }];

    let error = validate_scoped_x402_spend_policies(&declared)
        .expect_err("a token-symbol mint must be rejected");
    assert!(matches!(
        error,
        X402ScopedPolicyError::Invalid {
            scope_type: X402PolicyScopeKind::Workspace,
            ref scope_id,
            error: X402PolicyConfigError::TokenSymbolMint { .. },
        } if scope_id == "workspace-1"
    ));
}

#[test]
fn a_well_formed_declaration_set_passes_load_validation() {
    validate_scoped_x402_spend_policies(&full_chain_declarations())
        .expect("a well-formed declaration set must load");
}

#[test]
fn scoped_declarations_round_trip_through_toml_config() {
    let raw = r#"
[[x402_spend_policies]]
scope_type = "project"
scope_id = "project-1"

[x402_spend_policies.policy]
enabled = true
revision = 12
allowed_networks = ["solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"]
allowed_recipients = ["9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"]

[[x402_spend_policies.policy.allowed_assets]]
network = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
mint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

[[x402_spend_policies.policy.allowed_resources]]
origin = "https://api.example.com"
path_prefix = "/paid"

[x402_spend_policies.policy.caps]
max_credits_per_payment = 1000

[x402_spend_policies.policy.conversion]
numerator = 1
denominator = 1000
rounding = "up"
version = "usdc-devnet-v1"

[x402_spend_policies.policy.approval]
threshold_credits = 500
"#;

    #[derive(serde::Deserialize)]
    struct Document {
        x402_spend_policies: Vec<X402ScopedSpendPolicy>,
    }

    let document: Document = toml::from_str(raw).expect("scoped policy document must parse");
    validate_scoped_x402_spend_policies(&document.x402_spend_policies)
        .expect("parsed declarations must validate");

    let effective = resolve_effective_x402_spend_policy(
        &document.x402_spend_policies,
        &X402ScopeChain {
            tenant_id: "tenant-1",
            project_id: Some("project-1"),
            workspace_id: Some("workspace-1"),
            key_id: None,
            run_id: None,
        },
    );
    assert_eq!(effective.revision(), 12);
    assert_eq!(
        effective
            .source
            .as_ref()
            .map(|source| source.scope_id.as_str()),
        Some("project-1")
    );
}

#[test]
fn scope_kind_names_round_trip_and_reject_unknown_values() {
    for kind in X402PolicyScopeKind::ALL {
        assert_eq!(
            X402PolicyScopeKind::from_str_exact(kind.as_str()),
            Some(kind)
        );
    }
    assert_eq!(X402PolicyScopeKind::from_str_exact("organization"), None);
    assert_eq!(X402PolicyScopeKind::from_str_exact(""), None);
}

/// Declaration validation trimmed `scope_id` while resolution matched the raw
/// string, so `scope_id = " acme "` loaded clean, listed on the admin surface,
/// and could never be resolved by any request -- a permanently inert money
/// policy the operator had every reason to believe was in force.
#[test]
fn a_padded_declaration_resolves_for_the_unpadded_request() {
    let declared = vec![X402ScopedSpendPolicy {
        scope_type: X402PolicyScopeKind::Tenant,
        scope_id: "  acme  ".to_string(),
        policy: X402SpendPolicyConfig::from(policy(21)),
    }];
    validate_scoped_x402_spend_policies(&declared).expect("a padded declaration loads");

    let effective = resolve_effective_x402_spend_policy(&declared, &X402ScopeChain::tenant("acme"));

    assert!(effective.is_declared());
    assert_eq!(effective.revision(), 21);
    assert_eq!(
        effective
            .source
            .as_ref()
            .map(|source| source.scope_id.as_str()),
        Some("acme"),
        "the resolution evidence must name the id a request can actually send"
    );
}

/// The request side is normalized too, so a padded request id reaches an
/// unpadded declaration.
#[test]
fn a_padded_request_resolves_the_unpadded_declaration() {
    let declared = vec![X402ScopedSpendPolicy {
        scope_type: X402PolicyScopeKind::Project,
        scope_id: "proj-1".to_string(),
        policy: X402SpendPolicyConfig::from(policy(31)),
    }];

    let padded = resolve_effective_x402_spend_policy(
        &declared,
        &X402ScopeChain {
            tenant_id: " tenant-1 ",
            project_id: Some("\tproj-1 "),
            ..X402ScopeChain::default()
        },
    );
    let exact = resolve_effective_x402_spend_policy(
        &declared,
        &X402ScopeChain {
            tenant_id: "tenant-1",
            project_id: Some("proj-1"),
            ..X402ScopeChain::default()
        },
    );

    assert_eq!(padded, exact);
    assert_eq!(padded.revision(), 31);
}

/// A narrower level whose id is blank is absent, not an empty-id scope: an
/// empty id can never match a declaration (validation rejects those), so
/// carrying it would only pollute the inheritance evidence.
#[test]
fn a_blank_narrower_level_is_omitted_from_the_chain() {
    let chain = X402ScopeChain {
        tenant_id: " tenant-1 ",
        project_id: Some("   "),
        workspace_id: Some("ws-1"),
        ..X402ScopeChain::default()
    };

    assert_eq!(
        chain.levels(),
        vec![
            (X402PolicyScopeKind::Tenant, "tenant-1"),
            (X402PolicyScopeKind::Workspace, "ws-1"),
        ]
    );
}

/// Two declarations that differ only by padding are ONE scope, and a config
/// that declares both is ambiguous rather than "the first one wins".
#[test]
fn declarations_differing_only_by_padding_are_a_duplicate_scope() {
    let declared = vec![
        X402ScopedSpendPolicy {
            scope_type: X402PolicyScopeKind::Tenant,
            scope_id: "acme".to_string(),
            policy: X402SpendPolicyConfig::from(policy(1)),
        },
        X402ScopedSpendPolicy {
            scope_type: X402PolicyScopeKind::Tenant,
            scope_id: " acme ".to_string(),
            policy: X402SpendPolicyConfig::from(policy(2)),
        },
    ];

    assert!(matches!(
        validate_scoped_x402_spend_policies(&declared),
        Err(X402ScopedPolicyError::DuplicateScope { .. })
    ));
}

// --- Gate-owned coverage (#351 test gate): the documented tie rule ---

/// `resolve_effective_x402_spend_policy` documents that a tie within one scope
/// level "resolves to the FIRST declaration, so behaviour is still defined for
/// a config that somehow bypassed validation". Load validation rejects such a
/// set, so the rule is only reachable by calling resolution directly — which
/// means nothing pinned it, and swapping `find` for a reverse search left the
/// whole suite green. A documented determinism guarantee on a money surface has
/// to be executable, or it is a comment.
#[test]
fn a_tie_at_one_scope_level_deterministically_resolves_to_the_first_declaration() {
    let first = declaration(X402PolicyScopeKind::Tenant, "tenant-1", 7);
    let second = declaration(X402PolicyScopeKind::Tenant, "tenant-1", 99);
    let declared = vec![first, second];

    // The tie is exactly what load validation exists to prevent...
    assert!(matches!(
        validate_scoped_x402_spend_policies(&declared),
        Err(X402ScopedPolicyError::DuplicateScope { .. })
    ));

    // ...but if one ever reaches resolution, the answer is defined and stable.
    let chain = X402ScopeChain::tenant("tenant-1");
    let resolved = resolve_effective_x402_spend_policy(&declared, &chain);
    assert_eq!(
        resolved.revision(),
        7,
        "the first declaration wins a tie, deterministically"
    );
    // Repeat and reverse to show the answer is a property of order, not of
    // hashing or iteration nondeterminism.
    assert_eq!(
        resolve_effective_x402_spend_policy(&declared, &chain).revision(),
        7
    );
    let reversed: Vec<_> = declared.iter().rev().cloned().collect();
    assert_eq!(
        resolve_effective_x402_spend_policy(&reversed, &chain).revision(),
        99,
        "order is the whole tie-break rule, so reversing it must flip the answer"
    );
}

/// Precedence must be a TOTAL order over the five levels: for every declared
/// level, a request naming the full chain resolves to that level when it is the
/// narrowest declared one, and every narrower-wins pair is consistent.
#[test]
fn precedence_is_a_total_order_over_all_five_levels() {
    let all = X402PolicyScopeKind::ALL;
    assert_eq!(all.len(), 5);
    // Declare at every level with a revision equal to its precedence rank, so
    // the resolved revision names the level that won.
    let ids = ["tenant-1", "project-1", "workspace-1", "key-1", "run-1"];
    let full = X402ScopeChain {
        tenant_id: ids[0],
        project_id: Some(ids[1]),
        workspace_id: Some(ids[2]),
        key_id: Some(ids[3]),
        run_id: Some(ids[4]),
    };
    // Progressively drop the narrowest declaration; the next-narrowest must win
    // each time, and the last drop must fall back to the disabled default.
    for cut in (0..=all.len()).rev() {
        let declared: Vec<_> = (0..cut)
            .map(|rank| declaration(all[rank], ids[rank], rank as u64 + 1))
            .collect();
        let resolved = resolve_effective_x402_spend_policy(&declared, &full);
        if cut == 0 {
            assert!(!resolved.is_declared());
            assert!(
                !resolved.policy.enabled,
                "the fallback must deny everything"
            );
            assert_eq!(resolved.revision(), 0);
        } else {
            assert_eq!(
                resolved.revision(),
                cut as u64,
                "with {cut} levels declared, the narrowest declared one must win"
            );
            assert_eq!(
                resolved.source.as_ref().map(|s| s.scope_type),
                Some(all[cut - 1])
            );
        }
    }
}
