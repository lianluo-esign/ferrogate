// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-04
// description: Multi-level quota/rate-limit policy resolution (P1-3): merges
// tenant/project/workspace/key scope policies into one effective quota.

use ferrogate_storage::{QuotaScopeKind, StoredPlan, StoredQuotaPolicy};

/// The scope chain a request resolves to. Any level may be absent (e.g. a
/// request authenticated through a key that predates the workspace
/// hierarchy).
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaScopeChain<'a> {
    pub tenant_id: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub workspace_id: Option<&'a str>,
    pub key_id: Option<&'a str>,
}

/// The result of merging every defined policy across a scope chain.
///
/// - `model_allowlist = None` means no scope in the chain restricts models
///   (missing config = unrestricted); `Some(list)` is the intersection of
///   every scope that defines a non-empty allowlist.
/// - `rpm_limit` / `tpm_limit` / `monthly_budget_usd` are each the minimum
///   (tightest) value defined across the chain. This is the same thing as
///   "the nearest-to-the-request scope overrides, but can never exceed an
///   ancestor's cap" -- because `min` is commutative/associative, the two
///   framings always produce the same number, and `min`-across-the-chain is
///   simpler to implement and to verify.
/// - `denied_by = Some(scope)` means some scope in the chain has
///   `enabled = false`; the caller must fail closed regardless of the other
///   fields (they are left at their defaults when this is set).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EffectiveQuota {
    pub model_allowlist: Option<Vec<String>>,
    pub rpm_limit: Option<u64>,
    pub tpm_limit: Option<u64>,
    pub monthly_budget_usd: Option<f64>,
    pub denied_by: Option<QuotaScopeKind>,
}

impl EffectiveQuota {
    pub fn is_denied(&self) -> bool {
        self.denied_by.is_some()
    }

    pub fn allows_model(&self, model: &str) -> bool {
        self.model_allowlist
            .as_ref()
            .is_none_or(|allowlist| allowlist.iter().any(|allowed| allowed == model))
    }
}

/// Resolve the effective quota for one request's scope chain. `lookup` is
/// injected so callers can source policies from any backend (durable storage
/// in production, an in-memory map in tests) without this module depending
/// on how policies are fetched.
///
/// `plan` (issue #168) supplies the *floor* of the merge: a field is only
/// taken from the plan when no `StoredQuotaPolicy` in the chain sets it at
/// all. A plan can never make an explicit policy value tighter or looser --
/// it only fills in what would otherwise be unrestricted. This mirrors how a
/// plan is meant to be a sellable default bundle, not another cap layer
/// competing with the existing tenant/project/workspace/key `min`-across-
/// the-chain rule.
pub fn resolve_effective_quota(
    chain: QuotaScopeChain<'_>,
    lookup: impl Fn(QuotaScopeKind, &str) -> Option<StoredQuotaPolicy>,
    plan: Option<&StoredPlan>,
) -> EffectiveQuota {
    let scopes: [(QuotaScopeKind, Option<&str>); 4] = [
        (QuotaScopeKind::Tenant, chain.tenant_id),
        (QuotaScopeKind::Project, chain.project_id),
        (QuotaScopeKind::Workspace, chain.workspace_id),
        (QuotaScopeKind::Key, chain.key_id),
    ];
    let policies: Vec<StoredQuotaPolicy> = scopes
        .into_iter()
        .filter_map(|(scope_type, scope_id)| scope_id.and_then(|id| lookup(scope_type, id)))
        .collect();

    if let Some(disabled) = policies.iter().find(|policy| !policy.enabled) {
        return EffectiveQuota {
            denied_by: Some(disabled.scope_type),
            ..EffectiveQuota::default()
        };
    }

    let mut effective = EffectiveQuota::default();
    for policy in &policies {
        if !policy.model_allowlist.is_empty() {
            effective.model_allowlist = Some(match effective.model_allowlist.take() {
                Some(existing) => existing
                    .into_iter()
                    .filter(|model| policy.model_allowlist.contains(model))
                    .collect(),
                None => policy.model_allowlist.clone(),
            });
        }
        effective.rpm_limit = min_opt_u64(effective.rpm_limit, policy.rpm_limit);
        effective.tpm_limit = min_opt_u64(effective.tpm_limit, policy.tpm_limit);
        effective.monthly_budget_usd =
            min_opt_f64(effective.monthly_budget_usd, policy.monthly_budget_usd);
    }
    if let Some(plan) = plan {
        if effective.model_allowlist.is_none() && !plan.default_model_allowlist.is_empty() {
            effective.model_allowlist = Some(plan.default_model_allowlist.clone());
        }
        effective.rpm_limit = effective.rpm_limit.or(plan.default_rpm_limit);
        effective.tpm_limit = effective.tpm_limit.or(plan.default_tpm_limit);
        effective.monthly_budget_usd = effective
            .monthly_budget_usd
            .or(plan.default_monthly_budget_usd);
    }
    effective
}

fn min_opt_u64(existing: Option<u64>, next: Option<u64>) -> Option<u64> {
    match (existing, next) {
        (Some(existing), Some(next)) => Some(existing.min(next)),
        (Some(existing), None) => Some(existing),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

fn min_opt_f64(existing: Option<f64>, next: Option<f64>) -> Option<f64> {
    match (existing, next) {
        (Some(existing), Some(next)) => Some(existing.min(next)),
        (Some(existing), None) => Some(existing),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn policy(
        scope_type: QuotaScopeKind,
        scope_id: &str,
        model_allowlist: Vec<&str>,
        rpm_limit: Option<u64>,
        tpm_limit: Option<u64>,
        monthly_budget_usd: Option<f64>,
        enabled: bool,
    ) -> StoredQuotaPolicy {
        StoredQuotaPolicy {
            id: format!("{}:{scope_id}", scope_type.as_str()),
            scope_type,
            scope_id: scope_id.to_string(),
            model_allowlist: model_allowlist.into_iter().map(String::from).collect(),
            rpm_limit,
            tpm_limit,
            monthly_budget_usd,
            enabled,
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    fn lookup_from(
        policies: Vec<StoredQuotaPolicy>,
    ) -> impl Fn(QuotaScopeKind, &str) -> Option<StoredQuotaPolicy> {
        let map: HashMap<(QuotaScopeKind, String), StoredQuotaPolicy> = policies
            .into_iter()
            .map(|policy| ((policy.scope_type, policy.scope_id.clone()), policy))
            .collect();
        move |scope_type, scope_id| map.get(&(scope_type, scope_id.to_string())).cloned()
    }

    #[test]
    fn missing_policy_everywhere_is_unrestricted() {
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: Some("p1"),
                workspace_id: Some("w1"),
                key_id: Some("k1"),
            },
            lookup_from(vec![]),
            None,
        );
        assert!(!quota.is_denied());
        assert_eq!(quota.model_allowlist, None);
        assert_eq!(quota.rpm_limit, None);
        assert_eq!(quota.tpm_limit, None);
        assert_eq!(quota.monthly_budget_usd, None);
        assert!(quota.allows_model("anything"));
    }

    #[test]
    fn nearest_scope_overrides_but_cannot_exceed_ancestor_cap() {
        let policies = vec![
            policy(
                QuotaScopeKind::Tenant,
                "t1",
                vec![],
                Some(1_000),
                None,
                None,
                true,
            ),
            // Workspace tries to raise the cap above the tenant's ceiling;
            // it must be clamped down to 1_000, not honored as 5_000.
            policy(
                QuotaScopeKind::Workspace,
                "w1",
                vec![],
                Some(5_000),
                None,
                None,
                true,
            ),
        ];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: Some("w1"),
                key_id: None,
            },
            lookup_from(policies),
            None,
        );
        assert_eq!(quota.rpm_limit, Some(1_000));

        // Now the workspace tightens further below the tenant's cap -- the
        // nearest (tighter) value must win.
        let policies = vec![
            policy(
                QuotaScopeKind::Tenant,
                "t1",
                vec![],
                Some(1_000),
                None,
                None,
                true,
            ),
            policy(
                QuotaScopeKind::Workspace,
                "w1",
                vec![],
                Some(200),
                None,
                None,
                true,
            ),
        ];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: Some("w1"),
                key_id: None,
            },
            lookup_from(policies),
            None,
        );
        assert_eq!(quota.rpm_limit, Some(200));
    }

    #[test]
    fn model_allowlist_is_intersection_across_scopes() {
        let policies = vec![
            policy(
                QuotaScopeKind::Tenant,
                "t1",
                vec!["fast-chat", "smart-chat", "vision"],
                None,
                None,
                None,
                true,
            ),
            policy(
                QuotaScopeKind::Key,
                "k1",
                vec!["fast-chat", "vision"],
                None,
                None,
                None,
                true,
            ),
        ];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: Some("k1"),
            },
            lookup_from(policies),
            None,
        );
        assert!(quota.allows_model("fast-chat"));
        assert!(quota.allows_model("vision"));
        assert!(!quota.allows_model("smart-chat"));
        assert_eq!(quota.model_allowlist.unwrap().len(), 2);
    }

    #[test]
    fn contradictory_intersection_denies_every_model() {
        let policies = vec![
            policy(
                QuotaScopeKind::Tenant,
                "t1",
                vec!["fast-chat"],
                None,
                None,
                None,
                true,
            ),
            policy(
                QuotaScopeKind::Key,
                "k1",
                vec!["smart-chat"],
                None,
                None,
                None,
                true,
            ),
        ];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: Some("k1"),
            },
            lookup_from(policies),
            None,
        );
        assert!(!quota.allows_model("fast-chat"));
        assert!(!quota.allows_model("smart-chat"));
    }

    #[test]
    fn disabled_policy_anywhere_in_chain_is_a_hard_deny() {
        let policies = vec![
            policy(
                QuotaScopeKind::Tenant,
                "t1",
                vec![],
                Some(1_000),
                None,
                None,
                true,
            ),
            policy(
                QuotaScopeKind::Project,
                "p1",
                vec![],
                None,
                None,
                None,
                false,
            ),
        ];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: Some("p1"),
                workspace_id: None,
                key_id: None,
            },
            lookup_from(policies),
            None,
        );
        assert!(quota.is_denied());
        assert_eq!(quota.denied_by, Some(QuotaScopeKind::Project));
    }

    #[test]
    fn tpm_and_monthly_budget_follow_the_same_min_across_chain_rule() {
        let policies = vec![
            policy(
                QuotaScopeKind::Tenant,
                "t1",
                vec![],
                None,
                Some(1_000_000),
                Some(500.0),
                true,
            ),
            policy(
                QuotaScopeKind::Key,
                "k1",
                vec![],
                None,
                Some(50_000),
                Some(1_000.0),
                true,
            ),
        ];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: Some("k1"),
            },
            lookup_from(policies),
            None,
        );
        assert_eq!(quota.tpm_limit, Some(50_000));
        assert_eq!(quota.monthly_budget_usd, Some(500.0));
    }

    #[test]
    fn absent_scope_in_the_request_chain_is_simply_skipped() {
        // Key has no workspace_id at all (e.g. a pre-hierarchy key); only
        // tenant and key policies should apply.
        let policies = vec![
            policy(
                QuotaScopeKind::Tenant,
                "t1",
                vec![],
                Some(100),
                None,
                None,
                true,
            ),
            policy(
                QuotaScopeKind::Workspace,
                "w1",
                vec![],
                Some(1),
                None,
                None,
                true,
            ),
        ];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: Some("k1"),
            },
            lookup_from(policies),
            None,
        );
        assert_eq!(quota.rpm_limit, Some(100));
    }

    fn sample_plan() -> StoredPlan {
        StoredPlan {
            id: "plan-pro".into(),
            name: "Pro".into(),
            slug: "pro".into(),
            mcp_enabled: true,
            self_hosted_workers_enabled: true,
            admin_console_seats: Some(5),
            default_model_allowlist: vec!["fast-chat".into(), "smart-chat".into()],
            default_rpm_limit: Some(600),
            default_tpm_limit: Some(100_000),
            default_monthly_budget_usd: Some(250.0),
            created_at_unix: 1,
            updated_at_unix: 1,
            asset_hosting_enabled: true,
            default_asset_storage_quota_bytes: Some(1_000_000),
        }
    }

    #[test]
    fn plan_defaults_apply_when_no_explicit_policy_exists() {
        let plan = sample_plan();
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: None,
            },
            lookup_from(vec![]),
            Some(&plan),
        );
        assert!(!quota.is_denied());
        assert_eq!(quota.rpm_limit, Some(600));
        assert_eq!(quota.tpm_limit, Some(100_000));
        assert_eq!(quota.monthly_budget_usd, Some(250.0));
        assert!(quota.allows_model("fast-chat"));
        assert!(!quota.allows_model("vision"));
    }

    #[test]
    fn plan_defaults_are_overridden_by_an_explicit_policy() {
        let plan = sample_plan();
        let policies = vec![policy(
            QuotaScopeKind::Tenant,
            "t1",
            vec![],
            Some(50),
            None,
            Some(10.0),
            true,
        )];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: None,
            },
            lookup_from(policies),
            Some(&plan),
        );
        // rpm_limit and monthly_budget_usd are set by the explicit tenant
        // policy, so the plan's defaults for those fields are ignored...
        assert_eq!(quota.rpm_limit, Some(50));
        assert_eq!(quota.monthly_budget_usd, Some(10.0));
        // ...but tpm_limit and model_allowlist are untouched by any policy,
        // so the plan's defaults still apply.
        assert_eq!(quota.tpm_limit, Some(100_000));
        assert!(quota.allows_model("fast-chat"));
        assert!(!quota.allows_model("vision"));
    }

    #[test]
    fn disabled_policy_still_denies_even_with_a_plan_present() {
        let plan = sample_plan();
        let policies = vec![policy(
            QuotaScopeKind::Tenant,
            "t1",
            vec![],
            None,
            None,
            None,
            false,
        )];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: None,
            },
            lookup_from(policies),
            Some(&plan),
        );
        assert!(quota.is_denied());
        assert_eq!(quota.rpm_limit, None);
    }
}
