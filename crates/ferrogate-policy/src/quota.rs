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

/// Identifies the single scope in a chain whose configured limit is the
/// binding (tightest) one for a given dimension (rpm / tpm / monthly budget).
///
/// Rate-limit and monthly-budget windows are keyed on this scope so a
/// tenant/project/workspace-level cap is enforced as ONE aggregate counter
/// shared by every API key under it, instead of being counted independently
/// per key (which lets a tenant with N keys do N times the intended cap).
/// When the binding scope is the `Key` itself, the counter stays byte-for-
/// byte per-key -- see [`QuotaScopeSelector::counter_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaScopeSelector {
    pub kind: QuotaScopeKind,
    pub id: String,
}

impl QuotaScopeSelector {
    fn new(kind: QuotaScopeKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }

    /// The rate-limit / budget counter-window key for this binding scope.
    ///
    /// EVERY scope (including `Key`) is `"{kind}:{id}"`-namespaced. A `Key`
    /// winner is `"key:{api_key_id}"` -- previously it returned the RAW,
    /// tenant-controllable `api_key_id`, which shares the counter namespace with
    /// the broader `"tenant:/project:/workspace:{id}"` keys: a tenant could mint
    /// a virtual key whose id is `"tenant:<victim>"` and collide its per-key
    /// window with another tenant's aggregate window, poisoning the victim's
    /// RPM/TPM counter (cross-tenant DoS). The `"key:"` prefix makes a per-key
    /// counter structurally unable to equal any broader-scope key.
    pub fn counter_key(&self, api_key_id: &str) -> String {
        match self.kind {
            QuotaScopeKind::Key => format!("{}:{}", QuotaScopeKind::Key.as_str(), api_key_id),
            QuotaScopeKind::Tenant | QuotaScopeKind::Project | QuotaScopeKind::Workspace => {
                format!("{}:{}", self.kind.as_str(), self.id)
            }
        }
    }
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
/// - `rpm_limit_scope` / `tpm_limit_scope` / `monthly_budget_scope` each
///   record WHICH scope's value won that dimension's `min` (they can differ:
///   rpm may bind at the workspace while tpm binds at the tenant). Ties go to
///   the most specific scope (Key > Workspace > Project > Tenant), so a
///   per-key limit equal to a broader cap keeps per-key counting. Callers key
///   the corresponding rate-limit/budget window on this scope's
///   [`QuotaScopeSelector::counter_key`] so the cap holds across every key
///   under the winning scope.
/// - `denied_by = Some(scope)` means some scope in the chain has
///   `enabled = false`; the caller must fail closed regardless of the other
///   fields (they are left at their defaults when this is set).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EffectiveQuota {
    pub model_allowlist: Option<Vec<String>>,
    pub rpm_limit: Option<u64>,
    pub rpm_limit_scope: Option<QuotaScopeSelector>,
    pub tpm_limit: Option<u64>,
    pub tpm_limit_scope: Option<QuotaScopeSelector>,
    pub monthly_budget_usd: Option<f64>,
    pub monthly_budget_scope: Option<QuotaScopeSelector>,
    /// #428 (agent cost governance): tightest per-tenant monthly USD ceiling on
    /// CF-hosted-agent runtime cost across the chain, resolved with the same
    /// `min`-across-the-chain rule as `monthly_budget_usd` (a nearer scope
    /// overrides but can never exceed an ancestor's cap, with a plan default as
    /// the floor). This is the per-tenant source a later connector resolves into
    /// the slice-A `AgentBudgetPolicy.ceiling_usd`. `None` means no ceiling.
    pub agent_cost_budget_usd: Option<f64>,
    /// The scope whose `agent_cost_budget_usd` won the chain's `min`, recorded
    /// exactly like `monthly_budget_scope` so a caller can key any per-tenant
    /// agent-cost window on the winning scope's [`QuotaScopeSelector::counter_key`].
    pub agent_cost_budget_scope: Option<QuotaScopeSelector>,
    pub asset_storage_quota_bytes: Option<u64>,
    /// #259: dedicated per-object asset byte ceiling (each individual object
    /// must be <= this), resolved exactly like `asset_storage_quota_bytes` --
    /// a tenant-scoped policy override wins, else the plan default -- but
    /// distinct from and independent of that cumulative cap. `None` means no
    /// dedicated per-object ceiling applies.
    pub asset_max_object_bytes: Option<u64>,
    /// #262 (egress governance): tightest monthly egress/download byte budget
    /// across the chain, resolved with the same `min`-across-the-chain rule as
    /// `rpm_limit`/`monthly_budget_usd` (nearest scope overrides but can never
    /// exceed an ancestor's cap). `None` means no egress budget applies.
    pub monthly_egress_bytes_budget: Option<u64>,
    /// The scope whose `monthly_egress_bytes_budget` won the chain's `min`, so a
    /// caller can key the cumulative-egress counter on the winning scope's
    /// [`QuotaScopeSelector::counter_key`] exactly like the token/budget dims.
    pub monthly_egress_bytes_scope: Option<QuotaScopeSelector>,
    /// #262: tightest per-minute asset-download request cap across the chain,
    /// the download-side analogue of `rpm_limit`.
    pub download_rpm_limit: Option<u64>,
    pub download_rpm_limit_scope: Option<QuotaScopeSelector>,
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
        // Values stay `min`-across-the-chain (unchanged); `_scope` records the
        // scope whose value is that min, ties going to the most specific scope
        // because `policies` is ordered Tenant->Project->Workspace->Key and
        // `update_min_*` overrides on `<=` (a later, more specific scope wins a
        // tie). This never alters the numeric limit -- only which scope's
        // counter the caller keys the window on.
        update_min_u64_scope(
            &mut effective.rpm_limit,
            &mut effective.rpm_limit_scope,
            policy.rpm_limit,
            policy.scope_type,
            &policy.scope_id,
        );
        update_min_u64_scope(
            &mut effective.tpm_limit,
            &mut effective.tpm_limit_scope,
            policy.tpm_limit,
            policy.scope_type,
            &policy.scope_id,
        );
        update_min_f64_scope(
            &mut effective.monthly_budget_usd,
            &mut effective.monthly_budget_scope,
            policy.monthly_budget_usd,
            policy.scope_type,
            &policy.scope_id,
        );
        // #428: the per-tenant agent runtime-cost ceiling merges exactly like
        // `monthly_budget_usd` above (min-across-the-chain, ties to the most
        // specific scope), sourcing the slice-A AgentBudgetPolicy ceiling.
        update_min_f64_scope(
            &mut effective.agent_cost_budget_usd,
            &mut effective.agent_cost_budget_scope,
            policy.agent_cost_budget_usd,
            policy.scope_type,
            &policy.scope_id,
        );
        // #262: egress byte budget + download RPM merge exactly like rpm/tpm
        // (min-across-the-chain, ties to the most specific scope).
        update_min_u64_scope(
            &mut effective.monthly_egress_bytes_budget,
            &mut effective.monthly_egress_bytes_scope,
            policy.monthly_egress_bytes_budget,
            policy.scope_type,
            &policy.scope_id,
        );
        update_min_u64_scope(
            &mut effective.download_rpm_limit,
            &mut effective.download_rpm_limit_scope,
            policy.download_rpm_limit,
            policy.scope_type,
            &policy.scope_id,
        );
        if policy.scope_type == QuotaScopeKind::Tenant {
            effective.asset_storage_quota_bytes = policy.asset_storage_quota_bytes;
            // #259: the per-object ceiling resolves exactly like the cumulative
            // quota above -- tenant-scoped override wins -- but is tracked
            // independently, so a tenant can tighten individual-object size
            // without touching its cumulative storage budget (and vice versa).
            effective.asset_max_object_bytes = policy.asset_max_object_bytes;
        }
    }
    if let Some(plan) = plan {
        // A plan is a tenant-level default bundle (issue #168), so a limit it
        // supplies as a floor is a tenant-wide default: key its window on the
        // Tenant scope (aggregated across the tenant's keys) when a tenant id
        // is present, mirroring how an explicit tenant policy would be keyed.
        let plan_scope = chain
            .tenant_id
            .map(|id| QuotaScopeSelector::new(QuotaScopeKind::Tenant, id));
        if effective.model_allowlist.is_none() && !plan.default_model_allowlist.is_empty() {
            effective.model_allowlist = Some(plan.default_model_allowlist.clone());
        }
        if effective.rpm_limit.is_none() {
            if let Some(rpm) = plan.default_rpm_limit {
                effective.rpm_limit = Some(rpm);
                effective.rpm_limit_scope = plan_scope.clone();
            }
        }
        if effective.tpm_limit.is_none() {
            if let Some(tpm) = plan.default_tpm_limit {
                effective.tpm_limit = Some(tpm);
                effective.tpm_limit_scope = plan_scope.clone();
            }
        }
        if effective.monthly_budget_usd.is_none() {
            if let Some(budget) = plan.default_monthly_budget_usd {
                effective.monthly_budget_usd = Some(budget);
                effective.monthly_budget_scope = plan_scope.clone();
            }
        }
        // #428: the plan's agent-cost ceiling default fills in only when no
        // explicit scope policy set it, keyed on the tenant scope like the
        // monthly budget above.
        if effective.agent_cost_budget_usd.is_none() {
            if let Some(budget) = plan.default_agent_cost_budget_usd {
                effective.agent_cost_budget_usd = Some(budget);
                effective.agent_cost_budget_scope = plan_scope.clone();
            }
        }
        // #262: egress budget + download RPM take the plan floor only when no
        // explicit scope policy set them, keyed on the tenant scope (a plan is
        // a tenant-wide default bundle), mirroring rpm/tpm/budget above.
        if effective.monthly_egress_bytes_budget.is_none() {
            if let Some(budget) = plan.default_monthly_egress_bytes_budget {
                effective.monthly_egress_bytes_budget = Some(budget);
                effective.monthly_egress_bytes_scope = plan_scope.clone();
            }
        }
        if effective.download_rpm_limit.is_none() {
            if let Some(rpm) = plan.default_download_rpm_limit {
                effective.download_rpm_limit = Some(rpm);
                effective.download_rpm_limit_scope = plan_scope.clone();
            }
        }
        effective.asset_storage_quota_bytes = effective
            .asset_storage_quota_bytes
            .or(plan.default_asset_storage_quota_bytes);
        // #259: same plan-default fallback as the cumulative quota above -- the
        // plan's per-object default fills in only when no tenant policy set it.
        effective.asset_max_object_bytes = effective
            .asset_max_object_bytes
            .or(plan.default_asset_max_object_bytes);
    }
    effective
}

/// Fold one policy's `u64` limit into the running `min`, recording the scope
/// whose value now holds that min. Overrides the recorded scope on `<=` so
/// that, given the Tenant->Project->Workspace->Key iteration order, a tie is
/// awarded to the most specific (nearest-to-the-key) scope. The numeric value
/// is exactly `min_opt_u64(*value, candidate)`.
fn update_min_u64_scope(
    value: &mut Option<u64>,
    scope: &mut Option<QuotaScopeSelector>,
    candidate: Option<u64>,
    scope_type: QuotaScopeKind,
    scope_id: &str,
) {
    let Some(candidate) = candidate else {
        return;
    };
    if value.is_none_or(|current| candidate <= current) {
        *value = Some(candidate);
        *scope = Some(QuotaScopeSelector::new(scope_type, scope_id));
    }
}

/// `f64` analogue of [`update_min_u64_scope`] for the monthly-budget cap.
fn update_min_f64_scope(
    value: &mut Option<f64>,
    scope: &mut Option<QuotaScopeSelector>,
    candidate: Option<f64>,
    scope_type: QuotaScopeKind,
    scope_id: &str,
) {
    let Some(candidate) = candidate else {
        return;
    };
    if value.is_none_or(|current| candidate <= current) {
        *value = Some(candidate);
        *scope = Some(QuotaScopeSelector::new(scope_type, scope_id));
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
            agent_cost_budget_usd: None,
            asset_storage_quota_bytes: None,
            asset_max_object_bytes: None,
            alert_threshold_pcts: Vec::new(),
            enabled,
            created_at_unix: 1,
            updated_at_unix: 1,
            monthly_egress_bytes_budget: None,
            download_rpm_limit: None,
        }
    }

    /// Builder for an egress-dimension-only policy (#262): rpm/tpm/budget stay
    /// unset so a test exercises just the egress byte budget + download RPM
    /// merge without interference from the token dimensions.
    fn egress_policy(
        scope_type: QuotaScopeKind,
        scope_id: &str,
        monthly_egress_bytes_budget: Option<u64>,
        download_rpm_limit: Option<u64>,
    ) -> StoredQuotaPolicy {
        StoredQuotaPolicy {
            id: format!("{}:{scope_id}", scope_type.as_str()),
            scope_type,
            scope_id: scope_id.to_string(),
            model_allowlist: Vec::new(),
            rpm_limit: None,
            tpm_limit: None,
            monthly_budget_usd: None,
            agent_cost_budget_usd: None,
            asset_storage_quota_bytes: None,
            asset_max_object_bytes: None,
            alert_threshold_pcts: Vec::new(),
            enabled: true,
            created_at_unix: 1,
            updated_at_unix: 1,
            monthly_egress_bytes_budget,
            download_rpm_limit,
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
    fn winning_scope_is_recorded_per_dimension_and_rpm_tpm_can_differ() {
        // rpm binds at the workspace (200 < tenant 1000); tpm binds at the
        // tenant (1M < key 50k? no -- tenant 1M vs key 50k, key is tighter).
        // Construct so rpm winner != tpm winner to prove they're tracked
        // independently.
        let policies = vec![
            policy(
                QuotaScopeKind::Tenant,
                "t1",
                vec![],
                Some(1_000),
                Some(10_000),
                None,
                true,
            ),
            policy(
                QuotaScopeKind::Workspace,
                "w1",
                vec![],
                Some(200), // rpm winner
                Some(50_000),
                None,
                true,
            ),
            policy(
                QuotaScopeKind::Key,
                "k1",
                vec![],
                Some(500),
                Some(5_000), // tpm winner
                None,
                true,
            ),
        ];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: Some("w1"),
                key_id: Some("k1"),
            },
            lookup_from(policies),
            None,
        );
        assert_eq!(quota.rpm_limit, Some(200));
        assert_eq!(
            quota.rpm_limit_scope,
            Some(QuotaScopeSelector::new(QuotaScopeKind::Workspace, "w1"))
        );
        assert_eq!(quota.tpm_limit, Some(5_000));
        assert_eq!(
            quota.tpm_limit_scope,
            Some(QuotaScopeSelector::new(QuotaScopeKind::Key, "k1"))
        );
    }

    #[test]
    fn a_tie_between_a_broader_scope_and_the_key_is_awarded_to_the_key() {
        // Tenant and key both cap rpm at 100. The key (most specific) must win
        // the tie so per-key counting is preserved; the monthly budget ties
        // between tenant and key too and likewise resolves to the key.
        let policies = vec![
            policy(
                QuotaScopeKind::Tenant,
                "t1",
                vec![],
                Some(100),
                None,
                Some(10.0),
                true,
            ),
            policy(
                QuotaScopeKind::Key,
                "k1",
                vec![],
                Some(100),
                None,
                Some(10.0),
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
        assert_eq!(
            quota.rpm_limit_scope,
            Some(QuotaScopeSelector::new(QuotaScopeKind::Key, "k1"))
        );
        assert_eq!(
            quota.monthly_budget_scope,
            Some(QuotaScopeSelector::new(QuotaScopeKind::Key, "k1"))
        );
    }

    #[test]
    fn counter_key_is_namespaced_for_every_scope_including_key() {
        let key = QuotaScopeSelector::new(QuotaScopeKind::Key, "k1");
        // Per-key windows are "key:"-prefixed so they cannot collide with a
        // broader-scope key even when the api key id is attacker-chosen.
        assert_eq!(key.counter_key("vk-abc"), "key:vk-abc");
        let workspace = QuotaScopeSelector::new(QuotaScopeKind::Workspace, "w1");
        assert_eq!(workspace.counter_key("vk-abc"), "workspace:w1");
        let tenant = QuotaScopeSelector::new(QuotaScopeKind::Tenant, "t1");
        assert_eq!(tenant.counter_key("vk-abc"), "tenant:t1");
        let project = QuotaScopeSelector::new(QuotaScopeKind::Project, "p1");
        assert_eq!(project.counter_key("vk-abc"), "project:p1");
        // A per-key counter can never equal a broader-scope counter: a virtual
        // key whose id is "tenant:victim" hashes to "key:tenant:victim", not
        // "tenant:victim".
        assert_eq!(key.counter_key("tenant:victim"), "key:tenant:victim");
        assert_ne!(
            key.counter_key("tenant:victim"),
            tenant.counter_key("anything"),
        );
    }

    #[test]
    fn plan_supplied_limits_are_keyed_on_the_tenant_scope() {
        let plan = sample_plan();
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: Some("k1"),
            },
            lookup_from(vec![]),
            Some(&plan),
        );
        // The plan is a tenant-wide default bundle, so its rpm/tpm/budget
        // floors aggregate at the tenant, not per key.
        let tenant_scope = Some(QuotaScopeSelector::new(QuotaScopeKind::Tenant, "t1"));
        assert_eq!(quota.rpm_limit_scope, tenant_scope);
        assert_eq!(quota.tpm_limit_scope, tenant_scope);
        assert_eq!(quota.monthly_budget_scope, tenant_scope);
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
            default_agent_cost_budget_usd: Some(180.0),
            created_at_unix: 1,
            updated_at_unix: 1,
            asset_hosting_enabled: true,
            default_asset_storage_quota_bytes: Some(1_000_000),
            default_asset_max_object_bytes: Some(250_000),
            extension_tools_enabled: true,
            default_monthly_egress_bytes_budget: Some(5_000_000),
            default_download_rpm_limit: Some(120),
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
    fn agent_cost_budget_resolves_min_across_the_chain_with_plan_default() {
        // #428: the per-tenant agent runtime-cost ceiling behaves exactly like
        // `monthly_budget_usd` -- the tightest value across the chain wins (a
        // nearer scope can tighten but never loosen an ancestor cap), the
        // winning scope is tracked, and the plan default is only the floor
        // applied when no explicit policy set it.
        let tenant = StoredQuotaPolicy {
            agent_cost_budget_usd: Some(500.0),
            ..policy(QuotaScopeKind::Tenant, "t1", vec![], None, None, None, true)
        };
        let key = StoredQuotaPolicy {
            agent_cost_budget_usd: Some(120.0),
            ..policy(QuotaScopeKind::Key, "k1", vec![], None, None, None, true)
        };
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: Some("k1"),
            },
            lookup_from(vec![tenant, key]),
            None,
        );
        assert_eq!(quota.agent_cost_budget_usd, Some(120.0));
        assert_eq!(
            quota.agent_cost_budget_scope,
            Some(QuotaScopeSelector::new(QuotaScopeKind::Key, "k1"))
        );

        // With no explicit policy, the plan default fills in, keyed on the
        // tenant scope (a plan is a tenant-wide default bundle).
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
        assert_eq!(
            quota.agent_cost_budget_usd,
            plan.default_agent_cost_budget_usd
        );
        assert_eq!(
            quota.agent_cost_budget_scope,
            Some(QuotaScopeSelector::new(QuotaScopeKind::Tenant, "t1"))
        );

        // An explicit tenant policy overrides the plan default.
        let tenant = StoredQuotaPolicy {
            agent_cost_budget_usd: Some(42.0),
            ..policy(QuotaScopeKind::Tenant, "t1", vec![], None, None, None, true)
        };
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: None,
            },
            lookup_from(vec![tenant]),
            Some(&plan),
        );
        assert_eq!(quota.agent_cost_budget_usd, Some(42.0));
    }

    #[test]
    fn egress_budget_and_download_rpm_follow_min_across_the_chain() {
        // Tenant sets a loose egress budget; the workspace tightens it below
        // the tenant cap and must win. Download RPM binds independently at the
        // key. (#262)
        let policies = vec![
            egress_policy(QuotaScopeKind::Tenant, "t1", Some(10_000_000), Some(600)),
            egress_policy(QuotaScopeKind::Workspace, "w1", Some(2_000_000), None),
            egress_policy(QuotaScopeKind::Key, "k1", None, Some(30)),
        ];
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: Some("w1"),
                key_id: Some("k1"),
            },
            lookup_from(policies),
            None,
        );
        assert_eq!(quota.monthly_egress_bytes_budget, Some(2_000_000));
        assert_eq!(
            quota.monthly_egress_bytes_scope,
            Some(QuotaScopeSelector::new(QuotaScopeKind::Workspace, "w1"))
        );
        assert_eq!(quota.download_rpm_limit, Some(30));
        assert_eq!(
            quota.download_rpm_limit_scope,
            Some(QuotaScopeSelector::new(QuotaScopeKind::Key, "k1"))
        );
    }

    #[test]
    fn a_workspace_cannot_raise_the_egress_budget_above_the_tenant_ceiling() {
        // Workspace tries to widen the tenant's 1MB egress cap to 9MB; the
        // min-across-the-chain rule clamps it back to the tenant ceiling. (#262)
        let policies = vec![
            egress_policy(QuotaScopeKind::Tenant, "t1", Some(1_000_000), None),
            egress_policy(QuotaScopeKind::Workspace, "w1", Some(9_000_000), None),
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
        assert_eq!(quota.monthly_egress_bytes_budget, Some(1_000_000));
        assert_eq!(
            quota.monthly_egress_bytes_scope,
            Some(QuotaScopeSelector::new(QuotaScopeKind::Tenant, "t1"))
        );
    }

    #[test]
    fn plan_egress_floors_apply_only_when_no_explicit_policy_sets_them() {
        let plan = sample_plan();
        // No explicit policy: plan floors apply, keyed on the tenant scope.
        let quota = resolve_effective_quota(
            QuotaScopeChain {
                tenant_id: Some("t1"),
                project_id: None,
                workspace_id: None,
                key_id: Some("k1"),
            },
            lookup_from(vec![]),
            Some(&plan),
        );
        assert_eq!(quota.monthly_egress_bytes_budget, Some(5_000_000));
        assert_eq!(quota.download_rpm_limit, Some(120));
        assert_eq!(
            quota.monthly_egress_bytes_scope,
            Some(QuotaScopeSelector::new(QuotaScopeKind::Tenant, "t1"))
        );

        // An explicit tenant egress budget overrides the plan floor for that
        // dimension; the download-RPM floor (untouched by any policy) survives.
        let policies = vec![egress_policy(
            QuotaScopeKind::Tenant,
            "t1",
            Some(250_000),
            None,
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
        assert_eq!(quota.monthly_egress_bytes_budget, Some(250_000));
        assert_eq!(quota.download_rpm_limit, Some(120));
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
