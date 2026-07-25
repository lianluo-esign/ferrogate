// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Dedicated invariant tests for four-level asset quota resolution (#210).

use ferrogate_policy::{resolve_effective_quota, EffectiveQuota, QuotaScopeChain};
use ferrogate_storage::{QuotaScopeKind, StoredPlan, StoredQuotaPolicy};
use proptest::prelude::*;
use std::collections::HashMap;

fn policy(scope_type: QuotaScopeKind, scope_id: &str, bytes: u64) -> StoredQuotaPolicy {
    StoredQuotaPolicy {
        id: format!("{}:{scope_id}", scope_type.as_str()),
        scope_type,
        scope_id: scope_id.to_string(),
        model_allowlist: Vec::new(),
        rpm_limit: None,
        tpm_limit: None,
        monthly_budget_usd: None,
        asset_storage_quota_bytes: Some(bytes),
        asset_max_object_bytes: None,
        alert_threshold_pcts: Vec::new(),
        enabled: true,
        created_at_unix: 1,
        updated_at_unix: 1,
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
    }
}

/// Builds a policy carrying ONLY a per-object ceiling (#259): the cumulative
/// `asset_storage_quota_bytes` is cleared so a resolved value proves the
/// dedicated `asset_max_object_bytes` field resolves on its own.
fn per_object_policy(scope_type: QuotaScopeKind, scope_id: &str, bytes: u64) -> StoredQuotaPolicy {
    StoredQuotaPolicy {
        asset_storage_quota_bytes: None,
        asset_max_object_bytes: Some(bytes),
        ..policy(scope_type, scope_id, 0)
    }
}

fn resolve(policies: Vec<StoredQuotaPolicy>, plan: Option<&StoredPlan>) -> EffectiveQuota {
    let policies = policies
        .into_iter()
        .map(|policy| ((policy.scope_type, policy.scope_id.clone()), policy))
        .collect::<HashMap<_, _>>();
    resolve_effective_quota(
        QuotaScopeChain {
            tenant_id: Some("tenant"),
            project_id: Some("project"),
            workspace_id: Some("workspace"),
            key_id: Some("key"),
        },
        |scope_type, scope_id| policies.get(&(scope_type, scope_id.to_string())).cloned(),
        plan,
    )
}

#[test]
fn only_the_tenant_scope_can_supply_the_runtime_asset_quota() {
    assert_eq!(
        resolve(vec![policy(QuotaScopeKind::Tenant, "tenant", 50)], None).asset_storage_quota_bytes,
        Some(50)
    );
    for (scope_type, scope_id) in [
        (QuotaScopeKind::Project, "project"),
        (QuotaScopeKind::Workspace, "workspace"),
        (QuotaScopeKind::Key, "key"),
    ] {
        assert_eq!(
            resolve(vec![policy(scope_type, scope_id, 50)], None).asset_storage_quota_bytes,
            None
        );
    }
}

#[test]
fn explicit_scope_value_replaces_the_plan_default() {
    let plan = StoredPlan {
        id: "plan".into(),
        name: "Plan".into(),
        slug: "plan".into(),
        mcp_enabled: false,
        self_hosted_workers_enabled: false,
        admin_console_seats: None,
        default_model_allowlist: Vec::new(),
        default_rpm_limit: None,
        default_tpm_limit: None,
        default_monthly_budget_usd: None,
        asset_hosting_enabled: true,
        default_asset_storage_quota_bytes: Some(50),
        default_asset_max_object_bytes: None,
        extension_tools_enabled: false,
        created_at_unix: 1,
        updated_at_unix: 1,
        default_monthly_egress_bytes_budget: None,
        default_download_rpm_limit: None,
    };
    assert_eq!(
        resolve(Vec::new(), Some(&plan)).asset_storage_quota_bytes,
        Some(50)
    );
    assert_eq!(
        resolve(
            vec![policy(QuotaScopeKind::Tenant, "tenant", 1_000)],
            Some(&plan)
        )
        .asset_storage_quota_bytes,
        Some(1_000)
    );
}

/// #259: the dedicated per-object ceiling resolves with EXACTLY the
/// `asset_storage_quota_bytes` rules -- tenant-scoped override wins, else plan
/// default, and narrower scopes cannot supply it -- while staying fully
/// independent of the cumulative quota.
#[test]
fn per_object_ceiling_resolves_independently_of_the_cumulative_quota() {
    // A tenant-scoped per-object override resolves on its own.
    assert_eq!(
        resolve(
            vec![per_object_policy(QuotaScopeKind::Tenant, "tenant", 4_096)],
            None
        )
        .asset_max_object_bytes,
        Some(4_096)
    );
    // Narrower scopes cannot supply it, exactly like the cumulative quota.
    for (scope_type, scope_id) in [
        (QuotaScopeKind::Project, "project"),
        (QuotaScopeKind::Workspace, "workspace"),
        (QuotaScopeKind::Key, "key"),
    ] {
        assert_eq!(
            resolve(vec![per_object_policy(scope_type, scope_id, 4_096)], None)
                .asset_max_object_bytes,
            None
        );
    }

    // Plan default fills in when no tenant policy overrides it; a tenant policy
    // override replaces the plan default -- and neither touches the cumulative
    // asset_storage_quota_bytes, proving the two caps resolve independently.
    let plan = StoredPlan {
        id: "plan".into(),
        name: "Plan".into(),
        slug: "plan".into(),
        mcp_enabled: false,
        self_hosted_workers_enabled: false,
        admin_console_seats: None,
        default_model_allowlist: Vec::new(),
        default_rpm_limit: None,
        default_tpm_limit: None,
        default_monthly_budget_usd: None,
        asset_hosting_enabled: true,
        default_asset_storage_quota_bytes: Some(1_000_000),
        default_asset_max_object_bytes: Some(64_000),
        extension_tools_enabled: false,
        created_at_unix: 1,
        updated_at_unix: 1,
        default_monthly_egress_bytes_budget: None,
        default_download_rpm_limit: None,
    };
    // No policy: both caps come from the plan, each from its own default.
    let resolved = resolve(Vec::new(), Some(&plan));
    assert_eq!(resolved.asset_max_object_bytes, Some(64_000));
    assert_eq!(resolved.asset_storage_quota_bytes, Some(1_000_000));

    // A tenant policy that overrides ONLY the per-object ceiling leaves the
    // cumulative quota on the plan default -- the two are not coupled.
    let resolved = resolve(
        vec![per_object_policy(QuotaScopeKind::Tenant, "tenant", 8_192)],
        Some(&plan),
    );
    assert_eq!(resolved.asset_max_object_bytes, Some(8_192));
    assert_eq!(resolved.asset_storage_quota_bytes, Some(1_000_000));
}

proptest! {
    #[test]
    fn generic_numeric_quota_chain_always_uses_the_tightest_value(
        tenant in 1_u64..1_000_000,
        project in 1_u64..1_000_000,
        workspace in 1_u64..1_000_000,
        key in 1_u64..1_000_000,
    ) {
        let mut policies = vec![
            policy(QuotaScopeKind::Tenant, "tenant", tenant),
            policy(QuotaScopeKind::Project, "project", project),
            policy(QuotaScopeKind::Workspace, "workspace", workspace),
            policy(QuotaScopeKind::Key, "key", key),
        ];
        for (policy, limit) in policies.iter_mut().zip([tenant, project, workspace, key]) {
            policy.asset_storage_quota_bytes = None;
            policy.tpm_limit = Some(limit);
        }
        let actual = resolve(policies, None);
        prop_assert_eq!(actual.tpm_limit, Some(tenant.min(project).min(workspace).min(key)));
    }
}
