// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Dedicated storage-contract tests for tenant-only asset quota overrides (#210).

use ferrogate_storage::{validate_quota_policy, QuotaScopeKind, StoredQuotaPolicy};

fn policy(scope_type: QuotaScopeKind) -> StoredQuotaPolicy {
    StoredQuotaPolicy {
        id: format!("{}:scope", scope_type.as_str()),
        scope_type,
        scope_id: "scope".into(),
        model_allowlist: Vec::new(),
        rpm_limit: None,
        tpm_limit: None,
        monthly_budget_usd: None,
        asset_storage_quota_bytes: Some(50),
        alert_threshold_pcts: Vec::new(),
        enabled: true,
        created_at_unix: 1,
        updated_at_unix: 1,
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
    }
}

#[test]
fn tenant_asset_storage_quota_is_valid() {
    validate_quota_policy(&policy(QuotaScopeKind::Tenant)).unwrap();
}

#[test]
fn narrower_asset_storage_quota_scopes_are_rejected() {
    for scope_type in [
        QuotaScopeKind::Project,
        QuotaScopeKind::Workspace,
        QuotaScopeKind::Key,
    ] {
        let error = validate_quota_policy(&policy(scope_type)).unwrap_err();
        assert!(error.to_string().contains("tenant-only"));
    }
}
