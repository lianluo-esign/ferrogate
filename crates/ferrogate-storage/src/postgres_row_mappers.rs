// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Postgres `Row` -> `Stored*` mapper functions extracted from lib.rs
// (issues #429/#433 modular-layout cap). Pure row projections shared by the
// tokio-postgres SQL methods in the crate root; re-exported `pub(crate)` so all
// existing call sites resolve unchanged. No behaviour change.

//! Postgres row-mapper functions (`*_from_row`) for the control-plane store.
//!
//! Each function projects a `tokio_postgres::Row` into the corresponding
//! `Stored*` domain type. They were split out of `lib.rs` to keep the crate
//! entry file under the modular-layout line cap; behaviour is identical and the
//! crate root re-exports them `pub(crate)` so callers stay unqualified.

use super::*;

pub(crate) fn tenant_account_from_row(row: &PostgresRow) -> StoredTenantAccount {
    StoredTenantAccount {
        id: row.get::<_, String>(0),
        name: row.get::<_, String>(1),
        slug: row.get::<_, String>(2),
        status: row.get::<_, String>(3),
        plan_id: row.get::<_, String>(4),
        created_at_unix: row.get::<_, i64>(5),
        updated_at_unix: row.get::<_, i64>(6),
    }
}

pub(crate) fn admin_user_from_row(row: &PostgresRow) -> StoredAdminUser {
    StoredAdminUser {
        id: row.get::<_, String>(0),
        email: row.get::<_, String>(1),
        password_hash: row.get::<_, String>(2),
        display_name: row.get::<_, String>(3),
        superadmin: row.get::<_, bool>(4),
        created_at_unix: row.get::<_, i64>(5),
        updated_at_unix: row.get::<_, i64>(6),
        last_login_at_unix: row.get::<_, Option<i64>>(7),
        disabled_at_unix: row.get::<_, Option<i64>>(8),
    }
}

pub(crate) fn admin_user_membership_from_row(row: &PostgresRow) -> StoredAdminUserMembership {
    StoredAdminUserMembership {
        id: row.get::<_, String>(0),
        user_id: row.get::<_, String>(1),
        tenant_id: row.get::<_, String>(2),
        role: row.get::<_, String>(3),
        created_at_unix: row.get::<_, i64>(4),
    }
}

pub(crate) fn admin_user_refresh_token_from_row(row: &PostgresRow) -> StoredAdminUserRefreshToken {
    StoredAdminUserRefreshToken {
        id: row.get::<_, String>(0),
        user_id: row.get::<_, String>(1),
        token_hash: row.get::<_, String>(2),
        tenant_id: row.get::<_, Option<String>>(3),
        role: row.get::<_, Option<String>>(4),
        created_at_unix: row.get::<_, i64>(5),
        expires_at_unix: row.get::<_, i64>(6),
        revoked_at_unix: row.get::<_, Option<i64>>(7),
    }
}

pub(crate) fn sso_provider_config_from_row(
    row: &PostgresRow,
) -> Result<StoredSsoProviderConfig, StorageError> {
    let group_role_mapping_json = row.get::<_, String>(3);
    let group_role_mapping = serde_json::from_str(&group_role_mapping_json)
        .map_err(|error| StorageError::Serialization(error.to_string()))?;
    Ok(StoredSsoProviderConfig {
        tenant_id: row.get::<_, String>(0),
        provider_kind: row.get::<_, String>(1),
        default_role: row.get::<_, String>(2),
        group_role_mapping,
        oidc_issuer: row.get::<_, Option<String>>(4),
        oidc_client_id: row.get::<_, Option<String>>(5),
        oidc_client_secret_ref: row.get::<_, Option<String>>(6),
        oidc_redirect_uri: row.get::<_, Option<String>>(7),
        oidc_group_claim: row.get::<_, Option<String>>(8),
        saml_idp_entity_id: row.get::<_, Option<String>>(9),
        saml_idp_sso_url: row.get::<_, Option<String>>(10),
        saml_idp_certificate: row.get::<_, Option<String>>(11),
        saml_sp_entity_id: row.get::<_, Option<String>>(12),
        saml_acs_url: row.get::<_, Option<String>>(13),
        saml_email_attribute: row.get::<_, Option<String>>(14),
        saml_name_attribute: row.get::<_, Option<String>>(15),
        saml_groups_attribute: row.get::<_, Option<String>>(16),
        created_at_unix: row.get::<_, i64>(17),
        updated_at_unix: row.get::<_, i64>(18),
    })
}

pub(crate) fn sso_pending_flow_from_row(row: &PostgresRow) -> StoredSsoPendingFlow {
    StoredSsoPendingFlow {
        state: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        provider_kind: row.get::<_, String>(2),
        code_verifier: row.get::<_, Option<String>>(3),
        request_id: row.get::<_, Option<String>>(4),
        created_at_unix: row.get::<_, i64>(5),
        expires_at_unix: row.get::<_, i64>(6),
    }
}

pub(crate) fn api_key_from_row(row: &PostgresRow) -> Result<StoredApiKey, StorageError> {
    let id = row.get::<_, String>(0);
    let workspace_id = row.get::<_, String>(1);
    let tenant_id = row.get::<_, String>(2);
    let project_id = row.get::<_, String>(3);
    let scopes = deserialize_storage_document(&row.get::<_, String>(9))?;
    let allowed_models = deserialize_storage_document(&row.get::<_, String>(15))?;
    let allowed_providers = deserialize_storage_document(&row.get::<_, String>(16))?;
    Ok(StoredApiKey {
        id: id.clone(),
        workspace_id: workspace_id.clone(),
        tenant_id: tenant_id.clone(),
        project_id: project_id.clone(),
        name: row.get::<_, String>(4),
        key_prefix: row.get::<_, String>(5),
        key_hash: row.get::<_, String>(6),
        last4: row.get::<_, String>(7),
        enabled: row.get::<_, bool>(8),
        scopes,
        allowed_models,
        allowed_providers,
        tenant: api_key_tenant_context(&id, &tenant_id, &project_id, &workspace_id),
        monthly_token_budget: row.get::<_, Option<i64>>(17).map(nonnegative_u64),
        request_limit_per_minute: row.get::<_, Option<i64>>(18).map(nonnegative_u64),
        created_at_unix: nonnegative_u64(row.get::<_, i64>(10)),
        updated_at_unix: nonnegative_u64(row.get::<_, i64>(11)),
        rotated_at_unix: row.get::<_, Option<i64>>(12).map(nonnegative_u64),
        expires_at_unix: row.get::<_, Option<i64>>(13).map(nonnegative_u64),
        revoked_at_unix: row.get::<_, Option<i64>>(14).map(nonnegative_u64),
    })
}

pub(crate) fn project_from_row(row: &PostgresRow) -> StoredProject {
    StoredProject {
        id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        name: row.get::<_, String>(2),
        slug: row.get::<_, String>(3),
        status: row.get::<_, String>(4),
        created_at_unix: row.get::<_, i64>(5),
        updated_at_unix: row.get::<_, i64>(6),
    }
}

pub(crate) fn workspace_from_row(row: &PostgresRow) -> StoredWorkspace {
    StoredWorkspace {
        id: row.get::<_, String>(0),
        project_id: row.get::<_, String>(1),
        tenant_id: row.get::<_, String>(2),
        name: row.get::<_, String>(3),
        slug: row.get::<_, String>(4),
        environment: row.get::<_, String>(5),
        status: row.get::<_, String>(6),
        created_at_unix: row.get::<_, i64>(7),
        updated_at_unix: row.get::<_, i64>(8),
    }
}

pub(crate) fn quota_policy_from_row(row: &PostgresRow) -> Result<StoredQuotaPolicy, StorageError> {
    let scope_type_raw = row.get::<_, String>(1);
    let scope_type = QuotaScopeKind::from_str_opt(&scope_type_raw).ok_or_else(|| {
        StorageError::Runtime(format!(
            "unknown quota_policies.scope_type {scope_type_raw}"
        ))
    })?;
    let model_allowlist = deserialize_storage_document(&row.get::<_, String>(3))?;
    let alert_threshold_pcts = deserialize_storage_document(&row.get::<_, String>(10))?;
    Ok(StoredQuotaPolicy {
        id: row.get::<_, String>(0),
        scope_type,
        scope_id: row.get::<_, String>(2),
        model_allowlist,
        rpm_limit: row.get::<_, Option<i64>>(4).map(nonnegative_u64),
        tpm_limit: row.get::<_, Option<i64>>(5).map(nonnegative_u64),
        monthly_budget_usd: row.get::<_, Option<f64>>(6),
        enabled: row.get::<_, bool>(7),
        created_at_unix: row.get::<_, i64>(8),
        updated_at_unix: row.get::<_, i64>(9),
        alert_threshold_pcts,
        asset_storage_quota_bytes: row.get::<_, Option<i64>>(11).map(nonnegative_u64),
        monthly_egress_bytes_budget: row.get::<_, Option<i64>>(12).map(nonnegative_u64),
        download_rpm_limit: row.get::<_, Option<i64>>(13).map(nonnegative_u64),
        asset_max_object_bytes: row.get::<_, Option<i64>>(14).map(nonnegative_u64),
    })
}

pub(crate) fn plan_from_row(row: &PostgresRow) -> Result<StoredPlan, StorageError> {
    let default_model_allowlist = deserialize_storage_document(&row.get::<_, String>(6))?;
    Ok(StoredPlan {
        id: row.get::<_, String>(0),
        name: row.get::<_, String>(1),
        slug: row.get::<_, String>(2),
        mcp_enabled: row.get::<_, bool>(3),
        self_hosted_workers_enabled: row.get::<_, bool>(4),
        admin_console_seats: row.get::<_, Option<i64>>(5).map(nonnegative_u32),
        default_model_allowlist,
        default_rpm_limit: row.get::<_, Option<i64>>(7).map(nonnegative_u64),
        default_tpm_limit: row.get::<_, Option<i64>>(8).map(nonnegative_u64),
        default_monthly_budget_usd: row.get::<_, Option<f64>>(9),
        created_at_unix: row.get::<_, i64>(10),
        updated_at_unix: row.get::<_, i64>(11),
        asset_hosting_enabled: row.get::<_, bool>(12),
        default_asset_storage_quota_bytes: row.get::<_, Option<i64>>(13).map(nonnegative_u64),
        extension_tools_enabled: row.get::<_, bool>(14),
        default_monthly_egress_bytes_budget: row.get::<_, Option<i64>>(15).map(nonnegative_u64),
        default_download_rpm_limit: row.get::<_, Option<i64>>(16).map(nonnegative_u64),
        default_asset_max_object_bytes: row.get::<_, Option<i64>>(17).map(nonnegative_u64),
    })
}

pub(crate) fn asset_from_row(row: &PostgresRow) -> StoredAsset {
    StoredAsset {
        id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        project_id: row.get::<_, Option<String>>(2),
        asset_type: row.get::<_, String>(3),
        name: row.get::<_, String>(4),
        version: row.get::<_, String>(5),
        content_type: row.get::<_, String>(6),
        content_hash: row.get::<_, String>(7),
        size_bytes: nonnegative_u64(row.get::<_, i64>(8)),
        content: row.get::<_, Vec<u8>>(9),
        created_at_unix: row.get::<_, i64>(10),
        updated_at_unix: row.get::<_, i64>(11),
        storage_uri: row.get::<_, Option<String>>(12),
        variant: row.get::<_, String>(13),
        yanked: row.get::<_, bool>(14),
        visibility: AssetVisibility::from_stored(&row.get::<_, String>(15)),
    }
}

pub(crate) fn asset_channel_from_row(row: &PostgresRow) -> StoredAssetChannel {
    StoredAssetChannel {
        id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        asset_type: row.get::<_, String>(2),
        name: row.get::<_, String>(3),
        channel: row.get::<_, String>(4),
        version: row.get::<_, String>(5),
        updated_at_unix: row.get::<_, i64>(6),
    }
}

pub(crate) fn retention_policy_from_row(row: &PostgresRow) -> StoredRetentionPolicy {
    StoredRetentionPolicy {
        id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        resource_type: row.get::<_, String>(2),
        scope: row.get::<_, String>(3),
        // #263: keep_last_n is stored as a nullable BIGINT; a negative value
        // would be nonsensical, so clamp to a non-negative count.
        keep_last_n: row
            .get::<_, Option<i64>>(4)
            .map(|value| value.max(0) as u64),
        max_age_secs: row.get::<_, Option<i64>>(5),
        min_age_secs: row.get::<_, i64>(6),
        created_at_unix: row.get::<_, i64>(7),
        updated_at_unix: row.get::<_, i64>(8),
    }
}

pub(crate) fn ledger_entry_from_row(
    row: &PostgresRow,
) -> Result<ferrogate_billing::LedgerEntry, StorageError> {
    deserialize_storage_document(&row.get::<_, String>(0))
}

pub(crate) fn billing_report_outbox_from_row(
    row: &PostgresRow,
) -> Result<StoredBillingReportOutboxEntry, StorageError> {
    Ok(StoredBillingReportOutboxEntry {
        id: row.get::<_, String>(0),
        event: deserialize_storage_document(&row.get::<_, String>(1))?,
        // `attempts` is SQL INTEGER (i32); widen to i64 for the domain type.
        attempts: i64::from(row.get::<_, i32>(2)),
        next_attempt_unix: row.get::<_, i64>(3),
        dead_lettered_at_unix: row.get::<_, Option<i64>>(4),
    })
}

pub(crate) fn usage_monthly_rollup_from_row(
    row: &PostgresRow,
) -> Result<StoredUsageMonthlyRollup, StorageError> {
    let scope_type_raw: String = row.get(2);
    let scope_type = QuotaScopeKind::from_str_opt(&scope_type_raw).ok_or_else(|| {
        StorageError::Runtime(format!(
            "unknown usage_monthly_rollups.scope_type {scope_type_raw}"
        ))
    })?;
    Ok(StoredUsageMonthlyRollup {
        id: row.get(0),
        period_month: row.get(1),
        scope_type,
        scope_id: row.get(3),
        prompt_tokens: nonnegative_u64(row.get(4)),
        completion_tokens: nonnegative_u64(row.get(5)),
        total_tokens: nonnegative_u64(row.get(6)),
        cost_usd: row.get(7),
        request_count: nonnegative_u64(row.get(8)),
        error_count: nonnegative_u64(row.get(9)),
        updated_at_unix: row.get(10),
    })
}

pub(crate) fn usage_aggregate_from_row(row: PostgresRow) -> StoredUsageAggregate {
    StoredUsageAggregate {
        id: row.get(0),
        organization_id: row.get(1),
        project_id: row.get(2),
        api_key_id: row.get(3),
        logical_model: row.get(4),
        provider: row.get(5),
        usage: TokenUsage {
            prompt_tokens: nonnegative_u64(row.get(6)),
            completion_tokens: nonnegative_u64(row.get(7)),
            total_tokens: nonnegative_u64(row.get(8)),
        },
    }
}

pub(crate) fn managed_worker_template_from_row(row: PostgresRow) -> StoredManagedWorkerTemplate {
    StoredManagedWorkerTemplate {
        id: row.get(0),
        framework_adapter: row.get(1),
        isolation_backend_kind: row.get(2),
        enabled: row.get(3),
        max_tenant_sessions: row
            .get::<_, Option<i64>>(4)
            .and_then(|value| u32::try_from(value).ok()),
        max_workspace_sessions: row
            .get::<_, Option<i64>>(5)
            .and_then(|value| u32::try_from(value).ok()),
        created_at_unix: Some(nonnegative_u64(row.get(6))),
        updated_at_unix: Some(nonnegative_u64(row.get(7))),
    }
}

pub(crate) fn agent_worker_instance_from_row(row: PostgresRow) -> StoredAgentWorkerInstance {
    StoredAgentWorkerInstance {
        id: row.get(0),
        process_name: row.get(1),
        host_id: row.get(2),
        worker_version: row.get(3),
        status: row.get(4),
        started_at_unix: Some(nonnegative_u64(row.get(5))),
        last_seen_at_unix: row.get::<_, Option<i64>>(6).map(nonnegative_u64),
        process_json: row.get(7),
    }
}

pub(crate) fn managed_worker_session_from_row(row: PostgresRow) -> StoredManagedWorkerSession {
    StoredManagedWorkerSession {
        id: row.get(0),
        run_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        worker_template_id: row.get(4),
        agent_worker_instance_id: row.get(5),
        status: row.get(6),
        isolation_backend_kind: row.get(7),
        microvm_id: row.get(8),
        capability_envelope_id: row.get(9),
        requested_at_unix: Some(nonnegative_u64(row.get(10))),
        started_at_unix: row.get::<_, Option<i64>>(11).map(nonnegative_u64),
        completed_at_unix: row.get::<_, Option<i64>>(12).map(nonnegative_u64),
        cleanup_completed_at_unix: row.get::<_, Option<i64>>(13).map(nonnegative_u64),
        capability_envelope_json: row.get(14),
        resource_limits_json: row.get(15),
    }
}

pub(crate) fn managed_worker_lifecycle_event_from_row(
    row: PostgresRow,
) -> StoredManagedWorkerLifecycleEvent {
    StoredManagedWorkerLifecycleEvent {
        id: row.get(0),
        session_id: row.get(1),
        run_id: row.get(2),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(3).as_deref()),
        workspace_id: row.get(4),
        agent_worker_instance_id: row.get(5),
        status: row.get(6),
        action: row.get(7),
        outcome: row.get(8),
        occurred_at_unix: Some(nonnegative_u64(row.get(9))),
        evidence_json: row.get(10),
    }
}

pub(crate) fn managed_worker_isolation_selection_from_row(
    row: PostgresRow,
) -> StoredManagedWorkerIsolationSelection {
    StoredManagedWorkerIsolationSelection {
        session_id: row.get(0),
        run_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        agent_worker_instance_id: row.get(4),
        backend_name: row.get(5),
        backend_version: row.get(6),
        backend_kind: row.get(7),
        host_lifecycle_owner: row.get(8),
        gateway_controls_backend: row.get(9),
        capability_envelope_id: row.get(10),
        selected_at_unix: Some(nonnegative_u64(row.get(11))),
    }
}

pub(crate) fn managed_worker_isolation_policy_from_row(
    row: PostgresRow,
) -> StoredManagedWorkerIsolationPolicy {
    StoredManagedWorkerIsolationPolicy {
        session_id: row.get(0),
        cpu_count: u16::try_from(row.get::<_, i32>(1)).unwrap_or_default(),
        memory_mib: u32::try_from(row.get::<_, i32>(2)).unwrap_or_default(),
        disk_mib: u32::try_from(row.get::<_, i32>(3)).unwrap_or_default(),
        max_runtime_millis: row.get::<_, Option<i64>>(4).map(nonnegative_u64),
        direct_public_egress: row.get(5),
        gateway_control_channel: row.get(6),
        governed_egress: row.get(7),
        read_only_rootfs: row.get(8),
        writable_workspace: row.get(9),
        host_path_mounts: row.get(10),
    }
}

pub(crate) fn managed_worker_isolation_evidence_from_row(
    row: PostgresRow,
) -> StoredManagedWorkerIsolationEvidence {
    StoredManagedWorkerIsolationEvidence {
        id: row.get(0),
        session_id: row.get(1),
        lifecycle_event_id: row.get(2),
        run_id: row.get(3),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(4).as_deref()),
        workspace_id: row.get(5),
        agent_worker_instance_id: row.get(6),
        isolation_instance_id: row.get(7),
        action: row.get(8),
        outcome: row.get(9),
        failure_reason: row.get(10),
        occurred_at_unix: Some(nonnegative_u64(row.get(11))),
        evidence_json: row.get(12),
    }
}

pub(crate) fn self_hosted_worker_registration_from_row(
    row: PostgresRow,
) -> StoredSelfHostedWorkerRegistration {
    StoredSelfHostedWorkerRegistration {
        id: row.get(0),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(1).as_deref()),
        workspace_id: row.get(2),
        worker_name: row.get(3),
        status: row.get(4),
        identity_fingerprint: row.get(5),
        identity_expires_at_unix: row.get::<_, Option<i64>>(6).map(nonnegative_u64),
        orchestration_enabled: row.get(7),
        registered_at_unix: Some(nonnegative_u64(row.get(8))),
        last_seen_at_unix: row.get::<_, Option<i64>>(9).map(nonnegative_u64),
        trust_level: row.get(10),
        capability_envelope_json: row.get(11),
        token_secret: row.get(12),
    }
}

pub(crate) fn self_hosted_worker_heartbeat_from_row(
    row: PostgresRow,
) -> StoredSelfHostedWorkerHeartbeat {
    StoredSelfHostedWorkerHeartbeat {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        status: row.get(4),
        reported_at_unix: Some(nonnegative_u64(row.get(5))),
        observed_at_unix: Some(nonnegative_u64(row.get(6))),
        heartbeat_json: row.get(7),
    }
}

pub(crate) fn self_hosted_worker_telemetry_event_from_row(
    row: PostgresRow,
) -> StoredSelfHostedWorkerTelemetryEvent {
    StoredSelfHostedWorkerTelemetryEvent {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        kind: row.get(6),
        trust_level: row.get(7),
        occurred_at_unix: Some(nonnegative_u64(row.get(8))),
        ingested_at_unix: Some(nonnegative_u64(row.get(9))),
        event_json: row.get(10),
        request_id: row.get(11),
        trace_id: row.get(12),
        agent_run_id: row.get(13),
        parent_action_fingerprint: row.get(14),
    }
}

pub(crate) fn self_hosted_worker_artifact_from_row(
    row: PostgresRow,
) -> StoredSelfHostedWorkerArtifact {
    StoredSelfHostedWorkerArtifact {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        artifact_name: row.get(6),
        content_type: row.get(7),
        size_bytes: nonnegative_u64(row.get(8)),
        trust_level: row.get(9),
        created_at_unix: Some(nonnegative_u64(row.get(10))),
        artifact_json: row.get(11),
    }
}

pub(crate) fn self_hosted_worker_checkpoint_from_row(
    row: PostgresRow,
) -> StoredSelfHostedWorkerCheckpoint {
    StoredSelfHostedWorkerCheckpoint {
        id: row.get(0),
        worker_id: row.get(1),
        tenant: tenant_from_storage_key(row.get::<_, Option<String>>(2).as_deref()),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        checkpoint_name: row.get(6),
        size_bytes: nonnegative_u64(row.get(7)),
        trust_level: row.get(8),
        created_at_unix: Some(nonnegative_u64(row.get(9))),
        checkpoint_json: row.get(10),
    }
}

pub(crate) fn self_hosted_run_dispatch_from_row(
    row: PostgresRow,
    capabilities: &HashMap<String, Vec<String>>,
) -> StoredSelfHostedRunDispatch {
    let dispatch_id = row.get::<_, String>(0);
    StoredSelfHostedRunDispatch {
        required_capabilities: capabilities.get(&dispatch_id).cloned().unwrap_or_default(),
        dispatch_id,
        action: row.get(1),
        tenant_id: row.get::<_, Option<String>>(2).unwrap_or_default(),
        workspace_id: row.get(3),
        session_id: row.get(4),
        run_id: row.get(5),
        framework_adapter: row.get(6),
        workload_ref: row.get(7),
        queued_at_unix: Some(nonnegative_u64(row.get(8))),
        assigned_worker_id: row.get(9),
        lease_id: row.get(10),
        lease_expires_at_unix: row.get::<_, Option<i64>>(11).map(nonnegative_u64),
        attempt: nonnegative_u32(row.get(12)),
        acknowledged_status: row.get(13),
        acknowledged_at_unix: row.get::<_, Option<i64>>(14).map(nonnegative_u64),
        request_id: row.get(15),
        trace_id: row.get(16),
        agent_run_id: row.get(17),
        parent_action_fingerprint: row.get(18),
    }
}

pub(crate) fn guardrail_policy_revision_from_row(
    row: PostgresRow,
) -> Result<StoredGuardrailPolicyRevision, StorageError> {
    let revision = row.get::<_, i64>(2);
    Ok(StoredGuardrailPolicyRevision {
        id: row.get(0),
        policy_id: row.get(1),
        revision: u32::try_from(revision).map_err(|_| {
            StorageError::Serialization("guardrail policy revision is out of range".into())
        })?,
        policy_json: row.get(3),
        created_at_unix: nonnegative_u64(row.get(4)),
        created_by: row.get(5),
    })
}

pub(crate) fn guardrail_policy_binding_from_row(
    row: PostgresRow,
) -> Result<StoredGuardrailPolicyBinding, StorageError> {
    let active_revision = row
        .get::<_, Option<i64>>(1)
        .map(|revision| {
            u32::try_from(revision).map_err(|_| {
                StorageError::Serialization(
                    "active guardrail policy revision is out of range".into(),
                )
            })
        })
        .transpose()?;
    let archived_revisions = deserialize_storage_document::<Vec<u32>>(&row.get::<_, String>(2))?;
    Ok(StoredGuardrailPolicyBinding {
        policy_id: row.get(0),
        active_revision,
        archived_revisions,
        updated_at_unix: nonnegative_u64(row.get(3)),
        updated_by: row.get(4),
        generation: nonnegative_u64(row.get(5)),
    })
}
