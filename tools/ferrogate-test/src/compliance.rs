// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Reusable cross-component runtime compliance contracts for issue #210.

use crate::{
    cli::{LocalArgs, SupabaseLiveRestartArgs},
    constants::{ADMIN_AUTH, JSON_CONTENT},
    http::http_request_addr,
    local::{BillingHarness, LocalHarness},
    mocks::spawn_local_provider_upstream_with_timeout,
    supabase_schema::{
        connect_live_supabase, LiveSupabaseClient, LiveSupabaseScenario, LiveSupabaseSchema,
    },
};
use anyhow::{bail, Context, Result};
use ferrogate_billing::{BillingEvent, BillingUsageSource, ProviderAttempt, TokenUsage};
use ferrogate_core::TenantContext;
use ferrogate_storage::{
    ControlPlaneDocuments, PostgresStorageConfig, PostgresTlsMode, RuntimeStorageOptions,
    RuntimeStorageRepositories, StorageProviderKind,
};
use serde_json::{json, Value};
use std::{
    env,
    fmt::Debug,
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

const PROVIDER_ATTEMPT_V29_FIXTURE_SQL: &str = r#"
CREATE TABLE tenant_contexts (
    id TEXT PRIMARY KEY,
    organization_id TEXT,
    team_id TEXT,
    project_id TEXT,
    user_id TEXT,
    api_key_id TEXT,
    workspace_id TEXT
);
CREATE TABLE metering_events (
    request_id TEXT PRIMARY KEY,
    tenant_context_id TEXT NOT NULL REFERENCES tenant_contexts(id),
    trace_id TEXT,
    agent_run_id TEXT,
    workflow_id TEXT,
    workflow_version INTEGER,
    workflow_node_id TEXT,
    cluster_id TEXT,
    node_id TEXT,
    status_code INTEGER NOT NULL,
    occurred_at_unix BIGINT NOT NULL,
    cost_usd DOUBLE PRECISION,
    latency_ms BIGINT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE metering_event_routes (
    request_id TEXT PRIMARY KEY REFERENCES metering_events(request_id) ON DELETE CASCADE,
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_model TEXT
);
CREATE TABLE metering_event_usage (
    request_id TEXT PRIMARY KEY REFERENCES metering_events(request_id) ON DELETE CASCADE,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    usage_source TEXT NOT NULL
);
CREATE TABLE billing_ledger (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    trace_id TEXT,
    organization_id TEXT,
    project_id TEXT,
    workspace_id TEXT,
    api_key_id TEXT,
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_model TEXT NOT NULL,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    usage_source TEXT NOT NULL DEFAULT 'provider_usage',
    status_code INTEGER NOT NULL DEFAULT 0,
    input_cost DOUBLE PRECISION NOT NULL DEFAULT 0,
    output_cost DOUBLE PRECISION NOT NULL DEFAULT 0,
    total_cost DOUBLE PRECISION NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'USD',
    credits DOUBLE PRECISION NOT NULL DEFAULT 0,
    entry_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at_unix BIGINT,
    created_at_unix BIGINT NOT NULL
);
CREATE TABLE storage_schema_migrations (
    version BIGINT PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL DEFAULT '',
    applied_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);
INSERT INTO storage_schema_migrations(version, name)
VALUES (29, '029_tenant_only_asset_storage_quota');
INSERT INTO tenant_contexts
    (id, organization_id, project_id, workspace_id, api_key_id)
VALUES ('v29-tenant-context', 'v29-org', 'v29-project', 'v29-workspace', 'v29-key');
INSERT INTO metering_events
    (request_id, tenant_context_id, trace_id, status_code, occurred_at_unix,
     cost_usd, latency_ms, metadata_json)
VALUES ('v29-request', 'v29-tenant-context', 'v29-trace', 200, 1783641600,
        0.000011, 9, '{"fixture":"v29"}');
INSERT INTO metering_event_routes
    (request_id, logical_model, provider, provider_model)
VALUES ('v29-request', 'v29-model', 'openai', 'v29-provider-model');
INSERT INTO metering_event_usage
    (request_id, prompt_tokens, completion_tokens, total_tokens, usage_source)
VALUES ('v29-request', 3, 4, 7, 'provider_usage');
INSERT INTO billing_ledger
    (id, request_id, trace_id, organization_id, project_id, workspace_id, api_key_id,
     logical_model, provider, provider_model, prompt_tokens, completion_tokens,
     total_tokens, usage_source, status_code, input_cost, output_cost, total_cost,
     currency, credits, entry_json, occurred_at_unix, created_at_unix)
VALUES (
    'v29-ledger', 'v29-request', 'v29-trace', 'v29-org', 'v29-project',
    'v29-workspace', 'v29-key', 'v29-model', 'openai', 'v29-provider-model',
    3, 4, 7, 'provider_usage', 200, 0.000003, 0.000008, 0.000011,
    'USD', 11,
    '{"id":"v29-ledger","request_id":"v29-request","trace_id":"v29-trace","tenant":{"organization_id":"v29-org","project_id":"v29-project","workspace_id":"v29-workspace","api_key_id":"v29-key"},"logical_model":"v29-model","provider":"openai","provider_model":"v29-provider-model","usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7},"usage_source":"provider_usage","status_code":200,"cost":{"input_cost":0.000003,"output_cost":0.000008,"total_cost":0.000011,"currency":"USD"},"credits":11.0,"unit_price":{"input_price_per_1m":1.0,"output_price_per_1m":2.0,"currency":"USD"},"cost_source":"gateway_settled","occurred_at_unix":1783641600}',
    1783641600, 1783641600
);
"#;

pub(crate) trait ComponentContract {
    type Case: Debug;
    type Written: Debug + PartialEq;
    type Runtime: Debug;

    fn name(&self) -> &'static str;
    fn cases(&self) -> Vec<Self::Case>;
    fn write(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Written>;
    fn read(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Written>;
    fn exercise(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Runtime>;
    fn verify(
        &self,
        case: &Self::Case,
        written: &Self::Written,
        runtime: &Self::Runtime,
    ) -> Result<()>;
    fn cleanup(&self, gateway_addr: &str, case: &Self::Case) -> Result<()>;
}

pub(crate) fn run_component_compliance(args: &LocalArgs) -> Result<()> {
    let harness = LocalHarness::start(&args.ferrogate_bin, 0)?;
    run_component_compliance_at(&harness.gateway_addr)?;
    crate::provider_compliance::run_provider_compliance(args)?;
    println!("component-compliance scenario passed");
    Ok(())
}

pub(crate) fn run_component_compliance_supabase(args: &SupabaseLiveRestartArgs) -> Result<()> {
    if args.supabase_dsn.trim().is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    if !args.local.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run cargo build -p ferrogate-cli first",
            args.local.ferrogate_bin.display()
        );
    }
    let mut schema = LiveSupabaseSchema::create(args, LiveSupabaseScenario::Compliance)?;
    let schema_name = schema.name().to_string();
    let mut evidence = SupabaseEvidence::connect(args, schema_name.clone())?;
    let gateway_addr = crate::http::free_addr()?;
    evidence.install_provider_attempt_v29_fixture()?;
    evidence.inject_provider_attempt_migration_failure()?;
    let failed = BillingHarness::start_supabase(
        &args.local.ferrogate_bin,
        args.supabase_dsn.trim(),
        &schema_name,
        args.tls_mode.trim(),
    );
    if failed.is_ok() {
        bail!("fault-injected provider-attempt migration unexpectedly succeeded");
    }
    evidence.verify_provider_attempt_migration_rollback()?;
    evidence.clear_provider_attempt_migration_failure()?;
    let (initializer_a, initializer_b) = BillingHarness::start_supabase_concurrent_pair(
        &args.local.ferrogate_bin,
        args.supabase_dsn.trim(),
        &schema_name,
        args.tls_mode.trim(),
    )?;
    drop(initializer_a);
    drop(initializer_b);
    evidence.verify_provider_attempt_v29_upgrade()?;
    evidence.verify_validate_only_provider_attempt_contract(args)?;
    let stable_constraints = evidence.provider_attempt_constraint_identity()?;
    let billing = BillingHarness::start_supabase(
        &args.local.ferrogate_bin,
        args.supabase_dsn.trim(),
        &schema_name,
        args.tls_mode.trim(),
    )?;
    let restarted_constraints = evidence.provider_attempt_constraint_identity()?;
    if stable_constraints != restarted_constraints {
        bail!(
            "existing migration 30 reran destructive provider-attempt DDL: before={stable_constraints:?}, after={restarted_constraints:?}"
        );
    }
    let mut provider =
        ComplianceProvider::start(crate::provider_compliance::expected_provider_requests())?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("component-compliance-supabase.yaml");
    fs::write(
        &config_path,
        compliance_supabase_config(
            &gateway_addr,
            &schema_name,
            &provider.addr,
            &billing.billing_addr,
            args,
        )?,
    )?;
    let gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &config_path,
        &gateway_addr,
        args.supabase_dsn.trim(),
    )?;
    run_component_compliance_at(&gateway_addr)?;
    provision_provider_wallet(&gateway_addr)?;
    crate::provider_compliance::run_provider_compliance_at(&gateway_addr, &billing)?;
    run_live_repository_replay(args, &schema_name)?;
    let requests = provider.finish()?;
    crate::provider_compliance::assert_upstream_attempts(&requests)?;
    evidence.verify_contract_cleanup()?;
    drop(gateway);
    drop(billing);
    drop(evidence);
    schema.finish()?;
    println!("component-compliance-supabase scenario passed");
    Ok(())
}

pub(crate) fn run_component_compliance_at(gateway_addr: &str) -> Result<()> {
    let fixture = bootstrap_quota_fixture(gateway_addr)?;
    // #351: operator config -> Admin API effective policy -> runtime decision,
    // with allow / approval-required / deny cases proving the declaration the
    // operator wrote is the one the policy evaluation reads.
    assert_component_contract(
        gateway_addr,
        &crate::x402_spend_policy::X402SpendPolicyContract::new(),
    )?;
    crate::x402_spend_policy::assert_x402_spend_policy_surface(gateway_addr)?;
    assert_component_contract(gateway_addr, &QuotaScopeContract::new(&fixture))?;
    assert_component_contract(gateway_addr, &TenantAssetQuotaContract::new(&fixture))?;
    assert_narrow_asset_quota_scopes_are_rejected(gateway_addr, &fixture)?;
    // Runs last: it provisions the shared compliance tenant's prepaid wallet
    // (a 0-credit, i.e. already-exhausted, wallet), which would otherwise 429
    // the earlier chat/asset exercises before they reach their own gates.
    assert_component_contract(gateway_addr, &WalletExhaustionContract::new(&fixture))?;
    Ok(())
}

pub(crate) fn assert_component_contract<C: ComponentContract>(
    gateway_addr: &str,
    contract: &C,
) -> Result<()> {
    for case in contract.cases() {
        let result = (|| {
            let written = contract.write(gateway_addr, &case)?;
            let read = contract.read(gateway_addr, &case)?;
            if written != read {
                bail!(
                    "write/read mismatch for {} case {case:?}: wrote {written:?}, read {read:?}",
                    contract.name()
                );
            }
            let runtime = contract.exercise(gateway_addr, &case)?;
            contract.verify(&case, &written, &runtime)
        })()
        .with_context(|| {
            format!(
                "{} component contract case {case:?} failed",
                contract.name()
            )
        });

        let cleanup = contract
            .cleanup(gateway_addr, &case)
            .with_context(|| format!("{} cleanup for case {case:?} failed", contract.name()));
        match (result, cleanup) {
            (Err(error), _) => return Err(error),
            (Ok(()), Err(error)) => return Err(error),
            (Ok(()), Ok(())) => {}
        }
    }
    Ok(())
}

#[derive(Debug)]
struct QuotaFixture {
    key_id: String,
    key_secret: String,
}

#[derive(Clone, Copy, Debug)]
struct ScopeCase<'a> {
    scope_type: &'static str,
    scope_id: &'a str,
}

#[derive(Debug, PartialEq)]
struct QuotaPolicyProjection {
    scope_type: String,
    scope_id: String,
    enabled: bool,
}

#[derive(Debug)]
struct RuntimeDecision {
    status: u16,
    code: Option<String>,
}

struct QuotaScopeContract<'a> {
    fixture: &'a QuotaFixture,
}

impl<'a> QuotaScopeContract<'a> {
    fn new(fixture: &'a QuotaFixture) -> Self {
        Self { fixture }
    }
}

impl<'a> ComponentContract for QuotaScopeContract<'a> {
    type Case = ScopeCase<'a>;
    type Written = QuotaPolicyProjection;
    type Runtime = RuntimeDecision;

    fn name(&self) -> &'static str {
        "quota-scope-runtime"
    }

    fn cases(&self) -> Vec<Self::Case> {
        vec![
            ScopeCase {
                scope_type: "tenant",
                scope_id: "compliance-tenant",
            },
            ScopeCase {
                scope_type: "project",
                scope_id: "compliance-project",
            },
            ScopeCase {
                scope_type: "workspace",
                scope_id: "compliance-workspace",
            },
            ScopeCase {
                scope_type: "key",
                scope_id: &self.fixture.key_id,
            },
        ]
    }

    fn write(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Written> {
        quota_policy_request(gateway_addr, "PUT", case, r#"{"enabled":false}"#, 200)
    }

    fn read(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Written> {
        quota_policy_request(gateway_addr, "GET", case, "", 200)
    }

    fn exercise(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Runtime> {
        let auth = format!("Authorization: Bearer {}", self.fixture.key_secret);
        runtime_decision(
            gateway_addr,
            "POST",
            "/v1/chat/completions",
            &[&auth, JSON_CONTENT],
            r#"{"model":"fast-chat","messages":[]}"#,
        )
    }

    fn verify(
        &self,
        _case: &Self::Case,
        written: &Self::Written,
        runtime: &Self::Runtime,
    ) -> Result<()> {
        if written.enabled {
            bail!("quota contract fixture must write enabled=false");
        }
        if runtime.status != 403 || runtime.code.as_deref() != Some("quota_scope_disabled") {
            bail!("runtime ignored disabled quota scope: {runtime:?}");
        }
        Ok(())
    }

    fn cleanup(&self, gateway_addr: &str, case: &Self::Case) -> Result<()> {
        let path = quota_policy_path(case);
        expect_status(gateway_addr, "DELETE", &path, &[ADMIN_AUTH], "", 200)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct TenantAssetCase;

#[derive(Debug, PartialEq)]
struct AssetQuotaProjection {
    bytes: u64,
}

struct TenantAssetQuotaContract<'a> {
    fixture: &'a QuotaFixture,
}

impl<'a> TenantAssetQuotaContract<'a> {
    fn new(fixture: &'a QuotaFixture) -> Self {
        Self { fixture }
    }
}

impl ComponentContract for TenantAssetQuotaContract<'_> {
    type Case = TenantAssetCase;
    type Written = AssetQuotaProjection;
    type Runtime = RuntimeDecision;

    fn name(&self) -> &'static str {
        "tenant-asset-quota-runtime"
    }

    fn cases(&self) -> Vec<Self::Case> {
        vec![TenantAssetCase]
    }

    fn write(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Written> {
        asset_quota_projection(
            gateway_addr,
            "PUT",
            r#"{"asset_storage_quota_bytes":50}"#,
            200,
        )
    }

    fn read(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Written> {
        asset_quota_projection(gateway_addr, "GET", "", 200)
    }

    fn exercise(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Runtime> {
        let auth = format!("Authorization: Bearer {}", self.fixture.key_secret);
        expect_status(
            gateway_addr,
            "PUT",
            "/v1/assets/config_file/compliance-first/1.0.0",
            &[&auth, "Content-Type: text/plain"],
            &"a".repeat(30),
            200,
        )?;
        runtime_decision(
            gateway_addr,
            "PUT",
            "/v1/assets/config_file/compliance-second/1.0.0",
            &[&auth, "Content-Type: text/plain"],
            &"b".repeat(30),
        )
    }

    fn verify(
        &self,
        _case: &Self::Case,
        written: &Self::Written,
        runtime: &Self::Runtime,
    ) -> Result<()> {
        if written.bytes != 50 {
            bail!("tenant asset quota fixture must write 50 bytes");
        }
        if runtime.status != 403 || runtime.code.as_deref() != Some("asset_storage_quota_exceeded")
        {
            bail!("runtime ignored tenant asset quota: {runtime:?}");
        }
        Ok(())
    }

    fn cleanup(&self, gateway_addr: &str, _case: &Self::Case) -> Result<()> {
        let auth = format!("Authorization: Bearer {}", self.fixture.key_secret);
        expect_status(
            gateway_addr,
            "DELETE",
            "/v1/assets/config_file/compliance-first/1.0.0",
            &[&auth],
            "",
            200,
        )?;
        expect_status(
            gateway_addr,
            "DELETE",
            "/admin/v1/quota-policies/tenant/compliance-tenant",
            &[ADMIN_AUTH],
            "",
            200,
        )?;
        Ok(())
    }
}

/// End-to-end proof for the prepaid-wallet balance gate (issue #169) as it
/// flows through the `authenticate` -> `finalize_auth` -> `wallet_balance_exhausted`
/// chain that issue #373 converted to `async` (dropping the last quota-read
/// `block_on_sync_bridge`). A freshly created wallet starts at 0 credits, and
/// `wallet_balance_exhausted` treats `balance <= 0` as exhausted, so creating
/// the compliance tenant's wallet is the minimal exhausted-wallet fixture.
struct WalletExhaustionContract<'a> {
    fixture: &'a QuotaFixture,
}

impl<'a> WalletExhaustionContract<'a> {
    fn new(fixture: &'a QuotaFixture) -> Self {
        Self { fixture }
    }
}

#[derive(Clone, Copy, Debug)]
struct WalletExhaustionCase;

#[derive(Debug, PartialEq)]
struct WalletBalanceProjection {
    balance_credits: i64,
}

impl ComponentContract for WalletExhaustionContract<'_> {
    type Case = WalletExhaustionCase;
    type Written = WalletBalanceProjection;
    type Runtime = RuntimeDecision;

    fn name(&self) -> &'static str {
        "wallet-exhaustion-runtime"
    }

    fn cases(&self) -> Vec<Self::Case> {
        vec![WalletExhaustionCase]
    }

    fn write(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Written> {
        wallet_balance_projection(
            gateway_addr,
            "POST",
            "/admin/v1/wallets",
            r#"{"tenant_id":"compliance-tenant"}"#,
            201,
        )
    }

    fn read(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Written> {
        wallet_balance_projection(
            gateway_addr,
            "GET",
            "/admin/v1/wallets/compliance-tenant",
            "",
            200,
        )
    }

    fn exercise(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Runtime> {
        let auth = format!("Authorization: Bearer {}", self.fixture.key_secret);
        runtime_decision(
            gateway_addr,
            "POST",
            "/v1/chat/completions",
            &[&auth, JSON_CONTENT],
            r#"{"model":"fast-chat","messages":[]}"#,
        )
    }

    fn verify(
        &self,
        _case: &Self::Case,
        written: &Self::Written,
        runtime: &Self::Runtime,
    ) -> Result<()> {
        if written.balance_credits > 0 {
            bail!("wallet exhaustion fixture must start non-positive, got {written:?}");
        }
        if runtime.status != 429 || runtime.code.as_deref() != Some("wallet_balance_exhausted") {
            bail!("runtime admitted a request against an exhausted prepaid wallet: {runtime:?}");
        }
        Ok(())
    }

    fn cleanup(&self, gateway_addr: &str, _case: &Self::Case) -> Result<()> {
        // Wallets are not deletable (balance only ever moves through `/adjust`),
        // so restore a positive balance to leave the shared compliance-tenant
        // wallet non-exhausted for anything that runs after.
        expect_status(
            gateway_addr,
            "POST",
            "/admin/v1/wallets/compliance-tenant/adjust",
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"delta_credits":1000000}"#,
            200,
        )?;
        Ok(())
    }
}

fn wallet_balance_projection(
    gateway_addr: &str,
    method: &str,
    path: &str,
    body: &str,
    expected_status: u16,
) -> Result<WalletBalanceProjection> {
    let response = expect_json(
        gateway_addr,
        method,
        path,
        if body.is_empty() {
            &[ADMIN_AUTH]
        } else {
            &[ADMIN_AUTH, JSON_CONTENT]
        },
        body,
        expected_status,
    )?;
    Ok(WalletBalanceProjection {
        balance_credits: response["wallet"]["balance_credits"]
            .as_i64()
            .context("wallet.balance_credits must be a signed integer")?,
    })
}

fn bootstrap_quota_fixture(gateway_addr: &str) -> Result<QuotaFixture> {
    expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[ADMIN_AUTH, JSON_CONTENT],
        &json!({
            "id": "compliance-tenant",
            "name": "Component compliance tenant",
            "slug": "component-compliance-tenant"
        })
        .to_string(),
        201,
    )?;
    expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/plans",
        &[ADMIN_AUTH, JSON_CONTENT],
        &json!({
            "id": "compliance-plan",
            "name": "Component compliance plan",
            "slug": "component-compliance-plan",
            "asset_hosting_enabled": true,
            "default_asset_storage_quota_bytes": 1_000
        })
        .to_string(),
        201,
    )?;
    expect_json(
        gateway_addr,
        "PATCH",
        "/admin/v1/tenant-accounts/compliance-tenant",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"plan_id":"compliance-plan"}"#,
        200,
    )?;
    expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/projects",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"compliance-project","tenant_id":"compliance-tenant","name":"Component compliance project","slug":"component-compliance-project"}"#,
        201,
    )?;
    expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"compliance-workspace","project_id":"compliance-project","name":"Component compliance workspace","slug":"component-compliance-workspace"}"#,
        201,
    )?;
    let key = expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"name":"Component compliance key","workspace_id":"compliance-workspace","scopes":["assets.read","assets.write","chat.completions"],"allowed_models":["fast-chat"]}"#,
        201,
    )?;
    Ok(QuotaFixture {
        key_id: required_string(&key["key"]["id"], "virtual-key response key.id")?,
        key_secret: required_string(&key["secret"], "virtual-key response secret")?,
    })
}

fn assert_narrow_asset_quota_scopes_are_rejected(
    gateway_addr: &str,
    fixture: &QuotaFixture,
) -> Result<()> {
    for case in [
        ScopeCase {
            scope_type: "project",
            scope_id: "compliance-project",
        },
        ScopeCase {
            scope_type: "workspace",
            scope_id: "compliance-workspace",
        },
        ScopeCase {
            scope_type: "key",
            scope_id: &fixture.key_id,
        },
    ] {
        let path = quota_policy_path(&case);
        let rejected = expect_json(
            gateway_addr,
            "PUT",
            &path,
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"asset_storage_quota_bytes":50}"#,
            400,
        )?;
        if rejected["error"]["code"] != "invalid_quota_policy" {
            bail!("narrow asset quota returned the wrong error: {rejected}");
        }
        expect_status(gateway_addr, "GET", &path, &[ADMIN_AUTH], "", 404)?;
    }
    Ok(())
}

fn quota_policy_request(
    gateway_addr: &str,
    method: &str,
    case: &ScopeCase<'_>,
    body: &str,
    expected_status: u16,
) -> Result<QuotaPolicyProjection> {
    let path = quota_policy_path(case);
    let response = expect_json(
        gateway_addr,
        method,
        &path,
        if body.is_empty() {
            &[ADMIN_AUTH]
        } else {
            &[ADMIN_AUTH, JSON_CONTENT]
        },
        body,
        expected_status,
    )?;
    Ok(QuotaPolicyProjection {
        scope_type: required_string(&response["policy"]["scope_type"], "policy.scope_type")?,
        scope_id: required_string(&response["policy"]["scope_id"], "policy.scope_id")?,
        enabled: response["policy"]["enabled"]
            .as_bool()
            .context("policy.enabled must be a boolean")?,
    })
}

fn asset_quota_projection(
    gateway_addr: &str,
    method: &str,
    body: &str,
    expected_status: u16,
) -> Result<AssetQuotaProjection> {
    let response = expect_json(
        gateway_addr,
        method,
        "/admin/v1/quota-policies/tenant/compliance-tenant",
        if body.is_empty() {
            &[ADMIN_AUTH]
        } else {
            &[ADMIN_AUTH, JSON_CONTENT]
        },
        body,
        expected_status,
    )?;
    Ok(AssetQuotaProjection {
        bytes: response["policy"]["asset_storage_quota_bytes"]
            .as_u64()
            .context("policy.asset_storage_quota_bytes must be an unsigned integer")?,
    })
}

fn runtime_decision(
    gateway_addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
) -> Result<RuntimeDecision> {
    let response = http_request_addr(gateway_addr, method, path, headers, body)?;
    let parsed = serde_json::from_str::<Value>(&response.body).ok();
    Ok(RuntimeDecision {
        status: response.status,
        code: parsed
            .as_ref()
            .and_then(|body| body["error"]["code"].as_str())
            .map(str::to_string),
    })
}

fn quota_policy_path(case: &ScopeCase<'_>) -> String {
    format!(
        "/admin/v1/quota-policies/{}/{}",
        case.scope_type, case.scope_id
    )
}

fn expect_json(
    gateway_addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
    expected_status: u16,
) -> Result<Value> {
    let response = http_request_addr(gateway_addr, method, path, headers, body)?;
    if response.status != expected_status {
        bail!(
            "{method} {path} expected status {expected_status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    serde_json::from_str(&response.body)
        .with_context(|| format!("{method} {path} returned invalid JSON: {}", response.body))
}

fn expect_status(
    gateway_addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
    expected_status: u16,
) -> Result<String> {
    let response = http_request_addr(gateway_addr, method, path, headers, body)?;
    if response.status != expected_status {
        bail!(
            "{method} {path} expected status {expected_status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    Ok(response.body)
}

fn required_string(value: &Value, field: &str) -> Result<String> {
    value
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("{field} must be a string, got {value}"))
}

fn provision_provider_wallet(gateway_addr: &str) -> Result<()> {
    provision_wallet(gateway_addr, "org_demo", "provider-compliance", 1_000_000)?;
    provision_wallet(gateway_addr, "org_replay", "provider-replay", 1_000)?;
    Ok(())
}

fn provision_wallet(
    gateway_addr: &str,
    tenant_id: &str,
    slug: &str,
    balance_credits: i64,
) -> Result<()> {
    expect_status(
        gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[ADMIN_AUTH, JSON_CONTENT],
        &json!({
            "id": tenant_id,
            "name": format!("{tenant_id} compliance tenant"),
            "slug": slug
        })
        .to_string(),
        201,
    )?;
    expect_status(
        gateway_addr,
        "POST",
        "/admin/v1/wallets",
        &[ADMIN_AUTH, JSON_CONTENT],
        &json!({"tenant_id": tenant_id}).to_string(),
        201,
    )?;
    expect_status(
        gateway_addr,
        "POST",
        &format!("/admin/v1/wallets/{tenant_id}/adjust"),
        &[ADMIN_AUTH, JSON_CONTENT],
        &json!({"delta_credits": balance_credits}).to_string(),
        200,
    )?;
    Ok(())
}

fn run_live_repository_replay(args: &SupabaseLiveRestartArgs, schema: &str) -> Result<()> {
    let tls_mode = match args.tls_mode.trim() {
        "require" => PostgresTlsMode::Require,
        "verify_ca" | "verify-ca" => PostgresTlsMode::VerifyCa,
        "verify_full" | "verify-full" => PostgresTlsMode::VerifyFull,
        other => bail!("unsupported live repository TLS mode {other}"),
    };
    let repositories = RuntimeStorageRepositories::supabase(
        PostgresStorageConfig {
            dsn: args.supabase_dsn.clone(),
            pool_size: 1,
            pool_acquire_timeout_millis: 30_000,
            tls_mode,
            tls_ca_cert_path: args
                .tls_ca_cert_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            connect_timeout_secs: 10,
            statement_timeout_millis: 30_000,
            schema: Some(schema.to_string()),
            search_path: vec!["public".into()],
        },
        RuntimeStorageOptions {
            provider_order: vec![StorageProviderKind::Supabase, StorageProviderKind::Postgres],
            required: true,
            initialize_schema: false,
            migration_mode: "validate_only".into(),
            control_plane: ControlPlaneDocuments::default(),
            request_log_retention_records: 0,
            audit_event_retention_records: 0,
        },
    )?;
    let attempt = ProviderAttempt {
        provider_attempt_id: "live-replay-attempt".into(),
        provider_attempt_index: 4,
    };
    let original = BillingEvent {
        request_id: "live-replay-request-original".into(),
        trace_id: Some("live-replay-trace-original".into()),
        provider_attempt: attempt,
        agent_run_id: Some("provider-compliance-live-replay".into()),
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("org_replay".into()),
            ..TenantContext::default()
        },
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: TokenUsage::new(3, 5, 8),
        usage_source: BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_783_641_600),
        cost_usd: Some(0.000_125),
        latency_ms: Some(10),
        metadata: Default::default(),
        wallet_delta_credits: Some(-125),
        wallet_balance_after_credits: Some(875),
    };
    let settlement_id = ferrogate_billing::ledger::ledger_entry_id(&original);
    // This CLI tool has no tokio runtime anywhere in its call chain (a plain
    // sync `main`), so bridge the now-async storage calls with a dedicated
    // current-thread runtime rather than threading async through the whole
    // compliance-check call graph.
    let bridge_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build live-repository-replay async bridge runtime")?;
    let first_wallet = bridge_runtime.block_on(repositories.settle_wallet_balance(
        &settlement_id,
        "org_replay",
        -125,
        1_783_641_600,
    ))?;
    if !first_wallet.newly_applied || first_wallet.settlement.balance_after_credits != Some(875) {
        bail!("live repository first wallet settlement did not apply exactly once");
    }
    if !bridge_runtime.block_on(repositories.append_billing_event(original.clone()))? {
        bail!("live repository first provider attempt was not recorded");
    }

    let replay = original.clone();
    let replay_wallet = bridge_runtime.block_on(repositories.settle_wallet_balance(
        &settlement_id,
        "org_replay",
        -125,
        1_783_641_999,
    ))?;
    if replay_wallet.newly_applied || replay_wallet.settlement != first_wallet.settlement {
        bail!("live repository provider-attempt replay changed wallet settlement outcome");
    }
    if bridge_runtime.block_on(repositories.append_billing_event(replay))? {
        bail!("live repository provider-attempt replay created a second metering event");
    }
    let mut collision = original;
    collision.request_id = "live-replay-request-mutated".into();
    collision.trace_id = None;
    collision.tenant.organization_id = Some("org_replay_collision".into());
    if !matches!(
        bridge_runtime.block_on(repositories.append_billing_event(collision)),
        Err(ferrogate_storage::StorageError::Conflict(_))
    ) {
        bail!("live repository accepted a changed provider-attempt payload as replay");
    }
    Ok(())
}

fn compliance_supabase_config(
    gateway_addr: &str,
    schema: &str,
    provider_addr: &str,
    billing_addr: &str,
    args: &SupabaseLiveRestartArgs,
) -> Result<String> {
    let tls_mode = match args.tls_mode.trim() {
        "disable" | "prefer" | "require" | "verify_ca" | "verify_full" => args.tls_mode.trim(),
        other => bail!("unsupported Supabase TLS mode {other}"),
    };
    let ca = args
        .tls_ca_cert_path
        .as_ref()
        .map(|path| {
            format!(
                "  postgres_tls_ca_cert_path: {:?}\n",
                path.to_string_lossy()
            )
        })
        .unwrap_or_default();
    Ok(format!(
        r#"listen: "{gateway_addr}"
storage:
  provider: "supabase"
  required: true
  provider_order: ["supabase", "postgres"]
  supabase_dsn_env: "FERROGATE_SUPABASE_DSN"
  postgres_pool_size: 2
  postgres_pool_acquire_timeout_millis: 30000
  postgres_tls_mode: "{tls_mode}"
{ca}  postgres_connect_timeout_secs: 10
  postgres_statement_timeout_millis: 30000
  postgres_schema: "{schema}"
  postgres_search_path: ["public"]
  migration_mode: "auto"

billing_service:
  enabled: true
  endpoint: "http://{billing_addr}"
  timeout_millis: 2000
  token: "{}"
providers:
  - name: "openai"
    kind: "openai"
    base_url: "http://{provider_addr}/v1"
  - name: "backup-openai"
    kind: "openai"
    base_url: "http://{provider_addr}/v1"
models:
  - name: "fast-chat"
    provider: "openai"
    provider_model: "gpt-4o-mini"
    input_price_per_1m: 1.0
    output_price_per_1m: 2.0
  - name: "fallback-chat"
    provider: "openai"
    provider_model: "gpt-4o-mini-failover-primary"
    input_price_per_1m: 1.0
    output_price_per_1m: 2.0
    fallbacks:
      - provider: "backup-openai"
        provider_model: "gpt-4o-mini-fallback"
        input_price_per_1m: 1.0
        output_price_per_1m: 2.0
        priority: 0
        weight: 1
  - name: "gpt-5.5-chat"
    provider: "openai"
    provider_model: "gpt-5.5"
    input_price_per_1m: 5.0
    output_price_per_1m: 15.0
api_keys:
  - id: "client"
    name: "Component compliance client"
    key: "client-secret"
    scopes: ["chat.completions"]
    allowed_models: ["fast-chat", "fallback-chat", "gpt-5.5-chat"]
    organization_id: "org_demo"
    project_id: "project_gateway"
  - id: "admin"
    name: "Component compliance admin"
    key: "admin-secret"
    scopes: ["admin.read", "admin.write"]
{}"#,
        crate::constants::BILLING_SERVICE_TOKEN,
        // #351: the same operator-declared x402 spend policies the local TOML
        // config carries, so the write-read closure is proved on both storage
        // backends from one source of truth.
        crate::x402_spend_policy::x402_spend_policies_yaml(),
    ))
}

struct ComplianceProvider {
    addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<String>>>,
}

impl ComplianceProvider {
    fn start(expected_requests: usize) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let (addr, handle) = spawn_local_provider_upstream_with_timeout(
            expected_requests,
            Arc::clone(&stop),
            Duration::from_secs(300),
        )?;
        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
        })
    }

    fn finish(&mut self) -> Result<Vec<String>> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .take()
            .context("compliance provider join handle missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("compliance provider thread panicked"))
    }
}

impl Drop for ComplianceProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(binary: &Path, config: &Path, gateway_addr: &str, dsn: &str) -> Result<Self> {
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config)
            .env("FERROGATE_SUPABASE_DSN", dsn)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(
                if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                },
            )
            .spawn()
            .with_context(|| format!("failed to start {}", binary.display()))?;
        let mut guard = Self { child };
        guard.wait_for_readiness(gateway_addr)?;
        Ok(guard)
    }

    fn wait_for_readiness(&mut self, gateway_addr: &str) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(180) {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before compliance readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for compliance gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct SupabaseEvidence {
    client: LiveSupabaseClient,
    schema: String,
}

impl SupabaseEvidence {
    fn connect(args: &SupabaseLiveRestartArgs, schema: String) -> Result<Self> {
        Ok(Self {
            client: connect_live_supabase(args)?,
            schema,
        })
    }

    fn install_provider_attempt_v29_fixture(&mut self) -> Result<()> {
        let mut transaction = self.client.transaction()?;
        transaction.batch_execute(&format!(
            "SET LOCAL search_path TO \"{}\"; {PROVIDER_ATTEMPT_V29_FIXTURE_SQL}",
            self.schema
        ))?;
        transaction.commit()?;
        let shape = self.client.query_one(
            "SELECT \
               (SELECT COUNT(*) FROM information_schema.columns \
                WHERE table_schema = $1 AND table_name = 'metering_events' \
                  AND column_name = 'billing_event_id'), \
               (SELECT COUNT(*) FROM information_schema.columns \
                WHERE table_schema = $1 AND table_name = 'metering_events' \
                  AND column_name = 'provider_attempt_id'), \
               (SELECT COUNT(*) FROM pg_catalog.pg_tables \
                WHERE schemaname = $1 AND tablename = 'wallet_settlements')",
            &[&self.schema],
        )?;
        let shape = (
            shape.get::<_, i64>(0),
            shape.get::<_, i64>(1),
            shape.get::<_, i64>(2),
        );
        if shape != (0, 0, 0) {
            bail!("provider-attempt v29 fixture already contained v30 structures: {shape:?}");
        }
        Ok(())
    }

    fn inject_provider_attempt_migration_failure(&mut self) -> Result<()> {
        self.client.batch_execute(&format!(
            "ALTER TABLE \"{}\".metering_event_routes ADD COLUMN billing_event_id INTEGER",
            self.schema
        ))?;
        Ok(())
    }

    fn verify_provider_attempt_migration_rollback(&mut self) -> Result<()> {
        let evidence = self.client.query_one(
            &format!(
                "SELECT \
                   (SELECT COUNT(*) FROM \"{schema}\".storage_schema_migrations WHERE version = 30), \
                   (SELECT COUNT(*) FROM information_schema.columns \
                    WHERE table_schema = $1 AND table_name = 'metering_events' \
                      AND column_name IN ('billing_event_id', 'provider_attempt_id', \
                                          'provider_attempt_index', 'event_json')), \
                   (SELECT data_type FROM information_schema.columns \
                    WHERE table_schema = $1 AND table_name = 'metering_event_routes' \
                      AND column_name = 'billing_event_id'), \
                   (SELECT COUNT(*) FROM \"{schema}\".metering_events \
                    WHERE request_id = 'v29-request' AND trace_id = 'v29-trace'), \
                   (SELECT COALESCE(SUM(total_tokens), 0)::bigint \
                    FROM \"{schema}\".metering_event_usage \
                    WHERE request_id = 'v29-request'), \
                   (SELECT COUNT(*) FROM \"{schema}\".billing_ledger \
                    WHERE id = 'v29-ledger' AND total_cost = 0.000011)",
                schema = self.schema
            ),
            &[&self.schema],
        )?;
        let evidence = (
            evidence.get::<_, i64>(0),
            evidence.get::<_, i64>(1),
            evidence.get::<_, Option<String>>(2),
            evidence.get::<_, i64>(3),
            evidence.get::<_, i64>(4),
            evidence.get::<_, i64>(5),
        );
        if evidence != (0, 0, Some("integer".into()), 1, 7, 1) {
            bail!(
                "fault-injected provider-attempt migration did not roll back marker, DDL, and data: {evidence:?}"
            );
        }
        Ok(())
    }

    fn clear_provider_attempt_migration_failure(&mut self) -> Result<()> {
        self.client.batch_execute(&format!(
            "ALTER TABLE \"{}\".metering_event_routes DROP COLUMN billing_event_id",
            self.schema
        ))?;
        Ok(())
    }

    fn verify_provider_attempt_v29_upgrade(&mut self) -> Result<()> {
        let evidence = self.client.query_one(
            &format!(
                "SELECT e.billing_event_id, e.provider_attempt_id, e.provider_attempt_index, \
                        e.event_json->>'request_id', r.billing_event_id, u.billing_event_id, \
                        u.total_tokens, l.provider_attempt_id, l.provider_attempt_index, \
                        (SELECT name FROM \"{schema}\".storage_schema_migrations WHERE version = 30) \
                 FROM \"{schema}\".metering_events e \
                 JOIN \"{schema}\".metering_event_routes r \
                   ON r.billing_event_id = e.billing_event_id \
                 JOIN \"{schema}\".metering_event_usage u \
                   ON u.billing_event_id = e.billing_event_id \
                 JOIN \"{schema}\".billing_ledger l ON l.id = 'v29-ledger' \
                 WHERE e.request_id = 'v29-request'",
                schema = self.schema
            ),
            &[],
        )?;
        let evidence = (
            evidence.get::<_, String>(0),
            evidence.get::<_, String>(1),
            evidence.get::<_, i32>(2),
            evidence.get::<_, Option<String>>(3),
            evidence.get::<_, String>(4),
            evidence.get::<_, String>(5),
            evidence.get::<_, i64>(6),
            evidence.get::<_, String>(7),
            evidence.get::<_, i32>(8),
            evidence.get::<_, Option<String>>(9),
        );
        if evidence
            != (
                "v29-request".into(),
                String::new(),
                0,
                Some("v29-request".into()),
                "v29-request".into(),
                "v29-request".into(),
                7,
                String::new(),
                0,
                Some("030_provider_attempt_settlement_identity".into()),
            )
        {
            bail!("provider-attempt v29 historical data upgrade mismatch: {evidence:?}");
        }
        Ok(())
    }

    fn verify_validate_only_provider_attempt_contract(
        &mut self,
        args: &SupabaseLiveRestartArgs,
    ) -> Result<()> {
        self.client.batch_execute(&format!(
            "ALTER TABLE \"{}\".metering_events ALTER COLUMN event_json DROP NOT NULL",
            self.schema
        ))?;
        expect_validate_only_failure(args, &self.schema, "event_json")?;
        self.client.batch_execute(&format!(
            "ALTER TABLE \"{}\".metering_events ALTER COLUMN event_json SET NOT NULL",
            self.schema
        ))?;

        self.client.batch_execute(&format!(
            "ALTER TABLE \"{schema}\".metering_event_routes \
               DROP CONSTRAINT metering_event_routes_pkey; \
             ALTER TABLE \"{schema}\".metering_event_routes \
               ADD CONSTRAINT metering_event_routes_pkey PRIMARY KEY (request_id)",
            schema = self.schema
        ))?;
        expect_validate_only_failure(args, &self.schema, "primary key")?;
        self.client.batch_execute(&format!(
            "ALTER TABLE \"{schema}\".metering_event_routes \
               DROP CONSTRAINT metering_event_routes_pkey; \
             ALTER TABLE \"{schema}\".metering_event_routes \
               ADD CONSTRAINT metering_event_routes_pkey PRIMARY KEY (billing_event_id)",
            schema = self.schema
        ))?;

        self.client.batch_execute(&format!(
            "ALTER TABLE \"{schema}\".metering_event_routes \
               DROP CONSTRAINT metering_event_routes_billing_event_id_fkey; \
             ALTER TABLE \"{schema}\".metering_event_routes \
               ADD CONSTRAINT metering_event_routes_billing_event_id_fkey \
               FOREIGN KEY (billing_event_id) \
               REFERENCES \"{schema}\".metering_events(billing_event_id) ON DELETE NO ACTION",
            schema = self.schema
        ))?;
        expect_validate_only_failure(args, &self.schema, "ON DELETE CASCADE")?;
        self.client.batch_execute(&format!(
            "ALTER TABLE \"{schema}\".metering_event_routes \
               DROP CONSTRAINT metering_event_routes_billing_event_id_fkey; \
             ALTER TABLE \"{schema}\".metering_event_routes \
               ADD CONSTRAINT metering_event_routes_billing_event_id_fkey \
               FOREIGN KEY (billing_event_id) \
               REFERENCES \"{schema}\".metering_events(billing_event_id) ON DELETE CASCADE",
            schema = self.schema
        ))?;

        self.client.batch_execute(&format!(
            "ALTER TABLE \"{schema}\".metering_event_usage \
               DROP CONSTRAINT metering_event_usage_billing_event_id_fkey; \
             ALTER TABLE \"{schema}\".metering_event_usage \
               ADD CONSTRAINT metering_event_usage_billing_event_id_fkey \
               FOREIGN KEY (billing_event_id) \
               REFERENCES \"{schema}\".metering_events(billing_event_id) ON DELETE NO ACTION",
            schema = self.schema
        ))?;
        expect_validate_only_failure(args, &self.schema, "ON DELETE CASCADE")?;
        self.client.batch_execute(&format!(
            "ALTER TABLE \"{schema}\".metering_event_usage \
               DROP CONSTRAINT metering_event_usage_billing_event_id_fkey; \
             ALTER TABLE \"{schema}\".metering_event_usage \
               ADD CONSTRAINT metering_event_usage_billing_event_id_fkey \
               FOREIGN KEY (billing_event_id) \
               REFERENCES \"{schema}\".metering_events(billing_event_id) ON DELETE CASCADE",
            schema = self.schema
        ))?;
        Ok(())
    }

    fn provider_attempt_constraint_identity(&mut self) -> Result<Vec<(String, String)>> {
        let rows = self.client.query(
            &format!(
                "SELECT conname, oid::text FROM pg_constraint \
                 WHERE connamespace = '\"{}\"'::regnamespace \
                   AND conname IN ( \
                     'metering_events_pkey', 'metering_event_routes_pkey', \
                     'metering_event_routes_billing_event_id_fkey', \
                     'metering_event_usage_pkey', \
                     'metering_event_usage_billing_event_id_fkey' \
                   ) ORDER BY conname",
                self.schema
            ),
            &[],
        )?;
        let identity = rows
            .into_iter()
            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
            .collect::<Vec<_>>();
        if identity.len() != 5 {
            bail!(
                "provider-attempt constraint identity expected 5 rows, got {}: {identity:?}",
                identity.len()
            );
        }
        Ok(identity)
    }

    fn verify_contract_cleanup(&mut self) -> Result<()> {
        let migration = self.client.query_one(
            &format!(
                "SELECT name FROM \"{}\".storage_schema_migrations WHERE version = 30",
                self.schema
            ),
            &[],
        )?;
        let migration_name: String = migration.get(0);
        if migration_name != "030_provider_attempt_settlement_identity" {
            bail!("unexpected Supabase migration 30 name: {migration_name}");
        }
        self.verify_provider_attempt_rollup()?;
        self.verify_provider_attempt_wallet()?;
        self.verify_live_repository_replay()?;
        let invalid_insert = self.client.execute(
            &format!(
                "INSERT INTO \"{}\".quota_policies \
                 (id, scope_type, scope_id, asset_storage_quota_bytes) \
                 VALUES ('invalid-project-asset-quota', 'project', 'compliance-project', 50)",
                self.schema
            ),
            &[],
        );
        if invalid_insert.is_ok() {
            bail!("Supabase accepted a non-tenant asset storage quota directly");
        }
        for table in ["quota_policies", "stored_assets"] {
            let count: i64 = self
                .client
                .query_one(
                    &format!("SELECT COUNT(*) FROM \"{}\".{table}", self.schema),
                    &[],
                )?
                .get(0);
            if count != 0 {
                bail!("compliance cleanup left {count} rows in {table}");
            }
        }
        let tenant_count: i64 = self
            .client
            .query_one(
                &format!(
                    "SELECT COUNT(*) FROM \"{}\".tenants WHERE id = 'compliance-tenant'",
                    self.schema
                ),
                &[],
            )?
            .get(0);
        if tenant_count != 1 {
            bail!("compliance API writes did not reach the Supabase tenant table");
        }
        Ok(())
    }

    fn verify_provider_attempt_rollup(&mut self) -> Result<()> {
        let detail = self.client.query_one(
            &format!(
                "SELECT COUNT(*), COUNT(DISTINCT e.provider_attempt_id), \
                        MIN(e.provider_attempt_index), MAX(e.provider_attempt_index), \
                        SUM(u.total_tokens)::bigint, SUM(e.cost_usd) \
                 FROM \"{schema}\".metering_events e \
                 JOIN \"{schema}\".metering_event_usage u \
                   ON u.billing_event_id = e.billing_event_id \
                 WHERE e.agent_run_id = 'provider-compliance-multi-attempt'",
                schema = self.schema
            ),
            &[],
        )?;
        let count: i64 = detail.get(0);
        let distinct_attempts: i64 = detail.get(1);
        let min_index: Option<i32> = detail.get(2);
        let max_index: Option<i32> = detail.get(3);
        let tokens: Option<i128> = detail.get::<_, Option<i64>>(4).map(i128::from);
        let cost: Option<f64> = detail.get(5);
        if (count, distinct_attempts, min_index, max_index, tokens)
            != (2, 2, Some(0), Some(1), Some(13))
            || (cost.unwrap_or_default() - 0.000_020).abs() > 1e-12
        {
            bail!(
                "live Supabase multi-attempt detail mismatch: count={count}, distinct={distinct_attempts}, indexes={min_index:?}..{max_index:?}, tokens={tokens:?}, cost={cost:?}"
            );
        }

        let ledger = self.client.query_one(
            &format!(
                "SELECT COUNT(*), COUNT(DISTINCT provider_attempt_id), \
                        MIN(provider_attempt_index), MAX(provider_attempt_index), \
                        SUM(total_tokens)::bigint, SUM(total_cost) \
                 FROM \"{schema}\".billing_ledger \
                 WHERE request_id IN ( \
                     SELECT request_id FROM \"{schema}\".metering_events \
                     WHERE agent_run_id = 'provider-compliance-multi-attempt' \
                 )",
                schema = self.schema
            ),
            &[],
        )?;
        let ledger_values = (
            ledger.get::<_, i64>(0),
            ledger.get::<_, i64>(1),
            ledger.get::<_, Option<i32>>(2),
            ledger.get::<_, Option<i32>>(3),
            ledger.get::<_, Option<i64>>(4),
            ledger.get::<_, Option<f64>>(5),
        );
        if ledger_values.0 != 2
            || ledger_values.1 != 2
            || ledger_values.2 != Some(0)
            || ledger_values.3 != Some(1)
            || ledger_values.4 != Some(13)
            || (ledger_values.5.unwrap_or_default() - 0.000_020).abs() > 1e-12
        {
            bail!("live Supabase multi-attempt ledger mismatch: {ledger_values:?}");
        }

        let direct = self.client.query_one(
            &format!(
                "SELECT COUNT(*), SUM(u.total_tokens)::bigint, SUM(e.cost_usd), \
                        SUM(CASE WHEN e.status_code >= 400 THEN 1 ELSE 0 END)::bigint \
                 FROM \"{schema}\".metering_events e \
                 JOIN \"{schema}\".tenant_contexts t ON t.id = e.tenant_context_id \
                 JOIN \"{schema}\".metering_event_usage u \
                   ON u.billing_event_id = e.billing_event_id \
                 WHERE t.project_id = 'project_gateway'",
                schema = self.schema
            ),
            &[],
        )?;
        let rollup = self.client.query_one(
            &format!(
                "SELECT request_count, total_tokens, cost_usd, error_count \
                 FROM \"{schema}\".usage_monthly_rollups \
                 WHERE scope_type = 'project' AND scope_id = 'project_gateway'",
                schema = self.schema
            ),
            &[],
        )?;
        let direct_values = (
            direct.get::<_, i64>(0),
            direct.get::<_, Option<i64>>(1).unwrap_or_default(),
            direct.get::<_, Option<f64>>(2).unwrap_or_default(),
            direct.get::<_, Option<i64>>(3).unwrap_or_default(),
        );
        let rollup_values = (
            rollup.get::<_, i64>(0),
            rollup.get::<_, i64>(1),
            rollup.get::<_, f64>(2),
            rollup.get::<_, i64>(3),
        );
        if direct_values.0 != rollup_values.0
            || direct_values.1 != rollup_values.1
            || (direct_values.2 - rollup_values.2).abs() > 1e-12
            || direct_values.3 != rollup_values.3
        {
            bail!(
                "live Supabase provider-attempt rollup diverged: detail={direct_values:?}, rollup={rollup_values:?}"
            );
        }
        Ok(())
    }

    fn verify_provider_attempt_wallet(&mut self) -> Result<()> {
        let wallet = self.client.query_one(
            &format!(
                "SELECT balance_credits FROM \"{}\".wallets WHERE tenant_id = 'org_demo'",
                self.schema
            ),
            &[],
        )?;
        let balance: i64 = wallet.get(0);
        if balance != 999_943 {
            bail!("live Supabase provider settlements produced wallet balance {balance}, expected 999943");
        }

        let settlements = self.client.query_one(
            &format!(
                "SELECT COUNT(*), COUNT(DISTINCT id), SUM(delta_credits)::bigint \
                 FROM \"{}\".wallet_settlements WHERE tenant_id = 'org_demo'",
                self.schema
            ),
            &[],
        )?;
        let settlement_values = (
            settlements.get::<_, i64>(0),
            settlements.get::<_, i64>(1),
            settlements.get::<_, Option<i64>>(2),
        );
        if settlement_values != (6, 6, Some(-57)) {
            bail!("live Supabase provider wallet settlements mismatch: {settlement_values:?}");
        }

        let multi_attempt = self.client.query_one(
            &format!(
                "SELECT COUNT(*), SUM(s.delta_credits)::bigint \
                 FROM \"{schema}\".wallet_settlements s \
                 JOIN \"{schema}\".metering_events e ON e.billing_event_id = s.id \
                 WHERE e.agent_run_id = 'provider-compliance-multi-attempt'",
                schema = self.schema
            ),
            &[],
        )?;
        let multi_values = (
            multi_attempt.get::<_, i64>(0),
            multi_attempt.get::<_, Option<i64>>(1),
        );
        if multi_values != (2, Some(-20)) {
            bail!("live Supabase multi-attempt wallet settlement mismatch: {multi_values:?}");
        }

        let audit_count: i64 = self
            .client
            .query_one(
                &format!(
                    "SELECT COUNT(*) FROM \"{}\".audit_events \
                     WHERE action = 'wallet.settle' AND target = 'org_demo'",
                    self.schema
                ),
                &[],
            )?
            .get(0);
        if audit_count != 6 {
            bail!("live Supabase provider wallet audit count was {audit_count}, expected 6");
        }
        Ok(())
    }

    fn verify_live_repository_replay(&mut self) -> Result<()> {
        let row = self.client.query_one(
            &format!(
                "SELECT w.balance_credits, COUNT(DISTINCT s.id), \
                        COUNT(DISTINCT e.billing_event_id), \
                        COALESCE(MAX(r.request_count), 0), \
                        COALESCE(MAX(r.total_tokens), 0), \
                        COALESCE(MAX(r.cost_usd), 0) \
                 FROM \"{schema}\".wallets w \
                 LEFT JOIN \"{schema}\".wallet_settlements s ON s.tenant_id = w.tenant_id \
                 LEFT JOIN \"{schema}\".metering_events e \
                   ON e.provider_attempt_id = 'live-replay-attempt' \
                 LEFT JOIN \"{schema}\".usage_monthly_rollups r \
                   ON r.scope_type = 'tenant' AND r.scope_id = w.tenant_id \
                 WHERE w.tenant_id = 'org_replay' \
                 GROUP BY w.balance_credits",
                schema = self.schema
            ),
            &[],
        )?;
        let evidence = (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2),
            row.get::<_, i64>(3),
            row.get::<_, i64>(4),
            row.get::<_, f64>(5),
        );
        if evidence.0 != 875
            || evidence.1 != 1
            || evidence.2 != 1
            || evidence.3 != 1
            || evidence.4 != 8
            || (evidence.5 - 0.000_125).abs() > 1e-12
        {
            bail!("live repository replay evidence mismatch: {evidence:?}");
        }
        let collision_tenant_count: i64 = self
            .client
            .query_one(
                &format!(
                    "SELECT COUNT(*) FROM \"{}\".tenant_contexts \
                     WHERE organization_id = 'org_replay_collision'",
                    self.schema
                ),
                &[],
            )?
            .get(0);
        if collision_tenant_count != 0 {
            bail!(
                "live repository provider-attempt collision committed {collision_tenant_count} tenant-context side effects"
            );
        }
        Ok(())
    }
}

fn expect_validate_only_failure(
    args: &SupabaseLiveRestartArgs,
    schema: &str,
    expected: &str,
) -> Result<()> {
    let tls_mode = match args.tls_mode.trim() {
        "require" => PostgresTlsMode::Require,
        "verify_ca" | "verify-ca" => PostgresTlsMode::VerifyCa,
        "verify_full" | "verify-full" => PostgresTlsMode::VerifyFull,
        other => bail!("unsupported live repository TLS mode {other}"),
    };
    let result = RuntimeStorageRepositories::supabase(
        PostgresStorageConfig {
            dsn: args.supabase_dsn.clone(),
            pool_size: 1,
            pool_acquire_timeout_millis: 30_000,
            tls_mode,
            tls_ca_cert_path: args
                .tls_ca_cert_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            connect_timeout_secs: 10,
            statement_timeout_millis: 30_000,
            schema: Some(schema.to_string()),
            search_path: vec!["public".into()],
        },
        RuntimeStorageOptions {
            provider_order: vec![StorageProviderKind::Supabase, StorageProviderKind::Postgres],
            required: true,
            initialize_schema: false,
            migration_mode: "validate_only".into(),
            control_plane: ControlPlaneDocuments::default(),
            request_log_retention_records: 0,
            audit_event_retention_records: 0,
        },
    );
    match result {
        Ok(_) => bail!("validate-only accepted malformed provider-attempt schema: {expected}"),
        Err(error) if error.to_string().contains(expected) => Ok(()),
        Err(error) => bail!(
            "validate-only rejected malformed provider-attempt schema for the wrong reason; expected {expected:?}, got {error}"
        ),
    }
}

#[cfg(test)]
#[path = "compliance_test.rs"]
mod compliance_test;
