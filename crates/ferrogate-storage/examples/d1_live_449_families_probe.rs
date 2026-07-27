// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live D1 probe for the #449 billing/guardrail/worker-store families.

//! Gate-owned live validation for the #449 D1 slice: run the REAL
//! `RuntimeStorageRepositories` D1 backend against a REAL Cloudflare D1
//! database, exercising the non-atomic durable families that landed in #449 —
//! billing events, billing ledger, the billing report outbox lifecycle
//! (enqueue → list_due → dead_letter → list_dead_lettered → replay), guardrail
//! policy revisions (via the `GuardrailPolicyRepository` trait), managed worker
//! templates, and self-hosted worker registrations + activity stats — over the
//! actual admin-HTTP SQL (idempotent `INSERT ... DO NOTHING`, guarded
//! `UPDATE` + follow-up `SELECT`, `count(*) OVER()` pagination), then clean up.
//!
//! Opt-in only — requires FERROGATE_CF_ACCOUNT_ID / FERROGATE_CF_API_TOKEN.
//!
//! SKIPS cleanly (prints a notice, exits 0) when FERROGATE_CF_ACCOUNT_ID is
//! unset, so running this without credentials is a no-op rather than a failure.
//! With it set but another required variable missing the probe hard-errors: a
//! half-configured environment is an operator mistake, not an opt-out
//! (`support/probe_env.rs`, #495).
//! Run: cargo run -p ferrogate-storage --example d1_live_449_families_probe

use std::collections::BTreeMap;
use std::sync::Arc;

use ferrogate_billing::{
    charge, BillingEvent, BillingUsageSource, PriceBook, ProviderAttempt, TokenUsage,
};
use ferrogate_cloudflare::d1::{D1Client, D1CreateDatabaseRequest};
use ferrogate_cloudflare::{CloudflareClient, CloudflareConfig, EnvTokenResolver};
use ferrogate_core::TenantContext;
use ferrogate_storage::{
    CloudflareD1StorageOptions, GuardrailPolicyRepository, ReplayDeadLetterOutcome,
    RuntimeStorageRepositories, StorageError, StoredGuardrailPolicyRevision,
    StoredManagedWorkerTemplate, StoredSelfHostedWorkerRegistration,
};

#[path = "support/probe_env.rs"]
mod probe_env;

const SCHEMA: &str = include_str!("../../../sql/d1/001_init_d1.sql");
const PROBE: &str = "d1_live_449_families_probe";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let Some(env) = probe_env::opt_in(PROBE, &["FERROGATE_CF_API_TOKEN"])? else {
        return Ok(());
    };
    let account_id = env.account_id();
    let config = CloudflareConfig::new(account_id, "env://FERROGATE_CF_API_TOKEN");
    let client = CloudflareClient::new(config, Arc::new(EnvTokenResolver::from_process_env()))?;
    let d1 = D1Client::new(Arc::new(client));

    let name = format!(
        "ferrogate-gate-449-probe-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    println!("probe database: {name}");
    let created = d1
        .create_database(&D1CreateDatabaseRequest::named(name.clone()))
        .await?;
    let dbid = created
        .uuid
        .clone()
        .ok_or("create_database returned no uuid")?;

    let result = exercise(&d1, &dbid).await;

    // Cleanup on success AND failure (operator directive: no lingering
    // Cloudflare resources), then verify the exact name is gone.
    d1.delete_database(&dbid).await?;
    if d1
        .list_databases()
        .await?
        .iter()
        .any(|db| db.name.as_deref() == Some(name.as_str()))
    {
        return Err("probe database still listed after delete".into());
    }
    println!("deleted + verified absent");

    result?;
    println!("{PROBE}: PASS");
    Ok(())
}

fn sample_event(request_id: &str) -> BillingEvent {
    BillingEvent {
        request_id: request_id.into(),
        trace_id: Some(format!("trace-{request_id}")),
        provider_attempt: ProviderAttempt::for_request(request_id, 0),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("acme".into()),
            ..TenantContext::default()
        },
        logical_model: "chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: TokenUsage::new(1, 1, 2),
        usage_source: BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: Some(0.000_01),
        latency_ms: Some(3),
        metadata: BTreeMap::new(),
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
    }
}

async fn exercise(d1: &D1Client, dbid: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Apply the shipped schema (now carrying the #449 document tables) through
    // the real /query surface.
    let statements: Vec<String> = SCHEMA
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    for statement in &statements {
        d1.query(dbid, statement, &[]).await?;
    }
    println!("schema applied: {} statements", statements.len());

    // Same construction route ferrogate-cli uses, against the live database.
    let repos = RuntimeStorageRepositories::cloudflare_d1_from_client(
        d1.clone(),
        CloudflareD1StorageOptions {
            control_database_id: dbid.to_string(),
            tenant_databases: Default::default(),
            audit_event_retention_records: 100,
        },
    )?;

    // 1) Billing events — idempotent append + count(*) OVER() page.
    let event = sample_event("gate-req-1");
    if !repos.append_billing_event(event.clone()).await? {
        return Err("first append_billing_event should insert (true)".into());
    }
    if repos.append_billing_event(event.clone()).await? {
        return Err("second append_billing_event should be idempotent (false)".into());
    }
    let page = repos.billing_events_page(0, 20).await;
    if page.total != 1 || page.data != vec![event.clone()] {
        return Err(format!("billing_events_page mismatch: total={}", page.total).into());
    }
    println!("billing events: append idempotent + page ok");

    // 2) Billing ledger — settle a cost, append idempotent, read back.
    let entry = charge(&PriceBook::default(), &sample_event("gate-ledger"))
        .map_err(|e| format!("charge failed: {e:?}"))?;
    if !repos.append_billing_ledger_entry(&entry).await? {
        return Err("first append_billing_ledger_entry should insert (true)".into());
    }
    if repos.append_billing_ledger_entry(&entry).await? {
        return Err("second append_billing_ledger_entry should be idempotent (false)".into());
    }
    let fetched = repos
        .billing_ledger_entry(&entry.id)
        .await?
        .ok_or("billing_ledger_entry read-back returned none")?;
    if fetched != entry {
        return Err("billing_ledger_entry round-trip mismatch".into());
    }
    println!("billing ledger: append idempotent + read-back ok");

    // 3) Billing report outbox lifecycle: enqueue -> due -> dead-letter ->
    //    list dead-lettered -> replay -> back to due. Exercises the guarded
    //    UPDATE + follow-up SELECT (no `UPDATE ... RETURNING` on D1 HTTP).
    repos
        .enqueue_billing_report("gate-report", &event, 100)
        .await?;
    let due = repos.list_due_billing_reports(1_000, 10).await?;
    if !due.iter().any(|e| e.id == "gate-report") {
        return Err("enqueued report not returned by list_due".into());
    }
    repos.dead_letter_billing_report("gate-report", 200).await?;
    let dead = repos.list_dead_lettered_billing_reports(10).await?;
    if !dead.iter().any(|e| e.id == "gate-report") {
        return Err("dead-lettered report not returned by list_dead_lettered".into());
    }
    match repos
        .replay_dead_lettered_billing_report("gate-report", 500)
        .await?
    {
        ReplayDeadLetterOutcome::Replayed(replayed) if replayed.id == "gate-report" => {}
        other => {
            return Err(format!("replay expected Replayed(gate-report), got {other:?}").into())
        }
    }
    let due_after = repos.list_due_billing_reports(1_000, 10).await?;
    if !due_after.iter().any(|e| e.id == "gate-report") {
        return Err("replayed report did not return to the due list".into());
    }
    println!("billing outbox: enqueue/due/dead-letter/replay lifecycle ok");

    // 4) Guardrail policy revisions (sync GuardrailPolicyRepository trait):
    //    insert idempotent-on-(policy_id,revision), read back, reject replay.
    let revision = StoredGuardrailPolicyRevision {
        id: "gate-policy@1".into(),
        policy_id: "gate-policy".into(),
        revision: 1,
        policy_json: "{\"rules\":[]}".into(),
        created_at_unix: 1_753_000_000,
        created_by: "gate".into(),
    };
    repos.insert_guardrail_policy_revision(revision.clone())?;
    let got = repos
        .get_guardrail_policy_revision("gate-policy", 1)?
        .ok_or("guardrail revision read-back returned none")?;
    if got != revision {
        return Err("guardrail revision round-trip mismatch".into());
    }
    match repos.insert_guardrail_policy_revision(revision.clone()) {
        Err(StorageError::Conflict(_)) => {}
        other => return Err(format!("guardrail replay expected Conflict, got {other:?}").into()),
    }
    println!("guardrail revisions: insert + read + replay-conflict ok");

    // 5) Managed worker templates — upsert (ON CONFLICT DO UPDATE) + list.
    let template = StoredManagedWorkerTemplate {
        id: "gate-tmpl".into(),
        framework_adapter: "langgraph".into(),
        isolation_backend_kind: "firecracker".into(),
        enabled: true,
        max_tenant_sessions: Some(4),
        max_workspace_sessions: None,
        created_at_unix: Some(1_753_000_000),
        updated_at_unix: Some(1_753_000_001),
    };
    repos
        .upsert_managed_worker_template(template.clone())
        .await?;
    let templates = repos.managed_worker_templates().await;
    if templates != vec![template] {
        return Err(format!(
            "managed_worker_templates mismatch: {} rows",
            templates.len()
        )
        .into());
    }
    println!("managed worker templates: upsert + list ok");

    // 6) Self-hosted worker registration — upsert + read + activity stats.
    let registration = StoredSelfHostedWorkerRegistration {
        id: "gate-worker".into(),
        tenant: TenantContext {
            organization_id: Some("acme".into()),
            ..TenantContext::default()
        },
        workspace_id: "ws-1".into(),
        worker_name: "runner".into(),
        status: "active".into(),
        identity_fingerprint: "sha256:abc".into(),
        identity_expires_at_unix: None,
        orchestration_enabled: true,
        registered_at_unix: Some(1_753_000_000),
        last_seen_at_unix: None,
        trust_level: "trusted".into(),
        capability_envelope_json: "{}".into(),
        token_secret: "secret".into(),
    };
    repos
        .upsert_self_hosted_worker_registration(registration.clone())
        .await?;
    let fetched_reg = repos
        .self_hosted_worker_registration("gate-worker")
        .await
        .ok_or("self_hosted_worker_registration read-back returned none")?;
    if fetched_reg != registration {
        return Err("self-hosted worker registration round-trip mismatch".into());
    }
    // No telemetry/artifacts/checkpoints inserted -> aggregates are all zero.
    let stats = repos.self_hosted_worker_activity_stats("gate-worker").await;
    if stats.telemetry_event_count != 0
        || stats.artifact_count != 0
        || stats.checkpoint_count != 0
        || stats.latest_event_at_unix.is_some()
    {
        return Err(format!("activity stats expected all-zero, got {stats:?}").into());
    }
    println!("self-hosted worker: upsert + read + zero-activity stats ok");

    Ok(())
}
