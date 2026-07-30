// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Live Supabase E2E for subject-bound MCP OAuth identity and DB-driven RBAC.

use crate::{
    assertions::assert_secret_redacted,
    cli::SupabaseLiveRestartArgs,
    http::{free_addr, http_request_addr, http_request_addr_after_write, HttpResponse},
    mocks::read_http_request,
    supabase_schema::{
        connect_live_supabase, LiveSupabaseClient, LiveSupabaseScenario, LiveSupabaseSchema,
    },
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env, fs,
    io::{Read, Seek, Write},
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Barrier, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ADMIN_AUTH: &str = "Authorization: Bearer mcp-identity-admin-secret";
const USER_A_AUTH: &str = "Authorization: Bearer mcp-identity-user-a-secret";
const USER_B_AUTH: &str = "Authorization: Bearer mcp-identity-user-b-secret";
const JSON_CONTENT: &str = "Content-Type: application/json";
const USER_A: &str = "mcp-e2e-user-a";
const USER_B: &str = "mcp-e2e-user-b";
const TENANT_ID: &str = "mcp-e2e-tenant";
const PROJECT_ID: &str = "mcp-e2e-project";
const WORKSPACE_ID: &str = "mcp-e2e-workspace";
const OTHER_TENANT_ID: &str = "mcp-e2e-other-tenant";
const OTHER_PROJECT_ID: &str = "mcp-e2e-other-project";
const OTHER_WORKSPACE_ID: &str = "mcp-e2e-other-workspace";
const SERVER_NAME: &str = "identity";
const ORIGINAL_SERVER_NAME: &str = "original";
const SIGNED_SERVER_NAME: &str = "signed";
const ORIGINAL_AUDIENCE: &str = "urn:ferrogate:mcp:original:e2e";
const SIGNED_AUDIENCE: &str = "urn:ferrogate:mcp:signed:e2e";
const OIDC_SECRET: &[u8] = b"ferrogate-mcp-identity-e2e-signing-secret";
const SLOW_REFRESH_STAGE_DELAY: Duration = Duration::from_secs(6);
// Live Supabase proves the owner/waiter contract only; concurrency scale is local-test territory.
const LIVE_REFRESH_CONTENTION_CALLERS: usize = 2;
const IDENTITY_ACTIONS: [&str; 5] = [
    "mcp.execute",
    "mcp.identity.connect",
    "mcp.identity.read",
    "mcp.identity.revoke",
    "mcp.identity.use",
];

pub(crate) fn run_mcp_identity_supabase(args: &SupabaseLiveRestartArgs) -> Result<()> {
    if args.supabase_dsn.trim().is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    if !args.local.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run cargo build -p ferrogate-cli first",
            args.local.ferrogate_bin.display()
        );
    }
    let mut schema = LiveSupabaseSchema::create(args, LiveSupabaseScenario::McpIdentity)?;
    let schema_name = schema.name().to_string();
    let fixture_suffix = schema.run_id().replace('_', "-");
    let role_id = format!("mcp-e2e-capability-{fixture_suffix}");
    let role_slug = format!("mcp-e2e-bundle-{fixture_suffix}");
    let mut evidence = SupabaseEvidence::connect(args, schema_name.clone())?;
    let services = MockIdentityServices::start()?;
    let mut gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("mcp-identity-supabase.yaml");
    fs::write(
        &config_path,
        gateway_config(
            &gateway_addr,
            &services.oidc_addr,
            &services.mcp_addr,
            &schema_name,
            8,
            args,
        )?,
    )?;

    let mut gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &config_path,
        &gateway_addr,
        args.supabase_dsn.trim(),
    )?;
    verify_admin_rejects_unsupported_mode(&gateway_addr, &services.mcp_addr)?;
    let membership_class = evidence.install_subjects_and_dynamic_role(&role_id, &role_slug)?;

    let mismatched = start_authorize(&gateway_addr, USER_A_AUTH, USER_A)?;
    assert_error(
        &callback(
            &gateway_addr,
            &format!("{USER_B}|{}", mismatched.nonce),
            &mismatched.state,
        )?,
        403,
        "mcp_identity_subject_mismatch",
    )?;
    evidence.verify_no_active_credential(USER_A)?;

    let state_a = authorize(&gateway_addr, USER_A_AUTH, USER_A)?;
    let _state_b = authorize(&gateway_addr, USER_B_AUTH, USER_B)?;
    let replay = callback(&gateway_addr, USER_A, &state_a);
    assert_error(&replay?, 401, "mcp_oauth_state_invalid")?;

    assert_tool_subject(&call_tool(&gateway_addr, USER_A_AUTH, json!({}))?, USER_A)?;
    assert_tool_subject(&call_tool(&gateway_addr, USER_B_AUTH, json!({}))?, USER_B)?;

    let permission_revoked_flow = start_authorize(&gateway_addr, USER_A_AUTH, USER_A)?;
    let without_connect = IDENTITY_ACTIONS
        .iter()
        .copied()
        .filter(|action| *action != "mcp.identity.connect")
        .collect::<Vec<_>>();
    evidence.set_role_actions(&role_id, &without_connect)?;
    assert_error(
        &callback(
            &gateway_addr,
            &format!("{USER_A}|{}", permission_revoked_flow.nonce),
            &permission_revoked_flow.state,
        )?,
        403,
        "mcp_identity_rbac_denied",
    )?;
    evidence.set_role_actions(&role_id, &IDENTITY_ACTIONS)?;

    let revoke_invalidated_flow = start_authorize(&gateway_addr, USER_A_AUTH, USER_A)?;
    let revoked_a = http_request_addr(
        &gateway_addr,
        "DELETE",
        &format!("/v1/mcp/identity/{SERVER_NAME}"),
        &[USER_A_AUTH],
        "",
    )?;
    if revoked_a.status != 200 {
        bail!(
            "MCP identity revoke for outstanding-flow test failed: {}",
            revoked_a.raw
        );
    }
    assert_error(
        &callback(
            &gateway_addr,
            &format!("{USER_A}|{}", revoke_invalidated_flow.nonce),
            &revoke_invalidated_flow.state,
        )?,
        401,
        "mcp_oauth_state_invalid",
    )?;
    authorize(&gateway_addr, USER_A_AUTH, USER_A)?;

    verify_original_bearer_mode(&gateway_addr, &format!("http://{}", services.oidc_addr))?;
    verify_signed_jwt_mode(&gateway_addr, &services)?;
    evidence.verify_mcp_rls()?;

    let forged = http_request_addr(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            USER_A_AUTH,
            JSON_CONTENT,
            "x-ferrogate-user-id: mcp-e2e-user-b",
            "x-ferrogate-mcp-bearer: forged-cross-user-token",
        ],
        &tool_body(SERVER_NAME, json!({})),
    )?;
    assert_tool_subject(&forged, USER_A)?;

    services.slow_refresh.store(true, Ordering::SeqCst);
    evidence.expire_credential(USER_A)?;
    let refresh_before = services.refreshes.load(Ordering::SeqCst);
    let barrier = Arc::new(Barrier::new(LIVE_REFRESH_CONTENTION_CALLERS));
    let mut refresh_calls = Vec::new();
    for _ in 0..LIVE_REFRESH_CONTENTION_CALLERS {
        let gateway_addr = gateway_addr.clone();
        let barrier = Arc::clone(&barrier);
        refresh_calls.push(thread::spawn(move || {
            barrier.wait();
            call_tool(&gateway_addr, USER_A_AUTH, json!({}))
        }));
    }
    let (refresh_lease_id, initial_refresh_expiry) =
        evidence.wait_for_refresh_lease_claim(USER_A)?;
    trace_mcp_boundary("concurrent_refresh_lease_claimed");
    let first_refresh_expiry = match evidence.wait_for_refresh_lease_extension(
        USER_A,
        &refresh_lease_id,
        initial_refresh_expiry,
    ) {
        Ok(expiry) => expiry,
        Err(error) => {
            let output = gateway.read_process_log()?;
            bail!(
                "{error:#}; concurrent refresh gateway output tail: {}",
                text_tail(&output, 64 * 1024)
            );
        }
    };
    trace_mcp_boundary("concurrent_refresh_lease_extended_once");
    if let Err(error) =
        evidence.wait_for_refresh_lease_extension(USER_A, &refresh_lease_id, first_refresh_expiry)
    {
        let output = gateway.read_process_log()?;
        bail!(
            "{error:#}; concurrent refresh gateway output tail: {}",
            text_tail(&output, 64 * 1024)
        );
    }
    trace_mcp_boundary("concurrent_refresh_lease_extended_twice");
    for call in refresh_calls {
        let response = call
            .join()
            .map_err(|_| anyhow::anyhow!("concurrent refresh caller panicked"))??;
        if let Err(error) = assert_tool_subject(&response, USER_A) {
            let output = gateway.read_process_log()?;
            bail!(
                "concurrent refresh caller failed: {error:#}; {}",
                concurrent_refresh_failure_diagnostic(&response, &output)
            );
        }
    }
    let refresh_delta = services
        .refreshes
        .load(Ordering::SeqCst)
        .saturating_sub(refresh_before);
    if refresh_delta != 1 {
        bail!("concurrent MCP refresh expected one IdP grant, observed {refresh_delta}");
    }
    services.slow_refresh.store(false, Ordering::SeqCst);

    evidence.expire_credential(USER_A)?;
    let before_revoked_refresh = evidence.credential_snapshot(USER_A)?;
    let mut refresh_gate = services.arm_next_refresh_response()?;
    let (refresh_result_tx, refresh_result_rx) = mpsc::channel();
    let refresh_gateway_addr = gateway_addr.clone();
    let refresh_caller = thread::spawn(move || {
        let result = call_tool(&refresh_gateway_addr, USER_A_AUTH, json!({}));
        let _ = refresh_result_tx.send(result);
    });
    refresh_gate.wait_started(Duration::from_secs(60))?;
    let _ = evidence.wait_for_refresh_lease_claim(USER_A)?;
    let revoked_during_refresh = http_request_addr(
        &gateway_addr,
        "DELETE",
        &format!("/v1/mcp/identity/{SERVER_NAME}"),
        &[USER_A_AUTH],
        "",
    )?;
    if revoked_during_refresh.status != 200 {
        bail!(
            "MCP identity revoke during blocked refresh failed: {}",
            revoked_during_refresh.raw
        );
    }
    let revoked_refresh_snapshot =
        evidence.verify_revoked_refresh_snapshot(USER_A, &before_revoked_refresh)?;
    let blocked_refresh_response = refresh_result_rx
        .recv_timeout(Duration::from_secs(15))
        .context("blocked MCP refresh caller did not observe revocation before IdP release")??;
    assert_error(&blocked_refresh_response, 401, "mcp_identity_not_connected")?;
    refresh_caller
        .join()
        .map_err(|_| anyhow::anyhow!("blocked MCP refresh caller panicked"))?;
    refresh_gate.release();
    refresh_gate.wait_response_completed(Duration::from_secs(15))?;
    evidence.verify_snapshot_unchanged(USER_A, &revoked_refresh_snapshot)?;
    assert_error(
        &call_tool(&gateway_addr, USER_A_AUTH, json!({}))?,
        401,
        "mcp_identity_not_connected",
    )?;
    authorize(&gateway_addr, USER_A_AUTH, USER_A)?;
    assert_tool_subject(&call_tool(&gateway_addr, USER_A_AUTH, json!({}))?, USER_A)?;

    let replacement_gateway_addr = free_addr()?;
    let replacement_config_path = dir.path().join("mcp-identity-replacement.yaml");
    fs::write(
        &replacement_config_path,
        gateway_config(
            &replacement_gateway_addr,
            &services.oidc_addr,
            &services.mcp_addr,
            &schema_name,
            2,
            args,
        )?,
    )?;
    let replacement_gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &replacement_config_path,
        &replacement_gateway_addr,
        args.supabase_dsn.trim(),
    )?;

    evidence.expire_credential(USER_A)?;
    let before_crashed_refresh = evidence.credential_snapshot(USER_A)?;
    let refreshes_before_crash = services.refreshes.load(Ordering::SeqCst);
    let mut crashed_owner_gate = services.arm_next_refresh_response()?;
    let (crashed_owner_tx, crashed_owner_rx) = mpsc::channel();
    let crashed_owner_addr = gateway_addr.clone();
    let crashed_owner_caller = thread::spawn(move || {
        let result = call_tool(&crashed_owner_addr, USER_A_AUTH, json!({}));
        let _ = crashed_owner_tx.send(result);
    });
    crashed_owner_gate.wait_started(Duration::from_secs(60))?;
    let (crashed_lease_id, initial_crashed_lease_expiry) =
        evidence.wait_for_refresh_lease_claim(USER_A)?;
    let renewed_crashed_lease_expiry = evidence.wait_for_refresh_lease_extension(
        USER_A,
        &crashed_lease_id,
        initial_crashed_lease_expiry,
    )?;
    let abandoned_owner_grants = services
        .refreshes
        .load(Ordering::SeqCst)
        .saturating_sub(refreshes_before_crash);
    if abandoned_owner_grants != 1 {
        bail!(
            "crashed MCP refresh owner expected one IdP grant before termination, observed {abandoned_owner_grants}"
        );
    }

    drop(gateway);
    let crashed_lease_snapshot = evidence.refresh_lease_clock_snapshot(USER_A)?;
    if crashed_lease_snapshot.lease_id.as_deref() != Some(&crashed_lease_id) {
        bail!(
            "crashed gateway did not leave its MCP refresh lease in Supabase: expected {}, observed {:?}",
            crashed_lease_id,
            crashed_lease_snapshot.lease_id
        );
    }
    let crashed_lease_expiry = crashed_lease_snapshot
        .expires_at_unix
        .context("crashed gateway left an MCP refresh lease without an expiry")?;
    if crashed_lease_expiry < renewed_crashed_lease_expiry
        || crashed_lease_snapshot.db_now >= crashed_lease_expiry
    {
        bail!(
            "crashed gateway did not leave a live renewed MCP refresh lease: db_now={}, renewed_expiry={renewed_crashed_lease_expiry}, final_expiry={crashed_lease_expiry}",
            crashed_lease_snapshot.db_now
        );
    }
    let crashed_owner_result = crashed_owner_rx
        .recv_timeout(Duration::from_secs(15))
        .context("crashed MCP refresh caller did not terminate with its gateway")?;
    if matches!(&crashed_owner_result, Ok(response) if response.status == 200) {
        bail!("crashed MCP refresh owner unexpectedly returned a successful tool response");
    }
    crashed_owner_caller
        .join()
        .map_err(|_| anyhow::anyhow!("crashed MCP refresh caller panicked"))?;
    crashed_owner_gate.release();
    crashed_owner_gate.wait_response_completed(Duration::from_secs(15))?;

    services.slow_refresh.store(true, Ordering::SeqCst);
    let (replacement_started_tx, replacement_started_rx) = mpsc::channel();
    let (replacement_result_tx, replacement_result_rx) = mpsc::channel();
    let replacement_call_addr = replacement_gateway_addr.clone();
    let replacement_caller = thread::spawn(move || {
        let result = call_tool_after_write(&replacement_call_addr, USER_A_AUTH, json!({}), || {
            let _ = replacement_started_tx.send(());
        });
        let _ = replacement_result_tx.send(result);
    });
    replacement_started_rx
        .recv_timeout(Duration::from_secs(5))
        .context("replacement MCP refresh caller did not write its request")?;
    evidence.verify_old_refresh_lease_while_request_is_pending(
        USER_A,
        &crashed_lease_id,
        crashed_lease_expiry,
        Duration::from_secs(2),
    )?;
    match replacement_result_rx.try_recv() {
        Err(mpsc::TryRecvError::Empty) => {}
        Ok(_) => bail!("replacement MCP refresh call completed before the crashed lease expired"),
        Err(mpsc::TryRecvError::Disconnected) => {
            bail!("replacement MCP refresh caller disconnected before takeover")
        }
    }
    let replacement_lease = evidence.wait_for_refresh_lease_takeover(
        USER_A,
        &crashed_lease_id,
        crashed_lease_expiry,
    )?;
    if replacement_lease.lease_id == crashed_lease_id {
        bail!("replacement gateway reused the crashed owner's MCP refresh lease ID");
    }
    if replacement_lease.db_now <= crashed_lease_expiry {
        bail!(
            "replacement MCP refresh lease was observed before the crashed lease expired: db_now={}, old_expiry={crashed_lease_expiry}",
            replacement_lease.db_now
        );
    }
    let replacement_response = replacement_result_rx
        .recv_timeout(Duration::from_secs(45))
        .context("replacement MCP refresh caller did not complete")??;
    replacement_caller
        .join()
        .map_err(|_| anyhow::anyhow!("replacement MCP refresh caller panicked"))?;
    services.slow_refresh.store(false, Ordering::SeqCst);
    assert_tool_subject(&replacement_response, USER_A)
        .context("replacement gateway failed to refresh after crashed lease expiry")?;
    evidence.verify_replacement_refresh_snapshot(USER_A, &before_crashed_refresh)?;
    let total_crash_grants = services
        .refreshes
        .load(Ordering::SeqCst)
        .saturating_sub(refreshes_before_crash);
    let replacement_grants = total_crash_grants.saturating_sub(abandoned_owner_grants);
    if total_crash_grants != 2 || replacement_grants != 1 {
        bail!(
            "crash takeover expected two IdP POSTs: one abandoned crashed-owner grant and exactly one replacement grant; observed total={total_crash_grants}, abandoned_owner={abandoned_owner_grants}, replacement={replacement_grants}"
        );
    }
    gateway = replacement_gateway;
    gateway_addr = replacement_gateway_addr;

    evidence.expire_credential(USER_A)?;
    services.idp_outage.store(true, Ordering::SeqCst);
    assert_error(
        &call_tool(&gateway_addr, USER_A_AUTH, json!({}))?,
        503,
        "mcp_identity_provider_unavailable",
    )?;
    services.idp_outage.store(false, Ordering::SeqCst);
    assert_tool_subject(&call_tool(&gateway_addr, USER_A_AUTH, json!({}))?, USER_A)
        .context("refresh recovery after IdP outage failed")?;

    assert_error(
        &call_tool(&gateway_addr, USER_A_AUTH, json!({"force_401": true}))?,
        502,
        "mcp_upstream_unauthorized",
    )?;
    assert_tool_subject(&call_tool(&gateway_addr, USER_A_AUTH, json!({}))?, USER_A)?;

    evidence.unbind_role(&role_id)?;
    assert_error(
        &call_tool(&gateway_addr, USER_A_AUTH, json!({}))?,
        403,
        "mcp_tools_disabled",
    )?;
    evidence.bind_role(&role_id)?;
    let without_identity_use = IDENTITY_ACTIONS
        .iter()
        .copied()
        .filter(|action| *action != "mcp.identity.use")
        .collect::<Vec<_>>();
    evidence.set_role_actions(&role_id, &without_identity_use)?;
    assert_error(
        &call_tool(&gateway_addr, USER_A_AUTH, json!({}))?,
        403,
        "mcp_identity_rbac_denied",
    )?;
    evidence.set_role_actions(&role_id, &IDENTITY_ACTIONS)?;

    evidence.remove_membership(USER_A)?;
    assert_error(
        &call_tool(&gateway_addr, USER_A_AUTH, json!({}))?,
        403,
        "mcp_identity_membership_revoked",
    )?;
    evidence.restore_membership(USER_A, &membership_class)?;

    evidence.set_workspace_status("inactive")?;
    assert_error(
        &call_tool(&gateway_addr, USER_A_AUTH, json!({}))?,
        403,
        "mcp_identity_workspace_inactive",
    )?;
    evidence.set_workspace_status("active")?;

    evidence.verify_ciphertext_and_audit()?;
    let metrics = http_request_addr(&gateway_addr, "GET", "/metrics", &[ADMIN_AUTH], "")?;
    assert_metric_nonzero(&metrics, "ferrogate_mcp_identity_resolutions_total")?;
    assert_metric_nonzero(&metrics, "ferrogate_mcp_identity_failures_total")?;
    assert_metric_nonzero(&metrics, "ferrogate_mcp_identity_refreshes_total")?;

    assert_tool_subject(&call_tool(&gateway_addr, USER_B_AUTH, json!({}))?, USER_B)?;

    let revoked = http_request_addr(
        &gateway_addr,
        "DELETE",
        &format!("/v1/mcp/identity/{SERVER_NAME}"),
        &[USER_B_AUTH],
        "",
    )?;
    if revoked.status != 200 {
        bail!("MCP identity revoke failed: {}", revoked.raw);
    }
    assert_error(
        &call_tool(&gateway_addr, USER_B_AUTH, json!({}))?,
        401,
        "mcp_identity_not_connected",
    )?;
    if services.revocations.load(Ordering::SeqCst) == 0 {
        bail!("MCP identity revoke never reached the OIDC revocation endpoint");
    }
    evidence.verify_revocation_outcome(USER_B, "upstream_revoked")?;
    let metrics = http_request_addr(&gateway_addr, "GET", "/metrics", &[ADMIN_AUTH], "")?;
    assert_metric_nonzero(&metrics, "ferrogate_mcp_identity_revocations_total")?;
    drop(gateway);
    drop(evidence);
    drop(services);
    schema.finish()?;
    println!("mcp-identity-supabase scenario passed");
    Ok(())
}

#[cfg(test)]
fn assert_lock_conflict_busy_log(process_log: &str, operation: &str) -> Result<()> {
    let operation = format!("operation=\"{operation}\"");
    if has_lock_conflict_busy_log(process_log, &operation) {
        return Ok(());
    }
    bail!(
        "gateway log did not contain optimistic claim lock-conflict Busy evidence for \
         {operation}; tail: {}",
        text_tail(process_log, 16 * 1024)
    )
}

#[cfg(test)]
fn has_lock_conflict_busy_log(process_log: &str, operation: &str) -> bool {
    process_log.lines().any(|line| {
        line.contains(operation)
            && line.contains("storage_stage=\"refresh claim CAS\"")
            && line.contains("outcome=\"lock_conflict_busy\"")
    })
}

#[cfg(test)]
fn assert_storage_cancellation_evidence(
    process_log: &str,
    operation: &str,
    storage_stage: &str,
    watchdog_outcome: &str,
) -> Result<()> {
    let operation = format!("operation=\"{operation}\"");
    let storage_stage = format!("storage_stage=\"{storage_stage}\"");
    let watchdog_outcome = format!("outcome=\"{watchdog_outcome}\"");
    let synchronous = process_log.lines().any(|line| {
        line.contains(&operation)
            && line.contains(&storage_stage)
            && line.contains("outcome=\"storage_cancelled\"")
    });
    let commit_watchdog = watchdog_outcome.contains("commit");
    let response_deadline = process_log.lines().any(|line| {
        line.contains(&operation)
            && line.contains("outcome=\"response_deadline\"")
            && (line.contains("cancel_outcome=Cancelled")
                || line.contains("cancel_outcome=AlreadyCancelled")
                || (commit_watchdog && line.contains("cancel_outcome=CommitStarted")))
    });
    let watchdog = process_log.lines().any(|line| {
        line.contains(&operation)
            && line.contains(&storage_stage)
            && line.contains(&watchdog_outcome)
    });
    let complete_alternatives =
        usize::from(synchronous) + usize::from(response_deadline && watchdog);
    if complete_alternatives == 1 {
        return Ok(());
    }
    bail!(
        "gateway log contained {complete_alternatives} complete MCP storage cancellation \
         evidence alternatives for {operation}; expected exactly one synchronous cancellation \
         or one response-deadline plus watchdog pair; tail: {}",
        text_tail(process_log, 16 * 1024)
    )
}

fn text_tail(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut start = value.len() - max_bytes;
    while !value.is_char_boundary(start) {
        start += 1;
    }
    &value[start..]
}

fn trace_mcp_boundary(boundary: &str) {
    if env::var("FERROGATE_TEST_BOUNDARY_TRACE").as_deref() != Ok("1") {
        return;
    }
    let elapsed_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    eprintln!("mcp_identity_boundary unix_ms={elapsed_millis} boundary={boundary}");
}

fn verify_admin_rejects_unsupported_mode(gateway_addr: &str, mcp_addr: &str) -> Result<()> {
    let response = http_request_addr(
        gateway_addr,
        "POST",
        "/admin/v1/mcp-servers",
        &[ADMIN_AUTH, JSON_CONTENT],
        &json!({
            "name":"unsupported",
            "transport":"streamable_http",
            "url":format!("http://{mcp_addr}/mcp"),
            "auth_type":"oauth",
            "tools_to_execute":["whoami"]
        })
        .to_string(),
    )?;
    if response.status != 400 {
        bail!(
            "unsupported MCP auth mode expected Admin HTTP 400: {}",
            response.raw
        );
    }
    let body: Value = serde_json::from_str(&response.body)?;
    let message = body["error"]["message"].as_str().unwrap_or_default();
    if !message.contains(
        "MCP auth_type oauth is not implemented; use per_user_oauth for user-isolated OAuth or shared_headers for shared credentials",
    ) {
        bail!("Admin API did not preserve exact unsupported-mode validation: {body}");
    }
    Ok(())
}

struct PendingAuthorization {
    state: String,
    nonce: String,
}

fn start_authorize(gateway_addr: &str, auth: &str, user_id: &str) -> Result<PendingAuthorization> {
    let response = http_request_addr(
        gateway_addr,
        "POST",
        &format!("/v1/mcp/identity/{SERVER_NAME}/authorize"),
        &[auth],
        "",
    )?;
    if response.status != 200 {
        bail!("MCP authorize failed for {user_id}: {}", response.raw);
    }
    let body: Value = serde_json::from_str(&response.body)?;
    let state = body["state"]
        .as_str()
        .context("authorize response omitted state")?;
    let authorize_url = body["authorize_url"]
        .as_str()
        .context("authorize response omitted authorize_url")?;
    let nonce = query_value(authorize_url, "nonce").context("authorize URL omitted nonce")?;
    Ok(PendingAuthorization {
        state: state.to_string(),
        nonce,
    })
}

fn authorize(gateway_addr: &str, auth: &str, user_id: &str) -> Result<String> {
    let pending = start_authorize(gateway_addr, auth, user_id)?;
    let callback = callback(
        gateway_addr,
        &format!("{user_id}|{}", pending.nonce),
        &pending.state,
    )?;
    if callback.status != 200 {
        bail!("MCP callback failed for {user_id}: {}", callback.raw);
    }
    let connected: Value = serde_json::from_str(&callback.body)?;
    if connected["connected"] != true || connected["subject"] != user_id {
        bail!("MCP callback did not bind expected subject: {connected}");
    }
    Ok(pending.state)
}

fn callback(gateway_addr: &str, code: &str, state: &str) -> Result<HttpResponse> {
    http_request_addr(
        gateway_addr,
        "GET",
        &format!(
            "/v1/mcp/identity/callback?code={}&state={}",
            form_encode(code),
            form_encode(state)
        ),
        &[],
        "",
    )
}

fn call_tool(gateway_addr: &str, auth: &str, arguments: Value) -> Result<HttpResponse> {
    call_server_tool(gateway_addr, auth, SERVER_NAME, arguments, &[])
}

fn call_tool_after_write(
    gateway_addr: &str,
    auth: &str,
    arguments: Value,
    after_write: impl FnOnce(),
) -> Result<HttpResponse> {
    http_request_addr_after_write(
        gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[auth, JSON_CONTENT],
        &tool_body(SERVER_NAME, arguments),
        after_write,
    )
}

fn call_server_tool(
    gateway_addr: &str,
    auth: &str,
    server_name: &str,
    arguments: Value,
    extra_headers: &[&str],
) -> Result<HttpResponse> {
    let mut headers = vec![auth, JSON_CONTENT];
    headers.extend_from_slice(extra_headers);
    http_request_addr(
        gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &headers,
        &tool_body(server_name, arguments),
    )
}

fn tool_body(server_name: &str, arguments: Value) -> String {
    json!({"name": format!("{server_name}-whoami"), "arguments": arguments}).to_string()
}

fn assert_tool_subject(response: &HttpResponse, expected: &str) -> Result<()> {
    if response.status != 200 {
        bail!(
            "MCP tool expected 200, got {}: {}",
            response.status,
            response.raw
        );
    }
    let body: Value = serde_json::from_str(&response.body)?;
    if !body.to_string().contains(&format!("subject:{expected}")) {
        bail!("MCP upstream did not receive expected subject {expected}: {body}");
    }
    Ok(())
}

fn assert_error(response: &HttpResponse, status: u16, code: &str) -> Result<()> {
    if response.status != status {
        bail!(
            "expected HTTP {status}/{code}, got {}: {}",
            response.status,
            response.raw
        );
    }
    let body: Value = serde_json::from_str(&response.body)?;
    if body["error"]["code"] != code {
        bail!("expected error code {code}, got {body}");
    }
    Ok(())
}

fn response_request_id(response: &HttpResponse) -> Result<String> {
    let body: Value = serde_json::from_str(&response.body)?;
    if let Some(request_id) = body["request_id"]
        .as_str()
        .filter(|request_id| !request_id.is_empty())
    {
        return Ok(request_id.to_string());
    }
    response
        .raw
        .lines()
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("x-request-id")
                .then(|| value.trim())
                .filter(|request_id| !request_id.is_empty())
        })
        .map(str::to_string)
        .context("HTTP response did not contain request_id")
}

fn early_refresh_response_summary(response: &HttpResponse) -> String {
    let code = serde_json::from_str::<Value>(&response.body)
        .ok()
        .and_then(|body| body["error"]["code"].as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into());
    let request_id = response_request_id(response).unwrap_or_else(|_| "unknown".into());
    format!(
        "http_status={} error_code={} request_id={}",
        response.status, code, request_id
    )
}

fn concurrent_refresh_failure_diagnostic(response: &HttpResponse, process_log: &str) -> String {
    format!(
        "{}; gateway output tail: {}",
        early_refresh_response_summary(response),
        text_tail(process_log, 32 * 1024)
    )
}

fn assert_metric_nonzero(response: &HttpResponse, name: &str) -> Result<()> {
    let count = metric_count(response, name)?;
    if count == 0 {
        bail!("metric {name} was missing or zero: {}", response.body);
    }
    Ok(())
}

fn metric_count(response: &HttpResponse, name: &str) -> Result<u64> {
    if response.status != 200 {
        bail!("metrics endpoint failed: {}", response.raw);
    }
    let count = response
        .body
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    Ok(count)
}

fn mint_oidc_token(issuer: &str, subject: &str, audience: &str) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("mcp-e2e".into());
    Ok(encode(
        &header,
        &IdTokenClaims {
            iss: issuer.into(),
            sub: subject.into(),
            aud: audience.into(),
            nonce: "original-bearer".into(),
            iat: now,
            exp: now + 300,
        },
        &EncodingKey::from_secret(OIDC_SECRET),
    )?)
}

fn verify_original_bearer_mode(gateway_addr: &str, issuer: &str) -> Result<()> {
    let token_a = mint_oidc_token(issuer, USER_A, ORIGINAL_AUDIENCE)?;
    let token_b = mint_oidc_token(issuer, USER_B, ORIGINAL_AUDIENCE)?;
    let bearer_a = format!("x-ferrogate-mcp-bearer: {token_a}");
    let bearer_b = format!("x-ferrogate-mcp-bearer: {token_b}");
    assert_tool_subject(
        &call_server_tool(
            gateway_addr,
            USER_A_AUTH,
            ORIGINAL_SERVER_NAME,
            json!({}),
            &[&bearer_a],
        )?,
        USER_A,
    )?;
    assert_error(
        &call_server_tool(
            gateway_addr,
            USER_A_AUTH,
            ORIGINAL_SERVER_NAME,
            json!({}),
            &[&bearer_b],
        )?,
        403,
        "mcp_identity_subject_mismatch",
    )?;
    assert_error(
        &call_server_tool(
            gateway_addr,
            USER_B_AUTH,
            ORIGINAL_SERVER_NAME,
            json!({}),
            &[&bearer_a],
        )?,
        403,
        "mcp_identity_subject_mismatch",
    )?;
    assert_tool_subject(
        &call_server_tool(
            gateway_addr,
            USER_A_AUTH,
            ORIGINAL_SERVER_NAME,
            json!({}),
            &[
                &bearer_a,
                "x-ferrogate-user-id: mcp-e2e-user-b",
                "x-ferrogate-mcp-subject: mcp-e2e-user-b",
            ],
        )?,
        USER_A,
    )?;
    Ok(())
}

fn verify_signed_jwt_mode(gateway_addr: &str, services: &MockIdentityServices) -> Result<()> {
    let before = services.signed_verifications.load(Ordering::SeqCst);
    for _ in 0..2 {
        assert_tool_subject(
            &call_server_tool(
                gateway_addr,
                USER_A_AUTH,
                SIGNED_SERVER_NAME,
                json!({}),
                &[
                    "x-ferrogate-user-id: mcp-e2e-user-b",
                    "x-ferrogate-mcp-bearer: forged-original-token",
                ],
            )?,
            USER_A,
        )?;
    }
    let verified = services
        .signed_verifications
        .load(Ordering::SeqCst)
        .saturating_sub(before);
    if verified != 2 {
        bail!("signed JWT upstream verification expected 2 tokens, observed {verified}");
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    nonce: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct SignedIdentityClaims {
    iss: String,
    sub: String,
    aud: String,
    tenant_id: String,
    workspace_id: String,
    server_name: String,
    iat: i64,
    exp: i64,
    jti: String,
}

#[derive(Default)]
struct RefreshResponseGate {
    state: Mutex<RefreshResponseGateState>,
    changed: Condvar,
}

#[derive(Default)]
struct RefreshResponseGateState {
    armed: bool,
    started: bool,
    released: bool,
    response_completed: bool,
}

impl RefreshResponseGate {
    fn arm(self: &Arc<Self>) -> Result<RefreshResponseGateGuard> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("MCP refresh response gate lock poisoned"))?;
        if state.armed {
            bail!("MCP refresh response gate is already armed");
        }
        *state = RefreshResponseGateState {
            armed: true,
            started: false,
            released: false,
            response_completed: false,
        };
        Ok(RefreshResponseGateGuard {
            gate: Arc::clone(self),
            released: false,
        })
    }

    fn block_next_refresh_response(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if !state.armed || state.started {
            return false;
        }
        state.started = true;
        self.changed.notify_all();
        while state.armed && !state.released {
            let Ok(next) = self.changed.wait(state) else {
                return false;
            };
            state = next;
        }
        state.armed = false;
        self.changed.notify_all();
        true
    }

    fn wait_started(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("MCP refresh response gate lock poisoned"))?;
        while !state.started {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("MCP refresh token POST did not reach the response gate");
            }
            let (next, timed_out) = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| anyhow::anyhow!("MCP refresh response gate lock poisoned"))?;
            state = next;
            if timed_out.timed_out() && !state.started {
                bail!("MCP refresh token POST did not reach the response gate");
            }
        }
        Ok(())
    }

    fn release(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.released = true;
            self.changed.notify_all();
        }
    }

    fn mark_response_completed(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.response_completed = true;
            self.changed.notify_all();
        }
    }

    fn wait_response_completed(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("MCP refresh response gate lock poisoned"))?;
        while !state.response_completed {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("blocked MCP refresh response handler did not complete");
            }
            let (next, timed_out) = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| anyhow::anyhow!("MCP refresh response gate lock poisoned"))?;
            state = next;
            if timed_out.timed_out() && !state.response_completed {
                bail!("blocked MCP refresh response handler did not complete");
            }
        }
        Ok(())
    }
}

struct RefreshResponseGateGuard {
    gate: Arc<RefreshResponseGate>,
    released: bool,
}

impl RefreshResponseGateGuard {
    fn wait_started(&self, timeout: Duration) -> Result<()> {
        self.gate.wait_started(timeout)
    }

    fn release(&mut self) {
        if !self.released {
            self.gate.release();
            self.released = true;
        }
    }

    fn wait_response_completed(&self, timeout: Duration) -> Result<()> {
        self.gate.wait_response_completed(timeout)
    }
}

impl Drop for RefreshResponseGateGuard {
    fn drop(&mut self) {
        self.release();
    }
}

struct MockIdentityServices {
    oidc_addr: String,
    mcp_addr: String,
    stop: Arc<AtomicBool>,
    idp_outage: Arc<AtomicBool>,
    slow_refresh: Arc<AtomicBool>,
    refresh_gate: Arc<RefreshResponseGate>,
    refreshes: Arc<AtomicU64>,
    revocations: Arc<AtomicU64>,
    signed_verifications: Arc<AtomicU64>,
    handles: Vec<JoinHandle<()>>,
}

impl MockIdentityServices {
    fn start() -> Result<Self> {
        let oidc = TcpListener::bind("127.0.0.1:0")?;
        oidc.set_nonblocking(true)?;
        let oidc_addr = oidc.local_addr()?.to_string();
        let mcp = TcpListener::bind("127.0.0.1:0")?;
        mcp.set_nonblocking(true)?;
        let mcp_addr = mcp.local_addr()?.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let idp_outage = Arc::new(AtomicBool::new(false));
        let slow_refresh = Arc::new(AtomicBool::new(false));
        let refresh_gate = Arc::new(RefreshResponseGate::default());
        let refreshes = Arc::new(AtomicU64::new(0));
        let revocations = Arc::new(AtomicU64::new(0));
        let signed_verifications = Arc::new(AtomicU64::new(0));
        let signed_jtis = Arc::new(Mutex::new(HashSet::new()));

        let oidc_stop = Arc::clone(&stop);
        let outage = Arc::clone(&idp_outage);
        let slow = Arc::clone(&slow_refresh);
        let gate = Arc::clone(&refresh_gate);
        let refresh_count = Arc::clone(&refreshes);
        let revoke_count = Arc::clone(&revocations);
        let issuer = format!("http://{oidc_addr}");
        let oidc_handle = thread::spawn(move || {
            while !oidc_stop.load(Ordering::Relaxed) {
                match oidc.accept() {
                    Ok((mut stream, _)) => {
                        let issuer = issuer.clone();
                        let outage = Arc::clone(&outage);
                        let slow = Arc::clone(&slow);
                        let gate = Arc::clone(&gate);
                        let refresh_count = Arc::clone(&refresh_count);
                        let revoke_count = Arc::clone(&revoke_count);
                        thread::spawn(move || {
                            if let Ok(request) = read_http_request(&mut stream) {
                                let response = oidc_response(
                                    &request,
                                    &issuer,
                                    outage.load(Ordering::SeqCst),
                                    slow.load(Ordering::SeqCst),
                                    &gate,
                                    &refresh_count,
                                    &revoke_count,
                                );
                                let _ = write_response(&mut stream, response.0, &response.1);
                                if response.2 {
                                    gate.mark_response_completed();
                                }
                            }
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        let mcp_stop = Arc::clone(&stop);
        let mcp_issuer = format!("http://{oidc_addr}");
        let signed_count = Arc::clone(&signed_verifications);
        let seen_signed_jtis = Arc::clone(&signed_jtis);
        let mcp_handle = thread::spawn(move || {
            while !mcp_stop.load(Ordering::Relaxed) {
                match mcp.accept() {
                    Ok((mut stream, _)) => {
                        let mcp_issuer = mcp_issuer.clone();
                        let signed_count = Arc::clone(&signed_count);
                        let seen_signed_jtis = Arc::clone(&seen_signed_jtis);
                        thread::spawn(move || {
                            if let Ok(request) = read_http_request(&mut stream) {
                                let (status, body) = mcp_response(
                                    &request,
                                    &mcp_issuer,
                                    &signed_count,
                                    &seen_signed_jtis,
                                );
                                let _ = write_response(&mut stream, status, &body);
                            }
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            oidc_addr,
            mcp_addr,
            stop,
            idp_outage,
            slow_refresh,
            refresh_gate,
            refreshes,
            revocations,
            signed_verifications,
            handles: vec![oidc_handle, mcp_handle],
        })
    }

    fn arm_next_refresh_response(&self) -> Result<RefreshResponseGateGuard> {
        self.refresh_gate.arm()
    }
}

impl Drop for MockIdentityServices {
    fn drop(&mut self) {
        self.refresh_gate.release();
        self.stop.store(true, Ordering::SeqCst);
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

fn oidc_response(
    request: &str,
    issuer: &str,
    outage: bool,
    slow_refresh: bool,
    refresh_gate: &RefreshResponseGate,
    refreshes: &AtomicU64,
    revocations: &AtomicU64,
) -> (&'static str, String, bool) {
    if request.starts_with("GET /.well-known/openid-configuration ") {
        if slow_refresh {
            thread::sleep(SLOW_REFRESH_STAGE_DELAY);
        }
        return (
            "200 OK",
            json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "revocation_endpoint": format!("{issuer}/revoke")
            })
            .to_string(),
            false,
        );
    }
    if request.starts_with("GET /jwks ") {
        return (
            "200 OK",
            json!({"keys":[{
                "kty":"oct", "kid":"mcp-e2e", "use":"sig", "alg":"HS256",
                "k": URL_SAFE_NO_PAD.encode(OIDC_SECRET)
            }]})
            .to_string(),
            false,
        );
    }
    if request.starts_with("POST /revoke ") {
        revocations.fetch_add(1, Ordering::SeqCst);
        return ("200 OK", "{}".into(), false);
    }
    if request.starts_with("POST /token ") {
        if outage {
            return (
                "503 Service Unavailable",
                json!({"error":"temporarily_unavailable"}).to_string(),
                false,
            );
        }
        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default();
        let form = form_pairs(body);
        if form.get("grant_type").map(String::as_str) == Some("refresh_token") {
            refreshes.fetch_add(1, Ordering::SeqCst);
            let gated_refresh = refresh_gate.block_next_refresh_response();
            thread::sleep(if slow_refresh {
                SLOW_REFRESH_STAGE_DELAY
            } else {
                Duration::from_millis(250)
            });
            let subject = form
                .get("refresh_token")
                .and_then(|token| token.strip_prefix("refresh::"))
                .unwrap_or("unknown");
            return (
                "200 OK",
                json!({
                    "access_token": format!("access::{subject}::refreshed"),
                    "refresh_token": format!("refresh::{subject}"),
                    "token_type":"Bearer", "expires_in":300, "scope":"openid profile"
                })
                .to_string(),
                gated_refresh,
            );
        }
        let code = form.get("code").cloned().unwrap_or_default();
        let (subject, nonce) = code.split_once('|').unwrap_or(("unknown", "invalid"));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("mcp-e2e".into());
        let id_token = encode(
            &header,
            &IdTokenClaims {
                iss: issuer.into(),
                sub: subject.into(),
                aud: "mcp-e2e-client".into(),
                nonce: nonce.into(),
                iat: now,
                exp: now + 300,
            },
            &EncodingKey::from_secret(OIDC_SECRET),
        )
        .unwrap_or_default();
        return (
            "200 OK",
            json!({
                "access_token": format!("access::{subject}::initial"),
                "refresh_token": format!("refresh::{subject}"),
                "token_type":"Bearer", "expires_in":120, "scope":"openid profile",
                "id_token": id_token
            })
            .to_string(),
            false,
        );
    }
    (
        "404 Not Found",
        json!({"error":"not_found"}).to_string(),
        false,
    )
}

fn mcp_response(
    request: &str,
    issuer: &str,
    signed_verifications: &AtomicU64,
    signed_jtis: &Mutex<HashSet<String>>,
) -> (&'static str, String) {
    let body: Value = request
        .split_once("\r\n\r\n")
        .and_then(|(_, body)| serde_json::from_str(body).ok())
        .unwrap_or(Value::Null);
    let id = body["id"].clone();
    match body["method"].as_str() {
        Some("initialize") => (
            "200 OK",
            json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"identity-e2e","version":"1"}}}).to_string(),
        ),
        Some("tools/list") => (
            "200 OK",
            json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{"name":"whoami","description":"Return resolved identity","inputSchema":{"type":"object"}}]}}).to_string(),
        ),
        Some("ping") => ("200 OK", json!({"jsonrpc":"2.0","id":id,"result":{}}).to_string()),
        Some("tools/call") => {
            if body["params"]["arguments"]["force_401"] == true {
                return ("401 Unauthorized", String::new());
            }
            let path = request.lines().next().unwrap_or_default();
            let subject = if path.contains(" /mcp/original ") {
                match validate_original_upstream_token(request, issuer) {
                    Some(subject) => subject,
                    None => return ("401 Unauthorized", String::new()),
                }
            } else if path.contains(" /mcp/signed ") {
                match validate_signed_upstream_token(request, signed_jtis) {
                    Some(subject) => {
                        signed_verifications.fetch_add(1, Ordering::SeqCst);
                        subject
                    }
                    None => return ("401 Unauthorized", String::new()),
                }
            } else {
                request
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("Authorization: Bearer access::")
                            .or_else(|| line.strip_prefix("authorization: Bearer access::"))
                    })
                    .and_then(|value| value.split("::").next())
                    .unwrap_or("missing")
                    .to_string()
            };
            (
                "200 OK",
                json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":format!("subject:{subject}")}],"isError":false}}).to_string(),
            )
        }
        _ => ("400 Bad Request", json!({"error":"bad_request"}).to_string()),
    }
}

fn request_bearer(request: &str) -> Option<&str> {
    request.lines().find_map(|line| {
        line.strip_prefix("Authorization: Bearer ")
            .or_else(|| line.strip_prefix("authorization: Bearer "))
    })
}

fn validate_original_upstream_token(request: &str, issuer: &str) -> Option<String> {
    let token = request_bearer(request)?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[ORIGINAL_AUDIENCE]);
    let claims =
        decode::<IdTokenClaims>(token, &DecodingKey::from_secret(OIDC_SECRET), &validation)
            .ok()?
            .claims;
    Some(claims.sub)
}

fn validate_signed_upstream_token(
    request: &str,
    signed_jtis: &Mutex<HashSet<String>>,
) -> Option<String> {
    let token = request_bearer(request)?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["ferrogate"]);
    validation.set_audience(&[SIGNED_AUDIENCE]);
    let claims = decode::<SignedIdentityClaims>(
        token,
        &DecodingKey::from_secret(&signed_identity_key()),
        &validation,
    )
    .ok()?
    .claims;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())?;
    if claims.iss != "ferrogate"
        || claims.aud != SIGNED_AUDIENCE
        || claims.tenant_id != TENANT_ID
        || claims.workspace_id != WORKSPACE_ID
        || claims.server_name != SIGNED_SERVER_NAME
        || claims.exp.saturating_sub(claims.iat) != 60
        || claims.iat > now.saturating_add(5)
        || claims.iat < now.saturating_sub(10)
        || claims.jti.is_empty()
    {
        return None;
    }
    let mut seen = signed_jtis.lock().ok()?;
    if !seen.insert(claims.jti) {
        return None;
    }
    Some(claims.sub)
}

fn signed_identity_key() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ferrogate:mcp:signed-identity:v1");
    hasher.update("42".repeat(32).as_bytes());
    hasher.finalize().into()
}

fn write_response(stream: &mut impl Write, status: &str, body: &str) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

struct GatewayGuard {
    child: Child,
    process_log: Option<tempfile::NamedTempFile>,
}

fn gateway_process_log(debug_output: bool) -> Result<Option<tempfile::NamedTempFile>> {
    if debug_output {
        Ok(None)
    } else {
        Ok(Some(tempfile::NamedTempFile::new()?))
    }
}

impl GatewayGuard {
    fn start(binary: &Path, config: &Path, addr: &str, dsn: &str) -> Result<Self> {
        let debug_output = env::var("FERROGATE_TEST_DEBUG_STDERR").as_deref() == Ok("1");
        let process_log = gateway_process_log(debug_output)?;
        let stdout = match process_log.as_ref() {
            Some(log) => Stdio::from(log.reopen()?),
            None => Stdio::inherit(),
        };
        let stderr = match process_log.as_ref() {
            Some(log) => Stdio::from(log.reopen()?),
            None => Stdio::inherit(),
        };
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config)
            .env("FERROGATE_SUPABASE_DSN", dsn)
            .env("FERROGATE_PROVIDER_SECRET", "unused-provider-secret")
            .env("FERROGATE_TEST_MCP_OIDC_SECRET", "mcp-e2e-client-secret")
            .env("FERROGATE_MCP_IDENTITY_KEY", "42".repeat(32))
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .with_context(|| format!("failed to start {}", binary.display()))?;
        let mut guard = Self { child, process_log };
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(180) {
            if let Some(status) = guard.child.try_wait()? {
                let output = guard.read_process_log()?;
                bail!("FerroGate exited before MCP identity readiness: {status}; output: {output}");
            }
            match http_request_addr(addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(guard),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("FerroGate MCP identity readiness timed out: {last}")
    }

    fn read_process_log(&mut self) -> Result<String> {
        let Some(log) = self.process_log.as_mut() else {
            return Ok(String::new());
        };
        let mut output = String::new();
        log.as_file_mut().rewind()?;
        log.as_file_mut().read_to_string(&mut output)?;
        assert_secret_redacted(&output);
        Ok(output)
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
#[path = "mcp_identity_test.rs"]
mod mcp_identity_test;

#[derive(Clone, PartialEq, Eq)]
struct CredentialSnapshot {
    version: i64,
    authorization_generation: i64,
    refresh_lease_id: Option<String>,
    refresh_lease_expires_at_unix: Option<i64>,
    expires_at_unix: i64,
    revoked_at_unix: Option<i64>,
    access_token_nonce: Vec<u8>,
    access_token_ciphertext: Vec<u8>,
    refresh_token_nonce: Option<Vec<u8>>,
    refresh_token_ciphertext: Option<Vec<u8>>,
    last_refresh_outcome: Option<String>,
    last_revocation_outcome: Option<String>,
}

struct RefreshLeaseClockSnapshot {
    db_now: i64,
    lease_id: Option<String>,
    expires_at_unix: Option<i64>,
}

#[cfg(test)]
fn verify_refresh_completion_persisted(
    before: &CredentialSnapshot,
    after: &CredentialSnapshot,
) -> Result<()> {
    if after.version != before.version.saturating_add(1)
        || after.authorization_generation != before.authorization_generation
        || after.expires_at_unix <= before.expires_at_unix
        || after.access_token_nonce == before.access_token_nonce
        || after.access_token_ciphertext == before.access_token_ciphertext
        || after.refresh_token_nonce == before.refresh_token_nonce
        || after.refresh_token_ciphertext == before.refresh_token_ciphertext
        || after.refresh_lease_id.is_some()
        || after.refresh_lease_expires_at_unix.is_some()
        || after.revoked_at_unix != before.revoked_at_unix
        || after.last_refresh_outcome.as_deref() != Some("refreshed")
    {
        bail!("late MCP refresh completion did not persist authoritative refreshed material");
    }
    Ok(())
}

struct RefreshLeaseTakeover {
    db_now: i64,
    lease_id: String,
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

    fn install_subjects_and_dynamic_role(
        &mut self,
        role_id: &str,
        role_slug: &str,
    ) -> Result<String> {
        let prefix = format!("\"{}\".", self.schema);
        self.client.batch_execute(&format!(
            "INSERT INTO {prefix}tenants(id,name,slug) VALUES ('{TENANT_ID}','MCP E2E','mcp-e2e');
             INSERT INTO {prefix}projects(id,tenant_id,name,slug) VALUES ('{PROJECT_ID}','{TENANT_ID}','MCP E2E','mcp-e2e');
             INSERT INTO {prefix}workspaces(id,project_id,tenant_id,name,slug) VALUES ('{WORKSPACE_ID}','{PROJECT_ID}','{TENANT_ID}','MCP E2E','mcp-e2e');
             INSERT INTO {prefix}tenants(id,name,slug) VALUES ('{OTHER_TENANT_ID}','MCP E2E Other','mcp-e2e-other');
             INSERT INTO {prefix}projects(id,tenant_id,name,slug) VALUES ('{OTHER_PROJECT_ID}','{OTHER_TENANT_ID}','MCP E2E Other','mcp-e2e-other');
             INSERT INTO {prefix}workspaces(id,project_id,tenant_id,name,slug) VALUES ('{OTHER_WORKSPACE_ID}','{OTHER_PROJECT_ID}','{OTHER_TENANT_ID}','MCP E2E Other','mcp-e2e-other');"
        ))?;
        let membership_class: String = self.client.query_one(
            "SELECT (regexp_match(pg_get_constraintdef(c.oid), $$'([^']+)'$$))[1]
             FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
             WHERE n.nspname=$1 AND t.relname='admin_user_tenant_memberships' AND c.contype='c' LIMIT 1",
            &[&self.schema],
        )?.get(0);
        for user in [USER_A, USER_B] {
            self.client.execute(
                &format!("INSERT INTO {prefix}admin_users(id,email,password_hash,display_name) VALUES ($1,$2,'not-used',$3)"),
                &[&user, &format!("{user}@example.invalid"), &user],
            )?;
            self.restore_membership(user, &membership_class)?;
        }
        for (index, action) in IDENTITY_ACTIONS.iter().enumerate() {
            self.client.execute(
                &format!("INSERT INTO {prefix}permissions(id,key,name) VALUES ($1,$2,$3)"),
                &[
                    &format!("mcp-e2e-action-{index}"),
                    action,
                    &format!("MCP capability {index}"),
                ],
            )?;
        }
        self.client.execute(
            &format!("INSERT INTO {prefix}roles(id,name,slug,permission_keys_json) VALUES ($1,$2,$3,$4::text::jsonb)"),
            &[&role_id, &format!("Generated capability bundle {role_slug}"), &role_slug, &serde_json::to_string(&IDENTITY_ACTIONS)?],
        )?;
        self.bind_role(role_id)?;
        Ok(membership_class)
    }

    fn bind_role(&mut self, role_id: &str) -> Result<()> {
        self.client.execute(
            &format!("INSERT INTO \"{}\".tenant_role_bindings(id,tenant_id,role_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING", self.schema),
            &[&format!("binding-{role_id}"), &TENANT_ID, &role_id],
        )?;
        Ok(())
    }

    fn unbind_role(&mut self, role_id: &str) -> Result<()> {
        self.client.execute(
            &format!(
                "DELETE FROM \"{}\".tenant_role_bindings WHERE tenant_id=$1 AND role_id=$2",
                self.schema
            ),
            &[&TENANT_ID, &role_id],
        )?;
        Ok(())
    }

    fn set_role_actions(&mut self, role_id: &str, actions: &[&str]) -> Result<()> {
        self.client.execute(
            &format!(
                "UPDATE \"{}\".roles SET permission_keys_json=$2::text::jsonb WHERE id=$1",
                self.schema
            ),
            &[&role_id, &serde_json::to_string(actions)?],
        )?;
        Ok(())
    }

    fn remove_membership(&mut self, user: &str) -> Result<()> {
        self.client.execute(
            &format!("DELETE FROM \"{}\".admin_user_tenant_memberships WHERE user_id=$1 AND tenant_id=$2", self.schema),
            &[&user, &TENANT_ID],
        )?;
        Ok(())
    }

    fn restore_membership(&mut self, user: &str, membership_class: &str) -> Result<()> {
        self.client.execute(
            &format!("INSERT INTO \"{}\".admin_user_tenant_memberships(id,user_id,tenant_id,role) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING", self.schema),
            &[&format!("membership-{user}"), &user, &TENANT_ID, &membership_class],
        )?;
        Ok(())
    }

    fn set_workspace_status(&mut self, status: &str) -> Result<()> {
        self.client.execute(
            &format!(
                "UPDATE \"{}\".workspaces SET status=$2 WHERE id=$1",
                self.schema
            ),
            &[&WORKSPACE_ID, &status],
        )?;
        Ok(())
    }

    fn expire_credential(&mut self, user: &str) -> Result<()> {
        self.client.execute(
            &format!("UPDATE \"{}\".mcp_oauth_credentials SET expires_at_unix=0 WHERE user_id=$1 AND server_name=$2", self.schema),
            &[&user, &SERVER_NAME],
        )?;
        Ok(())
    }

    fn credential_snapshot(&mut self, user: &str) -> Result<CredentialSnapshot> {
        let row = self.client.query_one(
            &format!(
                "SELECT version,authorization_generation,refresh_lease_id, \
                        refresh_lease_expires_at_unix,expires_at_unix,revoked_at_unix, \
                        access_token_nonce,access_token_ciphertext,refresh_token_nonce, \
                        refresh_token_ciphertext,last_refresh_outcome,last_revocation_outcome \
                 FROM \"{}\".mcp_oauth_credentials WHERE user_id=$1 AND server_name=$2",
                self.schema
            ),
            &[&user, &SERVER_NAME],
        )?;
        Ok(CredentialSnapshot {
            version: row.get(0),
            authorization_generation: row.get(1),
            refresh_lease_id: row.get(2),
            refresh_lease_expires_at_unix: row.get(3),
            expires_at_unix: row.get(4),
            revoked_at_unix: row.get(5),
            access_token_nonce: row.get(6),
            access_token_ciphertext: row.get(7),
            refresh_token_nonce: row.get(8),
            refresh_token_ciphertext: row.get(9),
            last_refresh_outcome: row.get(10),
            last_revocation_outcome: row.get(11),
        })
    }

    fn verify_revoked_refresh_snapshot(
        &mut self,
        user: &str,
        before: &CredentialSnapshot,
    ) -> Result<CredentialSnapshot> {
        let revoked = self.credential_snapshot(user)?;
        if revoked.revoked_at_unix.is_none()
            || revoked.refresh_lease_id.is_some()
            || revoked.refresh_lease_expires_at_unix.is_some()
        {
            bail!("Supabase did not clear the refresh lease while revoking an in-flight refresh");
        }
        if revoked.version <= before.version
            || revoked.authorization_generation <= before.authorization_generation
        {
            bail!("Supabase revocation did not advance credential version and authorization generation");
        }
        if revoked.access_token_nonce != before.access_token_nonce
            || revoked.access_token_ciphertext != before.access_token_ciphertext
            || revoked.refresh_token_nonce != before.refresh_token_nonce
            || revoked.refresh_token_ciphertext != before.refresh_token_ciphertext
        {
            bail!("Supabase revocation unexpectedly changed encrypted MCP token material");
        }
        Ok(revoked)
    }

    fn verify_snapshot_unchanged(
        &mut self,
        user: &str,
        expected: &CredentialSnapshot,
    ) -> Result<()> {
        if self.credential_snapshot(user)? != *expected {
            bail!("stale IdP refresh response changed the revoked MCP credential snapshot");
        }
        Ok(())
    }

    fn refresh_lease_clock_snapshot(&mut self, user: &str) -> Result<RefreshLeaseClockSnapshot> {
        let row = self.client.query_one(
            &format!(
                "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT, \
                        refresh_lease_id,refresh_lease_expires_at_unix \
                 FROM \"{}\".mcp_oauth_credentials WHERE user_id=$1 AND server_name=$2",
                self.schema
            ),
            &[&user, &SERVER_NAME],
        )?;
        Ok(RefreshLeaseClockSnapshot {
            db_now: row.get(0),
            lease_id: row.get(1),
            expires_at_unix: row.get(2),
        })
    }

    fn verify_old_refresh_lease_while_request_is_pending(
        &mut self,
        user: &str,
        old_lease_id: &str,
        old_expiry: i64,
        observation: Duration,
    ) -> Result<()> {
        let first = self.refresh_lease_clock_snapshot(user)?;
        let observation_secs = i64::try_from(observation.as_secs()).unwrap_or(i64::MAX);
        let required_margin = observation_secs.saturating_add(3);
        if old_expiry.saturating_sub(first.db_now) < required_margin {
            bail!(
                "replacement MCP refresh request did not leave enough live-lease margin for observation: db_now={}, old_expiry={old_expiry}, required_margin={required_margin}",
                first.db_now
            );
        }
        let observed_until = first.db_now.saturating_add(observation_secs);
        let mut snapshot = first;
        loop {
            if snapshot.db_now >= old_expiry {
                bail!("replacement MCP refresh lease observation crossed the old expiry");
            }
            if snapshot.lease_id.as_deref() != Some(old_lease_id)
                || snapshot.expires_at_unix != Some(old_expiry)
            {
                bail!(
                    "replacement gateway changed the crashed MCP refresh lease before expiry: expected id={old_lease_id}, expiry={old_expiry}, observed id={:?}, expiry={:?}",
                    snapshot.lease_id,
                    snapshot.expires_at_unix
                );
            }
            if snapshot.db_now >= observed_until {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
            snapshot = self.refresh_lease_clock_snapshot(user)?;
        }
    }

    fn wait_for_refresh_lease_takeover(
        &mut self,
        user: &str,
        old_lease_id: &str,
        old_expiry: i64,
    ) -> Result<RefreshLeaseTakeover> {
        let started = Instant::now();
        let mut last_snapshot = None;
        while started.elapsed() < Duration::from_secs(30) {
            let snapshot = self.refresh_lease_clock_snapshot(user)?;
            if snapshot.db_now < old_expiry && snapshot.lease_id.as_deref() != Some(old_lease_id) {
                bail!(
                    "replacement gateway took over the MCP refresh lease before expiry: db_now={}, old_expiry={old_expiry}, old_id={old_lease_id}, observed_id={:?}",
                    snapshot.db_now,
                    snapshot.lease_id
                );
            }
            if snapshot.db_now > old_expiry {
                if let (Some(lease_id), Some(expires_at_unix)) =
                    (&snapshot.lease_id, snapshot.expires_at_unix)
                {
                    if lease_id != old_lease_id && expires_at_unix > snapshot.db_now {
                        return Ok(RefreshLeaseTakeover {
                            db_now: snapshot.db_now,
                            lease_id: lease_id.clone(),
                        });
                    }
                }
            }
            last_snapshot = Some((snapshot.db_now, snapshot.lease_id, snapshot.expires_at_unix));
            thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "replacement gateway never acquired a distinct MCP refresh lease after the crashed lease expired: old_id={old_lease_id}, old_expiry={old_expiry}, last={last_snapshot:?}"
        )
    }

    fn verify_replacement_refresh_snapshot(
        &mut self,
        user: &str,
        before: &CredentialSnapshot,
    ) -> Result<()> {
        let refreshed = self.credential_snapshot(user)?;
        let db_now = self.refresh_lease_clock_snapshot(user)?.db_now;
        if refreshed.revoked_at_unix.is_some()
            || refreshed.refresh_lease_id.is_some()
            || refreshed.refresh_lease_expires_at_unix.is_some()
        {
            bail!("replacement refresh did not leave an active credential with no lease");
        }
        if refreshed.version <= before.version
            || refreshed.expires_at_unix <= db_now
            || refreshed.last_refresh_outcome.as_deref() != Some("refreshed")
        {
            bail!("replacement refresh did not persist a newer usable MCP credential");
        }
        Ok(())
    }

    fn wait_for_refresh_lease_claim(&mut self, user: &str) -> Result<(String, i64)> {
        let query = format!(
            "SELECT refresh_lease_id,refresh_lease_expires_at_unix FROM \"{}\".mcp_oauth_credentials \
             WHERE user_id=$1 AND server_name=$2 AND refresh_lease_id IS NOT NULL",
            self.schema
        );
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            if let Some(row) = self.client.query_opt(&query, &[&user, &SERVER_NAME])? {
                let lease_id: String = row.get(0);
                let expires_at: i64 = row.get(1);
                return Ok((lease_id, expires_at));
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("Supabase never exposed the active MCP refresh lease")
    }

    fn wait_for_refresh_lease_extension(
        &mut self,
        user: &str,
        lease_id: &str,
        initial_expiry: i64,
    ) -> Result<i64> {
        let query = format!(
            "SELECT refresh_lease_expires_at_unix FROM \"{}\".mcp_oauth_credentials \
             WHERE user_id=$1 AND server_name=$2 AND refresh_lease_id=$3",
            self.schema
        );
        let started = Instant::now();
        let mut last_expiry = None;
        while started.elapsed() < Duration::from_secs(15) {
            if let Some(row) = self
                .client
                .query_opt(&query, &[&user, &SERVER_NAME, &lease_id])?
            {
                let expires_at: i64 = row.get(0);
                last_expiry = Some(expires_at);
                if expires_at > initial_expiry {
                    return Ok(expires_at);
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "Supabase MCP refresh lease did not advance while IdP refresh was in flight: initial={initial_expiry}, last={last_expiry:?}"
        )
    }

    fn verify_no_active_credential(&mut self, user: &str) -> Result<()> {
        let count: i64 = self
            .client
            .query_one(
                &format!(
                    "SELECT COUNT(*) FROM \"{}\".mcp_oauth_credentials \
                     WHERE user_id=$1 AND server_name=$2 AND revoked_at_unix IS NULL",
                    self.schema
                ),
                &[&user, &SERVER_NAME],
            )?
            .get(0);
        if count != 0 {
            bail!("subject-mismatched callback persisted an active MCP credential");
        }
        Ok(())
    }

    fn verify_mcp_rls(&mut self) -> Result<()> {
        let prefix = format!("\"{}\".", self.schema);
        self.client.batch_execute(&format!(
            "INSERT INTO {prefix}mcp_oauth_authorization_states \
               (tenant_id,workspace_id,user_id,server_name,generation,updated_at_unix) \
             VALUES ('{OTHER_TENANT_ID}','{OTHER_WORKSPACE_ID}','{USER_A}','rls-other',1,1);
             INSERT INTO {prefix}mcp_oauth_flows \
               (id,tenant_id,workspace_id,user_id,server_name,pkce_nonce,pkce_ciphertext,oidc_nonce, \
                authorization_generation,created_at_unix,expires_at_unix,consumed_at_unix) \
             VALUES ('rls-other-flow','{OTHER_TENANT_ID}','{OTHER_WORKSPACE_ID}','{USER_A}', \
                     'rls-other',decode('00','hex'),decode('00','hex'),'rls',1,1,2,NULL);
             INSERT INTO {prefix}mcp_oauth_credentials \
               (id,tenant_id,workspace_id,user_id,server_name,issuer,subject,token_type,scopes_json, \
                access_token_nonce,access_token_ciphertext,expires_at_unix,key_version,version, \
                authorization_generation,created_at_unix,updated_at_unix) \
             VALUES ('rls-other-credential','{OTHER_TENANT_ID}','{OTHER_WORKSPACE_ID}','{USER_A}', \
                     'rls-other','https://issuer.invalid','{USER_A}','Bearer','[]'::jsonb, \
                     decode('00','hex'),decode('00','hex'),2,1,1,1,1,1);
             GRANT USAGE ON SCHEMA \"{}\" TO authenticated;
             GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE \
               {prefix}mcp_oauth_authorization_states,{prefix}mcp_oauth_flows, \
               {prefix}mcp_oauth_credentials TO authenticated;",
            self.schema
        ))?;

        for tenant_id in [TENANT_ID, OTHER_TENANT_ID] {
            let mut transaction = self.client.transaction()?;
            transaction.batch_execute("SET LOCAL ROLE authenticated")?;
            transaction.query_one(
                "SELECT set_config('ferrogate.tenant_id',$1,TRUE), \
                        set_config('ferrogate.platform_mode','off',TRUE)",
                &[&tenant_id],
            )?;
            for table in [
                "mcp_oauth_authorization_states",
                "mcp_oauth_flows",
                "mcp_oauth_credentials",
            ] {
                let rows = transaction.query(
                    &format!("SELECT DISTINCT tenant_id FROM {prefix}{table}"),
                    &[],
                )?;
                let visible = rows
                    .into_iter()
                    .map(|row| row.get::<_, String>(0))
                    .collect::<Vec<_>>();
                if visible != [tenant_id.to_string()] {
                    bail!("RLS {table} leaked cross-tenant rows for {tenant_id}: {visible:?}");
                }
            }
            if tenant_id == TENANT_ID {
                let affected = transaction.execute(
                    &format!(
                        "UPDATE {prefix}mcp_oauth_authorization_states SET generation=generation+1 \
                         WHERE tenant_id=$1"
                    ),
                    &[&OTHER_TENANT_ID],
                )?;
                if affected != 0 {
                    bail!("tenant RLS allowed a cross-tenant MCP authorization-state update");
                }
            }
            transaction.commit()?;
        }

        let mut platform = self.client.transaction()?;
        platform.batch_execute("SET LOCAL ROLE authenticated")?;
        platform.query_one(
            "SELECT set_config('ferrogate.tenant_id','',TRUE), \
                    set_config('ferrogate.platform_mode','on',TRUE)",
            &[],
        )?;
        for table in [
            "mcp_oauth_authorization_states",
            "mcp_oauth_flows",
            "mcp_oauth_credentials",
        ] {
            let count: i64 = platform
                .query_one(
                    &format!("SELECT COUNT(DISTINCT tenant_id) FROM {prefix}{table}"),
                    &[],
                )?
                .get(0);
            if count != 2 {
                bail!("platform RLS context did not expose both MCP tenants for {table}");
            }
        }
        platform.commit()?;

        let mut forbidden = self.client.transaction()?;
        forbidden.batch_execute("SET LOCAL ROLE authenticated")?;
        forbidden.query_one(
            "SELECT set_config('ferrogate.tenant_id',$1,TRUE), \
                    set_config('ferrogate.platform_mode','off',TRUE)",
            &[&TENANT_ID],
        )?;
        let insert = forbidden.execute(
            &format!(
                "INSERT INTO {prefix}mcp_oauth_authorization_states \
                 (tenant_id,workspace_id,user_id,server_name,generation,updated_at_unix) \
                 VALUES ($1,$2,$3,'rls-forbidden-insert',1,1)"
            ),
            &[&OTHER_TENANT_ID, &OTHER_WORKSPACE_ID, &USER_A],
        );
        if insert.is_ok() {
            bail!("tenant RLS allowed a cross-tenant MCP authorization-state insert");
        }
        forbidden.rollback()?;
        Ok(())
    }

    fn verify_ciphertext_and_audit(&mut self) -> Result<()> {
        let plaintext_fragments: i64 = self.client.query_one(
            &format!("SELECT COUNT(*) FROM \"{}\".mcp_oauth_credentials WHERE position(convert_to('access::','UTF8') in access_token_ciphertext) > 0 OR position(convert_to('refresh::','UTF8') in COALESCE(refresh_token_ciphertext, ''::bytea)) > 0", self.schema),
            &[],
        ).map(|row| row.get(0)).unwrap_or(0);
        if plaintext_fragments != 0 {
            bail!("Supabase MCP credential rows contained plaintext token fragments");
        }
        let count: i64 = self.client.query_one(
            &format!("SELECT COUNT(*) FROM \"{}\".audit_events WHERE action IN ('mcp.identity.connect','mcp.identity.resolve') AND request_id IS NOT NULL AND audit_json::text NOT LIKE '%access::%' AND audit_json::text NOT LIKE '%refresh::%'", self.schema),
            &[],
        )?.get(0);
        if count < 4 {
            bail!("Supabase omitted MCP subject/decision audit evidence");
        }
        Ok(())
    }

    fn verify_revocation_outcome(&mut self, user: &str, expected: &str) -> Result<()> {
        let outcome: Option<String> = self
            .client
            .query_one(
                &format!(
                    "SELECT last_revocation_outcome FROM \"{}\".mcp_oauth_credentials WHERE user_id=$1 AND server_name=$2",
                    self.schema
                ),
                &[&user, &SERVER_NAME],
            )?
            .get(0);
        if outcome.as_deref() != Some(expected) {
            bail!("Supabase MCP revocation outcome mismatch: {outcome:?}");
        }
        Ok(())
    }
}

fn gateway_config(
    gateway_addr: &str,
    oidc_addr: &str,
    mcp_addr: &str,
    schema: &str,
    postgres_pool_size: usize,
    args: &SupabaseLiveRestartArgs,
) -> Result<String> {
    let tls_mode = match args.tls_mode.as_str() {
        "require" | "verify_ca" | "verify_full" => args.tls_mode.as_str(),
        other => bail!("invalid live Supabase TLS mode {other}"),
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
  postgres_pool_size: {postgres_pool_size}
  postgres_pool_acquire_timeout_millis: 30000
  postgres_tls_mode: "{tls_mode}"
{ca}  postgres_connect_timeout_secs: 10
  postgres_statement_timeout_millis: 30000
  postgres_schema: "{schema}"
  postgres_search_path: ["public"]
  migration_mode: "auto"
providers:
  - name: "unused"
    kind: "openai"
    base_url: "http://127.0.0.1:1/v1"
    api_key_env: "FERROGATE_PROVIDER_SECRET"
models:
  - name: "unused"
    provider: "unused"
    provider_model: "unused"
    capabilities: ["chat"]
    context_window: 8192
api_keys:
  - id: "mcp-e2e-admin"
    name: "MCP E2E admin"
    key: "mcp-identity-admin-secret"
    scopes: ["admin.read", "admin.write"]
    # #540: platform root is stated, never inherited from an omitted field.
    platform_operator: true
  - id: "mcp-e2e-key-a"
    name: "MCP E2E user A"
    key: "mcp-identity-user-a-secret"
    scopes: ["tools.read", "tools.execute"]
    organization_id: "{TENANT_ID}"
    project_id: "{PROJECT_ID}"
    workspace_id: "{WORKSPACE_ID}"
    user_id: "{USER_A}"
  - id: "mcp-e2e-key-b"
    name: "MCP E2E user B"
    key: "mcp-identity-user-b-secret"
    scopes: ["tools.read", "tools.execute"]
    organization_id: "{TENANT_ID}"
    project_id: "{PROJECT_ID}"
    workspace_id: "{WORKSPACE_ID}"
    user_id: "{USER_B}"
mcp_servers:
  - name: "{SERVER_NAME}"
    transport: "streamable_http"
    url: "http://{mcp_addr}/mcp"
    auth_type: "per_user_oauth"
    oauth:
      issuer: "http://{oidc_addr}"
      client_id: "mcp-e2e-client"
      client_secret_ref: "env://FERROGATE_TEST_MCP_OIDC_SECRET"
      redirect_uri: "http://{gateway_addr}/v1/mcp/identity/callback"
      scopes: ["openid", "profile"]
      allow_insecure_http: true
    tools_to_execute: ["whoami"]
    tools_to_auto_execute: ["whoami"]
    approval_policy: "never"
    timeout_ms: 3000
  - name: "{ORIGINAL_SERVER_NAME}"
    transport: "streamable_http"
    url: "http://{mcp_addr}/mcp/original"
    auth_type: "original_bearer"
    oauth:
      issuer: "http://{oidc_addr}"
      client_id: "{ORIGINAL_AUDIENCE}"
      scopes: ["openid", "profile"]
      allow_insecure_http: true
    tools_to_execute: ["whoami"]
    tools_to_auto_execute: ["whoami"]
    approval_policy: "never"
    timeout_ms: 3000
  - name: "{SIGNED_SERVER_NAME}"
    transport: "streamable_http"
    url: "http://{mcp_addr}/mcp/signed"
    auth_type: "ferrogate_signed_jwt"
    signed_jwt_audience: "{SIGNED_AUDIENCE}"
    tools_to_execute: ["whoami"]
    tools_to_auto_execute: ["whoami"]
    approval_policy: "never"
    timeout_ms: 3000
"#
    ))
}

fn query_value(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    form_pairs(query).remove(key)
}

fn form_pairs(value: &str) -> std::collections::HashMap<String, String> {
    value
        .split('&')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            Some((form_decode(key), form_decode(value)))
        })
        .collect()
}

fn form_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            let character = byte as char;
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '~') {
                character.to_string()
            } else if character == ' ' {
                "+".into()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn form_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => output.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                    output.push(byte);
                    index += 2;
                } else {
                    output.push(bytes[index]);
                }
            }
            byte => output.push(byte),
        }
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}
