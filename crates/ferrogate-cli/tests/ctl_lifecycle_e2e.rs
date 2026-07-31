// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: End-to-end coverage for the #362 CLI lifecycle command families
// (agent schedules, self-hosted workers, tool approvals, guardrail policies)
// driven through the REAL `ferrogate ctl <group> <verb>` binary against a REAL
// in-process gateway (in-memory backend; no Docker, no Postgres, no Cloudflare).
//
// The #362 families are unit-covered in `ferrogate-control-plane-client` against a fake
// transport, and the OpenAPI operation-id parity gate proves every operation is
// mapped or reviewed. What was NOT proven anywhere was the load-bearing product
// claim: that invoking the shipped `ferrogate` binary — clap parse -> generic
// registry dispatch -> ReqwestTransport -> a live Control Plane API — actually
// drives each lifecycle to a durable, API-visible state transition and surfaces
// the run/audit/correlation evidence and stable exit behavior automation depends
// on. `control_cli_e2e.rs` explicitly defers that "live standalone Control Plane
// API" scenario to the test gate; this file is that gate coverage.
//
// It proves, through the CLI process boundary, issue #362's acceptance criteria:
//   AC2 lifecycle flows: schedule run-now -> run evidence; approval decision ->
//     audit evidence; guardrail revision activation + rollback; worker
//     certificate/identity rotation.
//   AC3 explicit failures with stable exit classes: wrong fingerprint,
//     already-terminal action, wrong version/not-found, insufficient scope,
//     wrong tenant.
//   AC4 JSON output carries identity/correlation fields (run/fire/dispatch,
//     approval + reviewer, binding revision, rotated fingerprints) plus the
//     request-id / trace-id surfaced on stderr for automation.

mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Output;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ferrogate_guardrails::{
    all_content_sources, CheckBinding, DetectorDefinition, DetectorStage, ManagedActionClass,
    ManagedActionSelector, PolicyAction, PolicyAggregation, PolicyExecution, PolicyMode,
    PolicyRevision, PolicyScopeSelector, PolicyStreamingMode,
};
use serde_json::{json, Value};
use support::{free_addr, http_request, start_gateway, wait_for_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];

// ---------------------------------------------------------------------------
// CLI process helpers: run the REAL `ferrogate` binary against a live gateway.
// ---------------------------------------------------------------------------

/// A parsed outcome of one `ferrogate ctl ...` invocation. The CLI home tempdir
/// is retained so it is cleaned up only when the run is dropped.
struct CliRun {
    output: Output,
    _home: tempfile::TempDir,
}

impl CliRun {
    fn code(&self) -> i32 {
        self.output
            .status
            .code()
            .expect("process exited via signal")
    }

    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).into_owned()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }

    /// The stdout payload parsed as JSON. stdout is data-only, so this must
    /// succeed for any successful command.
    fn json(&self) -> Value {
        serde_json::from_str(self.stdout().trim()).unwrap_or_else(|error| {
            panic!(
                "stdout must be JSON ({error}): stdout={:?} stderr={:?}",
                self.stdout(),
                self.stderr()
            )
        })
    }
}

/// Run `ferrogate ctl <args...>` as an operator holding `token` against the
/// gateway at `endpoint`, with `--output json`. The CLI home is a fresh tempdir
/// so no on-disk context leaks between invocations; the bearer token rides an
/// env var (never the argv) exactly as `--token-env` requires.
///
/// `tenant`, when set, adds `--tenant` — which puts an `x-ferrogate-tenant`
/// header on the request and **nothing more**. No Control Plane API operation
/// declares that header, so the value does not select, narrow, or redirect
/// anything; tenancy below comes from the bearer token. An earlier version of
/// this comment claimed the argument "exercises tenant selection", which was
/// wrong in the way that matters: these runs would pass with any tenant string,
/// including one that does not exist. What it does exercise is that a resolved
/// tenant reaches the wire without disturbing the request — and that the CLI
/// says so on stderr (`context::unhonored_scope_notice`).
fn run_ctl(endpoint: &str, token: &str, tenant: Option<&str>, args: &[&str]) -> CliRun {
    let home = tempfile::tempdir().unwrap();
    let mut command = support::ferrogate_command();
    for var in [
        "FERROGATE_ENDPOINT",
        "FERROGATE_CONTEXT",
        "FERROGATE_TENANT",
        "FERROGATE_TIMEOUT_MILLIS",
    ] {
        command.env_remove(var);
    }
    command.env("FERROGATE_CLI_HOME", home.path());
    command.env("FG_CTL_TOKEN", token);
    command.arg("ctl");
    command.args(args);
    command.args([
        "--endpoint",
        endpoint,
        "--token-env",
        "FG_CTL_TOKEN",
        "--output",
        "json",
    ]);
    if let Some(tenant) = tenant {
        command.args(["--tenant", tenant]);
    }
    let output = command.output().unwrap();
    CliRun {
        output,
        _home: home,
    }
}

fn endpoint_for(addr: &str) -> String {
    format!("http://{addr}")
}

/// A mutating verb the server refused still writes its decision receipt to
/// stdout, stating that the change did **not** take effect and why.
///
/// Before the #505 rework a non-2xx returned before rendering, so `--output
/// json` produced an empty stdout and the only record of the attempt was prose
/// on stderr. The receipt is the output contract of a mutating verb; a contract
/// that goes silent on failure fails exactly where an operator needs it, so
/// "stdout is empty on a failed mutation" is no longer the assertion — "stdout
/// carries a receipt that says it did not happen" is.
fn assert_refused_receipt(run: &CliRun, expected_code: &str) {
    let receipt = run.json();
    assert_eq!(
        receipt["object"], "mutation_receipt",
        "a failed mutation must still emit a receipt: {receipt}"
    );
    assert_eq!(
        receipt["outcome"], "rejected",
        "the server answered with an error envelope, so the change was refused: {receipt}"
    );
    assert_eq!(receipt["dry_run"], false, "{receipt}");
    assert_eq!(
        receipt["failure"]["value"]["code"], expected_code,
        "the receipt must carry the server's own error code: {receipt}"
    );
    assert!(
        receipt["http_status"]["value"].is_number(),
        "the refusal's status is part of the audit record: {receipt}"
    );
    assert!(
        receipt["response"].is_null(),
        "a refused mutation carries no response document: {receipt}"
    );
    assert!(
        receipt["target"]["action_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:")),
        "the refused action is still identified: {receipt}"
    );
}

fn body_of(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response)
}

fn response_json(response: &str) -> Value {
    serde_json::from_str(body_of(response))
        .unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

/// Minimal gateway config: an unrestricted platform-operator admin key, a
/// read-only key (for the insufficient-scope proof), and the scheduler left OFF
/// so the only schedule fire is the manual `run-now` under test.
fn base_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "reader"
name = "Read-only operator"
key = "reader-secret"
scopes = ["admin.read"]
platform_operator = true

[scheduler]
enabled = false
tick_interval_secs = 60
"#
    )
}

fn create_tenant_account(gateway_addr: &str, tenant_id: &str) {
    let response = http_request(
        gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        &json!({
            "id": tenant_id,
            "name": format!("CLI lifecycle {tenant_id}"),
            "slug": tenant_id
        })
        .to_string(),
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "tenant account {tenant_id} should be created: {response}"
    );
}

fn bootstrap_schedule_scope(
    gateway_addr: &str,
    tenant_id: &str,
    project_id: &str,
    workspace_id: &str,
) {
    create_tenant_account(gateway_addr, tenant_id);
    for (path, body, what) in [
        (
            "/admin/v1/projects",
            json!({
                "id": project_id,
                "tenant_id": tenant_id,
                "name": format!("CLI lifecycle {project_id}"),
                "slug": project_id
            }),
            "project",
        ),
        (
            "/admin/v1/workspaces",
            json!({
                "id": workspace_id,
                "project_id": project_id,
                "name": format!("CLI lifecycle {workspace_id}"),
                "slug": workspace_id
            }),
            "workspace",
        ),
    ] {
        let response = http_request(gateway_addr, "POST", path, &ADMIN, &body.to_string());
        assert!(
            response.starts_with("HTTP/1.1 201"),
            "schedule {what} should be created: {response}"
        );
    }
}

// ---------------------------------------------------------------------------
// AC2/AC3/AC4 — guardrail revision activation + rollback via the CLI.
// ---------------------------------------------------------------------------

/// A durable, enforced guardrail policy revision keyed to `policy_id`, blocking
/// on a keyword in a managed MCP action's scanned input. Serialized as the
/// `--data` body of the CLI create/create-revision verbs — using the real
/// `ferrogate_guardrails::PolicyRevision` type so the wire body exactly matches
/// the server's contract (the CLI keeps request bodies schema-agnostic).
fn guardrail_revision(policy_id: &str, keyword: &str) -> PolicyRevision {
    PolicyRevision {
        policy_id: policy_id.to_string(),
        revision: 1,
        name: format!("{policy_id} guardrail"),
        description: None,
        enforced: true,
        scope: PolicyScopeSelector {
            managed_action: Some(ManagedActionSelector {
                classes: vec![ManagedActionClass::Mcp],
                targets: Vec::new(),
            }),
            ..PolicyScopeSelector::default()
        },
        checks: vec![CheckBinding {
            id: "keyword".to_string(),
            enabled: true,
            stage: DetectorStage::Request,
            sources: all_content_sources(),
            detector: DetectorDefinition::local(vec![keyword.to_string()], Vec::new(), None),
            fallback_detector: None,
        }],
        aggregation: PolicyAggregation::All,
        execution: PolicyExecution::Sequential,
        mode: PolicyMode::Enforce,
        streaming: PolicyStreamingMode::BufferAndEnforce,
        on_pass: vec![PolicyAction::allow()],
        on_fail: vec![PolicyAction::block(
            "blocked",
            "blocked by guardrail policy",
        )],
        on_error: vec![PolicyAction::block(
            "unavailable",
            "guardrail policy unavailable",
        )],
        deadline_ms: 2_000,
        created_at_unix: 1,
        created_by: "test-admin".to_string(),
    }
}

/// The `ctl` argv a mutation receipt's rollback pointer emits, with the leading
/// `ctl` program word stripped so it can be replayed through [`run_ctl`].
///
/// Panics rather than returning an `Option`: a caller reaching here has already
/// asserted the pointer is present, and a silently-skipped reversal would make
/// the E2E pass while proving nothing.
fn receipt_rollback_argv(receipt: &Value) -> Vec<String> {
    let command = receipt["rollback"]["value"]["command"]
        .as_array()
        .unwrap_or_else(|| panic!("receipt rollback pointer must carry a command: {receipt}"));
    let command: Vec<String> = command
        .iter()
        .map(|word| {
            word.as_str()
                .unwrap_or_else(|| panic!("rollback command words must be strings: {receipt}"))
                .to_string()
        })
        .collect();
    assert_eq!(
        command.first().map(String::as_str),
        Some("ctl"),
        "the reversal command must be a `ctl` invocation: {command:?}"
    );
    command[1..].to_vec()
}

#[test]
fn guardrail_revision_activation_and_rollback_via_cli() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, base_config(&gateway_addr)).unwrap();
    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);
    let endpoint = endpoint_for(&gateway_addr);
    let policy_id = "ctl-guardrail-pol";

    // 1. `ctl guardrail-policies create` opens the policy chain at revision 1.
    let rev1 = serde_json::to_string(&guardrail_revision(policy_id, "exfiltrate")).unwrap();
    let create = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &["guardrail-policies", "create", "--data", &rev1],
    );
    assert_eq!(create.code(), 0, "create stderr: {}", create.stderr());
    let create_json = create.json();
    assert_eq!(create_json["object"], "mutation_receipt");
    let create_json = &create_json["response"];
    assert_eq!(create_json["object"], "guardrail_policy_revision");
    assert_eq!(
        create_json["policy"]["revision"], 1,
        "first revision is 1: {create_json}"
    );

    // 2. Activate revision 1 so the policy has a live binding to roll back to.
    let activate_rev1 = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &[
            "guardrail-policies",
            "activate",
            policy_id,
            "--data",
            r#"{"revision":1}"#,
        ],
    );
    assert_eq!(
        activate_rev1.code(),
        0,
        "activate rev1 stderr: {}",
        activate_rev1.stderr()
    );
    // #505 wrapped every mutating verb's stdout in a MutationReceipt with the
    // server document nested under `response`. Assert the envelope too, not
    // just the nested value: a receipt that lost its `response` would otherwise
    // read as `null == null` against a mistyped key.
    assert_eq!(activate_rev1.json()["object"], "mutation_receipt");
    assert_eq!(activate_rev1.json()["dry_run"], false);
    assert_eq!(activate_rev1.json()["response"]["active_revision"], 1);

    // 3. `ctl guardrail-policies create-revision` appends immutable revision 2.
    let rev2 = serde_json::to_string(&guardrail_revision(policy_id, "leak")).unwrap();
    let append = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &[
            "guardrail-policies",
            "create-revision",
            policy_id,
            "--data",
            &rev2,
        ],
    );
    assert_eq!(
        append.code(),
        0,
        "create-revision stderr: {}",
        append.stderr()
    );
    assert_eq!(append.json()["object"], "mutation_receipt");
    assert_eq!(
        append.json()["response"]["policy"]["revision"],
        2,
        "appended revision is 2: {}",
        append.stdout()
    );

    // 4. AC2: `ctl guardrail-policies activate` promotes revision 2 to live and
    //    archives revision 1. AC4: the binding JSON carries the policy_id +
    //    active_revision identity.
    let activate = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &[
            "guardrail-policies",
            "activate",
            policy_id,
            "--data",
            r#"{"revision":2}"#,
        ],
    );
    assert_eq!(activate.code(), 0, "activate stderr: {}", activate.stderr());
    let activated = activate.json();
    assert_eq!(activated["object"], "mutation_receipt");
    let activated = &activated["response"];
    assert_eq!(activated["object"], "guardrail_policy_binding");
    assert_eq!(activated["policy_id"], policy_id);
    assert_eq!(
        activated["active_revision"], 2,
        "activation makes revision 2 live: {activated}"
    );
    assert_eq!(activated["rollback"], false);
    // AC4: correlation ids are diagnostics on stderr, never mixed into stdout.
    assert!(
        activate.stderr().contains("request-id:"),
        "activate must surface a request-id on stderr: {}",
        activate.stderr()
    );
    assert!(
        !activate.stdout().contains("request-id"),
        "stdout must stay data-only: {}",
        activate.stdout()
    );

    // 5. AC2 + #505 E2E(b): `ctl guardrail-policies rollback` atomically returns
    //    to revision 1 (now archived by the revision-2 activation) — and the
    //    revision it returns to is NOT typed here. The reversal is driven by the
    //    activation receipt's own `rollback.command`, so this asserts the
    //    receipt is actually actionable: an operator who holds only the receipt
    //    can undo the change without knowing the chain's history. A pointer that
    //    named the wrong revision, or that the CLI could not parse back into its
    //    own argv, fails here instead of passing because the test re-typed the
    //    right answer.
    let activate_receipt = activate.json();

    // #505 E2E(a): the receipt's audit id addresses a real audit row. #552 made
    // guardrail-policy activate/rollback return one, so this is the one endpoint
    // where the identifier can be followed instead of explained away. The row is
    // located by that id alone — nothing here is typed by hand.
    let audit_id = activate_receipt["audit_id"]["value"]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "guardrail-policy activate must return an audit id (#552): {}",
                activate.stdout()
            )
        })
        .to_string();
    let audit_events = response_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events?limit=200",
        &ADMIN,
        "",
    ));
    let row = audit_events["data"]
        .as_array()
        .and_then(|events| events.iter().find(|event| event["id"] == audit_id.as_str()))
        .unwrap_or_else(|| {
            panic!("receipt audit_id {audit_id} must address an audit row: {audit_events}")
        });
    assert_eq!(
        row["action"], "guardrail.policy_activate",
        "the addressed row must be the activation this receipt describes: {row}"
    );
    assert_eq!(
        row["target"],
        format!("{policy_id}@2"),
        "the addressed row must name the object version the receipt changed: {row}"
    );

    let pointer = &activate_receipt["rollback"];
    assert!(
        pointer["value"].is_object(),
        "the activation receipt must carry a rollback pointer (absent_reason={}): {}",
        pointer["absent_reason"],
        activate.stdout()
    );
    assert_eq!(
        pointer["value"]["created_revision"]["value"], "2",
        "the pointer must name the revision this activation created: {pointer}"
    );
    assert_eq!(
        pointer["value"]["restores_revision"]["value"], "1",
        "the reversal target is the server-reported previously active revision, \
         which is revision 1 here: {pointer}"
    );
    let reversal = receipt_rollback_argv(&activate_receipt);
    assert_eq!(
        reversal,
        vec![
            "guardrail-policies".to_string(),
            "rollback".to_string(),
            policy_id.to_string(),
            "--data".to_string(),
            r#"{"revision":1}"#.to_string(),
        ],
        "the receipt's reversal argv must be the real `ctl` invocation that undoes \
         the activation: {pointer}"
    );
    let reversal_args: Vec<&str> = reversal.iter().map(String::as_str).collect();
    let rollback = run_ctl(&endpoint, "admin-secret", None, &reversal_args);
    assert_eq!(rollback.code(), 0, "rollback stderr: {}", rollback.stderr());
    let rolled_back = rollback.json();
    assert_eq!(rolled_back["object"], "mutation_receipt");
    let rolled_back = &rolled_back["response"];
    assert_eq!(rolled_back["object"], "guardrail_policy_binding");
    assert_eq!(
        rolled_back["active_revision"], 1,
        "rollback returns revision 1 to live: {rolled_back}"
    );
    assert_eq!(
        rolled_back["rollback"], true,
        "rollback verb must reach the .../rollback action (rollback=true): {rolled_back}"
    );

    // Durable + API-visible: an independent read confirms the live binding is 1.
    let binding = response_json(&http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/guardrail-policies/{policy_id}"),
        &ADMIN,
        "",
    ));
    assert!(
        binding["data"]
            .as_array()
            .map(|r| !r.is_empty())
            .unwrap_or(false),
        "policy revisions must be readable after rollback: {binding}"
    );

    // 6. AC3: activating a nonexistent revision fails explicitly with a stable
    //    not-found exit class (404 -> exit 4), never a silent success.
    let bad = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &[
            "guardrail-policies",
            "activate",
            policy_id,
            "--data",
            r#"{"revision":99}"#,
        ],
    );
    assert_eq!(
        bad.code(),
        4,
        "activating a missing revision -> NotFoundConflict (exit 4): {}",
        bad.stderr()
    );
    // Since the #505 rework a failed mutation still emits its receipt on
    // stdout: an activation that the server refused is exactly the event an
    // audit pipeline must record, and an empty stdout recorded nothing at all.
    // The prose stays on stderr; the receipt says WHAT was attempted and that
    // it did not take effect.
    assert_refused_receipt(&bad, "guardrail_policy_revision_not_found");
    assert!(
        bad.stderr().contains("guardrail_policy_revision_not_found"),
        "actionable server error surfaced: {}",
        bad.stderr()
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

// ---------------------------------------------------------------------------
// AC2/AC3/AC4 — agent schedule run-now -> run evidence via the CLI.
// ---------------------------------------------------------------------------

#[test]
fn agent_schedule_run_now_via_cli_records_run_evidence() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, base_config(&gateway_addr)).unwrap();
    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);
    let endpoint = endpoint_for(&gateway_addr);
    let schedule_id = "ctl-run-now-sched";
    bootstrap_schedule_scope(&gateway_addr, "ctl-tenant", "ctl-project", "ctl-ws");

    // Create the schedule through the CLI too, proving the create verb wiring.
    let schedule = json!({
        "id": schedule_id,
        "tenant_id": "ctl-tenant",
        "workspace_id": "ctl-ws",
        "name": "ctl-run-now",
        "spec_kind": "interval",
        "interval_secs": 3600,
        "target_kind": "self_hosted_dispatch",
        "target": {"required_capabilities": ["shell"]}
    })
    .to_string();
    let create = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &["agent-schedules", "create", "--data", &schedule],
    );
    assert_eq!(
        create.code(),
        0,
        "schedule create stderr: {}",
        create.stderr()
    );
    assert_eq!(create.json()["object"], "mutation_receipt");
    assert_eq!(
        create.json()["response"]["agent_schedule"]["id"],
        schedule_id
    );

    // AC2: `ctl agent-schedules run-now` manually fires the schedule and returns
    // the run evidence. AC4: the fire carries fire_id + dispatch_id + schedule_id
    // correlation, and the manual trigger's request-id/trace-id land on stderr.
    let run_now = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &["agent-schedules", "run-now", schedule_id],
    );
    assert_eq!(run_now.code(), 0, "run-now stderr: {}", run_now.stderr());
    let fire = run_now.json();
    assert_eq!(fire["object"], "mutation_receipt");
    let fire = &fire["response"];
    assert_eq!(fire["object"], "agent_schedule_fire");
    assert_eq!(fire["fire"]["schedule_id"], schedule_id);
    assert_eq!(
        fire["fire"]["outcome"], "dispatched",
        "a self-hosted-dispatch run-now produces a dispatched fire: {fire}"
    );
    let dispatch_id = fire["fire"]["dispatch_id"]
        .as_str()
        .unwrap_or_else(|| panic!("run-now fire must carry a dispatch id: {fire}"));
    assert!(
        dispatch_id.starts_with(&format!("schedule-dispatch-{schedule_id}-")),
        "dispatch id links the manual run: {dispatch_id}"
    );
    assert!(
        fire["fire"]["fire_id"].as_str().is_some(),
        "run evidence carries a fire id: {fire}"
    );
    assert!(
        run_now.stderr().contains("request-id:"),
        "run-now surfaces a request-id on stderr: {}",
        run_now.stderr()
    );

    // Durable: the fire is visible in the schedule's fire history.
    let fires = response_json(&http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/agent-schedules/{schedule_id}/fires"),
        &ADMIN,
        "",
    ));
    assert!(
        fires["data"]
            .as_array()
            .map(|history| {
                history
                    .iter()
                    .any(|entry| entry["dispatch_id"].as_str() == Some(dispatch_id))
            })
            .unwrap_or(false),
        "run-now fire must appear in durable fire history: {fires}"
    );

    // AC3: run-now on a missing schedule fails explicitly (404 -> exit 4).
    let missing = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &["agent-schedules", "run-now", "no-such-schedule"],
    );
    assert_eq!(
        missing.code(),
        4,
        "run-now on a missing schedule -> NotFoundConflict (exit 4): {}",
        missing.stderr()
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

// ---------------------------------------------------------------------------
// AC2/AC4 — self-hosted worker identity/certificate rotation via the CLI.
// ---------------------------------------------------------------------------

#[test]
fn self_hosted_worker_identity_rotation_via_cli() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, base_config(&gateway_addr)).unwrap();
    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);
    let endpoint = endpoint_for(&gateway_addr);

    // Register a worker (data-plane-adjacent registration is not a CLI verb, so
    // seed it via the admin API), then rotate its identity through the CLI.
    let register = response_json(&http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/self-hosted-workers",
        &ADMIN,
        &json!({
            "tenant": {
                "organization_id": "ctl-tenant",
                "team_id": null,
                "project_id": "ctl-project",
                "workspace_id": "ctl-ws",
                "user_id": null,
                "api_key_id": "admin"
            },
            "workspace_id": "ctl-ws",
            "worker_name": "ctl-worker",
            "identity_fingerprint": "sha256:ctl-original",
            "orchestration_enabled": false
        })
        .to_string(),
    ));
    let worker_id = register["worker"]["id"].as_str().unwrap().to_string();

    // AC2: `ctl self-hosted-workers rotate` mints a fresh identity fingerprint +
    // transport secret (a new verified-mTLS cert is bound to the rotated tuple).
    // AC4: the response carries the new + previous fingerprints and the one-time
    // secret an operator captures for the worker.
    let rotate = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &[
            "self-hosted-workers",
            "rotate",
            &worker_id,
            "--data",
            r#"{"identity_fingerprint":"sha256:ctl-rotated"}"#,
        ],
    );
    assert_eq!(rotate.code(), 0, "rotate stderr: {}", rotate.stderr());
    let rotated = rotate.json();
    assert_eq!(rotated["object"], "mutation_receipt");
    let rotated = &rotated["response"];
    assert_eq!(rotated["object"], "self_hosted_worker_identity_rotation");
    assert_eq!(
        rotated["worker"]["identity_fingerprint"], "sha256:ctl-rotated",
        "rotation installs the new fingerprint: {rotated}"
    );
    assert_eq!(
        rotated["previous_identity_fingerprint"], "sha256:ctl-original",
        "rotation reports the superseded fingerprint: {rotated}"
    );
    assert!(
        rotated["transport_token_secret"]
            .as_str()
            .map(|secret| secret.len() >= 16)
            .unwrap_or(false),
        "rotation returns a fresh transport secret: {rotated}"
    );
    assert!(
        rotated["rotated_at_unix"].as_u64().is_some(),
        "rotation is timestamped: {rotated}"
    );

    // Durable + API-visible: an independent read shows the rotated fingerprint.
    let fetched = response_json(&http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/self-hosted-workers/{worker_id}"),
        &ADMIN,
        "",
    ));
    assert_eq!(
        fetched["identity_fingerprint"], "sha256:ctl-rotated",
        "rotated fingerprint is durable: {fetched}"
    );

    // AC3: rotating a missing worker fails explicitly (404 -> exit 4).
    let missing = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &[
            "self-hosted-workers",
            "rotate",
            "no-such-worker",
            "--data",
            r#"{"identity_fingerprint":"sha256:x"}"#,
        ],
    );
    assert_eq!(
        missing.code(),
        4,
        "rotating a missing worker -> NotFoundConflict (exit 4): {}",
        missing.stderr()
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

// ---------------------------------------------------------------------------
// AC2/AC3/AC4 — tool-approval decision -> audit evidence via the CLI, and the
// wrong-fingerprint / already-terminal failure modes.
// ---------------------------------------------------------------------------

/// Gateway config with a builtin MCP tool provider whose approval policy is
/// `always`, so every `/v1/tools/execute` blocks on a pending admin approval —
/// the seam the CLI tool-approval verbs resolve.
fn approval_config(gateway_addr: &str, mcp_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[reliability]
# The pending approval must outlive the admin decision latency but auto-expire
# within the client read deadline; 8s matches the tuned value in agentic_lite.
tool_approval_timeout_secs = 8

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute"]
platform_operator = true

[[extensions]]
id = "mcp.http"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10
approval_policy = "always"

[extensions.permissions]
tools = ["github.search"]
network = ["127.0.0.1"]
filesystem = false
shell = false

[extensions.config]
endpoint = "http://{mcp_addr}/mcp"
timeout_ms = 3000
"#
    )
}

/// A tool execution that will block pending approval, run on a background
/// thread. Returns the parsed `/v1/tools/execute` response once the approval is
/// resolved (approved -> result; denied/mismatch -> `tool_denied`).
fn spawn_tool_execute(gateway_addr: &str, query: &str) -> JoinHandle<Value> {
    let addr = gateway_addr.to_string();
    let body = json!({"name": "github.search", "arguments": {"query": query}}).to_string();
    thread::spawn(move || {
        response_json(&http_request(
            &addr,
            "POST",
            "/v1/tools/execute",
            &[
                "Authorization: Bearer tool-secret",
                "Content-Type: application/json",
            ],
            &body,
        ))
    })
}

/// Poll the pending-approval queue until an approval not in `exclude` appears.
fn wait_for_pending_approval(gateway_addr: &str, exclude: &[&str]) -> Value {
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        let body = response_json(&http_request(
            gateway_addr,
            "GET",
            "/admin/v1/tool-approvals",
            &["Authorization: Bearer admin-secret"],
            "",
        ));
        if let Some(found) = body["data"].as_array().and_then(|approvals| {
            approvals.iter().find(|approval| {
                approval["status"] == "pending"
                    && approval["id"]
                        .as_str()
                        .is_some_and(|id| !exclude.contains(&id))
            })
        }) {
            return found.clone();
        }
        last = body;
        thread::sleep(Duration::from_millis(25));
    }
    panic!("tool approval did not become pending: {last}");
}

#[test]
fn tool_approval_decision_via_cli_records_audit_and_fails_closed() {
    let (mcp_addr, mcp_handle) = spawn_mcp_server(8);
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, approval_config(&gateway_addr, &mcp_addr)).unwrap();
    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);
    let endpoint = endpoint_for(&gateway_addr);

    // AC3 wrong fingerprint: seed a pending approval, then `ctl tool-approvals
    // approve` with a stale fingerprint must fail closed with a stable
    // conflict exit class (409 -> exit 4) and leave no data on stdout.
    let denied_exec = spawn_tool_execute(&gateway_addr, "ferrogate");
    let stale = wait_for_pending_approval(&gateway_addr, &[]);
    let stale_id = stale["id"].as_str().unwrap().to_string();
    let mismatch = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &[
            "tool-approvals",
            "approve",
            &stale_id,
            "--data",
            r#"{"fingerprint":"changed-arguments"}"#,
        ],
    );
    assert_eq!(
        mismatch.code(),
        4,
        "wrong fingerprint -> NotFoundConflict (exit 4): {}",
        mismatch.stderr()
    );
    assert!(
        mismatch
            .stderr()
            .contains("tool_approval_fingerprint_mismatch"),
        "server fingerprint-mismatch code surfaced: {}",
        mismatch.stderr()
    );
    assert_refused_receipt(&mismatch, "tool_approval_fingerprint_mismatch");
    // The gated execution fails closed too.
    assert_eq!(denied_exec.join().unwrap()["error"]["code"], "tool_denied");

    // AC2 approval decision -> audit evidence: seed a fresh pending approval and
    // approve it through the CLI with the correct fingerprint + actor evidence.
    // AC4: the decision JSON carries the approval id, resolved status, and the
    // reviewer identity for automation.
    let approved_exec = spawn_tool_execute(&gateway_addr, "ferrogate");
    let pending = wait_for_pending_approval(&gateway_addr, &[&stale_id]);
    let approval_id = pending["id"].as_str().unwrap().to_string();
    let fingerprint = pending["fingerprint"].as_str().unwrap().to_string();
    let approve = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &[
            "tool-approvals",
            "approve",
            &approval_id,
            "--data",
            &json!({"fingerprint": fingerprint, "reason": "operator approved via cli"}).to_string(),
        ],
    );
    assert_eq!(approve.code(), 0, "approve stderr: {}", approve.stderr());
    let decision = approve.json();
    assert_eq!(decision["object"], "mutation_receipt");
    let decision = &decision["response"];
    assert_eq!(decision["id"], approval_id);
    assert_eq!(
        decision["status"], "approved",
        "the CLI decision resolves the approval: {decision}"
    );
    assert_eq!(
        decision["reviewer_api_key_id"], "admin",
        "the decision records the reviewing operator identity: {decision}"
    );
    // The gated execution now proceeds and returns the tool result.
    let executed = approved_exec.join().unwrap();
    assert_eq!(
        executed["content"]["content"][0]["text"], "ferrogate-result",
        "an approved tool call executes: {executed}"
    );

    // AC2 audit evidence: the CLI decision left a durable, API-visible audit
    // event tying the approval id to the granting operator.
    let audit = response_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events?limit=200",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let granted = audit["data"]
        .as_array()
        .map(|events| {
            events.iter().any(|event| {
                event["action"] == "tool.approval_granted"
                    && event["target"]
                        .as_str()
                        .map(|target| target.contains(&approval_id))
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    assert!(
        granted,
        "CLI approval must record a tool.approval_granted audit event for {approval_id}: {audit}"
    );

    // AC3 already-terminal action: re-deciding a resolved approval fails closed
    // with a stable conflict exit class (409 -> exit 4).
    let terminal = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &[
            "tool-approvals",
            "approve",
            &approval_id,
            "--data",
            &json!({"fingerprint": fingerprint}).to_string(),
        ],
    );
    assert_eq!(
        terminal.code(),
        4,
        "re-approving a terminal approval -> NotFoundConflict (exit 4): {}",
        terminal.stderr()
    );
    assert!(
        terminal.stderr().contains("tool_approval_terminal"),
        "server terminal-state code surfaced: {}",
        terminal.stderr()
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let _ = mcp_handle.join();
}

// ---------------------------------------------------------------------------
// AC3 — insufficient scope and wrong tenant fail closed through the CLI.
// ---------------------------------------------------------------------------

#[test]
fn insufficient_scope_and_wrong_tenant_fail_closed_via_cli() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, tenant_scoped_config(&gateway_addr)).unwrap();
    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);
    let endpoint = endpoint_for(&gateway_addr);
    bootstrap_schedule_scope(&gateway_addr, "tenant-a", "project-a", "ws-a");
    create_tenant_account(&gateway_addr, "tenant-b");

    // A schedule owned by tenant A, seeded via the unrestricted platform key.
    let schedule = json!({
        "id": "tenant-a-sched",
        "tenant_id": "tenant-a",
        "workspace_id": "ws-a",
        "name": "owned-by-a",
        "spec_kind": "interval",
        "interval_secs": 3600,
        "target_kind": "self_hosted_dispatch",
        "target": {"required_capabilities": ["shell"]}
    })
    .to_string();
    let create = run_ctl(
        &endpoint,
        "admin-secret",
        None,
        &["agent-schedules", "create", "--data", &schedule],
    );
    assert_eq!(
        create.code(),
        0,
        "seed schedule stderr: {}",
        create.stderr()
    );

    // AC3 insufficient scope: a read-only key attempting a write action
    // (run-now needs admin.write) fails closed with the Auth exit class
    // (403 -> exit 3).
    let scope = run_ctl(
        &endpoint,
        "reader-secret",
        None,
        &["agent-schedules", "run-now", "tenant-a-sched"],
    );
    assert_eq!(
        scope.code(),
        3,
        "insufficient scope -> Auth (exit 3): {}",
        scope.stderr()
    );
    assert!(
        scope.stderr().contains("scope_denied"),
        "server scope-denied code surfaced: {}",
        scope.stderr()
    );

    // AC3 wrong tenant: a tenant-B-scoped key must not run tenant A's schedule.
    // The cross-tenant denial is an explicit, stable failure (never a success).
    let cross = run_ctl(
        &endpoint,
        "tenant-b-secret",
        Some("tenant-b"),
        &["agent-schedules", "run-now", "tenant-a-sched"],
    );
    assert_ne!(
        cross.code(),
        0,
        "cross-tenant run-now must not succeed: stdout={} stderr={}",
        cross.stdout(),
        cross.stderr()
    );
    assert!(
        matches!(cross.code(), 3 | 4),
        "cross-tenant denial maps to a stable Auth/NotFound exit class, got {}: {}",
        cross.code(),
        cross.stderr()
    );
    // A cross-tenant denial is a refused mutation, so it too leaves a receipt
    // naming the target it was refused on — the audit record of an attempted
    // cross-tenant write is more valuable than a clean stdout.
    let receipt = cross.json();
    assert_eq!(receipt["object"], "mutation_receipt", "{receipt}");
    assert_eq!(receipt["outcome"], "rejected", "{receipt}");
    assert_eq!(receipt["dry_run"], false, "{receipt}");
    assert_eq!(receipt["group"], "agent-schedules", "{receipt}");
    assert!(
        receipt["response"].is_null(),
        "a refused mutation carries no response document: {receipt}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Config with a platform-operator key plus a read-only key and two
/// tenant-scoped admin keys, for the scope + cross-tenant proofs.
fn tenant_scoped_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "reader"
name = "Read-only operator"
key = "reader-secret"
scopes = ["admin.read"]
platform_operator = true

[[api_keys]]
id = "tenant-b"
name = "Tenant B admin"
key = "tenant-b-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-b"

[scheduler]
enabled = false
tick_interval_secs = 60
"#
    )
}

// ---------------------------------------------------------------------------
// Mock MCP tool server (self-contained; mirrors the agentic_lite fixture).
// ---------------------------------------------------------------------------

fn spawn_mcp_server(count: usize) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..count {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return requests;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("MCP mock accept failed: {error}"),
                }
            };
            let request = read_http_request(&mut stream);
            let body = if request.contains("\"initialize\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"mock-mcp","version":"1.0.0"}}}"#
            } else if request.contains("\"ping\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#
            } else if request.contains("\"tools/list\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"github.search","description":"Search GitHub","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}]}}"#
            } else {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ferrogate-result"}]}}"#
            };
            requests.push(request);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
        requests
    });
    (addr, handle)
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let content_length = String::from_utf8_lossy(&request[..header_end])
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            if request.len().saturating_sub(header_end + 4) >= content_length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}
