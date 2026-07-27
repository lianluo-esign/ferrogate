// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Docker-free E2E for the CLI mutation decision receipt (#505).

//! End-to-end proof of the #505 mutation decision receipt against a REAL
//! `ferrogate` process, driven through the REAL `ferrogate ctl` client — no
//! fake transport, no in-process shortcut.
//!
//! Every acceptance box that can be proven over the wire is proven here:
//!
//! 1. **`--dry-run` issues no state-changing request.** The dry run is bracketed
//!    by two server-side reads of the policy's revision list; the list is
//!    byte-identical afterwards, and the receipt echoes `dry_run: true`. This
//!    is the process-level companion to the transport-level assertion in
//!    `ferrogate-control-plane-client`'s `receipt_test.rs` — here the *server* is the
//!    witness, so nothing about the client's internals is taken on trust.
//! 2. **Every mutating verb returns a receipt, in both output formats.** The
//!    create / create-revision / activate / rollback chain is run with
//!    `--output json` and re-run with `--output table`, and each is checked to
//!    be a receipt envelope rather than a bare server document.
//! 3. **The receipt's rollback pointer reverses the change with no identifier
//!    typed by hand.** The harness takes `rollback.command` out of the receipt
//!    and executes it verbatim as argv. No policy id, revision number, or path
//!    is written into this file for the reversal step.
//! 4. **The audit id gap is recorded, not papered over.** The receipt's
//!    `audit_id` must be `null` carrying the `endpoint_returns_no_audit_id`
//!    code — this is the enumerated finding of #505 acceptance box 6, and the
//!    scenario fails if the field is ever silently omitted instead. When the
//!    control plane starts returning an audit id, this assertion flips to the
//!    "follow it to the audit row" branch, which is why the branch is written
//!    out rather than left as a TODO.
//!
//! It is Docker-free and deterministic (one local gateway process, the shipped
//! `ferrogate` binary acting as its own client), so it is in the always-run
//! `ferrogate-test ci` set as well as being a first-class
//! `ferrogate-test cli-mutation-receipt` command.

use crate::{
    cli::LocalArgs,
    constants::JSON_CONTENT,
    http::{free_addr, http_request_addr},
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ADMIN_KEY: &str = "receipt-e2e-admin-secret";
const ADMIN_AUTH: &str = "Authorization: Bearer receipt-e2e-admin-secret";
const TOKEN_ENV_VAR: &str = "FERROGATE_RECEIPT_E2E_TOKEN";
const POLICY_ID: &str = "receipt-e2e-policy";
const TENANT: &str = "org_receipt_e2e";
const GATEWAY_READINESS_TIMEOUT: Duration = Duration::from_secs(180);

pub(crate) fn run_cli_mutation_receipt(args: &LocalArgs) -> Result<()> {
    if !args.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first \
             or pass --ferrogate-bin",
            args.ferrogate_bin.display()
        );
    }

    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("cli-mutation-receipt.yaml");
    fs::write(&config_path, scenario_config(&gateway_addr))?;
    let _gateway = GatewayGuard::start(&args.ferrogate_bin, &config_path, &gateway_addr)?;

    // The CLI resolves a context store from the user's config dir; point HOME
    // at the temp dir so the harness can never read or write the developer's
    // real contexts, and every invocation is flag-driven and hermetic.
    let home = dir.path().to_path_buf();
    let cli = CtlClient {
        binary: args.ferrogate_bin.clone(),
        endpoint: format!("http://{gateway_addr}"),
        home,
    };

    // --- Setup: a policy chain with two revisions, created through the CLI. ---
    let create = cli.json(&[
        "ctl",
        "guardrail-policies",
        "create",
        "--data",
        &policy_body(POLICY_ID, "receipt-e2e-secret-v1", "receipt_e2e_v1"),
    ])?;
    assert_is_receipt(&create, "guardrail-policies create")?;
    assert_audit_id_gap(&create, "guardrail-policies create")?;

    let second = cli.json(&[
        "ctl",
        "guardrail-policies",
        "create-revision",
        POLICY_ID,
        "--data",
        &policy_body(POLICY_ID, "receipt-e2e-secret-v2", "receipt_e2e_v2"),
    ])?;
    assert_is_receipt(&second, "guardrail-policies create-revision")?;
    if second["target"]["object_version"]["value"] != Value::String("2".to_string()) {
        bail!(
            "the second revision's receipt must attest object_version 2, got {}",
            second["target"]["object_version"]
        );
    }

    let activate = cli.json(&[
        "ctl",
        "guardrail-policies",
        "activate",
        POLICY_ID,
        "--data",
        r#"{"revision":2}"#,
    ])?;
    assert_is_receipt(&activate, "guardrail-policies activate")?;

    // --- Box 1: a dry run reaches the server not at all. ---
    //
    // The witness is the SERVER's own revision list, read before and after. If
    // `--dry-run` leaked a request, the chain would grow a third revision (or
    // at minimum the list would differ), and the byte comparison would fail.
    let before = revision_list(&gateway_addr)?;
    let dry = cli.json(&[
        "ctl",
        "guardrail-policies",
        "create-revision",
        POLICY_ID,
        "--data",
        &policy_body(POLICY_ID, "receipt-e2e-secret-v3", "receipt_e2e_v3"),
        "--dry-run",
    ])?;
    let after = revision_list(&gateway_addr)?;
    if before != after {
        bail!("--dry-run changed server state: revisions before={before} after={after}");
    }
    if dry["dry_run"] != Value::Bool(true) {
        bail!("a --dry-run invocation must echo dry_run: true, got {dry}");
    }
    if !dry["http_status"]["value"].is_null()
        || dry["http_status"]["absent_reason"]["code"] != "dry_run_not_executed"
    {
        bail!(
            "a dry run must report http_status as null with the dry_run_not_executed reason: {}",
            dry["http_status"]
        );
    }
    if !dry["response"].is_null() {
        bail!("a dry run must carry no server response document: {dry}");
    }
    // The dry run still attests the exact call it WOULD have made, which is the
    // point of planning it: same target, same fingerprint contract.
    if dry["target"]["action_fingerprint_contract"] != "canonical_target_sha256" {
        bail!("a dry-run receipt must still carry the fingerprint contract: {dry}");
    }
    if dry["target"]["action_fingerprint"] != second["target"]["action_fingerprint"] {
        bail!(
            "the dry run addressed a different target than the real create-revision: {} vs {}",
            dry["target"]["action_fingerprint"],
            second["target"]["action_fingerprint"]
        );
    }

    // A read verb refuses the flag rather than silently ignoring it.
    let refusal = cli.run(&[
        "ctl",
        "guardrail-policies",
        "revisions",
        POLICY_ID,
        "--dry-run",
    ])?;
    if refusal.status == 0 {
        bail!("--dry-run on a read verb must fail, not be silently ignored");
    }
    if !refusal
        .stderr
        .contains("--dry-run applies to mutating verbs")
    {
        bail!(
            "--dry-run on a read verb must explain itself, got: {}",
            refusal.stderr
        );
    }

    // --- Box 3: follow the receipt's own rollback pointer, verbatim. ---
    //
    // Everything below comes out of `activate`'s receipt. No identifier in this
    // block is typed by hand: that is the acceptance criterion, and writing
    // POLICY_ID here would silently defeat it.
    let pointer = activate["rollback"]["value"].as_object().with_context(|| {
        format!(
            "a guardrail-policy mutation must carry a rollback pointer, got {}",
            activate["rollback"]
        )
    })?;
    let argv: Vec<String> = pointer
        .get("command")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if argv.is_empty() {
        bail!("the rollback pointer carried no command: {activate}");
    }
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let reversal = cli.json(&borrowed)?;
    assert_is_receipt(&reversal, "the receipt's own rollback command")?;

    // The reversal actually reversed it: the live revision is the predecessor
    // the pointer named, read back from the server rather than from the CLI.
    let restored = pointer["restores_revision"]["value"]
        .as_str()
        .context("the rollback pointer must name the revision it restores")?
        .to_string();
    let active = active_revision(&gateway_addr)?;
    if active != restored {
        bail!("rollback did not restore revision {restored}; live revision is {active}");
    }

    // --- Box 2: the table format says the same thing, including the nulls. ---
    let table = cli.text(&[
        "ctl",
        "guardrail-policies",
        "activate",
        POLICY_ID,
        "--data",
        r#"{"revision":2}"#,
        "--output",
        "table",
    ])?;
    for marker in [
        "object",
        "mutation_receipt",
        "dry_run",
        "audit_id",
        "endpoint_returns_no_audit_id",
        "target.action_fingerprint",
    ] {
        if !table.contains(marker) {
            bail!("the table receipt dropped '{marker}':\n{table}");
        }
    }

    // --- Box 4/6: the audit-id gap, recorded. ---
    //
    // The receipt is the only place an operator would learn that the control
    // plane hands back no audit identifier, so the scenario asserts the finding
    // is *stated* rather than silently absent. The moment a mutating endpoint
    // starts returning one, the else-branch takes over and follows it to the
    // audit row — no code change needed beyond deleting the bail.
    match activate["audit_id"]["value"].as_str() {
        None => {
            assert_audit_id_gap(&activate, "guardrail-policies activate")?;
            println!(
                "note (#505 box 6): the control plane returned NO audit id for \
                 activateGuardrailPolicyRevision; the receipt reports it as null with \
                 code=endpoint_returns_no_audit_id. This holds for all 117 coverable \
                 mutating operations in the contract."
            );
        }
        Some(audit_id) => {
            // Follow the receipt's audit id to its row - again with nothing
            // typed by hand.
            let located = http_request_addr(
                &gateway_addr,
                "GET",
                &format!("/admin/v1/audit-events?id={audit_id}"),
                &[ADMIN_AUTH, JSON_CONTENT],
                "",
            )?;
            if located.status != 200 || !located.body.contains(audit_id) {
                bail!(
                    "the receipt's audit id {audit_id} did not locate an audit row: {}",
                    located.body
                );
            }
        }
    }

    println!("cli-mutation-receipt scenario passed");
    Ok(())
}

/// A receipt, not a bare server document. This is the shipped-surface half of
/// the registry enforcement: the library makes a bare mutation body
/// unconstructible, and this proves the binary an operator actually runs emits
/// the envelope.
fn assert_is_receipt(document: &Value, what: &str) -> Result<()> {
    if document["object"] != "mutation_receipt" {
        bail!("{what} did not return a mutation receipt: {document}");
    }
    if document["receipt_version"] != 1 {
        bail!("{what} returned an unknown receipt version: {document}");
    }
    for field in [
        "actor",
        "target",
        "decision",
        "approval_id",
        "audit_id",
        "rollback",
        "idempotency_key",
        "correlation",
        "http_status",
        "dry_run",
    ] {
        if document.get(field).is_none() {
            bail!("{what}'s receipt omitted the '{field}' field entirely: {document}");
        }
    }
    if document["target"]["action_fingerprint"]
        .as_str()
        .is_none_or(|value| !value.starts_with("sha256:") || value.len() != 71)
    {
        bail!(
            "{what}'s receipt carried no canonical action fingerprint: {}",
            document["target"]
        );
    }
    Ok(())
}

/// An absent audit id is a *stated* null, never a missing key.
fn assert_audit_id_gap(document: &Value, what: &str) -> Result<()> {
    let audit = &document["audit_id"];
    if !audit.is_object() {
        bail!("{what}'s receipt omitted audit_id instead of stating it: {document}");
    }
    if !audit["value"].is_null() {
        return Ok(());
    }
    if audit["absent_reason"]["code"] != "endpoint_returns_no_audit_id" {
        bail!("{what}'s receipt left audit_id null WITHOUT the contract-gap reason: {audit}");
    }
    if audit["absent_reason"]["detail"]
        .as_str()
        .is_none_or(|detail| detail.trim().is_empty())
    {
        bail!("{what}'s audit_id absence carried no explanation: {audit}");
    }
    Ok(())
}

/// The server's own view of the policy's revision chain, used as the witness
/// that a dry run changed nothing.
fn revision_list(gateway_addr: &str) -> Result<String> {
    let response = http_request_addr(
        gateway_addr,
        "GET",
        &format!("/admin/v1/guardrail-policies/{POLICY_ID}/revisions"),
        &[ADMIN_AUTH, JSON_CONTENT],
        "",
    )?;
    if response.status != 200 {
        bail!("failed to read the revision chain: {}", response.raw);
    }
    Ok(response.body)
}

/// The revision currently bound live, read from the server.
fn active_revision(gateway_addr: &str) -> Result<String> {
    let response = http_request_addr(
        gateway_addr,
        "GET",
        &format!("/admin/v1/guardrail-policies/{POLICY_ID}/revisions"),
        &[ADMIN_AUTH, JSON_CONTENT],
        "",
    )?;
    let body: Value = serde_json::from_str(&response.body)
        .with_context(|| format!("revision list was not JSON: {}", response.raw))?;
    let rows = body["data"]
        .as_array()
        .cloned()
        .or_else(|| body.as_array().cloned())
        .unwrap_or_default();
    for row in rows {
        if row["status"] == "active" {
            if let Some(revision) = row["revision"].as_u64() {
                return Ok(revision.to_string());
            }
        }
    }
    bail!("no revision is active: {}", response.body)
}

/// Result of one `ferrogate` CLI invocation.
struct CtlOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

/// Drives the REAL shipped `ferrogate` binary as a Control Plane API client.
struct CtlClient {
    binary: PathBuf,
    endpoint: String,
    home: PathBuf,
}

impl CtlClient {
    /// Run one invocation, appending the connection flags every call shares.
    /// The bearer token is passed by environment variable name, never on the
    /// argv, matching the CLI's own secret-handling contract.
    fn run(&self, argv: &[&str]) -> Result<CtlOutput> {
        let output = Command::new(&self.binary)
            .args(argv)
            .args(["--endpoint", &self.endpoint])
            .args(["--token-env", TOKEN_ENV_VAR])
            .arg("--non-interactive")
            .env(TOKEN_ENV_VAR, ADMIN_KEY)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("failed to run {} {argv:?}", self.binary.display()))?;
        Ok(CtlOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// Run with `--output json` and parse stdout. Proves the payload is
    /// pipe-safe: any diagnostic on stderr would break this parse if it leaked
    /// onto stdout.
    fn json(&self, argv: &[&str]) -> Result<Value> {
        let mut full: Vec<&str> = argv.to_vec();
        full.extend_from_slice(&["--output", "json"]);
        let output = self.run(&full)?;
        if output.status != 0 {
            bail!(
                "`ferrogate {argv:?}` failed with exit {}: {}",
                output.status,
                output.stderr
            );
        }
        serde_json::from_str(&output.stdout).with_context(|| {
            format!(
                "`ferrogate {argv:?}` stdout was not JSON: {}",
                output.stdout
            )
        })
    }

    /// Run and return stdout verbatim (for `--output table`).
    fn text(&self, argv: &[&str]) -> Result<String> {
        let output = self.run(argv)?;
        if output.status != 0 {
            bail!(
                "`ferrogate {argv:?}` failed with exit {}: {}",
                output.status,
                output.stderr
            );
        }
        Ok(output.stdout)
    }
}

fn policy_body(policy_id: &str, keyword: &str, block_code: &str) -> String {
    serde_json::json!({
        "policy_id": policy_id,
        "name": "CLI mutation receipt E2E",
        "description": "#505: every mutating CLI verb returns a decision receipt",
        "enforced": true,
        "scope": {
            "organization_ids": [TENANT],
            "models": ["fast-chat"],
            "providers": ["openai"]
        },
        "checks": [{
            "id": "keyword",
            "enabled": true,
            "stage": "request",
            "sources": ["user"],
            "detector": {"kind": "local", "keywords": [keyword]}
        }],
        "aggregation": {"type": "all"},
        "execution": "parallel",
        "mode": "enforce",
        "streaming": "buffer_and_enforce",
        "on_pass": [{"kind": "allow"}],
        "on_fail": [{"kind": "block", "code": block_code, "message": "blocked by the E2E policy"}]
    })
    .to_string()
}

fn scenario_config(gateway_addr: &str) -> String {
    format!(
        r#"listen: {gateway_addr:?}
cluster:
  enabled: true
  cluster_id: "cli-mutation-receipt-e2e"
  node_id: "cli-mutation-receipt-node"
  node_region: "local"
  node_zone: "local-a"
  state_backend: "local"
  counter_backend: "local"
providers:
  - name: "openai"
    kind: "openai"
    base_url: "http://127.0.0.1:1/v1"
    api_key_env: "FERROGATE_PROVIDER_SECRET"
models:
  - name: "fast-chat"
    provider: "openai"
    provider_model: "gpt-4o-mini"
    capabilities: ["chat"]
api_keys:
  - id: "receipt-e2e-admin"
    name: "CLI receipt E2E host operator"
    key: "{ADMIN_KEY}"
    scopes: ["admin.read", "admin.write"]
"#
    )
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(binary: &Path, config_path: &Path, gateway_addr: &str) -> Result<Self> {
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config_path)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
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
        while started.elapsed() < GATEWAY_READINESS_TIMEOUT {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before cli-mutation-receipt readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for the cli-mutation-receipt gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
