// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Token4AI Cloud, FerroGate AI Gateway — gated real Claude Code
// harness E2E through the governed agent-worker execution path (#308).
//
//! #308 acceptance harness: run the ACTUAL `claude` binary through the
//! agent-worker framework-adapter execution path, gated honestly (explicit env
//! opt-in + prerequisite probe + clean skip message — never a fake pass),
//! following the KVM-gated pattern in `firecracker_agent_execution.rs`.
//!
//! Three layers:
//!
//! 1. **Ungated adapter plumbing** (`probe_handlers_reports_claude_code_readiness_ungated`):
//!    `agent-worker probe-handlers` resolves `AGENT_WORKER_CLAUDE_CODE_BIN`
//!    (fake script here — no tokens) and reports the claude-code handler
//!    ready/unready with accurate reasons. Complements the in-crate unit
//!    coverage in `src/handlers.rs`; always runs.
//!
//! 2. **Gated real-binary handler smokes** (`real_claude_*_gated`): with
//!    `FERROGATE_TEST_CLAUDE_CODE_E2E=1` AND a resolvable real claude binary
//!    (`AGENT_WORKER_CLAUDE_CODE_BIN`, else `claude` on PATH), the worker-owned
//!    `smoke-handler-binary` (--version probe) and `smoke-handler-task`
//!    (validated non-interactive template `--bare --print --permission-mode
//!    dontAsk --tools "" --no-session-persistence <prompt>`, template checked
//!    flag-by-flag against claude 2.1.215) run the REAL harness. The task
//!    smoke asserts real zero-exit plus the expected deterministic output via
//!    `smoke_handler_task`'s `Return exactly:` validation. TOKEN COST: the
//!    task smoke performs one real model call; prompts stay trivial.
//!
//! 3. **Gated governed execution path**: the in-crate seam
//!    (`exec_or_attach_framework_handler_with_authorizer`) is the established
//!    harness pattern for the governed run timeline without a live gateway, so
//!    Layer 3 lives as the gated unit test
//!    `claude_code_governed_execution_streams_real_harness_output_when_gated`
//!    in `src/handler_runtime.rs` (same gate env): capability.allowed lands on
//!    the run timeline BEFORE the real harness spawns, and the harness's
//!    actual output flows back through the normalized framework-event path.
//!    Run it with the same gate via
//!    `cargo test -p agent-worker --bin agent-worker claude_code_governed`.

use std::{env, fs, os::unix::fs::PermissionsExt, process::Command};

use serde_json::Value;

const AGENT_WORKER_BIN: &str = env!("CARGO_BIN_EXE_agent-worker");
/// Explicit opt-in for the real-harness layers: the task smoke consumes model
/// tokens and requires an authenticated claude CLI.
const GATE_ENV: &str = "FERROGATE_TEST_CLAUDE_CODE_E2E";
const CLAUDE_BIN_ENV: &str = "AGENT_WORKER_CLAUDE_CODE_BIN";

fn skip(test: &str, reason: &str) {
    println!("SKIP {test}: {reason}");
    eprintln!("SKIP {test}: {reason}");
}

/// Resolve the REAL claude binary: `AGENT_WORKER_CLAUDE_CODE_BIN` first, then
/// `claude` on PATH — mirroring how the firecracker E2E resolves its
/// prerequisites through explicit configuration before probing the host.
fn resolve_real_claude_binary() -> Option<String> {
    if let Ok(configured) = env::var(CLAUDE_BIN_ENV) {
        let trimmed = configured.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let output = Command::new("which").arg("claude").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!path.is_empty()).then_some(path)
}

/// Gate check shared by the real-binary layers: explicit env opt-in AND a
/// resolvable real binary. Returns the binary path when the test must run.
fn gated_real_claude_binary(test: &str) -> Option<String> {
    if env::var(GATE_ENV).ok().as_deref() != Some("1") {
        skip(
            test,
            &format!(
                "real Claude Code harness E2E not requested (export {GATE_ENV}=1 with an \
                 authenticated claude CLI; the task smoke consumes tokens)"
            ),
        );
        return None;
    }
    let Some(binary) = resolve_real_claude_binary() else {
        skip(
            test,
            &format!(
                "no real claude binary resolvable (set {CLAUDE_BIN_ENV} or put `claude` on PATH)"
            ),
        );
        return None;
    };
    Some(binary)
}

fn run_agent_worker_json(args: &[&str], envs: &[(&str, &str)]) -> Result<Value, String> {
    let mut command = Command::new(AGENT_WORKER_BIN);
    command.args(args);
    // The claude-code handler readiness must be decided by the env we pass
    // explicitly, not whatever the invoking shell exported.
    command.env_remove(CLAUDE_BIN_ENV);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to spawn {AGENT_WORKER_BIN} {args:?}: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str::<Value>(stdout.trim()).map_err(|error| {
        format!(
            "could not parse JSON from `agent-worker {args:?}` (status {:?}): {error}\nstdout: {stdout}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn claude_code_handler(probe: &Value) -> Value {
    probe["handlers"]
        .as_array()
        .and_then(|handlers| {
            handlers
                .iter()
                .find(|handler| handler["adapter_name"] == "claude-code")
        })
        .cloned()
        .unwrap_or_else(|| panic!("probe-handlers output missing claude-code handler: {probe}"))
}

/// Layer 1 (always runs, no tokens): the claude-code adapter plumbing through
/// the real `probe-handlers` surface — env var resolution, executable checks,
/// and accurate readiness reasons — using a fake script binary.
#[test]
fn probe_handlers_reports_claude_code_readiness_ungated() {
    // Unconfigured: fail-closed unready with the accurate reason.
    let probe = run_agent_worker_json(&["probe-handlers"], &[])
        .expect("probe-handlers must emit JSON without any configured binaries");
    let handler = claude_code_handler(&probe);
    assert_eq!(handler["ready"], false, "{probe}");
    assert_eq!(handler["framework"], "claude_code", "{probe}");
    assert!(
        handler["readiness_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("was not configured")),
        "{probe}"
    );

    // Configured with an executable file: ready, external version, code
    // process-shim capabilities.
    let temp = tempfile::tempdir().unwrap();
    let fake = temp.path().join("claude-fake");
    fs::write(&fake, "#!/bin/sh\nprintf 'claude fake %s\\n' \"$1\"\n").unwrap();
    let mut permissions = fs::metadata(&fake).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&fake, permissions).unwrap();
    let probe = run_agent_worker_json(
        &["probe-handlers"],
        &[(CLAUDE_BIN_ENV, fake.to_str().unwrap())],
    )
    .expect("probe-handlers must emit JSON with a configured fake binary");
    let handler = claude_code_handler(&probe);
    assert_eq!(handler["ready"], true, "{probe}");
    assert_eq!(handler["version"], "external", "{probe}");
    assert!(
        handler["capabilities"]
            .as_array()
            .is_some_and(|capabilities| capabilities.iter().any(|c| c == "shell")
                && capabilities.iter().any(|c| c == "filesystem")),
        "{probe}"
    );
}

/// Layer 2a (gated): the worker-owned binary smoke runs the REAL claude
/// `--version` probe and reports ready. No tokens consumed.
#[test]
fn real_claude_binary_smoke_reports_ready_gated() {
    const TEST: &str = "claude_code_harness_e2e_binary_smoke";
    let Some(binary) = gated_real_claude_binary(TEST) else {
        return;
    };

    let probe = run_agent_worker_json(&["probe-handlers"], &[(CLAUDE_BIN_ENV, &binary)])
        .expect("probe-handlers must emit JSON with the real claude binary configured");
    let handler = claude_code_handler(&probe);
    assert_eq!(handler["ready"], true, "{probe}");

    let smoke = run_agent_worker_json(
        &[
            "smoke-handler-binary",
            "--adapter",
            "claude-code",
            "--timeout-millis",
            "30000",
        ],
        &[(CLAUDE_BIN_ENV, &binary)],
    )
    .expect("smoke-handler-binary must emit JSON against the real claude binary");
    println!("real claude binary smoke evidence: {smoke}");
    assert_eq!(smoke["adapter_name"], "claude-code", "{smoke}");
    assert_eq!(smoke["env_var"], CLAUDE_BIN_ENV, "{smoke}");
    assert_eq!(
        smoke["probe_args"],
        serde_json::json!(["--version"]),
        "{smoke}"
    );
    assert_eq!(smoke["status_code"], 0, "{smoke}");
    // The real binary identifies itself, e.g. "2.1.215 (Claude Code)".
    assert!(
        smoke["stdout_excerpt"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("Claude Code")),
        "{smoke}"
    );
}

/// Layer 2b (gated, consumes tokens): the worker-owned task smoke executes the
/// REAL harness through the validated non-interactive template and the
/// expected deterministic output arrives through `smoke_handler_task`'s
/// validation (real zero-exit + expected-output check — the command exits
/// non-zero without JSON when either fails).
#[test]
fn real_claude_task_smoke_executes_template_and_returns_expected_output_gated() {
    const TEST: &str = "claude_code_harness_e2e_task_smoke";
    const PROMPT: &str = "Return exactly: ferrogate-claude-code-harness-e2e-ok";
    const MARKER: &str = "ferrogate-claude-code-harness-e2e-ok";
    let Some(binary) = gated_real_claude_binary(TEST) else {
        return;
    };

    let smoke = run_agent_worker_json(
        &[
            "smoke-handler-task",
            "--adapter",
            "claude-code",
            "--timeout-millis",
            "180000",
            "--prompt",
            PROMPT,
        ],
        &[(CLAUDE_BIN_ENV, &binary)],
    )
    .expect("smoke-handler-task must emit JSON when the real harness returns the expected output");
    println!("real claude task smoke evidence: {smoke}");
    assert_eq!(smoke["adapter_name"], "claude-code", "{smoke}");
    assert_eq!(smoke["status_code"], 0, "{smoke}");
    // The real harness's actual output line.
    assert!(
        smoke["stdout_excerpt"]
            .as_str()
            .is_some_and(|stdout| stdout.contains(MARKER)),
        "{smoke}"
    );
    // The exact validated template, prompt redacted from recorded argv.
    assert_eq!(
        smoke["task_args"],
        serde_json::json!([
            "--bare",
            "--print",
            "--permission-mode",
            "dontAsk",
            "--tools",
            "",
            "--no-session-persistence",
            "<prompt>",
        ]),
        "{smoke}"
    );
    assert_eq!(
        smoke["prompt_chars"].as_u64(),
        Some(PROMPT.chars().count() as u64),
        "{smoke}"
    );
}
