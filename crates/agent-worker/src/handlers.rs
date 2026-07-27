// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    env,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use ferrogate_runtime::{AgentWorkerFrameworkHandler, FrameworkAdapterCapabilities};
use serde_json::json;

pub(crate) fn probe_handlers_command() -> Result<()> {
    let handlers = framework_handlers();
    println!("{}", handlers_json(&handlers));
    Ok(())
}

pub(crate) fn smoke_handler_binary_command(adapter_name: &str, timeout_millis: u64) -> Result<()> {
    let result = smoke_handler_binary(adapter_name, timeout_millis)?;
    println!(
        "{}",
        json!({
            "process": "agent-worker",
            "handler_owner": "agent-worker",
            "gateway_handler_probe": false,
            "adapter_name": result.adapter_name,
            "env_var": result.env_var,
            "binary_path": result.binary_path.display().to_string(),
            "probe_args": result.probe_args,
            "status_code": result.status_code,
            "stdout_excerpt": result.stdout_excerpt,
            "stderr_excerpt": result.stderr_excerpt,
        })
    );
    Ok(())
}

pub(crate) fn smoke_handler_task_command(
    adapter_name: &str,
    timeout_millis: u64,
    prompt: &str,
) -> Result<()> {
    let result = smoke_handler_task(adapter_name, timeout_millis, prompt)?;
    println!(
        "{}",
        json!({
            "process": "agent-worker",
            "handler_owner": "agent-worker",
            "gateway_handler_probe": false,
            "adapter_name": result.adapter_name,
            "env_var": result.env_var,
            "binary_path": result.binary_path.display().to_string(),
            "task_args": redacted_args(&result.task_args, result.prompt_arg_index),
            "prompt_chars": result.prompt_chars,
            "status_code": result.status_code,
            "stdout_excerpt": result.stdout_excerpt,
            "stderr_excerpt": result.stderr_excerpt,
        })
    );
    Ok(())
}

pub(crate) fn framework_handlers() -> Vec<AgentWorkerFrameworkHandler> {
    vec![
        AgentWorkerFrameworkHandler {
            adapter_name: "native-harness".to_string(),
            framework: "native_harness".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: capability_names(FrameworkAdapterCapabilities::native_harness()),
            ready: true,
            readiness_reason: Some(
                "native harness is built into the agent-worker process".to_string(),
            ),
        },
        probed_binary_handler(
            "codex",
            "codex",
            "AGENT_WORKER_CODEX_BIN",
            "Codex CLI binary path was not configured",
        ),
        probed_binary_handler(
            "claude-code",
            "claude_code",
            "AGENT_WORKER_CLAUDE_CODE_BIN",
            "Claude Code binary path was not configured",
        ),
        probed_binary_handler(
            "hermes",
            "hermes",
            "AGENT_WORKER_HERMES_BIN",
            "Hermes binary path was not configured",
        ),
    ]
}

fn probed_binary_handler(
    adapter_name: &str,
    framework: &str,
    env_var: &str,
    missing_message: &str,
) -> AgentWorkerFrameworkHandler {
    let capabilities = capabilities_for_adapter(adapter_name);
    match configured_binary_error(env_var) {
        None => AgentWorkerFrameworkHandler {
            adapter_name: adapter_name.to_string(),
            framework: framework.to_string(),
            version: "external".to_string(),
            capabilities,
            ready: true,
            readiness_reason: Some(format!("{env_var} points to an executable file")),
        },
        Some(reason) if reason == format!("{env_var} was not configured") => {
            AgentWorkerFrameworkHandler {
                adapter_name: adapter_name.to_string(),
                framework: framework.to_string(),
                version: "unknown".to_string(),
                capabilities,
                ready: false,
                readiness_reason: Some(missing_message.to_string()),
            }
        }
        Some(reason) => AgentWorkerFrameworkHandler {
            adapter_name: adapter_name.to_string(),
            framework: framework.to_string(),
            version: "unknown".to_string(),
            capabilities,
            ready: false,
            readiness_reason: Some(reason),
        },
    }
}

fn capabilities_for_adapter(adapter_name: &str) -> Vec<String> {
    match adapter_name {
        "codex" | "claude-code" | "claude_code" => {
            capability_names(FrameworkAdapterCapabilities::code_process_shim())
        }
        "hermes" => capability_names(FrameworkAdapterCapabilities::hermes_process_shim()),
        _ => capability_names(FrameworkAdapterCapabilities::native_harness()),
    }
}

fn capability_names(capabilities: FrameworkAdapterCapabilities) -> Vec<String> {
    capabilities
        .capability_names()
        .into_iter()
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandlerBinarySmokeResult {
    pub(crate) adapter_name: &'static str,
    pub(crate) env_var: &'static str,
    pub(crate) binary_path: PathBuf,
    pub(crate) probe_args: Vec<&'static str>,
    pub(crate) status_code: Option<i32>,
    pub(crate) stdout_excerpt: String,
    pub(crate) stderr_excerpt: String,
}

pub(crate) fn smoke_handler_binary(
    adapter_name: &str,
    timeout_millis: u64,
) -> Result<HandlerBinarySmokeResult> {
    let target = handler_binary_smoke_target(adapter_name)?;
    let binary_path = configured_binary_path(target.env_var)?;
    let output = run_configured_handler_binary(
        target.adapter_name,
        &binary_path,
        &target
            .probe_args
            .iter()
            .map(|arg| arg.to_string())
            .collect::<Vec<_>>(),
        timeout_millis,
    )?;

    Ok(HandlerBinarySmokeResult {
        adapter_name: target.adapter_name,
        env_var: target.env_var,
        binary_path,
        probe_args: target.probe_args.to_vec(),
        status_code: output.status.code(),
        stdout_excerpt: output_excerpt(&output.stdout),
        stderr_excerpt: output_excerpt(&output.stderr),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandlerTaskSmokeResult {
    pub(crate) adapter_name: &'static str,
    pub(crate) env_var: &'static str,
    pub(crate) binary_path: PathBuf,
    pub(crate) task_args: Vec<String>,
    pub(crate) prompt_arg_index: usize,
    pub(crate) prompt_chars: usize,
    pub(crate) status_code: Option<i32>,
    pub(crate) stdout_excerpt: String,
    pub(crate) stderr_excerpt: String,
}

pub(crate) fn smoke_handler_task(
    adapter_name: &str,
    timeout_millis: u64,
    prompt: &str,
) -> Result<HandlerTaskSmokeResult> {
    let target = handler_binary_task_target(adapter_name, prompt)?;
    let binary_path = configured_binary_path(target.env_var)?;
    let output = run_configured_handler_binary(
        target.adapter_name,
        &binary_path,
        &target.task_args,
        timeout_millis,
    )?;
    if let Some(expected_output) = expected_exact_output(prompt) {
        let stdout_excerpt = output_excerpt(&output.stdout);
        if !stdout_excerpt.contains(&expected_output) {
            bail!(
                "agent-worker {} handler task smoke did not produce expected output {:?}; stdout_excerpt={:?}; stderr_excerpt={:?}",
                target.adapter_name,
                expected_output,
                stdout_excerpt,
                output_excerpt(&output.stderr)
            );
        }
    }

    Ok(HandlerTaskSmokeResult {
        adapter_name: target.adapter_name,
        env_var: target.env_var,
        binary_path,
        task_args: target.task_args,
        prompt_arg_index: target.prompt_arg_index,
        prompt_chars: prompt.chars().count(),
        status_code: output.status.code(),
        stdout_excerpt: output_excerpt(&output.stdout),
        stderr_excerpt: output_excerpt(&output.stderr),
    })
}

fn run_configured_handler_binary(
    adapter_name: &str,
    binary_path: &Path,
    args: &[String],
    timeout_millis: u64,
) -> Result<std::process::Output> {
    let mut child = Command::new(binary_path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "failed to start {} handler binary from {}",
                adapter_name,
                binary_path.display()
            )
        })?;
    let started_at = Instant::now();
    let timeout = Duration::from_millis(timeout_millis.max(1));
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "agent-worker {} handler binary command timed out after {}ms",
                adapter_name,
                timeout.as_millis()
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "agent-worker {} handler binary command exited with status {:?}",
            adapter_name,
            output.status.code()
        );
    }
    Ok(output)
}

#[derive(Debug, Clone, Copy)]
struct HandlerBinarySmokeTarget {
    adapter_name: &'static str,
    env_var: &'static str,
    probe_args: &'static [&'static str],
}

fn handler_binary_smoke_target(adapter_name: &str) -> Result<HandlerBinarySmokeTarget> {
    match adapter_name {
        "codex" => Ok(HandlerBinarySmokeTarget {
            adapter_name: "codex",
            env_var: "AGENT_WORKER_CODEX_BIN",
            probe_args: &["--version"],
        }),
        "claude-code" | "claude_code" => Ok(HandlerBinarySmokeTarget {
            adapter_name: "claude-code",
            env_var: "AGENT_WORKER_CLAUDE_CODE_BIN",
            probe_args: &["--version"],
        }),
        "hermes" => Ok(HandlerBinarySmokeTarget {
            adapter_name: "hermes",
            env_var: "AGENT_WORKER_HERMES_BIN",
            probe_args: &["--version"],
        }),
        "native-harness" | "native_harness" => bail!(
            "native-harness is built into agent-worker and has no external handler binary smoke"
        ),
        other => bail!("unsupported framework handler adapter for binary smoke: {other}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HandlerBinaryTaskTarget {
    adapter_name: &'static str,
    env_var: &'static str,
    task_args: Vec<String>,
    prompt_arg_index: usize,
}

fn handler_binary_task_target(adapter_name: &str, prompt: &str) -> Result<HandlerBinaryTaskTarget> {
    if prompt.trim().is_empty() {
        bail!("handler task smoke prompt must not be empty");
    }
    match adapter_name {
        "codex" => {
            let mut task_args = vec![
                "exec".to_string(),
                "--sandbox".to_string(),
                "read-only".to_string(),
                "--skip-git-repo-check".to_string(),
                "--ignore-rules".to_string(),
                "--ephemeral".to_string(),
            ];
            let prompt_arg_index = task_args.len();
            task_args.push(prompt.to_string());
            Ok(HandlerBinaryTaskTarget {
                adapter_name: "codex",
                env_var: "AGENT_WORKER_CODEX_BIN",
                task_args,
                prompt_arg_index,
            })
        }
        // Template validated against the real Claude Code CLI 2.1.215 (#308):
        // `--bare` (minimal mode; auth is strictly ANTHROPIC_API_KEY /
        // ANTHROPIC_AUTH_TOKEN / apiKeyHelper — OAuth and keychain are never
        // read), `--print` (non-interactive one-shot), `--permission-mode
        // dontAsk` (a documented choice), `--tools ""` (empty string disables
        // all built-in tools), and `--no-session-persistence` (documented,
        // requires `--print`). The gated
        // `tests/claude_code_harness_e2e.rs` re-proves this against the real
        // binary end to end.
        "claude-code" | "claude_code" => {
            let mut task_args = vec![
                "--bare".to_string(),
                "--print".to_string(),
                "--permission-mode".to_string(),
                "dontAsk".to_string(),
                "--tools".to_string(),
                String::new(),
                "--no-session-persistence".to_string(),
            ];
            let prompt_arg_index = task_args.len();
            task_args.push(prompt.to_string());
            Ok(HandlerBinaryTaskTarget {
                adapter_name: "claude-code",
                env_var: "AGENT_WORKER_CLAUDE_CODE_BIN",
                task_args,
                prompt_arg_index,
            })
        }
        "hermes" => {
            let mut task_args = vec!["--ignore-rules".to_string(), "-z".to_string()];
            let prompt_arg_index = task_args.len();
            task_args.push(prompt.to_string());
            Ok(HandlerBinaryTaskTarget {
                adapter_name: "hermes",
                env_var: "AGENT_WORKER_HERMES_BIN",
                task_args,
                prompt_arg_index,
            })
        }
        "native-harness" | "native_harness" => bail!(
            "native-harness is built into agent-worker and has no external handler task smoke"
        ),
        other => bail!("unsupported framework handler adapter for task smoke: {other}"),
    }
}

fn configured_binary_path(env_var: &str) -> Result<PathBuf> {
    if let Some(reason) = configured_binary_error(env_var) {
        bail!("{reason}");
    }
    let raw = env::var(env_var).map_err(|_| anyhow!("{env_var} was not configured"))?;
    Ok(PathBuf::from(raw.trim()))
}

fn configured_binary_error(env_var: &str) -> Option<String> {
    let raw = match env::var(env_var) {
        Ok(raw) => raw,
        Err(_) => return Some(format!("{env_var} was not configured")),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some(format!("{env_var} was not configured"));
    }
    let path = PathBuf::from(trimmed);
    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(_) => {
            return Some(format!(
                "{env_var} does not point to a file: {}",
                path.display()
            ));
        }
    };
    if !metadata.is_file() {
        return Some(format!(
            "{env_var} does not point to a file: {}",
            path.display()
        ));
    }
    if (metadata.permissions().mode() & 0o111) == 0 {
        return Some(format!("{env_var} is not executable: {}", path.display()));
    }
    None
}

pub(crate) fn redacted_args(args: &[String], prompt_arg_index: usize) -> Vec<String> {
    args.iter()
        .enumerate()
        .map(|(index, arg)| {
            if index == prompt_arg_index {
                "<prompt>".to_string()
            } else {
                arg.clone()
            }
        })
        .collect()
}

/// A handler binary's stdout/stderr, excerpted for the record.
///
/// This used to slice-and-lossy-decode the bytes itself, which is exactly the
/// raw-capture #526 swept out: a configured handler binary that prints an HTTP
/// exchange (a `curl -i`, a debug dump of its own upstream call) put every
/// credential header it saw into `stdout_excerpt` on a `cli.requested` event.
/// It now goes through the crate's one recorded-evidence chokepoint.
///
/// Worth naming because it is easy to assume otherwise: this result is NOT only
/// event metadata. `smoke_handler_binary_command` prints it straight to the
/// worker's stdout as JSON, where no metadata sweep runs — this call is the
/// only redaction on that path.
pub(crate) fn output_excerpt(output: &[u8]) -> String {
    const MAX_EXCERPT_BYTES: u64 = 512;
    crate::recorded_evidence::recorded_excerpt(
        crate::recorded_evidence::RecordedSurface::HandlerBinaryOutput,
        output,
        MAX_EXCERPT_BYTES,
    )
    .trim()
    .to_string()
}

fn expected_exact_output(prompt: &str) -> Option<String> {
    prompt
        .trim()
        .strip_prefix("Return exactly:")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn handlers_json(handlers: &[AgentWorkerFrameworkHandler]) -> String {
    let handlers = handlers
        .iter()
        .map(|handler| {
            json!({
                "adapter_name": handler.adapter_name,
                "framework": handler.framework,
                "version": handler.version,
                "capabilities": handler.capabilities,
                "ready": handler.ready,
                "readiness_reason": handler.readiness_reason,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "process": "agent-worker",
        "handler_owner": "agent-worker",
        "gateway_handler_probe": false,
        "handlers": handlers,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const DEFAULT_HANDLER_SMOKE_TIMEOUT_MILLIS: u64 = 2_000;

    #[test]
    fn framework_handler_probe_reports_native_ready_without_path_scanning() {
        let _env_lock = crate::test_support::lock_handler_env();
        env::remove_var("AGENT_WORKER_CODEX_BIN");
        env::remove_var("AGENT_WORKER_CLAUDE_CODE_BIN");
        env::remove_var("AGENT_WORKER_HERMES_BIN");

        let handlers = framework_handlers();

        let native = handlers
            .iter()
            .find(|handler| handler.adapter_name == "native-harness")
            .unwrap();
        assert!(native.ready);
        assert_eq!(native.framework, "native_harness");
        assert!(native
            .capabilities
            .iter()
            .any(|capability| capability == "tools"));
        assert!(native
            .capabilities
            .iter()
            .any(|capability| capability == "checkpoint"));
        assert!(native
            .capabilities
            .iter()
            .any(|capability| capability == "streaming"));

        let codex = handlers
            .iter()
            .find(|handler| handler.adapter_name == "codex")
            .unwrap();
        assert!(!codex.ready);
        assert!(codex
            .capabilities
            .iter()
            .any(|capability| capability == "filesystem"));
        assert!(codex
            .capabilities
            .iter()
            .any(|capability| capability == "shell"));
        assert!(codex
            .readiness_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("was not configured")));

        let hermes = handlers
            .iter()
            .find(|handler| handler.adapter_name == "hermes")
            .unwrap();
        assert!(hermes
            .capabilities
            .iter()
            .any(|capability| capability == "memory.read"));
        assert!(hermes
            .capabilities
            .iter()
            .any(|capability| capability == "subagents"));

        let json = handlers_json(&handlers);
        assert!(json.contains(r#""handler_owner":"agent-worker""#));
        assert!(json.contains(r#""gateway_handler_probe":false"#));
        assert!(json.contains(r#""capabilities":["#));
    }

    #[test]
    fn handler_binary_smoke_executes_worker_owned_configured_adapter_binary() {
        let _env_lock = crate::test_support::lock_handler_env();
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("codex-smoke");
        fs::write(
            &binary_path,
            "#!/bin/sh\nprintf 'codex smoke %s\\n' \"$1\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary_path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&binary_path, permissions).unwrap();
        env::set_var("AGENT_WORKER_CODEX_BIN", &binary_path);

        let result = smoke_handler_binary("codex", DEFAULT_HANDLER_SMOKE_TIMEOUT_MILLIS).unwrap();

        env::remove_var("AGENT_WORKER_CODEX_BIN");
        assert_eq!(result.adapter_name, "codex");
        assert_eq!(result.env_var, "AGENT_WORKER_CODEX_BIN");
        assert_eq!(result.binary_path, binary_path);
        assert_eq!(result.probe_args, vec!["--version"]);
        assert_eq!(result.status_code, Some(0));
        assert!(result.stdout_excerpt.contains("codex smoke --version"));
    }

    #[test]
    fn handler_task_smoke_executes_worker_owned_configured_adapter_binary() {
        let _env_lock = crate::test_support::lock_handler_env();
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("codex-task-smoke");
        fs::write(
            &binary_path,
            "#!/bin/sh\nprintf 'codex task args:'\nprintf ' [%s]' \"$@\"\nprintf '\\n'\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary_path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&binary_path, permissions).unwrap();
        env::set_var("AGENT_WORKER_CODEX_BIN", &binary_path);

        let result = smoke_handler_task(
            "codex",
            DEFAULT_HANDLER_SMOKE_TIMEOUT_MILLIS,
            "Return exactly smoke-ok",
        )
        .unwrap();

        env::remove_var("AGENT_WORKER_CODEX_BIN");
        assert_eq!(result.adapter_name, "codex");
        assert_eq!(result.env_var, "AGENT_WORKER_CODEX_BIN");
        assert_eq!(result.binary_path, binary_path);
        assert_eq!(result.task_args[0], "exec");
        assert!(result.task_args.iter().any(|arg| arg == "read-only"));
        assert!(!result
            .task_args
            .iter()
            .any(|arg| arg == "--ask-for-approval"));
        assert_eq!(
            result.task_args[result.prompt_arg_index],
            "Return exactly smoke-ok"
        );
        assert_eq!(
            result.prompt_chars,
            "Return exactly smoke-ok".chars().count()
        );
        assert_eq!(result.status_code, Some(0));
        assert!(result.stdout_excerpt.contains("codex task args:"));

        let redacted = redacted_args(&result.task_args, result.prompt_arg_index);
        assert_eq!(redacted[result.prompt_arg_index], "<prompt>");
        assert!(!redacted.iter().any(|arg| arg == "Return exactly smoke-ok"));
    }

    #[test]
    fn hermes_task_smoke_uses_global_oneshot_arguments() {
        let _env_lock = crate::test_support::lock_handler_env();
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("hermes-task-smoke");
        fs::write(
            &binary_path,
            "#!/bin/sh\nprintf 'hermes task args:'\nprintf ' [%s]' \"$@\"\nprintf '\\nReturn exactly smoke-ok\\n'\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary_path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&binary_path, permissions).unwrap();
        env::set_var("AGENT_WORKER_HERMES_BIN", &binary_path);

        let result = smoke_handler_task(
            "hermes",
            DEFAULT_HANDLER_SMOKE_TIMEOUT_MILLIS,
            "Return exactly smoke-ok",
        )
        .unwrap();

        env::remove_var("AGENT_WORKER_HERMES_BIN");
        assert_eq!(
            result.task_args,
            vec!["--ignore-rules", "-z", "Return exactly smoke-ok"]
        );
        assert_eq!(result.prompt_arg_index, 2);
        assert!(!result.task_args.iter().any(|arg| arg == "--max-turns"));
        assert!(result.stdout_excerpt.contains("hermes task args:"));
    }

    #[test]
    fn claude_code_task_smoke_uses_bare_print_oneshot_arguments() {
        // Locks the exact non-interactive template validated against the real
        // Claude Code CLI 2.1.215 (#308). Every flag below exists on claude
        // 2.x and does what the adapter assumes; see the module comment on
        // `handler_binary_task_target` and the gated real-harness E2E in
        // `tests/claude_code_harness_e2e.rs`.
        let _env_lock = crate::test_support::lock_handler_env();
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("claude-task-smoke");
        fs::write(
            &binary_path,
            "#!/bin/sh\nprintf 'claude task args:'\nprintf ' [%s]' \"$@\"\nprintf '\\nsmoke-ok\\n'\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary_path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&binary_path, permissions).unwrap();
        env::set_var("AGENT_WORKER_CLAUDE_CODE_BIN", &binary_path);

        let result = smoke_handler_task(
            "claude-code",
            DEFAULT_HANDLER_SMOKE_TIMEOUT_MILLIS,
            "Return exactly: smoke-ok",
        )
        .unwrap();

        env::remove_var("AGENT_WORKER_CLAUDE_CODE_BIN");
        assert_eq!(result.adapter_name, "claude-code");
        assert_eq!(result.env_var, "AGENT_WORKER_CLAUDE_CODE_BIN");
        assert_eq!(
            result.task_args,
            vec![
                "--bare",
                "--print",
                "--permission-mode",
                "dontAsk",
                "--tools",
                "",
                "--no-session-persistence",
                "Return exactly: smoke-ok",
            ]
        );
        assert_eq!(result.prompt_arg_index, 7);
        assert_eq!(result.status_code, Some(0));
        assert!(result.stdout_excerpt.contains("claude task args:"));
        assert!(result.stdout_excerpt.contains("smoke-ok"));
        let redacted = redacted_args(&result.task_args, result.prompt_arg_index);
        assert_eq!(redacted[result.prompt_arg_index], "<prompt>");
    }

    #[test]
    fn handler_task_smoke_rejects_zero_exit_without_expected_output() {
        let _env_lock = crate::test_support::lock_handler_env();
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("hermes-task-smoke");
        fs::write(
            &binary_path,
            "#!/bin/sh\nprintf 'API call failed after 3 retries: HTTP 402: Insufficient Balance\\n'\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary_path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&binary_path, permissions).unwrap();
        env::set_var("AGENT_WORKER_HERMES_BIN", &binary_path);

        let error = smoke_handler_task(
            "hermes",
            DEFAULT_HANDLER_SMOKE_TIMEOUT_MILLIS,
            "Return exactly: ferrogate-agent-worker-task-smoke",
        )
        .unwrap_err()
        .to_string();

        env::remove_var("AGENT_WORKER_HERMES_BIN");
        assert!(error.contains("did not produce expected output"));
        assert!(error.contains("Insufficient Balance"));
    }

    #[test]
    fn handler_task_smoke_rejects_empty_prompt_before_spawn() {
        let error = smoke_handler_task("hermes", DEFAULT_HANDLER_SMOKE_TIMEOUT_MILLIS, "   ")
            .unwrap_err()
            .to_string();

        assert!(error.contains("handler task smoke prompt must not be empty"));
    }

    #[test]
    fn handler_binary_smoke_fails_closed_when_binary_is_not_configured() {
        let _env_lock = crate::test_support::lock_handler_env();
        env::remove_var("AGENT_WORKER_HERMES_BIN");

        let error = smoke_handler_binary("hermes", DEFAULT_HANDLER_SMOKE_TIMEOUT_MILLIS)
            .unwrap_err()
            .to_string();

        assert!(error.contains("AGENT_WORKER_HERMES_BIN was not configured"));
    }

    #[test]
    fn handler_probe_and_smoke_reject_non_executable_adapter_binary() {
        let _env_lock = crate::test_support::lock_handler_env();
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("claude-smoke");
        fs::write(&binary_path, "#!/bin/sh\nprintf 'claude smoke\\n'\n").unwrap();
        let mut permissions = fs::metadata(&binary_path).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&binary_path, permissions).unwrap();
        env::set_var("AGENT_WORKER_CLAUDE_CODE_BIN", &binary_path);

        let handlers = framework_handlers();
        let error = smoke_handler_binary("claude-code", DEFAULT_HANDLER_SMOKE_TIMEOUT_MILLIS)
            .unwrap_err()
            .to_string();

        env::remove_var("AGENT_WORKER_CLAUDE_CODE_BIN");
        let claude = handlers
            .iter()
            .find(|handler| handler.adapter_name == "claude-code")
            .unwrap();
        assert!(!claude.ready);
        assert!(claude
            .readiness_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("is not executable")));
        assert!(error.contains("AGENT_WORKER_CLAUDE_CODE_BIN is not executable"));
    }
}
