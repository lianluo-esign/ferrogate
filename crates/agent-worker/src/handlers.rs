// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use ferrogate_runtime::AgentWorkerFrameworkHandler;
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

pub(crate) fn framework_handlers() -> Vec<AgentWorkerFrameworkHandler> {
    vec![
        AgentWorkerFrameworkHandler {
            adapter_name: "native-harness".to_string(),
            framework: "native_harness".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
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
    match env::var(env_var) {
        Ok(path) if !path.trim().is_empty() && Path::new(&path).is_file() => {
            AgentWorkerFrameworkHandler {
                adapter_name: adapter_name.to_string(),
                framework: framework.to_string(),
                version: "external".to_string(),
                ready: true,
                readiness_reason: Some(format!("{env_var} points to executable candidate {path}")),
            }
        }
        Ok(path) if !path.trim().is_empty() => AgentWorkerFrameworkHandler {
            adapter_name: adapter_name.to_string(),
            framework: framework.to_string(),
            version: "unknown".to_string(),
            ready: false,
            readiness_reason: Some(format!("{env_var} does not point to a file: {path}")),
        },
        _ => AgentWorkerFrameworkHandler {
            adapter_name: adapter_name.to_string(),
            framework: framework.to_string(),
            version: "unknown".to_string(),
            ready: false,
            readiness_reason: Some(missing_message.to_string()),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HandlerBinarySmokeResult {
    adapter_name: &'static str,
    env_var: &'static str,
    binary_path: PathBuf,
    probe_args: Vec<&'static str>,
    status_code: Option<i32>,
    stdout_excerpt: String,
    stderr_excerpt: String,
}

fn smoke_handler_binary(
    adapter_name: &str,
    timeout_millis: u64,
) -> Result<HandlerBinarySmokeResult> {
    let target = handler_binary_smoke_target(adapter_name)?;
    let binary_path = configured_binary_path(target.env_var)?;
    let mut child = Command::new(&binary_path)
        .args(target.probe_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "failed to start {} handler binary from {}",
                target.adapter_name,
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
                "agent-worker {} handler binary smoke timed out after {}ms",
                target.adapter_name,
                timeout.as_millis()
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "agent-worker {} handler binary smoke exited with status {:?}",
            target.adapter_name,
            output.status.code()
        );
    }

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

fn configured_binary_path(env_var: &str) -> Result<PathBuf> {
    let raw = env::var(env_var).map_err(|_| anyhow!("{env_var} was not configured"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{env_var} was not configured");
    }
    let path = PathBuf::from(trimmed);
    if !path.is_file() {
        bail!("{env_var} does not point to a file: {}", path.display());
    }
    Ok(path)
}

fn output_excerpt(output: &[u8]) -> String {
    const MAX_EXCERPT_BYTES: usize = 512;
    let length = output.len().min(MAX_EXCERPT_BYTES);
    String::from_utf8_lossy(&output[..length])
        .trim()
        .to_string()
}

fn handlers_json(handlers: &[AgentWorkerFrameworkHandler]) -> String {
    let handlers = handlers
        .iter()
        .map(|handler| {
            json!({
                "adapter_name": handler.adapter_name,
                "framework": handler.framework,
                "version": handler.version,
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

        let codex = handlers
            .iter()
            .find(|handler| handler.adapter_name == "codex")
            .unwrap();
        assert!(!codex.ready);
        assert!(codex
            .readiness_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("was not configured")));

        let json = handlers_json(&handlers);
        assert!(json.contains(r#""handler_owner":"agent-worker""#));
        assert!(json.contains(r#""gateway_handler_probe":false"#));
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
    fn handler_binary_smoke_fails_closed_when_binary_is_not_configured() {
        let _env_lock = crate::test_support::lock_handler_env();
        env::remove_var("AGENT_WORKER_HERMES_BIN");

        let error = smoke_handler_binary("hermes", DEFAULT_HANDLER_SMOKE_TIMEOUT_MILLIS)
            .unwrap_err()
            .to_string();

        assert!(error.contains("AGENT_WORKER_HERMES_BIN was not configured"));
    }
}
