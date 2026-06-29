// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    env,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
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
