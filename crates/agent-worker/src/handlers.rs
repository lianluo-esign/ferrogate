// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{env, path::Path};

use anyhow::Result;
use ferrogate_runtime::AgentWorkerFrameworkHandler;
use serde_json::json;

pub(crate) fn probe_handlers_command() -> Result<()> {
    let handlers = framework_handlers();
    println!("{}", handlers_json(&handlers));
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

    #[test]
    fn framework_handler_probe_reports_native_ready_without_path_scanning() {
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
}
