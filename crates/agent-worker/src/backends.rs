// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{env, path::Path};

use ferrogate_runtime::AgentWorkerIsolationBackendReport;

pub(crate) fn isolation_backends() -> Vec<AgentWorkerIsolationBackendReport> {
    vec![probed_isolation_backend(
        "firecracker",
        "firecracker_micro_vm",
        "AGENT_WORKER_FIRECRACKER_BIN",
        "Firecracker binary path was not configured",
    )]
}

fn probed_isolation_backend(
    backend_name: &str,
    kind: &str,
    env_var: &str,
    missing_message: &str,
) -> AgentWorkerIsolationBackendReport {
    match env::var(env_var) {
        Ok(path) if !path.trim().is_empty() && Path::new(&path).is_file() => {
            AgentWorkerIsolationBackendReport {
                backend_name: backend_name.to_string(),
                backend_version: "external".to_string(),
                kind: kind.to_string(),
                ready: true,
                readiness_reason: Some(format!("{env_var} points to executable candidate {path}")),
            }
        }
        Ok(path) if !path.trim().is_empty() => AgentWorkerIsolationBackendReport {
            backend_name: backend_name.to_string(),
            backend_version: "unknown".to_string(),
            kind: kind.to_string(),
            ready: false,
            readiness_reason: Some(format!("{env_var} does not point to a file: {path}")),
        },
        _ => AgentWorkerIsolationBackendReport {
            backend_name: backend_name.to_string(),
            backend_version: "unknown".to_string(),
            kind: kind.to_string(),
            ready: false,
            readiness_reason: Some(missing_message.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_registry_reports_firecracker_ready_only_from_configured_file() {
        let temp = tempfile::tempdir().unwrap();
        let firecracker_path = temp.path().join("firecracker");
        std::fs::write(&firecracker_path, b"not executed").unwrap();
        env::set_var("AGENT_WORKER_FIRECRACKER_BIN", &firecracker_path);

        let backends = isolation_backends();

        env::remove_var("AGENT_WORKER_FIRECRACKER_BIN");
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].backend_name, "firecracker");
        assert_eq!(backends[0].kind, "firecracker_micro_vm");
        assert!(backends[0].ready);
        assert!(backends[0]
            .readiness_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("AGENT_WORKER_FIRECRACKER_BIN")));

        env::set_var(
            "AGENT_WORKER_FIRECRACKER_BIN",
            temp.path().join("missing-firecracker"),
        );
        let missing = isolation_backends();
        env::remove_var("AGENT_WORKER_FIRECRACKER_BIN");
        assert!(!missing[0].ready);
        assert!(missing[0]
            .readiness_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("does not point to a file")));
    }
}
