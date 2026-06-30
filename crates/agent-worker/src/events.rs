// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-30
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Single normalized worker event schema shared by every framework adapter.
//!
//! Issue #84 requires that the Claude Code, Codex, Hermes, and native-harness
//! adapters all emit ONE normalized lifecycle and event stream so the control
//! plane never has to special-case a framework. This module owns that schema:
//!
//! - [`WorkerEventKind`] is the typed, dotted-wire event vocabulary
//!   (`session.started`, `run.completed`, ...). It is the only set of event
//!   names the control plane ever sees, regardless of which framework produced
//!   the event.
//! - [`NormalizedWorkerEvent`] is the serializable envelope. It carries the
//!   normalized identity (`framework`, `adapter`, `mode`, `session_id`,
//!   `run_id`) plus an OPAQUE [`serde_json::Value`] `metadata` field. All
//!   framework-specific detail is confined to `metadata`; the rest of the
//!   envelope has the same shape for every adapter.
//!
//! How a new adapter plugs in: emit [`ferrogate_runtime::NormalizedFrameworkEvent`]
//! values (as the existing adapters already do) and let
//! [`NormalizedWorkerEvent::from`] normalize them into this schema, or serialize
//! a [`NormalizedWorkerEvent`] directly. Framework-specific data goes under
//! `metadata` and never leaks into the typed envelope fields.

use std::collections::{BTreeMap, HashMap};

use ferrogate_runtime::{
    AgentWorkerFrameworkEventResult, FrameworkAdapterEventKind, FrameworkAdapterMode,
    NormalizedFrameworkEvent,
};
use serde::{Deserialize, Serialize};

/// Execution mode reported for every normalized worker event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorkerEventMode {
    Managed,
    SelfHosted,
}

impl WorkerEventMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::SelfHosted => "self_hosted",
        }
    }
}

impl From<FrameworkAdapterMode> for WorkerEventMode {
    fn from(mode: FrameworkAdapterMode) -> Self {
        match mode {
            FrameworkAdapterMode::Managed => Self::Managed,
            FrameworkAdapterMode::SelfHosted => Self::SelfHosted,
        }
    }
}

/// Normalized event vocabulary shared by all framework adapters.
///
/// Each variant serializes to its dotted wire string (for example
/// `session.started`). This mirrors [`FrameworkAdapterEventKind`] exactly so the
/// mapping from any adapter's framework-specific event is total and lossless:
/// no framework-specific event name can ever reach the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WorkerEventKind {
    #[serde(rename = "session.started")]
    SessionStarted,
    #[serde(rename = "run.started")]
    RunStarted,
    #[serde(rename = "capability.requested")]
    CapabilityRequested,
    #[serde(rename = "capability.allowed")]
    CapabilityAllowed,
    #[serde(rename = "capability.denied")]
    CapabilityDenied,
    #[serde(rename = "model.requested")]
    ModelRequested,
    #[serde(rename = "tool.requested")]
    ToolRequested,
    #[serde(rename = "tool.approved")]
    ToolApproved,
    #[serde(rename = "tool.denied")]
    ToolDenied,
    #[serde(rename = "tool.completed")]
    ToolCompleted,
    #[serde(rename = "mcp.tool.requested")]
    McpToolRequested,
    #[serde(rename = "skill.requested")]
    SkillRequested,
    #[serde(rename = "cli.requested")]
    CliRequested,
    #[serde(rename = "rest.requested")]
    RestRequested,
    #[serde(rename = "filesystem.requested")]
    FilesystemRequested,
    #[serde(rename = "secret.requested")]
    SecretRequested,
    #[serde(rename = "network.egress.requested")]
    NetworkEgressRequested,
    #[serde(rename = "browser.requested")]
    BrowserRequested,
    #[serde(rename = "memory.read")]
    MemoryRead,
    #[serde(rename = "memory.write")]
    MemoryWrite,
    #[serde(rename = "checkpoint.created")]
    CheckpointCreated,
    #[serde(rename = "artifact.created")]
    ArtifactCreated,
    #[serde(rename = "run.completed")]
    RunCompleted,
    #[serde(rename = "run.failed")]
    RunFailed,
    #[serde(rename = "run.cancelled")]
    RunCancelled,
    #[serde(rename = "session.closed")]
    SessionClosed,
}

impl WorkerEventKind {
    /// Dotted wire string for this event kind.
    ///
    /// This is the identical string produced by serializing the variant, kept
    /// as an explicit accessor so the lowering onto the management wire result
    /// does not have to round-trip through serde.
    pub(crate) fn as_wire_str(self) -> &'static str {
        match self {
            Self::SessionStarted => "session.started",
            Self::RunStarted => "run.started",
            Self::CapabilityRequested => "capability.requested",
            Self::CapabilityAllowed => "capability.allowed",
            Self::CapabilityDenied => "capability.denied",
            Self::ModelRequested => "model.requested",
            Self::ToolRequested => "tool.requested",
            Self::ToolApproved => "tool.approved",
            Self::ToolDenied => "tool.denied",
            Self::ToolCompleted => "tool.completed",
            Self::McpToolRequested => "mcp.tool.requested",
            Self::SkillRequested => "skill.requested",
            Self::CliRequested => "cli.requested",
            Self::RestRequested => "rest.requested",
            Self::FilesystemRequested => "filesystem.requested",
            Self::SecretRequested => "secret.requested",
            Self::NetworkEgressRequested => "network.egress.requested",
            Self::BrowserRequested => "browser.requested",
            Self::MemoryRead => "memory.read",
            Self::MemoryWrite => "memory.write",
            Self::CheckpointCreated => "checkpoint.created",
            Self::ArtifactCreated => "artifact.created",
            Self::RunCompleted => "run.completed",
            Self::RunFailed => "run.failed",
            Self::RunCancelled => "run.cancelled",
            Self::SessionClosed => "session.closed",
        }
    }
}

impl From<FrameworkAdapterEventKind> for WorkerEventKind {
    fn from(kind: FrameworkAdapterEventKind) -> Self {
        match kind {
            FrameworkAdapterEventKind::SessionStarted => Self::SessionStarted,
            FrameworkAdapterEventKind::RunStarted => Self::RunStarted,
            FrameworkAdapterEventKind::CapabilityRequested => Self::CapabilityRequested,
            FrameworkAdapterEventKind::CapabilityAllowed => Self::CapabilityAllowed,
            FrameworkAdapterEventKind::CapabilityDenied => Self::CapabilityDenied,
            FrameworkAdapterEventKind::ModelRequested => Self::ModelRequested,
            FrameworkAdapterEventKind::ToolRequested => Self::ToolRequested,
            FrameworkAdapterEventKind::ToolApproved => Self::ToolApproved,
            FrameworkAdapterEventKind::ToolDenied => Self::ToolDenied,
            FrameworkAdapterEventKind::ToolCompleted => Self::ToolCompleted,
            FrameworkAdapterEventKind::McpToolRequested => Self::McpToolRequested,
            FrameworkAdapterEventKind::SkillRequested => Self::SkillRequested,
            FrameworkAdapterEventKind::CliRequested => Self::CliRequested,
            FrameworkAdapterEventKind::RestRequested => Self::RestRequested,
            FrameworkAdapterEventKind::FilesystemRequested => Self::FilesystemRequested,
            FrameworkAdapterEventKind::SecretRequested => Self::SecretRequested,
            FrameworkAdapterEventKind::NetworkEgressRequested => Self::NetworkEgressRequested,
            FrameworkAdapterEventKind::BrowserRequested => Self::BrowserRequested,
            FrameworkAdapterEventKind::MemoryRead => Self::MemoryRead,
            FrameworkAdapterEventKind::MemoryWrite => Self::MemoryWrite,
            FrameworkAdapterEventKind::CheckpointCreated => Self::CheckpointCreated,
            FrameworkAdapterEventKind::ArtifactCreated => Self::ArtifactCreated,
            FrameworkAdapterEventKind::RunCompleted => Self::RunCompleted,
            FrameworkAdapterEventKind::RunFailed => Self::RunFailed,
            FrameworkAdapterEventKind::RunCancelled => Self::RunCancelled,
            FrameworkAdapterEventKind::SessionClosed => Self::SessionClosed,
        }
    }
}

/// One normalized worker event in the single schema every adapter serializes
/// into.
///
/// The envelope is framework-agnostic: `kind`, `mode`, `session_id`, and
/// `run_id` are normalized, `framework`/`adapter`/`adapter_version` carry the
/// adapter identity, and all framework-specific payload is confined to the
/// opaque `metadata` value. The control plane can read the envelope without
/// understanding any single framework.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct NormalizedWorkerEvent {
    pub(crate) kind: WorkerEventKind,
    pub(crate) framework: String,
    pub(crate) adapter: String,
    pub(crate) adapter_version: String,
    pub(crate) mode: WorkerEventMode,
    pub(crate) session_id: String,
    pub(crate) run_id: String,
    pub(crate) message: Option<String>,
    pub(crate) metadata: serde_json::Value,
}

impl NormalizedWorkerEvent {
    /// Lower the normalized event onto the management wire result type.
    ///
    /// The opaque metadata is flattened back into the string map the management
    /// protocol expects. Every adapter's events take this single path before
    /// they reach the control plane.
    pub(crate) fn into_management_event_result(self) -> AgentWorkerFrameworkEventResult {
        AgentWorkerFrameworkEventResult {
            session_id: self.session_id,
            run_id: self.run_id,
            adapter_name: self.adapter,
            adapter_version: self.adapter_version,
            framework: self.framework,
            mode: self.mode.as_str().to_string(),
            kind: self.kind.as_wire_str().to_string(),
            message: self.message,
            metadata: metadata_string_map(&self.metadata),
        }
    }
}

impl From<&NormalizedFrameworkEvent> for NormalizedWorkerEvent {
    fn from(event: &NormalizedFrameworkEvent) -> Self {
        Self {
            kind: WorkerEventKind::from(event.kind),
            framework: event.framework.as_str().to_string(),
            adapter: event.adapter_name.clone(),
            adapter_version: event.adapter_version.clone(),
            mode: WorkerEventMode::from(event.mode),
            session_id: event.session_id.clone(),
            run_id: event.run_id.clone(),
            message: event.message.clone(),
            metadata: metadata_to_value(&event.metadata),
        }
    }
}

/// Carry a framework-specific string metadata map into the opaque value field
/// without interpreting it.
fn metadata_to_value(metadata: &BTreeMap<String, String>) -> serde_json::Value {
    serde_json::Value::Object(
        metadata
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect(),
    )
}

/// Flatten opaque metadata back into the string map expected by the management
/// wire result. String values pass through unchanged; any non-string value is
/// rendered as compact JSON so no metadata is silently dropped.
fn metadata_string_map(metadata: &serde_json::Value) -> HashMap<String, String> {
    match metadata {
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, value)| {
                let value = match value {
                    serde_json::Value::String(value) => value.clone(),
                    other => other.to_string(),
                };
                (key.clone(), value)
            })
            .collect(),
        _ => HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::SupportedFramework;

    /// Every event kind the issue #84 vocabulary requires, paired with its
    /// dotted wire string. Extra variants beyond the required minimum mirror the
    /// runtime event kinds so the adapter mapping stays total.
    const KIND_WIRE_TABLE: &[(WorkerEventKind, &str)] = &[
        (WorkerEventKind::SessionStarted, "session.started"),
        (WorkerEventKind::RunStarted, "run.started"),
        (WorkerEventKind::CapabilityRequested, "capability.requested"),
        (WorkerEventKind::CapabilityAllowed, "capability.allowed"),
        (WorkerEventKind::CapabilityDenied, "capability.denied"),
        (WorkerEventKind::ModelRequested, "model.requested"),
        (WorkerEventKind::ToolRequested, "tool.requested"),
        (WorkerEventKind::ToolApproved, "tool.approved"),
        (WorkerEventKind::ToolDenied, "tool.denied"),
        (WorkerEventKind::ToolCompleted, "tool.completed"),
        (WorkerEventKind::McpToolRequested, "mcp.tool.requested"),
        (WorkerEventKind::SkillRequested, "skill.requested"),
        (WorkerEventKind::CliRequested, "cli.requested"),
        (WorkerEventKind::RestRequested, "rest.requested"),
        (WorkerEventKind::FilesystemRequested, "filesystem.requested"),
        (WorkerEventKind::SecretRequested, "secret.requested"),
        (
            WorkerEventKind::NetworkEgressRequested,
            "network.egress.requested",
        ),
        (WorkerEventKind::BrowserRequested, "browser.requested"),
        (WorkerEventKind::MemoryRead, "memory.read"),
        (WorkerEventKind::MemoryWrite, "memory.write"),
        (WorkerEventKind::CheckpointCreated, "checkpoint.created"),
        (WorkerEventKind::ArtifactCreated, "artifact.created"),
        (WorkerEventKind::RunCompleted, "run.completed"),
        (WorkerEventKind::RunFailed, "run.failed"),
        (WorkerEventKind::RunCancelled, "run.cancelled"),
        (WorkerEventKind::SessionClosed, "session.closed"),
    ];

    /// The required minimum vocabulary from issue #84, asserted to be covered.
    const REQUIRED_VOCABULARY: &[&str] = &[
        "session.started",
        "run.started",
        "capability.requested",
        "capability.allowed",
        "capability.denied",
        "model.requested",
        "tool.requested",
        "tool.approved",
        "tool.denied",
        "tool.completed",
        "mcp.tool.requested",
        "cli.requested",
        "rest.requested",
        "memory.read",
        "memory.write",
        "checkpoint.created",
        "artifact.created",
        "run.completed",
        "run.failed",
        "run.cancelled",
        "session.closed",
    ];

    #[test]
    fn every_worker_event_kind_round_trips_dotted_wire_string() {
        for (kind, wire) in KIND_WIRE_TABLE {
            assert_eq!(kind.as_wire_str(), *wire, "as_wire_str mismatch for {wire}");

            let serialized = serde_json::to_string(kind).unwrap();
            assert_eq!(
                serialized,
                format!("\"{wire}\""),
                "serde serialization mismatch for {wire}"
            );

            let parsed: WorkerEventKind = serde_json::from_str(&serialized).unwrap();
            assert_eq!(parsed, *kind, "round-trip mismatch for {wire}");
        }
    }

    #[test]
    fn required_issue_vocabulary_is_fully_covered() {
        for wire in REQUIRED_VOCABULARY {
            assert!(
                KIND_WIRE_TABLE
                    .iter()
                    .any(|(_, candidate)| candidate == wire),
                "required vocabulary kind {wire} is missing from WorkerEventKind"
            );
            // Every required wire string must deserialize into a typed kind.
            let parsed: WorkerEventKind = serde_json::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(parsed.as_wire_str(), *wire);
        }
    }

    #[test]
    fn worker_event_mode_round_trips() {
        for (mode, wire) in [
            (WorkerEventMode::Managed, "managed"),
            (WorkerEventMode::SelfHosted, "self_hosted"),
        ] {
            assert_eq!(mode.as_str(), wire);
            let serialized = serde_json::to_string(&mode).unwrap();
            assert_eq!(serialized, format!("\"{wire}\""));
            let parsed: WorkerEventMode = serde_json::from_str(&serialized).unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn opaque_metadata_is_preserved_through_round_trip() {
        let metadata = serde_json::json!({
            "external_target": "codex",
            "nested": { "raw_kind": "codex.tool_call", "attempt": 2 },
            "args": ["run", "--json"],
        });
        let event = NormalizedWorkerEvent {
            kind: WorkerEventKind::CapabilityAllowed,
            framework: "codex".to_string(),
            adapter: "codex".to_string(),
            adapter_version: "codex-1.0".to_string(),
            mode: WorkerEventMode::Managed,
            session_id: "session-opaque".to_string(),
            run_id: "run-opaque".to_string(),
            message: Some("opaque metadata preserved".to_string()),
            metadata: metadata.clone(),
        };

        let serialized = serde_json::to_string(&event).unwrap();
        let parsed: NormalizedWorkerEvent = serde_json::from_str(&serialized).unwrap();

        assert_eq!(parsed, event);
        // The framework-specific payload survives untouched and uninterpreted.
        assert_eq!(parsed.metadata, metadata);
        assert_eq!(parsed.metadata["nested"]["raw_kind"], "codex.tool_call");
    }

    #[test]
    fn framework_event_maps_into_normalized_worker_event_and_back() {
        let framework_event = NormalizedFrameworkEvent {
            session_id: "session-map".to_string(),
            run_id: "run-map".to_string(),
            adapter_name: "native-harness".to_string(),
            adapter_version: "native-harness-1.0".to_string(),
            framework: SupportedFramework::NativeHarness,
            mode: FrameworkAdapterMode::Managed,
            kind: FrameworkAdapterEventKind::RunCompleted,
            message: Some("normalized".to_string()),
            metadata: BTreeMap::from([
                ("external_target".to_string(), "native-harness".to_string()),
                ("decision".to_string(), "allowed".to_string()),
            ]),
        };

        let worker_event = NormalizedWorkerEvent::from(&framework_event);
        assert_eq!(worker_event.kind, WorkerEventKind::RunCompleted);
        assert_eq!(worker_event.framework, "native_harness");
        assert_eq!(worker_event.adapter, "native-harness");
        assert_eq!(worker_event.mode, WorkerEventMode::Managed);
        assert_eq!(worker_event.metadata["decision"], "allowed");

        // Lowering onto the management wire result is lossless for the original
        // string metadata the runtime produced.
        let result = worker_event.into_management_event_result();
        assert_eq!(result.kind, "run.completed");
        assert_eq!(result.framework, "native_harness");
        assert_eq!(result.mode, "managed");
        assert_eq!(result.adapter_name, "native-harness");
        assert_eq!(
            result.metadata.get("external_target").map(String::as_str),
            Some("native-harness")
        );
        assert_eq!(
            result.metadata.get("decision").map(String::as_str),
            Some("allowed")
        );
    }

    /// Build a representative happy-path lifecycle for one adapter, with
    /// framework-specific data deliberately stuffed into the opaque metadata so
    /// the golden comparison can prove that data never leaks into the typed
    /// envelope fields.
    fn representative_lifecycle(
        framework: SupportedFramework,
        adapter_name: &str,
    ) -> Vec<NormalizedFrameworkEvent> {
        let lifecycle = [
            FrameworkAdapterEventKind::SessionStarted,
            FrameworkAdapterEventKind::RunStarted,
            FrameworkAdapterEventKind::CapabilityRequested,
            FrameworkAdapterEventKind::CapabilityAllowed,
            FrameworkAdapterEventKind::ModelRequested,
            FrameworkAdapterEventKind::ToolRequested,
            FrameworkAdapterEventKind::ToolApproved,
            FrameworkAdapterEventKind::ToolCompleted,
            FrameworkAdapterEventKind::CheckpointCreated,
            FrameworkAdapterEventKind::ArtifactCreated,
            FrameworkAdapterEventKind::RunCompleted,
            FrameworkAdapterEventKind::SessionClosed,
        ];
        lifecycle
            .into_iter()
            .map(|kind| NormalizedFrameworkEvent {
                // Normalized identity is shared across adapters so the golden
                // comparison can assert the core envelope is framework-agnostic.
                session_id: "session-golden".to_string(),
                run_id: "run-golden".to_string(),
                adapter_name: adapter_name.to_string(),
                adapter_version: format!("{adapter_name}-1.0"),
                framework,
                mode: FrameworkAdapterMode::Managed,
                kind,
                message: Some(format!("{} {}", adapter_name, kind.as_str())),
                // Framework-specific, opaque payload.
                metadata: BTreeMap::from([
                    (
                        "raw_framework_kind".to_string(),
                        format!("{adapter_name}:{}", kind.as_str()),
                    ),
                    (
                        "framework_native_field".to_string(),
                        adapter_name.to_string(),
                    ),
                ]),
            })
            .collect()
    }

    fn envelope_field_names(value: &serde_json::Value) -> Vec<String> {
        let mut keys: Vec<String> = value
            .as_object()
            .expect("normalized worker event serializes to a JSON object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn golden_event_fixtures_map_all_adapters_into_one_schema() {
        // Table-driven over the four required adapters: (framework family,
        // adapter name).
        let adapters = [
            (SupportedFramework::ClaudeCode, "claude-code"),
            (SupportedFramework::Codex, "codex"),
            (SupportedFramework::Hermes, "hermes"),
            (SupportedFramework::NativeHarness, "native-harness"),
        ];

        let expected_kind_sequence = [
            "session.started",
            "run.started",
            "capability.requested",
            "capability.allowed",
            "model.requested",
            "tool.requested",
            "tool.approved",
            "tool.completed",
            "checkpoint.created",
            "artifact.created",
            "run.completed",
            "session.closed",
        ];
        let expected_envelope_fields = vec![
            "adapter".to_string(),
            "adapter_version".to_string(),
            "framework".to_string(),
            "kind".to_string(),
            "message".to_string(),
            "metadata".to_string(),
            "mode".to_string(),
            "run_id".to_string(),
            "session_id".to_string(),
        ];

        // Normalize each adapter's lifecycle into the single schema and capture
        // the serialized envelopes.
        let serialized_by_adapter: Vec<(String, Vec<serde_json::Value>)> = adapters
            .iter()
            .map(|(framework, adapter_name)| {
                let envelopes = representative_lifecycle(*framework, adapter_name)
                    .iter()
                    .map(|event| serde_json::to_value(NormalizedWorkerEvent::from(event)).unwrap())
                    .collect::<Vec<_>>();
                (adapter_name.to_string(), envelopes)
            })
            .collect();

        for (adapter_name, envelopes) in &serialized_by_adapter {
            // Same number of lifecycle events and the same normalized kind
            // sequence for every adapter.
            let kinds: Vec<&str> = envelopes
                .iter()
                .map(|event| event["kind"].as_str().unwrap())
                .collect();
            assert_eq!(
                kinds, expected_kind_sequence,
                "adapter {adapter_name} produced an unexpected normalized kind sequence"
            );

            for event in envelopes {
                // Identical envelope field set across every adapter and position.
                assert_eq!(
                    envelope_field_names(event),
                    expected_envelope_fields,
                    "adapter {adapter_name} produced an unexpected envelope shape"
                );
                // Mode and identity are normalized identically.
                assert_eq!(event["mode"], "managed");
                assert_eq!(event["session_id"], "session-golden");
                assert_eq!(event["run_id"], "run-golden");
                // Framework-specific data is confined to opaque metadata.
                assert!(event["metadata"].is_object());
            }
        }

        // Cross-adapter structural equality: stripping the framework identity and
        // the opaque metadata must leave byte-identical normalized cores at every
        // lifecycle position.
        let reference = &serialized_by_adapter[0].1;
        for (adapter_name, envelopes) in &serialized_by_adapter[1..] {
            assert_eq!(
                envelopes.len(),
                reference.len(),
                "adapter {adapter_name} produced a different lifecycle length"
            );
            for (position, (reference_event, event)) in
                reference.iter().zip(envelopes.iter()).enumerate()
            {
                let reference_core = normalized_core(reference_event);
                let event_core = normalized_core(event);
                assert_eq!(
                    reference_core, event_core,
                    "adapter {adapter_name} diverged from the shared schema at position {position}"
                );

                // The opaque metadata legitimately differs per framework, proving
                // framework-specific data lives only under `metadata`.
                assert_ne!(
                    reference_event["metadata"], event["metadata"],
                    "expected framework-specific metadata to differ for {adapter_name}"
                );
            }
        }
    }

    /// The framework-agnostic core: the envelope with adapter identity and
    /// opaque metadata removed. Equal across all adapters for the same lifecycle
    /// position.
    fn normalized_core(event: &serde_json::Value) -> serde_json::Value {
        let mut object = event.as_object().unwrap().clone();
        object.remove("framework");
        object.remove("adapter");
        object.remove("adapter_version");
        object.remove("metadata");
        // Per-adapter message text is identity-derived; reduce it to the kind so
        // the normalized core compares only the schema-level fields.
        object.insert(
            "message".to_string(),
            serde_json::Value::String(event["kind"].as_str().unwrap().to_string()),
        );
        serde_json::Value::Object(object)
    }
}
