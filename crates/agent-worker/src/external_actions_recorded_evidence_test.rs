// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Per-family recorded-evidence redaction (#526).
//!
//! #353 fixed the REST family's `response_excerpt` and proved it. Every other
//! family built its excerpt through its own constructor and none of them was
//! audited, so `output_excerpt`, `value_excerpt`, `content_excerpt`,
//! `stdout_excerpt`/`stderr_excerpt` and `page_state` were all still capable of
//! recording an upstream credential verbatim.
//!
//! These tests attack the builders the way a regression actually arrives: the
//! execution value is constructed with a RAW, UNREDACTED excerpt, exactly as a
//! future edit that forgets the excerpt helper would produce. The recorded
//! metadata must still be clean, because the redaction is a property of
//! recording, not of remembering to call the right helper.
//!
//! There are TWO exhaustive dispatches here, over two different domains,
//! because #526's first attempt only had the first one and it was structurally
//! blind to most of the crate:
//!
//! 1. [`ManagedExternalAction`] — the governed external-action families. A
//!    family added tomorrow does not compile until its builder is listed.
//! 2. [`RecordedSurface`] — EVERY recorded-evidence surface in the crate,
//!    including the four that are not external actions at all: a configured
//!    handler binary's stdout, a microVM guest workload's stdout, the
//!    Firecracker serial console, and a governed workload's output. Reverting
//!    any of those to its pre-#526 raw capture changed no assertion anywhere
//!    until this dispatch existed. Each arm feeds a credential to the REAL
//!    production recording site and asserts on the ARTIFACT it produces.
//!
//! What (2) forces and what it does not, stated rather than implied: a new
//! variant of `RecordedSurface` does not compile until an artifact arm exists
//! for it, and a new recording site cannot call an excerpt helper without
//! naming a surface (the helpers take one, and derive the redaction scope from
//! it). What it cannot force is a recording path that reaches none of
//! `recorded_evidence`'s helpers at all; `recorded_metadata` is the net under
//! that case for anything landing in event metadata, and the guest-frame and
//! REST-rejection sweeps below are the net for the two paths that are not
//! metadata maps.

use std::io::Write as _;

use ferrogate_runtime::{
    AgentWorkerFrameworkEventResult, CapabilityPolicy, ClassOnlyPolicyMode,
    SimpleCapabilityAuthorizer,
};

use super::*;

use crate::recorded_evidence::{RecordedSurface, REDACTED_HEADER_VALUE};

/// Obviously-fake credential material. Long enough that a surviving prefix
/// would still be a leak worth failing on.
const FAKE_SECRET: &str = "FAKECREDENTIALDONOTLOG0123456789abcdefghijklmnopqrstuvwxyz";

/// The blob a family would capture from an upstream that returns credentials —
/// a status line plus four different flavours of bearer material.
fn leaky_capture() -> String {
    format!(
        "HTTP/1.1 200 OK\n\
         content-type: text/plain\n\
         authorization: Bearer {FAKE_SECRET}\n\
         set-cookie: session={FAKE_SECRET}; HttpOnly\n\
         cookie: sid={FAKE_SECRET}\n\
         PAYMENT-SIGNATURE: {FAKE_SECRET}\n\
         \n\
         upstream body\n"
    )
}

fn tool_action() -> ManagedExternalAction {
    ManagedExternalAction::Tool(ManagedToolAction {
        tool_name: "native.echo".to_string(),
        arguments_policy: "smoke_literal:audited".to_string(),
    })
}

fn mcp_action() -> ManagedExternalAction {
    ManagedExternalAction::McpTool(ManagedMcpToolAction {
        server_name: "local-smoke".to_string(),
        tool_name: "echo".to_string(),
        arguments_policy: "exact_arguments".to_string(),
        arguments: serde_json::json!({"message": "audited"}),
    })
}

fn skill_action() -> ManagedExternalAction {
    ManagedExternalAction::Skill(ManagedSkillAction {
        skill_id: "builtin.skill.echo".to_string(),
        declared_capabilities: vec!["tools".to_string()],
    })
}

fn browser_action() -> ManagedExternalAction {
    ManagedExternalAction::Browser(ManagedBrowserAction {
        operation: ManagedBrowserOperation::Navigate,
        url: "about:blank".to_string(),
        timeout_millis: 2_000,
    })
}

fn memory_action() -> ManagedExternalAction {
    ManagedExternalAction::Memory(ManagedMemoryAction {
        access: ManagedMemoryAccess::Read,
        namespace: "session".to_string(),
        key: "summary".to_string(),
    })
}

fn secret_action() -> ManagedExternalAction {
    ManagedExternalAction::Secret(ManagedSecretAction {
        secret_id: "vault/fake-api-key".to_string(),
        purpose: "provider_call".to_string(),
    })
}

fn network_egress_action() -> ManagedExternalAction {
    ManagedExternalAction::NetworkEgress(ManagedNetworkEgressAction {
        host: "127.0.0.1".to_string(),
        port: 9,
        protocol: "tcp".to_string(),
        resolved_ips: vec!["127.0.0.1".to_string()],
    })
}

fn cli_action() -> ManagedExternalAction {
    ManagedExternalAction::Cli(ManagedCliAction {
        command: "/bin/echo".to_string(),
        args: vec!["audited".to_string()],
        working_dir: "/workspace".to_string(),
        env_policy: "clear".to_string(),
        timeout_millis: 2_000,
        stdout_limit_bytes: 512,
        stderr_limit_bytes: 512,
        artifact_capture: false,
    })
}

fn filesystem_action() -> ManagedExternalAction {
    ManagedExternalAction::Filesystem(ManagedFilesystemAction {
        path: "notes.txt".to_string(),
        access: ManagedFilesystemAccess::Read,
        workspace_relative: true,
    })
}

fn rest_action() -> ManagedExternalAction {
    ManagedExternalAction::Rest(ManagedRestAction {
        method: "GET".to_string(),
        url: "http://127.0.0.1:1/authorized".to_string(),
        headers_policy: "gateway_managed".to_string(),
        body_policy: "none".to_string(),
        timeout_millis: 2_000,
        retry_limit: 0,
        resolved_ips: vec!["127.0.0.1".to_string()],
        redirect_chain: Vec::new(),
    })
}

/// One family's real metadata builder, fed a deliberately UNREDACTED excerpt.
///
/// Returns the metadata plus the key that received the raw capture — `None` for
/// the two families whose evidence is numeric only and has nowhere to put it.
///
/// This `match` is exhaustive by design: adding a variant to
/// [`ManagedExternalAction`] breaks the build here until the new family's
/// builder is audited and listed.
fn recorded_metadata_for(
    action: &ManagedExternalAction,
    raw_capture: &str,
) -> (BTreeMap<String, String>, Option<&'static str>) {
    match action {
        ManagedExternalAction::Tool(action) => (
            GovernedToolExecution {
                output_excerpt: raw_capture.to_string(),
            }
            .metadata(action),
            Some("output_excerpt"),
        ),
        ManagedExternalAction::McpTool(action) => (
            GovernedMcpToolExecution {
                output_excerpt: raw_capture.to_string(),
            }
            .metadata(action),
            Some("output_excerpt"),
        ),
        ManagedExternalAction::Skill(action) => (
            GovernedSkillExecution {
                output_excerpt: raw_capture.to_string(),
            }
            .metadata(action),
            Some("output_excerpt"),
        ),
        ManagedExternalAction::Browser(action) => (
            GovernedBrowserExecution {
                page_state: raw_capture.to_string(),
            }
            .metadata(action),
            Some("page_state"),
        ),
        ManagedExternalAction::Memory(action) => (
            GovernedMemoryExecution {
                value_excerpt: raw_capture.to_string(),
            }
            .metadata(action),
            Some("value_excerpt"),
        ),
        ManagedExternalAction::Filesystem(action) => (
            GovernedFilesystemExecution {
                resolved_path: PathBuf::from("/workspace/notes.txt"),
                byte_len: raw_capture.len(),
                content_excerpt: raw_capture.to_string(),
            }
            .metadata(action),
            Some("content_excerpt"),
        ),
        ManagedExternalAction::Cli(action) => (
            GovernedCliExecution {
                status_code: Some(0),
                stdout_excerpt: raw_capture.to_string(),
                stderr_excerpt: raw_capture.to_string(),
            }
            .metadata(action),
            Some("stdout_excerpt"),
        ),
        ManagedExternalAction::Rest(action) => (
            GovernedRestExecution {
                status_code: 200,
                response_excerpt: raw_capture.to_string(),
            }
            .metadata(action),
            Some("response_excerpt"),
        ),
        // No free-text evidence field: these two record counts and
        // fingerprints only, so there is nothing for an upstream to inject
        // into. Listed rather than skipped so the audit is complete.
        ManagedExternalAction::Secret(action) => (
            GovernedSecretExecution { secret_len: 32 }.metadata(action),
            None,
        ),
        ManagedExternalAction::NetworkEgress(action) => (
            GovernedNetworkEgressExecution { bytes_written: 11 }.metadata(action),
            None,
        ),
    }
}

fn every_family() -> Vec<ManagedExternalAction> {
    vec![
        tool_action(),
        mcp_action(),
        skill_action(),
        browser_action(),
        memory_action(),
        secret_action(),
        network_egress_action(),
        cli_action(),
        filesystem_action(),
        rest_action(),
    ]
}

/// The acceptance criterion, per family: no metadata value recorded by ANY
/// governed external-action family carries an upstream `authorization`,
/// `cookie`, `set-cookie` or `PAYMENT-SIGNATURE` value — not even when the
/// execution value handed to the builder was never excerpted.
#[test]
fn no_family_records_bearer_material_in_event_metadata() {
    let raw = leaky_capture();

    for action in every_family() {
        let (metadata, leak_key) = recorded_metadata_for(&action, &raw);
        let family = metadata
            .get("external_action")
            .cloned()
            .unwrap_or_else(|| "<unnamed family>".to_string());

        for (key, value) in &metadata {
            assert!(
                !value.contains(&FAKE_SECRET[..12]),
                "family {family} recorded bearer material under {key}: {value}"
            );
        }

        let Some(leak_key) = leak_key else {
            // A family with no free-text evidence still has to have produced
            // real metadata — otherwise this loop would pass vacuously.
            assert!(
                metadata.contains_key("external_target"),
                "family {family} recorded no evidence at all: {metadata:?}"
            );
            continue;
        };

        let recorded = metadata
            .get(leak_key)
            .unwrap_or_else(|| panic!("family {family} did not record {leak_key}: {metadata:?}"));
        // Non-vacuity: the raw capture really did reach this key and was
        // rewritten there, rather than being dropped or never stored.
        assert!(
            recorded.contains("upstream body"),
            "family {family} did not actually record the capture under {leak_key}: {recorded}"
        );
        assert_eq!(
            recorded.matches(REDACTED_HEADER_VALUE).count(),
            4,
            "family {family} must redact all four credential values under {leak_key}: {recorded}"
        );
        // Names survive: the record still shows a credential was present.
        assert!(recorded.contains("authorization"), "{recorded}");
        assert!(recorded.contains("PAYMENT-SIGNATURE"), "{recorded}");
        // And non-credential evidence is untouched.
        assert!(recorded.contains("content-type: text/plain"), "{recorded}");
    }
}

/// The CLI family has three metadata builders, not one — success, cancellation
/// and dispatch failure — and the failure one records an ERROR STRING built
/// over data the callee controlled. A per-builder fix is exactly what #526
/// exists to stop, so all three are checked.
#[test]
fn the_cli_failure_and_cancellation_builders_are_swept_too() {
    let ManagedExternalAction::Cli(action) = cli_action() else {
        unreachable!("cli_action builds a CLI action")
    };
    let error = FrameworkAdapterError::CapabilityDenied(format!(
        "managed CLI action failed; upstream said:\nauthorization: Bearer {FAKE_SECRET}"
    ));

    let failure = governed_cli_failure_metadata(&action, &error);
    let recorded = failure
        .get("failure_reason")
        .expect("failure_reason recorded");
    assert!(!recorded.contains(&FAKE_SECRET[..12]), "{recorded}");
    assert!(
        recorded.contains("managed CLI action failed"),
        "the diagnostic must survive: {recorded}"
    );

    let cancellation = GovernedCliCancellation {
        cancellation_reason: format!("timed out; last line was\ncookie: sid={FAKE_SECRET}"),
        elapsed_millis: 12,
    }
    .metadata(&action);
    for (key, value) in &cancellation {
        assert!(
            !value.contains(&FAKE_SECRET[..12]),
            "cancellation metadata leaked under {key}: {value}"
        );
    }
}

/// A CLI action can carry the credential in its own ARGUMENTS (`--header
/// "authorization: …"`), which the builder echoes back into `args`. That is a
/// metadata value like any other and must not survive either.
#[test]
fn credential_bearing_cli_arguments_are_not_echoed_back_into_metadata() {
    let action = ManagedCliAction {
        command: "/usr/bin/curl".to_string(),
        args: vec![
            "-H".to_string(),
            format!("authorization: Bearer {FAKE_SECRET}"),
        ],
        working_dir: "/workspace".to_string(),
        env_policy: "clear".to_string(),
        timeout_millis: 2_000,
        stdout_limit_bytes: 512,
        stderr_limit_bytes: 512,
        artifact_capture: false,
    };

    let metadata = GovernedCliExecution {
        status_code: Some(0),
        stdout_excerpt: String::new(),
        stderr_excerpt: String::new(),
    }
    .metadata(&action);

    let args = metadata.get("args").expect("args recorded");
    assert!(!args.contains(&FAKE_SECRET[..12]), "{args}");
    assert!(args.contains("authorization"), "{args}");
}

// ---------------------------------------------------------------------------
// Every recorded-evidence SURFACE, not just every external-action family
// ---------------------------------------------------------------------------

/// The artifact a recorded-evidence surface actually emits, plus a marker that
/// proves the capture reached it.
struct SurfaceArtifact {
    /// Exactly what leaves the worker: an event-metadata map serialized as it
    /// is emitted, a JSON evidence blob, or the excerpt string that is embedded
    /// verbatim in one.
    recorded: String,
    /// A non-credential fragment of the capture. If this is missing the arm is
    /// vacuous — it proved nothing was leaked because nothing was recorded.
    reached_marker: &'static str,
}

/// A denying gateway authorizer. Self-hosted mode runs the workload regardless,
/// so this needs no allow policy to exercise the recording path.
fn report_only_authorizer() -> RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer> {
    RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions: std::collections::BTreeSet::new(),
        class_only_policy_mode: ClassOnlyPolicyMode::LegacyClassWide,
        ..CapabilityPolicy::default()
    }))
}

fn recorded_evidence_session() -> FrameworkAdapterSession {
    FrameworkAdapterSession {
        session_id: "agent-worker-recorded-evidence-session".to_string(),
        run_id: "agent-worker-recorded-evidence-run".to_string(),
        tenant_id: "recorded-evidence-tenant".to_string(),
        workspace_id: "recorded-evidence-workspace".to_string(),
        worker_id: "agent-worker-recorded-evidence".to_string(),
        isolation_backend: "local-process".to_string(),
        adapter_name: "native-harness".to_string(),
        adapter_version: env!("CARGO_PKG_VERSION").to_string(),
        framework: SupportedFramework::NativeHarness,
        mode: FrameworkAdapterMode::SelfHosted,
    }
}

/// One external-action family's real metadata builder, serialized the way the
/// event carrying it is.
fn family_artifact(action: &ManagedExternalAction, raw_capture: &str) -> SurfaceArtifact {
    let (metadata, _) = recorded_metadata_for(action, raw_capture);
    SurfaceArtifact {
        recorded: serde_json::to_string(&metadata).expect("metadata serializes"),
        reached_marker: "upstream body",
    }
}

/// Feed one recorded-evidence surface a credential through its REAL production
/// recording site and hand back what that site emits.
///
/// This `match` is exhaustive on purpose, and on the RIGHT enum this time: a
/// surface added to [`RecordedSurface`] does not compile until someone has had
/// to answer "what artifact does it produce, and is the credential in it?".
/// `ManagedExternalAction` could not do that job — it is structurally blind to
/// every surface that is not a governed external action, which is exactly how
/// `handlers::output_excerpt`, `backends::excerpt`,
/// `firecracker_guest_exec::execute_guest_workload` and
/// `run_governed_workload`'s `workload_output` were "fixed" with no assertion
/// anywhere.
fn artifact_for(surface: RecordedSurface, raw_capture: &str) -> SurfaceArtifact {
    match surface {
        // --- governed external-action families: the artifact is event metadata
        RecordedSurface::ToolOutput => family_artifact(&tool_action(), raw_capture),
        RecordedSurface::McpToolOutput => family_artifact(&mcp_action(), raw_capture),
        RecordedSurface::SkillOutput => family_artifact(&skill_action(), raw_capture),
        RecordedSurface::MemoryValue => family_artifact(&memory_action(), raw_capture),
        RecordedSurface::FilesystemContent => family_artifact(&filesystem_action(), raw_capture),
        RecordedSurface::CliOutput => family_artifact(&cli_action(), raw_capture),
        RecordedSurface::RestResponse => family_artifact(&rest_action(), raw_capture),

        // --- a configured handler binary's stdout/stderr. `output_excerpt`'s
        // return value is embedded verbatim in `cli.requested` metadata AND
        // printed straight to worker stdout by `smoke_handler_binary_command`,
        // where no metadata sweep runs.
        RecordedSurface::HandlerBinaryOutput => SurfaceArtifact {
            recorded: serde_json::json!({
                "process": "agent-worker",
                "stdout_excerpt": crate::handlers::output_excerpt(raw_capture.as_bytes()),
            })
            .to_string(),
            reached_marker: "upstream body",
        },

        // --- a microVM guest workload's own stdout, really spawned. This is
        // arbitrary attacker-reachable output: the guest prints it, the host
        // records it into the `run.completed` frame and the guest RPC response.
        RecordedSurface::GuestWorkloadOutput => {
            let workspace = tempfile::tempdir().expect("guest workspace");
            std::fs::write(workspace.path().join("capture.txt"), raw_capture)
                .expect("guest capture written");
            let result = crate::firecracker_guest_exec::execute_guest_workload(
                &crate::firecracker_guest_exec::FirecrackerGuestWorkloadSpec {
                    capability_action: "cli".to_string(),
                    command: "/bin/cat".to_string(),
                    args: vec!["capture.txt".to_string()],
                    timeout_millis: 10_000,
                    output_limit_bytes: 8_192,
                },
                workspace.path(),
            );
            assert!(
                result.executed,
                "guest workload did not run: {:?}",
                result.denial_reason
            );
            SurfaceArtifact {
                recorded: serde_json::to_string(&serde_json::json!({
                    "output_excerpt": result.output_excerpt,
                }))
                .expect("guest result serializes"),
                reached_marker: "upstream body",
            }
        }

        // --- the microVM serial console. The worst case in the crate: this
        // evidence is serialized straight to worker stdout by
        // `firecracker_boot_smoke_command` and there is NO downstream metadata
        // sweep anywhere on the path, so `backends::excerpt` is the only thing
        // between a guest and the operator's terminal.
        RecordedSurface::FirecrackerBootEvidence => {
            let evidence = crate::backends::FirecrackerBootEvidence {
                serial_boot_markers: vec!["linux_version"],
                serial_excerpt: crate::backends::excerpt(raw_capture, 16),
                firecracker_log_excerpt: crate::backends::excerpt(raw_capture, 12),
            };
            SurfaceArtifact {
                recorded: serde_json::to_string(&evidence).expect("boot evidence serializes"),
                reached_marker: "upstream body",
            }
        }

        // --- a governed workload's output, through the real enforcement core.
        // `workload_output` lands in `evidence_json()`, which no metadata sweep
        // covers.
        RecordedSurface::GovernedWorkloadOutput => {
            let capture = raw_capture.to_string();
            let execution = run_governed_workload(
                FrameworkAdapterMode::SelfHosted,
                &recorded_evidence_session(),
                &report_only_authorizer(),
                cli_action(),
                false,
                1_000,
                move || {
                    Ok(GovernedWorkloadOutcome {
                        exit_code: Some(0),
                        output: capture,
                        backend_name: "local-process".to_string(),
                        containment_summary: "recorded-evidence-probe".to_string(),
                    })
                },
            )
            .expect("self-hosted report-only execution must never block");
            assert!(execution.workload_ran, "the probe workload must have run");
            SurfaceArtifact {
                recorded: execution.evidence_json().to_string(),
                reached_marker: "upstream body",
            }
        }

        // --- an argument vector recorded back into evidence. The leak here is
        // the JOIN, not the call site: a space join hides a credential's header
        // name behind the flag that precedes it.
        RecordedSurface::Argv => SurfaceArtifact {
            recorded: crate::recorded_evidence::recorded_argv(&[
                "--header".to_string(),
                raw_capture.to_string(),
            ]),
            reached_marker: "upstream body",
        },
    }
}

/// The acceptance criterion for #526, per SURFACE: no recorded-evidence
/// artifact this crate emits carries an upstream `authorization`, `cookie`,
/// `set-cookie` or `PAYMENT-SIGNATURE` value — whichever surface produced it,
/// and whether or not a metadata sweep runs downstream of it.
///
/// Reverting any of the four non-family surfaces to its pre-#526 raw capture
/// (`String::from_utf8_lossy(&output[..length])`, `text.lines().take(n)`,
/// dropping `recorded_value`) fails here. Before this test, all three reverts
/// were silent.
#[test]
fn no_recorded_evidence_surface_emits_bearer_material() {
    let raw = leaky_capture();

    for surface in RecordedSurface::ALL {
        let artifact = artifact_for(surface, &raw);

        assert!(
            !artifact.recorded.contains(&FAKE_SECRET[..12]),
            "{surface:?} recorded bearer material: {}",
            artifact.recorded
        );
        // Non-vacuity: the capture really did reach this surface and was
        // rewritten there, rather than being dropped or never stored.
        assert!(
            artifact.recorded.contains(artifact.reached_marker),
            "{surface:?} did not actually record the capture: {}",
            artifact.recorded
        );
        assert!(
            artifact.recorded.contains(REDACTED_HEADER_VALUE),
            "{surface:?} recorded the capture without redacting anything: {}",
            artifact.recorded
        );
        // The NAME survives, so the record still shows a credential was there.
        assert!(
            artifact.recorded.contains("authorization"),
            "{surface:?} lost the header name: {}",
            artifact.recorded
        );
    }
}

/// `write_guest_event` is the ONE exit for a guest-side event frame, which is
/// why the sweep lives there instead of at the four call sites that build one.
/// Deleting it leaves the guest free to write a credential into any metadata
/// key it likes and have the host record the frame verbatim.
#[test]
fn the_guest_event_writer_sweeps_every_frame_it_emits() {
    let mut event = AgentWorkerFrameworkEventResult {
        session_id: "guest-session".to_string(),
        run_id: "guest-run".to_string(),
        adapter_name: "native-harness".to_string(),
        adapter_version: "test".to_string(),
        framework: "firecracker".to_string(),
        mode: "managed".to_string(),
        kind: "run.completed".to_string(),
        message: Some("guest workload completed".to_string()),
        metadata: std::collections::HashMap::new(),
    };
    // A key nobody classified as an excerpt, holding raw guest output — the
    // shape a new guest event added tomorrow would have.
    event
        .metadata
        .insert("a_new_guest_key".to_string(), leaky_capture());

    let mut frame = Vec::new();
    crate::firecracker_guest_exec::write_guest_event(&mut frame, event).expect("frame written");
    frame.flush().expect("frame flushed");

    let written = String::from_utf8(frame).expect("frame is utf-8");
    assert!(!written.contains(&FAKE_SECRET[..12]), "{written}");
    assert!(written.contains("upstream body"), "{written}");
    assert!(written.contains(REDACTED_HEADER_VALUE), "{written}");
}

/// `GovernedRestRejection::build` records `failure_reason`, an error string
/// built over data the UPSTREAM controlled, into a `rest.requested` event whose
/// metadata is assembled incrementally rather than through `recorded_metadata`.
/// Dropping its sweep re-opens #353 on the failure path.
#[test]
fn the_rest_rejection_builder_sweeps_its_upstream_derived_failure_reason() {
    let ManagedExternalAction::Rest(action) = rest_action() else {
        unreachable!("rest_action builds a REST action")
    };
    let rejection = GovernedRestRejection::build(
        &recorded_evidence_session(),
        &action,
        RequestWireStage::SentOrUnknown,
        true,
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action failed; upstream answered:\n{}",
            leaky_capture()
        )),
    );

    let recorded = rejection
        .event
        .metadata
        .get("failure_reason")
        .expect("failure_reason recorded");
    assert!(!recorded.contains(&FAKE_SECRET[..12]), "{recorded}");
    assert!(
        recorded.contains("managed REST action failed"),
        "the diagnostic must survive: {recorded}"
    );
    assert!(recorded.contains(REDACTED_HEADER_VALUE), "{recorded}");
}
