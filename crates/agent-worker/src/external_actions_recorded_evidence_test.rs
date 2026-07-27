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
//! The dispatch below is an exhaustive `match` on [`ManagedExternalAction`] on
//! purpose: a family added tomorrow does not compile until it is listed here,
//! so "the new family was never audited" cannot happen again silently.

use super::*;

use crate::recorded_evidence::REDACTED_HEADER_VALUE;

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
