// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::{
    assertions::*,
    cli::{AuthArgs, LocalArgs},
    constants::{
        ADMIN_AUTH, AUTH_TEST_CLIENT_2, CLIENT_AUTH, JSON_CONTENT, OBSERVER_AUTH,
        SELF_HOSTED_MTLS_HEADER, SELF_HOSTED_SYMMETRIC_AEAD_HEADER, SUPPORT_SKILL_HEADER,
    },
    local::{AuthHarness, LocalHarness},
    mocks::spawn_mock_third_party_auth_server,
};
use anyhow::{Context, Result};
use ferrogate_runtime::{
    SelfHostedWorkerIdentity, SelfHostedWorkerTransportFrame, SELF_HOSTED_WORKER_PROTOCOL_VERSION,
};
use std::{cell::RefCell, thread, time::Duration};

pub(crate) fn run_admin_api(args: &LocalArgs) -> Result<()> {
    let case = LocalHarness::start(&args.ferrogate_bin, 5)?;
    let self_hosted_worker_id = RefCell::new(String::new());
    let expired_self_hosted_worker_id = RefCell::new(String::new());
    let self_hosted_lease_id = RefCell::new(String::new());
    let self_hosted_event_cursor = RefCell::new(String::new());
    // The symmetric-AEAD transport secret is now provisioned server-side and is
    // independent of the public `identity_fingerprint` (a security fix: the
    // fingerprint is returned to admin readers and carried in cleartext frames).
    // It is returned exactly once in the registration/rotation response, so the
    // worker operator (this harness) must capture it and use it as the bearer
    // secret + AEAD key on every subsequent poll/ack/heartbeat/telemetry call.
    // `token_id` stays the public fingerprint; `token_secret` is this captured
    // value (#248).
    let self_hosted_worker_secret = RefCell::new(String::new());
    let expired_self_hosted_worker_secret = RefCell::new(String::new());

    case.expect_json("GET", "/healthz", &[], "", 200, |body| {
        assert_eq!(body["status"], "ok");
        Ok(())
    })?;
    case.expect_json("GET", "/readyz", &[], "", 200, |body| {
        assert_eq!(body["status"], "ready");
        assert_eq!(body["cluster"]["node_id"], "ferrogate-test-node");
        Ok(())
    })?;
    case.expect_json("GET", "/admin/v1/status", &[ADMIN_AUTH], "", 200, |body| {
        assert_eq!(body["service"], "ferrogate");
        assert_eq!(body["auth_required"], true);
        assert_eq!(body["cluster"]["ready"], true);
        assert_eq!(body["cluster"]["draining"], false);
        assert_eq!(body["storage"]["provider"], "memory");
        assert_eq!(body["storage"]["durable"], false);
        assert_eq!(body["storage"]["implemented"], true);
        assert_eq!(body["storage"]["required"], false);
        assert_eq!(body["storage"]["migration_mode"], "disabled");
        assert_eq!(body["storage"]["health"], "ok");
        assert_eq!(body["storage"]["contract_version"], 1);
        assert_eq!(body["storage"]["provider_order"][0], "supabase");
        assert_eq!(body["storage"]["provider_order"][1], "postgres");
        assert_eq!(body["analytics"]["provider"], "vector");
        assert_eq!(body["analytics"]["enabled"], false);
        assert_eq!(body["analytics"]["active"], false);
        assert_eq!(body["analytics"]["mode"], "pipeline");
        assert_eq!(body["analytics"]["health"], "disabled");
        assert!(body["analytics"]["last_success_at_unix"].is_null());
        assert!(body["analytics"]["last_export_error"].is_null());
        assert_eq!(body["analytics"]["contract_version"], 1);
        assert_eq!(body["observability"][0]["provider"], "vector");
        assert_eq!(body["observability"][0]["endpoint_source"], "observability");
        Ok(())
    })?;
    case.expect_json("GET", "/admin/status", &[ADMIN_AUTH], "", 200, |body| {
        assert_eq!(body["service"], "ferrogate");
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/admin/v1/providers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "name", "openai"));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/provider-health",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/managed-workers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["data"][0]["process_name"], "agent-worker");
            assert_eq!(body["data"][0]["process_boundary"], "external_process");
            assert_eq!(
                body["data"][0]["agent_worker_role"],
                "microvm_lifecycle_controller"
            );
            assert_eq!(body["data"][0]["capability_boundary"], "gateway_mediated");
            assert_eq!(
                body["data"][0]["isolation_backends"][0]["kind"],
                "firecracker_microvm"
            );
            assert_eq!(
                body["data"][0]["isolation_backends"][0]["host_lifecycle_owner"],
                "agent-worker"
            );
            assert_eq!(
                body["data"][0]["isolation_backends"][0]["gateway_controls_backend"],
                false
            );
            assert_eq!(body["data"][0]["persistence"]["provider"], "memory");
            assert_eq!(body["data"][0]["persistence"]["implemented"], false);
            assert_eq!(
                body["data"][0]["persistence"]["timeline_evidence_implemented"],
                true
            );
            assert_eq!(
                body["data"][0]["persistence"]["session_lifecycle_schema_ready"],
                false
            );
            assert_eq!(
                body["data"][0]["persistence"]["session_lifecycle_implemented"],
                false
            );
            assert_eq!(
                body["data"][0]["persistence"]["agent_worker_transport_implemented"],
                false
            );
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/managed-worker-sessions",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "list");
            assert_eq!(body["data"].as_array().map(Vec::len), Some(0));
            assert_eq!(body["total"], 0);
            assert_eq!(body["offset"], 0);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/framework-adapters",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "id", "claude-code"));
            assert!(list_contains(&body, "id", "codex"));
            assert!(list_contains(&body, "id", "hermes"));
            assert!(list_contains(&body, "id", "native-harness"));
            let native = admin_list_item(&body, "id", "native-harness")
                .context("native harness adapter should be listed")?;
            assert_eq!(native["integration_status"], "contract_ready");
            assert_eq!(native["enabled"], true);
            assert_eq!(native["managed_capability_boundary"], "gateway_mediated");
            assert_eq!(
                native["self_hosted_trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(native["public_api_exposes_framework_details"], false);
            assert_eq!(native["persistence"]["implemented"], true);
            assert_eq!(native["persistence"]["provider"], "supabase_postgres");
            assert_eq!(
                native["persistence"]["session_table"],
                "managed_worker_sessions"
            );
            assert_eq!(
                native["persistence"]["lifecycle_event_table"],
                "managed_worker_lifecycle_events"
            );
            assert_eq!(
                native["persistence"]["normalized_event_table"],
                "agent_run_events"
            );
            assert_eq!(native["persistence"]["session_records_implemented"], true);
            assert_eq!(
                native["persistence"]["lifecycle_event_records_implemented"],
                true
            );
            assert_eq!(
                native["persistence"]["normalized_event_records_implemented"],
                true
            );
            let codex =
                admin_list_item(&body, "id", "codex").context("codex adapter should be listed")?;
            assert_eq!(codex["integration_status"], "process_shim_contract_ready");
            assert_eq!(codex["enabled"], false);
            assert_eq!(codex["persistence"]["implemented"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/self-hosted-workers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["data"][0]["execution_owner"], "customer");
            assert_eq!(
                body["data"][0]["enforcement_boundary"],
                "customer_owned_host"
            );
            assert_eq!(
                body["data"][0]["trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(body["data"][0]["transport_actions"][0], "register_worker");
            assert!(body["data"][0]["transport_actions"]
                .as_array()
                .is_some_and(|actions| actions.iter().any(|action| action == "poll_run")
                    && actions.iter().any(|action| action == "cancel_run")
                    && actions.iter().any(|action| action == "resume_run")
                    && actions.iter().any(|action| action == "close_session")
                    && actions.iter().any(|action| action == "ack_run")));
            assert_eq!(body["data"][0]["dispatch_contract"]["implemented"], true);
            assert_eq!(
                body["data"][0]["dispatch_contract"]["transport_shape"],
                "worker_initiated_outbound_polling"
            );
            assert_eq!(
                body["data"][0]["dispatch_contract"]["current_protocol_version"],
                1
            );
            assert_eq!(
                body["data"][0]["dispatch_contract"]["minimum_supported_protocol_version"],
                1
            );
            assert_eq!(
                body["data"][0]["dispatch_contract"]["lease_ack_implemented"],
                true
            );
            assert_eq!(
                body["data"][0]["dispatch_contract"]["inbound_customer_host_required"],
                false
            );
            // #243 Phase 2: the verified mutual-TLS transport core landed, so the
            // gateway now (correctly) reports the production transport as
            // implemented.
            assert_eq!(
                body["data"][0]["dispatch_contract"]["production_mtls_transport_implemented"],
                true
            );
            assert!(body["data"][0]["dispatch_contract"]["actions"]
                .as_array()
                .is_some_and(|actions| actions.iter().any(|action| action == "start_run")
                    && actions.iter().any(|action| action == "cancel_run")
                    && actions.iter().any(|action| action == "resume_run")
                    && actions.iter().any(|action| action == "close_session")));
            assert_eq!(body["data"][0]["registration_api"]["implemented"], true);
            assert_eq!(body["data"][0]["persistence"]["implemented"], false);
            assert_eq!(
                body["data"][0]["persistence"]["registration_implemented"],
                true
            );
            assert_eq!(body["data"][0]["persistence"]["detail_implemented"], true);
            assert_eq!(
                body["data"][0]["persistence"]["heartbeat_implemented"],
                true
            );
            assert_eq!(
                body["data"][0]["persistence"]["telemetry_event_implemented"],
                true
            );
            assert_eq!(
                body["data"][0]["persistence"]["artifact_metadata_implemented"],
                true
            );
            assert_eq!(
                body["data"][0]["persistence"]["checkpoint_metadata_implemented"],
                true
            );
            assert_eq!(
                body["data"][0]["persistence"]["identity_fingerprint_rotation_implemented"],
                true
            );
            assert_eq!(
                body["data"][0]["persistence"]["stale_visibility_implemented"],
                true
            );
            assert_eq!(
                body["data"][0]["persistence"]["worker_transport_implemented"],
                true
            );
            let transport_paths = body["data"][0]["persistence"]["worker_transport_paths"]
                .as_array()
                .context("self-hosted worker transport paths should be listed")?;
            for path in [
                "/v1/self-hosted-workers/heartbeat",
                "/v1/self-hosted-workers/events",
                "/v1/self-hosted-workers/artifacts",
                "/v1/self-hosted-workers/checkpoints",
                "/v1/self-hosted-workers/runs/poll",
                "/v1/self-hosted-workers/runs/ack",
            ] {
                assert!(
                    transport_paths.iter().any(|entry| entry == path),
                    "self-hosted worker transport path {path} should be listed"
                );
            }
            assert_eq!(body["data"][0]["persistence"]["provider"], "memory");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/self-hosted-worker-records",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "list");
            assert_eq!(body["data"].as_array().map(Vec::len), Some(0));
            assert_eq!(body["total"], 0);
            assert_eq!(body["offset"], 0);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/self-hosted-workers",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "tenant": {
            "organization_id": "org_demo",
            "project_id": "project_gateway",
            "api_key_id": "key_admin"
          },
          "workspace_id": "workspace-1",
          "worker_name": "customer-worker-invalid",
          "identity_fingerprint": "sha256:test-worker-invalid",
          "orchestration_enabled": true,
          "capability_envelope_json": "{not-json"
        }"#,
        400,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_registration"
            );
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("capability_envelope_json")));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/self-hosted-workers",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "tenant": {
            "organization_id": "org_demo",
            "project_id": "project_gateway",
            "api_key_id": "key_admin"
          },
          "workspace_id": "workspace-1",
          "worker_name": "customer-worker-a",
          "identity_fingerprint": "sha256:test-worker",
          "identity_expires_at_unix": 9999999999,
          "orchestration_enabled": true,
          "capability_envelope_json": "{\"frameworks\":[\"codex\"],\"capabilities\":[\"shell\",\"mcp\"]}"
        }"#,
        201,
        |body| {
            assert_eq!(body["object"], "self_hosted_worker");
            let worker_id = body["worker"]["id"]
                .as_str()
                .context("self-hosted worker id should be present")?;
            assert!(worker_id.starts_with("self-hosted-worker-"));
            self_hosted_worker_id.replace(worker_id.to_string());
            let transport_token_secret = body["transport_token_secret"]
                .as_str()
                .context("registration must return the provisioned transport_token_secret")?;
            assert!(!transport_token_secret.is_empty());
            assert_ne!(
                transport_token_secret, "sha256:test-worker",
                "the provisioned transport secret must NOT be the public fingerprint"
            );
            self_hosted_worker_secret.replace(transport_token_secret.to_string());
            assert_eq!(body["worker"]["workspace_id"], "workspace-1");
            assert_eq!(body["worker"]["worker_name"], "customer-worker-a");
            assert_eq!(body["worker"]["status"], "registered");
            assert_eq!(body["worker"]["identity_fingerprint"], "sha256:test-worker");
            assert_eq!(body["worker"]["identity_expires_at_unix"], 9999999999_u64);
            assert_eq!(body["worker"]["orchestration_enabled"], true);
            assert_eq!(
                body["worker"]["trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(body["worker"]["stale"], false);
            assert!(body["worker"]["stale_after_unix"].is_null());
            assert_eq!(body["worker"]["stale_threshold_secs"], 300);
            assert_eq!(body["worker"]["telemetry_event_count"], 0);
            assert_eq!(body["worker"]["artifact_count"], 0);
            assert_eq!(body["worker"]["checkpoint_count"], 0);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/self-hosted-workers",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "tenant": {
            "organization_id": "org_demo",
            "project_id": "project_gateway",
            "api_key_id": "key_admin"
          },
          "workspace_id": "workspace-1",
          "worker_name": "customer-worker-expired",
          "identity_fingerprint": "sha256:test-worker",
          "identity_expires_at_unix": 999,
          "orchestration_enabled": true
        }"#,
        201,
        |body| {
            assert_eq!(body["object"], "self_hosted_worker");
            let worker_id = body["worker"]["id"]
                .as_str()
                .context("expired self-hosted worker id should be present")?;
            expired_self_hosted_worker_id.replace(worker_id.to_string());
            let transport_token_secret = body["transport_token_secret"]
                .as_str()
                .context("registration must return the provisioned transport_token_secret")?;
            expired_self_hosted_worker_secret.replace(transport_token_secret.to_string());
            assert_eq!(body["worker"]["identity_expires_at_unix"], 999_u64);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_poll_body(
            &expired_self_hosted_worker_id.borrow(),
            "sha256:test-worker",
            &expired_self_hosted_worker_secret.borrow(),
        ),
        401,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_identity");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("expired")));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &[JSON_CONTENT],
        &self_hosted_worker_poll_body(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker",
            &self_hosted_worker_secret.borrow(),
        ),
        401,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_transport_security"
            );
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_poll_body(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker",
            "sha256:wrong-worker",
        ),
        401,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_identity");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_poll_body_for_scope(
            "org_other",
            "workspace-1",
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker",
            &self_hosted_worker_secret.borrow(),
        ),
        401,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_identity");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        "{",
        400,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_transport"
            );
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &oversized_self_hosted_transport_body(),
        413,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "self_hosted_worker_payload_too_large"
            );
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_poll_body_with_protocol(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker",
            &self_hosted_worker_secret.borrow(),
            0,
        ),
        400,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_transport"
            );
            Ok(())
        },
    )?;
    let tampered_encrypted_poll_body = tampered_encrypted_self_hosted_worker_poll_body(
        &self_hosted_worker_id.borrow(),
        "sha256:test-worker",
        &self_hosted_worker_secret.borrow(),
        31,
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &[JSON_CONTENT, SELF_HOSTED_SYMMETRIC_AEAD_HEADER],
        &tampered_encrypted_poll_body,
        400,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_transport"
            );
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("failed authentication")));
            Ok(())
        },
    )?;
    let encrypted_poll_body = encrypted_self_hosted_worker_poll_body(
        &self_hosted_worker_id.borrow(),
        "sha256:test-worker",
        &self_hosted_worker_secret.borrow(),
        32,
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &[JSON_CONTENT, SELF_HOSTED_SYMMETRIC_AEAD_HEADER],
        &encrypted_poll_body,
        200,
        |body| {
            let body = decrypted_self_hosted_transport_response(
                body,
                &self_hosted_worker_secret.borrow(),
            )?;
            assert_eq!(body["object"], "self_hosted_run_lease");
            assert_eq!(
                body["dispatch_id"],
                format!("self-hosted-dispatch-{}", self_hosted_worker_id.borrow())
            );
            assert_eq!(body["worker_id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["tenant_id"], "org_demo");
            assert_eq!(body["workspace_id"], "workspace-1");
            assert_eq!(body["action"], "start_run");
            assert_eq!(body["framework_adapter"], "codex");
            assert_eq!(body["required_capabilities"][0], "shell");
            assert_eq!(body["trust_level"], "reported_by_self_hosted_worker");
            let lease_id = body["lease_id"]
                .as_str()
                .context("self-hosted worker lease id should be present")?;
            self_hosted_lease_id.replace(lease_id.to_string());
            Ok(())
        },
    )?;
    let encrypted_ack_body = encrypted_self_hosted_worker_ack_body(
        &self_hosted_worker_id.borrow(),
        "sha256:test-worker",
        &self_hosted_worker_secret.borrow(),
        &self_hosted_lease_id.borrow(),
        33,
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/ack",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        "{",
        400,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_transport"
            );
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/ack",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &oversized_self_hosted_transport_body(),
        413,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "self_hosted_worker_payload_too_large"
            );
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/ack",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_ack_body_for_scope(
            "org_demo",
            "workspace-other",
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker",
            &self_hosted_worker_secret.borrow(),
            &self_hosted_lease_id.borrow(),
        ),
        401,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_identity");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/runs/ack",
        &[JSON_CONTENT, SELF_HOSTED_SYMMETRIC_AEAD_HEADER],
        &encrypted_ack_body,
        200,
        |body| {
            let body = decrypted_self_hosted_transport_response(
                body,
                &self_hosted_worker_secret.borrow(),
            )?;
            assert_eq!(body["object"], "self_hosted_run_ack");
            assert_eq!(
                body["dispatch_id"],
                format!("self-hosted-dispatch-{}", self_hosted_worker_id.borrow())
            );
            assert_eq!(body["lease_id"], *self_hosted_lease_id.borrow());
            assert_eq!(body["worker_id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["action"], "start_run");
            assert_eq!(body["status"], "accepted");
            assert_eq!(body["trust_level"], "reported_by_self_hosted_worker");
            Ok(())
        },
    )?;
    let self_hosted_worker_detail_path = format!(
        "/admin/v1/self-hosted-workers/{}",
        self_hosted_worker_id.borrow()
    );
    case.expect_json(
        "GET",
        &self_hosted_worker_detail_path,
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["workspace_id"], "workspace-1");
            assert_eq!(body["worker_name"], "customer-worker-a");
            assert_eq!(body["status"], "registered");
            assert_eq!(body["identity_fingerprint"], "sha256:test-worker");
            assert_eq!(body["identity_expires_at_unix"], 9999999999_u64);
            assert_eq!(body["orchestration_enabled"], true);
            assert_eq!(body["trust_level"], "reported_by_self_hosted_worker");
            assert_eq!(body["stale"], false);
            assert!(body["stale_after_unix"].is_null());
            assert_eq!(body["stale_threshold_secs"], 300);
            assert_eq!(body["telemetry_event_count"], 0);
            assert_eq!(body["artifact_count"], 0);
            assert_eq!(body["checkpoint_count"], 0);
            Ok(())
        },
    )?;
    let self_hosted_worker_rotate_path = format!("{self_hosted_worker_detail_path}/rotate");
    case.expect_json(
        "POST",
        &self_hosted_worker_rotate_path,
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "identity_fingerprint": "sha256:test-worker-rotated",
          "identity_expires_at_unix": 8888888888
        }"#,
        200,
        |body| {
            assert_eq!(body["object"], "self_hosted_worker_identity_rotation");
            assert_eq!(body["worker"]["id"], *self_hosted_worker_id.borrow());
            assert_eq!(
                body["worker"]["identity_fingerprint"],
                "sha256:test-worker-rotated"
            );
            assert_eq!(body["worker"]["identity_expires_at_unix"], 8888888888_u64);
            assert_eq!(body["previous_identity_fingerprint"], "sha256:test-worker");
            assert_eq!(body["previous_identity_expires_at_unix"], 9999999999_u64);
            assert!(body["rotated_at_unix"].as_u64().is_some());
            // Rotation issues a fresh transport secret; capture it so every
            // post-rotation transport call keys off the new secret (#248).
            let transport_token_secret = body["transport_token_secret"]
                .as_str()
                .context("rotation must return the freshly-issued transport_token_secret")?;
            assert!(!transport_token_secret.is_empty());
            assert_ne!(transport_token_secret, *self_hosted_worker_secret.borrow());
            self_hosted_worker_secret.replace(transport_token_secret.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        &self_hosted_worker_detail_path,
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["identity_fingerprint"], "sha256:test-worker-rotated");
            assert_eq!(body["identity_expires_at_unix"], 8888888888_u64);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/heartbeat",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_heartbeat_body(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker",
            &self_hosted_worker_secret.borrow(),
            "online",
            124,
        ),
        401,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_identity");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/heartbeat",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_heartbeat_body_with_payload(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "online",
            125,
            "{not-json",
        ),
        400,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_heartbeat"
            );
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("heartbeat_json")));
            Ok(())
        },
    )?;
    let encrypted_heartbeat_body = encrypted_self_hosted_transport_body(
        &self_hosted_worker_id.borrow(),
        "sha256:test-worker-rotated",
        &self_hosted_worker_secret.borrow(),
        &self_hosted_worker_heartbeat_body(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "online",
            125,
        ),
        41,
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/heartbeat",
        &[JSON_CONTENT, SELF_HOSTED_SYMMETRIC_AEAD_HEADER],
        &encrypted_heartbeat_body,
        201,
        |body| {
            let body = decrypted_self_hosted_transport_response(
                body,
                &self_hosted_worker_secret.borrow(),
            )?;
            assert_eq!(body["object"], "self_hosted_worker_heartbeat");
            assert_eq!(body["worker"]["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["worker"]["status"], "online");
            assert_eq!(body["heartbeat"]["status"], "online");
            assert_eq!(body["heartbeat"]["reported_at_unix"], 125);
            assert!(body["heartbeat"]["observed_at_unix"].as_u64().is_some());
            Ok(())
        },
    )?;
    let self_hosted_worker_heartbeat_path = format!("{self_hosted_worker_detail_path}/heartbeat");
    case.expect_json(
        "POST",
        &self_hosted_worker_heartbeat_path,
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "status": "online",
          "reported_at_unix": 122,
          "heartbeat_json": "{not-json"
        }"#,
        400,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_heartbeat"
            );
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("heartbeat_json")));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        &self_hosted_worker_heartbeat_path,
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "status": "online",
          "reported_at_unix": 126,
          "heartbeat_json": "{\"load\":0.42}"
        }"#,
        201,
        |body| {
            assert_eq!(body["object"], "self_hosted_worker_heartbeat");
            assert_eq!(body["worker"]["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["worker"]["status"], "online");
            assert_eq!(
                body["worker"]["latest_heartbeat"]["id"],
                body["heartbeat"]["id"]
            );
            assert_eq!(body["heartbeat"]["status"], "online");
            assert_eq!(body["heartbeat"]["reported_at_unix"], 126);
            assert!(body["heartbeat"]["observed_at_unix"].as_u64().is_some());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        &self_hosted_worker_detail_path,
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["status"], "online");
            assert_eq!(body["latest_heartbeat"]["status"], "online");
            assert_eq!(body["latest_heartbeat"]["reported_at_unix"], 126);
            assert!(body["last_seen_at_unix"].as_u64().is_some());
            assert_eq!(body["stale"], false);
            assert!(body["stale_after_unix"].as_u64().is_some());
            assert_eq!(body["stale_threshold_secs"], 300);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/events",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_event_body(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "unknown",
            449,
        ),
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_event");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("kind must be one of")));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/events",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_event_body_with_payload(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "lifecycle",
            450,
            "{not-json",
        ),
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_event");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("event_json")));
            Ok(())
        },
    )?;
    let encrypted_event_body = encrypted_self_hosted_transport_body(
        &self_hosted_worker_id.borrow(),
        "sha256:test-worker-rotated",
        &self_hosted_worker_secret.borrow(),
        &self_hosted_worker_event_body(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "lifecycle",
            450,
        ),
        42,
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/events",
        &[JSON_CONTENT, SELF_HOSTED_SYMMETRIC_AEAD_HEADER],
        &encrypted_event_body,
        201,
        |body| {
            let body = decrypted_self_hosted_transport_response(
                body,
                &self_hosted_worker_secret.borrow(),
            )?;
            assert_eq!(body["object"], "self_hosted_worker_event");
            assert_eq!(body["worker"]["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["worker"]["telemetry_event_count"], 1);
            assert_eq!(body["worker"]["latest_event_at_unix"], 450);
            assert_eq!(body["event"]["worker_id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["event"]["session_id"], "session-transport");
            assert_eq!(body["event"]["run_id"], "run-transport");
            assert_eq!(body["event"]["kind"], "lifecycle");
            assert_eq!(
                body["event"]["trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(body["event"]["occurred_at_unix"], 450);
            assert!(body["event"]["ingested_at_unix"].as_u64().is_some());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/self-hosted-runs/run-transport",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "self_hosted_run_timeline");
            assert_eq!(body["run_id"], "run-transport");
            assert_eq!(body["session_ids"][0], "session-transport");
            assert_eq!(body["worker_ids"][0], *self_hosted_worker_id.borrow());
            assert_eq!(body["trust_level"], "reported_by_self_hosted_worker");
            assert_eq!(body["reported_event_count"], 1);
            assert_eq!(body["lifecycle_event_count"], 1);
            assert_eq!(body["latest_lifecycle_state"], "running");
            assert_eq!(body["events"][0]["kind"], "lifecycle");
            assert_eq!(
                body["events"][0]["trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(body["events"][0]["event_json"], r#"{"state":"running"}"#);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/self-hosted-runs/missing-run",
        &[ADMIN_AUTH],
        "",
        404,
        |body| {
            assert_eq!(body["error"]["code"], "self_hosted_run_not_found");
            Ok(())
        },
    )?;
    let self_hosted_worker_events_path = format!("{self_hosted_worker_detail_path}/events");
    case.expect_json(
        "POST",
        &self_hosted_worker_events_path,
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "session_id": "session-1",
          "run_id": "run-1",
          "kind": "unknown",
          "occurred_at_unix": 455,
          "event_json": "{\"message\":\"bad kind\"}"
        }"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_event");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("kind must be one of")));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        &self_hosted_worker_events_path,
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "session_id": "session-1",
          "run_id": "run-1",
          "kind": "tool_call",
          "occurred_at_unix": 456,
          "event_json": "{\"tool\":\"shell\"}"
        }"#,
        201,
        |body| {
            assert_eq!(body["object"], "self_hosted_worker_event");
            assert_eq!(body["worker"]["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["worker"]["telemetry_event_count"], 2);
            assert_eq!(body["worker"]["latest_event_at_unix"], 456);
            assert_eq!(body["event"]["worker_id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["event"]["session_id"], "session-1");
            assert_eq!(body["event"]["run_id"], "run-1");
            assert_eq!(body["event"]["kind"], "tool_call");
            assert_eq!(
                body["event"]["trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(body["event"]["occurred_at_unix"], 456);
            assert!(body["event"]["ingested_at_unix"].as_u64().is_some());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        &format!("{self_hosted_worker_events_path}?limit=1"),
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "self_hosted_worker_event_stream");
            assert_eq!(body["worker_id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["trust_level"], "reported_by_self_hosted_worker");
            assert_eq!(body["total"], 2);
            assert_eq!(body["limit"], 1);
            assert!(body["after_event_id"].is_null());
            assert_eq!(body["data"].as_array().map(Vec::len), Some(1));
            assert_eq!(body["data"][0]["kind"], "lifecycle");
            assert_eq!(body["data"][0]["event_json"], r#"{"state":"running"}"#);
            let cursor = body["next_after_event_id"]
                .as_str()
                .context("self-hosted event stream cursor should be present")?;
            assert!(cursor.starts_with("self-hosted-event-"));
            self_hosted_event_cursor.replace(cursor.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        &format!(
            "{self_hosted_worker_events_path}?after_event_id={}&limit=10",
            self_hosted_event_cursor.borrow()
        ),
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "self_hosted_worker_event_stream");
            assert_eq!(body["after_event_id"], *self_hosted_event_cursor.borrow());
            assert_eq!(body["data"].as_array().map(Vec::len), Some(1));
            assert_eq!(body["data"][0]["kind"], "tool_call");
            assert_eq!(body["data"][0]["run_id"], "run-1");
            assert_eq!(body["next_after_event_id"], body["data"][0]["id"]);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/self-hosted-workers/missing-worker/events",
        &[ADMIN_AUTH],
        "",
        404,
        |body| {
            assert_eq!(body["error"]["code"], "self_hosted_worker_not_found");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        &self_hosted_worker_detail_path,
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["telemetry_event_count"], 2);
            assert_eq!(body["latest_event_at_unix"], 456);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/artifacts",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_artifact_body(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "artifact-transport-too-large",
            "transport-oversized.bin",
            16_777_217,
            786,
        ),
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_artifact");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("size_bytes")));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/artifacts",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_artifact_body_with_payload(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "artifact-transport-invalid-json",
            "transport-invalid-json.log",
            64,
            787,
            "{not-json",
        ),
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_artifact");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("artifact_json")));
            Ok(())
        },
    )?;
    let encrypted_artifact_body = encrypted_self_hosted_transport_body(
        &self_hosted_worker_id.borrow(),
        "sha256:test-worker-rotated",
        &self_hosted_worker_secret.borrow(),
        &self_hosted_worker_artifact_body(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "artifact-transport",
            "transport.log",
            64,
            787,
        ),
        43,
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/artifacts",
        &[JSON_CONTENT, SELF_HOSTED_SYMMETRIC_AEAD_HEADER],
        &encrypted_artifact_body,
        201,
        |body| {
            let body = decrypted_self_hosted_transport_response(
                body,
                &self_hosted_worker_secret.borrow(),
            )?;
            assert_eq!(body["object"], "self_hosted_worker_artifact");
            assert_eq!(body["worker"]["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["worker"]["artifact_count"], 1);
            assert_eq!(body["worker"]["latest_artifact_at_unix"], 787);
            assert_eq!(body["artifact"]["id"], "artifact-transport");
            assert_eq!(
                body["artifact"]["worker_id"],
                *self_hosted_worker_id.borrow()
            );
            assert_eq!(body["artifact"]["session_id"], "session-transport");
            assert_eq!(body["artifact"]["run_id"], "run-transport");
            assert_eq!(body["artifact"]["artifact_name"], "transport.log");
            assert_eq!(body["artifact"]["content_type"], "text/plain");
            assert_eq!(body["artifact"]["size_bytes"], 64);
            assert_eq!(
                body["artifact"]["trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(body["artifact"]["created_at_unix"], 787);
            Ok(())
        },
    )?;
    let self_hosted_worker_artifacts_path = format!("{self_hosted_worker_detail_path}/artifacts");
    case.expect_json(
        "POST",
        &self_hosted_worker_artifacts_path,
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "artifact_id": "artifact-too-large",
          "session_id": "session-1",
          "run_id": "run-1",
          "artifact_name": "oversized.bin",
          "content_type": "application/octet-stream",
          "size_bytes": 16777217,
          "created_at_unix": 788,
          "artifact_json": "{\"sha256\":\"oversized\"}"
        }"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_self_hosted_worker_artifact");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("size_bytes")));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        &self_hosted_worker_artifacts_path,
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "artifact_id": "artifact-1",
          "session_id": "session-1",
          "run_id": "run-1",
          "artifact_name": "stdout.log",
          "content_type": "text/plain",
          "size_bytes": 128,
          "created_at_unix": 789,
          "artifact_json": "{\"sha256\":\"abc\"}"
        }"#,
        201,
        |body| {
            assert_eq!(body["object"], "self_hosted_worker_artifact");
            assert_eq!(body["worker"]["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["worker"]["artifact_count"], 2);
            assert_eq!(body["worker"]["latest_artifact_at_unix"], 789);
            assert_eq!(body["artifact"]["id"], "artifact-1");
            assert_eq!(
                body["artifact"]["worker_id"],
                *self_hosted_worker_id.borrow()
            );
            assert_eq!(body["artifact"]["session_id"], "session-1");
            assert_eq!(body["artifact"]["run_id"], "run-1");
            assert_eq!(body["artifact"]["artifact_name"], "stdout.log");
            assert_eq!(body["artifact"]["content_type"], "text/plain");
            assert_eq!(body["artifact"]["size_bytes"], 128);
            assert_eq!(
                body["artifact"]["trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(body["artifact"]["created_at_unix"], 789);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        &self_hosted_worker_detail_path,
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["artifact_count"], 2);
            assert_eq!(body["latest_artifact_at_unix"], 789);
            Ok(())
        },
    )?;
    let self_hosted_worker_checkpoints_path =
        format!("{self_hosted_worker_detail_path}/checkpoints");
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/checkpoints",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_checkpoint_body(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "checkpoint-transport-too-large",
            "transport-oversized-state",
            16_777_217,
            888,
        ),
        400,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_checkpoint"
            );
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("size_bytes")));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/checkpoints",
        &[JSON_CONTENT, SELF_HOSTED_MTLS_HEADER],
        &self_hosted_worker_checkpoint_body_with_payload(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "checkpoint-transport-invalid-json",
            "transport-invalid-json-state",
            192,
            889,
            "{not-json",
        ),
        400,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_checkpoint"
            );
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("checkpoint_json")));
            Ok(())
        },
    )?;
    let encrypted_checkpoint_body = encrypted_self_hosted_transport_body(
        &self_hosted_worker_id.borrow(),
        "sha256:test-worker-rotated",
        &self_hosted_worker_secret.borrow(),
        &self_hosted_worker_checkpoint_body(
            &self_hosted_worker_id.borrow(),
            "sha256:test-worker-rotated",
            &self_hosted_worker_secret.borrow(),
            "checkpoint-transport",
            "transport-resume-state",
            192,
            889,
        ),
        44,
    )?;
    case.expect_json(
        "POST",
        "/v1/self-hosted-workers/checkpoints",
        &[JSON_CONTENT, SELF_HOSTED_SYMMETRIC_AEAD_HEADER],
        &encrypted_checkpoint_body,
        201,
        |body| {
            let body = decrypted_self_hosted_transport_response(
                body,
                &self_hosted_worker_secret.borrow(),
            )?;
            assert_eq!(body["object"], "self_hosted_worker_checkpoint");
            assert_eq!(body["worker"]["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["worker"]["checkpoint_count"], 1);
            assert_eq!(body["worker"]["latest_checkpoint_at_unix"], 889);
            assert_eq!(body["checkpoint"]["id"], "checkpoint-transport");
            assert_eq!(
                body["checkpoint"]["worker_id"],
                *self_hosted_worker_id.borrow()
            );
            assert_eq!(body["checkpoint"]["session_id"], "session-transport");
            assert_eq!(body["checkpoint"]["run_id"], "run-transport");
            assert_eq!(
                body["checkpoint"]["checkpoint_name"],
                "transport-resume-state"
            );
            assert_eq!(body["checkpoint"]["size_bytes"], 192);
            assert_eq!(
                body["checkpoint"]["trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(body["checkpoint"]["created_at_unix"], 889);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        &self_hosted_worker_checkpoints_path,
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "checkpoint_id": "checkpoint-too-large",
          "session_id": "session-1",
          "run_id": "run-1",
          "checkpoint_name": "oversized-state",
          "size_bytes": 16777217,
          "created_at_unix": 889,
          "checkpoint_json": "{\"sha256\":\"oversized\"}"
        }"#,
        400,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "invalid_self_hosted_worker_checkpoint"
            );
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("size_bytes")));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        &self_hosted_worker_checkpoints_path,
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{
          "checkpoint_id": "checkpoint-1",
          "session_id": "session-1",
          "run_id": "run-1",
          "checkpoint_name": "resume-state",
          "size_bytes": 256,
          "created_at_unix": 890,
          "checkpoint_json": "{\"sha256\":\"def\"}"
        }"#,
        201,
        |body| {
            assert_eq!(body["object"], "self_hosted_worker_checkpoint");
            assert_eq!(body["worker"]["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["worker"]["checkpoint_count"], 2);
            assert_eq!(body["worker"]["latest_checkpoint_at_unix"], 890);
            assert_eq!(body["checkpoint"]["id"], "checkpoint-1");
            assert_eq!(
                body["checkpoint"]["worker_id"],
                *self_hosted_worker_id.borrow()
            );
            assert_eq!(body["checkpoint"]["session_id"], "session-1");
            assert_eq!(body["checkpoint"]["run_id"], "run-1");
            assert_eq!(body["checkpoint"]["checkpoint_name"], "resume-state");
            assert_eq!(body["checkpoint"]["size_bytes"], 256);
            assert_eq!(
                body["checkpoint"]["trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(body["checkpoint"]["created_at_unix"], 890);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        &self_hosted_worker_detail_path,
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["id"], *self_hosted_worker_id.borrow());
            assert_eq!(body["checkpoint_count"], 2);
            assert_eq!(body["latest_checkpoint_at_unix"], 890);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/self-hosted-workers/missing-worker",
        &[ADMIN_AUTH],
        "",
        404,
        |body| {
            assert_eq!(body["error"]["code"], "self_hosted_worker_not_found");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/self-hosted-worker-records",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "list");
            assert_eq!(body["data"].as_array().map(Vec::len), Some(2));
            assert_eq!(body["total"], 2);
            assert_eq!(body["offset"], 0);
            let records = body["data"]
                .as_array()
                .context("self-hosted worker records data should be an array")?;
            let worker = records
                .iter()
                .find(|record| record["id"] == *self_hosted_worker_id.borrow())
                .context("registered self-hosted worker should be present in list")?;
            let expired_worker = records
                .iter()
                .find(|record| record["id"] == *expired_self_hosted_worker_id.borrow())
                .context("expired self-hosted worker should be present in list")?;
            assert_eq!(worker["workspace_id"], "workspace-1");
            assert_eq!(worker["worker_name"], "customer-worker-a");
            assert_eq!(worker["status"], "online");
            assert_eq!(worker["identity_fingerprint"], "sha256:test-worker-rotated");
            assert_eq!(worker["identity_expires_at_unix"], 8888888888_u64);
            assert_eq!(worker["orchestration_enabled"], true);
            assert_eq!(worker["trust_level"], "reported_by_self_hosted_worker");
            assert_eq!(worker["stale"], false);
            assert!(worker["stale_after_unix"].as_u64().is_some());
            assert_eq!(worker["stale_threshold_secs"], 300);
            assert_eq!(worker["latest_heartbeat"]["status"], "online");
            assert_eq!(worker["telemetry_event_count"], 2);
            assert_eq!(worker["latest_event_at_unix"], 456);
            assert_eq!(worker["artifact_count"], 2);
            assert_eq!(worker["latest_artifact_at_unix"], 789);
            assert_eq!(worker["checkpoint_count"], 2);
            assert_eq!(worker["latest_checkpoint_at_unix"], 890);
            assert_eq!(expired_worker["identity_expires_at_unix"], 999_u64);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/provider-models?provider=openai",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["data"][0]["provider"], "openai");
            assert_eq!(body["data"][0]["status"], "ok");
            assert!(array_contains(
                &body["data"][0],
                "models",
                "id",
                "provider-chat"
            ));
            let raw = body.to_string();
            assert_secret_redacted(&raw);
            assert!(!raw.contains("FERROGATE_PROVIDER_SECRET"));
            assert!(!raw.contains("provider-secret"));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/observability",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["data"][0]["provider"], "vector");
            assert_eq!(body["data"][0]["enabled"], true);
            assert_eq!(body["data"][0]["protocol"], "otlp_http_json");
            assert_eq!(body["data"][0]["prometheus_metrics_path"], "/metrics");
            assert!(body["data"][0]["endpoint"]
                .as_str()
                .is_some_and(|endpoint| endpoint.starts_with("http://127.0.0.1:")));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/extensions",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            Ok(())
        },
    )?;
    case.expect_json("GET", "/admin/v1/tools", &[ADMIN_AUTH], "", 200, |body| {
        assert!(body["data"].is_array());
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/admin/v1/tool-approvals",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "list");
            assert_eq!(body["total"], 0);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/tool-approvals/approval-missing/approve",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"fingerprint":"missing"}"#,
        404,
        |body| {
            assert_eq!(body["error"]["code"], "tool_approval_not_found");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/mcp-servers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            Ok(())
        },
    )?;

    let plugin = r#"{"id":"hook.noop.harness","kind":"request_hook","source":"builtin","enabled":true,"order":90,"permissions":{"tools":[],"network":[],"filesystem":false,"shell":false},"config":{"mode":"harness"}}"#;
    case.expect_json(
        "POST",
        "/admin/v1/plugins",
        &[ADMIN_AUTH, JSON_CONTENT],
        plugin,
        201,
        |body| {
            assert_eq!(body["plugin"]["id"], "hook.noop.harness");
            assert_eq!(body["plugin"]["kind"], "request_hook");
            assert_eq!(body["plugin"]["active"], true);
            assert_eq!(body["plugin"]["health"], "ok");
            assert_array_contains(&body["plugin"]["capabilities"], "request_hook")?;
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/plugins/hook.noop.harness",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["id"], "hook.noop.harness");
            assert_eq!(body["active"], true);
            assert_array_contains(&body["capabilities"], "request_hook")?;
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    let updated_plugin = r#"{"id":"hook.noop.harness","kind":"request_hook","source":"builtin","enabled":false,"order":90,"permissions":{"tools":[],"network":[],"filesystem":false,"shell":false},"config":{"mode":"harness-disabled"}}"#;
    case.expect_json(
        "PATCH",
        "/admin/v1/plugins/hook.noop.harness",
        &[ADMIN_AUTH, JSON_CONTENT],
        updated_plugin,
        200,
        |body| {
            assert_eq!(body["plugin"]["id"], "hook.noop.harness");
            assert_eq!(body["plugin"]["enabled"], false);
            assert_eq!(body["plugin"]["active"], false);
            assert_eq!(body["plugin"]["health"], "disabled");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/tool-sessions/ferrogate-test-session",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["total"], 0);
            Ok(())
        },
    )?;
    case.expect_json("GET", "/admin/v1/models", &[ADMIN_AUTH], "", 200, |body| {
        assert!(list_contains(&body, "name", "fast-chat"));
        Ok(())
    })?;
    case.expect_json("GET", "/admin/v1/tenants", &[ADMIN_AUTH], "", 200, |body| {
        assert!(body["data"].is_array());
        Ok(())
    })?;

    let api_key = r#"{"id":"test-client","name":"Test client","key":"test-secret","scopes":["models.read","chat.completions","responses.create"],"allowed_models":["fast-chat"],"organization_id":"org_test","project_id":"project_harness"}"#;
    case.expect_json(
        "POST",
        "/admin/v1/api-keys",
        &[ADMIN_AUTH, JSON_CONTENT],
        api_key,
        201,
        |body| {
            assert_eq!(body["key"]["id"], "test-client");
            assert_eq!(body["key"]["key_source"], "inline");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/api-keys/test-client",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["key"]["id"], "test-client");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    // #540: `api_key_from_mutation` is a full replace, so a PATCH that omits
    // organization_id sends a key that declares no tenant identity. It is
    // restated here rather than relied on: the binding SURVIVES today only
    // because `apply_tenant_refs_to_api_keys` re-applies it from the tenants
    // documents the create wrote, which is a re-merge two layers below the
    // request and not something a fixture should lean on silently.
    let updated_api_key = r#"{"id":"test-client","name":"Updated test client","key":"test-secret-2","scopes":["models.read","chat.completions","responses.create"],"allowed_models":["fast-chat"],"organization_id":"org_test","enabled":true}"#;
    case.expect_json(
        "PATCH",
        "/admin/v1/api-keys/test-client",
        &[ADMIN_AUTH, JSON_CONTENT],
        updated_api_key,
        200,
        |body| {
            assert_eq!(body["key"]["name"], "Updated test client");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;

    let policy = r#"{"name":"block-test-client","effect":"deny","api_key_ids":["test-client"],"models":["fast-chat"],"providers":["openai"],"code":"blocked_by_ferrogate_test","message":"blocked by ferrogate-test","enabled":true}"#;
    case.expect_json(
        "POST",
        "/admin/v1/policies",
        &[ADMIN_AUTH, JSON_CONTENT],
        policy,
        201,
        |body| {
            assert_eq!(body["policy"]["name"], "block-test-client");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/policies/block-test-client",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["policy"]["enabled"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[AUTH_TEST_CLIENT_2, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"policy denial coverage"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "blocked_by_ferrogate_test");
            assert_eq!(body["error"]["message"], "blocked by ferrogate-test");
            assert!(body["error"]["request_id"].is_string());
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    let disabled_policy = r#"{"name":"block-test-client","effect":"deny","api_key_ids":["test-client"],"models":["fast-chat"],"providers":["openai"],"code":"blocked_by_ferrogate_test","message":"blocked by ferrogate-test","enabled":false}"#;
    case.expect_json(
        "PATCH",
        "/admin/v1/policies/block-test-client",
        &[ADMIN_AUTH, JSON_CONTENT],
        disabled_policy,
        200,
        |body| {
            assert_eq!(body["policy"]["enabled"], false);
            Ok(())
        },
    )?;

    let gateway_config = r#"{"id":"harness-profile","name":"Harness profile","revision":2,"api_key_ids":["test-client"],"cache_enabled":false}"#;
    case.expect_json(
        "POST",
        "/admin/v1/gateway-configs",
        &[ADMIN_AUTH, JSON_CONTENT],
        gateway_config,
        201,
        |body| {
            assert_eq!(body["gateway_config"]["id"], "harness-profile");
            assert_eq!(body["gateway_config"]["cache_enabled"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/gateway-configs/harness-profile",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["gateway_config"]["revision"], 2);
            Ok(())
        },
    )?;

    // #542: `/admin/v1/config/validate` runs the gateway's own startup posture
    // gate, so a candidate config states whether it authenticates. Without the
    // `[auth]` section this candidate has no credential source at all and is
    // reported invalid -- the same answer `ferrogate run` would give it.
    let config_candidate = serde_json::json!({
        "config_toml": format!("listen = \"{}\"\n[auth]\ndisabled = true\n", case.gateway_addr)
    })
    .to_string();
    case.expect_json(
        "POST",
        "/admin/v1/config/validate",
        &[ADMIN_AUTH, JSON_CONTENT],
        &config_candidate,
        200,
        |body| {
            assert_eq!(body["valid"], true);
            assert_eq!(body["listener_reload_required"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/config/reload",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"config_toml":"listen = \"not-an-address\"\n"}"#,
        200,
        |body| {
            assert_eq!(body["valid"], false);
            assert_eq!(body["committed"], false);
            Ok(())
        },
    )?;
    case.expect_json("GET", "/admin/v1/drain", &[ADMIN_AUTH], "", 200, |body| {
        assert_eq!(body["draining"], false);
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/admin/v1/drain",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"drain":true}"#,
        200,
        |body| {
            assert_eq!(body["draining"], true);
            assert_eq!(body["accepting_new_requests"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/drain",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"drain":false}"#,
        200,
        |body| {
            assert_eq!(body["draining"], false);
            Ok(())
        },
    )?;

    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[AUTH_TEST_CLIENT_2, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"admin coverage"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/request-logs",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "logical_model", "fast-chat"));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/metering-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "logical_model", "fast-chat"));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/billing-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "logical_model", "fast-chat"));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/usage-aggregates",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/audit-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "action", "api_key.upsert"));
            assert!(list_contains(&body, "action", "policy.upsert"));
            assert!(list_contains(&body, "action", "gateway_config.upsert"));
            assert!(list_contains(&body, "action", "plugin.upsert"));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_text("GET", "/metrics", &[ADMIN_AUTH], "", 200, |body| {
        assert!(body.contains("ferrogate_request_logs_total"));
        Ok(())
    })?;
    thread::sleep(Duration::from_secs(6));
    case.expect_vector_otlp_export()?;

    case.expect_json(
        "DELETE",
        "/admin/v1/gateway-configs/harness-profile",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "DELETE",
        "/admin/v1/policies/block-test-client",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "DELETE",
        "/admin/v1/plugins/hook.noop.harness",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/audit-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "action", "plugin.delete"));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "DELETE",
        "/admin/v1/api-keys/test-client",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;

    assert_api_key_tenancy_enforcement(&case)?;

    println!("admin-api scenario passed");
    Ok(())
}

/// #340 acceptance box 4 -- "cross-tenant combinations are blocked client-side
/// AND rejected authoritatively by the API" -- as a runnable harness scenario.
///
/// The admin console cascades its workspace picker from the selected project,
/// but a UI convention is not an invariant: any curl, SDK or stale console build
/// posts straight to `/admin/v1/api-keys`. This drives the enforcement through a
/// real gateway process with the console entirely out of the loop, so the box
/// stays proved in `ferrogate-test ci` (which calls `run_admin_api`) and not only
/// in the crate's own integration test.
fn assert_api_key_tenancy_enforcement(case: &LocalHarness) -> Result<()> {
    for tenant in ["tenancy-box4-a", "tenancy-box4-b"] {
        case.expect_json(
            "POST",
            "/admin/v1/tenant-accounts",
            &[ADMIN_AUTH, JSON_CONTENT],
            &format!(r#"{{"id":"{tenant}","name":"{tenant}","slug":"{tenant}"}}"#),
            201,
            |_| Ok(()),
        )?;
    }
    for (project, tenant) in [
        ("box4-project-a", "tenancy-box4-a"),
        ("box4-project-b", "tenancy-box4-b"),
    ] {
        case.expect_json(
            "POST",
            "/admin/v1/projects",
            &[ADMIN_AUTH, JSON_CONTENT],
            &format!(
                r#"{{"id":"{project}","tenant_id":"{tenant}","name":"{project}","slug":"{project}"}}"#
            ),
            201,
            |_| Ok(()),
        )?;
    }
    for (workspace, project) in [
        ("box4-workspace-a", "box4-project-a"),
        ("box4-workspace-b", "box4-project-b"),
    ] {
        case.expect_json(
            "POST",
            "/admin/v1/workspaces",
            &[ADMIN_AUTH, JSON_CONTENT],
            &format!(
                r#"{{"id":"{workspace}","project_id":"{project}","name":"{workspace}","slug":"{workspace}"}}"#
            ),
            201,
            |_| Ok(()),
        )?;
    }

    // A consistent triple is the control: the rejections below must come from the
    // tenancy check, not from some unrelated validation of this payload shape.
    case.expect_json(
        "POST",
        "/admin/v1/api-keys",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"box4-consistent","name":"Consistent","key":"box4-consistent-secret","organization_id":"tenancy-box4-a","project_id":"box4-project-a","workspace_id":"box4-workspace-a"}"#,
        201,
        |body| {
            assert_eq!(body["key"]["project_id"], "box4-project-a");
            assert_eq!(body["key"]["workspace_id"], "box4-workspace-a");
            Ok(())
        },
    )?;

    // Project A paired with project B's workspace: the exact combination the
    // console cascade prevents, refused server-side with the same payload.
    case.expect_json(
        "POST",
        "/admin/v1/api-keys",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"box4-cross-project","name":"Cross project","key":"box4-cross-secret","project_id":"box4-project-a","workspace_id":"box4-workspace-b"}"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_api_key");
            assert!(
                body["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("box4-workspace-b"),
                "rejection must name the offending workspace: {body}"
            );
            Ok(())
        },
    )?;

    // A project owned by a tenant other than the key's declared organization.
    case.expect_json(
        "POST",
        "/admin/v1/api-keys",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"box4-cross-tenant","name":"Cross tenant","key":"box4-cross-tenant-secret","organization_id":"tenancy-box4-a","project_id":"box4-project-b"}"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_api_key");
            Ok(())
        },
    )?;

    // Neither rejected key reached the runtime snapshot.
    for rejected in ["box4-cross-project", "box4-cross-tenant"] {
        case.expect_json(
            "GET",
            &format!("/admin/v1/api-keys/{rejected}"),
            &[ADMIN_AUTH],
            "",
            404,
            |_| Ok(()),
        )?;
    }

    // The update path enforces the same invariant: a key stored with a legal
    // pair cannot be walked into an illegal one.
    case.expect_json(
        "PUT",
        "/admin/v1/api-keys/box4-consistent",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"box4-consistent","name":"Consistent","key":"box4-consistent-secret","project_id":"box4-project-a","workspace_id":"box4-workspace-b"}"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_api_key");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/api-keys/box4-consistent",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(
                body["key"]["workspace_id"], "box4-workspace-a",
                "the refused update must not have been persisted: {body}"
            );
            Ok(())
        },
    )?;

    case.expect_json(
        "DELETE",
        "/admin/v1/api-keys/box4-consistent",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;

    // --- GET /admin/v1/overview (#339 contract, #343 cockpit) ---------------
    //
    // The admin console's cockpit renders THIS payload. Its whole honesty rule
    // ("never render a value it cannot know") is only as good as the wire shape
    // it parses, and the shape had already drifted once undetected: the console
    // read a `self_hosted_workers.by_status.active` bucket no gateway code path
    // writes, and typed `virtual_keys` as a number after #458 made it an object
    // (rendering "NaN"). Both defects were invisible to every unit test on both
    // sides, because both sides only ever saw their own fixtures. This case is
    // the end-to-end check: it asserts the shape against the LIVE gateway.
    case.expect_json(
        "GET",
        "/admin/v1/overview",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "control_plane.overview");
            assert!(
                body["generated_at_unix"].as_u64().is_some_and(|at| at > 0),
                "overview must carry a generated timestamp: {body}"
            );
            // A key with no organization sees the global scope.
            assert_eq!(body["scope"]["kind"], "global");

            // All four sections are present and each declares a status + source, so
            // the console can distinguish `ok` from `unavailable` per section.
            for section in ["runtime", "control_plane", "usage", "alerts"] {
                let status = body[section]["status"].as_str().unwrap_or_default();
                assert!(
                    status == "ok" || status == "unavailable",
                    "overview section {section} must declare ok|unavailable, got {status}: {body}"
                );
                assert!(
                    body[section]["source"].is_string(),
                    "overview section {section} must name its source: {body}"
                );
                if status == "unavailable" {
                    assert!(
                        body[section]["data"].is_null(),
                        "an unavailable section must carry no payload (never a zeroed one): {body}"
                    );
                }
            }

            // Runtime is config-derived and must always be available.
            assert_eq!(body["runtime"]["status"], "ok");
            let runtime = &body["runtime"]["data"];
            assert!(runtime["providers"]["total"].as_u64().is_some());
            assert!(runtime["providers"]["enabled"].as_u64().is_some());
            assert!(runtime["mcp_servers"]["connected"].as_u64().is_some());
            assert!(runtime["mcp_servers"]["disconnected"].as_u64().is_some());

            // Usage carries BOTH a lifetime and a current-month rollup, keyed by an
            // explicit `YYYY-MM`. This is the #343 box-2 provenance guarantee: the
            // console's global token total comes from a durable aggregate that also
            // reports its own period, not from whichever usage report happened to
            // be latest. A single unlabelled total could not satisfy it.
            assert_eq!(body["usage"]["status"], "ok");
            let usage = &body["usage"]["data"];
            let period = usage["current_period_month"].as_str().unwrap_or_default();
            assert!(
                period.len() == 7 && period.as_bytes()[4] == b'-',
                "usage must state its current period as YYYY-MM, got {period:?}: {body}"
            );
            let lifetime = usage["lifetime"]["total_tokens"]
                .as_u64()
                .unwrap_or_else(|| panic!("usage.lifetime.total_tokens must be a number: {body}"));
            let month = usage["current_month"]["total_tokens"]
                .as_u64()
                .unwrap_or_else(|| {
                    panic!("usage.current_month.total_tokens must be a number: {body}")
                });
            assert!(
                month <= lifetime,
                "the current month must be a subset of lifetime ({month} > {lifetime}): {body}"
            );
            for field in [
                "prompt_tokens",
                "completion_tokens",
                "total_tokens",
                "request_count",
                "error_count",
            ] {
                assert!(
                    usage["lifetime"][field].as_u64().is_some(),
                    "usage.lifetime.{field} must be a number: {body}"
                );
            }
            assert!(usage["lifetime"]["cost_usd"].as_f64().is_some());

            assert_eq!(body["control_plane"]["status"], "ok");
            let control_plane = &body["control_plane"]["data"];

            // #343 box 4, the exact defect d68fe9b fixed: the console derives
            // "healthy workers" from the status labels the gateway REALLY writes
            // (`registered` on registration, the worker-reported `online` on
            // heartbeat). It deliberately does not recognize `active`. If the
            // gateway ever emitted `active`, the console would render N/A for a
            // healthy fleet — so pin the live label set here rather than in a
            // fixture that can be edited to agree with the bug.
            let by_status = control_plane["self_hosted_workers"]["by_status"]
                .as_object()
                .unwrap_or_else(|| {
                    panic!("self_hosted_workers.by_status must be an object: {body}")
                });
            assert!(
                !by_status.contains_key("active"),
                "the gateway must not emit an `active` worker status (the console cannot \
             classify it and renders N/A): {body}"
            );
            assert!(
                by_status
                    .keys()
                    .any(|status| status == "registered" || status == "online"),
                "this harness registered self-hosted workers, so the histogram must carry a \
             `registered`/`online` bucket the console can classify as healthy: {body}"
            );
            for (status, count) in by_status {
                assert!(
                    count.as_u64().is_some(),
                    "worker status bucket {status} must be a number: {body}"
                );
            }
            assert!(control_plane["self_hosted_workers"]["total"]
                .as_u64()
                .is_some());

            // #458 shapes the console parses. `virtual_keys` is an OBJECT: the day
            // it was a bare number the cockpit printed "NaN" on screen.
            assert!(
                control_plane["virtual_keys"].is_object(),
                "virtual_keys must be a {{total,enabled}} object, not a bare number: {body}"
            );
            assert!(control_plane["virtual_keys"]["total"].as_u64().is_some());
            assert!(control_plane["virtual_keys"]["enabled"].as_u64().is_some());
            for field in ["count", "storage_bytes", "referenced", "unreferenced"] {
                assert!(
                    control_plane["assets"][field].as_u64().is_some(),
                    "assets.{field} must be a number: {body}"
                );
            }
            // Not-applicable is NULL, never a fabricated zero: there is no single
            // per-scope asset-storage quota for the global view.
            assert!(
                control_plane["assets"]["storage_quota_bytes"].is_null(),
                "the global scope has no applicable asset-storage quota; it must be \
             null, never 0: {body}"
            );
            assert!(control_plane["pending_tool_approvals"].as_u64().is_some());
            assert!(control_plane["quota_pressure"].is_array());
            // Policy governance is global-only; it is populated here and `null` for
            // a tenant-scoped caller (distinct from zero).
            for field in [
                "guardrail_policy_revisions",
                "guardrail_policy_bindings",
                "quota_policies",
                "policy_rules",
            ] {
                assert!(
                    control_plane["policy_governance"][field].as_u64().is_some(),
                    "policy_governance.{field} must be a number at global scope: {body}"
                );
            }
            assert!(control_plane["agent_runs"]["total"].as_u64().is_some());
            assert!(control_plane["agent_runs"]["by_status"].is_object());

            // The alert summary is bounded and every entry is triageable: the
            // console maps `kind` to a title + pivot link, and an entry it cannot
            // read is counted as an unreadable alert rather than dropped.
            assert_eq!(body["alerts"]["status"], "ok");
            let alerts = &body["alerts"]["data"];
            assert!(alerts["total"].as_u64().is_some());
            assert!(alerts["truncated"].is_boolean());
            assert!(alerts["unavailable_sources"].is_array());
            let entries = alerts["entries"]
                .as_array()
                .unwrap_or_else(|| panic!("alerts.entries must be an array: {body}"));
            for entry in entries {
                assert!(
                    entry["kind"].is_string() && entry["severity"].is_string(),
                    "every alert must carry a kind + severity the console can title: {body}"
                );
                assert!(entry["summary"].is_string());
                assert!(entry["evidence"].is_array());
                assert!(entry["evidence_truncated"].is_boolean());
            }
            Ok(())
        },
    )?;

    // The overview reads the whole control plane, so it is gated on
    // `admin.read`: an unauthenticated caller and a key without the scope are
    // both refused rather than served a zeroed payload.
    case.expect_json("GET", "/admin/v1/overview", &[], "", 401, |body| {
        assert!(body["error"]["code"].is_string());
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/admin/v1/overview",
        &[OBSERVER_AUTH],
        "",
        403,
        |body| {
            assert!(body["error"]["code"].is_string());
            Ok(())
        },
    )?;

    // A TENANT-SCOPED reader (the `client` key holds `admin.read` and declares
    // `organization_id = org_demo`) gets the same contract narrowed to its own
    // tenant — and this is where #343's "not-applicable is distinct from zero"
    // rule is proven against the live gateway rather than a fixture. Guardrail
    // revisions, quota policies, and policy rules are not per-tenant
    // attributable, so the gateway sends `policy_governance: null`; the console
    // renders that whole group as N/A. Were it ever serialized as a zeroed
    // object, the cockpit would confidently report "0 policy rules" to a tenant
    // whose platform has many — the precise fabrication the issue forbids.
    case.expect_json(
        "GET",
        "/admin/v1/overview",
        &[CLIENT_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["scope"]["kind"], "tenant");
            assert_eq!(body["scope"]["tenant_id"], "org_demo");
            assert!(
                body["control_plane"]["data"]["policy_governance"].is_null(),
                "policy governance is not attributable per tenant; it must be null, \
             never a zeroed object: {body}"
            );
            assert!(
                body["control_plane"]["data"]["assets"]["storage_quota_bytes"].is_null(),
                "a tenant without an explicit asset-storage quota override has no \
             applicable quota; it must be null, never 0: {body}"
            );
            // The rest of the contract is unchanged in shape, so the same console
            // parser handles both scopes.
            assert!(body["control_plane"]["data"]["virtual_keys"].is_object());
            assert!(body["usage"]["data"]["current_month"]["total_tokens"]
                .as_u64()
                .is_some());
            Ok(())
        },
    )?;

    Ok(())
}

pub(crate) fn run_auth_api(args: &AuthArgs) -> Result<()> {
    let case = AuthHarness::start(&args.ferrogate_auth_bin)?;

    case.expect_json("GET", "/healthz", &[], "", 200, |body| {
        assert_eq!(body["service"], "ferrogate-auth");
        assert_eq!(body["status"], "ok");
        Ok(())
    })?;
    case.expect_json("GET", "/v1/healthz", &[], "", 200, |body| {
        assert_eq!(body["service"], "ferrogate-auth");
        Ok(())
    })?;
    case.expect_json("GET", "/v1/tenants", &[], "", 200, |body| {
        assert!(array_contains(&body, "tenants", "id", "tenant-example"));
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/v1/auth/resolve-api-key",
        &[JSON_CONTENT],
        r#"{"presented_key":"dev-secret"}"#,
        200,
        |body| {
            assert_eq!(body["tenant"]["organization_id"], "org-example");
            assert_eq!(body["subject"]["type"], "api_key");
            assert_eq!(body["scopes"][0], "models.read");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/auth/authorize",
        &[JSON_CONTENT],
        r#"{"tenant":{"organization_id":"org-example","team_id":"team-example","project_id":"project-example","user_id":null,"api_key_id":"key-example"},"subject":{"type":"api_key","api_key_id":"key-example"},"action":"chat.completions","resource":"model:fast-chat"}"#,
        200,
        |body| {
            assert_eq!(body["allowed"], true);
            assert_eq!(body["reason"], "matched_rbac_binding");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/auth/authorize",
        &[JSON_CONTENT],
        r#"{"tenant":{"organization_id":"org-example","team_id":"team-example","project_id":"project-example","user_id":null,"api_key_id":"key-example"},"subject":{"type":"api_key","api_key_id":"key-example"},"action":"responses.create","resource":"model:fast-chat"}"#,
        200,
        |body| {
            assert_eq!(body["allowed"], false);
            assert_eq!(body["reason"], "no_matching_rbac_binding");
            Ok(())
        },
    )?;

    // --- Scenario coverage: api-key resolution failure and multi-tenant paths (#103) ---

    // Unknown secret must fail closed with 401 invalid_api_key.
    case.expect_json(
        "POST",
        "/v1/auth/resolve-api-key",
        &[JSON_CONTENT],
        r#"{"presented_key":"not-a-real-secret"}"#,
        401,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_api_key");
            Ok(())
        },
    )?;

    // A second tenant's key resolves to that tenant and subject, not a shared one.
    case.expect_json(
        "POST",
        "/v1/auth/resolve-api-key",
        &[JSON_CONTENT],
        r#"{"presented_key":"client-secret"}"#,
        200,
        |body| {
            assert_eq!(body["tenant"]["organization_id"], "org_demo");
            assert_eq!(body["subject"]["api_key_id"], "client");
            Ok(())
        },
    )?;

    // Malformed request body must be rejected as invalid_json, not silently accepted.
    case.expect_json(
        "POST",
        "/v1/auth/resolve-api-key",
        &[JSON_CONTENT],
        "this is not json",
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_json");
            Ok(())
        },
    )?;

    // --- Scenario coverage: RBAC wildcard, cross-tenant isolation, second tenant (#103) ---

    // Wildcard resource permission (`models.read` on `*`) grants any resource.
    case.expect_json(
        "POST",
        "/v1/auth/authorize",
        &[JSON_CONTENT],
        r#"{"tenant":{"organization_id":"org-example","team_id":"team-example","project_id":"project-example","user_id":null,"api_key_id":"key-example"},"subject":{"type":"api_key","api_key_id":"key-example"},"action":"models.read","resource":"model:anything-at-all"}"#,
        200,
        |body| {
            assert_eq!(body["allowed"], true);
            assert_eq!(body["reason"], "matched_rbac_binding");
            Ok(())
        },
    )?;

    // Cross-tenant isolation: the key-example subject presented under a different
    // tenant (org_demo) must NOT match its org-example binding — fail closed.
    case.expect_json(
        "POST",
        "/v1/auth/authorize",
        &[JSON_CONTENT],
        r#"{"tenant":{"organization_id":"org_demo","team_id":null,"project_id":"project_gateway","user_id":null,"api_key_id":"key-example"},"subject":{"type":"api_key","api_key_id":"key-example"},"action":"chat.completions","resource":"model:fast-chat"}"#,
        200,
        |body| {
            assert_eq!(body["allowed"], false);
            assert_eq!(body["reason"], "no_matching_rbac_binding");
            Ok(())
        },
    )?;

    // The second tenant's own subject is authorized under its own binding.
    case.expect_json(
        "POST",
        "/v1/auth/authorize",
        &[JSON_CONTENT],
        r#"{"tenant":{"organization_id":"org_demo","team_id":null,"project_id":"project_gateway","user_id":null,"api_key_id":"client"},"subject":{"type":"api_key","api_key_id":"client"},"action":"chat.completions","resource":"model:fast-chat"}"#,
        200,
        |body| {
            assert_eq!(body["allowed"], true);
            assert_eq!(body["reason"], "matched_rbac_binding");
            Ok(())
        },
    )?;

    // Malformed authorize body must be rejected as invalid_json.
    case.expect_json(
        "POST",
        "/v1/auth/authorize",
        &[JSON_CONTENT],
        "{ broken",
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_json");
            Ok(())
        },
    )?;

    // Unknown endpoint must fail closed with 404, not leak into another handler.
    case.expect_json("GET", "/v1/does-not-exist", &[], "", 404, |body| {
        assert_eq!(body["error"]["code"], "not_found");
        Ok(())
    })?;

    println!("auth-api scenario passed");
    Ok(())
}

fn self_hosted_worker_poll_body(worker_id: &str, token_id: &str, token_secret: &str) -> String {
    self_hosted_worker_poll_body_with_protocol(worker_id, token_id, token_secret, 1)
}

fn encrypted_self_hosted_worker_poll_body(
    worker_id: &str,
    token_id: &str,
    token_secret: &str,
    nonce_byte: u8,
) -> Result<String> {
    encrypted_self_hosted_transport_body(
        worker_id,
        token_id,
        token_secret,
        &self_hosted_worker_poll_body(worker_id, token_id, token_secret),
        nonce_byte,
    )
}

fn tampered_encrypted_self_hosted_worker_poll_body(
    worker_id: &str,
    token_id: &str,
    token_secret: &str,
    nonce_byte: u8,
) -> Result<String> {
    let mut frame = encrypted_self_hosted_transport_frame(
        worker_id,
        token_id,
        token_secret,
        &self_hosted_worker_poll_body(worker_id, token_id, token_secret),
        nonce_byte,
    )?;
    frame.protocol_version = frame.protocol_version.saturating_add(1);
    serde_json::to_string(&frame).context("serialize tampered self-hosted encrypted poll frame")
}

fn self_hosted_worker_poll_body_with_protocol(
    worker_id: &str,
    token_id: &str,
    token_secret: &str,
    protocol_version: u32,
) -> String {
    self_hosted_worker_poll_body_for_scope_with_protocol(
        "org_demo",
        "workspace-1",
        worker_id,
        token_id,
        token_secret,
        protocol_version,
    )
}

fn self_hosted_worker_poll_body_for_scope(
    tenant_id: &str,
    workspace_id: &str,
    worker_id: &str,
    token_id: &str,
    token_secret: &str,
) -> String {
    self_hosted_worker_poll_body_for_scope_with_protocol(
        tenant_id,
        workspace_id,
        worker_id,
        token_id,
        token_secret,
        1,
    )
}

fn self_hosted_worker_poll_body_for_scope_with_protocol(
    tenant_id: &str,
    workspace_id: &str,
    worker_id: &str,
    token_id: &str,
    token_secret: &str,
    protocol_version: u32,
) -> String {
    format!(
        r#"{{
          "protocol_version": {protocol_version},
          "identity": {{
            "tenant_id": "{tenant_id}",
            "workspace_id": "{workspace_id}",
            "worker_id": "{worker_id}",
            "token_id": "{token_id}",
            "token_secret": "{token_secret}"
          }},
          "supported_capabilities": ["shell", "mcp"],
          "now_unix": 1000,
          "lease_duration_secs": 60
        }}"#
    )
}

fn self_hosted_worker_ack_body(
    worker_id: &str,
    token_id: &str,
    token_secret: &str,
    lease_id: &str,
) -> String {
    self_hosted_worker_ack_body_for_scope(
        "org_demo",
        "workspace-1",
        worker_id,
        token_id,
        token_secret,
        lease_id,
    )
}

fn encrypted_self_hosted_worker_ack_body(
    worker_id: &str,
    token_id: &str,
    token_secret: &str,
    lease_id: &str,
    nonce_byte: u8,
) -> Result<String> {
    encrypted_self_hosted_transport_body(
        worker_id,
        token_id,
        token_secret,
        &self_hosted_worker_ack_body(worker_id, token_id, token_secret, lease_id),
        nonce_byte,
    )
}

fn encrypted_self_hosted_transport_body(
    worker_id: &str,
    token_id: &str,
    token_secret: &str,
    plaintext_json: &str,
    nonce_byte: u8,
) -> Result<String> {
    let frame = encrypted_self_hosted_transport_frame(
        worker_id,
        token_id,
        token_secret,
        plaintext_json,
        nonce_byte,
    )?;
    serde_json::to_string(&frame).context("serialize self-hosted encrypted transport frame")
}

fn encrypted_self_hosted_transport_frame(
    worker_id: &str,
    token_id: &str,
    token_secret: &str,
    plaintext_json: &str,
    nonce_byte: u8,
) -> Result<SelfHostedWorkerTransportFrame> {
    let identity = SelfHostedWorkerIdentity {
        tenant_id: "org_demo".to_string(),
        workspace_id: "workspace-1".to_string(),
        worker_id: worker_id.to_string(),
        token_id: token_id.to_string(),
        token_secret: token_secret.to_string(),
        observed_at_unix: None,
    };
    SelfHostedWorkerTransportFrame::encrypt_json(
        SELF_HOSTED_WORKER_PROTOCOL_VERSION,
        &identity,
        plaintext_json,
        token_secret,
        [nonce_byte; 24],
    )
    .context("encrypt self-hosted worker transport frame")
}

fn decrypted_self_hosted_transport_response(
    body: serde_json::Value,
    token_secret: &str,
) -> Result<serde_json::Value> {
    let frame: SelfHostedWorkerTransportFrame =
        serde_json::from_value(body).context("decode encrypted self-hosted response")?;
    let plaintext_json = frame
        .decrypt_json(token_secret)
        .context("decrypt self-hosted response frame")?;
    serde_json::from_str(&plaintext_json).context("decode self-hosted response JSON")
}

fn self_hosted_worker_ack_body_for_scope(
    tenant_id: &str,
    workspace_id: &str,
    worker_id: &str,
    token_id: &str,
    token_secret: &str,
    lease_id: &str,
) -> String {
    format!(
        r#"{{
          "protocol_version": 1,
          "identity": {{
            "tenant_id": "{tenant_id}",
            "workspace_id": "{workspace_id}",
            "worker_id": "{worker_id}",
            "token_id": "{token_id}",
            "token_secret": "{token_secret}"
          }},
          "dispatch_id": "self-hosted-dispatch-{worker_id}",
          "action": "start_run",
          "lease_id": "{lease_id}",
          "run_id": "self-hosted-run-{worker_id}",
          "status": "accepted",
          "reported_at_unix": 1001
        }}"#
    )
}

fn self_hosted_worker_heartbeat_body(
    worker_id: &str,
    identity_fingerprint: &str,
    token_secret: &str,
    status: &str,
    reported_at_unix: u64,
) -> String {
    self_hosted_worker_heartbeat_body_with_payload(
        worker_id,
        identity_fingerprint,
        token_secret,
        status,
        reported_at_unix,
        r#"{"load":0.24}"#,
    )
}

fn self_hosted_worker_heartbeat_body_with_payload(
    worker_id: &str,
    identity_fingerprint: &str,
    token_secret: &str,
    status: &str,
    reported_at_unix: u64,
    heartbeat_json: &str,
) -> String {
    format!(
        r#"{{
          "identity": {{
            "tenant_id": "org_demo",
            "workspace_id": "workspace-1",
            "worker_id": "{worker_id}",
            "token_id": "{identity_fingerprint}",
            "token_secret": "{token_secret}"
          }},
          "status": "{status}",
          "reported_at_unix": {reported_at_unix},
          "heartbeat_json": {heartbeat_json:?}
        }}"#
    )
}

fn self_hosted_worker_event_body(
    worker_id: &str,
    identity_fingerprint: &str,
    token_secret: &str,
    kind: &str,
    occurred_at_unix: u64,
) -> String {
    self_hosted_worker_event_body_with_payload(
        worker_id,
        identity_fingerprint,
        token_secret,
        kind,
        occurred_at_unix,
        r#"{"state":"running"}"#,
    )
}

fn self_hosted_worker_event_body_with_payload(
    worker_id: &str,
    identity_fingerprint: &str,
    token_secret: &str,
    kind: &str,
    occurred_at_unix: u64,
    event_json: &str,
) -> String {
    format!(
        r#"{{
          "identity": {{
            "tenant_id": "org_demo",
            "workspace_id": "workspace-1",
            "worker_id": "{worker_id}",
            "token_id": "{identity_fingerprint}",
            "token_secret": "{token_secret}"
          }},
          "session_id": "session-transport",
          "run_id": "run-transport",
          "kind": "{kind}",
          "occurred_at_unix": {occurred_at_unix},
          "event_json": {event_json:?}
        }}"#
    )
}

fn self_hosted_worker_artifact_body(
    worker_id: &str,
    identity_fingerprint: &str,
    token_secret: &str,
    artifact_id: &str,
    artifact_name: &str,
    size_bytes: u64,
    created_at_unix: u64,
) -> String {
    self_hosted_worker_artifact_body_with_payload(
        worker_id,
        identity_fingerprint,
        token_secret,
        artifact_id,
        artifact_name,
        size_bytes,
        created_at_unix,
        r#"{"sha256":"transport"}"#,
    )
}

#[allow(clippy::too_many_arguments)]
fn self_hosted_worker_artifact_body_with_payload(
    worker_id: &str,
    identity_fingerprint: &str,
    token_secret: &str,
    artifact_id: &str,
    artifact_name: &str,
    size_bytes: u64,
    created_at_unix: u64,
    artifact_json: &str,
) -> String {
    format!(
        r#"{{
          "identity": {{
            "tenant_id": "org_demo",
            "workspace_id": "workspace-1",
            "worker_id": "{worker_id}",
            "token_id": "{identity_fingerprint}",
            "token_secret": "{token_secret}"
          }},
          "artifact_id": "{artifact_id}",
          "session_id": "session-transport",
          "run_id": "run-transport",
          "artifact_name": "{artifact_name}",
          "content_type": "text/plain",
          "size_bytes": {size_bytes},
          "created_at_unix": {created_at_unix},
          "artifact_json": {artifact_json:?}
        }}"#
    )
}

fn self_hosted_worker_checkpoint_body(
    worker_id: &str,
    identity_fingerprint: &str,
    token_secret: &str,
    checkpoint_id: &str,
    checkpoint_name: &str,
    size_bytes: u64,
    created_at_unix: u64,
) -> String {
    self_hosted_worker_checkpoint_body_with_payload(
        worker_id,
        identity_fingerprint,
        token_secret,
        checkpoint_id,
        checkpoint_name,
        size_bytes,
        created_at_unix,
        r#"{"sha256":"transport-checkpoint"}"#,
    )
}

#[allow(clippy::too_many_arguments)]
fn self_hosted_worker_checkpoint_body_with_payload(
    worker_id: &str,
    identity_fingerprint: &str,
    token_secret: &str,
    checkpoint_id: &str,
    checkpoint_name: &str,
    size_bytes: u64,
    created_at_unix: u64,
    checkpoint_json: &str,
) -> String {
    format!(
        r#"{{
          "identity": {{
            "tenant_id": "org_demo",
            "workspace_id": "workspace-1",
            "worker_id": "{worker_id}",
            "token_id": "{identity_fingerprint}",
            "token_secret": "{token_secret}"
          }},
          "checkpoint_id": "{checkpoint_id}",
          "session_id": "session-transport",
          "run_id": "run-transport",
          "checkpoint_name": "{checkpoint_name}",
          "size_bytes": {size_bytes},
          "created_at_unix": {created_at_unix},
          "checkpoint_json": {checkpoint_json:?}
        }}"#
    )
}

fn oversized_self_hosted_transport_body() -> String {
    format!(r#"{{"padding":"{}"}}"#, "x".repeat(1024 * 1024 + 1))
}

pub(crate) fn run_gateway_api(args: &LocalArgs) -> Result<()> {
    let mut case = LocalHarness::start_with_billing_and_agent(&args.ferrogate_bin, 12)?;

    case.expect_json("GET", "/v1/models", &[CLIENT_AUTH], "", 200, |body| {
        assert!(list_contains(&body, "id", "fast-chat"));
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/.well-known/agent.json",
        &[CLIENT_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            assert!(list_contains(&body, "id", "agent.echo"));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/agents/agent.echo/message:send",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":"msg-1","method":"message:send","params":{"message":{"role":"user","parts":[{"type":"text","text":"hello"}]}}}"#,
        200,
        |body| {
            assert_eq!(body["result"]["content"][0]["text"], "agent-result");
            assert_eq!(body["result"]["isError"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/.well-known/agent.json",
        &[OBSERVER_AUTH],
        "",
        403,
        |body| {
            assert_eq!(body["error"]["code"], "scope_denied");
            Ok(())
        },
    )?;
    let agent_upstream_endpoint = case.agent_endpoint()?;
    let agent_upstream = format!(
        r#"{{"id":"pi-agent-us","name":"Pi Agent US","description":"Community agent upstream","enabled":true,"protocol":"a2a","endpoint":"http://{agent_upstream_endpoint}/a2a","tenant_ids":["client"],"capabilities":["invoke","read","stream","discover"]}}"#
    );
    case.expect_json(
        "POST",
        "/admin/v1/agent-upstreams",
        &[ADMIN_AUTH, JSON_CONTENT],
        &agent_upstream,
        201,
        |body| {
            assert_eq!(body["object"], "agent_upstream");
            assert_eq!(body["agent_upstream"]["id"], "pi-agent-us");
            assert_eq!(body["agent_upstream"]["protocol"], "a2a");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-upstreams/pi-agent-us",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "agent_upstream");
            assert_eq!(body["agent_upstream"]["id"], "pi-agent-us");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/.well-known/agent.json",
        &[CLIENT_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            assert!(list_contains(&body, "id", "pi-agent-us"));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/agents/pi-agent-us/message:stream",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":"msg-2","method":"message:stream","params":{"message":{"role":"user","parts":[{"type":"text","text":"hello"}]}}}"#,
        200,
        |body| {
            assert_eq!(body["result"]["content"][0]["text"], "agent-stream");
            Ok(())
        },
    )?;
    case.expect_json(
        "PUT",
        "/admin/v1/agent-upstreams/pi-agent-us",
        &[ADMIN_AUTH, JSON_CONTENT],
        &format!(
            r#"{{"id":"pi-agent-us","name":"Pi Agent US","enabled":false,"protocol":"a2a","endpoint":"http://{agent_upstream_endpoint}/a2a","tenant_ids":["client"],"capabilities":["invoke","read"]}}"#
        ),
        200,
        |body| {
            assert_eq!(body["agent_upstream"]["enabled"], false);
            assert_eq!(body["agent_upstream"]["capabilities"][1], "read");
            Ok(())
        },
    )?;
    case.expect_json(
        "DELETE",
        "/admin/v1/agent-upstreams/pi-agent-us",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-upstreams",
        &[OBSERVER_AUTH, JSON_CONTENT],
        &agent_upstream,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "scope_denied");
            Ok(())
        },
    )?;
    case.expect_json("GET", "/v1/models", &[], "", 401, |body| {
        assert_eq!(body["error"]["code"], "missing_api_key");
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"support-flow","name":"Support flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"draft","kind":"model","model":"fast-chat","providers":["openai"],"token_budget":600}],"edges":[],"max_model_calls":1,"max_iterations":2,"token_budget":600}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "support-flow");
            assert_eq!(body["agent_workflow"]["workflow"]["version"], 1);
            assert_eq!(
                body["agent_workflow"]["workflow"]["nodes"][0]["providers"][0],
                "openai"
            );
            assert_eq!(body["agent_workflow"]["counters"]["request_count"], 0);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"budget-flow","name":"Budget flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"draft","kind":"model","model":"fast-chat","token_budget":600}],"edges":[],"max_model_calls":10,"max_iterations":2,"token_budget":600}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "budget-flow");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"bad-tool-flow","name":"Bad tool flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"missing","kind":"tool","tool":"tool.missing"}],"edges":[],"max_tool_calls":1}"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_agent_workflow");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("references unknown tool tool.missing")));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"bad-provider-flow","name":"Bad provider flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"draft","kind":"model","model":"fast-chat","providers":["missing-provider"]}],"edges":[],"max_model_calls":1}"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_agent_workflow");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("references unknown provider missing-provider")));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"provider-flow","name":"Provider flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"draft","kind":"model","model":"fast-chat","providers":["anthropic"]}],"edges":[],"max_model_calls":10,"max_iterations":2}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "provider-flow");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"timeout-flow","name":"Timeout flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"draft","kind":"model","model":"fast-chat"}],"edges":[],"max_model_calls":10,"max_iterations":2,"timeout_millis":1}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "timeout-flow");
            assert_eq!(body["agent_workflow"]["workflow"]["timeout_millis"], 1);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"tool-flow","name":"Tool flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"echo","kind":"tool","tool":"tool.echo","max_iterations":2}],"edges":[],"max_tool_calls":1,"max_iterations":2}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "tool-flow");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"parallel-flow","name":"Parallel flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"echo","kind":"tool","tool":"tool.echo","max_iterations":3}],"edges":[],"max_tool_calls":2,"max_parallelism":1,"max_iterations":3}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "parallel-flow");
            assert_eq!(body["agent_workflow"]["workflow"]["max_parallelism"], 1);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"graph-flow","name":"Graph flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"start","kind":"model","model":"fast-chat"},{"id":"review","kind":"model","model":"fast-chat"}],"edges":[{"from":"start","to":"review"}],"max_model_calls":10,"max_iterations":3}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "graph-flow");
            assert_eq!(
                body["agent_workflow"]["workflow"]["edges"][0]["from"],
                "start"
            );
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    let support_skill = r#"{"id":"support-skill","name":"Support skill","version":"1.0.0","description":"Pi-compatible support skill package","enabled":true,"api_key_ids":["client"],"compatibility":{"agent_runtimes":["pi-agent","codex","claude-code"]},"permissions":{"tools":["tool.echo"],"network":[],"filesystem":false,"shell":false,"tenant_scope":true,"secrets":false,"admin_mutation":false},"capabilities":[{"kind":"plugin","id":"tool.echo","description":"governed builtin echo plugin"},{"kind":"tool","id":"tool.echo","description":"echo tool through FerroGate tool governance"},{"kind":"mcp_server","id":"http","description":"HTTP MCP server binding"},{"kind":"mcp_tool","id":"http-search","description":"MCP search tool through FerroGate MCP governance"},{"kind":"agent_workflow","id":"support-flow","description":"bounded support workflow"}],"metadata":{"display":"Support","token":"client-secret"}}"#;
    case.expect_json(
        "POST",
        "/admin/v1/skill-packages",
        &[ADMIN_AUTH, JSON_CONTENT],
        support_skill,
        201,
        |body| {
            assert_eq!(body["object"], "skill_package");
            assert_eq!(body["skill_package"]["id"], "support-skill");
            assert_eq!(body["skill_package"]["version"], "1.0.0");
            assert_eq!(body["skill_package"]["capabilities"][1]["kind"], "tool");
            assert_eq!(body["skill_package"]["metadata"]["token"], "[redacted]");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/skill-packages/support-skill",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "skill_package");
            assert_eq!(body["skill_package"]["id"], "support-skill");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json("GET", "/v1/skills", &[CLIENT_AUTH], "", 200, |body| {
        let skill = admin_list_item(&body, "id", "support-skill")
            .context("support skill was not visible to owning client")?;
        assert_eq!(skill["name"], "Support skill");
        assert_eq!(skill["compatibility"]["agent_runtimes"][0], "pi-agent");
        assert!(skill.get("metadata").is_none());
        assert_secret_redacted(&body.to_string());
        Ok(())
    })?;
    case.expect_json("GET", "/v1/skills", &[OBSERVER_AUTH], "", 200, |body| {
        assert!(!list_contains(&body, "id", "support-skill"));
        assert_secret_redacted(&body.to_string());
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/v1/tools/execute",
        &[CLIENT_AUTH, JSON_CONTENT, SUPPORT_SKILL_HEADER],
        r#"{"name":"tool.echo","arguments":{"message":"skill-governed-tool"},"session_id":"skill-tool-session"}"#,
        200,
        |body| {
            assert_eq!(body["name"], "tool.echo");
            assert_eq!(body["is_error"], false);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/mcp/tool/execute",
        &[CLIENT_AUTH, JSON_CONTENT, SUPPORT_SKILL_HEADER],
        r#"{"name":"http-search","arguments":{"query":"skill-mcp"},"session_id":"skill-mcp-session"}"#,
        200,
        |body| {
            assert_eq!(body["name"], "http-search");
            assert_eq!(body["is_error"], false);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT, SUPPORT_SKILL_HEADER],
        r#"{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{"name":"http-search","arguments":{"query":"skill-native-mcp"}}}"#,
        200,
        |body| {
            assert_eq!(body["result"]["content"][0]["text"], "ferrogate-result");
            assert_eq!(body["result"]["isError"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/tools/execute",
        &[OBSERVER_AUTH, JSON_CONTENT, SUPPORT_SKILL_HEADER],
        r#"{"name":"tool.echo","arguments":{"message":"blocked"}}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "skill_package_not_allowed");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    let embedded_skill = r#"{"id":"embedded-skill","name":"Embedded skill","version":"1.0.0","description":"Skill package with owned resources","enabled":true,"api_key_ids":["client"],"compatibility":{"agent_runtimes":["pi-agent","codex","claude-code"]},"permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":true,"secrets":false,"admin_mutation":false},"capabilities":[{"kind":"plugin","id":"tool.health_check","description":"owned health-check tool provider"},{"kind":"tool","id":"tool.health_check","description":"owned health-check tool"},{"kind":"mcp_server","id":"skillhttp","description":"owned MCP server binding"},{"kind":"mcp_tool","id":"skillhttp-search","description":"owned MCP search tool"},{"kind":"prompt_template","id":"embedded-prompt","description":"owned prompt template"},{"kind":"agent_workflow","id":"embedded-flow","description":"owned workflow"}],"resources":{"plugins":[{"id":"tool.health_check","kind":"tool_provider","version":"1.0.0","manifest":{"name":"Health check","capabilities":["tool_provider"],"required_permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":false,"secrets":false,"admin_mutation":false},"hooks":[]},"enabled":true,"source":"builtin","order":11,"approval_policy":"never","permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":false,"secrets":false,"admin_mutation":false},"config":{"registered_by":"embedded-skill"}}],"mcp_servers":[{"name":"skillhttp","transport":"streamable_http","url":"http://127.0.0.1:1/mcp","auth_type":"none","headers":[],"tools_to_execute":["search"],"tools_to_auto_execute":["search"],"approval_policy":"never","tool_include":["search"],"tool_regex":[],"tls":{},"timeout_ms":100,"health_ping_interval_secs":10,"max_reconnect_attempts":1,"min_reconnect_backoff_secs":1,"max_reconnect_backoff_secs":1}],"prompt_templates":[{"id":"embedded-prompt","name":"Embedded prompt","status":"active","target":"chat_completions","model":"fast-chat","variables":[],"versions":[{"revision":1,"status":"active","messages":[{"role":"system","content":"Use gateway policy."}]}]}],"agent_workflows":[{"id":"embedded-flow","name":"Embedded flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"health","kind":"tool","tool":"tool.health_check","max_iterations":1}],"edges":[],"max_tool_calls":1,"max_iterations":1}]},"metadata":{"display":"Embedded","token":"client-secret"}}"#;
    case.expect_json(
        "POST",
        "/admin/v1/skill-packages",
        &[ADMIN_AUTH, JSON_CONTENT],
        embedded_skill,
        201,
        |body| {
            assert_eq!(body["object"], "skill_package");
            assert_eq!(body["skill_package"]["id"], "embedded-skill");
            assert_eq!(
                body["skill_package"]["resources"]["plugins"][0]["config"]["registered_by"],
                "embedded-skill"
            );
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/plugins/tool.health_check",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["id"], "tool.health_check");
            assert_eq!(body["enabled"], true);
            assert_array_contains(&body["tools"], "tool.health_check")
                .context("skill-owned plugin must expose tool.health_check")?;
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json("GET", "/admin/v1/tools", &[ADMIN_AUTH], "", 200, |body| {
        let tool = admin_list_item(&body, "name", "tool.health_check")
            .context("skill-owned tool was not materialized")?;
        assert_eq!(tool["extension_id"], "tool.health_check");
        assert_secret_redacted(&body.to_string());
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/admin/v1/mcp-servers/skillhttp",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["name"], "skillhttp");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/tools/execute",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-skill-package: embedded-skill",
        ],
        r#"{"name":"tool.health_check","arguments":{},"session_id":"embedded-skill-tool-session"}"#,
        200,
        |body| {
            assert_eq!(body["name"], "tool.health_check");
            assert_eq!(body["content"]["status"], "ok");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    let disabled_embedded_skill = r#"{"id":"embedded-skill","name":"Embedded skill","version":"1.0.0","description":"Skill package with owned resources","enabled":false,"api_key_ids":["client"],"compatibility":{"agent_runtimes":["pi-agent","codex","claude-code"]},"permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":true,"secrets":false,"admin_mutation":false},"capabilities":[{"kind":"plugin","id":"tool.health_check"},{"kind":"tool","id":"tool.health_check"},{"kind":"mcp_server","id":"skillhttp"},{"kind":"mcp_tool","id":"skillhttp-search"},{"kind":"prompt_template","id":"embedded-prompt"},{"kind":"agent_workflow","id":"embedded-flow"}],"resources":{"plugins":[{"id":"tool.health_check","kind":"tool_provider","version":"1.0.0","manifest":{"name":"Health check","capabilities":["tool_provider"],"required_permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":false,"secrets":false,"admin_mutation":false},"hooks":[]},"enabled":true,"source":"builtin","order":11,"approval_policy":"never","permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":false,"secrets":false,"admin_mutation":false},"config":{"registered_by":"embedded-skill"}}],"mcp_servers":[{"name":"skillhttp","transport":"streamable_http","url":"http://127.0.0.1:1/mcp","auth_type":"none","headers":[],"tools_to_execute":["search"],"tools_to_auto_execute":["search"],"approval_policy":"never","tool_include":["search"],"tool_regex":[],"tls":{},"timeout_ms":100,"health_ping_interval_secs":10,"max_reconnect_attempts":1,"min_reconnect_backoff_secs":1,"max_reconnect_backoff_secs":1}],"prompt_templates":[{"id":"embedded-prompt","name":"Embedded prompt","status":"active","target":"chat_completions","model":"fast-chat","variables":[],"versions":[{"revision":1,"status":"active","messages":[{"role":"system","content":"Use gateway policy."}]}]}],"agent_workflows":[{"id":"embedded-flow","name":"Embedded flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"health","kind":"tool","tool":"tool.health_check","max_iterations":1}],"edges":[],"max_tool_calls":1,"max_iterations":1}]},"metadata":{"display":"Embedded","token":"client-secret"}}"#;
    case.expect_json(
        "PUT",
        "/admin/v1/skill-packages/embedded-skill",
        &[ADMIN_AUTH, JSON_CONTENT],
        disabled_embedded_skill,
        200,
        |body| {
            assert_eq!(body["object"], "skill_package");
            assert_eq!(body["skill_package"]["enabled"], false);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/plugins/tool.health_check",
        &[ADMIN_AUTH],
        "",
        404,
        |body| {
            assert_eq!(body["error"]["code"], "plugin_not_found");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json("GET", "/admin/v1/tools", &[ADMIN_AUTH], "", 200, |body| {
        assert!(!list_contains(&body, "name", "tool.health_check"));
        assert_secret_redacted(&body.to_string());
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/admin/v1/mcp-servers/skillhttp",
        &[ADMIN_AUTH],
        "",
        404,
        |body| {
            assert_eq!(body["error"]["code"], "mcp_server_not_found");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/audit-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let raw = body.to_string();
            assert!(raw.contains("skill_package:support-skill@1.0.0/tool_session:skill-tool-session"));
            assert!(raw.contains("skill_package:support-skill@1.0.0/tool_session:skill-mcp-session/mcp:http/tool:search"));
            assert!(raw.contains("skill_package:support-skill@1.0.0/mcp:http/tool:search"));
            assert!(raw.contains("skill_package=support-skill@1.0.0"));
            assert_secret_redacted(&raw);
            Ok(())
        },
    )?;
    case.expect_json(
        "PUT",
        "/admin/v1/skill-packages/support-skill",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"support-skill","name":"Support skill","version":"1.0.0","description":"Pi-compatible support skill package","enabled":false,"api_key_ids":["client"],"compatibility":{"agent_runtimes":["pi-agent","codex","claude-code"]},"permissions":{"tools":["tool.echo"],"network":[],"filesystem":false,"shell":false,"tenant_scope":true,"secrets":false,"admin_mutation":false},"capabilities":[{"kind":"plugin","id":"tool.echo"},{"kind":"tool","id":"tool.echo"},{"kind":"mcp_server","id":"http"},{"kind":"mcp_tool","id":"http-search"},{"kind":"agent_workflow","id":"support-flow"}],"metadata":{"display":"Support","token":"client-secret"}}"#,
        200,
        |body| {
            assert_eq!(body["object"], "skill_package");
            assert_eq!(body["skill_package"]["enabled"], false);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/v1/skills/support-skill",
        &[CLIENT_AUTH],
        "",
        404,
        |body| {
            assert_eq!(body["error"]["code"], "skill_package_not_found");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"gateway coverage client-secret"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_text(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","stream":true,"messages":[{"role":"user","content":"gateway stream coverage"}]}"#,
        200,
        |body| {
            assert!(body.contains("stream-ok"), "missing streaming delta: {body}");
            assert!(body.contains("[DONE]"), "missing streaming terminator: {body}");
            assert_secret_redacted(body);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"provider upstream error"}]}"#,
        400,
        |body| {
            assert_eq!(body["error"]["type"], "provider_error");
            assert_eq!(body["error"]["code"], "bad_provider_request");
            assert_eq!(body["error"]["provider_status"], 400);
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("bad provider request")));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-run-e2e",
            "x-ferrogate-workflow-id: support-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow coverage"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-graph-e2e",
            "x-ferrogate-workflow-id: graph-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: review",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow graph rejected"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_edge_not_allowed");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-graph-e2e",
            "x-ferrogate-workflow-id: graph-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: start",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow graph start"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-graph-e2e",
            "x-ferrogate-workflow-id: graph-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: review",
            "x-ferrogate-workflow-iteration: 2",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow graph review"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-timeout-e2e",
            "x-ferrogate-workflow-id: timeout-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow timeout seed"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    thread::sleep(Duration::from_millis(1_100));
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-timeout-e2e",
            "x-ferrogate-workflow-id: timeout-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 2",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow timeout rejected"}]}"#,
        429,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_timeout_exceeded");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-workflow-id: budget-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow denied"}],"max_tokens":1000}"#,
        429,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_token_budget_exceeded");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-workflow-id: provider-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow provider denied"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_provider_not_allowed");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-workflow-id: support-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow model call limit"}]}"#,
        429,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_model_call_limit_exceeded");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/responses",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","input":"gateway responses coverage"}"#,
        200,
        |body| {
            assert_eq!(body["object"], "response");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-config: static-profile",
            "x-ferrogate-agent-run-id: agent-run-e2e",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"profile coverage"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-config: missing-profile",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"bad profile"}]}"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "gateway_config_not_found");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"missing-chat","messages":[{"role":"user","content":"bad model"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "model_not_allowed");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: provider-fallback-e2e-1",
        ],
        r#"{"model":"fallback-chat","messages":[{"role":"user","content":"fallback first"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_eq!(body["choices"][0]["message"]["content"], "fallback ok");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: provider-fallback-e2e-2",
        ],
        r#"{"model":"fallback-chat","messages":[{"role":"user","content":"fallback circuit skip"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_eq!(body["choices"][0]["message"]["content"], "fallback ok");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/drain",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"drain":true}"#,
        200,
        |body| {
            assert_eq!(body["draining"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"drained"}]}"#,
        503,
        |body| {
            assert_eq!(body["error"]["code"], "node_draining");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/drain",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"drain":false}"#,
        200,
        |_| Ok(()),
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/request-logs",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let raw = body.to_string();
            assert!(raw.contains("openai.chat.completions"));
            assert!(raw.contains("openai.responses"));
            assert!(raw.contains("agent-run-e2e"));
            assert!(raw.contains("workflow-run-e2e"));
            assert!(raw.contains("\"workflow_id\":\"support-flow\""));
            assert!(raw.contains("\"workflow_version\":1"));
            assert!(raw.contains("\"workflow_node_id\":\"draft\""));
            assert!(raw.contains("workflow_token_budget_exceeded"));
            assert!(raw.contains("workflow_timeout_exceeded"));
            assert_secret_redacted(&raw);
            Ok(())
        },
    )?;
    case.expect_text(
        "GET",
        "/admin/v1/request-log-exports?organization_id=org_demo&project_id=project_gateway&model=fast-chat&provider=openai&status=200&limit=10",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let records = parse_jsonl(body)?;
            assert!(!records.is_empty());
            let chat = records
                .iter()
                .find(|record| {
                    record["route"] == "openai.chat.completions"
                        && record["agent_run_id"] == "agent-run-e2e"
                })
                .context("missing chat completion export record with agent run evidence")?;
            assert_eq!(chat["object"], "request_log_export");
            assert_eq!(chat["tenant"]["organization_id"], "org_demo");
            assert_eq!(chat["tenant"]["project_id"], "project_gateway");
            assert_eq!(chat["logical_model"], "fast-chat");
            assert_eq!(chat["provider"], "openai");
            assert_eq!(chat["provider_model"], "gpt-4o-mini");
            assert_eq!(chat["status_code"], 200);
            assert_eq!(chat["agent_run_id"], "agent-run-e2e");
            assert_eq!(chat["usage"]["total_tokens"], 2);
            assert_eq!(chat["prompt_recorded"], true);
            assert_eq!(chat["response_recorded"], true);
            assert!(chat["prompt_body"]
                .as_str()
                .is_some_and(|prompt| prompt.contains("profile coverage")));
            assert!(records
                .iter()
                .any(|record| record["route"] == "openai.responses"));
            let workflow_chat = records
                .iter()
                .find(|record| record["agent_run_id"] == "workflow-run-e2e")
                .context("missing workflow export record")?;
            assert_eq!(workflow_chat["workflow_id"], "support-flow");
            assert_eq!(workflow_chat["workflow_version"], 1);
            assert_eq!(workflow_chat["workflow_node_id"], "draft");
            assert_secret_redacted(body);
            assert!(!body.contains("provider-secret"));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-workflows/support-flow",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "support-flow");
            assert_eq!(body["agent_workflow"]["counters"]["request_count"], 2);
            assert_eq!(body["agent_workflow"]["counters"]["error_count"], 1);
            assert_eq!(body["agent_workflow"]["counters"]["billing_event_count"], 1);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let workflow = body["data"]
                .as_array()
                .and_then(|items| {
                    items
                        .iter()
                        .find(|item| item["workflow"]["id"] == "support-flow")
                })
                .context("agent workflow summary was not listed")?;
            assert_eq!(workflow["workflow"]["version"], 1);
            assert_eq!(workflow["counters"]["request_count"], 2);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/billing-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let raw = body.to_string();
            assert!(raw.contains("\"workflow_id\":\"support-flow\""));
            assert!(raw.contains("\"workflow_version\":1"));
            assert!(raw.contains("\"workflow_node_id\":\"draft\""));
            assert_secret_redacted(&raw);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-runs",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let run = admin_list_item(&body, "id", "agent-run-e2e")
                .context("agent run summary was not listed")?;
            assert_eq!(run["object"], "agent_run");
            assert_eq!(run["status"], "completed");
            assert_eq!(run["request_count"], 1);
            assert_eq!(run["billing_event_count"], 1);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-runs/agent-run-e2e",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "agent_run_timeline");
            assert_eq!(body["id"], "agent-run-e2e");
            assert_eq!(body["summary"]["id"], "agent-run-e2e");
            assert_eq!(body["requests"][0]["agent_run_id"], "agent-run-e2e");
            assert_eq!(body["billing_events"][0]["agent_run_id"], "agent-run-e2e");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/agent-runs",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-workflow-id: parallel-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: echo",
        ],
        r#"{"input":"run the parallel denied harness","max_turns":3,"timeout_millis":1000,"tool_calls":[{"name":"tool.echo","arguments":{"message":"first"}},{"name":"tool.echo","arguments":{"message":"second"}}]}"#,
        429,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "workflow_parallelism_limit_exceeded"
            );
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/agent-runs",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-workflow-id: tool-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: echo",
        ],
        r#"{"input":"run the denied harness","max_turns":3,"timeout_millis":1000,"tool_calls":[{"name":"tool.echo","arguments":{"message":"first"}},{"name":"tool.echo","arguments":{"message":"second"}}]}"#,
        429,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_tool_call_limit_exceeded");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/agent-runs",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: agent-run-harness",
            "x-ferrogate-workflow-id: tool-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: echo",
        ],
        r#"{"input":"run the bounded harness","max_turns":3,"timeout_millis":1000,"tool_calls":[{"name":"tool.echo","arguments":{"message":"from ferrogate-test"},"session_id":"agent-harness-tool-session"}]}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_run");
            assert_eq!(body["id"], "agent-run-harness");
            assert_eq!(body["status"], "completed");
            assert_eq!(body["turns_executed"], 2);
            assert_eq!(body["output"], "run the bounded harness");
            assert_eq!(body["tool_results"].as_array().unwrap().len(), 1);
            assert_eq!(
                body["tool_results"][0]["content"]["echo"]["message"],
                "from ferrogate-test"
            );
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-runs/agent-run-harness",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "agent_run_timeline");
            assert_eq!(body["id"], "agent-run-harness");
            assert_eq!(body["summary"]["request_count"], 0);
            assert_eq!(body["summary"]["audit_event_count"], 7);
            assert_eq!(body["summary"]["agent_event_count"], 7);
            assert_eq!(body["run"]["id"], "agent-run-harness");
            assert_eq!(body["run"]["status"], "completed");
            assert_eq!(body["run"]["provider"], "ferrogate.external");
            assert_eq!(body["agent_events"].as_array().unwrap().len(), 7);
            assert!(body["agent_events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| {
                    event["kind"] == "tool_call_completed"
                        && event["run_id"] == "agent-run-harness"
                        && event["outcome"] == "success"
                }));
            assert!(body["agent_events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| {
                    event["kind"] == "capability.allowed"
                        && event["run_id"] == "agent-run-harness"
                        && event["target"] == "tool.echo"
                        && event["tool_call_id"] == "mock-tool-call"
                        && event["outcome"] == "allowed"
                }));
            assert!(body["audit_events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| {
                    event["action"] == "tool.execute"
                        && event["target"] == "tool_session:agent-harness-tool-session"
                        && event["outcome"] == "success"
                        && event["agent_run_id"] == "agent-run-harness"
                        && event["workflow_id"] == "tool-flow"
                        && event["workflow_version"] == 1
                        && event["workflow_node_id"] == "echo"
                }));
            assert!(body["audit_events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| {
                    event["action"] == "agent.run_completed"
                        && event["agent_run_id"] == "agent-run-harness"
                        && event["workflow_id"] == "tool-flow"
                        && event["workflow_node_id"] == "echo"
                }));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-workflows/tool-flow",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "tool-flow");
            assert_eq!(body["agent_workflow"]["counters"]["request_count"], 0);
            assert_eq!(body["agent_workflow"]["counters"]["billing_event_count"], 0);
            assert_eq!(body["agent_workflow"]["counters"]["audit_event_count"], 7);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_text("GET", "/metrics", &[ADMIN_AUTH], "", 200, |body| {
        assert!(body.contains("ferrogate_request_logs_total"));
        Ok(())
    })?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ferrogate-test","version":"1.0.0"}}}"#,
        200,
        |body| {
            assert_eq!(body["jsonrpc"], "2.0");
            assert_eq!(body["id"], 1);
            assert_eq!(body["result"]["protocolVersion"], "2025-06-18");
            assert_eq!(body["result"]["serverInfo"]["name"], "ferrogate");
            assert!(body["result"]["instructions"]
                .as_str()
                .is_some_and(|instructions| instructions.contains("governed MCP gateway")));
            // Issue #257: the asset resource surface is advertised alongside tools.
            assert!(
                body["result"]["capabilities"]["resources"].is_object(),
                "initialize must advertise the resources capability: {body}"
            );
            Ok(())
        },
    )?;
    case.expect_text(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        202,
        |body| {
            assert!(body.is_empty());
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        200,
        |body| {
            assert_mcp_tool_present(&body, "http-search", "Search the harness MCP upstream")?;
            assert_mcp_tool_present(&body, "stdio-search", "Blocking stdio search")?;
            // Issue #257: the built-in fetch_asset tool is advertised to an
            // assets.read key alongside the MCP-upstream tools.
            assert!(
                body["result"]["tools"]
                    .as_array()
                    .is_some_and(|tools| tools.iter().any(|tool| {
                        tool["name"] == "builtin.fetch_asset"
                            && tool["inputSchema"]["type"] == "object"
                    })),
                "builtin.fetch_asset must be advertised in tools/list: {body}"
            );
            Ok(())
        },
    )?;
    // Issue #257: the asset resource ingress. The client holds assets.read and a
    // tenant, so resources/list succeeds (empty for this asset-less tenant -- an
    // ENTITLED empty list, not a masked 403) and resources/read of an unknown
    // asset fails closed with an invalid-params error.
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":20,"method":"resources/list","params":{}}"#,
        200,
        |body| {
            assert!(
                body["result"]["resources"].is_array(),
                "resources/list must return a resources array: {body}"
            );
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":21,"method":"resources/read","params":{"uri":"asset://cli_tool/absent/9.9.9"}}"#,
        200,
        |body| {
            assert_eq!(body["error"]["code"], -32602);
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("no asset")));
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"http-search","arguments":{"query":"ferrogate"}}}"#,
        200,
        |body| {
            let content = body["result"]["content"]
                .as_array()
                .with_context(|| format!("MCP tools/call response missing content array: {body}"))?;
            assert_eq!(content[0]["type"], "text");
            assert_eq!(content[0]["text"], "ferrogate-result");
            assert_eq!(body["result"]["isError"], false);
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"http-write","arguments":{"value":"denied"}}}"#,
        200,
        |body| {
            assert_eq!(body["error"]["code"], -32001);
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("not allowlisted")));
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"stdio-search","arguments":{"query":"blocked"}}}"#,
        200,
        |body| {
            assert_eq!(body["jsonrpc"], "2.0");
            assert_eq!(body["id"], 5);
            assert_eq!(body["error"]["code"], -32000);
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("timed out after 1 seconds")));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/mcp-servers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let stdio = admin_list_item(&body, "name", "stdio")
                .context("stdio MCP server status missing")?;
            assert_eq!(stdio["transport"], "stdio");
            assert_eq!(stdio["health"], "ok");
            assert_eq!(stdio["connected"], true);
            assert!(stdio["tools"].as_u64().is_some_and(|tools| tools >= 1));
            assert!(stdio["reconnect_attempts"]
                .as_u64()
                .is_some_and(|attempts| attempts >= 1));
            assert!(stdio["last_connected_at_unix"].as_u64().is_some());
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}"#,
        200,
        |body| {
            assert_mcp_tool_present(&body, "http-search", "Search the harness MCP upstream")?;
            assert_mcp_tool_present(&body, "stdio-search", "Blocking stdio search")?;
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"http-search","arguments":{"query":"mcp-tool-error"}}}"#,
        200,
        |body| {
            assert_eq!(body["jsonrpc"], "2.0");
            assert_eq!(body["id"], 8);
            assert_eq!(body["result"]["isError"], true);
            assert_eq!(
                body["result"]["content"][0]["text"],
                "tool rejected by harness"
            );
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/mcp/tool/execute",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"name":"http-search","arguments":{"query":"mcp-tool-error"},"session_id":"mcp-tool-error-session"}"#,
        200,
        |body| {
            assert_eq!(body["object"], "tool_execution");
            assert_eq!(body["name"], "http-search");
            assert_eq!(body["is_error"], true);
            assert_eq!(
                body["content"]["content"][0]["text"],
                "tool rejected by harness"
            );
            assert_eq!(body["session_id"], "mcp-tool-error-session");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"http-search","arguments":{"query":"mcp-malformed"}}}"#,
        200,
        |body| {
            assert_eq!(body["jsonrpc"], "2.0");
            assert_eq!(body["id"], 9);
            assert_eq!(body["error"]["code"], -32000);
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("invalid MCP tools/call result")));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/mcp-servers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let http = admin_list_item(&body, "name", "http")
                .context("HTTP MCP server status missing after malformed upstream response")?;
            assert_eq!(http["transport"], "streamable_http");
            match http["health"].as_str() {
                Some("degraded") => {
                    assert_eq!(http["connected"], false);
                    assert_eq!(http["tools"], 0);
                    assert!(http["last_error"]
                        .as_str()
                        .is_some_and(|message| message.contains("invalid MCP tools/call result")));
                }
                Some("ok") => {
                    assert_eq!(http["connected"], true);
                    assert!(http["tools"]
                        .as_u64()
                        .is_some_and(|tool_count| tool_count > 0));
                    assert!(http["last_error"].is_null());
                }
                other => panic!("unexpected HTTP MCP health after malformed response: {other:?}"),
            }
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}"#,
        401,
        |body| {
            assert_eq!(body["error"]["code"], "missing_api_key");
            Ok(())
        },
    )?;
    case.expect_openmeter_export()?;
    case.wait_for_metering_export_status()?;
    case.expect_agent_run_otlp_trace_export("agent-run-e2e")?;
    let provider_requests = case.take_provider_requests()?;
    assert_eq!(
        provider_requests
            .iter()
            .filter(|request| request.contains(r#""model":"gpt-4o-mini-failover-primary""#))
            .count(),
        1,
        "primary failover provider should be called once before its circuit opens: {provider_requests:#?}"
    );
    assert_eq!(
        provider_requests
            .iter()
            .filter(|request| request.contains(r#""model":"gpt-4o-mini-fallback""#))
            .count(),
        2,
        "fallback provider should handle both fallback-chat requests: {provider_requests:#?}"
    );
    assert!(
        provider_requests
            .iter()
            .any(|request| request.contains("provider upstream error")),
        "provider error scenario did not reach the upstream mock: {provider_requests:#?}"
    );
    assert!(
        provider_requests.iter().any(|request| {
            request.contains(r#""stream":true"#) && request.contains("gateway stream coverage")
        }),
        "streaming scenario did not reach the upstream mock: {provider_requests:#?}"
    );

    println!("gateway-api scenario passed");
    Ok(())
}

/// #121: end-to-end proof of the gateway function egress broker through the live
/// binary. The harness enables the broker (FG_FN_* env) with an allowlist for
/// org_demo pointing at a deliberately unreachable https upstream, so the full
/// pipeline (auth → allowlist → scoped-token mint → request build → egress
/// attempt) is exercised via the fail-closed, deny, and unreachable-upstream
/// paths without needing a live Supabase project.
pub(crate) fn run_function_egress_api(args: &LocalArgs) -> Result<()> {
    let case = LocalHarness::start_with_billing_and_agent(&args.ferrogate_bin, 13)?;

    // Unauthenticated → 401 (broker is enabled, so this is an auth failure, not 503).
    case.expect_json(
        "POST",
        "/v1/functions/execute",
        &[JSON_CONTENT],
        r#"{"target":{"base_url":"https://127.0.0.1:1","function_slug":"charge-credits","auth_key_ref":"secret:svc"},"body_json":"{}"}"#,
        401,
        |_body| Ok(()),
    )?;

    // Authenticated but the slug is not on the tenant allowlist → 403 fail-closed.
    case.expect_json(
        "POST",
        "/v1/functions/execute",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"target":{"base_url":"https://127.0.0.1:1","function_slug":"not-allowlisted","auth_key_ref":"secret:svc"},"body_json":"{}"}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "function_denied");
            Ok(())
        },
    )?;

    // Authenticated + allowlisted: the gateway authorizes, mints a scoped token,
    // builds the request, and attempts egress to the unreachable upstream → 502.
    // Reaching this status proves the whole live pipeline ran end to end.
    case.expect_json(
        "POST",
        "/v1/functions/execute",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"target":{"base_url":"https://127.0.0.1:1","function_slug":"charge-credits","auth_key_ref":"secret:svc"},"body_json":"{\"amount\":5}"}"#,
        502,
        |body| {
            assert_eq!(body["error"]["code"], "function_upstream_error");
            Ok(())
        },
    )?;

    // Closed-loop proof: every governed function decision must be persisted to
    // the control-plane audit store (control plane -> DB), so both the deny and
    // the upstream-error outcomes must be readable back through the admin API.
    case.expect_json(
        "GET",
        "/admin/v1/audit-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let events = body["data"].as_array().expect("audit-events data array");
            assert!(
                events.iter().any(|event| {
                    event["action"] == "function.execute" && event["outcome"] == "denied"
                }),
                "a denied function.execute audit event must be persisted"
            );
            assert!(
                events.iter().any(|event| {
                    event["action"] == "function.execute" && event["outcome"] == "upstream_error"
                }),
                "an upstream_error function.execute audit event must be persisted"
            );
            Ok(())
        },
    )?;

    println!("function-egress-api scenario passed");
    Ok(())
}

pub(crate) fn run_gateway_external_auth_api(local: &LocalArgs, auth_args: &AuthArgs) -> Result<()> {
    let auth = AuthHarness::start(&auth_args.ferrogate_auth_bin)?;
    let case = LocalHarness::start_with_external_auth(&local.ferrogate_bin, 2, &auth.auth_addr)?;

    case.expect_json("GET", "/v1/models", &[CLIENT_AUTH], "", 200, |body| {
        assert!(list_contains(&body, "id", "fast-chat"));
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"external auth allow"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_eq!(body["usage"]["total_tokens"], 2);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"blocked-chat","messages":[{"role":"user","content":"external auth deny"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "rbac_denied");
            Ok(())
        },
    )?;

    println!("gateway-external-auth-api scenario passed");
    Ok(())
}

/// Compatibility entrypoint for the gateway-to-billing chain. The reusable
/// provider contract owns the success, exact gpt-5.5 price, fallback, and
/// reported-usage error assertions so `component-compliance` and this command
/// cannot drift into separate definitions of correct settlement.
pub(crate) fn run_gateway_billing_chain(local: &LocalArgs) -> Result<()> {
    crate::provider_compliance::run_provider_compliance(local)?;
    println!("gateway-billing-chain scenario passed");
    Ok(())
}

pub(crate) fn run_gateway_third_party_auth_api(local: &LocalArgs) -> Result<()> {
    let auth = spawn_mock_third_party_auth_server(5)?;
    let case = LocalHarness::start_with_external_auth(&local.ferrogate_bin, 2, &auth.addr)?;

    case.expect_json("GET", "/v1/models", &[CLIENT_AUTH], "", 200, |body| {
        assert!(list_contains(&body, "id", "fast-chat"));
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"third party allow"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"blocked-chat","messages":[{"role":"user","content":"third party deny"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "rbac_denied");
            Ok(())
        },
    )?;

    let requests = auth.join()?;
    assert!(
        requests
            .iter()
            .any(|request| request.contains("POST /v1/auth/resolve-api-key ")),
        "third-party auth mock did not receive resolve-api-key request"
    );
    assert!(
        requests
            .iter()
            .any(|request| request.contains("POST /v1/auth/authorize ")),
        "third-party auth mock did not receive authorize request"
    );

    println!("gateway-third-party-auth-api scenario passed");
    Ok(())
}
