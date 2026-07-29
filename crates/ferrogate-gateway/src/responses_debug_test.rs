// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-29
// description: Debug redaction guards for show-once gateway response credentials (#492).

use super::*;

const TRANSPORT_SECRET: &str = "fg_worker_transport_secret_debug_canary";
const PRIVATE_KEY: &str =
    "-----BEGIN PRIVATE KEY-----\nfg-private-key-debug-canary\n-----END PRIVATE KEY-----";
const VIRTUAL_KEY_SECRET: &str = "fg_virtual_key_secret_debug_canary";

fn assert_no_secret_or_prefix(rendered: &str, secret: &str, label: &str) {
    assert!(
        !rendered.contains(secret),
        "{label} leaked completely into Debug: {rendered}"
    );
    for prefix_len in [4usize, 8, 16] {
        let prefix = &secret[..prefix_len];
        assert!(
            !rendered.contains(prefix),
            "{label} leaked a {prefix_len}-char prefix into Debug: {rendered}"
        );
    }
}

fn tenant() -> ferrogate_core::TenantContext {
    ferrogate_core::TenantContext {
        organization_id: Some("tenant-a".into()),
        team_id: None,
        project_id: Some("project-a".into()),
        workspace_id: Some("workspace-a".into()),
        user_id: None,
        api_key_id: None,
    }
}

fn worker() -> AdminSelfHostedWorkerRecord {
    AdminSelfHostedWorkerRecord {
        id: "worker-1".into(),
        tenant: tenant(),
        workspace_id: "workspace-a".into(),
        worker_name: "worker-a".into(),
        status: "registered".into(),
        identity_fingerprint: "fp-worker".into(),
        identity_expires_at_unix: Some(1_800_000_000),
        orchestration_enabled: true,
        registered_at_unix: Some(1_700_000_000),
        last_seen_at_unix: None,
        trust_level: "verified_mtls".into(),
        stale: false,
        stale_after_unix: None,
        stale_threshold_secs: 300,
        latest_heartbeat: None,
        telemetry_event_count: 0,
        artifact_count: 0,
        checkpoint_count: 0,
        latest_event_at_unix: None,
        latest_artifact_at_unix: None,
        latest_checkpoint_at_unix: None,
    }
}

fn certificate() -> AdminSelfHostedWorkerClientCertificate {
    AdminSelfHostedWorkerClientCertificate {
        spiffe_id: "spiffe://ferrogate/self-hosted/tenant-a/workspace-a/worker-a/token".into(),
        certificate_pem: "-----BEGIN CERTIFICATE-----\npublic-cert\n-----END CERTIFICATE-----"
            .into(),
        private_key_pem: PRIVATE_KEY.into(),
        fingerprint: "cert-fingerprint".into(),
        serial: "01".into(),
        not_after_unix: 1_800_000_000,
    }
}

#[test]
fn registration_response_debug_redacts_transport_secret_and_private_key() {
    let rendered = format!(
        "{:?}",
        AdminSelfHostedWorkerRegistrationResponse {
            object: "self_hosted_worker.registration",
            worker: worker(),
            transport_token_secret: TRANSPORT_SECRET.into(),
            client_certificate: Some(certificate()),
        }
    );

    assert_no_secret_or_prefix(&rendered, TRANSPORT_SECRET, "transport token secret");
    assert_no_secret_or_prefix(&rendered, PRIVATE_KEY, "client private key");
    assert!(
        rendered.contains("transport_token_secret: \"<redacted>\""),
        "{rendered}"
    );
    assert!(
        rendered.contains("private_key_pem: \"<redacted>\""),
        "{rendered}"
    );
    assert!(rendered.contains("worker-a"), "{rendered}");
    assert!(rendered.contains("cert-fingerprint"), "{rendered}");
}

#[test]
fn rotation_response_debug_redacts_fresh_transport_secret_and_private_key() {
    let rendered = format!(
        "{:?}",
        AdminSelfHostedWorkerRotateResponse {
            object: "self_hosted_worker.rotation",
            worker: worker(),
            transport_token_secret: TRANSPORT_SECRET.into(),
            client_certificate: Some(certificate()),
            previous_identity_fingerprint: "old-fp".into(),
            previous_identity_expires_at_unix: Some(1_700_000_000),
            rotated_at_unix: Some(1_700_000_100),
        }
    );

    assert_no_secret_or_prefix(
        &rendered,
        TRANSPORT_SECRET,
        "rotated transport token secret",
    );
    assert_no_secret_or_prefix(&rendered, PRIVATE_KEY, "rotated client private key");
    assert!(
        rendered.contains("transport_token_secret: \"<redacted>\""),
        "{rendered}"
    );
    assert!(
        rendered.contains("private_key_pem: \"<redacted>\""),
        "{rendered}"
    );
    assert!(rendered.contains("old-fp"), "{rendered}");
}

fn virtual_key() -> AdminVirtualApiKey {
    AdminVirtualApiKey {
        id: "vk-1".into(),
        workspace_id: "workspace-a".into(),
        tenant_id: "tenant-a".into(),
        project_id: "project-a".into(),
        name: "automation".into(),
        key_prefix: "fg_live".into(),
        last4: "9abc".into(),
        enabled: true,
        scopes: vec!["ai:chat".into()],
        allowed_models: Vec::new(),
        allowed_providers: Vec::new(),
        monthly_token_budget: None,
        request_limit_per_minute: None,
        created_at_unix: 1_700_000_000,
        updated_at_unix: 1_700_000_000,
        rotated_at_unix: None,
        expires_at_unix: None,
        revoked_at_unix: None,
    }
}

#[test]
fn virtual_key_mutation_response_debug_redacts_show_once_secret() {
    let rendered = format!(
        "{:?}",
        AdminVirtualApiKeyMutationResponse {
            object: "virtual_api_key",
            key: virtual_key(),
            secret: Some(VIRTUAL_KEY_SECRET.into()),
        }
    );

    assert_no_secret_or_prefix(&rendered, VIRTUAL_KEY_SECRET, "virtual key secret");
    assert!(
        rendered.contains(&format!(
            "secret: Some(\"<redacted:{} bytes>\")",
            VIRTUAL_KEY_SECRET.len()
        )),
        "{rendered}"
    );
    assert!(rendered.contains("vk-1"), "{rendered}");
    assert!(rendered.contains("fg_live"), "{rendered}");
}
