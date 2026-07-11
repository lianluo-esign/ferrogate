// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for Supabase storage scenario isolation configuration.

use super::*;

fn supabase_storage(schema: &str, live: bool) -> ControlPlaneRestartStorage<'_> {
    ControlPlaneRestartStorage::Supabase {
        dsn: "postgresql://unused",
        tls: PostgresRestartTls {
            mode: "require",
            ca_cert_path: None,
        },
        schema,
        live,
    }
}

#[test]
fn restart_configs_preserve_one_schema_across_auto_and_validate_only() {
    let schema = "ferrogate_test_rst_fixture";
    let storage = supabase_storage(schema, true);
    let auto = storage.restart_config(
        "127.0.0.1:18080",
        false,
        false,
        StorageMigrationMode::Auto,
        None,
    );
    let validate = storage.restart_config(
        "127.0.0.1:18081",
        false,
        false,
        StorageMigrationMode::ValidateOnly,
        None,
    );

    for config in [&auto, &validate] {
        assert!(config.contains(&format!("postgres_schema: {schema}")));
        assert!(!config.contains("postgres_schema: ferrogate_control"));
    }
    assert!(auto.contains("migration_mode: auto"));
    assert!(validate.contains("migration_mode: validate_only"));
    assert_eq!(storage.readiness_timeout(), Duration::from_secs(180));
}

#[test]
fn token4ai_fixture_identity_is_threaded_into_config_auth_and_evidence() {
    let fixture = LiveToken4aiFixture::new("fixture-run");
    let config = supabase_storage("ferrogate_test_t4ai_fixture", true)
        .live_token4ai_provider_config(
            "127.0.0.1:18080",
            "https://api.token4ai.cloud/v1",
            "provider-model",
            &fixture,
            StorageMigrationMode::Auto,
        );

    assert!(config.contains(&format!("id: \"{}\"", fixture.client_id)));
    assert!(config.contains(&format!("key: \"{}\"", fixture.client_secret)));
    assert!(config.contains(&format!("organization_id: \"{}\"", fixture.tenant_id)));
    assert!(config.contains(&format!("project_id: \"{}\"", fixture.project_id)));
    assert!(!config.contains("\n  - id: client\n"));
    assert_eq!(
        fixture.authorization_header(),
        format!("Authorization: Bearer {}", fixture.client_secret)
    );

    let aggregate = serde_json::json!({
        "api_key_id": fixture.client_id,
        "logical_model": "live-chat",
        "provider": "token4ai"
    });
    let event = serde_json::json!({
        "tenant": {"api_key_id": fixture.client_id},
        "logical_model": "live-chat",
        "provider": "token4ai"
    });
    assert!(live_token4ai_evidence_matches(
        &aggregate,
        &fixture.client_id
    ));
    assert!(live_token4ai_evidence_matches(&event, &fixture.client_id));
    assert!(!live_token4ai_evidence_matches(&event, "client"));
}

#[test]
fn local_supabase_compatible_storage_keeps_short_readiness_timeout() {
    assert_eq!(
        supabase_storage("ferrogate_control", false).readiness_timeout(),
        Duration::from_secs(60)
    );
}
