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

/// The schema the `supabase-restart` scenario applies, read here directly so
/// this test can disagree with the storage crate rather than echo it.
const CONTROL_PLANE_INIT_SQL: &str = include_str!("../../../sql/001_init_postgres.sql");

/// Last `(version, name)` recorded by the migration ledger in the SQL file --
/// the answer the harness must be expecting, computed without consulting the
/// harness or `ferrogate_storage`.
fn init_sql_head_migration() -> (u64, String) {
    let mut head: Option<(u64, String)> = None;
    let mut lines = CONTROL_PLANE_INIT_SQL.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "INSERT INTO storage_schema_migrations (version, name)" {
            continue;
        }
        let values = lines
            .find(|candidate| !candidate.trim().is_empty())
            .expect("a migration ledger INSERT must be followed by its VALUES clause");
        let body = values
            .trim()
            .strip_prefix("VALUES (")
            .and_then(|rest| rest.split(')').next())
            .and_then(|body| body.split_once(", "))
            .unwrap_or_else(|| panic!("unparsable migration ledger VALUES clause: {values}"));
        let version: u64 = body
            .0
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("unparsable migration version: {values}"));
        if head.as_ref().is_none_or(|(seen, _)| version > *seen) {
            head = Some((version, body.1.trim().trim_matches('\'').to_string()));
        }
    }
    head.expect("sql/001_init_postgres.sql must record migrations")
}

/// The `supabase-restart` migration assertion must expect the head of the SQL
/// the scenario actually applies.
///
/// Catches: the #511 regression in its original form -- a hand-written
/// `"50:050_bucket_backed_asset_size_constraint"` (or any other literal) in
/// place of the derived head. Because the expected value is recomputed here from
/// the SQL, ANY divergence between the harness's expectation and the file reds,
/// including the harness simply falling behind a new migration.
#[test]
fn the_supabase_restart_migration_expectation_is_the_head_of_the_applied_sql() {
    let (version, name) = init_sql_head_migration();
    assert_eq!(expected_head_migration(), format!("{version}:{name}"));
}

/// No second hard-coded migration identity may live in the scenario file.
///
/// Catches: a future slice re-introducing a pinned migration name or
/// `<version>:<name>` marker anywhere in `storage.rs` (a new "and migration 61
/// must be present" check, say) -- the exact shape that made this scenario fail
/// on its own bookkeeping instead of on the durability it exists to prove. The
/// only permitted way to name the head is `expected_head_migration`.
#[test]
fn the_scenario_file_carries_no_hand_written_migration_literal() {
    const SCENARIO_SOURCE: &str = include_str!("storage.rs");
    let bytes = SCENARIO_SOURCE.as_bytes();
    let mut offenders = Vec::new();
    for (index, window) in bytes.windows(4).enumerate().skip(1) {
        // A migration identity always reads as three digits then '_', quoted
        // (`"059_..."`) or preceded by its version (`"59:059_..."`).
        let looks_like_name = window[0].is_ascii_digit()
            && window[1].is_ascii_digit()
            && window[2].is_ascii_digit()
            && window[3] == b'_';
        let anchored = matches!(bytes[index - 1], b'"' | b'\'' | b':');
        if looks_like_name && anchored {
            let end = (index + 40).min(bytes.len());
            offenders.push(String::from_utf8_lossy(&bytes[index..end]).into_owned());
        }
    }
    assert!(
        offenders.is_empty(),
        "storage.rs must derive the schema head from ferrogate_storage, but it \
         names migrations directly: {offenders:?}"
    );
    assert!(
        SCENARIO_SOURCE.contains("ferrogate_storage::POSTGRES_SCHEMA_VERSION")
            && SCENARIO_SOURCE.contains("ferrogate_storage::POSTGRES_SCHEMA_NAME"),
        "the scenario must still read the derived head it is meant to assert against"
    );
}
