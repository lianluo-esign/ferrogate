// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::process::Command;

fn ferrogate() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ferrogate"))
}

#[test]
fn check_accepts_ferrogate_caddyfile_fixture() {
    let output = ferrogate()
        .args(["validate", "--config", "../../Ferrogate/Caddyfile"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FerroGate config OK"));
    assert!(stdout.contains("admin=localhost:2019"));
    assert!(stdout.contains("snapshot="));
    assert!(stdout.contains("upstreams=1"));
    assert!(stdout.contains("providers=1"));
    assert!(stdout.contains("models=1"));
    assert!(stdout.contains("api_keys=1"));
    assert!(stdout.contains("auth_required=true"));
}

#[test]
fn check_accepts_existing_toml_configuration() {
    let output = ferrogate()
        .args([
            "validate",
            "--config",
            "../../config/ferrogate.example.toml",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("providers=4"));
    assert!(stdout.contains("models=3"));
    assert!(stdout.contains("api_keys=1"));
}

#[test]
fn check_reports_unsupported_directive_with_source_span_and_hint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Caddyfile");
    std::fs::write(
        &path,
        r#"
:8080 {
    file_server
}
"#,
    )
    .unwrap();

    let output = ferrogate()
        .args(["validate", "--config", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("file_server"));
    assert!(stderr.contains("unsupported directive"));
    assert!(stderr.contains("supported MVP directives"));
    assert!(stderr.contains("Caddyfile:3:5"));
}

#[test]
fn check_alias_remains_compatible_with_validate() {
    let output = ferrogate()
        .args(["check", "--config", "../../Ferrogate/Caddyfile"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn validate_uses_default_ferrogate_caddyfile_path() {
    let output = ferrogate()
        .arg("validate")
        .current_dir("../..")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("FerroGate config OK"));
}

#[test]
fn validate_uses_ferrogate_config_environment_variable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &path,
        // #542: a pure L7 reverse proxy with no credential source states its
        // posture, or `validate` refuses it exactly as `run` would.
        r#"
listen = "127.0.0.1:0"

[auth]
disabled = true

[[upstreams]]
name = "env"
url = "http://127.0.0.1:18080"

[[routes]]
name = "env"
upstream = "env"
path_prefixes = ["/env"]
"#,
    )
    .unwrap();

    let output = ferrogate()
        .arg("validate")
        .env("FERROGATE_CONFIG", &path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("listen=127.0.0.1:0"));
}

/// #542 rework, finding 3: `ferrogate check` is the documented pre-flight for a
/// release that intentionally stops existing deployments, so it must be where an
/// operator finds out -- not the next restart.
///
/// Pins the `ensure_auth_posture_is_declared(config)?` call in
/// `lifecycle::format_validate_report` and the `?` on it in `lib.rs`. Delete
/// either and this config prints `FerroGate config OK ... auth_required=true`
/// and exits 0, for a config `ferrogate run` refuses to boot.
#[test]
fn check_refuses_a_config_with_no_credential_source_and_names_both_remedies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &path,
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "env"
url = "http://127.0.0.1:18080"

[[routes]]
name = "env"
upstream = "env"
path_prefixes = ["/env"]
"#,
    )
    .unwrap();

    let output = ferrogate()
        .args(["check", "--config", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("FerroGate config OK"), "{stdout}");
    assert!(stderr.contains("no credential source"), "{stderr}");
    assert!(stderr.contains("disabled = true"), "{stderr}");
}

/// #542 rework, finding 2: the Caddy-migrated deployment. A keyless Caddyfile
/// reverse proxy is refused with a remedy its own config format can express,
/// and accepted once it says `auth off` -- the case that had no test at all.
///
/// Pins the `"auth"` global-options arm in `caddyfile/parser.rs`, the bridge
/// mapping in `config/loader.rs`, and the Caddyfile spelling in the refusal.
#[test]
fn check_offers_a_keyless_caddyfile_a_remedy_it_can_actually_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Caddyfile");
    let reverse_proxy_only = r#"
:8080 {
    handle_path /proxy/* {
        reverse_proxy https://httpbin.org
    }
}
"#;
    std::fs::write(&path, reverse_proxy_only).unwrap();

    let refused = ferrogate()
        .args(["check", "--config", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("no credential source"), "{stderr}");
    assert!(stderr.contains("auth off"), "{stderr}");

    std::fs::write(&path, format!("{{\n    auth off\n}}\n{reverse_proxy_only}")).unwrap();

    let accepted = ferrogate()
        .args(["check", "--config", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        accepted.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let stdout = String::from_utf8_lossy(&accepted.stdout);
    assert!(stdout.contains("FerroGate config OK"), "{stdout}");
    assert!(stdout.contains("auth_required=false"), "{stdout}");
}

#[test]
fn reload_validates_config_and_reports_planned_execution() {
    let output = ferrogate()
        .args(["reload", "--config", "../../Ferrogate/Caddyfile"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FerroGate reload config OK"));
    assert!(stdout.contains("snapshot="));
    assert!(stdout.contains("mode=validate-only"));
    assert!(stdout.contains("swap=false"));
    assert!(stdout.contains("--admin-url"));
    assert!(stdout.contains("--graceful-upgrade"));
}

#[test]
fn reload_admin_api_mode_requires_admin_token() {
    let output = ferrogate()
        .args([
            "reload",
            "--config",
            "../../Ferrogate/Caddyfile",
            "--admin-url",
            "http://127.0.0.1:8080",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("admin reload requires --admin-token"));
}

#[test]
fn reload_graceful_upgrade_requires_pid_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(&path, r#"listen = "127.0.0.1:0""#).unwrap();

    let output = ferrogate()
        .args([
            "reload",
            "--config",
            path.to_str().unwrap(),
            "--graceful-upgrade",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("graceful upgrade reload requires"));
    assert!(stderr.contains("graceful_upgrade_pid_file"));
}

#[test]
fn reload_rejects_invalid_candidate_before_reporting_swap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(&path, r#"listen = "not-an-address""#).unwrap();

    let output = ferrogate()
        .args(["reload", "--config", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("FerroGate reload config OK"));
    assert!(!stdout.contains("swap=false"));
    assert!(stderr.contains("field listen"));
}

#[test]
fn validate_does_not_echo_inline_api_key_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &path,
        r#"
listen = "127.0.0.1:0"

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "super-secret-inline"
"#,
    )
    .unwrap();

    let output = ferrogate()
        .args(["validate", "--config", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("super-secret-inline"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("super-secret-inline"));
}

#[test]
fn reload_does_not_echo_secret_env_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &path,
        r#"
listen = "127.0.0.1:0"

[[api_keys]]
id = "key_dev"
name = "Development key"
key_env = "FERROGATE_TEST_SECRET"
"#,
    )
    .unwrap();

    let output = ferrogate()
        .args(["reload", "--config", path.to_str().unwrap()])
        .env("FERROGATE_TEST_SECRET", "super-secret-env")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("super-secret-env"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("super-secret-env"));
}

#[test]
fn hash_key_generates_config_hash_without_echoing_extra_text() {
    let output = ferrogate()
        .args(["hash-key", "--secret", "client-secret"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("blake2b:"));
    assert!(!stdout.contains("client-secret"));
    assert!(String::from_utf8_lossy(&output.stderr).is_empty());
}

#[test]
fn storage_migration_rejects_unsupported_source_provider() {
    let output = ferrogate()
        .args([
            "storage",
            "migrate-to-supabase",
            "--source-provider",
            "turso_libsql",
            "--source-postgres-dsn",
            "postgresql://source:secret@127.0.0.1:5432/source",
            "--target-supabase-dsn",
            "postgresql://target:secret@127.0.0.1:5432/target",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported --source-provider turso_libsql"));
    assert!(stderr.contains("supports postgres"));
    assert!(!stderr.contains("postgresql://source:secret"));
    assert!(!stderr.contains("postgresql://target:secret"));
}

#[test]
fn storage_migration_requires_source_dsn_without_echoing_target_secret() {
    let output = ferrogate()
        .args([
            "storage",
            "migrate-to-supabase",
            "--target-supabase-dsn",
            "postgresql://target:secret@127.0.0.1:5432/target",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("source postgres DSN requires inline value or env-name argument"));
    assert!(!stderr.contains("postgresql://target:secret"));
}
