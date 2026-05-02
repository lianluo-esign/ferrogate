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
    assert!(stdout.contains("routes=1"));
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
    assert!(stdout.contains("planned for P2"));
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
