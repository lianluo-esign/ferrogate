// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::{
    assertions::{assert_array_contains, assert_secret_redacted, list_contains},
    fixtures::toml_basic_string,
    http::{free_addr, http_request_addr},
    ADMIN_AUTH, CLIENT_AUTH, JSON_CONTENT,
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env,
    io::Read,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub(crate) struct MySqlRestartTls<'a> {
    pub(crate) mode: &'a str,
    pub(crate) ca_cert_path: Option<&'a Path>,
}

#[derive(Clone, Copy)]
pub(crate) struct PostgresRestartTls<'a> {
    pub(crate) mode: &'a str,
    pub(crate) ca_cert_path: Option<&'a Path>,
}

#[derive(Clone, Copy)]
pub(crate) enum ControlPlaneRestartStorage<'a> {
    Postgres {
        dsn: &'a str,
        tls: PostgresRestartTls<'a>,
    },
    Supabase {
        dsn: &'a str,
        tls: PostgresRestartTls<'a>,
    },
    Mysql {
        dsn: &'a str,
        tls: MySqlRestartTls<'a>,
    },
}

impl ControlPlaneRestartStorage<'_> {
    pub(crate) fn supports_durable_metering(self) -> bool {
        matches!(
            self,
            ControlPlaneRestartStorage::Postgres { .. }
                | ControlPlaneRestartStorage::Supabase { .. }
        )
    }

    pub(crate) fn provider_name(self) -> &'static str {
        match self {
            ControlPlaneRestartStorage::Supabase { .. } => "supabase",
            ControlPlaneRestartStorage::Postgres { .. } => "postgres",
            ControlPlaneRestartStorage::Mysql { .. } => "mysql",
        }
    }

    pub(crate) fn apply_env(self, command: &mut Command) {
        match self {
            ControlPlaneRestartStorage::Postgres { dsn, .. } => {
                command.env("FERROGATE_POSTGRES_DSN", dsn);
            }
            ControlPlaneRestartStorage::Supabase { dsn, .. } => {
                command.env("FERROGATE_SUPABASE_DSN", dsn);
            }
            ControlPlaneRestartStorage::Mysql { dsn, .. } => {
                command.env("FERROGATE_MYSQL_DSN", dsn);
            }
        }
    }

    fn storage_block_with_migration_mode(self, migration_mode: StorageMigrationMode) -> String {
        match self {
            ControlPlaneRestartStorage::Postgres { tls, .. } => {
                let ca_cert_path = tls
                    .ca_cert_path
                    .map(|path| {
                        format!(
                            "\n  postgres_tls_ca_cert_path: {}",
                            toml_basic_string(&path.to_string_lossy())
                        )
                    })
                    .unwrap_or_default();
                format!(
                    r#"storage:
  provider: postgres
  required: true
  provider_order:
    - supabase
    - postgres
    - mysql
  postgres_dsn_env: FERROGATE_POSTGRES_DSN
  postgres_pool_size: 2
  postgres_tls_mode: {tls_mode}{ca_cert_path}
  postgres_connect_timeout_secs: 5
  postgres_statement_timeout_millis: 30000
  postgres_schema: ferrogate_control
  postgres_search_path:
    - public
  migration_mode: {migration_mode}"#,
                    tls_mode = tls.mode,
                    ca_cert_path = ca_cert_path,
                    migration_mode = migration_mode.as_str()
                )
            }
            ControlPlaneRestartStorage::Supabase { tls, .. } => {
                let ca_cert_path = tls
                    .ca_cert_path
                    .map(|path| {
                        format!(
                            "\n  postgres_tls_ca_cert_path: {}",
                            toml_basic_string(&path.to_string_lossy())
                        )
                    })
                    .unwrap_or_default();
                format!(
                    r#"storage:
  provider: supabase
  required: true
  provider_order:
    - supabase
    - postgres
    - mysql
  supabase_dsn_env: FERROGATE_SUPABASE_DSN
  postgres_pool_size: 2
  postgres_tls_mode: {tls_mode}{ca_cert_path}
  postgres_connect_timeout_secs: 5
  postgres_statement_timeout_millis: 30000
  postgres_schema: ferrogate_control
  postgres_search_path:
    - public
  migration_mode: {migration_mode}"#,
                    tls_mode = tls.mode,
                    ca_cert_path = ca_cert_path,
                    migration_mode = migration_mode.as_str()
                )
            }
            ControlPlaneRestartStorage::Mysql { tls, .. } => {
                let ca_cert_path = tls
                    .ca_cert_path
                    .map(|path| {
                        format!(
                            "\n  mysql_tls_ca_cert_path: {}",
                            toml_basic_string(&path.to_string_lossy())
                        )
                    })
                    .unwrap_or_default();
                format!(
                    r#"storage:
  provider: mysql
  required: true
  provider_order:
    - supabase
    - postgres
    - mysql
  mysql_dsn_env: FERROGATE_MYSQL_DSN
  mysql_pool_size: 2
  mysql_tls_mode: {tls_mode}{ca_cert_path}
  mysql_connect_timeout_secs: 5
  migration_mode: {migration_mode}"#,
                    tls_mode = tls.mode,
                    ca_cert_path = ca_cert_path,
                    migration_mode = migration_mode.as_str()
                )
            }
        }
    }

    pub(crate) fn restart_config(
        self,
        gateway_addr: &str,
        include_plugins: bool,
        include_mcp_server: bool,
        migration_mode: StorageMigrationMode,
        provider_base_url: Option<&str>,
    ) -> String {
        let plugins = if include_plugins {
            r#"
plugins:
  - id: tool.echo
    kind: tool_provider
    source: builtin
    enabled: true
    order: 10
    approval_policy: never
    permissions:
      tools:
        - tool.echo
"#
        } else {
            ""
        };
        let mcp_server = if include_mcp_server {
            r#"
mcp_servers:
  - name: dbhttp
    transport: streamable_http
    url: "http://127.0.0.1:1/mcp"
    tools_to_execute:
      - search
    tools_to_auto_execute:
      - search
    tool_include:
      - search
    approval_policy: never
    timeout_ms: 100
"#
        } else {
            ""
        };
        let provider_base_url = provider_base_url.unwrap_or("http://127.0.0.1:1/v1");
        format!(
            r#"
listen: "{gateway_addr}"

{storage}

reliability:
  tool_approval_timeout_secs: 1

providers:
  - name: openai
    kind: openai
    base_url: "{provider_base_url}"
    api_key_env: FERROGATE_PROVIDER_SECRET

models:
  - name: fast-chat
    provider: openai
    provider_model: gpt-4o-mini
    capabilities:
      - chat

api_keys:
  - id: admin
    name: Admin
    key: admin-secret
    scopes:
      - admin.read
      - admin.write
      - tools.read
      - tools.execute
{plugins}
{mcp_server}
"#,
            storage = self.storage_block_with_migration_mode(migration_mode),
            provider_base_url = provider_base_url
        )
    }

    pub(crate) fn live_token4ai_provider_config(
        self,
        gateway_addr: &str,
        provider_base_url: &str,
        provider_model: &str,
        migration_mode: StorageMigrationMode,
    ) -> String {
        format!(
            r#"
listen: "{gateway_addr}"

{storage}

providers:
  - name: token4ai
    kind: openai
    base_url: "{provider_base_url}"
    api_key_env: FERROGATE_PROVIDER_SECRET

models:
  - name: live-chat
    provider: token4ai
    provider_model: "{provider_model}"
    capabilities:
      - chat

api_keys:
  - id: client
    name: Live Token4AI client
    key: client-secret
    scopes:
      - models.read
      - chat.completions
    allowed_models:
      - live-chat
    organization_id: org_token4ai_live
    project_id: project_gateway
  - id: admin
    name: Admin
    key: admin-secret
    scopes:
      - admin.read
      - admin.write
"#,
            storage = self.storage_block_with_migration_mode(migration_mode),
            provider_base_url = provider_base_url,
            provider_model = provider_model,
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) enum StorageMigrationMode {
    Auto,
    ValidateOnly,
}

impl StorageMigrationMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            StorageMigrationMode::Auto => "auto",
            StorageMigrationMode::ValidateOnly => "validate_only",
        }
    }
}

pub(crate) struct TursoRestartHarness {
    _dir: tempfile::TempDir,
    gateway_addr: String,
    gateway: Child,
    stderr: Option<std::process::ChildStderr>,
    expected_storage_provider: &'static str,
    expected_migration_mode: StorageMigrationMode,
}

impl TursoRestartHarness {
    pub(crate) fn start(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        include_plugins: bool,
        include_mcp_server: bool,
    ) -> Result<Self> {
        Self::start_with_migration_mode(
            ferrogate_bin,
            storage,
            include_plugins,
            include_mcp_server,
            StorageMigrationMode::Auto,
            None,
        )
    }

    pub(crate) fn start_with_migration_mode(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        include_plugins: bool,
        include_mcp_server: bool,
        migration_mode: StorageMigrationMode,
        provider_base_url: Option<&str>,
    ) -> Result<Self> {
        if !ferrogate_bin.exists() {
            bail!(
                "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
                ferrogate_bin.display()
            );
        }

        let gateway_addr = free_addr()?;
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("ferrogate.yaml");
        std::fs::write(
            &config_path,
            storage.restart_config(
                &gateway_addr,
                include_plugins,
                include_mcp_server,
                migration_mode,
                provider_base_url,
            ),
        )?;

        let mut command = Command::new(ferrogate_bin);
        command
            .args(["run", "--config"])
            .arg(&config_path)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
            command.stderr(Stdio::inherit());
        } else {
            command.stderr(Stdio::piped());
        }
        storage.apply_env(&mut command);
        let gateway = command
            .spawn()
            .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            gateway_addr,
            gateway,
            stderr: None,
            expected_storage_provider: storage.provider_name(),
            expected_migration_mode: migration_mode,
        };
        harness.stderr = harness.gateway.stderr.take();
        harness.wait_for_gateway()?;
        Ok(harness)
    }

    pub(crate) fn start_live_token4ai_provider(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        provider_base_url: &str,
        provider_model: &str,
        provider_api_key: &str,
    ) -> Result<Self> {
        Self::start_live_token4ai_provider_with_migration_mode(
            ferrogate_bin,
            storage,
            provider_base_url,
            provider_model,
            provider_api_key,
            StorageMigrationMode::Auto,
        )
    }

    pub(crate) fn start_live_token4ai_provider_with_migration_mode(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        provider_base_url: &str,
        provider_model: &str,
        provider_api_key: &str,
        migration_mode: StorageMigrationMode,
    ) -> Result<Self> {
        if !ferrogate_bin.exists() {
            bail!(
                "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
                ferrogate_bin.display()
            );
        }

        let gateway_addr = free_addr()?;
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("ferrogate-token4ai-live.yaml");
        std::fs::write(
            &config_path,
            storage.live_token4ai_provider_config(
                &gateway_addr,
                provider_base_url,
                provider_model,
                migration_mode,
            ),
        )?;

        let mut command = Command::new(ferrogate_bin);
        command
            .args(["run", "--config"])
            .arg(&config_path)
            .env("FERROGATE_PROVIDER_SECRET", provider_api_key)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
            command.stderr(Stdio::inherit());
        } else {
            command.stderr(Stdio::piped());
        }
        storage.apply_env(&mut command);
        let gateway = command
            .spawn()
            .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            gateway_addr,
            gateway,
            stderr: None,
            expected_storage_provider: storage.provider_name(),
            expected_migration_mode: migration_mode,
        };
        harness.stderr = harness.gateway.stderr.take();
        harness.wait_for_gateway()?;
        Ok(harness)
    }

    fn wait_for_gateway(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(60) {
            if let Some(status) = self.gateway.try_wait()? {
                let stderr = self.read_stderr();
                assert_secret_redacted(&stderr);
                bail!(
                    "ferrogate process exited before readiness check: {status}; stderr: {stderr}"
                );
            }
            match http_request_addr(&self.gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(250));
        }
        bail!(
            "timed out waiting for durable-storage FerroGate on {}; last response: {last}",
            self.gateway_addr
        );
    }

    fn read_stderr(&mut self) -> String {
        let Some(mut stderr) = self.stderr.take() else {
            return String::new();
        };
        let mut output = String::new();
        let _ = stderr.read_to_string(&mut output);
        output
    }

    pub(crate) fn expect_json<F>(
        &self,
        method: &str,
        path: &str,
        headers: &[&str],
        body: &str,
        expected_status: u16,
        check: F,
    ) -> Result<()>
    where
        F: FnOnce(Value) -> Result<()>,
    {
        let response = http_request_addr(&self.gateway_addr, method, path, headers, body)
            .with_context(|| format!("failed HTTP request {method} {path}"))?;
        if response.status != expected_status {
            bail!(
                "{method} {path} expected status {expected_status}, got {}; raw: {}",
                response.status,
                response.raw
            );
        }
        let body: Value = serde_json::from_str(&response.body).with_context(|| {
            format!(
                "failed to parse JSON body for {method} {path}: {}",
                response.body
            )
        })?;
        check(body)
    }

    pub(crate) fn expect_storage_status(&self) -> Result<()> {
        self.expect_json("GET", "/admin/v1/status", &[ADMIN_AUTH], "", 200, |body| {
            assert_eq!(body["storage"]["provider"], self.expected_storage_provider);
            assert_eq!(body["storage"]["durable"], true);
            assert_eq!(body["storage"]["implemented"], true);
            assert_eq!(body["storage"]["required"], true);
            assert_eq!(
                body["storage"]["migration_mode"],
                self.expected_migration_mode.as_str()
            );
            assert_eq!(body["storage"]["health"], "ok");
            assert_eq!(body["storage"]["provider_order"][0], "supabase");
            assert_eq!(body["storage"]["provider_order"][1], "postgres");
            assert_eq!(body["storage"]["provider_order"][2], "mysql");
            if matches!(self.expected_storage_provider, "supabase" | "postgres") {
                assert_eq!(body["storage"]["schema"]["engine"], "postgres");
                assert_eq!(body["storage"]["schema"]["version"], 3);
                assert_eq!(
                    body["storage"]["schema"]["name"],
                    "003_supabase_structured_metering_usage"
                );
                assert_eq!(body["storage"]["schema"]["validated"], true);
                assert!(body["storage"]["schema"]["checksum"]
                    .as_str()
                    .is_some_and(|checksum| checksum.len() == 16));
            } else {
                assert!(body["storage"]["schema"].is_null());
            }
            assert_secret_redacted(&body.to_string());
            Ok(())
        })
    }

    pub(crate) fn expect_api_key(&self, id: &str) -> Result<()> {
        self.expect_api_key_named(id, "Durable storage restart test key")
    }

    pub(crate) fn expect_api_key_named(&self, id: &str, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/api-keys/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["key"]["id"], id);
                assert_eq!(body["key"]["name"], name);
                assert_eq!(body["key"]["key_source"], "inline");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_restored_api_key_models_access(&self, id: &str) -> Result<()> {
        let auth = format!("Authorization: Bearer {id}-secret");
        self.expect_json("GET", "/v1/models", &[auth.as_str()], "", 200, |body| {
            assert!(list_contains(&body, "id", "fast-chat"));
            assert_secret_redacted(&body.to_string());
            Ok(())
        })
    }

    pub(crate) fn expect_gateway_config(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/gateway-configs/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["gateway_config"]["id"], id);
                assert_eq!(
                    body["gateway_config"]["name"],
                    "Durable storage restart profile"
                );
                assert_eq!(body["gateway_config"]["revision"], 7);
                assert_eq!(body["gateway_config"]["cache_enabled"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_metered_chat_completion(
        &self,
        api_key_id: &str,
        profile_id: &str,
    ) -> Result<()> {
        let auth = format!("Authorization: Bearer {api_key_id}-secret");
        let profile = format!("x-ferrogate-config: {profile_id}");
        self.expect_json(
            "POST",
            "/v1/chat/completions",
            &[auth.as_str(), JSON_CONTENT, profile.as_str()],
            r#"{"model":"fast-chat","messages":[{"role":"user","content":"durable metering check"}]}"#,
            200,
            |body| {
                assert_eq!(body["object"], "chat.completion");
                assert_eq!(body["usage"]["total_tokens"], 2);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_durable_metering_usage(
        &self,
        api_key_id: &str,
        expected_total: u64,
    ) -> Result<()> {
        self.expect_json(
            "GET",
            "/admin/v1/metering-events?limit=100",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let events = body["data"]
                    .as_array()
                    .context("metering events response data must be an array")?;
                let event = events
                    .iter()
                    .find(|event| {
                        event["tenant"]["api_key_id"] == api_key_id
                            && event["logical_model"] == "fast-chat"
                            && event["provider"] == "openai"
                    })
                    .with_context(|| {
                        format!("durable metering event for API key {api_key_id} was not found")
                    })?;
                assert_eq!(event["usage_source"], "provider_usage");
                assert_eq!(event["usage"]["total_tokens"], expected_total);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;

        self.expect_json(
            "GET",
            "/admin/v1/usage-aggregates",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let aggregates = body["data"]
                    .as_array()
                    .context("usage aggregates response data must be an array")?;
                let aggregate = aggregates
                    .iter()
                    .find(|aggregate| {
                        aggregate["api_key_id"] == api_key_id
                            && aggregate["logical_model"] == "fast-chat"
                            && aggregate["provider"] == "openai"
                    })
                    .with_context(|| {
                        format!(
                            "durable usage aggregate for API key {api_key_id} was not found in {body}"
                        )
                    })?;
                assert_eq!(aggregate["usage"]["total_tokens"], expected_total);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_durable_request_and_audit_evidence(&self, api_key_id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            "/admin/v1/request-logs?limit=100",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let logs = body["data"]
                    .as_array()
                    .context("request logs response data must be an array")?;
                let log = logs
                    .iter()
                    .find(|log| {
                        log["tenant"]["api_key_id"] == api_key_id
                            && log["logical_model"] == "fast-chat"
                            && log["provider"] == "openai"
                            && log["status_code"] == 200
                    })
                    .with_context(|| {
                        format!(
                            "durable request log for API key {api_key_id} was not found in {body}"
                        )
                    })?;
                assert_eq!(log["prompt_recorded"], false);
                assert_eq!(log["response_recorded"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;

        self.expect_json(
            "GET",
            "/admin/v1/audit-events?limit=200",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let events = body["data"]
                    .as_array()
                    .context("audit events response data must be an array")?;
                let event = events
                    .iter()
                    .find(|event| {
                        event["actor_api_key_id"] == "admin"
                            && event["target"].as_str().is_some_and(|target| {
                                target == api_key_id || target.contains(api_key_id)
                            })
                            && event["outcome"] == "committed"
                    })
                    .with_context(|| {
                        format!(
                            "durable audit event for API key {api_key_id} was not found in {body}"
                        )
                    })?;
                assert!(event["action"].as_str().is_some_and(|action| {
                    action == "api_key.upsert" || action == "api_key.delete"
                }));
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_live_token4ai_completion(
        &self,
        request_marker: &str,
        provider_model: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "model": "live-chat",
            "messages": [
                {
                    "role": "user",
                    "content": format!("Reply with exactly: ok. Marker: {request_marker}")
                }
            ],
            "max_tokens": 64
        })
        .to_string();
        self.expect_json(
            "POST",
            "/v1/chat/completions",
            &[CLIENT_AUTH, JSON_CONTENT],
            &body,
            200,
            |body| {
                assert_eq!(body["object"], "chat.completion");
                assert!(
                    body["usage"]["total_tokens"].as_u64().unwrap_or_default() > 0,
                    "provider usage total_tokens must be positive: {body}"
                );
                assert_secret_redacted(&body.to_string());
                if let Some(model) = body["model"].as_str() {
                    assert!(
                        !model.trim().is_empty(),
                        "provider response model must not be empty"
                    );
                } else {
                    assert!(
                        !provider_model.trim().is_empty(),
                        "configured provider model must not be empty"
                    );
                }
                Ok(())
            },
        )
    }

    pub(crate) fn expect_live_token4ai_metering_usage(
        &self,
        request_marker: &str,
        provider_model: &str,
    ) -> Result<()> {
        let event_total = self.live_token4ai_metering_total(request_marker, provider_model)?;
        if event_total == 0 {
            bail!("live Token4AI metering total_tokens must be positive");
        }

        self.expect_json(
            "GET",
            "/admin/v1/usage-aggregates",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let aggregates = body["data"]
                    .as_array()
                    .context("usage aggregates response data must be an array")?;
                let aggregate = aggregates
                    .iter()
                    .find(|aggregate| {
                        aggregate["api_key_id"] == "client"
                            && aggregate["logical_model"] == "live-chat"
                            && aggregate["provider"] == "token4ai"
                    })
                    .with_context(|| {
                        format!(
                            "live Token4AI usage aggregate for marker {request_marker} was not found in {body}"
                        )
                    })?;
                assert_eq!(aggregate["usage"]["total_tokens"], event_total);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn live_token4ai_metering_total(
        &self,
        request_marker: &str,
        provider_model: &str,
    ) -> Result<u64> {
        let mut total = 0;
        self.expect_json(
            "GET",
            "/admin/v1/metering-events?limit=100",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let events = body["data"]
                    .as_array()
                    .context("metering events response data must be an array")?;
                let event = events
                    .iter()
                    .rev()
                    .find(|event| {
                        event["tenant"]["api_key_id"] == "client"
                            && event["logical_model"] == "live-chat"
                            && event["provider"] == "token4ai"
                    })
                    .with_context(|| {
                        format!(
                            "live Token4AI metering event for marker {request_marker} was not found in {body}"
                        )
                    })?;
                assert_eq!(event["provider_model"], provider_model);
                assert_eq!(event["usage_source"], "provider_usage");
                total = event["usage"]["total_tokens"]
                    .as_u64()
                    .context("metering event usage.total_tokens must be an integer")?;
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        Ok(total)
    }

    pub(crate) fn expect_policy(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/policies/{name}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["policy"]["name"], name);
                assert_eq!(body["policy"]["enabled"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_missing_api_key(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/api-keys/{id}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "api_key_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_missing_gateway_config(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/gateway-configs/{id}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "gateway_config_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_missing_policy(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/policies/{name}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "policy_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_restored_policy_denies_chat(&self, id: &str) -> Result<()> {
        let auth = format!("Authorization: Bearer {id}-secret");
        self.expect_json(
            "POST",
            "/v1/chat/completions",
            &[auth.as_str(), JSON_CONTENT],
            r#"{"model":"fast-chat","messages":[{"role":"user","content":"durable policy check"}]}"#,
            403,
            |body| {
                assert_eq!(body["error"]["code"], "blocked_by_storage_restart_test");
                assert_eq!(
                    body["error"]["message"],
                    "blocked by durable storage restart test"
                );
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_prompt_template(&self, id: &str, status: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/prompt-templates/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["prompt_template"]["id"], id);
                assert_eq!(
                    body["prompt_template"]["name"],
                    "Durable storage restart prompt"
                );
                assert_eq!(body["prompt_template"]["status"], status);
                assert_eq!(body["prompt_template"]["active_revision"], 1);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_agent_upstream(&self, id: &str, enabled: bool) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/agent-upstreams/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["agent_upstream"]["id"], id);
                assert_eq!(body["agent_upstream"]["enabled"], enabled);
                assert_eq!(body["agent_upstream"]["protocol"], "a2a");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_missing_agent_upstream(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/agent-upstreams/{id}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "agent_upstream_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_restored_prompt_template_render(
        &self,
        api_key_id: &str,
        template_id: &str,
    ) -> Result<()> {
        let auth = format!("Authorization: Bearer {api_key_id}-secret");
        self.expect_json(
            "POST",
            &format!("/v1/prompts/{template_id}/render"),
            &[auth.as_str(), JSON_CONTENT],
            r#"{"variables":{"topic":"durable storage"}}"#,
            200,
            |body| {
                assert_eq!(body["model"], "fast-chat");
                assert_eq!(body["temperature"], 0.1);
                assert_eq!(body["messages"][0]["role"], "user");
                assert_eq!(body["messages"][0]["content"], "Summarize durable storage");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_mcp_server(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            "/admin/v1/mcp-servers",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let servers = body["data"]
                    .as_array()
                    .context("mcp servers response data must be an array")?;
                let server = servers
                    .iter()
                    .find(|server| server["name"] == name)
                    .with_context(|| format!("MCP server {name} was not restored from storage"))?;
                assert_eq!(server["transport"], "streamable_http");
                assert_eq!(server["health"], "degraded");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_missing_mcp_server(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/mcp-servers/{name}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "mcp_server_not_found");
                Ok(())
            },
        )
    }

    pub(crate) fn register_echo_plugin(&self) -> Result<()> {
        self.register_echo_plugin_with_policy("never")
    }

    fn register_echo_plugin_with_policy(&self, approval_policy: &str) -> Result<()> {
        let body = serde_json::json!({
            "id": "tool.echo",
            "kind": "tool_provider",
            "source": "builtin",
            "enabled": true,
            "order": 10,
            "approval_policy": approval_policy,
            "permissions": {
                "tools": ["tool.echo"],
                "network": [],
                "filesystem": false,
                "shell": false
            },
            "config": {
                "registered_by": "ferrogate-test"
            }
        })
        .to_string();
        self.expect_json(
            "POST",
            "/admin/v1/plugins",
            &[ADMIN_AUTH, JSON_CONTENT],
            &body,
            201,
            |body| {
                assert_eq!(body["object"], "plugin");
                assert_eq!(body["plugin"]["id"], "tool.echo");
                assert_eq!(body["plugin"]["kind"], "tool_provider");
                assert_eq!(body["plugin"]["source"], "builtin");
                assert_eq!(body["plugin"]["enabled"], true);
                assert_eq!(body["plugin"]["active"], true);
                assert_eq!(body["plugin"]["health"], "ok");
                assert_eq!(body["plugin"]["approval_policy"], approval_policy);
                assert_array_contains(&body["plugin"]["capabilities"], "tool_provider")
                    .context("registered plugin must advertise tool_provider capability")?;
                assert_array_contains(&body["plugin"]["tools"], "tool.echo")
                    .context("registered plugin must expose tool.echo")?;
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn register_mcp_server(&self, name: &str) -> Result<()> {
        let body = serde_json::json!({
            "name": name,
            "transport": "streamable_http",
            "url": "http://127.0.0.1:1/mcp",
            "auth_type": "none",
            "tools_to_execute": ["search"],
            "tools_to_auto_execute": ["search"],
            "approval_policy": "never",
            "tool_include": ["search"],
            "tool_regex": [],
            "headers": [],
            "tls": {},
            "timeout_ms": 100,
            "health_ping_interval_secs": 30,
            "max_reconnect_attempts": 3,
            "min_reconnect_backoff_secs": 1,
            "max_reconnect_backoff_secs": 5
        })
        .to_string();
        self.expect_json(
            "POST",
            "/admin/v1/mcp-servers",
            &[ADMIN_AUTH, JSON_CONTENT],
            &body,
            201,
            |body| {
                assert_eq!(body["object"], "mcp_server");
                assert_eq!(body["server"]["name"], name);
                assert_eq!(body["server"]["transport"], "streamable_http");
                assert_eq!(body["server"]["health"], "degraded");
                assert_eq!(body["server"]["connected"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn delete_mcp_server(&self, name: &str) -> Result<()> {
        self.expect_json(
            "DELETE",
            &format!("/admin/v1/mcp-servers/{name}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["object"], "mcp_server");
                assert_eq!(body["id"], name);
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )
    }

    pub(crate) fn create_expired_echo_approval(&self) -> Result<String> {
        self.register_echo_plugin_with_policy("always")?;
        let mut request_id = String::new();
        self.expect_json(
            "POST",
            "/v1/tools/execute",
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"name":"tool.echo","arguments":{"message":"approval durability"}}"#,
            403,
            |body| {
                assert_eq!(body["error"]["code"], "tool_denied");
                request_id = body["error"]["request_id"]
                    .as_str()
                    .context("tool approval error response must include request_id")?
                    .to_string();
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        let mut approval_id = String::new();
        self.expect_json(
            "GET",
            "/admin/v1/tool-approvals",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let approvals = body["data"]
                    .as_array()
                    .context("tool approvals response data must be an array")?;
                let approval = approvals
                    .iter()
                    .find(|approval| approval["request_id"] == request_id)
                    .with_context(|| {
                        format!("tool approval for request {request_id} was not persisted")
                    })?;
                assert_eq!(approval["tool_name"], "tool.echo");
                assert_eq!(approval["status"], "expired");
                assert_eq!(approval["approval_policy"], "always");
                assert_secret_redacted(&body.to_string());
                approval_id = approval["id"]
                    .as_str()
                    .context("tool approval id missing")?
                    .to_string();
                Ok(())
            },
        )?;
        Ok(approval_id)
    }

    pub(crate) fn expect_tool_approval(&self, id: &str, status: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/tool-approvals/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["id"], id);
                assert_eq!(body["tool_name"], "tool.echo");
                assert_eq!(body["status"], status);
                assert_eq!(body["approval_policy"], "always");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_plugin(&self, id: &str) -> Result<()> {
        self.expect_json("GET", "/admin/v1/plugins", &[ADMIN_AUTH], "", 200, |body| {
            let plugins = body["data"]
                .as_array()
                .context("plugins response data must be an array")?;
            let plugin = plugins
                .iter()
                .find(|plugin| plugin["id"] == id)
                .with_context(|| format!("plugin {id} was not restored from storage"))?;
            assert_eq!(plugin["source"], "builtin");
            assert_eq!(plugin["enabled"], true);
            assert_eq!(plugin["active"], true);
            assert_eq!(plugin["health"], "ok");
            assert_array_contains(&plugin["capabilities"], "tool_provider")
                .context("plugin must advertise the tool_provider capability")?;
            assert_array_contains(&plugin["tools"], "tool.echo")
                .context("plugin must advertise its registered tool")?;
            assert_secret_redacted(&body.to_string());
            Ok(())
        })?;
        self.expect_json(
            "GET",
            &format!("/admin/v1/plugins/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["id"], id);
                assert_eq!(body["source"], "builtin");
                assert_eq!(body["enabled"], true);
                assert_eq!(body["active"], true);
                assert_eq!(body["health"], "ok");
                assert_array_contains(&body["capabilities"], "tool_provider")
                    .context("plugin detail must advertise the tool_provider capability")?;
                assert_array_contains(&body["tools"], "tool.echo")
                    .context("plugin detail must advertise its registered tool")?;
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        self.expect_json(
            "GET",
            &format!("/admin/v1/plugins/{id}/tools"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let tools = body["data"]
                    .as_array()
                    .context("plugin tools response data must be an array")?;
                let tool = tools
                    .iter()
                    .find(|tool| tool["name"] == "tool.echo")
                    .context("plugin tool.echo was not listed")?;
                assert_eq!(tool["extension_id"], id);
                assert_eq!(tool["approval_policy"], "never");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_echo_tool(&self) -> Result<()> {
        self.expect_json(
            "POST",
            "/v1/tools/execute",
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"name":"tool.echo","arguments":{"message":"plugin durable restore"}}"#,
            200,
            |body| {
                assert_eq!(body["object"], "tool_execution");
                assert_eq!(body["name"], "tool.echo");
                assert_eq!(body["content"]["echo"]["message"], "plugin durable restore");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }
}

impl Drop for TursoRestartHarness {
    fn drop(&mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
    }
}
