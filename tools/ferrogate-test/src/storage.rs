// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::fixtures::toml_basic_string;
use std::{path::Path, process::Command};

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
