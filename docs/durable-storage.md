<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

---
title: Durable Control-Plane Storage
description: Supabase, Turso/libSQL, PostgreSQL, and MySQL storage guidance for FerroGate control-plane state.
permalink: /durable-storage/
---

# Durable Control-Plane Storage

FerroGate keeps durable control-plane storage separate from analytics storage.
This boundary is for low-frequency transactional resources that operators read
by ID and mutate through the Admin API.

Durable control-plane storage is appropriate for:

- API keys and their policy-visible metadata;
- policies;
- gateway config profiles;
- prompt template metadata and revisions;
- plugin registrations and permission declarations;
- MCP server registrations and execution allowlists;
- MCP/tool approval records used as operator evidence;
- future tenant, workspace, and agent-control resources.

It is not the primary store for high-ingest observability data. Request logs,
traces/spans, usage metrics, billing/metering analytics, and dashboard
aggregates belong to the analytics warehouse path in
[`docs/analytics-warehouse.md`](analytics-warehouse.md).

## Provider Order

The default commercial provider order is fixed in config validation:

```toml
[storage]
provider_order = ["supabase", "turso_libsql", "postgres", "mysql"]
```

`supabase` is the default commercial cloud provider. It uses the PostgreSQL wire
protocol and checked-in PostgreSQL schema while preserving Supabase-specific
config and Admin/status evidence. Turso/libSQL, PostgreSQL, and MySQL remain
implemented compatibility paths behind the same repository contract instead of
gateway-core special cases.

## Supabase

Use a Supabase direct or session-pooler DSN through an environment variable so
passwords never appear in the config file:

```yaml
storage:
  provider: supabase
  required: true
  provider_order:
    - supabase
    - turso_libsql
    - postgres
    - mysql
  supabase_dsn_env: "FERROGATE_SUPABASE_DSN"
  postgres_pool_size: 4
  postgres_tls_mode: verify_full
  postgres_tls_ca_cert_path: "/etc/ferrogate/supabase-ca.pem"
  postgres_connect_timeout_secs: 5
  postgres_statement_timeout_millis: 30000
  postgres_schema: ferrogate_control
  postgres_search_path:
    - public
  migration_mode: auto
```

Runtime behavior:

- `storage.required: true` fails closed if Supabase cannot be initialized.
- `migration_mode: auto` runs the checked-in PostgreSQL schema at startup.
- Admin/status evidence reports `provider: supabase` without returning the DSN.
- `supabase_dsn_env` is required for Supabase so credentials stay secret-backed.
- Supabase requires `postgres_tls_mode: require`, `verify_ca`, or `verify_full`.
- Direct and session-pooler DSNs are supported first. Transaction-pooler mode
  must not rely on prepared statements unless the selected Rust client path is
  explicitly verified for that mode.
- Control-plane resources use the same document-store contract as the existing
  PostgreSQL implementation.

The schema file is
[`sql/001_init_postgres.sql`](../sql/001_init_postgres.sql).

## Turso Cloud / Remote libSQL

Use a `libsql://` URL and keep the auth token in an environment variable:

```yaml
storage:
  provider: turso_libsql
  required: true
  provider_order:
    - supabase
    - turso_libsql
    - postgres
    - mysql
  libsql_url: "libsql://your-database.aws-ap-northeast-1.turso.io"
  libsql_auth_token_env: "FERROGATE_LIBSQL_AUTH_TOKEN"
  migration_mode: auto
```

Runtime behavior:

- `storage.required: true` fails closed if the durable provider cannot be
  initialized.
- `migration_mode: auto` runs the checked-in schema at startup.
- Remote `libsql://` URLs require a non-empty token.
- Admin/status evidence reports the active backend without returning the token.

The schema file is [`sql/001_init_libsql.sql`](../sql/001_init_libsql.sql). It
creates resource-oriented control-plane tables so new Admin API resource types
can be added without creating a new hot-path coupling to one database vendor.

## PostgreSQL

Use a PostgreSQL DSN through an environment variable so passwords do not appear
in the config file:

```yaml
storage:
  provider: postgres
  required: true
  provider_order:
    - supabase
    - turso_libsql
    - postgres
    - mysql
  postgres_dsn_env: "FERROGATE_POSTGRES_DSN"
  postgres_pool_size: 4
  postgres_tls_mode: verify_full
  postgres_tls_ca_cert_path: "/etc/ferrogate/postgres-ca.pem"
  postgres_connect_timeout_secs: 5
  postgres_statement_timeout_millis: 30000
  postgres_schema: ferrogate_control
  postgres_search_path:
    - public
  migration_mode: auto
```

For local development, a DSN can use keyword/value format:

```bash
export FERROGATE_POSTGRES_DSN='host=127.0.0.1 port=5432 user=postgres password=postgres dbname=ferrogate sslmode=disable'
```

Runtime behavior:

- `storage.required: true` fails closed if PostgreSQL cannot be initialized.
- `migration_mode: auto` runs the checked-in PostgreSQL schema at startup.
- Admin/status evidence reports `provider: postgres` without returning the DSN.
- Control-plane resources use the same document-store contract as libSQL.
- `postgres_pool_size` opens a small fixed connection pool for Admin API
  control-plane mutations and restart restore.
- `postgres_connect_timeout_secs` is applied to each PostgreSQL connection
  attempt.
- `postgres_statement_timeout_millis` sets the session statement timeout on
  every pooled PostgreSQL connection.
- `postgres_schema` is created if missing and prepended to the session
  `search_path`; `postgres_search_path` appends additional schemas.
- `postgres_tls_mode` accepts `disable`, `prefer`, `require`, `verify_ca`, and
  `verify_full`. `require` encrypts the connection without certificate
  verification, `verify_ca` verifies the certificate chain, and `verify_full`
  verifies both the chain and hostname. Use `postgres_tls_ca_cert_path` when
  your managed PostgreSQL provider or private CA requires an explicit root CA.
  Use `disable` only for local Docker tests or trusted private networks.

The schema file is
[`sql/001_init_postgres.sql`](../sql/001_init_postgres.sql).

## MySQL

Use a MySQL URL through an environment variable so passwords do not appear in
checked-in config:

```yaml
storage:
  provider: mysql
  required: true
  provider_order:
    - supabase
    - turso_libsql
    - postgres
    - mysql
  mysql_dsn_env: "FERROGATE_MYSQL_DSN"
  mysql_pool_size: 4
  mysql_tls_mode: verify_ca
  mysql_tls_ca_cert_path: "/etc/ferrogate/mysql-ca.pem"
  mysql_connect_timeout_secs: 5
  migration_mode: auto
```

For local development:

```bash
export FERROGATE_MYSQL_DSN='mysql://root:mysql@127.0.0.1:3306/ferrogate?prefer_socket=false'
```

Runtime behavior:

- `storage.required: true` fails closed if MySQL cannot be initialized.
- `migration_mode: auto` runs the checked-in MySQL schema at startup.
- Admin/status evidence reports `provider: mysql` without returning the DSN.
- Control-plane resources use the same document-store contract as libSQL and
  PostgreSQL.
- `mysql_pool_size` configures the maximum MySQL client pool size for Admin API
  control-plane mutations and restart restore.
- `mysql_tls_mode` accepts `disable`, `require`, `verify_ca`, and
  `verify_full`. `require` encrypts the connection without certificate
  verification, `verify_ca` verifies the certificate chain, and `verify_full`
  verifies both the chain and hostname. Use `mysql_tls_ca_cert_path` when your
  managed MySQL provider or private CA requires an explicit root CA.
- `mysql_connect_timeout_secs` is applied to MySQL TCP connection attempts.

The schema file is [`sql/001_init_mysql.sql`](../sql/001_init_mysql.sql).

## Local File-Backed libSQL

For deterministic local development and CI-safe durability tests, the same
`turso_libsql` provider also supports `file://` URLs:

```yaml
storage:
  provider: turso_libsql
  required: true
  provider_order:
    - supabase
    - turso_libsql
    - postgres
    - mysql
  libsql_url: "file:///tmp/ferrogate-control-plane.db"
  migration_mode: auto
```

`file://` uses the libSQL client local database path and does not require an
auth token. This is not a replacement for Turso Cloud in production. It exists
to prove the provider contract locally without depending on external network
availability.

## Verification

Build the gateway and test harness:

```bash
cargo build -p ferrogate-cli -p ferrogate-test --locked
```

Run the deterministic local libSQL restart test:

```bash
./target/debug/ferrogate-test libsql-file-restart
```

Run the Supabase-compatible restart test against a local TLS-enabled PostgreSQL
container:

```bash
./target/debug/ferrogate-test supabase-restart
```

Run the Docker-backed PostgreSQL restart test:

```bash
./target/debug/ferrogate-test postgres-restart
```

Run the Docker-backed MySQL restart test:

```bash
./target/debug/ferrogate-test mysql-restart
```

Run the Docker-backed MySQL TLS restart test:

```bash
./target/debug/ferrogate-test mysql-tls-restart
```

This starts real FerroGate gateway processes against the same local libSQL
database file and verifies through the Admin API that these resources survive
restart:

- API key;
- gateway config profile;
- plugin registration;
- MCP server registration;
- prompt template.

It then deletes or archives those resources, restarts again, and verifies the
post-cleanup state.

`ferrogate-test ci` includes the local libSQL restart, local libSQL server
restart, Supabase-compatible restart, PostgreSQL restart, PostgreSQL TLS
restart, MySQL restart, and MySQL TLS restart tests:

```bash
./target/debug/ferrogate-test ci
```

The live Turso Cloud restart test is intentionally opt-in because it requires a
real cloud database and secret:

```bash
FERROGATE_LIBSQL_URL="libsql://your-database.aws-ap-northeast-1.turso.io" \
FERROGATE_LIBSQL_AUTH_TOKEN="..." \
./target/debug/ferrogate-test turso-libsql-restart
```

The live scenario rejects non-`libsql://` URLs so it cannot silently become an
HTTPS-only workaround.

## Backup And Export

For Supabase, use Supabase managed backups/PITR for the database behind
`storage.supabase_dsn_env`. FerroGate does not copy control-plane state into the
analytics warehouse.

For Turso Cloud, use the provider's managed backup/export workflow for the
database that backs `storage.libsql_url`.

For PostgreSQL, use your managed PostgreSQL backup/PITR workflow for the
database behind `storage.postgres_dsn_env`.

For MySQL, use your managed MySQL backup/PITR workflow for the database behind
`storage.mysql_dsn_env`.

For local `file://` databases, snapshot the database file only when the gateway
is stopped or when your filesystem/database tooling can provide a consistent
snapshot. Treat the file as control-plane state and protect it like API-key and
policy data.

## Failure Semantics

- Missing `storage.libsql_url` fails config validation when
  `provider: turso_libsql`.
- Missing `storage.supabase_dsn_env` fails config validation when
  `provider: supabase`.
- Supabase rejects plaintext or opportunistic TLS modes; use
  `postgres_tls_mode: require`, `verify_ca`, or `verify_full`.
- Remote `libsql://` and `https://` URLs require either
  `storage.libsql_auth_token` or `storage.libsql_auth_token_env`.
- Local `file://` URLs do not use a token.
- Missing `storage.postgres_dsn` and `storage.postgres_dsn_env` fails config
  validation when `provider: postgres`.
- Invalid `storage.postgres_pool_size`, PostgreSQL timeout values, schema, or
  search-path identifiers fail config validation.
- Invalid `storage.postgres_tls_ca_cert_path` values fail startup instead of
  silently falling back to the system trust store.
- Missing `storage.mysql_dsn` and `storage.mysql_dsn_env` fails config
  validation when `provider: mysql`.
- Invalid `storage.mysql_tls_ca_cert_path` values fail startup instead of
  silently falling back to the system trust store.
- Invalid `storage.mysql_pool_size` and `storage.mysql_connect_timeout_secs`
  fail config validation.
- With `storage.required: true`, initialization errors prevent startup instead
  of falling back to memory.
- Admin mutations that fail to persist are rejected or rolled back before the
  runtime state is treated as committed.
