<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

---
title: Durable Control-Plane Storage
description: Supabase-first durable storage guidance for FerroGate control-plane state.
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

Supabase is the durable system of record for control-plane resources and the
operator evidence needed to explain gateway decisions. High-write telemetry can
still be exported to the analytics warehouse, but the gateway keeps normalized
request, audit, agent-run, billing, and usage evidence tables in Supabase so
Admin API views and incident reconstruction do not depend on an external
warehouse being available.

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
- `migration_mode: auto` runs the checked-in PostgreSQL schema at startup. Use
  it for local development, test environments, and first-boot CI harnesses.
- `migration_mode: validate_only` or `disabled` is the production posture when
  operators manage Supabase migrations outside the gateway process. In those
  modes the checked-in schema must already exist before startup.
- Admin/status evidence reports `provider: supabase` without returning the DSN.
- Admin/status evidence also reports non-secret `required`, `migration_mode`,
  `health`, and checked schema fields so operators can debug startup posture
  without exposing credentials.
- `supabase_dsn_env` is required for Supabase so credentials stay secret-backed.
- Supabase requires `postgres_tls_mode: require`, `verify_ca`, or `verify_full`.
- `verify_full` is the preferred production mode when the host certificate and
  CA chain validate cleanly. `require` is encrypted but does not verify the
  certificate chain or hostname; reserve it for test environments or managed
  setups where the CA bundle is not available to the runner.
- Direct and session-pooler DSNs are supported first. Transaction-pooler mode
  must not rely on prepared statements unless the selected Rust client path is
  explicitly verified for that mode.
- Control-plane resource documents are stored as `JSONB` in
  `control_plane_resources`.

Pooler guidance:

- Direct DSNs are simplest and best for low-frequency Admin API control-plane
  CRUD when the gateway replica count is small.
- Session-pooler DSNs are the preferred managed-cloud posture for horizontally
  scaled gateways because each FerroGate process still expects session-level
  settings such as statement timeout and search path.
- Transaction-pooler DSNs need explicit validation with the Rust PostgreSQL
  client behavior before production use; do not assume session settings,
  prepared statement behavior, or advisory-lock style migration coordination
  survives transaction pooling.

Least-privilege guidance:

- Do not use the Supabase service-role key as a gateway database credential.
  FerroGate needs a PostgreSQL DSN for the configured control schema, not a
  Supabase REST service-role token.
- Browser `anon` keys are not runtime database credentials. They are intended
  for client-facing Supabase APIs and RLS-mediated application access, while
  FerroGate is a server-side gateway that reads and writes internal control
  tables through PostgreSQL.
- Create a database role scoped to the FerroGate control schema and grant only
  the privileges needed for the chosen migration posture: DDL plus DML for
  `migration_mode: auto`, or DML on the pre-created tables for
  `validate_only`/`disabled`.
- Keep Supabase RLS policies for application-facing tables separate from the
  gateway control schema. The recommended posture is to keep RLS disabled for
  FerroGate-owned internal control tables and isolate access with schema
  ownership plus a least-privilege database role. If operators require RLS on
  the control schema, every policy must explicitly grant the FerroGate database
  role the same CRUD surface the Admin API needs; do not replace gateway policy
  with Supabase client-key policies.
- FerroGate's agent, tool, and API calls must still enter through the AI
  Gateway so auth, policy, billing, audit, and observability remain the
  security boundary.

Failure and redaction expectations:

- Admin/status returns provider, required flag, migration mode, health, provider
  order, contract version, and schema checksum/name/version. It never returns
  the Supabase DSN, password, service-role token, pooler password, or CA file
  contents.
- Missing `storage.supabase_dsn_env` or a missing environment variable reports
  the field/env name only. It must not print the secret value.
- PostgreSQL connection failures are rendered with DSN password material
  redacted before they reach startup stderr or harness failure output.

The schema file is
[`sql/001_init_postgres.sql`](../sql/001_init_postgres.sql).

When `postgres_schema: ferrogate_control` is set, FerroGate creates the tables
under the `ferrogate_control` schema, not under Supabase's default `public`
schema. In the Supabase dashboard, switch the table/schema selector to
`ferrogate_control`, or verify with:

```sql
select table_schema, table_name
from information_schema.tables
where table_schema = 'ferrogate_control'
order by table_name;
```

Supabase table ownership:

- `control_plane_resources`: Admin API resource documents such as API keys,
  policies, gateway configs, prompt templates, plugins, MCP servers, tool
  approvals, and agent upstreams. Document payloads use `JSONB`; resource kind
  and ID remain the stable list/get keys.
- `agent_runs` and `agent_run_events`: agent execution timelines and tool/model
  turn evidence. These tables support tenant, request, trace, and timeline
  lookups.
- `request_logs`: normalized gateway request evidence for Admin API request
  log views, cache status, status/error filtering, and model/provider queries.
- `audit_events`: operator- and runtime-visible security decisions including
  policy, tool, MCP, and Admin API mutations.
- `billing_metering_events`: one row per metered gateway request with
  tenant/model/provider token usage and usage-source evidence. This v2 table is
  kept for migration compatibility.
- `usage_aggregates`: compatibility rollups by organization, project, API key,
  tenant, logical model, and provider. This v2 table is kept for migration
  compatibility.
- `tenant_contexts`: compact tenant dimension records reused by structured
  metering and usage rollups.
- `metering_events`, `metering_event_routes`, and `metering_event_usage`:
  normalized v3 metering evidence. FerroGate writes one event row per request
  and joins route plus token usage tables for Admin API reads, avoiding JSON
  blobs for billing facts.
- `usage_aggregate_rollups`: normalized v3 usage rollups keyed by tenant
  context, logical model, and provider. Token counters are updated
  incrementally from accepted metering events.
- `storage_schema_migrations`: applied schema versions and migration names used
  by local validation and future admin status evidence.

The schema is intentionally incremental: v3 adds structured billing/usage
tables without dropping the older v2 compatibility tables. Document-style JSONB
is reserved for control-plane resources and runtime evidence documents; billing
facts use relational columns and joins so operators can query them directly in
Supabase.

## Evidence Boundary And Write Pressure

Supabase is the synchronous system of record for the evidence that an operator
needs to explain an Admin API or billing decision from the gateway itself:

- control-plane documents and mutations;
- request logs exposed by `/admin/v1/request-logs`;
- audit events exposed by `/admin/v1/audit-events`;
- agent-run timelines and tool/model events;
- metering events and usage rollups exposed by `/admin/v1/metering-events`,
  `/admin/v1/billing-events`, and `/admin/v1/usage-aggregates`.

ClickHouse and Vector remain the high-volume analytics boundary. Use them for
large dashboard scans, long-running trace/span exploration, warehouse
aggregations, and sampled or transformed observability streams. They may carry
copies of request, audit, billing, and metric records, but they are not the
source of truth for the Admin API evidence chain.

The Supabase write path is deliberately bounded:

- request logs are one upsert per gateway request keyed by `request_id`;
- audit events are one insert per operator/runtime decision keyed by event ID;
- metering events are one idempotent insert per metered request plus an
  incremental usage rollup update;
- Admin list endpoints use pagination and indexed relational dimensions rather
  than scanning JSONB payloads.

`analytics.request_log_retention_records` and
`analytics.audit_event_retention_records` still bound in-memory compatibility
providers. Supabase/Postgres deployments must use database-side retention for
durable evidence tables: partition by time or tenant, archive old partitions,
or delete rows according to the tenant's compliance window. Do not rely on the
in-memory retention knobs to prune Supabase tables.

Export paths are independent. Enabling Vector, ClickHouse, OTLP, or external
metering export sends copies of records out of FerroGate; it must not replace
the Supabase evidence write, and operators should not add those exports back
into the same Admin API tables or usage rollups. Duplicate warehouse rows are an
analytics concern; duplicate Supabase metering writes are prevented by
`request_id` idempotency.

Retention expectations:

- Control-plane documents are retained until deleted through the Admin API.
- Request logs, audit events, agent-run timelines, and metering events are
  operational evidence. Production Supabase deployments should apply explicit
  retention partitions or archival jobs sized to tenant policy and compliance
  requirements.
- Usage aggregates are durable billing state and should be retained for the
  billing/audit window, not pruned with high-volume telemetry exports.

## Legacy libSQL Compatibility

The `turso_libsql` provider remains implemented for compatibility and
deterministic local/provider-contract coverage. It is not the current
commercial control-plane target; use Supabase for new production control-table
deployments.

For compatibility testing, use a `libsql://` URL and keep the auth token in an
environment variable:

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
auth token. This is not a production control-plane target. It exists to prove
the provider contract locally without depending on external network
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

The focused `rust-supabase-storage-tests` CI module runs that deterministic
scenario without cloud credentials. If repository secrets provide
`FERROGATE_SUPABASE_DSN`, the same module also runs the opt-in live Supabase
smoke scenario. The smoke starts a local FerroGate process, initializes the
real Supabase schema with `migration_mode: auto`, writes a real control-plane
API-key row, restarts with `validate_only`, and verifies the row through the
Admin API:

```bash
FERROGATE_SUPABASE_DSN="postgresql://..." \
./target/debug/ferrogate-test supabase-live-smoke
```

For live model-provider billing coverage, the harness can route a real
OpenAI-compatible chat completion through Token4AI AI Gateway and verify that
provider-reported token usage is persisted to Supabase metering and usage
rollup tables before and after a `validate_only` restart:

```bash
FERROGATE_SUPABASE_DSN="postgresql://..." \
FERROGATE_TOKEN4AI_OPENAI_API_KEY="..." \
./target/debug/ferrogate-test supabase-live-token4ai-provider
```

The provider base URL defaults to `https://api.token4ai.cloud/v1`. Override it
with `FERROGATE_TOKEN4AI_OPENAI_BASE_URL` only for controlled test endpoints.
Do not commit provider API keys; pass them through environment variables or CI
secrets.

The heavier `supabase-live-restart` scenario remains available for full remote
CRUD/reload coverage, but it can be slow on externally hosted test databases.

Set `FERROGATE_SUPABASE_TLS_CA_CERT` in GitHub secrets only when the live
Supabase deployment requires a private root CA; the workflow writes it to a
temporary file and passes `FERROGATE_SUPABASE_TLS_CA_CERT_PATH` to the harness.
Set `FERROGATE_SUPABASE_TLS_MODE` only when the live test environment needs to
override the default `verify_full` posture, for example `require` on a
controlled test database where encrypted transport is required but runner CA
validation is not available.

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

The live remote-libSQL restart test is intentionally opt-in because it requires
a real cloud database and secret:

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

For legacy remote libSQL deployments, use the provider's managed backup/export
workflow for the database that backs `storage.libsql_url`.

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
