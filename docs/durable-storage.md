<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

---
title: Durable Control-Plane Storage
description: Turso/libSQL and local libSQL storage guidance for FerroGate control-plane state.
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
provider_order = ["turso_libsql", "postgres", "mysql"]
```

`turso_libsql` is the implemented durable provider today. PostgreSQL and MySQL
are follow-up providers and must implement the same repository contract instead
of changing gateway control-plane code.

## Turso Cloud / Remote libSQL

Use a `libsql://` URL and keep the auth token in an environment variable:

```yaml
storage:
  provider: turso_libsql
  required: true
  provider_order:
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

## Local File-Backed libSQL

For deterministic local development and CI-safe durability tests, the same
`turso_libsql` provider also supports `file://` URLs:

```yaml
storage:
  provider: turso_libsql
  required: true
  provider_order:
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

`ferrogate-test ci` includes this local restart test:

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

For Turso Cloud, use the provider's managed backup/export workflow for the
database that backs `storage.libsql_url`. FerroGate does not copy control-plane
state into the analytics warehouse.

For local `file://` databases, snapshot the database file only when the gateway
is stopped or when your filesystem/database tooling can provide a consistent
snapshot. Treat the file as control-plane state and protect it like API-key and
policy data.

## Failure Semantics

- Missing `storage.libsql_url` fails config validation when
  `provider: turso_libsql`.
- Remote `libsql://` and `https://` URLs require either
  `storage.libsql_auth_token` or `storage.libsql_auth_token_env`.
- Local `file://` URLs do not use a token.
- With `storage.required: true`, initialization errors prevent startup instead
  of falling back to memory.
- Admin mutations that fail to persist are rejected or rolled back before the
  runtime state is treated as committed.
