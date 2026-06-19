<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

---
title: Analytics Warehouse
description: Vector and ClickHouse analytics delivery guidance for FerroGate observability data.
permalink: /analytics-warehouse/
---

# Analytics Warehouse

FerroGate sends high-write observability and usage data through the analytics
delivery boundary, not through durable control-plane storage.

Use the analytics warehouse path for:

- request logs;
- trace/span-like request attempt records;
- usage metrics and token accounting records;
- billing/metering analytics;
- dashboard aggregates and charts.

Use durable control-plane storage for API keys, policies, gateway config
profiles, prompt templates, and tool approval records. See
[`docs/durable-storage.md`](durable-storage.md).

## Storage Decision Matrix

| Scenario | Better fit |
| --- | --- |
| API key / policy / config point lookup | SQLite / Turso / PostgreSQL |
| Control-plane CRUD | SQLite / Turso / PostgreSQL |
| Recent request list, small-scale local testing | SQLite can be acceptable |
| Massive request logs | ClickHouse |
| Traces / spans queries | ClickHouse |
| Usage metrics aggregation | ClickHouse |
| Billing / metering analytics | ClickHouse |
| Dashboard chart statistics | ClickHouse |

## Pipeline Mode: FerroGate To Vector To ClickHouse

Pipeline mode is the default analytics provider shape because Vector can fan
out, transform, filter, sample, and route events to many downstream sinks.

```toml
[analytics]
enabled = true
provider = "vector"
required = true
vector_endpoint = "http://127.0.0.1:4319"
export_timeout_secs = 3
batch_max_events = 500
flush_interval_millis = 1000
queue_capacity = 10000
```

FerroGate sends flat NDJSON analytics events to Vector. The checked-in
`ferrogate-test` Docker scenario configures Vector to deliver those events to
ClickHouse tables created from
[`sql/clickhouse/001_init_analytics.sql`](../sql/clickhouse/001_init_analytics.sql).

Run the Docker-backed pipeline scenario:

```bash
cargo build -p ferrogate-cli -p ferrogate-test --locked
./target/debug/ferrogate-test run analytics-vector-clickhouse
```

The scenario starts ClickHouse and Vector containers, sends a real AI request
through FerroGate, waits for warehouse rows, then verifies Admin API analytics
status reports a successful export.

## Direct Warehouse Mode: FerroGate To ClickHouse

Direct mode removes Vector and writes analytics batches straight to ClickHouse:

```toml
[analytics]
enabled = true
provider = "clickhouse"
required = true
clickhouse_url = "http://127.0.0.1:8123"
export_timeout_secs = 3
batch_max_events = 500
flush_interval_millis = 1000
queue_capacity = 10000
```

Use `clickhouse_url_env` instead of `clickhouse_url` when the URL contains
credentials.

Run the direct ClickHouse scenario:

```bash
cargo build -p ferrogate-cli -p ferrogate-test --locked
./target/debug/ferrogate-test run analytics-direct-clickhouse
```

This starts a ClickHouse container, initializes the analytics schema, sends a
real AI request through FerroGate, verifies warehouse rows, and checks Admin API
analytics evidence.

## Runtime Evidence

`GET /admin/v1/status` reports the analytics backend evidence:

- provider: `vector`, `clickhouse`, or `none`;
- mode: `pipeline`, `direct_warehouse`, or `disabled`;
- active/required flags;
- health;
- last successful export time;
- last export error.

Export failures update analytics status. They do not belong in the
control-plane database and they do not turn Turso/libSQL into a warehouse.

## Local Verification Commands

Run deterministic local API coverage plus the local libSQL durability test:

```bash
./target/debug/ferrogate-test ci
```

Run the warehouse E2E scenarios when Docker is available:

```bash
./target/debug/ferrogate-test run analytics-direct-clickhouse
./target/debug/ferrogate-test run analytics-vector-clickhouse
```

The Docker scenarios are intentionally not part of the default local CI command
because they start fixed-name containers and require Docker networking.
