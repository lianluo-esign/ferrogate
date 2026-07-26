<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-26
  description: FerroGate telemetry-collector Worker — OTLP/JSON ingest, limits, deploy (issue #520).
-->

# FerroGate telemetry-collector Worker (issue #520)

The Worker that makes Cloudflare usable as FerroGate's observability backend.

## Why this Worker has to exist

Cloudflare ships **no observability ingest endpoint anywhere on the platform**:

| Store | Write path | Reachable from a Rust process? |
| --- | --- | --- |
| Analytics Engine | `env.DATASET.writeDataPoint()` — a Worker **binding** | **No.** The dataset's only HTTP API is the SQL **read** API. |
| Workers Logs | `console.log()` inside a Worker invocation | **No.** There is no write API. |
| OTLP | — | **No.** Cloudflare runs no OTLP receiver. |

So a FerroGate process running in a container cannot write telemetry to Cloudflare
directly, at all. The only way to make Cloudflare the observability backend is a
collector Worker we deploy ourselves — the same fronting-Worker pattern already used
for agents in issue #413.

Cloudflare's own **native Workers OTLP export** emits this same OTLP/HTTP + JSON shape,
so this one collector ingests **both** FerroGate-side and CF-Worker-side telemetry into
the same store: point a Worker's OTLP exporter at this endpoint and its spans land next
to the gateway's, correlated by `traceId`.

## Wire contract

`Content-Type: application/json` — **JSON only, never protobuf**. Cloudflare supports no
binary OTLP anywhere, so JSON is a platform-wide constraint rather than a preference.

| Method + path | Body |
| --- | --- |
| `POST /v1/metrics` | `{"resourceMetrics":[{"resource":{…},"scopeMetrics":[{"scope":{…},"metrics":[…]}]}]}` |
| `POST /v1/traces` | `{"resourceSpans":[{"resource":{…},"scopeSpans":[{"scope":{…},"spans":[…]}]}]}` |
| `POST /v1/logs` | `{"resourceLogs":[{"resource":{…},"scopeLogs":[{"scope":{…},"logRecords":[…]}]}]}` |
| `GET /healthz` | — (unauthenticated liveness probe) |

Request headers:

| Header | Required | Meaning |
| --- | --- | --- |
| `Content-Type: application/json` | yes | OTLP/HTTP JSON encoding. |
| `Authorization: Bearer <token>` | yes | The `COLLECTOR_TOKEN` shared secret. Anything else is **401**. |
| `X-FerroGate-Tenant: <tenant-id>` | no | When absent the tenant is derived from record attributes (see below). |

Record shapes are exactly what `crates/ferrogate-observability/src/otlp.rs` builds:

- **metrics** — every FerroGate metric is a monotonic `sum` with `dataPoints[].asDouble`
  and `attributes[] = {key, value:{stringValue}}`. `gauge` and `histogram` are also
  accepted, because Cloudflare's native export emits them.
- **spans** — `traceId`, `spanId`, `parentSpanId` (`null` for a root span), `name`,
  `kind`, `startTimeUnixNano` / `endTimeUnixNano` as JSON **strings** of nanoseconds
  (they exceed 2^53, so they are never coerced to `Number`; durations are computed in
  `BigInt`), `attributes[]`.
- **logs** — `timeUnixNano` (string), `traceId`, `spanId`, `severityText`,
  `body.stringValue`, `attributes[]`.

### Responses

```json
{"accepted": 42, "dataPoints": 42, "dropped": 0}
```

- `accepted` — records taken from the payload (data points / spans / log records).
- `dataPoints` — Analytics Engine `writeDataPoint()` calls actually made. Always `0` for
  `/v1/logs`: log records go to Workers Logs, not Analytics Engine.
- `dropped` — records lost, either structurally unusable in the payload or past the
  250-write per-invocation cap. The breakdown (`droppedOverCap` vs `droppedUnusable`) is
  emitted on the per-request `signal: "ingest"` log line.

| Status | When |
| --- | --- |
| `200` | Batch accepted (possibly with `dropped > 0`). |
| `400` | Body is not JSON, or is JSON that is not the OTLP envelope for that route. |
| `401` | Missing, non-Bearer, or wrong `Authorization`. A wrong token is deliberately *not* distinguished from a missing one. |
| `404` / `405` | Unknown path / non-`POST` on an ingest path. |
| `413` | Body over `MAX_BODY_BYTES` (checked on `Content-Length` first, then on the buffered length). |
| `500` | `COLLECTOR_TOKEN` is not configured — the collector fails **closed** rather than accepting anonymous telemetry. |

A single unusable record never fails the batch: OTLP exporters retry **whole** batches,
so rejecting thousands of good spans over one bad one would amplify load.

## Where the data goes

**Analytics Engine (`env.TELEMETRY`)** — metrics and span *summaries*. Blob positions are
fixed, because AE blobs are positional columns:

| Point | `indexes[0]` | blobs | doubles |
| --- | --- | --- | --- |
| metric | tenant id | `metric`, name, service, scope, type, then sorted `key=value` attributes | `[value]` |
| span | tenant id | `span`, name, traceId, spanId, parentSpanId, service, scope, then sorted `key=value` attributes | `[durationMs, kind]` |

**Workers Logs (`console.log`)** — one flat JSON object per log record and per span.
Workers Logs auto-extracts and indexes JSON fields, so every field is queryable. Spans go
to **both** stores: AE carries the queryable numeric summary, the log line carries the
correlatable ids and attributes. Logs are also the *complete* record — AE writes stop at
the per-invocation cap, log lines do not.

## Limits enforced in code

All of these live in one place: `src/limits.ts`.

| Limit | Value | Enforcement |
| --- | --- | --- |
| Indexes per AE data point | **exactly 1** | The **tenant id** and nothing else. The index is the axis Cloudflare samples and partitions on, so it must be the tenancy key. |
| AE index size | **96 bytes** | Truncated on a UTF-8 code-point boundary; empty falls back to `unknown` (a point with no index cannot be written). |
| Blobs per AE data point | **20** | Extra blobs dropped. |
| Doubles per AE data point | **20** | Extra doubles dropped; non-finite values become `0`. |
| Combined blob size per point | **16 KB** | Budget spent front-to-back (identifying blobs first); the blob that does not fit whole is clipped, the rest dropped. Never handed oversized to `writeDataPoint()`, which would throw and lose the whole point. |
| `writeDataPoint()` calls per invocation | **250** | Counted. Past the cap the writer stops, and the remainder is reported in `dropped` **and** in one `console.warn` (`event: telemetry.analytics.limits`). Never a silent truncation. |
| Workers Logs line | **256 KB** | `attr.*` fields shed first, then the body is clipped, so the line stays *valid JSON* (a platform-truncated line is unparseable). |
| Logpush `logs`+`exceptions` | **16,384 chars combined** | Much tighter than the 256 KB line cap. Lines are kept lean (bounded field lengths, at most 32 attributes) so a Logpush consumer does not lose the tail. |
| Request body | `MAX_BODY_BYTES` (default 4 MiB) | `413`. |

### Tenant resolution

`X-FerroGate-Tenant` → resource attributes → record attributes → `unknown`, searching
`ferrogate.tenant_id`, `tenant_id`, `tenant.id`, `tenant`, `service.namespace` in that
order. The result becomes the AE index, so it is never empty.

## Layout

```
src/index.ts      routing + wiring only (no logic)
src/auth.ts       bearer gate, tenant resolution, JSON helper
src/ingest.ts     per-signal pipeline: body read/size check -> parse -> fan out -> summary
src/otlp.ts       the three OTLP/JSON payload shapes: parse + validate
src/analytics.ts  Analytics Engine point building + limit enforcement
src/logs.ts       structured Workers Logs emission
src/limits.ts     every Cloudflare hard limit, in one place
test/             workerd-hosted suite (vitest-pool-workers + miniflare)
```

## Develop, test, deploy

```bash
npm install
npm run typecheck          # tsc --noEmit
npm test                   # vitest run — boots the real Worker in workerd
npm run dev                # wrangler dev

# ONE-TIME per environment: seed the shared secret. Never committed.
wrangler secret put COLLECTOR_TOKEN

npm run deploy             # wrangler deploy
```

The test suite runs the real `src/index.ts` in workerd via
`@cloudflare/vitest-pool-workers` + miniflare — no Docker, no live Cloudflare account, no
network. miniflare implements the Analytics Engine binding locally, so the production
`writeDataPoint()` path executes for real; because nothing inside a Worker can read those
writes back, the point shape and the limit clamps are additionally asserted against an
observable stub in `test/limits.test.ts`.

The Analytics Engine dataset (`ferrogate_telemetry`) does not need to be pre-created — it
is created on first write.

### Pointing FerroGate at it

Set the OTLP exporter endpoint to the deployed Worker's origin (the collector appends the
`/v1/...` path itself, matching `build_otlp_request`) and send `Authorization: Bearer
<COLLECTOR_TOKEN>` plus, where known, `X-FerroGate-Tenant`.

## Cost

Requires the **Workers Paid** plan: **$5/month per ACCOUNT**, not per Worker — one
subscription covers this collector alongside every other FerroGate Worker. Included in
that $5:

- 10M requests/month
- 30M CPU-milliseconds/month
- 20M Workers Logs events/month (retained 7 days)
- 10M Analytics Engine data points/month

Two design choices exist to protect those budgets:
`[observability.logs] invocation_logs = false` drops the automatic one-per-request
invocation events, which would roughly **double** the billable log events of an ingest
Worker while duplicating the ingest summary line; and log records are never written to
Analytics Engine, so the 10M data-point budget is spent only on metrics and span
summaries.

## Observability of the collector itself

`wrangler.toml` sets **three independent switches** — `enabled` alone does **not** turn on
tracing:

```toml
[observability]
enabled = true

[observability.logs]
enabled = true
invocation_logs = false

[observability.traces]
enabled = true
```
