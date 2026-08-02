# Exporting evidence to a customer SIEM (#683)

FerroGate holds the authoritative record of what it did in two D1 tables:

- `request_logs` — one row per inference decision (#664);
- `audit_events` — every applied control-plane mutation, hash-chained and
  anchored to R2 so alteration is detectable (#684, `audit-tamper-evidence.md`).

This document describes the **export pump**: how those rows are pushed to a
customer's Splunk, Datadog, generic HTTPS collector or R2/S3 bucket, what the
delivery guarantee is, what it is not, and how to replay a window.

Implementation: `apps/control-plane/src/siem/`. Proof:
`apps/control-plane/test/siem-export.test.ts`.

## Why a pump rather than Cloudflare Logpush

Logpush is the obvious answer and it does not work here. It ships **Cloudflare's
own datasets** (`workers_trace_events` and friends) — there is no ingest API for
an application's rows — its delivery floor is around a minute, and, decisively,
**it cannot backfill**: data produced while a Logpush job is broken is gone from
the destination forever. See `docs/cloudflare-observability.md`.

"Cannot backfill" is exactly the property this feature is about, so the pump owns
its own cursor instead.

## The guarantee

> A row that is inside a sink's tenant fence, older than that sink's visibility
> horizon, and after that sink's cursor **will be delivered at least once**,
> unless retention deletes it first.

The mechanism is one ordering rule: **deliver, then advance the cursor.** Every
failure — a 5xx, a reset connection, an evicted isolate, a cron tick that never
ran, a Worker redeploy mid-batch — leaves the cursor where it was, so the next
tick re-sends that batch.

### What is NOT claimed

- **Not exactly-once.** The acknowledgement itself can be lost: the sink can
  store a batch and die before answering. Exactly-once across a boundary we do
  not control is not available at any price. The choice is which way to err, and
  for an audit trail it is duplicate over gap — a duplicate is visible in the
  destination, a gap is not.
- **Duplication is bounded** by one batch per interruption. Every batch carries
  a stable `x-ferrogate-batch-id` header (and, for an R2 sink, an object key
  derived from the batch), so a collector can collapse a repeat. Rows also carry
  their own stable `id`.
- **The visibility lag is a mitigation, not a proof.** A `request_logs` row is
  keyed on when the request STARTED and written when it COMPLETED, so a slow
  request lands behind a cursor that has already passed its timestamp. The pump
  therefore never advances past `now - visibility_lag_seconds` (default 60). A
  request that runs LONGER than the lag can still be missed; widen
  `visibility_lag_seconds` on a deployment with long streaming responses. This
  residual is stated rather than hidden because it is the only known way a row
  can be skipped.
- **Retention still wins.** A row deleted by the retention job before a stalled
  sink catches up is gone. Keep retention comfortably longer than the longest
  outage you intend to survive.

## Configuring a sink

`SIEM_EXPORT_SINKS` in `apps/control-plane/wrangler.toml` — a JSON array. The
committed value is `"[]"`, meaning **no egress**: evidence leaving the platform
is an operator decision, never a deployment default.

```jsonc
[
  {
    "id": "acme-splunk",              // stable; it keys the cursor row
    "tenant": "acme",                 // REQUIRED — the fence
    "streams": ["request_logs", "audit_events"],
    "batch_size": 500,                // rows per delivery
    "max_batches_per_tick": 20,       // back-pressure per cron tick
    "visibility_lag_seconds": 60,
    "start_at_unix": 0,               // 0 = the whole retained history
    "destination": {
      "kind": "http",
      "endpoint": "https://http-inputs-acme.splunkcloud.com/services/collector/raw",
      "auth": {
        "header": "Authorization",
        "prefix": "Splunk ",
        "secret_ref": "env://ACME_SPLUNK_HEC_TOKEN"
      }
    }
  }
]
```

Vendor header shapes:

| Sink                | `header`        | `prefix`   |
| ------------------- | --------------- | ---------- |
| Splunk HEC          | `Authorization` | `Splunk `  |
| Datadog logs intake | `DD-API-KEY`    | `` (empty) |
| Generic collector   | `Authorization` | `Bearer `  |

An R2 destination instead:

```jsonc
{ "kind": "r2", "prefix": "acme/" }
```

which writes NDJSON objects into the `SIEM_EXPORTS` bucket under
`siem-exports/v1/<prefix><sink>/<stream>/<padded-ts>-<row-id>.jsonl`. The key is
derived from the batch, so a re-delivery overwrites rather than accumulates, and
the zero-padded timestamp makes R2's lexical `list` order chronological.

### Three things the configuration cannot express

Enforced by the parser (`src/siem/config.ts`), not by convention:

1. **A sink without a `tenant` does not parse.** There is no "export everything"
   mode. An un-attributed `request_logs` row is a *platform operator's* own
   traffic; handing it to a customer would be a cross-tenant disclosure.
2. **`secret_ref` must be an `env://` reference.** `wrangler.toml` is committed
   plaintext — an inline token would be a credential in git. A `vault://` or
   `cf://` reference is refused too: inside a Worker every backend arrives as a
   binding, so those would look configured and never resolve.
3. **An `http` endpoint must be `https`.**

### Provisioning the credential

```sh
wrangler secret put ACME_SPLUNK_HEC_TOKEN --name ferrogate-control-plane
```

The credential never appears in a report, a log line or an error. The sink's
response **body is never read**, because real HEC and collector endpoints echo
the presented token back in their 401 text; the endpoint URL is kept out of error
messages too, since some collectors carry a token in the path. A redaction filter
over every reported message is the second lock on the same door.

## Replaying a window

A SIEM outage, a bad index mapping, a compliance re-ingest: bump the epoch and
name a start.

```jsonc
"replay": { "epoch": 1, "from_unix": 1753900000 }
```

On the next tick the cursor rewinds to `from_unix` (inclusive) and re-delivers
forwards. The **applied epoch is stored on the cursor row**, so the rewind
happens exactly once however many ticks read the same configuration — without
that, a replay instruction left in the config would restart the export every
minute and the sink would never converge. To replay again, bump the epoch again.

## Reading the cursor

```sh
wrangler d1 execute ferrogate-control --command \
  "SELECT sink_id, stream, tenant, last_ts, last_id, delivered, replay_epoch, \
          updated_at_unix FROM siem_export_cursors ORDER BY sink_id, stream"
```

`delivered` is cumulative acknowledged rows, which is what distinguishes "the
pump is running and has nothing to send" from "the pump has never run" — two
states that look identical in the destination.

Each cron tick also reports the pass; `wrangler tail` shows `siemExport` with a
per-(sink, stream) status of `delivered`, `idle` or `failed` plus a redacted
error.

## Deployment checklist

1. `wrangler d1 migrations apply ferrogate-control` — creates
   `siem_export_cursors` (`sql/d1-ts/control/0005_*`).
2. Create the R2 bucket if any sink uses `kind: "r2"`, and set `bucket_name` for
   the `SIEM_EXPORTS` binding. **Do not point it at the `AUDIT_ANCHORS`
   bucket**: that bucket's value is that the principals who can edit the
   database cannot rewrite it, and the bulk-export path must not hold write
   access to it.
3. `wrangler secret put` each `secret_ref` name.
4. Fill in `SIEM_EXPORT_SINKS` and deploy. The `[triggers] crons = ["* * * * *"]`
   stanza already runs the pump; there is no separate Worker to deploy.
5. Watch `wrangler tail` for the first tick, then check the destination against
   `siem_export_cursors.delivered`.

## What the tests prove, and what only a deployment can

`apps/control-plane/test/siem-export.test.ts` runs the real pump against a real
D1 binding and a real R2 binding inside workerd, with a stand-in collector over
`fetch`. It proves the fence (from both tenants' sides and for un-attributed
rows), resumption after a killed pump with no loss and bounded duplication, the
visibility lag, replay idempotence, the forward-only cursor, and that the
credential reaches the sink and nothing else.

It does not prove anything about a real Splunk or Datadog endpoint, a real R2
bucket, or that Cloudflare fires the Cron Trigger on schedule. Verify those on
the first deployment.
