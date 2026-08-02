/**
 * The SIEM EXPORT PUMP (#683) — the egress path evidence did not have.
 *
 * ## Why a pump at all, and why not Logpush
 *
 * `request_logs` (#664) and the hash-chained `audit_events` (#684) are the
 * authoritative record of what this platform did, and they lived in D1 with no
 * way out except an operator polling `GET /admin/v1/request-log-exports`. A
 * security team's evidence has to be IN their estate — Splunk, Datadog, an S3
 * bucket — under their retention, not behind our API.
 *
 * Cloudflare Logpush cannot do it: Logpush ships Cloudflare's OWN datasets
 * (`workers_trace_events` and friends) and has no ingest for an application's
 * rows, it cannot backfill a window it missed, and its delivery floor is about
 * a minute anyway (`docs/cloudflare-observability.md`). "Cannot backfill" is
 * disqualifying on its own for the property this issue is actually about.
 *
 * ## The guarantee, stated precisely
 *
 * **At-least-once.** A row that is visible to a sink's fence, older than its
 * visibility horizon, and after its cursor WILL be delivered to that sink at
 * least once, unless it is deleted by retention first. The cursor advances only
 * after the sink acknowledges, so every failure mode — a 5xx, a reset
 * connection, an evicted isolate, a cron tick that never ran — re-sends rather
 * than skips. The duplication that buys is bounded by ONE batch per
 * interruption, and every batch carries a stable `x-ferrogate-batch-id` (and,
 * on R2, a key derived from the batch) so the destination can collapse it.
 *
 * **Not exactly-once, and not claimed.** Exactly-once across a boundary we do
 * not control is not available: the acknowledgement itself can be lost. The
 * honest choice is which side to err on, and for an audit trail it is duplicate
 * over gap — a duplicate is visible in the destination and a gap is not.
 *
 * ## What runs this
 *
 * The existing minute Cron Trigger (`src/schedule/scheduled.ts`), alongside the
 * schedule tick and the audit anchor. No new Worker, no new Queue: the work is
 * a bounded number of batches per tick, and the cursor makes an interrupted
 * tick a resumption rather than a loss — which is exactly the property that
 * lets a cheap scheduler carry it.
 */
import { resolveControlDatabase, resolveSiemExportBucket } from "../adapters.js";
import type { ControlPlaneBindings } from "../ports.js";
import { type SiemSink, type SiemStream, parseSiemSinks } from "./config.js";
import {
  type SiemCursorPosition,
  advanceSiemCursor,
  applyReplay,
  readSiemCursor,
} from "./cursor.js";
import {
  SiemDeliveryError,
  deliverSiemBatch,
  redactSecrets,
  resolveSinkCredential,
} from "./destination.js";
import { readSiemBatch } from "./source.js";

/** What one (sink, stream) leg did this tick. */
export interface SiemStreamReport {
  readonly sink: string;
  readonly stream: SiemStream;
  /**
   * `delivered` — rows were acknowledged; `idle` — the sink is caught up;
   * `failed` — a batch was not acknowledged and its rows remain to be sent.
   */
  readonly status: "delivered" | "idle" | "failed";
  /** Batches ACKNOWLEDGED (the failed one is not counted). */
  readonly batches: number;
  /** Rows acknowledged. */
  readonly rows: number;
  /** The cursor after this tick, or `null` when nothing has ever been acknowledged. */
  readonly cursor: SiemCursorPosition | null;
  /** Redacted failure text; `null` on success. */
  readonly error: string | null;
}

export interface SiemExportReport {
  readonly sinks: number;
  readonly streams: readonly SiemStreamReport[];
  /**
   * A configuration that did not parse, redacted. Reported rather than thrown:
   * a bad sink list must not take the schedule tick down with it, but it must
   * not be silent either — evidence quietly ceasing to flow is indistinguishable
   * in the destination from nothing having happened.
   */
  readonly configError: string | null;
}

const EMPTY_POSITION: SiemCursorPosition = { ts: 0, id: "" };

/**
 * Where this leg resumes from: the stored cursor, after any replay the operator
 * has asked for, falling back to the sink's configured start.
 */
async function resumePosition(
  db: D1Database,
  sink: SiemSink,
  stream: SiemStream,
  now: number,
): Promise<{ position: SiemCursorPosition; replayEpoch: number }> {
  if (sink.replay !== null) {
    // Idempotent by epoch — see `applyReplay`. Running it before the read is
    // what makes the rewind visible to THIS tick rather than the next one.
    await applyReplay(db, {
      sinkId: sink.id,
      stream,
      tenant: sink.tenant,
      epoch: sink.replay.epoch,
      fromUnix: sink.replay.fromUnix,
      now,
    });
  }
  const cursor = await readSiemCursor(db, sink.id, stream);
  if (cursor === null) {
    return {
      position: sink.startAtUnix > 0 ? { ts: sink.startAtUnix, id: "" } : EMPTY_POSITION,
      replayEpoch: sink.replay?.epoch ?? 0,
    };
  }
  return { position: cursor.position, replayEpoch: cursor.replayEpoch };
}

/**
 * Drain one (sink, stream) up to `maxBatchesPerTick`.
 *
 * The loop body's ORDER is the guarantee and must not be rearranged: read a
 * batch, deliver it, and only then advance the cursor. Advancing first would
 * turn every delivery failure into a permanent, invisible gap.
 */
async function pumpStream(
  db: D1Database,
  env: ControlPlaneBindings,
  sink: SiemSink,
  stream: SiemStream,
  now: number,
): Promise<SiemStreamReport> {
  const horizon = now - sink.visibilityLagSeconds;
  let { position, replayEpoch } = await resumePosition(db, sink, stream, now);
  let batches = 0;
  let rows = 0;

  // Resolved ONCE per leg rather than per batch: one place where a live
  // credential exists, and one place where a resolution failure can happen.
  let credential: string | null;
  try {
    credential = await resolveSinkCredential(sink.destination, env);
  } catch (error) {
    return report(sink, stream, "failed", 0, 0, position, error, []);
  }
  const secrets = credential === null ? [] : [credential];
  const bucket = resolveSiemExportBucket(env);

  try {
    while (batches < sink.maxBatchesPerTick) {
      const batch = await readSiemBatch(db, stream, sink.tenant, position, horizon, sink.batchSize);
      if (batch.length === 0) break;
      const last = batch[batch.length - 1] as (typeof batch)[number];
      const ref = { sink, stream, position: last.position };

      await deliverSiemBatch(
        sink,
        ref,
        batch.map((row) => row.document),
        { credential, bucket },
      );

      // ACKNOWLEDGED — and only now does the cursor move.
      await advanceSiemCursor(db, {
        sinkId: sink.id,
        stream,
        tenant: sink.tenant,
        position: last.position,
        rows: batch.length,
        replayEpoch,
        now,
      });
      position = last.position;
      batches += 1;
      rows += batch.length;
    }
  } catch (error) {
    return report(sink, stream, "failed", batches, rows, position, error, secrets);
  }
  return report(
    sink,
    stream,
    rows > 0 ? "delivered" : "idle",
    batches,
    rows,
    position,
    null,
    secrets,
  );
}

function report(
  sink: SiemSink,
  stream: SiemStream,
  status: SiemStreamReport["status"],
  batches: number,
  rows: number,
  position: SiemCursorPosition,
  error: unknown,
  secrets: readonly string[],
): SiemStreamReport {
  const message =
    error === null || error === undefined
      ? null
      : redactSecrets(
          error instanceof SiemDeliveryError || error instanceof Error
            ? error.message
            : "unknown delivery failure",
          secrets,
        );
  return {
    sink: sink.id,
    stream,
    status,
    batches,
    rows,
    // `{ts:0,id:""}` is "nothing acknowledged yet", which a caller should see as
    // no cursor rather than as position zero.
    cursor: position.ts === 0 && position.id === "" ? null : position,
    error: message,
  };
}

/**
 * One export pass over every configured sink.
 *
 * Sinks and their streams are pumped SEQUENTIALLY. A tick has a modest CPU and
 * subrequest budget, and a sink that is down must not consume the budget of one
 * that is up — bounding each leg to `maxBatchesPerTick` is what shares it. The
 * cost of sequential legs is latency, which a cursor makes irrelevant: whatever
 * a tick does not reach, the next tick resumes.
 */
export async function runSiemExportPass(
  env: ControlPlaneBindings,
  now: number = Math.floor(Date.now() / 1000),
): Promise<SiemExportReport> {
  let sinks: readonly SiemSink[];
  try {
    sinks = parseSiemSinks(env.SIEM_EXPORT_SINKS);
  } catch (error) {
    const message = error instanceof Error ? error.message : "unparseable sink configuration";
    console.warn(`control-plane: SIEM export disabled — ${message}`);
    return { sinks: 0, streams: [], configError: message };
  }
  if (sinks.length === 0) return { sinks: 0, streams: [], configError: null };

  const db = resolveControlDatabase(env);
  if (db === null) {
    // `CONTROL_PLANE_STORE = "memory"` or no `DB`: there is no evidence table to
    // export from. Loud, because a deployment that configured a sink and gets
    // nothing has no other way to find out.
    console.warn(
      "control-plane: SIEM export configured but no control database is bound; nothing to export",
    );
    return { sinks: sinks.length, streams: [], configError: null };
  }

  const streams: SiemStreamReport[] = [];
  for (const sink of sinks) {
    for (const stream of sink.streams) {
      streams.push(await pumpStream(db, env, sink, stream, now));
    }
  }
  return { sinks: sinks.length, streams, configError: null };
}
