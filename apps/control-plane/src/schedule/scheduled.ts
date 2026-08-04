/**
 * The `scheduled` seam for the agent-schedule tick.
 *
 * ## Read this before believing the scheduler runs
 *
 * Everything under `src/schedule/` is reachable from the HTTP surface — create,
 * replace, merge, delete and `run-now` all go through it, and
 * `test/schedule-wiring.test.ts` proves each of those mounts by removal. The
 * TICK is the exception: on Cloudflare a periodic tick is a Cron Trigger, which
 * means a `scheduled` handler on the module `wrangler.toml`'s `main` points at
 * (`src/worker.ts`) plus a `[triggers] crons` stanza. Both halves are already
 * wired in this Worker, and the entrypoint test drives the same default export
 * that Cloudflare invokes:
 *
 * ```ts
 * // apps/control-plane/src/worker.ts
 * export { default } from "./index.js";
 * export { scheduled } from "./schedule/scheduled.js";   // <- ADD
 * ```
 *
 * ```toml
 * # apps/control-plane/wrangler.toml
 * [triggers]
 * crons = ["* * * * *"]                                  # <- ADD
 * ```
 *
 * (A Worker's `scheduled` handler and its `fetch` handler may be separate named
 * exports of the entry module; `export default withAliasCanonicalization(app)`
 * stays exactly as it is. `* * * * *` is the finest granularity Cron Triggers
 * offer, which is also the finest granularity a 5-field cron expression can
 * ask for, so nothing is lost — a sub-minute schedule would need a Durable
 * Object alarm instead.)
 *
 * `test/cron-trigger.test.ts` checks the committed trigger and
 * `test/worker-entry.test.ts` invokes the default export through the same shape
 * workerd uses. A scheduler whose tick is never invoked is exactly the defect
 * `docs/rewrite/parity-audit-storage.md` §4.2 recorded, so both wiring halves
 * stay under test here.
 */

import { resolveAuditAnchorBucket, resolveControlDatabase, resolveDeps } from "../adapters.js";
import { anchorAuditChains } from "../audit/anchor.js";
import { type SpendAnomalyReport, runSpendAnomalyPass } from "../finops/pass.js";
import type { ControlPlaneBindings, ControlPlaneDeps } from "../ports.js";
import { type SiemExportReport, runSiemExportPass } from "../siem/pump.js";
import {
  reconcileProvisionedTenantCatalogAudits,
  type TenantCatalogAuditSweepReport,
} from "../store/tenant-model-catalog.js";
import { type ScheduleTickSummary, runScheduleTick } from "./engine.js";

/** What `scheduled` reports back, so a tail log says something useful. */
export interface ScheduledTickReport extends ScheduleTickSummary {
  readonly at: number;
  /**
   * What the audit-anchor pass did (#684): how many anchors were written, or
   * why none were. `"unconfigured"` means the deployment binds no R2 bucket and
   * therefore has a hash chain with NOTHING pinning its head — visible in a tail
   * log rather than silent, because that gap is invisible from every response.
   */
  readonly auditAnchor: "unconfigured" | "failed" | { written: number; skipped: number };
  /**
   * What the SIEM export pass did (#683): how many sinks were configured and
   * what each (sink, stream) leg delivered, skipped or failed on.
   *
   * Reported on every tick rather than only when something moved, because "the
   * pump ran and had nothing to send" and "the pump did not run" are the two
   * states an operator most needs to tell apart — and in the DESTINATION they
   * look identical.
   */
  readonly siemExport: SiemExportReport;
  /**
   * What the spend-anomaly detector did (#697): how many scopes it evaluated,
   * how many episodes opened, how many notifications went out — or WHY it did
   * nothing.
   *
   * On the report for the same reason the other two passes are: "the detector
   * ran and nothing was anomalous" and "the detector did not run" are the two
   * states an operator most needs to tell apart, and in an alert channel they
   * are indistinguishable. `skipped: "already_evaluated"` is the ordinary
   * answer on 59 of every 60 ticks.
   */
  readonly spendAnomaly: SpendAnomalyReport;
  /** What the scheduled tenant-catalog audit pass delivered or retained for retry. */
  readonly tenantCatalogAudit: TenantCatalogAuditSweepReport;
}

/**
 * One tick of the agent-schedule engine, built from the Worker's bindings.
 *
 * Deps come from `resolveDeps` — the SAME composition root every request uses —
 * rather than from a second, tick-only construction. That is deliberate: a
 * scheduler holding its own store would be able to fire schedules the request
 * path cannot see, and the tenancy lifecycle gate it enforces would be a
 * different gate from the one the admin surface enforces.
 *
 * Errors are swallowed into the report rather than thrown. A `scheduled`
 * handler that throws is retried by the platform, and retrying a tick whose
 * failure is a bad schedule definition would re-run every OTHER due schedule in
 * the batch with it — the fire ledger makes that harmless but not free.
 */
export async function runScheduledTick(
  env: ControlPlaneBindings,
  now: number = Math.floor(Date.now() / 1000),
): Promise<ScheduledTickReport> {
  const deps = resolveDeps(env, { requestId: `cron-${now}` });
  const tenantCatalogAudit = await catalogAuditPass(deps);
  const summary = await runScheduleTick(
    { store: deps.store, lifecycle: deps.lifecycle, nodeId: "control-plane-cron" },
    now,
  );
  return {
    at: now,
    ...summary,
    auditAnchor: await anchorPass(env, now),
    siemExport: await siemPass(env, now),
    // MOUNT GATE (#697). Delete this line and `test/spend-anomaly.test.ts` goes
    // red on every assertion: the detector would exist, be unit-tested, and
    // never once run — which is the `docs/rewrite/parity-audit-storage.md` §4.2
    // defect this file's own docblock warns about, one layer further out.
    //
    // `runSpendAnomalyPass` never rejects; it folds every failure into its
    // report, so it cannot make the platform retry this tick and re-dispatch
    // the schedules above.
    spendAnomaly: await runSpendAnomalyPass(env, now),
    tenantCatalogAudit,
  };
}

async function catalogAuditPass(
  deps: Pick<ControlPlaneDeps, "controlDatabase" | "tenantDatabases" | "tenantStorage">,
): Promise<TenantCatalogAuditSweepReport> {
  if (deps.controlDatabase === null) {
    return {
      scanned: 0,
      reconciled: 0,
      failed: 0,
      skipped: "control_database_unavailable",
    };
  }
  return reconcileProvisionedTenantCatalogAudits(
    deps.tenantStorage ?? deps.tenantDatabases,
    deps.controlDatabase,
  );
}

/**
 * The audit-anchor pass (#684), riding the SAME minute tick as the scheduler.
 *
 * It runs on every tick rather than on a slower cadence of its own because the
 * anchor cadence IS the detection window: a row appended and deleted between
 * two anchors was never pinned and cannot be missed by comparison. A tick that
 * finds no new chain head writes nothing (the job skips an already-anchored
 * head), so the cost of the fast cadence is one grouped query and one R2 `head`
 * per chain.
 *
 * Failures are caught and reported, never thrown: a `scheduled` handler that
 * throws is retried by the platform, and retrying would re-run the SCHEDULE
 * half of the tick — dispatching schedules a second time because an evidence
 * write failed is a worse outcome than a late anchor.
 */
async function anchorPass(
  env: ControlPlaneBindings,
  now: number,
): Promise<ScheduledTickReport["auditAnchor"]> {
  const db = resolveControlDatabase(env);
  const bucket = resolveAuditAnchorBucket(env);
  if (db === null) return "unconfigured";
  try {
    const result = await anchorAuditChains(db, bucket, now);
    if (result.unconfigured) {
      console.warn(
        "control-plane: audit chains are NOT anchored — no [[r2_buckets]] AUDIT_ANCHORS binding; " +
          "a truncated audit trail will not be detectable (see docs/audit-tamper-evidence.md)",
      );
      return "unconfigured";
    }
    return { written: result.written, skipped: result.skipped };
  } catch (error) {
    console.warn("control-plane: audit anchor pass failed", error);
    return "failed";
  }
}

/**
 * The SIEM export pass (#683), riding the same minute tick.
 *
 * Errors are caught here rather than thrown for the reason the anchor pass
 * gives one paragraph up, and it applies with more force: a `scheduled` handler
 * that throws is RETRIED by the platform, and retrying because a customer's
 * collector answered 503 would re-dispatch every due SCHEDULE in the batch. The
 * pump does not need the retry — its cursor is the retry, and the next tick is
 * a minute away.
 */
async function siemPass(env: ControlPlaneBindings, now: number): Promise<SiemExportReport> {
  try {
    return await runSiemExportPass(env, now);
  } catch (error) {
    // Deliberately not `String(error)` into the report: `runSiemExportPass`
    // already redacts what it reports, and an escaped exception is the one path
    // whose text nothing has vetted.
    console.warn(
      "control-plane: SIEM export pass failed",
      error instanceof Error ? error.name : "",
    );
    return { sinks: 0, streams: [], configError: "siem export pass failed" };
  }
}

/**
 * The `ExportedHandler["scheduled"]` shape workerd expects.
 *
 * `waitUntil` is NOT used to background the tick: the platform keeps the
 * invocation alive for the returned promise, and detaching it would let the
 * isolate be evicted mid-batch, leaving fire rows claimed with no dispatch
 * behind them. Awaiting is what makes the claim-then-dispatch order safe.
 */
export const scheduled: ExportedHandlerScheduledHandler<ControlPlaneBindings> = async (
  controller,
  env,
) => {
  await runScheduledTick(env, Math.floor(controller.scheduledTime / 1000));
};
