/**
 * The maintenance Cron seam for the control plane.
 *
 * Agent schedules no longer run from this handler. Each TenantDataObject owns
 * the earliest schedule deadline, its native alarm publishes one tenant-only
 * wake-up to the queue, and `alarm-queue.ts` performs the claim and dispatch.
 * This Cron remains for fleet maintenance passes that are intentionally not
 * schedule execution: tenant-catalog reconciliation, audit anchoring, SIEM
 * export and spend-anomaly detection.
 *
 * `test/cron-trigger.test.ts` checks that the maintenance trigger remains
 * declared, while `test/worker-entry.test.ts` checks that the default export
 * exposes the handler shape workerd invokes.
 */

import { resolveAuditAnchorBucket, resolveControlDatabase, resolveDeps } from "../adapters.js";
import { anchorAuditChains } from "../audit/anchor.js";
import { type SpendAnomalyReport, runSpendAnomalyPass } from "../finops/pass.js";
import type { ControlPlaneBindings, ControlPlaneDeps } from "../ports.js";
import { type SiemExportReport, runSiemExportPass } from "../siem/pump.js";
import { type SharedConfigPassReport, fanOutSharedConfig } from "../store/shared-config.js";
import {
  type TenantCatalogAuditSweepReport,
  reconcileProvisionedTenantCatalogAudits,
} from "../store/tenant-model-catalog.js";
import type { ScheduleTickSummary } from "./engine.js";

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
  /**
   * What the shared-config push pass (#948) delivered: `skipped: "unchanged"`
   * on every tick where the platform config revision has not moved past the
   * fleet watermark — the ordinary answer, since config is edited rarely and an
   * idle fleet must do zero tenant-object work — and a `pushed`/`failed` count
   * on the tick after an operator edits a plan/group/announcement.
   */
  readonly sharedConfig: SharedConfigPassReport;
}

/**
 * One minute of the control-plane maintenance work, built from the Worker's
 * bindings.
 *
 * Deps come from `resolveDeps` — the SAME composition root every request uses —
 * Schedule execution is deliberately absent here. TenantDataObject native
 * alarms publish tenant wake-ups to the queue consumer in `alarm-queue.ts`; a
 * fleet-wide Cron scan would reintroduce a second schedule authority and race
 * the per-object fire claim.
 *
 * Errors are swallowed into the report rather than thrown. A `scheduled`
 * handler that throws is retried by the platform; maintenance passes own their
 * own cursors and retry policy, so a transient failure must not turn into a
 * second schedule execution path.
 */
export async function runScheduledTick(
  env: ControlPlaneBindings,
  now: number = Math.floor(Date.now() / 1000),
): Promise<ScheduledTickReport> {
  const deps = resolveDeps(env, { requestId: `cron-${now}` });
  const tenantCatalogAudit = await catalogAuditPass(deps, now);
  const summary: ScheduleTickSummary = {
    scanned: 0,
    fired: [],
    skipped: [],
    advanced: [],
    errors: [],
  };
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
    // report, so it cannot make the platform retry this maintenance pass.
    spendAnomaly: await runSpendAnomalyPass(env, now),
    tenantCatalogAudit,
    sharedConfig: await sharedConfigPass(deps, now),
  };
}

/**
 * How often (in minutes) the shared-config push pass is allowed to fan out.
 *
 * The pass first checks the fleet watermark (`shared_config_push_state`) against
 * the platform config revision and does NOTHING when they match — the common
 * case — so this cadence only bounds how fast a config EDIT reaches the fleet,
 * not how often idle ticks cost anything. A few minutes of staleness on
 * plans/groups/announcements is the eventual-consistency contract the mirror is
 * built on. Kept coarser than a minute so a burst of edits coalesces into one
 * fan-out rather than one per edit.
 */
export const SHARED_CONFIG_PUSH_PERIOD_MIN = 5;

async function sharedConfigPass(
  deps: Pick<ControlPlaneDeps, "controlDatabase" | "tenantDatabases" | "tenantStorage">,
  now: number,
): Promise<SharedConfigPassReport> {
  if (deps.controlDatabase === null) {
    return {
      revision: 0,
      scanned: 0,
      pushed: 0,
      failed: 0,
      skipped: "control_database_unavailable",
    };
  }
  // Gate on the minute count like the catalog sweep; a missed tick is harmless
  // because the watermark makes the next eligible window re-decide from scratch.
  if (Math.floor(now / 60) % SHARED_CONFIG_PUSH_PERIOD_MIN !== 0) {
    return { revision: 0, scanned: 0, pushed: 0, failed: 0, skipped: "unchanged" };
  }
  return fanOutSharedConfig(deps, now);
}

/**
 * How often (in minutes) the catalog-audit backstop sweep is allowed to run.
 *
 * `reconcileProvisionedTenantCatalogAudits` is an O(N) FLEET sweep: it enumerates
 * every provisioned tenant, opens each tenant DO, and writes any pending outbox
 * rows to the SINGLE control DO. Run every minute it was a ~16s control-DO burst
 * that serialized on the one control-DO thread against the latency-critical login
 * path (observed login TTFB spiking to ~8s during a tick). It is only a BACKSTOP —
 * catalog audits are delivered inline at write time; this sweep just drains outbox
 * rows whose inline delivery failed, and the outbox keeps those rows durable until
 * a later window delivers them. So a coarse cadence is safe and removes 14 of every
 * 15 contention windows.
 */
export const CATALOG_RECONCILE_PERIOD_MIN = 15;

async function catalogAuditPass(
  deps: Pick<ControlPlaneDeps, "controlDatabase" | "tenantDatabases">,
  now: number,
): Promise<TenantCatalogAuditSweepReport> {
  if (deps.controlDatabase === null) {
    return {
      scanned: 0,
      reconciled: 0,
      failed: 0,
      skipped: "control_database_unavailable",
    };
  }
  // Cron ticks land on the minute (`controller.scheduledTime`), so gate on the
  // minute count rather than raw seconds. A missed tick is harmless — the outbox
  // is durable and the next eligible window reconciles it.
  if (Math.floor(now / 60) % CATALOG_RECONCILE_PERIOD_MIN !== 0) {
    return { scanned: 0, reconciled: 0, failed: 0, skipped: "cadence_skipped" };
  }
  return reconcileProvisionedTenantCatalogAudits(deps.tenantDatabases, deps.controlDatabase);
}

/**
 * The audit-anchor pass (#684), riding the same minute maintenance tick.
 *
 * It runs on every tick rather than on a slower cadence of its own because the
 * anchor cadence IS the detection window: a row appended and deleted between
 * two anchors was never pinned and cannot be missed by comparison. A tick that
 * finds no new chain head writes nothing (the job skips an already-anchored
 * head), so the cost of the fast cadence is one grouped query and one R2 `head`
 * per chain.
 *
 * Failures are caught and reported, never thrown: a `scheduled` handler that
 * throws is retried by the platform, and retrying an evidence write must not
 * introduce a second schedule execution path.
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
 * that throws is RETRIED by the platform. The pump owns its cursor, so its next
 * maintenance pass is the retry and no schedule dispatch is coupled to it.
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
 * `waitUntil` is NOT used to background the maintenance pass: the platform
 * keeps the invocation alive for the returned promise, so its cursor and
 * report are settled before the invocation ends.
 */
export const scheduled: ExportedHandlerScheduledHandler<ControlPlaneBindings> = async (
  controller,
  env,
) => {
  await runScheduledTick(env, Math.floor(controller.scheduledTime / 1000));
};
