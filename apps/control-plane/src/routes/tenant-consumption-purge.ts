/**
 * `POST /admin/v1/tenant-consumption-purge` — a platform-operator-only, guarded
 * purge of ONE tenant's 消费事件 (billing/usage) and 模型请求 (request/agent
 * telemetry) rows from that tenant's own TenantDataObject.
 *
 * ## Why this route has to exist at all
 *
 * `billing_events` (消费事件) and `request_logs` (模型请求), plus every rollup /
 * ledger / burn table derived from them, are TENANT-PRIVATE: they live in each
 * tenant's own Durable Object and are NEVER projected to the control database
 * (see `routes/admin_cost_record.ts` — the operator surface reads control D1,
 * which for these tables is empty or a stale mirror). Hard-deleting a test
 * tenant's control-D1 rows therefore leaves the AUTHORITATIVE consumption data
 * alive and orphaned inside the DO, still attributable, still counting. There
 * is no contract operation that reaches into a specific tenant's DO to erase it,
 * so cleaning up a decommissioned test tenant needs this dedicated, heavily
 * fenced route.
 *
 * ## What it deletes — and what it deliberately keeps
 *
 * The allowlist below is exactly the consumption + request surface. It does NOT
 * touch `wallets` (the balance survives), `tenant_database_identity`, api keys,
 * projects, workspaces, assets, or anything else — this is a consumption/usage
 * wipe, not a tenant teardown.
 *
 * ## The fences (all fail CLOSED)
 *
 * A route that unconditionally `DELETE FROM`s a tenant's tables is a foot-gun, so
 * every precondition refuses rather than assumes:
 *
 *  1. **platform operator only.** This path is not in the contract, so
 *     `contractAuth` passes it through UNAUTHENTICATED (it only guards the
 *     documented 214). The handler re-authenticates the presented key itself and
 *     requires `auth.platformOperator === true`; a tenant-scoped key is 403.
 *  2. **`confirm` must equal `tenant_id`.** A fat-fingered id cannot be purged by
 *     accident — the operator has to type the same id twice.
 *  3. **`acknowledge` must be the literal `PURGE_CONSUMPTION`.** No bare id can
 *     trigger a delete; the caller has to spell out the intent.
 *  4. **keep-tenant denylist.** The live keep tenant is refused unconditionally,
 *     independent of every other check, so no combination of inputs can reach it.
 *  5. **control status must be `deleted`.** The control database is consulted and
 *     the tenant must already be marked `deleted`. An active/suspended tenant —
 *     or one the control plane has never heard of — is refused. A missing control
 *     database is 503, never an implicit allow.
 *  6. **mis-routing tripwire.** The opened DO's own
 *     `tenant_database_identity(id=1).tenant_id` must match the requested id. If
 *     the router ever handed back the wrong object, the DELETEs never run.
 *  7. **authoritative DO only.** A tenant with no provisioned DO is a no-op (not
 *     an error); a DO reachable only as a shared/native handle is 503, never a
 *     downgrade that would delete from the wrong place.
 *
 * The DELETEs are UNCONDITIONAL (`DELETE FROM <table>`), which is correct and
 * complete precisely because the DO is single-tenant: there is no other tenant's
 * data in it to catch, and some of these tables carry no `tenant_id` column to
 * scope on. Fence 6 is what earns that unconditional form. The operation is
 * idempotent — re-running it deletes nothing new — so a partial failure is safe
 * to retry, and per-table results (including per-table errors) are returned so
 * the operator sees exactly what happened.
 */
import type { Hono } from "hono";
import { HttpError } from "../middleware/errors.js";
import { extractApiKey, MISSING_API_KEY_MESSAGE, resolveOrThrow } from "../middleware/auth.js";
import type { ControlPlaneEnv } from "../ports.js";
import { tenantDatabaseFor } from "../store/tenancy.js";

/** The mounted path. Out-of-contract, like `/health` and `/version`. */
export const TENANT_CONSUMPTION_PURGE_PATH = "/admin/v1/tenant-consumption-purge";

/** The literal a caller must send in `acknowledge` for any delete to run. */
const ACKNOWLEDGEMENT = "PURGE_CONSUMPTION";

/**
 * The keep tenant (jamesduanling). Refused unconditionally, ahead of every other
 * check, so it can never be purged regardless of its control status.
 */
const KEEP_TENANT_ID = "tenant-9a03494f-728d-4871-bc9f-63baa0f48b24";

/**
 * The consumption (消费事件) + request (模型请求) tables, and only those.
 *
 * `wallets` is intentionally ABSENT — the balance is preserved. Identity, keys,
 * projects, workspaces and assets are likewise untouched. Any name here that a
 * particular DO's schema does not have is silently skipped (and reported), so
 * the list is safe across DO schema versions.
 */
const CONSUMPTION_REQUEST_TABLES: readonly string[] = [
  // 模型请求 — request & agent-run execution telemetry
  "request_logs",
  "agent_run_events",
  "agent_runs",
  "batch_request_results",
  "batches",
  // 消费事件 — billing events, ledger, usage rollups, spend accounting
  "billing_events",
  "billing_ledger",
  "billing_report_outbox",
  "usage_aggregate_rollups",
  "usage_metadata_rollups",
  "usage_monthly_rollups",
  "usage_event_claims",
  "usage_projection_retries",
  "agent_cost_burn",
  "spend_anomaly_episodes",
  "budget_alert_notifications",
  "wallet_reservations",
  "wallet_settlements",
];

interface PurgeBody {
  readonly tenant_id: string;
  readonly confirm: string;
  readonly acknowledge: string;
}

/** Parse and shape-check the request body. Any deviation is a 400. */
async function readPurgeBody(c: {
  req: { json: () => Promise<unknown> };
}): Promise<PurgeBody> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    throw new HttpError(400, "invalid_request_body", "request body must be JSON");
  }
  if (typeof raw !== "object" || raw === null) {
    throw new HttpError(400, "invalid_request_body", "request body must be a JSON object");
  }
  const body = raw as Record<string, unknown>;
  const tenantId = body.tenant_id;
  const confirm = body.confirm;
  const acknowledge = body.acknowledge;
  if (typeof tenantId !== "string" || tenantId.trim() === "") {
    throw new HttpError(400, "invalid_request_body", "tenant_id is required");
  }
  if (typeof confirm !== "string") {
    throw new HttpError(400, "invalid_request_body", "confirm is required");
  }
  if (typeof acknowledge !== "string") {
    throw new HttpError(400, "invalid_request_body", "acknowledge is required");
  }
  return { tenant_id: tenantId.trim(), confirm, acknowledge };
}

/** The set of allowlisted tables this DO actually has, for the skip report. */
async function existingTables(db: D1Database): Promise<Set<string>> {
  const placeholders = CONSUMPTION_REQUEST_TABLES.map(() => "?").join(", ");
  const rows = await db
    .prepare(
      `SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (${placeholders})`,
    )
    .bind(...CONSUMPTION_REQUEST_TABLES)
    .all<{ name: string }>();
  return new Set((rows.results ?? []).map((r) => r.name));
}

/**
 * Mount the purge route on the control-plane app, OUTSIDE the contract registry
 * (exactly as `/health` and `/version` mount). Returns the mounted path so the
 * composition root can assert on what it wired, like the other seams.
 */
export function mountTenantConsumptionPurge(app: Hono<ControlPlaneEnv>): string {
  app.post(TENANT_CONSUMPTION_PURGE_PATH, async (c) => {
    const deps = c.get("deps");

    // --- fence 1: platform operator only (this path is unauthenticated by the
    // contract middleware, so authenticate here) ---------------------------
    const presentedKey = extractApiKey(c.req.raw.headers);
    if (presentedKey === null) {
      throw new HttpError(401, "missing_api_key", MISSING_API_KEY_MESSAGE);
    }
    const auth = resolveOrThrow(await deps.apiKeys.authenticate(presentedKey));
    if (auth.platformOperator !== true) {
      throw new HttpError(
        403,
        "platform_operator_required",
        "tenant-consumption-purge is restricted to platform operators",
      );
    }

    const body = await readPurgeBody(c);

    // --- fences 2 & 3: double-confirmation of intent ------------------------
    if (body.confirm !== body.tenant_id) {
      throw new HttpError(
        400,
        "confirm_mismatch",
        "confirm must equal tenant_id",
      );
    }
    if (body.acknowledge !== ACKNOWLEDGEMENT) {
      throw new HttpError(
        400,
        "acknowledge_required",
        `acknowledge must be the literal "${ACKNOWLEDGEMENT}"`,
      );
    }

    // --- fence 4: keep-tenant denylist, ahead of everything else ------------
    if (body.tenant_id === KEEP_TENANT_ID) {
      throw new HttpError(
        403,
        "tenant_protected",
        "this tenant is protected and cannot be purged",
      );
    }

    // --- fence 5: control status must be `deleted` (fail closed) ------------
    if (deps.controlDatabase === null) {
      throw new HttpError(
        503,
        "control_unavailable",
        "control database is unavailable; cannot verify tenant status",
      );
    }
    const statusRow = await deps.controlDatabase
      .prepare("SELECT status FROM tenants WHERE id = ?")
      .bind(body.tenant_id)
      .first<{ status: string }>();
    if (statusRow === null) {
      throw new HttpError(
        404,
        "tenant_unknown",
        `tenant ${body.tenant_id} is not known to the control plane`,
      );
    }
    if (statusRow.status !== "deleted") {
      throw new HttpError(
        403,
        "tenant_not_deleted",
        `tenant ${body.tenant_id} has status "${statusRow.status}"; only tenants marked "deleted" can be purged`,
      );
    }

    // --- fence 7: authoritative DO only. A tenant with no provisioned DO is a
    // clean no-op; a non-DO handle 503s inside tenantDatabaseFor's callers. ---
    const handle = await tenantDatabaseFor(deps.tenantDatabases, body.tenant_id);
    if (handle === null) {
      return c.json({
        tenant_id: body.tenant_id,
        database: "absent",
        identity_verified: false,
        deleted: {},
        skipped: [],
        total: 0,
      });
    }
    if (handle.source !== "durable_object") {
      throw new HttpError(
        503,
        "tenant_evidence_unavailable",
        `tenant ${body.tenant_id} is not backed by an authoritative TenantDataObject`,
      );
    }
    const db = handle.db;

    // --- fence 6: mis-routing tripwire. If the DO knows its own tenant and it
    // is not the one we were asked to purge, delete NOTHING. -----------------
    const identityRow = await db
      .prepare("SELECT tenant_id FROM tenant_database_identity WHERE id = 1")
      .first<{ tenant_id: string }>()
      .catch(() => null);
    let identityVerified = false;
    if (identityRow !== null && typeof identityRow.tenant_id === "string") {
      if (identityRow.tenant_id !== body.tenant_id) {
        throw new HttpError(
          409,
          "tenant_identity_mismatch",
          `opened database identifies as tenant ${identityRow.tenant_id}, not ${body.tenant_id}; refusing to purge`,
        );
      }
      identityVerified = true;
    }

    // --- the purge: unconditional per-table DELETE, single-tenant DO --------
    const present = await existingTables(db);
    const deleted: Record<string, number> = {};
    const errors: Record<string, string> = {};
    const skipped: string[] = [];
    let total = 0;
    for (const table of CONSUMPTION_REQUEST_TABLES) {
      if (!present.has(table)) {
        skipped.push(table);
        continue;
      }
      try {
        const result = await db.prepare(`DELETE FROM ${table}`).run();
        const changes = result.meta?.changes ?? 0;
        deleted[table] = changes;
        total += changes;
      } catch (error) {
        errors[table] = error instanceof Error ? error.message : String(error);
      }
    }

    return c.json({
      tenant_id: body.tenant_id,
      database: "durable_object",
      identity_verified: identityVerified,
      deleted,
      skipped,
      ...(Object.keys(errors).length > 0 ? { errors } : {}),
      total,
    });
  });

  return TENANT_CONSUMPTION_PURGE_PATH;
}
