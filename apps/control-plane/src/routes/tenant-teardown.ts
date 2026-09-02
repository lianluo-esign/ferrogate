/**
 * `POST /admin/v1/tenant-teardown` — a platform-operator-only, heavily fenced,
 * IRREVERSIBLE cascade that destroys ONE tenant across every storage layer it
 * touches: its own TenantDataObject (all data tables), the control database's
 * tenant-scoped rows and evidence projections, the KV key/identity directories,
 * and the routing roster. It is the teardown superset of
 * `tenant-consumption-purge.ts` (which only wipes 18 consumption tables inside
 * the DO and deliberately keeps keys/wallets/projects).
 *
 * ## Why this route has to exist
 *
 * There is NO contract DELETE for a tenant — decommissioning is modelled as the
 * status transition `PATCH {status:"deleted"}`, which BLOCKS the tenant and
 * de-authenticates its keys but leaves every historical row alive: the DO's ~80
 * tables, the control projections (`agent_runs`, `request_logs`, `audit_events`,
 * usage rollups…), the api-key directory, memberships, quota/spend policies, the
 * roster row, and the KV/identity caches. Those are the orphans the operator
 * asked to cascade-delete. This route is the one place that reaches all of them.
 *
 * ## The load-bearing ORDER
 *
 * Control-plane evidence projections are RE-MATERIALIZED by live gateway
 * traffic (a request from a still-valid key writes `request_logs`/`agent_runs`
 * back). So the cascade must BLOCK FIRST — kill the keys (both hops: the KV
 * `akd:v1:*` mirror and the `api_key_directory` row) — and only then purge
 * projections, or the purge races the write-back and loses. Killing keys is
 * therefore step 1, and deleting the `tenants` row (which fence 5 reads) is the
 * LAST step so a mid-cascade crash re-runs idempotently against the same fences.
 *
 * ## What it KEEPS (reported, never silently dropped) — see `residuals`
 *
 *  - **Financial records** (`billing_events`, `billing_ledger`): revenue
 *    evidence of money that actually moved, retained by design like audit
 *    anchors. `billing_report_outbox` (in-flight delivery state) IS deleted.
 *  - **Audit anchors** (R2, per-tenant chain): the tamper-evidence proof that
 *    this very teardown was legitimate. The control `audit_events` PROJECTION
 *    rows for the tenant ARE deleted; the immutable R2 anchor chain is kept.
 *  - **R2 asset bytes**: the DO's asset METADATA rows are wiped, but the object
 *    bytes under `assets/v1/t/{tenant}/*` are retained — the asset reclaimer
 *    port is delete-by-key-only (no list, by security design), so a prefix wipe
 *    needs a separate erasure job. The tenant is unreachable, so nothing can
 *    resolve or serve them.
 *  - **The DO object itself**: `retireTenantStorage` empties + de-rosters it but
 *    RETAINS the physical object (documented CF limitation; needs an out-of-band
 *    erasure job with the receipt it returns).
 *  - **Account-global tables** (`plans`, `roles`, `permissions`, `gateway_*`,
 *    `platform_*`, `spend_anomaly_runs`, `managed_worker_*`) are NEVER touched.
 *
 * ## The fences (all fail CLOSED — mirror `tenant-consumption-purge.ts`)
 *
 *  1. platform operator only (this path is out-of-contract → unauthenticated by
 *     `contractAuth`; the handler re-authenticates and requires `platformOperator`).
 *  2. `confirm` must equal `tenant_id` (type the id twice).
 *  3. `acknowledge` must be the literal `TEARDOWN_TENANT`.
 *  4. keep-tenant denylist, ahead of everything else.
 *  5. control status must be `deleted`. UNLIKE purge, a MISSING `tenants` row is
 *     NOT a 404 — step 8 deletes it, so a re-run finds it absent and proceeds in
 *     `already_absent` mode to sweep any residue. A row that exists but is not
 *     `deleted` is still refused (block-before-teardown is mandatory).
 *  6. mis-routing tripwire: the opened DO's `tenant_database_identity(id=1)` must
 *     match; a mismatch deletes NOTHING.
 *  7. authoritative DO only. UNLIKE purge, a null handle does NOT early-return —
 *     the DO is simply skipped and the control/KV/roster sweep still runs (this
 *     is also the idempotent re-run path once the roster row is gone). A non-DO
 *     handle is 503, never a downgrade.
 *
 * Every layer reports counts and per-item errors instead of aborting; the whole
 * operation is idempotent (all `DELETE … WHERE`), so a partial failure is safe
 * to retry — and re-running shortly after is RECOMMENDED to sweep any in-flight
 * write-back that landed between key-kill and projection-purge.
 */
import type { Hono } from "hono";
import { HttpError } from "../middleware/errors.js";
import { extractApiKey, MISSING_API_KEY_MESSAGE, resolveOrThrow } from "../middleware/auth.js";
import type { ControlPlaneEnv } from "../ports.js";
import { tenantDatabaseFor } from "../store/tenancy.js";
import { retireTenantStorage } from "@ferrogate/storage";

/** The mounted path. Out-of-contract, like `/health` and the purge route. */
export const TENANT_TEARDOWN_PATH = "/admin/v1/tenant-teardown";

/** The literal a caller must send in `acknowledge` for any delete to run. */
const ACKNOWLEDGEMENT = "TEARDOWN_TENANT";

/**
 * The keep tenant (jamesduanling). Refused unconditionally, ahead of every other
 * check, so it can never be torn down regardless of its control status.
 */
const KEEP_TENANT_ID = "tenant-9a03494f-728d-4871-bc9f-63baa0f48b24";

/**
 * Control tables scoped by a literal `tenant_id` column — deleted with
 * `WHERE tenant_id = ?`. Derived from `sql/d1-ts/control/*.sql`.
 *
 * DELIBERATELY ABSENT and handled elsewhere: `api_key_directory` +
 * `static_api_keys` (step 1, key-kill first); `admin_user_tenant_memberships` +
 * `admin_user_refresh_tokens` (step 2, identity); `tenant_databases` +
 * `tenant_*_rollups` (step 6, `retireTenantStorage`); `tenants` (step 8, last).
 * `billing_events`/`billing_ledger` are financial residuals (kept by design).
 */
const CONTROL_TENANT_ID_TABLES: readonly string[] = [
  "control_plane_replay_floors",
  "gateway_models", // only this tenant's PRIVATE models; global rows (tenant_id NULL) survive
  "site_domain_verifications",
  "site_domains",
  "sso_pending_flows",
  "sso_provider_configs",
  "tenant_provider_credentials",
  "tenant_role_bindings",
  "billing_report_outbox", // in-flight delivery state, distinct from the retained ledger
];

/**
 * Control tables scoped by a `tenant` column (the composite storage-key spelling
 * the evidence projections use) — deleted with `WHERE tenant = ?`.
 */
const CONTROL_TENANT_TABLES: readonly string[] = [
  "agent_runs",
  "agent_run_events",
  "request_logs",
  "audit_events", // the control PROJECTION rows; the R2 anchor chain is kept
  "delegation_revocations",
  "experiment_shadow_legs",
  "online_eval_leg_quality",
  "online_eval_scores",
  "siem_export_cursors",
  "guardrail_evaluations", // carries `tenant`; its child rows are swept just before it
];

/**
 * Control tables scoped by `(scope_type, scope_id)`, where `scope_id` may be the
 * tenant id OR a descendant project/workspace/api-key id. Deleted with
 * `WHERE scope_id IN (…)` over the harvested descendant set, so per-project /
 * per-key policies do not orphan. Ids are UUIDs, so matching `scope_id` alone
 * (no `scope_type`) is exact.
 */
const CONTROL_SCOPE_TABLES: readonly string[] = [
  "quota_policies",
  "budget_alert_notifications",
  "semantic_cache_policies",
  "spend_anomaly_episodes",
  "spend_throttles",
];

interface TeardownBody {
  readonly tenant_id: string;
  readonly confirm: string;
  readonly acknowledge: string;
}

/** Parse and shape-check the request body. Any deviation is a 400. */
async function readTeardownBody(c: {
  req: { json: () => Promise<unknown> };
}): Promise<TeardownBody> {
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

/** The subset of `names` this database actually has, for existence-guarded deletes. */
async function existingTables(db: D1Database, names: readonly string[]): Promise<Set<string>> {
  if (names.length === 0) return new Set();
  const placeholders = names.map(() => "?").join(", ");
  const rows = await db
    .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (${placeholders})`)
    .bind(...names)
    .all<{ name: string }>();
  return new Set((rows.results ?? []).map((r) => r.name));
}

/** Split an array into fixed-size chunks (for bounded `IN (…)` deletes). */
function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * Mount the teardown route on the control-plane app, OUTSIDE the contract
 * registry (exactly as `/health` and the purge route mount). Returns the mounted
 * path so the composition root can assert on what it wired.
 */
export function mountTenantTeardown(app: Hono<ControlPlaneEnv>): string {
  app.post(TENANT_TEARDOWN_PATH, async (c) => {
    const deps = c.get("deps");

    // --- fence 1: platform operator only ------------------------------------
    const presentedKey = extractApiKey(c.req.raw.headers);
    if (presentedKey === null) {
      throw new HttpError(401, "missing_api_key", MISSING_API_KEY_MESSAGE);
    }
    const auth = resolveOrThrow(await deps.apiKeys.authenticate(presentedKey));
    if (auth.platformOperator !== true) {
      throw new HttpError(
        403,
        "platform_operator_required",
        "tenant-teardown is restricted to platform operators",
      );
    }

    const body = await readTeardownBody(c);

    // --- fences 2 & 3: double-confirmation of intent ------------------------
    if (body.confirm !== body.tenant_id) {
      throw new HttpError(400, "confirm_mismatch", "confirm must equal tenant_id");
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
        "this tenant is protected and cannot be torn down",
      );
    }

    // --- fence 5: control status must be `deleted` (missing = already torn) --
    if (deps.controlDatabase === null) {
      throw new HttpError(
        503,
        "control_unavailable",
        "control database is unavailable; cannot verify tenant status",
      );
    }
    const controlDb = deps.controlDatabase;
    const tid = body.tenant_id;
    const statusRow = await controlDb
      .prepare("SELECT status FROM tenants WHERE id = ?")
      .bind(tid)
      .first<{ status: string }>();
    const alreadyAbsent = statusRow === null;
    if (statusRow !== null && statusRow.status !== "deleted") {
      throw new HttpError(
        403,
        "tenant_not_deleted",
        `tenant ${tid} has status "${statusRow.status}"; mark it "deleted" (block + de-authenticate) before teardown`,
      );
    }

    const errors: Record<string, string> = {};
    const guard = async (label: string, fn: () => Promise<void>): Promise<void> => {
      try {
        await fn();
      } catch (error) {
        errors[label] = error instanceof Error ? error.message : String(error);
      }
    };
    const runDelete = async (sql: string, ...binds: unknown[]): Promise<number> => {
      const result = await controlDb
        .prepare(sql)
        .bind(...binds)
        .run();
      return result.meta?.changes ?? 0;
    };

    // ==================== step 1: kill key authentication ===================
    // First destructive step: without this, in-flight requests re-materialize
    // the very projections we are about to purge.
    const keys = { directory_deleted: 0, static_deleted: 0, kv_deleted: 0 };
    const apiKeyIds: string[] = [];
    await guard("keys.api_key_directory", async () => {
      const rows = await controlDb
        .prepare("SELECT key_hash, id FROM api_key_directory WHERE tenant_id = ?")
        .bind(tid)
        .all<{ key_hash: string; id: string }>();
      for (const row of rows.results ?? []) {
        if (typeof row.id === "string") apiKeyIds.push(row.id);
        if (deps.keyDirectory !== null && typeof row.key_hash === "string") {
          await guard(`keys.kv.${row.key_hash.slice(0, 8)}`, async () => {
            await deps.keyDirectory!.delete(row.key_hash);
            keys.kv_deleted += 1;
          });
        }
      }
      keys.directory_deleted = await runDelete(
        "DELETE FROM api_key_directory WHERE tenant_id = ?",
        tid,
      );
    });
    await guard("keys.static_api_keys", async () => {
      // Tenant-owned static keys only; operator keys (tenant_id NULL) are untouched.
      keys.static_deleted = await runDelete(
        "DELETE FROM static_api_keys WHERE tenant_id = ?",
        tid,
      );
    });

    // ==================== step 2: identity (memberships + KV) ================
    const identity = { members_seen: 0, kv_deleted: 0, orphan_users_deleted: 0 };
    const orphanUserIds: string[] = [];
    await guard("identity.scan", async () => {
      const members = await controlDb
        .prepare("SELECT user_id FROM admin_user_tenant_memberships WHERE tenant_id = ?")
        .bind(tid)
        .all<{ user_id: string }>();
      for (const { user_id } of members.results ?? []) {
        if (typeof user_id !== "string") continue;
        identity.members_seen += 1;
        const other = await controlDb
          .prepare(
            "SELECT COUNT(*) AS n FROM admin_user_tenant_memberships WHERE user_id = ? AND tenant_id <> ?",
          )
          .bind(user_id, tid)
          .first<{ n: number }>();
        if ((other?.n ?? 0) > 0) continue; // cross-tenant human: keep identity + account
        const u = await controlDb
          .prepare("SELECT email, superadmin FROM admin_users WHERE id = ?")
          .bind(user_id)
          .first<{ email: string; superadmin: number }>();
        if (u?.email && deps.identityDirectory !== null) {
          await guard(`identity.kv.${user_id}`, async () => {
            await deps.identityDirectory!.delete(u.email);
            identity.kv_deleted += 1;
          });
        }
        if (u && u.superadmin === 0) orphanUserIds.push(user_id); // tenant-only, non-operator
      }
    });
    await guard("identity.memberships", async () => {
      await runDelete("DELETE FROM admin_user_tenant_memberships WHERE tenant_id = ?", tid);
    });
    await guard("identity.refresh_tokens", async () => {
      await runDelete("DELETE FROM admin_user_refresh_tokens WHERE tenant_id = ?", tid);
    });
    for (const uid of orphanUserIds) {
      await guard(`identity.orphan_user.${uid}`, async () => {
        await runDelete("DELETE FROM admin_user_refresh_tokens WHERE user_id = ?", uid);
        const n = await runDelete("DELETE FROM admin_users WHERE id = ?", uid);
        identity.orphan_users_deleted += n;
      });
    }

    // ==================== step 3: DO full wipe ==============================
    // fence 7 (handle) + fence 6 (identity tripwire) apply here; a null handle is
    // NOT an error — skip the DO and keep sweeping control/KV/roster.
    let durableObject:
      | { database: "durable_object"; identity_verified: boolean; tables: Record<string, number>; total: number }
      | { database: "absent" }
      | { database: "unavailable" };
    const projectIds: string[] = [];
    const workspaceIds: string[] = [];
    const handle = await tenantDatabaseFor(deps.tenantDatabases, tid);
    if (handle === null) {
      durableObject = { database: "absent" };
    } else if (handle.source !== "durable_object") {
      throw new HttpError(
        503,
        "tenant_evidence_unavailable",
        `tenant ${tid} is not backed by an authoritative TenantDataObject`,
      );
    } else {
      const db = handle.db;
      // fence 6: mis-routing tripwire.
      const identityRow = await db
        .prepare("SELECT tenant_id FROM tenant_database_identity WHERE id = 1")
        .first<{ tenant_id: string }>()
        .catch(() => null);
      let identityVerified = false;
      if (identityRow !== null && typeof identityRow.tenant_id === "string") {
        if (identityRow.tenant_id !== tid) {
          throw new HttpError(
            409,
            "tenant_identity_mismatch",
            `opened database identifies as tenant ${identityRow.tenant_id}, not ${tid}; refusing to tear down`,
          );
        }
        identityVerified = true;
      }

      // Harvest descendant ids for the scope-based control sweep BEFORE wiping.
      await guard("durable_object.harvest", async () => {
        const present = await existingTables(db, ["projects", "workspaces"]);
        if (present.has("projects")) {
          const rows = await db.prepare("SELECT id FROM projects").all<{ id: string }>();
          for (const r of rows.results ?? []) if (typeof r.id === "string") projectIds.push(r.id);
        }
        if (present.has("workspaces")) {
          const rows = await db.prepare("SELECT id FROM workspaces").all<{ id: string }>();
          for (const r of rows.results ?? []) if (typeof r.id === "string") workspaceIds.push(r.id);
        }
      });

      // Enumerate every data table and drain it, multi-pass to satisfy FK order.
      // Keep the migration ledger + identity row so the emptied object stays a
      // valid, migrated, self-identifying shell.
      const tableRows = await db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )
        .all<{ name: string }>();
      const KEEP = new Set(["storage_schema_migrations", "tenant_database_identity"]);
      const dataTables = (tableRows.results ?? [])
        .map((r) => r.name)
        .filter((n) => typeof n === "string" && !KEEP.has(n));
      const tables: Record<string, number> = {};
      let remaining = new Set(dataTables);
      let lastError = "";
      for (let pass = 0; pass < 6 && remaining.size > 0; pass += 1) {
        let progressed = false;
        for (const table of [...remaining]) {
          try {
            const result = await db.prepare(`DELETE FROM ${table}`).run();
            tables[table] = (tables[table] ?? 0) + (result.meta?.changes ?? 0);
            remaining.delete(table);
            progressed = true;
          } catch (error) {
            lastError = error instanceof Error ? error.message : String(error);
          }
        }
        if (!progressed) break; // a cycle / genuinely undeletable set — report below
      }
      for (const table of remaining) errors[`durable_object.${table}`] = lastError || "undeleted";
      const total = Object.values(tables).reduce((a, b) => a + b, 0);
      durableObject = { database: "durable_object", identity_verified: identityVerified, tables, total };
    }

    // ==================== step 4: control tenant-scoped sweep ===============
    // Keys are dead, so no traffic re-materializes these.
    const controlRows: Record<string, number> = {};
    const allControlTables = [
      ...CONTROL_TENANT_ID_TABLES,
      ...CONTROL_TENANT_TABLES,
      ...CONTROL_SCOPE_TABLES,
      "guardrail_check_evaluations",
      "control_plane_resources",
    ];
    const presentControl = await existingTables(controlDb, allControlTables);

    for (const table of CONTROL_TENANT_ID_TABLES) {
      if (!presentControl.has(table)) continue;
      await guard(`control.${table}`, async () => {
        controlRows[table] = await runDelete(`DELETE FROM ${table} WHERE tenant_id = ?`, tid);
      });
    }

    // Guardrail child rows first (keyed by parent evaluation_id), then the parents.
    if (presentControl.has("guardrail_check_evaluations") && presentControl.has("guardrail_evaluations")) {
      await guard("control.guardrail_check_evaluations", async () => {
        controlRows.guardrail_check_evaluations = await runDelete(
          "DELETE FROM guardrail_check_evaluations WHERE evaluation_id IN (SELECT id FROM guardrail_evaluations WHERE tenant = ?)",
          tid,
        );
      });
    }
    for (const table of CONTROL_TENANT_TABLES) {
      if (!presentControl.has(table)) continue;
      await guard(`control.${table}`, async () => {
        controlRows[table] = await runDelete(`DELETE FROM ${table} WHERE tenant = ?`, tid);
      });
    }

    // Scope-based tables: match scope_id against {tenant} ∪ projects ∪ workspaces ∪ api-keys.
    const scopeIds = [tid, ...projectIds, ...workspaceIds, ...apiKeyIds];
    for (const table of CONTROL_SCOPE_TABLES) {
      if (!presentControl.has(table)) continue;
      await guard(`control.${table}`, async () => {
        let deleted = 0;
        for (const part of chunk(scopeIds, 100)) {
          const placeholders = part.map(() => "?").join(", ");
          deleted += await runDelete(
            `DELETE FROM ${table} WHERE scope_id IN (${placeholders})`,
            ...part,
          );
        }
        controlRows[table] = deleted;
      });
    }

    // The generic config-document table: every tenant-owned resource document.
    if (presentControl.has("control_plane_resources")) {
      await guard("control.control_plane_resources", async () => {
        controlRows.control_plane_resources = await runDelete(
          "DELETE FROM control_plane_resources WHERE json_extract(document_json, '$.tenant_id') = ?",
          tid,
        );
      });
    }
    const controlTotal = Object.values(controlRows).reduce((a, b) => a + b, 0);

    // ==================== step 6: rollups + roster (de-list) ================
    const roster = { removed: false };
    await guard("roster.retire", async () => {
      const receipt = await retireTenantStorage(deps.tenantDatabases, tid);
      roster.removed = receipt.rosterRowRemoved;
    });

    // ==================== step 8: delete the tenants row (LAST) =============
    let tenantsRowDeleted = false;
    await guard("tenants.row", async () => {
      const n = await runDelete("DELETE FROM tenants WHERE id = ?", tid);
      tenantsRowDeleted = n > 0;
    });

    return c.json({
      tenant_id: tid,
      status: "torn_down",
      already_absent: alreadyAbsent,
      keys,
      identity,
      durable_object: durableObject,
      control_rows: { ...controlRows, total: controlTotal },
      roster,
      r2: {
        assets_retained: true,
        note: "object bytes under assets/v1/t/{tenant}/* retained; DO asset metadata wiped. Needs an out-of-band erasure job (reclaimer is delete-by-key only).",
      },
      residuals: {
        financial_records: "billing_events + billing_ledger retained (revenue evidence, like audit anchors)",
        audit_anchors: "R2 per-tenant anchor chain retained (tamper-evidence proof of this teardown)",
        durable_object: "physical object retained + de-rostered by retireTenantStorage; empty but billable until an erasure job runs",
        siem_exports: "SIEM_EXPORTS keyed by sink, not tenant — not swept",
      },
      tenants_row_deleted: tenantsRowDeleted,
      ...(Object.keys(errors).length > 0 ? { errors } : {}),
    });
  });

  return TENANT_TEARDOWN_PATH;
}
