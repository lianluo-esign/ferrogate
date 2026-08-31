/**
 * `POST /admin/v1/quota-policy-backfill` — a platform-operator-only, one-time
 * sweep that copies every typed `quota_policies` ENFORCEMENT row from the
 * CONTROL database into the `quota_policies` table of the tenant object that
 * owns it.
 *
 * ## Why this route has to exist — the deploy-ordering invariant it satisfies
 *
 * The quota-policy relocation off the control database (part of the control-D1
 * removal) moves the typed enforcement row into each tenant's own object. The
 * writer already dual-writes it there on every operator edit
 * (`routes/quota_policy.ts::shadowProjectQuotaPolicyToTenant`), and the readers
 * are switched to read from the object — the finops spend-anomaly pass already,
 * the three admission workers and the gateway policy sources next. But a reader
 * pointed at an object whose table has never been written reads "no policy",
 * and that is NOT direction-neutral: `finops/source.ts::readTenantPoliciesFleet`
 * spells out that a missing tuning row reverts a LOOSENED tenant to the tight
 * shipped defaults (louder alerts), and the admission chain reading an empty
 * table admits UNLIMITED traffic for a tenant the operator had capped.
 *
 * Those failures only exist in the window between "reader deployed" and "row
 * present". The writer's dual-write closes that window for any policy edited
 * AFTER it ships, but not for the policies already sitting on control that
 * nobody re-saves. This route closes it for those: run ONCE after the writer
 * dual-write is deployed and BEFORE (or immediately alongside) the readers are
 * pointed at the objects, so every object's table already holds exactly what the
 * gateway enforces from control today. "Provisioning precedes traffic", applied
 * to the rows rather than the table — the same ordering `0033_quota_policies.sql`
 * establishes for the table itself.
 *
 * ## Why a straight column COPY, not a re-projection
 *
 * The obvious reuse — feed each control row back through
 * `store/quota_registry.ts::projectQuotaPolicy` — is WRONG here. That projection
 * is DOCUMENT-shaped: it reads `record.model_allowlist` / `record.required_tags`
 * / `record.residency_regions` (the JSON arrays a `POST` body carries), whereas a
 * typed row holds `model_allowlist_json` / `required_tags_json` / … (JSON
 * strings), and it decodes the integer booleans as booleans
 * (`record.enabled !== false`, `record.require_zero_data_retention === true`) —
 * against a typed row whose `enabled` is the integer `0` those tests read the
 * WRONG way. So re-projection would silently drop the array/tag/residency fields
 * and mis-copy the disabled flags. A verbatim column-for-column copy preserves
 * every value — JSON strings, `0`/`1` flags and `NULL`s alike — and the two
 * tables are byte-identical by construction (`0033_quota_policies.sql` reproduces
 * the final 41-column control shape on purpose), so a copy is total.
 *
 * ## Idempotent, additive, safe to re-run
 *
 * Every write is `INSERT … ON CONFLICT (id) DO UPDATE`, so a second run
 * overwrites each object row with control's authoritative values and changes
 * nothing else. The sweep NEVER deletes: a policy deleted on control but whose
 * delete-shadow failed for one object leaves a stale object row this route will
 * not remove (that heals on the next edit of that scope, or a targeted delete) —
 * it is a backfill, not a reconciler, and it says so in the residual report.
 *
 * ## The fences (fail CLOSED)
 *
 *  1. **platform operator only** — this path is out-of-contract, so `contractAuth`
 *     passes it through unauthenticated; the handler re-authenticates and requires
 *     `platformOperator === true`, exactly as `tenant-consumption-purge` does.
 *  2. **`acknowledge` must be the literal `BACKFILL_QUOTA_POLICIES`** — no bare
 *     call sweeps; the operator spells out the intent. (Distinct from the purge /
 *     teardown literals so a mis-pasted body cannot cross routes.)
 *  3. **control database present** — it is the READ source; a null control
 *     database is `503`, never a silent empty sweep.
 *
 * There is no keep-tenant fence and no per-tenant `status=deleted` fence: this is
 * an ADDITIVE, fleet-wide copy, not a tenant-targeted destruction. Writing the
 * keep tenant's OWN policy into its OWN object is the correct outcome, not one to
 * refuse. `dry_run: true` computes the plan (per-owner counts and residuals)
 * without writing, so an operator can see what a run would touch first.
 */
import type { Hono } from "hono";
import { extractApiKey, MISSING_API_KEY_MESSAGE, resolveOrThrow } from "../middleware/auth.js";
import { HttpError } from "../middleware/errors.js";
import type { ControlPlaneDeps, ControlPlaneEnv } from "../ports.js";
import { QUOTA_SCOPE_KINDS, type QuotaScopeKind, quotaPolicyTenantId } from "./quota_policy.js";

/** The mounted path. Out-of-contract, like `/health` and the purge route. */
export const QUOTA_POLICY_BACKFILL_PATH = "/admin/v1/quota-policy-backfill";

/** The literal a caller must send in `acknowledge` for the sweep to run. */
const ACKNOWLEDGEMENT = "BACKFILL_QUOTA_POLICIES";

interface BackfillBody {
  readonly acknowledge: string;
  readonly dry_run: boolean;
}

/** Parse and shape-check the request body. Any deviation is a 400. */
async function readBackfillBody(c: {
  req: { json: () => Promise<unknown> };
}): Promise<BackfillBody> {
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
  if (typeof body.acknowledge !== "string") {
    throw new HttpError(400, "invalid_request_body", "acknowledge is required");
  }
  if (body.dry_run !== undefined && typeof body.dry_run !== "boolean") {
    throw new HttpError(400, "invalid_request_body", "dry_run must be a boolean");
  }
  return { acknowledge: body.acknowledge, dry_run: body.dry_run === true };
}

/** The `quota_policies` columns this object actually has (schema-version safe). */
async function objectPolicyColumns(db: D1Database): Promise<Set<string>> {
  const rows = await db
    .prepare("SELECT name FROM pragma_table_info('quota_policies')")
    .all<{ name: string }>();
  return new Set((rows.results ?? []).map((r) => r.name));
}

/**
 * The `INSERT … ON CONFLICT (id) DO UPDATE` that copies one row verbatim. Every
 * column but the `id` conflict key is refreshed from `excluded`, so a re-run
 * overwrites an existing object row with control's authoritative values.
 */
function upsertSql(columns: readonly string[]): string {
  const placeholders = columns.map(() => "?").join(", ");
  const updates = columns
    .filter((column) => column !== "id")
    .map((column) => `${column} = excluded.${column}`)
    .join(", ");
  return `INSERT INTO quota_policies (${columns.join(", ")}) VALUES (${placeholders})
          ON CONFLICT (id) DO UPDATE SET ${updates}`;
}

/** A control row whose owner could not be resolved, reported not swept. */
interface Residual {
  readonly id: string;
  readonly scope_type: string;
  readonly scope_id: string;
  readonly reason: "unknown_scope" | "unresolved_owner";
}

/**
 * Mount the backfill route OUTSIDE the contract registry (like `/health` and the
 * purge/teardown routes). Returns the path so the composition root can assert on
 * what it wired, keeping `wiring.test.ts`'s non-contract mount list honest.
 */
export function mountQuotaPolicyBackfill(app: Hono<ControlPlaneEnv>): string {
  app.post(QUOTA_POLICY_BACKFILL_PATH, async (c) => {
    const deps: ControlPlaneDeps = c.get("deps");

    // --- fence 1: platform operator only -----------------------------------
    const presentedKey = extractApiKey(c.req.raw.headers);
    if (presentedKey === null) {
      throw new HttpError(401, "missing_api_key", MISSING_API_KEY_MESSAGE);
    }
    const auth = resolveOrThrow(await deps.apiKeys.authenticate(presentedKey));
    if (auth.platformOperator !== true) {
      throw new HttpError(
        403,
        "platform_operator_required",
        "quota-policy-backfill is restricted to platform operators",
      );
    }

    const body = await readBackfillBody(c);

    // --- fence 2: explicit acknowledgement ---------------------------------
    if (body.acknowledge !== ACKNOWLEDGEMENT) {
      throw new HttpError(
        400,
        "acknowledge_required",
        `acknowledge must be the literal "${ACKNOWLEDGEMENT}"`,
      );
    }

    // --- fence 3: control database is the READ source (fail closed) --------
    if (deps.controlDatabase === null) {
      throw new HttpError(
        503,
        "control_unavailable",
        "control database is unavailable; cannot read the quota policies to backfill",
      );
    }

    // Read every typed enforcement row exactly as it stands on control today.
    const sourceRows = (
      await deps.controlDatabase
        .prepare("SELECT * FROM quota_policies")
        .all<Record<string, unknown>>()
    ).results;

    // Group the rows by the tenant object that owns them, resolving each owner
    // with the SAME rule the live writer uses. An unresolvable owner is reported,
    // never guessed and never allowed to fail the whole sweep.
    const rowsByTenant = new Map<string, Record<string, unknown>[]>();
    const residuals: Residual[] = [];
    for (const row of sourceRows) {
      const scopeType = String(row.scope_type ?? "");
      const scopeId = String(row.scope_id ?? "");
      const id = String(row.id ?? `${scopeType}:${scopeId}`);
      if (!(QUOTA_SCOPE_KINDS as readonly string[]).includes(scopeType)) {
        residuals.push({ id, scope_type: scopeType, scope_id: scopeId, reason: "unknown_scope" });
        continue;
      }
      let tenantId: string;
      try {
        tenantId = await quotaPolicyTenantId(deps, scopeType as QuotaScopeKind, scopeId, row);
      } catch {
        residuals.push({
          id,
          scope_type: scopeType,
          scope_id: scopeId,
          reason: "unresolved_owner",
        });
        continue;
      }
      const bucket = rowsByTenant.get(tenantId);
      if (bucket === undefined) rowsByTenant.set(tenantId, [row]);
      else bucket.push(row);
    }

    // Only write to tenants that already have a provisioned Durable Object — an
    // object that does not exist yet has no table to backfill (the writer's
    // shadow skips it too, and it self-heals when the object is provisioned and
    // the policy next edited).
    const provisioned = new Set(await deps.tenantDatabases.provisionedTenants());

    const written: Record<string, number> = {};
    const errors: Record<string, string> = {};
    let skippedUnprovisioned = 0;
    let skippedNonDurable = 0;
    let total = 0;

    for (const [tenantId, rows] of rowsByTenant) {
      if (!provisioned.has(tenantId)) {
        skippedUnprovisioned += rows.length;
        continue;
      }
      let handle: Awaited<ReturnType<typeof deps.tenantDatabases.forTenant>>;
      try {
        handle = await deps.tenantDatabases.forTenant(tenantId);
      } catch (error) {
        errors[tenantId] = error instanceof Error ? error.message : String(error);
        continue;
      }
      if (handle.source !== "durable_object") {
        skippedNonDurable += rows.length;
        continue;
      }

      // Copy only columns the object's table actually has (schema-version safe),
      // intersected with what the control row carries. The two schemas are
      // byte-identical by construction, so this is the full set in practice.
      const firstRow = rows[0];
      if (firstRow === undefined) continue; // unreachable: buckets are never empty
      const objectColumns = await objectPolicyColumns(handle.db);
      const copyColumns = Object.keys(firstRow).filter((column) => objectColumns.has(column));
      if (copyColumns.length === 0) {
        errors[tenantId] = "tenant object has no matching quota_policies columns";
        continue;
      }

      if (body.dry_run) {
        written[tenantId] = rows.length;
        total += rows.length;
        continue;
      }

      const sql = upsertSql(copyColumns);
      let count = 0;
      for (const row of rows) {
        try {
          await handle.db
            .prepare(sql)
            .bind(...copyColumns.map((column) => row[column] ?? null))
            .run();
          count += 1;
        } catch (error) {
          const rowId = String(row.id ?? "");
          errors[`${tenantId}:${rowId}`] = error instanceof Error ? error.message : String(error);
        }
      }
      written[tenantId] = count;
      total += count;
    }

    return c.json({
      acknowledged: true,
      dry_run: body.dry_run,
      source_rows: sourceRows.length,
      written,
      total,
      skipped: {
        unprovisioned: skippedUnprovisioned,
        non_durable_object: skippedNonDurable,
      },
      ...(residuals.length > 0 ? { residuals } : {}),
      ...(Object.keys(errors).length > 0 ? { errors } : {}),
    });
  });

  return QUOTA_POLICY_BACKFILL_PATH;
}
