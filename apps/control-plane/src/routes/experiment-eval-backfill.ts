/**
 * `POST /admin/v1/experiment-eval-backfill` — a platform-operator-only, GATED,
 * resumable sweep that copies every `experiment_shadow_legs` and
 * `online_eval_scores` PROJECTION row from the CONTROL database into the same
 * table of the tenant object that owns it.
 *
 * ## Why this route exists — the same ordering keystone as quota-policy-backfill
 *
 * The experiment/eval relocation off the control database (part of the
 * control-D1 removal / Track A red line) makes each tenant's own object the
 * authority for its shadow legs and eval scores. The gateway already
 * DUAL-WRITES every new row there — `experiments/sink.ts::writeShadowLeg` and
 * `evals/consumer.ts::writeTenantOnlineEvalScores` — but that closes the gap
 * only for rows produced AFTER the dual-write shipped. The historical rows that
 * predate it sit ONLY in the control projection. This route copies those into
 * the owning objects, so a reader pointed at an object never meets an empty
 * table for traffic that really happened. "Provisioning precedes traffic",
 * applied to the rows — exactly what `quota-policy-backfill.ts` does for
 * `quota_policies`.
 *
 * ## Why a straight column COPY
 *
 * The control projection tables are byte-identical to the tenant tables save for
 * one extra leading `projection_key` column (`sql/d1-ts/control/0018_*` rebuilt
 * both to `projection_key TEXT PRIMARY KEY`; the tenant twins in
 * `sql/d1-ts/tenant/0018_usage_evaluation_audit.sql` carry the natural keys
 * `leg_id` and `(request_id, criterion_id)`). So a verbatim column copy —
 * intersecting the control row's keys with the object's `pragma_table_info`,
 * which drops `projection_key` automatically — reproduces every value, and the
 * upsert lands it under the natural primary key the tenant table already has.
 *
 * ## Why the OWNER needs no resolution (unlike quota)
 *
 * Both tables carry a literal `tenant TEXT NOT NULL` column on BOTH the control
 * projection and the tenant table. The owner is simply `String(row.tenant)` —
 * no scope decode, no JOIN, no `projection_key` parsing. A row whose `tenant` is
 * empty is reported as a residual, never guessed.
 *
 * ## Why it PAGES and returns a cursor (unlike quota)
 *
 * `quota_policies` is one typed row per scope — small enough to sweep whole in
 * one request. These are PER-REQUEST evidence tables and can be large, and every
 * write to a tenant object is a SUBREQUEST (bounded per HTTP request by the
 * platform), so a whole-table drain in one call would blow that ceiling. Instead
 * this route copies ONE `projection_key`-ordered page per call (the control
 * PRIMARY KEY, so the scan is index-aligned and totally ordered) and returns each
 * table's `next_cursor` — the last `projection_key` it read when the page came
 * back full. The operator threads that back on the next call until every table
 * reports `next_cursor: null`. The cursor is stateless: it is returned to the
 * caller, never written to any control table, so this route mirrors NO tenant
 * data back into the shared control store — the red line it exists to help retire.
 *
 * ## Idempotent, additive, safe to re-run
 *
 * Every write is `INSERT … ON CONFLICT (<natural key>) DO UPDATE`, so a re-run
 * (or a redelivered page) overwrites each object row with control's values and
 * changes nothing else. The sweep NEVER deletes — it is a backfill, not a
 * reconciler.
 *
 * ## The fences (fail CLOSED)
 *
 *  1. **platform operator only** — out-of-contract, so the handler
 *     re-authenticates and requires `platformOperator === true`.
 *  2. **`acknowledge` must be the literal `BACKFILL_EXPERIMENT_EVAL`** — distinct
 *     from every other operator literal so a mis-pasted body cannot cross routes.
 *  3. **gated `CONTROL_EXPERIMENT_EVAL_BACKFILL === "on"`** — DEFAULT OFF. Copying
 *     historical rows into tenant objects is a one-time production operation an
 *     operator opts into at deploy time, exactly like `GATEWAY_PLATFORM_BILLING_BACKFILL`.
 *  4. **control database present** — it is the READ source; a null control
 *     database is `503`, never a silent empty sweep.
 */
import type { Hono } from "hono";
import { extractApiKey, MISSING_API_KEY_MESSAGE, resolveOrThrow } from "../middleware/auth.js";
import { HttpError } from "../middleware/errors.js";
import type { ControlPlaneDeps, ControlPlaneEnv } from "../ports.js";

/** The mounted path. Out-of-contract, like `/health` and the quota backfill. */
export const EXPERIMENT_EVAL_BACKFILL_PATH = "/admin/v1/experiment-eval-backfill";

/** The literal a caller must send in `acknowledge` for the sweep to run. */
const ACKNOWLEDGEMENT = "BACKFILL_EXPERIMENT_EVAL";

/**
 * The env var that arms the sweep. DEFAULT OFF (`wrangler.toml` commits `"off"`);
 * only exactly `"on"` runs it. Named here so tests and operators share one spelling.
 */
export const EXPERIMENT_EVAL_BACKFILL_FLAG = "CONTROL_EXPERIMENT_EVAL_BACKFILL";

/**
 * Rows copied per call, per table. One page per call keeps the tenant-object
 * writes (each a SUBREQUEST) well under the per-request ceiling; the operator
 * threads `next_cursor` back to cover a large table across many calls. The
 * default is modest because BOTH tables run in one call; `page_size` in the body
 * lets an operator tune it, clamped to {@link MAX_PAGE_SIZE}.
 */
const DEFAULT_PAGE_SIZE = 200;
const MAX_PAGE_SIZE = 1000;

/** The control PRIMARY KEY that orders every page — control-only, dropped on copy. */
const CURSOR_COLUMN = "projection_key";

/**
 * The two projection families this route relocates. `conflictKeys` is the
 * NATURAL primary key of the tenant table (NOT `projection_key`, which lives only
 * on the control side and is filtered out by the `pragma_table_info` intersect).
 */
interface TableSpec {
  readonly table: string;
  readonly conflictKeys: readonly string[];
}

const TABLES: readonly TableSpec[] = [
  { table: "experiment_shadow_legs", conflictKeys: ["leg_id"] },
  { table: "online_eval_scores", conflictKeys: ["request_id", "criterion_id"] },
];

const TABLE_NAMES: ReadonlySet<string> = new Set(TABLES.map((spec) => spec.table));

interface BackfillBody {
  readonly acknowledge: string;
  readonly dry_run: boolean;
  readonly page_size: number;
  readonly cursor: Readonly<Record<string, string>>;
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
  let pageSize = DEFAULT_PAGE_SIZE;
  if (body.page_size !== undefined) {
    if (
      typeof body.page_size !== "number" ||
      !Number.isInteger(body.page_size) ||
      body.page_size < 1
    ) {
      throw new HttpError(400, "invalid_request_body", "page_size must be a positive integer");
    }
    pageSize = Math.min(body.page_size, MAX_PAGE_SIZE);
  }
  const cursor: Record<string, string> = {};
  if (body.cursor !== undefined) {
    if (typeof body.cursor !== "object" || body.cursor === null) {
      throw new HttpError(400, "invalid_request_body", "cursor must be an object");
    }
    for (const [key, value] of Object.entries(body.cursor as Record<string, unknown>)) {
      if (!TABLE_NAMES.has(key)) {
        throw new HttpError(400, "invalid_request_body", `cursor.${key} is not a backfilled table`);
      }
      if (typeof value !== "string") {
        throw new HttpError(400, "invalid_request_body", `cursor.${key} must be a string`);
      }
      cursor[key] = value;
    }
  }
  return { acknowledge: body.acknowledge, dry_run: body.dry_run === true, page_size: pageSize, cursor };
}

/** The columns a tenant object's copy of `table` actually has (schema-version safe). */
async function objectColumns(db: D1Database, table: string): Promise<Set<string>> {
  const rows = await db
    .prepare("SELECT name FROM pragma_table_info(?)")
    .bind(table)
    .all<{ name: string }>();
  return new Set((rows.results ?? []).map((r) => r.name));
}

/**
 * The `INSERT … ON CONFLICT (<naturalKey>) DO UPDATE` that copies one row
 * verbatim. Every column but the conflict keys is refreshed from `excluded`, so a
 * re-run overwrites an existing object row with control's authoritative values.
 */
function upsertSql(
  table: string,
  columns: readonly string[],
  conflictKeys: readonly string[],
): string {
  const placeholders = columns.map(() => "?").join(", ");
  const conflict = new Set(conflictKeys);
  const updates = columns
    .filter((column) => !conflict.has(column))
    .map((column) => `${column} = excluded.${column}`)
    .join(", ");
  const action = updates.length > 0 ? `DO UPDATE SET ${updates}` : "DO NOTHING";
  return `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${placeholders})
          ON CONFLICT (${conflictKeys.join(", ")}) ${action}`;
}

interface TableResult {
  readonly source_rows: number;
  readonly written: number;
  readonly next_cursor: string | null;
  readonly skipped: { unprovisioned: number; non_durable_object: number };
  readonly residuals: number;
  readonly errors: Record<string, string>;
}

/**
 * Copy ONE page of `spec.table`'s control projection into the owning objects,
 * starting after `startCursor` (a `projection_key`). Returns the last
 * `projection_key` in the page as `next_cursor` when the page came back FULL
 * (more may remain), or `null` when the table is exhausted.
 */
async function backfillTable(
  control: D1Database,
  deps: ControlPlaneDeps,
  spec: TableSpec,
  startCursor: string | undefined,
  pageSize: number,
  dryRun: boolean,
): Promise<TableResult> {
  const statement =
    startCursor === undefined
      ? control
          .prepare(`SELECT * FROM ${spec.table} ORDER BY ${CURSOR_COLUMN} ASC LIMIT ?`)
          .bind(pageSize)
      : control
          .prepare(
            `SELECT * FROM ${spec.table} WHERE ${CURSOR_COLUMN} > ? ` +
              `ORDER BY ${CURSOR_COLUMN} ASC LIMIT ?`,
          )
          .bind(startCursor, pageSize);
  const rows = (await statement.all<Record<string, unknown>>()).results;

  const errors: Record<string, string> = {};
  let written = 0;
  let skippedUnprovisioned = 0;
  let skippedNonDurable = 0;
  let residuals = 0;

  if (rows.length === 0) {
    return {
      source_rows: 0,
      written: 0,
      next_cursor: null,
      skipped: { unprovisioned: 0, non_durable_object: 0 },
      residuals: 0,
      errors,
    };
  }

  const rowsByTenant = new Map<string, Record<string, unknown>[]>();
  for (const row of rows) {
    const tenantId = String(row.tenant ?? "").trim();
    if (tenantId === "") {
      residuals += 1;
      continue;
    }
    const bucket = rowsByTenant.get(tenantId);
    if (bucket === undefined) rowsByTenant.set(tenantId, [row]);
    else bucket.push(row);
  }

  const provisioned = new Set(await deps.tenantDatabases.provisionedTenants());

  for (const [tenantId, tenantRows] of rowsByTenant) {
    if (!provisioned.has(tenantId)) {
      skippedUnprovisioned += tenantRows.length;
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
      skippedNonDurable += tenantRows.length;
      continue;
    }

    const firstRow = tenantRows[0];
    if (firstRow === undefined) continue; // unreachable: buckets are never empty
    const objectCols = await objectColumns(handle.db, spec.table);
    const copyColumns = Object.keys(firstRow).filter((column) => objectCols.has(column));
    if (copyColumns.length === 0) {
      errors[tenantId] = `tenant object has no matching ${spec.table} columns`;
      continue;
    }

    if (dryRun) {
      written += tenantRows.length;
      continue;
    }

    const sql = upsertSql(spec.table, copyColumns, spec.conflictKeys);
    for (const row of tenantRows) {
      try {
        await handle.db
          .prepare(sql)
          .bind(...copyColumns.map((column) => row[column] ?? null))
          .run();
        written += 1;
      } catch (error) {
        const rowKey = String(row[CURSOR_COLUMN] ?? "");
        errors[`${tenantId}:${rowKey}`] = error instanceof Error ? error.message : String(error);
      }
    }
  }

  const last = rows[rows.length - 1];
  const nextCursor =
    rows.length === pageSize && last !== undefined ? String(last[CURSOR_COLUMN]) : null;

  return {
    source_rows: rows.length,
    written,
    next_cursor: nextCursor,
    skipped: { unprovisioned: skippedUnprovisioned, non_durable_object: skippedNonDurable },
    residuals,
    errors,
  };
}

/**
 * Mount the backfill route OUTSIDE the contract registry (like `/health` and the
 * quota backfill). Returns the path so the composition root can assert on what
 * it wired, keeping `wiring.test.ts`'s non-contract mount list honest.
 */
export function mountExperimentEvalBackfill(app: Hono<ControlPlaneEnv>): string {
  app.post(EXPERIMENT_EVAL_BACKFILL_PATH, async (c) => {
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
        "experiment-eval-backfill is restricted to platform operators",
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

    // --- fence 3: the sweep is armed (DEFAULT OFF) -------------------------
    if (c.env.CONTROL_EXPERIMENT_EVAL_BACKFILL !== "on") {
      throw new HttpError(
        409,
        "backfill_disabled",
        `experiment-eval-backfill is disabled; deploy with ${EXPERIMENT_EVAL_BACKFILL_FLAG}="on" to arm it`,
      );
    }

    // --- fence 4: control database is the READ source (fail closed) --------
    const control = deps.controlDatabase;
    if (control === null) {
      throw new HttpError(
        503,
        "control_unavailable",
        "control database is unavailable; cannot read the projections to backfill",
      );
    }

    const perTable: Record<string, TableResult> = {};
    for (const spec of TABLES) {
      const start = body.cursor[spec.table];
      perTable[spec.table] = await backfillTable(
        control,
        deps,
        spec,
        start === "" || start === undefined ? undefined : start,
        body.page_size,
        body.dry_run,
      );
    }

    return c.json({
      acknowledged: true,
      dry_run: body.dry_run,
      page_size: body.page_size,
      per_table: perTable,
    });
  });

  return EXPERIMENT_EVAL_BACKFILL_PATH;
}
