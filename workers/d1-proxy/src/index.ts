// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: FerroGate d1-proxy Worker (issue #450). A bearer-authenticated HTTP front over a
//   NATIVE D1 binding (env.DB). The D1 REST HTTP query API has no multi-statement-with-params
//   transaction and no `RETURNING`, so the atomic-transition control-plane families (wallets,
//   payments, workflow budgets, append_billing_event_with_outbox_enqueue, guardrail CAS) cannot
//   be served over REST. This Worker holds the D1 binding and exposes exactly the two primitives
//   REST lacks: an ATOMIC `env.DB.batch([...])` and a single `prepare().bind().all()` — both with
//   `RETURNING` support — for the Rust `D1ControlPlaneStore` atomic hot path. REST (the landed
//   `D1Client`) stays the transport for the non-atomic/admin surface (see
//   docs/cloudflare-d1-backend.md §"proxy-Worker D1 binding").

import { json, requireBearer } from "./auth";

/**
 * Worker bindings.
 *
 * `DB` is the NATIVE D1 binding this Worker fronts — bound in wrangler.toml to
 * the FerroGate CONTROL database (the account-global atomic families — billing
 * metering + outbox, guardrail-binding CAS — all route to the control database,
 * exactly like the #447/#449 REST families).
 *
 * PER-TENANT bindings (issue #455): the database-per-tenant topology places a
 * tenant's financial state (wallets/reservations) in that tenant's OWN D1
 * database. The Workers runtime can ONLY reach a D1 database through a
 * statically-declared binding (there is no runtime "open database by id" API —
 * verified against `@cloudflare/workers-types`' `D1Database` and the D1 Worker
 * API docs), so each tenant database is bound here under its own name (by
 * convention `TENANT_DB_<TENANT_ID>`, `-` folded to `_`, uppercased) and a
 * request selects it by NAME via the optional `database` field
 * (see [`resolveDatabase`]). Onboarding a tenant therefore requires adding its
 * `[[d1_databases]]` binding to wrangler.toml and redeploying — the same
 * per-binding, redeploy-to-onboard reality the #423 Secrets-Store bindings have.
 * A request with no `database` (or `database == "DB"`) targets the control
 * database, so the #450 control-DB path is unchanged.
 *
 * `D1_PROXY_TOKEN` is the DIY bearer credential FerroGate presents (seeded via
 * `wrangler secret put D1_PROXY_TOKEN`; the Rust side resolves the same secret
 * through the #405/#417 credential seam).
 *
 * The index signature carries the per-tenant `TENANT_DB_*` D1 bindings, which
 * vary per deployment and so cannot be named statically here; [`resolveDatabase`]
 * duck-types each resolved value back to a `D1Database` before use, so a request
 * can never coerce a non-D1 binding (e.g. the `D1_PROXY_TOKEN` string) into a
 * database handle.
 */
export interface Env {
  /** Native D1 binding (the control database). Runs prepare/bind/batch/RETURNING. */
  DB: D1Database;
  /** DIY auth secret. Compared (constant-time) against the request bearer token. */
  D1_PROXY_TOKEN: string;
  /** Per-tenant `TENANT_DB_*` D1 bindings + any other deployment-specific binding. */
  [binding: string]: D1Database | string | undefined;
}

/** The binding name of the control database (the #450 default target). */
const CONTROL_DATABASE_BINDING = "DB";

/**
 * Resolve the request's target D1 binding to a native `D1Database`, or return a
 * rejection string (fail-closed 400) when the named binding is unknown or is not
 * a D1 database.
 *
 * An omitted/empty `database`, or the literal control binding name, targets
 * `env.DB` — keeping the #450 control-DB path byte-for-byte unchanged. Any other
 * value names a per-tenant `[[d1_databases]]` binding (there is no runtime
 * select-by-id API; a database is reachable only through a declared binding).
 * The resolved value is duck-typed back to a `D1Database` so a caller cannot
 * name a non-database binding (e.g. `D1_PROXY_TOKEN`) and have it used as one.
 */
function resolveDatabase(env: Env, database: unknown): D1Database | string {
  if (database === undefined || database === null || database === "") {
    return env.DB;
  }
  if (typeof database !== "string") {
    return "`database` must be a string binding name";
  }
  if (database === CONTROL_DATABASE_BINDING) {
    return env.DB;
  }
  const candidate = env[database];
  if (!isD1Database(candidate)) {
    return `unknown D1 database binding ${JSON.stringify(database)} \
(add its [[d1_databases]] binding to the Worker and redeploy)`;
  }
  return candidate;
}

/** Structural check that `value` is a native `D1Database` binding. */
function isD1Database(value: unknown): value is D1Database {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as D1Database).prepare === "function" &&
    typeof (value as D1Database).batch === "function"
  );
}

/**
 * A SQL bind value accepted over the wire. The Rust client sends every param as
 * a decimal/`"1"`/`"0"`/empty-for-NULL STRING (the documented D1 all-strings
 * contract SQLite column affinity converts on insert), but numbers/booleans/null
 * are accepted too so a future non-Rust caller is not boxed in.
 */
type SqlBinding = string | number | boolean | null;

/** One statement in a request: `sql` with positional `?` placeholders + `params`. */
interface ProxyStatement {
  sql: string;
  params?: SqlBinding[];
}

/** Request body of `POST /d1/batch`. */
interface BatchRequestBody {
  /** Target D1 binding name (issue #455); omitted/`"DB"` = control database. */
  database?: unknown;
  statements?: unknown;
}

/**
 * Request body of `POST /d1/query`: the single statement (`sql` + `params`),
 * plus the optional `database` binding selector (issue #455). `prepareStatement`
 * ignores the extra `database` field, so the control-DB body shape is unchanged.
 */
interface QueryRequestBody {
  database?: unknown;
}

// D1 documented limits this Worker guards up front (a 400 is cheaper than a
// binding round-trip that will fail anyway): <=100 bound params/statement, and
// a defensive cap on statements/batch (a batch is a single atomic unit).
const MAX_PARAMS_PER_STATEMENT = 100;
const MAX_STATEMENTS_PER_BATCH = 100;

/** Cloudflare-style success envelope, so the Rust `CloudflareEnvelope` decodes it verbatim. */
function okEnvelope(result: unknown): Response {
  return json({ success: true, errors: [], messages: [], result }, 200);
}

/**
 * Cloudflare-style error envelope. The Rust client maps `{ code, message }` +
 * HTTP status through the SAME `CloudflareError::from_response` path the REST
 * client uses, so proxy failures surface identically to REST failures.
 */
function errEnvelope(code: number, message: string, status: number): Response {
  return json({ success: false, errors: [{ code, message }], messages: [], result: null }, status);
}

/** True when `value` is an acceptable single SQL bind value. */
function isSqlBinding(value: unknown): value is SqlBinding {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  );
}

/**
 * Validate + normalize one statement descriptor from an untrusted body into a
 * bound `D1PreparedStatement`. Returns a string on rejection (fail-closed 400).
 */
function prepareStatement(db: D1Database, raw: unknown): D1PreparedStatement | string {
  if (typeof raw !== "object" || raw === null) {
    return "each statement must be an object { sql, params? }";
  }
  const statement = raw as ProxyStatement;
  if (typeof statement.sql !== "string" || statement.sql.length === 0) {
    return "statement.sql must be a non-empty string";
  }
  const params = statement.params ?? [];
  if (!Array.isArray(params) || !params.every(isSqlBinding)) {
    return "statement.params must be an array of string|number|boolean|null";
  }
  if (params.length > MAX_PARAMS_PER_STATEMENT) {
    return `statement binds ${params.length} params; D1 allows at most ${MAX_PARAMS_PER_STATEMENT}`;
  }
  // `bind(...[])` is a no-op that returns the same statement, so a
  // parameterless statement passes through unchanged.
  return db.prepare(statement.sql).bind(...params);
}

/**
 * `POST /d1/batch` — run an ATOMIC multi-statement batch.
 *
 * `env.DB.batch([...])` wraps every statement in a single implicit transaction:
 * if ANY statement fails the WHOLE batch rolls back (the exact guarantee the
 * REST HTTP query API cannot give — that is the reason this Worker exists). Each
 * statement's `results` array carries its `RETURNING` rows, so a 2-table atomic
 * write (metering event + outbox enqueue) commits together and reports which
 * rows it produced.
 */
async function handleBatch(request: Request, env: Env): Promise<Response> {
  let body: BatchRequestBody;
  try {
    body = (await request.json()) as BatchRequestBody;
  } catch {
    return errEnvelope(400, "invalid JSON body", 400);
  }
  // Select the target database (tenant binding or the control default) BEFORE
  // preparing statements: a batch is one atomic unit against ONE database.
  const db = resolveDatabase(env, body.database);
  if (typeof db === "string") {
    return errEnvelope(400, db, 400);
  }
  const rawStatements = body.statements;
  if (!Array.isArray(rawStatements) || rawStatements.length === 0) {
    return errEnvelope(400, "batch requires a non-empty `statements` array", 400);
  }
  if (rawStatements.length > MAX_STATEMENTS_PER_BATCH) {
    return errEnvelope(
      400,
      `batch has ${rawStatements.length} statements; the cap is ${MAX_STATEMENTS_PER_BATCH}`,
      400,
    );
  }
  const prepared: D1PreparedStatement[] = [];
  for (const raw of rawStatements) {
    const stmt = prepareStatement(db, raw);
    if (typeof stmt === "string") {
      return errEnvelope(400, stmt, 400);
    }
    prepared.push(stmt);
  }
  try {
    // The atomic unit: all-or-nothing. Returns one D1Result per statement.
    const results = await db.batch(prepared);
    return okEnvelope(results.map(serializeResult));
  } catch (err) {
    // A failed statement rolled the WHOLE batch back — nothing was committed.
    // Code 5001 = D1 execution failure. Deliberately NOT a Cloudflare auth /
    // scope / rate-limit code (1000/9103/9107/9109/9106/10000/10013), so the
    // Rust client maps it to a plain API error, not a misclassified auth failure.
    return errEnvelope(5001, `d1 batch failed (rolled back): ${errorMessage(err)}`, 502);
  }
}

/**
 * `POST /d1/query` — run ONE `prepare().bind(...).all()` statement, `RETURNING`
 * included. This is the single-statement companion to `/d1/batch` for atomic
 * ops whose CAS is expressible as one `UPDATE ... RETURNING` / `INSERT ...
 * RETURNING` (the compare-and-swap the REST API cannot express).
 */
async function handleQuery(request: Request, env: Env): Promise<Response> {
  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return errEnvelope(400, "invalid JSON body", 400);
  }
  // The optional `database` selector rides alongside the statement fields;
  // `prepareStatement` reads only `sql`/`params`, so it ignores it.
  const db = resolveDatabase(env, (raw as QueryRequestBody | null)?.database);
  if (typeof db === "string") {
    return errEnvelope(400, db, 400);
  }
  const stmt = prepareStatement(db, raw);
  if (typeof stmt === "string") {
    return errEnvelope(400, stmt, 400);
  }
  try {
    const result = await stmt.all();
    return okEnvelope(serializeResult(result));
  } catch (err) {
    // Code 5001 = D1 execution failure (see handleBatch for the code rationale).
    return errEnvelope(5001, `d1 query failed: ${errorMessage(err)}`, 502);
  }
}

/**
 * Reshape a native `D1Result` into the wire shape the Rust `D1QueryResult`
 * decodes (`{ results, success, meta }`) — the SAME shape the REST query
 * endpoint returns per statement, so the Rust side reuses one decoder for both
 * transports.
 */
function serializeResult(result: D1Result): { results: unknown[]; success: boolean; meta: unknown } {
  return {
    results: result.results ?? [],
    success: result.success,
    meta: result.meta,
  };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Unauthenticated liveness probe (exposes no secret, touches no data).
    if (url.pathname === "/healthz") {
      return json({ ok: true, worker: "ferrogate-d1-proxy" });
    }

    // Every data route is POST-only and bearer-gated (fail-closed).
    const denied = requireBearer(request, env.D1_PROXY_TOKEN);
    if (denied) return denied;
    if (request.method !== "POST") {
      return errEnvelope(405, "d1 routes are POST-only", 405);
    }

    switch (url.pathname) {
      case "/d1/batch":
        return handleBatch(request, env);
      case "/d1/query":
        return handleQuery(request, env);
      default:
        return errEnvelope(404, `unknown route: ${url.pathname}`, 404);
    }
  },
} satisfies ExportedHandler<Env>;
