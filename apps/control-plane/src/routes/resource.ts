/**
 * The generic, contract-driven resource machinery.
 *
 * 214 operations, and roughly 170 of them are the SAME six shapes over ~60
 * named collections:
 *
 * ```
 *   GET    /admin/v1/{collection}          → list
 *   POST   /admin/v1/{collection}          → create   (201)
 *   GET    /admin/v1/{collection}/{id}     → read     (404 when absent)
 *   PUT    /admin/v1/{collection}/{id}     → replace  (200)
 *   PATCH  /admin/v1/{collection}/{id}     → merge    (200)
 *   DELETE /admin/v1/{collection}/{id}     → delete   (200, AdminDeleteResponse)
 * ```
 *
 * Hand-writing those 170 handlers is how a port drifts: one of them forgets the
 * tenant check, one answers 200 where Rust answers 201, one returns a bare array
 * instead of the `AdminList` envelope. So the shape is derived from the
 * contract path template and implemented ONCE here. A group module declares its
 * collections (name, response object, Zod body schema) and hands over explicit
 * `overrides` for the genuinely custom operations — activate, rollback,
 * run-now, verify, rotate, replay, the nested sub-collections.
 *
 * The build is fail-closed: `crudGroup` THROWS at module load if a contract
 * operation in the group matches neither a declared collection shape nor an
 * override. A new operation in the JSON therefore breaks the build rather than
 * silently 404-ing at runtime.
 *
 * Status/envelope parity is taken from
 * `crates/ferrogate-gateway/src/server/agent_schedules.rs` (the canonical admin
 * CRUD family): POST without a path id → **201 Created**, PUT/PATCH on an
 * existing id → **200 OK**, DELETE → **200** with
 * `{ object, id, deleted: true }`, list → the `AdminList` envelope.
 */
import type { Context } from "hono";
import { z } from "zod";
import { type ApiOperation, STABLE_PATH_PREFIX } from "../contract.js";
import { HttpError } from "../middleware/errors.js";
import {
  type CallerScope,
  type ControlPlaneDeps,
  type ControlPlaneEnv,
  StoreConflictError,
  type StoreRecord,
  callerScope,
} from "../ports.js";
import { adminDeleted, adminItem, listResponse, parseListQuery } from "../responses.js";

/** Every route handler in this app. */
export type Handler = (c: Context<ControlPlaneEnv>) => Promise<Response> | Response;

/** A contract group's contribution to the route table. */
export interface GroupModule {
  /** The contract `group` this module owns (must match `route_patterns`). */
  readonly group: string;
  /** Build `operationId → handler` for exactly the operations passed in. */
  build(operations: readonly ApiOperation[]): Map<string, Handler>;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

/**
 * Rust `limits().admin_body_max_bytes()`. Over the limit is
 * `413 payload_too_large`, answered before the body is parsed.
 */
export const ADMIN_BODY_MAX_BYTES = 1_048_576;

/** The caller resolved by the auth middleware, as a store scope. */
export function scopeOf(c: Context<ControlPlaneEnv>): CallerScope {
  const auth = c.get("auth");
  if (auth === null || auth === undefined) {
    // Unreachable behind `contractAuth`, which sets `auth` for every bearer
    // operation. Fail closed rather than defaulting to platform root.
    throw new HttpError(401, "invalid_api_key", "invalid API key");
  }
  return callerScope(auth);
}

export function depsOf(c: Context<ControlPlaneEnv>): ControlPlaneDeps {
  return c.get("deps");
}

/**
 * Zod-validate a JSON request body. Rust answers `400 invalid_request_body`
 * with the deserializer's own message; the Zod issue list plays that role here.
 */
export async function readJson<S extends z.ZodTypeAny>(
  c: Context<ControlPlaneEnv>,
  schema: S,
): Promise<z.infer<S>> {
  const declaredLength = c.req.header("content-length");
  if (declaredLength !== undefined) {
    const length = Number.parseInt(declaredLength, 10);
    if (Number.isSafeInteger(length) && length > ADMIN_BODY_MAX_BYTES) {
      throw new HttpError(
        413,
        "payload_too_large",
        `request body exceeds maximum size of ${ADMIN_BODY_MAX_BYTES} bytes`,
      );
    }
  }

  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    throw new HttpError(400, "invalid_request_body", "request body must be a JSON object");
  }

  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
      .join("; ");
    throw new HttpError(400, "invalid_request_body", `request body is invalid: ${detail}`);
  }
  return parsed.data;
}

/**
 * A path parameter, Zod-validated. Rust treats an empty or slash-bearing id as
 * "no such route" (`if id.is_empty() || id.contains('/') { return not_found }`),
 * so a blank segment is a 404 here too, never a 500 downstream.
 */
export const pathParamSchema = z.string().trim().min(1);

export function pathParam(c: Context<ControlPlaneEnv>, name: string): string {
  const parsed = pathParamSchema.safeParse(c.req.param(name));
  if (!parsed.success) {
    throw new HttpError(404, "not_found", `no route for ${c.req.method} ${c.req.path}`);
  }
  return parsed.data;
}

/** JSON response with the request-id headers Rust attaches to every response. */
export function json(c: Context<ControlPlaneEnv>, status: number, body: unknown): Response {
  const requestId = c.get("requestId") ?? null;
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (requestId !== null) {
    headers["x-request-id"] = requestId;
    headers["x-trace-id"] = requestId;
  }
  return new Response(JSON.stringify(body), { status, headers });
}

/** Raw (non-JSON) response — the dashboard HTML and the Prometheus exposition. */
export function raw(
  c: Context<ControlPlaneEnv>,
  status: number,
  contentType: string,
  body: string,
): Response {
  const requestId = c.get("requestId") ?? null;
  const headers: Record<string, string> = { "content-type": contentType };
  if (requestId !== null) {
    headers["x-request-id"] = requestId;
    headers["x-trace-id"] = requestId;
  }
  return new Response(body, { status, headers });
}

// ---------------------------------------------------------------------------
// Collection specification
// ---------------------------------------------------------------------------

/**
 * The permissive base body every admin resource accepts. Admin payloads are
 * open-ended configuration documents whose full shape lives in the (still
 * concurrently-written) `@ferrogate/schemas`; `passthrough()` keeps unknown
 * fields instead of silently dropping operator data, which would be a real
 * behaviour regression.
 *
 * PORT-TODO(P: inventory-edge-control §4) — KEPT, sharpened. Tightening each
 * collection to its per-resource Rust mutation struct (e.g.
 * `AdminAgentScheduleMutation`) is still the target, and it is blocked on a
 * DEPENDENCY, not on the platform: `@ferrogate/schemas` today exports only the
 * WIRE schemas (`./wire.ts` plus re-exports of `@ferrogate/core`'s tenancy,
 * tool and error types) — there is no per-admin-resource mutation schema to
 * point a collection at. Hand-writing ~60 of them here would put the authority
 * in the wrong package and guarantee two copies that drift.
 *
 * The collections that DO have an authoritative schema already use it rather
 * than this base: `routes/guardrail_policy.ts` validates stored revisions with
 * `@ferrogate/guardrails`' `checkBindingSchema` / `policyScopeSelectorSchema`,
 * and `routes/admin_config_ops.ts` validates candidate configs with
 * `@ferrogate/config`'s real loader. That is the shape the rest takes when the
 * schemas land: swap `body`/`patch` on the `CollectionSpec`, nothing else.
 *
 * Meanwhile `passthrough()` is the SAFE approximation, not the lazy one — the
 * alternative, `strict()` against a guessed shape, would reject operator fields
 * the Rust surface accepts, and `strip()` would silently discard them.
 */
export const adminRecordSchema = z
  .object({
    id: z.string().trim().min(1).optional(),
    name: z.string().trim().min(1).optional(),
    enabled: z.boolean().optional(),
    tenant_id: z.string().trim().min(1).nullish(),
  })
  .passthrough();

export type AdminRecordBody = z.infer<typeof adminRecordSchema>;

/** One CRUD collection under `/admin/v1/`. */
export interface CollectionSpec {
  /** Path segment, e.g. `agent-schedules`. */
  readonly segment: string;
  /** Singular name used in the response envelope, e.g. `agent_schedule`. */
  readonly object: string;
  /** Store collection key. Defaults to {@link CollectionSpec.segment}. */
  readonly collection?: string;
  /**
   * Body field that carries the record's identity on create. Defaults to `id`.
   * Some collections are keyed by a natural key instead (`name` for
   * `mcp-servers`/`policies`, `hostname` for `site-domains`).
   */
  readonly idField?: string;
  /** Schema for POST / PUT bodies. */
  readonly body?: z.ZodTypeAny;
  /** Schema for PATCH bodies. Defaults to {@link CollectionSpec.body}. */
  readonly patch?: z.ZodTypeAny;
  /**
   * Project the stored document into a TYPED table in the control database.
   *
   * A handful of collections are not only operator documents: another Worker
   * reads a typed row keyed off the same id and will not see the document at
   * all. `plans` and `tenant-accounts` are two — `apps/gateway`'s
   * `d1QuotaPolicySource` joins `plans` to `tenants.plan_id` on the admission
   * path of every authenticated request — and before this hook existed the
   * generic handlers wrote only the document, so those tables stayed empty on
   * every deployment and every configured limit resolved to NO limit.
   *
   * Declared on the SPEC rather than called from a bespoke override so it
   * cannot be wired on POST and forgotten on PUT/PATCH: all three legs below
   * run it, on the record the store actually committed.
   *
   * It runs only when {@link ControlPlaneDeps.controlDatabase} is bound. That
   * is not a silent fallback — `controlDatabase` is `null` exactly when
   * `CONTROL_PLANE_STORE = "memory"` or no `DB` is bound, i.e. when this
   * deployment has no control database for a typed row to live in, and the
   * document store it is running on is not durable either.
   */
  readonly project?: (db: D1Database, record: StoreRecord, nowUnix: number) => Promise<void>;
  /**
   * Provision the record's per-tenant STORAGE (#820), after {@link
   * CollectionSpec.project} has written the typed row it admits on.
   *
   * Declared for `tenant-accounts` only. A tenant's data lives in its own
   * Durable Object, addressed `idFromName(tenantId)`, and that object exists the
   * moment anything writes to it — so onboarding is not "create a database" any
   * more, it is "record that this tenant exists, and put the first rows in".
   * Nothing did either, so a tenant created here was absent from the fleet
   * roster and answered `400 model_not_found` on its first inference request.
   *
   * It is a SEPARATE hook from `project` rather than folded into it because the
   * two have different signatures for a reason: `project` gets a `D1Database`
   * and writes one control row, while provisioning needs the tenant ROUTER (it
   * writes into a different store entirely) and must run strictly AFTER the
   * typed row exists — {@link provisionTenantStorageFor} refuses a tenant with
   * no `tenants` row, and that refusal is what keeps a typo from manufacturing a
   * billable object.
   *
   * Ordered after `project` for the same reason and enforced by
   * {@link runProjection} calling them in that order, not by convention.
   */
  readonly provision?: (deps: ControlPlaneDeps, record: StoreRecord) => Promise<unknown>;
  /**
   * Remove the TYPED row {@link CollectionSpec.project} wrote, on DELETE.
   *
   * Declaring `project` without this is the defect it exists to prevent, one
   * verb over: `DELETE` answers `200 {"deleted": true}`, the document goes, the
   * typed row the other Worker reads stays, and the operator is told a change
   * took effect that did not.
   *
   * **It runs BEFORE the document is removed**, which is the opposite of
   * {@link CollectionSpec.project}'s ordering and is deliberate: for a GRANT
   * (`roles`, `tenant_role_bindings`) a residual typed row is a permission that
   * still applies, so the authority row must go first and a crash in between
   * must leave the caller with LESS access, not more. Collections whose typed
   * row is a LIMIT rather than a grant fail closed the other way and keep their
   * bespoke delete override (see `store/quota_registry.ts`).
   *
   * The tenancy fence lives in the store, so {@link deleteHandler} resolves the
   * row for the caller's scope FIRST and skips the whole path on a 404 —
   * without that, "delete the typed row before the document" would itself be an
   * unfenced cross-tenant write.
   */
  readonly unproject?: (db: D1Database, id: string, record: StoreRecord) => Promise<void>;
}

interface ResolvedSpec {
  readonly segment: string;
  readonly object: string;
  readonly collection: string;
  readonly idField: string;
  readonly body: z.ZodTypeAny;
  readonly patch: z.ZodTypeAny;
  readonly project:
    | ((db: D1Database, record: StoreRecord, nowUnix: number) => Promise<void>)
    | null;
  readonly provision: ((deps: ControlPlaneDeps, record: StoreRecord) => Promise<unknown>) | null;
  readonly unproject: ((db: D1Database, id: string, record: StoreRecord) => Promise<void>) | null;
}

function resolveSpec(spec: CollectionSpec): ResolvedSpec {
  const body = spec.body ?? adminRecordSchema;
  return {
    segment: spec.segment,
    object: spec.object,
    collection: spec.collection ?? spec.segment,
    idField: spec.idField ?? "id",
    body,
    patch: spec.patch ?? body,
    project: spec.project ?? null,
    provision: spec.provision ?? null,
    unproject: spec.unproject ?? null,
  };
}

/**
 * Run a spec's {@link CollectionSpec.project} hook for a committed record.
 *
 * AFTER the document write, deliberately: see the ordering table in
 * `store/quota_registry.ts`. A crash between the two legs then leaves a
 * configured limit that is not yet enforced (healed by the next write), never
 * an enforced limit the operator cannot see.
 */
async function runProjection(
  c: Context<ControlPlaneEnv>,
  spec: ResolvedSpec,
  record: StoreRecord,
): Promise<void> {
  const deps = depsOf(c);
  const db = deps.controlDatabase;
  if (spec.project !== null && db !== null) {
    await spec.project(db, record, Math.floor(Date.now() / 1000));
  }
  // AFTER the typed row, never before: the provisioner admits a tenant on its
  // `tenants` row, so running these in the other order would refuse every
  // freshly created tenant on its own creation. The ordering is here rather than
  // in a comment on the two hooks because this is the only place both are called.
  if (spec.provision !== null) {
    await spec.provision(deps, record);
  }
}

// ---------------------------------------------------------------------------
// The six generic handlers
// ---------------------------------------------------------------------------

export function listHandler(spec: ResolvedSpec): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
    const page = await deps.store.list(spec.collection, scopeOf(c), query);
    return json(c, 200, listResponse(page, query));
  };
}

export function createHandler(spec: ResolvedSpec): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const body = (await readJson(c, spec.body)) as Record<string, unknown>;
    const declaredId = body[spec.idField];
    const id =
      typeof declaredId === "string" && declaredId.trim() !== ""
        ? declaredId.trim()
        : crypto.randomUUID();
    const record: StoreRecord = { ...body, [spec.idField]: id, id };
    try {
      const stored = await deps.store.create(spec.collection, scopeOf(c), record);
      await runProjection(c, spec, stored);
      // Rust: POST with no path id is 201 Created.
      return json(c, 201, adminItem(spec.object, stored));
    } catch (error) {
      if (error instanceof StoreConflictError) {
        throw new HttpError(409, "conflict", `${spec.object} ${id} already exists`);
      }
      throw error;
    }
  };
}

export function readHandler(spec: ResolvedSpec, param: string): Handler {
  return async (c) => {
    const id = pathParam(c, param);
    const record = await depsOf(c).store.get(spec.collection, scopeOf(c), id);
    if (record === null) throw notFound(spec, id);
    return json(c, 200, adminItem(spec.object, record));
  };
}

export function replaceHandler(spec: ResolvedSpec, param: string): Handler {
  return async (c) => {
    const id = pathParam(c, param);
    const body = (await readJson(c, spec.body)) as Record<string, unknown>;
    const stored = await depsOf(c).store.replace(spec.collection, scopeOf(c), id, {
      ...body,
      [spec.idField]: id,
    });
    if (stored === null) throw notFound(spec, id);
    await runProjection(c, spec, stored);
    // Rust: an upsert WITH a path id is 200 OK, not 201.
    return json(c, 200, adminItem(spec.object, stored));
  };
}

export function mergeHandler(spec: ResolvedSpec, param: string): Handler {
  return async (c) => {
    const id = pathParam(c, param);
    const body = (await readJson(c, spec.patch)) as Record<string, unknown>;
    const stored = await depsOf(c).store.merge(spec.collection, scopeOf(c), id, body);
    if (stored === null) throw notFound(spec, id);
    await runProjection(c, spec, stored);
    return json(c, 200, adminItem(spec.object, stored));
  };
}

export function deleteHandler(spec: ResolvedSpec, param: string): Handler {
  return async (c) => {
    const id = pathParam(c, param);
    const deps = depsOf(c);
    const scope = scopeOf(c);

    const db = deps.controlDatabase;
    if (spec.unproject !== null && db !== null) {
      // The store is where the tenancy fence lives, so the row is resolved for
      // THIS caller's scope before its authority row is touched; a row the
      // caller cannot see is a 404 and nothing is written. Then the typed row
      // goes first — see `CollectionSpec.unproject`.
      const visible = await deps.store.get(spec.collection, scope, id);
      if (visible === null) throw notFound(spec, id);
      await spec.unproject(db, id, visible);
    }

    const removed = await deps.store.remove(spec.collection, scope, id);
    if (!removed) throw notFound(spec, id);
    return json(c, 200, adminDeleted(spec.object, id));
  };
}

/**
 * The 404 a tenant-scoped caller gets for a row that exists but belongs to
 * another tenant — indistinguishable from "no such row", which is the point:
 * a 403 here would confirm the resource's existence across the tenant boundary.
 */
function notFound(spec: ResolvedSpec, id: string): HttpError {
  return new HttpError(404, "not_found", `${spec.object} ${id} not found`);
}

// ---------------------------------------------------------------------------
// Sub-resource helpers (used by group modules for nested collections)
// ---------------------------------------------------------------------------

/**
 * A read-only sub-collection such as `/{id}/fires` or `/{id}/ledger`: scoped to
 * the parent row, 404 when the parent is not visible to the caller.
 */
export function subListHandler(options: {
  readonly parent: CollectionSpec;
  readonly parentParam: string;
  readonly collection: string;
  /** Field on the child rows that references the parent id. */
  readonly parentField: string;
}): Handler {
  const parent = resolveSpec(options.parent);
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const parentId = pathParam(c, options.parentParam);
    if ((await deps.store.get(parent.collection, scope, parentId)) === null) {
      throw notFound(parent, parentId);
    }
    const url = new URL(c.req.url);
    const query = parseListQuery(url, deps.listDefaultLimit, deps.listMaxLimit);
    const scoped = {
      ...query,
      // Force the parent filter regardless of what the client asked for.
      filters: { ...query.filters, [options.parentField]: parentId },
    };
    const page = await deps.store.list(options.collection, scope, scoped);
    return json(c, 200, listResponse(page, scoped));
  };
}

/**
 * A POST action on an existing row (`activate`, `rotate`, `run-now`, `verify`,
 * `approve`, …): loads the row for the caller's scope, applies `apply`, stores
 * the result, and answers `200 { object, <object> }`.
 */
export function actionHandler(options: {
  readonly spec: CollectionSpec;
  readonly param: string;
  /** Body schema; omit for actions Rust accepts with no body. */
  readonly body?: z.ZodTypeAny;
  readonly apply: (
    record: StoreRecord,
    body: Record<string, unknown>,
    now: number,
  ) => Record<string, unknown>;
  /**
   * Run after the merge commits, on the record the store returned.
   *
   * `enable` / `disable` / `revoke` are the actions that decide whether a
   * credential still authenticates, and the rows a data-plane authenticator
   * actually reads are NOT the document this handler wrote (see
   * `store/virtual_keys.ts`). Without this hook those three actions changed
   * only the operator's view of the key.
   *
   * Distinct from {@link CollectionSpec.project} because these writes carry a
   * DIRECTION — whether they loosen or tighten the credential — and that
   * decides which of two databases is written first.
   */
  readonly after?: (c: Context<ControlPlaneEnv>, record: StoreRecord) => Promise<void>;
}): Handler {
  const spec = resolveSpec(options.spec);
  const bodySchema = options.body ?? z.record(z.unknown()).optional();
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const id = pathParam(c, options.param);
    const existing = await deps.store.get(spec.collection, scope, id);
    if (existing === null) throw notFound(spec, id);

    // Rust reads an empty body as the default mutation for these actions, so an
    // absent body is not an error.
    const hasBody = (c.req.header("content-length") ?? "0") !== "0";
    const body = hasBody ? ((await readJson(c, bodySchema)) as Record<string, unknown>) : {};

    const patch = options.apply(existing, body, Math.floor(Date.now() / 1000));
    const stored = await deps.store.merge(spec.collection, scope, id, patch);
    if (stored === null) throw notFound(spec, id);
    if (options.after !== undefined) await options.after(c, stored);
    return json(c, 200, adminItem(spec.object, stored));
  };
}

/** A read-only listing with no mutations and no item route (reports, feeds). */
export function readOnlyCollection(segment: string, object: string): CollectionSpec {
  return { segment, object };
}

// ---------------------------------------------------------------------------
// The group builder
// ---------------------------------------------------------------------------

/** Path template shape of an operation, relative to `/admin/v1/`. */
function relativeSegments(operation: ApiOperation): string[] | null {
  if (!operation.path.startsWith(`${STABLE_PATH_PREFIX}/`)) return null;
  return operation.path.slice(STABLE_PATH_PREFIX.length + 1).split("/");
}

function paramName(segment: string): string | null {
  if (!segment.startsWith("{") || !segment.endsWith("}")) return null;
  const inner = segment.slice(1, -1);
  return inner.startsWith("*") ? null : inner;
}

/**
 * Build a group's `operationId → handler` map.
 *
 * Resolution order, per operation:
 *  1. an explicit entry in `overrides` (custom actions, nested routes, the
 *     un-versioned root paths);
 *  2. the derived CRUD shape for a declared collection;
 *  3. **throw** — an unhandled contract operation is a build failure.
 */
export function crudGroup(
  group: string,
  collections: readonly CollectionSpec[],
  overrides: Readonly<Record<string, Handler>> = {},
): GroupModule {
  const specs = new Map(collections.map((spec) => [spec.segment, resolveSpec(spec)]));

  return {
    group,
    build(operations) {
      const handlers = new Map<string, Handler>();
      for (const operation of operations) {
        const override = overrides[operation.operationId];
        if (override !== undefined) {
          handlers.set(operation.operationId, override);
          continue;
        }

        const segments = relativeSegments(operation);
        const head = segments?.[0];
        const spec = head === undefined ? undefined : specs.get(head);
        if (segments === undefined || segments === null || spec === undefined) {
          throw new Error(
            `control-plane group ${group}: operation ${operation.operationId} (${operation.method} ${operation.path}) has no handler`,
          );
        }

        const derived = deriveCrudHandler(spec, operation, segments);
        if (derived === null) {
          throw new Error(
            `control-plane group ${group}: operation ${operation.operationId} (${operation.method} ${operation.path}) is not a plain CRUD shape — add an override`,
          );
        }
        handlers.set(operation.operationId, derived);
      }

      // Every declared override must correspond to an operation in this group,
      // or the group module has drifted from the contract in the other
      // direction (a handler for an operation that no longer exists).
      const known = new Set(operations.map((operation) => operation.operationId));
      for (const operationId of Object.keys(overrides)) {
        if (!known.has(operationId)) {
          throw new Error(
            `control-plane group ${group}: override ${operationId} matches no contract operation in this group`,
          );
        }
      }
      return handlers;
    },
  };
}

function deriveCrudHandler(
  spec: ResolvedSpec,
  operation: ApiOperation,
  segments: readonly string[],
): Handler | null {
  if (segments.length === 1) {
    if (operation.method === "GET") return listHandler(spec);
    if (operation.method === "POST") return createHandler(spec);
    return null;
  }
  if (segments.length === 2) {
    const param = paramName(segments[1] ?? "");
    if (param === null) return null;
    switch (operation.method) {
      case "GET":
        return readHandler(spec, param);
      case "PUT":
        return replaceHandler(spec, param);
      case "PATCH":
        return mergeHandler(spec, param);
      case "DELETE":
        return deleteHandler(spec, param);
      default:
        return null;
    }
  }
  return null;
}

/** Re-exported so group modules can build one-off handlers over a spec. */
export { resolveSpec };
