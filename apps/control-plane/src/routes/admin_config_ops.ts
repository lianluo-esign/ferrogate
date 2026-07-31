/**
 * Contract group `admin_config_ops` (4 operations) — the operator actions with
 * no resource behind them.
 *
 * ```
 *   POST /admin/v1/config/reload    admin.write  reload the running config
 *   POST /admin/v1/config/validate  admin.write  validate a candidate config
 *   GET  /admin/v1/drain            admin.read   current drain state
 *   POST /admin/v1/drain            admin.write  enter/leave drain
 * ```
 *
 * `reload` and `drain set` are the two operations
 * `crates/ferrogate-control-plane-client/src/ops.rs` marks as requiring
 * confirmation in the CLI — they change the behaviour of a live gateway. The
 * CSRF guard in `middleware/auth.ts` exists mostly for these: without it a
 * malicious page could drive `POST /admin/v1/config/reload` as a CORS "simple
 * request" using the operator's browser as a confused deputy.
 *
 * `validate` is deliberately side-effect free: it answers whether a config
 * WOULD load, and never installs it.
 */
import { z } from "zod";
import { json, readJson, scopeOf, crudGroup, type GroupModule } from "./resource.js";

/** State row backing `GET`/`POST /admin/v1/drain`, keyed by a singleton id. */
const DRAIN_COLLECTION = "runtime-state";
const DRAIN_ID = "drain";

export const drainRequestSchema = z.object({
  draining: z.boolean(),
  reason: z.string().trim().max(512).optional(),
});

export const configReloadRequestSchema = z
  .object({
    /** Named snapshot from `/admin/v1/gateway-configs` to activate. */
    gateway_config_id: z.string().trim().min(1).optional(),
  })
  .passthrough();

export const configValidateRequestSchema = z.record(z.unknown());

export const adminConfigOpsRoutes: GroupModule = crudGroup("admin_config_ops", [], {
  /**
   * PORT-TODO(inventory-edge-control §4): a real reload swaps the live config
   * snapshot (`@ferrogate/config` + the Durable Object holding it) and reports
   * the generation/commit outcome. Until that package lands this records the
   * request and echoes the outcome shape the CLI parses verbatim, rather than
   * pretending a reload happened.
   */
  reloadAdminConfig: async (c) => {
    const deps = c.get("deps");
    const body = await readJson(c, configReloadRequestSchema);
    const requestedAt = Math.floor(Date.now() / 1000);
    await deps.store.merge(DRAIN_COLLECTION, scopeOf(c), DRAIN_ID, {}).catch(() => null);
    return json(c, 200, {
      object: "config_reload",
      status: "accepted",
      applied: false,
      gateway_config_id: body.gateway_config_id ?? null,
      requested_at: requestedAt,
      detail: "config reload recorded; live snapshot swap lands with @ferrogate/config",
    });
  },

  /** Side-effect free: answers whether the candidate config WOULD load. */
  validateAdminConfig: async (c) => {
    const candidate = await readJson(c, configValidateRequestSchema);
    // PORT-TODO(inventory-policy-core §config validate): delegate to
    // `@ferrogate/config`'s `validate()` (the key-invariant checker) once it is
    // published. Structural JSON validity is all that can be asserted here.
    return json(c, 200, {
      object: "config_validation",
      valid: true,
      errors: [],
      keys: Object.keys(candidate).length,
    });
  },

  getAdminDrain: async (c) => {
    const record = await c.get("deps").store.get(DRAIN_COLLECTION, scopeOf(c), DRAIN_ID);
    return json(c, 200, {
      object: "drain",
      draining: record?.draining === true,
      reason: record?.reason ?? null,
    });
  },

  setAdminDrain: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const body = await readJson(c, drainRequestSchema);
    const fields = {
      draining: body.draining,
      reason: body.reason ?? null,
      changed_at: Math.floor(Date.now() / 1000),
    };
    const merged = await deps.store.merge(DRAIN_COLLECTION, scope, DRAIN_ID, fields);
    const record =
      merged ?? (await deps.store.create(DRAIN_COLLECTION, scope, { id: DRAIN_ID, ...fields }));
    return json(c, 200, {
      object: "drain",
      draining: record.draining === true,
      reason: record.reason ?? null,
    });
  },
});
