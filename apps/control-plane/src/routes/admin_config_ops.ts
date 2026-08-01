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
import {
  configSnapshotId,
  loadConfigFromObject,
  tenancyPostureWarnings,
  validateConfigAsync,
} from "@ferrogate/config";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { type GroupModule, crudGroup, json, readJson, scopeOf } from "./resource.js";

/** State row backing `GET`/`POST /admin/v1/drain`, keyed by a singleton id. */
const DRAIN_COLLECTION = "runtime-state";
const DRAIN_ID = "drain";
/** The singleton row naming which gateway-config snapshot is currently active. */
const ACTIVE_CONFIG_ID = "active-config";

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
   * Promote a named `/admin/v1/gateway-configs` snapshot to be the active one.
   *
   * What this DOES do, and Rust's `reload_process_local` does too: refuse a
   * candidate that would not load. The named snapshot is read, run through the
   * SAME `@ferrogate/config` gate `validate` uses, and a candidate that fails is
   * a `409 config_reload_rejected` with the loader's own first `field …:` — the
   * activation record is not written, so a bad config cannot become the active
   * one. Rust's identical refusal is what stops a reload from taking a running
   * gateway down; skipping it here and "accepting" every reload would be the
   * dangerous half of the operation implemented without the safe half.
   *
   * It then records the activation durably (`runtime-state/active-config`,
   * carrying the `configSnapshotId` of what was promoted), which is the state a
   * data-plane isolate reads on its next config fetch.
   *
   * PORT-TODO(L: inventory-edge-control §4) — PLATFORM LIMIT, sharpened: a Worker
   * isolate cannot be told to swap an in-memory snapshot the way Rust's
   * `ArcSwap` + `reload_process_local` does. There is no process to signal:
   * isolates are created and evicted by the platform, an arbitrary number of
   * them are live at once across colos, and nothing can reach into a running one
   * from outside. The closest CONSTRUCTION is a Durable Object as the single
   * snapshot holder that every isolate reads through, which is a `apps/gateway`
   * design decision (it owns the read side) and cannot be made unilaterally
   * here. So this endpoint promotes DURABLY and reports `applied: false` with
   * `propagation: "on_next_isolate_config_read"` rather than claiming an
   * instantaneous fleet-wide swap it cannot perform — `applied: true` would be a
   * lie an operator would act on during an incident.
   */
  reloadAdminConfig: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const body = await readJson(c, configReloadRequestSchema);
    const requestedAt = Math.floor(Date.now() / 1000);

    let snapshotId: string | null = null;
    const gatewayConfigId = body.gateway_config_id ?? null;
    if (gatewayConfigId !== null) {
      const candidate = await deps.store.get("gateway-configs", scope, gatewayConfigId);
      if (candidate === null) {
        throw new HttpError(404, "not_found", `gateway config ${gatewayConfigId} not found`);
      }
      const raw = (
        typeof candidate.config === "object" && candidate.config !== null
          ? candidate.config
          : candidate
      ) as Record<string, unknown>;
      const options = { apiKeysAreControlPlaneDocuments: true };
      try {
        const { config } = loadConfigFromObject(raw, options);
        await validateConfigAsync(config, options);
        snapshotId = configSnapshotId(config);
      } catch (error) {
        throw new HttpError(
          409,
          "config_reload_rejected",
          error instanceof Error ? error.message : String(error),
        );
      }
    }

    const fields = {
      gateway_config_id: gatewayConfigId,
      config_snapshot_id: snapshotId,
      activated_at: requestedAt,
    };
    const activated =
      (await deps.store.merge(DRAIN_COLLECTION, scope, ACTIVE_CONFIG_ID, fields)) ??
      (await deps.store.create(DRAIN_COLLECTION, scope, { id: ACTIVE_CONFIG_ID, ...fields }));

    return json(c, 200, {
      object: "config_reload",
      status: "accepted",
      // The candidate is durably active; no live isolate has been swapped.
      applied: false,
      propagation: "on_next_isolate_config_read",
      gateway_config_id: gatewayConfigId,
      config_snapshot_id: activated.config_snapshot_id ?? null,
      requested_at: requestedAt,
      detail:
        "candidate validated and recorded as the active config snapshot; running isolates pick it up on their next config read (Workers cannot swap an in-memory snapshot in a live isolate)",
    });
  },

  /**
   * Side-effect free: answers whether the candidate config WOULD load.
   *
   * This is `@ferrogate/config`'s real gate — `loadConfigFromObject` (alias
   * migration → Zod parse → `Config::validate()`) followed by
   * `validateConfigAsync`'s one asynchronous leg, the Ed25519 signed-snapshot
   * key material (#206), which WebCrypto cannot check synchronously. Running
   * the same function the loader runs is the point: a "valid" here that the
   * loader would then refuse is worse than no endpoint at all, because it is
   * the answer an operator promotes a config on.
   *
   * The Rust gate `bail!`s the FIRST `field <path>: <reason>` it meets and the
   * check ORDER is itself observable, so `errors` carries exactly one entry —
   * synthesising a full issue list would report problems in an order the loader
   * does not, and would claim to have checked things it stopped before.
   *
   * `apiKeysAreControlPlaneDocuments` is TRUE here: on this Worker the api-key
   * rows are durable control-plane documents, not a config file, so an
   * undeclared tenant identity is REPORTED rather than refused (#540). Refusing
   * would lock an operator out of the very API that repairs those rows.
   */
  validateAdminConfig: async (c) => {
    const candidate = await readJson(c, configValidateRequestSchema);
    const options = { apiKeysAreControlPlaneDocuments: true };
    try {
      const { config, warnings } = loadConfigFromObject(candidate, options);
      await validateConfigAsync(config, options);
      return json(c, 200, {
        object: "config_validation",
        valid: true,
        errors: [],
        warnings: [...warnings, ...tenancyPostureWarnings(config)],
        keys: Object.keys(candidate).length,
      });
    } catch (error) {
      // 200 with `valid: false`, NOT 4xx: the caller asked a question and got
      // an answer. A 400 here would be indistinguishable from "your validate
      // request was malformed", which is a different fact.
      return json(c, 200, {
        object: "config_validation",
        valid: false,
        errors: [error instanceof Error ? error.message : String(error)],
        warnings: [],
        keys: Object.keys(candidate).length,
      });
    }
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
