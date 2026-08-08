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
import { PriceBook } from "@ferrogate/billing";
import {
  configSnapshotId,
  loadConfigFromObject,
  tenancyPostureWarnings,
  validateConfigAsync,
} from "@ferrogate/config";
import { z } from "zod";
import { modelCatalogInputsFromEnv } from "../../../gateway/src/inference/catalog.js";
import { HttpError } from "../middleware/errors.js";
import {
  type PlatformCatalogImportGraph,
  envInputsToImportGraph,
  importGraphReferentialError,
  mergeImportGraphs,
  rateCardToImportGraph,
} from "../store/platform-catalog-import.js";
import {
  PlatformModelCatalogStore,
  isMissingPlatformCatalogError,
} from "../store/platform-model-catalog.js";
import {
  DRAIN_COLLECTION,
  DRAIN_ID,
  drainDocument,
  parseDrainDocument,
} from "../store/runtime_state.js";
import { type GroupModule, crudGroup, depsOf, json, readJson, scopeOf } from "./resource.js";

/**
 * State row backing `GET`/`POST /admin/v1/drain`, keyed by a singleton id.
 *
 * The names and the document shape come from `../store/runtime_state.ts` rather
 * than being spelled here, because THREE Workers now read this row —
 * `apps/mcp` and `apps/agent-runtime` enforce the drain off it per request, and
 * `apps/gateway` refuses off `GATEWAY_DRAIN`. Before FC-1 the constants lived
 * only in this file and nothing read the row at all; a shared definition is
 * what makes "the operator applied it here" and "the enforcer reads it there"
 * the same fact. `apps/mcp/test/drain-fleet.test.ts` writes with
 * {@link drainDocument} and requires both enforcers to shut.
 */
export { DRAIN_COLLECTION, DRAIN_ID };
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

/**
 * `POST /admin/v1/config/import-model-catalog` body (#892).
 *
 * The env pair is supplied here rather than read only from this Worker's own
 * bindings: the import is a one-shot bootstrap an operator runs with the values
 * they are migrating, and pasting them keeps the control-plane Worker from
 * holding a second, drift-prone copy of the gateway's `GATEWAY_*` vars. Each of
 * `providers`/`models`/`cloudflare` may be the raw JSON string (exactly as the
 * var holds it) or an already-parsed array/object; an omitted field falls back to
 * the matching binding when the deployment chose to bind it. `.strict()` for the
 * same reason every other body in this file is: a misspelled key fails loudly.
 */
export const configImportModelCatalogRequestSchema = z
  .object({
    providers: z.union([z.string(), z.array(z.unknown())]).optional(),
    models: z.union([z.string(), z.array(z.unknown())]).optional(),
    cloudflare: z.union([z.string(), z.record(z.unknown())]).optional(),
    /** Also import `withDefaultRateCard()` as platform-kind price rows. Default `true`. */
    include_default_rate_card: z.boolean().optional(),
  })
  .strict();

const EMPTY_IMPORT_GRAPH: PlatformCatalogImportGraph = {
  providers: [],
  models: [],
  offerings: [],
};

/** A body field or the matching binding, normalized to the JSON string the parser reads. */
function importEnvString(
  bodyValue: string | readonly unknown[] | Record<string, unknown> | undefined,
  boundValue: string | undefined,
): string | undefined {
  if (bodyValue === undefined) return boundValue;
  return typeof bodyValue === "string" ? bodyValue : JSON.stringify(bodyValue);
}

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

  /**
   * The state the whole fleet enforces off.
   *
   * Parsed with the SAME {@link parseDrainDocument} `apps/mcp` and
   * `apps/agent-runtime` use, so what an operator is TOLD and what the
   * enforcers DO cannot diverge — the FC-1 defect in miniature. A row that the
   * enforcers ignore (tenant-attributed, or `draining` not the JSON boolean
   * `true`) must therefore read back here as "not draining" too.
   */
  getAdminDrain: async (c) => {
    const record = await c.get("deps").store.get(DRAIN_COLLECTION, scopeOf(c), DRAIN_ID);
    const state = parseDrainDocument(record as Record<string, unknown> | null);
    return json(c, 200, {
      object: "drain",
      draining: state.draining,
      reason: state.reason,
      accepting_new_requests: state.accepting_new_requests,
    });
  },

  /**
   * Enter or leave the operator drain — the ONE write three Workers read.
   *
   * ## Why this operation is PLATFORM-OPERATOR ONLY
   *
   * The contract gives it `admin.write`, which a TENANT administrator can hold.
   * That was harmless while nothing read the row. It is not harmless now: every
   * Worker resolves `runtime-state/drain` by primary key, so a tenant-scoped
   * caller who could mint it would take the entire DEPLOYMENT out of service
   * for every other tenant — a cross-tenant denial of service reachable from an
   * intended, correctly-scoped credential. Two independent defences, because
   * one of them being bypassed must not be enough:
   *
   *  1. this fence — a non-platform caller is `403 tenant_scope_denied` and
   *     never reaches the store;
   *  2. `tenant_id: null` is PINNED by {@link drainDocument}, and every enforcer
   *     IGNORES a drain document that carries a tenant
   *     (`parseDrainDocument`). So even a row written by some other path cannot
   *     drain the fleet from inside one tenant.
   *
   * `403` and not `404`: the caller is authenticated and the operation exists;
   * what they lack is the scope. That is the same answer `bearerAuth` gives a
   * credential that names no tenant, and it does not disclose deployment state.
   */
  setAdminDrain: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    if (scope.kind !== "platform_operator") {
      throw new HttpError(
        403,
        "tenant_scope_denied",
        "the operator drain is deployment-wide state; a tenant-scoped credential cannot set it",
      );
    }
    const body = await readJson(c, drainRequestSchema);
    const document = drainDocument({
      draining: body.draining,
      reason: body.reason ?? null,
      changedAt: Math.floor(Date.now() / 1000),
    });
    const { id: _id, ...fields } = document;
    const merged = await deps.store.merge(DRAIN_COLLECTION, scope, DRAIN_ID, fields);
    const record = merged ?? (await deps.store.create(DRAIN_COLLECTION, scope, { ...document }));
    const state = parseDrainDocument(record as Record<string, unknown>);
    return json(c, 200, {
      object: "drain",
      draining: state.draining,
      reason: state.reason,
      accepting_new_requests: state.accepting_new_requests,
      // Rust flipped an in-process `AtomicBool` and every request saw it
      // instantly. Here the fleet reads a durable row, so the honest statement
      // is that enforcement lands on each Worker's NEXT request — not that it
      // has already landed everywhere.
      propagation: "on_next_request_per_worker",
    });
  },

  /**
   * Bootstrap the platform model catalog from the env tables + default rate card
   * (#892, epic #810) — PLATFORM-OPERATOR ONLY, idempotent, re-runnable.
   *
   * ## Why it lives here and why it is platform-operator only
   *
   * #889–#891 made the platform catalog authoritative-when-present, but a real
   * deployment's catalog still lives in `GATEWAY_PROVIDERS`/`GATEWAY_MODELS` and
   * `PriceBook.withDefaultRateCard()`. Until those are imported the managed path
   * serves nobody and the env path can never be demoted. This is the one
   * operation that fills it. Like {@link setAdminDrain} it is deployment-wide
   * state a tenant credential must never touch, so the SAME fence guards it: a
   * non-platform caller is `403 tenant_scope_denied` and never reaches the store.
   *
   * ## Idempotent by construction
   *
   * The env pair is parsed with the SAME `modelCatalogInputsFromEnv` the data
   * plane uses, turned into deterministic-id rows
   * ({@link envInputsToImportGraph}), and written under `INSERT OR IGNORE`
   * ({@link PlatformModelCatalogStore.importGraph}) with ONE revision bump and
   * ONE audit row. A re-run inserts nothing and only advances the revision. The
   * default rate card becomes `platform`-kind priced offerings
   * ({@link rateCardToImportGraph}); those price rows are excluded from the
   * data-plane route build and from tenant seeds (see the store), so they record
   * the card without pretending to be routable legs.
   *
   * ## Deploy order
   *
   * Run this (verify the reported counts), THEN — as a SEPARATE, deferred
   * Zero-D1-S5 follow-up — the `GATEWAY_*` vars MAY be emptied. This operation
   * does not touch env handling; the gateway still falls back to the env tables
   * whenever the platform catalog is empty.
   */
  importModelCatalog: async (c) => {
    const scope = scopeOf(c);
    if (scope.kind !== "platform_operator") {
      throw new HttpError(
        403,
        "tenant_scope_denied",
        "the platform model catalog is deployment-wide state; a tenant-scoped credential cannot import it",
      );
    }
    const deps = depsOf(c);
    if (deps.controlDatabase === null) {
      throw new HttpError(
        503,
        "control_database_unavailable",
        "control database is required for the platform catalog",
      );
    }

    const body = await readJson(c, configImportModelCatalogRequestSchema);
    const envLike = {
      GATEWAY_PROVIDERS: importEnvString(body.providers, c.env.GATEWAY_PROVIDERS),
      GATEWAY_MODELS: importEnvString(body.models, c.env.GATEWAY_MODELS),
      GATEWAY_CLOUDFLARE: importEnvString(body.cloudflare, c.env.GATEWAY_CLOUDFLARE),
    };
    const parsed = modelCatalogInputsFromEnv(
      envLike as Parameters<typeof modelCatalogInputsFromEnv>[0],
    );
    if (!parsed.ok) {
      throw new HttpError(400, "invalid_request_body", `env catalog is invalid: ${parsed.reason}`);
    }

    const includeCard = body.include_default_rate_card ?? true;
    const envGraph = envInputsToImportGraph(parsed.inputs.providers, parsed.inputs.models);
    const envModelNames = new Set(parsed.inputs.models.map((model) => model.name));
    const cardGraph = includeCard
      ? rateCardToImportGraph(PriceBook.withDefaultRateCard(), envModelNames)
      : EMPTY_IMPORT_GRAPH;
    const graph = mergeImportGraphs(envGraph, cardGraph);

    const referentialError = importGraphReferentialError(graph);
    if (referentialError !== null) {
      throw new HttpError(
        400,
        "invalid_request_body",
        `env catalog is invalid: ${referentialError}`,
      );
    }

    const store = new PlatformModelCatalogStore({
      db: deps.controlDatabase,
      requestId: c.get("requestId") ?? null,
    });
    let result: Awaited<ReturnType<PlatformModelCatalogStore["importGraph"]>>;
    try {
      result = await store.importGraph(scope, graph);
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) {
        throw new HttpError(
          503,
          "control_database_unavailable",
          "the platform model catalog schema is not applied to the control database yet",
        );
      }
      throw error;
    }

    return json(c, 200, {
      object: "platform_catalog_import",
      scope: "platform",
      include_default_rate_card: includeCard,
      // Rows the graph carried (attempted), rows this call actually INSERTED
      // (0 on a re-run), and the resulting totals — the count verification shape
      // an operator runs in production.
      attempted: {
        providers: graph.providers.length,
        models: graph.models.length,
        offerings: graph.offerings.length,
      },
      inserted: result.inserted,
      counts: result.counts,
      revision: result.revision,
    });
  },
});
