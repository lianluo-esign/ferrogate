/**
 * The 18 `/v1/assets/**` Hono routes owned by `apps/gateway`.
 *
 * | contract operation | method + path | scope |
 * |---|---|---|
 * | `listAssets`               | GET    `/v1/assets`                                        | `assets.read`  |
 * | `getAssetStorageSummary`   | GET    `/v1/assets/storage/summary`                        | `assets.read`  |
 * | `listWithheldAssets`       | GET    `/v1/assets/withheld`                               | `assets.read`  |
 * | `listAssetsByType`         | GET    `/v1/assets/{asset_type}`                           | `assets.read`  |
 * | `getAssetManifest`         | GET    `/v1/assets/{t}/{name}/manifest`                    | `assets.read`  |
 * | `listAssetChannels`        | GET    `/v1/assets/{t}/{name}/channels`                    | `assets.read`  |
 * | `putAssetChannel`          | PUT    `/v1/assets/{t}/{name}/channels/{channel}`          | `assets.write` |
 * | `deleteAssetChannel`       | DELETE `/v1/assets/{t}/{name}/channels/{channel}`          | `assets.write` |
 * | `yankAssetVersion`         | POST   `/v1/assets/{t}/{name}/{version}/yank`              | `assets.write` |
 * | `unyankAssetVersion`       | DELETE `/v1/assets/{t}/{name}/{version}/yank`              | `assets.write` |
 * | `promoteAssetVisibility`   | POST   `/v1/assets/{t}/{name}/{version}/visibility`        | `assets.write` |
 * | `getAsset`                 | GET    `/v1/assets/{t}/{name}/{version}`                   | `assets.read`  |
 * | `putAsset`                 | PUT    `/v1/assets/{t}/{name}/{version}`                   | `assets.write` |
 * | `deleteAsset`              | DELETE `/v1/assets/{t}/{name}/{version}`                   | `assets.write` |
 * | `createAssetUploadIntent`  | POST   `/v1/assets/presign/upload/{t}/{name}/{version}`    | `assets.write` |
 * | `commitAssetUpload`        | POST   `/v1/assets/presign/commit/{t}/{name}/{version}`    | `assets.write` |
 * | `abortAssetUpload`         | POST   `/v1/assets/presign/abort/{t}/{name}/{version}`     | `assets.write` |
 * | `getAssetDownloadUrl`      | GET    `/v1/assets/presign/download/{t}/{name}/{version}`  | `assets.read`  |
 *
 * Not one path or scope is written out below: every route is mounted through
 * `GatewayRouter.register(operation_id, handler)`, which reads the path, the
 * method, and the guard straight out of the contract (ROUTE-MAP invariant 1).
 * A typo here cannot produce a route the contract does not declare.
 *
 * **Registration order is load-bearing.** The Rust dispatcher matched reserved
 * literals before the generic `{asset_type}` / `{version}` arms
 * (`assets.rs::handle_assets`), so `withheld` can never be read as an asset
 * family and a DELETE of the channel named `yank` can never be read as an
 * unyank of the version named `channels`. The registration order below
 * reproduces that precedence; see `ORDERED_ASSET_OPERATION_IDS`.
 *
 * Authentication is NOT done here. The contract-driven middleware in
 * `../middleware/auth.ts` has already enforced `auth.kind` + `auth.scope` by
 * the time a handler runs; this module only reads the resolved caller and adds
 * the asset-specific entitlement/tenancy checks that live in the service.
 */
import type { Context } from "hono";
import type { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { GatewayEnv } from "../ports.js";
import type { GatewayRouter, RouteModule } from "../routes/index.js";
import {
  BuiltinEicarScreener,
  InMemoryAssetAuditSink,
  InMemoryAssetMetadataStore,
  InMemoryAssetObjectStore,
  UnavailablePresigner,
  type AssetAuthFailure,
  type AssetCaller,
  isAuthFailure,
} from "./ports.js";
import {
  assetChannelParamsSchema,
  assetNameParamsSchema,
  assetTypeParamsSchema,
  assetVersionParamsSchema,
  assetVisibilityPromotionRequestSchema,
  channelMoveQuerySchema,
  presignAbortRequestSchema,
  presignCommitRequestSchema,
  presignUploadIntentRequestSchema,
  pushQuerySchema,
  platformQuerySchema,
  withheldQuerySchema,
} from "./schemas.js";
import {
  AssetService,
  type AssetFailure,
  type AssetPullResult,
  type AssetRequestContext,
  type AssetResult,
  type AssetServiceDeps,
} from "./service.js";

// ---------------------------------------------------------------------------
// Caller resolution
// ---------------------------------------------------------------------------

/**
 * The asset-specific entitlements the Rust handlers read off `StoredPlan` +
 * `EffectiveQuota`. Narrow local interface: `@ferrogate/billing` and
 * `@ferrogate/storage` are still stubs, so this app declares only what it
 * consumes and an adapter satisfies it later without moving a call site.
 */
export interface AssetEntitlements {
  /** Cumulative tenant asset-storage budget. `undefined` = unbounded. */
  readonly assetStorageQuotaBytes?: number | undefined;
  /** Dedicated per-object ceiling. `undefined` = unbounded. */
  readonly assetMaxObjectBytes?: number | undefined;
  /** Rust `tenant_can_host`: plan grant OR a bound `assets.host` role. */
  readonly assetHostingEnabled: boolean;
}

export interface AssetEntitlementsPort {
  resolve(tenantId: string): Promise<AssetEntitlements>;
}

/**
 * Worker bindings this module reads on top of `GatewayBindings`.
 *
 * PORT-TODO(inventory-request-path.md §1.6 "Asset hosting"): entitlements move
 * to D1 (`StoredPlan` + role bindings) via `@ferrogate/storage`. Until then a
 * JSON var is the bootstrap path, exactly as the API-key vars are.
 */
export interface AssetBindings {
  /** JSON map: tenant id → `AssetEntitlements` (snake_case keys). */
  readonly ASSET_ENTITLEMENTS?: string;
}

type AssetEnv = {
  Bindings: GatewayEnv["Bindings"] & AssetBindings;
  Variables: GatewayEnv["Variables"];
};

/**
 * Fail-closed default: a tenant with no entitlement row may NOT host assets.
 * Read surfaces stay open (they do not require hosting), so a lapsed plan stops
 * new publishes without stranding what the tenant already published.
 */
export const NO_ASSET_HOSTING: AssetEntitlements = { assetHostingEnabled: false };

function parseEntitlements(raw: unknown): AssetEntitlements {
  if (typeof raw !== "object" || raw === null) return NO_ASSET_HOSTING;
  const row = raw as Record<string, unknown>;
  const number = (value: unknown): number | undefined =>
    typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
  return {
    assetStorageQuotaBytes: number(row["asset_storage_quota_bytes"]),
    assetMaxObjectBytes: number(row["asset_max_object_bytes"]),
    assetHostingEnabled: row["asset_hosting_enabled"] === true,
  };
}

/** `ASSET_ENTITLEMENTS` var → {@link AssetEntitlementsPort}. */
export function entitlementsFromEnv(env: AssetBindings): AssetEntitlementsPort {
  let table: Record<string, unknown> | null = null;
  if (typeof env.ASSET_ENTITLEMENTS === "string") {
    try {
      const parsed: unknown = JSON.parse(env.ASSET_ENTITLEMENTS);
      if (typeof parsed === "object" && parsed !== null) {
        table = parsed as Record<string, unknown>;
      }
    } catch {
      // A malformed var must not silently grant hosting; it grants nothing.
      table = null;
    }
  }
  return {
    async resolve(tenantId: string): Promise<AssetEntitlements> {
      if (table === null) return NO_ASSET_HOSTING;
      return parseEntitlements(table[tenantId]);
    },
  };
}

/** Resolves the {@link AssetCaller} for one already-authenticated request. */
export type AssetCallerResolver = (
  c: Context<AssetEnv>,
) => Promise<AssetCaller | AssetAuthFailure>;

/**
 * Default resolver: the `AuthContext` the contract middleware already put on
 * the context, joined with the tenant's asset entitlements.
 *
 * A credential with no tenant attribution resolves to the empty tenant id,
 * which the service turns into the Rust `403 tenant_required` — an unforgeable
 * value that matches no row, so it can never read another tenant's assets.
 */
export function defaultCallerResolver(
  entitlements?: AssetEntitlementsPort,
): AssetCallerResolver {
  return async (c) => {
    const auth = c.get("auth");
    if (auth === null || auth === undefined) {
      return { status: 401, code: "invalid_api_key", message: "invalid API key" };
    }
    const tenantId = auth.tenancy.tenantId ?? "";
    const port = entitlements ?? entitlementsFromEnv(c.env);
    const grants = tenantId === "" ? NO_ASSET_HOSTING : await port.resolve(tenantId);
    return {
      tenantId,
      projectId: auth.tenancy.projectId ?? undefined,
      scopes: auth.scopes,
      assetStorageQuotaBytes: grants.assetStorageQuotaBytes,
      assetMaxObjectBytes: grants.assetMaxObjectBytes,
      assetHostingEnabled: grants.assetHostingEnabled,
    };
  };
}

// ---------------------------------------------------------------------------
// Request plumbing
// ---------------------------------------------------------------------------

/** Rust `declared_agent_run_id` (#522): validated, optional correlation id. */
const AGENT_RUN_ID = /^[A-Za-z0-9][A-Za-z0-9_:.-]{0,127}$/;

function requestContext(c: Context<AssetEnv>): AssetRequestContext {
  const declared = c.req.header("x-ferrogate-agent-run-id")?.trim();
  if (declared !== undefined && declared !== "" && !AGENT_RUN_ID.test(declared)) {
    throw new HttpError(
      400,
      "invalid_agent_run_id_header",
      "x-ferrogate-agent-run-id must be 1-128 characters of [A-Za-z0-9_:.-] starting alphanumeric",
    );
  }
  return {
    requestId: c.get("requestId") ?? "",
    // PORT-TODO(inventory-request-path.md §governed actions): the per-tenant
    // "require a declared run id" switch and the unjoinable-action metric live
    // in `@ferrogate/observability` + `@ferrogate/policy`, still stubs. The
    // header is validated and threaded onto every audit row today; only the
    // optional ENFORCEMENT (default OFF in Rust) is outstanding.
    agentRunId: declared === "" ? undefined : declared,
  };
}

/** Zod-validate a path/query bag, or answer the Rust `400 invalid_request`. */
function parseOrThrow<T extends z.ZodTypeAny>(schema: T, value: unknown): z.infer<T> {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("; ");
    throw new HttpError(400, "invalid_request", detail);
  }
  return parsed.data;
}

/** Read + Zod-validate a JSON control body (Rust `read_control_body`). */
async function controlBody<T extends z.ZodTypeAny>(
  c: Context<AssetEnv>,
  schema: T,
): Promise<z.infer<T>> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    throw new HttpError(400, "invalid_request_body", "request body is not valid JSON");
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    // `.strict()` bodies mean a typo'd screening field fails loudly here rather
    // than silently skipping a control (Rust `deny_unknown_fields`).
    const detail = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("; ");
    throw new HttpError(400, "invalid_request", detail);
  }
  return parsed.data;
}

/** Every service refusal leaves through the app's uniform error envelope. */
function raise(failure: AssetFailure): never {
  throw new HttpError(failure.status, failure.code, failure.message);
}

function render<T>(result: AssetResult<T>): Response {
  if (!result.ok) raise(result);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...(result.headers ?? {}),
  };
  return new Response(JSON.stringify(result.body), { status: result.status, headers });
}

function renderBytes(result: AssetPullResult): Response {
  if (!result.ok) raise(result);
  const body: BodyInit | null =
    result.bytes === null
      ? null
      : (result.bytes.buffer.slice(
          result.bytes.byteOffset,
          result.bytes.byteOffset + result.bytes.byteLength,
        ) as ArrayBuffer);
  return new Response(body, { status: result.status, headers: { ...result.headers } });
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

export interface AssetRouteModuleOptions {
  /** A pre-built service. Wins over `deps`. */
  readonly service?: AssetService | undefined;
  /**
   * Ports for a service built here. Omitted ports fall back to the offline
   * in-memory defaults, which is enough to boot and to test but presigns
   * nothing (`asset_bucket_unavailable`, exactly as an unconfigured Rust
   * gateway answers).
   */
  readonly deps?: Partial<AssetServiceDeps> | undefined;
  readonly caller?: AssetCallerResolver | undefined;
  readonly entitlements?: AssetEntitlementsPort | undefined;
}

/**
 * Registration order, reserved literals first — see the module docstring. The
 * anti-drift test asserts this list is exactly the contract's 18 asset
 * operation ids, so neither a missing route nor a stray one can hide in it.
 */
export const ORDERED_ASSET_OPERATION_IDS = [
  // Reserved literals, ahead of every generic `{asset_type}` arm.
  "getAssetStorageSummary",
  "listWithheldAssets",
  // The presign family: a 6-segment space that no generic arm can reach.
  "createAssetUploadIntent",
  "commitAssetUpload",
  "abortAssetUpload",
  "getAssetDownloadUrl",
  // Reserved third/fourth segments, ahead of the `{version}` arms.
  "getAssetManifest",
  "listAssetChannels",
  "putAssetChannel",
  "deleteAssetChannel",
  "yankAssetVersion",
  "unyankAssetVersion",
  "promoteAssetVisibility",
  // Generic arms last.
  "listAssets",
  "listAssetsByType",
  "getAsset",
  "putAsset",
  "deleteAsset",
] as const;

export function buildAssetService(deps?: Partial<AssetServiceDeps>): AssetService {
  return new AssetService({
    objects: deps?.objects ?? new InMemoryAssetObjectStore(),
    metadata: deps?.metadata ?? new InMemoryAssetMetadataStore(),
    presigner: deps?.presigner ?? new UnavailablePresigner(),
    screener: deps?.screener ?? new BuiltinEicarScreener(),
    audit: deps?.audit ?? new InMemoryAssetAuditSink(),
    limits: deps?.limits,
    now: deps?.now,
  });
}

/** The `RouteModule` `createGatewayApp({ modules })` mounts. */
export function assetRouteModule(options: AssetRouteModuleOptions = {}): RouteModule {
  const service = options.service ?? buildAssetService(options.deps);
  const resolveCaller = options.caller ?? defaultCallerResolver(options.entitlements);

  /** Resolve the caller or answer its refusal. */
  const caller = async (c: Context<AssetEnv>): Promise<AssetCaller> => {
    const resolved = await resolveCaller(c);
    if (isAuthFailure(resolved)) {
      throw new HttpError(resolved.status, resolved.code, resolved.message);
    }
    return resolved;
  };

  return {
    operationIds: [...ORDERED_ASSET_OPERATION_IDS],
    register(router: GatewayRouter): void {
      const on = (
        operationId: string,
        handler: (c: Context<AssetEnv>) => Promise<Response>,
      ): void => {
        router.register(operationId, (c) => handler(c as unknown as Context<AssetEnv>));
      };

      // --- reserved literals ------------------------------------------------

      on("getAssetStorageSummary", async (c) =>
        render(await service.storageSummary(await caller(c))),
      );

      on("listWithheldAssets", async (c) => {
        const query = parseOrThrow(withheldQuerySchema, c.req.query());
        return render(await service.listWithheldAssets(await caller(c), query));
      });

      // --- presign family ---------------------------------------------------

      on("createAssetUploadIntent", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const body = await controlBody(c, presignUploadIntentRequestSchema);
        return render(
          await service.createUploadIntent(
            await caller(c),
            refOf(params),
            body,
            requestContext(c),
          ),
        );
      });

      on("commitAssetUpload", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const body = await controlBody(c, presignCommitRequestSchema);
        return render(
          await service.commitUpload(await caller(c), refOf(params), body, requestContext(c)),
        );
      });

      on("abortAssetUpload", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const body = await controlBody(c, presignAbortRequestSchema);
        return render(
          await service.abortUpload(await caller(c), refOf(params), body, requestContext(c)),
        );
      });

      on("getAssetDownloadUrl", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        return render(
          await service.downloadUrl(await caller(c), refOf(params), requestContext(c)),
        );
      });

      // --- reserved third/fourth segments -----------------------------------

      on("getAssetManifest", async (c) => {
        const params = parseOrThrow(assetNameParamsSchema, c.req.param());
        return render(await service.manifest(await caller(c), nameOf(params)));
      });

      on("listAssetChannels", async (c) => {
        const params = parseOrThrow(assetNameParamsSchema, c.req.param());
        return render(await service.listChannels(await caller(c), nameOf(params)));
      });

      on("putAssetChannel", async (c) => {
        const params = parseOrThrow(assetChannelParamsSchema, c.req.param());
        // The move target is a query param, not a body: Rust
        // `handle_channel_move` requires `?version=` and answers
        // `400 channel_target_required` without it. Parsed leniently here so
        // the SERVICE owns that code rather than Zod inventing another one.
        const version = c.req.query("version");
        if (version !== undefined && version !== "") {
          parseOrThrow(channelMoveQuerySchema, { version });
        }
        return render(
          await service.putChannel(
            await caller(c),
            nameOf(params),
            params.channel,
            version,
            requestContext(c),
          ),
        );
      });

      on("deleteAssetChannel", async (c) => {
        const params = parseOrThrow(assetChannelParamsSchema, c.req.param());
        return render(
          await service.deleteChannel(
            await caller(c),
            nameOf(params),
            params.channel,
            requestContext(c),
          ),
        );
      });

      on("yankAssetVersion", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        return render(
          await service.setVersionYank(await caller(c), refOf(params), true, requestContext(c)),
        );
      });

      on("unyankAssetVersion", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        return render(
          await service.setVersionYank(await caller(c), refOf(params), false, requestContext(c)),
        );
      });

      on("promoteAssetVisibility", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const query = parseOrThrow(platformQuerySchema, c.req.query());
        const body = await controlBody(c, assetVisibilityPromotionRequestSchema);
        return render(
          await service.promoteVisibility(
            await caller(c),
            { ...refOf(params), variant: query.platform ?? "" },
            body,
            requestContext(c),
          ),
        );
      });

      // --- generic arms -----------------------------------------------------

      on("listAssets", async (c) => render(await service.listAssets(await caller(c))));

      on("listAssetsByType", async (c) => {
        const params = parseOrThrow(assetTypeParamsSchema, c.req.param());
        return render(await service.listAssets(await caller(c), params.asset_type));
      });

      on("getAsset", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const query = parseOrThrow(platformQuerySchema, c.req.query());
        return renderBytes(
          await service.pullAsset(
            await caller(c),
            { assetType: params.asset_type, name: params.name, reference: params.version },
            {
              platform: query.platform,
              headers: c.req.raw.headers,
              method: c.req.method,
            },
          ),
        );
      });

      on("putAsset", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const query = parseOrThrow(pushQuerySchema, c.req.query());
        // The caller is resolved BEFORE the body is read, so an unauthorized
        // oversized push is still an auth refusal and not `payload_too_large`
        // (the Rust ordering note in `chat.rs:158`, which holds here too).
        const resolved = await caller(c);
        const context = requestContext(c);
        const content = new Uint8Array(await c.req.arrayBuffer());
        return render(
          await service.putAsset(
            resolved,
            { ...refOf(params), variant: query.platform ?? "" },
            {
              contentType: c.req.header("content-type") ?? undefined,
              content,
              channel: query.channel,
            },
            context,
          ),
        );
      });

      on("deleteAsset", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const query = parseOrThrow(platformQuerySchema, c.req.query());
        return render(
          await service.deleteAsset(
            await caller(c),
            { ...refOf(params), variant: query.platform ?? "" },
            requestContext(c),
          ),
        );
      });
    },
  };
}

function refOf(params: { asset_type: string; name: string; version: string }) {
  return { assetType: params.asset_type, name: params.name, version: params.version };
}

function nameOf(params: { asset_type: string; name: string }) {
  return { assetType: params.asset_type, name: params.name };
}
