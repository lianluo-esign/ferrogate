/**
 * The `/v1/assets/**` and OpenAI-compatible `/v1/files` Hono routes owned by
 * `apps/gateway`.
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
import type { AuthContext, GatewayEnv } from "../ports.js";
import {
  type QuotaBindings,
  quotaPolicySourceFromEnv,
  resolveQuotaWindows,
  subjectFor,
} from "../ratelimit/index.js";
import type { GatewayRouter, RouteModule } from "../routes/index.js";
import {
  assetAuditSinkFromEnv,
  assetBundleIndexStoreFromEnv,
  assetMetadataStoreFromEnv,
} from "./d1.js";
import {
  type AssetEgressQuota,
  NO_ASSET_EGRESS_METER,
  assetEgressCountersFromEnv,
  assetEgressMeterFromEnv,
  assetEgressPricePerGb,
} from "@ferrogate/billing";
import { D1AssetEntitlements } from "./entitlements.js";
import { withAssetGuardrailScreening } from "./guardrail-screener.js";
import {
  type AssetAuthFailure,
  type AssetCaller,
  type AssetObjectStore,
  BuiltinEicarScreener,
  InMemoryAssetAuditSink,
  InMemoryAssetBundleIndexStore,
  InMemoryAssetMetadataStore,
  InMemoryAssetObjectStore,
  UnavailablePresigner,
  isAuthFailure,
} from "./ports.js";
import { type AssetScannerBindings, assetScreenerFromEnv } from "./scan.js";
import {
  assetChannelParamsSchema,
  assetNameParamsSchema,
  assetTypeParamsSchema,
  assetVersionParamsSchema,
  assetVisibilityPromotionRequestSchema,
  channelMoveQuerySchema,
  fileIdParamsSchema,
  fileListQuerySchema,
  platformQuerySchema,
  presignAbortRequestSchema,
  presignCommitRequestSchema,
  presignUploadIntentRequestSchema,
  pullQuerySchema,
  pushQuerySchema,
  withheldQuerySchema,
} from "./schemas.js";
import {
  type AssetFailure,
  type AssetPullResult,
  type AssetRequestContext,
  type AssetResult,
  AssetService,
  type AssetServiceDeps,
} from "./service.js";
import { type SignaturePolicyBindings, withSignatureVerification } from "./signature-screener.js";
import { type AssetSignatureInput, parseSignatureFormat } from "./signature.js";
import { SigV4Presigner } from "./sigv4.js";

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
 * The DURABLE source landed in `./entitlements.ts`: {@link D1AssetEntitlements}
 * reads `tenants.plan_id → plans` for the plan half and the
 * Permission → Role → TenantRoleBinding graph for the `assets.host` role half,
 * i.e. both sides of the Rust `tenant_can_host` disjunction
 * (`assets.rs:1804`). {@link entitlementsFromEnv} puts it in front of the var
 * below, which now answers only for a tenant with no `tenants` row.
 */
export interface AssetBindings {
  /** JSON map: tenant id → `AssetEntitlements` (snake_case keys). */
  readonly ASSET_ENTITLEMENTS?: string;
  /**
   * Rust `FG_REQUIRE_AGENT_RUN_ID` (#522): the per-tenant governed-action
   * enforcement switch. Unset ⇒ OFF for every tenant, which is the Rust
   * default posture. See {@link tenantRequiresDeclaredActionId}.
   */
  readonly FG_REQUIRE_AGENT_RUN_ID?: string;
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
    assetStorageQuotaBytes: number(row.asset_storage_quota_bytes),
    assetMaxObjectBytes: number(row.asset_max_object_bytes),
    assetHostingEnabled: row.asset_hosting_enabled === true,
  };
}

/**
 * Worker `env` → {@link AssetEntitlementsPort}.
 *
 * DURABLE FIRST: with `CONTROL_DB` bound, {@link D1AssetEntitlements} answers
 * from `tenants → plans` plus the `assets.host` role grant — the two halves of
 * the Rust `tenant_can_host` — and the var below is consulted only for a tenant
 * the control plane has never heard of. Without the binding the behaviour is
 * exactly what it was: the var, and nothing else.
 */
export function entitlementsFromEnv(env: AssetBindings): AssetEntitlementsPort {
  const configured = configuredEntitlementsFromEnv(env);
  return (
    D1AssetEntitlements.fromEnv(env as unknown as Record<string, unknown>, {
      fallback: configured,
    }) ?? configured
  );
}

/** The `ASSET_ENTITLEMENTS` var alone — the bootstrap leg. */
export function configuredEntitlementsFromEnv(env: AssetBindings): AssetEntitlementsPort {
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
export type AssetCallerResolver = (c: Context<AssetEnv>) => Promise<AssetCaller | AssetAuthFailure>;

/**
 * Default resolver: the `AuthContext` the contract middleware already put on
 * the context, joined with the tenant's asset entitlements.
 *
 * A credential with no tenant attribution resolves to the empty tenant id,
 * which the service turns into the Rust `403 tenant_required` — an unforgeable
 * value that matches no row, so it can never read another tenant's assets.
 */
export function defaultCallerResolver(entitlements?: AssetEntitlementsPort): AssetCallerResolver {
  return async (c) => {
    const auth = c.get("auth");
    if (auth === null || auth === undefined) {
      return { status: 401, code: "invalid_api_key", message: "invalid API key" };
    }
    const tenantId = auth.tenancy.tenantId ?? "";
    const port = entitlements ?? entitlementsFromEnv(c.env);
    const grants = tenantId === "" ? NO_ASSET_HOSTING : await port.resolve(tenantId);
    const apiKeyId = auth.subject ?? "";
    return {
      tenantId,
      projectId: auth.tenancy.projectId ?? undefined,
      scopes: auth.scopes,
      assetStorageQuotaBytes: grants.assetStorageQuotaBytes,
      assetMaxObjectBytes: grants.assetMaxObjectBytes,
      assetHostingEnabled: grants.assetHostingEnabled,
      apiKeyId,
      effectiveQuota: await resolveEgressQuota(c, apiKeyId),
    };
  };
}

/**
 * The egress half of the caller's resolved quota (issue #262, finding D4).
 *
 * The MERGE is not re-implemented: `resolveQuotaWindows` +
 * `@ferrogate/policy`'s `resolveEffectiveQuota` already own min-across-the-chain
 * and the plan floor, and `subjectFor` already owns the chain projection. This
 * only decides WHEN to ask.
 *
 * Why it is resolved here rather than read off the context: `rateLimit()` (the
 * middleware that resolves the same quota for the inference path) does not
 * publish its resolution on `GatewayVariables`, and `src/ports.ts` is not this
 * slice's to extend. Resolving again costs one policy lookup on the asset
 * surface only — memoized by the caller's own D1 source per env — and it keeps
 * the egress gate working even for a deployment that mounts the asset module
 * without the rate-limit middleware.
 *
 * A FAILED lookup yields `{}`, i.e. no egress limits. That is deliberate and is
 * NOT a fail-open on a configured budget: the same lookup failing on the
 * inference path is already a hard `503 quota_resolution_unavailable` from
 * `rateLimit()`, which runs first and would have refused the request before it
 * ever reached a handler. Duplicating that refusal here would let an asset
 * READ start failing for a reason the middleware had already adjudicated.
 */
async function resolveEgressQuota(
  c: Context<AssetEnv>,
  apiKeyId: string,
): Promise<AssetEgressQuota> {
  if (apiKeyId === "") return {};
  const subject = subjectFor(c as unknown as Context<GatewayEnv>);
  if (subject === null) return {};
  const resolution = await resolveQuotaWindows(
    quotaPolicySourceFromEnv(c.env as unknown as QuotaBindings),
    subject,
  );
  return resolution.ok ? resolution.quota : {};
}

// ---------------------------------------------------------------------------
// Request plumbing
// ---------------------------------------------------------------------------

/** Rust `declared_agent_run_id` (#522): validated, optional correlation id. */
const AGENT_RUN_ID = /^[A-Za-z0-9][A-Za-z0-9_:.-]{0,127}$/;

/**
 * The per-tenant governed-action enforcement switch — Rust
 * `REQUIRE_AGENT_RUN_ID_ENV` (`server/local.rs:10692`).
 *
 * The NAME is kept verbatim (no `GATEWAY_` prefix) because the Rust comment is
 * explicit that this is an OPERATOR ENV SWITCH deliberately kept out of the
 * config schema "so it adds no OpenAPI surface" — a Worker var of the same name
 * is the same switch, and every operator runbook that mentions
 * `FG_REQUIRE_AGENT_RUN_ID` keeps working.
 */
export const REQUIRE_AGENT_RUN_ID_VAR = "FG_REQUIRE_AGENT_RUN_ID";

/**
 * Rust `governed_action_tenant_key`: the low-cardinality key both the
 * enforcement switch and the (still-deferred) unjoinable-action metric match
 * on. Derived ONLY from the authenticated identity — never from a
 * client-declared value — preferring the broadest stable scope down to the API
 * key id, and empty when the credential carries no attribution at all.
 *
 * The Rust chain is `organization_id → project_id → team_id → workspace_id →
 * user_id → api_key_id`. This tree's `Tenancy` has no separate organization or
 * team tier (`tenantId` IS the broadest scope, and `AuthContext.subject` is the
 * api-key id), so the chain collapses to the five below with the same ordering
 * and the same "" fallback.
 */
export function governedActionTenantKey(auth: AuthContext | null | undefined): string {
  if (auth === null || auth === undefined) return "";
  const { tenantId, projectId, workspaceId, userId } = auth.tenancy;
  return (tenantId || projectId || workspaceId || userId || auth.subject || "").trim();
}

/**
 * Rust `tenant_requires_declared_action_id`, verbatim:
 *
 *   - unset / empty              → OFF for every tenant (the default posture)
 *   - `1|true|yes|on|all|*`      → ON for every tenant
 *   - comma/whitespace-separated → ON only for the listed tenant keys
 *
 * A tenant key that is empty is never matched by a LIST (there is nothing to
 * match), but is still covered by the global forms — an unattributed credential
 * is exactly the one an operator running `all` wants to refuse.
 */
export function tenantRequiresDeclaredActionId(
  configured: string | undefined,
  tenantKey: string,
): boolean {
  const config = configured?.trim();
  if (config === undefined || config === "") return false;
  if (["1", "true", "yes", "on", "all", "*"].includes(config.toLowerCase())) return true;
  const key = tenantKey.trim();
  if (key === "") return false;
  return config
    .split(/[,\s]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "")
    .some((entry) => entry === key);
}

/**
 * Rust `resolve_asset_action_id` (#522) — the governed-action id for one asset
 * request.
 *
 * Three outcomes, exactly the Rust `AssetActionIdOutcome`: a malformed header is
 * `400 invalid_agent_run_id_header`; an absent id with per-tenant enforcement ON
 * is `400 agent_run_id_required`; anything else proceeds with the (possibly
 * absent) id. An id is NEVER fabricated — a synthesized correlation id would
 * make an unjoinable action look joined, which is worse than admitting the gap.
 *
 * PORT-TODO(P: inventory-request-path.md §governed actions): the low-cardinality
 * UNJOINABLE-ACTION METRIC (`record_unjoinable_action(tenant, surface)`) that
 * Rust increments on the absent-id branch is still deferred. Not a platform
 * limit — `@ferrogate/observability` already defines
 * `UnjoinableActionMetricTotal` and miniflare really emulates
 * `writeDataPoint` — but an OWNERSHIP one: it wants the single `TELEMETRY`
 * Analytics Engine dataset that `apps/gateway/wrangler.toml`'s "NOT DECLARED"
 * block reserves jointly for this sink, the metering sink and `apps/telemetry`,
 * and there is no local read-back to assert a row against. The ENFORCEMENT half
 * — the part with a wire-visible consequence — is ported here.
 */
function requestContext(c: Context<AssetEnv>): AssetRequestContext {
  const declared = c.req.header("x-ferrogate-agent-run-id")?.trim();
  if (declared !== undefined && declared !== "" && !AGENT_RUN_ID.test(declared)) {
    throw new HttpError(
      400,
      "invalid_agent_run_id_header",
      "x-ferrogate-agent-run-id must be 1-128 characters of [A-Za-z0-9_:.-] starting alphanumeric",
    );
  }

  const agentRunId = declared === undefined || declared === "" ? undefined : declared;
  if (agentRunId === undefined) {
    const configured = (c.env as { FG_REQUIRE_AGENT_RUN_ID?: string } | undefined)
      ?.FG_REQUIRE_AGENT_RUN_ID;
    if (tenantRequiresDeclaredActionId(configured, governedActionTenantKey(c.get("auth")))) {
      throw new HttpError(
        400,
        "agent_run_id_required",
        "this tenant requires a declared x-ferrogate-agent-run-id on governed agent traffic",
      );
    }
  }

  return { requestId: c.get("requestId") ?? "", agentRunId };
}

/**
 * The three `x-asset-signature*` headers → an {@link AssetSignatureInput},
 * ported from `server/assets.rs:638-651`.
 *
 * Absent `x-asset-signature` means an UNSIGNED publish, which is a labeled
 * state rather than a refusal. An unrecognised `x-asset-signature-format`
 * falls back to `minisign` exactly as Rust's `.unwrap_or(Minisign)` does — NOT
 * to "skip verification", which is the shape that would let a typo in a header
 * turn a signed publish into an unsigned one.
 */
function assetSignatureFromHeaders(headers: Headers): AssetSignatureInput | undefined {
  const material = headers.get("x-asset-signature");
  if (material === null || material.trim() === "") return undefined;
  const declaredFormat = headers.get("x-asset-signature-format");
  const keyId = headers.get("x-asset-signature-key-id")?.trim();
  return {
    format:
      (declaredFormat === null ? undefined : parseSignatureFormat(declaredFormat)) ?? "minisign",
    material,
    ...(keyId !== undefined && keyId !== "" ? { keyId } : {}),
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

interface MultipartUploadFile {
  readonly name: string;
  readonly type: string;
  readonly size: number;
  stream(): ReadableStream<Uint8Array>;
}

function isMultipartUploadFile(value: unknown): value is MultipartUploadFile {
  if (typeof value !== "object" || value === null) return false;
  const file = value as Partial<MultipartUploadFile>;
  return (
    typeof file.name === "string" &&
    typeof file.size === "number" &&
    Number.isSafeInteger(file.size) &&
    file.size >= 0 &&
    typeof file.stream === "function"
  );
}

/** Decode the OpenAI multipart upload into the asset service's narrow input. */
async function fileUploadBody(
  c: Context<AssetEnv>,
): Promise<{
  size_bytes: number;
  stream: () => ReadableStream<Uint8Array>;
  contentType: string;
  metadata: { filename: string; purpose: string };
}> {
  let form: FormData;
  try {
    form = await c.req.formData();
  } catch {
    throw new HttpError(
      400,
      "invalid_multipart",
      "request body is not a readable multipart/form-data document",
    );
  }
  const purpose = form.get("purpose");
  const upload = form.get("file") as unknown;
  if (
    typeof purpose !== "string" ||
    purpose.trim() === "" ||
    purpose.length > 64 ||
    !isMultipartUploadFile(upload)
  ) {
    throw new HttpError(
      400,
      "invalid_request",
      "multipart uploads require a non-empty purpose and a file field",
    );
  }
  const filename = upload.name.trim();
  if (filename === "" || filename.length > 512) {
    throw new HttpError(400, "invalid_request", "file must have a filename of 1-512 characters");
  }
  try {
    return {
      size_bytes: upload.size,
      stream: () => upload.stream(),
      contentType: upload.type || "application/octet-stream",
      metadata: { filename, purpose: purpose.trim() },
    };
  } catch {
    throw new HttpError(400, "invalid_request", "could not read the uploaded file");
  }
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
  /**
   * Ports resolved from the REQUEST's Worker bindings, merged over
   * {@link AssetRouteModuleOptions.deps}.
   *
   * This exists for the same reason `inferenceRouteModule` takes `models` as a
   * factory: the route module is built ONCE at module scope, while `env.ASSETS`
   * (and the S3 credentials the presigner needs) only exist per request. The
   * built {@link AssetService} is memoized on the `env` OBJECT — a `WeakMap`,
   * never a plain field — so two concurrent requests each see their own
   * bindings and neither can observe the other's, while the service is still
   * constructed once per isolate.
   *
   * Pass {@link assetDepsFromEnv} at the composition root. With neither this
   * nor `deps` the offline in-memory defaults apply, which is what makes the
   * unit suites binding-free.
   */
  readonly depsFromEnv?: ((env: Record<string, unknown>) => Partial<AssetServiceDeps>) | undefined;
  readonly caller?: AssetCallerResolver | undefined;
  readonly entitlements?: AssetEntitlementsPort | undefined;
}

// ---------------------------------------------------------------------------
// Binding-resolved ports
// ---------------------------------------------------------------------------

/**
 * Worker bindings the asset object path reads.
 *
 * `ASSETS` is the R2 bucket. The five `ASSET_S3_*` entries are what the
 * PRESIGNED family needs and the bucket binding cannot supply — see
 * {@link sigV4PresignerFromEnv}.
 */
export interface AssetObjectBindings {
  /** `[[r2_buckets]] binding = "ASSETS"`. Holds the bytes of every hosted asset. */
  readonly ASSETS?: unknown;
  /** `https://<account_id>.r2.cloudflarestorage.com` — R2's **S3** endpoint. */
  readonly ASSET_S3_ENDPOINT?: string;
  /** Bucket name as the S3 API addresses it. */
  readonly ASSET_S3_BUCKET?: string;
  /** R2 is always `auto`; configurable for an S3-compatible deployment. */
  readonly ASSET_S3_REGION?: string;
  /** SECRET (`wrangler secret put`), never a plaintext var. */
  readonly ASSET_S3_ACCESS_KEY_ID?: string;
  /** SECRET (`wrangler secret put`), never a plaintext var. */
  readonly ASSET_S3_SECRET_ACCESS_KEY?: string;
  /** Optional STS session token, for a temporary credential. */
  readonly ASSET_S3_SESSION_TOKEN?: string;
}

/** Structural check for a live `R2Bucket` — the port is deliberately R2-shaped. */
function isAssetObjectStore(value: unknown): value is AssetObjectStore {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<AssetObjectStore>;
  return (
    typeof candidate.put === "function" &&
    typeof candidate.get === "function" &&
    typeof candidate.head === "function" &&
    typeof candidate.delete === "function"
  );
}

function nonEmpty(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

/**
 * The production {@link AssetPresigner}, or `null`.
 *
 * PLATFORM FACT, not a shortcut: the Workers `R2Bucket` binding has no presign
 * method. R2 presigned URLs are an **S3-API** feature (SigV4 over
 * `https://<account_id>.r2.cloudflarestorage.com`), so they need an S3 access
 * key pair that the bucket binding does not carry and cannot derive. All five
 * required values must be bound; a partial set yields `null` and the presign
 * family keeps answering `503 asset_bucket_unavailable`, which is the Rust
 * unconfigured posture. Half-configuring must never produce a URL the bucket
 * will reject.
 */
export function sigV4PresignerFromEnv(env: AssetObjectBindings): SigV4Presigner | null {
  const endpoint = nonEmpty(env.ASSET_S3_ENDPOINT);
  const bucket = nonEmpty(env.ASSET_S3_BUCKET);
  const accessKeyId = nonEmpty(env.ASSET_S3_ACCESS_KEY_ID);
  const secretAccessKey = nonEmpty(env.ASSET_S3_SECRET_ACCESS_KEY);
  if (
    endpoint === undefined ||
    bucket === undefined ||
    accessKeyId === undefined ||
    secretAccessKey === undefined
  ) {
    return null;
  }
  const sessionToken = nonEmpty(env.ASSET_S3_SESSION_TOKEN);
  return new SigV4Presigner({
    endpoint,
    bucket,
    // R2's S3 API is always `auto`; the var exists for S3-compatible targets.
    region: nonEmpty(env.ASSET_S3_REGION) ?? "auto",
    accessKeyId,
    secretAccessKey,
    ...(sessionToken !== undefined ? { sessionToken } : {}),
  });
}

/**
 * Worker bindings → asset ports. The composition root's half of the R2 wiring.
 *
 * Each port is decided on its OWN evidence, never all-or-nothing:
 *
 *  - `ASSETS` bound ⇒ the real bucket holds the bytes. Absent ⇒
 *    `InMemoryAssetObjectStore`, whose contents die with the isolate, so a push
 *    appears to succeed and a later read 404s. That is a local-dev posture, not
 *    a deployment one.
 *  - the five `ASSET_S3_*` values bound ⇒ {@link SigV4Presigner}. Absent ⇒
 *    `UnavailablePresigner` ⇒ `503 asset_bucket_unavailable`.
 *  - `presignEnabled` is turned on ONLY when BOTH hold. A presigned URL against
 *    a bucket the gateway is not also reading from would stage bytes the commit
 *    step could never find, and a bucket with no signing credentials cannot
 *    issue one at all — so the flag tracks the conjunction, not either half.
 *
 *  - the `ASSET_SCANNER*` vars ⇒ the configured malware-scan backend
 *    (`./scan.ts`, the port of Rust `AssetScanConfig::from_env`). Absent ⇒ the
 *    offline {@link BuiltinEicarScreener} `buildAssetService` already defaults
 *    to, which is the Rust unconfigured posture. `assetScreenerFromEnv` returns
 *    `null` for that case rather than re-supplying the default, so the
 *    fallback stays in exactly one place.
 *
 *  - `DB` bound (the TENANT D1) ⇒ {@link D1AssetMetadataStore}: the asset
 *    REGISTRY — `stored_assets` + `asset_channels` — is durable. Absent ⇒ the
 *    in-isolate `InMemoryAssetMetadataStore`, whose rows die with the isolate.
 *    This is the half `docs/rewrite/parity-audit-storage.md` §4.8 found
 *    missing, and it is the more dangerous half of the two: the BYTES were
 *    already durable in R2, so without it a published asset's object outlives
 *    the row that finds it (an unresolvable `latest`), and a YANK — the kill
 *    switch for a bad artifact — does not survive a deploy. `test/assets/
 *    wiring.test.ts` fails if this line is removed.
 *
 * `DB` is the TENANT database because `stored_assets`/`asset_channels` are in
 * `sql/d1-ts/tenant/`; a store pointed at `CONTROL_DB` would fail loudly with
 * `no such table`, which is the migration split working as designed.
 */
export function assetDepsFromEnv(env: Record<string, unknown>): Partial<AssetServiceDeps> {
  const bindings = env as AssetObjectBindings;
  const objects = isAssetObjectStore(bindings.ASSETS) ? bindings.ASSETS : undefined;
  const presigner = sigV4PresignerFromEnv(bindings);
  // Stage (4) of the Rust screening order, then stage (2) IN FRONT of it:
  // `withSignatureVerification` wraps whichever scanner was selected, so a
  // `require_signature` refusal happens before the scanner is consulted, which
  // is the Rust ordering. With neither publisher keys nor the requirement set
  // it returns its argument by identity, so this line is inert by default —
  // and `?? new BuiltinEicarScreener()` matches `buildAssetService`'s own
  // fallback, so the composed screener is never built over a DIFFERENT inner
  // one than the service would have used.
  const scanScreener = assetScreenerFromEnv(env as AssetScannerBindings);
  const inner = scanScreener ?? new BuiltinEicarScreener();
  const signed = withSignatureVerification(inner, env as SignaturePolicyBindings);
  // #740, the LAST stage: `signature-screener.ts` → scanner → guardrail, which
  // is the order the issue asks for and the order that costs least — a push
  // refused for a bad signature never pays for a detector pass. Like
  // `withSignatureVerification` this returns its argument BY IDENTITY when no
  // guardrail policy is configured.
  const composed = withAssetGuardrailScreening(signed, env);
  // Both decorators return their argument BY IDENTITY when unconfigured. That
  // case falls back to the existing `null ⇒ buildAssetService supplies the
  // default` contract, so the default screener keeps living in exactly one
  // place.
  const screener = composed === inner ? scanScreener : composed;
  const metadata = assetMetadataStoreFromEnv(env);
  // #736: the `static_site` bundle file index lives in the SAME tenant D1 as
  // `stored_assets`, so it is bound exactly when the metadata store is. Absent
  // ⇒ the service's in-memory index, which matches the in-memory metadata
  // fallback beside it: the two halves of a bundle version are never split
  // across a durable store and an isolate-local one.
  const bundles = assetBundleIndexStoreFromEnv(env);
  const audit = assetAuditSinkFromEnv(env);
  const objectStoreEnabled = objects !== undefined || devInMemoryPortsEnabled(env);
  // #262 egress governance (finding D4). ALWAYS supplied, never conditional on
  // a binding: the deny gate is what enforces a configured byte budget, and
  // making it depend on `BILLING_DB` would mean an operator who has not wired
  // billing gets unmetered AND uncapped bandwidth — the exact defect D4 named.
  // Only the METER degrades without a billing database.
  const pricePerGb = assetEgressPricePerGb();
  const egress = {
    counters: assetEgressCountersFromEnv(env),
    meter: assetEgressMeterFromEnv(env) ?? NO_ASSET_EGRESS_METER,
    ...(pricePerGb !== undefined ? { pricePerGb } : {}),
  };
  return {
    ...(objects !== undefined ? { objects } : {}),
    ...(metadata !== null ? { metadata } : {}),
    ...(bundles !== null ? { bundles } : {}),
    ...(audit !== null ? { audit } : {}),
    ...(presigner !== null ? { presigner } : {}),
    ...(screener !== null ? { screener } : {}),
    egress,
    limits: {
      objectStoreEnabled,
      ...(objects !== undefined && presigner !== null ? { presignEnabled: true } : {}),
    },
  };
}

/**
 * The repo's existing "this is a developer's machine" switch —
 * `FG_DEV_IN_MEMORY_PORTS`, the same var `apps/mcp` and `apps/agent-runtime`
 * declare, and which `docs/rewrite/CLOUD-VERIFICATION.md` §B1 requires be
 * overridden to `"0"` for the live deploy.
 *
 * Exactly `"1"` opens the in-memory object store; anything else (including
 * absent, which is the gateway's committed posture — this Worker declares no
 * such var) leaves an unbound `ASSETS` binding refusing with
 * `503 asset_bucket_unavailable`.
 *
 * The polarity is the point. It is NOT read as "is this production?" — it is
 * read as "did somebody SAY in-memory is acceptable here?", so forgetting to
 * set anything yields the safe answer rather than the convenient one.
 */
function devInMemoryPortsEnabled(env: Record<string, unknown>): boolean {
  return String((env as { FG_DEV_IN_MEMORY_PORTS?: unknown }).FG_DEV_IN_MEMORY_PORTS ?? "") === "1";
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

/** The five OpenAI-compatible `/v1/files` operations. */
export const ORDERED_FILE_OPERATION_IDS = [
  "listFiles",
  "createFile",
  "getFile",
  "getFileContent",
  "deleteFile",
] as const;

export function buildAssetService(deps?: Partial<AssetServiceDeps>): AssetService {
  return new AssetService({
    objects: deps?.objects ?? new InMemoryAssetObjectStore(),
    metadata: deps?.metadata ?? new InMemoryAssetMetadataStore(),
    presigner: deps?.presigner ?? new UnavailablePresigner(),
    screener: deps?.screener ?? new BuiltinEicarScreener(),
    audit: deps?.audit ?? new InMemoryAssetAuditSink(),
    bundles: deps?.bundles ?? new InMemoryAssetBundleIndexStore(),
    limits: deps?.limits,
    now: deps?.now,
  });
}

/** The `RouteModule` `createGatewayApp({ modules })` mounts. */
export function assetRouteModule(options: AssetRouteModuleOptions = {}): RouteModule {
  /**
   * The service, when it does not depend on request bindings. Built once, as
   * before — `options.service` wins, then a `deps`-only module.
   */
  const fixed =
    options.service ?? (options.depsFromEnv === undefined ? buildAssetService(options.deps) : null);

  /**
   * Otherwise: one service per `env` OBJECT, memoized on it. Same device as
   * `modelsFromEnv` / the metering backend resolver, and for the same reason —
   * a module-scoped "current env" slot would be last-write-wins under
   * concurrency, which for an object store means one tenant's push landing in
   * whatever bucket the other request was holding.
   */
  const byEnv = new WeakMap<object, AssetService>();
  const serviceFor = (c: Context<AssetEnv>): AssetService => {
    if (fixed !== null) {
      return fixed;
    }
    const env = (c.env ?? {}) as Record<string, unknown>;
    const cached = byEnv.get(env);
    if (cached !== undefined) {
      return cached;
    }
    const built = buildAssetService({
      ...options.deps,
      ...options.depsFromEnv?.(env),
    });
    byEnv.set(env, built);
    return built;
  };

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
    operationIds: [...ORDERED_ASSET_OPERATION_IDS, ...ORDERED_FILE_OPERATION_IDS],
    register(router: GatewayRouter): void {
      /**
       * Every asset operation goes through here, and the `finally` is why:
       * the durable audit sink BUFFERS during the handler (its `record` is
       * synchronous at 24 call sites in `service.ts`) and commits exactly once
       * per request. A `finally` rather than a trailing statement because the
       * audit row an operator most wants is the one on the REFUSED request —
       * `403 no_asset_hosting`, `409 asset_version_immutable`,
       * `413 payload_too_large` — and every one of those leaves this function
       * by `throw`.
       *
       * The flush is AWAITED, not `waitUntil`-ed: `c.executionCtx` throws when
       * the app is driven by `app.request(...)`, and an audit trail that exists
       * only under one of the two call styles is exactly the kind of seam this
       * codebase has shipped unmounted before. Asset operations already pay an
       * R2 round trip, so one D1 `batch()` is not the cost that matters here.
       */
      const on = (
        operationId: string,
        handler: (c: Context<AssetEnv>) => Promise<Response>,
      ): void => {
        router.register(operationId, async (c) => {
          const context = c as unknown as Context<AssetEnv>;
          try {
            return await handler(context);
          } finally {
            await serviceFor(context).flushAudit();
          }
        });
      };

      // --- reserved literals ------------------------------------------------

      on("getAssetStorageSummary", async (c) =>
        render(await serviceFor(c).storageSummary(await caller(c))),
      );

      on("listWithheldAssets", async (c) => {
        const query = parseOrThrow(withheldQuerySchema, c.req.query());
        return render(await serviceFor(c).listWithheldAssets(await caller(c), query));
      });

      // --- presign family ---------------------------------------------------

      on("createAssetUploadIntent", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const body = await controlBody(c, presignUploadIntentRequestSchema);
        return render(
          await serviceFor(c).createUploadIntent(
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
          await serviceFor(c).commitUpload(await caller(c), refOf(params), body, requestContext(c)),
        );
      });

      on("abortAssetUpload", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const body = await controlBody(c, presignAbortRequestSchema);
        return render(
          await serviceFor(c).abortUpload(await caller(c), refOf(params), body, requestContext(c)),
        );
      });

      on("getAssetDownloadUrl", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        return render(
          await serviceFor(c).downloadUrl(await caller(c), refOf(params), requestContext(c)),
        );
      });

      // --- OpenAI Files projection ------------------------------------------

      on("createFile", async (c) => {
        // Resolve auth and the governed-action context before reading multipart
        // bytes, matching the inline asset push ordering.
        const resolved = await caller(c);
        const context = requestContext(c);
        const body = await fileUploadBody(c);
        return render(await serviceFor(c).createFile(resolved, body, context));
      });

      on("listFiles", async (c) => {
        const query = parseOrThrow(fileListQuerySchema, c.req.query());
        return render(await serviceFor(c).listFiles(await caller(c), query));
      });

      on("getFile", async (c) => {
        const params = parseOrThrow(fileIdParamsSchema, c.req.param());
        return render(await serviceFor(c).getFile(await caller(c), params.file_id));
      });

      on("getFileContent", async (c) => {
        const params = parseOrThrow(fileIdParamsSchema, c.req.param());
        return renderBytes(
          await serviceFor(c).fileContent(
            await caller(c),
            params.file_id,
            { headers: c.req.raw.headers, method: c.req.method },
            requestContext(c),
          ),
        );
      });

      on("deleteFile", async (c) => {
        const params = parseOrThrow(fileIdParamsSchema, c.req.param());
        return render(
          await serviceFor(c).deleteFile(await caller(c), params.file_id, requestContext(c)),
        );
      });

      // --- reserved third/fourth segments -----------------------------------

      on("getAssetManifest", async (c) => {
        const params = parseOrThrow(assetNameParamsSchema, c.req.param());
        return render(await serviceFor(c).manifest(await caller(c), nameOf(params)));
      });

      on("listAssetChannels", async (c) => {
        const params = parseOrThrow(assetNameParamsSchema, c.req.param());
        return render(await serviceFor(c).listChannels(await caller(c), nameOf(params)));
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
          await serviceFor(c).putChannel(
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
          await serviceFor(c).deleteChannel(
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
          await serviceFor(c).setVersionYank(
            await caller(c),
            refOf(params),
            true,
            requestContext(c),
          ),
        );
      });

      on("unyankAssetVersion", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        return render(
          await serviceFor(c).setVersionYank(
            await caller(c),
            refOf(params),
            false,
            requestContext(c),
          ),
        );
      });

      on("promoteAssetVisibility", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const query = parseOrThrow(platformQuerySchema, c.req.query());
        const body = await controlBody(c, assetVisibilityPromotionRequestSchema);
        return render(
          await serviceFor(c).promoteVisibility(
            await caller(c),
            { ...refOf(params), variant: query.platform ?? "" },
            body,
            requestContext(c),
          ),
        );
      });

      // --- generic arms -----------------------------------------------------

      on("listAssets", async (c) => render(await serviceFor(c).listAssets(await caller(c))));

      on("listAssetsByType", async (c) => {
        const params = parseOrThrow(assetTypeParamsSchema, c.req.param());
        return render(await serviceFor(c).listAssets(await caller(c), params.asset_type));
      });

      // #262 egress governance (data-plane certification finding D4) — LIVE.
      //
      // Rust `handle_asset_pull` (`server/assets.rs:1114-1136`) runs the deny
      // gate and the meter around the download, and both are now ported into
      // `AssetService.pullAsset` (`egress.ts` + `service.ts#egressDenial` /
      // `#recordEgress`) rather than into this handler, so the presigned
      // download path gets the same gate rather than a second copy of it.
      //
      // The composition is `assetDepsFromEnv`, which supplies
      // `egress: { counters, meter, pricePerGb }` UNCONDITIONALLY — see the
      // comment there for why the gate must not depend on a billing binding.
      //
      // `requestContext(c)` is threaded in below because the meter writes the
      // PULL-side audit row (`asset.pull`), which carries the request id and
      // the #522 `agent_run_id` correlation exactly as the push/delete rows do.
      on("getAsset", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const query = parseOrThrow(pullQuerySchema, c.req.query());
        return renderBytes(
          await serviceFor(c).pullAsset(
            await caller(c),
            { assetType: params.asset_type, name: params.name, reference: params.version },
            {
              platform: query.platform,
              // #736: one file of an expanded `static_site` bundle. Threaded
              // through the SAME operation, so channels/ranges/yank/variants
              // are the ones already documented for `getAsset`.
              bundlePath: query.path,
              headers: c.req.raw.headers,
              method: c.req.method,
            },
            requestContext(c),
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
          await serviceFor(c).putAsset(
            resolved,
            { ...refOf(params), variant: query.platform ?? "" },
            {
              contentType: c.req.header("content-type") ?? undefined,
              content,
              channel: query.channel,
              signature: assetSignatureFromHeaders(c.req.raw.headers),
            },
            context,
          ),
        );
      });

      on("deleteAsset", async (c) => {
        const params = parseOrThrow(assetVersionParamsSchema, c.req.param());
        const query = parseOrThrow(platformQuerySchema, c.req.query());
        return render(
          await serviceFor(c).deleteAsset(
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
