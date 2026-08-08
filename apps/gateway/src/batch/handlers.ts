import {
  type BatchStatus,
  type BatchStore,
  D1BatchStore,
  type StoredBatch,
} from "@ferrogate/storage";
/**
 * The `/v1/batches` API surface.
 *
 * Slice 1 owns request validation, tenant-scoped persistence, and the OpenAI
 * job-state projection. It deliberately does not execute JSONL requests.
 */
import type { Context } from "hono";
import { z } from "zod";
import { D1AssetMetadataStore, assetDatabaseFromTenantResolver } from "../assets/d1.js";
import { randomHex128 } from "../assets/hash.js";
import {
  type AssetCaller,
  type AssetCallerResolver,
  buildAssetService,
  defaultCallerResolver,
} from "../assets/index.js";
import { isAuthFailure } from "../assets/ports.js";
import { HttpError } from "../middleware/errors.js";
import type { GatewayEnv } from "../ports.js";
import type { GatewayRouter, RouteModule } from "../routes/index.js";
import { tenantDatabaseOf } from "../tenancy/middleware.js";
import { enqueueBatchJob } from "./queue.js";

/**
 * Endpoints the executor can actually run.
 *
 * `/v1/completions` was accepted by slice 1 and is REMOVED here (#698 slice 2).
 * The gateway's inference module serves chat/embeddings/responses and has no
 * legacy completions operation, so a batch created against it could be accepted
 * and then never executed — a job that sits at `validating` until its 24-hour
 * window expires is a worse answer to the caller than a 400 at creation time.
 */
export const BATCH_ENDPOINTS = ["/v1/chat/completions", "/v1/embeddings"] as const;

type BatchEndpoint = (typeof BATCH_ENDPOINTS)[number];

/** The OpenAI wire projection of a stored batch row. */
export interface OpenAIBatch {
  readonly id: string;
  readonly object: "batch";
  readonly endpoint: string;
  readonly errors: null;
  readonly input_file_id: string;
  readonly completion_window: string;
  readonly status: BatchStatus;
  readonly output_file_id: string | null;
  readonly error_file_id: string | null;
  readonly created_at: number;
  readonly in_progress_at: number | null;
  readonly expires_at: number;
  readonly finalizing_at: number | null;
  readonly completed_at: number | null;
  readonly failed_at: number | null;
  readonly expired_at: number | null;
  readonly cancelling_at: number | null;
  readonly cancelled_at: number | null;
  readonly request_counts: {
    readonly total: number;
    readonly completed: number;
    readonly failed: number;
  };
  readonly metadata: Readonly<Record<string, string>>;
}

interface BatchCreateRequest {
  readonly input_file_id: string;
  readonly endpoint: string;
  readonly completion_window: string;
  readonly metadata?: Readonly<Record<string, string>> | undefined;
}

const batchCreateSchema = z
  .object({
    input_file_id: z.string().min(1),
    endpoint: z.string().min(1),
    completion_window: z.string().min(1),
    metadata: z.record(z.string()).optional(),
  })
  .strict();

const batchListSchema = z
  .object({
    after: z.string().min(1).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  })
  .strict();

export interface BatchRouteModuleOptions {
  /** Fixed store and file service ports for request-level tests. */
  readonly store?: BatchStore | undefined;
  readonly fileService?: ReturnType<typeof buildAssetService> | undefined;
  readonly caller?: AssetCallerResolver | undefined;
  readonly now?: (() => number) | undefined;
}

interface BatchResources {
  readonly store: BatchStore;
  readonly fileService: ReturnType<typeof buildAssetService>;
}

function unixNow(now: (() => number) | undefined): number {
  return now?.() ?? Math.floor(Date.now() / 1000);
}

/** `c.executionCtx` without the throw (`app.request()` creates none). */
function executionContextOf(
  c: Context<GatewayEnv>,
): { waitUntil(work: Promise<unknown>): void } | undefined {
  try {
    return c.executionCtx;
  } catch {
    return undefined;
  }
}

function nullTimestamp(value: number | undefined): number | null {
  return value ?? null;
}

function batchObject(batch: StoredBatch): OpenAIBatch {
  return {
    id: batch.id,
    object: "batch",
    endpoint: batch.endpoint,
    errors: null,
    input_file_id: batch.inputFileId,
    completion_window: batch.completionWindow,
    status: batch.status,
    output_file_id: batch.outputFileId ?? null,
    error_file_id: batch.errorFileId ?? null,
    created_at: batch.createdAtUnix,
    in_progress_at: nullTimestamp(batch.inProgressAtUnix),
    expires_at: batch.expiresAtUnix,
    finalizing_at: nullTimestamp(batch.finalizingAtUnix),
    completed_at: nullTimestamp(batch.completedAtUnix),
    failed_at: nullTimestamp(batch.failedAtUnix),
    expired_at: nullTimestamp(batch.expiredAtUnix),
    cancelling_at: nullTimestamp(batch.cancellingAtUnix),
    cancelled_at: nullTimestamp(batch.cancelledAtUnix),
    request_counts: { ...batch.requestCounts },
    metadata: { ...batch.metadata },
  };
}

function json<T>(body: T, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function raiseMissingBatch(batchId: string): never {
  throw new HttpError(404, "not_found", `batch ${batchId} was not found`);
}

function requiredBatchId(value: string | undefined): string {
  if (value === undefined || value === "") {
    throw new HttpError(400, "invalid_request", "batch_id is required");
  }
  return value;
}

function parseBodyFailure(error: unknown): never {
  const message = error instanceof Error ? error.message : "request body is not valid JSON";
  throw new HttpError(400, "invalid_request", message);
}

async function createBody(c: Context<GatewayEnv>): Promise<BatchCreateRequest> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch (error) {
    return parseBodyFailure(error);
  }
  const parsed = batchCreateSchema.safeParse(raw);
  if (!parsed.success) {
    throw new HttpError(
      400,
      "invalid_request",
      parsed.error.issues
        .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
        .join("; "),
    );
  }
  return parsed.data;
}

function validateEndpoint(endpoint: string): BatchEndpoint {
  if ((BATCH_ENDPOINTS as readonly string[]).includes(endpoint)) return endpoint as BatchEndpoint;
  throw new HttpError(
    400,
    "invalid_request",
    `endpoint must be one of ${BATCH_ENDPOINTS.join(", ")}`,
  );
}

function validateCompletionWindow(completionWindow: string): void {
  if (completionWindow !== "24h") {
    throw new HttpError(400, "invalid_request", 'completion_window must be "24h"');
  }
}

async function resolvedCaller(
  c: Context<GatewayEnv>,
  resolveCaller: AssetCallerResolver,
): Promise<AssetCaller> {
  const resolved = await resolveCaller(c as Parameters<AssetCallerResolver>[0]);
  if (isAuthFailure(resolved)) {
    throw new HttpError(resolved.status, resolved.code, resolved.message);
  }
  return resolved;
}

function fileValidationFailure(fileId: string): never {
  throw new HttpError(404, "not_found", `input file ${fileId} was not found`);
}

/**
 * Build the per-request durable ports. Both stores use the authenticated
 * tenant accessor; neither can fall back to CONTROL_DB or a shared tenant.
 */
async function resourcesFor(
  c: Context<GatewayEnv>,
  options: BatchRouteModuleOptions,
): Promise<BatchResources> {
  if (options.store !== undefined && options.fileService !== undefined) {
    return { store: options.store, fileService: options.fileService };
  }

  const accessor = tenantDatabaseOf(c);
  const handle = await accessor.handle();
  return {
    store: options.store ?? new D1BatchStore(handle),
    fileService:
      options.fileService ??
      buildAssetService({
        metadata: new D1AssetMetadataStore(
          assetDatabaseFromTenantResolver(() => accessor.handle()),
        ),
      }),
  };
}

function renderList(data: readonly StoredBatch[], hasMore: boolean): Response {
  return json({ object: "list", data: data.map(batchObject), has_more: hasMore });
}

export function batchRouteModule(options: BatchRouteModuleOptions = {}): RouteModule {
  const resolveCaller = options.caller ?? defaultCallerResolver();
  const now = () => unixNow(options.now);

  return {
    operationIds: ["createBatch", "retrieveBatch", "cancelBatch", "listBatches"],
    register(router: GatewayRouter): void {
      router.register("createBatch", async (c) => {
        const caller = await resolvedCaller(c, resolveCaller);
        const body = await createBody(c);
        const endpoint = validateEndpoint(body.endpoint);
        validateCompletionWindow(body.completion_window);
        const resources = await resourcesFor(c, options);
        const file = await resources.fileService.getFile(caller, body.input_file_id);
        if (!file.ok) fileValidationFailure(body.input_file_id);

        const createdAtUnix = now();
        const batch: StoredBatch = {
          id: `batch_${randomHex128()}`,
          tenantId: caller.tenantId,
          inputFileId: body.input_file_id,
          endpoint,
          completionWindow: body.completion_window,
          status: "validating",
          requestCounts: { total: 0, completed: 0, failed: 0 },
          metadata: { ...(body.metadata ?? {}) },
          createdAtUnix,
          expiresAtUnix: createdAtUnix + 24 * 60 * 60,
          // The scope chain the executor re-applies the budget ladder against.
          // It has no request and therefore no `AuthContext`, so this is the
          // only surviving record of WHO is spending. See `./governance.ts`.
          apiKeyId: caller.apiKeyId ?? "",
          projectId: caller.projectId,
          nextLineIndex: 0,
          attemptCount: 0,
        };
        await resources.store.create(batch);

        // The slice-2 executor, asked for on `waitUntil` so the client is not
        // held while a queue send happens. With no `BATCH_JOBS` binding this
        // is a documented no-op and the 1-minute Cron sweep picks the job up
        // instead — which is why it is fire-and-forget and never awaited into
        // the response.
        const enqueue = enqueueBatchJob(c.env, batch.tenantId, batch.id);
        const ctx = executionContextOf(c);
        if (ctx !== undefined) ctx.waitUntil(enqueue);
        else await enqueue;
        return json(batchObject(batch), 200);
      });

      router.register("retrieveBatch", async (c) => {
        const caller = await resolvedCaller(c, resolveCaller);
        const batchId = requiredBatchId(c.req.param("batch_id"));
        const resolved = await (await resourcesFor(c, options)).store.get(caller.tenantId, batchId);
        if (resolved === undefined) raiseMissingBatch(batchId);
        return json(batchObject(resolved));
      });

      router.register("listBatches", async (c) => {
        const caller = await resolvedCaller(c, resolveCaller);
        const parsed = batchListSchema.safeParse(c.req.query());
        if (!parsed.success) {
          throw new HttpError(
            400,
            "invalid_request",
            parsed.error.issues
              .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
              .join("; "),
          );
        }
        const result = await (await resourcesFor(c, options)).store.list(
          caller.tenantId,
          parsed.data.after,
          parsed.data.limit,
        );
        return renderList(result.data, result.hasMore);
      });

      router.register("cancelBatch", async (c) => {
        const caller = await resolvedCaller(c, resolveCaller);
        const batchId = requiredBatchId(c.req.param("batch_id"));
        const resources = await resourcesFor(c, options);
        const current = await resources.store.get(caller.tenantId, batchId);
        if (current === undefined) raiseMissingBatch(batchId);
        if (current.status === "cancelled") return json(batchObject(current));

        // Slice 2: the store decides between the two arms on the row's LEASE.
        // An unleased job has no tick running on it and is cancelled outright;
        // a leased one goes to `cancelling` and the executor that owns it
        // finishes the transition, so an abandoned job never publishes output.
        // Both are visible to the caller as OpenAI's own two-step.
        const cancelled = await resources.store.requestCancel(caller.tenantId, batchId, now());
        if (cancelled === undefined) {
          // A distinct refusal code, not `invalid_request`: the gateway maps
          // `invalid_request` to 400 everywhere else, and the fleet ratchet
          // (test 4.1) requires one status per refusal code across all Workers.
          throw new HttpError(409, "batch_not_cancellable", `batch ${batchId} cannot be cancelled`);
        }
        return json(batchObject(cancelled));
      });
    },
  };
}
