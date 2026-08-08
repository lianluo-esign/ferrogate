/**
 * The batch EXECUTOR — the thing slice 1 left a labelled seam for (#698).
 *
 * ```
 *   createBatch ──enqueue──▶ BATCH_JOBS queue ──▶ consumeBatchJobBatch
 *                                                       │
 *   [triggers] crons ──▶ sweepBatchExecution ────────────┤
 *                                                       ▼
 *                                                 runBatchTick
 *                       claim(lease) ─▶ admit ─▶ dispatch/poll ─▶ meter
 *                                              ─▶ results rows
 *                                              ─▶ output/error /v1/files
 *                                              ─▶ status transition ─▶ release
 * ```
 *
 * ## Two triggers, one tick, and why the lease is the whole design
 *
 * A queue message is the FAST path (a job starts within seconds of creation)
 * and the Cron is the RECOVERY path (a message that was never produced, a
 * consumer that died mid-job, a native job that has to be polled until the
 * provider finishes). Both call this same function, and both WILL sometimes
 * call it for the same job at the same time, because Queues are at-least-once
 * and the Cron does not know what the queue is doing.
 *
 * A batch line is a paid provider call, so "run it twice" is money, not a
 * duplicate row. {@link BatchStore.claim} is therefore a single guarded UPDATE
 * and everything below it runs only for the invocation that won. A tick that
 * dies without releasing leaves the lease to expire, which is what makes a
 * crashed executor recoverable without any liveness protocol.
 *
 * ## Why a tick is bounded, and what the cursor buys
 *
 * A Worker invocation has a wall-clock and CPU budget; a 50,000-line batch does
 * not fit in one. So a tick executes at most
 * {@link DEFAULT_MAX_LINES_PER_TICK} lines, writes each line's result to
 * `batch_request_results`, advances `next_line_index`, and hands the job back.
 * The cursor is the resume point AND — because the results table is keyed on
 * `(batch_id, line_index)` — the thing that makes a redelivered tick idempotent
 * rather than a doubled bill.
 *
 * ## THE GOVERNANCE POINT, because it is the point of the issue
 *
 * `#698` exists so that async bulk traffic goes through the SAME governance as
 * interactive traffic. That is not free off-request: `rateLimit()` is Hono
 * middleware and cannot be called here. `./governance.ts` composes the ladder
 * from the same primitives and this module calls it — budget/wallet before the
 * tick and every {@link BATCH_BUDGET_RECHECK_LINES} lines, residency per route
 * before any prompt leaves. A refusal ENDS the job (`failed`) with the refusal
 * recorded on the row, rather than silently skipping lines, because a batch
 * that quietly produced 12,000 of 50,000 outputs is worse than one that says
 * why it stopped.
 *
 * ## The retry rule, stated (the evals consumer's rule, restated for money)
 *
 *  - a line that cannot be PARSED becomes an error line. It cannot become valid
 *    on redelivery.
 *  - a line whose provider call fails becomes an error line and the job carries
 *    on. Retrying a whole tick because line 900 timed out would re-dispatch 899
 *    paid calls.
 *  - only a failure to PERSIST results or to publish the output file arms the
 *    queue's retry, because there the calls have already been paid for and the
 *    rows are the thing that survives.
 */
import {
  BATCH_TERMINAL_STATUSES,
  type BatchExecutionMode,
  type BatchRequestCounts,
  type BatchStatus,
  type BatchStore,
  D1BatchStore,
  type StoredBatch,
  type StoredBatchResult,
} from "@ferrogate/storage";
import { D1AssetMetadataStore, assetDatabaseFromTenantResolver } from "../assets/d1.js";
import {
  type AssetCaller,
  type AssetService,
  assetDepsFromEnv,
  buildAssetService,
  entitlementsFromEnv,
} from "../assets/index.js";
import { defaultAdapterRegistry } from "../inference/adapters.js";
import { modelsFromEnv } from "../inference/catalog.js";
import { dispatcherFromEnv } from "../inference/defaults.js";
import { readBoundedProviderBody } from "../inference/dispatch.js";
import type {
  InferenceBindings,
  InferenceOperation,
  PhysicalRoute,
  UpstreamDispatcher,
  Usage,
  UsageSink,
} from "../inference/ports.js";
import { usageFromResponseBody, usageProviderKindFor } from "../inference/usage.js";
import { type TenancyBindings, resolverForEnv } from "../tenancy/index.js";
import {
  BATCH_BUDGET_RECHECK_LINES,
  type BatchGovernance,
  type BatchRefusal,
  createBatchGovernance,
} from "./governance.js";
import {
  type BatchInputLine,
  batchErrorLine,
  batchOutputLine,
  jsonlLines,
  parseBatchInputLine,
  renderJsonl,
} from "./jsonl.js";
import {
  NATIVE_BATCH_COST_MULTIPLIER,
  type NativeBatchFamily,
  type NativeBatchFetch,
  cancelNativeBatch,
  downloadNativeBatchOutput,
  nativeBatchFamilyFor,
  nativeBatchSupportsEndpoint,
  pollNativeBatch,
  submitNativeBatch,
  uploadNativeBatchInput,
} from "./provider-native.js";

/** Lines one invocation will dispatch before handing the job back. */
export const DEFAULT_MAX_LINES_PER_TICK = 25;
/** How long a claim is held. Longer than a tick, shorter than the Cron gap × 2. */
export const DEFAULT_LEASE_SECONDS = 120;
/** Per-line upstream deadline. No client is waiting; a wedged provider is not. */
export const DEFAULT_LINE_TIMEOUT_MS = 60_000;
/** Ceiling on one provider response body. */
export const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
/** Ceiling on the input JSONL a tick will hold in memory. */
export const DEFAULT_MAX_INPUT_BYTES = 16 * 1024 * 1024;

/**
 * Which inference operation each accepted batch endpoint runs as.
 *
 * EXPORTED so `test/batch-executor.test.ts` can assert it is TOTAL over
 * `BATCH_ENDPOINTS`. An endpoint `createBatch` accepts but this map does not
 * cover is a job that is admitted and can never run — the exact defect that
 * removed `/v1/completions` from the accepted set in slice 2.
 */
export const OPERATION_FOR_ENDPOINT: Readonly<Record<string, InferenceOperation>> = {
  "/v1/chat/completions": "chat.completions",
  "/v1/embeddings": "embeddings",
};

/** What one tick did. The queue consumer and the Cron both report these. */
export interface BatchTickResult {
  readonly batchId: string;
  readonly status: BatchStatus | "unclaimed";
  readonly mode: BatchExecutionMode | "none";
  readonly executed: number;
  readonly failed: number;
  /** True when the tick could not persist and the delivery must be retried. */
  readonly retry: boolean;
  readonly detail?: string | undefined;
}

/** Every seam the tests replace. Production resolves each from `env`. */
export interface BatchExecutorDeps {
  readonly store?: ((env: unknown, tenantId: string) => Promise<BatchStore>) | undefined;
  readonly files?: ((env: unknown, tenantId: string) => Promise<AssetService>) | undefined;
  readonly caller?: ((env: unknown, batch: StoredBatch) => Promise<AssetCaller>) | undefined;
  readonly routeFor?: ((env: unknown, model: string) => PhysicalRoute | null) | undefined;
  readonly dispatcher?: ((env: unknown) => UpstreamDispatcher) | undefined;
  readonly governance?: ((env: unknown, batch: StoredBatch) => BatchGovernance) | undefined;
  readonly usage?: UsageSink | undefined;
  readonly http?: NativeBatchFetch | undefined;
  /** Unix SECONDS. */
  readonly now?: (() => number) | undefined;
  /** This invocation's lease identity. Defaults to a fresh random value. */
  readonly owner?: string | undefined;
  readonly maxLinesPerTick?: number | undefined;
  readonly leaseSeconds?: number | undefined;
  readonly timeoutMs?: number | undefined;
  readonly maxResponseBytes?: number | undefined;
  readonly maxInputBytes?: number | undefined;
  /** Slice 3. `false` pins every job to the local executor. */
  readonly nativePassthrough?: boolean | undefined;
}

interface ResolvedDeps {
  readonly storeFor: (env: unknown, tenantId: string) => Promise<BatchStore>;
  readonly filesFor: (env: unknown, tenantId: string) => Promise<AssetService>;
  readonly callerFor: (env: unknown, batch: StoredBatch) => Promise<AssetCaller>;
  readonly routeFor: (env: unknown, model: string) => PhysicalRoute | null;
  readonly dispatcherFor: (env: unknown) => UpstreamDispatcher;
  readonly governanceFor: (env: unknown, batch: StoredBatch) => BatchGovernance;
  readonly usage: UsageSink | undefined;
  readonly http: NativeBatchFetch;
  readonly now: () => number;
  readonly owner: string;
  readonly maxLinesPerTick: number;
  readonly leaseSeconds: number;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly maxInputBytes: number;
  readonly nativePassthrough: boolean;
}

async function tenantHandleFor(env: unknown, tenantId: string) {
  return resolverForEnv(env as TenancyBindings).forTenant(tenantId);
}

/**
 * The off-request equivalent of `handlers.ts::resourcesFor`.
 *
 * It composes the SAME service — `assetDepsFromEnv` for R2, screening and
 * audit, with the metadata store pinned to THIS tenant's database. Publishing
 * the output through the real asset service (rather than writing R2 keys
 * directly) is what keeps a batch's output inside the tenant's storage quota,
 * its screening policy and its audit trail, and what makes the output a real
 * `/v1/files` object the client can already fetch.
 */
async function defaultFileService(env: unknown, tenantId: string): Promise<AssetService> {
  const resolver = resolverForEnv(env as TenancyBindings);
  return buildAssetService({
    ...assetDepsFromEnv(env as Record<string, unknown>),
    metadata: new D1AssetMetadataStore(
      assetDatabaseFromTenantResolver(() => resolver.forTenant(tenantId)),
    ),
  });
}

/**
 * The synthesized caller.
 *
 * `defaultCallerResolver` reads an `AuthContext` off a Hono context and there
 * is none here, so the caller is rebuilt from what the batch row records: its
 * tenant, its creating credential, and that tenant's CURRENT entitlements —
 * re-read rather than persisted, so a tenant whose hosting was revoked after
 * the batch was created cannot still publish output.
 *
 * The scope set is exactly `assets.write` + `assets.read`: the executor writes
 * the two output files and reads the input, and nothing else. It is NOT the
 * creating key's full scope set, which would give a background job more
 * authority than the work needs.
 */
async function defaultCaller(env: unknown, batch: StoredBatch): Promise<AssetCaller> {
  const grants = await entitlementsFromEnv(env as never).resolve(batch.tenantId);
  return {
    tenantId: batch.tenantId,
    projectId: batch.projectId,
    scopes: ["assets.read", "assets.write"],
    assetStorageQuotaBytes: grants.assetStorageQuotaBytes,
    assetMaxObjectBytes: grants.assetMaxObjectBytes,
    assetHostingEnabled: grants.assetHostingEnabled,
    apiKeyId: batch.apiKeyId ?? "",
  };
}

function resolveDeps(deps: BatchExecutorDeps): ResolvedDeps {
  return {
    storeFor:
      deps.store ??
      (async (env, tenantId) => new D1BatchStore(await tenantHandleFor(env, tenantId))),
    filesFor: deps.files ?? defaultFileService,
    callerFor: deps.caller ?? defaultCaller,
    routeFor:
      deps.routeFor ?? ((env, model) => modelsFromEnv(env as InferenceBindings).resolve(model)),
    dispatcherFor: deps.dispatcher ?? ((env) => dispatcherFromEnv(env as InferenceBindings)),
    governanceFor: deps.governance ?? ((env, batch) => createBatchGovernance(env, batch)),
    usage: deps.usage,
    http: deps.http ?? ((input, init) => fetch(input, init)),
    now: deps.now ?? (() => Math.floor(Date.now() / 1000)),
    owner: deps.owner ?? `tick_${crypto.randomUUID()}`,
    maxLinesPerTick: deps.maxLinesPerTick ?? DEFAULT_MAX_LINES_PER_TICK,
    leaseSeconds: deps.leaseSeconds ?? DEFAULT_LEASE_SECONDS,
    timeoutMs: deps.timeoutMs ?? DEFAULT_LINE_TIMEOUT_MS,
    maxResponseBytes: deps.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    maxInputBytes: deps.maxInputBytes ?? DEFAULT_MAX_INPUT_BYTES,
    nativePassthrough: deps.nativePassthrough ?? true,
  };
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

async function publishJsonl(
  files: AssetService,
  caller: AssetCaller,
  batchId: string,
  suffix: "output" | "error",
  text: string,
): Promise<string | undefined> {
  const bytes = new TextEncoder().encode(text);
  const created = await files.createFile(
    caller,
    {
      size_bytes: bytes.byteLength,
      stream: () =>
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(bytes);
            controller.close();
          },
        }),
      contentType: "application/jsonl",
      metadata: { filename: `${batchId}_${suffix}.jsonl`, purpose: "batch_output" },
    },
    { requestId: `${batchId}_${suffix}` },
  );
  return created.ok ? created.body.id : undefined;
}

/** Assemble both files from the durable result rows and finish the job. */
async function finalize(
  store: BatchStore,
  files: AssetService,
  caller: AssetCaller,
  batch: StoredBatch,
  resolved: ResolvedDeps,
): Promise<BatchTickResult> {
  const nowUnix = resolved.now();
  const finalizingRow =
    batch.status === "finalizing"
      ? batch
      : ((await store.updateStatus(batch.tenantId, batch.id, "finalizing", nowUnix)) ?? batch);

  const results = await store.listResults(batch.id);
  const succeeded = results.filter((result) => result.succeeded);
  const failed = results.filter((result) => !result.succeeded);

  const outputFileId =
    succeeded.length === 0
      ? undefined
      : await publishJsonl(
          files,
          caller,
          batch.id,
          "output",
          renderJsonl(succeeded.map((result) => result.body)),
        );
  const errorFileId =
    failed.length === 0
      ? undefined
      : await publishJsonl(
          files,
          caller,
          batch.id,
          "error",
          renderJsonl(failed.map((result) => result.body)),
        );

  if (
    (succeeded.length > 0 && outputFileId === undefined) ||
    (failed.length > 0 && errorFileId === undefined)
  ) {
    // The lines are PAID FOR and their rows are durable. Refusing to complete
    // leaves the job claimable, so the next tick re-publishes from the same
    // rows — it does not re-dispatch. Completing with a missing file would
    // hand the client a `completed` batch whose results do not exist.
    return {
      batchId: batch.id,
      status: finalizingRow.status,
      mode: batch.executionMode ?? "local",
      executed: 0,
      failed: 0,
      retry: true,
      detail: "the batch output file could not be published",
    };
  }

  const counts: BatchRequestCounts = {
    total: Math.max(finalizingRow.requestCounts.total, results.length),
    completed: succeeded.length,
    failed: failed.length,
  };
  await store.saveProgress(batch.tenantId, batch.id, {
    requestCounts: counts,
    ...(outputFileId !== undefined ? { outputFileId } : {}),
    ...(errorFileId !== undefined ? { errorFileId } : {}),
  });
  const completed = await store.updateStatus(batch.tenantId, batch.id, "completed", nowUnix);
  return {
    batchId: batch.id,
    status: completed?.status ?? "finalizing",
    mode: batch.executionMode ?? "local",
    executed: succeeded.length,
    failed: failed.length,
    retry: false,
  };
}

async function failJob(
  store: BatchStore,
  batch: StoredBatch,
  refusal: BatchRefusal,
  nowUnix: number,
): Promise<BatchTickResult> {
  await store.saveProgress(batch.tenantId, batch.id, {
    failureCode: refusal.code,
    failureMessage: refusal.message,
  });
  const failed = await store.updateStatus(batch.tenantId, batch.id, "failed", nowUnix);
  return {
    batchId: batch.id,
    status: failed?.status ?? batch.status,
    mode: batch.executionMode ?? "none",
    executed: 0,
    failed: 0,
    retry: false,
    detail: `${refusal.code}: ${refusal.message}`,
  };
}

// ---------------------------------------------------------------------------
// The local path
// ---------------------------------------------------------------------------

function usageForLine(
  batch: StoredBatch,
  route: PhysicalRoute,
  operation: InferenceOperation,
  lineIndex: number,
  status: number,
  body: unknown,
  discount: number,
): Usage {
  // `usageProviderKindFor` is the security control `chat.rs:1026` describes:
  // reading an Anthropic envelope with the OpenAI extractor scrapes nothing and
  // meters the call at zero, which is a budget bypass rather than a nicety.
  const dialect = usageProviderKindFor("chat.completions", route.providerKind);
  const reported = usageFromResponseBody(dialect, body);
  const scale = (value: number | undefined): number | undefined =>
    value === undefined ? undefined : value * discount;
  return {
    requestId: `${batch.id}_req_${lineIndex}`,
    route: `${route.provider}.${operation}`,
    logicalModel: route.logicalModel,
    provider: route.provider,
    providerModel: route.providerModel,
    stream: false,
    status,
    promptTokens: reported?.promptTokens,
    completionTokens: reported?.completionTokens,
    totalTokens: reported?.totalTokens,
    cachedInputTokens: reported?.cachedInputTokens,
    tenantId: batch.tenantId,
    projectId: batch.projectId,
    // The batch's own metadata plus its id, so a tenant can reconcile a
    // month's ledger against the job that produced it.
    metadata: { ...batch.metadata, batch_id: batch.id },
    // The DISCOUNT is applied to the PRICES, never to the token counts: halving
    // tokens would corrupt every usage rollup and every quota that reads them.
    inputPricePer1m: scale(route.inputPricePer1m),
    outputPricePer1m: scale(route.outputPricePer1m),
  };
}

interface LineOutcome {
  readonly result: StoredBatchResult;
  readonly succeeded: boolean;
}

async function executeLine(
  env: unknown,
  batch: StoredBatch,
  line: BatchInputLine,
  operation: InferenceOperation,
  governance: BatchGovernance,
  dispatcher: UpstreamDispatcher,
  resolved: ResolvedDeps,
): Promise<LineOutcome> {
  const nowUnix = resolved.now();
  const error = (code: string, message: string): LineOutcome => ({
    succeeded: false,
    result: {
      batchId: batch.id,
      lineIndex: line.lineIndex,
      customId: line.customId,
      succeeded: false,
      body: batchErrorLine(batch.id, line.lineIndex, line.customId, { code, message }),
      createdAtUnix: nowUnix,
    },
  });

  const model = String(line.body.model ?? "");
  const route = resolved.routeFor(env, model);
  if (route === null) {
    return error("model_not_found", `model ${model} is not available in this deployment`);
  }
  const admitted = await governance.admitRoute(route);
  if (!admitted.ok) return error(admitted.code, admitted.message);

  const adapter = defaultAdapterRegistry.adapterFor(route.providerKind);
  if (adapter === null) {
    return error("unsupported_provider", `provider kind ${route.providerKind} has no adapter`);
  }
  const built = adapter.buildUpstreamRequest({
    operation,
    route,
    logicalModel: route.logicalModel,
    providerModel: route.providerModel,
    stream: false,
    // `stream` is forced off: a batch output line is a buffered body, and a
    // caller who set `stream: true` in the JSONL gets it stripped rather than
    // an SSE stream nobody is reading.
    body: { ...line.body, model: route.providerModel, stream: false },
  });
  if (!built.ok) {
    return error("invalid_request", `the request could not be prepared for ${route.provider}`);
  }

  let response: Response;
  try {
    response = await dispatcher.dispatch(built.request, AbortSignal.timeout(resolved.timeoutMs));
  } catch (caught) {
    return error(
      "provider_unavailable",
      `the provider call failed: ${caught instanceof Error ? caught.message : String(caught)}`,
    );
  }

  let text: string;
  try {
    text = await readBoundedProviderBody(response, resolved.maxResponseBytes);
  } catch (caught) {
    return error(
      "provider_error",
      `the provider response could not be read: ${
        caught instanceof Error ? caught.message : String(caught)
      }`,
    );
  }
  let body: unknown;
  try {
    body = JSON.parse(text) as unknown;
  } catch {
    return error("provider_error", "the provider response was not valid JSON");
  }

  // METERED WHETHER OR NOT THE CALL SUCCEEDED, exactly like the request path:
  // a provider that answered 400 after reading the prompt has still consumed
  // input tokens on some families, and a 200-only meter under-bills them.
  resolved.usage?.record(
    usageForLine(batch, route, operation, line.lineIndex, response.status, body, 1),
    { env },
  );

  if (response.status < 200 || response.status >= 300) {
    return error("provider_error", `the provider answered with status ${response.status}`);
  }
  return {
    succeeded: true,
    result: {
      batchId: batch.id,
      lineIndex: line.lineIndex,
      customId: line.customId,
      succeeded: true,
      body: batchOutputLine(batch.id, line.lineIndex, line.customId, response.status, body),
      createdAtUnix: nowUnix,
    },
  };
}

// ---------------------------------------------------------------------------
// The tick
// ---------------------------------------------------------------------------

/**
 * Advance ONE batch by at most one tick's worth of work.
 *
 * `undefined` when the job could not be claimed — another invocation owns it,
 * or it is already terminal. NEVER throws for a per-line failure; see the
 * retry rule in the module docs for the two things that do arm a retry.
 */
export async function runBatchTick(
  env: unknown,
  tenantId: string,
  batchId: string,
  deps: BatchExecutorDeps = {},
): Promise<BatchTickResult> {
  const resolved = resolveDeps(deps);
  const store = await resolved.storeFor(env, tenantId);
  const nowUnix = resolved.now();

  const claimed = await store.claim(
    tenantId,
    batchId,
    resolved.owner,
    nowUnix,
    resolved.leaseSeconds,
  );
  if (claimed === undefined) {
    return {
      batchId,
      status: "unclaimed",
      mode: "none",
      executed: 0,
      failed: 0,
      retry: false,
      detail: "another invocation holds the lease, or the batch is terminal",
    };
  }

  try {
    return await advance(env, store, claimed, resolved);
  } catch (error) {
    // An unexpected failure inside the tick. The lease is released in
    // `finally`, so the next trigger picks the job up from its cursor; nothing
    // is lost and nothing is re-dispatched (the results rows survive).
    return {
      batchId,
      status: claimed.status,
      mode: claimed.executionMode ?? "none",
      executed: 0,
      failed: 0,
      retry: true,
      detail: error instanceof Error ? error.message : String(error),
    };
  } finally {
    await store.release(tenantId, batchId, resolved.owner);
  }
}

async function advance(
  env: unknown,
  store: BatchStore,
  batch: StoredBatch,
  resolved: ResolvedDeps,
): Promise<BatchTickResult> {
  const nowUnix = resolved.now();
  const files = await resolved.filesFor(env, batch.tenantId);
  const caller = await resolved.callerFor(env, batch);

  // 1. A client cancellation the executor now has to honour. Nothing is
  //    published: a job the caller abandoned must not leave output behind.
  if (batch.status === "cancelling") {
    await cancelNativeBatchFor(env, files, caller, batch, resolved);
    const cancelled = await store.updateStatus(batch.tenantId, batch.id, "cancelled", nowUnix);
    return {
      batchId: batch.id,
      status: cancelled?.status ?? "cancelling",
      mode: batch.executionMode ?? "none",
      executed: 0,
      failed: 0,
      retry: false,
    };
  }

  // 2. The 24h completion window. Expiry is checked BEFORE spend: a job that
  //    has run out of time must not pay for one more line first.
  if (batch.expiresAtUnix <= nowUnix) {
    await cancelNativeBatchFor(env, files, caller, batch, resolved);
    const expired = await store.updateStatus(batch.tenantId, batch.id, "expired", nowUnix);
    return {
      batchId: batch.id,
      status: expired?.status ?? batch.status,
      mode: batch.executionMode ?? "none",
      executed: 0,
      failed: 0,
      retry: false,
    };
  }

  // 3. The admission ladder, before anything is dispatched or submitted.
  const governance = resolved.governanceFor(env, batch);
  const admitted = await governance.admitSpend();
  if (!admitted.ok) {
    await cancelNativeBatchFor(env, files, caller, batch, resolved);
    return failJob(store, batch, admitted, nowUnix);
  }

  // 4. Read the input. An unreadable input is the ONE thing that fails a whole
  //    job rather than a line: there are no lines to fail.
  const pulled = await files.fileContent(
    caller,
    batch.inputFileId,
    { headers: new Headers() },
    { requestId: batch.id },
  );
  if (!pulled.ok || pulled.bytes === null) {
    return failJob(
      store,
      batch,
      {
        code: "batch_input_unreadable",
        message: `input file ${batch.inputFileId} could not be read`,
      },
      nowUnix,
    );
  }
  if (pulled.bytes.byteLength > resolved.maxInputBytes) {
    return failJob(
      store,
      batch,
      {
        code: "batch_input_too_large",
        message: `input file exceeds ${resolved.maxInputBytes} bytes`,
      },
      nowUnix,
    );
  }
  const inputText = new TextDecoder().decode(pulled.bytes);
  const physicalLines = jsonlLines(inputText);

  const operation = OPERATION_FOR_ENDPOINT[batch.endpoint];
  if (operation === undefined) {
    return failJob(
      store,
      batch,
      {
        code: "batch_endpoint_unsupported",
        message: `endpoint ${batch.endpoint} has no executor in this deployment`,
      },
      nowUnix,
    );
  }

  // 5. Slice 3 — decide (once) whether the provider runs this job for us.
  const mode = await selectExecutionMode(env, store, batch, physicalLines, resolved);
  if (mode === "native") {
    return advanceNative(env, store, files, caller, batch, pulled.bytes, governance, resolved);
  }

  return advanceLocal(
    env,
    store,
    files,
    caller,
    batch,
    physicalLines,
    operation,
    governance,
    resolved,
  );
}

/**
 * Pick — and PERSIST — the execution strategy.
 *
 * Persisted rather than recomputed on every tick because a catalogue edit
 * mid-flight must not make a job that is already sitting on OpenAI's batch
 * queue start being re-executed line by line here (which would bill twice).
 */
async function selectExecutionMode(
  env: unknown,
  store: BatchStore,
  batch: StoredBatch,
  lines: readonly { index: number; raw: string }[],
  resolved: ResolvedDeps,
): Promise<BatchExecutionMode> {
  if (batch.executionMode !== undefined) return batch.executionMode;
  const chosen = resolved.nativePassthrough
    ? (nativeModeFor(env, batch, lines, resolved) ?? "local")
    : "local";
  await store.saveProgress(batch.tenantId, batch.id, { executionMode: chosen });
  return chosen;
}

/**
 * `"native"` only when EVERY line names the same model and that model's route
 * is a family with a batch endpoint that serves this batch's endpoint.
 *
 * The "every line, same model" rule is not a simplification — a provider batch
 * is submitted against one endpoint and one credential, so a mixed-model job
 * genuinely cannot be one native submission. Mixed jobs fall through to the
 * local executor and lose only the discount.
 */
function nativeModeFor(
  env: unknown,
  batch: StoredBatch,
  lines: readonly { index: number; raw: string }[],
  resolved: ResolvedDeps,
): BatchExecutionMode | null {
  let model: string | undefined;
  for (const line of lines) {
    const parsed = parseBatchInputLine(line.raw, line.index, batch.endpoint);
    if (!parsed.ok) return null;
    const lineModel = String(parsed.line.body.model ?? "");
    if (model === undefined) model = lineModel;
    else if (model !== lineModel) return null;
  }
  if (model === undefined) return null;
  const route = resolved.routeFor(env, model);
  if (route === null) return null;
  const family = nativeBatchFamilyFor(route);
  if (family === null || !nativeBatchSupportsEndpoint(family, batch.endpoint)) return null;
  return "native";
}

/**
 * Tell the provider to stop, when our copy of the job has gone terminal.
 *
 * The route is re-derived from the INPUT FILE rather than persisted on the row,
 * which keeps 0023 to the columns the lifecycle actually needs. That is why
 * this is best effort in two places at once: the input may have been deleted,
 * and the provider may refuse. Neither can be allowed to stop the local
 * transition — the client has cancelled, and a job that stays `cancelling`
 * forever because a provider was unreachable is the worse outcome.
 */
async function cancelNativeBatchFor(
  env: unknown,
  files: AssetService,
  caller: AssetCaller,
  batch: StoredBatch,
  resolved: ResolvedDeps,
): Promise<void> {
  if (batch.providerBatchId === undefined) return;
  try {
    const pulled = await files.fileContent(
      caller,
      batch.inputFileId,
      { headers: new Headers() },
      { requestId: batch.id },
    );
    if (!pulled.ok || pulled.bytes === null) return;
    const target = nativeTargetFor(env, batch, pulled.bytes, resolved);
    if (target === null) return;
    await cancelNativeBatch(
      target.family,
      target.route,
      batch.providerBatchId,
      resolved.http,
      resolved.timeoutMs,
    );
  } catch (error) {
    console.warn(
      `[ferrogate] batch ${batch.id}: the upstream cancellation could not be sent: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/** The native (slice 3) arm: submit once, then poll to completion. */
async function advanceNative(
  env: unknown,
  store: BatchStore,
  files: AssetService,
  caller: AssetCaller,
  batch: StoredBatch,
  inputBytes: Uint8Array,
  governance: BatchGovernance,
  resolved: ResolvedDeps,
): Promise<BatchTickResult> {
  const nowUnix = resolved.now();
  const resolvedNative = nativeTargetFor(env, batch, inputBytes, resolved);
  if (resolvedNative === null) {
    // The route disappeared from the catalogue between ticks. Fall back to the
    // local executor rather than stranding the job: `execution_mode` is
    // rewritten so the next tick takes the local arm from the top.
    await store.saveProgress(batch.tenantId, batch.id, { executionMode: "local" });
    return {
      batchId: batch.id,
      status: batch.status,
      mode: "local",
      executed: 0,
      failed: 0,
      retry: false,
      detail: "the native route is no longer available; falling back to local execution",
    };
  }
  const { route, family } = resolvedNative;

  if (batch.providerBatchId === undefined) {
    // Residency BEFORE a single prompt byte leaves for the provider.
    const admitted = await governance.admitRoute(route);
    if (!admitted.ok) return failJob(store, batch, admitted, nowUnix);

    const uploaded = await uploadNativeBatchInput(
      family,
      route,
      inputBytes,
      resolved.http,
      resolved.timeoutMs,
    );
    if (!uploaded.ok) {
      // A submission failure is RETRYABLE, not fatal: nothing was charged and
      // the provider may simply be busy. The lease frees, the Cron tries again.
      return {
        batchId: batch.id,
        status: batch.status,
        mode: "native",
        executed: 0,
        failed: 0,
        retry: true,
        detail: uploaded.message,
      };
    }
    const submitted = await submitNativeBatch(
      {
        family,
        route,
        endpoint: batch.endpoint,
        inputFileId: uploaded.fileId,
        completionWindow: batch.completionWindow,
      },
      resolved.http,
      resolved.timeoutMs,
    );
    if (!submitted.ok) {
      return {
        batchId: batch.id,
        status: batch.status,
        mode: "native",
        executed: 0,
        failed: 0,
        retry: true,
        detail: submitted.message,
      };
    }
    await store.saveProgress(batch.tenantId, batch.id, {
      providerBatchId: submitted.providerBatchId,
      provider: route.provider,
    });
    const started =
      batch.status === "validating"
        ? await store.updateStatus(batch.tenantId, batch.id, "in_progress", nowUnix)
        : batch;
    return {
      batchId: batch.id,
      status: started?.status ?? batch.status,
      mode: "native",
      executed: 0,
      failed: 0,
      retry: false,
      detail: `submitted as ${submitted.providerBatchId}`,
    };
  }

  const status = await pollNativeBatch(
    family,
    route,
    batch.providerBatchId,
    resolved.http,
    resolved.timeoutMs,
  );
  if (status === undefined || status.state === "in_progress") {
    return {
      batchId: batch.id,
      status: batch.status,
      mode: "native",
      executed: 0,
      failed: 0,
      retry: false,
      detail: "the provider is still running this batch",
    };
  }
  if (status.state === "failed") {
    return failJob(
      store,
      batch,
      {
        code: "provider_error",
        message: `the provider reported the batch as ${status.detail ?? "failed"}`,
      },
      nowUnix,
    );
  }
  if (status.state === "cancelled") {
    // Two hops, because `cancelled` is not reachable from `in_progress` for a
    // job the executor owns: the state machine routes an executor-observed
    // cancellation through `cancelling`, which is also what a client polling
    // `retrieveBatch` between the two ticks would see. The first hop is a
    // no-op when the row is already `cancelling` (a client cancel raced us).
    await store.updateStatus(batch.tenantId, batch.id, "cancelling", nowUnix);
    const done = await store.updateStatus(batch.tenantId, batch.id, "cancelled", nowUnix);
    return {
      batchId: batch.id,
      status: done?.status ?? batch.status,
      mode: "native",
      executed: 0,
      failed: 0,
      retry: false,
    };
  }

  // Completed upstream. Pull the provider's own output JSONL, meter every line
  // it reports (at the discounted price), and store the lines as ours.
  const reference = status.outputFileId;
  if (reference === undefined) {
    return failJob(
      store,
      batch,
      { code: "provider_error", message: "the provider completed the batch with no output file" },
      nowUnix,
    );
  }
  const text = await downloadNativeBatchOutput(
    family,
    route,
    reference,
    resolved.http,
    resolved.timeoutMs,
    resolved.maxInputBytes,
  );
  if (text === undefined) {
    return {
      batchId: batch.id,
      status: batch.status,
      mode: "native",
      executed: 0,
      failed: 0,
      retry: true,
      detail: "the provider output could not be downloaded",
    };
  }

  const results: StoredBatchResult[] = [];
  for (const { index, raw } of jsonlLines(text)) {
    let line: Record<string, unknown>;
    try {
      line = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      continue;
    }
    const customId = typeof line.custom_id === "string" ? line.custom_id : "";
    const response = line.response as { status_code?: unknown; body?: unknown } | null | undefined;
    const statusCode = typeof response?.status_code === "number" ? response.status_code : 0;
    const succeeded = line.error === null || line.error === undefined;
    resolved.usage?.record(
      usageForLine(
        batch,
        route,
        batch.endpoint === "/v1/embeddings" ? "embeddings" : "chat.completions",
        index,
        statusCode,
        response?.body,
        NATIVE_BATCH_COST_MULTIPLIER,
      ),
      { env },
    );
    results.push({
      batchId: batch.id,
      lineIndex: index,
      customId,
      succeeded,
      body: line,
      createdAtUnix: nowUnix,
    });
  }
  await store.putResults(batch.id, results);
  const advanced =
    (await store.saveProgress(batch.tenantId, batch.id, {
      nextLineIndex: results.length,
      requestCounts: {
        total: results.length,
        completed: results.filter((result) => result.succeeded).length,
        failed: results.filter((result) => !result.succeeded).length,
      },
    })) ?? batch;
  return finalize(store, files, caller, advanced, resolved);
}

/** Which native route this job is running on, re-resolved from its first line. */
function nativeTargetFor(
  env: unknown,
  batch: StoredBatch,
  inputBytes: Uint8Array,
  resolved: ResolvedDeps,
): { route: PhysicalRoute; family: NativeBatchFamily } | null {
  const lines = jsonlLines(new TextDecoder().decode(inputBytes));
  const first = lines[0];
  if (first === undefined) return null;
  const parsed = parseBatchInputLine(first.raw, first.index, batch.endpoint);
  if (!parsed.ok) return null;
  const route = resolved.routeFor(env, String(parsed.line.body.model ?? ""));
  if (route === null) return null;
  const family = nativeBatchFamilyFor(route);
  if (family === null || !nativeBatchSupportsEndpoint(family, batch.endpoint)) return null;
  return { route, family };
}

/** The local arm: dispatch this tick's slice of lines ourselves. */
async function advanceLocal(
  env: unknown,
  store: BatchStore,
  files: AssetService,
  caller: AssetCaller,
  batch: StoredBatch,
  physicalLines: readonly { index: number; raw: string }[],
  operation: InferenceOperation,
  governance: BatchGovernance,
  resolved: ResolvedDeps,
): Promise<BatchTickResult> {
  const nowUnix = resolved.now();
  const started =
    batch.status === "validating"
      ? ((await store.updateStatus(batch.tenantId, batch.id, "in_progress", nowUnix)) ?? batch)
      : batch;

  const cursor = started.nextLineIndex ?? 0;
  const pending = physicalLines.filter((line) => line.index >= cursor);
  if (pending.length === 0) {
    return finalize(store, files, caller, started, resolved);
  }

  const dispatcher = resolved.dispatcherFor(env);
  const slice = pending.slice(0, resolved.maxLinesPerTick);
  const results: StoredBatchResult[] = [];
  let executed = 0;
  let failed = 0;
  let stoppedBy: BatchRefusal | undefined;
  let sinceBudgetCheck = 0;

  for (const { index, raw } of slice) {
    // Re-read the budget periodically. See `governance.ts` on why this is not
    // per line.
    if (sinceBudgetCheck >= BATCH_BUDGET_RECHECK_LINES) {
      const still = await governance.admitSpend();
      sinceBudgetCheck = 0;
      if (!still.ok) {
        stoppedBy = still;
        break;
      }
    }
    sinceBudgetCheck += 1;

    const parsed = parseBatchInputLine(raw, index, batch.endpoint);
    if (!parsed.ok) {
      failed += 1;
      results.push({
        batchId: batch.id,
        lineIndex: index,
        customId: parsed.customId,
        succeeded: false,
        body: batchErrorLine(batch.id, index, parsed.customId, {
          code: parsed.code,
          message: parsed.message,
        }),
        createdAtUnix: nowUnix,
      });
      continue;
    }
    const outcome = await executeLine(
      env,
      started,
      parsed.line,
      operation,
      governance,
      dispatcher,
      resolved,
    );
    results.push(outcome.result);
    if (outcome.succeeded) executed += 1;
    else failed += 1;
  }

  // The rows FIRST, and only then the cursor: a crash between them re-executes
  // the tail of this tick, which the `(batch_id, line_index)` key absorbs. The
  // reverse order would silently drop paid results.
  try {
    await store.putResults(batch.id, results);
  } catch (error) {
    return {
      batchId: batch.id,
      status: started.status,
      mode: "local",
      executed,
      failed,
      retry: true,
      detail: `batch results could not be persisted: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }

  const lastIndex = results.at(-1)?.lineIndex;
  const nextCursor = lastIndex === undefined ? cursor : lastIndex + 1;
  const priorCounts = started.requestCounts;
  const advanced =
    (await store.saveProgress(batch.tenantId, batch.id, {
      nextLineIndex: nextCursor,
      requestCounts: {
        total: physicalLines.length,
        completed: priorCounts.completed + executed,
        failed: priorCounts.failed + failed,
      },
    })) ?? started;

  if (stoppedBy !== undefined) {
    return failJob(store, advanced, stoppedBy, nowUnix);
  }
  const remaining = physicalLines.filter((line) => line.index >= nextCursor);
  if (remaining.length === 0) {
    return finalize(store, files, caller, advanced, resolved);
  }
  return {
    batchId: batch.id,
    status: advanced.status,
    mode: "local",
    executed,
    failed,
    retry: false,
    detail: `${remaining.length} lines remain`,
  };
}

// ---------------------------------------------------------------------------
// Fan-out
// ---------------------------------------------------------------------------

/** Every claimable job for one tenant, oldest first. Never throws. */
export async function runTenantBatchTicks(
  env: unknown,
  tenantId: string,
  limit: number,
  deps: BatchExecutorDeps = {},
): Promise<readonly BatchTickResult[]> {
  const resolved = resolveDeps(deps);
  const out: BatchTickResult[] = [];
  let store: BatchStore;
  try {
    store = await resolved.storeFor(env, tenantId);
  } catch {
    return out;
  }
  let claimable: readonly StoredBatch[];
  try {
    claimable = await store.claimable(tenantId, resolved.now(), limit);
  } catch {
    return out;
  }
  for (const batch of claimable) {
    if (BATCH_TERMINAL_STATUSES.includes(batch.status)) continue;
    try {
      out.push(await runBatchTick(env, tenantId, batch.id, { ...deps, store: async () => store }));
    } catch (error) {
      console.warn(
        `[ferrogate] batch tick failed for ${batch.id}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
  return out;
}
