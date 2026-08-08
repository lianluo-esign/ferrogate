/**
 * The batch executor (#698, slices 2 and 3).
 *
 * Every assertion here is written to FAIL if the behaviour is inverted, which
 * is the house rule this repo's dominant defect mode (the vacuous test) exists
 * for. In particular the governance tests assert on the DISPATCH COUNT, not
 * only on the resulting status: a gate that refused the job but had already
 * paid for the calls would still produce `status: "failed"`, and a test that
 * only read the status would pass on it.
 */
import { MemoryBatchStore, type StoredBatch } from "@ferrogate/storage";
import { describe, expect, test } from "vitest";
import { buildAssetService } from "../src/assets/index.js";
import type { AssetCaller } from "../src/assets/index.js";
import { InMemoryAssetMetadataStore } from "../src/assets/ports.js";
import {
  BATCH_ENDPOINTS,
  type BatchExecutorDeps,
  type BatchGovernance,
  OPERATION_FOR_ENDPOINT,
  consumeBatchJobBatch,
  jsonlLines,
  nativeBatchFamilyFor,
  nativeBatchStatusFrom,
  nativeBatchSupportsEndpoint,
  parseBatchInputLine,
  runBatchTick,
  runTenantBatchTicks,
  submitNativeBatch,
} from "../src/batch/index.js";
import { BATCH_BUDGET_RECHECK_LINES } from "../src/batch/index.js";
import { DEFAULT_MAX_LINES_PER_TICK } from "../src/batch/index.js";
import type { PhysicalRoute, Usage, UsageSink } from "../src/inference/ports.js";

const TENANT = "tenant_exec";
const START_UNIX = 1_700_000_000;

const ROUTE: PhysicalRoute = {
  logicalModel: "demo-chat",
  provider: "openai",
  providerModel: "gpt-4o-mini",
  providerKind: "openai-compatible",
  enabled: true,
  baseUrl: "https://upstream.test/v1",
  apiKey: "sk-test",
  inputPricePer1m: 100,
  outputPricePer1m: 200,
};

const ALLOW_ALL: BatchGovernance = {
  async admitSpend() {
    return { ok: true };
  },
  async admitRoute() {
    return { ok: true };
  },
};

function chatLine(customId: string, model = "demo-chat"): string {
  return JSON.stringify({
    custom_id: customId,
    method: "POST",
    url: "/v1/chat/completions",
    body: { model, messages: [{ role: "user", content: "hi" }] },
  });
}

function upstreamOk(): Response {
  return new Response(
    JSON.stringify({
      id: "chatcmpl-1",
      object: "chat.completion",
      choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
      usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

interface Harness {
  readonly store: MemoryBatchStore;
  readonly deps: BatchExecutorDeps;
  readonly dispatched: { count: number };
  readonly metered: Usage[];
  readonly files: ReturnType<typeof buildAssetService>;
  readonly caller: AssetCaller;
  createBatch(input: string, overrides?: Partial<StoredBatch>): Promise<StoredBatch>;
  fileText(fileId: string): Promise<string>;
}

async function harness(
  options: {
    readonly governance?: BatchGovernance;
    readonly respond?: () => Response;
    readonly http?: (input: string, init: RequestInit) => Promise<Response>;
    readonly maxLinesPerTick?: number;
    readonly nativePassthrough?: boolean;
    readonly route?: PhysicalRoute | null;
    readonly now?: () => number;
  } = {},
): Promise<Harness> {
  const store = new MemoryBatchStore();
  const metadata = new InMemoryAssetMetadataStore();
  const now = options.now ?? (() => START_UNIX);
  const files = buildAssetService({ metadata, now });
  const caller: AssetCaller = {
    tenantId: TENANT,
    scopes: ["assets.read", "assets.write"],
    assetHostingEnabled: true,
    apiKeyId: "key_exec",
  };
  const dispatched = { count: 0 };
  const metered: Usage[] = [];
  const usage: UsageSink = {
    record(u) {
      metered.push(u);
    },
  };

  const deps: BatchExecutorDeps = {
    store: async () => store,
    files: async () => files,
    caller: async () => caller,
    routeFor: () => (options.route === undefined ? ROUTE : options.route),
    dispatcher: () => ({
      async dispatch() {
        dispatched.count += 1;
        return (options.respond ?? upstreamOk)();
      },
    }),
    governance: () => options.governance ?? ALLOW_ALL,
    usage,
    now,
    owner: "tick_test",
    maxLinesPerTick: options.maxLinesPerTick ?? 25,
    nativePassthrough: options.nativePassthrough ?? false,
    ...(options.http === undefined ? {} : { http: options.http }),
  };

  return {
    store,
    deps,
    dispatched,
    metered,
    files,
    caller,
    async createBatch(input, overrides = {}): Promise<StoredBatch> {
      const bytes = new TextEncoder().encode(input);
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
          metadata: { filename: "input.jsonl", purpose: "batch" },
        },
        { requestId: "seed" },
      );
      if (!created.ok) throw new Error(`the seed input file was refused: ${created.message}`);
      const batch: StoredBatch = {
        id: `batch_${Math.random().toString(16).slice(2)}`,
        tenantId: TENANT,
        inputFileId: created.body.id,
        endpoint: "/v1/chat/completions",
        completionWindow: "24h",
        status: "validating",
        requestCounts: { total: 0, completed: 0, failed: 0 },
        metadata: {},
        createdAtUnix: now(),
        expiresAtUnix: now() + 24 * 60 * 60,
        apiKeyId: "key_exec",
        nextLineIndex: 0,
        attemptCount: 0,
        ...overrides,
      };
      await store.create(batch);
      return batch;
    },
    async fileText(fileId: string): Promise<string> {
      const pulled = await files.fileContent(
        caller,
        fileId,
        { headers: new Headers() },
        { requestId: "read" },
      );
      if (!pulled.ok || pulled.bytes === null) throw new Error("the file could not be read");
      return new TextDecoder().decode(pulled.bytes);
    },
  };
}

// ---------------------------------------------------------------------------
// JSONL
// ---------------------------------------------------------------------------

describe("batch endpoint coverage", () => {
  test("every endpoint createBatch ACCEPTS has an executor operation", () => {
    // The ratchet for the slice-2 narrowing: adding an endpoint to
    // BATCH_ENDPOINTS without teaching the executor what to run would admit a
    // job that sits at `validating` until its 24-hour window expires.
    for (const endpoint of BATCH_ENDPOINTS) {
      expect(OPERATION_FOR_ENDPOINT[endpoint]).toBeDefined();
    }
    expect(BATCH_ENDPOINTS).not.toContain("/v1/completions");
  });
});

describe("batch JSONL parsing", () => {
  test("keeps the ORIGINAL physical index across blank lines", () => {
    expect(jsonlLines("a\n\n\nb\n")).toEqual([
      { index: 0, raw: "a" },
      { index: 3, raw: "b" },
    ]);
  });

  test("refuses a line whose url overrides the batch's declared endpoint", () => {
    const parsed = parseBatchInputLine(
      JSON.stringify({ custom_id: "x", url: "/v1/embeddings", body: { model: "m" } }),
      0,
      "/v1/chat/completions",
    );
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("unreachable");
    expect(parsed.code).toBe("invalid_request");
    expect(parsed.customId).toBe("x");
  });

  test("accepts a line that omits url and method, defaulting to the batch endpoint", () => {
    const parsed = parseBatchInputLine(
      JSON.stringify({ custom_id: "x", body: { model: "m" } }),
      4,
      "/v1/chat/completions",
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) throw new Error("unreachable");
    expect(parsed.line).toMatchObject({ lineIndex: 4, customId: "x", url: "/v1/chat/completions" });
  });

  test("refuses a body with no model", () => {
    const parsed = parseBatchInputLine(
      JSON.stringify({ custom_id: "x", body: {} }),
      0,
      "/v1/chat/completions",
    );
    expect(parsed.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The local executor
// ---------------------------------------------------------------------------

describe("batch executor — local path", () => {
  test("runs every line, meters each one, and publishes a real /v1/files output", async () => {
    const fixture = await harness();
    const batch = await fixture.createBatch(`${chatLine("a")}\n${chatLine("b")}\n`);

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("completed");
    expect(result.mode).toBe("local");
    expect(fixture.dispatched.count).toBe(2);
    expect(fixture.metered).toHaveLength(2);
    expect(fixture.metered[0]).toMatchObject({
      tenantId: TENANT,
      provider: "openai",
      providerModel: "gpt-4o-mini",
      promptTokens: 11,
      completionTokens: 7,
      // Undiscounted on the local path: these are ordinary synchronous calls.
      inputPricePer1m: 100,
      outputPricePer1m: 200,
    });

    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.status).toBe("completed");
    expect(stored?.requestCounts).toEqual({ total: 2, completed: 2, failed: 0 });
    expect(stored?.errorFileId).toBeUndefined();
    expect(stored?.outputFileId).toBeDefined();

    const output = await fixture.fileText(stored?.outputFileId ?? "");
    const lines = output
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ custom_id: "a", error: null });
    expect(lines[1]).toMatchObject({ custom_id: "b", error: null });
    expect((lines[0]?.response as { status_code: number }).status_code).toBe(200);
  });

  test("a malformed line becomes an error-file line and the other lines still run", async () => {
    const fixture = await harness();
    const batch = await fixture.createBatch(`${chatLine("a")}\nnot json\n${chatLine("c")}\n`);

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("completed");
    // Two dispatches, NOT three: the bad line never reached a provider.
    expect(fixture.dispatched.count).toBe(2);
    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.requestCounts).toEqual({ total: 3, completed: 2, failed: 1 });
    expect(stored?.outputFileId).toBeDefined();
    expect(stored?.errorFileId).toBeDefined();

    const errors = (await fixture.fileText(stored?.errorFileId ?? "")).trim().split("\n");
    expect(errors).toHaveLength(1);
    expect(JSON.parse(errors[0] ?? "")).toMatchObject({
      response: null,
      error: { code: "invalid_request" },
    });
  });

  test("a provider refusal becomes an error line and is STILL metered", async () => {
    const fixture = await harness({
      respond: () =>
        new Response(JSON.stringify({ error: { message: "nope" } }), {
          status: 400,
          headers: { "content-type": "application/json" },
        }),
    });
    const batch = await fixture.createBatch(`${chatLine("a")}\n`);

    await runBatchTick({}, TENANT, batch.id, fixture.deps);

    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.requestCounts).toEqual({ total: 1, completed: 0, failed: 1 });
    // Metered at the status the provider returned. A 200-only meter would
    // under-bill families that charge for a rejected prompt.
    expect(fixture.metered).toHaveLength(1);
    expect(fixture.metered[0]?.status).toBe(400);
  });

  test("an unresolvable model is a per-line error, not a job failure", async () => {
    const fixture = await harness({ route: null });
    const batch = await fixture.createBatch(`${chatLine("a")}\n`);

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("completed");
    expect(fixture.dispatched.count).toBe(0);
    const stored = await fixture.store.get(TENANT, batch.id);
    const errors = (await fixture.fileText(stored?.errorFileId ?? "")).trim();
    expect(JSON.parse(errors)).toMatchObject({ error: { code: "model_not_found" } });
  });

  test("an unreadable input file fails the JOB, with the refusal on the row", async () => {
    const fixture = await harness();
    const batch = await fixture.createBatch(`${chatLine("a")}\n`, {
      inputFileId: "file-missing",
    });

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("failed");
    expect(fixture.dispatched.count).toBe(0);
    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.failureCode).toBe("batch_input_unreadable");
  });

  test("resumes from the cursor across ticks and never re-dispatches a done line", async () => {
    const fixture = await harness({ maxLinesPerTick: 1 });
    const batch = await fixture.createBatch(
      `${chatLine("a")}\n${chatLine("b")}\n${chatLine("c")}\n`,
    );

    const first = await runBatchTick({}, TENANT, batch.id, fixture.deps);
    expect(first.status).toBe("in_progress");
    expect(fixture.dispatched.count).toBe(1);
    expect((await fixture.store.get(TENANT, batch.id))?.nextLineIndex).toBe(1);

    await runBatchTick({}, TENANT, batch.id, fixture.deps);
    const third = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(third.status).toBe("completed");
    // Exactly three paid calls for three lines across three ticks. A cursor
    // that failed to advance would show 6.
    expect(fixture.dispatched.count).toBe(3);
    const output = await fixture.fileText(
      (await fixture.store.get(TENANT, batch.id))?.outputFileId ?? "",
    );
    expect(output.trim().split("\n")).toHaveLength(3);
  });

  test("a second invocation cannot claim a leased job and dispatches nothing", async () => {
    const fixture = await harness();
    const batch = await fixture.createBatch(`${chatLine("a")}\n`);

    // A live lease held by somebody else.
    const other = await fixture.store.claim(TENANT, batch.id, "tick_other", START_UNIX, 120);
    expect(other).toBeDefined();

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("unclaimed");
    expect(fixture.dispatched.count).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Governance — the point of the issue
// ---------------------------------------------------------------------------

describe("batch executor — governance", () => {
  test("a budget refusal fails the job BEFORE any provider call is paid for", async () => {
    const fixture = await harness({
      governance: {
        async admitSpend() {
          return {
            ok: false,
            code: "monthly_budget_exceeded",
            message: "quota policy monthly budget has been exhausted for this scope",
          };
        },
        async admitRoute() {
          return { ok: true };
        },
      },
    });
    const batch = await fixture.createBatch(`${chatLine("a")}\n${chatLine("b")}\n`);

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("failed");
    // THE assertion. A gate that ran after dispatch would leave this at 2 and
    // still produce `failed`.
    expect(fixture.dispatched.count).toBe(0);
    expect(fixture.metered).toHaveLength(0);
    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.failureCode).toBe("monthly_budget_exceeded");
    expect(stored?.outputFileId).toBeUndefined();
  });

  test("the MID-TICK budget re-check fires and stops the tick where it fired", async () => {
    // The rung both module docblocks describe. It was unreachable while
    // BATCH_BUDGET_RECHECK_LINES equalled DEFAULT_MAX_LINES_PER_TICK: the guard
    // runs at the top of the loop, so the counter only ever reached 24.
    expect(BATCH_BUDGET_RECHECK_LINES).toBeLessThan(DEFAULT_MAX_LINES_PER_TICK);
    let admissions = 0;
    const fixture = await harness({
      maxLinesPerTick: DEFAULT_MAX_LINES_PER_TICK,
      governance: {
        async admitSpend() {
          admissions += 1;
          // The tick's own opening check passes; the money runs out under it.
          if (admissions === 1) return { ok: true };
          return {
            ok: false,
            code: "monthly_budget_exceeded",
            message: "quota policy monthly budget has been exhausted for this scope",
          };
        },
        async admitRoute() {
          return { ok: true };
        },
      },
    });
    const lines = Array.from({ length: DEFAULT_MAX_LINES_PER_TICK }, (_, index) =>
      chatLine(`line_${index}`),
    ).join("\n");
    const batch = await fixture.createBatch(`${lines}\n`);

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("failed");
    // EXACTLY the re-check interval, not the whole slice. Before the fix this
    // was 25 — every line of the tick paid for after the budget was gone.
    expect(admissions).toBe(2);
    expect(fixture.dispatched.count).toBe(BATCH_BUDGET_RECHECK_LINES);
    expect(fixture.metered).toHaveLength(BATCH_BUDGET_RECHECK_LINES);

    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.failureCode).toBe("monthly_budget_exceeded");
    // And the paid lines are RETRIEVABLE rather than stranded in the results
    // table behind a `failed` row with no files.
    expect(stored?.outputFileId).toBeDefined();
    const output = (await fixture.fileText(stored?.outputFileId ?? "")).trim().split("\n");
    expect(output).toHaveLength(BATCH_BUDGET_RECHECK_LINES);
  });

  test("a residency refusal drops the line without dialling the provider", async () => {
    const fixture = await harness({
      governance: {
        async admitSpend() {
          return { ok: true };
        },
        async admitRoute() {
          return {
            ok: false,
            code: "residency_policy_not_satisfiable",
            message: "route openai may not carry this tenant's data",
          };
        },
      },
    });
    const batch = await fixture.createBatch(`${chatLine("a")}\n`);

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("completed");
    expect(fixture.dispatched.count).toBe(0);
    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.requestCounts).toEqual({ total: 1, completed: 0, failed: 1 });
    expect(JSON.parse((await fixture.fileText(stored?.errorFileId ?? "")).trim())).toMatchObject({
      error: { code: "residency_policy_not_satisfiable" },
    });
  });
});

// ---------------------------------------------------------------------------
// Cancellation and expiry
// ---------------------------------------------------------------------------

describe("batch executor — lifecycle", () => {
  test("a cancelling job is finished as cancelled and publishes NO output", async () => {
    const fixture = await harness();
    const batch = await fixture.createBatch(`${chatLine("a")}\n`, { status: "cancelling" });

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("cancelled");
    expect(fixture.dispatched.count).toBe(0);
    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.outputFileId).toBeUndefined();
  });

  test("requestCancel takes the cancelling arm only while a lease is live", async () => {
    const fixture = await harness();
    const idle = await fixture.createBatch(`${chatLine("a")}\n`);
    const unleased = await fixture.store.requestCancel(TENANT, idle.id, START_UNIX);
    expect(unleased?.status).toBe("cancelled");

    const busy = await fixture.createBatch(`${chatLine("a")}\n`);
    await fixture.store.claim(TENANT, busy.id, "tick_other", START_UNIX, 120);
    const leased = await fixture.store.requestCancel(TENANT, busy.id, START_UNIX);
    expect(leased?.status).toBe("cancelling");
  });

  test("a batch past its completion window expires without spending", async () => {
    const fixture = await harness();
    const batch = await fixture.createBatch(`${chatLine("a")}\n`, {
      expiresAtUnix: START_UNIX - 1,
    });

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("expired");
    expect(fixture.dispatched.count).toBe(0);
  });

  test("expiry PUBLISHES the lines it already paid for instead of stranding them", async () => {
    // A job that ran one tick and then ran out of time has metered, durable
    // result rows. Ending it with no `output_file_id` bills the tenant for
    // output reachable through neither `/v1/batches/{id}` nor `/v1/files`.
    let clock = START_UNIX;
    const fixture = await harness({ maxLinesPerTick: 1, now: () => clock });
    const batch = await fixture.createBatch(`${chatLine("a")}\n${chatLine("b")}\n`);

    const first = await runBatchTick({}, TENANT, batch.id, fixture.deps);
    expect(first.status).toBe("in_progress");
    expect(fixture.dispatched.count).toBe(1);

    clock = batch.expiresAtUnix + 1;
    const second = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(second.status).toBe("expired");
    // Still one paid call: expiry must not dispatch line b on the way out.
    expect(fixture.dispatched.count).toBe(1);
    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.status).toBe("expired");
    // THE assertion. Before the fix this was `undefined` while `listResults`
    // held a metered row for line a.
    expect(stored?.outputFileId).toBeDefined();
    const output = (await fixture.fileText(stored?.outputFileId ?? "")).trim().split("\n");
    expect(output).toHaveLength(1);
    expect(JSON.parse(output[0] ?? "")).toMatchObject({ custom_id: "a" });
  });

  test("a cancel that lands MID-TICK publishes nothing, on this tick or the next", async () => {
    // `requestCancel` is a get-then-update against a row the tick already holds
    // the lease on, so `-> finalizing` is refused. Swallowing that refusal with
    // `?? batch` used to publish the output anyway and leave a `cancelled`
    // batch carrying an `output_file_id`.
    const fixture = await harness();
    const batch = await fixture.createBatch(`${chatLine("a")}\n`);
    const cancelMidFlight: BatchExecutorDeps = {
      ...fixture.deps,
      dispatcher: () => ({
        async dispatch() {
          await fixture.store.requestCancel(TENANT, batch.id, START_UNIX);
          return upstreamOk();
        },
      }),
    };

    const first = await runBatchTick({}, TENANT, batch.id, cancelMidFlight);
    expect(first.status).not.toBe("completed");
    const midTick = await fixture.store.get(TENANT, batch.id);
    expect(midTick?.status).toBe("cancelling");
    expect(midTick?.outputFileId).toBeUndefined();
    expect(midTick?.errorFileId).toBeUndefined();

    const second = await runBatchTick({}, TENANT, batch.id, fixture.deps);
    expect(second.status).toBe("cancelled");
    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.status).toBe("cancelled");
    expect(stored?.outputFileId).toBeUndefined();
  });

  test("runTenantBatchTicks advances every claimable job and skips terminal ones", async () => {
    const fixture = await harness();
    const first = await fixture.createBatch(`${chatLine("a")}\n`);
    const second = await fixture.createBatch(`${chatLine("b")}\n`);
    await fixture.store.updateStatus(TENANT, second.id, "cancelled", START_UNIX);

    const results = await runTenantBatchTicks({}, TENANT, 10, fixture.deps);

    expect(results.map((result) => result.batchId)).toEqual([first.id]);
    expect(fixture.dispatched.count).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Slice 3 — provider-native passthrough
// ---------------------------------------------------------------------------

describe("provider-native batch selection", () => {
  test("only a credentialled family with a batch endpoint qualifies", () => {
    expect(nativeBatchFamilyFor(ROUTE)).toBe("openai");
    expect(nativeBatchFamilyFor({ ...ROUTE, apiKey: undefined })).toBeNull();
    expect(nativeBatchFamilyFor({ ...ROUTE, providerKind: "gemini" })).toBeNull();
    expect(nativeBatchSupportsEndpoint("openai", "/v1/chat/completions")).toBe(true);
    expect(nativeBatchSupportsEndpoint("openai", "/v1/responses")).toBe(false);
    // Declared but not wired: an anthropic job falls back to the local path.
    expect(nativeBatchSupportsEndpoint("anthropic", "/v1/chat/completions")).toBe(false);
  });

  test("an unknown upstream status is read as failed, never as still-running", () => {
    expect(nativeBatchStatusFrom("openai", { status: "in_progress" })).toEqual({
      state: "in_progress",
    });
    expect(nativeBatchStatusFrom("openai", { status: "expired" })?.state).toBe("failed");
    expect(nativeBatchStatusFrom("openai", { status: "something_new" })?.state).toBe("failed");
  });
});

describe("batch executor — native path", () => {
  function nativeHttp(state: { phase: "running" | "done" }, calls: string[]) {
    return async (input: string, init: RequestInit): Promise<Response> => {
      calls.push(`${String(init.method ?? "GET")} ${input}`);
      if (input.endsWith("/files") && init.method === "POST") {
        return new Response(JSON.stringify({ id: "file-upstream" }), { status: 200 });
      }
      if (input.endsWith("/batches") && init.method === "POST") {
        return new Response(JSON.stringify({ id: "batch_upstream" }), { status: 200 });
      }
      if (input.endsWith("/batches/batch_upstream")) {
        return new Response(
          JSON.stringify(
            state.phase === "running"
              ? { status: "in_progress" }
              : { status: "completed", output_file_id: "file-out" },
          ),
          { status: 200 },
        );
      }
      if (input.endsWith("/files/file-out/content")) {
        return new Response(
          `${JSON.stringify({
            id: "req-0",
            custom_id: "a",
            response: {
              status_code: 200,
              body: { usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } },
            },
            error: null,
          })}\n`,
          { status: 200 },
        );
      }
      return new Response("{}", { status: 404 });
    };
  }

  test("submits to the provider, polls, and meters the results at HALF price", async () => {
    const state: { phase: "running" | "done" } = { phase: "running" };
    const calls: string[] = [];
    const fixture = await harness({
      nativePassthrough: true,
      http: nativeHttp(state, calls),
    });
    const batch = await fixture.createBatch(`${chatLine("a")}\n`);

    const submitted = await runBatchTick({}, TENANT, batch.id, fixture.deps);
    expect(submitted.mode).toBe("native");
    expect(submitted.status).toBe("in_progress");
    // The gateway did NOT dispatch the line itself — that is the whole point.
    expect(fixture.dispatched.count).toBe(0);
    expect(calls).toContain("POST https://upstream.test/v1/files");
    expect(calls).toContain("POST https://upstream.test/v1/batches");
    const afterSubmit = await fixture.store.get(TENANT, batch.id);
    expect(afterSubmit?.providerBatchId).toBe("batch_upstream");
    expect(afterSubmit?.executionMode).toBe("native");

    const polled = await runBatchTick({}, TENANT, batch.id, fixture.deps);
    expect(polled.status).toBe("in_progress");
    // Still nothing submitted twice.
    expect(calls.filter((call) => call === "POST https://upstream.test/v1/batches")).toHaveLength(
      1,
    );

    state.phase = "done";
    const finished = await runBatchTick({}, TENANT, batch.id, fixture.deps);
    expect(finished.status).toBe("completed");
    expect(fixture.dispatched.count).toBe(0);
    expect(fixture.metered).toHaveLength(1);
    expect(fixture.metered[0]).toMatchObject({
      promptTokens: 10,
      completionTokens: 5,
      // The ~50% batch discount, applied to the PRICES and never to the token
      // counts (halving tokens would corrupt every usage rollup).
      inputPricePer1m: 50,
      outputPricePer1m: 100,
    });
    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.outputFileId).toBeDefined();
    expect(stored?.requestCounts).toEqual({ total: 1, completed: 1, failed: 0 });
  });

  test("a mixed-model job cannot be one native submission and runs locally", async () => {
    const calls: string[] = [];
    const fixture = await harness({
      nativePassthrough: true,
      http: nativeHttp({ phase: "done" }, calls),
    });
    const batch = await fixture.createBatch(
      `${chatLine("a", "demo-chat")}\n${chatLine("b", "other-model")}\n`,
    );

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.mode).toBe("local");
    expect(result.status).toBe("completed");
    expect(calls).toHaveLength(0);
    expect(fixture.dispatched.count).toBe(2);
  });

  /**
   * A finished upstream batch whose lines are SPLIT across the two files
   * OpenAI publishes: `output_file_id` for the requests that succeeded,
   * `error_file_id` for the ones that did not.
   */
  function splitHttp(
    upstream: {
      readonly outputFileId?: string | undefined;
      readonly errorFileId?: string | undefined;
      readonly output?: readonly string[] | undefined;
      readonly errors?: readonly string[] | undefined;
    },
    calls: string[],
  ) {
    return async (input: string, init: RequestInit): Promise<Response> => {
      calls.push(`${String(init.method ?? "GET")} ${input}`);
      if (input.endsWith("/files") && init.method === "POST") {
        return new Response(JSON.stringify({ id: "file-upstream" }), { status: 200 });
      }
      if (input.endsWith("/batches") && init.method === "POST") {
        return new Response(JSON.stringify({ id: "batch_upstream" }), { status: 200 });
      }
      if (input.endsWith("/batches/batch_upstream")) {
        return new Response(
          JSON.stringify({
            status: "completed",
            ...(upstream.outputFileId === undefined
              ? {}
              : { output_file_id: upstream.outputFileId }),
            ...(upstream.errorFileId === undefined ? {} : { error_file_id: upstream.errorFileId }),
          }),
          { status: 200 },
        );
      }
      if (input.endsWith("/files/file-out/content")) {
        return new Response(`${(upstream.output ?? []).join("\n")}\n`, { status: 200 });
      }
      if (input.endsWith("/files/file-err/content")) {
        return new Response(`${(upstream.errors ?? []).join("\n")}\n`, { status: 200 });
      }
      return new Response("{}", { status: 404 });
    };
  }

  function nativeOk(customId: string): string {
    return JSON.stringify({
      id: `req-${customId}`,
      custom_id: customId,
      response: {
        status_code: 200,
        body: { usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } },
      },
      error: null,
    });
  }

  test("the provider's ERROR file is pulled too; an errored line is not destroyed", async () => {
    const calls: string[] = [];
    const fixture = await harness({
      nativePassthrough: true,
      http: splitHttp(
        {
          outputFileId: "file-out",
          errorFileId: "file-err",
          output: [nativeOk("a")],
          errors: [
            JSON.stringify({
              id: "req-b",
              custom_id: "b",
              response: null,
              error: { code: "rate_limit_exceeded", message: "slow down" },
            }),
          ],
        },
        calls,
      ),
    });
    const batch = await fixture.createBatch(`${chatLine("a")}\n${chatLine("b")}\n`);

    await runBatchTick({}, TENANT, batch.id, fixture.deps);
    const finished = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(finished.status).toBe("completed");
    // THE call the passthrough never used to make.
    expect(calls).toContain("GET https://upstream.test/v1/files/file-err/content");
    const stored = await fixture.store.get(TENANT, batch.id);
    // The tenant submitted TWO requests and both are accounted for. Before the
    // fix this read `{ total: 1, completed: 1, failed: 0 }`.
    expect(stored?.requestCounts).toEqual({ total: 2, completed: 1, failed: 1 });
    expect(stored?.outputFileId).toBeDefined();
    expect(stored?.errorFileId).toBeDefined();
    const errors = (await fixture.fileText(stored?.errorFileId ?? "")).trim().split("\n");
    expect(errors).toHaveLength(1);
    expect(JSON.parse(errors[0] ?? "")).toMatchObject({ custom_id: "b" });
    const output = (await fixture.fileText(stored?.outputFileId ?? "")).trim().split("\n");
    expect(output).toHaveLength(1);
    expect(JSON.parse(output[0] ?? "")).toMatchObject({ custom_id: "a" });
  });

  test("a batch whose every line failed upstream publishes the error file, not a dead job", async () => {
    // OpenAI answers `completed` with `output_file_id: null` when nothing
    // succeeded. That used to hit the "no output file" arm and kill the job,
    // discarding results the provider had already produced and billed for.
    const calls: string[] = [];
    const fixture = await harness({
      nativePassthrough: true,
      http: splitHttp(
        {
          errorFileId: "file-err",
          errors: [
            JSON.stringify({
              id: "req-a",
              custom_id: "a",
              response: null,
              error: { code: "invalid_request", message: "bad" },
            }),
          ],
        },
        calls,
      ),
    });
    const batch = await fixture.createBatch(`${chatLine("a")}\n`);

    await runBatchTick({}, TENANT, batch.id, fixture.deps);
    const finished = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(finished.status).toBe("completed");
    const stored = await fixture.store.get(TENANT, batch.id);
    expect(stored?.failureCode).toBeUndefined();
    expect(stored?.requestCounts).toEqual({ total: 1, completed: 0, failed: 1 });
    expect(stored?.errorFileId).toBeDefined();
    expect(stored?.outputFileId).toBeUndefined();
  });

  test("a non-2xx line in the provider's output file is an ERROR line, as it is locally", async () => {
    const calls: string[] = [];
    const fixture = await harness({
      nativePassthrough: true,
      http: splitHttp(
        {
          outputFileId: "file-out",
          output: [
            nativeOk("a"),
            JSON.stringify({
              id: "req-b",
              custom_id: "b",
              response: { status_code: 400, body: { error: { message: "nope" } } },
              error: null,
            }),
          ],
        },
        calls,
      ),
    });
    const batch = await fixture.createBatch(`${chatLine("a")}\n${chatLine("b")}\n`);

    await runBatchTick({}, TENANT, batch.id, fixture.deps);
    await runBatchTick({}, TENANT, batch.id, fixture.deps);

    const stored = await fixture.store.get(TENANT, batch.id);
    // Classifying on `error` alone counted the 400 as a success.
    expect(stored?.requestCounts).toEqual({ total: 2, completed: 1, failed: 1 });
    const errors = (await fixture.fileText(stored?.errorFileId ?? "")).trim().split("\n");
    expect(JSON.parse(errors[0] ?? "")).toMatchObject({ custom_id: "b" });
    // Both lines are metered, at the discounted price, whatever their status.
    expect(fixture.metered).toHaveLength(2);
    expect(fixture.metered.map((usage) => usage.status).sort()).toEqual([200, 400]);
  });

  test("a cancelled native job tells the PROVIDER to stop", async () => {
    const calls: string[] = [];
    const fixture = await harness({
      nativePassthrough: true,
      http: splitHttp({ outputFileId: "file-out", output: [nativeOk("a")] }, calls),
    });
    const batch = await fixture.createBatch(`${chatLine("a")}\n`, {
      status: "cancelling",
      executionMode: "native",
      providerBatchId: "batch_upstream",
    });

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.status).toBe("cancelled");
    // The upstream job is still running and still billing until it is told to
    // stop. Every existing lifecycle test built a batch with NO providerBatchId,
    // so `cancelNativeBatchFor` short-circuited on its first line.
    expect(calls).toContain("POST https://upstream.test/v1/batches/batch_upstream/cancel");
    expect((await fixture.store.get(TENANT, batch.id))?.outputFileId).toBeUndefined();
  });

  test("the anthropic arm REFUSES to submit rather than posting an empty request set", async () => {
    const calls: string[] = [];
    const outcome = await submitNativeBatch(
      {
        family: "anthropic",
        route: { ...ROUTE, providerKind: "anthropic", baseUrl: "https://anthropic.test/v1" },
        endpoint: "/v1/chat/completions",
        inputFileId: "file-x",
        completionWindow: "24h",
      },
      async (input, init) => {
        calls.push(`${String(init.method ?? "GET")} ${input}`);
        return new Response(JSON.stringify({ id: "msgbatch_1" }), { status: 200 });
      },
      1000,
    );

    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.code).toBe("unsupported");
    // NOTHING was sent. `{ requests: [] }` would have taken back a real batch
    // id for a job whose input was never submitted, and later reported it
    // `completed` with zero results.
    expect(calls).toEqual([]);
  });

  test("native passthrough switched off pins the job to the local executor", async () => {
    const calls: string[] = [];
    const fixture = await harness({
      nativePassthrough: false,
      http: nativeHttp({ phase: "done" }, calls),
    });
    const batch = await fixture.createBatch(`${chatLine("a")}\n`);

    const result = await runBatchTick({}, TENANT, batch.id, fixture.deps);

    expect(result.mode).toBe("local");
    expect(calls).toHaveLength(0);
    expect(fixture.dispatched.count).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// The queue leg
// ---------------------------------------------------------------------------

describe("batch job queue", () => {
  test("only a batch.job body decodes; every other queue's body is left alone", async () => {
    const fixture = await harness();
    const acked: unknown[] = [];
    const result = await consumeBatchJobBatch(
      {
        messages: [
          {
            body: { object: "online_eval_sample", request_id: "r" },
            ack() {
              acked.push("eval");
            },
          },
        ],
      },
      {},
      fixture.deps,
    );
    expect(result.ticked).toBe(0);
    expect(result.malformed).toBe(1);
    expect(acked).toEqual(["eval"]);
    expect(fixture.dispatched.count).toBe(0);
  });

  test("a delivery runs the tick and re-enqueues a job with lines left", async () => {
    const sent: unknown[] = [];
    const fixture = await harness({ maxLinesPerTick: 1 });
    const batch = await fixture.createBatch(`${chatLine("a")}\n${chatLine("b")}\n`);
    const env = {
      BATCH_JOBS: {
        async send(body: unknown) {
          sent.push(body);
        },
        async sendBatch() {},
      },
    };

    const result = await consumeBatchJobBatch(
      {
        messages: [
          { body: { object: "batch.job", tenant_id: TENANT, batch_id: batch.id }, ack() {} },
        ],
      },
      env,
      fixture.deps,
    );

    expect(result.ticked).toBe(1);
    expect(result.retried).toBe(false);
    expect(result.reenqueued).toBe(1);
    expect(sent).toEqual([{ object: "batch.job", tenant_id: TENANT, batch_id: batch.id }]);
    expect(fixture.dispatched.count).toBe(1);
  });

  test("a native job the provider is still running is NOT re-enqueued", async () => {
    // Otherwise the consumer busy-polls the upstream batch endpoint for the
    // job's whole 24h completion window: `advanceNative` returns the row's
    // unchanged `in_progress`, which is in CONTINUES, and `max_batch_timeout`
    // is 5s. The Cron owns the poll leg (see src/batch/sweep.ts).
    const sent: unknown[] = [];
    const calls: string[] = [];
    const fixture = await harness({
      nativePassthrough: true,
      http: async (input: string, init: RequestInit) => {
        calls.push(`${String(init.method ?? "GET")} ${input}`);
        if (input.endsWith("/files") && init.method === "POST") {
          return new Response(JSON.stringify({ id: "file-upstream" }), { status: 200 });
        }
        if (input.endsWith("/batches") && init.method === "POST") {
          return new Response(JSON.stringify({ id: "batch_upstream" }), { status: 200 });
        }
        return new Response(JSON.stringify({ status: "in_progress" }), { status: 200 });
      },
    });
    const batch = await fixture.createBatch(`${chatLine("a")}\n`);
    const env = {
      BATCH_JOBS: {
        async send(body: unknown) {
          sent.push(body);
        },
        async sendBatch() {},
      },
    };
    const deliver = () =>
      consumeBatchJobBatch(
        {
          messages: [
            { body: { object: "batch.job", tenant_id: TENANT, batch_id: batch.id }, ack() {} },
          ],
        },
        env,
        fixture.deps,
      );

    const submit = await deliver();
    const poll = await deliver();

    expect(submit.reenqueued).toBe(0);
    expect(poll.reenqueued).toBe(0);
    expect(sent).toEqual([]);
    // The job is genuinely still running — this is not "it went terminal".
    expect((await fixture.store.get(TENANT, batch.id))?.status).toBe("in_progress");
    // One submit + one poll. A re-enqueuing consumer would multiply this by
    // however many round trips fit in the completion window.
    expect(calls.filter((call) => call.endsWith("/batches/batch_upstream"))).toHaveLength(1);
  });

  test("a completed job is NOT re-enqueued", async () => {
    const sent: unknown[] = [];
    const fixture = await harness();
    const batch = await fixture.createBatch(`${chatLine("a")}\n`);
    const env = {
      BATCH_JOBS: {
        async send(body: unknown) {
          sent.push(body);
        },
        async sendBatch() {},
      },
    };

    await consumeBatchJobBatch(
      {
        messages: [
          { body: { object: "batch.job", tenant_id: TENANT, batch_id: batch.id }, ack() {} },
        ],
      },
      env,
      fixture.deps,
    );

    expect(sent).toEqual([]);
  });
});
