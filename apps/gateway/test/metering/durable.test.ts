/**
 * DURABLE metering, end to end, on real Cloudflare bindings.
 *
 * `gateway.test.ts` drives the composed gateway with the in-isolate ledger, so
 * it proves the SEAM. This file proves the STORAGE: the same composition, but
 * `env.BILLING_DB` is the real D1 the deployed control migration created and
 * `env.BILLING` is the real Queue producer `wrangler.toml` declares, and the
 * drain runs on a real `ExecutionContext` created by `cloudflare:test`. Nothing
 * between the HTTP request and the SQLite row is a double:
 *
 *   app.fetch(request, env, ctx)
 *     → contract router → auth guard → meteringDrain → Zod → dispatch
 *     → sseUsageTap / buffered handler → sink.record(usage)
 *     → ctx.waitUntil(sink.flush({ env, ctx }))
 *     → D1LedgerStore.record  (env.BILLING_DB, one batch, ON CONFLICT)
 *     → QueueBillingReportPublisher.deliver  (env.BILLING)
 *
 * Only the OUTBOUND provider `fetch` is intercepted.
 *
 * ## Why `app.fetch(request, env, ctx)` and not `SELF`
 *
 * `SELF` would run `src/worker.ts`, whose model registry is pinned EMPTY by
 * `vitest.config.ts` (deliberately, so `test/contract.test.ts` can assert the
 * empty-registry behaviour) — every request would answer `400 model_not_found`
 * and never reach the sink. Building the same app here with a one-route
 * registry keeps the real `env` and the real `ExecutionContext` while giving
 * the request something to dispatch to. The wiring under test —
 * `createMeteringUsageSink({ bindings: meteringBindingsFromEnv })` plus
 * `meteringDrain(sink)` as the outermost middleware — is character-for-character
 * what `src/index.ts` does.
 */
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { RequestIdFactory } from "../../src/inference/index.js";
import {
  CREDITS_EXACT_FIELD,
  D1LedgerStore,
  InMemoryMeteringOutbox,
  MAX_BILLING_OUTBOX_ATTEMPTS,
  type MeteringUsageSink,
  OUTBOX_SWEEP_GRACE_SECONDS,
  createMeteringUsageSink,
  meteringBindingsFromEnv,
  meteringDrain,
  billingEventToWire,
  ledgerDocument,
} from "../../src/metering/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
  providerSse,
  readBody,
} from "../inference/provider-mock.js";
import {
  RecordingDatabase,
  RecordingQueue,
  billingDb,
  ledgerEntryJson,
  resetMeteringTables,
  rowCount,
} from "./d1-harness.js";
import { FIXTURE_CREDITS, chargeFixture, pricedBook, usageFixture } from "./fixtures.js";
import { resetTenantBillingState, tenantObjectDb } from "../tenant-object.js";

const BASE = "https://gw.test";
const AUTHED = { authorization: "Bearer fg_root", "content-type": "application/json" };

async function tenantRowCount(
  table: "billing_events" | "billing_ledger" | "billing_report_outbox",
): Promise<number> {
  const row = await tenantObjectDb("tenant_a")
    .prepare(`SELECT count(*) AS n FROM ${table}`)
    .first<{ n: number }>();
  return Number(row?.n ?? 0);
}

async function tenantLedgerEntryJson(id: string): Promise<string | undefined> {
  const row = await tenantObjectDb("tenant_a")
    .prepare("SELECT entry_json FROM billing_ledger WHERE id = ?")
    .bind(id)
    .first<{ entry_json: string }>();
  return row?.entry_json;
}

/** Request ids the test controls, so "same id twice" is expressible. */
function fixedRequestIds(id: string): RequestIdFactory {
  return { next: (): string => id };
}

function incrementingRequestIds(): RequestIdFactory {
  let next = 0;
  return {
    next: (): string => {
      next += 1;
      return `fg-${next.toString(16).padStart(16, "0")}`;
    },
  };
}

interface DurableHarness {
  readonly sink: MeteringUsageSink;
  readonly queue: RecordingQueue;
  readonly env: Record<string, unknown>;
  /** Serve one request on a REAL `ExecutionContext`, then await its `waitUntil`. */
  call(path: string, init: RequestInit): Promise<Response>;
  /** Await the `waitUntil` work of the most recent call. */
  settle(): Promise<void>;
  /** The body of the most recent streamed response, for the disconnect tests. */
  readonly lastContext: ExecutionContext | undefined;
}

/**
 * The composition root, on real bindings.
 *
 * `models` is a one-route registry; `bindings: meteringBindingsFromEnv` is the
 * production resolver, reading `BILLING_DB` / `BILLING` off whichever `env` the
 * request carries.
 */
function durableGateway(
  options: {
    readonly requestId?: string;
    readonly database?: RecordingDatabase;
    readonly providerModel?: string;
  } = {},
): DurableHarness {
  const queue = new RecordingQueue();
  const bindings: Record<string, unknown> = {
    ...(env as unknown as Record<string, unknown>),
    BILLING: queue,
    ...(options.database !== undefined ? { BILLING_DB: options.database } : {}),
  };

  const sink = createMeteringUsageSink({
    priceBook: pricedBook(),
    bindings: meteringBindingsFromEnv,
  });

  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([
          options.providerModel === undefined
            ? OPENAI_ROUTE
            : { ...OPENAI_ROUTE, providerModel: options.providerModel },
        ]),
        requestIds:
          options.requestId === undefined
            ? incrementingRequestIds()
            : fixedRequestIds(options.requestId),
        usage: sink,
      }),
    ],
    middleware: [meteringDrain(sink)],
  });

  let context: ExecutionContext | undefined;
  return {
    sink,
    queue,
    env: bindings,
    get lastContext(): ExecutionContext | undefined {
      return context;
    },
    async call(path, init): Promise<Response> {
      context = createExecutionContext();
      return app.fetch(new Request(`${BASE}${path}`, init), bindings, context);
    },
    async settle(): Promise<void> {
      if (context !== undefined) {
        await waitOnExecutionContext(context);
      }
    },
  };
}

function chatBody(stream: boolean, model = "gpt-4o-mini"): string {
  return JSON.stringify({
    model,
    messages: [{ role: "user", content: "hi" }],
    ...(stream ? { stream: true } : {}),
  });
}

const BUFFERED_COMPLETION = {
  id: "chatcmpl-1",
  object: "chat.completion",
  model: "gpt-4o-mini",
  choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
  usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
};

/** Early usage frame, then more content, then a LARGER trailing usage frame. */
const EARLY_USAGE_FRAMES: readonly string[] = [
  'data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"He"},"finish_reason":null}]}',
  'data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"llo"},"finish_reason":null}],"usage":{"prompt_tokens":11,"completion_tokens":2,"total_tokens":13}}',
  ...Array.from(
    { length: 40 },
    (_unused, index) =>
      `data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":" ${index}"},"finish_reason":null}]}`,
  ),
  'data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":40,"total_tokens":51}}',
  "data: [DONE]",
];

let provider: ProviderInterceptor | undefined;

beforeEach(async () => {
  await resetMeteringTables();
  await resetTenantBillingState(["tenant_a", "tenant_b"]);
});

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

/** The `credits_exact` decimal string SQLite is really holding for a row. */
async function storedCredits(id: string): Promise<string | undefined> {
  const json = await ledgerEntryJson(id);
  if (json === undefined) {
    return undefined;
  }
  const value = (JSON.parse(json) as Record<string, unknown>)[CREDITS_EXACT_FIELD];
  return typeof value === "string" ? value : undefined;
}

async function tenantStoredCredits(id: string): Promise<string | undefined> {
  const json = await tenantLedgerEntryJson(id);
  if (json === undefined) return undefined;
  const value = (JSON.parse(json) as Record<string, unknown>)[CREDITS_EXACT_FIELD];
  return typeof value === "string" ? value : undefined;
}

// ---------------------------------------------------------------------------

describe("durable metering — the bindings are real", () => {
  it("resolves BILLING_DB / BILLING off the request's env, never module state", () => {
    const h = durableGateway();
    // `ledgerFor(env)` is the per-request backend. Two different envs must not
    // share one: that is the concurrency property the widened seam exists for.
    const first = h.sink.ledgerFor(h.env);
    const second = h.sink.ledgerFor({ ...h.env });
    expect(first).not.toBe(h.sink.ledger); // NOT the in-isolate fallback
    expect(second).not.toBe(first); // resolved per env object
    // …and an env with no bindings falls back rather than throwing.
    expect(h.sink.ledgerFor({})).toBe(h.sink.ledger);
  });

  it("records tenant billing and wallet settlement in one tenant batch", async () => {
    const tenantDb = tenantObjectDb("tenant_a");
    await tenantDb.batch([
      tenantDb.prepare("DELETE FROM billing_report_outbox"),
      tenantDb.prepare("DELETE FROM billing_ledger"),
      tenantDb.prepare("DELETE FROM billing_events"),
      tenantDb.prepare("DELETE FROM wallet_settlements"),
      tenantDb.prepare("DELETE FROM wallets"),
      tenantDb
        .prepare(
          "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, " +
            "updated_at_unix) VALUES (?, ?, ?, 0, ?, ?)",
        )
        .bind("tenant_a", "tenant_a", 100, 1_700_000_000, 1_700_000_000),
    ]);

    const store = new D1LedgerStore(tenantDb, { tenantId: "tenant_a" });
    const charge = chargeFixture("tenant-a-billing-1", FIXTURE_CREDITS);

    expect(await store.record(charge)).toEqual({ status: "recorded" });
    expect(
      await tenantDb
        .prepare("SELECT tenant_id, organization_id FROM billing_ledger WHERE id = ?")
        .bind(charge.id)
        .first(),
    ).toEqual({ tenant_id: "tenant_a", organization_id: "tenant_a" });
    expect(
      await tenantDb.prepare("SELECT balance_credits FROM wallets WHERE id = ?").bind("tenant_a").first(),
    ).toEqual({ balance_credits: 96 });
    expect(
      await tenantDb
        .prepare(
          "SELECT tenant_id, delta_credits, balance_after_credits FROM wallet_settlements WHERE id = ?",
        )
        .bind(charge.id)
        .first(),
    ).toEqual({ tenant_id: "tenant_a", delta_credits: -4, balance_after_credits: 96 });

    expect(await store.record(charge)).toEqual({ status: "duplicate" });
    expect(await tenantDb.prepare("SELECT count(*) AS count FROM wallet_settlements").first()).toEqual({
      count: 1,
    });
  });

  it("does not debit a wallet when a divergent replay conflicts", async () => {
    const tenantDb = tenantObjectDb("tenant_a");
    const charge = chargeFixture("tenant-a-billing-conflict", FIXTURE_CREDITS);
    await tenantDb.batch([
      tenantDb
        .prepare(
          "INSERT INTO billing_events " +
            "(billing_event_id, tenant_id, request_id, provider_attempt_index, occurred_at_unix, event_json) " +
            "VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(
          charge.id,
          "tenant_a",
          charge.requestId,
          charge.entry.provider_attempt.provider_attempt_index,
          charge.occurredAtUnix,
          JSON.stringify(billingEventToWire(charge.event)),
        ),
      tenantDb
        .prepare(
          "INSERT INTO billing_ledger " +
            "(id, tenant_id, organization_id, project_id, api_key_id, created_at_unix, entry_json) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(
          charge.id,
          "tenant_a",
          "tenant_a",
          "project_1",
          null,
          charge.occurredAtUnix,
          JSON.stringify(ledgerDocument(charge)),
        ),
      tenantDb
        .prepare(
          "INSERT INTO billing_report_outbox " +
            "(id, tenant_id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix, updated_at_unix, event_json) " +
            "VALUES (?, ?, 0, ?, NULL, ?, ?, ?)",
        )
        .bind(
          charge.id,
          "tenant_a",
          charge.occurredAtUnix,
          charge.occurredAtUnix,
          charge.occurredAtUnix,
          JSON.stringify(billingEventToWire(charge.event)),
        ),
      tenantDb
        .prepare(
          "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix) " +
            "VALUES (?, ?, ?, 0, ?, ?)",
        )
        .bind("tenant_a", "tenant_a", 100, charge.occurredAtUnix, charge.occurredAtUnix),
    ]);

    const store = new D1LedgerStore(tenantDb, { tenantId: "tenant_a" });
    const divergent = { ...charge, credits: FIXTURE_CREDITS + 1n };
    const outcome = await store.record(divergent);

    expect(outcome.status).toBe("conflict");
    expect(
      await tenantDb.prepare("SELECT balance_credits FROM wallets WHERE id = ?").bind("tenant_a").first(),
    ).toEqual({ balance_credits: 100 });
    expect(await tenantDb.prepare("SELECT count(*) AS count FROM wallet_settlements").first()).toEqual({
      count: 0,
    });
  });

  it("rolls back billing, outbox, and wallet state when the tenant batch fails", async () => {
    const tenantDb = tenantObjectDb("tenant_a");
    const failingDb = new RecordingDatabase(tenantDb);
    failingDb.failBatchIndex = 5;
    const store = new D1LedgerStore(failingDb, { tenantId: "tenant_a" });
    const charge = chargeFixture("tenant-a-billing-rollback", FIXTURE_CREDITS);

    await tenantDb
      .prepare(
        "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix) " +
          "VALUES (?, ?, ?, 0, ?, ?)",
      )
      .bind("tenant_a", "tenant_a", 100, charge.occurredAtUnix, charge.occurredAtUnix)
      .run();

    await expect(store.record(charge)).rejects.toThrow();
    expect(await tenantRowCount("billing_events")).toBe(0);
    expect(await tenantRowCount("billing_ledger")).toBe(0);
    expect(await tenantRowCount("billing_report_outbox")).toBe(0);
    expect(await tenantDb.prepare("SELECT count(*) AS count FROM wallet_settlements").first()).toEqual({
      count: 0,
    });
    expect(
      await tenantDb.prepare("SELECT balance_credits FROM wallets WHERE id = ?").bind("tenant_a").first(),
    ).toEqual({ balance_credits: 100 });

    failingDb.failBatchIndex = undefined;
    expect(await store.record(charge)).toEqual({ status: "recorded" });
  });

  it("refuses wallet settlements outside SQLite int64 before the tenant batch", async () => {
    const tenantDb = tenantObjectDb("tenant_a");
    const charge = chargeFixture("tenant-a-billing-int64", FIXTURE_CREDITS);
    await tenantDb
      .prepare(
        "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix) " +
          "VALUES (?, ?, ?, 0, ?, ?)",
      )
      .bind("tenant_a", "tenant_a", 100, charge.occurredAtUnix, charge.occurredAtUnix)
      .run();

    const store = new D1LedgerStore(tenantDb, { tenantId: "tenant_a" });
    await expect(store.record({ ...charge, credits: (1n << 63n) + 1n })).rejects.toThrow("SQLite int64");
    expect(await tenantRowCount("billing_events")).toBe(0);
    expect(await tenantRowCount("billing_ledger")).toBe(0);
    expect(await tenantRowCount("billing_report_outbox")).toBe(0);
    expect(await tenantDb.prepare("SELECT count(*) AS count FROM wallet_settlements").first()).toEqual({
      count: 0,
    });
    expect(
      await tenantDb.prepare("SELECT balance_credits FROM wallets WHERE id = ?").bind("tenant_a").first(),
    ).toEqual({ balance_credits: 100 });
  });
});

describe("durable metering — both shapes of the widened seam", () => {
  /**
   * `UsageSink.record(u, rc?)` has two callers by design, and BOTH have to
   * persist:
   *
   *  - `rc` ABSENT — what `src/inference/handlers.ts` does today. The sink
   *    captures into the outbox and deliberately schedules no drain of its own
   *    (it has no `env` to drain into); `meteringDrain()` supplies `{ env, ctx }`
   *    from the middleware chain. Every other test in this file is this shape.
   *  - `rc` PRESENT — the one-line change `src/metering/index.ts` documents for
   *    `handlers.ts`. The sink drains itself, on the request's own `waitUntil`,
   *    against the request's own bindings. This test is that shape, and it is
   *    why the change is additive rather than a rewrite.
   */
  it("persists when `record` is given the request context directly", async () => {
    const queue = new RecordingQueue();
    const bindings = { ...(env as unknown as Record<string, unknown>), BILLING: queue };
    const sink = createMeteringUsageSink({
      priceBook: pricedBook(),
      bindings: meteringBindingsFromEnv,
    });
    const ctx = createExecutionContext();

    sink.record(usageFixture(), { env: bindings, ctx });
    await waitOnExecutionContext(ctx);

    expect(await tenantRowCount("billing_ledger")).toBe(1);
    expect(await tenantRowCount("billing_report_outbox")).toBe(0);
    expect(queue.sent).toHaveLength(1);
    expect(queue.sent[0]?.credits).toBe(FIXTURE_CREDITS.toString());
  });

  it("captures but does not settle when `record` is given no context", async () => {
    const sink = createMeteringUsageSink({
      priceBook: pricedBook(),
      bindings: meteringBindingsFromEnv,
    });

    sink.record(usageFixture());
    // Nothing to await: with a resolver configured and no `rc`, the sink
    // schedules NO drain. Draining here would settle into the in-isolate
    // fallback ledger and then delete the outbox row — a lost charge dressed up
    // as a successful one. The charge waits in the outbox for `meteringDrain()`.
    expect(sink.outbox.size).toBe(1);
    expect(await rowCount("billing_ledger")).toBe(0);
    expect(sink.stats.charged).toBe(1);
  });
});

describe("durable metering — a completed request", () => {
  it("writes exactly ONE ledger row, one event row and one outbox intent", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const h = durableGateway();

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    expect(response.status).toBe(200);
    const requestId = response.headers.get("x-request-id");
    expect(requestId).toBeTruthy();

    // (No "nothing is persisted yet" assertion here: for a BUFFERED response
    // the `waitUntil` work runs concurrently with the test's own awaits, so a
    // zero would be a race, not a property. The property — the client is never
    // made to wait on the durable write — is proved deterministically by
    // "serves the whole response while the D1 write is still blocked" below,
    // and by the streaming case, where the drain provably cannot have started.)
    await h.settle();

    expect(await rowCount("billing_ledger")).toBe(1);
    expect(await rowCount("billing_events")).toBe(1);
    // The outbox row was committed in the SAME batch (#150) and then removed by
    // the successful delivery — so a zero here is "delivered", not "never written".
    expect(await rowCount("billing_report_outbox")).toBe(0);
    expect(h.sink.stats.recorded).toBe(1);
    expect(h.sink.stats.delivered).toBe(1);

    const row = await billingDb()
      .prepare("SELECT id, organization_id, entry_json FROM billing_ledger")
      .first<{ id: string; organization_id: string | null; entry_json: string }>();
    expect(row?.id).toContain(requestId as string);
    const entry = JSON.parse(row?.entry_json ?? "{}") as Record<string, unknown>;
    expect(entry.provider_model).toBe("gpt-4o-mini-2024-07-18");
    expect(entry[CREDITS_EXACT_FIELD]).toBe(FIXTURE_CREDITS.toString());

    // …and exactly one billing report reached the real Queue producer.
    expect(h.queue.sent).toHaveLength(1);
    expect(h.queue.sent[0]?.id).toBe(row?.id);
    expect(h.queue.sent[0]?.credits).toBe(FIXTURE_CREDITS.toString());
  });

  it("does not double-charge the SAME request id (idempotency, issue #213)", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    // Both calls mint the same request id, so both settle to the same
    // `ledger_entry_id` — the replay shape a retrying client produces.
    const h = durableGateway({ requestId: "fg-00000000deadbeef" });

    await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    await h.settle();
    await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    await h.settle();

    // ONE row. The second write hit `ON CONFLICT (…) DO NOTHING`, was reloaded,
    // compared, and reported as a duplicate.
    expect(await rowCount("billing_ledger")).toBe(1);
    expect(await rowCount("billing_events")).toBe(1);
    // …and — the part a row count alone would NOT catch, because `ON CONFLICT`
    // stops the second INSERT either way — the replay produced no second
    // downstream report. A duplicate report is a double charge wherever the
    // consumer settles wallets.
    expect(h.queue.sent).toHaveLength(1);
    expect(h.sink.stats.recorded).toBe(1);
    expect(h.sink.stats.duplicates).toBe(1);
    // The stored charge is the FIRST settlement, unchanged.
    expect(
      await storedCredits("ferrogate:provider-attempt:fg-00000000deadbeef:provider-attempt:0"),
    ).toBe(FIXTURE_CREDITS.toString());
  });

  it("serves the whole response while the D1 write is still blocked", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));

    // A real D1, reached through a decorator that will not let `batch()` start
    // until the test says so. If metering were inline the response could not
    // have been produced before `release()`.
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const inner = new RecordingDatabase();
    const gated = new RecordingDatabase({
      prepare: (sql: string) => inner.prepare(sql),
      batch: async (statements) => {
        await gate;
        return inner.batch(statements);
      },
    });
    const h = durableGateway({ database: gated });

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ id: "chatcmpl-1" });

    // The complete response body reached the client with the write still gated.
    expect(await rowCount("billing_ledger")).toBe(0);

    release?.();
    await h.settle();
    expect(await rowCount("billing_ledger")).toBe(1);
    expect(h.queue.sent).toHaveLength(1);
  });

  it("meters an upstream failure durably too, so a 502 is not free", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({ error: { message: "upstream boom" } }, 500),
    );
    const h = durableGateway();

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    expect(response.status).toBe(500);
    await h.settle();

    expect(await rowCount("billing_ledger")).toBe(1);
    const entry = JSON.parse(
      (
        await billingDb()
          .prepare("SELECT entry_json FROM billing_ledger")
          .first<{ entry_json: string }>()
      )?.entry_json ?? "{}",
    ) as Record<string, unknown>;
    expect(entry.status_code).toBe(500);
    expect(entry[CREDITS_EXACT_FIELD]).toBe("0");
  });
});

describe("durable metering — fail closed (issue #129, corrected by #663)", () => {
  /**
   * CHANGED FOR #663, deliberately and not around.
   *
   * This block used to assert `billing_events` = 0 as CORRECT behaviour, i.e.
   * it encoded the defect as intent: a served, billable request against a model
   * outside the rate card was recorded NOWHERE, and the suite called that
   * fail-closed. It is not. Rust's `state_billing_metering.rs:146-152` skipped
   * only the WALLET DEBIT when `cost_usd` was absent and ran
   * `append_billing_event_with_outbox_enqueue` regardless, so the same input
   * produced an event row there and zero rows here.
   *
   * What #129 actually forbids is BILLING — a `billing_ledger` row, an outbox
   * intent, a downstream report, a charge of zero. Those four assertions are
   * unchanged and still the point of this test. The fifth, on `billing_events`,
   * was wrong and is inverted.
   */
  it("bills nothing, but still records the usage (null cost_usd)", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        ...BUFFERED_COMPLETION,
        model: "unpriced",
        usage: { prompt_tokens: 100, completion_tokens: 100, total_tokens: 200 },
      }),
    );
    // Resolves and dispatches fine, but is absent from the rate card.
    const h = durableGateway({ providerModel: "unpriced-model-9000" });

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    // The CLIENT is served normally — fail-closed is a BILLING refusal, not a
    // request refusal; the Rust gateway also served the response.
    expect(response.status).toBe(200);
    await h.settle();

    // NOTHING IS BILLED: no ledger row, no outbox intent, no queue message.
    // Billing at zero here would be a free-inference bug, and it would be
    // invisible. This is #129 and it is unchanged.
    expect(await rowCount("billing_ledger")).toBe(0);
    expect(await rowCount("billing_report_outbox")).toBe(0);
    expect(h.queue.sent).toHaveLength(0);

    // …but the USAGE IS RECORDED (#663). Asserting 0 here — as this file used
    // to — is asserting that a request the customer was served and the provider
    // was paid for leaves no trace at all.
    expect(await rowCount("billing_events")).toBe(1);
    const stored = await billingDb()
      .prepare("SELECT request_id, event_json FROM billing_events")
      .first<{ request_id: string; event_json: string }>();
    const event = JSON.parse(stored?.event_json ?? "{}") as {
      provider_model: string;
      cost_usd?: number | null;
      usage: { prompt_tokens: number; completion_tokens: number };
    };
    expect(event.provider_model).toBe("unpriced-model-9000");
    // NULL, never 0 — the row says "this happened and nobody could price it",
    // which is a different statement from "this cost nothing".
    expect(event.cost_usd ?? null).toBeNull();
    // The token counts are what make it re-priceable once a rule is added.
    expect(event.usage.prompt_tokens).toBe(100);
    expect(event.usage.completion_tokens).toBe(100);

    // The refusal is COUNTED and inspectable, never silent.
    expect(h.sink.stats.priceNotFound).toBe(1);
    expect(h.sink.stats.unpricedRecorded).toBe(1);
    expect(h.sink.unpriced[0]?.providerModel).toBe("unpriced-model-9000");
  });

  it("routes an unpriced event by matching request attribution", async () => {
    const h = durableGateway();
    const requestId = "fg-unpriced-tenant-attribution";
    const context = createExecutionContext();

    h.sink.record(
      usageFixture({
        requestId,
        providerModel: "unpriced-model-9000",
        tenantId: undefined,
        projectId: undefined,
      }),
      {
        env: h.env,
        ctx: context,
        attribution: { requestId, tenantId: "tenant_a" },
      },
    );
    await waitOnExecutionContext(context);

    expect(await rowCount("billing_events")).toBe(0);
    expect(await tenantRowCount("billing_events")).toBe(1);
    const row = await tenantObjectDb("tenant_a")
      .prepare("SELECT tenant_id, event_json FROM billing_events")
      .first<{ tenant_id: string; event_json: string }>();
    expect(row?.tenant_id).toBe("tenant_a");
    expect(JSON.parse(row?.event_json ?? "{}")).toMatchObject({
      request_id: requestId,
      tenant: { organization_id: "tenant_a" },
    });
  });
});

describe("durable metering — integer credits past 2^53", () => {
  it("carries an exact bigint through BOTH durable seams", async () => {
    const huge = 9_007_199_254_740_993n; // 2^53 + 1
    const id = "ferrogate:huge";
    const outbox = new InMemoryMeteringOutbox();
    outbox.enqueue(chargeFixture(id, huge), 0);

    const queue = new RecordingQueue();
    const sink = createMeteringUsageSink({
      priceBook: pricedBook(),
      outbox,
      bindings: meteringBindingsFromEnv,
    });
    await sink.flush({
      env: { ...(env as unknown as Record<string, unknown>), BILLING: queue },
    });

    // D1: the decimal string SQLite really holds.
    expect(await tenantStoredCredits(id)).toBe("9007199254740993");
    // Queue: the same string, because a Queue body is JSON/structured-clone
    // encoded and a JSON number would arrive one credit short.
    expect(queue.sent[0]?.credits).toBe("9007199254740993");
    expect(BigInt(queue.sent[0]?.credits ?? "0")).toBe(huge);
    // …and it reads back through the store as the same bigint.
    expect((await sink.ledgerFor({ ...env }, "tenant_a").get(id))?.credits).toBe(huge);
    expect((await sink.ledgerFor({ ...env }, "tenant_a").totals()).credits).toBe(huge);
  });
});

describe("durable metering — streaming", () => {
  it("persists the usage frame that arrives long after the response started", async () => {
    provider = interceptProviderFetch(() => providerSse(EARLY_USAGE_FRAMES));
    const h = durableGateway();

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(true),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    // Headers are out and nothing is persisted: the usage frame has not been
    // read yet, so metering CANNOT have delayed them.
    expect(await rowCount("billing_ledger")).toBe(0);

    const body = await readBody(response);
    expect(body).toContain("[DONE]");
    await h.settle();

    expect(await rowCount("billing_ledger")).toBe(1);
    const entry = JSON.parse(
      (
        await billingDb()
          .prepare("SELECT entry_json FROM billing_ledger")
          .first<{ entry_json: string }>()
      )?.entry_json ?? "{}",
    ) as { usage?: Record<string, number>; [key: string]: unknown };
    // The FINAL usage frame wins, not the early partial one.
    // The three zeros are #667's counters: this fixture's provider reports no
    // cached or reasoning tokens, and the equality stays EXACT (rather than
    // becoming a `toMatchObject`) so a future change that started smuggling
    // non-zero cached tokens into an uncached request would fail here.
    expect(entry.usage).toEqual({
      prompt_tokens: 11,
      completion_tokens: 40,
      total_tokens: 51,
      cached_input_tokens: 0,
      cache_write_tokens: 0,
      reasoning_tokens: 0,
    });
    // 11 * 0.15/1e6 + 40 * 0.6/1e6 = 2.565e-5 USD ⇒ 26 credits (25.65, rounded).
    expect(entry[CREDITS_EXACT_FIELD]).toBe("26");
    expect(h.queue.sent).toHaveLength(1);
  });

  it("persists what was consumed when the client disconnects mid-stream", async () => {
    provider = interceptProviderFetch(() => providerSse(EARLY_USAGE_FRAMES));
    const h = durableGateway();

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(true),
    });
    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    const decoder = new TextDecoder();
    let seen = "";
    while (!seen.includes('"completion_tokens":2')) {
      const chunk = await reader.read();
      expect(chunk.done, "the early usage frame must arrive before the stream ends").toBe(false);
      seen += decoder.decode(chunk.value, { stream: true });
    }
    // The trailing 40-token usage frame has NOT been delivered.
    expect(seen).not.toContain('"completion_tokens":40');
    await reader.cancel("client went away");

    await h.settle();

    // The charge SURVIVED the hang-up, in D1, with the consumed tokens — not
    // the trailing frame (billing tokens nobody received) and not nothing (the
    // cost leak the tap's `cancel()` exists to close).
    expect(await rowCount("billing_ledger")).toBe(1);
    const entry = JSON.parse(
      (
        await billingDb()
          .prepare("SELECT entry_json FROM billing_ledger")
          .first<{ entry_json: string }>()
      )?.entry_json ?? "{}",
    ) as { usage?: Record<string, number>; usage_source?: string; [key: string]: unknown };
    expect(entry.usage).toEqual({
      prompt_tokens: 11,
      completion_tokens: 2,
      total_tokens: 13,
      // #667 — an abandoned stream reported no cached/reasoning counters.
      cached_input_tokens: 0,
      cache_write_tokens: 0,
      reasoning_tokens: 0,
    });
    // 11 * 0.15/1e6 + 2 * 0.6/1e6 = 2.85e-6 USD ⇒ 3 credits.
    expect(entry[CREDITS_EXACT_FIELD]).toBe("3");
    expect(entry.usage_source).toBe("provider_usage");
    expect(h.queue.sent).toHaveLength(1);
  });
});

describe("durable metering — the Cron sweep recovers a stranded charge", () => {
  /**
   * Strand one charge: the ledger batch commits (so the tenant IS charged) and
   * the Queue publish fails, then the isolate that owned the retry goes away.
   * A FRESH `MeteringUsageSink` stands in for the next isolate — it has an empty
   * in-memory outbox, exactly like a cold start, so the only trace of the charge
   * is the durable `billing_report_outbox` row.
   */
  async function strandOneCharge(): Promise<{
    id: string;
    nextAttemptUnix: number;
    attempts: number;
  }> {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const h = durableGateway();
    h.queue.failure = new Error("queue unavailable");
    await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    await h.settle();

    const row = await billingDb()
      .prepare("SELECT id, attempts, next_attempt_unix FROM billing_report_outbox")
      .first<{ id: string; attempts: number; next_attempt_unix: number }>();
    expect(row, "the strand step must leave a durable outbox row").toBeTruthy();
    expect(await rowCount("billing_ledger")).toBe(1);
    return {
      id: row?.id ?? "",
      nextAttemptUnix: row?.next_attempt_unix ?? 0,
      attempts: row?.attempts ?? 0,
    };
  }

  /** A cold isolate: fresh sink, empty in-memory outbox, real bindings. */
  function coldSink(queue: RecordingQueue): {
    sink: MeteringUsageSink;
    rc: { env: Record<string, unknown> };
  } {
    return {
      sink: createMeteringUsageSink({
        priceBook: pricedBook(),
        bindings: meteringBindingsFromEnv,
      }),
      rc: { env: { ...(env as unknown as Record<string, unknown>), BILLING: queue } },
    };
  }

  it("re-publishes it and drops the intent", async () => {
    const stranded = await strandOneCharge();
    const queue = new RecordingQueue();
    const { sink, rc } = coldSink(queue);

    // The in-memory outbox of this "new isolate" knows nothing.
    expect(sink.outbox.size).toBe(0);

    await sink.sweep(rc, stranded.nextAttemptUnix + OUTBOX_SWEEP_GRACE_SECONDS + 1);

    expect(queue.sent).toHaveLength(1);
    expect(queue.sent[0]?.id).toBe(stranded.id);
    expect(queue.sent[0]?.credits).toBe(FIXTURE_CREDITS.toString());
    expect(await rowCount("billing_report_outbox")).toBe(0);
    expect(sink.stats.delivered).toBe(1);
    // …and it did NOT re-run the ledger write: one row before, one row after,
    // and no `duplicate` (which would have dropped the row UNDELIVERED — the
    // exact failure `OutboxRecord.settled` exists to prevent).
    expect(await rowCount("billing_ledger")).toBe(1);
    expect(sink.stats.duplicates).toBe(0);
    expect(sink.stats.recorded).toBe(0);
  });

  it("leaves a row still owned by its own request's waitUntil alone", async () => {
    const stranded = await strandOneCharge();
    const queue = new RecordingQueue();
    const { sink, rc } = coldSink(queue);

    // One second inside the grace window.
    await sink.sweep(rc, stranded.nextAttemptUnix + OUTBOX_SWEEP_GRACE_SECONDS - 1);

    expect(queue.sent).toHaveLength(0);
    expect(await rowCount("billing_report_outbox")).toBe(1);
  });

  it("arms the durable backoff ladder when the re-publish also fails", async () => {
    const stranded = await strandOneCharge();
    const queue = new RecordingQueue();
    queue.failure = new Error("still unavailable");
    const { sink, rc } = coldSink(queue);
    const now = stranded.nextAttemptUnix + OUTBOX_SWEEP_GRACE_SECONDS + 1;

    // The strand step's OWN failed publish already wrote its attempt through to
    // the durable row — the request-time drain keeps the same ladder the sweep
    // reads, which is what makes the two paths one counter rather than two.
    expect(stranded.attempts).toBe(1);

    await sink.sweep(rc, now);

    expect(sink.stats.deliveryFailures).toBe(1);
    const row = await billingDb()
      .prepare(
        "SELECT attempts, next_attempt_unix, dead_lettered_at_unix FROM billing_report_outbox",
      )
      .first<{
        attempts: number;
        next_attempt_unix: number;
        dead_lettered_at_unix: number | null;
      }>();
    // attempts 1 → 2, and the deadline moved out by the SECOND rung of the
    // capped exponential ladder (1, 2, 4, 8, 16, 32, 60…) — the ladder is read
    // from the durable row, so it survives the isolate that started it.
    expect(row?.attempts).toBe(2);
    expect(row?.next_attempt_unix).toBe(now + 2);
    expect(row?.dead_lettered_at_unix).toBeNull();
    // …and the charge is still there to retry, not silently dropped.
    expect(await rowCount("billing_report_outbox")).toBe(1);
  });

  it("dead-letters past MAX_BILLING_OUTBOX_ATTEMPTS and never sweeps it again", async () => {
    const stranded = await strandOneCharge();
    const queue = new RecordingQueue();
    queue.failure = new Error("permanently unavailable");
    const { sink, rc } = coldSink(queue);
    const now = stranded.nextAttemptUnix + OUTBOX_SWEEP_GRACE_SECONDS + 1;

    // One rung short of the cutoff.
    await billingDb()
      .prepare("UPDATE billing_report_outbox SET attempts = ? WHERE id = ?")
      .bind(MAX_BILLING_OUTBOX_ATTEMPTS - 1, stranded.id)
      .run();

    await sink.sweep(rc, now);

    expect(sink.stats.deadLettered).toBe(1);
    const row = await billingDb()
      .prepare("SELECT dead_lettered_at_unix FROM billing_report_outbox")
      .first<{ dead_lettered_at_unix: number | null }>();
    expect(row?.dead_lettered_at_unix).toBe(now);

    // A dead letter is kept for inspection (#143) but is out of the due set, so
    // a permanently-undeliverable report cannot starve every later sweep.
    queue.failure = undefined;
    await sink.sweep(rc, now + 100_000);
    expect(queue.sent).toHaveLength(1); // only the failed attempt, no new one
    expect(await rowCount("billing_report_outbox")).toBe(1);
  });

  it("is a no-op against a backend with no durable outbox", async () => {
    // An `env` with no `BILLING_DB` falls back to the in-isolate ledger, which
    // writes no durable intent. The sweep must return quietly, not throw.
    const sink = createMeteringUsageSink({
      priceBook: pricedBook(),
      bindings: meteringBindingsFromEnv,
    });
    await sink.sweep({ env: {} });
    expect(sink.stats.delivered).toBe(0);
  });
});

describe("durable metering — an outage keeps the charge", () => {
  it("leaves the outbox row queued when the Queue rejects, and delivers on the next drain", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const h = durableGateway();
    h.queue.failure = new Error("queue unavailable");

    await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    await h.settle();

    // The ledger row landed — the batch committed before the publish — and the
    // durable outbox row is still there, which is what a Cron sweep recovers.
    expect(await rowCount("billing_ledger")).toBe(1);
    expect(await rowCount("billing_report_outbox")).toBe(1);
    expect(h.sink.stats.recorded).toBe(1);
    expect(h.sink.stats.delivered).toBe(0);
    expect(h.sink.stats.deliveryFailures).toBe(1);
  });

  it("never lets a D1 outage reach the client", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const database = new RecordingDatabase();
    database.failure = new Error("D1_ERROR: network");
    const h = durableGateway({ database });

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    // 200 to the caller; the metering failure is counted, not surfaced.
    expect(response.status).toBe(200);
    await h.settle();

    expect(await rowCount("billing_ledger")).toBe(0);
    expect(h.sink.stats.deliveryFailures).toBe(1);
    expect(h.queue.sent).toHaveLength(0);
  });
});
