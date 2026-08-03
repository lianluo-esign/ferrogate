/**
 * ANTI-UNMOUNT — the committed-token FEEDBACK LOOP, closed end to end.
 *
 * Two admission gates read tables that, before this slice, **nothing in
 * `apps/` ever wrote**:
 *
 *  - `src/ratelimit/quota.ts::d1SpendSource` reads `usage_monthly_rollups` to
 *    decide the monthly USD budget;
 *  - `src/ratelimit/token-budget.ts` reads `usage_aggregate_rollups` (through
 *    `@ferrogate/storage`'s `sumApiKeyCommittedTokens`) to decide
 *    `api_keys.monthly_token_budget`.
 *
 * `docs/rewrite/parity-audit-storage.md` §4.3 names the second one: "TS has the
 * *consumer* … but **no production caller**, because nothing supplies
 * `committed`." This file proves the supply exists, and the LAST test closes
 * the circle: it drives a real request through the real composition and then
 * asks the real budget source what it now reads.
 *
 * The mount under test is `MeteringUsageSink.#accumulate`, called from
 * `#deliverOnce` on the `recorded` branch. Delete that call and every test in
 * "the loop" goes red.
 */
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import {
  type MeteringAttribution,
  createMeteringUsageSink,
  meteringBindingsFromEnv,
  meteringDrain,
  usageContextId,
  usageDatabaseFrom,
  usageScopesFor,
  usageWriteFor,
} from "../../src/metering/index.js";
import { d1TokenBudgetSource, rateLimit } from "../../src/ratelimit/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { tenantDatabase } from "../../src/tenancy/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import { interceptProviderFetch, providerJson } from "../inference/provider-mock.js";
import { RecordingQueue, resetMeteringTables } from "./d1-harness.js";
import { chargeFixture, pricedBook, usageFixture } from "./fixtures.js";

const db = (env as unknown as { DB: D1Database }).DB;
const BASE = "https://gw.test";

const ATTRIBUTION: MeteringAttribution = {
  requestId: "fg-000000000000002a",
  tenantId: "tenant_a",
  projectId: "project_1",
  workspaceId: "ws_1",
  apiKeyId: "key_metered",
};

interface RollupRow {
  readonly total_tokens: number;
  readonly api_key_id: string | null;
}

/** Every `usage_aggregate_rollups` row, joined to the context it is filed under. */
async function aggregateRows(): Promise<RollupRow[]> {
  const result = await db
    .prepare(
      "SELECT r.total_tokens AS total_tokens, c.api_key_id AS api_key_id " +
        "FROM usage_aggregate_rollups r JOIN tenant_contexts c ON c.id = r.tenant_context_id",
    )
    .all<RollupRow>();
  return result.results;
}

async function monthlyScopes(): Promise<{ scope_type: string; scope_id: string }[]> {
  const result = await db
    .prepare("SELECT scope_type, scope_id FROM usage_monthly_rollups ORDER BY scope_type")
    .all<{ scope_type: string; scope_id: string }>();
  return result.results;
}

beforeEach(async () => {
  await resetMeteringTables();
  await db.prepare("DELETE FROM usage_aggregate_rollups").run();
  await db.prepare("DELETE FROM usage_monthly_rollups").run();
  await db.prepare("DELETE FROM tenant_contexts").run();
  await db.prepare("DELETE FROM api_keys").run();
});

// ---------------------------------------------------------------------------
// The pure projection
// ---------------------------------------------------------------------------

describe("usageWriteFor — attribution belongs to ONE request", () => {
  test("a matching request id contributes the api-key scope", () => {
    const charge = chargeFixture(ATTRIBUTION.requestId, 4n);
    const write = usageWriteFor(charge, ATTRIBUTION);
    expect(write?.context.apiKeyId).toBe("key_metered");
    expect(write?.scopes.map((scope) => scope.scopeType)).toEqual([
      "tenant",
      "project",
      "workspace",
      "key",
    ]);
  });

  test("a NON-matching request id is dropped, not applied to someone else's charge", () => {
    // A drain pass can pick up an outbox row left by an EARLIER request whose
    // drain failed. Stamping this request's credential onto that charge would
    // attribute one key's spend to another; dropping it under-attributes.
    const charge = chargeFixture("fg-some-other-request", 4n);
    const write = usageWriteFor(charge, ATTRIBUTION);
    expect(write?.context.apiKeyId).toBeUndefined();
    // The tenant/project rollups still land — only the per-key leg is lost.
    expect(write?.scopes.map((scope) => scope.scopeType)).toEqual(["tenant", "project"]);
  });

  test("a charge with no scope at all is REFUSED, never written", () => {
    const charge = chargeFixture("fg-orphan", 4n);
    const orphan = { ...charge, event: { ...charge.event, tenant: {} } };
    expect(usageWriteFor(orphan, undefined)).toBeNull();
  });

  test("the context id is a shared dimension, not per-request", () => {
    // A per-request id would make `usage_aggregate_rollups` unbounded and turn
    // `sumApiKeyCommittedTokens`'s join into a full scan.
    expect(usageContextId(["t", undefined, "", "k"])).toBe("t:-:-:k");
    expect(usageScopesFor(undefined, chargeFixture("x", 1n).event)).toEqual([
      { scopeType: "tenant", scopeId: "tenant_a" },
      { scopeType: "project", scopeId: "project_1" },
    ]);
  });

  test("usageDatabaseFrom only accepts a real D1 binding", () => {
    expect(usageDatabaseFrom({ DB: db })).toBe(db);
    expect(usageDatabaseFrom({ DB: "a-var-string" })).toBeUndefined();
    expect(usageDatabaseFrom(undefined)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The drain writes the rollups
// ---------------------------------------------------------------------------

describe("the loop: the metering drain accumulates into the tenant database", () => {
  function sinkFor(queue: RecordingQueue) {
    return createMeteringUsageSink({
      priceBook: pricedBook(),
      bindings: meteringBindingsFromEnv,
    });
  }

  function bindings(queue: RecordingQueue): Record<string, unknown> {
    return { ...(env as unknown as Record<string, unknown>), BILLING: queue };
  }

  test("a settled charge lands in usage_aggregate_rollups under the api key", async () => {
    const queue = new RecordingQueue();
    const sink = sinkFor(queue);

    sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
    await sink.flush({ env: bindings(queue), attribution: ATTRIBUTION });

    expect(sink.stats.recorded).toBe(1);
    expect(sink.stats.aggregated).toBe(1);
    expect(await aggregateRows()).toEqual([{ total_tokens: 15, api_key_id: "key_metered" }]);
  });

  test("and in usage_monthly_rollups for every scope in the chain", async () => {
    const queue = new RecordingQueue();
    const sink = sinkFor(queue);
    sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
    await sink.flush({ env: bindings(queue), attribution: ATTRIBUTION });

    // `usage_monthly_rollups` is what `d1SpendSource.committedSpendUsd` reads.
    expect(await monthlyScopes()).toEqual([
      { scope_type: "key", scope_id: "key_metered" },
      { scope_type: "project", scope_id: "project_1" },
      { scope_type: "tenant", scope_id: "tenant_a" },
      { scope_type: "workspace", scope_id: "ws_1" },
    ]);
  });

  test("a REPLAY accumulates nothing — the accumulate is additive, not idempotent", async () => {
    const queue = new RecordingQueue();
    const sink = sinkFor(queue);
    const rc = { env: bindings(queue), attribution: ATTRIBUTION };

    sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
    await sink.flush(rc);
    // Same request id ⇒ same `ledgerEntryId` ⇒ the control-database claim
    // answers `duplicate`, and the tenant-database accumulate must NOT run.
    sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
    await sink.flush(rc);

    expect(sink.stats.aggregated).toBe(1);
    expect(await aggregateRows()).toEqual([{ total_tokens: 15, api_key_id: "key_metered" }]);
  });

  test("with no tenant database bound nothing accumulates and nothing throws", async () => {
    const queue = new RecordingQueue();
    const sink = sinkFor(queue);
    // Destructured out rather than `delete`d: the point is that the key is
    // ABSENT, not undefined — `env.DB` must not even be present for the
    // aggregate leg's binding probe to skip.
    const { DB: _unbound, ...withoutDb } = bindings(queue);

    sink.record(usageFixture({ requestId: ATTRIBUTION.requestId }));
    await sink.flush({ env: withoutDb, attribution: ATTRIBUTION });

    // The billing ledger still settles — only the aggregate leg is absent.
    expect(sink.stats.recorded).toBe(1);
    expect(sink.stats.aggregated).toBe(0);
    expect(await aggregateRows()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The circle: a real request makes the real budget source read a real number
// ---------------------------------------------------------------------------

/**
 * THE MOUNT GATE, and the reason this file exists.
 *
 * One inference request through the real composition — `createGatewayApp` with
 * `meteringDrain(sink)` outermost and `rateLimit()` behind it, on a REAL
 * `ExecutionContext` — followed by asking `d1TokenBudgetSource` (the object
 * `admitTokensPerMinute` uses) what the key has now committed.
 *
 * Before this slice that number was 0 forever, no matter how much traffic ran.
 */
describe("the loop, closed: a served request moves the token budget's own reading", () => {
  const KEY_ID = "key_loop";

  async function seedBudgetedKey(budget: number): Promise<void> {
    await db
      .prepare(
        "INSERT OR REPLACE INTO api_keys " +
          "(id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4, " +
          " enabled, monthly_token_budget, created_at_unix, updated_at_unix) " +
          "VALUES (?, 'ws_1', 'tenant_a', 'project_1', 'k', 'pfx', 'hash_loop', '0000', 1, ?, 1, 1)",
      )
      .bind(KEY_ID, budget)
      .run();
  }

  test("committed tokens go from 0 to the request's real total", async () => {
    await seedBudgetedKey(1_000_000);
    const budgets = d1TokenBudgetSource(db);

    const before = await budgets.forApiKey(KEY_ID, "tenant_a");
    expect(before).toEqual({ ok: true, budget: 1_000_000, committedTokens: 0 });

    const queue = new RecordingQueue();
    const sink = createMeteringUsageSink({
      priceBook: pricedBook(),
      bindings: meteringBindingsFromEnv,
    });
    const { app } = createGatewayApp({
      modules: [
        inferenceRouteModule({
          models: new InMemoryModelResolver([OPENAI_ROUTE]),
          requestIds: { next: () => "fg-00000000000000ff" },
          usage: sink,
        }),
      ],
      // The deployed order: the drain is OUTERMOST so it sees the final
      // response; `tenantDatabase()` next, because the limiter's wallet guard
      // (admission step 3b) reads the accessor it parks; the limiter behind
      // both. Omitting the middle entry is a 500 naming it rather than a quiet
      // fall back to the shared `DB`, which is the point of that throw.
      middleware: [meteringDrain(sink), tenantDatabase(), rateLimit()],
    });

    const bindings: Record<string, unknown> = {
      ...(env as unknown as Record<string, unknown>),
      BILLING: queue,
      // A durable/native key whose id is the one the budget is filed under, so
      // `meteringDrain`'s attribution names it.
      GATEWAY_NATIVE_API_KEYS: JSON.stringify([
        { key: "fg_loop", id: KEY_ID, tenant_id: "tenant_a", project_id: "project_1", scopes: [] },
      ]),
    };

    const provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
        usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
      }),
    );
    try {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request(`${BASE}/v1/chat/completions`, {
          method: "POST",
          headers: { authorization: "Bearer fg_loop", "content-type": "application/json" },
          body: JSON.stringify({
            model: "gpt-4o-mini",
            messages: [{ role: "user", content: "hi" }],
          }),
        }),
        bindings,
        ctx,
      );
      expect(response.status).toBe(200);
      await waitOnExecutionContext(ctx);
    } finally {
      provider.restore();
    }

    // THE ASSERTION. The gate's own source now reads the tokens the request
    // really spent, because the drain wrote the rows it sums.
    const after = await budgets.forApiKey(KEY_ID, "tenant_a");
    expect(after).toEqual({ ok: true, budget: 1_000_000, committedTokens: 15 });
  });
});
