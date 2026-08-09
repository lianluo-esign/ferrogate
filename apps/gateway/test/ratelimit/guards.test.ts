/**
 * ANTI-UNMOUNT — the four guards that existed, were tested, and guarded nothing.
 *
 * `docs/rewrite/parity-audit-storage.md` §4.1/§4.3 and the markers in
 * `packages/policy/src/{policy-engine,workflow-budget}.ts` all describe the same
 * defect: a correct, covered implementation with ZERO importers under `apps/`.
 * This file exists so that each of the four call sites `src/ratelimit/` now
 * makes cannot be deleted without a test going red.
 *
 * Each `describe` below names the ONE line whose removal turns it red. That is
 * the point of the file — the guards themselves are already proven by
 * `packages/storage/test/d1/wallet-d1.test.ts`,
 * `packages/policy/test/policy-engine.test.ts` and
 * `packages/policy/test/workflow-budget.test.ts`. What was never proven is that
 * the gateway CALLS them.
 *
 * Nothing here is mocked at the storage layer: `env.DB` is miniflare's real
 * SQLite tenant database with the DEPLOYED migration applied
 * (`test/setup-d1.ts`), `env.RATE_LIMIT` is the real Durable Object namespace
 * `wrangler.toml` declares, and `SELF` is `src/worker.ts` with
 * `GATEWAY_MIDDLEWARE`, i.e. `rateLimit()` with NO arguments — so every default
 * asserted here is the default the deployed Worker gets.
 *
 * ## WHERE THE WALLET LIVES (#819)
 *
 * `wrangler.toml` now ships `GATEWAY_TENANT_DB_ROUTING = "durable_object"`, so
 * the deployed wallet guard reads the tenant's OWN Durable Object rather than
 * the shared `env.DB`. The mount gate therefore seeds and asserts through
 * {@link tenantWalletDb}, not `db` — and that is not a test detail to tidy
 * away, it is the property being gated: seeding `env.DB` and watching the guard
 * refuse would now prove only that some database somewhere had a row in it.
 * The two 429/hold cases below FAILED against `env.DB` the moment routing was
 * turned on, which is the correct signal and the reason they were moved.
 *
 * The UNIT cases in the same file keep using `db`: `d1WalletAdmission(db)` is
 * the `"off"`-mode constructor and is still shipped for self-hosted
 * single-tenant deploys, so it is still worth its coverage.
 */
import { SELF, env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import type { MiddlewareHandler } from "hono";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { GatewayEnv } from "../../src/ports.js";
import {
  DEFAULT_WALLET_HOLD_CREDITS,
  WORKFLOW_ID_HEADER,
  WORKFLOW_RUN_ID_HEADER,
  WORKFLOW_VERSION_HEADER,
  compilePolicyRules,
  d1TokenBudgetSource,
  d1WalletAdmission,
  d1WorkflowBudgetSource,
  expandPolicyRule,
  policyRulesFromEnv,
  rateLimit,
  walletHoldCreditsFromEnv,
  workflowDeclarationFrom,
} from "../../src/ratelimit/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { tenantDatabase } from "../../src/tenancy/index.js";
import { ALL_ROUTES, errorBody, fixedRequestIds } from "../inference/fixtures.js";
import { interceptProviderFetch, providerJson } from "../inference/provider-mock.js";
import { controlNamespace } from "../support/control-namespace.js";

const db = (env as unknown as { DB: D1Database }).DB;
const vars = env as unknown as Record<string, string | undefined>;

/**
 * One tenant's routed database — the same object `SELF` reaches, addressed the
 * same way (`TENANT_DATA.idFromName(tenantId)`).
 *
 * Built through `@ferrogate/storage`'s router rather than by calling
 * `idFromName` here, so this helper cannot drift from the addressing the
 * gateway actually uses. If it did, the mount gate would seed one object and
 * assert against another, and would pass or fail for reasons unrelated to the
 * guard.
 */
function tenantWalletDb(tenantId: string): D1Database {
  const bindings = env as unknown as {
    TENANT_DATA: ConstructorParameters<typeof DurableObjectTenantDatabaseRouter>[0];
    CONTROL_DB: D1Database;
  };
  return new DurableObjectTenantDatabaseRouter(
    bindings.TENANT_DATA,
    bindings.CONTROL_DB,
  ).databaseFor(tenantId);
}

const NOW = 1_800_000_000;
const LATER = NOW + 3600;

const BASE = "https://gateway.test";
/** `GET /v1/models` — the cheapest authenticated contract operation. */
const MODELS = `${BASE}/v1/models`;
/** tenant_a, api key id `key_unscoped`, empty scope set ⇒ data-plane access. */
const TENANT_A_KEY = "fg_tenant_unscoped";
const TENANT_A_KEY_ID = "key_unscoped";

interface ErrorEnvelope {
  readonly error: { readonly code: string; readonly message: string; readonly type: string };
}

async function seedWallet(tenantId: string, balanceCredits: number): Promise<void> {
  await db
    .prepare(
      "INSERT OR REPLACE INTO wallets " +
        "(id, tenant_id, balance_credits, created_at_unix, updated_at_unix) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(tenantId, tenantId, balanceCredits, NOW, NOW)
    .run();
}

async function reservationRows(
  tenantId: string,
): Promise<{ id: string; status: string; amount_credits: number }[]> {
  const result = await db
    .prepare(
      "SELECT id, status, amount_credits FROM wallet_reservations WHERE tenant_id = ? ORDER BY id",
    )
    .bind(tenantId)
    .all<{ id: string; status: string; amount_credits: number }>();
  return result.results;
}

/** {@link seedWallet}, but into the tenant's OWN object — what `SELF` reads. */
async function seedRoutedWallet(tenantId: string, balanceCredits: number): Promise<void> {
  await tenantWalletDb(tenantId)
    .prepare(
      "INSERT OR REPLACE INTO wallets " +
        "(id, tenant_id, balance_credits, created_at_unix, updated_at_unix) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(tenantId, tenantId, balanceCredits, NOW, NOW)
    .run();
}

/** {@link reservationRows}, but from the tenant's OWN object. */
async function routedReservationRows(
  tenantId: string,
): Promise<{ id: string; status: string; amount_credits: number }[]> {
  const result = await tenantWalletDb(tenantId)
    .prepare(
      "SELECT id, status, amount_credits FROM wallet_reservations WHERE tenant_id = ? ORDER BY id",
    )
    .bind(tenantId)
    .all<{ id: string; status: string; amount_credits: number }>();
  return result.results;
}

async function get(key: string, headers: Record<string, string> = {}): Promise<Response> {
  return await SELF.fetch(MODELS, { headers: { Authorization: `Bearer ${key}`, ...headers } });
}

/** Restore every var this file mutates, so one test cannot leak into the next. */
const MUTATED_VARS = ["GATEWAY_POLICY_RULES", "GATEWAY_WALLET_HOLD_CREDITS"] as const;
const savedVars = new Map<string, string | undefined>();

beforeAll(async () => {
  // `test/setup-d1.ts` seeds the fixture tenants' roster rows but leaves
  // `migration_state` at its schema DEFAULT — 'shared', a PRE-cutover state
  // that makes `BackendDispatchingTenantDatabaseRouter` serve tenant_a from the
  // legacy shared `env.DB`. The mount gates below assert the post-cutover
  // posture (the tenant's own object is the authority), so record the cutover.
  await (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB.prepare(
    "UPDATE tenant_databases SET migration_state = 'done' WHERE tenant_id = 'tenant_a'",
  ).run();
});

beforeEach(async () => {
  for (const name of MUTATED_VARS) savedVars.set(name, vars[name]);
  // The tenant's OBJECT is truncated explicitly, and it has to be: this pool's
  // per-test isolated storage rolls back D1 and the DO key-value API, but the
  // rows a Durable Object holds in `ctx.storage.sql` survive into the next test
  // — measured here, when three holds taken by earlier cases showed up in a
  // case that had taken none. Without these two statements the mount gate would
  // read another test's ledger and pass or fail for the wrong reason.
  const routed = tenantWalletDb("tenant_a");
  await routed.prepare("DELETE FROM wallet_reservations").run();
  await routed.prepare("DELETE FROM wallets").run();
  await routed.prepare("DELETE FROM workflow_run_budgets").run();
  await db.prepare("DELETE FROM wallets").run();
  await db.prepare("DELETE FROM wallet_reservations").run();
  await db.prepare("DELETE FROM workflow_run_budgets").run();
  await db.prepare("DELETE FROM api_keys").run();
  await db.prepare("DELETE FROM tenant_contexts").run();
  await db.prepare("DELETE FROM usage_aggregate_rollups").run();
});

afterEach(() => {
  for (const name of MUTATED_VARS) {
    const saved = savedVars.get(name);
    if (saved === undefined) delete vars[name];
    else vars[name] = saved;
  }
});

// ===========================================================================
// 1. WALLET NO-OVERSELL — `@ferrogate/storage`'s `D1WalletStore`
// ===========================================================================

describe("wallet no-oversell: the guard object", () => {
  test("a tenant with no wallet row is `not_applicable`, never a denial", async () => {
    const guard = d1WalletAdmission(db, { holdCredits: 5 });
    expect(await guard.reserve("tenant_a", "hold_a", NOW)).toEqual({ kind: "not_applicable" });
  });

  test("a funded wallet is admitted and the hold is a REAL durable row", async () => {
    await seedWallet("tenant_a", 100);
    const guard = d1WalletAdmission(db, { holdCredits: 30 });
    const outcome = await guard.reserve("tenant_a", "hold_a", NOW);

    expect(outcome.kind).toBe("admitted");
    expect(await reservationRows("tenant_a")).toEqual([
      { id: "hold_a", status: "active", amount_credits: 30 },
    ]);

    // The `finally` in `rateLimit` calls exactly this.
    if (outcome.kind === "admitted") await outcome.hold.release();
    expect((await reservationRows("tenant_a"))[0]?.status).toBe("released");
  });

  test("a hold that does not fit is `insufficient`, with the arithmetic", async () => {
    await seedWallet("tenant_a", 10);
    const guard = d1WalletAdmission(db, { holdCredits: 25 });
    expect(await guard.reserve("tenant_a", "hold_big", NOW)).toEqual({
      kind: "insufficient",
      availableCredits: 10,
      requestedCredits: 25,
    });
  });

  /**
   * THE PROPERTY. 12 reserves issued together against a balance that affords 3.
   *
   * This is the race D1 cannot close with a read: `SELECT balance` followed by
   * `INSERT` admits all 12, because every reader sees the same funded balance.
   * The storage guard puts the predicate inside the INSERT, so SQLite evaluates
   * it against one committed snapshot per writer.
   *
   * The guard under test is `d1WalletAdmission` over a real D1 handle — the
   * exact `@ferrogate/storage` guard `rateLimit()`'s `routedWalletAdmission`
   * builds over the tenant object's handle — with the hold size read the way the
   * composition root reads it.
   */
  test("12 concurrent reserves against a balance affording 3 admit EXACTLY 3", async () => {
    await seedWallet("tenant_a", 30);
    vars.GATEWAY_WALLET_HOLD_CREDITS = "10";
    const guard = d1WalletAdmission(db, { holdCredits: walletHoldCreditsFromEnv(env as never) });

    const outcomes = await Promise.all(
      Array.from({ length: 12 }, (_, index) => guard.reserve("tenant_a", `burst_${index}`, NOW)),
    );

    expect(outcomes.filter((o) => o.kind === "admitted")).toHaveLength(3);
    expect(outcomes.filter((o) => o.kind === "insufficient")).toHaveLength(9);
    // And the durable state agrees: exactly 3 holds of 10 against a 30 balance.
    expect(await reservationRows("tenant_a")).toHaveLength(3);
  });

  test("a replayed hold id returns the FIRST outcome and takes no second hold", async () => {
    await seedWallet("tenant_a", 100);
    const guard = d1WalletAdmission(db, { holdCredits: 40 });
    expect((await guard.reserve("tenant_a", "hold_dup", NOW)).kind).toBe("admitted");
    expect((await guard.reserve("tenant_a", "hold_dup", NOW + 5)).kind).toBe("admitted");
    expect(await reservationRows("tenant_a")).toHaveLength(1);
  });

  test("a storage outage is `unavailable` (→503), never `insufficient` (→429)", async () => {
    const broken = {
      prepare(): never {
        throw new Error("D1_ERROR: no such table: wallets");
      },
    } as unknown as D1Database;
    const outcome = await d1WalletAdmission(broken).reserve("tenant_a", "hold_x", NOW);
    expect(outcome.kind).toBe("unavailable");
  });

  test("a hold size that is not a positive integer is ignored, not applied", () => {
    // `D1WalletStore` THROWS on a non-positive amount; applying one would turn
    // every wallet tenant's request into a 500.
    expect(walletHoldCreditsFromEnv({})).toBe(DEFAULT_WALLET_HOLD_CREDITS);
    expect(walletHoldCreditsFromEnv({ GATEWAY_WALLET_HOLD_CREDITS: "0" })).toBe(
      DEFAULT_WALLET_HOLD_CREDITS,
    );
    expect(walletHoldCreditsFromEnv({ GATEWAY_WALLET_HOLD_CREDITS: "-4" })).toBe(
      DEFAULT_WALLET_HOLD_CREDITS,
    );
    expect(walletHoldCreditsFromEnv({ GATEWAY_WALLET_HOLD_CREDITS: "2.5" })).toBe(
      DEFAULT_WALLET_HOLD_CREDITS,
    );
    expect(walletHoldCreditsFromEnv({ GATEWAY_WALLET_HOLD_CREDITS: "250" })).toBe(250);
  });
});

/**
 * MOUNT GATE. Delete the `wallet.reserve(...)` block from `rateLimit` (step 3b
 * in `src/ratelimit/middleware.ts`) and the tests below go red while every
 * other suite stays green.
 *
 * Since #819 they also gate the ROUTING: they seed
 * {@link seedRoutedWallet} — tenant_a's own Durable Object, addressed exactly
 * as the deployed Worker addresses it — so removing `tenantDatabase()` from
 * `GATEWAY_MIDDLEWARE`, or reverting the guard to `env.DB`, turns them red too.
 * The last case in this block is the one that states that directly.
 */
describe("wallet no-oversell: MOUNTED in the deployed app", () => {
  test("a request that would OVERDRAW the wallet is refused before dispatch", async () => {
    // Balance 5 is POSITIVE, so step 3 (the balance read) admits it — this can
    // only be refused by the reserve, which asks for 10 and does not fit.
    await seedRoutedWallet("tenant_a", 5);
    vars.GATEWAY_WALLET_HOLD_CREDITS = "10";

    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(429);
    const body = (await response.json()) as ErrorEnvelope;
    expect(body.error.code).toBe("wallet_balance_exhausted");
    expect(body.error.message).toBe("prepaid credit balance has been exhausted for this tenant");
    // Refused, so nothing may be left holding the tenant's money.
    expect(await routedReservationRows("tenant_a")).toHaveLength(0);
  });

  test("an admitted request takes a durable hold and RELEASES it on the way out", async () => {
    await seedRoutedWallet("tenant_a", 5_000);

    expect((await get(TENANT_A_KEY)).status).toBe(200);

    const rows = await routedReservationRows("tenant_a");
    expect(rows).toHaveLength(1);
    // The hold really was taken (so the guard ran) and really was let go (so a
    // served request cannot strand the tenant's credits) — JS has no `Drop`, so
    // this is `rateLimit`'s `finally`.
    expect(rows[0]?.status).toBe("released");
    expect(rows[0]?.amount_credits).toBe(DEFAULT_WALLET_HOLD_CREDITS);
  });

  test("a tenant with no wallet is untouched — the guard stays opt-in", async () => {
    expect((await get(TENANT_A_KEY)).status).toBe(200);
    expect(await routedReservationRows("tenant_a")).toHaveLength(0);
  });

  test("the guard reads the TENANT'S OBJECT, not the shared DB", async () => {
    // The routing assertion, stated as a contradiction between the two
    // databases: the shared `DB` is funded, the tenant's own object is not.
    // A guard still reading `env.DB` sees 5,000 credits and serves; the routed
    // guard sees no wallet row at all.
    await seedWallet("tenant_a", 5_000);
    vars.GATEWAY_WALLET_HOLD_CREDITS = "10";

    expect((await get(TENANT_A_KEY)).status).toBe(200);
    // No hold in EITHER database: not in the object (no wallet ⇒ opt-out), and
    // not in the shared one (nothing routes there any more).
    expect(await routedReservationRows("tenant_a")).toHaveLength(0);
    expect(await reservationRows("tenant_a")).toHaveLength(0);

    // And the inverse, in the same test so neither half can rot alone: fund the
    // OBJECT below the hold and the very same request is refused.
    await seedRoutedWallet("tenant_a", 5);
    const refused = await get(TENANT_A_KEY);
    expect(refused.status).toBe(429);
    expect(((await refused.json()) as ErrorEnvelope).error.code).toBe("wallet_balance_exhausted");
  });
});

// ===========================================================================
// 2. OPERATOR DENY RULES — `@ferrogate/policy`'s `BasicPolicyEngine`
// ===========================================================================

describe("deny rules: compilation", () => {
  test("empty subject lists are WILDCARDS, not 'matches nothing'", () => {
    // Rust `expand_optional_subjects`. Getting this backwards turns a
    // tenant-wide deny into a no-op.
    const rules = expandPolicyRule({
      name: "r",
      effect: "deny",
      organization_ids: [],
      project_ids: [],
      api_key_ids: [],
      models: [],
      providers: [],
      code: "c",
      message: "m",
      enabled: true,
    });
    expect(rules).toHaveLength(1);
    expect(rules[0]?.subject).toEqual({});
  });

  test("subject lists expand into the CROSS PRODUCT", () => {
    const rules = expandPolicyRule({
      name: "r",
      effect: "deny",
      organization_ids: ["t1", "t2"],
      project_ids: ["p1"],
      api_key_ids: ["k1", "k2"],
      models: [],
      providers: [],
      code: "c",
      message: "m",
      enabled: true,
    });
    expect(rules).toHaveLength(4);
    expect(rules.map((rule) => rule.subject.apiKeyId).sort()).toEqual(["k1", "k1", "k2", "k2"]);
  });

  test("disabled and non-deny rules are dropped", () => {
    const base = {
      name: "r",
      organization_ids: [],
      project_ids: [],
      api_key_ids: [],
      models: [],
      providers: [],
      code: "c",
      message: "m",
    };
    const set = compilePolicyRules([
      { ...base, effect: "deny", enabled: false },
      { ...base, effect: "allow", enabled: true },
    ]);
    expect(set.engine.rules).toHaveLength(0);
  });

  test("only a model/provider rule makes the request body worth reading", () => {
    const base = {
      name: "r",
      effect: "deny",
      organization_ids: ["t"],
      project_ids: [],
      api_key_ids: [],
      code: "c",
      message: "m",
      enabled: true,
    };
    expect(compilePolicyRules([{ ...base, models: [], providers: [] }]).needsRequestDocument).toBe(
      false,
    );
    expect(
      compilePolicyRules([{ ...base, models: ["gpt-4o"], providers: [] }]).needsRequestDocument,
    ).toBe(true);
    expect(
      compilePolicyRules([{ ...base, models: [], providers: ["openai"] }]).needsRequestDocument,
    ).toBe(true);
  });

  test("an UNREADABLE rule table fails CLOSED, it does not become 'no rules'", () => {
    // The opposite of `quota.ts::parseJsonVar`, and deliberately so: losing a
    // quota limit can only leave a limit unset, but losing a DENY rule grants
    // access.
    expect(policyRulesFromEnv({ GATEWAY_POLICY_RULES: "{not json" }).ok).toBe(false);
    expect(policyRulesFromEnv({ GATEWAY_POLICY_RULES: '{"a":1}' }).ok).toBe(false);
    expect(policyRulesFromEnv({ GATEWAY_POLICY_RULES: "[{}]" }).ok).toBe(false);
    // Absent and empty are NOT malformed: they mean "no rules configured".
    expect(policyRulesFromEnv({}).ok).toBe(true);
    expect(policyRulesFromEnv({ GATEWAY_POLICY_RULES: "  " }).ok).toBe(true);
  });
});

/**
 * MOUNT GATE. Delete the `evaluatePolicyRules(...)` block from `rateLimit`
 * (step 6) and every test below goes red.
 */
describe("deny rules: MOUNTED in the deployed app", () => {
  test("a tenant-scoped deny rule actually DENIES — 403 with the RULE's code", async () => {
    vars.GATEWAY_POLICY_RULES = JSON.stringify([
      {
        name: "block-tenant-a",
        organization_ids: ["tenant_a"],
        code: "tenant_frozen",
        message: "tenant_a is frozen pending review",
      },
    ]);

    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(403);
    const body = (await response.json()) as ErrorEnvelope;
    // The rule's OWN code and message, as `server/chat.rs:421` renders them —
    // not a generic `policy_denied`.
    expect(body.error.code).toBe("tenant_frozen");
    expect(body.error.message).toBe("tenant_a is frozen pending review");
  });

  test("a rule naming a DIFFERENT tenant does not deny this one", async () => {
    vars.GATEWAY_POLICY_RULES = JSON.stringify([
      { name: "block-b", organization_ids: ["tenant_b"], code: "nope", message: "no" },
    ]);
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });

  test("a per-API-KEY rule denies exactly that credential", async () => {
    vars.GATEWAY_POLICY_RULES = JSON.stringify([
      {
        name: "block-key",
        api_key_ids: [TENANT_A_KEY_ID],
        code: "key_blocked",
        message: "blocked",
      },
    ]);
    expect(((await (await get(TENANT_A_KEY)).json()) as ErrorEnvelope).error.code).toBe(
      "key_blocked",
    );
    // A DIFFERENT credential is untouched — the rule is per key, not per tenant.
    expect((await get("fg_root")).status).toBe(200);
  });

  test("an unreadable rule table refuses with 503, never silently allows", async () => {
    vars.GATEWAY_POLICY_RULES = "[[[";
    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(503);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe("policy_rules_unavailable");
  });

  test("no rules configured ⇒ the shipped default allows everything", async () => {
    // `delete` on the LIVE `env` object, not a spread copy: the app under test
    // holds the same reference, so replacing `vars` with a copy would leave the
    // handler still reading the configured value. The `afterEach` at the top of
    // this file restores it the same way.
    // biome-ignore lint/performance/noDelete: the binding must be absent on the shared `env` identity the worker reads.
    delete vars.GATEWAY_POLICY_RULES;
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });
});

/**
 * A model-scoped rule needs the request document, which the middleware reads
 * from a `Request.clone()`. Driven through the REAL `createGatewayApp` +
 * `rateLimit()` + `inferenceRouteModule` composition so the clone is proven not
 * to disturb the handler's own read of the body.
 */
describe("deny rules: model- and provider-scoped, over a real inference request", () => {
  const CHAT = `${BASE}/v1/chat/completions`;
  const NATIVE_KEYS = JSON.stringify([
    { key: "fg_pol", id: "key_pol", tenant_id: "tenant_pol", scopes: [] },
  ]);

  const registry = new InMemoryModelResolver(ALL_ROUTES);

  function gateway(policyRules: unknown[], middleware: readonly MiddlewareHandler<GatewayEnv>[]) {
    const { app } = createGatewayApp({
      modules: [inferenceRouteModule({ models: registry, requestIds: fixedRequestIds })],
      middleware,
    });
    const fullEnv = {
      GATEWAY_NATIVE_API_KEYS: NATIVE_KEYS,
      GATEWAY_POLICY_RULES: JSON.stringify(policyRules),
      GATEWAY_PROVIDERS: "[]",
      GATEWAY_MODELS: "[]",
    };
    return (body: unknown) =>
      app.request(
        CHAT,
        {
          method: "POST",
          headers: { authorization: "Bearer fg_pol", "content-type": "application/json" },
          body: JSON.stringify(body),
        },
        fullEnv,
      );
  }

  test("a model-scoped rule denies that model and passes another", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({
        id: "c1",
        object: "chat.completion",
        choices: [
          { index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" },
        ],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }),
    );
    try {
      const denyRules = [
        { name: "no-4o", models: ["gpt-4o-mini"], code: "model_banned", message: "banned" },
      ];
      const denied = await gateway(denyRules, [rateLimit()])({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "x" }],
      });
      expect(denied.status).toBe(403);
      expect((await errorBody(denied)).error.code).toBe("model_banned");
      // Refused BEFORE the provider was paid.
      expect(provider.requests).toHaveLength(0);

      // A rule naming ANOTHER model leaves this one alone — and the handler
      // still reads the body the middleware cloned. A clone that consumed the
      // body would answer 400 `invalid_json` here instead of 200.
      const otherRules = [
        { name: "no-images", models: ["image-model"], code: "model_banned", message: "banned" },
      ];
      const allowed = await gateway(otherRules, [rateLimit()])({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "x" }],
      });
      expect(allowed.status).toBe(200);
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });

  test("a provider-scoped rule resolves the provider through the model registry", async () => {
    const provider = interceptProviderFetch(() => undefined);
    try {
      const call = gateway(
        [
          {
            name: "no-openai",
            providers: ["openai-main"],
            code: "provider_banned",
            message: "banned",
          },
        ],
        // The composition injects its OWN `ModelResolver`, so the policy engine
        // is pointed at the same one — otherwise a provider-scoped rule would
        // resolve against the (empty) config-var registry and match nothing.
        // `src/index.ts` gets this for free: both sides are `modelsFromEnv`.
        [rateLimit({ providerForModel: (model) => registry.resolve(model)?.provider })],
      );
      const denied = await call({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "x" }],
      });
      expect(denied.status).toBe(403);
      expect((await errorBody(denied)).error.code).toBe("provider_banned");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});

// ===========================================================================
// 3. WORKFLOW-RUN BUDGET PRE-FLIGHT — `@ferrogate/policy`
// ===========================================================================

async function seedRunBudget(
  id: string,
  runId: string,
  tenantId: string,
  overrides: Partial<{
    token_budget: number | null;
    wall_clock_deadline_unix: number | null;
    spent_tokens: number;
    status: string;
  }> = {},
): Promise<void> {
  await seedRunBudgetInto(db, id, runId, tenantId, overrides);
}

/**
 * {@link seedRunBudget}, but into the tenant's OWN object — what `SELF` reads.
 *
 * The mount gate needs this and the unit cases do not: since #819 the deployed
 * `rateLimit()` resolves admission step 5 through `tenantDatabaseOf(c)`, so a
 * budget seeded into the shared `DB` is a row the Worker never sees. Seeding
 * both from one statement builder is what stops the two copies drifting into
 * disagreeing column lists.
 */
async function seedRoutedRunBudget(
  id: string,
  runId: string,
  tenantId: string,
  overrides: Parameters<typeof seedRunBudget>[3] = {},
): Promise<void> {
  await seedRunBudgetInto(tenantWalletDb(tenantId), id, runId, tenantId, overrides);
}

async function seedRunBudgetInto(
  target: D1Database,
  id: string,
  runId: string,
  tenantId: string,
  overrides: Partial<{
    token_budget: number | null;
    wall_clock_deadline_unix: number | null;
    spent_tokens: number;
    status: string;
  }> = {},
): Promise<void> {
  await target
    .prepare(
      "INSERT OR REPLACE INTO workflow_run_budgets " +
        "(id, workflow_id, workflow_version, run_id, tenant_id, token_budget, " +
        " wall_clock_deadline_unix, spent_credits, spent_tokens, spent_tool_calls, status, " +
        " created_at_unix, updated_at_unix) VALUES (?, 'wf_1', 1, ?, ?, ?, ?, 0, ?, 0, ?, ?, ?)",
    )
    .bind(
      id,
      runId,
      tenantId,
      overrides.token_budget ?? null,
      overrides.wall_clock_deadline_unix ?? null,
      overrides.spent_tokens ?? 0,
      overrides.status ?? "active",
      NOW,
      NOW,
    )
    .run();
}

describe("workflow budget: the declaration", () => {
  test("no headers at all is 'absent' — not every request is a workflow step", () => {
    expect(workflowDeclarationFrom(new Headers()).kind).toBe("absent");
  });

  test("a PARTIAL declaration is invalid, never silently ungated", () => {
    const headers = new Headers({ [WORKFLOW_RUN_ID_HEADER]: "run_1" });
    const result = workflowDeclarationFrom(headers);
    expect(result.kind).toBe("invalid");
  });

  test("a non-integer version is invalid", () => {
    const headers = new Headers({
      [WORKFLOW_ID_HEADER]: "wf_1",
      [WORKFLOW_VERSION_HEADER]: "one",
      [WORKFLOW_RUN_ID_HEADER]: "run_1",
    });
    expect(workflowDeclarationFrom(headers).kind).toBe("invalid");
  });

  test("all three present parses", () => {
    const headers = new Headers({
      [WORKFLOW_ID_HEADER]: "wf_1",
      [WORKFLOW_VERSION_HEADER]: "3",
      [WORKFLOW_RUN_ID_HEADER]: "run_1",
    });
    expect(workflowDeclarationFrom(headers)).toEqual({
      kind: "declared",
      step: { workflowId: "wf_1", workflowVersion: 3, runId: "run_1" },
    });
  });
});

describe("workflow budget: the source", () => {
  const step = { workflowId: "wf_1", workflowVersion: 1, runId: "run_1" };

  test("a run with no envelope is 'unbudgeted' — nothing caps it", async () => {
    expect(await d1WorkflowBudgetSource(db).forStep(step, "tenant_a")).toEqual({
      kind: "unbudgeted",
    });
  });

  test("the row is found by the STORAGE package's own deterministic id", async () => {
    // Re-deriving the id here (or in `workflow.ts`) with one separator out of
    // place would look up a row that never matches — i.e. it would silently
    // un-gate every run, which is the failure this test exists to catch.
    const { workflowRunBudgetId } = await import("@ferrogate/storage");
    const id = workflowRunBudgetId("wf_1", 1, "run_1");
    await seedRunBudget(id, "run_1", "tenant_a", { token_budget: 500 });

    const lookup = await d1WorkflowBudgetSource(db).forStep(step, "tenant_a");
    expect(lookup.kind).toBe("found");
    expect(lookup.kind === "found" && lookup.budget.tokenBudget).toBe(500);
  });

  test("another tenant's run is `unavailable`, NOT `unbudgeted`", async () => {
    const { workflowRunBudgetId } = await import("@ferrogate/storage");
    await seedRunBudget(workflowRunBudgetId("wf_1", 1, "run_1"), "run_1", "tenant_other");
    const lookup = await d1WorkflowBudgetSource(db).forStep(step, "tenant_a");
    // Answering `unbudgeted` would let a caller run ungated by naming someone
    // else's run id.
    expect(lookup.kind).toBe("unavailable");
  });
});

/**
 * MOUNT GATE. Delete the `enforceWorkflowBudget(...)` call from `rateLimit`
 * (step 5) and every test below goes red.
 *
 * Seeded through {@link seedRoutedRunBudget} for the same reason the wallet
 * gate above uses {@link seedRoutedWallet}: since #819 admission step 5
 * resolves through `tenantDatabaseOf(c)`, so a budget in the shared `DB` is a
 * row the deployed Worker never reads. The two steps deliberately use the SAME
 * database — see `defaultWorkflowBudgets` on why one admission decision must
 * not straddle two topologies.
 */
describe("workflow budget: MOUNTED in the deployed app", () => {
  function workflowHeaders(runId: string): Record<string, string> {
    return {
      [WORKFLOW_ID_HEADER]: "wf_1",
      [WORKFLOW_VERSION_HEADER]: "1",
      [WORKFLOW_RUN_ID_HEADER]: runId,
    };
  }

  test("a partial declaration is refused with 400", async () => {
    const response = await get(TENANT_A_KEY, { [WORKFLOW_RUN_ID_HEADER]: "run_x" });
    expect(response.status).toBe(400);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe(
      "invalid_workflow_declaration",
    );
  });

  test("an EXHAUSTED run denies every subsequent step — 402", async () => {
    const { workflowRunBudgetId } = await import("@ferrogate/storage");
    await seedRoutedRunBudget(workflowRunBudgetId("wf_1", 1, "run_dead"), "run_dead", "tenant_a", {
      status: "exhausted",
    });

    const response = await get(TENANT_A_KEY, workflowHeaders("run_dead"));
    // `StatusCode::PAYMENT_REQUIRED` — `server/agent_runs.rs:756`, verbatim.
    expect(response.status).toBe(402);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe("workflow_budget_exceeded");
  });

  test("a run past its wall-clock deadline denies", async () => {
    const { workflowRunBudgetId } = await import("@ferrogate/storage");
    await seedRoutedRunBudget(workflowRunBudgetId("wf_1", 1, "run_late"), "run_late", "tenant_a", {
      // Already in the past relative to the real clock the deployed app uses.
      wall_clock_deadline_unix: 1,
    });
    expect((await get(TENANT_A_KEY, workflowHeaders("run_late"))).status).toBe(402);
  });

  test("a healthy run inside its envelope is served", async () => {
    const { workflowRunBudgetId } = await import("@ferrogate/storage");
    await seedRunBudget(workflowRunBudgetId("wf_1", 1, "run_ok"), "run_ok", "tenant_a", {
      token_budget: 1_000_000,
      wall_clock_deadline_unix: LATER + 1e9,
    });
    expect((await get(TENANT_A_KEY, workflowHeaders("run_ok"))).status).toBe(200);
  });

  test("a request declaring no workflow is not gated at all", async () => {
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });
});

// ===========================================================================
// 4. `api_keys.monthly_token_budget` — the committed-token loop, READ half
// ===========================================================================

async function seedApiKeyInto(
  target: D1Database,
  id: string,
  monthlyTokenBudget: number | null,
): Promise<void> {
  await target
    .prepare(
      "INSERT OR REPLACE INTO api_keys " +
        "(id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4, " +
        " enabled, monthly_token_budget, created_at_unix, updated_at_unix) " +
        "VALUES (?, 'ws_a', 'tenant_a', 'proj_a', 'k', ?, ?, '0000', 1, ?, ?, ?)",
    )
    .bind(id, `pfx_${id}`, `hash_${id}`, monthlyTokenBudget, NOW, NOW)
    .run();
}

async function seedApiKey(id: string, monthlyTokenBudget: number | null): Promise<void> {
  await seedApiKeyInto(db, id, monthlyTokenBudget);
}

async function seedCommittedTokensInto(
  target: D1Database,
  apiKeyId: string,
  totalTokens: number,
): Promise<void> {
  const contextId = `ctx_${apiKeyId}`;
  await target
    .prepare(
      "INSERT OR REPLACE INTO tenant_contexts (id, organization_id, api_key_id) VALUES (?, 'tenant_a', ?)",
    )
    .bind(contextId, apiKeyId)
    .run();
  await target
    .prepare(
      "INSERT OR REPLACE INTO usage_aggregate_rollups " +
        "(id, tenant_context_id, logical_model, provider, prompt_tokens, completion_tokens, " +
        " total_tokens, updated_at_unix) VALUES (?, ?, 'm', 'p', 0, 0, ?, ?)",
    )
    .bind(`agg_${apiKeyId}`, contextId, totalTokens, NOW)
    .run();
}

async function seedCommittedTokens(apiKeyId: string, totalTokens: number): Promise<void> {
  await seedCommittedTokensInto(db, apiKeyId, totalTokens);
}

describe("monthly token budget: the source", () => {
  test("a key with a NULL budget reads as `undefined`, never as zero", async () => {
    await seedApiKey(TENANT_A_KEY_ID, null);
    expect(await d1TokenBudgetSource(db).forApiKey(TENANT_A_KEY_ID, "tenant_a")).toEqual({
      ok: true,
      budget: undefined,
      committedTokens: 0,
    });
  });

  test("a budgeted key sums its committed tokens through @ferrogate/storage", async () => {
    await seedApiKey(TENANT_A_KEY_ID, 1_000);
    await seedCommittedTokens(TENANT_A_KEY_ID, 750);
    expect(await d1TokenBudgetSource(db).forApiKey(TENANT_A_KEY_ID, "tenant_a")).toEqual({
      ok: true,
      budget: 1_000,
      committedTokens: 750,
    });
  });

  test("another key's usage is not counted", async () => {
    await seedApiKey(TENANT_A_KEY_ID, 1_000);
    await seedCommittedTokens("key_other", 9_999);
    const reading = await d1TokenBudgetSource(db).forApiKey(TENANT_A_KEY_ID, "tenant_a");
    expect(reading.ok === true && reading.committedTokens).toBe(0);
  });

  test("a lookup failure is `ok: false`, never 'no budget'", async () => {
    const broken = {
      prepare(): never {
        throw new Error("D1_ERROR: no such table: api_keys");
      },
    } as unknown as D1Database;
    expect((await d1TokenBudgetSource(broken).forApiKey("k", "t")).ok).toBe(false);
  });
});

/**
 * MOUNT GATE. Delete the `admitMonthlyTokenBudget(...)` call from
 * `admitTokensPerMinute` — or the `tokenBudget` / `apiKeyId` fields from the
 * `setResolvedWindows(...)` call in `rateLimit` — and this goes red.
 *
 * Driven through the REAL `createGatewayApp` + `rateLimit()` +
 * `inferenceRouteModule` composition, because the budget is charged where the
 * token ESTIMATE exists: inside the handler, after `planUpstream` and before
 * dispatch, exactly where Rust charges it.
 */
describe("monthly token budget: MOUNTED on the inference path", () => {
  const CHAT = `${BASE}/v1/chat/completions`;
  const NATIVE_KEYS = JSON.stringify([
    { key: "fg_budget", id: "key_budget", tenant_id: "tenant_a", scopes: [] },
  ]);

  /**
   * The deployed routing posture: `GATEWAY_TENANT_DB_ROUTING` unset defaults to
   * `durable_object`, so `defaultTokenBudget` reads `api_keys.monthly_token_budget`
   * and the committed-token sum from the TENANT'S OWN OBJECT through
   * `tenantDatabaseOf(c)` — which is why `tenantDatabase()` is mounted ahead of
   * `rateLimit()` (same order as `GATEWAY_MIDDLEWARE`) and why the seeds below
   * go through {@link seedApiKeyInto}/{@link seedCommittedTokensInto} against
   * `tenantWalletDb("tenant_a")`, not the shared `db`. A row seeded into
   * `env.DB` is one the deployed source never reads.
   */
  async function call(body: unknown): Promise<Response> {
    const { app } = createGatewayApp({
      modules: [
        inferenceRouteModule({
          models: new InMemoryModelResolver(ALL_ROUTES),
          requestIds: fixedRequestIds,
        }),
      ],
      middleware: [tenantDatabase(), rateLimit()],
    });
    const bindings = env as unknown as Record<string, unknown>;
    return app.request(
      CHAT,
      {
        method: "POST",
        headers: { authorization: "Bearer fg_budget", "content-type": "application/json" },
        body: JSON.stringify(body),
      },
      {
        GATEWAY_NATIVE_API_KEYS: NATIVE_KEYS,
        GATEWAY_PROVIDERS: "[]",
        GATEWAY_MODELS: "[]",
        DB: db,
        CONTROL_DB: bindings.CONTROL_DB,
        CONTROL_DATA: controlNamespace(),
        TENANT_DATA: bindings.TENANT_DATA,
        RATE_LIMIT: bindings.RATE_LIMIT,
      },
    );
  }

  const CHAT_BODY = { model: "gpt-4o-mini", messages: [{ role: "user", content: "hello" }] };

  const routedDb = () => tenantWalletDb("tenant_a");

  beforeEach(async () => {
    // Same explicit truncation as the wallet gate above: the object's
    // `ctx.storage.sql` rows are not part of the pool's per-test rollback.
    await routedDb().prepare("DELETE FROM usage_aggregate_rollups").run();
    await routedDb().prepare("DELETE FROM tenant_contexts").run();
    await routedDb().prepare("DELETE FROM api_keys").run();
  });

  test("a key whose committed tokens already exceed its budget is REFUSED", async () => {
    await seedApiKeyInto(routedDb(), "key_budget", 100);
    await seedCommittedTokensInto(routedDb(), "key_budget", 100);

    const provider = interceptProviderFetch(() => undefined);
    try {
      const response = await call(CHAT_BODY);
      expect(response.status).toBe(429);
      expect((await errorBody(response)).error.code).toBe("token_budget_exceeded");
      // The whole point: refused WITHOUT paying the provider.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  test("a key with budget left is served", async () => {
    await seedApiKeyInto(routedDb(), "key_budget", 1_000_000);
    await seedCommittedTokensInto(routedDb(), "key_budget", 10);

    const provider = interceptProviderFetch(() =>
      providerJson({
        id: "c1",
        object: "chat.completion",
        choices: [
          { index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" },
        ],
        usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
      }),
    );
    try {
      expect((await call(CHAT_BODY)).status).toBe(200);
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });

  test("a key with NO budget column set is never refused by this gate", async () => {
    await seedApiKeyInto(routedDb(), "key_budget", null);
    await seedCommittedTokensInto(routedDb(), "key_budget", 10_000_000);

    const provider = interceptProviderFetch(() =>
      providerJson({
        id: "c1",
        object: "chat.completion",
        choices: [
          { index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" },
        ],
        usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
      }),
    );
    try {
      expect((await call(CHAT_BODY)).status).toBe(200);
    } finally {
      provider.restore();
    }
  });
});
