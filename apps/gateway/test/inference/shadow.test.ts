/**
 * Shadow / mirror traffic — driven END TO END through the real inference
 * router, never through `runShadowMirror` in isolation.
 *
 * ## WHY THIS FILE IS SHAPED LIKE THIS
 *
 * Before this slice, `shadowSampled` and `ShadowBudgetLedger` were fully ported
 * and covered by 28 package tests, and `apps/gateway` mirrored NOTHING: an
 * operator could configure `shadow = { provider, provider_model,
 * sample_percent }`, watch `packages/config` validate it, and receive zero
 * mirrored requests forever. A test that called `shadowSampled` directly would
 * have been green through the whole of that state — which is exactly the defect
 * class the porting rules name.
 *
 * So every case here goes through `harness(...)` → `createInferenceRouter` →
 * `planUpstream` → `dispatchCandidates`, with only the OUTBOUND provider
 * `fetch` intercepted. The mount gates, i.e. the assertions that go RED if the
 * wiring is removed from `handlers.ts`:
 *
 *  - "mirrors a sampled caller's request to the shadow provider" — red if
 *    `spawnShadowMirror` is dropped from `dispatchCandidates`.
 *  - "does not mirror a caller the shadow bucket excludes" — red if the
 *    `shadowSampled` gate is replaced by an unconditional mirror.
 *  - "records exactly ONE usage event, for the route that served the client" —
 *    red if the mirror is ever routed through `deps.usage`. THE DOUBLE-BILL
 *    GATE, together with "records no usage at all when only the mirror
 *    succeeds".
 *  - "answers the client without waiting for the mirror" — red if the mirror
 *    is awaited on the request path. THE LATENCY GATE.
 *  - "a mirror that fails does not fail, or alter, the client's response" —
 *    red if any failure escapes `runShadowMirror`.
 *  - "a failing mirror never opens the primary provider's circuit" — red if
 *    the mirror is dispatched through `dispatchWithFailover` (which records
 *    breaker outcomes) instead of the raw dispatcher.
 *  - "stops mirroring once max_requests is spent" — red if the budget ledger
 *    is dropped from `runShadowMirror`.
 *  - "picks the SHADOW_BUDGET Durable Object over the per-isolate ledger" —
 *    red if `shadowBudgetFor` stops reading the binding, which would silently
 *    turn a global cap of N into N per live isolate.
 *
 * The DEPLOYED-Worker gate — the mirror firing from a `GATEWAY_MODELS` table,
 * through `SELF.fetch` — is `test/inference/shadow-mount.test.ts`.
 */
import { rolloutBucket } from "@ferrogate/routing";
import { afterEach, describe, expect, it } from "vitest";
import { InMemoryProviderCircuit, shadowBudgetFor } from "../../src/inference/index.js";
import type {
  Caller,
  InferenceDeps,
  PhysicalRoute,
  ReliabilitySettings,
} from "../../src/inference/index.js";
import { harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const MODEL = "mirrored-model";

const CHAT_BODY = { model: MODEL, messages: [{ role: "user", content: "hi" }] };

const CHAT_OK = {
  id: "chatcmpl-ok",
  object: "chat.completion",
  model: MODEL,
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
};

function route(overrides: Partial<PhysicalRoute> & { provider: string }): PhysicalRoute {
  return {
    logicalModel: MODEL,
    providerModel: "gpt-4o-mini",
    providerKind: "openai",
    baseUrl: `https://${overrides.provider}.test/v1`,
    apiKey: "sk-test",
    enabled: true,
    ...overrides,
  };
}

function providerOf(url: string): string {
  return new URL(url).hostname.replace(/\.test$/, "");
}

function keyedCaller(apiKeyId: string): InferenceDeps["caller"] {
  return (): Caller => ({ scope: { kind: "platform_operator" }, apiKeyId });
}

/**
 * A key the `"shadow"` salt buckets IN (or OUT) at 50%.
 *
 * Computed from the PACKAGE's own hash rather than hard-coded, so a second
 * bucketing implementation appearing anywhere in the gateway diverges here
 * instead of quietly agreeing.
 */
function shadowKey(sampled: boolean): string {
  for (let i = 0; i < 1000; i += 1) {
    const key = `mirror-${i}`;
    if (rolloutBucket("shadow", key) < 50 === sampled) {
      return key;
    }
  }
  throw new Error("no sticky key found for the requested shadow bucket");
}

/** Primary + mirror. The mirror is at a LOWER priority so the ladder would
 * happily fall onto it if `servableCandidates` ever stopped stripping it. */
const MIRRORED: readonly PhysicalRoute[] = [
  route({ provider: "primary", priority: 0 }),
  route({ provider: "mirror", priority: 5, shadowPercent: 100, shadowMaxRequests: 0 }),
];

/** Poll until `predicate` holds — the mirror is fire-and-forget, so its
 * outbound call lands after the client's response, not before it. */
async function waitFor(predicate: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 200; i += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(`timed out waiting for ${what}`);
}

let provider: ReturnType<typeof interceptProviderFetch> | undefined;

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

// ---------------------------------------------------------------------------
// The mirror fires — MOUNT GATE for @ferrogate/routing's shadow half
// ---------------------------------------------------------------------------

describe("shadow mirroring uses @ferrogate/routing sampling", () => {
  it("mirrors a sampled caller's request to the shadow provider", async () => {
    provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    const app = harness({ caller: keyedCaller("any-key") }, MIRRORED);

    const res = await app.post("/v1/chat/completions", CHAT_BODY);
    expect(res.status).toBe(200);

    // BOTH providers were dialled for ONE client request — that is the mirror.
    await waitFor(
      () =>
        (provider as NonNullable<typeof provider>).requests.some(
          (request) => providerOf(request.url) === "mirror",
        ),
      "the shadow mirror to be dispatched",
    );
    expect(new Set(provider.requests.map((request) => providerOf(request.url)))).toEqual(
      new Set(["primary", "mirror"]),
    );
    // The client was SERVED by the primary. Dispatch ORDER is deliberately not
    // asserted: the mirror is spawned before the primary `await` (so it never
    // queues behind it) and which socket opens first is a scheduling detail.
    // What the client got is not.
    expect(app.usage.last?.provider).toBe("primary");
  });

  it("does not mirror a caller the shadow bucket excludes", async () => {
    provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    const unsampled = shadowKey(false);
    const app = harness({ caller: keyedCaller(unsampled) }, [
      route({ provider: "primary", priority: 0 }),
      route({ provider: "mirror", priority: 5, shadowPercent: 50, shadowMaxRequests: 0 }),
    ]);

    const res = await app.post("/v1/chat/completions", CHAT_BODY);
    expect(res.status).toBe(200);

    // Give an unwanted mirror every chance to appear before asserting absence.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(provider.requests.map((request) => providerOf(request.url))).toEqual(["primary"]);
  });

  it("mirrors exactly the callers @ferrogate/routing samples, and no others", async () => {
    const keys = ["m-a", "m-b", "m-c", "m-d", "m-e", "m-f", "m-g", "m-h"];
    const mirrored: Record<string, boolean> = {};
    for (const key of keys) {
      const intercept = interceptProviderFetch(() => providerJson(CHAT_OK));
      try {
        const app = harness({ caller: keyedCaller(key) }, [
          route({ provider: "primary", priority: 0 }),
          route({ provider: "mirror", priority: 5, shadowPercent: 50, shadowMaxRequests: 0 }),
        ]);
        await app.post("/v1/chat/completions", CHAT_BODY);
        await new Promise((resolve) => setTimeout(resolve, 20));
        mirrored[key] = intercept.requests.some((request) => providerOf(request.url) === "mirror");
      } finally {
        intercept.restore();
      }
    }

    const expected = Object.fromEntries(
      keys.map((key) => [key, rolloutBucket("shadow", key) < 50]),
    );
    expect(mirrored).toEqual(expected);
    // The split must be real, not "all in" or "all out".
    expect(new Set(Object.values(mirrored))).toEqual(new Set([true, false]));
  });

  it("never mirrors a caller with no sticky identity", async () => {
    provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    // The default caller is a platform operator with no api-key id.
    const app = harness({}, MIRRORED);

    expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(200);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(provider.requests.map((request) => providerOf(request.url))).toEqual(["primary"]);
  });

  it("mirrors as a NON-streaming call even when the client asked to stream", async () => {
    provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "mirror"
        ? providerJson(CHAT_OK)
        : new Response('data: {"choices":[]}\n\ndata: [DONE]\n\n', {
            status: 200,
            headers: { "content-type": "text/event-stream" },
          }),
    );
    const app = harness({ caller: keyedCaller("any-key") }, MIRRORED);

    const res = await app.post("/v1/chat/completions", { ...CHAT_BODY, stream: true });
    expect(res.status).toBe(200);
    await res.text();

    await waitFor(
      () =>
        (provider as NonNullable<typeof provider>).requests.some(
          (request) => providerOf(request.url) === "mirror",
        ),
      "the shadow mirror to be dispatched",
    );
    const mirrored = provider.requests.find((request) => providerOf(request.url) === "mirror");
    // Rust forces `stream: false` on the mirrored body: the response is
    // discarded, so a bounded body is simpler and usage still arrives in it.
    expect((mirrored?.body as { stream?: unknown }).stream).toBe(false);
    // ...and the CLIENT's request was still streamed.
    const primary = provider.requests.find((request) => providerOf(request.url) === "primary");
    expect((primary?.body as { stream?: unknown }).stream).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Guarantee 1 — a mirror never affects the client's response
// ---------------------------------------------------------------------------

describe("a mirror never affects the client's response", () => {
  it("answers the client without waiting for the mirror", async () => {
    // The mirror's body never arrives until the test opens this gate, so if the
    // request path awaited the mirror at any point the assertion below could
    // not run at all — the test would hang rather than fail, which is why the
    // gate is opened in a `finally`.
    let openGate: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      openGate = resolve;
    });
    let mirrorRequested = false;

    provider = interceptProviderFetch((request) => {
      if (providerOf(request.url) !== "mirror") {
        return providerJson(CHAT_OK);
      }
      mirrorRequested = true;
      return new Response(
        new ReadableStream<Uint8Array>({
          async start(controller) {
            await gate;
            controller.enqueue(new TextEncoder().encode(JSON.stringify(CHAT_OK)));
            controller.close();
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });

    try {
      const app = harness({ caller: keyedCaller("any-key") }, MIRRORED);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      // THE LATENCY GATE: a full client response while the mirror is still
      // mid-flight with an unread body.
      expect(res.status).toBe(200);
      expect((await res.json<{ id: string }>()).id).toBe("chatcmpl-ok");
      await waitFor(() => mirrorRequested, "the shadow mirror to be dispatched");
      expect(mirrorRequested).toBe(true);
    } finally {
      openGate?.();
    }
  });

  it("a mirror that fails does not fail, or alter, the client's response", async () => {
    provider = interceptProviderFetch((request) => {
      if (providerOf(request.url) === "mirror") {
        throw new Error("mirror provider is on fire");
      }
      return providerJson(CHAT_OK);
    });

    const app = harness({ caller: keyedCaller("any-key") }, MIRRORED);
    const res = await app.post("/v1/chat/completions", CHAT_BODY);

    expect(res.status).toBe(200);
    expect((await res.json<{ id: string }>()).id).toBe("chatcmpl-ok");
    await waitFor(
      () =>
        (provider as NonNullable<typeof provider>).requests.some(
          (request) => providerOf(request.url) === "mirror",
        ),
      "the failing shadow mirror to be attempted",
    );
  });

  it("a failing mirror never opens the primary provider's circuit", async () => {
    // The breaker is armed at a threshold of ONE, so a single recorded failure
    // opens it. If the mirror were dispatched through the failover ladder its
    // 503 would open `mirror`'s circuit AND count as a dispatch outcome; more
    // importantly, a shadow provider that shares a name with a primary would
    // shed the client's own traffic. Nothing the mirror does may reach here.
    const settings: Partial<ReliabilitySettings> = {
      circuitFailureThreshold: 1,
      circuitCooldownMs: 60_000,
      maxDispatchRetries: 0,
    };
    const circuit = new InMemoryProviderCircuit({
      circuitFailureThreshold: 1,
      circuitCooldownMs: 60_000,
      maxDispatchRetries: 0,
    });

    provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "mirror"
        ? providerJson({ error: "mirror down" }, 503)
        : providerJson(CHAT_OK),
    );

    const app = harness(
      { caller: keyedCaller("any-key"), reliability: settings, circuit },
      MIRRORED,
    );
    expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(200);
    await waitFor(
      () =>
        (provider as NonNullable<typeof provider>).requests.some(
          (request) => providerOf(request.url) === "mirror",
        ),
      "the failing shadow mirror to be attempted",
    );

    // THE GATE: the mirror answered 503 and the breaker never heard about it.
    expect(await circuit.allows("mirror")).toBe(true);
    expect(await circuit.allows("primary")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Guarantee 2 — a mirror never double-bills
// ---------------------------------------------------------------------------

describe("a mirror never double-bills", () => {
  it("records exactly ONE usage event, for the route that served the client", async () => {
    provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    const app = harness({ caller: keyedCaller("any-key") }, MIRRORED);

    expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(200);
    await waitFor(
      () =>
        (provider as NonNullable<typeof provider>).requests.some(
          (request) => providerOf(request.url) === "mirror",
        ),
      "the shadow mirror to be dispatched",
    );
    // Let any (nonexistent) mirror metering land before counting.
    await new Promise((resolve) => setTimeout(resolve, 20));

    // THE DOUBLE-BILL GATE. Two dispatches, ONE billable event, and it names
    // the provider the client was actually served by.
    expect(app.usage.records).toHaveLength(1);
    expect(app.usage.last?.provider).toBe("primary");
    expect(app.usage.last?.totalTokens).toBe(4);
  });

  it("records no usage at all when only the mirror succeeds", async () => {
    provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "mirror"
        ? providerJson(CHAT_OK)
        : providerJson({ error: "down" }, 503),
    );
    const app = harness({ caller: keyedCaller("any-key") }, MIRRORED);

    // The client is refused — the mirror is not a fallback.
    expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(503);
    await waitFor(
      () =>
        (provider as NonNullable<typeof provider>).requests.some(
          (request) => providerOf(request.url) === "mirror",
        ),
      "the shadow mirror to be dispatched",
    );
    await new Promise((resolve) => setTimeout(resolve, 20));

    // One usage row for the FAILED primary (status 503, no tokens) and nothing
    // whatsoever for the successful mirror — whose tokens are real and must
    // never be charged to the tenant.
    expect(app.usage.records).toHaveLength(1);
    expect(app.usage.last?.provider).toBe("primary");
    expect(app.usage.last?.status).toBe(503);
  });
});

// ---------------------------------------------------------------------------
// The budget cap — `shadow_budget_try_consume`
// ---------------------------------------------------------------------------

describe("the shadow budget caps mirrored dispatches", () => {
  it("stops mirroring once max_requests is spent, and keeps serving clients", async () => {
    provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    // A ledger scoped to this test, so the module-scoped isolate ledger (and
    // every other test in the file) cannot move the count under it.
    let consumed = 0;
    const budget = {
      async tryConsume(_key: string, limit: number): Promise<boolean> {
        if (limit === 0) return true;
        if (consumed >= limit) return false;
        consumed += 1;
        return true;
      },
      async consumed(): Promise<number> {
        return consumed;
      },
    };

    const app = harness({ caller: keyedCaller("any-key"), shadowBudget: budget }, [
      route({ provider: "primary", priority: 0 }),
      route({ provider: "mirror", priority: 5, shadowPercent: 100, shadowMaxRequests: 2 }),
    ]);

    for (let i = 0; i < 4; i += 1) {
      expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(200);
    }
    await waitFor(
      () =>
        (provider as NonNullable<typeof provider>).requests.filter(
          (r) => providerOf(r.url) === "mirror",
        ).length === 2,
      "exactly two mirrors to be admitted",
    );
    await new Promise((resolve) => setTimeout(resolve, 20));

    const byProvider = provider.requests.map((request) => providerOf(request.url));
    // Four client requests all served; only two mirrored.
    expect(byProvider.filter((name) => name === "primary")).toHaveLength(4);
    expect(byProvider.filter((name) => name === "mirror")).toHaveLength(2);
    expect(consumed).toBe(2);
  });

  it("picks the SHADOW_BUDGET Durable Object over the per-isolate ledger", async () => {
    // The isolate ledger is the fallback for an UNBOUND deployment...
    const isolate = shadowBudgetFor({});
    expect(await isolate.tryConsume("scope-a", 1)).toBe(true);
    expect(await isolate.tryConsume("scope-a", 1)).toBe(false);

    // ...and a bound namespace wins. The stub is shaped like the real
    // `[[durable_objects.bindings]]` namespace (`idFromName` + `get`), which is
    // exactly what `shadowBudgetFor` discriminates on, so this asserts the
    // SELECTION and the DO call, not a reimplementation of the ledger.
    const calls: number[] = [];
    const namespace = {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        async tryConsume(limit: number): Promise<boolean> {
          calls.push(limit);
          return calls.length <= limit;
        },
        async consumed(): Promise<number> {
          return calls.length;
        },
      }),
    };
    const durable = shadowBudgetFor({ SHADOW_BUDGET: namespace } as never);
    expect(durable).not.toBe(isolate);
    expect(await durable.tryConsume("scope-b", 1)).toBe(true);
    expect(await durable.tryConsume("scope-b", 1)).toBe(false);
    expect(calls).toEqual([1, 1]);

    // `limit === 0` is UNCAPPED and must not pay a DO round trip per mirror.
    expect(await durable.tryConsume("scope-b", 0)).toBe(true);
    expect(calls).toEqual([1, 1]);
  });

  it("does not charge the budget for an unsampled caller", async () => {
    provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    let charges = 0;
    const budget = {
      async tryConsume(): Promise<boolean> {
        charges += 1;
        return true;
      },
      async consumed(): Promise<number> {
        return charges;
      },
    };

    const app = harness({ caller: keyedCaller(shadowKey(false)), shadowBudget: budget }, [
      route({ provider: "primary", priority: 0 }),
      route({ provider: "mirror", priority: 5, shadowPercent: 50, shadowMaxRequests: 10 }),
    ]);
    expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(200);
    await new Promise((resolve) => setTimeout(resolve, 20));

    // Rust charges the budget LAST, "so a disabled provider or an unsampled
    // caller never consumes budget".
    expect(charges).toBe(0);
  });
});
