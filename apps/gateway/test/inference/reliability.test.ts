/**
 * The reliability layer, driven end to end through the real inference router.
 *
 * ## WHY THIS FILE IS SHAPED LIKE THIS
 *
 * Every assertion here goes through `createInferenceRouter` and the real
 * `fetchDispatcher`, with only the OUTBOUND provider `fetch` intercepted. That
 * is deliberate and it is the whole point of the file: `reliability.ts` and
 * `candidates.ts` could each be unit-tested green while `handlers.ts` still
 * dispatched exactly once, which is precisely the "implemented, tested, never
 * mounted" state the parity audit found in `@ferrogate/routing` and
 * `isRetryableStatus`. A test that called `dispatchWithFailover` directly would
 * survive un-wiring the ladder; these do not.
 *
 * The mount gates, i.e. the assertions that go RED if the wiring is removed:
 *
 *  - "retries the same provider" / "falls over to the second candidate" —
 *    red if `handlers.ts` stops calling `dispatchCandidates`.
 *  - "does not retry a non-retryable status" — red if the retry predicate is
 *    replaced by an unconditional retry.
 *  - "short-circuits once the breaker opens" — red if `dispatchWithFailover`
 *    stops consulting `circuit.allows`.
 *  - "routes the canary bucket to the canary provider" — red if `applyCanary`
 *    is dropped from `planUpstream` (the canary carries a LOWER priority than
 *    the primary, so nothing but the rollout can put it first).
 *  - "never serves a shadow route" — red if `servableCandidates` is dropped.
 *  - "excludes a route that cannot stream" — red if `eligibleCandidates` is
 *    dropped from `planUpstream`.
 *  - "does not retry after the first byte" — red if a retry is ever moved
 *    behind the response headers.
 */
import { rolloutBucket } from "@ferrogate/routing";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_RELIABILITY,
  DurableObjectProviderCircuit,
  InMemoryProviderCircuit,
  ProviderCircuitState,
  attemptDecision,
  isRetryableUpstreamStatus,
  reliabilityFromVar,
} from "../../src/inference/index.js";
import type {
  Caller,
  InferenceDeps,
  PhysicalRoute,
  ProviderCircuitNamespace,
  ReliabilitySettings,
} from "../../src/inference/index.js";
import { errorBody, harness } from "./fixtures.js";
import {
  OPENAI_CHAT_STREAM_FRAMES,
  interceptProviderFetch,
  providerJson,
  providerSse,
  providerSseThatFaults,
  readBody,
} from "./provider-mock.js";

const MODEL = "ladder-model";

/** A chat completion body an OpenAI-compatible upstream would answer. */
const CHAT_BODY = { model: MODEL, messages: [{ role: "user", content: "hi" }] };

/** A minimal successful chat completion. */
const CHAT_OK = {
  id: "chatcmpl-ok",
  object: "chat.completion",
  model: "gpt-4o-mini",
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

/** Which provider an intercepted URL belongs to (`https://<provider>.test/...`). */
function providerOf(url: string): string {
  return new URL(url).hostname.replace(/\.test$/, "");
}

/** Reliability settings with the breaker on. */
function withBreaker(overrides: Partial<ReliabilitySettings> = {}): ReliabilitySettings {
  return {
    circuitFailureThreshold: 2,
    circuitCooldownMs: 30_000,
    maxDispatchRetries: 0,
    ...overrides,
  };
}

/** A caller with a stable api-key id, so the rollouts have a sticky key. */
function keyedCaller(apiKeyId: string): InferenceDeps["caller"] {
  return (): Caller => ({ scope: { kind: "platform_operator" }, apiKeyId });
}

// ---------------------------------------------------------------------------
// The retry predicate — imported, not re-implemented
// ---------------------------------------------------------------------------

describe("the retry predicate comes from @ferrogate/providers", () => {
  it("delegates to the provider family's isRetryableStatus", () => {
    // `BaseProviderAdapter.isRetryableStatus`: 429 and the whole 5xx band.
    expect(isRetryableUpstreamStatus("openai", 429)).toBe(true);
    expect(isRetryableUpstreamStatus("anthropic", 503)).toBe(true);
    expect(isRetryableUpstreamStatus("gemini", 500)).toBe(true);
    // Client errors are the provider's own answer and are never retried.
    expect(isRetryableUpstreamStatus("openai", 400)).toBe(false);
    expect(isRetryableUpstreamStatus("openai", 404)).toBe(false);
    expect(isRetryableUpstreamStatus("anthropic", 422)).toBe(false);
  });

  it("fails closed on a provider kind the package does not know", () => {
    // `ProviderAdapterRegistry.adapterFor` THROWS for an unknown kind; Rust
    // wraps the same call in `.unwrap_or(false)`.
    expect(isRetryableUpstreamStatus("not-a-family", 503)).toBe(false);
  });
});

describe("attemptDecision reproduces ProviderAttemptDecision", () => {
  it("retries the provider while attempts remain", () => {
    expect(attemptDecision(true, 0, 2, true)).toBe("retry_provider");
    expect(attemptDecision(true, 1, 2, true)).toBe("retry_provider");
  });

  it("falls through to the next candidate once retries are spent", () => {
    expect(attemptDecision(true, 2, 2, true)).toBe("try_fallback_route");
  });

  it("returns the error when nothing is left to try", () => {
    expect(attemptDecision(true, 2, 2, false)).toBe("return_error");
  });

  it("never retries or fails over on a non-retryable outcome", () => {
    expect(attemptDecision(false, 0, 5, true)).toBe("return_error");
  });
});

// ---------------------------------------------------------------------------
// Retry — MOUNT GATE
// ---------------------------------------------------------------------------

describe("same-provider retry", () => {
  it("retries a retryable status and succeeds on the second attempt", async () => {
    let attempts = 0;
    const provider = interceptProviderFetch(() => {
      attempts += 1;
      return attempts === 1 ? providerJson({ error: "overloaded" }, 503) : providerJson(CHAT_OK);
    });
    try {
      const app = harness({ reliability: { maxDispatchRetries: 1 } }, [
        route({ provider: "solo" }),
      ]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(res.status).toBe(200);
      expect(attempts).toBe(2);
      // BOTH attempts went to the same provider — a retry is not a failover.
      expect(provider.requests.map((request) => providerOf(request.url))).toEqual(["solo", "solo"]);
      // The response the client is served is the SECOND attempt's.
      expect(((await res.json()) as { id: string }).id).toBe("chatcmpl-ok");
    } finally {
      provider.restore();
    }
  });

  it("does not retry a non-retryable status, and relays it verbatim", async () => {
    let attempts = 0;
    const provider = interceptProviderFetch(() => {
      attempts += 1;
      return providerJson({ error: { message: "bad request" } }, 400);
    });
    try {
      // Retries are generously available; the PREDICATE is what refuses.
      const app = harness({ reliability: { maxDispatchRetries: 5 } }, [
        route({ provider: "solo" }),
      ]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(res.status).toBe(400);
      expect(attempts).toBe(1);
    } finally {
      provider.restore();
    }
  });

  it("stops at max retries and relays the last retryable status", async () => {
    let attempts = 0;
    const provider = interceptProviderFetch(() => {
      attempts += 1;
      return providerJson({ error: "overloaded" }, 503);
    });
    try {
      const app = harness({ reliability: { maxDispatchRetries: 2 } }, [
        route({ provider: "solo" }),
      ]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      // 1 initial + 2 retries, and then the provider's own status reaches the
      // client rather than a synthesized gateway error.
      expect(attempts).toBe(3);
      expect(res.status).toBe(503);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// Failover ladder — MOUNT GATE
// ---------------------------------------------------------------------------

describe("failover ladder", () => {
  it("reaches the second candidate when the first answers a retryable status", async () => {
    const provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "primary"
        ? providerJson({ error: "overloaded" }, 503)
        : providerJson(CHAT_OK),
    );
    try {
      const app = harness({}, [
        route({ provider: "primary", priority: 0 }),
        route({ provider: "backup", priority: 1 }),
      ]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(res.status).toBe(200);
      expect(provider.requests.map((request) => providerOf(request.url))).toEqual([
        "primary",
        "backup",
      ]);
      // Metering attributes the call to the provider that ACTUALLY served it.
      expect(app.usage.last?.provider).toBe("backup");
    } finally {
      provider.restore();
    }
  });

  it("fails over on a transport failure, not only on a status", async () => {
    const provider = interceptProviderFetch((request) => {
      if (providerOf(request.url) === "primary") {
        throw new TypeError("Network connection lost.");
      }
      return providerJson(CHAT_OK);
    });
    try {
      const app = harness({}, [
        route({ provider: "primary", priority: 0 }),
        route({ provider: "backup", priority: 1 }),
      ]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(res.status).toBe(200);
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("walks candidates in priority then weight order", async () => {
    const provider = interceptProviderFetch(() => providerJson({ error: "overloaded" }, 503));
    try {
      const app = harness({}, [
        // Declared out of order on purpose: the ORDERING is what is asserted.
        route({ provider: "third", priority: 2 }),
        route({ provider: "lightweight", priority: 1, weight: 1 }),
        route({ provider: "heavy", priority: 1, weight: 9 }),
        route({ provider: "first", priority: 0 }),
      ]);
      await app.post("/v1/chat/completions", CHAT_BODY);

      expect(provider.requests.map((request) => providerOf(request.url))).toEqual([
        "first",
        "heavy",
        "lightweight",
        "third",
      ]);
    } finally {
      provider.restore();
    }
  });

  it("relays the last candidate's error once the ladder is exhausted", async () => {
    const provider = interceptProviderFetch(() => providerJson({ error: "down" }, 500));
    try {
      const app = harness({}, [
        route({ provider: "primary", priority: 0 }),
        route({ provider: "backup", priority: 1 }),
      ]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(provider.requests).toHaveLength(2);
      expect(res.status).toBe(500);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// Circuit breaker — MOUNT GATE
// ---------------------------------------------------------------------------

describe("provider circuit breaker", () => {
  it("opens after the configured number of consecutive failures and short-circuits", async () => {
    const provider = interceptProviderFetch(() => providerJson({ error: "down" }, 503));
    try {
      // ONE candidate, threshold 2: the third request must not reach the wire.
      const circuit = new InMemoryProviderCircuit(withBreaker());
      const app = harness({ reliability: withBreaker(), circuit }, [route({ provider: "wedged" })]);

      expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(503);
      expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(503);
      expect(provider.requests).toHaveLength(2);
      expect(circuit.snapshot("wedged").consecutiveFailures).toBe(2);

      const shorted = await app.post("/v1/chat/completions", CHAT_BODY);
      expect(shorted.status).toBe(503);
      const body = await errorBody(shorted);
      expect(body.error.code).toBe("provider_circuit_open");
      expect(body.error.message).toBe("provider wedged circuit breaker is open");
      // THE GATE: no third outbound request was made.
      expect(provider.requests).toHaveLength(2);
    } finally {
      provider.restore();
    }
  });

  it("skips a candidate whose circuit is open instead of failing the request", async () => {
    const provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "wedged"
        ? providerJson({ error: "down" }, 503)
        : providerJson(CHAT_OK),
    );
    try {
      const circuit = new InMemoryProviderCircuit(withBreaker({ circuitFailureThreshold: 1 }));
      const app = harness({ reliability: withBreaker({ circuitFailureThreshold: 1 }), circuit }, [
        route({ provider: "wedged", priority: 0 }),
        route({ provider: "healthy", priority: 1 }),
      ]);

      // First request: wedged fails (opening its circuit), healthy serves.
      expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(200);
      expect(provider.requests.map((request) => providerOf(request.url))).toEqual([
        "wedged",
        "healthy",
      ]);

      // Second request: the open circuit is SKIPPED, so `wedged` is never dialled.
      expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(200);
      expect(provider.requests.map((request) => providerOf(request.url))).toEqual([
        "wedged",
        "healthy",
        "healthy",
      ]);
    } finally {
      provider.restore();
    }
  });

  it("is OFF unless the operator configures both a threshold and a cooldown", async () => {
    const provider = interceptProviderFetch(() => providerJson({ error: "down" }, 503));
    try {
      // Rust: `provider_circuit_config` is `None` unless BOTH fields are set,
      // and `provider_circuit_allows` then returns true unconditionally.
      const app = harness({}, [route({ provider: "wedged" })]);
      for (let i = 0; i < 5; i += 1) {
        expect((await app.post("/v1/chat/completions", CHAT_BODY)).status).toBe(503);
      }
      expect(provider.requests).toHaveLength(5);
    } finally {
      provider.restore();
    }
  });

  it("does not count a non-retryable client error against the circuit", async () => {
    const provider = interceptProviderFetch(() => providerJson({ error: "bad" }, 400));
    try {
      const circuit = new InMemoryProviderCircuit(withBreaker());
      const app = harness({ reliability: withBreaker(), circuit }, [route({ provider: "picky" })]);

      await app.post("/v1/chat/completions", CHAT_BODY);
      await app.post("/v1/chat/completions", CHAT_BODY);
      await app.post("/v1/chat/completions", CHAT_BODY);

      // Rust guards `record_provider_failure` with `if retryable_status`.
      expect(circuit.snapshot("picky").consecutiveFailures).toBe(0);
      expect(provider.requests).toHaveLength(3);
    } finally {
      provider.restore();
    }
  });

  it("clears the streak on a success", async () => {
    let calls = 0;
    const provider = interceptProviderFetch(() => {
      calls += 1;
      return calls === 1 ? providerJson({ error: "down" }, 503) : providerJson(CHAT_OK);
    });
    try {
      const circuit = new InMemoryProviderCircuit(withBreaker());
      const app = harness({ reliability: withBreaker(), circuit }, [route({ provider: "flappy" })]);

      await app.post("/v1/chat/completions", CHAT_BODY);
      expect(circuit.snapshot("flappy").consecutiveFailures).toBe(1);
      await app.post("/v1/chat/completions", CHAT_BODY);
      expect(circuit.snapshot("flappy").consecutiveFailures).toBe(0);
    } finally {
      provider.restore();
    }
  });
});

describe("ProviderCircuitState — the shared arithmetic", () => {
  it("opens at the threshold and re-allows only after the cooldown elapses", () => {
    const state = new ProviderCircuitState();
    expect(state.allowsRequest(1_000, 0)).toBe(true);

    state.recordFailure(2, 100);
    expect(state.allowsRequest(1_000, 100)).toBe(true);
    state.recordFailure(2, 200);
    expect(state.snapshot.openedAtMs).toBe(200);

    expect(state.allowsRequest(1_000, 900)).toBe(false);
    // `>=`, exactly as Rust compares it.
    expect(state.allowsRequest(1_000, 1_200)).toBe(true);
  });

  it("stays open across the cooldown until a success closes it", () => {
    const state = new ProviderCircuitState();
    state.recordFailure(1, 0);
    expect(state.allowsRequest(100, 200)).toBe(true);
    // Still marked open: only a SUCCESS clears `openedAtMs`, so the very next
    // failure re-opens immediately rather than spending a fresh threshold.
    expect(state.snapshot.openedAtMs).toBe(0);
    state.recordSuccess();
    expect(state.snapshot).toEqual({ consecutiveFailures: 0, openedAtMs: null });
  });
});

describe("DurableObjectProviderCircuit", () => {
  /** A namespace whose stubs run the REAL state machine, one per DO name. */
  function fakeNamespace(states: Map<string, ProviderCircuitState>): {
    namespace: ProviderCircuitNamespace;
    names: string[];
  } {
    const names: string[] = [];
    const namespace = {
      idFromName(name: string): unknown {
        names.push(name);
        return { name };
      },
      get(id: { name: string }): unknown {
        const state = states.get(id.name) ?? new ProviderCircuitState();
        states.set(id.name, state);
        return {
          allows: async (cooldownMs: number) => state.allowsRequest(cooldownMs, 0),
          recordSuccess: async () => state.recordSuccess(),
          recordFailure: async (threshold: number) => state.recordFailure(threshold, 0),
        };
      },
    } as unknown as ProviderCircuitNamespace;
    return { namespace, names };
  }

  it("addresses one instance per provider, namespaced", async () => {
    const states = new Map<string, ProviderCircuitState>();
    const { namespace, names } = fakeNamespace(states);
    const circuit = new DurableObjectProviderCircuit(namespace, withBreaker());

    await circuit.recordFailure("openai-main");
    await circuit.recordFailure("openai-main");
    await circuit.recordFailure("anthropic-main");

    expect(names).toEqual([
      "provider:openai-main",
      "provider:openai-main",
      "provider:anthropic-main",
    ]);
    expect(states.get("provider:openai-main")?.snapshot.consecutiveFailures).toBe(2);
    // Providers do not share a counter.
    expect(states.get("provider:anthropic-main")?.snapshot.consecutiveFailures).toBe(1);
    expect(await circuit.allows("openai-main")).toBe(false);
    expect(await circuit.allows("anthropic-main")).toBe(true);
  });

  it("fails OPEN when the Durable Object dispatch throws", async () => {
    const namespace = {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        allows: async () => {
          throw new Error("durable object unavailable");
        },
        recordSuccess: async () => undefined,
        recordFailure: async () => undefined,
      }),
    } as unknown as ProviderCircuitNamespace;
    const circuit = new DurableObjectProviderCircuit(namespace, withBreaker());

    // A breaker outage must not become an inference outage.
    expect(await circuit.allows("openai-main")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Canary / shadow — MOUNT GATE for @ferrogate/routing
// ---------------------------------------------------------------------------

describe("canary rollout uses @ferrogate/routing bucketing", () => {
  /**
   * The canary is declared at a LOWER priority than the primary, so nothing but
   * `applyCanary` can put it first. Drop the rollout call and the "selected"
   * caller silently lands on `stable`, which is the assertion below.
   */
  const CANARY_ROUTES: readonly PhysicalRoute[] = [
    route({ provider: "stable", priority: 0 }),
    route({ provider: "canary", priority: 5, canaryPercent: 50 }),
  ];

  it("routes exactly the callers @ferrogate/routing buckets in, and no others", async () => {
    const keys = ["key-a", "key-b", "key-c", "key-d", "key-e", "key-f", "key-g", "key-h"];
    const served: Record<string, string> = {};
    for (const key of keys) {
      const provider = interceptProviderFetch(() => providerJson(CHAT_OK));
      try {
        const app = harness({ caller: keyedCaller(key) }, CANARY_ROUTES);
        await app.post("/v1/chat/completions", CHAT_BODY);
        served[key] = providerOf(provider.lastRequest().url);
      } finally {
        provider.restore();
      }
    }

    // The expectation is computed from the PACKAGE's own hash, not hard-coded:
    // if the gateway ever grew a second bucketing implementation this diverges.
    const expected = Object.fromEntries(
      keys.map((key) => [key, rolloutBucket("canary", key) < 50 ? "canary" : "stable"]),
    );
    expect(served).toEqual(expected);

    // The split must be real, not "everything on one side" — a bucketing that
    // always answered the same way would satisfy the equality above.
    const distinct = new Set(Object.values(served));
    expect(distinct).toEqual(new Set(["canary", "stable"]));
  });

  it("is sticky: the same key lands on the same route every time", async () => {
    const key = keys0();
    const seen: string[] = [];
    for (let i = 0; i < 4; i += 1) {
      const provider = interceptProviderFetch(() => providerJson(CHAT_OK));
      try {
        const app = harness({ caller: keyedCaller(key) }, CANARY_ROUTES);
        await app.post("/v1/chat/completions", CHAT_BODY);
        seen.push(providerOf(provider.lastRequest().url));
      } finally {
        provider.restore();
      }
    }
    expect(new Set(seen).size).toBe(1);
  });

  it("keeps the canary out of the ladder entirely for an unselected caller", async () => {
    const unselected = keys0(false);
    const provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "stable"
        ? providerJson({ error: "down" }, 503)
        : providerJson(CHAT_OK),
    );
    try {
      const app = harness({ caller: keyedCaller(unselected) }, CANARY_ROUTES);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      // The stable route failed and there was NO fallback, because a canary the
      // caller was not bucketed into is dropped rather than demoted.
      expect(res.status).toBe(503);
      expect(provider.requests.map((request) => providerOf(request.url))).toEqual(["stable"]);
    } finally {
      provider.restore();
    }
  });

  it("drops the canary when the caller has no sticky identity", async () => {
    const provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    try {
      // The default caller is a platform operator with no api-key id: there is
      // no stable key to bucket on, so the rollout is simply off.
      const app = harness({}, CANARY_ROUTES);
      await app.post("/v1/chat/completions", CHAT_BODY);
      expect(providerOf(provider.lastRequest().url)).toBe("stable");
    } finally {
      provider.restore();
    }
  });
});

/** A key the `"canary"` salt buckets IN (or OUT, for `selected = false`) at 50%. */
function keys0(selected = true): string {
  for (let i = 0; i < 1000; i += 1) {
    const key = `sticky-${i}`;
    if (rolloutBucket("canary", key) < 50 === selected) {
      return key;
    }
  }
  throw new Error("no sticky key found for the requested bucket");
}

describe("shadow routes are mirrors, never candidates", () => {
  it("never serves a client from a shadow route, even when everything else fails", async () => {
    const provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "primary"
        ? providerJson({ error: "down" }, 503)
        : providerJson(CHAT_OK),
    );
    try {
      const app = harness({ caller: keyedCaller("shadow-key") }, [
        route({ provider: "primary", priority: 0 }),
        route({ provider: "mirror", priority: 1, shadowPercent: 100, shadowMaxRequests: 0 }),
      ]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      // Without `servableCandidates` the mirror would have served this 200.
      expect(res.status).toBe(503);
      // ...and the CLIENT's bytes are the failed primary's, never the healthy
      // mirror's. This is the assertion that used to read "the mirror was never
      // dialled at all", which stopped distinguishing anything once
      // `shadow.ts` landed and the mirror IS dialled — as a mirror. What the
      // client is served by is the property that was always meant.
      expect(await res.text()).not.toContain("chatcmpl-ok");

      // The LADDER walked the primary and stopped: the mirror is not a
      // fallback. Anything the mirror dispatched is fire-and-forget and
      // arrives on `ctx.waitUntil`, which is why its dispatch is counted
      // separately rather than asserted absent.
      const dialled = provider.requests.map((request) => providerOf(request.url));
      expect(dialled.filter((name) => name === "primary")).toEqual(["primary"]);
      expect(dialled.filter((name) => name === "mirror").length).toBeLessThanOrEqual(1);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// Route eligibility (issue #582) — MOUNT GATE
// ---------------------------------------------------------------------------

describe("route eligibility runs before dispatch", () => {
  it("excludes a route that does not declare `streaming` from a streaming request", async () => {
    const provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "streamer"
        ? providerSse(OPENAI_CHAT_STREAM_FRAMES)
        : providerJson(CHAT_OK),
    );
    try {
      const app = harness({}, [
        route({ provider: "buffered", priority: 0, capabilities: ["chat"] }),
        route({ provider: "streamer", priority: 1, capabilities: ["chat", "streaming"] }),
      ]);
      const res = await app.post("/v1/chat/completions", { ...CHAT_BODY, stream: true });

      expect(res.status).toBe(200);
      // The incompatible route was never dialled — excluded, not failed over.
      expect(provider.requests.map((request) => providerOf(request.url))).toEqual(["streamer"]);
    } finally {
      provider.restore();
    }
  });

  it("answers 400 invalid_request when no route satisfies the request", async () => {
    const provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    try {
      const app = harness({}, [route({ provider: "buffered", capabilities: ["chat"] })]);
      const res = await app.post("/v1/chat/completions", { ...CHAT_BODY, stream: true });

      expect(res.status).toBe(400);
      const body = await errorBody(res);
      expect(body.error.code).toBe("invalid_request");
      expect(body.error.message).toBe(
        `no physical route for model ${MODEL} satisfies the request requirements`,
      );
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("excludes a route whose declared context window cannot hold the request", async () => {
    const provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    try {
      const app = harness({}, [
        route({ provider: "tiny", priority: 0, capabilities: ["chat"], contextWindow: 8 }),
        route({ provider: "roomy", priority: 1, capabilities: ["chat"], contextWindow: 200_000 }),
      ]);
      const res = await app.post("/v1/chat/completions", {
        model: MODEL,
        messages: [{ role: "user", content: "x".repeat(4000) }],
        max_tokens: 1024,
      });

      expect(res.status).toBe(200);
      expect(provider.requests.map((request) => providerOf(request.url))).toEqual(["roomy"]);
    } finally {
      provider.restore();
    }
  });

  it("enforces the caller's region allowlist with 403 region_not_allowed", async () => {
    const provider = interceptProviderFetch(() => providerJson(CHAT_OK));
    try {
      const app = harness(
        {
          caller: () => ({ scope: { kind: "platform_operator" }, regionAllowlist: ["eu-west-1"] }),
        },
        [route({ provider: "us", region: "us-east-1" })],
      );
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(res.status).toBe(403);
      const body = await errorBody(res);
      expect(body.error.code).toBe("region_not_allowed");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("leaves a capability-neutral route reachable by every surface", async () => {
    // The documented deviation: a route declaring NO capabilities is neutral.
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const app = harness({}, [route({ provider: "legacy" })]);
      const res = await app.post("/v1/chat/completions", { ...CHAT_BODY, stream: true });
      expect(res.status).toBe(200);
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// Streaming: the point of no return — MOUNT GATE
// ---------------------------------------------------------------------------

describe("a stream that faults mid-body is never retried", () => {
  it("makes exactly one attempt and surfaces the fault instead of truncating", async () => {
    const provider = interceptProviderFetch(() =>
      providerSseThatFaults([OPENAI_CHAT_STREAM_FRAMES[0] as string]),
    );
    try {
      const app = harness({ reliability: { maxDispatchRetries: 3 } }, [
        route({ provider: "primary", priority: 0 }),
        route({ provider: "backup", priority: 1 }),
      ]);
      const res = await app.post("/v1/chat/completions", { ...CHAT_BODY, stream: true });

      // The gateway committed at the headers: 200, streaming.
      expect(res.status).toBe(200);

      // Reading the body FAULTS. It does not end cleanly, which is what makes
      // the truncation visible to the client instead of silent.
      await expect(readBody(res)).rejects.toThrow();

      // THE GATE: one attempt, despite three retries and a healthy fallback
      // being available. Bytes were already flushed; there is no going back.
      expect(provider.requests).toHaveLength(1);
      expect(providerOf(provider.requests[0]?.url ?? "")).toBe("primary");
    } finally {
      provider.restore();
    }
  });

  it("still fails over when the upstream refuses BEFORE any byte is flushed", async () => {
    // The complement of the test above: a streaming request whose upstream
    // answers a retryable STATUS has flushed nothing, so the ladder applies.
    const provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "primary"
        ? providerJson({ error: "overloaded" }, 503)
        : providerSse(OPENAI_CHAT_STREAM_FRAMES),
    );
    try {
      const app = harness({}, [
        route({ provider: "primary", priority: 0 }),
        route({ provider: "backup", priority: 1 }),
      ]);
      const res = await app.post("/v1/chat/completions", { ...CHAT_BODY, stream: true });

      expect(res.status).toBe(200);
      expect(provider.requests).toHaveLength(2);
      expect(await readBody(res)).toContain("chatcmpl-test");
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

describe("GATEWAY_RELIABILITY", () => {
  it("parses the Rust [reliability] block", () => {
    expect(
      reliabilityFromVar(
        JSON.stringify({
          provider_circuit_breaker_failure_threshold: 5,
          provider_circuit_breaker_cooldown_secs: 30,
          provider_dispatch_max_retries: 2,
        }),
      ),
    ).toEqual({
      circuitFailureThreshold: 5,
      circuitCooldownMs: 30_000,
      maxDispatchRetries: 2,
    });
  });

  it("falls back to the Rust defaults — breaker off, no retries — when unset", () => {
    expect(reliabilityFromVar(undefined)).toEqual(DEFAULT_RELIABILITY);
    expect(DEFAULT_RELIABILITY).toEqual({
      circuitFailureThreshold: 0,
      circuitCooldownMs: 0,
      maxDispatchRetries: 0,
    });
  });

  it("refuses a malformed or out-of-range var instead of half-applying it", () => {
    expect(reliabilityFromVar("{not json")).toEqual(DEFAULT_RELIABILITY);
    // The Rust validator refuses a zero threshold outright.
    expect(
      reliabilityFromVar(JSON.stringify({ provider_circuit_breaker_failure_threshold: 0 })),
    ).toEqual(DEFAULT_RELIABILITY);
    // `.strict()` — an unknown key is a typo, not something to ignore.
    expect(reliabilityFromVar(JSON.stringify({ provider_circuit_breaker_treshold: 5 }))).toEqual(
      DEFAULT_RELIABILITY,
    );
  });
});
