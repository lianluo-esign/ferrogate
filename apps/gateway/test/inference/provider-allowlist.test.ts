/**
 * ANTI-UNMOUNT: the per-key PROVIDER allowlist (`auth.rs:146`
 * `can_use_provider`) reaches the 403 gate.
 *
 * ## Why this is its own suite
 *
 * Exactly the same two-hop dead seam `test/inference/allowlist.test.ts` exists
 * for, one column over. `keys/store.ts` parses `allowed_providers_json`,
 * `keys/resolver.ts::toAuthContext` publishes it as
 * `AuthContext.allowedProviders`, and both files' tests were green — while
 * NOTHING in the inference path read the field. A key restricted to `openai`
 * could dispatch to any provider in the catalog and the whole suite stayed
 * green, because no single file was wrong: the CHAIN had no reader.
 *
 * ## The two properties that are NOT interchangeable with a route exclusion
 *
 * Rust checks the SELECTED candidate inside the `'routes:` loop
 * (`chat.rs:318`, `messages.rs:302`, `embeddings.rs:252`, `images.rs:269`),
 * immediately after the circuit-breaker check, and refuses with
 * `return Ok(())` — no fall-through. So:
 *
 *  - POSITION: a disallowed provider whose circuit is OPEN, with a next
 *    candidate, is SKIPPED by the circuit arm and never reaches the 403 — the
 *    request succeeds on the fallback;
 *  - TERMINALITY: the same disallowed provider with a CLOSED circuit ends the
 *    request at 403 even though that identical fallback exists.
 *
 * An implementation that modelled the allowlist as a `routeExclusionReasons`
 * code (which the old PORT-TODO proposed) passes every "refuses" test and
 * SILENTLY SERVES the second case. "refuses a disallowed provider even when an
 * ALLOWED fallback exists" is the assertion that separates the two, and it is
 * the reason this suite is not three lines long.
 */
import { describe, expect, it } from "vitest";
import {
  InMemoryModelResolver,
  attemptDecision,
  callerCanUseProvider,
  callerFromAuth,
  createInferenceRouter,
  dispatchWithFailover,
} from "../../src/inference/index.js";
import type {
  AttemptCandidate,
  AttemptResult,
  Caller,
  InferenceRejection,
  PhysicalRoute,
  ProviderCircuit,
  ReliabilitySettings,
} from "../../src/inference/index.js";
import type { AuthContext } from "../../src/ports.js";
import { errorBody, fixedRequestIds } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

/**
 * One logical model, two PHYSICAL routes on two different providers: `alpha`
 * at priority 0 (tried first) and `beta` as the fallback. Both are `openai`
 * FAMILY, which is the point — the gate is on the provider-table row name, not
 * on `providerKind`.
 */
const ROUTES: readonly PhysicalRoute[] = [
  {
    logicalModel: "dual",
    provider: "alpha",
    providerModel: "m",
    providerKind: "openai",
    baseUrl: "https://alpha.test/v1",
    apiKey: "sk-alpha",
    enabled: true,
    priority: 0,
  },
  {
    logicalModel: "dual",
    provider: "beta",
    providerModel: "m",
    providerKind: "openai",
    baseUrl: "https://beta.test/v1",
    apiKey: "sk-beta",
    enabled: true,
    priority: 1,
  },
];

/** The `AuthContext` `keys/resolver.ts::toAuthContext` builds for a durable key. */
function durableKey(allowedProviders?: readonly string[]): AuthContext {
  return {
    subject: "key_1",
    tenancy: { tenantId: "acme" },
    scopes: [],
    platformOperator: false,
    source: "durable_native",
    ...(allowedProviders === undefined ? {} : { allowedProviders }),
  };
}

async function chat(auth: AuthContext): Promise<Response> {
  const router = createInferenceRouter({
    models: new InMemoryModelResolver(ROUTES),
    requestIds: fixedRequestIds,
    caller: (): Caller => callerFromAuth(auth),
  });
  return await router.request("https://gw.test/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "dual", messages: [{ role: "user", content: "hi" }] }),
  });
}

const OK_BODY = {
  id: "chatcmpl-1",
  object: "chat.completion",
  model: "m",
  choices: [
    { index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" },
  ],
};

// ---------------------------------------------------------------------------
// The predicate
// ---------------------------------------------------------------------------

describe("callerCanUseProvider is the Rust can_use_provider predicate", () => {
  const restricted: Caller = {
    scope: { kind: "tenant", tenantId: "acme" },
    allowedProviders: ["alpha"],
  };

  it("admits a provider named by the allowlist and refuses one that is not", () => {
    expect(callerCanUseProvider(restricted, "alpha")).toBe(true);
    expect(callerCanUseProvider(restricted, "beta")).toBe(false);
  });

  it("treats an ABSENT or EMPTY allowlist as no allowlist", () => {
    // `allowed_providers.is_empty() || allowed_providers.contains(p)`. A
    // credential source with no such column must not read as "may use nothing".
    expect(callerCanUseProvider({ scope: restricted.scope }, "beta")).toBe(true);
    expect(
      callerCanUseProvider({ ...restricted, allowedProviders: [] }, "beta"),
    ).toBe(true);
  });

  it("lets a DENY win over an allowlist that names the provider", () => {
    expect(
      callerCanUseProvider({ ...restricted, deniedProviders: ["alpha"] }, "alpha"),
    ).toBe(false);
  });
});

describe("callerFromAuth carries the credential's provider allowlist", () => {
  it("copies a NON-EMPTY allowlist onto the caller", () => {
    expect(callerFromAuth(durableKey(["alpha"])).allowedProviders).toEqual(["alpha"]);
  });

  it("omits an EMPTY allowlist rather than forwarding it", () => {
    expect(callerFromAuth(durableKey([])).allowedProviders).toBeUndefined();
    expect(callerFromAuth(durableKey()).allowedProviders).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The ladder: position and terminality
// ---------------------------------------------------------------------------

const SETTINGS: ReliabilitySettings = {
  maxDispatchRetries: 0,
  circuitFailureThreshold: 3,
  circuitCooldownMs: 30_000,
};

/** A circuit that is open for exactly the providers named. */
function circuitOpenFor(...open: readonly string[]): ProviderCircuit {
  return {
    async allows(provider: string): Promise<boolean> {
      return !open.includes(provider);
    },
    async recordSuccess(): Promise<void> {},
    async recordFailure(): Promise<void> {},
  };
}

function candidatesFor(...providers: readonly string[]): AttemptCandidate[] {
  return providers.map((provider) => ({
    route: ROUTES.find((route) => route.provider === provider) as PhysicalRoute,
    upstream: {
      provider,
      endpoint: `https://${provider}.test/v1/chat/completions`,
      method: "POST" as const,
      headers: {},
      stream: false,
    },
  }));
}

function isRejection(value: AttemptResult): value is InferenceRejection {
  return !(value instanceof Response);
}

describe("dispatchWithFailover places the provider gate exactly where Rust does", () => {
  it("refuses TERMINALLY — an allowed fallback candidate is NOT tried", async () => {
    const tried: string[] = [];
    const outcome = await dispatchWithFailover({
      candidates: candidatesFor("alpha", "beta"),
      circuit: circuitOpenFor(),
      settings: SETTINGS,
      providerAllowed: (provider) => provider === "beta",
      attempt: async (candidate) => {
        tried.push(candidate.route.provider);
        return new Response("{}", { status: 200 });
      },
      isRejection,
    });

    // Rust: `write_json_error(403 provider_not_allowed); return Ok(())`.
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.rejection.status).toBe(403);
    expect(outcome.rejection.code).toBe("provider_not_allowed");
    expect(outcome.rejection.message).toBe(
      "API key is not allowed to use provider alpha",
    );
    // The assertion a route-EXCLUSION implementation cannot satisfy: `beta` is
    // allowed and eligible, and it is still never reached.
    expect(tried).toEqual([]);
  });

  it("runs AFTER the circuit, so an open circuit skips past the gate", async () => {
    // `alpha` is disallowed AND its circuit is open, with `beta` behind it.
    // Rust's `continue` in the circuit arm fires first, so the 403 is never
    // reached and the request is SERVED by the allowed fallback. A gate placed
    // before the circuit check would 403 here instead.
    const tried: string[] = [];
    const outcome = await dispatchWithFailover({
      candidates: candidatesFor("alpha", "beta"),
      circuit: circuitOpenFor("alpha"),
      settings: SETTINGS,
      providerAllowed: (provider) => provider === "beta",
      attempt: async (candidate) => {
        tried.push(candidate.route.provider);
        return new Response("{}", { status: 200 });
      },
      isRejection,
    });

    expect(outcome.ok).toBe(true);
    expect(tried).toEqual(["beta"]);
  });

  it("charges no attempt and opens no socket when it refuses", async () => {
    const outcome = await dispatchWithFailover({
      candidates: candidatesFor("alpha"),
      circuit: circuitOpenFor(),
      settings: SETTINGS,
      providerAllowed: () => false,
      attempt: async () => {
        throw new Error("the gate let a disallowed provider through");
      },
      isRejection,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.attempts).toBe(0);
  });

  it("is inert for a credential that allows everything — the control", async () => {
    const tried: string[] = [];
    const outcome = await dispatchWithFailover({
      candidates: candidatesFor("alpha", "beta"),
      circuit: circuitOpenFor(),
      settings: SETTINGS,
      providerAllowed: () => true,
      attempt: async (candidate) => {
        tried.push(candidate.route.provider);
        return new Response("{}", { status: 200 });
      },
      isRejection,
    });
    expect(outcome.ok).toBe(true);
    expect(tried).toEqual(["alpha"]);
    // `attemptDecision` is untouched by the new arm: a 0-retry success is one
    // attempt, not zero, so `attempts - 1` still indexes the served attempt.
    expect(attemptDecision(false, 0, 0, true)).toBe("return_error");
  });
});

// ---------------------------------------------------------------------------
// End to end, through the real router — the MOUNT GATE
// ---------------------------------------------------------------------------

describe("the provider allowlist reaches the 403 on the request path", () => {
  it("refuses a provider outside the credential's allowlist — MOUNT GATE", async () => {
    // Red if `callerFromAuth` stops forwarding `allowedProviders`, red if
    // `dispatchCandidates` stops passing `providerAllowed`, red if the ladder
    // stops consulting it. `interceptProviderFetch` throwing on any outbound
    // call means a leaked dispatch fails the test rather than passing quietly.
    const provider = interceptProviderFetch(() => undefined);
    try {
      const res = await chat(durableKey(["beta"]));
      expect(res.status).toBe(403);
      const body = await errorBody(res);
      expect(body.error.code).toBe("provider_not_allowed");
      expect(body.error.message).toBe("API key is not allowed to use provider alpha");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("admits a provider INSIDE the allowlist — the control", async () => {
    // Without this, a `callerFromAuth` that forwarded a bogus non-empty list
    // for every credential would pass the refusal test by refusing everything.
    const provider = interceptProviderFetch(() => providerJson(OK_BODY));
    try {
      const res = await chat(durableKey(["alpha"]));
      expect(res.status).toBe(200);
      expect(provider.requests).toHaveLength(1);
      expect(provider.lastRequest().url).toContain("alpha.test");
    } finally {
      provider.restore();
    }
  });

  it("leaves a credential with NO provider allowlist unrestricted", async () => {
    // Fail-OPEN in the correct direction: static/dev/external credentials have
    // no such column and must not read as "may use no provider at all".
    const provider = interceptProviderFetch(() => providerJson(OK_BODY));
    try {
      const res = await chat(durableKey());
      expect(res.status).toBe(200);
      expect(provider.lastRequest().url).toContain("alpha.test");
    } finally {
      provider.restore();
    }
  });
});

describe("the gate covers ALL FOUR dispatching surfaces, as Rust does", () => {
  // Rust repeats `can_use_provider` verbatim in four handlers — `chat.rs:318`
  // (serving both `/v1/chat/completions` and `/v1/responses`),
  // `messages.rs:302`, `embeddings.rs:252`, `images.rs:269`. This port funnels
  // all four through `dispatchCandidates`, so one gate serves all of them; this
  // suite is what stops a future refactor from inlining one surface's dispatch
  // and silently dropping its gate — the exact way four copied Rust arms rot.
  const SURFACES: readonly (readonly [string, Record<string, unknown>])[] = [
    ["/v1/chat/completions", { messages: [{ role: "user", content: "hi" }] }],
    ["/v1/responses", { input: "hi" }],
    ["/v1/messages", { max_tokens: 16, messages: [{ role: "user", content: "hi" }] }],
    ["/v1/embeddings", { input: "hi" }],
    ["/v1/images/generations", { prompt: "a cat" }],
  ];

  for (const [path, body] of SURFACES) {
    it(`refuses on ${path}`, async () => {
      const router = createInferenceRouter({
        models: new InMemoryModelResolver(ROUTES),
        requestIds: fixedRequestIds,
        caller: (): Caller => callerFromAuth(durableKey(["beta"])),
      });
      const provider = interceptProviderFetch(() => undefined);
      try {
        const res = await router.request(`https://gw.test${path}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ model: "dual", ...body }),
        });
        expect(res.status).toBe(403);
        expect((await errorBody(res)).error.code).toBe("provider_not_allowed");
        expect(provider.requests).toHaveLength(0);
      } finally {
        provider.restore();
      }
    });
  }
});
