/**
 * ANTI-UNMOUNT for the provider reliability layer — the circuit breaker as the
 * DEPLOYED Worker runs it.
 *
 * ## Why this file had to be written during integration
 *
 * `test/inference/reliability.test.ts` is thorough about the LADDER: retry,
 * failover, eligibility, canary and the breaker arithmetic. Every one of its
 * cases builds its own `harness({ reliability, circuit })` and hands the
 * breaker in explicitly. That is exactly the shape of the defect this wave
 * exists to close: with the `circuit` argument supplied by the test, nothing
 * asserts that the COMPOSITION ROOT supplies one.
 *
 * It was measured, not assumed. Two mutations were run against the full
 * gateway suite before this file existed:
 *
 *   1. `defaults.ts::providerCircuitFor` — replace `env["PROVIDER_CIRCUIT"]`
 *      with `undefined`, so the Durable Object binding is never read and the
 *      breaker silently degrades to a per-isolate `Map`.
 *      → 1235 passed. GREEN.
 *   2. `defaults.ts` — replace `deps.circuit ?? providerCircuitFor(...)` with
 *      `deps.circuit ?? NO_PROVIDER_CIRCUIT`, i.e. NO breaker at all on the
 *      deployed data plane, a wedged provider dialled forever.
 *      → 1235 passed. GREEN.
 *
 * Both mutations are caught here, and only here.
 *
 * Everything below goes through `SELF.fetch` — `src/worker.ts` → `src/index.ts`
 * → `createGatewayApp` → the mounted inference module — against the real
 * `wrangler.toml` bindings, so `PROVIDER_CIRCUIT` is the real Durable Object
 * namespace and not a stand-in.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { ProviderCircuitSnapshot } from "../../src/inference/reliability.js";

const BASE = "https://gw.test";
const UPSTREAM_HOST = "api.wedged.example";

/** One provider, so a failure streak belongs to exactly one circuit. */
const PROVIDERS = JSON.stringify([
  { name: "wedged", kind: "openai", base_url: `https://${UPSTREAM_HOST}/v1` },
]);
const MODELS = JSON.stringify([
  { name: "breaker-probe", provider: "wedged", provider_model: "breaker-probe-physical" },
]);
const KEYS = JSON.stringify([
  { key: "fg_breaker", id: "key_breaker", tenant_id: "tenant_a", scopes: [] },
]);

/**
 * Threshold 2 and no same-provider retries, so the arithmetic under test is
 * "two requests, two failures, third is short-circuited" with nothing else
 * moving. A LONG cooldown keeps the open circuit open for the whole file.
 */
const RELIABILITY = JSON.stringify({
  provider_circuit_breaker_failure_threshold: 2,
  provider_circuit_breaker_cooldown_secs: 600,
  provider_dispatch_max_retries: 0,
});

const OVERRIDES: Record<string, string> = {
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: KEYS,
  GATEWAY_RELIABILITY: RELIABILITY,
};

const ORIGINAL: Record<string, unknown> = {};
const mutable = env as unknown as Record<string, unknown>;

beforeAll(() => {
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

/** Every call to the wedged provider fails, and each one is counted. */
function wedgeUpstream(): { calls: () => number; restore: () => void } {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!url.includes(UPSTREAM_HOST)) {
      return await original(input as RequestInfo, init);
    }
    calls += 1;
    return new Response(JSON.stringify({ error: "upstream down" }), {
      status: 503,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return {
    calls: () => calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

async function chat(): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await SELF.fetch(`${BASE}/v1/chat/completions`, {
    method: "POST",
    headers: { authorization: "Bearer fg_breaker", "content-type": "application/json" },
    body: JSON.stringify({
      model: "breaker-probe",
      messages: [{ role: "user", content: "does the breaker exist in production" }],
    }),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

function errorCode(body: Record<string, unknown>): string | undefined {
  return (body.error as { code?: string } | undefined)?.code;
}

/**
 * The breaker state the DURABLE OBJECT holds for this provider, read through
 * the same `PROVIDER_CIRCUIT` binding the request path uses.
 *
 * This read is what distinguishes "a breaker ran" from "THE Durable Object
 * breaker ran": a per-isolate `Map` would open the circuit just as well inside
 * one test file, and mutation (1) above would have stayed green forever.
 */
async function durableSnapshot(provider: string): Promise<ProviderCircuitSnapshot> {
  const namespace = (env as unknown as Record<string, DurableObjectNamespace | undefined>)
    .PROVIDER_CIRCUIT;
  if (namespace === undefined) {
    // Not a soft skip: an unbound namespace means `wrangler.toml` lost the
    // `[[durable_objects.bindings]]` stanza, which is half the mount.
    throw new Error("PROVIDER_CIRCUIT is not bound — wrangler.toml lost the DO binding");
  }
  const stub = namespace.get(namespace.idFromName(`provider:${provider}`));
  return await (stub as unknown as { snapshot(): Promise<ProviderCircuitSnapshot> }).snapshot();
}

describe("the deployed Worker breaks the circuit on a wedged provider", () => {
  let upstream: ReturnType<typeof wedgeUpstream> | undefined;

  afterEach(() => {
    upstream?.restore();
    upstream = undefined;
  });

  it("short-circuits the third request and stops dialling the provider", async () => {
    upstream = wedgeUpstream();

    // Two real attempts, two real failures — the provider IS reachable from the
    // deployed composition, so the refusal below is the breaker's and not a
    // dead route.
    expect((await chat()).status).toBe(503);
    expect((await chat()).status).toBe(503);
    expect(upstream.calls()).toBe(2);

    // Threshold reached. The third request must never leave the Worker.
    const shorted = await chat();
    expect(shorted.status).toBe(503);
    expect(errorCode(shorted.body)).toBe("provider_circuit_open");
    // THE GATE: no third outbound request. Without a breaker on the deployed
    // data plane this is 3.
    expect(upstream.calls()).toBe(2);
  });

  it("kept that state in the PROVIDER_CIRCUIT Durable Object, not an isolate Map", async () => {
    // Depends on the streak the case above produced: a DO instance survives
    // between requests and between tests, which is the whole reason the state
    // lives there rather than in a module-scope `Map` that every new isolate
    // gets a fresh copy of.
    const snapshot = await durableSnapshot("wedged");
    expect(snapshot.consecutiveFailures).toBeGreaterThanOrEqual(2);
    expect(snapshot.openedAtMs).not.toBeNull();
  });

  it("a HEALTHY provider's circuit is untouched — one DO instance per provider", async () => {
    const snapshot = await durableSnapshot("some-other-provider");
    expect(snapshot).toEqual({ consecutiveFailures: 0, openedAtMs: null });
  });
});
