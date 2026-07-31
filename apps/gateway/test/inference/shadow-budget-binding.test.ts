/**
 * ANTI-UNMOUNT for the `SHADOW_BUDGET` Durable Object BINDING — the wrangler
 * half of the shadow spend cap.
 *
 * ## Why this file exists alongside `shadow.test.ts` and `shadow-mount.test.ts`
 *
 * `shadow.test.ts` proves `shadowBudgetFor` picks a Durable Object over the
 * per-isolate ledger — but it hands the function a namespace the TEST built, so
 * it says nothing about whether `apps/gateway/wrangler.toml` declares one.
 * `shadow-mount.test.ts` mirrors with an UNCAPPED route (`max_requests: 0`),
 * and an uncapped budget short-circuits before the DO hop by design, so it
 * never touches the binding either.
 *
 * That gap was measured, not assumed: deleting the whole
 * `[[durable_objects.bindings]] SHADOW_BUDGET` stanza from `wrangler.toml` left
 * all 1390 gateway tests GREEN. A deployed gateway would then cap shadow spend
 * PER ISOLATE — the operator's `max_requests` multiplied by however many
 * isolates Cloudflare happens to run — while every test agreed the cap worked.
 * Shadow traffic is real money spent on responses no client ever sees, so that
 * is the expensive direction to be wrong in.
 *
 * So this file uses a CAPPED route and asserts on the REAL binding.
 *
 * MUTATION: remove the binding from `wrangler.toml` (or the
 * `export { ShadowBudgetDurableObject }` from `src/worker.ts`, which stops the
 * Worker booting at all) and both cases below go red.
 */
import { DurableObjectShadowBudgetLedger } from "@ferrogate/routing/durable-objects";
import type { ShadowBudgetNamespace } from "@ferrogate/routing/durable-objects";
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

const BASE = "https://gw.test";
const PRIMARY_HOST = "api.budget-primary.example";
const MIRROR_HOST = "api.budget-mirror.example";
/** Also the budget SCOPE KEY — `runShadowMirror` charges `mirror.logicalModel`. */
const MODEL = "budget-probe";

const PROVIDERS = JSON.stringify([
  { name: "primary", kind: "openai", base_url: `https://${PRIMARY_HOST}/v1` },
  { name: "mirror", kind: "openai", base_url: `https://${MIRROR_HOST}/v1` },
]);

/**
 * A 100%-sampled mirror CAPPED AT ONE. The cap is the point: `max_requests: 0`
 * is uncapped and `DurableObjectShadowBudgetLedger.tryConsume` returns `true`
 * without a round trip, so an uncapped route cannot detect a missing binding.
 */
const MODELS = JSON.stringify([
  {
    name: MODEL,
    provider: "primary",
    provider_model: "primary-physical",
    shadow: {
      provider: "mirror",
      provider_model: "mirror-physical",
      sample_percent: 100,
      max_requests: 1,
    },
  },
]);

const KEYS = JSON.stringify([
  { key: "fg_budget", id: "key_budget", tenant_id: "tenant_a", scopes: [] },
]);

const OVERRIDES: Record<string, string> = {
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: KEYS,
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

/** The namespace `wrangler.toml` is supposed to declare. */
function namespace(): ShadowBudgetNamespace {
  const slot = (env as unknown as Record<string, unknown>)["SHADOW_BUDGET"];
  if (
    typeof slot !== "object" ||
    slot === null ||
    typeof (slot as ShadowBudgetNamespace).idFromName !== "function"
  ) {
    throw new Error(
      "`SHADOW_BUDGET` is not bound. `apps/gateway/wrangler.toml` must declare " +
        "[[durable_objects.bindings]] name = \"SHADOW_BUDGET\", class_name = " +
        '"ShadowBudgetDurableObject" (migration tag v3), and `src/worker.ts` must ' +
        "re-export the class. Without it the shadow spend cap is PER ISOLATE.",
    );
  }
  return slot as ShadowBudgetNamespace;
}

const CHAT_OK = {
  id: "chatcmpl-primary",
  object: "chat.completion",
  model: MODEL,
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
};

interface Upstream {
  readonly hosts: string[];
  restore(): void;
}

function stubUpstreams(): Upstream {
  const original = globalThis.fetch;
  const hosts: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const host = new URL(url).hostname;
    if (host !== PRIMARY_HOST && host !== MIRROR_HOST) {
      return await original(input as RequestInfo, init);
    }
    hosts.push(host);
    return new Response(
      JSON.stringify(host === MIRROR_HOST ? { id: "chatcmpl-mirror" } : CHAT_OK),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as typeof fetch;
  return {
    hosts,
    restore(): void {
      globalThis.fetch = original;
    },
  };
}

async function chat(): Promise<Response> {
  return await SELF.fetch(`${BASE}/v1/chat/completions`, {
    method: "POST",
    headers: { authorization: "Bearer fg_budget", "content-type": "application/json" },
    body: JSON.stringify({
      model: MODEL,
      messages: [{ role: "user", content: "charge the durable budget" }],
    }),
  });
}

async function waitForMirror(upstream: Upstream): Promise<void> {
  for (let index = 0; index < 300; index += 1) {
    if (upstream.hosts.includes(MIRROR_HOST)) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error("timed out waiting for the deployed Worker to mirror the request");
}

let upstream: Upstream | undefined;

beforeEach(async () => {
  // Each case starts from a known counter; the DO is persistent across files.
  await new DurableObjectShadowBudgetLedger(namespace()).reset(MODEL);
});

afterEach(() => {
  upstream?.restore();
  upstream = undefined;
});

describe("the deployed Worker charges the SHADOW_BUDGET Durable Object", () => {
  it("a mirrored request is visible to a ledger the request never touched", async () => {
    upstream = stubUpstreams();

    expect((await chat()).status).toBe(200);
    await waitForMirror(upstream);

    // THE BINDING GATE. A ledger built here, on the namespace from `env`,
    // shares nothing with the request's own ledger EXCEPT the Durable Object —
    // so a non-zero count is only explicable by the deployed path having gone
    // through it. With the binding removed, `namespace()` throws.
    const consumed = await new DurableObjectShadowBudgetLedger(namespace()).consumed(MODEL);
    expect(consumed).toBe(1);
  });

  it("enforces `max_requests` against that durable count, not an isolate map", async () => {
    // Spend the whole cap from OUTSIDE the request path first.
    const ledger = new DurableObjectShadowBudgetLedger(namespace());
    expect(await ledger.tryConsume(MODEL, 1)).toBe(true);

    upstream = stubUpstreams();
    expect((await chat()).status).toBe(200);

    // The request must find the budget already spent. An isolate-local ledger
    // would know nothing about the charge above and would mirror anyway —
    // which is exactly the over-spend an unbound `SHADOW_BUDGET` causes.
    for (let index = 0; index < 50; index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    expect(upstream.hosts).not.toContain(MIRROR_HOST);
    expect(upstream.hosts).toContain(PRIMARY_HOST);
    expect(await ledger.consumed(MODEL)).toBe(1);
  });
});
