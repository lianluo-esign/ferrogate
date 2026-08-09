/**
 * `workers-ai` on a Worker with NO `AI` binding — the fail-closed half of
 * issue #673.
 *
 * ## Why this is its own file
 *
 * `handlers.ts::envScopedDeps` memoizes the resolved dependencies per `env`
 * OBJECT in a `WeakMap`, so the dispatcher is built from whatever `env.AI` held
 * at the FIRST request of an isolate and never re-read. Deleting the binding
 * partway through `workers-ai.test.ts` would therefore prove nothing — the
 * already-memoized dispatcher still holds the double. `@cloudflare/vitest-pool-
 * workers` gives each test FILE its own isolate, so a file that never installs a
 * double is the only honest way to exercise the unbound path.
 *
 * ## Why the posture matters
 *
 * The tempting alternative is to let the prepared request fall through to
 * `fetch` — it addresses a real Workers AI REST URL, after all. That would send
 * an UNAUTHENTICATED request to `api.cloudflare.com` and answer the client with
 * whatever Cloudflare says about a missing token, having already left the
 * platform the operator asked to stay on. Failing loudly with a message that
 * names the missing binding is the same posture `bedrock`/`vertex` take when
 * their credential is absent.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const BASE = "https://gw.test";

const PROVIDERS = JSON.stringify([
  {
    name: "cf-ai",
    kind: "workers-ai",
    base_url: "https://api.cloudflare.com/client/v4/accounts/acct_placeholder/ai",
  },
]);

const MODELS = JSON.stringify([
  {
    name: "edge-chat",
    provider: "cf-ai",
    provider_model: "@cf/meta/llama-3.1-8b-instruct",
    capabilities: ["chat", "streaming"],
  },
]);

const KEYS = JSON.stringify([
  { key: "fg_workers_ai_unbound", id: "key_wa_unbound", tenant_id: "tenant_a", scopes: [] },
]);

const ORIGINAL: Record<string, unknown> = {};
const OVERRIDES: Record<string, unknown> = {
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: KEYS,
};

const mutable = env as unknown as Record<string, unknown>;

beforeAll(() => {
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
  // The premise of the file, made explicit rather than assumed: this isolate
  // stands in for a deploy whose `wrangler.toml` carries NO `[ai]` stanza. The
  // pool loads the committed config, which does carry one, so the binding is
  // removed here — before the first request of the isolate, since
  // `envScopedDeps` memoizes the dispatcher on the FIRST request and never
  // re-reads `env.AI` (see the file docblock).
  expect(mutable.AI).toBeDefined();
  ORIGINAL.AI = mutable.AI;
  // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
  delete mutable.AI;
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

describe("a workers-ai route with no AI binding", () => {
  it("answers 503 naming the missing binding, and never leaves the platform", async () => {
    const original = globalThis.fetch;
    let egress = 0;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      egress += 1;
      return await original(input as RequestInfo, init);
    }) as typeof fetch;

    try {
      const res = await SELF.fetch(`${BASE}/v1/chat/completions`, {
        method: "POST",
        headers: {
          authorization: "Bearer fg_workers_ai_unbound",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          model: "edge-chat",
          messages: [{ role: "user", content: "hello" }],
        }),
      });

      // 503, and the message names the missing stanza. Not a bare
      // `502 provider_dispatch_error: provider request failed (transport)` —
      // that is what a THROWN dispatcher error renders as, and it tells an
      // operator nothing actionable. See `unboundBindingResponse`.
      expect(res.status).toBe(503);
      // The gateway relays a non-2xx provider body verbatim on this surface, so
      // what the client sees is the Cloudflare-shaped envelope
      // `unboundBindingResponse` synthesized — which is exactly the point: the
      // message survives to the operator instead of being flattened into
      // `provider request failed (transport)`.
      const body = (await res.json()) as {
        success: boolean;
        errors: { code: number; message: string }[];
      };
      expect(body.success).toBe(false);
      expect(body.errors[0]?.message).toBe(
        "workers-ai provider 'cf-ai' requires the AI binding; declare [ai] in wrangler.toml",
      );
      expect(egress).toBe(0);
    } finally {
      globalThis.fetch = original;
    }
  });
});
