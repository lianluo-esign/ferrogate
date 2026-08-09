/**
 * THE TWO OPERATOR KNOBS ON `/v1/responses` CONVERSATION STATE (issue #689,
 * audit blocker 3).
 *
 * `GATEWAY_RESPONSES_STORE` (the three-rung ladder) and
 * `GATEWAY_RESPONSES_RETENTION` (the per-tenant window) were implemented, wired
 * at `src/inference/defaults.ts`, and held by NOTHING: mutating BOTH
 * `responseStoreMode` and `resolveRetentionSeconds` to ignore their input left
 * the whole gateway suite green. That is this repository's named dominant defect
 * mode — a feature that reads as delivered and is not.
 *
 * ## What these tests are careful NOT to do
 *
 * The obvious test is a unit test of the two functions, and it is worthless
 * here: both already had one, and both mutations survived it, because a unit
 * test proves the function computes and says nothing about whether the request
 * path ever consults it. `#764` made the same distinction for the `apps/mcp`
 * mounts an hour before this — the giveaway is that pinning the CALL SITE
 * ("`defaults.ts` calls `responseStoreMode`") repeats the mistake one level up:
 * a call whose result is discarded still passes.
 *
 * So every assertion below is a CLIENT-VISIBLE consequence of the knob's value,
 * reached over the ordinary request path with the var supplied the way a
 * deployment supplies it — through `env`, never through an injected `deps`
 * override that would drive straight past the code being pinned:
 *
 *  - the ladder decides whether a caller's answer is REFUSED, silently not
 *    stored, or stored without being asked for — three different statuses and
 *    three different second turns;
 *  - the retention window decides WHEN a second turn stops working, and it has
 *    to do so per tenant: one tenant's conversation expires while another
 *    tenant's, created in the same second, still continues.
 */
import { describe, expect, it } from "vitest";
import { InMemoryConversationStore } from "../../src/inference/conversation-store.js";
import type { Caller, InferenceDeps } from "../../src/inference/index.js";
import { ALL_ROUTES, errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

/** A minimal Responses answer with one assistant message. */
function responseBody(text: string): Record<string, unknown> {
  return {
    id: "resp_upstream_policy",
    object: "response",
    model: "gpt-4o-mini-2024-07-18",
    output: [
      {
        type: "message",
        role: "assistant",
        status: "completed",
        content: [{ type: "output_text", text }],
      },
    ],
    usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
  };
}

function callerFor(tenantId: string): () => Caller {
  return () => ({ scope: { kind: "tenant", tenantId } });
}

/**
 * A harness whose conversation policy comes from `env`, exactly as the deployed
 * Worker's does: `responseStoreMode` and `responseRetentionSeconds` are left
 * UNSET on `deps`, so `resolveInferenceDeps` must read the two vars itself.
 * Injecting either would prove nothing about the deployed wiring.
 */
function policyHarness(
  store: InMemoryConversationStore,
  tenant: string,
  env: Record<string, unknown>,
  overrides: InferenceDeps = {},
) {
  return harness(
    { conversations: store, caller: callerFor(tenant), ...overrides },
    ALL_ROUTES,
    env,
  );
}

// ---------------------------------------------------------------------------
// GATEWAY_RESPONSES_STORE — the three-rung operator ladder
// ---------------------------------------------------------------------------

describe("GATEWAY_RESPONSES_STORE decides what a caller may persist (#689)", () => {
  it('"off" REFUSES `store: true` — it does not quietly serve and forget', async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hello")));
    try {
      const h = policyHarness(store, "acme", { GATEWAY_RESPONSES_STORE: "off" });
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "remember this",
        store: true,
      });

      // The whole point of the rung: an operator who turned storage OFF gets a
      // caller who KNOWS it is off, not one who believes their state was kept.
      expect(res.status).toBe(403);
      expect((await errorBody(res)).error.code).toBe("response_store_disabled");
      // Refused before dispatch: nothing billed for an answer that cannot be
      // used the way the caller asked.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it('"off" still serves an ordinary request, and stores nothing', async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hello")));
    try {
      const h = policyHarness(store, "acme", { GATEWAY_RESPONSES_STORE: "off" });
      const res = await h.post("/v1/responses", { model: "gpt-4o-mini", input: "hi" });
      expect(res.status).toBe(200);
      expect(res.headers.get("x-ferrogate-response-stored")).toBe("false");

      const id = String(((await res.json()) as Record<string, unknown>).id);
      const read = await h.get(`/v1/responses/${id}`);
      expect(read.status).toBe(404);
    } finally {
      provider.restore();
    }
  });

  it('"opt_in" (the committed default) stores only when ASKED', async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hello")));
    try {
      // The var is absent, which is what `wrangler.toml` ships.
      const h = policyHarness(store, "acme", {});

      const unasked = await h.post("/v1/responses", { model: "gpt-4o-mini", input: "hi" });
      expect(unasked.status).toBe(200);
      expect(unasked.headers.get("x-ferrogate-response-stored")).toBe("false");
      const unaskedId = String(((await unasked.json()) as Record<string, unknown>).id);
      expect((await h.get(`/v1/responses/${unaskedId}`)).status).toBe(404);

      const asked = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "hi",
        store: true,
      });
      expect(asked.headers.get("x-ferrogate-response-stored")).toBe("true");
      const askedId = String(((await asked.json()) as Record<string, unknown>).id);
      expect((await h.get(`/v1/responses/${askedId}`)).status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it('"default_on" stores a turn the caller never asked to store', async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hello")));
    try {
      const h = policyHarness(store, "acme", { GATEWAY_RESPONSES_STORE: "default_on" });
      const res = await h.post("/v1/responses", { model: "gpt-4o-mini", input: "hi" });
      expect(res.status).toBe(200);
      // THE rung. Under `opt_in` this same request stores nothing, so a mode
      // resolver that ignored the var would answer `false` here.
      expect(res.headers.get("x-ferrogate-response-stored")).toBe("true");

      const id = String(((await res.json()) as Record<string, unknown>).id);
      const read = await h.get(`/v1/responses/${id}`);
      expect(read.status).toBe(200);

      // And it is a usable conversation, not merely a row: the second turn
      // replays the first without the caller having opted in at all.
      const second = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "and again",
        previous_response_id: id,
      });
      expect(second.status).toBe(200);
      const replayed = provider.lastRequest().body as Record<string, unknown>;
      expect(replayed.input).toEqual([
        { role: "user", content: "hi" },
        {
          type: "message",
          role: "assistant",
          status: "completed",
          content: [{ type: "output_text", text: "hello" }],
        },
        { role: "user", content: "and again" },
      ]);
    } finally {
      provider.restore();
    }
  });

  it("an UNRECOGNISED value falls back to the default rather than throwing", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hello")));
    try {
      const h = policyHarness(store, "acme", { GATEWAY_RESPONSES_STORE: "ON, obviously" });
      // Fails SAFE: the fallback stores less, not more — an unasked turn is not
      // persisted, and an explicit `store: true` still works.
      const unasked = await h.post("/v1/responses", { model: "gpt-4o-mini", input: "hi" });
      expect(unasked.status).toBe(200);
      expect(unasked.headers.get("x-ferrogate-response-stored")).toBe("false");
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// GATEWAY_RESPONSES_RETENTION — the PER-TENANT window
// ---------------------------------------------------------------------------

describe("GATEWAY_RESPONSES_RETENTION is honoured PER TENANT (#689)", () => {
  /** `{"default": 24, "acme": 1}` — hours, the documented JSON form. */
  const RETENTION = { GATEWAY_RESPONSES_RETENTION: JSON.stringify({ default: 24, acme: 1 }) };

  it("expires the overridden tenant's conversation while the fleet default is still live", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("first")));
    let now = 1_000_000;
    try {
      const acme = policyHarness(store, "acme", RETENTION, { nowUnixSeconds: () => now });
      const globex = policyHarness(store, "globex", RETENTION, { nowUnixSeconds: () => now });

      const acmeFirst = await acme.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "remember",
        store: true,
      });
      const globexFirst = await globex.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "remember",
        store: true,
      });
      expect(acmeFirst.headers.get("x-ferrogate-response-stored")).toBe("true");
      expect(globexFirst.headers.get("x-ferrogate-response-stored")).toBe("true");
      const acmeId = String(((await acmeFirst.json()) as Record<string, unknown>).id);
      const globexId = String(((await globexFirst.json()) as Record<string, unknown>).id);

      // Two hours later: past `acme`'s one-hour override, far short of the
      // 24-hour default `globex` gets.
      now += 2 * 3600;

      const acmeSecond = await acme.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "continue",
        previous_response_id: acmeId,
      });
      // THE assertion. A retention resolver that ignored the tenant id would
      // give `acme` the 24-hour default and this would be a 200.
      expect(acmeSecond.status).toBe(404);
      expect((await errorBody(acmeSecond)).error.code).toBe("previous_response_expired");
      expect((await acme.get(`/v1/responses/${acmeId}`)).status).toBe(404);

      // Stated the other way round too, so "everything expired" cannot pass:
      // the SAME store, the same clock, a different tenant, still continuable.
      const globexSecond = await globex.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "continue",
        previous_response_id: globexId,
      });
      expect(globexSecond.status).toBe(200);
      expect((await globex.get(`/v1/responses/${globexId}`)).status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it("a bare number is the FLEET-WIDE window, and it governs every tenant", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("first")));
    let now = 2_000_000;
    try {
      // Two hours, as the bare form ships it.
      const h = policyHarness(
        store,
        "acme",
        { GATEWAY_RESPONSES_RETENTION: "2" },
        {
          nowUnixSeconds: () => now,
        },
      );
      const first = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "remember",
        store: true,
      });
      const id = String(((await first.json()) as Record<string, unknown>).id);

      // One hour on: inside the window a resolver that ignored the var would
      // NOT have produced (the default is 24h, so this leg alone proves little)
      // — it is the pair with the next assertion that pins the value.
      now += 3600;
      expect((await h.get(`/v1/responses/${id}`)).status).toBe(200);

      // Three hours on: past the configured two, well inside the 24-hour
      // default. A resolver that ignored the var answers 200 here.
      now += 2 * 3600;
      expect((await h.get(`/v1/responses/${id}`)).status).toBe(404);
      const continued = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "continue",
        previous_response_id: id,
      });
      expect(continued.status).toBe(404);
      expect((await errorBody(continued)).error.code).toBe("previous_response_expired");
    } finally {
      provider.restore();
    }
  });

  it("a tenant entry of 0 is a HARD zero — an explicit ask is refused", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("first")));
    try {
      const env = {
        GATEWAY_RESPONSES_RETENTION: JSON.stringify({ default: 24, acme: 0 }),
      };
      const acme = policyHarness(store, "acme", env);
      const refused = await acme.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "remember",
        store: true,
      });
      // Never rounded up to the default — that would be a silent grant of
      // retention to a tenant who negotiated none.
      expect(refused.status).toBe(403);
      expect((await errorBody(refused)).error.code).toBe("response_store_disabled");

      // The same request from a tenant on the default window is served.
      const globex = policyHarness(store, "globex", env);
      const served = await globex.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "remember",
        store: true,
      });
      expect(served.status).toBe(200);
      expect(served.headers.get("x-ferrogate-response-stored")).toBe("true");
    } finally {
      provider.restore();
    }
  });
});
