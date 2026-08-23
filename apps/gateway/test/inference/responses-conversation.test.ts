/**
 * `POST /v1/responses` conversation state, end to end (issue #689).
 *
 * The outbound provider `fetch` is intercepted; EVERYTHING else is the real
 * code — Zod validation, the conversation prologue, the chain walk, the upstream
 * body construction, the id rewrite, the store, and `GET`/`DELETE
 * /v1/responses/{id}`.
 *
 * The defect these pin: before this slice `previous_response_id` and `store`
 * were relayed to whichever provider the ladder picked, so a second turn was
 * either refused upstream or — the dangerous case — answered from half a
 * conversation with nothing in the response saying so.
 */
import { describe, expect, it, vi } from "vitest";
import { publishConversationReplayScreener } from "../../src/guardrails/conversation-replay.js";
import { InMemoryConversationStore } from "../../src/inference/conversation-store.js";
import type { StoredResponseTurn } from "../../src/inference/conversation-store.js";
import { MAX_CONVERSATION_TURNS } from "../../src/inference/conversation.js";
import type { Caller, InferenceDeps } from "../../src/inference/index.js";
import { ALL_ROUTES, OPENAI_ROUTE, errorBody, harness, tenantCaller } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

/**
 * The same route, but ASSERTING zero data retention (#681).
 *
 * A ZDR tenant's request is refused at route ELIGIBILITY unless some route
 * declares `zeroDataRetention: true`, so a ZDR test on the default catalogue
 * would go green on a 403 from the wrong gate.
 */
const ZDR_ROUTE = { ...OPENAI_ROUTE, zeroDataRetention: true } as const;

/** A minimal Responses body, with one assistant message in `output`. */
function responseBody(text: string, id = "resp_upstream_1"): Record<string, unknown> {
  return {
    id,
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

/** A caller in `tenant`, optionally under a zero-data-retention policy. */
function callerFor(tenant: string, zeroDataRetention = false): () => Caller {
  if (!zeroDataRetention) return tenantCaller(tenant);
  return () => ({
    scope: { kind: "tenant", tenantId: tenant },
    residency: {
      regionGated: false,
      allowedRegions: [],
      requireZeroDataRetention: true,
      logResidency: "unconstrained",
    },
  });
}

/**
 * A harness sharing ONE conversation store, so two different tenants' routers
 * read the same rows — which is exactly what a shared physical database looks
 * like under `GATEWAY_TENANT_DB_ROUTING = "off"`, and therefore the only setup
 * in which a tenant-fence test can fail.
 */
function conversationHarness(
  store: InMemoryConversationStore,
  tenant: string,
  overrides: InferenceDeps = {},
) {
  return harness({ conversations: store, caller: callerFor(tenant), ...overrides });
}

describe("POST /v1/responses — continuing a conversation (#689)", () => {
  it("replays the whole prior transcript as `input`, and never relays our id upstream", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("Paris.")));
    let firstId: string;
    try {
      const h = conversationHarness(store, "acme");
      const first = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "What is the capital of France?",
        store: true,
      });
      expect(first.status).toBe(200);
      const firstBody = (await first.json()) as Record<string, unknown>;
      firstId = String(firstBody.id);
      // The id is OURS, not the provider's — see `conversation.ts::mintResponseId`.
      expect(firstId).toMatch(/^resp_[0-9a-f]{32}$/);
      expect(firstBody["x-ferrogate-upstream-response-id"]).toBe("resp_upstream_1");
      expect(first.headers.get("x-ferrogate-response-id")).toBe(firstId);
      expect(first.headers.get("x-ferrogate-response-stored")).toBe("true");

      const second = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "And of Germany?",
        previous_response_id: firstId,
      });
      expect(second.status).toBe(200);

      const upstream = provider.lastRequest().body as Record<string, unknown>;
      // THE assertion: turn 1's question, turn 1's answer, then turn 2.
      expect(upstream.input).toEqual([
        { role: "user", content: "What is the capital of France?" },
        {
          type: "message",
          role: "assistant",
          status: "completed",
          content: [{ type: "output_text", text: "Paris." }],
        },
        { role: "user", content: "And of Germany?" },
      ]);
      // Our id space is not the provider's, and FerroGate is the store of
      // record. Its id must not reach the upstream, and provider-side storage is
      // disabled explicitly rather than delegated to an upstream default.
      expect(upstream.previous_response_id).toBeUndefined();
      expect(upstream.store).toBe(false);
    } finally {
      provider.restore();
    }
  });

  it("REFUSES an unknown previous_response_id instead of starting fresh", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hi")));
    try {
      const h = conversationHarness(store, "acme");
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "continue",
        previous_response_id: "resp_does_not_exist",
      });
      expect(res.status).toBe(404);
      expect((await errorBody(res)).error.code).toBe("previous_response_not_found");
      // The refusal happens BEFORE dispatch: no provider call, nothing billed.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("fails closed when a foreign turn needs screening but no screener is available", async () => {
    const store = new InMemoryConversationStore();
    await store.append(
      { tenantId: "acme", projectId: "" },
      {
        responseId: "resp_foreign_unscreened",
        previousResponseId: null,
        screeningApiKeyId: "key_other",
        turnIndex: 0,
        model: "gpt-4o-mini",
        input: [{ role: "user", content: "stored question" }],
        response: responseBody("stored answer", "resp_foreign_unscreened"),
        createdAtUnix: 0,
        expiresAtUnix: 4_000_000_000,
      },
    );
    const provider = interceptProviderFetch(() => providerJson(responseBody("must not dispatch")));
    try {
      const h = harness(
        { conversations: store, caller: callerFor("acme") },
        ALL_ROUTES,
        {},
        { conversationReplayScreener: false },
      );
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "continue",
        previous_response_id: "resp_foreign_unscreened",
      });

      expect(res.status).toBe(503);
      expect((await errorBody(res)).error.code).toBe("guardrail_screening_unavailable");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("re-screens a turn from another API key even when both keys select the same policies", async () => {
    const store = new InMemoryConversationStore();
    const screen = vi.fn(async ({ response }) => ({ ok: true as const, response }));
    const provider = interceptProviderFetch(() => providerJson(responseBody("same answer")));
    try {
      const h = harness(
        {
          conversations: store,
          caller: (request) => ({
            scope: { kind: "tenant", tenantId: "acme" },
            apiKeyId:
              request.headers.get("authorization") === "Bearer credential-a" ? "key_a" : "key_b",
          }),
        },
        ALL_ROUTES,
        {},
        { conversationReplayScreener: false },
      );
      const post = async (credential: string, body: unknown): Promise<Response> => {
        const request = new Request("https://gw.test/v1/responses", {
          method: "POST",
          headers: {
            authorization: `Bearer ${credential}`,
            "content-type": "application/json",
          },
          body: JSON.stringify(body),
        });
        publishConversationReplayScreener(request, {
          policyRevisionMarker: "[]",
          screen,
        });
        return await h.router.request(request);
      };
      const first = await post("credential-a", {
        model: "gpt-4o-mini",
        input: "first",
        store: true,
      });
      expect(first.status).toBe(200);
      const firstId = String(((await first.json()) as Record<string, unknown>).id);
      const stored = await store.chain({ tenantId: "acme", projectId: "" }, firstId, 0);
      expect(stored.ok && stored.turns[0]?.screeningApiKeyId).toBe("key_a");
      expect(stored.ok && stored.turns[0]?.screeningPolicyRevision).toBe("[]");

      const second = await post("credential-b", {
        model: "gpt-4o-mini",
        input: "continue",
        previous_response_id: firstId,
      });

      expect(second.status).toBe(200);
      expect(screen).toHaveBeenCalledOnce();
    } finally {
      provider.restore();
    }
  });

  it("REFUSES an expired previous_response_id, distinguishably from an unknown one", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hi")));
    try {
      // One second of retention, and a clock that has already moved past it.
      let now = 1_000;
      const h = harness({
        conversations: store,
        caller: callerFor("acme"),
        nowUnixSeconds: () => now,
        responseRetentionSeconds: () => 1,
      });
      const first = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "hi",
        store: true,
      });
      const id = String(((await first.json()) as Record<string, unknown>).id);

      now = 1_100;
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "again",
        previous_response_id: id,
      });
      expect(res.status).toBe(404);
      expect((await errorBody(res)).error.code).toBe("previous_response_expired");
    } finally {
      provider.restore();
    }
  });

  it("forks rather than races: two continuations of one parent both succeed", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("root")));
    try {
      const h = conversationHarness(store, "acme");
      const root = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "root question",
        store: true,
      });
      const rootId = String(((await root.json()) as Record<string, unknown>).id);

      const [left, right] = await Promise.all([
        h.post("/v1/responses", {
          model: "gpt-4o-mini",
          input: "branch A",
          previous_response_id: rootId,
          store: true,
        }),
        h.post("/v1/responses", {
          model: "gpt-4o-mini",
          input: "branch B",
          previous_response_id: rootId,
          store: true,
        }),
      ]);
      expect(left.status).toBe(200);
      expect(right.status).toBe(200);
      const leftId = String(((await left.json()) as Record<string, unknown>).id);
      const rightId = String(((await right.json()) as Record<string, unknown>).id);
      expect(leftId).not.toBe(rightId);

      // Each branch replays ONLY its own history: three rows, two chains of two.
      const owner = { tenantId: "acme", projectId: "" };
      const leftChain = await store.chain(owner, leftId, 0);
      const rightChain = await store.chain(owner, rightId, 0);
      expect(leftChain.ok && leftChain.turns.map((t) => t.responseId)).toEqual([rootId, leftId]);
      expect(rightChain.ok && rightChain.turns.map((t) => t.responseId)).toEqual([rootId, rightId]);
      expect(store.size).toBe(3);
    } finally {
      provider.restore();
    }
  });

  it("bounds the chain and REFUSES at the cap rather than truncating context", async () => {
    const store = new InMemoryConversationStore();
    const owner = { tenantId: "acme", projectId: "" };
    // Seed a chain that is already at the cap, straight into the store: the
    // point under test is the bound, not the hundred provider calls.
    let previous: string | null = null;
    for (let index = 0; index < MAX_CONVERSATION_TURNS; index += 1) {
      const turn: StoredResponseTurn = {
        responseId: `resp_seed_${index}`,
        previousResponseId: previous,
        turnIndex: index,
        model: "gpt-4o-mini",
        input: [{ role: "user", content: `turn ${index}` }],
        response: responseBody(`answer ${index}`, `resp_seed_${index}`),
        createdAtUnix: 0,
        expiresAtUnix: 4_000_000_000,
      };
      await store.append(owner, turn);
      previous = turn.responseId;
    }

    const provider = interceptProviderFetch(() => providerJson(responseBody("nope")));
    try {
      const h = conversationHarness(store, "acme");
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "one more",
        previous_response_id: `resp_seed_${MAX_CONVERSATION_TURNS - 1}`,
      });
      expect(res.status).toBe(409);
      expect((await errorBody(res)).error.code).toBe("conversation_chain_too_long");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});

describe("POST /v1/responses — the tenant fence (#689)", () => {
  it("does NOT resolve another tenant's previous_response_id", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("secret")));
    try {
      const acme = conversationHarness(store, "acme");
      const first = await acme.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "acme's confidential question",
        store: true,
      });
      const acmeId = String(((await first.json()) as Record<string, unknown>).id);

      // A DIFFERENT tenant presents acme's id — the whole point being that
      // `previous_response_id` is caller-supplied and therefore forgeable.
      const other = conversationHarness(store, "globex");
      const res = await other.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "what were we discussing?",
        previous_response_id: acmeId,
      });

      expect(res.status).toBe(404);
      expect((await errorBody(res)).error.code).toBe("previous_response_not_found");
      // Nothing of acme's reached a provider on globex's behalf.
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });

  it("does NOT let another tenant GET or DELETE the stored response", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("secret")));
    try {
      const acme = conversationHarness(store, "acme");
      const first = await acme.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "acme's confidential question",
        store: true,
      });
      const acmeId = String(((await first.json()) as Record<string, unknown>).id);

      const other = conversationHarness(store, "globex");
      const read = await other.get(`/v1/responses/${acmeId}`);
      expect(read.status).toBe(404);
      const removed = await other.router.request(`https://gw.test/v1/responses/${acmeId}`, {
        method: "DELETE",
      });
      expect(removed.status).toBe(404);
      // The row is still acme's, untouched by the failed cross-tenant DELETE.
      expect(store.size).toBe(1);
      expect((await acme.get(`/v1/responses/${acmeId}`)).status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it("refuses conversation state to a credential that is not confined to a tenant", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hi")));
    try {
      // The default harness caller is a PLATFORM OPERATOR — no tenant, so no
      // conversation state, exactly as `tenancy/middleware.ts` decides for the
      // per-tenant database.
      const h = harness({ conversations: store });
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "hi",
        store: true,
      });
      expect(res.status).toBe(403);
      expect((await errorBody(res)).error.code).toBe("conversation_store_unscoped");
      expect(store.size).toBe(0);

      // ...and an ORDINARY request from the same credential is untouched.
      const plain = await h.post("/v1/responses", { model: "gpt-4o-mini", input: "hi" });
      expect(plain.status).toBe(200);
    } finally {
      provider.restore();
    }
  });
});

describe("POST /v1/responses — retention policy (#681 × #689)", () => {
  it("REFUSES store: true for a zero-data-retention tenant, and stores nothing", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hi")));
    try {
      const h = harness({ conversations: store, caller: callerFor("zdr-tenant", true) });
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "regulated prompt",
        store: true,
      });
      expect(res.status).toBe(403);
      expect((await errorBody(res)).error.code).toBe("zero_data_retention_conflict");
      expect(store.size).toBe(0);
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("serves an ordinary ZDR request and persists nothing", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hi")));
    try {
      // A route that ASSERTS zero data retention, or #681's own route
      // eligibility would refuse this request before the store is consulted —
      // which would make the test pass for the wrong reason.
      const h = harness({ conversations: store, caller: callerFor("zdr-tenant", true) }, [
        { ...ZDR_ROUTE },
      ]);
      const res = await h.post("/v1/responses", { model: "gpt-4o-mini", input: "regulated" });
      expect(res.status).toBe(200);
      expect(res.headers.get("x-ferrogate-response-stored")).toBe("false");
      expect(store.size).toBe(0);
    } finally {
      provider.restore();
    }
  });

  it("does not persist by default (`opt_in`), and does under `default_on`", async () => {
    const optIn = new InMemoryConversationStore();
    const alwaysOn = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hi")));
    try {
      const a = conversationHarness(optIn, "acme");
      await a.post("/v1/responses", { model: "gpt-4o-mini", input: "hi" });
      expect(optIn.size).toBe(0);

      const b = harness({
        conversations: alwaysOn,
        caller: callerFor("acme"),
        responseStoreMode: "default_on",
      });
      await b.post("/v1/responses", { model: "gpt-4o-mini", input: "hi" });
      expect(alwaysOn.size).toBe(1);
    } finally {
      provider.restore();
    }
  });

  it("REFUSES store: true when the operator has switched persistence off", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("hi")));
    try {
      const h = harness({
        conversations: store,
        caller: callerFor("acme"),
        responseStoreMode: "off",
      });
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "hi",
        store: true,
      });
      expect(res.status).toBe(403);
      expect((await errorBody(res)).error.code).toBe("response_store_disabled");
    } finally {
      provider.restore();
    }
  });

  it("REFUSES store: true on a deployment with no durable store bound", async () => {
    const provider = interceptProviderFetch(() => providerJson(responseBody("hi")));
    try {
      // No `conversations` injected and no `DB` binding under `app.request` ⇒
      // `NO_CONVERSATION_STORE`.
      const h = harness({ caller: callerFor("acme") });
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "hi",
        store: true,
      });
      expect(res.status).toBe(503);
      expect((await errorBody(res)).error.code).toBe("response_store_disabled");
    } finally {
      provider.restore();
    }
  });
});

describe("GET/DELETE /v1/responses/{id} (#689)", () => {
  it("returns the stored body, then deletes it, then 404s", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("Paris.")));
    try {
      const h = conversationHarness(store, "acme");
      const created = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "capital of France?",
        store: true,
      });
      const body = (await created.json()) as Record<string, unknown>;
      const id = String(body.id);

      const read = await h.get(`/v1/responses/${id}`);
      expect(read.status).toBe(200);
      expect(await read.json()).toEqual(body);

      const deleted = await h.router.request(`https://gw.test/v1/responses/${id}`, {
        method: "DELETE",
      });
      expect(deleted.status).toBe(200);
      expect(await deleted.json()).toEqual({ id, object: "response", deleted: true });

      expect((await h.get(`/v1/responses/${id}`)).status).toBe(404);
    } finally {
      provider.restore();
    }
  });

  it("REFUSES a continuation whose ancestor was deleted, rather than shortening it", async () => {
    const store = new InMemoryConversationStore();
    const provider = interceptProviderFetch(() => providerJson(responseBody("answer")));
    try {
      const h = conversationHarness(store, "acme");
      const root = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "turn one",
        store: true,
      });
      const rootId = String(((await root.json()) as Record<string, unknown>).id);
      const child = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "turn two",
        previous_response_id: rootId,
        store: true,
      });
      const childId = String(((await child.json()) as Record<string, unknown>).id);

      await h.router.request(`https://gw.test/v1/responses/${rootId}`, { method: "DELETE" });

      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "turn three",
        previous_response_id: childId,
      });
      expect(res.status).toBe(404);
      expect((await errorBody(res)).error.code).toBe("conversation_chain_broken");
    } finally {
      provider.restore();
    }
  });
});

describe("POST /v1/responses — streaming turns (#689)", () => {
  it("carries the conversation id in the headers and stores the assembled turn", async () => {
    const store = new InMemoryConversationStore();
    // The UPSTREAM's own frames, in the chat dialect an OpenAI-compatible
    // provider streams. `ResponsesStreamNormalizer` turns them into the
    // `response.*` sequence the client sees, and the capture reads THAT — which
    // is the property under test: the stored transcript is the one the caller
    // was served, not the one the provider happened to send.
    const sse =
      'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n' +
      'data: {"choices":[{"delta":{"content":" world"}}]}\n\n' +
      'data: {"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}\n\n' +
      "data: [DONE]\n\n";
    const provider = interceptProviderFetch(
      () => new Response(sse, { headers: { "content-type": "text/event-stream" } }),
    );
    try {
      const h = conversationHarness(store, "acme");
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "say hello",
        stream: true,
        store: true,
      });
      expect(res.status).toBe(200);
      const id = res.headers.get("x-ferrogate-response-id");
      expect(id).toMatch(/^resp_[0-9a-f]{32}$/);
      // Drain the stream so the tap's flush runs.
      expect(await res.text()).toContain("response.output_text.delta");

      const stored = await store.get({ tenantId: "acme", projectId: "" }, String(id), 0);
      expect(stored).not.toBeNull();
      expect(stored?.response.output).toEqual([
        {
          type: "message",
          role: "assistant",
          status: "completed",
          content: [{ type: "output_text", text: "Hello world" }],
        },
      ]);
    } finally {
      provider.restore();
    }
  });
});
