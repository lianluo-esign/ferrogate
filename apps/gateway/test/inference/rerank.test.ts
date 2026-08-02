/**
 * `POST /v1/rerank` — the ninth inference operation (issue #676).
 *
 * ## Why the deployed Worker, and not a handler unit test alone
 *
 * The premise of the issue is a GOVERNANCE hole: a team that needs reranking
 * wires a second vendor around the gateway, and that spend leaves FerroGate's
 * view. Closing it means the operation has to be reachable on the SAME path a
 * production request takes — contract row, `contractAuth` guard, `rateLimit()`
 * middleware, metering sink — not merely present in a router that a test
 * constructs by hand. So the guard and the transport legs below go through
 * `SELF.fetch` → `src/worker.ts` → `src/index.ts` → `createGatewayApp`, against
 * the committed `wrangler.toml`, exactly as `test/inference/workers-ai.test.ts`
 * does for the ninth provider family it depends on.
 *
 * The `env.AI` double is the same device and for the same reason: the pool DOES
 * bind the real thing (the committed `[ai]` stanza), but calling `.run()` on it
 * offline throws `Binding AI needs to be run remotely`. What the double cannot
 * prove is Cloudflare's own reranker wire behaviour; that is stated in the PR
 * body rather than papered over.
 *
 * ## Why the estimate/metering legs use the inner router instead
 *
 * Metering on the deployed Worker lands in D1 through `MeteringUsageSink`, and
 * asserting a token count there would be asserting the billing writer, not this
 * operation. `harness()` supplies the shipped `InMemoryUsageSink` on the same
 * `UsageSink` port the deployed sink implements, and `setInferenceRequestScope`
 * is the SAME seam `inference/route-module.ts` publishes the TPM governor
 * through in production — so "metered" and "rate-limited" are pinned against
 * the real ports rather than a mock of them.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  setInferenceRequestScope,
  type PhysicalRoute,
  type TokenAdmissionHandle,
  type TokenGovernor,
} from "../../src/inference/index.js";
import { INFERENCE_OPERATION_IDS } from "../../src/routes/index.js";
import { ALL_ROUTES, errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const BASE = "https://gw.test";

// ---------------------------------------------------------------------------
// The deployed Worker: contract row, guard, and the Workers AI transport
// ---------------------------------------------------------------------------

const PROVIDERS = JSON.stringify([
  {
    name: "cf-ai",
    kind: "workers-ai",
    base_url: "https://api.cloudflare.com/client/v4/accounts/acct_placeholder/ai",
  },
]);

const MODELS = JSON.stringify([
  {
    name: "edge-rerank",
    provider: "cf-ai",
    provider_model: "@cf/baai/bge-reranker-base",
    capabilities: ["rerank"],
  },
  // A CHAT model, declared with chat capabilities only. It exists so the
  // eligibility gate has something to refuse: a reranking request must never be
  // quietly served by a text-generation model, which would answer prose where
  // the caller asked for scores.
  {
    name: "edge-chat",
    provider: "cf-ai",
    provider_model: "@cf/meta/llama-3.1-8b-instruct",
    capabilities: ["chat", "streaming"],
  },
]);

const KEYS = JSON.stringify([
  // Empty scope set: every data-plane scope, no admin one.
  { key: "fg_rerank", id: "key_rerank", tenant_id: "tenant_a", scopes: [] },
  // Authenticated but holding an unrelated scope — must be 403 `scope_denied`.
  { key: "fg_rerank_readonly", id: "key_rr", tenant_id: "tenant_a", scopes: ["skills.read"] },
]);

interface RecordedRun {
  readonly model: string;
  readonly input: Record<string, unknown>;
}

/** The recording double for `env.AI` (the slice the dispatcher uses). */
class RecordingAi {
  readonly runs: RecordedRun[] = [];
  #next: (model: string, input: Record<string, unknown>) => unknown = () => ({});

  answerWith(fn: (model: string, input: Record<string, unknown>) => unknown): void {
    this.#next = fn;
  }

  async run(model: string, input: Record<string, unknown>): Promise<unknown> {
    this.runs.push({ model, input });
    return this.#next(model, input);
  }
}

const ai = new RecordingAi();

const ORIGINAL: Record<string, unknown> = {};
const OVERRIDES: Record<string, unknown> = {
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: KEYS,
  AI: ai,
};

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

/** Count every outbound `fetch`, so "the binding served it" is provable. */
function countEgress(): { calls: () => number; restore: () => void } {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls += 1;
    return await original(input as RequestInfo, init);
  }) as typeof fetch;
  return { calls: () => calls, restore: () => void (globalThis.fetch = original) };
}

let egress: ReturnType<typeof countEgress> | undefined;

afterEach(() => {
  egress?.restore();
  egress = undefined;
});

function rerank(body: unknown, key = "fg_rerank"): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/rerank`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /v1/rerank is a guarded contract operation", () => {
  it("is registered as an inference operation", () => {
    expect([...INFERENCE_OPERATION_IDS]).toContain("createRerank");
  });

  it("401s an unauthenticated caller — never a free reranking oracle", async () => {
    const res = await SELF.fetch(`${BASE}/v1/rerank`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "edge-rerank", query: "q", documents: ["a"] }),
    });
    expect(res.status).toBe(401);
    expect((await errorBody(res)).error.code).toBe("missing_api_key");
  });

  it("403s a key that holds an unrelated scope", async () => {
    const res = await rerank(
      { model: "edge-rerank", query: "q", documents: ["a"] },
      "fg_rerank_readonly",
    );
    expect(res.status).toBe(403);
    expect((await errorBody(res)).error.code).toBe("scope_denied");
  });

  it("400s a body with no documents to rank", async () => {
    const res = await rerank({ model: "edge-rerank", query: "q", documents: [] });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("invalid_request");
  });
});

describe("POST /v1/rerank is served by Workers AI reranker models", () => {
  it("runs the reranker on the AI binding and answers ranked scores, with no egress", async () => {
    egress = countEgress();
    // `@cf/baai/bge-reranker-base`'s native answer: `{ response: [{ id, score }] }`,
    // where `id` is the INDEX of the context in the request.
    ai.answerWith(() => ({
      response: [
        { id: 2, score: 0.97 },
        { id: 0, score: 0.42 },
        { id: 1, score: 0.01 },
      ],
    }));

    const res = await rerank({
      model: "edge-rerank",
      query: "how do I rotate a key",
      documents: ["billing docs", "quota docs", "key rotation guide"],
      top_n: 3,
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      object: "list",
      model: "edge-rerank",
      results: [
        { index: 2, relevance_score: 0.97 },
        { index: 0, relevance_score: 0.42 },
        { index: 1, relevance_score: 0.01 },
      ],
    });

    // The PHYSICAL model reached the binding, in the reranker's native input
    // grammar — `contexts`, not OpenAI's `input`, and `top_k`, not `top_n`.
    expect(ai.runs.at(-1)?.model).toBe("@cf/baai/bge-reranker-base");
    expect(ai.runs.at(-1)?.input).toEqual({
      query: "how do I rotate a key",
      contexts: [{ text: "billing docs" }, { text: "quota docs" }, { text: "key rotation guide" }],
      top_k: 3,
    });
    expect(egress.calls()).toBe(0);
  });

  it("echoes the ranked documents when the caller asks for them", async () => {
    egress = countEgress();
    ai.answerWith(() => ({ response: [{ id: 1, score: 0.9 }] }));

    const res = await rerank({
      model: "edge-rerank",
      query: "q",
      documents: ["alpha", "beta"],
      top_n: 1,
      return_documents: true,
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      object: "list",
      model: "edge-rerank",
      results: [{ index: 1, relevance_score: 0.9, document: { text: "beta" } }],
    });
    expect(egress.calls()).toBe(0);
  });

  it("refuses to rerank on a model that declares no rerank capability", async () => {
    egress = countEgress();
    const before = ai.runs.length;

    const res = await rerank({ model: "edge-chat", query: "q", documents: ["a", "b"] });

    expect(res.status).toBe(400);
    // The chat model was never invoked: a text-generation model would answer
    // prose where the caller asked for scores.
    expect(ai.runs.length).toBe(before);
    expect(egress.calls()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Metering and rate limiting, on the shipped ports
// ---------------------------------------------------------------------------

/** A `workers-ai` rerank route reached over the REST surface (no binding here). */
const RERANK_ROUTE: PhysicalRoute = {
  logicalModel: "rerank-model",
  provider: "cf-ai",
  providerModel: "@cf/baai/bge-reranker-base",
  providerKind: "workers-ai",
  baseUrl: "https://api.cloudflare.com/client/v4/accounts/acct_placeholder/ai",
  enabled: true,
  capabilities: ["rerank"],
};

const ROUTES: readonly PhysicalRoute[] = [...ALL_ROUTES, RERANK_ROUTE];

/** Cloudflare's REST envelope around the reranker's native answer. */
const REST_ANSWER = {
  result: { response: [{ id: 0, score: 0.75 }] },
  success: true,
  errors: [],
  messages: [],
};

describe("POST /v1/rerank is metered", () => {
  it("records a usage row attributing the call to the served route", async () => {
    const provider = interceptProviderFetch(() => providerJson(REST_ANSWER));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1/rerank", {
        model: "rerank-model",
        query: "hello",
        documents: ["world"],
      });

      expect(res.status).toBe(200);
      // The REST leg addresses the same run surface the binding short-circuits.
      expect(provider.lastRequest().url).toBe(
        "https://api.cloudflare.com/client/v4/accounts/acct_placeholder/ai/run/@cf/baai/bge-reranker-base",
      );
      expect(h.usage.last).toMatchObject({
        route: "rerank",
        logicalModel: "rerank-model",
        provider: "cf-ai",
        providerModel: "@cf/baai/bge-reranker-base",
        stream: false,
        status: 200,
      });
    } finally {
      provider.restore();
    }
  });
});

describe("POST /v1/rerank is rate-limited", () => {
  /** Records every TPM admission the inference path asks for. */
  function spyGovernor(): { readonly admitted: number[]; readonly governor: TokenGovernor } {
    const admitted: number[] = [];
    return {
      admitted,
      governor: {
        admit: async (estimatedTokens: number): Promise<TokenAdmissionHandle | null> => {
          admitted.push(estimatedTokens);
          return null;
        },
        settle: async (): Promise<void> => {},
      },
    };
  }

  function post(body: unknown, governor: TokenGovernor): Request {
    const request = new Request(`${BASE}/v1/rerank`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    setInferenceRequestScope(request, { tokens: governor });
    return request;
  }

  it("reserves the query AND every document against the TPM window", async () => {
    const spy = spyGovernor();
    const provider = interceptProviderFetch(() => providerJson(REST_ANSWER));
    try {
      const h = harness({}, ROUTES);
      const res = await h.router.fetch(
        post(
          {
            model: "rerank-model",
            query: "0123456789012345678901234567890123456789",
            documents: ["0123456789012345678901234567890123456789"],
          },
          spy.governor,
        ),
      );
      expect(res.status).toBe(200);
      // 40 chars of query + 40 chars of document at the tree's `chars/4`
      // estimator. A reservation that counted only the query would be 10 — and
      // the documents are the bulk of a reranking request, so counting them is
      // the difference between a gate and a formality.
      expect(spy.admitted).toEqual([20]);
    } finally {
      provider.restore();
    }
  });

  it("refuses with the governor's status when the window is exhausted", async () => {
    const refusing: TokenGovernor = {
      admit: async () => ({
        status: 429,
        code: "tpm_limit_exceeded",
        message: "tokens-per-minute limit exceeded",
      }),
      settle: async (): Promise<void> => {},
    };
    const provider = interceptProviderFetch(() => providerJson(REST_ANSWER));
    try {
      const h = harness({}, ROUTES);
      const res = await h.router.fetch(
        post({ model: "rerank-model", query: "q", documents: ["a"] }, refusing),
      );
      expect(res.status).toBe(429);
      expect((await errorBody(res)).error.code).toBe("tpm_limit_exceeded");
      // Refused BEFORE the upstream was dialled — a rate limit that pays for
      // the call it is refusing limits nothing.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});
