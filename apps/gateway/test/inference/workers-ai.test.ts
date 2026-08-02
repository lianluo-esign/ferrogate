/**
 * The NINTH provider family — Workers AI — driven through the **deployed
 * Worker**, not through a registry unit test.
 *
 * ## Why `SELF.fetch` and nothing smaller
 *
 * `packages/providers/src/registry.ts` carries a standing warning that the
 * deployed data plane never goes through `ProviderAdapterRegistry`: it builds
 * adapters one at a time via `packageProviderAdapter()` in
 * `apps/gateway/src/inference/adapters.ts`, which is why the Cloudflare
 * AI-Gateway routing on that class is dead code in production. A ninth family
 * registered only on that class would be equally unreachable, and a unit test
 * against it would be green while every real request answered
 * `model_not_found`. So every assertion below goes through `SELF.fetch` →
 * `src/worker.ts` → `src/index.ts` → `createGatewayApp`, against the real
 * `wrangler.toml`, exactly as a production request does.
 *
 * ## Why the `AI` binding is installed on `env` here
 *
 * `env` from `cloudflare:test` IS the object the Worker sees (the same trick
 * `test/cache/deployed.test.ts` uses for its vars), so a recording double can
 * be put on `env.AI` before the first request and the deployed composition root
 * picks it up through `dispatcherFromEnv`. A REAL `[ai]` binding cannot be
 * exercised offline — miniflare proxies it to the live Cloudflare API — so a
 * double is the only way to prove the wiring without a network round trip and
 * an account. What the double CANNOT prove is Workers AI's own wire behaviour;
 * that is stated in the PR body rather than papered over.
 *
 * ## The property under test
 *
 * The family must be indistinguishable from the other eight at the handler
 * boundary: an OpenAI-shaped buffered completion, an OpenAI-shaped SSE stream
 * ending in `[DONE]` with a usage frame the meter can scrape, and an OpenAI
 * embeddings list — while `globalThis.fetch` is NEVER called, because the whole
 * point of the family is that the inference never leaves Cloudflare.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
declare global {
  interface ImportMeta {
    glob(pattern: string, options: object): Record<string, string>;
  }
}

/**
 * Vite inlines both files at build time — the only way a workerd test with no
 * filesystem can read a config at all, and the same mechanism
 * `test/env-var-drift.test.ts` uses. See the "derived deploy config" describe at
 * the bottom for why the second file exists.
 */
const TOML = import.meta.glob("../../wrangler{,.vitest}.toml", {
  query: "?raw",
  import: "default",
  eager: true,
});

function toml(suffix: string): string {
  const entry = Object.entries(TOML).find(([path]) => path.endsWith(suffix));
  if (entry === undefined || typeof entry[1] !== "string" || entry[1].length === 0) {
    throw new Error(`expected exactly one non-empty ${suffix}, found ${Object.keys(TOML)}`);
  }
  return entry[1];
}

const COMMITTED_WRANGLER_TOML = toml("/wrangler.toml");
const POOL_WRANGLER_TOML = toml("/wrangler.vitest.toml");

const BASE = "https://gw.test";

/**
 * A `workers-ai` provider row. `base_url` is the REAL Workers AI REST root for
 * an account (`.../accounts/<id>/ai`) — the prepared request is a genuine REST
 * request that the binding short-circuits, not a sentinel URL.
 */
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
  {
    name: "edge-embed",
    provider: "cf-ai",
    provider_model: "@cf/baai/bge-base-en-v1.5",
    capabilities: ["embeddings"],
  },
]);

/** A durable key with an EMPTY scope set: every data-plane scope, no admin one. */
const KEYS = JSON.stringify([
  { key: "fg_workers_ai", id: "key_workers_ai", tenant_id: "tenant_a", scopes: [] },
]);

interface RecordedRun {
  readonly model: string;
  readonly input: Record<string, unknown>;
}

/**
 * The recording double for `env.AI`. Structurally the slice of the binding the
 * dispatcher uses (`run(model, input, options?)`), which is the same slice
 * `@ferrogate/guardrails`' `WorkersAiBinding` declares.
 */
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

/**
 * Count every outbound `fetch`. The family's whole value proposition is that
 * inference does not leave Cloudflare, so "the binding was used" is only proved
 * together with "the network was not".
 */
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

function post(path: string, body: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      authorization: "Bearer fg_workers_ai",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

describe("workers-ai is reachable on the deployed data plane", () => {
  it("serves a buffered chat completion off the AI binding, with no egress", async () => {
    egress = countEgress();
    ai.answerWith(() => ({
      response: "hi from the edge",
      usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
    }));

    const res = await post("/v1/chat/completions", {
      model: "edge-chat",
      messages: [{ role: "user", content: "hello" }],
      stream: false,
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      object: string;
      model: string;
      choices: { message: { role: string; content: string }; finish_reason: string }[];
      usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
    };
    expect(body.object).toBe("chat.completion");
    expect(body.choices[0]?.message).toEqual({ role: "assistant", content: "hi from the edge" });
    expect(body.choices[0]?.finish_reason).toBe("stop");
    // The usage-extraction contract: the same `usage` object every other family
    // reports, so `usageProviderKindFor`'s OpenAI extractor meters this call.
    expect(body.usage).toEqual({ prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 });

    // The PHYSICAL model reached the binding, never the logical name.
    expect(ai.runs.at(-1)?.model).toBe("@cf/meta/llama-3.1-8b-instruct");
    expect(ai.runs.at(-1)?.input).toMatchObject({
      messages: [{ role: "user", content: "hello" }],
    });
    expect(egress.calls()).toBe(0);
  });

  it("streams OpenAI chat.completion.chunk frames ending in [DONE], with a usage frame", async () => {
    egress = countEgress();
    ai.answerWith(
      () =>
        new ReadableStream<Uint8Array>({
          start(controller) {
            const encoder = new TextEncoder();
            controller.enqueue(encoder.encode('data: {"response":"hi "}\n\n'));
            controller.enqueue(
              encoder.encode(
                'data: {"response":"there","usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}\n\n',
              ),
            );
            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            controller.close();
          },
        }),
    );

    const res = await post("/v1/chat/completions", {
      model: "edge-chat",
      messages: [{ role: "user", content: "hello" }],
      stream: true,
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");
    const text = await res.text();

    // The binding was asked to stream — not buffered and chopped up afterwards.
    expect(ai.runs.at(-1)?.input).toMatchObject({ stream: true });

    const frames = text
      .split("\n\n")
      .filter((frame) => frame.startsWith("data: "))
      .map((frame) => frame.slice("data: ".length));
    expect(frames.at(-1)).toBe("[DONE]");

    const chunks = frames
      .filter((frame) => frame !== "[DONE]")
      .map((frame) => JSON.parse(frame) as Record<string, unknown>);
    expect(chunks.every((chunk) => chunk["object"] === "chat.completion.chunk")).toBe(true);

    const content = chunks
      .flatMap((chunk) => (chunk["choices"] as { delta?: { content?: string } }[]) ?? [])
      .map((choice) => choice.delta?.content ?? "")
      .join("");
    expect(content).toBe("hi there");

    // The scrapable usage frame — without it the meter falls back to the
    // 512-token estimate, which is the documented token-budget bypass.
    const usageFrame = chunks.find((chunk) => chunk["usage"] !== undefined);
    expect(usageFrame?.["usage"]).toEqual({
      prompt_tokens: 4,
      completion_tokens: 2,
      total_tokens: 6,
    });
    expect(egress.calls()).toBe(0);
  });

  it("serves embeddings off the binding, translated to the OpenAI list shape", async () => {
    egress = countEgress();
    ai.answerWith(() => ({
      shape: [2, 3],
      data: [
        [0.1, 0.2, 0.3],
        [0.4, 0.5, 0.6],
      ],
    }));

    const res = await post("/v1/embeddings", {
      model: "edge-embed",
      input: ["alpha", "beta"],
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      object: string;
      model: string;
      data: { object: string; index: number; embedding: number[] }[];
    };
    expect(body.object).toBe("list");
    expect(body.model).toBe("edge-embed");
    expect(body.data).toEqual([
      { object: "embedding", index: 0, embedding: [0.1, 0.2, 0.3] },
      { object: "embedding", index: 1, embedding: [0.4, 0.5, 0.6] },
    ]);

    expect(ai.runs.at(-1)?.model).toBe("@cf/baai/bge-base-en-v1.5");
    expect(ai.runs.at(-1)?.input).toEqual({ text: ["alpha", "beta"] });
    expect(egress.calls()).toBe(0);
  });

  it("lists the workers-ai models in the deployed catalog", async () => {
    const res = await SELF.fetch(`${BASE}/v1/models`, {
      headers: { authorization: "Bearer fg_workers_ai" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { id: string; owned_by?: string }[] };
    expect(body.data.map((model) => model.id).sort()).toEqual(["edge-chat", "edge-embed"]);
  });
});

/**
 * THE DERIVED DEPLOY CONFIG — the one place this slice weakens a guarantee, so
 * it is fenced here rather than left implicit.
 *
 * `wrangler.toml` declares `[ai] binding = "AI"` because the deployed Worker
 * reads it. `@cloudflare/vitest-pool-workers` cannot load that stanza offline
 * (see `vitest.config.ts`), so the POOL is pointed at a generated copy with the
 * stanza removed. That substitution is safe only for as long as it removes
 * exactly the `[ai]` stanza and nothing else — otherwise every other config gate
 * in this suite would be asserting against the committed file while the Worker
 * under test booted from a different one.
 */
describe("the pool's derived wrangler config differs from the committed one only in [ai]", () => {
  const stanza = (toml: string, header: string): string[] => {
    const out: string[] = [];
    let inside = false;
    for (const line of toml.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed === header) {
        inside = true;
        continue;
      }
      if (inside && trimmed.startsWith("[")) break;
      if (inside) out.push(trimmed);
    }
    return out.filter((line) => line.length > 0 && !line.startsWith("#"));
  };

  it("the committed config declares the binding and the derived one does not", () => {
    expect(stanza(COMMITTED_WRANGLER_TOML, "[ai]")).toContain('binding = "AI"');
    expect(stanza(POOL_WRANGLER_TOML, "[ai]")).toEqual([]);
    expect(/^\[ai\]/m.test(POOL_WRANGLER_TOML)).toBe(false);
  });

  it("removes NOTHING else — every other line survives verbatim", () => {
    // Reconstruct what the committed file looks like with only `[ai]` dropped
    // and compare to the generated file's body. Any other divergence — a
    // dropped binding, a rewritten var, a stale regeneration — fails here.
    const withoutAi: string[] = [];
    let inAi = false;
    for (const line of COMMITTED_WRANGLER_TOML.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed === "[ai]") {
        inAi = true;
        continue;
      }
      if (inAi && trimmed.startsWith("[")) inAi = false;
      if (!inAi) withoutAi.push(line);
    }
    // The generated file prepends a three-line "DO NOT EDIT" banner.
    const generated = POOL_WRANGLER_TOML.split(/\r?\n/);
    const banner = generated.slice(0, 3);
    expect(banner.every((line) => line.startsWith("#"))).toBe(true);
    expect(banner.join("\n")).toContain("GENERATED by vitest.config.ts");
    expect(generated.slice(3)).toEqual(withoutAi);
  });
});
