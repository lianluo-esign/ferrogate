/**
 * ANTI-UNMOUNT for the shadow mirror — `@ferrogate/routing`'s mirror half as
 * the DEPLOYED Worker runs it, from a `GATEWAY_MODELS` table.
 *
 * ## Why this file exists alongside `shadow.test.ts`
 *
 * `test/inference/shadow.test.ts` drives `createInferenceRouter` with an
 * injected `InMemoryModelResolver`, so it proves `handlers.ts` mirrors when a
 * route carries `shadowPercent`. What it CANNOT prove is that the deployed
 * catalog ever produces such a route: `catalog.ts` has validated a
 * `shadow: { provider, provider_model, sample_percent }` block since wave 9,
 * and until this slice the flattened mirror route it produced was read by
 * nothing but `servableCandidates`, which threw it away. An operator could
 * configure a mirror, see `ferrogate check` pass, and mirror nothing.
 *
 * So every request below goes through `SELF.fetch` — `src/worker.ts` →
 * `src/index.ts` → `createGatewayApp` → the mounted inference route module —
 * with the shadow declared the way a real deployment declares it, in the
 * `GATEWAY_MODELS` var.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

const BASE = "https://gw.test";
const PRIMARY_HOST = "api.primary-probe.example";
const MIRROR_HOST = "api.mirror-probe.example";

const PROVIDERS = JSON.stringify([
  { name: "primary", kind: "openai", base_url: `https://${PRIMARY_HOST}/v1` },
  { name: "mirror", kind: "openai", base_url: `https://${MIRROR_HOST}/v1` },
]);

/**
 * A model with a 100%-sampled, uncapped mirror — the exact `[[models]].shadow`
 * shape `catalog.ts::shadowRouteSchema` validates.
 */
const MODELS = JSON.stringify([
  {
    name: "shadow-probe",
    provider: "primary",
    provider_model: "primary-physical",
    shadow: {
      provider: "mirror",
      provider_model: "mirror-physical",
      sample_percent: 100,
      max_requests: 0,
    },
  },
]);

const KEYS = JSON.stringify([
  { key: "fg_shadow", id: "key_shadow", tenant_id: "tenant_a", scopes: [] },
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

const CHAT_OK = {
  id: "chatcmpl-primary",
  object: "chat.completion",
  model: "shadow-probe",
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
};

interface Upstream {
  readonly hosts: string[];
  readonly bodies: Record<string, unknown>[];
  restore(): void;
}

/** Intercept both probe providers; anything else falls through. */
function stubUpstreams(mirrorStatus = 200): Upstream {
  const original = globalThis.fetch;
  const hosts: string[] = [];
  const bodies: Record<string, unknown>[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const host = new URL(url).hostname;
    if (host !== PRIMARY_HOST && host !== MIRROR_HOST) {
      return await original(input as RequestInfo, init);
    }
    hosts.push(host);
    bodies.push(
      typeof init?.body === "string"
        ? (JSON.parse(init.body) as Record<string, unknown>)
        : ({} as Record<string, unknown>),
    );
    return new Response(
      JSON.stringify(host === MIRROR_HOST ? { id: "chatcmpl-mirror" } : CHAT_OK),
      {
        status: host === MIRROR_HOST ? mirrorStatus : 200,
        headers: { "content-type": "application/json" },
      },
    );
  }) as typeof fetch;
  return {
    hosts,
    bodies,
    restore(): void {
      globalThis.fetch = original;
    },
  };
}

async function chat(body?: unknown): Promise<Response> {
  return await SELF.fetch(`${BASE}/v1/chat/completions`, {
    method: "POST",
    headers: { authorization: "Bearer fg_shadow", "content-type": "application/json" },
    body: JSON.stringify(
      body ?? {
        model: "shadow-probe",
        messages: [{ role: "user", content: "does the mirror exist in production" }],
      },
    ),
  });
}

/** The mirror rides `ctx.waitUntil`, so it lands after the client's response. */
async function waitForMirror(upstream: Upstream): Promise<void> {
  for (let i = 0; i < 300; i += 1) {
    if (upstream.hosts.includes(MIRROR_HOST)) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error("timed out waiting for the deployed Worker to mirror the request");
}

let upstream: Upstream | undefined;

afterEach(() => {
  upstream?.restore();
  upstream = undefined;
});

describe("the deployed Worker mirrors a configured shadow route", () => {
  it("dispatches to BOTH providers for one client request", async () => {
    upstream = stubUpstreams();

    const response = await chat();
    expect(response.status).toBe(200);
    // The client is served by the PRIMARY, always.
    expect(((await response.json()) as { id: string }).id).toBe("chatcmpl-primary");

    // THE MOUNT GATE. Remove `spawnShadowMirror` from `dispatchCandidates` and
    // this times out with only the primary host recorded.
    await waitForMirror(upstream);
    expect(new Set(upstream.hosts)).toEqual(new Set([PRIMARY_HOST, MIRROR_HOST]));
  });

  it("puts the CLIENT'S body on the mirror, with streaming forced off", async () => {
    upstream = stubUpstreams();

    const response = await chat({
      model: "shadow-probe",
      messages: [{ role: "user", content: "mirror me" }],
      stream: true,
    });
    expect(response.status).toBe(200);
    await response.text();
    await waitForMirror(upstream);

    const mirrored = upstream.bodies[upstream.hosts.indexOf(MIRROR_HOST)] as {
      model?: unknown;
      stream?: unknown;
      messages?: { content?: unknown }[];
    };
    // The PROVIDER-side model id of the shadow leg, not the client's logical
    // name and not the primary's physical id — proof the mirror went through
    // the catalog's own shadow route rather than a copy of the primary.
    expect(mirrored.model).toBe("mirror-physical");
    expect(mirrored.messages?.[0]?.content).toBe("mirror me");
    // Rust forces the mirror non-streaming; the response is discarded, so a
    // bounded body is simpler and usage still arrives inside it.
    expect(mirrored.stream).toBe(false);

    // ...and the client's own dispatch was still a stream.
    const primary = upstream.bodies[upstream.hosts.indexOf(PRIMARY_HOST)] as {
      stream?: unknown;
      model?: unknown;
    };
    expect(primary.stream).toBe(true);
    expect(primary.model).toBe("primary-physical");
  });

  it("a mirror that fails leaves the client's response untouched", async () => {
    upstream = stubUpstreams(500);

    const response = await chat();
    expect(response.status).toBe(200);
    expect(((await response.json()) as { id: string }).id).toBe("chatcmpl-primary");
    await waitForMirror(upstream);
  });

  it("never serves the client from the mirror when the primary is down", async () => {
    const original = globalThis.fetch;
    const hosts: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const host = new URL(url).hostname;
      if (host !== PRIMARY_HOST && host !== MIRROR_HOST) {
        return await original(input as RequestInfo, init);
      }
      hosts.push(host);
      return host === MIRROR_HOST
        ? new Response(JSON.stringify({ id: "chatcmpl-mirror" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          })
        : new Response(JSON.stringify({ error: "primary down" }), {
            status: 503,
            headers: { "content-type": "application/json" },
          });
    }) as typeof fetch;

    try {
      const response = await chat();
      // A mirror is NOT a fallback. `servableCandidates` strips it out of the
      // ladder before eligibility, so the only servable route failed and the
      // client is told so — even though a healthy provider was dialled for the
      // same request microseconds later.
      expect(response.status).toBe(503);
      const body = (await response.json()) as { id?: string };
      expect(body.id).toBeUndefined();
    } finally {
      globalThis.fetch = original;
    }
  });
});
