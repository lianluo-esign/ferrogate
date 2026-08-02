/**
 * DATA RESIDENCY ON EVERY LEG THAT LEAVES THE ISOLATE (#681).
 *
 * ## The two questions this file exists to answer
 *
 * `candidates.ts::routeExclusionReasons` has had a region gate since the #173
 * port, and `test/inference/reliability.test.ts` proves it refuses a
 * single out-of-region route. That is the EASY half. A residency guarantee is
 * only worth what it is worth when something goes wrong, so the cases here are
 * the ones a config flag does not cover:
 *
 *  1. **FAILOVER.** The primary is in region and fails; the fallback is not in
 *     region. A gate applied to the primary and forgotten on the fallback holds
 *     under every happy-path test and breaks exactly in production.
 *  2. **THE MIRROR.** `shadow.ts::shadowMirrorFor` selects its route from the
 *     FULL candidate list — `handlers.ts` calls it on `resolved`, before
 *     `servableCandidates` and before `eligibleCandidates` — so the shadow leg
 *     has never been shown a residency policy at all. It is not a failover in
 *     the ladder sense, but it is the same defect shape and it is WORSE: the
 *     whole prompt is sent to the mirrored provider, the client's response is
 *     unaffected, and nothing anywhere reports that it happened.
 *
 * Both are driven end to end through the real `createInferenceRouter`, with
 * only the outbound provider `fetch` intercepted, because a test that called
 * `residencyViolations` directly would stay green through the entire defect.
 */
import { afterEach, describe, expect, it } from "vitest";
import type { Caller, InferenceDeps, PhysicalRoute } from "../../src/inference/index.js";
import { errorBody, harness } from "./fixtures.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "./provider-mock.js";

const MODEL = "resident-model";

const CHAT_BODY = { model: MODEL, messages: [{ role: "user", content: "eu personal data" }] };

const CHAT_OK = {
  id: "chatcmpl-ok",
  object: "chat.completion",
  model: MODEL,
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

/** Which provider an intercepted call went to, from its host. */
function providerOf(url: string): string {
  return new URL(url).hostname.replace(/\.test$/, "");
}

/**
 * A caller under an EU-only residency policy.
 *
 * `apiKeyId` is not decoration: `shadowMirrorFor` refuses to mirror a caller
 * with no sticky identity, so without it the mirror cases below would pass for
 * the wrong reason — the residency gate could be entirely absent and the mirror
 * still would not fire.
 */
function euCaller(): InferenceDeps["caller"] {
  return (): Caller => ({
    scope: { kind: "tenant", tenantId: "eu-tenant" },
    apiKeyId: "key_eu",
    regionAllowlist: ["eu-west-1"],
  });
}

/** Poll until `predicate` holds — the mirror lands AFTER the client's response. */
async function settle(): Promise<void> {
  for (let i = 0; i < 50; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

let provider: ProviderInterceptor | undefined;

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

// ---------------------------------------------------------------------------
// 1. The failover ladder
// ---------------------------------------------------------------------------

describe("#681 — failover cannot leave the tenant's region", () => {
  it("refuses rather than falling over onto an out-of-region route", async () => {
    // The EU primary answers a RETRYABLE 503, which is precisely the condition
    // that makes a ladder walk to the next candidate. The US fallback is at a
    // lower priority and is healthy, so an unguarded ladder serves the request
    // from it and the client never learns the prompt left the EU.
    provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "eu"
        ? new Response(JSON.stringify({ error: { message: "overloaded" } }), {
            status: 503,
            headers: { "content-type": "application/json" },
          })
        : providerJson(CHAT_OK),
    );

    const app = harness(
      { caller: euCaller() },
      [
        route({ provider: "eu", region: "eu-west-1", priority: 0 }),
        route({ provider: "us", region: "us-east-1", priority: 1 }),
      ],
    );

    const res = await app.post("/v1/chat/completions", CHAT_BODY);

    // The request FAILS. It is not served out of region, and it is not served
    // at all — which is the whole rule (#674, again in #690): what cannot be
    // expressed within policy is refused, never degraded.
    expect(res.status).not.toBe(200);
    expect(provider.requests.map((request) => providerOf(request.url))).toEqual(["eu"]);
  });

  it("still fails over between two IN-region routes", async () => {
    // The complement, and the reason the assertion above is about the region
    // and not about failover being switched off: residency must cost the tenant
    // nothing it did not ask for.
    provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "eu-a"
        ? new Response("{}", { status: 503, headers: { "content-type": "application/json" } })
        : providerJson(CHAT_OK),
    );

    const app = harness(
      { caller: euCaller() },
      [
        route({ provider: "eu-a", region: "eu-west-1", priority: 0 }),
        route({ provider: "eu-b", region: "eu-west-1", priority: 1 }),
      ],
    );

    const res = await app.post("/v1/chat/completions", CHAT_BODY);

    expect(res.status).toBe(200);
    expect(provider.requests.map((request) => providerOf(request.url))).toEqual(["eu-a", "eu-b"]);
  });
});

// ---------------------------------------------------------------------------
// 2. The shadow mirror — THE HOLE
// ---------------------------------------------------------------------------

describe("#681 — the shadow mirror cannot leave the tenant's region", () => {
  it("does not mirror an EU tenant's prompt to an out-of-region shadow route", async () => {
    provider = interceptProviderFetch(() => providerJson(CHAT_OK));

    const app = harness(
      { caller: euCaller() },
      [
        route({ provider: "eu", region: "eu-west-1", priority: 0 }),
        route({
          provider: "us-mirror",
          region: "us-east-1",
          priority: 5,
          shadowPercent: 100,
          shadowMaxRequests: 0,
        }),
      ],
    );

    const res = await app.post("/v1/chat/completions", CHAT_BODY);
    expect(res.status).toBe(200);

    // The mirror is fire-and-forget, so "it did not happen" needs the isolate
    // to be given the chance to make it happen first.
    await settle();

    expect(provider.requests.map((request) => providerOf(request.url))).toEqual(["eu"]);
  });

  it("still mirrors to an IN-region shadow route", async () => {
    // Without this, the assertion above would also pass on a build where
    // mirroring was simply broken.
    provider = interceptProviderFetch(() => providerJson(CHAT_OK));

    const app = harness(
      { caller: euCaller() },
      [
        route({ provider: "eu", region: "eu-west-1", priority: 0 }),
        route({
          provider: "eu-mirror",
          region: "eu-west-1",
          priority: 5,
          shadowPercent: 100,
          shadowMaxRequests: 0,
        }),
      ],
    );

    const res = await app.post("/v1/chat/completions", CHAT_BODY);
    expect(res.status).toBe(200);

    for (let i = 0; i < 200 && provider.requests.length < 2; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }

    expect(provider.requests.map((request) => providerOf(request.url)).sort()).toEqual([
      "eu",
      "eu-mirror",
    ]);
  });

  it("names the region constraint when nothing in the catalog can serve it", async () => {
    provider = interceptProviderFetch(() => providerJson(CHAT_OK));

    const app = harness({ caller: euCaller() }, [
      route({ provider: "us", region: "us-east-1" }),
    ]);

    const res = await app.post("/v1/chat/completions", CHAT_BODY);

    expect(res.status).toBe(403);
    const body = await errorBody(res);
    expect(body.error.code).toBe("region_not_allowed");
    // An operator cannot act on "policy refused this". The refusal has to say
    // WHICH constraint failed and what would satisfy it.
    expect(body.error.message).toContain("eu-west-1");
    expect(provider.requests).toHaveLength(0);
  });
});
