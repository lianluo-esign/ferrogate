/**
 * ATTRIBUTION TAG ENFORCEMENT (#678), driven through the DEPLOYED middleware
 * chain.
 *
 * ## Why this file composes `GATEWAY_MIDDLEWARE` rather than its own list
 *
 * The defect this slice closes is that nothing REJECTS an untagged request, and
 * "nothing" is a property of the chain the Worker actually runs — not of a
 * middleware that exists in `src/` and is mounted nowhere. `test/metering/
 * wiring.test.ts` learned that the hard way: deleting `meteringDrain(usage)`
 * from the composition root left 794 tests green. So every behavioural case
 * below builds the app from the exported `GATEWAY_MIDDLEWARE` array, i.e. the
 * same handlers in the same order `src/index.ts` ships, and only the route
 * module (an in-memory model resolver, a deterministic request-id factory and
 * an in-memory metering sink) and the outbound provider `fetch` are doubles.
 *
 * That also makes the LADDER assertions meaningful. Two of them —
 * "the refusal happens after admission has been charged" and "the refusal
 * happens before guardrail screening" — are statements about ORDER, and order
 * is exactly what a test with a hand-rolled middleware list cannot see.
 *
 * ## MUTATION LOG — what was broken, and what went red
 *
 * FerroGate's dominant defect mode is correct code with a green test that does
 * not hold it, so each claim below was falsified against the tree before this
 * file was believed. Every mutation was reverted; `grep MUTATION-678` is empty.
 *
 * | mutation (in `src/`)                                        | red |
 * |-------------------------------------------------------------|-----|
 * | `source.ts`: drop `AND scope_id = ?` from the tenant lookup   | `binds the tenant, and only ever looks at the tenant scope` (`policy-source.test.ts`) |
 * | `source.ts`: cache entries keyed `"ANY"` instead of by tenant | `never answers tenant B from tenant A's entry`; `does not let tenant A's REJECT policy refuse tenant B` |
 * | `middleware.ts`: `keyTagsOf` returns the FIRST key's tags for every later request | `defaults tenant B's request from tenant B's key` — tenant B's charge came back stamped `team: "growth"`, i.e. one tenant's spend attributed to another; and `still refuses when the key declares nothing to default FROM` |
 * | `handlers.ts`: `attributedMetadata` returns the caller's map only | `fills a missing required tag … and bills it under that value` — the request was served and the charge's `metadata` was `{}` |
 * | `index.ts`: `attributionTags()` unmounted                     | 9 of the 13 cases here |
 * | `index.ts`: gate moved BEHIND `guardrails()`                   | `runs BEFORE guardrail screening` (answered `guardrail_blocked`) + the mount gate |
 * | `index.ts`: gate moved AHEAD of `rateLimit()`                  | `runs AFTER admission` (the second, correctly tagged request was 200 instead of 429) + the mount gate |
 *
 * The third row is the one the issue singles out: it is a real cross-tenant
 * attribution leak, and it is caught by value, not by status code.
 */
import { env as poolEnv } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { GATEWAY_MIDDLEWARE } from "../../src/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { RequestIdFactory } from "../../src/inference/index.js";
import {
  InMemoryLedgerStore,
  InMemoryMeteringOutbox,
  MeteringUsageSink,
  TrackingScheduler,
} from "../../src/metering/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { FINGERPRINT_SECRET_REF, secretScanPolicy } from "../guardrails/fixtures.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";
import { pricedBook } from "../metering/fixtures.js";

const BASE = "https://gw.test";

/**
 * Two tenants, and within tenant A two keys: one that DECLARES its own
 * attribution and one that declares none.
 *
 * `tenant_b`'s key declares a DIFFERENT value for the same tag key, which is
 * what makes the fence assertions falsifiable — a defaulting bug that reached
 * across tenants would stamp `growth` on tenant B's spend, and a test whose two
 * tenants shared a value could not tell the difference.
 */
const KEYS = [
  {
    key: "fg_a_tagged",
    id: "key_a_tagged",
    tenant_id: "tenant_a",
    project_id: "project_a",
    attribution_tags: { team: "growth" },
  },
  { key: "fg_a_bare", id: "key_a_bare", tenant_id: "tenant_a", project_id: "project_a" },
  {
    key: "fg_b_tagged",
    id: "key_b_tagged",
    tenant_id: "tenant_b",
    project_id: "project_b",
    attribution_tags: { team: "billing" },
  },
];

interface PolicyVar {
  readonly tenant_id: string;
  readonly required_tags: readonly string[];
  readonly on_missing: "reject" | "default_from_key";
}

/** Distinct request ids, so two calls are two charges and not one replay. */
function incrementingRequestIds(): RequestIdFactory {
  let next = 0;
  return {
    next: (): string => {
      next += 1;
      return `fg-${next.toString(16).padStart(16, "0")}`;
    },
  };
}

interface Harness {
  readonly ledger: InMemoryLedgerStore;
  readonly scheduler: TrackingScheduler;
  call(key: string, body: unknown): Promise<Response>;
}

function gateway(
  options: {
    readonly policies?: readonly PolicyVar[];
    readonly quotas?: readonly Record<string, unknown>[];
    readonly guardrails?: boolean;
  } = {},
): Harness {
  const ledger = new InMemoryLedgerStore();
  const scheduler = new TrackingScheduler();
  const sink = new MeteringUsageSink({
    priceBook: pricedBook(),
    ledger,
    outbox: new InMemoryMeteringOutbox(),
    scheduler,
  });

  const env: Record<string, unknown> = {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify(KEYS),
    ...(options.policies === undefined
      ? {}
      : { GATEWAY_ATTRIBUTION_POLICIES: JSON.stringify(options.policies) }),
    ...(options.quotas === undefined
      ? {}
      : {
          GATEWAY_QUOTA_POLICIES: JSON.stringify(options.quotas),
          // The REAL `RateLimiterDurableObject` from `wrangler.toml`. Without
          // it `limiterForEnv` builds a fresh `InMemoryRateLimiter` per
          // request, whose `Map` is discarded before the next one — so an RPM
          // limit could never be reached and the "the refusal was counted"
          // assertion below would be vacuous rather than informative.
          RATE_LIMIT: (poolEnv as unknown as Record<string, unknown>)["RATE_LIMIT"],
        }),
    ...(options.guardrails === true
      ? {
          GATEWAY_GUARDRAIL_POLICIES: JSON.stringify([secretScanPolicy()]),
          [FINGERPRINT_SECRET_REF]: "test-fingerprint-key",
        }
      : {}),
  };

  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([OPENAI_ROUTE]),
        requestIds: incrementingRequestIds(),
        usage: sink,
      }),
    ],
    // THE LINE UNDER TEST: the deployed chain, in the deployed order.
    middleware: GATEWAY_MIDDLEWARE,
  });

  return {
    ledger,
    scheduler,
    call: async (key, body) =>
      app.request(
        `${BASE}/v1/chat/completions`,
        {
          method: "POST",
          headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
          body: JSON.stringify(body),
        },
        env,
      ),
  };
}

function chat(metadata?: Record<string, string>, content = "hi"): Record<string, unknown> {
  return {
    model: "gpt-4o-mini",
    messages: [{ role: "user", content }],
    ...(metadata === undefined ? {} : { metadata }),
  };
}

let provider: ProviderInterceptor | undefined;

function upstreamAnswers(): ProviderInterceptor {
  provider = interceptProviderFetch(() =>
    providerJson({
      id: "chatcmpl-1",
      object: "chat.completion",
      model: "gpt-4o-mini",
      choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
    }),
  );
  return provider;
}

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

/**
 * The tags a settled charge carries — `billing_events.event_json -> metadata`,
 * which is precisely the column #677's `?tag=` predicate reads.
 *
 * Charges are correlated by REQUEST ID rather than by ledger position: the
 * billing event's `tenant` is populated from the served ROUTE's tenancy (an
 * operator-owned registry field), not from the authenticated caller, so it
 * cannot be used to tell two tenants' charges apart here. The request id is the
 * value the client is handed in `x-request-id` and the one the sink keys on.
 */
async function chargedTags(
  h: Harness,
  response: Response,
): Promise<Record<string, string> | undefined> {
  await h.scheduler.idle();
  const requestId = response.headers.get("x-request-id");
  const charge = h.ledger.charges.find((candidate) => candidate.requestId === requestId);
  return charge?.event.metadata;
}

describe("#678 — a tenant policy that REQUIRES named tags", () => {
  it("refuses an untagged request, and does not pay for a provider call", async () => {
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [{ tenant_id: "tenant_a", required_tags: ["team"], on_missing: "reject" }],
    });

    const response = await h.call("fg_a_tagged", chat());

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      error: {
        message: 'request is missing required attribution tags: "team"',
        type: "ferrogate_error",
        code: "attribution_tags_required",
        request_id: response.headers.get("x-request-id"),
      },
    });
    // The whole point of the ladder position: a refusal that cost a provider
    // call would be a worse bug than the untagged request it refused.
    expect(upstream.requests).toHaveLength(0);
  });

  it("serves a request that carries the required tag, and bills it under that tag", async () => {
    upstreamAnswers();
    const h = gateway({
      policies: [{ tenant_id: "tenant_a", required_tags: ["team"], on_missing: "reject" }],
    });

    const response = await h.call("fg_a_tagged", chat({ team: "growth" }));

    expect(response.status).toBe(200);
    expect(await chargedTags(h, response)).toEqual({ team: "growth" });
  });

  it("names every missing tag, not just the first", async () => {
    upstreamAnswers();
    const h = gateway({
      policies: [
        { tenant_id: "tenant_a", required_tags: ["team", "cost_center"], on_missing: "reject" },
      ],
    });

    const response = await h.call("fg_a_tagged", chat({ team: "growth" }));
    const body = (await response.json()) as { error: { message: string } };

    expect(response.status).toBe(403);
    expect(body.error.message).toContain("cost_center");
    expect(body.error.message).not.toContain('"team"');
  });

  it("is OFF for a tenant no policy names — enforcement is configured, never implicit", async () => {
    upstreamAnswers();
    const h = gateway({
      policies: [{ tenant_id: "tenant_a", required_tags: ["team"], on_missing: "reject" }],
    });

    const response = await h.call("fg_b_tagged", chat());

    expect(response.status).toBe(200);
    expect(await chargedTags(h, response)).toEqual({});
  });

  it("is OFF entirely when no policy is configured at all", async () => {
    upstreamAnswers();
    const h = gateway();

    expect((await h.call("fg_a_tagged", chat())).status).toBe(200);
  });
});

describe("#678 — the DEFAULT branch, from the virtual key's own attribution", () => {
  it("fills a missing required tag from the presented key and bills it under that value", async () => {
    upstreamAnswers();
    const h = gateway({
      policies: [
        { tenant_id: "tenant_a", required_tags: ["team"], on_missing: "default_from_key" },
      ],
    });

    const response = await h.call("fg_a_tagged", chat());

    expect(response.status).toBe(200);
    // Not merely "the request was served": the tag has to reach the surface
    // #677 queries, or the request is still unattributable and the default is
    // theatre.
    expect(await chargedTags(h, response)).toEqual({ team: "growth" });
  });

  it("never overwrites a tag the caller stated", async () => {
    upstreamAnswers();
    const h = gateway({
      policies: [
        { tenant_id: "tenant_a", required_tags: ["team"], on_missing: "default_from_key" },
      ],
    });

    const response = await h.call("fg_a_tagged", chat({ team: "platform" }));

    expect(response.status).toBe(200);
    expect(await chargedTags(h, response)).toEqual({ team: "platform" });
  });

  it("still refuses when the key declares nothing to default FROM", async () => {
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [
        { tenant_id: "tenant_a", required_tags: ["team"], on_missing: "default_from_key" },
      ],
    });

    const response = await h.call("fg_a_bare", chat());

    // `default_from_key` is "default what CAN be defaulted"; a required tag the
    // key cannot supply is still an unattributable request, and admitting it
    // would reintroduce the exact decay this issue closes.
    expect(response.status).toBe(403);
    expect(upstream.requests).toHaveLength(0);
  });
});

describe("#678 — the tenant fence on defaulting", () => {
  it("defaults tenant B's request from tenant B's key, never from tenant A's", async () => {
    upstreamAnswers();
    const h = gateway({
      policies: [
        { tenant_id: "tenant_a", required_tags: ["team"], on_missing: "default_from_key" },
        { tenant_id: "tenant_b", required_tags: ["team"], on_missing: "default_from_key" },
      ],
    });

    // Tenant A first, so any cross-request cache is populated with `growth`
    // before tenant B is ever seen — which is the shape the fence has to
    // survive in a warm isolate.
    const first = await h.call("fg_a_tagged", chat());
    const second = await h.call("fg_b_tagged", chat());
    expect([first.status, second.status]).toEqual([200, 200]);

    expect(await chargedTags(h, first)).toEqual({ team: "growth" });
    // The assertion this whole file is built around: tenant B's spend is
    // attributed to tenant B's own team, and `growth` never crosses over.
    expect(await chargedTags(h, second)).toEqual({ team: "billing" });
  });

  it("does not let tenant A's REJECT policy refuse tenant B, warm isolate or not", async () => {
    upstreamAnswers();
    const h = gateway({
      policies: [{ tenant_id: "tenant_a", required_tags: ["cost_center"], on_missing: "reject" }],
    });

    expect((await h.call("fg_a_tagged", chat())).status).toBe(403);
    expect((await h.call("fg_b_tagged", chat())).status).toBe(200);
  });
});

describe("#678 — where the refusal sits on the ladder", () => {
  it("runs AFTER admission, so an untagged flood still burns the caller's RPM window", async () => {
    upstreamAnswers();
    const h = gateway({
      policies: [{ tenant_id: "tenant_a", required_tags: ["team"], on_missing: "reject" }],
      quotas: [{ scope_type: "tenant", scope_id: "tenant_a", rpm_limit: 1 }],
    });

    // The untagged request is refused — and has already been counted.
    expect((await h.call("fg_a_tagged", chat())).status).toBe(403);
    // A perfectly tagged request now hits the window the refusal consumed. If
    // the tag gate ran ahead of `rateLimit()`, this would be a 403 and an
    // untagged flood would be an unmetered one.
    const second = await h.call("fg_a_tagged", chat({ team: "growth" }));
    expect(second.status).toBe(429);
  });

  it("runs BEFORE guardrail screening, so a refused request buys no detector work", async () => {
    upstreamAnswers();
    const h = gateway({
      guardrails: true,
      policies: [{ tenant_id: "tenant_a", required_tags: ["team"], on_missing: "reject" }],
    });

    // A prompt the guardrail policy blocks, sent WITHOUT the required tag.
    // Whichever gate runs first owns the answer.
    const response = await h.call("fg_a_tagged", chat(undefined, "leak FERROGATE-GUARDRAIL-PROBE"));
    const body = (await response.json()) as { error: { code: string } };

    expect(response.status).toBe(403);
    expect(body.error.code).toBe("attribution_tags_required");

    // ...and the same prompt WITH the tag is still screened, so this is an
    // ordering assertion and not an accidental disabling of guardrails.
    const screened = await h.call(
      "fg_a_tagged",
      chat({ team: "growth" }, "leak FERROGATE-GUARDRAIL-PROBE"),
    );
    expect(((await screened.json()) as { error: { code: string } }).error.code).toBe(
      "guardrail_blocked",
    );
  });
});

describe("#678 — the mount", () => {
  const names = GATEWAY_MIDDLEWARE.map((handler) => handler.name);

  it("is mounted between admission and screening in the deployed chain", () => {
    // Structural, because ORDER is invisible to a behavioural test that only
    // ever exercises one gate at a time — and because deleting the mount is the
    // regression that historically stayed green.
    const gate = names.indexOf("attributionTagsMiddleware");
    expect(gate).toBeGreaterThan(names.indexOf("rateLimitMiddleware"));
    expect(gate).toBeLessThan(names.indexOf("guardrailsMiddleware"));
  });
});
