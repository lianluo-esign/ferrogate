/**
 * RESIDENCY ENFORCEMENT (#681), driven through the DEPLOYED middleware chain.
 *
 * ## Why this file composes `GATEWAY_MIDDLEWARE` rather than its own list
 *
 * Because the defect is that the control was NOT ARMED, and "armed" is a
 * property of the chain the Worker actually runs. `inference/candidates.ts` has
 * had a region gate since the #173 port and it read `Caller.regionAllowlist`,
 * which `identity.ts::callerFromAuth` never set and no credential column ever
 * populated — so every deployed request saw an empty allowlist and every route
 * passed. Every unit test that injected its own `caller` was green throughout.
 * A test that injects a caller therefore cannot hold this slice; only one that
 * starts from a bearer token and the exported middleware array can.
 *
 * So each case below builds the app from the exported `GATEWAY_MIDDLEWARE`
 * array — the same handlers in the same order `src/index.ts` ships — and only
 * the route module (an in-memory model resolver and a deterministic request-id
 * factory) and the outbound provider `fetch` are doubles.
 *
 * ## MOUNT GATES — what goes red if the wiring is removed
 *
 *  - drop `residency()` from `GATEWAY_MIDDLEWARE` → every REFUSAL case here
 *    turns 200 and the out-of-region provider is called;
 *  - drop the `residencyPolicyFor(request)` argument in
 *    `inference/route-module.ts::publishRequestScope` → same, because the
 *    policy is resolved and then never reaches the routing decision. That is
 *    the exact two-hop dead seam #681 exists to close, so it has its own case:
 *    "the policy reaches the ROUTING decision, not just the middleware".
 */
import { afterEach, describe, expect, it } from "vitest";

import { GATEWAY_MIDDLEWARE } from "../../src/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { PhysicalRoute, RequestIdFactory } from "../../src/inference/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";

const BASE = "https://gw.test";
const MODEL = "resident-model";

/**
 * Two tenants. `tenant_eu` is governed below; `tenant_us` never is, and exists
 * so every refusal assertion has a control that proves the refusal came from
 * THIS tenant's policy rather than from the catalogue being unusable.
 */
const KEYS = [
  { key: "fg_eu", id: "key_eu", tenant_id: "tenant_eu", project_id: "project_eu" },
  { key: "fg_us", id: "key_us", tenant_id: "tenant_us", project_id: "project_us" },
];

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

const EU_ROUTE = route({ provider: "eu", region: "eu-west-1", priority: 0 });
const EU_ZDR_ROUTE = route({
  provider: "eu-zdr",
  region: "eu-west-1",
  zeroDataRetention: true,
  priority: 0,
});
const US_ROUTE = route({ provider: "us", region: "us-east-1", priority: 1 });

function providerOf(url: string): string {
  return new URL(url).hostname.replace(/\.test$/, "");
}

interface PolicyVar {
  readonly tenant_id: string;
  readonly residency_regions?: unknown;
  readonly require_zero_data_retention?: unknown;
  readonly log_residency?: unknown;
}

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
  call(key: string, body?: unknown): Promise<Response>;
}

function gateway(options: {
  readonly policies?: readonly PolicyVar[];
  readonly logRegion?: string;
  readonly routes?: readonly PhysicalRoute[];
  readonly middleware?: readonly unknown[];
}): Harness {
  const env: Record<string, unknown> = {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify(KEYS),
    ...(options.policies === undefined
      ? {}
      : { GATEWAY_RESIDENCY_POLICIES: JSON.stringify(options.policies) }),
    ...(options.logRegion === undefined ? {} : { GATEWAY_LOG_REGION: options.logRegion }),
  };

  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver(options.routes ?? [EU_ROUTE, US_ROUTE]),
        requestIds: incrementingRequestIds(),
      }),
    ],
    // THE LINE UNDER TEST: the deployed chain, in the deployed order.
    middleware: (options.middleware ?? GATEWAY_MIDDLEWARE) as typeof GATEWAY_MIDDLEWARE,
  });

  return {
    call: async (key, body) =>
      app.request(
        `${BASE}/v1/chat/completions`,
        {
          method: "POST",
          headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
          body: JSON.stringify(
            body ?? { model: MODEL, messages: [{ role: "user", content: "eu personal data" }] },
          ),
        },
        env,
      ),
  };
}

let provider: ProviderInterceptor | undefined;

function upstreamAnswers(): ProviderInterceptor {
  provider = interceptProviderFetch(() =>
    providerJson({
      id: "chatcmpl-1",
      object: "chat.completion",
      model: MODEL,
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

async function errorOf(response: Response): Promise<{ code: string; message: string }> {
  const body = (await response.json()) as { error: { code: string; message: string } };
  return body.error;
}

// ---------------------------------------------------------------------------
// The region leg, from a bearer token
// ---------------------------------------------------------------------------

describe("#681 — a tenant residency policy constrains route eligibility", () => {
  it("the policy reaches the ROUTING decision, not just the middleware", async () => {
    // THE HEADLINE CASE. Before this slice the gate existed and nothing armed
    // it, so this exact request — a governed tenant, a catalogue with only an
    // out-of-region route — answered 200 from `us`.
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [{ tenant_id: "tenant_eu", residency_regions: ["eu-west-1"] }],
      routes: [US_ROUTE],
    });

    const response = await h.call("fg_eu");

    expect(response.status).toBe(403);
    const error = await errorOf(response);
    expect(error.code).toBe("region_not_allowed");
    expect(error.message).toContain("eu-west-1");
    expect(upstream.requests).toHaveLength(0);
  });

  it("serves the same tenant from an IN-region route", async () => {
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [{ tenant_id: "tenant_eu", residency_regions: ["eu-west-1"] }],
    });

    const response = await h.call("fg_eu");

    expect(response.status).toBe(200);
    expect(upstream.requests.map((request) => providerOf(request.url))).toEqual(["eu"]);
  });

  it("does not apply tenant EU's policy to a tenant nothing governs", async () => {
    // The fence. Without a per-tenant key on both the lookup and the cache, a
    // warm isolate would refuse this request under the other tenant's policy.
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [{ tenant_id: "tenant_eu", residency_regions: ["eu-west-1"] }],
      routes: [US_ROUTE],
    });

    const refused = await h.call("fg_eu");
    expect(refused.status).toBe(403);

    const served = await h.call("fg_us");
    expect(served.status).toBe(200);
    expect(upstream.requests.map((request) => providerOf(request.url))).toEqual(["us"]);
  });

  it("refuses rather than downgrading when only a non-ZDR route is in region", async () => {
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [
        {
          tenant_id: "tenant_eu",
          residency_regions: ["eu-west-1"],
          require_zero_data_retention: true,
        },
      ],
      // ONLY the in-region route. With the US route in the catalogue too the
      // refusal is `residency_policy_not_satisfiable` — correctly, because BOTH
      // constraints then have an unmet route — and this case is specifically
      // about the retention code being reachable on its own.
      routes: [EU_ROUTE],
    });

    const response = await h.call("fg_eu");

    expect(response.status).toBe(403);
    expect((await errorOf(response)).code).toBe("zero_data_retention_required");
    expect(upstream.requests).toHaveLength(0);
  });

  it("serves it once a route ASSERTS zero data retention", async () => {
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [
        {
          tenant_id: "tenant_eu",
          residency_regions: ["eu-west-1"],
          require_zero_data_retention: true,
        },
      ],
      routes: [EU_ROUTE, EU_ZDR_ROUTE, US_ROUTE],
    });

    const response = await h.call("fg_eu");

    expect(response.status).toBe(200);
    expect(upstream.requests.map((request) => providerOf(request.url))).toEqual(["eu-zdr"]);
  });
});

// ---------------------------------------------------------------------------
// Log placement
// ---------------------------------------------------------------------------

describe("#681 — a residency policy also constrains where the LOG lands", () => {
  it("refuses when the deployment declares no log region at all", async () => {
    // "Nobody has said" is not "yes" — the same modelling as ZDR. A deployment
    // that has never heard of `GATEWAY_LOG_REGION` cannot satisfy an in-region
    // log policy by default, which is what makes the control worth buying.
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [
        {
          tenant_id: "tenant_eu",
          residency_regions: ["eu-west-1"],
          log_residency: "in_region",
        },
      ],
    });

    const response = await h.call("fg_eu");

    expect(response.status).toBe(403);
    const error = await errorOf(response);
    expect(error.code).toBe("log_residency_unsatisfiable");
    expect(error.message).toContain("GATEWAY_LOG_REGION");
    // And it refused BEFORE dispatch: the prompt never left, which is the whole
    // point of refusing rather than serving-and-not-logging.
    expect(upstream.requests).toHaveLength(0);
  });

  it("refuses when the declared log region is OUTSIDE the tenant's list", async () => {
    const h = gateway({
      policies: [
        {
          tenant_id: "tenant_eu",
          residency_regions: ["eu-west-1"],
          log_residency: "in_region",
        },
      ],
      logRegion: "us-east-1",
    });
    upstreamAnswers();

    const response = await h.call("fg_eu");

    expect(response.status).toBe(403);
    const error = await errorOf(response);
    expect(error.code).toBe("log_residency_unsatisfiable");
    expect(error.message).toContain("us-east-1");
  });

  it("serves when the declared log region is inside it", async () => {
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [
        {
          tenant_id: "tenant_eu",
          residency_regions: ["eu-west-1"],
          log_residency: "in_region",
        },
      ],
      logRegion: "eu-west-1",
    });

    const response = await h.call("fg_eu");

    expect(response.status).toBe(200);
    expect(upstream.requests.map((request) => providerOf(request.url))).toEqual(["eu"]);
  });

  it("leaves an ungoverned log alone when the tenant only pinned INFERENCE", async () => {
    // The complement: a tenant that says nothing about logs is served on a
    // deployment that declares no log region, exactly as before #681.
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [{ tenant_id: "tenant_eu", residency_regions: ["eu-west-1"] }],
    });

    expect((await h.call("fg_eu")).status).toBe(200);
    expect(upstream.requests).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// The fail direction
// ---------------------------------------------------------------------------

describe("#681 — a policy that cannot be READ refuses, it does not serve", () => {
  it("answers 503 for a policy row this gateway cannot parse", async () => {
    // The inverse of #678's fail-open reading, and the reason is stated in
    // `residency/source.ts`: an unreadable ATTRIBUTION requirement can only
    // refuse traffic that was already served, while an unreadable RESIDENCY
    // requirement read as "not enforced" SERVES — possibly out of region — and
    // succeeds, so nobody finds out.
    const upstream = upstreamAnswers();
    const h = gateway({
      policies: [{ tenant_id: "tenant_eu", residency_regions: ["eu-west-1", 7] }],
    });

    const response = await h.call("fg_eu");

    expect(response.status).toBe(503);
    expect((await errorOf(response)).code).toBe("residency_policy_unavailable");
    expect(upstream.requests).toHaveLength(0);
  });

  it("refuses a policy that pins the log in region without naming a region", async () => {
    const h = gateway({
      policies: [{ tenant_id: "tenant_eu", log_residency: "in_region" }],
    });
    upstreamAnswers();

    const response = await h.call("fg_eu");

    expect(response.status).toBe(503);
    expect((await errorOf(response)).message).toContain("residency_regions");
  });
});

// ---------------------------------------------------------------------------
// The mount gate
// ---------------------------------------------------------------------------

describe("#681 — the gate is MOUNTED on the deployed chain", () => {
  it("goes back to serving out of region once residency() is removed", async () => {
    // Not a behaviour assertion — a wiring one. It measures what the suite
    // would look like if `residency()` were dropped from `GATEWAY_MIDDLEWARE`,
    // so the reader can see that the refusals above come from the mount and not
    // from something ambient in the harness.
    const upstream = upstreamAnswers();
    const withoutGate = GATEWAY_MIDDLEWARE.filter(
      (entry) => (entry as { name?: string }).name !== "residencyMiddleware",
    );
    expect(withoutGate).toHaveLength(GATEWAY_MIDDLEWARE.length - 1);

    const h = gateway({
      policies: [{ tenant_id: "tenant_eu", residency_regions: ["eu-west-1"] }],
      routes: [US_ROUTE],
      middleware: withoutGate,
    });

    const response = await h.call("fg_eu");

    expect(response.status).toBe(200);
    expect(upstream.requests.map((request) => providerOf(request.url))).toEqual(["us"]);
  });
});
