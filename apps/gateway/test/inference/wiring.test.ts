/**
 * ANTI-UNMOUNT: the inference handlers are wired to the AUTHENTICATED identity
 * and to the tokens-per-minute window of the app the Worker actually exports.
 *
 * ## Why this file exists as its own suite
 *
 * `inferenceRouteModule` delegates with `inner.fetch(c.req.raw, c.env, ctx)`,
 * which starts a FRESH Hono context. Everything the outer chain resolved —
 * `c.get("auth")` from `contractAuth`, the merged quota windows from
 * `rateLimit()` — is invisible on the other side of that call unless something
 * carries it across (`src/inference/identity.ts`).
 *
 * When nothing did, the failure was silent in the worst possible way. Every
 * other suite in `test/inference/` drives `createInferenceRouter` directly and
 * INJECTS its own `caller`, so all of them passed while the deployed Worker
 * resolved `defaultCallerResolver` — a PLATFORM OPERATOR with no model
 * allow/deny list — for every real request. Three Rust gates were dead:
 *
 *   1. `AuthContext::can_use_model` → 403 `model_not_allowed`;
 *   2. the tenant model-visibility filter (issue #515) on BOTH `GET /v1/models`
 *      and invocation — `scopeCanSeeModel` returns `true` unconditionally for a
 *      platform operator, so one tenant could list and invoke another tenant's
 *      private logical model;
 *   3. `try_consume_api_key_tokens_per_minute` (Rust step 5) — the TPM window,
 *      which `enforceTokensPerMinute` could not see and no handler called.
 *
 * So every assertion below drives the REAL `createGatewayApp` composition with
 * the REAL `contractAuth` guard and the REAL `rateLimit()` middleware. Deleting
 * the `publishRequestScope(c)` line in `src/inference/route-module.ts` — the
 * single line that carries the outer context across — turns this file red and
 * leaves the rest of the suite green. That is the property being bought.
 */
import type { MiddlewareHandler } from "hono";
import { describe, expect, it } from "vitest";
import {
  InMemoryModelResolver,
  estimateChatCompletionUsage,
  inferenceRouteModule,
} from "../../src/inference/index.js";
import type { GatewayEnv } from "../../src/ports.js";
import { InMemoryRateLimiter, rateLimit } from "../../src/ratelimit/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { ALL_ROUTES, TENANT_PRIVATE_ROUTE, errorBody, fixedRequestIds } from "./fixtures.js";
import { interceptProviderFetch } from "./provider-mock.js";

const BASE = "https://gw.test";
const CHAT = `${BASE}/v1/chat/completions`;
const MODELS = `${BASE}/v1/models`;

/**
 * Credentials the real `contractAuth` guard resolves.
 *
 * `fg_other_tenant` belongs to `tenant_b` and lists NO scopes: an empty durable
 * scope set grants every data-plane scope (and no `admin.*` one), so it passes
 * the contract scope check for all six inference operations while still being
 * tenant-confined. That is exactly the credential shape the #515 gate governs.
 */
const NATIVE_KEYS = JSON.stringify([
  { key: "fg_other_tenant", id: "key_other", tenant_id: "tenant_b", scopes: [] },
  { key: "fg_acme", id: "key_acme", tenant_id: TENANT_PRIVATE_ROUTE.tenantId, scopes: [] },
]);

/** One operator-authored static key ⇒ platform operator, the contrast case. */
const STATIC_KEYS = JSON.stringify([{ key: "fg_root", id: "key_root", platform_operator: true }]);

const BASE_ENV = {
  GATEWAY_NATIVE_API_KEYS: NATIVE_KEYS,
  GATEWAY_STATIC_API_KEYS: STATIC_KEYS,
};

function gateway(
  env: Record<string, string> = {},
  middleware: readonly MiddlewareHandler<GatewayEnv>[] = [],
) {
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver(ALL_ROUTES),
        requestIds: fixedRequestIds,
      }),
    ],
    middleware,
  });
  const fullEnv = { ...BASE_ENV, ...env };
  return (url: string, init?: RequestInit) => app.request(url, init, fullEnv);
}

function bearer(key: string): Record<string, string> {
  return { authorization: `Bearer ${key}`, "content-type": "application/json" };
}

// ---------------------------------------------------------------------------
// 1. The caller is the AUTHENTICATED caller (issue #515)
// ---------------------------------------------------------------------------

describe('the mounted module derives its caller from c.get("auth")', () => {
  it("hides another tenant's private model from GET /v1/models", async () => {
    const call = gateway();
    const res = await call(MODELS, { headers: bearer("fg_other_tenant") });

    expect(res.status).toBe(200);
    const listing = (await res.json()) as { data: { id: string }[] };
    const ids = listing.data.map((model) => model.id);
    // The catalog IS reachable — the filter is a filter, not an empty answer.
    expect(ids).toContain("gpt-4o-mini");
    // …but `acme-private` belongs to tenant `acme`, and this key is `tenant_b`.
    expect(ids).not.toContain("acme-private");
  });

  it("shows the owning tenant its own private model", async () => {
    const call = gateway();
    const res = await call(MODELS, { headers: bearer("fg_acme") });

    const listing = (await res.json()) as { data: { id: string }[] };
    expect(listing.data.map((model) => model.id)).toContain("acme-private");
  });

  it("still shows a platform operator everything", async () => {
    const call = gateway();
    const res = await call(MODELS, { headers: bearer("fg_root") });

    const listing = (await res.json()) as { data: { id: string }[] };
    expect(listing.data.map((model) => model.id)).toContain("acme-private");
  });

  it("refuses INVOCATION of another tenant's private model as model_not_found", async () => {
    // The listing filter and the invocation gate MUST agree: a foreign tenant
    // that GUESSES the logical name learns nothing from the refusal, and no
    // request is dispatched. `interceptProviderFetch` throws on any outbound
    // call, so a dispatch would fail the test rather than pass it quietly.
    const provider = interceptProviderFetch(() => undefined);
    try {
      const call = gateway();
      const res = await call(CHAT, {
        method: "POST",
        headers: bearer("fg_other_tenant"),
        body: JSON.stringify({ model: "acme-private", messages: [{ role: "user", content: "x" }] }),
      });

      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.code).toBe("model_not_found");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Rust step 5 — tokens per minute — is actually enforced
// ---------------------------------------------------------------------------

/**
 * `tenant_b` gets a TPM limit of 600 and a generous RPM, so only the TOKEN
 * window can produce a 429.
 *
 * The estimate for the request below is the 512-token default completion
 * reservation plus a small prompt, i.e. ~516: the first request fits inside
 * 600, the second cannot. If the estimate were not charged at all — or charged
 * as zero — both would pass.
 */
const TPM_ENV = {
  GATEWAY_QUOTA_POLICIES: JSON.stringify([
    { scope_type: "tenant", scope_id: "tenant_b", rpm_limit: 1000, tpm_limit: 600 },
  ]),
};

const CHAT_BODY = JSON.stringify({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "hello" }],
});

function okChatCompletion(): Response {
  return new Response(
    JSON.stringify({
      id: "chatcmpl-1",
      object: "chat.completion",
      choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }],
      usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

describe("the mounted module enforces the resolved TPM window", () => {
  it("refuses the second request with the Rust 429 tpm_limit_exceeded", async () => {
    const provider = interceptProviderFetch(() => okChatCompletion());
    try {
      const call = gateway(TPM_ENV, [rateLimit({ limiter: new InMemoryRateLimiter() })]);
      const post = () =>
        call(CHAT, { method: "POST", headers: bearer("fg_other_tenant"), body: CHAT_BODY });

      const first = await post();
      expect(first.status).toBe(200);

      const second = await post();
      expect(second.status).toBe(429);
      const body = await errorBody(second);
      expect(body.error.code).toBe("tpm_limit_exceeded");
      // Rust `server/chat.rs`'s message, verbatim.
      expect(body.error.message).toBe(
        "quota policy tokens-per-minute limit is exhausted for this request",
      );
      expect(body.error.type).toBe("ferrogate_error");

      // The refusal happened BEFORE dispatch — the whole point of a
      // pre-dispatch gate is not paying a provider for a request it refuses.
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });

  it("tells the caller how big the TOKEN window is and what is left of it (#726)", async () => {
    // The TPM refusal is the one place where "remaining" is NOT trivially zero:
    // `TokenWindow.tryConsume` refuses on `used + estimate > limit`, so a
    // refused caller can still have real headroom — just not enough for THIS
    // request. Emitting a constant `0` here (the shape a presence-only test
    // cannot tell apart) would tell a client with 84 tokens left that it has
    // none, and it would stop sending the small requests that still fit.
    const provider = interceptProviderFetch(() => okChatCompletion());
    try {
      const call = gateway(TPM_ENV, [rateLimit({ limiter: new InMemoryRateLimiter() })]);
      const post = () =>
        call(CHAT, { method: "POST", headers: bearer("fg_other_tenant"), body: CHAT_BODY });

      expect((await post()).status).toBe(200);
      const denied = await post();
      expect(denied.status).toBe(429);

      // The window's own configured cap, not the RPM one (1000) and not a
      // constant: `GATEWAY_QUOTA_POLICIES` above says 600.
      expect(denied.headers.get("x-ratelimit-limit-tokens")).toBe("600");
      // Exactly what the first request left behind. The estimator is imported
      // rather than a number being pinned, so this stays true if the default
      // completion reservation changes — and stays FALSE for any implementation
      // that reports a constant.
      const charged = estimateChatCompletionUsage(JSON.parse(CHAT_BODY), "gpt-4o-mini")
        .totalTokens;
      expect(charged).toBeGreaterThan(0);
      expect(denied.headers.get("x-ratelimit-remaining-tokens")).toBe(String(600 - charged));

      const retryAfter = Number(denied.headers.get("retry-after"));
      expect(retryAfter).toBeGreaterThan(0);
      expect(retryAfter).toBeLessThanOrEqual(60);
      expect(denied.headers.get("x-ratelimit-reset-tokens")).toBe(`${retryAfter}s`);
      // The REQUESTS dimension is untouched: this window did not refuse, and
      // reporting it would be inventing a number.
      expect(denied.headers.get("x-ratelimit-limit-requests")).toBeNull();
    } finally {
      provider.restore();
    }
  });

  it("does not charge TPM for a request the model gate already refused", async () => {
    // Rust checks TPM inside the provider-attempt loop, i.e. AFTER route
    // resolution. An unknown model must not burn a minute's worth of tokens.
    const provider = interceptProviderFetch(() => okChatCompletion());
    try {
      const call = gateway(TPM_ENV, [rateLimit({ limiter: new InMemoryRateLimiter() })]);
      const unknown = await call(CHAT, {
        method: "POST",
        headers: bearer("fg_other_tenant"),
        body: JSON.stringify({
          model: "no-such-model",
          messages: [{ role: "user", content: "x" }],
        }),
      });
      expect(unknown.status).toBe(400);
      expect((await errorBody(unknown)).error.code).toBe("model_not_found");

      // The window is untouched, so a real request still succeeds.
      const real = await call(CHAT, {
        method: "POST",
        headers: bearer("fg_other_tenant"),
        body: CHAT_BODY,
      });
      expect(real.status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it("settles the reservation against real usage when settlement is opted in", async () => {
    // The reservation/settlement split, end to end. The ESTIMATE is ~516 (the
    // 512 default completion reservation plus a small prompt), so under Rust
    // semantics — reserve only, never settle — the 600-token window is spent
    // after the second request, which the test above asserts.
    //
    // With `settleTokens: true` the same window absorbs many more, because each
    // response reports 5 REAL tokens and the estimate is swapped for that.
    // Five requests would be ~2580 reserved and only ~25 settled.
    const provider = interceptProviderFetch(() => okChatCompletion());
    try {
      const call = gateway(TPM_ENV, [
        rateLimit({ limiter: new InMemoryRateLimiter(), settleTokens: true }),
      ]);
      for (let i = 0; i < 5; i += 1) {
        const res = await call(CHAT, {
          method: "POST",
          headers: bearer("fg_other_tenant"),
          body: CHAT_BODY,
        });
        expect(res.status, `request ${i}`).toBe(200);
      }
      expect(provider.requests).toHaveLength(5);
    } finally {
      provider.restore();
    }
  });

  it("leaves a request with no TPM policy ungoverned", async () => {
    // No `GATEWAY_QUOTA_POLICIES` at all ⇒ `tpm_window()` is None ⇒ unlimited,
    // which is the Rust behavior (an absent policy does not deny).
    const provider = interceptProviderFetch(() => okChatCompletion());
    try {
      const call = gateway({}, [rateLimit({ limiter: new InMemoryRateLimiter() })]);
      for (let i = 0; i < 5; i += 1) {
        const res = await call(CHAT, {
          method: "POST",
          headers: bearer("fg_other_tenant"),
          body: CHAT_BODY,
        });
        expect(res.status, `request ${i}`).toBe(200);
      }
    } finally {
      provider.restore();
    }
  });
});
