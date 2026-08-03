/**
 * Shared fixtures for the inference tests: a small model catalog and a router
 * builder wired to the in-memory ports.
 *
 * Nothing here mocks the code under test. `InMemoryModelResolver` and
 * `InMemoryUsageSink` are the shipped default implementations of the
 * `ModelResolver`/`UsageSink` ports (`src/inference/defaults.ts`) — the same
 * objects a production deployment gets until `@ferrogate/routing` and
 * `@ferrogate/billing` are adapted onto the seams. Only the OUTBOUND provider
 * `fetch` is intercepted (see `provider-mock.ts`).
 */
import { Hono } from "hono";
import {
  InMemoryModelResolver,
  InMemoryUsageSink,
  createInferenceRouter,
  responseStateCommit,
} from "../../src/inference/index.js";
import type {
  Caller,
  InferenceDeps,
  PhysicalRoute,
  RequestIdFactory,
} from "../../src/inference/index.js";

/** Deterministic request ids so envelope assertions can be exact. */
export const fixedRequestIds: RequestIdFactory = {
  next: () => "fg-000000000000002a",
};

export const OPENAI_ROUTE: PhysicalRoute = {
  logicalModel: "gpt-4o-mini",
  provider: "openai-main",
  providerModel: "gpt-4o-mini-2024-07-18",
  providerKind: "openai",
  baseUrl: "https://api.openai.example/v1/",
  apiKey: "sk-test-openai",
  enabled: true,
};

export const ANTHROPIC_ROUTE: PhysicalRoute = {
  logicalModel: "claude-logical",
  provider: "anthropic-main",
  providerModel: "claude-3-5-sonnet-20241022",
  providerKind: "anthropic",
  baseUrl: "https://api.anthropic.example/v1",
  apiKey: "sk-test-anthropic",
  enabled: true,
};

export const EMBEDDINGS_ROUTE: PhysicalRoute = {
  logicalModel: "text-embed",
  provider: "openai-main",
  providerModel: "text-embedding-3-small",
  providerKind: "openai-compatible",
  baseUrl: "https://api.openai.example/v1",
  apiKey: "sk-test-openai",
  enabled: true,
};

export const IMAGES_ROUTE: PhysicalRoute = {
  logicalModel: "image-model",
  provider: "openai-main",
  providerModel: "dall-e-3",
  providerKind: "openai",
  baseUrl: "https://api.openai.example/v1",
  apiKey: "sk-test-openai",
  enabled: true,
};

/** A model that exists but is switched off → `model_disabled`, not `model_not_found`. */
export const DISABLED_ROUTE: PhysicalRoute = {
  logicalModel: "retired-model",
  provider: "openai-main",
  providerModel: "gpt-3.5-turbo",
  providerKind: "openai",
  baseUrl: "https://api.openai.example/v1",
  enabled: false,
};

/** A model private to tenant `acme` (issue #515 listing/invocation agreement). */
export const TENANT_PRIVATE_ROUTE: PhysicalRoute = {
  logicalModel: "acme-private",
  provider: "openai-main",
  providerModel: "gpt-4o",
  providerKind: "openai",
  baseUrl: "https://api.openai.example/v1",
  enabled: true,
  tenantId: "acme",
};

export const ALL_ROUTES: readonly PhysicalRoute[] = [
  OPENAI_ROUTE,
  ANTHROPIC_ROUTE,
  EMBEDDINGS_ROUTE,
  IMAGES_ROUTE,
  DISABLED_ROUTE,
  TENANT_PRIVATE_ROUTE,
];

export interface TestHarness {
  /**
   * The inference router as the gateway MOUNTS it: `responseStateCommit()`
   * wrapping `createInferenceRouter(...)`. See {@link harness}.
   */
  readonly router: Hono<{ Bindings: Record<string, unknown> }>;
  readonly usage: InMemoryUsageSink;
  /** POST a JSON body to an inference path. */
  post(path: string, body: unknown, init?: RequestInit): Promise<Response>;
  /** GET an inference path. */
  get(path: string, init?: RequestInit): Promise<Response>;
}

/**
 * Build a router over {@link ALL_ROUTES} (or a supplied catalog).
 *
 * ## Why the inner router is WRAPPED rather than driven directly (issue #689)
 *
 * `/v1/responses` conversation state is written by `responseStateCommit()`, a
 * middleware that sits ABOVE the guardrail response stage precisely so the bytes
 * it files are the bytes the client receives (`src/inference/conversation-commit.ts`).
 * A harness that called `createInferenceRouter(...)` alone would drive a request
 * path from which the write is missing, so every storing test would either fail
 * or — the worse outcome — be quietly rewritten to assert less.
 *
 * The wrapper is the production composition minus screening: the same
 * middleware, in the same relative position, delegating into the same inner app
 * through the same `inner.fetch(c.req.raw, …)` call `route-module.ts` makes. It
 * is transparent to every operation that is not a storing `/v1/responses` call —
 * one `WeakMap` lookup after `next()`.
 *
 * `env` reaches the inner app's `depsFor(c.env)`, which is what lets a test pin
 * an env-configured policy (`GATEWAY_RESPONSES_STORE`,
 * `GATEWAY_RESPONSES_RETENTION`) instead of injecting past it.
 */
export function harness(
  overrides: InferenceDeps = {},
  routes: readonly PhysicalRoute[] = ALL_ROUTES,
  env: Record<string, unknown> = {},
): TestHarness {
  const usage = new InMemoryUsageSink();
  const inner = createInferenceRouter({
    models: new InMemoryModelResolver(routes),
    usage,
    requestIds: fixedRequestIds,
    ...overrides,
  });
  const router = new Hono<{ Bindings: Record<string, unknown> }>();
  router.use("*", responseStateCommit());
  // The same delegation `src/inference/route-module.ts` performs, including the
  // `c.req.raw` identity the pending-turn carrier is keyed by.
  router.all("*", (c) => inner.fetch(c.req.raw, c.env as Parameters<typeof inner.fetch>[1]));

  return {
    router,
    usage,
    async post(path, body, init): Promise<Response> {
      return await router.request(
        `https://gw.test${path}`,
        {
          ...(init ?? {}),
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...((init?.headers as Record<string, string> | undefined) ?? {}),
          },
          body: typeof body === "string" ? body : JSON.stringify(body),
        },
        env,
      );
    },
    async get(path, init): Promise<Response> {
      return await router.request(
        `https://gw.test${path}`,
        { method: "GET", ...(init ?? {}) },
        env,
      );
    },
  };
}

/** A tenant-scoped caller (`CallerScope::Tenant`). */
export function tenantCaller(tenantId: string, projectId?: string): () => Caller {
  return () => ({
    scope: { kind: "tenant", tenantId },
    ...(projectId !== undefined ? { projectId } : {}),
  });
}

/** A caller whose key denies one model (`AuthContext.denied_models`). */
export function callerDenying(...models: readonly string[]): () => Caller {
  return () => ({ scope: { kind: "platform_operator" }, deniedModels: models });
}

/** Parse a response body as the FerroGate error envelope. */
export async function errorBody(response: Response): Promise<{
  error: { message: string; type: string; code: string; request_id: string | null };
}> {
  return (await response.json()) as {
    error: { message: string; type: string; code: string; request_id: string | null };
  };
}
