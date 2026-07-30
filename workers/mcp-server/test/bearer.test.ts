// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Worker-side coverage for the MCP server's automation-bearer resolution and the
//   route gate in front of it (issue #409). Runs the REAL Worker in workerd via
//   @cloudflare/vitest-pool-workers — no Docker, no Cloudflare account, no network.
//
//   WHY THIS EXISTS: the credential source order (Secrets Store binding first, plain
//   `secret_text` second) and its degradations (store throws / store returns "") had no
//   executable guard. Inverting the precedence, swapping `||` for `??`, or dropping the
//   `Bearer`-prefix gate all left CI green while changing who gets in.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { describe, it, expect } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker, {
  presentsBearer,
  resolveAutomationBearer,
  type Env,
  type SecretsStoreSecretBinding,
} from "../src/index";

/**
 * Observable stand-in for a Cloudflare Secrets Store binding.
 *
 * miniflare has no Secrets Store emulation, and the failure modes under test
 * (an unreachable store, a deleted secret read back as "") cannot be produced on
 * demand from a real one. Counting `reads` is also the only way to assert the
 * negative that matters: an anonymous request must drive NO store read.
 */
class StubStore implements SecretsStoreSecretBinding {
  reads = 0;
  constructor(private readonly outcome: { value: string } | { throws: Error }) {}
  async get(): Promise<string> {
    this.reads += 1;
    if ("throws" in this.outcome) throw this.outcome.throws;
    return this.outcome.value;
  }
}

/** The miniflare-provided bindings (DO + OAuth KV) plus the per-test secret sources. */
function testEnv(overrides: Partial<Env> = {}): Env {
  return { ...(env as unknown as Env), ...overrides };
}

async function fetchWorker(request: Request, workerEnv: Env): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, workerEnv, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

function mcpRequest(authorization?: string): Request {
  return new Request("https://mcp.test/mcp", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(authorization ? { authorization } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  });
}

/**
 * Whether the OAuth provider — not the automation shortcut — answered.
 *
 * The provider rejects an API-route request it cannot authenticate with
 * `401` + `WWW-Authenticate: Bearer realm="OAuth"`. Nothing on the automation
 * path emits that header, so this cleanly separates "turned away at the front
 * door" from "admitted".
 */
async function wentToOAuth(response: Response): Promise<boolean> {
  return (
    response.status === 401 &&
    (response.headers.get("www-authenticate") ?? "").includes('realm="OAuth"')
  );
}

/**
 * Whether the request was admitted and handed to the MCP transport.
 *
 * Asserted POSITIVELY rather than as `!wentToOAuth(...)`: a 500 from any cause
 * would satisfy the negation and read as "the credential was accepted". The
 * observable proof is the transport's own JSON-RPC error — `serve("/mcp")`
 * demands an `Mcp-Session-Id` on a non-initialize POST, and only code past the
 * bearer check can produce it.
 */
async function reachedMcpTransport(response: Response): Promise<boolean> {
  if (response.status !== 400) return false;
  const body = (await response.json()) as { jsonrpc?: string; error?: { message?: string } };
  return body.jsonrpc === "2.0" && (body.error?.message ?? "").includes("Mcp-Session-Id");
}

describe("automation bearer resolution", () => {
  it("prefers the Secrets Store value and ignores the plain secret", async () => {
    const store = new StubStore({ value: "from-store" });
    const workerEnv = testEnv({
      MCP_BEARER_TOKEN_STORE: store,
      MCP_BEARER_TOKEN: "from-plain-secret",
    });

    expect(await resolveAutomationBearer(workerEnv)).toBe("from-store");

    // The precedence is not merely returned, it is what the door honours: the
    // store value is admitted...
    const admitted = await fetchWorker(mcpRequest("Bearer from-store"), workerEnv);
    expect(await reachedMcpTransport(admitted)).toBe(true);

    // ...and the shadowed plain secret is NOT a second valid credential.
    const rejected = await fetchWorker(mcpRequest("Bearer from-plain-secret"), workerEnv);
    expect(await wentToOAuth(rejected)).toBe(true);
  });

  it("falls back to the plain secret when the store read throws", async () => {
    const store = new StubStore({ throws: new Error("secrets store unreachable") });
    const workerEnv = testEnv({
      MCP_BEARER_TOKEN_STORE: store,
      MCP_BEARER_TOKEN: "from-plain-secret",
    });

    expect(await resolveAutomationBearer(workerEnv)).toBe("from-plain-secret");

    const admitted = await fetchWorker(mcpRequest("Bearer from-plain-secret"), workerEnv);
    expect(await reachedMcpTransport(admitted)).toBe(true);
  });

  it("falls back to the plain secret when the store returns an empty value", async () => {
    const store = new StubStore({ value: "" });
    const workerEnv = testEnv({
      MCP_BEARER_TOKEN_STORE: store,
      MCP_BEARER_TOKEN: "from-plain-secret",
    });

    expect(await resolveAutomationBearer(workerEnv)).toBe("from-plain-secret");
    expect(store.reads).toBe(1);

    const admitted = await fetchWorker(mcpRequest("Bearer from-plain-secret"), workerEnv);
    expect(await reachedMcpTransport(admitted)).toBe(true);
  });

  it("has no automation credential when neither binding is present", async () => {
    const workerEnv = testEnv({
      MCP_BEARER_TOKEN_STORE: undefined,
      MCP_BEARER_TOKEN: undefined,
    });

    expect(await resolveAutomationBearer(workerEnv)).toBeUndefined();

    // With no credential to match, /mcp is OAuth-only — it must NOT fall through
    // to the Durable Object.
    const response = await fetchWorker(mcpRequest("Bearer anything-at-all"), workerEnv);
    expect(await wentToOAuth(response)).toBe(true);
  });

  it("treats an empty plain secret as absent rather than as the empty token", async () => {
    const workerEnv = testEnv({ MCP_BEARER_TOKEN_STORE: undefined, MCP_BEARER_TOKEN: "" });

    expect(await resolveAutomationBearer(workerEnv)).toBeUndefined();

    // `Bearer ` with nothing after it would match an empty expected token under a
    // comparison that did not reject the empty credential first.
    const response = await fetchWorker(mcpRequest("Bearer "), workerEnv);
    expect(await wentToOAuth(response)).toBe(true);
  });
});

describe("the Bearer-prefix gate in front of the store read", () => {
  it("performs no store read for a request that presents no credential", async () => {
    const store = new StubStore({ value: "from-store" });
    const workerEnv = testEnv({ MCP_BEARER_TOKEN_STORE: store, MCP_BEARER_TOKEN: undefined });

    const response = await fetchWorker(mcpRequest(), workerEnv);

    // An anonymous caller must not be able to drive an external secret read —
    // nor, therefore, one store-failure log line per anonymous request.
    expect(store.reads).toBe(0);
    expect(await wentToOAuth(response)).toBe(true);
  });

  it("performs no store read for a non-Bearer authorization scheme", async () => {
    const store = new StubStore({ value: "from-store" });
    const workerEnv = testEnv({ MCP_BEARER_TOKEN_STORE: store, MCP_BEARER_TOKEN: undefined });

    await fetchWorker(mcpRequest("Basic dXNlcjpwYXNz"), workerEnv);

    expect(store.reads).toBe(0);
  });

  it("performs no store read on the unauthenticated liveness probe", async () => {
    const store = new StubStore({ value: "from-store" });
    const workerEnv = testEnv({ MCP_BEARER_TOKEN_STORE: store, MCP_BEARER_TOKEN: undefined });

    const response = await fetchWorker(
      new Request("https://mcp.test/healthz", { headers: { authorization: "Bearer from-store" } }),
      workerEnv,
    );

    expect(response.status).toBe(200);
    expect(store.reads).toBe(0);
  });

  it("reads the store exactly once for a request that does present a bearer", async () => {
    const store = new StubStore({ value: "from-store" });
    const workerEnv = testEnv({ MCP_BEARER_TOKEN_STORE: store, MCP_BEARER_TOKEN: undefined });

    await fetchWorker(mcpRequest("Bearer from-store"), workerEnv);

    // One read per bearer-presenting request, deliberately un-memoised so that
    // rotating the secret in the store takes effect without a redeploy.
    expect(store.reads).toBe(1);
  });

  it("classifies authorization headers without allocating a comparison", () => {
    expect(presentsBearer(mcpRequest("Bearer x"))).toBe(true);
    expect(presentsBearer(mcpRequest())).toBe(false);
    expect(presentsBearer(mcpRequest("Basic x"))).toBe(false);
    // Scheme matching is the HTTP-exact one the router uses; "bearer x" is not it.
    expect(presentsBearer(mcpRequest("bearer x"))).toBe(false);
  });
});
