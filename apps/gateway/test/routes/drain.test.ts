/**
 * `503 node_draining` — cutover finding **D6**, through the DEPLOYED Worker.
 *
 * The finding, verbatim: *"`GATEWAY_DRAIN=true` flips `/readyz` to 503 and
 * leaves `/v1/chat/completions` serving normally, so an operator draining a
 * deployment before a migration still takes new billable traffic."*
 * `grep -rn "node_draining" apps/` returned nothing.
 *
 * In Rust the SAME flag `/readyz` reads is re-checked per AI request by
 * `plan_ai_ingress` and by four sibling handlers — `chat.rs:2862`,
 * `embeddings.rs:98`, `images.rs:115`, `messages.rs:145`,
 * `governed_decision.rs:502` — each refusing
 * `503 node_draining "gateway node is draining and is not accepting new AI
 * requests"`.
 *
 * Everything below goes through `SELF.fetch`, i.e. `src/worker.ts` →
 * `src/index.ts` → `createGatewayApp`, because the gate is mounted inside
 * `createGatewayApp` and a gate that exists but is not on the deployed app is
 * the defect this project keeps re-discovering. `env` from `cloudflare:test` is
 * the same object the Worker reads.
 *
 * Three properties are asserted, not one:
 *
 *  1. the flag REFUSES the five spend-producing operations, with Rust's exact
 *     status, code and message;
 *  2. it is re-read PER REQUEST — the same isolate flips both ways — which is
 *     the half a module-scope `const draining = …` would silently break;
 *  3. it refuses NOTHING else. A drain that also 503'd `/healthz` would take
 *     the node out of rotation for the wrong reason, and one that 503'd
 *     `/v1/models` would refuse a read that spends nothing.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";
import { DRAIN_VAR } from "../../src/routes/readiness.js";

const BASE = "https://gw.test";
const mutable = env as unknown as Record<string, unknown>;
/** Operator-authored static key with no scope list ⇒ every scope. */
const ROOT = { authorization: "Bearer fg_root", "content-type": "application/json" } as const;

afterEach(() => {
  delete mutable[DRAIN_VAR];
});

/** The five operations Rust re-checks the drain flag on. */
const AI_ROUTES = [
  ["createChatCompletion", "/v1/chat/completions"],
  ["createResponse", "/v1/responses"],
  ["createMessage", "/v1/messages"],
  ["createEmbedding", "/v1/embeddings"],
  ["createImage", "/v1/images/generations"],
] as const;

interface Envelope {
  error: { message: string; code: string };
}

async function envelope(res: Response): Promise<Envelope["error"]> {
  return ((await res.json()) as Envelope).error;
}

function postAi(path: string): Promise<Response> {
  // A deliberately INVALID body: it is what makes the ordering assertion
  // meaningful. Undrained this is `400 invalid_request` from the inference
  // module's own Zod chain, so a drained `503 node_draining` proves the gate
  // ran BEFORE the body was ever examined — which is where Rust puts it.
  return SELF.fetch(`${BASE}${path}`, { method: "POST", headers: ROOT, body: "{}" });
}

describe("GATEWAY_DRAIN refuses new AI requests", () => {
  it("answers 503 node_draining on all five spend-producing operations", async () => {
    mutable[DRAIN_VAR] = "true";
    for (const [operationId, path] of AI_ROUTES) {
      const res = await postAi(path);
      expect(res.status, operationId).toBe(503);
      const error = await envelope(res);
      expect(error.code, operationId).toBe("node_draining");
      // Rust's message, verbatim — an operator greps for it.
      expect(error.message, operationId).toBe(
        "gateway node is draining and is not accepting new AI requests",
      );
    }
  });

  it("refuses BEFORE the request body is validated", async () => {
    // The negative control for the case above: undrained, the very same
    // request is the inference module's `400 invalid_request`.
    for (const [operationId, path] of AI_ROUTES) {
      const res = await postAi(path);
      expect(res.status, operationId).toBe(400);
      expect((await envelope(res)).code, operationId).toBe("invalid_request");
    }
  });

  it("re-reads the flag PER REQUEST, not once at boot", async () => {
    // The property `drainStatus(env)` being a pure env read buys, and the one a
    // memoised `const draining` would destroy without failing anything else.
    // Same isolate, same Worker instance, three requests.
    expect((await postAi("/v1/chat/completions")).status).toBe(400);
    mutable[DRAIN_VAR] = "true";
    expect((await postAi("/v1/chat/completions")).status).toBe(503);
    delete mutable[DRAIN_VAR];
    expect((await postAi("/v1/chat/completions")).status).toBe(400);
  });

  it("uses the SAME flag /readyz uses, with the same parsing", async () => {
    // One flag, one spelling rule. `/readyz` accepts only the exact (trimmed,
    // case-folded) `"true"`, and a typo must not half-drain a deployment —
    // refusing traffic while still reporting ready, or the reverse.
    for (const value of ["false", "1", "yes", "", "  "]) {
      mutable[DRAIN_VAR] = value;
      expect((await SELF.fetch(`${BASE}/readyz`)).status, value).toBe(200);
      expect((await postAi("/v1/chat/completions")).status, value).toBe(400);
    }
    for (const value of ["true", "TRUE", " true "]) {
      mutable[DRAIN_VAR] = value;
      expect((await SELF.fetch(`${BASE}/readyz`)).status, value).toBe(503);
      expect((await postAi("/v1/chat/completions")).status, value).toBe(503);
    }
  });
});

describe("GATEWAY_DRAIN refuses nothing else", () => {
  it("leaves /healthz and /v1/models serving while drained", async () => {
    mutable[DRAIN_VAR] = "true";

    // Liveness is not readiness: a draining node is still alive, and Rust's
    // `handle_healthz` has no drain branch at all.
    const health = await SELF.fetch(`${BASE}/healthz`);
    expect(health.status).toBe(200);
    expect(((await health.json()) as { status: string }).status).toBe("ok");

    // `listModels` is the sixth inference operation and is NOT one of the five
    // Rust guards: it spends nothing, so draining must not refuse it.
    const models = await SELF.fetch(`${BASE}/v1/models`, { headers: ROOT });
    expect(models.status).toBe(200);
  });

  it("leaves the tooling and asset surfaces on their own ladders", async () => {
    mutable[DRAIN_VAR] = "true";
    // `/v1/tools` is the gateway's documented 501 and must stay it — a drain
    // that swallowed every route would hide exactly that kind of divergence.
    const tools = await SELF.fetch(`${BASE}/v1/tools`, { headers: ROOT });
    expect(tools.status).toBe(501);

    // ...and an asset read is refused by the asset service, not by the drain.
    const assets = await SELF.fetch(`${BASE}/v1/assets`, { headers: ROOT });
    expect(assets.status).not.toBe(503);
  });

  it("still refuses an UNAUTHENTICATED AI request as 401, not 503", async () => {
    // Ordering that matters for the same reason the 7-step ingress order
    // matters: a drained node must not become an oracle that tells an
    // anonymous caller anything about its own posture.
    mutable[DRAIN_VAR] = "true";
    const res = await SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(res.status).toBe(401);
    expect((await envelope(res)).code).toBe("missing_api_key");
  });
});
