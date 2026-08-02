/**
 * ONE RPM window across the fleet — issue #666, CUTOVER-READINESS finding B10.
 *
 * ## The defect
 *
 * A virtual key capped at 60 rpm was charged 60 on `apps/gateway` **plus 60 per
 * `apps/mcp` isolate plus 60 per `apps/agent-runtime` isolate**, because the
 * cross-script
 *
 *     [[durable_objects.bindings]]
 *     name = "RATE_LIMIT"
 *     class_name = "RateLimiterDurableObject"
 *     script_name = "ferrogate-gateway"
 *
 * stanza was committed COMMENTED OUT, with "UNCOMMENT AT DEPLOY TIME" above it.
 * The committed tree was therefore the broken configuration, and when a deploy
 * forgot the two lines nothing errored: `counterFromEnv` fell back to the
 * per-isolate `InMemoryRequestCounter` and the tenant quietly got several times
 * the limit they were sold. It failed OPEN, on a control customers pay for, and
 * an agent job spends real provider money.
 *
 * ## What makes this suite able to see it
 *
 * `vitest.config.ts` now registers an AUXILIARY WORKER named
 * `ferrogate-gateway` carrying the gateway's real `RateLimiterDurableObject`
 * (`apps/gateway/test/support/rate-limit-aux-worker.ts`), so workerd can
 * resolve the `script_name` offline and the stanza is committed LIVE.
 *
 * `test/admission.test.ts` already proves this Worker refuses at its own cap.
 * That is a different property and it stayed green throughout the defect. What
 * is asserted here is that the window it charges is the GATEWAY'S — the counter
 * is charged from outside this Worker, through the binding, exactly as
 * `/v1/chat/completions` charges it, and this Worker is then required to find
 * it spent.
 *
 * ## What it does NOT prove
 *
 * That the `ferrogate-gateway` script deployed to Cloudflare is that source, or
 * that it was deployed first. Neither is provable offline — but both now fail
 * the DEPLOY loudly, because `wrangler deploy` rejects a `script_name` binding
 * whose target script does not exist. That refusal is the deploy-time assertion
 * issue #666 asked for in place of a comment.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import {
  DurableObjectRequestCounter,
  counterFromEnv,
  perKeyCounterKey,
} from "../src/admission/index.js";
import { bearer, get, post } from "./fixtures.js";

/** The cross-script namespace, as narrowly as this file needs it. */
interface RateLimitBinding {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): { consumeRequest(limit: number): Promise<{ allowed: boolean }> };
}

/**
 * Charge one request against a counter key THROUGH THE BINDING — i.e. do
 * precisely what `apps/gateway` does when the same credential calls
 * `/v1/chat/completions`.
 */
async function chargeAsGateway(counterKey: string, limit: number): Promise<boolean> {
  const namespace = (env as unknown as { RATE_LIMIT?: RateLimitBinding }).RATE_LIMIT;
  if (namespace === undefined) {
    // Named rather than left as a `TypeError`, because this exact absence IS
    // the defect: an unbound RATE_LIMIT is the per-Worker quota multiplier.
    throw new Error(
      "RATE_LIMIT is not bound on apps/agent-runtime — the cross-script gateway counter is missing (#666)",
    );
  }
  const result = await namespace.get(namespace.idFromName(counterKey)).consumeRequest(limit);
  return result.allowed;
}

/** `POST /v1/agent-jobs` — the money-spending verb the bypass reached. */
async function submit(key: string): Promise<Response> {
  return await post("/v1/agent-jobs", bearer(key), {
    input: "write the patch",
    required_capabilities: ["coding"],
  });
}

async function codeOf(response: Response): Promise<string> {
  const body = (await response.json()) as { error?: { code?: string } };
  return body.error?.code ?? "";
}

describe("the committed config binds the gateway's counter, not a private one", () => {
  it("resolves env.RATE_LIMIT from the cross-script stanza", () => {
    // The whole defect in one assertion: with the stanza commented out (its
    // state before #666) this binding is `undefined` on every isolate.
    expect(
      (env as unknown as { RATE_LIMIT?: unknown }).RATE_LIMIT,
      "apps/agent-runtime/wrangler.toml is not binding RATE_LIMIT cross-script",
    ).toBeDefined();
  });

  it("mounts the DURABLE counter, never the per-isolate fallback", () => {
    // `counterFromEnv` is what `src/admission/admit.ts` calls on every request,
    // and it probes for the RPC surface before using the binding — so this also
    // asserts the resolved namespace really answers `idFromName`/`get`.
    expect(counterFromEnv(env)).toBeInstanceOf(DurableObjectRequestCounter);
  });
});

describe("a window spent on apps/gateway is already spent on apps/agent-runtime", () => {
  it("REFUSES the first agent job when the gateway already used the only slot", async () => {
    // `sk-shared-rpm-spent` carries `requestLimitPerMinute: 1`.
    expect(await chargeAsGateway(perKeyCounterKey("key-shared-rpm-spent"), 1)).toBe(true);

    // Under the per-isolate fallback this is a 202: this Worker's Map has never
    // heard of the credential, which is the "call the other endpoint" bypass
    // priced in money.
    const refused = await submit("sk-shared-rpm-spent");
    expect(refused.status).toBe(429);
    expect(await codeOf(refused)).toBe("rate_limit_exceeded");
  });

  it("charges the SAME instance in the other direction — the job spends the gateway's window", async () => {
    // `sk-shared-rpm-split` carries `requestLimitPerMinute: 2`.
    const admitted = await submit("sk-shared-rpm-split");
    expect(admitted.status).toBe(202);

    // One of the two slots is gone, so the gateway gets exactly one more. If
    // this Worker had counted in its own namespace, BOTH would be allowed.
    const counterKey = perKeyCounterKey("key-shared-rpm-split");
    expect(await chargeAsGateway(counterKey, 2)).toBe(true);
    expect(await chargeAsGateway(counterKey, 2)).toBe(false);
  });

  it("keeps separate credentials on separate instances", async () => {
    // The negative control. Sharing one NAMESPACE must not mean sharing one
    // WINDOW: a collision here would let any tenant drain another's budget.
    // `sk-shared-rpm-spent`'s slot was consumed above; this credential's is not.
    const read = await get("/v1/agent-jobs/job-does-not-exist", bearer("sk-shared-rpm-untouched"));
    expect(read.status).toBe(404);
  });
});
