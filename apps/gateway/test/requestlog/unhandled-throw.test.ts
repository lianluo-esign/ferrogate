/**
 * The #664 evidence row on the #733 failure path.
 *
 * "An outage where the client got a malformed 500 and the log recorded nothing
 * is two failures." `requestLogging()` writes its row AFTER `await next()`
 * (`src/requestlog/middleware.ts:195`), so whether a row exists for an
 * unhandled failure depends entirely on whether that failure comes back as a
 * RESPONSE or as a THROW — and that is precisely what #733 changes. Asserting
 * it rather than assuming it is the whole point of this file.
 *
 * Driven through `SELF.fetch`, i.e. through `export default app` in
 * `src/index.ts`, which is the module `wrangler deploy` ships. A unit-composed
 * app would prove the middleware and say nothing about the deployed Worker.
 *
 * The trigger is the issue's own reproduction: a request body nested deep
 * enough to exhaust the stack while the pre-dispatch token estimate walks it
 * (`src/inference/estimate.ts::promptCharacterCount` is recursive). Depth is
 * ESCALATED rather than pinned because the exact threshold is a workerd/V8
 * implementation detail; if none of them overflows any more the case fails
 * loudly and asks to be re-derived.
 */
import { SELF, createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { inferenceRouteModule } from "../../src/inference/index.js";
import type { ModelResolver } from "../../src/inference/index.js";
import {
  createRequestLogSink,
  requestLogBindingsFromEnv,
  requestLogging,
} from "../../src/requestlog/index.js";
import { requestLogFromWire } from "../../src/requestlog/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import {
  RecordingQueue,
  applyControlMigrations,
  resetPlatformRequestLogs,
  storedPlatformRequestLogs,
} from "./harness.js";

beforeAll(applyControlMigrations);
beforeEach(async () => {
  // 0045 (Track A) DROPPED the control `request_logs` mirror; the platform
  // object is the sole authoritative home for these unattributed rows.
  await resetPlatformRequestLogs();
});

/** A body whose `messages[0].content` is `depth` nested arrays. */
function nestedBody(depth: number): string {
  let content: unknown = "x";
  for (let i = 0; i < depth; i += 1) content = [content];
  return JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content }] });
}

/**
 * Poll for the row. `SELF.fetch` resolves when the RESPONSE is flushed and the
 * durable write is deliberately after that; the pool runs the real queue, whose
 * `max_batch_timeout` is 5 seconds. See `mount.test.ts::awaitRow`.
 *
 * The request is authenticated as `fg_root`, a `platform_operator` key, so its
 * row is UNATTRIBUTED and — post-G2 (`projectRequestLogToControl: false`) —
 * authoritative in the PLATFORM_DATA object, never in the (frozen, DROP-bound)
 * control projection. So the poll reads the platform object.
 */
async function awaitRow(
  budgetMs = 20000,
): Promise<Awaited<ReturnType<typeof storedPlatformRequestLogs>>> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    const rows = await storedPlatformRequestLogs();
    if (rows.length > 0) return rows;
    if (Date.now() >= deadline) return rows;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("an unhandled failure is still recorded", () => {
  it("answers the envelope AND lands a request_logs row", async () => {
    let response: Response | undefined;
    for (const depth of [20_000, 80_000, 320_000]) {
      const candidate = await SELF.fetch("https://gw.test/v1/chat/completions", {
        method: "POST",
        headers: { authorization: "Bearer fg_root", "content-type": "application/json" },
        body: nestedBody(depth),
      });
      if (candidate.status === 500) {
        response = candidate;
        break;
      }
    }
    expect(response, "no nesting depth produced a 500 — re-derive this case").toBeDefined();
    const res = response as Response;

    // Leg 1 — the client gets the documented envelope, not `text/plain`.
    expect(res.headers.get("content-type")).toContain("application/json");
    const body = (await res.json()) as {
      error: { code: string; type: string; request_id: string };
    };
    expect(body.error.type).toBe("ferrogate_error");
    expect(body.error.code).toBe("internal_error");

    // Leg 2 — and the outage is in the durable trail, keyed by the id the
    // client was told. A malformed 500 with no row is two failures.
    const rows = await awaitRow();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status_code).toBe(500);
    expect(rows[0]?.request_id).toBe(res.headers.get("x-request-id"));
    expect(rows[0]?.error_code).toBe("internal_error");
  }, 30_000);
});

// ---------------------------------------------------------------------------
// The value Hono will not route to `onError` — and why the boundary is mounted
// LOW as well as high
// ---------------------------------------------------------------------------

/**
 * The env for the composed case, with a `RecordingQueue` behind
 * `REQUEST_LOG`.
 *
 * The SINK is the real `createRequestLogSink(requestLogBindingsFromEnv)` —
 * exactly what `src/index.ts` mounts — so the assertion below reads what the
 * production writer actually produced, not what a double was told. Only the
 * Queue binding is a recorder, which is the shape `write.test.ts` uses.
 */
function envWith(queue: RecordingQueue): Record<string, unknown> {
  return {
    ...(env as unknown as Record<string, unknown>),
    TENANT_DATA: env.TENANT_DATA,
    REQUEST_LOG: queue,
    GATEWAY_STATIC_API_KEYS: JSON.stringify([
      { key: "fg_root", id: "key_root", platform_operator: true },
    ]),
  };
}

describe("a throw Hono refuses to route still reaches the request log", () => {
  it("records a 500 row for a thrown LITERAL", async () => {
    // A thrown non-`Error` is the case Hono's `compose` rethrows rather than
    // handing to `onError`, so it escapes the inner inference app AND the route
    // handler. Only a `try`/`catch` in the outer chain turns it back into a
    // `Response` — and only one mounted BELOW `requestLogging()` does so inside
    // that middleware's `await next()` window.
    //
    // THE GATE: delete the second `app.use("*", envelopeBoundary)` in
    // `src/routes/index.ts` (the one immediately above the routes) and the
    // client still gets a correct envelope from the outer mount while this
    // assertion goes red — the client sees an outage and the #664 trail records
    // nothing, which is the two-failure shape this issue names.
    const queue = new RecordingQueue();
    const { app } = createGatewayApp({
      modules: [
        inferenceRouteModule({
          models: (() => {
            throw "provider catalog is a literal, not an Error";
          }) as () => ModelResolver,
        }),
      ],
      middleware: [requestLogging(createRequestLogSink(requestLogBindingsFromEnv))],
    });

    const ctx = createExecutionContext();
    const res = await app.fetch(
      new Request("https://gw.test/v1/chat/completions", {
        method: "POST",
        headers: { authorization: "Bearer fg_root", "content-type": "application/json" },
        body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] }),
      }),
      envWith(queue),
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(500);
    expect((await res.json()) as unknown).toMatchObject({
      error: { type: "ferrogate_error", code: "internal_error" },
    });

    // Decoded with the SAME `requestLogFromWire` the queue consumer uses, so
    // the assertion is on a row that would really have landed in D1.
    expect(queue.sent).toHaveLength(1);
    const record = requestLogFromWire(queue.sent[0]);
    expect(record?.statusCode).toBe(500);
    expect(record?.requestId).toBe(res.headers.get("x-request-id"));
    expect(record?.errorCode).toBe("internal_error");
  });
});
