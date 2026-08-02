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
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applyControlMigrations, resetRequestLogs, storedRequestLogs } from "./harness.js";

beforeAll(applyControlMigrations);
beforeEach(resetRequestLogs);

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
 */
async function awaitRow(budgetMs = 20000): Promise<Awaited<ReturnType<typeof storedRequestLogs>>> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    const rows = await storedRequestLogs();
    if (rows.length > 0) return rows;
    if (Date.now() >= deadline) return rows;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("an unhandled failure is still recorded", () => {
  it(
    "answers the envelope AND lands a request_logs row",
    async () => {
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
    },
    30_000,
  );
});
