/**
 * MCP-R4 — `app.onError((error, c) => …)` in `createMcpApp`
 * (`apps/mcp/src/routes/index.ts`).
 *
 * ## The hole this closes
 *
 * `docs/rewrite/MOUNT-SEAMS.md` §16.2 recorded this row as NEWLY UNPROVEN in
 * wave 15 and it was still open in wave 18: rewriting the envelope code
 * `"internal_error"` to a marker was GREEN across all 397 MCP tests, and
 * `grep -rn internal_error apps/mcp/test` returned nothing. The 500 envelope
 * this Worker answers with — the one an operator's alerting parses, and the one
 * that must NOT carry the thrown message across the trust boundary — was
 * asserted by no test at all.
 *
 * ## Why the probe route is registered on the DEPLOYED app object
 *
 * The seam lives inside `createMcpApp`, and `src/index.ts` builds the Worker's
 * app by calling exactly that factory (MCP-C3). Rather than construct a second
 * app — the factory-vs-mount confusion that made GW-A1 and CLI-7 fake mounts —
 * this file imports the SAME `app` instance `export default` publishes and
 * attaches one probe route to it. Nothing else in the tree serves that path,
 * and `app.onError` is a hook rather than a route, so attaching a route
 * afterwards does not reorder anything.
 *
 * The request is then driven through `SELF`, i.e. through `src/worker.ts` →
 * `src/index.ts` → this same object, so the 500 asserted below is produced by
 * the handler the deployed Worker installed, not by a copy of it.
 *
 * MUTATION (proved in wave 18): change `"internal_error"` in
 * `src/routes/index.ts`'s `app.onError` to any other code → the first case
 * below is RED. Delete the `app.onError(...)` block → Hono answers its built-in
 * `500 Internal Server Error` as text and all three cases are RED.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../src/index.js";

const BASE = "https://ferrogate.test";
/** A path no route module claims, so nothing else can answer it. */
const PROBE = "/__mount_gate/onerror-probe";

/** The message the handler must never let escape. */
const SECRET = "upstream-credential-9f3c2a";

beforeAll(() => {
  app.get(PROBE, () => {
    throw new Error(SECRET);
  });
});

describe("the deployed Worker's unhandled-error envelope", () => {
  it("answers 500 with the internal_error envelope, not Hono's plain-text 500", async () => {
    const res = await SELF.fetch(`${BASE}${PROBE}`);

    expect(res.status).toBe(500);
    expect(res.headers.get("content-type") ?? "").toContain("application/json");
    expect(await res.json()).toEqual({
      error: {
        code: "internal_error",
        message: "the MCP gateway could not complete this request",
        request_id: expect.any(String),
      },
    });
  });

  it("does NOT leak the thrown message across the boundary", async () => {
    const res = await SELF.fetch(`${BASE}${PROBE}`);
    const text = await res.text();
    // The whole reason the handler rewrites the body: a provider credential or
    // an internal hostname in a thrown Error must not reach the caller.
    expect(text).not.toContain(SECRET);
  });

  it("carries the caller's x-request-id, so a 500 is correlatable to its log line", async () => {
    const res = await SELF.fetch(`${BASE}${PROBE}`, {
      headers: { "x-request-id": "req-mcp-onerror-gate" },
    });

    expect(res.status).toBe(500);
    const body = (await res.json()) as { error?: { request_id?: string } };
    expect(body.error?.request_id).toBe("req-mcp-onerror-gate");
  });
});
