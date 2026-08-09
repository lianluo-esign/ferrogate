/**
 * The two mount lines of `apps/agent-runtime/src/index.ts` that NOTHING in this
 * repository asserted, measured by mutation in wave 18.
 *
 * ## AR-C2 — `app.notFound(notFoundHandler)`
 *
 * `docs/rewrite/MOUNT-SEAMS.md` §16.2 recorded this row as NEWLY UNPROVEN in
 * wave 15 and left it open: deleting the line was GREEN across every
 * agent-runtime test, and wave 18 re-measured the same result (385 + 51 green
 * with the handler unmounted). The reason is precise and worth keeping: every
 * 404 the rest of the suite provokes is thrown by `src/middleware/auth.ts`,
 * which answers an identical `404 not_found` for an undocumented path *inside*
 * an owned prefix. `contractAuth` is mounted on `/v1/*`, so it only ever sees
 * those paths. Hono's `notFound` hook therefore fires ONLY outside `/v1/*` —
 * exactly the region no test probed.
 *
 * Unmounted, Hono answers its built-in `404 Not Found` as `text/plain` with no
 * body envelope and no correlation id, so an operator's monitoring sees an
 * un-parseable 404 from one Worker in a fleet whose every other Worker answers
 * the FerroGate envelope. The cases below drive a path outside `/v1/*` through
 * `SELF` — the deployed Worker, not a locally assembled Hono app — and assert
 * the envelope Hono's default cannot produce.
 *
 * ## AR-V1 — `app.get("/version", …)`
 *
 * Never enumerated in any wave's seam table (the systemic failure this wave
 * exists to fix: a MISSING row is invisible, a wrong row is not). `gateway`,
 * `mcp`, `control-plane` and `telemetry` all mount `/version`; only this
 * Worker's copy was asserted by nothing. Deleting it was GREEN across all 436
 * tests. Unmounted, `/version` falls through to the same `notFound` above, so
 * a deploy-verification script that reads the operation count off `/version`
 * gets a 404 and cannot tell a stale deploy from a missing route.
 *
 * Both probes are anonymous on purpose: `/version` and an unknown root path are
 * outside the `/v1/*` guard, so a credential is neither sent nor required, and
 * a future change that starts challenging them fails here.
 */
import { SELF } from "cloudflare:test";
import { PUBLIC_API_MAJOR } from "@ferrogate/core";
import { describe, expect, it } from "vitest";
import { EXPECTED_OWNED_OPERATION_COUNT } from "../../src/contract.js";

const BASE = "https://agent-runtime.test";

describe("the deployed Worker answers an UNKNOWN path outside /v1/* with the FerroGate envelope", () => {
  it("returns the JSON error envelope, not Hono's built-in text/plain 404", async () => {
    // Deliberately outside `/v1/*`: inside it, `contractAuth` throws its own
    // 404 first and this seam is unreachable — which is why it went unproven.
    const res = await SELF.fetch(`${BASE}/no-such-root-path`);

    expect(res.status).toBe(404);
    // Hono's default 404 is `text/plain`. Only `notFoundHandler` produces JSON.
    expect(res.headers.get("content-type") ?? "").toContain("application/json");

    const body = (await res.json()) as {
      error?: { code?: string; message?: string; request_id?: string | null };
    };
    expect(body.error?.code).toBe("not_found");
    expect(body.error?.message).toBe("resource not found");
    // `writeError` stamps the correlation id `correlation` minted. Hono's
    // built-in 404 carries neither the body nor this header.
    expect(body.error?.request_id).toBeTruthy();
  });

  it("echoes the caller's x-request-id on that 404, so the refusal is correlatable", async () => {
    const res = await SELF.fetch(`${BASE}/still-no-such-path`, {
      headers: { "x-request-id": "req-ar-notfound-gate" },
    });

    expect(res.status).toBe(404);
    expect(res.headers.get("x-request-id")).toBe("req-ar-notfound-gate");
    const body = (await res.json()) as { error?: { request_id?: string | null } };
    expect(body.error?.request_id).toBe("req-ar-notfound-gate");
  });

  it("does NOT answer a plain-text body — the assertion that fails when unmounted", async () => {
    const res = await SELF.fetch(`${BASE}/another-unknown`);
    const text = await res.text();
    expect(text.trim()).not.toBe("404 Not Found");
    expect(() => JSON.parse(text)).not.toThrow();
  });
});

describe("the deployed Worker serves GET /version", () => {
  it("answers 200 with the public API major and this Worker's owned-operation count", async () => {
    const res = await SELF.fetch(`${BASE}/version`);

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      api: PUBLIC_API_MAJOR,
      operations: EXPECTED_OWNED_OPERATION_COUNT,
    });
  });

  it("serves it ANONYMOUSLY — /version is outside the /v1/* contract guard", async () => {
    const res = await SELF.fetch(`${BASE}/version`, {
      headers: { authorization: "Bearer definitely-not-a-key" },
    });
    // A bad credential must not change the answer: the guard does not run here.
    expect(res.status).toBe(200);
  });
});
