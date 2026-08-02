/**
 * THE REGISTRATION-ORDER RULE that decides whether a gateway route is alive.
 *
 * `createGatewayApp` ends with
 *
 *     app.all("*", options.reverseProxy ?? reverseProxyFallThrough());
 *
 * and its docblock states the correctness argument: *"LAST, and the position is
 * the whole correctness argument"*. Hono runs matched handlers in REGISTRATION
 * order, and with `GATEWAY_ROUTES` unset the fall-through answers `c.notFound()`
 * rather than delegating — so it TERMINATES the chain. Every route registered
 * after it is dead.
 *
 * ## Why this file exists
 *
 * Wave 18 measured the consequence. `apps/gateway/src/index.ts:243` registers
 *
 *     app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));
 *
 * AFTER `createGatewayApp` has already installed the fall-through, so the
 * deployed gateway answers `404 not_found` on `GET /version` — the only one of
 * the five Workers that does not serve it. `docs/rewrite/MOUNT-SEAMS.md` §16.2
 * had recorded that row as "unproven" and §16.3 as "the route is removed;
 * `/version` then falls through to the reverse-proxy fall-through. Real." The
 * second half of that reading was wrong: the fall-through ALREADY wins, so
 * deleting the line changes nothing observable. It is a dead route, not an
 * ungated one, and no mutation can prove a dead seam.
 *
 * **Wave 18 fixed it.** `/version` now lives inside `createGatewayApp`, one line
 * below `/health` and one line above the fall-through, and the block at the
 * bottom of this file is the gate that holds it there. What the rest of this
 * file does is pin the RULE that made the defect a defect — so the next route
 * registered on the wrong side of the fall-through fails here rather than in
 * production.
 */
import { SELF } from "cloudflare:test";
import { PUBLIC_API_MAJOR } from "@ferrogate/core";
import { beforeAll, describe, expect, it } from "vitest";
import app from "../../src/index.js";

const BASE = "https://gateway.test";

/** A path no contract operation and no operator route claims. */
const LATE_PROBE = "/__mount_gate/registered-after-the-fallthrough";

beforeAll(() => {
  // Attached to the DEPLOYED app object, after `createGatewayApp` returned —
  // i.e. in exactly the position `src/index.ts:243` puts `/version`.
  app.get(LATE_PROBE, (c) => c.json({ reached: true }));
});

describe("the reverse-proxy fall-through is the last live registration", () => {
  it("serves a route registered BEFORE it (the positive control)", async () => {
    // `app.get("/health", …)` is registered inside `createGatewayApp`, one line
    // above the fall-through. If the fall-through were moved ahead of it — or
    // `/health` moved below it — this is the assertion that fails.
    const res = await SELF.fetch(`${BASE}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("SHADOWS a route registered AFTER it — the mechanism that kills /version", async () => {
    const res = await SELF.fetch(`${BASE}${LATE_PROBE}`);

    // Not a quirk to be worked around: the catch-all must terminate, or an
    // operator reverse-proxy route could be bypassed by anything registered
    // later. The rule is right; registering a route below it is the mistake.
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error?: { code?: string } };
    expect(body.error?.code).toBe("not_found");
  });

  it("answers that shadowed path with the gateway's OWN envelope, not Hono's default", async () => {
    // Proves the 404 above comes from the gateway chain (fall-through →
    // `c.notFound()` → `gatewayNotFoundHandler`) rather than from Hono never
    // having matched anything, which would be a different failure entirely.
    const res = await SELF.fetch(`${BASE}${LATE_PROBE}`);
    expect(res.headers.get("content-type") ?? "").toContain("application/json");
    const body = (await res.json()) as { error?: { message?: string } };
    expect(body.error?.message).toContain(LATE_PROBE);
  });
});

/**
 * GW-C11 — CLOSED in wave 18 by the integrate step.
 *
 * The fix was the one-line move this file's `todo` specified: `/version` left
 * `src/index.ts` (where it sat BELOW the fall-through and was unreachable) and
 * is now registered inside `createGatewayApp`, immediately beside
 * `app.get("/health", …)` and immediately above `app.all("*", …)`.
 *
 * Re-prove the seam by deleting that registration from
 * `src/routes/index.ts` — this block must go RED with a `404`, which is the
 * status the DEPLOYED gateway really returned for seventeen waves.
 */
describe("GET /version is served by the deployed gateway (GW-C11, fixed)", () => {
  it("answers 200 with the public API major, through SELF", async () => {
    const res = await SELF.fetch(`${BASE}/version`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ api: PUBLIC_API_MAJOR });
  });

  it("is registered ABOVE the fall-through, unlike the late probe", async () => {
    // The contrast is the assertion: two routes on the same app, one placed
    // correctly and one placed the way `/version` used to be.
    expect((await SELF.fetch(`${BASE}/version`)).status).toBe(200);
    expect((await SELF.fetch(`${BASE}${LATE_PROBE}`)).status).toBe(404);
  });
});
