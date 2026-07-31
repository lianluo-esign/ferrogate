import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("health", () => {
  it("GET /health returns { ok: true }", async () => {
    const res = await SELF.fetch("https://ferrogate.test/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  /**
   * The two SHARED contract probes. This Worker shipped without them — the
   * suite could not see it, because it drives the 197 operations this app owns
   * and these are owned by no app. A real `wrangler dev --local` boot answered
   * `404 not_found` on `/healthz`, which is what every uptime check and
   * load-balancer origin probe would have seen.
   *
   * Anonymous by contract: asserted with NO credential, so a future guard that
   * accidentally covers them fails here rather than in production.
   */
  it("GET /healthz is anonymous and reports this service", async () => {
    const res = await SELF.fetch("https://ferrogate.test/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "ok",
      service: "ferrogate-control-plane",
      runtime: "workers",
    });
  });

  it("GET /readyz is anonymous and reports this service", async () => {
    const res = await SELF.fetch("https://ferrogate.test/readyz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "ready",
      service: "ferrogate-control-plane",
      runtime: "workers",
    });
  });
});
