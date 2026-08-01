import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { RUNTIME_NAME, SERVICE_NAME, SERVICE_VERSION } from "../src/routes/index.js";

describe("health", () => {
  it("GET /health returns { ok: true }", async () => {
    const res = await SELF.fetch("https://ferrogate.test/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  /**
   * Cutover certification, operation 53: `/healthz` answered
   * `{status, service, runtime}` where Rust's `HealthResponse`
   * (`local.rs::handle_healthz`) also carries
   * `version: env!("CARGO_PKG_VERSION")`. An operator checking which build a
   * colo is serving had nothing to read.
   */
  it("GET /healthz carries Rust's four HealthResponse fields, version included", async () => {
    const res = await SELF.fetch("https://ferrogate.test/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "ok",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
    });
  });

  it("reports a version, not an empty string", () => {
    // A blank `version` would satisfy the shape above and tell an operator
    // nothing, so the constant itself is pinned.
    expect(SERVICE_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});
