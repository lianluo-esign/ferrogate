/**
 * The liveness/readiness surface, driven through the REAL exported Worker.
 *
 * `/healthz` + `/readyz` are the two SHARED contract operations every Worker
 * implements (`docs/rewrite/ROUTE-MAP.md`), both `auth.kind: "anonymous"`.
 * `/health` + `/version` are the scaffold probes, kept.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { SERVICE_VERSION } from "../src/app.js";
import app, { RUNTIME_NAME, SERVICE_NAME } from "../src/index.js";
import { RecordingDataset, envWithSink, envWithoutSink } from "./fixtures.js";

describe("health", () => {
  it("GET /health returns { ok: true }", async () => {
    const res = await SELF.fetch("https://ferrogate.test/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("GET /version reports the public API major", async () => {
    const res = await SELF.fetch("https://ferrogate.test/version");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ api: "v1" });
  });
});

describe("getHealthz (GET /healthz)", () => {
  /**
   * `docs/rewrite/cert2-dataplane.md` finding **A11** — Rust's `HealthResponse`
   * carries `version = env!("CARGO_PKG_VERSION")` — named `apps/mcp` alone. The
   * wave-19 boot proof found the member missing on this collector too, so an
   * operator curling it could not tell which build answered.
   */
  it("answers 200 with Rust's four HealthResponse members, unauthenticated", async () => {
    const res = await SELF.fetch("https://ferrogate.test/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "ok",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
    });
    // A blank version satisfies the shape and tells an operator nothing.
    expect(SERVICE_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("is anonymous: a bad bearer token does NOT turn it into a 401", async () => {
    const res = await SELF.fetch("https://ferrogate.test/healthz", {
      headers: { authorization: "Bearer definitely-not-the-token" },
    });
    expect(res.status).toBe(200);
  });
});

describe("getReadyz (GET /readyz)", () => {
  it("is ready when the Analytics Engine binding is configured", async () => {
    const res = await SELF.fetch("https://ferrogate.test/readyz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "ready",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
      sink: { configured: true, name: "analytics_engine" },
    });
  });

  it("is anonymous", async () => {
    const res = await SELF.fetch("https://ferrogate.test/readyz", {
      headers: { authorization: "Bearer definitely-not-the-token" },
    });
    expect(res.status).toBe(200);
  });

  it("reports NOT ready (503) when the deploy has no sink binding", async () => {
    // The same exported app, given the env an unconfigured deploy would have.
    const res = await app.request("https://ferrogate.test/readyz", {}, envWithoutSink());
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({
      status: "not_ready",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
      sink: { configured: false, name: null },
    });
  });

  it("reports ready again once a sink binding is present", async () => {
    const res = await app.request(
      "https://ferrogate.test/readyz",
      {},
      envWithSink(new RecordingDataset()),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { sink: { configured: boolean } };
    expect(body.sink.configured).toBe(true);
  });
});
