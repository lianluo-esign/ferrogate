/**
 * The two SHARED contract operations ROUTE-MAP.md requires in EVERY Worker —
 * `GET /healthz` and `GET /readyz` — plus the pre-contract `/health` probe they
 * join rather than replace.
 *
 * `test/contract.test.ts` proves both are mounted on the app the Worker exports
 * and reachable over `SELF.fetch`. This file holds the SEMANTICS the probes
 * exist for, which a reachability probe alone cannot: liveness and readiness
 * must be able to DISAGREE. `/readyz` is exercised through `SELF` only on the
 * ready arm — the bindings in `wrangler.toml` are fixed for the whole run — so
 * the `not_ready` arm is asserted against the same pure function the handler
 * calls, and the deployed answer is asserted to BE that function's output.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { healthReport, readinessReport } from "../src/index.js";
import { portsBound, resolvePorts } from "../src/ports.js";
import { MCP_PROTOCOL_REVISION, SERVICE_VERSION } from "../src/routes/index.js";

const BASE = "https://ferrogate.test";

describe("health", () => {
  it("GET /health returns { ok: true }", async () => {
    const res = await SELF.fetch(`${BASE}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("GET /healthz reports liveness with this Worker's identity", async () => {
    const res = await SELF.fetch(`${BASE}/healthz`);
    expect(res.status).toBe(200);
    // The deployed answer IS the pure report — no second, drifting shape.
    expect(await res.json()).toEqual(healthReport());
    expect(healthReport()).toMatchObject({ status: "ok", service: "ferrogate-mcp" });
  });

  /**
   * `docs/rewrite/cert2-dataplane.md` finding **A11**: Rust's `HealthResponse`
   * carries `version = env!("CARGO_PKG_VERSION")` and this document had no
   * member for it, so an operator could not tell which build a colo served.
   *
   * The literal shape is asserted here, NOT against `healthReport()`. Comparing
   * the response to the function that produced it (as the case above does, on
   * purpose, to prove the deployed answer is not a second copy) can never catch
   * a member being dropped from both at once.
   */
  it("GET /healthz is Rust's four-member HealthResponse, and nothing else", async () => {
    const res = await SELF.fetch(`${BASE}/healthz`);
    expect(await res.json()).toEqual({
      status: "ok",
      service: "ferrogate-mcp",
      version: SERVICE_VERSION,
      runtime: "workers",
    });
    // A blank version satisfies the shape and tells an operator nothing.
    expect(SERVICE_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });

  /**
   * `protocol` used to be a fifth member of the health document — an invention
   * of this Worker on a SHARED contract operation, which is how `/healthz` came
   * to answer a different shape depending on who served it.
   *
   * Removing it must not remove the CAPABILITY, so the three surfaces that
   * still publish the revision are asserted here. Without this, "drop the
   * member" and "lose the discovery path" look identical.
   */
  it("still publishes the protocol revision, on /version and /readyz", async () => {
    const version = await SELF.fetch(`${BASE}/version`);
    expect(version.status).toBe(200);
    expect(await version.json()).toMatchObject({ protocol: MCP_PROTOCOL_REVISION });

    const readyz = await SELF.fetch(`${BASE}/readyz`);
    expect(readyz.status).toBe(200);
    expect(await readyz.json()).toMatchObject({ protocol: MCP_PROTOCOL_REVISION });

    const health = (await (await SELF.fetch(`${BASE}/healthz`)).json()) as Record<string, unknown>;
    expect(Object.keys(health)).not.toContain("protocol");
  });

  it("GET /readyz reports READY while the ports are bound", async () => {
    const res = await SELF.fetch(`${BASE}/readyz`);
    expect(res.status).toBe(200);
    const ready = readinessReport({ FG_DEV_IN_MEMORY_PORTS: "1" });
    expect(ready.status).toBe(200);
    expect(await res.json()).toEqual(ready.body);
  });
});

describe("readiness is a real signal, not a constant", () => {
  it("answers 503 not_ready when the Worker has no bound port bundle", () => {
    // The posture a production isolate is in until the D1/KV/Secrets-Store
    // ports are wired: `resolvePorts` installs `UnboundAuth` and every
    // authenticated surface answers 503. A `/readyz` that still said "ready"
    // there would tell a load balancer to send it traffic it cannot serve.
    const report = readinessReport({});
    expect(report.status).toBe(503);
    expect(report.body.status).toBe("not_ready");
    expect(report.body.dependencies).toEqual({ ready: false });
  });

  it("distinguishes liveness from readiness", () => {
    // Liveness does NOT depend on the bindings — an unready isolate is still
    // alive, and `/healthz` must keep saying so or an orchestrator will restart
    // a Worker whose only problem is unbound configuration.
    expect(healthReport().status).toBe("ok");
    expect(readinessReport({}).body.status).toBe("not_ready");
    // ...and both reports agree on WHO is answering.
    expect(readinessReport({}).body.service).toBe(healthReport().service);
    expect(readinessReport({}).body.version).toBe(healthReport().version);
    expect(readinessReport({}).body.runtime).toBe(healthReport().runtime);
  });

  it("tracks the SAME predicate resolvePorts branches on", async () => {
    // If `portsBound` and `resolvePorts` ever disagree, readiness becomes a lie
    // in one direction or the other, so bind-state and auth-state are asserted
    // together here and neither can move alone.
    expect(portsBound({ FG_DEV_IN_MEMORY_PORTS: "1" })).toBe(true);
    expect(portsBound({})).toBe(false);

    // The unbound bundle really does refuse to authenticate...
    const unbound = await resolvePorts({}).auth.authenticate(
      new Headers({ authorization: "Bearer anything" }),
      "tools.read",
    );
    expect(unbound).toMatchObject({ status: 503 });
    // ...and readiness reports exactly that isolate as not ready.
    expect(readinessReport({}).status).toBe(503);
  });
});
