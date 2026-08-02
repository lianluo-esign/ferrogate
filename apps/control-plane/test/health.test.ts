import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import {
  RUNTIME_NAME,
  SERVICE_VERSION,
  healthReport,
  readinessReport,
} from "../src/routes/health.js";

const SERVICE = "ferrogate-control-plane";

/**
 * The bindings a deployment WITHOUT a control database actually has.
 *
 * `ControlPlaneBindings` declares `DB` as REQUIRED — that is the shape a
 * correctly-provisioned deploy has, and making it optional would let a surface
 * forget it — while `resolveControlDatabase` reads `env.DB ?? null` because a
 * deploy CAN be missing the binding and the probe's whole job is to say so. The
 * cast is exactly that gap, written once here rather than at each call site.
 */
function withoutControlDatabase(extra: Record<string, string> = {}): ControlPlaneBindings {
  return extra as unknown as ControlPlaneBindings;
}

describe("health", () => {
  it("GET /health returns { ok: true }", async () => {
    const res = await SELF.fetch("https://ferrogate.test/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  /**
   * The two SHARED contract probes. This Worker shipped without them — the
   * suite could not see it, because it drives the 203 operations this app owns
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
      service: SERVICE,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
    });
  });

  /**
   * `docs/rewrite/cert2-dataplane.md` finding **A11** — Rust's `HealthResponse`
   * (`crates/ferrogate-gateway/src/responses.rs:69`) carries
   * `version = env!("CARGO_PKG_VERSION")` — named `apps/mcp` alone. The wave-19
   * boot proof (`docs/rewrite/CUTOVER-READINESS.md` §3.3) found the member
   * missing on this Worker and on `apps/telemetry` as well: the finding was
   * correct in kind and understated 2×.
   *
   * A blank `version` would satisfy the shape above and tell an operator
   * nothing, so the constant itself is pinned.
   */
  it("reports a real version rather than an empty member", () => {
    expect(SERVICE_VERSION).toMatch(/^\d+\.\d+\.\d+/);
    expect(healthReport().version).toBe(SERVICE_VERSION);
  });

  /**
   * `/readyz` answered the string `"ready"`. It could not report anything else,
   * ever, under any configuration — the same defect wave 17 fixed on
   * `apps/agent-runtime`, whose certification verdict was "a load balancer
   * pointed at `/readyz` gets ready from a Worker that cannot serve, forever".
   *
   * The deployed Worker binds `DB`, so the READY arm is asserted through
   * `SELF`; the `not_ready` arm is asserted against the SAME exported app given
   * the env a database-less deployment has. Both drive the real app — an
   * assertion against the pure function alone could not tell whether the mounted
   * handler consults it.
   */
  it("GET /readyz is anonymous and reports READY while the control DB is bound", async () => {
    const res = await SELF.fetch("https://ferrogate.test/readyz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "ready",
      service: SERVICE,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
      dependencies: { ready: true },
    });
  });

  it("GET /readyz answers 503 not_ready with no control database", async () => {
    // `CONTROL_PLANE_STORE = "memory"` is the explicit by-name request for a run
    // WITHOUT a database: every admin write is acknowledged with a 201 and every
    // one of them is gone at the next isolate eviction. Alive, but not a
    // deployment that should be taking traffic.
    // The DEFAULT export — the handler `wrangler deploy` installs, alias fold
    // and all — given the env a database-less deployment has.
    const res = await worker.fetch(
      new Request("https://ferrogate.test/readyz"),
      withoutControlDatabase({ CONTROL_PLANE_STORE: "memory" }),
      {} as ExecutionContext,
    );
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({
      status: "not_ready",
      service: SERVICE,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
      dependencies: { ready: false },
    });
  });

  it("keeps liveness independent of readiness", () => {
    // An isolate with no database is still ALIVE, and `/healthz` must keep
    // saying so or an orchestrator restarts a Worker whose only problem is
    // configuration.
    expect(healthReport().status).toBe("ok");
    expect(
      readinessReport(withoutControlDatabase({ CONTROL_PLANE_STORE: "memory" })).body.status,
    ).toBe("not_ready");
    // ...and both documents agree on WHO is answering.
    const notReady = readinessReport(withoutControlDatabase()).body;
    expect(notReady.service).toBe(healthReport().service);
    expect(notReady.version).toBe(healthReport().version);
    expect(notReady.runtime).toBe(healthReport().runtime);
  });
});
