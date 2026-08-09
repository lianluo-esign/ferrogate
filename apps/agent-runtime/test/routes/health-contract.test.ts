/**
 * `GET /healthz` + `GET /readyz` in the shape ROUTE-MAP requires of every
 * Worker — cutover certification operations 53 and 54.
 *
 * The finding: `apps/agent-runtime` answered a flat `200 {"ok":true}` on both,
 * where gateway/mcp answer `{status, service, runtime, …}` and port the Rust
 * readiness decision table. `/readyz` in particular could never answer 503, so
 * a rollout of an agent-runtime whose credential authorities are unbound —
 * which refuses EVERY authenticated surface with
 * `503 agent_runtime_unavailable` — was never rolled back.
 *
 * ## What is proven here, and what is not
 *
 * The seam (`src/routes/health.ts`) is driven through a locally-mounted Hono
 * app with REAL bindings, so the decision table is exercised on both sides of
 * every branch. The deployed-Worker block below is `todo` because mounting it
 * is a one-line edit to `src/index.ts`, a composition root this slice may not
 * write to; the exact line is in that block's name and in the seam's module
 * doc. Once it lands, deleting it turns the block RED — that is the mount gate.
 */
import { SELF, env } from "cloudflare:test";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import type { AgentRuntimeBindings, AgentRuntimeEnv } from "../../src/ports.js";
import { configFromEnv } from "../../src/ports.js";
import {
  RUNTIME_NAME,
  SERVICE_NAME,
  SERVICE_VERSION,
  healthRoutes,
  readinessReport,
  runtimeEnabled,
} from "../../src/routes/health.js";

const BASE = "https://agent-runtime.test";

/** The seam, mounted the way `src/index.ts` is asked to mount it. */
function mounted(): Hono<AgentRuntimeEnv> {
  const app = new Hono<AgentRuntimeEnv>();
  app.route("/", healthRoutes);
  return app;
}

/** The real bindings this suite boots with — ports resolvable, runtime on. */
function servingEnv(): AgentRuntimeBindings {
  return env as unknown as AgentRuntimeBindings;
}

describe("GET /healthz — the contract document", () => {
  it("answers {status, service, version, runtime}, not {ok:true}", async () => {
    const response = await mounted().request(`${BASE}/healthz`, {}, servingEnv());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      status: "ok",
      service: SERVICE_NAME,
      // Rust `HealthResponse.version` = `env!("CARGO_PKG_VERSION")`. Its
      // ABSENCE on the gateway was recorded as a separate small gap; here the
      // whole document was missing.
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
    });
  });

  it("names this Worker, not another one", () => {
    expect(SERVICE_NAME).toBe("ferrogate-agent-runtime");
    expect(RUNTIME_NAME).toBe("workers");
  });
});

describe("GET /readyz — the Rust readiness decision table", () => {
  it("answers 200 ready / state_loaded when the ports resolve and the runtime is on", async () => {
    const response = await mounted().request(`${BASE}/readyz`, {}, servingEnv());
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.status).toBe("ready");
    expect(body.ready).toBe(true);
    expect(body.readiness_reason).toBe("state_loaded");
    expect(body.draining).toBe(false);
    expect(body.accepting_new_requests).toBe(true);
    expect(body.dependencies).toEqual({ ready: true });
    expect(body.service).toBe(SERVICE_NAME);
    expect(body.version).toBe(SERVICE_VERSION);
  });

  it("answers 503 not_ready / revision_missing when the ports cannot resolve", async () => {
    // `resolveDeps` FAILS CLOSED with neither `DB`/`CONTROL_DB` nor the dev
    // in-memory switch — and every authenticated surface then answers
    // `503 agent_runtime_unavailable`. This is the state the flat `{ok:true}`
    // reported as healthy.
    const unbound = { AGENT_RUNTIME_ENABLED: "1" } as unknown as AgentRuntimeBindings;
    const response = await mounted().request(`${BASE}/readyz`, {}, unbound);
    expect(response.status).toBe(503);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.status).toBe("not_ready");
    expect(body.ready).toBe(false);
    expect(body.readiness_reason).toBe("revision_missing");
    expect(body.dependencies).toEqual({ ready: false });
  });

  it("answers 503 not_ready / operator_drain when the operator disabled the runtime", async () => {
    const drained = { ...servingEnv(), AGENT_RUNTIME_ENABLED: "0" };
    const response = await mounted().request(`${BASE}/readyz`, {}, drained);
    expect(response.status).toBe(503);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.status).toBe("not_ready");
    expect(body.readiness_reason).toBe("operator_drain");
    expect(body.draining).toBe(true);
    expect(body.accepting_new_requests).toBe(false);
    // The STATE half is still reported honestly: the ports are fine, the
    // operator is not accepting. Collapsing the two would lose that.
    expect(body.dependencies).toEqual({ ready: true });
  });

  it("reports operator_drain even when the ports are ALSO unresolvable", () => {
    // Drain outranks state in the reason, as `clusterStatus` orders it.
    const both = { AGENT_RUNTIME_ENABLED: "0" } as unknown as AgentRuntimeBindings;
    const report = readinessReport(both);
    expect(report.status).toBe(503);
    expect(report.body.readiness_reason).toBe("operator_drain");
    expect(report.body.dependencies).toEqual({ ready: false });
  });

  it("keeps the readiness_reason vocabulary the gateway's", async () => {
    // ONE vocabulary across the Workers, so an operator dashboard needs one
    // mapping. `apps/gateway/src/routes/readiness.ts` is the source.
    const reasons = new Set<string>();
    for (const candidate of [
      servingEnv(),
      { AGENT_RUNTIME_ENABLED: "1" } as unknown as AgentRuntimeBindings,
      { ...servingEnv(), AGENT_RUNTIME_ENABLED: "0" },
    ] as readonly AgentRuntimeBindings[]) {
      reasons.add(readinessReport(candidate).body.readiness_reason);
    }
    expect(reasons).toEqual(new Set(["state_loaded", "revision_missing", "operator_drain"]));
    await Promise.resolve();
  });

  it("re-reads the switch PER REQUEST rather than caching it at boot", async () => {
    const app = mounted();
    const bindings = { ...servingEnv(), AGENT_RUNTIME_ENABLED: "1" };
    expect((await app.request(`${BASE}/readyz`, {}, bindings)).status).toBe(200);
    // Same app object, same isolate — only the binding changed.
    expect(
      (await app.request(`${BASE}/readyz`, {}, { ...bindings, AGENT_RUNTIME_ENABLED: "0" })).status,
    ).toBe(503);
    expect((await app.request(`${BASE}/readyz`, {}, bindings)).status).toBe(200);
  });
});

describe("AGENT_RUNTIME_ENABLED — the probe agrees with the handlers", () => {
  it("answers exactly what configFromEnv answers, for every spelling", () => {
    // The property that matters is AGREEMENT, not a re-stated rule: a probe
    // reporting `not_ready` on a deployment `requireRuntimeEnabled` is happily
    // serving (or the reverse) is a worse lie than the flat `{ok:true}`. Note
    // `"false"` and `"off"` are ON — only the exact `"0"` disables — which is
    // precisely the rule an independent re-parse would have got wrong.
    for (const raw of ["0", " 0 ", "1", "true", "false", "FALSE", "no", "off", "", "  ", "x"]) {
      const bindings = { AGENT_RUNTIME_ENABLED: raw } as AgentRuntimeBindings;
      expect(runtimeEnabled(bindings), raw).toBe(configFromEnv(bindings).enabled);
    }
    const unset = {} as AgentRuntimeBindings;
    expect(runtimeEnabled(unset)).toBe(configFromEnv(unset).enabled);
    expect(runtimeEnabled(undefined)).toBe(true);
  });

  it("and only the exact `0` drains — the rule this delegation protects", () => {
    expect(runtimeEnabled({ AGENT_RUNTIME_ENABLED: "0" } as AgentRuntimeBindings)).toBe(false);
    expect(runtimeEnabled({ AGENT_RUNTIME_ENABLED: "false" } as AgentRuntimeBindings)).toBe(true);
  });
});

describe("/health stays the terse scaffold probe", () => {
  it("still answers { ok: true }", async () => {
    const response = await mounted().request(`${BASE}/health`, {}, servingEnv());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
  });
});

/**
 * THE MOUNT GATE — pending ONE line in a composition root this slice may not
 * write to.
 *
 * `src/index.ts` today carries three inline probe handlers. Replacing them with
 *
 *     app.route("/", healthRoutes);
 *
 * (plus `import { healthRoutes } from "./routes/health.js";`) makes the block
 * below pass; deleting that line again makes it RED. It drives `SELF` — the
 * real `export default app` in real workerd — precisely so it cannot be
 * satisfied by `src/routes/health.ts` merely existing.
 *
 * Measured before this file was written, against the unmounted tree:
 * `SELF.fetch("/readyz")` → **200 `{"ok":true}`** on a Worker whose readiness
 * it never checked.
 */
describe("the deployed Worker serves the contract probes", () => {
  it("GET /healthz answers the contract document, not { ok: true }", async () => {
    const response = await SELF.fetch(`${BASE}/healthz`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      status: "ok",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
    });
  });

  it("GET /readyz answers the decision table, not { ok: true }", async () => {
    // The measured pre-mount answer was `200 {"ok":true}` — a body with none of
    // these members. Asserting the MEMBERS is what makes the mount seam load-
    // bearing: re-inlining `c.json({ ok: true })` in `src/index.ts` fails here.
    const response = await SELF.fetch(`${BASE}/readyz`);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.service).toBe(SERVICE_NAME);
    expect(body.version).toBe(SERVICE_VERSION);
    expect(body.runtime).toBe(RUNTIME_NAME);
    expect(body.status).toBe(response.status === 200 ? "ready" : "not_ready");
    expect(body.ready).toBe(response.status === 200);
    // The whole point of the port: a 503 is now REACHABLE, and the reason names
    // which conjunct failed.
    expect(["state_loaded", "revision_missing", "operator_drain"]).toContain(body.readiness_reason);
    expect(typeof body.draining).toBe("boolean");
    expect(typeof body.accepting_new_requests).toBe("boolean");
    expect(body.dependencies).toEqual({ ready: expect.any(Boolean) });
    expect(body).not.toEqual({ ok: true });
  });

  it("keeps both probes ANONYMOUS — ahead of contractAuth", async () => {
    // `app.route("/", healthRoutes)` must stay above `app.use("/v1/*", …)`;
    // moving it below would 401/404 these with no other test noticing.
    for (const path of ["/healthz", "/readyz", "/health"]) {
      const response = await SELF.fetch(`${BASE}${path}`);
      expect([200, 503], path).toContain(response.status);
    }
  });

  it("GET /health stays the terse scaffold probe on the real Worker", async () => {
    const response = await SELF.fetch(`${BASE}/health`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
  });
});
