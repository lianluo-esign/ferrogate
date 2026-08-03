/**
 * `GET /healthz` + `GET /readyz` — the two SHARED contract probes, in the ONE
 * document shape `docs/rewrite/ROUTE-MAP.md` requires of every Worker.
 *
 * ## The two defects this closes
 *
 * **1. `/healthz` had no `version`.** Rust's `HealthResponse`
 * (`crates/ferrogate-gateway/src/responses.rs:69-74`) is `{status, service,
 * version, runtime}`, with `version = env!("CARGO_PKG_VERSION")`.
 * `docs/rewrite/cert2-dataplane.md` finding **A11** recorded the member missing
 * and named `apps/mcp` alone; the wave-19 boot proof
 * (`docs/rewrite/CUTOVER-READINESS.md` §3.3) found it missing on THIS Worker and
 * on `apps/telemetry` as well — the finding was understated 2×. An operator
 * asking a colo which build it serves got nothing back.
 *
 * **2. `/readyz` was the string `"ready"`.** It could not report anything else,
 * ever, under any configuration. That is the exact defect wave 17 fixed on
 * `apps/agent-runtime`, where the certification's verdict was:
 *
 * > *A load balancer pointed at agent-runtime's `/readyz` gets "ready" from a
 * > Worker that cannot serve, forever.*
 *
 * ## What readiness MEANS on the control plane
 *
 * This Worker's entire job is durable administrative state. `resolveStore`
 * (`../adapters.ts`) recognises exactly two postures, and the docstring there is
 * blunt about why there is no third:
 *
 *  - `CONTROL_PLANE_STORE = "memory"` → the in-memory reference store, an
 *    explicit by-name request for a run WITHOUT a database. Every write is
 *    acknowledged with a `201` and every one of them is gone at the next isolate
 *    eviction;
 *  - otherwise → D1, which REQUIRES the `DB` binding.
 *
 * Readiness is therefore **"is this deployment serving from the control
 * database"**, and it is asked through {@link resolveControlDatabase} rather
 * than re-parsed here — one switch, one answer, so the probe and the store can
 * never disagree about which posture a deployment is in. A memory-mode
 * deployment answers `503 not_ready`: it is alive (`/healthz` still says `ok`)
 * and it serves every admin route, but it is not a deployment that should be
 * taking traffic whose acknowledged writes will vanish.
 *
 * The third posture — durable requested, `DB` unbound — never reaches this
 * handler: `resolveStore` throws on the first request and `app.use("*", deps)`
 * in the composition root turns that into an error response before routing. It
 * is still non-2xx to a load balancer, which is the answer that matters.
 *
 * ## MOUNTING — one line, in `./index.ts`, not in the composition root
 *
 * `mountSharedProbes(app)` is called from {@link registerRoutes} — the function
 * `src/index.ts` already calls for the 214 contract operations — and NOT from
 * `src/index.ts` itself, which is a composition root this slice may not edit.
 * The probes are mounted without being appended to the record `registerRoutes`
 * returns, so the 214-operation count `test/wiring.test.ts` pins does not move.
 *
 * The two inline handlers that used to live in `src/index.ts` are DELETED rather
 * than left in place: Hono runs every matching handler in registration order, so
 * leaving them would have made this Worker declare TWO health documents for one
 * path — the exact per-Worker divergence the fleet gate exists to stop, and it
 * refuses a second declaration outright. That deletion is the ONLY edit made to
 * a composition root by this slice, it removes code and adds none, and it is
 * flagged for the integrate step.
 *
 * **Mount gate (proven by mutation):** delete `mountSharedProbes(app);` from
 * `registerRoutes` and `bun run test` goes RED in `test/health.test.ts` with
 * `404 no route for GET /healthz` — the fleet-standard path every uptime check
 * and load-balancer origin probe uses. Seam recorded in
 * `docs/rewrite/MOUNT-SEAMS.md` terms alongside `CP-*`.
 */
import type { Hono } from "hono";
import { SERVICE_NAME, resolveControlDatabase } from "../adapters.js";
import type { ControlPlaneBindings, ControlPlaneEnv } from "../ports.js";

/** Rust reports `runtime: "pingora"`; the Pingora data plane is eliminated. */
export const RUNTIME_NAME = "workers";

/**
 * `HealthResponse.version` — Rust `env!("CARGO_PKG_VERSION")`.
 *
 * The TypeScript equivalent is the workspace version — `package.json`'s
 * `"0.0.0"` — carried as a constant rather than imported, because a
 * `resolveJsonModule` import of the ROOT manifest would bundle it into the
 * Worker. It is the SAME value `StoreRuntimeStatus` already reports through
 * `GET /admin/v1/status` (`../adapters.ts`, `version = "0.0.0"`), and
 * `test/health.test.ts` asserts the two agree rather than trusting that they do.
 */
export const SERVICE_VERSION = "0.0.0";

/** Body of `GET /healthz` (Rust `HealthResponse`), in the struct's own order. */
export interface HealthReport {
  readonly status: "ok";
  readonly service: string;
  readonly version: string;
  readonly runtime: string;
}

/** Body of `GET /readyz`: the identity members, then this Worker's evidence. */
export interface ReadinessReport {
  readonly status: "ready" | "not_ready";
  readonly service: string;
  readonly version: string;
  readonly runtime: string;
  readonly dependencies: { readonly ready: boolean };
}

/** `GET /healthz` — liveness. 200 as soon as the isolate runs, as in Rust. */
export function healthReport(): HealthReport {
  return {
    status: "ok",
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    runtime: RUNTIME_NAME,
  };
}

/**
 * `GET /readyz`, evaluated PER REQUEST.
 *
 * Per request, not memoised at module scope: the answer is a function of the
 * bindings of the request being served, and a probe answering from a snapshot
 * taken on some earlier request is the same class of lie as the constant it
 * replaces.
 */
export function readinessReport(env: ControlPlaneBindings | undefined): {
  readonly status: 200 | 503;
  readonly body: ReadinessReport;
} {
  const ready = env !== undefined && resolveControlDatabase(env) !== null;
  return {
    status: ready ? 200 : 503,
    body: {
      status: ready ? "ready" : "not_ready",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
      dependencies: { ready },
    },
  };
}

/**
 * Mount the two probes on the app the Worker exports.
 *
 * Plain `app.get` rather than the contract-driven registry on purpose: folding
 * them into `registerRoutes`'s loop would move them inside the operation count
 * `test/wiring.test.ts` pins, and they are owned by no group. `contractAuth`
 * still runs over them — it is an `app.use("*", …)` — and passes them through
 * because neither path is one of the 214 operations it guards, which is how
 * `/health` and `/version` have always been treated.
 */
export function mountSharedProbes(app: Hono<ControlPlaneEnv>): void {
  app.get("/healthz", (c) => c.json(healthReport()));
  app.get("/readyz", (c) => {
    const report = readinessReport(c.env);
    return c.json(report.body, report.status);
  });
}
