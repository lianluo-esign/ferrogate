/**
 * The `ferrogate-telemetry` Hono app.
 *
 * Routing and wiring only — the pipeline lives in `ingest.ts`. Every route this
 * Worker serves is declared once in {@link TELEMETRY_ROUTES} and mounted from
 * that table, so a declared route cannot be missing from the app the Worker
 * exports (`test/routes.test.ts` asserts the table against the live app AND
 * drives each entry through `SELF`).
 */
import { PUBLIC_API_MAJOR } from "@ferrogate/core";
import { Hono } from "hono";
import { requireBearer } from "./auth.js";
import { TelemetryErrorCode, errorBody } from "./errors.js";
import { handleIngest } from "./ingest.js";
import { type TelemetryBindings, resolveSink } from "./ports.js";
import type { Signal } from "./schemas.js";
import type { TelemetrySink } from "./sink.js";

/** Service identity echoed by `/healthz` and `/readyz`. */
export const SERVICE_NAME = "ferrogate-telemetry";
/** Rust reported `runtime: "tokio"`; this collector runs on `workerd`. */
export const RUNTIME_NAME = "workers";
/**
 * `HealthResponse.version` — Rust `env!("CARGO_PKG_VERSION")`
 * (`crates/ferrogate-gateway/src/responses.rs:72`).
 *
 * `docs/rewrite/cert2-dataplane.md` finding **A11** named only `apps/mcp`; the
 * wave-19 boot proof (`docs/rewrite/CUTOVER-READINESS.md` §3.3) found the member
 * missing here too, so an operator curling this collector's `/healthz` could not
 * tell which build answered.
 *
 * The TypeScript equivalent of `CARGO_PKG_VERSION` is the workspace version —
 * `package.json`'s `"0.0.0"` — carried as a constant rather than imported,
 * because a `resolveJsonModule` import of the ROOT manifest would bundle it into
 * the Worker. Every other Worker in the fleet carries it the same way.
 */
export const SERVICE_VERSION = "0.0.0";

/**
 * The two SHARED contract operations, implemented in **every** Worker
 * (`docs/rewrite/ROUTE-MAP.md`; `auth.kind: "anonymous"`, `visibility:
 * "public"` in `docs/openapi/runtime-api-contract.json`).
 */
export const SHARED_OPERATION_IDS = ["getHealthz", "getReadyz"] as const;

/**
 * The OTLP/HTTP route table. These paths are fixed by the OTLP specification
 * and are exactly what `@ferrogate/observability`'s `CloudflareBackend` (and
 * Cloudflare's own native Workers OTLP export) POSTs to.
 */
export const OTLP_ROUTES: Readonly<Record<string, Signal>> = {
  "/v1/metrics": "metrics",
  "/v1/traces": "traces",
  "/v1/logs": "logs",
};

/** One mounted route, for the anti-drift test. */
export interface TelemetryRoute {
  readonly method: "GET" | "POST";
  readonly path: string;
  /** Contract `operation_id` for the two shared ops; `null` for the rest. */
  readonly operationId: string | null;
  /** `true` when no `Authorization` header is required. */
  readonly anonymous: boolean;
}

/** Everything this Worker serves. The app is built from exactly this list. */
export const TELEMETRY_ROUTES: readonly TelemetryRoute[] = [
  { method: "GET", path: "/healthz", operationId: "getHealthz", anonymous: true },
  { method: "GET", path: "/readyz", operationId: "getReadyz", anonymous: true },
  // Kept from the scaffold: `/health` is the historic liveness probe and
  // `/version` reports the public API major, as in every other app here.
  { method: "GET", path: "/health", operationId: null, anonymous: true },
  { method: "GET", path: "/version", operationId: null, anonymous: true },
  { method: "POST", path: "/v1/metrics", operationId: null, anonymous: false },
  { method: "POST", path: "/v1/traces", operationId: null, anonymous: false },
  { method: "POST", path: "/v1/logs", operationId: null, anonymous: false },
];

/** Options for {@link createTelemetryApp}. */
export interface TelemetryAppOptions {
  /**
   * Sink override. Production passes nothing: the sink is resolved per request
   * from the `TELEMETRY` binding, so a Worker deployed WITHOUT the dataset
   * answers 503 instead of crashing.
   */
  readonly sink?: TelemetrySink | null;
}

export type TelemetryApp = Hono<TelemetryBindings>;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Build the app. `src/index.ts` calls this with no options and exports the
 * result as the Worker's default handler — there is exactly one composition
 * root, and the tests drive it rather than a bespoke router.
 */
export function createTelemetryApp(options: TelemetryAppOptions = {}): TelemetryApp {
  const app = new Hono<TelemetryBindings>();

  // --- shared contract operations (anonymous) ------------------------------

  // Rust `HealthResponse`, all four members in the struct's declaration order.
  // The shape is identical on all five Workers and
  // `test/fleet-health-contract.test.ts` is the gate that keeps it that way.
  app.get("/healthz", (c) =>
    c.json({
      status: "ok",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
    }),
  );

  app.get("/readyz", (c) => {
    // Readiness for a collector is "can it store what it is sent". With no
    // Analytics Engine binding every ingest answers 503, so reporting `ready`
    // would lie to whatever is gating traffic on this probe.
    const sink = options.sink ?? resolveSink(c.env);
    const configured = sink !== null && sink !== undefined;
    return c.json(
      {
        status: configured ? "ready" : "not_ready",
        service: SERVICE_NAME,
        version: SERVICE_VERSION,
        runtime: RUNTIME_NAME,
        sink: { configured, name: configured ? sink.name : null },
      },
      configured ? 200 : 503,
    );
  });

  // --- scaffold routes kept ------------------------------------------------

  app.get("/health", (c) => c.json({ ok: true }));
  app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));

  // --- OTLP/HTTP+JSON ingest ----------------------------------------------

  for (const [path, signal] of Object.entries(OTLP_ROUTES)) {
    app.post(path, async (c) => {
      const denial = requireBearer(c.req.raw, c.env?.COLLECTOR_TOKEN);
      if (denial) return denial;
      return handleIngest(signal, c.req.raw, c.env, options.sink);
    });
    // Anything but POST on an OTLP path is 405, not 404: the route exists.
    app.all(path, () =>
      json(
        errorBody(
          TelemetryErrorCode.MethodNotAllowed,
          `${path} accepts POST only (OTLP/HTTP + JSON)`,
        ),
        405,
      ),
    );
  }

  app.notFound((c) =>
    json(
      errorBody(TelemetryErrorCode.NotFound, `unknown route: ${new URL(c.req.url).pathname}`),
      404,
    ),
  );

  return app;
}
