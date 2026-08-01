/**
 * The three constants that identify THIS deployment on every probe and every
 * exposition — Rust's `SERVICE_NAME`, its `runtime` string, and
 * `env!("CARGO_PKG_VERSION")`.
 *
 * They live in their own module rather than in `./index.ts` because `./index.ts`
 * is the app factory: `./metrics.ts` needs the service name for
 * `ferrogate_info{service=…}` and `./index.ts` mounts `./metrics.ts`, so keeping
 * them there would make the two modules import each other. `./index.ts`
 * re-exports all three, so every existing importer is unchanged.
 */

/** Service identity echoed by `/healthz`, `/readyz` and `/metrics`. */
export const SERVICE_NAME = "ferrogate-gateway";

/** Rust reports `runtime: "pingora"`; the Pingora data plane is eliminated. */
export const RUNTIME_NAME = "workers";

/**
 * `HealthResponse.version` — Rust `env!("CARGO_PKG_VERSION")`
 * (`local.rs::handle_healthz`).
 *
 * The cutover certification recorded its ABSENCE: `/healthz` answered
 * `{status, service, runtime}` where Rust also carries `version`, so an
 * operator checking which build a colo serves had nothing to read.
 *
 * The TypeScript equivalent of `CARGO_PKG_VERSION` is the workspace version —
 * `package.json`'s `"0.0.0"` — carried as a constant rather than imported,
 * because a `resolveJsonModule` import of the ROOT manifest would bundle it
 * into the Worker. `apps/control-plane/src/adapters.ts` reports the same value
 * through `StoreRuntimeStatus`, so the two agree today and
 * `test/health.test.ts` pins this one.
 */
export const SERVICE_VERSION = "0.0.0";
