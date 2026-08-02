/**
 * The deploy entrypoint — the module `wrangler.toml`'s `main` points at.
 *
 * workerd treats every named export of the entry module as a service
 * entrypoint and rejects any that is not a function / `ExportedHandler` /
 * `WorkerEntrypoint` or `DurableObject` class. `index.ts` re-exports the
 * ingest/sink/schema surface (`OTLP_ROUTES`, `TELEMETRY_ROUTES`,
 * `handleIngest`, `TelemetryErrorCode`, …) — several of which are plain
 * objects — so pointing `main` at it fails the Worker at startup. See
 * `apps/gateway/src/worker.ts` for the full write-up and the error text.
 *
 * The default export is the app `createTelemetryApp()` built in `index.ts`,
 * re-exported unchanged; this file composes nothing.
 */
export { default } from "./index.js";
