/**
 * Type the `env` that `cloudflare:test` hands the tests as this Worker's own
 * bindings.
 *
 * `cloudflare:test` declares `env` as `Cloudflare.Env`, which is EMPTY until a
 * project augments it — so without this file a test that reads or overrides an
 * operator var (`MAX_BODY_BYTES`, `COLLECTOR_TOKEN`) is a type error, and a
 * cast to silence it would type the whole thing as `any` and hide a rename.
 *
 * `apps/agent-runtime/test/env.d.ts` does the same for that Worker; this is the
 * telemetry twin.
 */
import type { TelemetryEnv } from "../src/ports.js";

declare global {
  namespace Cloudflare {
    interface Env extends TelemetryEnv {}
  }
}
