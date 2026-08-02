/**
 * Type the `env` that `cloudflare:test` hands tests as this Worker's bindings.
 *
 * `cloudflare:test` declares `env` as `Cloudflare.Env`, which is empty until a
 * project augments it. Augmenting it here means a test that reads or overrides
 * an operator var is checked against the REAL binding surface rather than
 * silently typed as `any` — a renamed var then fails the typecheck instead of
 * quietly becoming a no-op assertion.
 */
import type { AgentRuntimeBindings } from "../src/ports.js";

declare global {
  namespace Cloudflare {
    interface Env extends AgentRuntimeBindings {}
  }
}
