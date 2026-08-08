/**
 * Types the `env` that `cloudflare:test` hands the durable specs.
 *
 * `AgentRuntimeBindings` already declares `DB` / `CONTROL_DB` / `AGENT_UPSTREAMS`
 * (optional there, because the committed `wrangler.toml` does not bind them
 * yet). Here they are REQUIRED and non-optional, plus the two migration
 * bundles the harness config injects — so a spec that forgets a binding fails
 * the typecheck instead of dereferencing `undefined` at runtime.
 */
import type { D1Migration } from "cloudflare:test";
import type { DurableObjectNamespace } from "@cloudflare/workers-types";
import type { AgentRuntimeBindings } from "../../../src/ports.js";

declare global {
  namespace Cloudflare {
    interface Env extends AgentRuntimeBindings {
      /** Tenant schema: `api_keys`. */
      DB: D1Database;
      /**
       * Control schema: `self_hosted_worker_registrations` et al. Zero-D1 S5
       * (#881): the real binding is the cross-script `CONTROL_DATA` object; the
       * specs read this facade alias, wired in `setup.ts`.
       */
      CONTROL_DB: D1Database;
      /** The singleton control object the deployed Worker reads. */
      CONTROL_DATA: DurableObjectNamespace;
      TENANT_MIGRATIONS: D1Migration[];
    }
  }
}
