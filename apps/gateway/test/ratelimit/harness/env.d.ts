/**
 * Types the `env` that `cloudflare:test` hands the rate-limit specs, so a spec
 * can reach the REAL `RATE_LIMIT` namespace without casting.
 *
 * `cloudflare:test` exports `env` as `Cloudflare.Env`, which is the global
 * ambient binding namespace, so the harness bindings are declared there.
 *
 * Scoped to this harness: `apps/gateway/src/ports.ts` (`GatewayBindings`) is the
 * composition root's file, and the integrate step adds `RATE_LIMIT` there.
 */
import type { RateLimiterDurableObject } from "../../../src/ratelimit/index.js";

declare global {
  namespace Cloudflare {
    interface Env {
      RATE_LIMIT: DurableObjectNamespace<RateLimiterDurableObject>;
      GATEWAY_QUOTA_POLICIES: string;
      GATEWAY_PLANS: string;
      GATEWAY_TENANT_PLANS: string;
    }
  }
}
