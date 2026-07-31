/**
 * Type the `env` that `cloudflare:test` hands tests as this Worker's bindings.
 *
 * `cloudflare:test` declares `env` as `Cloudflare.Env`, which is empty until a
 * project augments it. Augmenting it here means a test that reads `env.DB` or
 * `env.MCP_OAUTH_KV` is checked against the REAL binding surface declared in
 * `wrangler.toml` rather than silently typed as `any` — a renamed binding then
 * fails the typecheck instead of quietly becoming a no-op assertion.
 */
import type { McpEnv } from "../src/ports.js";

declare global {
  namespace Cloudflare {
    interface Env extends McpEnv {}
  }
}
