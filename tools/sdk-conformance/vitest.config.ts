import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/**
 * The SDK-conformance project.
 *
 * ## What this boots, and why it is the DEPLOYED gateway
 *
 * `configPath` points at `apps/gateway/wrangler.toml` — the committed deploy
 * config, not a harness copy. So `SELF` is `apps/gateway/src/worker.ts` with the
 * real Durable Object namespaces (`RATE_LIMIT`, `PROVIDER_CIRCUIT`), the real
 * D1 bindings and the real middleware chain. The claim under test is "point the
 * official SDK at FerroGate and change nothing else", and that claim is about
 * the deployed Worker; a bespoke `new Hono()` would prove nothing about it.
 *
 * Only `[vars]` are overridden below, exactly as `apps/gateway/vitest.config.ts`
 * does it: an explicit miniflare binding wins over the `[vars]` block AND over
 * a developer's local `.dev.vars`, which is what keeps this suite hermetic on
 * every machine.
 *
 * ## Why a separate workspace rather than more files under `apps/gateway/test/`
 *
 * `openai` and `@anthropic-ai/sdk` are ~30 transitive packages of vendor code.
 * They are devDependencies of THIS workspace so they can never be reached from
 * `apps/gateway/src/**` — a conformance suite that let vendor code leak into the
 * deployed Worker's dependency closure would be buying the compatibility claim
 * by importing the counterparty.
 */

/** The REAL tenant migration — see `apps/gateway/test/setup-d1.ts` for why. */
const migrations = await readD1Migrations("../../sql/d1-ts/tenant");

/**
 * The credentials the suite presents, covering the whole auth taxonomy.
 *
 * `scopes: []` on a native key means "data-plane access, never admin" (see
 * `apps/gateway/src/adapters.ts`), which is what an inference client needs.
 */
const NATIVE_API_KEYS = [
  // The healthy credential nearly every case uses.
  { key: "fg_conformance", id: "key_conformance", tenant_id: "tenant_sdk", scopes: [] },
  // SUSPENDED native key ⇒ 401 `invalid_api_key` (never 403 — a revoked
  // credential must be indistinguishable from an unknown one).
  {
    key: "fg_conformance_suspended",
    id: "key_conformance_suspended",
    tenant_id: "tenant_sdk",
    scopes: [],
    enabled: false,
  },
  // Healthy key belonging to a SUSPENDED TENANT ⇒ 403 `tenancy_suspended`.
  {
    key: "fg_conformance_tenant_down",
    id: "key_conformance_tenant_down",
    tenant_id: "tenant_sdk_suspended",
    scopes: [],
  },
  // The 429 leg: its tenant carries an rpm_limit of 2 (see GATEWAY_QUOTA_POLICIES).
  { key: "fg_conformance_throttled", id: "key_throttled", tenant_id: "tenant_sdk_rpm", scopes: [] },
];

/**
 * Two upstreams, one per provider dialect.
 *
 * Both hostnames are `.test` (RFC 6761 reserved) and nothing ever resolves them:
 * `test/harness.ts` intercepts `globalThis.fetch` for the duration of each case.
 * The gateway's own dispatch path is untouched — it reads `globalThis.fetch` at
 * call time precisely so it can be intercepted.
 */
const PROVIDERS = [
  {
    name: "openai-upstream",
    kind: "openai",
    base_url: "https://api.openai.conformance.test/v1",
    // NAMES a binding; the value never appears in the provider table. The
    // binding below holds an obvious non-credential — no upstream is ever
    // dialled, so nothing here has to be, or may be, real.
    api_key_var: "CONFORMANCE_UPSTREAM_KEY",
  },
  {
    name: "anthropic-upstream",
    kind: "anthropic",
    base_url: "https://api.anthropic.conformance.test/v1",
    api_key_var: "CONFORMANCE_UPSTREAM_KEY",
  },
];

const MODELS = [
  {
    name: "gpt-4o-mini",
    provider: "openai-upstream",
    provider_model: "gpt-4o-mini-2024-07-18",
    context_window: 128_000,
  },
  {
    name: "claude-3-5-sonnet-20241022",
    provider: "anthropic-upstream",
    provider_model: "claude-3-5-sonnet-20241022",
  },
  // An Anthropic-protocol request served by an OPENAI upstream — the
  // translate-in/translate-out leg an "/v1/messages against any model" claim
  // depends on.
  {
    name: "claude-on-openai",
    provider: "openai-upstream",
    provider_model: "gpt-4o-mini-2024-07-18",
  },
];

/**
 * `tenant_sdk_rpm` gets 2 requests per minute so the 429 leg is deterministic
 * and needs no clock control: the third request in a file is refused.
 *
 * Read by `quotaPolicySourceFromEnv` (`apps/gateway/src/ratelimit/quota.ts`)
 * ONLY while no control database is bound. `apps/gateway/wrangler.toml` binds
 * `BILLING_DB`, which is the control database and therefore wins — so
 * `test/errors.test.ts` seeds the equivalent `quota_policies` ROW instead and
 * this table is the documented fallback, not the live source. Both are kept in
 * step deliberately: if the binding is ever dropped, the leg still runs.
 */
const QUOTA_POLICIES = [{ scope_type: "tenant", scope_id: "tenant_sdk_rpm", rpm_limit: 2 }];

/**
 * The `[[services]] binding = "TELEMETRY_COLLECTOR"` target.
 *
 * Not optional: miniflare REFUSES TO START a Worker whose service binding names
 * an undefined service, so without this stub every file here errors before it is
 * imported. It answers 204 and records nothing — no `TELEMETRY_TOKEN` is set, so
 * the gateway never emits to it anyway.
 */
const TELEMETRY_COLLECTOR_STUB = {
  name: "ferrogate-telemetry",
  modules: true,
  script: "export default { fetch: () => new Response(null, { status: 204 }) };",
} as const;

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "../../apps/gateway/wrangler.toml" },
      // LOAD-BEARING since #673 put an `[ai]` stanza in the committed deploy
      // config: an AI binding is classified remote-only, so the default
      // (`true`) makes this pool open a proxy session against the live
      // Cloudflare API and every file here dies before collection with
      // "it's necessary to set a CLOUDFLARE_API_TOKEN environment variable"
      // (measured 2026-08-02, wrangler 4.116). `false` keeps the suite
      // hermetic — `env.AI` still exists and throws
      // "Binding AI needs to be run remotely" if anything ever calls it.
      // `apps/gateway/vitest.config.ts` carries the identical line for the
      // identical reason; the two must stay in step.
      remoteBindings: false,
      miniflare: {
        bindings: {
          GATEWAY_NATIVE_API_KEYS: JSON.stringify(NATIVE_API_KEYS),
          GATEWAY_STATIC_API_KEYS: "[]",
          ASSET_ENTITLEMENTS: JSON.stringify({
            tenant_sdk: { asset_hosting_enabled: true },
          }),
          SELF_HOSTED_WORKER_REGISTRY: "[]",
          TENANCY_LIFECYCLE: JSON.stringify({ tenant_sdk_suspended: "suspended" }),
          TENANT_RBAC_ACTIONS: "{}",
          GATEWAY_PROVIDERS: JSON.stringify(PROVIDERS),
          GATEWAY_MODELS: JSON.stringify(MODELS),
          GATEWAY_QUOTA_POLICIES: JSON.stringify(QUOTA_POLICIES),
          // The value `api_key_var` names. NOT a credential: no request in this
          // suite leaves workerd, and the string is asserted against in
          // `test/chat.test.ts` to show the gateway substitutes its OWN
          // upstream credential for the caller's.
          CONFORMANCE_UPSTREAM_KEY: "upstream-key-placeholder-not-a-credential",
          TEST_D1_SCHEMA: migrations,
        },
        workers: [TELEMETRY_COLLECTOR_STUB],
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
    setupFiles: ["./test/setup.ts"],
  },
});
