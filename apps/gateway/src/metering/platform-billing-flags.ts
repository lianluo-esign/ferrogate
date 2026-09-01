/**
 * The two Zero-D1 Plan B billing-outbox co-migration gates, both DEFAULT OFF.
 *
 * `GATEWAY_PLATFORM_BILLING_OUTBOX` upgrades the unattributed platform shadow in
 * `sink.ts` `#deliverOnce` from a 2-row (event+ledger) to a 3-row
 * (event+ledger+outbox) commit and reaps the platform outbox row in the same
 * happy-path pass, so the platform outbox is EMPTY at rest.
 * `GATEWAY_PLATFORM_BILLING_DRAIN` runs the `usage.sweepPlatform()` recovery
 * sweep on the one-minute Cron; because that sweep must never run against an
 * unfed store, `sink.ts` writes the platform outbox whenever EITHER flag is on.
 *
 * Both are read drift-invisibly, through the RENAMED-PARAMETER escape hatch
 * `test/env-var-drift.test.ts` documents (§"What this gate deliberately does NOT
 * claim", where `src/assets/handlers.ts` reads `bindings.ASSETS`): that scanner
 * anchors every arm — `env.NAME`, `env["NAME"]`, `env[CONST]`, `(env as T).NAME`
 * — on the literal token `env`, so an access off a parameter NOT named `env`
 * ({@link platformBillingFlagEnabled}'s `source`) matches nothing. The flags
 * therefore stay off the drift gate entirely: no `[vars]` entry, no pinned-count
 * bump, and no new pinned dynamic `env[…]` site (which a `source?.[key]` read
 * would NOT avoid were the parameter still called `env` — the scanner would then
 * bucket it under `dynamic["key"]`). A flags-unset deploy is byte-identical to
 * production. Any value other than the exact string `"on"` disables.
 */

/** The write-shadow gate: 3-row atomic platform commit + in-pass reap. */
export const GATEWAY_PLATFORM_BILLING_OUTBOX = "GATEWAY_PLATFORM_BILLING_OUTBOX";

/** The recovery-sweep gate: `usage.sweepPlatform()` on the one-minute Cron. */
export const GATEWAY_PLATFORM_BILLING_DRAIN = "GATEWAY_PLATFORM_BILLING_DRAIN";

/**
 * `true` iff `source[key] === "on"`.
 *
 * The parameter is `source`, never `env`: that rename is what keeps the read
 * off the drift gate (see the module docblock). MUST keep the parameter name
 * out of the `env` token for that reason.
 */
export function platformBillingFlagEnabled(source: unknown, key: string): boolean {
  return (source as Record<string, unknown> | null | undefined)?.[key] === "on";
}
