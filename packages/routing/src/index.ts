/**
 * `@ferrogate/routing` — route match + canary/shadow rollout selection.
 *
 * Faithful clean-room port of the Rust crate `ferrogate-routing`
 * (`lib.rs` + `rollout.rs`). Pure, deterministic primitives shared by the
 * gateway's request path; zero I/O.
 *
 *  - `fnv`     — FNV-1a64 hash + the deterministic `rolloutBucket` (byte-identical
 *                to Rust: exact FNV constants and `salt\0key` framing).
 *  - `rollout` — `canarySelected` / `shadowSampled` / `ShadowBudgetLedger`.
 *  - `route`   — `RouteMatch` / `RouteMatcher` (the dynamic-route abstraction).
 *
 * `ShadowBudgetDurableObject` / `DurableObjectShadowBudgetLedger` — the
 * cross-isolate shadow budget — are NOT re-exported here. They `import
 * "cloudflare:workers"`, which only resolves inside `workerd`, and this barrel
 * is imported from plain-node contexts (the CLI, plain vitest suites). They are
 * reachable at the `@ferrogate/routing/durable-objects` subpath instead; only
 * the ledger INTERFACE, whose import is type-only and therefore erased, is
 * re-exported below.
 *
 * ## THE "THIS PACKAGE IS NOT MOUNTED" MARKER IS CLOSED — do not re-add it
 *
 * It claimed a recursive grep for `from "@ferrogate/routing"` across every
 * `src` under `apps` and `packages` returned exactly one hit, inside a
 * docstring. That is now false in every clause, and each replacement is
 * checkable:
 *
 *  - **Canary rollout is live.** `apps/gateway/src/inference/candidates.ts`
 *    value-imports `canarySelected`, and `applyCanary` runs on the deployed
 *    resolution path in `src/inference/handlers.ts`.
 *    `apps/gateway/test/inference/reliability.test.ts` drives the real
 *    `createInferenceRouter` with only the outbound provider `fetch`
 *    intercepted, declares the canary at a LOWER priority than the primary so
 *    nothing but `applyCanary` can promote it, and computes the expected split
 *    from this package's own `rolloutBucket` — a second bucketing
 *    implementation in the gateway would diverge and fail.
 *  - **Shadow mirroring is live.** `apps/gateway/src/inference/shadow.ts`
 *    value-imports `shadowSampled` + `ShadowBudgetLedger` here and
 *    `DurableObjectShadowBudgetLedger` from the `/durable-objects` subpath,
 *    and `handlers.ts` fires the mirror.
 *  - **`ShadowBudgetDurableObject` is mounted.** `apps/gateway/src/worker.ts`
 *    re-exports it from `@ferrogate/routing/durable-objects` and
 *    `apps/gateway/wrangler.toml` declares the `SHADOW_BUDGET` binding, so the
 *    shadow cap is cross-isolate rather than N-per-isolate. Both halves are
 *    required by the workerd entry-module rule and both are present.
 *
 * ## PORT-TODO(inventory-request-path §1.3) — `RouteMatcher` HAS NO IMPLEMENTOR.
 * ## DEFERRED FEATURE, NOT A PLATFORM LIMIT, NOT A WIRING MISS, NOT CLOSED.
 *
 * `route.ts` ships `RouteMatch` + `RouteMatcher` and stops there, which is
 * FAITHFUL: the Rust crate `ferrogate-routing` also ships only the trait — the
 * concrete matcher lives in the gateway over `AppState`'s hot-reloadable
 * runtime route table (`state_routing.rs:816 match_runtime_route`). Adding a
 * concrete matcher to this package would diverge from the crate, not close the
 * gap, so it deliberately is not here.
 *
 * What is genuinely missing is the CONSUMER, and it is outside this package:
 * the operator reverse-proxy fall-through marked at
 * `apps/gateway/src/routes/index.ts:379`. Until it lands, an operator's
 * `[[routes]]`/`[[upstreams]]` config validates cleanly in `packages/config`
 * and proxies nothing — a request matching no route group 404s instead of
 * falling through. That implementor is what `RouteMatcher` exists for; the
 * upstream rotation it needs (`select_runtime_upstream_endpoint`) has no
 * counterpart here either.
 *
 * The bucketing must stay byte-exact against Rust (`fnv.ts` keeps the
 * `0xcbf29ce484222325` / `0x100000001b3` constants and the `salt\0key`
 * framing); `test/fnv.test.ts` pins it against the Rust vectors.
 * See `docs/rewrite/parity-audit-request-path.md` F7 and
 * `docs/rewrite/parity-audit-dead-packages.md` §4.
 */

export { fnv1a64, rolloutBucket } from "./fnv.js";
export { canarySelected, shadowSampled, ShadowBudgetLedger } from "./rollout.js";
export type { RouteMatch, RouteMatcher } from "./route.js";
export type { AsyncShadowBudgetLedger } from "./shadow-budget-do.js";
