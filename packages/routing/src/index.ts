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
 * ## PORT-TODO(inventory-request-path §2, §1.7) — THIS PACKAGE IS NOT MOUNTED
 *
 * Every export below is fully ported, covered by 28 tests, and **imported by
 * zero application code**. A recursive grep for `from "@ferrogate/routing"`
 * across every `src` directory in `apps` and `packages` returns exactly one
 * hit, and it is inside a docstring in
 * `./shadow-budget-do.ts`. `@ferrogate/routing` is a declared dependency of
 * `apps/gateway/package.json` and no module in `apps/gateway/src` imports it.
 *
 * This is the defect class the porting rules name: implemented, tested, green —
 * and dead in production. Concretely unreachable today:
 *
 *  - **Canary rollout.** Rust `AppState::canary_route` (`state_rollout.rs:47`)
 *    calls `canary_selected(sticky_key, canary.percent)` to divert a sticky
 *    subset of traffic to a canary route. `packages/config` validates
 *    `canaryRouteSchema` (`schema/entities.ts:65`), so an operator can configure
 *    a canary, pass validation, and have 0% of traffic reach it.
 *  - **Shadow mirroring.** `server/shadow.rs:69` gates the mirror on
 *    `shadow_sampled(...)` and `:78` caps it with
 *    `shadow_budget_try_consume(logical_model, shadow.max_requests)`. No shadow
 *    dispatch exists in `apps/gateway` at all.
 *  - **`ShadowBudgetDurableObject`.** Exported from no `worker.ts` and bound in
 *    no `wrangler.toml`. Per the workerd entry-module rule, wiring it requires
 *    the owning app to add `export { ShadowBudgetDurableObject } from
 *    "@ferrogate/routing/durable-objects";` to its entry module AND a matching
 *    `[[durable_objects.bindings]]` + `[[migrations]]` block, or the Worker
 *    fails at startup with "Durable Object class ... not found" — a failure
 *    `@cloudflare/vitest-pool-workers` does NOT reproduce.
 *  - **`RouteMatcher`** is an interface with no implementation and no caller;
 *    see the PORT-TODO in `apps/gateway/src/routes/index.ts` on the operator
 *    reverse-proxy fall-through, which is what would implement it.
 *
 * The bucketing itself is byte-exact against Rust and must stay that way when
 * this is wired up (`fnv.ts` keeps the `0xcbf29ce484222325` /
 * `0x100000001b3` constants and the `salt\0key` framing). When a consumer
 * lands, it must ship an assertion that FAILS if the rollout call is removed —
 * a test that only exercises `canarySelected` directly would stay green through
 * exactly the state this marker describes.
 * See `docs/rewrite/parity-audit-request-path.md` F7.
 */

export { fnv1a64, rolloutBucket } from "./fnv.js";
export { canarySelected, shadowSampled, ShadowBudgetLedger } from "./rollout.js";
export type { RouteMatch, RouteMatcher } from "./route.js";
export type { AsyncShadowBudgetLedger } from "./shadow-budget-do.js";
