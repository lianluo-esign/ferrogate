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
 * ## THE "`RouteMatcher` HAS NO IMPLEMENTOR" MARKER IS CLOSED — do not re-add it
 *
 * It read "`RouteMatcher` HAS NO IMPLEMENTOR … what is genuinely missing is the
 * CONSUMER, and it is outside this package: the operator reverse-proxy
 * fall-through marked at `apps/gateway/src/routes/index.ts:379`". That
 * fall-through has since LANDED, so the marker's one factual claim is false and
 * a stale marker is worse than none — it teaches the next reader that a shipped
 * feature is missing.
 *
 * The implementor, checkable by file:line:
 * `apps/gateway/src/routes/reverse-proxy.ts:133` declares
 * `export class RuntimeRouteTable implements RouteMatcher`, with
 * `matchRoute(host: string | undefined, path: string): RouteMatch | undefined`
 * at `:179` — the exact signature `route.ts` fixes — built from the
 * `GATEWAY_ROUTES` / `GATEWAY_UPSTREAMS` vars through `@ferrogate/config`'s
 * `routeRuleSchema` / `upstreamSchema`, mounted on the app the Worker exports
 * (`apps/gateway/src/routes/index.ts` → `src/index.ts`) and gated by
 * `apps/gateway/test/routes/reverse-proxy.test.ts`. Rust's
 * `select_runtime_upstream_endpoint` rotation landed there too, which is where
 * it belongs: the Rust crate `ferrogate-routing` does not ship it either.
 *
 * What has NOT changed, and must not be "fixed": `route.ts` still ships only
 * `RouteMatch` + `RouteMatcher`. That is FAITHFUL — the Rust crate also ships
 * only the trait (`crates/ferrogate-routing/src/lib.rs`, 21 lines, `pub trait
 * RouteMatcher` and nothing that implements it), because the concrete matcher
 * needs `AppState`'s hot-reloadable route table. Adding a concrete matcher HERE
 * would diverge from the crate, and would hand the gateway a second matcher to
 * disagree with. `test/route.test.ts` pins what this package genuinely owes:
 * that the interface is satisfiable by an ordinary object and that a miss is
 * `undefined` rather than a throw or a fallback route — a fallback would
 * silently send an unrouted request to some upstream.
 *
 * Note for whoever next reads the gateway side: its module docstring still
 * calls the class `ConfigRouteMatcher`, which is the name it was written under;
 * the exported class is `RuntimeRouteTable`. That rename is an `apps/gateway`
 * edit, not a gap here.
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
