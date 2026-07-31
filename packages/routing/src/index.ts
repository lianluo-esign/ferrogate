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
 */

export { fnv1a64, rolloutBucket } from "./fnv.js";
export { canarySelected, shadowSampled, ShadowBudgetLedger } from "./rollout.js";
export type { RouteMatch, RouteMatcher } from "./route.js";
