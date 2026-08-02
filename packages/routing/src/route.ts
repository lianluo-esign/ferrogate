/**
 * Route matching boundary.
 *
 * Clean-room port of the `RouteMatch` struct and `RouteMatcher` trait from the
 * Rust crate `ferrogate-routing` (`lib.rs`). In the Rust code the trait is the
 * abstract dynamic-route matcher, implemented over `AppState`'s hot-reloadable
 * runtime route table; the crate itself ships only the abstraction (no concrete
 * matcher), so the faithful port is the interface pair.
 */

/** A resolved dynamic route: its logical name and the upstream it targets. */
export interface RouteMatch {
  routeName: string;
  upstreamName: string;
}

/**
 * The abstract dynamic-route matcher. Implementors resolve an optional `host`
 * plus request `path` to a {@link RouteMatch}, or `undefined` when no runtime
 * route matches (Rust `Option<RouteMatch>` → `RouteMatch | undefined`).
 *
 * The port is COMPLETE at this layer and deliberately stops here: the Rust
 * crate `ferrogate-routing` itself ships only the trait — the concrete matcher
 * lives in the gateway, over `AppState`'s hot-reloadable runtime route table.
 * Shipping a matcher here would be a divergence from the crate, not a closure.
 * The TS concrete implementation is correspondingly a Hono/`matchit` matcher in
 * `apps/gateway`.
 */
export interface RouteMatcher {
  matchRoute(host: string | undefined, path: string): RouteMatch | undefined;
}
