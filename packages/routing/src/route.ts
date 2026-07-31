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
 * PORT-TODO(inventory §2.8): the concrete implementation is a Hono / `matchit`
 * equivalent over the runtime route table and lives in apps/gateway; this
 * package ships only the interface the data plane implements, matching the Rust
 * crate which likewise ships only the trait.
 */
export interface RouteMatcher {
  matchRoute(host: string | undefined, path: string): RouteMatch | undefined;
}
