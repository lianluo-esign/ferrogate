/**
 * `/control/v1/*` → `/admin/v1/*` canonicalization, applied BEFORE routing.
 *
 * `ROUTE-MAP.md` invariant 7 and `crates/ferrogate-admin/src/control_plane.rs`:
 * `/control/v1` is the legacy alias of the Control Plane API and `/admin/v1` is
 * its canonical spelling. The Rust ingress folds the alias at `request_filter`
 * time — before the route table is consulted — so both prefixes observe **one**
 * route table, one guard, one set of error codes. Folding any later (per-route
 * aliases, a duplicate router) is exactly how the two spellings drift apart.
 *
 * Hono resolves the whole middleware+handler chain in a single `router.match()`
 * at dispatch, so a Hono `use()` middleware is already TOO LATE to change which
 * route is selected. The fold is therefore a wrapper around `app.fetch`: the
 * `Request` handed to Hono has already been rewritten, and everything
 * downstream — the contract match, the auth middleware, the handler, the error
 * envelope — is oblivious to which spelling the client used.
 *
 * Whole-segment semantics come straight from the Rust unit tests
 * (`control_plane_test.rs`): `/control/v1` → `/admin/v1`, `/control/v1/x` →
 * `/admin/v1/x`, while `/control/v1x`, `/control/v1x/y`, `/control` and
 * `/controlled/v1` are NOT the alias — they are different resources and must
 * never be captured.
 */
import { canonicalizeAliasPath } from "../contract.js";

/**
 * Rewrite an alias URL onto its canonical form, preserving query and fragment.
 * Returns `null` when `url` is not an alias.
 */
export function canonicalizeAliasUrl(url: string): string | null {
  const parsed = new URL(url);
  const canonical = canonicalizeAliasPath(parsed.pathname);
  if (canonical === null) return null;
  parsed.pathname = canonical;
  return parsed.toString();
}

/**
 * Return the request the router should see. An alias request is rebuilt at its
 * canonical URL — never redirected: an alias is the SAME operation, not a
 * different location, so a 30x would be a behaviour change (and would break
 * every non-redirect-following CLI/SDK client the Rust tree serves).
 */
export function canonicalizeAliasRequest(request: Request): Request {
  const canonicalUrl = canonicalizeAliasUrl(request.url);
  if (canonicalUrl === null) return request;
  return new Request(canonicalUrl, request);
}

/** A `fetch` handler, as a Worker default export exposes it. */
export interface FetchLike<Env> {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Response | Promise<Response>;
}

/**
 * Wrap a Hono app so `/control/v1/*` is folded onto `/admin/v1/*` before Hono
 * routes. Use as the Worker's default export.
 */
export function withAliasCanonicalization<Env>(app: FetchLike<Env>): FetchLike<Env> {
  return {
    fetch(request, env, ctx) {
      return app.fetch(canonicalizeAliasRequest(request), env, ctx);
    },
  };
}
