/**
 * The carrier for the tags the gate DEFAULTED onto one request (#678).
 *
 * A `WeakMap` keyed by the inbound `Request`, for the same three reasons
 * `requestlog/facts.ts` and `inference/identity.ts` give for theirs: the
 * enforcement middleware runs on the OUTER app while the handler that stamps
 * `Usage.metadata` runs inside `inner.fetch`'s fresh Hono context, so a context
 * variable cannot cross; a module-level "current request" is a cross-request
 * leak the first time two requests interleave on an `await` — and this value is
 * one tenant's attribution, so that leak would be a chargeback error; and the
 * `Request` is per-request by construction and collected with the request.
 *
 * Only the DEFAULTS travel, never the effective map. The caller's own tags are
 * already in the body the handler parses, so re-carrying them would create a
 * second source of truth for the same fact.
 */

import type { TagMap } from "./policy.js";

const DEFAULTS = new WeakMap<Request, TagMap>();

/** Nothing was defaulted — shared, so the common path allocates nothing. */
const NONE: TagMap = Object.freeze({});

/**
 * Publish the tags the gate supplied for `request`.
 *
 * Never throws: a `WeakMap` rejects a non-object key, and a bookkeeping failure
 * must not become a client-visible one. An empty map is not stored at all,
 * which keeps {@link attributionDefaultsFor} on its allocation-free path.
 */
export function recordAttributionDefaults(request: Request, defaults: TagMap): void {
  if (Object.keys(defaults).length === 0) return;
  try {
    DEFAULTS.set(request, defaults);
  } catch {
    // See above — best effort. The consequence is that the request is served
    // with the caller's own tags only, which is the pre-#678 behaviour.
  }
}

/** The tags defaulted for `request`, or an empty map. */
export function attributionDefaultsFor(request: Request): TagMap {
  try {
    return DEFAULTS.get(request) ?? NONE;
  } catch {
    return NONE;
  }
}
