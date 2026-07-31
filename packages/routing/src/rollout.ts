/**
 * Canary + shadow/mirror rollout selection (issue #276).
 *
 * Clean-room port of `ferrogate-routing::rollout`. Pure, deterministic
 * selection primitives shared by the gateway's request path. Canary picks a
 * sticky percentage of traffic for a new provider/model (evaluated fully, like
 * the primary route); shadow picks a sampled, budget-capped fraction of traffic
 * to *mirror* to a secondary provider without affecting the client response.
 *
 * Both decisions hash a caller-stable *sticky key* (api key / tenant) via
 * {@link rolloutBucket} so a given caller lands consistently on (or off) the
 * split, and so tests can assert an exact distribution from a fixed set of keys.
 */
import { rolloutBucket } from "./fnv.js";

/**
 * True when a request with `stickyKey` falls in the canary bucket for the given
 * percentage. `0` never selects, `>= 100` always selects, and every value in
 * between is sticky per key (same key -> same answer). Uses the `"canary"` salt.
 */
export function canarySelected(stickyKey: string, percent: number): boolean {
  if (percent <= 0) {
    return false;
  }
  if (percent >= 100) {
    return true;
  }
  return rolloutBucket("canary", stickyKey) < percent;
}

/**
 * True when a request with `stickyKey` is sampled for shadow mirroring. Uses a
 * distinct salt (`"shadow"`) from {@link canarySelected} so the two rollouts
 * sample independent subsets of callers.
 */
export function shadowSampled(stickyKey: string, samplePercent: number): boolean {
  if (samplePercent <= 0) {
    return false;
  }
  if (samplePercent >= 100) {
    return true;
  }
  return rolloutBucket("shadow", stickyKey) < samplePercent;
}

/**
 * Process-lifetime budget cap for shadow-mirror dispatches, keyed by an
 * arbitrary budget scope (the gateway keys it by logical model). Caps the
 * mirror's cost: once `limit` shadow requests have been admitted for a key,
 * further requests are refused until the process restarts. `limit === 0` means
 * uncapped.
 *
 * PORT-TODO(inventory §2.8): the Rust type is a `Mutex<HashMap>` counter scoped
 * to one process. On Workers there is no single long-lived process, so a
 * cross-isolate cap must be backed by a **Durable Object** counter (or KV, with
 * the same non-atomic caveat as the gateway rate-limit counters). This class
 * preserves the exact per-isolate semantics; the DO/KV binding wiring belongs in
 * apps/gateway. JS is single-threaded so the mutex/poison-recovery logic
 * collapses to a plain Map with no locking.
 */
export class ShadowBudgetLedger {
  readonly #used = new Map<string, number>();

  /**
   * Admits one shadow dispatch against `key`, returning `true` when it is within
   * budget (and charging it), or `false` when the cap is reached. `limit === 0`
   * is uncapped and records nothing.
   */
  tryConsume(key: string, limit: number): boolean {
    if (limit === 0) {
      return true;
    }
    const current = this.#used.get(key) ?? 0;
    if (current >= limit) {
      return false;
    }
    this.#used.set(key, current + 1);
    return true;
  }

  /** Number of shadow dispatches charged so far against `key`. */
  consumed(key: string): number {
    return this.#used.get(key) ?? 0;
  }
}
