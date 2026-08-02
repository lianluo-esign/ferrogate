/**
 * Counter-key derivation — the SECURITY-CRITICAL half of this module.
 *
 * A counter key names a shared rate-limit window. Two requests that derive the
 * same key contend for the same budget, so "which string is the key" IS an
 * isolation boundary: if a tenant could make its per-key window collide with
 * another tenant's aggregate window, it would drain a victim's RPM/TPM budget
 * and deny them service (cross-tenant DoS).
 *
 * The invariant, ported from `ferrogate_policy::QuotaScopeSelector::counter_key`
 * and `ferrogate_gateway::auth::AuthContext::request_windows`:
 *
 *   **EVERY key is `"{kind}:{id}"`-namespaced, including the `key` scope.**
 *
 * A key-scope winner is `"key:{api_key_id}"`, never the bare, tenant-controllable
 * `api_key_id`. So a tenant that mints a virtual key whose id is literally
 * `"tenant:victim"` produces `"key:tenant:victim"` — structurally unequal to the
 * victim's `"tenant:victim"` aggregate window.
 *
 * That derivation is NOT re-implemented here: {@link QuotaScopeSelector.counterKey}
 * from `@ferrogate/policy` is called directly, so there is exactly one copy of
 * the rule in the tree. What this module adds is the second half a port needs:
 * a boundary check ({@link assertNamespacedCounterKey}) that refuses to address
 * a Durable Object with any string that is not namespaced, so a future caller
 * cannot re-introduce the raw-id path without the request failing loudly.
 */
import {
  type EffectiveQuota,
  type QuotaScopeKind,
  QuotaScopeSelector,
  quotaScopeKindFromStr,
} from "@ferrogate/policy";

/** One `(counterKey, limit)` admission window. Rust `(String, u64)`. */
export interface CounterWindow {
  /** ALWAYS `"{kind}:{id}"` — see {@link assertNamespacedCounterKey}. */
  readonly counterKey: string;
  readonly limit: number;
}

/** Thrown when a counter key is not scope-namespaced. Never reaches a client. */
export class CounterKeyNamespaceError extends Error {
  override readonly name = "CounterKeyNamespaceError";
  constructor(readonly counterKey: string) {
    super(
      `counter key ${JSON.stringify(counterKey)} is not scope-namespaced; expected "{tenant|project|workspace|key}:{id}"`,
    );
  }
}

/**
 * Split a counter key into its scope kind and id, or `null` if it is not a
 * legal counter key.
 *
 * Only the FIRST `:` separates — `"key:tenant:victim"` is
 * `{ kind: "key", id: "tenant:victim" }`, which is precisely the case the
 * namespacing defends: the attacker's colon-bearing id stays inside the id half
 * and can never be re-read as a `tenant` scope.
 */
export function parseCounterKey(
  counterKey: string,
): { readonly kind: QuotaScopeKind; readonly id: string } | null {
  const separator = counterKey.indexOf(":");
  if (separator <= 0) return null;
  const kind = quotaScopeKindFromStr(counterKey.slice(0, separator));
  if (kind === undefined) return null;
  const id = counterKey.slice(separator + 1);
  if (id === "") return null;
  return { kind, id };
}

/** `true` iff `counterKey` carries a known scope namespace and a non-empty id. */
export function isNamespacedCounterKey(counterKey: string): boolean {
  return parseCounterKey(counterKey) !== null;
}

/**
 * Fail-closed boundary guard. Every entry point that can address a counter
 * window ({@link RateLimiter} implementations, the DO stub factory) runs this
 * first, so a raw `api_key_id` — or any other unnamespaced, caller-influenced
 * string — can never become a Durable Object name.
 *
 * This is defense in depth, not the primary control: the primary control is
 * that all derivation goes through `QuotaScopeSelector.counterKey`. The guard
 * exists because "the derivation is correct today" is not a property a future
 * call site preserves on its own.
 */
export function assertNamespacedCounterKey(counterKey: string): void {
  if (!isNamespacedCounterKey(counterKey)) {
    throw new CounterKeyNamespaceError(counterKey);
  }
}

/**
 * The counter key for a scope selector — the ONE derivation site.
 *
 * Delegates to `@ferrogate/policy`. `apiKeyId` is only consulted for the `key`
 * scope (a `key`-scoped policy's own `scopeId` is the policy row's subject,
 * while the window must be per *presented credential*), matching Rust.
 */
export function counterKeyForScope(scope: QuotaScopeSelector, apiKeyId: string): string {
  const key = scope.counterKey(apiKeyId);
  assertNamespacedCounterKey(key);
  return key;
}

/** The per-credential window key, `"key:{api_key_id}"`. Rust `per_key_counter`. */
export function perKeyCounterKey(apiKeyId: string): string {
  return counterKeyForScope(new QuotaScopeSelector("key", apiKeyId), apiKeyId);
}

/**
 * Port of `AuthContext::request_windows()` — the RPM windows a request is
 * admitted against, in Rust's order.
 *
 * Two independent sources can impose an RPM cap:
 *
 *  1. the TOK-12 per-key `request_limit_per_minute` on the credential itself,
 *     always counted at `"key:{api_key_id}"`;
 *  2. the merged quota chain's `rpm_limit`, counted at the scope that WON the
 *     `min` — so a tenant/project/workspace cap is one aggregate window shared
 *     by every key beneath it, while a key-scoped cap stays per-key.
 *
 * When both land on the same counter key they are collapsed to the tighter of
 * the two (`existing.1 = existing.1.min(limit)`) rather than charged twice,
 * exactly as Rust's `add` closure does.
 */
export function requestWindows(
  apiKeyId: string,
  quota: EffectiveQuota,
  requestLimitPerMinute?: number,
): CounterWindow[] {
  const perKey = perKeyCounterKey(apiKeyId);
  const windows: { counterKey: string; limit: number }[] = [];
  const add = (counterKey: string, limit: number): void => {
    const existing = windows.find((w) => w.counterKey === counterKey);
    if (existing !== undefined) {
      existing.limit = Math.min(existing.limit, limit);
      return;
    }
    windows.push({ counterKey, limit });
  };

  if (requestLimitPerMinute !== undefined) {
    add(perKey, requestLimitPerMinute);
  }
  if (quota.rpmLimit !== undefined) {
    const scope = quota.rpmLimitScope;
    add(scope === undefined ? perKey : counterKeyForScope(scope, apiKeyId), quota.rpmLimit);
  }
  return windows;
}

/**
 * Port of `AuthContext::tpm_window()` — the single TPM window, or `null`.
 *
 * TPM only ever comes from the quota chain (there is no per-key TOK-12 TPM), so
 * the counter is the scope whose `tpm_limit` won the `min`.
 *
 * PORT-DEVIATION (deliberate, security): when a TPM limit is present but its
 * winning scope is absent, Rust falls back to `api_key_id.to_string()` — the
 * RAW id, with no `"key:"` prefix (state.rs / auth.rs `tpm_window`), unlike
 * `request_windows`, which falls back to the namespaced `per_key_counter`. That
 * asymmetry is reachable: `resolveEffectiveQuota` sets a plan-default TPM with
 * NO scope when the chain carries no `tenantId`, and it is exactly the
 * collision the namespacing exists to prevent — an api key whose id is
 * `"tenant:victim"` would consume the victim tenant's aggregate TPM window.
 * This port uses the namespaced `"key:{api_key_id}"` fallback for both
 * dimensions. No behavior is dropped (the window is still per credential, with
 * the same limit); only the reachable cross-tenant collision is closed.
 */
export function tpmWindow(apiKeyId: string, quota: EffectiveQuota): CounterWindow | null {
  if (quota.tpmLimit === undefined) return null;
  const scope = quota.tpmLimitScope;
  const counterKey =
    scope === undefined ? perKeyCounterKey(apiKeyId) : counterKeyForScope(scope, apiKeyId);
  return { counterKey, limit: quota.tpmLimit };
}

/**
 * The counter key for the monthly-token-budget hold. Rust keys
 * `token_reservations` on the bare `api_key_id`; namespaced here for the same
 * reason as {@link tpmWindow}. Budget holds live in their own field of the DO,
 * so sharing an instance with the RPM window is not a collision.
 */
export function tokenBudgetCounterKey(apiKeyId: string): string {
  return perKeyCounterKey(apiKeyId);
}

/**
 * The counter key for a prepaid-wallet credit hold. Rust keys
 * `wallet_reservations` on the bare tenant id (`organization_id`); namespaced
 * to `"tenant:{id}"` here, which is also what the quota merge already uses for
 * a tenant-scope window.
 */
export function walletCounterKey(tenantId: string): string {
  return counterKeyForScope(new QuotaScopeSelector("tenant", tenantId), tenantId);
}
