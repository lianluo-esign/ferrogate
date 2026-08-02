/**
 * The RPM counter layer of the MCP admission gate — Rust
 * `auth.rs::require_request_budget` plus `AuthContext::request_windows()`.
 *
 * ## Counter-key derivation is SECURITY-CRITICAL and is NOT written here
 *
 * A counter key names a shared rate-limit window, so "which string is the key"
 * IS an isolation boundary: if a tenant could make its per-key window collide
 * with another tenant's aggregate window it would drain the victim's budget and
 * deny them service. The invariant is
 *
 *   **every key is `"{kind}:{id}"`-namespaced, including the `key` scope**,
 *
 * so a tenant that mints a virtual key whose id is literally `"tenant:victim"`
 * produces `"key:tenant:victim"` — structurally unequal to the victim's
 * `"tenant:victim"` window. That derivation lives in ONE place in the tree,
 * `@ferrogate/policy`'s {@link QuotaScopeSelector.counterKey}, and this module
 * calls it rather than re-deriving it. What this module adds is the boundary
 * check ({@link assertNamespacedCounterKey}) that refuses to address a counter
 * with any string that is not namespaced, so a future call site cannot
 * re-introduce the raw-id path silently.
 *
 * ## One counter namespace across Workers, not one per Worker
 *
 * `docs/rewrite/CUTOVER-READINESS.md` finding D1 states the requirement
 * precisely: the fix "needs all three Workers to share ONE counter namespace,
 * or a per-Worker counter hands each surface a full quota (a different bug)".
 *
 * So this app declares NO Durable Object class of its own. {@link RateLimiterNamespace}
 * is the structural shape of `apps/gateway`'s ALREADY-DEPLOYED
 * `RateLimiterDurableObject`, and the integrate step binds that same namespace
 * here with a cross-script `script_name` (see `./index.ts` for the exact
 * stanza). A key at 60 rpm is then charged the same window whether it calls
 * `/v1/chat/completions` or MCP `tools/call`, which is the whole point.
 *
 * With NO namespace bound the {@link InMemoryMcpRateLimiter} is used. It is
 * per-isolate, so N isolates give N independent counters and a limit of 60 rpm
 * silently becomes 60·N — stated loudly here because it is a real degradation.
 * It is still strictly better than the alternative of not counting at all: a
 * misconfigured deploy that served unlimited traffic is the defect this file
 * exists to close. `apps/gateway/src/ratelimit/memory.ts` makes the same trade
 * for the same reason.
 */
import {
  type EffectiveQuota,
  type QuotaScopeKind,
  QuotaScopeSelector,
  quotaScopeKindFromStr,
} from "@ferrogate/policy";

/** The Rust window length (`ApiKeyRequestWindow`). */
export const WINDOW_SECONDS = 60;

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
 * Split a counter key into its scope kind and id, or `null`.
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
 * window runs this first, so a raw `api_key_id` — or any other
 * caller-influenced string — can never become a Durable Object name.
 *
 * Defense in depth, not the primary control: the primary control is that all
 * derivation goes through {@link QuotaScopeSelector.counterKey}.
 */
export function assertNamespacedCounterKey(counterKey: string): void {
  if (!isNamespacedCounterKey(counterKey)) throw new CounterKeyNamespaceError(counterKey);
}

/**
 * The counter key for a scope selector — the ONE derivation site.
 *
 * `apiKeyId` is only consulted for the `key` scope (a `key`-scoped policy's own
 * `scopeId` is the policy row's subject, while the window must be per
 * *presented credential*), matching Rust.
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
 *  1. the TOK-12 per-key `request_limit_per_minute` carried on the credential
 *     itself, always counted at `"key:{api_key_id}"`;
 *  2. the merged quota chain's `rpm_limit`, counted at the scope that WON the
 *     `min` — so a tenant/project/workspace cap is one aggregate window shared
 *     by every key beneath it, while a key-scoped cap stays per-key.
 *
 * When both land on the same counter key they collapse to the tighter of the
 * two rather than being charged twice, exactly as Rust's `add` closure does.
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

  if (requestLimitPerMinute !== undefined) add(perKey, requestLimitPerMinute);
  if (quota.rpmLimit !== undefined) {
    const scope = quota.rpmLimitScope;
    add(scope === undefined ? perKey : counterKeyForScope(scope, apiKeyId), quota.rpmLimit);
  }
  return windows;
}

// ---------------------------------------------------------------------------
// The window arithmetic
// ---------------------------------------------------------------------------

/** Rust u64 saturating arithmetic, in a language with one number type. */
function saturatingSub(a: number, b: number): number {
  return Math.max(0, a - b);
}

/** Serializable state of one fixed window. */
interface WindowState {
  windowStartedAt: number;
  used: number;
}

/**
 * Roll the window over when `now` is a full {@link WINDOW_SECONDS} past its
 * start. A FIXED window anchored at first use, not minute-aligned or sliding:
 * the boundary moves to `now` on the first call after expiry. The classic
 * fixed-window burst (up to `2 * limit` across a boundary) is inherited from
 * Rust deliberately — changing it here would be a silent behaviour change, not
 * a port.
 */
function rollOver(state: WindowState, now: number): void {
  if (saturatingSub(now, state.windowStartedAt) >= WINDOW_SECONDS) {
    state.windowStartedAt = now;
    state.used = 0;
  }
}

/** Whole seconds until the current window expires; `0` when it already has. */
export function secondsUntilWindowReset(state: WindowState, now: number): number {
  return saturatingSub(WINDOW_SECONDS, saturatingSub(now, state.windowStartedAt));
}

/**
 * Requests-per-minute window. Rust `ApiKeyRequestWindow`.
 *
 * `limit === 0` rejects every request (`used >= 0` is immediately true), which
 * is the Rust behaviour and the reason a zero RPM policy is a hard stop rather
 * than "unlimited".
 */
export class RequestWindow {
  constructor(readonly state: WindowState = { windowStartedAt: 0, used: 0 }) {}

  /** Rust `try_consume(limit, now) -> bool`. Charges 1 on success. */
  tryConsume(limit: number, now: number): boolean {
    rollOver(this.state, now);
    if (this.state.used >= limit) return false;
    this.state.used += 1;
    return true;
  }
}

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

/**
 * The result of an RPM admission check.
 *
 * `unavailable` is a first-class outcome rather than a thrown error because
 * Rust distinguishes it: `try_consume_api_key_request` returns
 * `anyhow::Result<bool>`, and an `Err` becomes `503
 * governance_counter_unavailable`, NOT a 429. Collapsing the two would turn a
 * counter-backend outage into a rate-limit denial and hide it.
 */
export type RateLimitOutcome =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      readonly counterKey: string;
      readonly limit: number;
      readonly retryAfterSeconds: number;
    }
  | { readonly allowed: "unavailable"; readonly detail: string };

/**
 * The narrow limiter port the MCP admission gate codes against.
 *
 * Only the REQUEST dimension is here. TPM has no MCP counterpart: Rust charges
 * it in each AI handler once a token estimate exists (`server/chat.rs`), and an
 * MCP `tools/call` produces no such estimate — inventing one would be a new
 * control, not a port.
 */
export interface McpRateLimiter {
  /**
   * Rust:
   *
   * ```rust
   * for (counter_key, limit) in auth.request_windows() {
   *     require_request_budget(state, &counter_key, limit, request_id)?;
   * }
   * ```
   *
   * Windows are charged IN ORDER and the first denial short-circuits, so an
   * earlier window has already been incremented when a later one denies. That
   * is Rust's behaviour and is preserved deliberately: the windows are
   * independent budgets, and the partial charge is what makes a caller that
   * keeps retrying past a tenant cap also burn its own key budget rather than
   * probing for free.
   */
  consumeRequest(windows: readonly CounterWindow[]): Promise<RateLimitOutcome>;
}

// ---------------------------------------------------------------------------
// Backend 1 — the SHARED Durable Object namespace (production)
// ---------------------------------------------------------------------------

/** The reply shape of `apps/gateway`'s `RateLimiterDurableObject.consumeRequest`. */
export interface DoRequestResult {
  readonly allowed: boolean;
  readonly retryAfterSeconds: number;
}

/**
 * The binding shape this module needs, declared STRUCTURALLY.
 *
 * It is deliberately not an import of `apps/gateway`: one app must not depend
 * on another app's module graph. What is shared is the deployed NAMESPACE (via
 * `script_name`), which is a deploy-time fact, and the RPC method name +
 * argument list, which is the wire contract between the two — pinned by
 * `test/admission-wiring.test.ts` so a rename on either side is caught here.
 */
export interface RateLimiterNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): { consumeRequest(limit: number): Promise<DoRequestResult> };
}

/** Render a thrown value for the `governance_counter_unavailable` detail. */
function detailOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * The production limiter: one Durable Object instance per counter key, in the
 * namespace `apps/gateway` already deploys.
 *
 * FAIL-CLOSED NOTE. A DO RPC failure is reported as `unavailable` (→ 503),
 * never laundered into an allow. Rust's `Redis` cluster backend propagates the
 * same failure as `Err`, which is the 503; only its single-process `Local`
 * backend failed open, and that backend has no Workers analogue.
 */
export class DurableObjectMcpRateLimiter implements McpRateLimiter {
  constructor(private readonly namespace: RateLimiterNamespace) {}

  async consumeRequest(windows: readonly CounterWindow[]): Promise<RateLimitOutcome> {
    for (const window of windows) {
      // OUTSIDE the try: a namespacing violation is a programming error and
      // must propagate as a 500, never be laundered into the `unavailable`
      // arm, which would let a bad call site look like a transient outage.
      assertNamespacedCounterKey(window.counterKey);
      const stub = this.namespace.get(this.namespace.idFromName(window.counterKey));
      try {
        const result = await stub.consumeRequest(window.limit);
        if (!result.allowed) {
          return {
            allowed: false,
            counterKey: window.counterKey,
            limit: window.limit,
            retryAfterSeconds: result.retryAfterSeconds,
          };
        }
      } catch (error) {
        return { allowed: "unavailable", detail: detailOf(error) };
      }
    }
    return { allowed: true };
  }
}

// ---------------------------------------------------------------------------
// Backend 2 — single isolate (no namespace bound)
// ---------------------------------------------------------------------------

/**
 * A single-isolate limiter. The direct analogue of Rust's
 * `ClusterCounterBackend::Local`, and NOT a correct production backend on
 * Workers — see the module header.
 */
export class InMemoryMcpRateLimiter implements McpRateLimiter {
  readonly #windows = new Map<string, RequestWindow>();
  readonly #clock: () => number;

  constructor(clock: () => number = () => Math.floor(Date.now() / 1000)) {
    this.#clock = clock;
  }

  #window(counterKey: string): RequestWindow {
    assertNamespacedCounterKey(counterKey);
    let window = this.#windows.get(counterKey);
    if (window === undefined) {
      window = new RequestWindow();
      this.#windows.set(counterKey, window);
    }
    return window;
  }

  async consumeRequest(windows: readonly CounterWindow[]): Promise<RateLimitOutcome> {
    const now = this.#clock();
    for (const window of windows) {
      const state = this.#window(window.counterKey);
      if (!state.tryConsume(window.limit, now)) {
        return {
          allowed: false,
          counterKey: window.counterKey,
          limit: window.limit,
          retryAfterSeconds: secondsUntilWindowReset(state.state, now),
        };
      }
    }
    return { allowed: true };
  }

  /** Forget every window. The test seam for "a fresh isolate". */
  clear(): void {
    this.#windows.clear();
  }
}

/**
 * The per-isolate fallback limiter.
 *
 * A SINGLETON, and that is load-bearing: `resolvePorts` runs once per request,
 * so a limiter constructed there would start every request with an empty window
 * and count nothing at all.
 */
let fallbackLimiter: InMemoryMcpRateLimiter | undefined;

export function inMemoryLimiter(): InMemoryMcpRateLimiter {
  fallbackLimiter ??= new InMemoryMcpRateLimiter();
  return fallbackLimiter;
}

/** Forget every in-isolate counter window. Tests call this in `beforeEach`. */
export function resetInMemoryCounters(): void {
  inMemoryLimiter().clear();
}

/** Bindings {@link limiterForEnv} reads. */
export interface CounterBindings {
  /**
   * The SHARED `RateLimiterDurableObject` namespace, bound cross-script from
   * `apps/gateway`. Absent ⇒ the per-isolate fallback.
   */
  readonly RATE_LIMIT?: RateLimiterNamespace | undefined;
}

/**
 * Pick the limiter for an environment.
 *
 * A bound `RATE_LIMIT` namespace gives the atomic, cross-isolate, CROSS-WORKER
 * counter. With no binding the in-memory limiter is used, which is per-isolate
 * and therefore not a correct production limiter — that is why it is only
 * reached when the operator has bound nothing, and why the module header says
 * so loudly. Falling back to "no limiting whatsoever" would be worse: a
 * misconfigured deploy would silently serve unlimited traffic.
 */
export function limiterForEnv(env: CounterBindings): McpRateLimiter {
  const namespace = env.RATE_LIMIT;
  return namespace === undefined ? inMemoryLimiter() : new DurableObjectMcpRateLimiter(namespace);
}
