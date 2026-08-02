/**
 * The RPM counter this Worker charges — and the single most important wiring
 * decision in this module.
 *
 * ## The counter namespace MUST be the gateway's, not a second one
 *
 * Rust served `/v1/chat/completions` and `/v1/agent-jobs` from ONE process, so
 * both charged the SAME `ClusterCounterBackend` entry: a key capped at 60 rpm
 * got 60 requests per minute across every surface it could reach. Splitting the
 * data plane into five Workers does not change the intent, and a per-Worker
 * counter would quietly double the cap — each surface handing out its own full
 * quota is only marginally better than the bypass this module exists to close.
 *
 * So this file defines **no Durable Object class**. It defines a CLIENT that
 * speaks `apps/gateway`'s `RateLimiterDurableObject` RPC protocol
 * (`consumeRequest(limit) -> { allowed, retryAfterSeconds }`), to be bound with
 * `script_name` so both Workers address ONE namespace and one instance per
 * counter key. Declaring the class here instead would compile, deploy, pass
 * every test — and silently create a second namespace. See the WIRING block in
 * `./index.ts` for the exact stanza.
 *
 * ## What happens with no binding
 *
 * {@link InMemoryRequestCounter}: a module-scope `Map`, i.e. per-isolate. That
 * is NOT a correct production limiter — N isolates give N independent counters
 * — and it is only ever reached when the operator has bound no counter at all.
 * The alternative (no limiting whatsoever when the binding is missing) is
 * strictly worse: a misconfigured deploy would serve unlimited traffic and
 * nothing would say so. `apps/gateway/src/ratelimit/memory.ts` takes the same
 * position for the same reason.
 *
 * Note what fail-closed does and does not mean here. A counter OUTAGE (an RPC
 * that throws) is reported `unavailable` and becomes **503
 * `governance_counter_unavailable`**, never a 429 and never an admission —
 * Rust's `require_request_budget` `Err(_)` arm. A missing BINDING is a
 * different event: it is a deployment that has not been wired yet, and it
 * degrades to the local counter rather than refusing every request.
 */
import type { CounterWindow } from "./keys.js";
import { assertNamespacedCounterKey } from "./keys.js";
import { RequestWindow, secondsUntilWindowReset } from "./window.js";

/**
 * The result of an RPM admission check.
 *
 * `unavailable` is a first-class outcome rather than a thrown error because
 * Rust distinguishes it: `try_consume_api_key_request` returns
 * `anyhow::Result<bool>` and an `Err` becomes 503, NOT a 429. Collapsing the two
 * would turn a counter-backend outage into a rate-limit denial and hide it.
 */
export type RequestAdmission =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      /** The window that denied. Used for metrics; never shown to the client. */
      readonly counterKey: string;
      readonly limit: number;
      readonly retryAfterSeconds: number;
    }
  | { readonly allowed: "unavailable"; readonly detail: string };

/** The narrow port the admission ladder codes against. */
export interface RequestCounter {
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
   * earlier window in the list has already been incremented when a later one
   * denies. That is Rust's behaviour and is preserved deliberately: the windows
   * are independent budgets (a per-key cap and a tenant aggregate), and the
   * partial charge is what makes a caller that keeps retrying past a tenant cap
   * also burn its own key budget rather than probing for free.
   */
  consumeRequest(windows: readonly CounterWindow[]): Promise<RequestAdmission>;
}

// ---------------------------------------------------------------------------
// The Durable Object client
// ---------------------------------------------------------------------------

/** The `consumeRequest` reply shape `RateLimiterDurableObject` returns. */
export interface DoRequestResult {
  readonly allowed: boolean;
  /** Whole seconds until the denying window rolls. `0` when allowed. */
  readonly retryAfterSeconds: number;
}

/**
 * The binding shape this client needs, declared STRUCTURALLY.
 *
 * Structural on purpose: the class lives in another Worker's script, so there
 * is no type to import and no build-time coupling between the two apps. What
 * couples them is the RPC method name and its reply shape, which is why both
 * are written out here rather than inferred.
 */
export interface RateLimiterNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): { consumeRequest(limit: number): Promise<DoRequestResult> };
}

/** Render a thrown value for the `governance_counter_unavailable` detail. */
function detailOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** The production counter: one DO instance per counter key. */
export class DurableObjectRequestCounter implements RequestCounter {
  constructor(private readonly namespace: RateLimiterNamespace) {}

  async consumeRequest(windows: readonly CounterWindow[]): Promise<RequestAdmission> {
    for (const window of windows) {
      // OUTSIDE the try: a namespacing violation is a programming error and
      // must propagate as a 500, never be laundered into the `unavailable`
      // (503) arm, which would let a bad call site look like a transient outage.
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
// The single-isolate fallback
// ---------------------------------------------------------------------------

/**
 * Per-isolate counter. Correct arithmetic, wrong blast radius — see the module
 * header. Used only when no `RATE_LIMIT` namespace is bound.
 */
export class InMemoryRequestCounter implements RequestCounter {
  readonly #windows = new Map<string, RequestWindow>();

  constructor(
    private readonly nowUnixSeconds: () => number = () => Math.floor(Date.now() / 1000),
  ) {}

  async consumeRequest(windows: readonly CounterWindow[]): Promise<RequestAdmission> {
    const now = this.nowUnixSeconds();
    for (const window of windows) {
      assertNamespacedCounterKey(window.counterKey);
      let state = this.#windows.get(window.counterKey);
      if (state === undefined) {
        state = new RequestWindow();
        this.#windows.set(window.counterKey, state);
      }
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
}

/**
 * ONE per-isolate counter for the whole Worker.
 *
 * Module scope rather than per-request, because a counter rebuilt per request
 * counts nothing at all — the defect an in-memory limiter is easiest to write
 * with. `test/admission.test.ts` fails if this becomes per-request.
 */
const LOCAL_COUNTER = new InMemoryRequestCounter();

/** Bindings this module reads. */
export interface CounterBindings {
  /**
   * `apps/gateway`'s `RateLimiterDurableObject` namespace, bound with
   * `script_name = "ferrogate-gateway"` so both Workers share ONE window per
   * counter key. Absent ⇒ the per-isolate fallback.
   *
   * `unknown`, not {@link RateLimiterNamespace}: the class lives in another
   * Worker's script, so there is nothing to import and nothing workerd will
   * type-check for us. {@link counterFromEnv} probes it for the RPC surface
   * instead of trusting a declaration.
   */
  readonly RATE_LIMIT?: unknown;
}

/**
 * Pick the counter for an environment.
 *
 * The binding is probed for the RPC method, not merely for presence: a `[vars]`
 * entry named `RATE_LIMIT` is a STRING, and handing a string to `idFromName`
 * would throw on the request path — a 500 for every authenticated caller —
 * rather than degrading to the local counter.
 */
export function counterFromEnv(env: CounterBindings): RequestCounter {
  const namespace = env.RATE_LIMIT as Partial<RateLimiterNamespace> | undefined;
  if (
    namespace === undefined ||
    typeof namespace.idFromName !== "function" ||
    typeof namespace.get !== "function"
  ) {
    return LOCAL_COUNTER;
  }
  return new DurableObjectRequestCounter(namespace as RateLimiterNamespace);
}
