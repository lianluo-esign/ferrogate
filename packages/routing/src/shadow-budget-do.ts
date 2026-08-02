/**
 * `ShadowBudgetDurableObject` + `DurableObjectShadowBudgetLedger` — the
 * cross-isolate replacement for the Rust `Mutex<HashMap>` shadow-mirror budget
 * (inventory §2.8).
 *
 * ## Why the in-isolate ledger is not enough
 *
 * `ShadowBudgetLedger` (`./rollout.ts`) is a faithful port of the Rust type: a
 * process-lifetime cap keyed by budget scope. On Workers there IS no process.
 * Isolates are created and destroyed per colo, per version, per burst, so N
 * live isolates give N independent counters and a cap of 1000 shadow
 * dispatches silently becomes 1000·N. For a cost cap, over-counting the budget
 * is spending real money on mirrored inference the operator asked not to spend.
 *
 * A Durable Object is the platform's answer: exactly one instance per id,
 * globally, single-threaded. The Rust map KEY becomes the DO NAME
 * (`idFromName(key)`), so each instance holds ONE scope's counter rather than a
 * map of them, and a hot scope's blast radius is one DO.
 *
 * ## Two honest differences from the Rust, both stated rather than hidden
 *
 * 1. **`tryConsume` becomes `async`.** A DO call is a network hop; there is no
 *    synchronous cross-isolate atomic anywhere on the platform. The seam is
 *    therefore {@link AsyncShadowBudgetLedger}, and a caller must `await` the
 *    admission before dispatching the mirror.
 * 2. **"Process lifetime" becomes "DO lifetime + storage".** The count is
 *    written through to `ctx.storage`, so eviction does not silently reset the
 *    cap — strictly stronger than the Rust process memory, and the correct
 *    direction for a spend cap. {@link ShadowBudgetDurableObject.reset} exists
 *    for the operator action Rust got for free from a restart.
 *
 * ## Composition-root wiring (NOT this package)
 *
 * ```toml
 * # apps/gateway/wrangler.toml
 * [[durable_objects.bindings]]
 * name = "SHADOW_BUDGET"
 * class_name = "ShadowBudgetDurableObject"
 *
 * [[migrations]]
 * tag = "v_shadow_budget"
 * new_sqlite_classes = ["ShadowBudgetDurableObject"]
 * ```
 *
 * ```ts
 * // apps/gateway/src/worker.ts — workerd rejects a DO class that the ENTRY
 * // module does not export:
 * export { ShadowBudgetDurableObject } from "@ferrogate/routing";
 * ```
 */
import { DurableObject } from "cloudflare:workers";

const COUNT_KEY = "shadow:used";

/**
 * The async admission seam. {@link ShadowBudgetLedger} (in-isolate) and
 * {@link DurableObjectShadowBudgetLedger} (cross-isolate) both satisfy it, so a
 * deployment can swap one for the other without touching a dispatch site.
 */
export interface AsyncShadowBudgetLedger {
  /** Admit one shadow dispatch against `key`; `false` when the cap is reached. */
  tryConsume(key: string, limit: number): Promise<boolean>;
  /** Dispatches charged so far against `key`. */
  consumed(key: string): Promise<number>;
}

/** One budget scope's counter. Reachable only through the DO binding (no `fetch`). */
export class ShadowBudgetDurableObject extends DurableObject {
  #used = 0;

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx as never, env as never);
    // `blockConcurrencyWhile` is the lock: no RPC is delivered until the
    // restore completes, so a cold instance cannot serve `tryConsume` against
    // a zero it is about to overwrite.
    ctx.blockConcurrencyWhile(async () => {
      this.#used = (await ctx.storage.get<number>(COUNT_KEY)) ?? 0;
    });
  }

  /**
   * Charge one dispatch if it fits. `limit === 0` is UNCAPPED and records
   * nothing — identical to the Rust, and the reason an uncapped deployment
   * pays for no storage writes.
   */
  async tryConsume(limit: number): Promise<boolean> {
    if (limit === 0) {
      return true;
    }
    if (this.#used >= limit) {
      return false;
    }
    this.#used += 1;
    // Unawaited: the DO output gate holds the reply until the write lands, so
    // this costs no latency and cannot return an admission a crash would
    // un-count.
    void this.ctx.storage.put(COUNT_KEY, this.#used);
    return true;
  }

  /** Dispatches charged so far. */
  async consumed(): Promise<number> {
    return this.#used;
  }

  /** Clear the counter — the operator action a Rust process restart gave free. */
  async reset(): Promise<void> {
    this.#used = 0;
    await this.ctx.storage.delete(COUNT_KEY);
  }
}

/** The `[[durable_objects.bindings]]` entry this ledger needs. */
export type ShadowBudgetNamespace = DurableObjectNamespace<ShadowBudgetDurableObject>;

/**
 * {@link AsyncShadowBudgetLedger} backed by {@link ShadowBudgetDurableObject} —
 * one instance per budget scope, so the cap holds across every isolate.
 */
export class DurableObjectShadowBudgetLedger implements AsyncShadowBudgetLedger {
  constructor(private readonly namespace: ShadowBudgetNamespace) {}

  #stub(key: string): DurableObjectStub<ShadowBudgetDurableObject> {
    return this.namespace.get(this.namespace.idFromName(key));
  }

  async tryConsume(key: string, limit: number): Promise<boolean> {
    // Short-circuit BEFORE the hop: an uncapped rollout must not pay a DO
    // round trip per mirrored request.
    if (limit === 0) {
      return true;
    }
    return await this.#stub(key).tryConsume(limit);
  }

  async consumed(key: string): Promise<number> {
    return await this.#stub(key).consumed();
  }

  /** Clear one scope's counter. */
  async reset(key: string): Promise<void> {
    await this.#stub(key).reset();
  }
}
