/**
 * `ProviderCircuitDurableObject` — the cross-isolate provider circuit breaker.
 *
 * ## Why a Durable Object and not a module-scope Map
 *
 * The Rust breaker is `Arc<HashMap<String, ProviderCircuitBreaker>>` on
 * `AppState`: one process, one map, so "5 consecutive failures" means five
 * failures observed by the whole gateway. A Worker has no process. Isolates are
 * created and destroyed per colo, per version and per burst, so
 * `InMemoryProviderCircuit`'s `Map` counts failures PER ISOLATE — with `K` live
 * isolates a wedged provider absorbs up to `threshold · K` failures before every
 * isolate has opened, and each one re-probes on its own cooldown. That is the
 * same arithmetic that forced the rate-limit counters onto a DO
 * (`ratelimit/durable-object.ts`), and it has the same answer.
 *
 * One instance per PROVIDER NAME (`idFromName(provider)`), so a wedged provider
 * concentrates on one object and a healthy one never serializes behind it.
 * Provider names come from the operator's `GATEWAY_PROVIDERS` table, never from
 * a caller, so no request input can choose a DO id here.
 *
 * ## Durability
 *
 * The snapshot is written through to `ctx.storage` (unawaited — DO output
 * gating holds the reply until the write lands, so it costs no latency and
 * cannot acknowledge a state a crash would lose) and restored in the
 * constructor under `blockConcurrencyWhile`. An evicted instance therefore
 * comes back with its circuit still open, which is strictly stronger than the
 * Rust process memory.
 *
 * ## ===========================================================================
 * ## WIRING — LANDED. This class is MOUNTED, not inert.
 * ## ===========================================================================
 *
 * This block used to read "three edits, none of them in this directory" and
 * open with "this class is inert until the composition root mounts it". Both
 * sentences are now false, and leaving them standing was the worse direction of
 * error: a reader would conclude the deployed breaker was a per-isolate `Map`.
 * Verified in the tree:
 *
 *  1. `apps/gateway/src/worker.ts:87` —
 *     `export { ProviderCircuitDurableObject } from "./inference/index.js";`
 *     workerd resolves a DO binding's `class_name` against the ENTRY module, so
 *     without this line the Worker fails AT STARTUP.
 *     `@cloudflare/vitest-pool-workers` does NOT reproduce that check — the
 *     whole unit suite stays green on an unbootable Worker, which is exactly
 *     how the same mistake shipped once already.
 *  2. `apps/gateway/wrangler.toml:768-773` — the binding plus migration
 *     `tag = "v2"` with **`new_sqlite_classes`**. Not `new_classes`: that
 *     variant deploys cleanly and then hands the breaker the wrong storage
 *     backend. vitest never reads `[[migrations]]`, so the assertion that holds
 *     this lives in `test/wrangler-bindings.test.ts`, which parses the TOML.
 *  3. `apps/gateway/src/ports.ts:383` —
 *     `readonly PROVIDER_CIRCUIT?: DurableObjectNamespace;` on `GatewayBindings`
 *     (and `GATEWAY_RELIABILITY?: string` at `:399`).
 *
 * The DO being MOUNTED is not the same as the breaker being ON, and the
 * distinction is deliberate. `apps/gateway/wrangler.toml:286` commits
 * `GATEWAY_RELIABILITY = "{}"` — an EMPTY policy, so
 * {@link ReliabilitySettings}' defaults apply and `providerCircuitFor` takes
 * arm 1 and returns `NO_PROVIDER_CIRCUIT`. That reproduces Rust's
 * "`provider_circuit_config == None` ⇒ no breaker" exactly, so a deployed
 * gateway behaves identically to the pre-wiring single dispatch until an
 * operator fills the policy in. Committing real thresholds here would BOTH
 * invent an operator policy the Rust tree does not ship AND leak into every
 * unit test, since `vitest.config.ts` loads `wrangler.toml`. Turning it on is
 * a deploy-time decision:
 *
 * ```toml
 * GATEWAY_RELIABILITY = '{"provider_circuit_breaker_failure_threshold":5,"provider_circuit_breaker_cooldown_secs":30,"provider_dispatch_max_retries":1}'
 * ```
 *
 * Nothing in `src/index.ts` changes: the inference router reads its ports out
 * of the per-request `env`, so `providerCircuitFor` picks the DO up from the
 * binding alone. `test/inference/reliability-mount.test.ts` is the gate — it
 * drives `SELF.fetch` and then reads the breaker state back out of the real
 * `PROVIDER_CIRCUIT` namespace, which is what distinguishes "a breaker ran"
 * from "THE Durable Object breaker ran".
 */
import { DurableObject } from "cloudflare:workers";
import {
  ProviderCircuitState,
  closedCircuit,
  type ProviderCircuit,
  type ProviderCircuitSnapshot,
  type ReliabilitySettings,
} from "./reliability.js";

const CIRCUIT_STORAGE_KEY = "provider:circuit";

/**
 * One provider's breaker state. Every method is an RPC entry point reachable
 * only through the `PROVIDER_CIRCUIT` binding — there is no `fetch()` surface,
 * so this object is not addressable from the internet.
 */
export class ProviderCircuitDurableObject extends DurableObject {
  #circuit = new ProviderCircuitState();

  /**
   * Unix-milliseconds clock, kept as a plain field (not an RPC method) so
   * `cloudflare:test`'s `runInDurableObject` can pin time exactly the way
   * `RateLimiterDurableObject.clock` is pinned. Nothing reachable over the DO
   * binding can rewrite it.
   */
  clock: () => number = () => Date.now();

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env as never);
    // The DO "lock": no RPC runs until the restore completes.
    ctx.blockConcurrencyWhile(async () => {
      const stored = await ctx.storage.get<ProviderCircuitSnapshot>(CIRCUIT_STORAGE_KEY);
      this.#circuit = new ProviderCircuitState(stored ?? closedCircuit());
    });
  }

  /** `provider_circuit_allows` for this provider. */
  allows(cooldownMs: number): boolean {
    return this.#circuit.allowsRequest(cooldownMs, this.clock());
  }

  /** `record_provider_success`. */
  recordSuccess(): void {
    this.#circuit.recordSuccess();
    void this.ctx.storage.put(CIRCUIT_STORAGE_KEY, this.#circuit.snapshot);
  }

  /** `record_provider_failure`. */
  recordFailure(failureThreshold: number): void {
    this.#circuit.recordFailure(failureThreshold, this.clock());
    void this.ctx.storage.put(CIRCUIT_STORAGE_KEY, this.#circuit.snapshot);
  }

  /** Diagnostics only; the request path never calls this. */
  snapshot(): ProviderCircuitSnapshot {
    return this.#circuit.snapshot;
  }
}

/** The `PROVIDER_CIRCUIT` binding, narrowed to what this module calls. */
export interface ProviderCircuitNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): DurableObjectStub<ProviderCircuitDurableObject>;
}

/**
 * {@link ProviderCircuit} backed by {@link ProviderCircuitDurableObject}.
 *
 * FAIL-OPEN, deliberately, and it is the one place in this slice that does:
 * a DO dispatch failure means the BREAKER is unavailable, not that the provider
 * is. Refusing the request would turn a control-plane blip into a total
 * inference outage, and the Rust counterpart fails open too (`allows_request`
 * returns `true` when the `Mutex` is poisoned). The rate limiter's opposite
 * choice — 503 `governance_counter_unavailable` — is correct THERE because a
 * missing counter would let a caller exceed a paid quota; a missing breaker
 * only costs one wasted upstream attempt, which the ladder already tolerates.
 */
export class DurableObjectProviderCircuit implements ProviderCircuit {
  readonly #namespace: ProviderCircuitNamespace;
  readonly #settings: ReliabilitySettings;

  constructor(namespace: ProviderCircuitNamespace, settings: ReliabilitySettings) {
    this.#namespace = namespace;
    this.#settings = settings;
  }

  #stub(provider: string): DurableObjectStub<ProviderCircuitDurableObject> {
    return this.#namespace.get(this.#namespace.idFromName(`provider:${provider}`));
  }

  async allows(provider: string): Promise<boolean> {
    try {
      return await this.#stub(provider).allows(this.#settings.circuitCooldownMs);
    } catch {
      return true;
    }
  }

  async recordSuccess(provider: string): Promise<void> {
    try {
      await this.#stub(provider).recordSuccess();
    } catch {
      /* the breaker is unavailable; the response is already decided */
    }
  }

  async recordFailure(provider: string): Promise<void> {
    try {
      await this.#stub(provider).recordFailure(this.#settings.circuitFailureThreshold);
    } catch {
      /* the breaker is unavailable; the response is already decided */
    }
  }
}
