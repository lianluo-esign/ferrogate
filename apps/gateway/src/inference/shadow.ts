/**
 * Shadow / mirror traffic dispatch — the port of `server/shadow.rs` (issue
 * #276), the half of `@ferrogate/routing` that had no consumer at all.
 *
 * `candidates.ts` already knew how to *recognise* a shadow route: it strips it
 * out of the servable ladder so a mirror can never be handed to a client. What
 * did not exist anywhere in `apps/gateway` was the mirror itself. A deployment
 * could configure `shadow = { provider, provider_model, sample_percent }`,
 * watch `packages/config` validate it, and receive exactly zero mirrored
 * requests — `shadowSampled` was called from nothing on the request path and
 * `ShadowBudgetDurableObject` was reachable from no module in any app.
 *
 * | this module              | Rust (`server/shadow.rs`)                    |
 * |-------------------------|----------------------------------------------|
 * | {@link shadowMirrorFor} | `shadow_decision` (sampling half)            |
 * | {@link shadowBudgetFor} | `AppState::shadow_budget_try_consume`        |
 * | {@link spawnShadowMirror} | `spawn_shadow_mirror`                      |
 * | {@link runShadowMirror} | `execute_shadow_dispatch`                    |
 *
 * ## THE TWO GUARANTEES, AND HOW EACH IS ENFORCED HERE
 *
 * ### 1. A mirror NEVER affects the client's response
 *
 * Five independent mechanisms, because this is the guarantee that costs real
 * money and real availability when it breaks:
 *
 *  - **It is never a candidate.** `candidates.ts::servableCandidates` removes
 *    every route carrying `shadowPercent` from the ladder BEFORE eligibility
 *    runs, so failover cannot fall onto the mirror even when every primary is
 *    down (`test/inference/reliability.test.ts`).
 *  - **It is never awaited.** {@link spawnShadowMirror} returns `void`
 *    synchronously. The work is handed to `ctx.waitUntil` — the Workers
 *    equivalent of Rust's `tokio::spawn` — which keeps the isolate alive past
 *    the flushed response without holding it. With no `ExecutionContext` (a
 *    unit test driving `app.request`) it degrades to a detached promise, which
 *    is the same non-blocking shape.
 *  - **Its response is discarded.** {@link runShadowMirror} reads the body
 *    under the same `providerResponseMaxBytes` cap the primary uses and throws
 *    it away. No `Response` object built here is ever returned to a caller.
 *  - **Every failure is swallowed.** The dispatch is wrapped, and so is the
 *    synchronous plan/build half, so neither a provider outage nor an adapter
 *    that refuses the mirrored body can surface as a rejected promise on the
 *    request path.
 *  - **It never touches the circuit breaker.** {@link runShadowMirror} calls
 *    `deps.dispatcher` DIRECTLY and never `deps.circuit.recordSuccess/
 *    recordFailure`. Routing shadow failures into the breaker would let a
 *    mirror the client cannot even see open a circuit and shed the client's
 *    OWN traffic, which is the exact inversion of "shadow never affects the
 *    response". Rust says the same thing in one line: "Never records provider
 *    circuit-breaker success/failure, so shadow traffic never influences
 *    primary routing."
 *
 * ### 2. A mirror NEVER double-bills
 *
 * The metering seam is `deps.usage.record`, and this module does not import,
 * reference, or reach it — there is no code path from a mirrored dispatch to a
 * `Usage` row, a ledger entry, a billing-outbox row or a Queue publish. Nor
 * does it touch the tokens-per-minute governor (`identity.ts::TokenGovernor`),
 * so a mirrored request neither consumes nor settles the caller's TPM window.
 * The mirrored provider's own invoice still charges the operator — that is the
 * POINT of a shadow, and Rust's log line says it exactly: "metered as shadow,
 * not billed". What must never happen is the TENANT being charged twice for
 * one client request, and the enforcement of that is structural: one request
 * produces exactly one `recordUsage` call, from the attempt that produced the
 * served response, in `handlers.ts`.
 *
 * ## Rust order preserved, with ONE documented move
 *
 * Rust gates in the order sampled → provider enabled → budget charged, and
 * charges the budget INLINE on the request path because a `Mutex<HashMap>`
 * lock is free. Here the charge is a Durable Object round trip, so it moves
 * INSIDE the spawned task: charging inline would add a cross-colo hop to the
 * latency of every mirrored client request, breaking guarantee 1 to preserve a
 * call order that is invisible from outside. The relative order of the three
 * gates is unchanged — sampling still runs first (so an unsampled caller never
 * costs a DO hop), the provider-enabled check is already applied upstream by
 * `ModelResolver.candidates`, which only ever returns ENABLED routes, and the
 * budget is still charged before the mirror is dispatched.
 */
import { ShadowBudgetLedger, shadowSampled } from "@ferrogate/routing";
import type { AsyncShadowBudgetLedger } from "@ferrogate/routing";
import { DurableObjectShadowBudgetLedger } from "@ferrogate/routing/durable-objects";
import type { ShadowBudgetNamespace } from "@ferrogate/routing/durable-objects";
import { type ResidencyPolicy, residencyViolations } from "../residency/policy.js";
import { stickyKeyFor } from "./candidates.js";
import { dispatchDeadline, readBoundedProviderBody } from "./dispatch.js";
import type {
  Caller,
  InferenceBindings,
  InferenceOperation,
  PhysicalRoute,
  ResolvedInferenceDeps,
} from "./ports.js";

/**
 * The mirror one request selected, gathered on the primary path and moved into
 * the fire-and-forget task (Rust `ShadowMirrorParams`).
 */
export interface ShadowMirror {
  /** The mirror route, carrying `shadowPercent` / `shadowMaxRequests`. */
  readonly route: PhysicalRoute;
  /** Ingress operation, so the adapter builds the right upstream shape. */
  readonly operation: InferenceOperation;
  /** Logical model — also the budget scope key, exactly as in Rust. */
  readonly logicalModel: string;
  /** The client body to mirror. `stream` is forced off by {@link runShadowMirror}. */
  readonly body: Record<string, unknown>;
}

/**
 * `shadow_decision`'s sampling half — the mirror for this caller, or `null`.
 *
 * PURE and synchronous, and takes the FULL candidate list (before
 * `servableCandidates` strips the mirror out), which is why `handlers.ts` calls
 * it on `resolved` rather than on the eligible set.
 *
 * A caller with no sticky identity is never mirrored: there is nothing stable
 * to bucket on, so a per-request decision would mirror a random
 * `samplePercent`% of every caller's traffic instead of a stable
 * `samplePercent`% of callers — the same reason `applyCanary` drops the canary
 * for an identity-less caller.
 *
 * ## THE RESIDENCY GATE (#681), AND WHY IT HAD TO BE HERE
 *
 * Taking the FULL list is exactly what made this the residency hole. The mirror
 * is not a candidate, so `candidates.ts::eligibleCandidates` never sees it:
 * before this gate, an EU-only tenant's entire prompt was dispatched to a
 * mirror route in `us-east-1` on every sampled request, the client's response
 * was unaffected, and nothing anywhere reported it. It is the failure the issue
 * describes — a policy honoured on the primary and forgotten on a secondary
 * leg — in its worst form, because it is silent by construction.
 *
 * ## DROPPING THE MIRROR, RATHER THAN REFUSING THE REQUEST
 *
 * This is the one place in this slice where the governing "refuse, never
 * degrade" rule (#674, #690) does NOT produce a refusal, and the asymmetry is
 * deliberate rather than an exception carved for convenience.
 *
 * That rule is about the guarantee the CLIENT was given. A mirror is not part
 * of it: the client is served in region either way, and the request it made is
 * fulfilled exactly as its policy requires. What the mirror would add is an
 * OPERATOR-side measurement — a shadow evaluation of a second provider — whose
 * only effect on the tenant is that its prompt leaves the region. Refusing the
 * client's request because the OPERATOR configured an out-of-region shadow
 * would punish the tenant for a decision it did not make and cannot see, and
 * would turn "we measure a second provider" into an outage for every governed
 * tenant. So the compliant action, and the one that honours the guarantee, is
 * not to mirror.
 *
 * The operator-visible consequence — a shadow evaluation whose sample excludes
 * governed tenants — is real and is stated here so it is not discovered as a
 * surprise in a report. It is the correct trade: an incomplete measurement is
 * an operator problem, an out-of-region prompt is a breach.
 */
export function shadowMirrorFor(
  candidates: readonly PhysicalRoute[],
  caller: Caller,
  operation: InferenceOperation,
  logicalModel: string,
  body: Record<string, unknown>,
  residencyPolicy: ResidencyPolicy | null,
): ShadowMirror | null {
  const route = candidates.find((candidate) => candidate.shadowPercent !== undefined);
  if (route === undefined) {
    return null;
  }
  // BEFORE sampling, so the decision does not depend on which bucket the caller
  // landed in: a residency-ineligible mirror is never mirrored to, for anyone,
  // rather than "usually not".
  if (residencyViolations(route, residencyPolicy).length > 0) {
    return null;
  }
  const stickyKey = stickyKeyFor(caller);
  if (stickyKey === null) {
    return null;
  }
  if (!shadowSampled(stickyKey, route.shadowPercent ?? 0)) {
    return null;
  }
  return { route, operation, logicalModel, body };
}

/**
 * The per-isolate budget ledger, used when `SHADOW_BUDGET` is not bound.
 *
 * PORT-TODO(L: `packages/routing/src/rollout.ts` `ShadowBudgetLedger`): PLATFORM
 * LIMIT, and **this arm is no longer the deployed one.** A cap of `N` becomes
 * `N` per LIVE ISOLATE here, because there is no process for a process-lifetime
 * counter to live in.
 *
 * The wiring that binds `SHADOW_BUDGET` HAS LANDED — see {@link shadowBudgetFor},
 * where the three edits are listed as done with their anchors. So the deployed
 * gateway holds the cap globally in the Durable Object, and this arm is now only
 * reachable from a caller that builds an `env` WITHOUT the binding (tests, and
 * any future embedding of this module). It is kept, and kept marked, because it
 * is still the only answer available when the binding is absent, and because
 * "cap per isolate" must never be mistaken for "cap".
 *
 * Do NOT "fix" this by widening the ledger's lifetime: module scope IS the
 * isolate, and there is no wider lifetime on the platform short of the DO.
 */
const ISOLATE_SHADOW_BUDGET = new ShadowBudgetLedger();

/** {@link ShadowBudgetLedger} behind the async seam the DO ledger defines. */
const isolateShadowBudget: AsyncShadowBudgetLedger = {
  async tryConsume(key: string, limit: number): Promise<boolean> {
    return ISOLATE_SHADOW_BUDGET.tryConsume(key, limit);
  },
  async consumed(key: string): Promise<number> {
    return ISOLATE_SHADOW_BUDGET.consumed(key);
  },
};

/**
 * `AppState::shadow_budget_try_consume`'s backing store for a Worker `env`.
 *
 * Two arms, and the order is the contract: the `SHADOW_BUDGET` Durable Object
 * when it is bound (the only cross-isolate cap on the platform — see
 * `@ferrogate/routing/durable-objects`), the per-isolate ledger otherwise. The
 * fallback is deliberately not "no cap": a loose cap over-spends by a bounded
 * factor, an absent one over-spends without bound.
 *
 * ## ========================================================================
 * ## WIRING — LANDED. All three edits are in the tree.
 * ## ========================================================================
 *
 * This block used to read "three edits, none of them in this directory" and
 * list them as outstanding. They are done, and leaving that text standing was
 * actively misleading: a reader would conclude the DO arm was inert and that
 * the deployed gateway capped shadow spend per isolate. Verified in the tree:
 *
 *  1. `apps/gateway/src/worker.ts:103` —
 *     `export { ShadowBudgetDurableObject } from "@ferrogate/routing/durable-objects";`
 *     workerd resolves a DO binding's `class_name` against the ENTRY module, so
 *     without this line the Worker fails AT STARTUP.
 *     `@cloudflare/vitest-pool-workers` does NOT run that check, so the unit
 *     suite would stay green on an unbootable Worker —
 *     `test/wrangler-bindings.test.ts` is what actually holds it.
 *  2. `apps/gateway/wrangler.toml:794-799` — the binding plus migration
 *     `tag = "v3"` with **`new_sqlite_classes`** (NOT `new_classes`: the
 *     `new_classes` variant deploys fine and then gives the counter the wrong
 *     storage backend). vitest never reads migrations at all;
 *     `test/wrangler-bindings.test.ts` parses the TOML and asserts the variant.
 *  3. `apps/gateway/src/ports.ts:437` —
 *     `readonly SHADOW_BUDGET?: DurableObjectNamespace;` on `GatewayBindings`.
 *
 * Nothing in `src/index.ts` changes: the inference router resolves its ports
 * out of the per-request `env`, so this function picks the DO up from the
 * binding alone.
 *
 * MUTATION-PROVEN (wave 5): replacing `env["SHADOW_BUDGET"]` below with
 * `undefined` — so the binding is never read and the cap silently degrades to
 * per-isolate — turns `test/inference/shadow-budget-binding.test.ts` and
 * `test/inference/shadow.test.ts` RED (2 failed / 13 passed). The DO arm is the
 * one the deployed path takes.
 */
export function shadowBudgetFor(env: InferenceBindings): AsyncShadowBudgetLedger {
  const namespace = env["SHADOW_BUDGET"];
  if (
    typeof namespace === "object" &&
    namespace !== null &&
    typeof (namespace as ShadowBudgetNamespace).idFromName === "function"
  ) {
    return new DurableObjectShadowBudgetLedger(namespace as ShadowBudgetNamespace);
  }
  return isolateShadowBudget;
}

/**
 * `spawn_shadow_mirror` — fire-and-forget, on the request's `ExecutionContext`.
 *
 * Returns `void` SYNCHRONOUSLY and is never awaited by the request path. The
 * `try`/`catch` is not decoration: `ctx.waitUntil` itself throws when the
 * `ExecutionContext` belongs to a request that has already been finalized, and
 * a throw here would turn a mirroring problem into a client-visible 500 — the
 * precise failure this whole module is built to make impossible.
 */
export function spawnShadowMirror(
  deps: ResolvedInferenceDeps,
  mirror: ShadowMirror,
  ctx: { waitUntil(work: Promise<unknown>): void } | undefined,
): void {
  try {
    const work = runShadowMirror(deps, mirror);
    if (ctx === undefined) {
      // No `ExecutionContext` (a unit test driving `app.request`). A detached
      // promise is the same non-blocking shape; `runShadowMirror` never
      // rejects, so this cannot become an unhandled rejection.
      void work;
      return;
    }
    ctx.waitUntil(work);
  } catch {
    // A mirror is never allowed to fail a request. See the module docs.
  }
}

/**
 * `execute_shadow_dispatch` — charge the budget, mirror, discard.
 *
 * NEVER REJECTS. Every leg is inside the `try`, including the adapter build,
 * because `spawnShadowMirror` hands the returned promise to `ctx.waitUntil` and
 * a rejected `waitUntil` promise is a logged Worker exception on a request that
 * otherwise succeeded.
 *
 * Exported so the budget/dispatch behaviour is directly assertable, but the
 * request path only ever reaches it through {@link spawnShadowMirror}.
 */
export async function runShadowMirror(
  deps: ResolvedInferenceDeps,
  mirror: ShadowMirror,
): Promise<void> {
  try {
    // Rust charges the budget LAST of the three gates, "only once we know we
    // would actually dispatch, so a disabled provider or an unsampled caller
    // never consumes budget". Sampling already ran in `shadowMirrorFor`, and
    // `ModelResolver.candidates` only yields enabled routes, so this is the
    // last gate here too. `0` is uncapped and costs no round trip.
    const admitted = await deps.shadowBudget.tryConsume(
      mirror.logicalModel,
      mirror.route.shadowMaxRequests ?? 0,
    );
    if (!admitted) {
      return;
    }

    const adapter = deps.adapters.adapterFor(mirror.route.providerKind);
    if (adapter === null) {
      return;
    }

    // Mirror as a NON-streaming call regardless of the client's `stream` flag,
    // verbatim Rust: "the response is discarded, so a bounded body is simpler
    // and safer than a streamed one, and usage still comes back in the body".
    // The body is COPIED before `stream` is overwritten — the object handed in
    // is the same one `planUpstream` built the primary's upstream request from,
    // and mutating it would rewrite the CLIENT's request.
    const built = adapter.buildUpstreamRequest({
      operation: mirror.operation,
      route: mirror.route,
      logicalModel: mirror.logicalModel,
      providerModel: mirror.route.providerModel,
      stream: false,
      body: { ...mirror.body, stream: false },
    });
    if (!built.ok) {
      return;
    }

    // No client abort signal: a client hanging up must not truncate a
    // measurement it cannot see. The dispatch DEADLINE still applies, so a
    // wedged mirror cannot hold the isolate open indefinitely.
    const deadline = dispatchDeadline(deps.limits.dispatchTimeoutMs, undefined);
    const response = await deps.dispatcher.dispatch(built.request, deadline.signal);

    // Drain under the same cap the primary path uses, so a mirror cannot buffer
    // an unbounded provider body into the isolate. The result is discarded:
    // nothing here is returned, metered, or billed.
    await readBoundedProviderBody(response, deps.limits.providerResponseMaxBytes);
  } catch {
    // Swallowed, exactly as Rust swallows every arm of `execute_shadow_dispatch`.
  }
}
