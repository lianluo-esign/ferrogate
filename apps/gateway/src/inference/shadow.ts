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
import type { ShadowLegErrorCode } from "../experiments/index.js";
import { routePriceSettledCostUsd } from "../metering/route-price.js";
import { type ResidencyPolicy, residencyViolations } from "../residency/policy.js";
import { stickyKeyFor } from "./candidates.js";
import { dispatchDeadline, readBoundedProviderBody } from "./dispatch.js";
import { callerCanUseProvider } from "./ports.js";
import type {
  Caller,
  InferenceBindings,
  InferenceOperation,
  PhysicalRoute,
  ResolvedInferenceDeps,
} from "./ports.js";
import { usageFromResponseBody, usageProviderKindFor } from "./usage.js";
import type { ProviderUsage } from "./usage.js";

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
  /**
   * #693 — everything the shadow ARM's evidence row needs, gathered on the
   * request path because none of it is reachable from inside the detached task.
   *
   * Attached by `handlers.ts::withShadowObservation`, which is the one place
   * that has the mirror, the experiment and the id the CLIENT was told all at
   * once. `undefined` when the model declares no experiment, or when the caller
   * has no authenticated tenant — a leg with no tenant has nowhere to be filed
   * and nobody the measurement could be reported to.
   */
  readonly observation?: ShadowMirrorObservationContext | undefined;
  /**
   * #693 (quality half) — hand the mirrored response body BACK, so the online
   * evaluation sampler can score the arm no client was served.
   *
   * Attached by `handlers.ts::withShadowObservation` and ONLY when the sampler
   * has already cleared this exchange for content capture
   * (`evals/shadow-leg.ts` states the gate). Absent is the normal case and
   * means the response is read for its token counts and discarded exactly as it
   * always was.
   *
   * It is the resolver of a promise the sampler already holds, so it is
   * IDEMPOTENT — a second call after the first is a no-op — which is what lets
   * {@link runShadowMirror} guarantee settlement from a `finally` without
   * having to know whether the success path already settled it.
   */
  readonly retain?: ((body: string | undefined) => void) | undefined;
  /**
   * #894 — override the budget key and cap this mirror is charged against.
   *
   * Absent ⇒ Rust's own pair, `(logicalModel, route.shadowMaxRequests ?? 0)`,
   * which is what an EXPERIMENT mirror has always used. A candidate-coverage
   * mirror needs its own: its route is a servable ladder candidate, so it
   * carries no `shadowMaxRequests` at all and would charge a cap of `0` —
   * "uncapped" — against the shared per-model key. Uncapped is exactly the
   * property a mirror that spends real tokens on responses no client sees must
   * not have.
   */
  readonly budget?: { readonly key: string; readonly limit: number } | undefined;
}

/** The identity half of a shadow leg's evidence row. See {@link ShadowMirror}. */
export interface ShadowMirrorObservationContext {
  /**
   * `{clientRequestId}~shadow`, computed ONCE by
   * `handlers.ts::withShadowObservation`.
   *
   * DERIVED rather than random so a retried mirror overwrites its own row
   * instead of inflating the arm's sample — and it is the id the shadow arm's
   * eval SCORE is filed under too, so a leg's cost, latency and quality all
   * join on one key. Carried here rather than re-derived by each consumer
   * because two derivations of one id are two chances to disagree about it.
   */
  readonly legId: string;
  readonly experimentId: string;
  /** The id the CLIENT was told, which is what makes the two arms a PAIR. */
  readonly clientRequestId: string;
  readonly tenantId: string;
  readonly projectId?: string | undefined;
  readonly apiKeyId?: string | undefined;
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
 *  2. `apps/gateway/wrangler.toml` — the binding plus
 *     `[exports.ShadowBudgetDurableObject]` with `storage = "sqlite"`.
 *     `storage = "legacy-kv"` would deploy with the wrong backend. Vitest
 *     does not validate this lifecycle map;
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
 * ALWAYS SETTLES `mirror.retain` (#693). The outer `finally` calls it with
 * `undefined`, which is a no-op once the success path has already settled it
 * with the body. That guarantee is load-bearing rather than tidy:
 * `evals/middleware.ts` AWAITS the promise this resolver belongs to, from
 * inside `ctx.waitUntil`, so a path that returned without settling would hold
 * the isolate open until the platform killed it — on every mirrored request
 * that took that path.
 *
 * Exported so the budget/dispatch behaviour is directly assertable, but the
 * request path only ever reaches it through {@link spawnShadowMirror}.
 */
export async function runShadowMirror(
  deps: ResolvedInferenceDeps,
  mirror: ShadowMirror,
): Promise<void> {
  const observation = mirror.observation;
  const startedAt = Date.now();
  /**
   * #693 — record the leg, and swallow anything the recording itself throws.
   *
   * A no-op when there is no observation context (see {@link ShadowMirror}).
   * `deps.experiments.observeShadowLeg` never rejects either, so the `try` here
   * is depth at the one seam where a throw would become a logged Worker
   * exception on a request that had already been served.
   */
  const record = async (outcome: {
    readonly statusCode?: number | undefined;
    readonly errorCode?: ShadowLegErrorCode | undefined;
    readonly usage?: ProviderUsage | undefined;
  }): Promise<void> => {
    if (observation === undefined) return;
    try {
      await deps.experiments.observeShadowLeg({
        // Computed once, on the request path — see the field's own docs.
        legId: observation.legId,
        clientRequestId: observation.clientRequestId,
        experimentId: observation.experimentId,
        tenantId: observation.tenantId,
        projectId: observation.projectId,
        apiKeyId: observation.apiKeyId,
        logicalModel: mirror.logicalModel,
        provider: mirror.route.provider,
        providerModel: mirror.route.providerModel,
        statusCode: outcome.statusCode,
        errorCode: outcome.errorCode,
        latencyMs: Math.max(0, Date.now() - startedAt),
        promptTokens: outcome.usage?.promptTokens,
        completionTokens: outcome.usage?.completionTokens,
        totalTokens: outcome.usage?.totalTokens,
        costUsd: shadowLegCostUsd(mirror, outcome.usage),
        observedAtUnix: Math.floor(Date.now() / 1000),
      });
    } catch {
      // A mirror is never allowed to fail a request, and its evidence is never
      // allowed to fail the mirror.
    }
  };

  try {
    // Rust charges the budget LAST of the three gates, "only once we know we
    // would actually dispatch, so a disabled provider or an unsampled caller
    // never consumes budget". Sampling already ran in `shadowMirrorFor`, and
    // `ModelResolver.candidates` only yields enabled routes, so this is the
    // last gate here too. `0` is uncapped and costs no round trip.
    const admitted = await deps.shadowBudget.tryConsume(
      mirror.budget?.key ?? mirror.logicalModel,
      mirror.budget?.limit ?? mirror.route.shadowMaxRequests ?? 0,
    );
    if (!admitted) {
      // #693 — RECORDED, not dropped. A budget refusal is the operator's own
      // cap doing its job, but an arm whose refused legs are invisible reports
      // a smaller and healthier-looking sample than it actually took — and the
      // shadow arm's sample size is what decides whether the comparison is
      // shown at all.
      await record({ errorCode: "shadow_budget_exhausted" });
      return;
    }

    const adapter = deps.adapters.adapterFor(mirror.route.providerKind);
    if (adapter === null) {
      await record({ errorCode: "adapter_unavailable" });
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
      await record({ errorCode: "adapter_refused" });
      return;
    }

    // No client abort signal: a client hanging up must not truncate a
    // measurement it cannot see. The dispatch DEADLINE still applies, so a
    // wedged mirror cannot hold the isolate open indefinitely.
    const deadline = dispatchDeadline(deps.limits.dispatchTimeoutMs, undefined);
    const response = await deps.dispatcher.dispatch(built.request, deadline.signal);

    // Drain under the same cap the primary path uses, so a mirror cannot buffer
    // an unbounded provider body into the isolate. The result is still
    // discarded: nothing here is returned, metered, or billed.
    const text = await readBoundedProviderBody(response, deps.limits.providerResponseMaxBytes);

    // #693 (quality half) — HAND THE BODY BACK, and only on a 200.
    //
    // A non-200 mirror has no answer for a judge to score, and scoring error
    // envelopes would drag the arm's mean down whenever the mirrored provider
    // had a bad hour — turning a reliability problem into a fake quality
    // regression. That is the SAME rule
    // `evals/middleware.ts::evaluableResponse` applies to the served arm,
    // applied here rather than paralleled there because this is the only place
    // the mirror's status exists. The failure is NOT lost: the leg row below
    // records it, so the arm's error rate is unaffected by this.
    //
    // `retain` is absent unless the sampler asked for it, so on all other
    // traffic the only thing that still leaves this body is token COUNTS.
    if (response.status === 200) mirror.retain?.(text);

    // The one thing taken from that body for the leg row, and it is a COUNT
    // rather than content. The evidence row carries tokens and a cost; no
    // prompt and no completion text is stored, exactly as
    // `0009_online_eval.sql` refuses to store either.
    await record({ statusCode: response.status, usage: shadowUsageFrom(mirror, text) });
  } catch {
    // Swallowed, exactly as Rust swallows every arm of `execute_shadow_dispatch`
    // — and the leg is STILL recorded, because an arm whose failures vanish
    // looks healthier than the arm it is being compared against, which is the
    // direction that promotes a bad variant.
    await record({ errorCode: "provider_dispatch_error" });
  } finally {
    // #693 — SETTLE, whatever happened. Idempotent: a no-op once the success
    // path above resolved it with the body. See this function's docblock for
    // why an unsettled promise here would hold the isolate open.
    mirror.retain?.(undefined);
  }
}

/**
 * The mirror's own token counts, read from the body that was about to be
 * discarded (#693).
 *
 * The dialect is chosen exactly as the served path chooses it
 * (`usageProviderKindFor`), because the mirror is usually a DIFFERENT family
 * from the primary — that is the point of the experiment — and reading an
 * Anthropic body with the OpenAI extractor yields NO usage rather than wrong
 * usage, i.e. an arm silently reported as costing nothing.
 *
 * Total: any parse failure is `undefined`, which the leg row stores as NULL.
 * "The provider reported no usage" and "we could not read it" mean the same
 * thing to a report — this row has no tokens — and neither may be recorded as
 * an observed zero, which would drag the arm's mean cost down.
 */
function shadowUsageFrom(mirror: ShadowMirror, text: string): ProviderUsage | undefined {
  // Only the two operations `usageProviderKindFor` accepts. The rest of the
  // family (embeddings, rerank, images, the audio surface) settle on units a
  // token extractor cannot read, so their legs carry latency and status and no
  // tokens — which is the honest answer, not a gap.
  const dialectOperation =
    mirror.operation === "chat.completions" || mirror.operation === "responses"
      ? mirror.operation
      : undefined;
  if (dialectOperation === undefined) return undefined;
  try {
    return usageFromResponseBody(
      usageProviderKindFor(dialectOperation, mirror.route.providerKind),
      JSON.parse(text) as unknown,
    );
  } catch {
    return undefined;
  }
}

/**
 * What the mirrored dispatch cost THE OPERATOR, priced from the shadow route's
 * own registry rates (#693).
 *
 * `routePriceSettledCostUsd` is the same function the served path settles with
 * (#663), reused rather than reimplemented so both arms' costs come out of one
 * piece of code — two pricing paths that could disagree would turn a cost
 * comparison between arms into a comparison between rounding rules.
 *
 * Nobody is BILLED for this number. The customer never received this response
 * and never asked for the second provider, so `armChargedTo('shadow')` is
 * `operator` and `deps.usage.record` is not reachable from this module at all.
 * The figure exists so an operator can see what the experiment costs THEM.
 */
function shadowLegCostUsd(
  mirror: ShadowMirror,
  usage: ProviderUsage | undefined,
): number | undefined {
  if (usage === undefined) return undefined;
  return routePriceSettledCostUsd({
    requestId: mirror.observation?.clientRequestId ?? "",
    route: `${mirror.route.provider}.shadow`,
    logicalModel: mirror.logicalModel,
    provider: mirror.route.provider,
    providerModel: mirror.route.providerModel,
    stream: false,
    status: 200,
    promptTokens: usage.promptTokens,
    completionTokens: usage.completionTokens,
    totalTokens: usage.totalTokens,
    inputPricePer1m: mirror.route.inputPricePer1m,
    outputPricePer1m: mirror.route.outputPricePer1m,
    cachedInputPricePer1m: mirror.route.cachedInputPricePer1m,
  });
}

// ---------------------------------------------------------------------------
// #894 — CANDIDATE COVERAGE
// ---------------------------------------------------------------------------

/**
 * The fleet backstop on coverage spend, per `(tenant, logical model)`.
 *
 * The TENANT's control is `OnlineEvalPolicy.coveragePercent`, which is the knob
 * that decides whether coverage happens at all and how much of their sampled
 * traffic it touches. This constant is the OPERATOR's floor under a
 * misconfiguration — a tenant who sets 100 on a high-volume model still cannot
 * turn the gateway into an unbounded second dispatcher.
 *
 * Same ledger, same semantics and the same caveat as every other shadow cap:
 * with `SHADOW_BUDGET` bound it is a global count in the Durable Object; without
 * it, it is a count PER LIVE ISOLATE (`ISOLATE_SHADOW_BUDGET`). "Cap per
 * isolate" must never be read as "cap".
 */
export const COVERAGE_BUDGET_LIMIT = 500;

/** `coverage:{tenant}:{logicalModel}` — never the experiment mirror's key. */
export function coverageBudgetKey(tenantId: string, logicalModel: string): string {
  return `coverage:${tenantId}:${logicalModel}`;
}

/**
 * Rotates coverage across a ladder's non-primary candidates.
 *
 * A fixed `candidates[1]` would give the second-choice leg every coverage
 * sample and leave the third and fourth permanently at `no_signal` — i.e. it
 * would reproduce, one position further down, exactly the blind spot #894
 * exists to remove. Module scope is the isolate, which is the same lifetime
 * `nextRoutingCursor` uses for the priority rotation.
 *
 * MONOTONIC, and reduced modulo the ladder only at the point of USE. The first
 * cut stored `(cursor + 1) % nonPrimary.length`, i.e. it reduced the SHARED
 * cursor by the CURRENT ladder's length — so a two-leg ladder (one non-primary,
 * `% 1 === 0`) reset the cursor to zero on every sample, and any short busy
 * ladder clamped it into its own small range. A longer ladder sharing the
 * isolate then started its rotation at position 0 or 1 essentially always and
 * its deeper candidates stayed at `no_signal` for ever — reproducing the very
 * blind spot the rotation exists to remove. Wraps like
 * `strategy.ts::nextRoutingCursor`, for the same reason.
 */
let coverageCursor = 0;

/**
 * The coverage mirror for this request, or `null`.
 *
 * PURE except for the rotation cursor, and synchronous: it is called from
 * `handlers.ts::dispatchCandidates` beside `spawnShadowMirror`, on the
 * already-eligible, already-ordered SERVABLE ladder.
 *
 * ## What it is for
 *
 * `online_eval_scores` only ever contains rows for legs that SERVED (or that an
 * experiment mirrored). A cheap candidate sitting at position 2 of a ladder is
 * never routed to while position 0 is healthy, so it accumulates no scores, so
 * `evals/leg-quality.ts` reports `no_signal` for it for ever. Coverage buys the
 * missing population: the same prompt, to a non-primary candidate, scored by the
 * same judge under the same criteria as the leg that served.
 *
 * ## Every gate it inherits, and the one it adds
 *
 *  - **The eval retention gate.** `coveragePercent` reaches this function only
 *    through `InferenceRequestScope.coverageEvalPercent`, which `route-module.ts`
 *    supplies only when `evals/shadow-leg.ts::shadowEvalRetentionRequested` is
 *    true — i.e. only after the sampler's capture plan cleared opt-in, ZDR,
 *    criteria and the sample bucket. A tenant that must not be sampled is never
 *    covered, and neither is a request the sampler did not select.
 *  - **Per-tenant opt-in.** `coveragePercent` defaults to 0 (OFF) for every
 *    tenant including those already opted into evaluation; see
 *    `evals/policy.ts` on why coverage is a strictly larger consent.
 *  - **Residency (#681).** Re-applied here even though every candidate already
 *    passed `eligibleCandidates(..., residencyPolicy)`: `shadowMirrorFor` exists
 *    because a second dispatch leg silently escaped the policy once, and a
 *    selector that relies on an upstream gate staying where it is would be the
 *    same hole in a new place.
 *  - **The credential's PROVIDER allow/deny list.** See below — this one is
 *    added here rather than inherited, because nothing upstream applies it.
 *  - **A PER-REQUEST bucket.** See below — deliberately NOT the sticky
 *    per-caller bucket the canary and the experiment mirror use.
 *  - **A budget**, {@link COVERAGE_BUDGET_LIMIT}, charged in `runShadowMirror`.
 *
 * It is `null` for a single-candidate ladder — there is no non-primary leg to
 * cover — which is also why enabling coverage cannot change any deployment whose
 * models resolve to one route.
 *
 * ## Why the provider allowlist is re-applied here
 *
 * `ports.ts::callerCanUseProvider` is consulted in exactly ONE place on the
 * served path: `reliability.ts::dispatchWithFailover`, per candidate, where a
 * refusal is TERMINAL (403 `provider_not_allowed`). `planUpstream`'s candidate
 * list is deliberately NOT filtered by it — `identity.ts` records why an
 * exclusion would be wrong there. That leaves the coverage mirror, which reads
 * `planned.candidates`, free to dispatch the tenant's prompt to a provider the
 * credential is explicitly forbidden to use, and to pay for the completion.
 * Worse, the mirror is spawned BEFORE the ladder runs, so a request whose
 * PRIMARY is denied — one the gateway is about to refuse with 403 and serve
 * nothing for — would already have shipped the prompt to a second provider. So
 * both halves are checked: a denied primary refuses coverage outright, and the
 * non-primary set is filtered.
 *
 * The primary refusal is deliberately the CONSERVATIVE reading. A denied
 * primary whose circuit is also open is skipped by `dispatchWithFailover`
 * before the allowlist gate, so that one request would in fact be served by
 * candidate 1 — and refusing coverage for it costs a measurement, while
 * admitting it would mean guessing which candidate the breaker will pick from
 * outside the ladder. Under-measuring is the safe error; spending is not.
 *
 * ## Why the bucket is per REQUEST, not per caller
 *
 * The canary and the experiment mirror are sticky per API key because a caller
 * must get a CONSISTENT experience. Coverage is the opposite kind of thing: it
 * is a measurement whose only consumer is `evals/leg-quality.ts`, which compares
 * the covered leg's mean against the SERVED leg's mean. The served leg's scores
 * come from every caller; a sticky coverage bucket would draw the covered leg's
 * scores from one fixed caller subset, and the comparator would then be reading
 * a difference between two prompt POPULATIONS as a difference between two
 * providers — precisely the cross-population comparison `evals/policy.ts:20-46`
 * forbids, and enough to demote a leg that is not worse. A sticky bucket also
 * breaks the spend bound: with one API key, `coveragePercent = 5` mirrors either
 * 0% or 100% of that tenant's sampled requests depending on a single hash.
 *
 * The key is therefore the per-request `samplingKey` (the client request id),
 * which is uniform across callers and still deterministic — so the function
 * stays testable and a redelivery cannot flip the decision.
 */
export function coverageMirrorFor(input: {
  readonly candidates: readonly PhysicalRoute[];
  readonly caller: Caller;
  readonly tenantId: string;
  readonly operation: InferenceOperation;
  readonly logicalModel: string;
  readonly body: Record<string, unknown>;
  readonly coveragePercent: number;
  readonly residencyPolicy: ResidencyPolicy | null;
  /** The client request id — see the per-request bucket note above. */
  readonly samplingKey: string;
}): ShadowMirror | null {
  if (!(input.coveragePercent > 0)) return null;
  const primary = input.candidates[0];
  if (primary === undefined) return null;
  // A request whose primary the credential may not use is refused 403 by the
  // ladder and serves nothing. It must not have spent money on a mirror first.
  if (!callerCanUseProvider(input.caller, primary.provider)) return null;

  const nonPrimary = input.candidates
    .slice(1)
    .filter((candidate) => callerCanUseProvider(input.caller, candidate.provider));
  if (nonPrimary.length === 0) return null;

  if (!shadowSampled(`${input.samplingKey}~coverage`, input.coveragePercent)) return null;

  const cursor = coverageCursor;
  coverageCursor = cursor >= Number.MAX_SAFE_INTEGER ? 0 : cursor + 1;
  const rotated: PhysicalRoute[] = [];
  for (let index = 0; index < nonPrimary.length; index += 1) {
    rotated.push(nonPrimary[(cursor + index) % nonPrimary.length] as PhysicalRoute);
  }

  const route = rotated.find(
    (candidate) => residencyViolations(candidate, input.residencyPolicy).length === 0,
  );
  if (route === undefined) return null;

  return {
    route,
    operation: input.operation,
    logicalModel: input.logicalModel,
    body: input.body,
    budget: {
      key: coverageBudgetKey(input.tenantId, input.logicalModel),
      limit: COVERAGE_BUDGET_LIMIT,
    },
  };
}
