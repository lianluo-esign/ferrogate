/**
 * Candidate-route selection: eligibility, ordering, and canary/shadow rollout.
 *
 * This is the half of the reliability layer that runs BEFORE the first socket
 * is opened — the Rust `model_routing.rs` (564 lines) + `state_rollout.rs` pair
 * that `docs/rewrite/parity-audit-request-path.md` records as F5 and F7.
 *
 * | this module                      | Rust                                                 |
 * |----------------------------------|------------------------------------------------------|
 * | {@link routeRequirements}        | `ModelRouteRequirements::from_request`                |
 * | {@link routeExclusionReasons}    | `model_routing::route_exclusion_reasons`              |
 * | {@link eligibleCandidates}       | `ModelRoutingDecision::consider` + `::rejection`      |
 * | {@link orderCandidates}          | `state_routing.rs:517-540` priority → weight ordering |
 * | {@link applyCanary}              | `AppState::canary_route` (`state_rollout.rs:47`)      |
 * | {@link servableCandidates}       | `server/shadow.rs` — a mirror is not a candidate      |
 *
 * The mirror DISPATCH itself (`server/shadow.rs:69,78`, `spawn_shadow_mirror`)
 * is `./shadow.ts`: it had to leave this module because the budget cap became
 * an `async` Durable Object call and everything here is a pure decision.
 *
 * ## `@ferrogate/routing` IS THE ROLLOUT IMPLEMENTATION
 *
 * `canarySelected` / `shadowSampled` / `ShadowBudgetLedger` are imported from
 * the package, not re-derived. They are byte-exact FNV-1a64 against the Rust
 * (`salt\0key` framing, `0xcbf29ce484222325` / `0x100000001b3`) and carry 28
 * tests — and until this module landed the package had ZERO importers in
 * `apps/*`, so a configured canary diverted 0% of traffic. Re-implementing the
 * bucketing here would have kept it that way while looking wired.
 */
import { canarySelected } from "@ferrogate/routing";
import type { Caller, ModelCapability, PhysicalRoute } from "./ports.js";

// ---------------------------------------------------------------------------
// Requirements
// ---------------------------------------------------------------------------

/** Which ingress surface a request arrived on (`ModelEndpointKind`). */
export type ModelEndpointKind =
  | "chat.completions"
  | "responses"
  | "messages"
  | "embeddings"
  | "images";

/** `ModelRouteRequirements`. */
export interface RouteRequirements {
  /** Capabilities the route must declare (`BTreeSet<ModelCapability>`). */
  readonly capabilities: readonly ModelCapability[];
  /** `required_context_window` — input upper bound + explicit output tokens. */
  readonly requiredContextWindow?: number | undefined;
  /**
   * `unbounded_media_context` — an image-bearing prompt has no computable
   * token upper bound, so NO route may claim to fit it. Rust pushes
   * `MediaContextUnbounded` unconditionally in that case.
   */
  readonly unboundedMediaContext: boolean;
}

/** True for a request body field that carries tools. */
function hasTools(body: Record<string, unknown>): boolean {
  const tools = body["tools"];
  return Array.isArray(tools) && tools.length > 0;
}

/** `structured_output_requested` — `response_format` / `text.format` json_schema. */
function wantsStructuredOutput(body: Record<string, unknown>): boolean {
  const format = body["response_format"];
  if (typeof format === "object" && format !== null) {
    const type = (format as { type?: unknown }).type;
    return type === "json_schema" || type === "json_object";
  }
  return false;
}

/** `request_contains_image_input` — any multimodal content part. */
function hasImageInput(body: Record<string, unknown>): boolean {
  const messages = body["messages"];
  if (!Array.isArray(messages)) {
    return false;
  }
  for (const message of messages) {
    const content = (message as { content?: unknown } | null)?.content;
    if (!Array.isArray(content)) {
      continue;
    }
    for (const part of content) {
      const type = (part as { type?: unknown } | null)?.type;
      if (type === "image_url" || type === "image" || type === "input_image") {
        return true;
      }
    }
  }
  return false;
}

/** `explicit_output_token_bound` — the caller's declared output ceiling. */
function explicitOutputTokens(body: Record<string, unknown>): number | undefined {
  for (const key of ["max_tokens", "max_output_tokens", "max_completion_tokens"]) {
    const value = body[key];
    if (typeof value === "number" && Number.isInteger(value) && value > 0) {
      return value;
    }
  }
  return undefined;
}

/**
 * `ModelRouteRequirements::from_request`.
 *
 * `inputTokenUpperBound` is the prompt half of the pre-dispatch estimate
 * (`estimate.ts`), which is the same quantity Rust threads in as
 * `request_input_token_upper_bound`.
 */
export function routeRequirements(
  endpoint: ModelEndpointKind,
  body: Record<string, unknown>,
  stream: boolean,
  inputTokenUpperBound: number,
): RouteRequirements {
  const capabilities: ModelCapability[] = [];
  const require = (capability: ModelCapability): void => {
    if (!capabilities.includes(capability)) {
      capabilities.push(capability);
    }
  };

  switch (endpoint) {
    case "embeddings":
      require("embeddings");
      break;
    case "images":
      require("images");
      break;
    default:
      require("chat");
      break;
  }
  if (stream) {
    require("streaming");
  }
  if (hasTools(body)) {
    require("tools");
  }
  if (wantsStructuredOutput(body)) {
    require("structured_output");
  }

  const conversational =
    endpoint === "chat.completions" || endpoint === "responses" || endpoint === "messages";
  const imageInput = conversational && hasImageInput(body);
  if (imageInput) {
    require("vision");
  }

  if (imageInput) {
    return { capabilities, unboundedMediaContext: true };
  }
  if (!conversational) {
    return { capabilities, unboundedMediaContext: false };
  }
  const output = explicitOutputTokens(body) ?? 0;
  const required = inputTokenUpperBound + output;
  return {
    capabilities,
    ...(required > 0 ? { requiredContextWindow: required } : {}),
    unboundedMediaContext: false,
  };
}

// ---------------------------------------------------------------------------
// Eligibility
// ---------------------------------------------------------------------------

/**
 * `ModelRouteExclusionReason::code()`.
 *
 * Rust's `context_window_undeclared` is deliberately absent — see deviation 2
 * on {@link routeExclusionReasons}. Listing a code this port can never emit
 * would be a vocabulary that lies about the gate.
 */
export type RouteExclusionCode =
  | "missing_capability"
  | "media_context_unbounded"
  | "context_window_too_small"
  | "region_undeclared"
  | "region_not_allowed";

/** One reason a candidate route was refused. */
export interface RouteExclusion {
  readonly provider: string;
  readonly providerModel: string;
  readonly code: RouteExclusionCode;
  readonly detail: string;
}

/**
 * `route_exclusion_reasons`.
 *
 * PORT-TODO(P: model_routing.rs `allow_undeclared_capabilities`): PARTIAL — this
 * function is WIDER than Rust on THREE legs, not the two this marker used to
 * claim. Deviation 3 was found by re-reading `model_routing.rs:374` for this
 * pass and is stated below; the "these are the only two" sentence that stood
 * here was wrong, which is exactly the rot a marker is supposed to prevent.
 *
 * Deviations 1 and 2 follow ONE rule: **a gate is armed by the operator
 * declaring the field, never by omitting it.** An armed route is held to the
 * exact Rust test, and an undeclared field can only ever mean "this leg does
 * not apply", never "this route wins by default". Deviation 3 does NOT follow
 * that rule and is a plain widening — see below.
 *
 * ## Why none of the three is closed here
 *
 * All three are portable in the sense that Cloudflare forbids nothing; what
 * blocks each one is a file this slice does not own.
 *
 *  - 1 and 2 need `apps/gateway/wrangler.toml`'s `GATEWAY_MODELS` to start
 *    declaring `capabilities` and `context_window` on every route before the
 *    strict reading can be turned on, and **no agent may edit a `wrangler.toml`**
 *    (the integrate step owns it). Turning on the Rust reading against today's
 *    `GATEWAY_MODELS = "[]"` documented example — which omits both fields — 400s
 *    every streaming request in the tree.
 *  - 3 needs an existing green assertion to change its expected status, and
 *    assertions may not be weakened or deleted. Named below.
 *
 *  1. **Capabilities.** Rust treats an empty `capabilities` as neutral only when
 *     `allow_undeclared_capabilities` holds (conversational endpoint, no explicit
 *     output bound, no image input, required set exactly `{Chat}`), so in Rust a
 *     STREAMING request or an embedding excludes an undeclared route. Here an
 *     empty `capabilities` is neutral for every endpoint. `ports.ts` already
 *     documents `PhysicalRoute.capabilities` as "empty is the legacy
 *     capability-neutral case", and every `GATEWAY_MODELS` deployment today
 *     omits it — the Rust reading would turn every streaming request in this
 *     tree into `400 invalid_request`.
 *  2. **Context window.** Rust excludes a route whose `context_window` is
 *     undeclared (`ContextWindowUndeclared`) unless it is legacy-neutral, i.e.
 *     declaring `capabilities` obliges you to declare `context_window` too.
 *     Here an undeclared window never excludes; a DECLARED one that is too
 *     small excludes exactly as Rust excludes it. Rust can afford the stricter
 *     reading because its validator refuses to boot and the operator sees it at
 *     once; a Worker would instead 400 live traffic on a config that has been
 *     valid in this tree since the catalog landed.
 *  3. **Unbounded media context — NEW, and NOT a narrowing.** `model_routing.rs:374`
 *     is `if requirements.unbounded_media_context { reasons.push(MediaContextUnbounded) }`
 *     — UNCONDITIONAL, per route, with no reference to `route.context_window`
 *     and no legacy-neutral escape (`allow_undeclared_capabilities` is itself
 *     forced false by `!unbounded_media_context` at line 110). So in Rust an
 *     image-bearing chat request excludes EVERY candidate, `eligible_routes` is
 *     empty, and `ModelRoutingDecision::rejection` answers
 *     `400 invalid_request "no physical route for model X satisfies the request
 *     requirements"`. Vision is unroutable in the Rust tree, full stop.
 *     This port pushes the reason only when `route.contextWindow !== undefined`,
 *     so a route that declares no window SERVES the image request. That is
 *     strictly more permissive than Rust and it is not covered by the
 *     declare-to-arm rule, because Rust's leg is not armed by a declaration.
 *
 *     Left as a deviation rather than corrected because
 *     `test/inference/validation.test.ts` → "accepts the multimodal
 *     content-part array form" asserts `200` on exactly this request against a
 *     window-less route. Making the leg 1:1 turns that into `400`, i.e. it
 *     requires changing a green assertion's expectation, which a porting slice
 *     may not do unilaterally. It needs an explicit decision: reproduce Rust
 *     (vision stops working) or keep the port's behavior (vision works, parity
 *     broken on an edge Rust arguably got wrong). Either way it is a decision,
 *     not a port. `test/inference/eligibility-deviations.test.ts` pins the
 *     CURRENT behavior in both directions so it cannot drift further while the
 *     decision is outstanding.
 *
 * Region is not deviated from at all: an empty allowlist is no gate in both
 * trees, and a non-empty one excludes an undeclared `region` in both.
 */
export function routeExclusionReasons(
  route: PhysicalRoute,
  requirements: RouteRequirements,
  regionAllowlist: readonly string[],
): readonly RouteExclusion[] {
  const declared = route.capabilities ?? [];
  const capabilityNeutral = declared.length === 0;
  const reasons: RouteExclusion[] = [];
  const push = (code: RouteExclusionCode, detail: string): void => {
    reasons.push({
      provider: route.provider,
      providerModel: route.providerModel,
      code,
      detail,
    });
  };

  if (!capabilityNeutral) {
    for (const required of requirements.capabilities) {
      if (!declared.includes(required)) {
        push("missing_capability", `required_capability=${required}`);
      }
    }
  }

  if (requirements.unboundedMediaContext) {
    // DEVIATION 3 (see the marker above). Rust pushes this for EVERY route,
    // unconditionally, so an image-bearing prompt has NO eligible route at all
    // and 400s. This guard restricts the exclusion to routes that declared a
    // context window, which lets a window-less route serve the request. The old
    // comment here claimed the Rust net effect was "a vision request only
    // survives on a capability-neutral route or one that declares `vision`" —
    // that is not what `model_routing.rs:374` does; nothing survives.
    if (route.contextWindow !== undefined) {
      push("media_context_unbounded", "input_token_upper_bound=unbounded");
    }
  } else if (
    requirements.requiredContextWindow !== undefined &&
    route.contextWindow !== undefined
  ) {
    const required = requirements.requiredContextWindow;
    if (route.contextWindow < required) {
      push(
        "context_window_too_small",
        `required_context_window=${required};declared_context_window=${route.contextWindow}`,
      );
    }
  }

  if (regionAllowlist.length > 0) {
    if (route.region === undefined) {
      push("region_undeclared", "declared_region=none");
    } else if (!regionAllowlist.includes(route.region)) {
      push("region_not_allowed", `declared_region=${route.region}`);
    }
  }

  return reasons;
}

/** `ModelRoutingDecision` — what survived, and why the rest did not. */
export interface RoutingDecision {
  readonly eligible: readonly PhysicalRoute[];
  readonly exclusions: readonly RouteExclusion[];
}

/** `ModelRoutingDecision::consider`, over the whole candidate list. */
export function eligibleCandidates(
  routes: readonly PhysicalRoute[],
  requirements: RouteRequirements,
  regionAllowlist: readonly string[],
): RoutingDecision {
  const eligible: PhysicalRoute[] = [];
  const exclusions: RouteExclusion[] = [];
  for (const route of routes) {
    const reasons = routeExclusionReasons(route, requirements, regionAllowlist);
    if (reasons.length === 0) {
      eligible.push(route);
    } else {
      exclusions.push(...reasons);
    }
  }
  return { eligible, exclusions };
}

/**
 * `ModelRoutingDecision::rejection` — the status/code pair for "nothing
 * survived".
 *
 * A region-only exclusion is `403 region_not_allowed` (a TENANT policy refused
 * the route); anything else is `400 invalid_request` (the REQUEST asked for
 * something no route offers). Rust splits them on
 * `has_request_requirement_exclusion`, and the split matters: a data-residency
 * refusal must not read as a malformed request.
 */
export function routingRejectionFor(
  logicalModel: string,
  exclusions: readonly RouteExclusion[],
): { readonly status: 400 | 403; readonly code: string; readonly message: string } {
  const requestRequirement = exclusions.some(
    (exclusion) =>
      exclusion.code !== "region_undeclared" && exclusion.code !== "region_not_allowed",
  );
  return requestRequirement
    ? {
        status: 400,
        code: "invalid_request",
        message: `no physical route for model ${logicalModel} satisfies the request requirements`,
      }
    : {
        status: 403,
        code: "region_not_allowed",
        message: `no candidate route for model ${logicalModel} satisfies this tenant's region allowlist`,
      };
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

/**
 * `state_routing.rs:517-540` — priority ascending, then weight DESCENDING,
 * then provider and provider model for a total order.
 *
 * A total order is not cosmetic: without the last two keys the candidate list
 * would depend on `GATEWAY_MODELS` array order for ties, so the same
 * configuration could fail over differently across two deployments. Sorting is
 * stable in JS, but the config array is not a meaningful tiebreak.
 *
 * This is the BASE order only — the one every strategy tiebreaks on and the one
 * `RoutingStrategy::Priority` rotates. The four `candidate_model_routes` arms,
 * including the weighted round-robin within a priority group
 * (`model_route_counter` / `weighted_start_index`), are
 * `strategy.ts::orderCandidatesByStrategy`, applied by `handlers.ts` to the
 * ELIGIBLE survivors — which is where Rust applies them too, after
 * `model_routing.rs` and before the first dispatch.
 *
 * It stays a separate, strategy-free function because `ModelResolver.candidates`
 * is synchronous and knows neither the request's token estimate nor the provider
 * observations, and because a total order is what makes the strategy arms
 * deterministic: without the provider/provider-model tiebreak the candidate list
 * would depend on `GATEWAY_MODELS` array order and two deployments of the same
 * config could fail over differently.
 */
export function orderCandidates(routes: readonly PhysicalRoute[]): readonly PhysicalRoute[] {
  return [...routes].sort((left, right) => {
    const priority = (left.priority ?? 0) - (right.priority ?? 0);
    if (priority !== 0) {
      return priority;
    }
    const weight = (right.weight ?? 0) - (left.weight ?? 0);
    if (weight !== 0) {
      return weight;
    }
    const provider = left.provider.localeCompare(right.provider);
    return provider !== 0 ? provider : left.providerModel.localeCompare(right.providerModel);
  });
}

// ---------------------------------------------------------------------------
// Canary / shadow
// ---------------------------------------------------------------------------

/**
 * The caller-stable key both rollouts bucket on (`AppState::canary_route`'s
 * `sticky_key`).
 *
 * API key id first, tenant second — the Rust order. It must NOT fall back to
 * the request id: a per-request key would re-roll the dice on every call, so a
 * 10% canary would send 10% of each CALLER's traffic instead of 10% of callers,
 * and a caller could see the canary and the primary alternately mid-session.
 * With no stable identity at all there is no sticky key and the rollout is
 * simply off.
 */
export function stickyKeyFor(caller: Caller): string | null {
  if (caller.apiKeyId !== undefined && caller.apiKeyId !== "") {
    return caller.apiKeyId;
  }
  if (caller.scope.kind === "tenant" && caller.scope.tenantId !== "") {
    return caller.scope.tenantId;
  }
  return null;
}

/**
 * `AppState::canary_route` — promote the canary route to the head of the
 * candidate list for the sticky subset of callers it selects.
 *
 * Rust REPLACES the primary route with the canary ("evaluated fully, like the
 * primary route"). Promoting instead of replacing keeps the ladder's failover
 * property: a selected caller gets the canary first, and if it is wedged the
 * request still completes on the stable route rather than being pinned to a
 * broken rollout. That is additive — an unselected caller's list is untouched.
 */
export function applyCanary(
  candidates: readonly PhysicalRoute[],
  caller: Caller,
): readonly PhysicalRoute[] {
  const canary = candidates.find((route) => route.canaryPercent !== undefined);
  if (canary === undefined) {
    return candidates;
  }
  const stickyKey = stickyKeyFor(caller);
  if (stickyKey === null) {
    return candidates.filter((route) => route !== canary);
  }
  if (!canarySelected(stickyKey, canary.canaryPercent ?? 0)) {
    return candidates.filter((route) => route !== canary);
  }
  return [canary, ...candidates.filter((route) => route !== canary)];
}

/**
 * The MIRROR half of the rollout lives in `./shadow.ts`.
 *
 * `shadowSampled` + the budget ledger are called from
 * `shadow.ts::shadowMirrorFor` / `runShadowMirror`, which `handlers.ts` reaches
 * through `dispatchCandidates` — i.e. on the deployed request path, once per
 * dispatched inference request. They are NOT here because the budget charge had
 * to become `async` (it is a Durable Object hop, see
 * `shadow.ts::shadowBudgetFor`) and this module is deliberately pure and
 * synchronous: every function in it is a decision, not an effect.
 *
 * What stays here is the half that IS a decision — {@link servableCandidates},
 * below, which is what makes "a mirror is never served to a client" structural
 * rather than a promise.
 */

/**
 * A shadow route is a MIRROR, never a candidate the client can be served from.
 *
 * Rust keeps them out of `eligible_routes` entirely; here the two live in one
 * flattened table (see `catalog.ts`), so the split happens on the way in. Miss
 * this and a shadow provider silently becomes a failover target — i.e. the
 * client is served by the provider that was only ever meant to be measured.
 */
export function servableCandidates(
  candidates: readonly PhysicalRoute[],
): readonly PhysicalRoute[] {
  return candidates.filter((route) => route.shadowPercent === undefined);
}
