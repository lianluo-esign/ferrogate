/**
 * What a client is told about a logical model on `GET /v1/models` and
 * `GET /v1/models/{model}` (issue #670).
 *
 * ## Why this is a derivation and not new configuration
 *
 * Every field below already exists in `[[models]]` and is already parsed onto
 * {@link PhysicalRoute} by `catalog.ts` — `capabilities`, `context_window`,
 * `input_price_per_1m`, `output_price_per_1m`. Adding a parallel
 * `modalities = [...]` key to the model table would create a SECOND source of
 * truth for something the capability vocabulary already decides
 * (`docs/model-route-capabilities.md`: `vision` means an image input block is
 * accepted, `images` means the route serves `POST /v1/images/generations`,
 * `embeddings` means it serves `POST /v1/embeddings`), and the two would drift
 * the first time an operator set one and not the other. So the modality answer
 * is COMPUTED from the capability declaration, and this file is the only place
 * that mapping exists.
 *
 * ## Which route answers, when a logical model has several
 *
 * A logical model flattens into one PRIMARY leg plus its fallbacks/canary
 * (`catalog.ts::buildModelCatalog`), and capabilities are declared PER LEG —
 * that is `docs/model-route-capabilities.md`'s rule, not a choice made here.
 * The three fields are therefore aggregated differently, and each rule follows
 * from what the eligibility gate (`candidates.ts::eligibleCandidates`) will
 * actually do with the request the answer is used to plan:
 *
 *  - **capabilities: the UNION over the legs.** A vision request is servable if
 *    ANY eligible leg declares `vision`, because the gate excludes the legs that
 *    do not and dispatches the one that does. Reporting only the primary's
 *    declaration would tell a client "no vision" about a model that serves
 *    vision through its fallback.
 *  - **context_window: the MAXIMUM declared.** Same argument: the gate admits
 *    the request if some leg's window covers it. `null` means NO leg declares
 *    one, which is "undeclared", not "unlimited" — an undeclared window is a
 *    hard exclusion for anything but the capability-neutral legacy case.
 *  - **pricing: the PRIMARY leg's.** Price is not a capability: it is what this
 *    request is likely to cost, and the primary is the leg that serves under the
 *    default `priority` strategy. It is an estimate and is documented as one —
 *    a failover, a canary, or a cost-aware `routing_strategy` can put a
 *    differently-priced leg on the wire. Taking a max here would systematically
 *    overstate the bill; taking a min would understate it.
 *
 * `null` prices mean UNPRICED, and that is a real state: the config validator
 * only forces prices when `routing_strategy = lowest_cost` / `balanced` or the
 * billing service is enabled (`packages/config/src/validate/entities.ts:95-144`),
 * so an operator may legitimately ship a model with no price. `0` is a genuinely
 * FREE route and must stay distinguishable from it, which is why the field is
 * `number | null` and never an omitted key or a `0` default.
 */
import type { ModelCapability, PhysicalRoute } from "./ports.js";
import type { OpenAiModel } from "./schemas.js";

/**
 * Capability vocabulary in CONFIG order (`catalog.ts::capabilitySchema`).
 *
 * The union below is emitted in this order rather than in first-seen order so
 * the wire answer for a given catalog is stable no matter how the legs were
 * written down — a client diffing two `GET /v1/models` responses should see a
 * change only when the configuration actually changed.
 */
const CAPABILITY_ORDER: readonly ModelCapability[] = [
  "chat",
  "streaming",
  "vision",
  "images",
  "embeddings",
  "rerank",
  "tools",
  "structured_output",
];

/**
 * What a model consumes and produces.
 *
 * `embedding` is an output "modality" only in the loose sense OpenRouter and
 * LiteLLM use the word — it is a vector, not a medium. It is spelled out anyway
 * because the alternative (calling an embeddings model's output `text`) would be
 * false, and omitting the output entirely would make the field unusable for
 * exactly the routing decision a client asks it for.
 *
 * `score` (issue #676) is here for that same reason, one step further: a
 * reranker emits a relevance number per document. Calling that `text` would be
 * false and calling it `embedding` would be worse — a client that reads
 * `embedding` will try to do vector arithmetic on a scalar. Leaving the output
 * EMPTY was the other candidate, and is rejected on this file's own rule: an
 * empty output array says "produces nothing", which is a different claim from
 * "produces something this vocabulary cannot name".
 */
export type ModelModality = "text" | "image" | "embedding" | "score";

/** Input/output modality support for one logical model. */
export interface ModelModalities {
  readonly input: ModelModality[];
  readonly output: ModelModality[];
}

/** Per-1M-token prices, in USD. `null` on either leg means UNPRICED. */
export interface ModelPricing {
  readonly currency: "USD";
  /** Naming the unit on the wire so `3` can never be read as "$3 per call". */
  readonly unit: "per_1m_tokens";
  readonly input: number | null;
  readonly output: number | null;
}

/**
 * One entry of `GET /v1/models`, and the whole body of `GET /v1/models/{model}`.
 *
 * The first four fields are the OpenAI `Model` object byte for byte; everything
 * after them is additive, which is what keeps an OpenAI-shaped client working
 * unchanged (unknown keys are ignored by every SDK) while giving an integrator
 * the metadata OpenRouter/LiteLLM/Vercel all publish.
 */
export interface ModelDescriptor {
  readonly id: string;
  readonly object: "model";
  readonly created: number;
  readonly owned_by: string;
  readonly capabilities: ModelCapability[];
  readonly context_window: number | null;
  readonly modalities: ModelModalities;
  readonly pricing: ModelPricing;
}

/**
 * Compile-time parity guard, in the style of `packages/schemas`'s
 * `assertScopeParity`: what this file BUILDS must satisfy the schema
 * `schemas.ts` publishes as the wire contract for `listModels` / `getModel`.
 * Add a field to one and not the other and this stops type-checking, which is
 * cheaper than discovering the divergence from a response body.
 */
export const assertModelDescriptorParity = (model: ModelDescriptor): OpenAiModel => model;

/**
 * Capability declaration → modality support.
 *
 * Text input is unconditional: every route in the vocabulary takes text (an
 * images route takes a text `prompt`, an embeddings route takes text `input`).
 * Image INPUT is exactly the `vision` capability, by that capability's own
 * definition.
 *
 * On the output side, an EMPTY declaration is the capability-neutral legacy row,
 * which `docs/model-route-capabilities.md` says stays eligible only for a
 * chat-style request with no extra feature — so `text` is the honest answer for
 * it, and the empty `capabilities` array beside it is what tells a client the
 * declaration is absent rather than exhaustive.
 */
export function modalitiesFor(capabilities: readonly ModelCapability[]): ModelModalities {
  const declared = new Set(capabilities);
  const input: ModelModality[] = ["text"];
  if (declared.has("vision")) {
    input.push("image");
  }

  const output: ModelModality[] = [];
  // Anything chat-shaped emits text; so does an undeclared legacy row.
  if (
    capabilities.length === 0 ||
    declared.has("chat") ||
    declared.has("streaming") ||
    declared.has("tools") ||
    declared.has("structured_output") ||
    declared.has("vision")
  ) {
    output.push("text");
  }
  if (declared.has("images")) {
    output.push("image");
  }
  if (declared.has("embeddings")) {
    output.push("embedding");
  }
  if (declared.has("rerank")) {
    output.push("score");
  }
  return { input, output };
}

/**
 * Describe one logical model.
 *
 * `entry` is the row `ModelResolver.catalog()` returns for the model (one per
 * logical name); `legs` is `ModelResolver.candidates()` for it — the primary
 * first, in `orderCandidates` order. `legs` may be empty when a resolver
 * predates the candidate seam, in which case `entry` is the only thing known and
 * is used as the sole leg.
 *
 * `id` and `owned_by` come from `entry` and are unchanged from the pre-#670 wire
 * shape: `owned_by` is `[[models]].owned_by` falling back to the provider name,
 * and `created` is the hard-coded `0` the Rust tree emitted (the config carries
 * no creation time and inventing one would be a lie a client could sort on).
 */
export function describeModel(
  entry: PhysicalRoute,
  legs: readonly PhysicalRoute[],
): ModelDescriptor {
  const routes = legs.length > 0 ? legs : [entry];

  const declared = new Set<ModelCapability>();
  for (const route of routes) {
    for (const capability of route.capabilities ?? []) {
      declared.add(capability);
    }
  }
  const capabilities = CAPABILITY_ORDER.filter((capability) => declared.has(capability));

  const windows = routes
    .map((route) => route.contextWindow)
    .filter((window): window is number => typeof window === "number");
  const contextWindow = windows.length === 0 ? null : Math.max(...windows);

  // The leg that serves under the default `priority` strategy — see the header.
  const primary = routes[0] as PhysicalRoute;

  return {
    id: entry.logicalModel,
    object: "model",
    created: 0,
    owned_by: entry.ownedBy ?? entry.provider,
    capabilities,
    context_window: contextWindow,
    modalities: modalitiesFor(capabilities),
    pricing: {
      currency: "USD",
      unit: "per_1m_tokens",
      input: primary.inputPricePer1m ?? null,
      output: primary.outputPricePer1m ?? null,
    },
  };
}
