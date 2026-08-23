/**
 * `403 attribution_tags_required` — the enforcement seam for #678.
 *
 * ============================================================================
 * WHERE THIS SITS ON THE LADDER, AND WHY
 * ============================================================================
 *
 * `src/index.ts` mounts it between `rateLimit()` and `guardrails()`:
 *
 *   contractAuth → meteringDrain → requestTelemetry → requestLogging
 *                → rateLimit → **attributionTags** → guardrails
 *                → tenantDatabase → responseCache → validate → dispatch
 *
 * Each of those neighbours is a decision, not a coincidence.
 *
 *  - **AFTER `contractAuth`** — structurally forced twice over. The policy is
 *    per-TENANT and the tenant only exists once the credential resolves; and the
 *    tags are in the BODY, so reading them before authentication would invert
 *    the rule `chat.rs:158` states and this tree preserves everywhere else
 *    ("authenticate before reading the body, so an unauthenticated oversized
 *    request is still `missing_api_key` and not `payload_too_large`").
 *
 *  - **AFTER `rateLimit()`** — so an untagged request still BURNS the caller's
 *    RPM/quota window. Refusing ahead of admission would create an unmetered
 *    refusal path: a client could flood the gateway with untagged requests, pay
 *    nothing against its own limits, and never be throttled. That is the same
 *    argument `nodeDrainGate` makes for its own position ("a drained node would
 *    stop charging admission counters that Rust still charges"), and it is why
 *    the cheaper-looking position is the wrong one.
 *
 *  - **BEFORE `guardrails()`** — because guardrail screening is the first stage
 *    that can spend real money. `src/index.ts` says so about its own ordering:
 *    "Reversing the two would spend detector work — including paid provider
 *    calls — on requests that were never admitted." A request this gate refuses
 *    is never dispatched, so screening it would buy detector work for a prompt
 *    that reaches no model. A refusal that costs a provider call is a worse bug
 *    than the untagged request it refused.
 *
 *  - **AHEAD of `responseCache` and the routes** — a cache HIT is still a
 *    request, and an untagged one still produces an unattributable record.
 *
 * The refusal is still RECORDED: `requestLogging()` is mounted three layers
 * further out and wraps everything below it, so a 403 from here lands in the
 * #664 request log exactly like a 429 from `rateLimit()` or a 403 from
 * `guardrails()`. An enforcement point invisible to the audit trail would be its
 * own defect.
 *
 * ============================================================================
 * WHY 403 AND NOT 400
 * ============================================================================
 *
 * The body is well-formed; what refuses it is POLICY. That is the same
 * distinction the rest of the path draws — `invalid_request_metadata` (400) is a
 * metadata map that violates the #171 BOUNDS, while `model_not_allowed`,
 * `provider_not_allowed`, `workflow_provider_not_allowed` and `guardrail_blocked`
 * are all 403 because a well-formed request was refused by a rule. An identical
 * request from a tenant with no policy is served, which is the definition of a
 * policy refusal rather than a malformed one.
 */
import type { Context, MiddlewareHandler, Next } from "hono";
import { HttpError } from "../middleware/errors.js";
import type { GatewayEnv } from "../ports.js";
import { recordAttributionDefaults } from "./defaults.js";
import { type TagMap, attributionDecision, missingTagMessage } from "./policy.js";
import {
  type AttributionBindings,
  type AttributionPolicySource,
  attributionPolicySourceFromEnv,
} from "./source.js";

/**
 * The operations an attribution policy governs: the five that SPEND.
 *
 * The same five `routes/drain.ts::DRAIN_GUARDED_OPERATION_IDS` names, and for
 * the same reason rather than by import — the two lists answer different
 * questions ("may this node take new work" vs "is this work attributable") and
 * a future divergence in either should read as a decision, not as a typo in a
 * shared constant.
 *
 * `listModels`, `getModel` and `countMessageTokens` are deliberately absent:
 * none of them dispatches to a provider, none of them settles a
 * `billing_events` row, and so none of them can produce the unattributable cost
 * this gate exists to prevent. Refusing a catalogue read or a token estimate
 * because a caller forgot a tag would break exactly the pre-flight a client runs
 * while trying to get its tagging right.
 */
export const ATTRIBUTED_OPERATION_IDS: readonly string[] = [
  "createChatCompletion",
  "createResponse",
  "createMessage",
  // `geminiGenerateContent` — the Gemini-native ingress dispatches to a
  // provider and settles a `billing_events` row like the generative surfaces
  // beside it, so an untagged call produces the same unattributable cost this
  // gate exists to prevent.
  "geminiGenerateContent",
  "createEmbedding",
  "createImage",
];

/**
 * Cap on the body this middleware will read to find `metadata`.
 *
 * It MUST be at least the inference reader's own cap
 * (`inference/defaults.ts::inferenceBodyMaxBytes`, 1 MiB): a body between the
 * two caps would skip enforcement here and still be SERVED downstream, which is
 * a hole shaped exactly like the defect. It is the same number for that reason,
 * and `guardrails/middleware.ts` reads its request body under the same one.
 */
const MAX_BODY_BYTES = 1024 * 1024;

export interface AttributionMiddlewareOptions {
  /** Override the policy source. Production reads it from `env`. */
  readonly policies?:
    | AttributionPolicySource
    | ((env: AttributionBindings) => AttributionPolicySource);
  /** Override the guarded operation set (tests narrow it). */
  readonly operationIds?: readonly string[];
}

/**
 * Enforce the calling tenant's attribution policy.
 *
 * Inert — one `Map` lookup or one cached D1 read — for every deployment that has
 * configured no policy, which is every deployment until an operator opts in.
 */
export function attributionTags(
  options: AttributionMiddlewareOptions = {},
): MiddlewareHandler<GatewayEnv> {
  const guarded = new Set(options.operationIds ?? ATTRIBUTED_OPERATION_IDS);

  return async function attributionTagsMiddleware(c, next: Next): Promise<void> {
    const operation = (c as Context<GatewayEnv>).get("operation");
    if (operation === null || operation === undefined || !guarded.has(operation.operationId)) {
      await next();
      return;
    }

    const auth = c.get("auth");
    // A contract-`anonymous` request, or one the guard did not authenticate.
    // None of the five guarded operations is anonymous, so this is the
    // inner-app / misconfiguration arm; there is no tenant to look a policy up
    // by, and inventing one would be inventing an enforcement decision.
    if (auth === null || auth === undefined) {
      await next();
      return;
    }

    // The AUTHENTICATED tenant — never a header, never a body field. This is the
    // value the fence is built on; see `./source.ts`.
    const tenantId = auth.tenancy.tenantId;
    if (tenantId === null || tenantId === undefined || tenantId === "") {
      // A platform-operator or unclassified credential belongs to no tenant, so
      // no per-tenant policy can name it. Its spend is the operator's own.
      await next();
      return;
    }

    const env = c.env as unknown as AttributionBindings;
    const source =
      typeof options.policies === "function"
        ? options.policies(env)
        : (options.policies ?? attributionPolicySourceFromEnv(env));

    const resolved = await source.policyFor(tenantId);
    if (!resolved.ok) {
      // An outage, not an admission. Admitting here would open precisely the
      // window this control closes; and the sibling admission gate one layer up
      // already answers 503 on the same database, so this costs no availability
      // a request under a bound `CONTROL_DB` did not already have.
      throw new HttpError(
        503,
        "attribution_policy_unavailable",
        `attribution policy lookup failed: ${resolved.detail}`,
      );
    }
    if (resolved.policy === null) {
      await next();
      return;
    }

    const decision = attributionDecision(
      resolved.policy,
      await requestTags(c.req.raw),
      keyTagsOf(auth),
    );
    if (decision.kind === "refuse") {
      throw new HttpError(403, "attribution_tags_required", missingTagMessage(decision.missing));
    }
    // Keyed by the inbound `Request` — the same object `route-module.ts` hands
    // to `inner.fetch` and reads the scope back from.
    recordAttributionDefaults(c.req.raw, decision.defaults);
    await next();
  };
}

/**
 * The tags the presented CREDENTIAL declares — the "virtual key's own
 * attribution" the issue names as the defaulting source.
 *
 * It comes off `AuthContext`, which is the credential THIS request presented and
 * which the authenticator resolved from this request's own bearer token. There
 * is no second lookup and no cache keyed on anything but that resolution, so
 * there is no path by which another tenant's key could supply these values.
 */
function keyTagsOf(auth: { readonly attributionTags?: TagMap | undefined }): TagMap | undefined {
  return auth.attributionTags;
}

/**
 * Read `metadata` off the request body WITHOUT consuming it.
 *
 * `Request.clone()` tees the body in workerd, so the inference reader downstream
 * still sees the original bytes, its own `payload_too_large` / `invalid_json`
 * behaviour is untouched, and `c.req.bodyCache` is never populated — the same
 * device, for the same reason, as `guardrails/middleware.ts::readJsonBodyBounded`.
 *
 * ## An unreadable body means "do not enforce", and that is not a hole
 *
 * A body that is absent, over the cap, not JSON, or not an object cannot be
 * enforced against — and must not be, because the DOWNSTREAM reader owns the
 * precise refusal for each of those (`payload_too_large`, `invalid_json`,
 * `invalid_request`). Answering `attribution_tags_required` for an oversized
 * body would replace an accurate error with a misleading one. None of those
 * requests can be SERVED, so skipping enforcement admits nothing: the request
 * is refused a few layers down with a better message.
 */
async function requestTags(request: Request): Promise<TagMap | undefined> {
  if (request.body === null) return undefined;
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const length = Number.parseInt(declared, 10);
    if (Number.isFinite(length) && length > MAX_BODY_BYTES) return undefined;
  }
  try {
    const bytes = await readBounded(request.clone(), MAX_BODY_BYTES);
    if (bytes === undefined) return undefined;
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
    const metadata = (parsed as Record<string, unknown>).metadata;
    if (typeof metadata !== "object" || metadata === null || Array.isArray(metadata)) {
      return undefined;
    }
    // Only string values are attribution. A non-string (which the #171 schema
    // refuses downstream anyway) is dropped rather than stringified, so
    // `{"team": null}` cannot satisfy a policy.
    const tags: Record<string, string> = {};
    for (const [key, value] of Object.entries(metadata as Record<string, unknown>)) {
      if (typeof value === "string") tags[key] = value;
    }
    return tags;
  } catch {
    return undefined;
  }
}

/** Read at most `max` bytes, or `undefined` when the body exceeds it. */
async function readBounded(request: Request, max: number): Promise<Uint8Array | undefined> {
  const body = request.body;
  if (body === null) return undefined;
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    total += chunk.value.byteLength;
    if (total > max) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(chunk.value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}
