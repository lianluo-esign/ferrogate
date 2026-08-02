/**
 * PROMPT-BY-REFERENCE on the inference path (#694).
 *
 * Without this, using a versioned prompt took two hops: `POST /v1/prompts/{id}/render`
 * to get a body, then `POST /v1/chat/completions` to send it. Two hops means the
 * caller holds the rendered prompt, which in turn means the caller decides which
 * revision ran — and a "deploy" of a prompt change becomes a change every client
 * has to adopt.
 *
 * With this, the caller sends a REFERENCE:
 *
 * ```json
 * { "prompt": { "id": "tpl_support", "label": "production",
 *               "variables": { "customer": "Ada" } } }
 * ```
 *
 * and the pointer is resolved at the edge, in this Worker, before the request
 * is validated as a chat/responses body. Moving `production` to a new revision
 * changes what every one of those callers runs, with no client change and no
 * deploy.
 *
 * ## Where this sits in the chain, and why exactly there
 *
 * `readInferenceBody` (bounded read + JSON parse) → **this** → `validateBody`
 * (Zod) → the handler. After the body read because it needs the parsed JSON;
 * BEFORE Zod because the expansion is what produces the `model` and `messages`
 * that Zod is about to require. Running it after validation would mean every
 * prompt-by-reference request first failed as "messages is required".
 *
 * The AUTHENTICATED caller is already on the context by then
 * (`inferenceCaller`, set by the first middleware), which is what lets the label
 * lookup be scoped to the right tenant. Nothing in the body influences the
 * scope.
 *
 * ## What the expansion may and may not overwrite
 *
 * The template OWNS `model` and the message list: those are the prompt. A body
 * that carries both a `prompt` reference and its own `messages`/`input` is
 * REFUSED rather than merged — merging would let a caller append to an
 * operator's system prompt, and silently dropping the caller's messages would
 * lose a request they believed they sent.
 *
 * The caller KEEPS its own sampling parameters (`temperature`, `top_p`,
 * `max_tokens`) when it sets them explicitly; the version's values are the
 * default. A caller that writes `temperature: 0.9` and silently gets the
 * template's 0.25 has no way to discover why its request behaved differently.
 *
 * ## Failure is loud, always
 *
 * Every unresolvable reference is a 4xx/5xx with a specific code, and the
 * request never reaches a provider. The alternative — dispatching with an empty
 * or default system prompt — answers 200, costs money, and is invisible until
 * someone notices the output got worse.
 */
import { PromptLabelError } from "@ferrogate/config";
import type { MiddlewareHandler } from "hono";
import {
  type PromptLabelBindings,
  promptLabelRejection,
  resolvePromptLabel,
} from "../prompts/labels.js";
import {
  PromptRenderError,
  type PromptTemplateBindings,
  findPromptTemplateVersion,
  parsePromptTemplates,
  renderPromptTemplate,
} from "../prompts/template.js";
import { errorResponse, reject } from "./errors.js";
import type { InferenceRejection } from "./errors.js";
import type { InferenceEnv } from "./handlers.js";
import type { CallerScope } from "./ports.js";

/** The member a caller sets to reference a prompt instead of writing one. */
export const PROMPT_REFERENCE_MEMBER = "prompt";

/** The two members a rendered prompt occupies, per template `target`. */
const RENDERED_MESSAGE_MEMBERS = ["messages", "input"] as const;

/** A parsed `prompt` reference. */
export interface PromptReference {
  readonly id: string;
  /** Exactly one of `label` / `revision` is set. */
  readonly label: string | null;
  readonly revision: number | null;
  readonly variables: Readonly<Record<string, unknown>>;
}

/** `true` for a plain JSON object (not an array, not null). */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Parse the `prompt` member, or throw an {@link InferenceRejection}.
 *
 * `.strict()`-equivalent by hand rather than with Zod: an unknown member inside
 * `prompt` is refused, because a caller who wrote `{"revison": 2}` must be told
 * so rather than silently served the label — or, worse, the active revision.
 */
export function parsePromptReference(raw: unknown): PromptReference {
  const invalid = (detail: string): InferenceRejection =>
    reject(400, "invalid_request", `invalid prompt reference: ${detail}`);

  if (!isRecord(raw)) throw invalid("prompt must be an object");

  const known = new Set(["id", "label", "revision", "variables"]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) throw invalid(`unknown member ${key}`);
  }

  const id = raw["id"];
  if (typeof id !== "string" || id.trim() === "") throw invalid("prompt.id is required");

  const label = raw["label"];
  if (label !== undefined && (typeof label !== "string" || label.trim() === "")) {
    throw invalid("prompt.label must be a non-empty string");
  }
  const revision = raw["revision"];
  if (revision !== undefined && !Number.isInteger(revision)) {
    throw invalid("prompt.revision must be a whole number");
  }
  // Exclusive, for the same reason the render endpoint refuses both: either
  // precedence rule makes the ignored one look honoured.
  if (label !== undefined && revision !== undefined) {
    throw invalid("prompt must not name both a label and a revision");
  }

  const variables = raw["variables"];
  if (variables !== undefined && !isRecord(variables)) {
    throw invalid("prompt.variables must be an object");
  }

  return {
    id: id.trim(),
    label: typeof label === "string" ? label : null,
    revision: typeof revision === "number" ? revision : null,
    variables: (variables as Record<string, unknown> | undefined) ?? {},
  };
}

/**
 * Resolve a reference to a rendered request body.
 *
 * Throws {@link InferenceRejection} for every failure — there is no arm that
 * returns a partially-rendered or empty body.
 */
export async function renderPromptReference(
  env: (PromptTemplateBindings & PromptLabelBindings) | undefined,
  scope: CallerScope,
  reference: PromptReference,
): Promise<Record<string, unknown>> {
  const template = parsePromptTemplates(env?.GATEWAY_PROMPT_TEMPLATES).find(
    (candidate) => candidate.id === reference.id,
  );
  if (template === undefined) {
    throw reject(
      404,
      "prompt_template_not_found",
      `prompt template ${reference.id} was not found`,
    );
  }
  if (template.status !== "active") {
    throw reject(
      409,
      "prompt_template_inactive",
      `prompt template ${reference.id} is not active`,
    );
  }

  let revision = reference.revision;
  if (reference.label !== null) {
    try {
      const pointer = await resolvePromptLabel(env, scope, reference.id, reference.label);
      revision = pointer.revision;
    } catch (error) {
      if (error instanceof PromptLabelError) {
        const rejection = promptLabelRejection(error);
        throw reject(rejection.status, rejection.code, rejection.message);
      }
      throw error;
    }
  }

  const version = findPromptTemplateVersion(template, revision);
  if (version === undefined) {
    // Reachable from a LABEL as well as from an explicit revision: the control
    // plane cannot see the operator's version table, so it accepts a pointer to
    // any revision and the edge is where an impossible one is caught.
    throw reject(
      404,
      "prompt_template_version_not_found",
      "prompt template version was not found",
    );
  }
  if (version.status !== "active") {
    throw reject(
      409,
      "prompt_template_version_inactive",
      `prompt template version ${version.revision} is not active`,
    );
  }

  try {
    return renderPromptTemplate(template, version, reference.variables);
  } catch (error) {
    if (error instanceof PromptRenderError) {
      throw reject(400, "prompt_template_render_failed", error.message);
    }
    throw error;
  }
}

/**
 * Merge a rendered prompt into the caller's request body.
 *
 * The template wins on `model` and on the message member; the caller wins on
 * everything it set explicitly (`stream`, `temperature`, `metadata`, …). See
 * the module docblock for why the split is that way round.
 */
export function mergeRenderedPrompt(
  body: Record<string, unknown>,
  rendered: Record<string, unknown>,
): Record<string, unknown> {
  const { [PROMPT_REFERENCE_MEMBER]: _reference, ...rest } = body;
  const merged: Record<string, unknown> = { ...rendered, ...rest };
  // `rest` cannot carry `model`, `messages` or `input` — the guard in
  // `expandPromptReference` refuses a body that does — so re-asserting the
  // template's values here is belt-and-braces against a future edit that
  // relaxes that guard without noticing this line.
  merged["model"] = rendered["model"];
  for (const member of RENDERED_MESSAGE_MEMBERS) {
    if (member in rendered) merged[member] = rendered[member];
    else delete merged[member];
  }
  return merged;
}

/**
 * Re-present the EXPANDED body to everything downstream that reads the request.
 *
 * Setting `c.req.bodyCache.json` alone is NOT enough, and the reason is a
 * genuine Hono subtlety worth writing down rather than rediscovering:
 * `HonoRequest#json()` is implemented as `#cachedBody("text")`, and
 * `#cachedBody` falls back to *whichever key was cached FIRST* when the one it
 * wants is absent. `readInferenceBody` has already called `c.req.arrayBuffer()`
 * by this point, so `arrayBuffer` is that first key — the Zod validator would
 * re-decode the ORIGINAL bytes and never see the expansion, i.e. every
 * prompt-by-reference request would fail as "missing field `model`". (It did,
 * before this function existed.)
 *
 * So the cache is CLEARED and `raw` is replaced with the expanded bytes, which
 * is exactly what `readInferenceBody` does one step earlier. Every later reader
 * — the validator, a re-read in a handler, the cache-key builder — then sees
 * one body, and there is no path on which validation and dispatch disagree
 * about what was sent.
 */
function republishBody(
  c: Parameters<MiddlewareHandler<InferenceEnv>>[0],
  expanded: Record<string, unknown>,
): void {
  const cache = c.req.bodyCache as unknown as Record<string, unknown>;
  for (const key of Object.keys(cache)) delete cache[key];
  c.req.raw = new Request(c.req.raw.url, {
    method: c.req.raw.method,
    headers: c.req.raw.headers,
    body: JSON.stringify(expanded),
  });
}

/**
 * The middleware. A body with no `prompt` member passes straight through, so
 * this costs one property read on every request that does not use the feature.
 */
export function expandPromptReference(): MiddlewareHandler<InferenceEnv> {
  return async (c, next) => {
    const body = c.get("inferenceBody");
    if (!isRecord(body) || body[PROMPT_REFERENCE_MEMBER] === undefined) {
      await next();
      return;
    }

    const requestId = c.get("requestId");
    try {
      // The caller may not supply its own prompt content alongside a reference.
      // Refused rather than merged: merging lets a client append to an
      // operator's system prompt, and dropping lets a client believe it sent
      // messages that were discarded.
      for (const member of ["model", ...RENDERED_MESSAGE_MEMBERS]) {
        if (body[member] !== undefined) {
          throw reject(
            400,
            "invalid_request",
            `invalid prompt reference: ${member} must not be set alongside prompt`,
          );
        }
      }

      const reference = parsePromptReference(body[PROMPT_REFERENCE_MEMBER]);
      const rendered = await renderPromptReference(
        c.env as (PromptTemplateBindings & PromptLabelBindings) | undefined,
        c.get("inferenceCaller").scope,
        reference,
      );
      const expanded = mergeRenderedPrompt(body, rendered);
      c.set("inferenceBody", expanded);
      republishBody(c, expanded);
    } catch (error) {
      if (isRejection(error)) return errorResponse(error, requestId);
      throw error;
    }

    await next();
    return;
  };
}

/** `reject()` returns a plain object, so the guard is structural. */
function isRejection(value: unknown): value is InferenceRejection {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    "code" in value &&
    "message" in value
  );
}
