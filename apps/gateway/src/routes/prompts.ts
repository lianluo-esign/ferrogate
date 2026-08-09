/**
 * `POST /v1/prompts/{id}/render` — server-side prompt-template rendering.
 *
 * Clean-room port of `server/local.rs::handle_prompt_template_render` plus its
 * six helpers (`find_prompt_template`, `find_prompt_template_version`,
 * `active_prompt_template_version`, `render_prompt_template`,
 * `render_prompt_template_text`, `prompt_template_variable_value`) —
 * `docs/legacy/inventory-request-path.md` §prompts.
 *
 * ## Why this replaced a 501
 *
 * The old stub said "blocked on the `prompt_templates` read model in
 * `apps/control-plane`". That was wrong in the same way the skills stub was:
 * `handle_prompt_template_render` reads `state.config.prompt_templates` — the
 * `[[prompt_templates]]` OPERATOR CONFIG TABLE — and never a repository. The
 * table is `GATEWAY_PROMPT_TEMPLATES` here, parsed with the SAME
 * `promptTemplateSchema` `@ferrogate/config` uses for the operator document.
 *
 * ## What this endpoint IS
 *
 * It renders and returns a request body; it does NOT dispatch it. That is the
 * Rust behavior (`write_json_response(… &rendered …)`) and it is why the
 * operation is worth having: an operator owns the prompt, a client owns only the
 * variables, and the client can then post the rendered body to
 * `/v1/chat/completions` or `/v1/responses` itself.
 *
 * Which is exactly why the MODEL GATES below are not optional decoration.
 * Because the render names a model, an ungated render would let an under-scoped
 * key discover which models exist and what another tenant's private models are
 * called. Rust runs the full model ladder here before it renders anything, and
 * so does this.
 *
 * ## The one deliberate divergence, stated rather than hidden
 *
 * Rust calls `state.resolve_model` (which distinguishes `ModelDisabled` from
 * unknown) and SEPARATELY `candidate_model_routes(...).eligible_routes`, so a
 * model that resolves but whose every route is ineligible (e.g. excluded by the
 * caller's region allowlist) answers `403 provider_not_allowed`. This port
 * follows `inference/handlers.ts::planUpstream` instead — an empty candidate
 * list is `400 model_disabled` / `400 model_not_found` — because a rendered body
 * that cannot be dispatched is worse than a refusal, and the render must agree
 * with what `/v1/chat/completions` would answer for the same model on the same
 * credential. Divergence is confined to which 4xx an already-refused request
 * receives; no request is admitted here that inference would refuse.
 *
 * ## Residue (NOT closed, and not a platform limit)
 *
 * PORT-TODO(cert3-dataplane A8 · `server/local.rs::handle_prompt_template_render`):
 * this route writes NO audit row. Recorded as a marker rather than prose because
 * `cert2-dataplane` A8 named it, `cert3-dataplane` re-confirmed it unchanged a
 * wave later, and a paragraph is not something `grep -rn "PORT-TODO"` finds.
 *
 * Rust records an `admin_audit_event` on every arm of this handler — success and
 * each refusal, carrying `variable_count` and `variable_schema_hash`. There is
 * no admin-audit sink anywhere in `apps/gateway/src` to write to (the audit
 * tables live in `apps/control-plane`), so no audit trail is emitted. That is a
 * SCOPE gap in a different app, not a Workers limitation — Analytics Engine or a
 * D1 insert would both carry it. It is called out here rather than silently
 * dropped so the next owner does not assume this route is audited.
 */

import { PromptLabelError } from "@ferrogate/config";
import type { Context } from "hono";
import { modelsFromEnv } from "../inference/catalog.js";
import { resolveCandidates } from "../inference/defaults.js";
import { callerFromAuth } from "../inference/identity.js";
import type { InferenceBindings } from "../inference/ports.js";
import {
  type PhysicalRoute,
  callerCanUseModel,
  callerCanUseProvider,
  scopeCanSeeModel,
} from "../inference/ports.js";
import { HttpError } from "../middleware/errors.js";
import type { AuthContext, GatewayEnv } from "../ports.js";
import type { PromptLabelBindings } from "../prompts/labels.js";
import { promptLabelRejection, resolvePromptLabel } from "../prompts/labels.js";
import {
  PromptRenderError,
  type PromptTemplateBindings,
  findPromptTemplateVersion,
  parsePromptTemplates,
  renderPromptTemplate,
} from "../prompts/template.js";

// The renderer moved to `../prompts/template.ts` (#694) so the inference
// prompt-by-reference expander can reach it without `inference/` importing
// `routes/`, which already imports `inference/`. Re-exported verbatim: every
// existing importer and every existing test keeps working, and the module that
// OWNS the algorithm is now the one with no dependencies on either side.
export {
  PROMPT_TEMPLATES_VAR,
  PromptRenderError,
  activePromptTemplateVersion,
  findPromptTemplateVersion,
  parsePromptTemplates,
  promptVariableToString,
  promptVariableValue,
  renderPromptTemplate,
  renderPromptText,
} from "../prompts/template.js";
export type { PromptTemplateBindings, RenderedPrompt } from "../prompts/template.js";

/**
 * `PromptTemplateRenderRequest`. All three members are optional.
 *
 * `label` is the #694 addition and it is EXCLUSIVE with `revision`: a body
 * carrying both is a caller who does not know which one they meant, and
 * silently preferring one would make the other look honoured. See
 * {@link readRenderRequest}.
 */
export interface PromptTemplateRenderRequest {
  readonly variables: Readonly<Record<string, unknown>>;
  readonly revision: number | null;
  readonly label: string | null;
}

/** The one message every malformed body gets, so the shape is never inferable. */
const INVALID_RENDER_BODY =
  "request body must be JSON with variables and an optional revision or label";

/**
 * `PromptTemplateRenderRequest` off the wire.
 *
 * An EMPTY body is `{ variables: {}, revision: null, label: null }`, not a 400 —
 * Rust checks `body.is_empty()` first, so `POST` with no body renders the active
 * version with defaults. Anything present but not a JSON object is
 * `400 invalid_request_body`.
 */
async function readRenderRequest(c: Context<GatewayEnv>): Promise<PromptTemplateRenderRequest> {
  const raw = await c.req.text();
  if (raw.trim() === "") {
    return { variables: {}, revision: null, label: null };
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    throw new HttpError(400, "invalid_request_body", INVALID_RENDER_BODY);
  }
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new HttpError(400, "invalid_request_body", INVALID_RENDER_BODY);
  }
  const body = decoded as Record<string, unknown>;
  const variables = body.variables;
  const revision = body.revision;
  const label = body.label;
  if (
    variables !== undefined &&
    (typeof variables !== "object" || variables === null || Array.isArray(variables))
  ) {
    throw new HttpError(400, "invalid_request_body", INVALID_RENDER_BODY);
  }
  if (revision !== undefined && revision !== null && !Number.isInteger(revision)) {
    throw new HttpError(400, "invalid_request_body", INVALID_RENDER_BODY);
  }
  if (label !== undefined && label !== null && typeof label !== "string") {
    throw new HttpError(400, "invalid_request_body", INVALID_RENDER_BODY);
  }
  // EXCLUSIVE, not "label wins" or "revision wins". A body naming both is a
  // caller who does not know which one they meant, and either precedence rule
  // makes the ignored one look honoured — which is how a rollback lands on the
  // revision it was rolling back FROM.
  if (typeof revision === "number" && typeof label === "string" && label.trim() !== "") {
    throw new HttpError(
      400,
      "invalid_request_body",
      "request body must not name both a revision and a label",
    );
  }
  return {
    variables: (variables as Record<string, unknown> | undefined) ?? {},
    revision: typeof revision === "number" ? revision : null,
    label: typeof label === "string" && label.trim() !== "" ? label : null,
  };
}

/**
 * The credential a request with no `AuthContext` is evaluated as.
 *
 * `contractAuth` has already run for this bearer operation, so `c.get("auth")`
 * is non-null in production and this value is unreachable. It exists so that if
 * the operation is ever re-declared anonymous, the model gates below still RUN
 * — against a caller confined to the empty-string tenant, which matches no
 * route — rather than being skipped. Fail-closed on a shape that should not
 * occur, instead of `if (auth === null) render()`.
 */
const NO_CREDENTIAL: AuthContext = {
  subject: null,
  tenancy: { tenantId: null },
  scopes: [],
  platformOperator: false,
  source: "static_config",
};

/**
 * Resolve a label to a revision, turning every failure into an HTTP refusal.
 *
 * There is no fallback arm on purpose. "Label not found ⇒ render the active
 * revision" would be a 200 carrying a prompt the operator did not deploy, and
 * "label not found ⇒ render nothing" would be a 200 carrying an empty system
 * prompt. Both are invisible until the output quality or the bill moves, which
 * is precisely the failure mode #694 exists to remove.
 */
async function labelledRevision(
  c: Context<GatewayEnv>,
  scope: Parameters<typeof resolvePromptLabel>[1],
  templateId: string,
  label: string,
): Promise<number> {
  try {
    const pointer = await resolvePromptLabel(
      c.env as PromptLabelBindings | undefined,
      scope,
      templateId,
      label,
    );
    return pointer.revision;
  } catch (error) {
    if (error instanceof PromptLabelError) {
      const rejection = promptLabelRejection(error);
      throw new HttpError(rejection.status, rejection.code, rejection.message);
    }
    throw error;
  }
}

/** The `renderPromptTemplate` operation handler. */
export async function renderPromptTemplateHandler(c: Context<GatewayEnv>): Promise<Response> {
  const id = c.req.param("id") ?? "";
  // Body FIRST, exactly as Rust does: a malformed body is refused before the
  // template lookup, so a client with a broken payload cannot use the 404-vs-400
  // split to probe which template ids exist.
  const request = await readRenderRequest(c);

  const env = c.env as PromptTemplateBindings | undefined;
  const template = parsePromptTemplates(env?.GATEWAY_PROMPT_TEMPLATES).find(
    (candidate) => candidate.id === id,
  );
  if (template === undefined) {
    throw new HttpError(404, "prompt_template_not_found", `prompt template ${id} was not found`);
  }

  // `callerFromAuth` carries `allowedModels` AND `allowedProviders` off the
  // `api_keys` row, so the two per-key allowlist gates below are the SAME
  // predicate the inference ladder applies — a key that may not use a model
  // through `/v1/chat/completions` cannot obtain a body naming it here either.
  const caller = callerFromAuth(c.get("auth") ?? NO_CREDENTIAL);

  // --- the model ladder, in the Rust order -------------------------------
  if (!callerCanUseModel(caller, template.model)) {
    throw new HttpError(
      403,
      "model_not_allowed",
      `API key is not allowed to use model ${template.model}`,
    );
  }

  const models = modelsFromEnv((c.env ?? {}) as InferenceBindings);
  const candidates = resolveCandidates(models, template.model);
  if (candidates.length === 0) {
    const known = models.catalog().find((route) => route.logicalModel === template.model);
    throw known === undefined
      ? new HttpError(400, "model_not_found", `unknown model ${template.model}`)
      : new HttpError(400, "model_disabled", `model ${template.model} is disabled`);
  }

  if (!scopeCanSeeModel(caller.scope, caller.projectId, candidates[0] as PhysicalRoute)) {
    throw new HttpError(
      403,
      "model_not_visible",
      `model ${template.model} is not visible to this tenant`,
    );
  }

  if (!candidates.some((route) => callerCanUseProvider(caller, route.provider))) {
    throw new HttpError(
      403,
      "provider_not_allowed",
      `API key is not allowed to use any provider for model ${template.model}`,
    );
  }

  // --- template/version state, AFTER the model ladder --------------------
  // The order is Rust's and it is deliberate: a caller who may not use the
  // model learns nothing about the template's lifecycle state.
  if (template.status !== "active") {
    throw new HttpError(409, "prompt_template_inactive", `prompt template ${id} is not active`);
  }

  // --- label resolution, at the EDGE -------------------------------------
  // AFTER the model ladder and the template-status gate, for the same reason
  // those come first: a caller who may not use this template must not learn
  // which labels it has. The pointer read is one KV `get` against a key derived
  // from the AUTHENTICATED caller's scope, so a tenant cannot reach another
  // tenant's pointer by naming the same template id and label.
  const revision =
    request.label === null
      ? request.revision
      : await labelledRevision(c, caller.scope, id, request.label);

  const version = findPromptTemplateVersion(template, revision);
  if (version === undefined) {
    throw new HttpError(
      404,
      "prompt_template_version_not_found",
      "prompt template version was not found",
    );
  }
  if (version.status !== "active") {
    throw new HttpError(
      409,
      "prompt_template_version_inactive",
      `prompt template version ${version.revision} is not active`,
    );
  }

  try {
    return c.json(renderPromptTemplate(template, version, request.variables));
  } catch (error) {
    if (error instanceof PromptRenderError) {
      throw new HttpError(400, "prompt_template_render_failed", error.message);
    }
    throw error;
  }
}
