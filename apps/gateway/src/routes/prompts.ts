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
 * Rust records an `admin_audit_event` on every arm of this handler — success and
 * each refusal, carrying `variable_count` and `variable_schema_hash`. There is
 * no admin-audit sink anywhere in `apps/gateway/src` to write to (the audit
 * tables live in `apps/control-plane`), so no audit trail is emitted. That is a
 * SCOPE gap in a different app, not a Workers limitation — Analytics Engine or a
 * D1 insert would both carry it. It is called out here rather than silently
 * dropped so the next owner does not assume this route is audited.
 */
import { type PromptTemplate, type PromptTemplateVersion, promptTemplateSchema } from "@ferrogate/config";
import type { Context } from "hono";
import { resolveCandidates } from "../inference/defaults.js";
import { modelsFromEnv } from "../inference/catalog.js";
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

/** JSON array of `PromptTemplate` records — Rust `[[prompt_templates]]`. */
export const PROMPT_TEMPLATES_VAR = "GATEWAY_PROMPT_TEMPLATES";

/** Bindings this module reads on top of `GatewayBindings`. */
export interface PromptTemplateBindings {
  readonly GATEWAY_PROMPT_TEMPLATES?: string | undefined;
}

/** `PromptTemplateRenderRequest`. Both members are `#[serde(default)]`. */
export interface PromptTemplateRenderRequest {
  readonly variables: Readonly<Record<string, unknown>>;
  readonly revision: number | null;
}

/** The rendered request body Rust writes back. Shape depends on `target`. */
export type RenderedPrompt = Record<string, unknown>;

/**
 * Parse the var, fail-closed — same posture and same reasoning as
 * `parseSkillPackages`: a malformed table renders NOTHING (every id 404s)
 * rather than rendering something the operator did not author.
 */
export function parsePromptTemplates(raw: string | undefined): readonly PromptTemplate[] {
  if (raw === undefined || raw.trim() === "") return [];
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(decoded)) return [];
  const templates: PromptTemplate[] = [];
  for (const entry of decoded) {
    const parsed = promptTemplateSchema.safeParse(entry);
    if (parsed.success) templates.push(parsed.data);
  }
  return templates;
}

/**
 * `active_prompt_template_version` — the highest-revision ACTIVE version, and
 * if none is active, the highest-revision version of any status.
 *
 * The fallback is Rust's (`.or_else(|| … max_by_key(revision))`) and it is not
 * dead code: the caller then checks `version.status != Active` and answers
 * `409 prompt_template_version_inactive`. Returning the newest INACTIVE version
 * rather than `None` is what makes the refusal say "the version is inactive"
 * instead of "no such version".
 */
export function activePromptTemplateVersion(
  template: PromptTemplate,
): PromptTemplateVersion | undefined {
  const highest = (versions: readonly PromptTemplateVersion[]): PromptTemplateVersion | undefined =>
    versions.reduce<PromptTemplateVersion | undefined>(
      (best, version) => (best === undefined || version.revision > best.revision ? version : best),
      undefined,
    );
  return highest(template.versions.filter((v) => v.status === "active")) ?? highest(template.versions);
}

/** `find_prompt_template_version`: an explicit revision, else the active one. */
export function findPromptTemplateVersion(
  template: PromptTemplate,
  revision: number | null,
): PromptTemplateVersion | undefined {
  if (revision !== null) {
    return template.versions.find((version) => version.revision === revision);
  }
  return activePromptTemplateVersion(template);
}

/**
 * `prompt_template_json_value_to_string`.
 *
 * `null` becomes the EMPTY STRING, not the four characters `null` — so a client
 * that sends `{"who": null}` erases the placeholder rather than writing the word
 * "null" into the operator's prompt. Arrays and objects are re-serialized as
 * compact JSON, which is `serde_json::Value::to_string`.
 */
export function promptVariableToString(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  return JSON.stringify(value);
}

/** Raised by the renderer; the caller renders it as `400 prompt_template_render_failed`. */
export class PromptRenderError extends Error {
  override readonly name = "PromptRenderError";
}

/**
 * `prompt_template_variable_value`.
 *
 * An UNDECLARED variable is an error even when the client supplied a value:
 * the template's `variables` list is the contract, so `{{secret}}` cannot be
 * smuggled into a prompt by a client that happens to send a `secret` key.
 */
export function promptVariableValue(
  template: PromptTemplate,
  name: string,
  variables: Readonly<Record<string, unknown>>,
): string {
  const declaration = template.variables.find((variable) => variable.name === name);
  if (declaration === undefined) {
    throw new PromptRenderError(`prompt variable ${name} is not declared`);
  }
  if (Object.hasOwn(variables, name)) {
    return promptVariableToString(variables[name]);
  }
  if (declaration.default !== null) {
    return declaration.default;
  }
  if (declaration.required) {
    throw new PromptRenderError(`required prompt variable ${name} is missing`);
  }
  return "";
}

/**
 * `render_prompt_template_text` — `{{name}}` substitution, single pass.
 *
 * SINGLE PASS is the security property, not a simplification: the cursor only
 * ever moves FORWARD past a substituted value, so a variable whose value itself
 * contains `{{other}}` is emitted literally and never re-expanded. A recursive
 * renderer would let a client's variable reach a second variable's default.
 *
 * An unterminated `{{` is an error rather than a literal — Rust `bail!`s — so a
 * malformed template fails loudly instead of leaking its own source text.
 */
export function renderPromptText(
  template: PromptTemplate,
  content: string,
  variables: Readonly<Record<string, unknown>>,
): string {
  let rendered = "";
  let cursor = 0;
  for (;;) {
    const start = content.indexOf("{{", cursor);
    if (start === -1) break;
    rendered += content.slice(cursor, start);
    const end = content.indexOf("}}", start + 2);
    if (end === -1) {
      throw new PromptRenderError("unclosed prompt variable");
    }
    rendered += promptVariableValue(template, content.slice(start + 2, end).trim(), variables);
    cursor = end + 2;
  }
  return rendered + content.slice(cursor);
}

/**
 * `render_prompt_template` — the rendered request body.
 *
 * `target` decides the member name and nothing else: `chat_completions` emits
 * `messages`, `responses` emits `input`. The three sampling fields are emitted
 * ONLY when the version declares them, so an absent `temperature` stays absent
 * rather than becoming an invented default the provider would then apply.
 */
export function renderPromptTemplate(
  template: PromptTemplate,
  version: PromptTemplateVersion,
  variables: Readonly<Record<string, unknown>>,
): RenderedPrompt {
  const messages = version.messages.map((message) => ({
    role: message.role,
    content: renderPromptText(template, message.content, variables),
  }));
  const request: Record<string, unknown> = { model: template.model };
  if (template.target === "responses") {
    request["input"] = messages;
  } else {
    request["messages"] = messages;
  }
  if (version.temperature !== null) request["temperature"] = version.temperature;
  if (version.top_p !== null) request["top_p"] = version.top_p;
  if (version.max_tokens !== null) request["max_tokens"] = version.max_tokens;
  return request;
}

/**
 * `PromptTemplateRenderRequest` off the wire.
 *
 * An EMPTY body is `{ variables: {}, revision: null }`, not a 400 — Rust checks
 * `body.is_empty()` first, so `POST` with no body renders the active version
 * with defaults. Anything present but not a JSON object is
 * `400 invalid_request_body`.
 */
async function readRenderRequest(c: Context<GatewayEnv>): Promise<PromptTemplateRenderRequest> {
  const raw = await c.req.text();
  if (raw.trim() === "") {
    return { variables: {}, revision: null };
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    throw new HttpError(
      400,
      "invalid_request_body",
      "request body must be JSON with variables and optional revision",
    );
  }
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new HttpError(
      400,
      "invalid_request_body",
      "request body must be JSON with variables and optional revision",
    );
  }
  const body = decoded as Record<string, unknown>;
  const variables = body["variables"];
  const revision = body["revision"];
  if (variables !== undefined && (typeof variables !== "object" || variables === null || Array.isArray(variables))) {
    throw new HttpError(
      400,
      "invalid_request_body",
      "request body must be JSON with variables and optional revision",
    );
  }
  if (revision !== undefined && revision !== null && !Number.isInteger(revision)) {
    throw new HttpError(
      400,
      "invalid_request_body",
      "request body must be JSON with variables and optional revision",
    );
  }
  return {
    variables: (variables as Record<string, unknown> | undefined) ?? {},
    revision: typeof revision === "number" ? revision : null,
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
    const known = models
      .catalog()
      .find((route) => route.logicalModel === template.model);
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

  const version = findPromptTemplateVersion(template, request.revision);
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
