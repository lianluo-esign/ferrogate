/**
 * The prompt-template MACHINERY: parse the operator table, select a version,
 * substitute variables, build the request body.
 *
 * Moved here verbatim from `routes/prompts.ts` (#694) and NOT rewritten — the
 * behaviour, the comments and the Rust provenance are unchanged, and
 * `routes/prompts.ts` re-exports every name so existing importers and tests are
 * untouched.
 *
 * The move exists because there are now TWO consumers, and they sit on opposite
 * sides of the module graph. `routes/prompts.ts` (the render endpoint) imports
 * from `../inference/*`; `inference/prompt-reference.ts` (the prompt-by-label
 * expander on the chat path) needs the same renderer. Leaving the renderer in
 * `routes/prompts.ts` would make `inference/` import `routes/` which already
 * imports `inference/` — a real cycle, which ESM tolerates right up until the
 * evaluation order changes under a bundler and a `const` is briefly undefined.
 * This module imports nothing from either side.
 */
import { type PromptTemplate, type PromptTemplateVersion, promptTemplateSchema } from "@ferrogate/config";

/** JSON array of `PromptTemplate` records — Rust `[[prompt_templates]]`. */
export const PROMPT_TEMPLATES_VAR = "GATEWAY_PROMPT_TEMPLATES";

/** Bindings this module reads on top of `GatewayBindings`. */
export interface PromptTemplateBindings {
  readonly GATEWAY_PROMPT_TEMPLATES?: string | undefined;
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
