/**
 * Canonical structured-output requirement + per-family translation (issue #674).
 *
 * ## Why this module exists
 *
 * `response_format: {"type":"json_schema"}` used to reach an OpenAI-family
 * upstream only because {@link ./openai.OpenAiCompatibleAdapter} copies the
 * caller's body wholesale. Every other family rebuilds the upstream body
 * field-by-field, so the field was dropped on the floor: a failover from OpenAI
 * to Anthropic or Gemini silently changed the OUTPUT CONTRACT — the caller asked
 * for a schema and got prose. A gateway whose failover changes the response
 * shape is not a failover, so the requirement is parsed once into
 * {@link CanonicalStructuredOutput} and re-emitted in each family's dialect:
 *
 * | family                | dialect                                              |
 * |-----------------------|------------------------------------------------------|
 * | OpenAI-compatible     | native `response_format` (untouched passthrough)      |
 * | Anthropic (Messages)  | forced tool call — `tools` + `tool_choice`            |
 * | Bedrock (Converse)    | forced tool call — `toolConfig.tools`/`.toolChoice`   |
 * | Gemini / Vertex       | `generationConfig.responseMimeType` + `responseSchema`|
 * | Workers AI (#673)     | native `response_format`, schema UNWRAPPED under       |
 * |                       | `json_schema` — see `./workers_ai.ts`                  |
 *
 * ## Refuse rather than degrade
 *
 * The one thing this module must never do is accept a requirement it cannot
 * express and send the request anyway. Silently returning unconstrained text to
 * a caller who asked for a schema is the same defect, one layer down. So every
 * requirement a family cannot carry raises {@link AdapterError} — an
 * `UnsupportedCapability` when the family has no way to express it at all, an
 * `InvalidRequest` when the request itself is self-contradictory. The reliability
 * layer then treats the route as unusable for THIS request instead of degrading
 * it. `docs/structured-outputs.md` is the caller-facing statement of the same
 * table.
 */
import { AdapterError } from "./types.js";
import { asObject, asStr, getField, isArray, isObject } from "./json.js";
import type { Json, JsonObject, OwnedJsonObject } from "./json.js";

// ---------------------------------------------------------------------------
// Canonical representation
// ---------------------------------------------------------------------------

/**
 * The provider-neutral output contract a request asked for.
 *
 * `unmodeled` is deliberately a value rather than a throw at parse time: the
 * OpenAI family passes an unknown `response_format` through untouched (it is
 * OpenAI's field and OpenAI may grow new members faster than this tree), while
 * every family that has to TRANSLATE refuses it. Collapsing it to `undefined`
 * would reintroduce exactly the silent drop this module exists to remove.
 */
export type CanonicalStructuredOutput =
  | { readonly kind: "json_object" }
  | {
      readonly kind: "json_schema";
      readonly name: string;
      readonly description?: string;
      readonly schema: Json;
      /** OpenAI's `strict` flag; every translation below is strict anyway. */
      readonly strict: boolean;
    }
  | { readonly kind: "unmodeled"; readonly type: string };

/** Fallback name when the caller omitted one (OpenAI requires it; be lenient). */
const DEFAULT_SCHEMA_NAME = "structured_output";

/** `POST /v1/chat/completions` — the requirement lives in `response_format`. */
export const structuredOutputFromChatBody = (
  body: Json | undefined,
): CanonicalStructuredOutput | undefined =>
  parseStructuredOutputFormat(getField(body, "response_format"), "response_format");

/**
 * `POST /v1/responses` — the requirement lives in `text.format`, which is the
 * same object with `json_schema`'s members hoisted to the top level. A
 * chat-shaped `response_format` on this surface is accepted too: the request
 * schemas are `.passthrough()`, so callers do send it, and reading it is
 * strictly better than dropping it.
 */
export function structuredOutputFromResponsesBody(
  body: Json | undefined,
): CanonicalStructuredOutput | undefined {
  const textFormat = getField(getField(body, "text"), "format");
  if (textFormat !== undefined && textFormat !== null) {
    return parseStructuredOutputFormat(textFormat, "text.format");
  }
  return structuredOutputFromChatBody(body);
}

function parseStructuredOutputFormat(
  value: Json | undefined,
  field: string,
): CanonicalStructuredOutput | undefined {
  if (value === undefined || value === null) return undefined;
  const object = asObject(value);
  if (!object) {
    throw AdapterError.invalidRequest(`\`${field}\` must be a JSON object`);
  }
  const type = asStr(object["type"]);
  if (type === undefined) {
    throw AdapterError.invalidRequest(`\`${field}\` must carry a string \`type\``);
  }
  switch (type) {
    case "text":
      // An explicit "give me prose" is the absence of a requirement.
      return undefined;
    case "json_object":
      return { kind: "json_object" };
    case "json_schema": {
      // Chat nests the members under `json_schema`; Responses hoists them.
      const nested = asObject(object["json_schema"]) ?? object;
      const schema = nested["schema"];
      if (!isObject(schema)) {
        throw AdapterError.invalidRequest(
          `\`${field}\` of type json_schema requires an object \`schema\``,
        );
      }
      const name = asStr(nested["name"]);
      const description = asStr(nested["description"]);
      return {
        kind: "json_schema",
        name: name !== undefined && name.trim().length > 0 ? name : DEFAULT_SCHEMA_NAME,
        ...(description !== undefined ? { description } : {}),
        schema,
        strict: nested["strict"] === true,
      };
    }
    default:
      return { kind: "unmodeled", type };
  }
}

// ---------------------------------------------------------------------------
// Shared refusals
// ---------------------------------------------------------------------------

const unmodeledRefusal = (type: string, providerKind: string): AdapterError =>
  AdapterError.unsupportedCapability(
    `structured output (response_format type "${type}" cannot be translated)`,
    providerKind,
  );

/**
 * Tool names are `[a-zA-Z0-9_-]{1,64}` on both Anthropic and Bedrock, while the
 * schema name is free-form. Sanitizing keeps a caller's readable name visible in
 * the upstream request (it shows up in the response's tool-use block) without
 * letting an exotic name produce a 400 from the provider.
 */
export function coercionToolName(schemaName: string): string {
  const sanitized = schemaName.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
  return sanitized.replace(/^_+$/, "") === "" ? DEFAULT_SCHEMA_NAME : sanitized;
}

// ---------------------------------------------------------------------------
// Anthropic — tool-call coercion
// ---------------------------------------------------------------------------

/**
 * Apply the requirement to an Anthropic `/v1/messages` body, in place.
 *
 * Anthropic has no `response_format`. The documented way to force a shape is a
 * single-tool schema plus `tool_choice: {"type":"tool"}`, which makes the model
 * emit a `tool_use` block whose `input` validates against the schema. Note the
 * consequence, which is a deliberate judgement call: with a forced tool choice
 * the model cannot call the caller's OWN tools on this turn. They stay in the
 * `tools` array for the next turn, and honouring the schema is the contract the
 * caller is being promised here — but the two directly contradictory cases (a
 * name collision, or a `tool_choice` naming something else) are refused rather
 * than silently resolved in the coercion's favour.
 */
export function applyStructuredOutputToAnthropic(
  body: OwnedJsonObject,
  structured: CanonicalStructuredOutput,
  providerKind: string,
): void {
  if (structured.kind === "unmodeled") throw unmodeledRefusal(structured.type, providerKind);
  if (structured.kind === "json_object") {
    // Anthropic has no schema-less JSON mode; a "just give me JSON" instruction
    // in the prompt is a suggestion, not a contract, so it would be a degrade.
    throw AdapterError.unsupportedCapability(
      "structured output (response_format json_object has no Anthropic equivalent; send a json_schema)",
      providerKind,
    );
  }

  const name = coercionToolName(structured.name);
  const tools = isArray(body["tools"]) ? [...(body["tools"] as Json[])] : [];
  for (const tool of tools) {
    // Both spellings, because `/v1/responses` reaches this with the caller's
    // OpenAI-shaped `{"type":"function","function":{"name":…}}` tools in place.
    const toolName =
      asStr(getField(tool, "name")) ?? asStr(getField(getField(tool, "function"), "name"));
    if (toolName === name) {
      throw AdapterError.invalidRequest(
        `structured output cannot be coerced: the request already defines a tool named "${name}"`,
      );
    }
  }
  assertToolChoiceAllowsCoercion(body["tool_choice"], name);

  const coercionTool: JsonObject = { name, input_schema: structured.schema };
  if (structured.description !== undefined) coercionTool["description"] = structured.description;
  tools.push(coercionTool);
  body["tools"] = tools;
  body["tool_choice"] = { type: "tool", name };
}

/**
 * A caller `tool_choice` that names a DIFFERENT tool, or forbids tools outright,
 * cannot coexist with a forced coercion tool: one of the two would have to be
 * discarded, and discarding either is a silent contract change. `auto`/`any`
 * are strictly weaker than the coercion and are tightened rather than refused.
 */
function assertToolChoiceAllowsCoercion(choice: Json | undefined, name: string): void {
  if (choice === undefined || choice === null) return;
  const type = asStr(getField(choice, "type")) ?? asStr(choice);
  if (type === "none") {
    throw AdapterError.invalidRequest(
      "structured output cannot be coerced: `tool_choice` forbids tool use, but the schema is delivered as a forced tool call",
    );
  }
  if (type === "tool" || type === "function") {
    const chosen =
      asStr(getField(choice, "name")) ?? asStr(getField(getField(choice, "function"), "name"));
    if (chosen !== undefined && chosen !== name) {
      throw AdapterError.invalidRequest(
        `structured output cannot be coerced: \`tool_choice\` forces the tool "${chosen}", which contradicts the schema coercion tool "${name}"`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Bedrock Converse — tool-call coercion
// ---------------------------------------------------------------------------

/**
 * Apply the requirement to a Bedrock `Converse` body, in place.
 *
 * Converse is model-agnostic and has no `response_format` either; its
 * `toolConfig` is the same coercion in a different envelope
 * (`toolSpec.inputSchema.json`). Anthropic-on-Bedrock is the single most common
 * failover partner for a direct Anthropic route, so leaving this family out
 * would have preserved the bug for the pair that most needs it fixed.
 */
export function applyStructuredOutputToBedrockConverse(
  body: OwnedJsonObject,
  structured: CanonicalStructuredOutput,
  providerKind: string,
): void {
  if (structured.kind === "unmodeled") throw unmodeledRefusal(structured.type, providerKind);
  if (structured.kind === "json_object") {
    throw AdapterError.unsupportedCapability(
      "structured output (response_format json_object has no Bedrock Converse equivalent; send a json_schema)",
      providerKind,
    );
  }

  const name = coercionToolName(structured.name);
  const toolSpec: JsonObject = { name, inputSchema: { json: structured.schema } };
  if (structured.description !== undefined) toolSpec["description"] = structured.description;
  body["toolConfig"] = { tools: [{ toolSpec }], toolChoice: { tool: { name } } };
}

// ---------------------------------------------------------------------------
// Gemini / Vertex — responseSchema
// ---------------------------------------------------------------------------

/**
 * Apply the requirement to a Gemini `generationConfig`, in place.
 *
 * Gemini constrains decoding directly: `responseMimeType: "application/json"`
 * plus an OpenAPI-3.0-subset `responseSchema`. Unlike Anthropic it CAN honour a
 * schema-less JSON mode, so `json_object` is translated rather than refused.
 */
export function applyStructuredOutputToGemini(
  config: JsonObject,
  structured: CanonicalStructuredOutput,
  providerKind: string,
): void {
  if (structured.kind === "unmodeled") throw unmodeledRefusal(structured.type, providerKind);
  config["responseMimeType"] = "application/json";
  if (structured.kind === "json_object") return;
  config["responseSchema"] = geminiResponseSchema(structured.schema, providerKind);
}

/**
 * JSON Schema keywords that CHANGE WHICH SHAPES VALIDATE and that Gemini's
 * `Schema` has no member for. Dropping one of these would hand the model a
 * different contract than the caller wrote — e.g. `oneOf` erased leaves an empty
 * object schema that accepts anything — so they are refused.
 */
const GEMINI_UNSUPPORTED_KEYWORDS = [
  "$ref",
  "$defs",
  "definitions",
  "allOf",
  "oneOf",
  "not",
  "patternProperties",
  "if",
  "then",
  "else",
  "dependentSchemas",
] as const;

/**
 * Keywords Gemini's `Schema` proto accepts. The API rejects unknown members
 * outright, so translation is an allow-list: anything else is dropped. What that
 * loses is only VALUE-level refinement (`exclusiveMinimum`, `multipleOf`, …) —
 * never the shape — and `docs/structured-outputs.md` says so out loud.
 */
const GEMINI_SCHEMA_KEYWORDS = new Set([
  "type",
  "format",
  "title",
  "description",
  "nullable",
  "enum",
  "maxItems",
  "minItems",
  "properties",
  "required",
  "minProperties",
  "maxProperties",
  "minLength",
  "maxLength",
  "pattern",
  "example",
  "anyOf",
  "propertyOrdering",
  "default",
  "items",
  "minimum",
  "maximum",
]);

/** JSON Schema → Gemini `Schema`, refusing what the subset cannot express. */
export function geminiResponseSchema(schema: Json, providerKind: string): Json {
  if (isArray(schema)) return schema.map((entry) => geminiResponseSchema(entry, providerKind));
  if (!isObject(schema)) return schema;

  for (const keyword of GEMINI_UNSUPPORTED_KEYWORDS) {
    if (schema[keyword] !== undefined) {
      throw AdapterError.unsupportedCapability(
        `structured output (schema keyword \`${keyword}\` is outside Gemini's responseSchema subset)`,
        providerKind,
      );
    }
  }

  const translated: JsonObject = {};
  for (const [key, value] of Object.entries(schema)) {
    if (!GEMINI_SCHEMA_KEYWORDS.has(key)) continue;
    if (key === "properties" && isObject(value)) {
      const properties: JsonObject = {};
      for (const [property, subSchema] of Object.entries(value)) {
        properties[property] = geminiResponseSchema(subSchema, providerKind);
      }
      translated[key] = properties;
      continue;
    }
    if (key === "items" || key === "anyOf") {
      translated[key] = geminiResponseSchema(value, providerKind);
      continue;
    }
    translated[key] = value;
  }
  return translated;
}
