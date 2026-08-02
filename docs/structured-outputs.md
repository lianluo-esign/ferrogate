# Structured Outputs Across Provider Families

A caller who sends `response_format` is stating an OUTPUT CONTRACT, not a
provider-specific hint. FerroGate may serve that request from any physical route
its ladder selects, so the contract has to survive a failover between provider
families. If it did not, a failover would silently change the response shape,
which is not a failover.

FerroGate therefore parses the requirement ONCE into a provider-neutral form and
re-emits it in the selected family's dialect. What a family cannot express is
REFUSED — never dropped, never approximated with a prompt instruction.

## Where the requirement is read

| Endpoint | Field |
|---|---|
| `POST /v1/chat/completions` | `response_format` |
| `POST /v1/responses` | `text.format`, falling back to `response_format` |

Both spellings collapse to the same requirement: `json_object` (any JSON) or
`json_schema` (a named JSON Schema, optionally `strict`). An explicit
`{"type":"text"}` is the absence of a requirement.

A request that names a `json_schema` without an object `schema` is rejected as
`invalid_request` by every family that has to translate it. The OpenAI-compatible
family passes its own field through untouched and lets OpenAI adjudicate it.

## What each family sends

| Family | Wire form |
|---|---|
| OpenAI-compatible (`openai`, `deepseek`, `vllm`, `grok`, `openrouter`, `azure-openai`, …) | native `response_format`, unmodified |
| Anthropic | a forced tool call: the schema becomes `tools: [{name, input_schema}]` with `tool_choice: {"type":"tool","name":…}` |
| Bedrock (Converse) | the same coercion in Converse's envelope: `toolConfig.tools[].toolSpec.inputSchema.json` + `toolConfig.toolChoice.tool` |
| Gemini / Vertex | `generationConfig.responseMimeType: "application/json"` plus `generationConfig.responseSchema` |
| Workers AI | native `response_format`, but the schema is re-emitted UNWRAPPED under `json_schema` — Workers AI's JSON Mode takes the schema itself there, where OpenAI nests `{name, schema, strict}`. Passing the caller's object through verbatim would hand the model a schema whose top level is `{name, schema, strict}`, which constrains nothing the caller asked for. |

The tool name is the schema's `name`, sanitized to `[a-zA-Z0-9_-]{1,64}`, so it
stays readable in the upstream request and in the `tool_use` block that comes
back.

### Consequence of the Anthropic/Bedrock coercion

An Anthropic-family answer to a schema request arrives as a `tool_use` content
block whose `input` is the JSON, not as message text. That is the price of a
GUARANTEE: a forced tool call is the only construct Anthropic offers that
actually constrains the output. A caller who wants the identical response
envelope across families should route structured requests at a logical model
whose routes are all one family.

While a coercion tool is forced, the caller's own tools cannot be invoked on that
turn. They remain in the request for the following turn.

## When FerroGate refuses

A refusal removes the route from the candidate ladder for THAT request. If
another eligible route can honour the contract, the request is served by it and
the refusing route is never dispatched to — no tokens are spent on an answer that
would have broken the contract. If nothing can honour it, the caller gets:

- `400 model_capability_unsupported` — no family on the ladder can express the
  requirement;
- `400 invalid_request` — the request contradicts itself.

| Case | Families | Why |
|---|---|---|
| `{"type":"json_object"}` | Anthropic, Bedrock | Neither has a schema-less JSON mode. A prompt-level "answer in JSON" is a suggestion, not a contract. Gemini CAN honour it (`responseMimeType`), and does. |
| A `response_format.type` FerroGate does not model | every translating family | An unknown contract cannot be translated, and dropping it is the defect this page exists to prevent. |
| Schema uses `$ref`, `$defs`, `definitions`, `allOf`, `oneOf`, `not`, `patternProperties`, `if`/`then`/`else`, `dependentSchemas` | Gemini, Vertex | Gemini's `responseSchema` is an OpenAPI 3.0 subset with no member for these. Erasing one INVERTS the contract — an erased `oneOf` accepts anything. |
| The coercion tool would shadow a tool the request already defines | Anthropic, Bedrock | Two different schemas would answer to one name. |
| `tool_choice` is `none`, or forces a different tool | Anthropic, Bedrock | Directly contradicts the forced coercion; resolving it either way silently discards half of what the caller asked for. |

### What Gemini translation drops, deliberately

Gemini's `Schema` rejects unknown members, so translation is an allow-list
(`type`, `format`, `title`, `description`, `nullable`, `enum`, `properties`,
`required`, `items`, `anyOf`, `minimum`, `maximum`, `minLength`, `maxLength`,
`pattern`, `propertyOrdering`, `default`, `example`, `min/maxItems`,
`min/maxProperties`). Members outside it — `$schema`, `additionalProperties`,
`exclusiveMinimum`, `multipleOf`, … — are dropped rather than refused, because
they refine VALUES and never the shape. The object graph the caller asked for is
always preserved exactly or the request is refused.

## Route eligibility

`response_format.type` of `json_object`/`json_schema` also makes the request
require the `structured_output` capability, so a route that DECLARES
capabilities without it is excluded before any of the above runs. See
[`model-route-capabilities.md`](./model-route-capabilities.md).

## Where this lives

`packages/providers/src/structured.ts` is the single implementation; the family
adapters and `CanonicalAiRequest` call it. `apps/gateway/src/inference/adapters.ts`
re-implements five families for the Worker and calls the SAME functions rather
than carrying a second copy of the translation.

Tests: `packages/providers/test/structured-outputs.test.ts` (translation and
refusal at the adapter boundary) and
`apps/gateway/test/inference/structured-outputs.test.ts` (the requirement on the
wire, and the ladder's behaviour when a family refuses).
