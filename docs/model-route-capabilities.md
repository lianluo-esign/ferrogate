# Physical Model Route Capabilities

FerroGate filters physical model routes before cost, latency, health, priority,
or canary ordering. Capability declarations belong to each provider/model pair,
not to the logical model as a whole. Primary, fallback, and canary routes must
therefore declare their own `capabilities` and `context_window` values.

The capability vocabulary is closed:

| Value | Request requirement |
|---|---|
| `chat` | Chat Completions, Responses, or Anthropic Messages. A completely undeclared legacy route remains eligible only for a request with no additional feature or context requirement. |
| `streaming` | The parsed request enables streaming. |
| `vision` | Chat, Responses, or Messages input contains a recognized `image`, `image_url`, or `input_image` content block. |
| `images` | The request enters `POST /v1/images/generations`. |
| `embeddings` | The request enters `POST /v1/embeddings`. |
| `tools` | The request contains non-empty `tools`, or FerroGate will inject configured gateway tools. |
| `structured_output` | `response_format.type`, or Responses `text.format.type`, is `json_object` or `json_schema`. |

Unknown values fail config parsing. An empty declaration remains compatible
only with a chat-style request that has no explicit feature or context
requirement. This exemption does not apply to a non-empty declaration: a route
declared as `embeddings` or `images` without `chat` is excluded from plain chat
traffic. Once a request requires any additional feature, an undeclared route is
excluded rather than being tried optimistically.

## Context Rule

Context filtering uses only the caller's explicit maximum output-token field:

| Endpoint | Field |
|---|---|
| Chat Completions | `max_completion_tokens`, falling back to `max_tokens` |
| Responses | `max_output_tokens` |
| Anthropic Messages | `max_tokens` |
| Embeddings and Images | none |

FerroGate does not add estimated prompt tokens. Its token estimator has
fallbacks and cannot prove exact context fit, so using it here would turn an
estimate into a hidden routing guarantee. When an explicit bound is present, a
route with no `context_window`, or one smaller than the bound, is excluded.

## Decision Evidence

Each request produces bounded request-correlated audit evidence through the
existing investigation API. `model_route.excluded` records the physical
provider/model identity and one stable outcome code:

- `missing_capability`
- `context_window_undeclared`
- `context_window_too_small`
- `region_undeclared`
- `region_not_allowed`

`model_route.selected` records the first eligible route and the ordering reason
(`priority_order`, `lowest_cost`, `lowest_latency`, `balanced`, or
`canary_bucket`). Evidence includes requirement names and numeric bounds only.
It retains the existing authenticated actor-key correlation, but never copies
prompts, tool arguments, secrets, caller-supplied client metadata, or response
bodies. At most 32 exclusion reasons are stored for one decision; a
`model_route.exclusions_truncated` event makes further omission explicit.
