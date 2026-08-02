# Prompt Caching Across Provider Families

A caller who wants a prompt cached is stating an intent about MONEY and about
DATA RETENTION, not a provider-specific hint. FerroGate may serve that request
from any physical route its ladder selects, so the intent has to survive a
failover between provider families. If it did not, the same request would be
served with a ~90% prefix discount on one leg and at full price on the next,
with nothing in the response to say which one ran.

FerroGate therefore parses the intent ONCE into a provider-neutral directive and
re-emits it in the selected family's mechanism. What a family cannot express is
REFUSED — never dropped, never approximated with a different lifetime. This is
the same rule, and the same shape, as
[`structured-outputs.md`](./structured-outputs.md).

## Where the intent is read

| Endpoint | Field |
|---|---|
| `POST /v1/chat/completions` | `prompt_cache` |
| `POST /v1/responses` | `prompt_cache` |
| `POST /v1/messages` | `prompt_cache`, else a native `cache_control` marker anywhere in the body |

```json
{
  "model": "claims-assistant",
  "messages": [{"role": "system", "content": "…10k tokens of policy…"},
               {"role": "user", "content": "is claim 91 covered?"}],
  "prompt_cache": {"mode": "explicit", "ttl": "1h"}
}
```

`mode` is required. `ttl` is `"5m"` (default) or `"1h"` and is accepted only
with `mode: "explicit"` — a lifetime on a mode that promises nothing would read
as a guarantee the gateway never made, so it is rejected as `invalid_request`.

An Anthropic-native caller on `/v1/messages` does not have to change anything:
a `cache_control` marker in the request is read as `{"mode": "explicit"}` (with
its `ttl`) and carried forward. The marker's PLACEMENT is not carried — the
OpenAI grammar the ingress translates into has nowhere to hold it — so the
re-emitted breakpoint lands at the canonical boundary described below.

`/v1/messages` reads `prompt_cache` for the same reason every other ingress
does: it is served by the same route ladder, so a directive it did not read
could not be refused, and the caller would get a 200 from a route that had
quietly declined to honour it. That matters most for `off`, where a 200 means
the prompt WAS written into a provider cache the caller asked it be kept out of.

A request that carries BOTH a `prompt_cache` and native `cache_control` markers
is governed by `prompt_cache` — the stated directive is the deliberate one.
`{"mode": "off"}` therefore strips the markers rather than honouring them.

## The three modes

| Mode | Meaning | Refused by |
|---|---|---|
| `auto` | Best effort: use whatever prefix caching this family offers. No guarantee. | nobody |
| `explicit` | A contract: place a cache breakpoint at the static prefix, for `ttl`. | every family with no per-request breakpoint |
| `off` | A contract: do not write this prompt into a provider prompt cache. | every family whose caching cannot be disabled |

`off` is a retention/isolation control, not a cost knob. On the families that
can honour it, honouring it also means REMOVING any native `cache_control` the
caller left in the body — otherwise the directive would be a comment rather than
a control.

## What each family sends

| Family | Wire form |
|---|---|
| Anthropic | `cache_control: {"type":"ephemeral"}` (plus `"ttl":"1h"` when asked) on the last block of the static prefix |
| Bedrock (Converse) | a `{"cachePoint":{"type":"default"}}` block appended to the same boundary |
| OpenAI-compatible (`openai`, `deepseek`, `vllm`, `grok`, `openrouter`, `azure-openai`, …) | nothing — the family caches long prefixes automatically |
| Gemini / Vertex | nothing — implicit caching |
| Workers AI | nothing — no prompt cache exists |

The breakpoint boundary is the end of the STATIC prefix: the top-level `system`
if the body has one, else the last leading `system`-role message, else the last
tool, else the last content block of the last message. Anthropic renders its
cache prefix `tools` → `system` → `messages`, so one marker at the system
boundary covers the tools too and leaves the volatile turn — the caller's actual
question — outside the cached span.

A caller that placed its own `cache_control` markers keeps them, and no second
breakpoint is added: Anthropic allows four per request, and a caller who marked
its own boundaries has made a better-informed decision than the default.

`prompt_cache` is FerroGate's own member and never reaches a provider.

Each candidate on a failover ladder is prepared against a private copy of the
request. An Anthropic leg that is attempted and fails therefore leaves nothing
behind: the OpenAI leg that follows sends the body the caller wrote, with no
`cache_control` on it and no rewritten content blocks. Which routes were tried
is not observable in what the surviving route sends.

## When FerroGate refuses

| Directive | Refused by | Why |
|---|---|---|
| `explicit` | OpenAI-compatible, Gemini, Vertex | the family picks its own prefix and lifetime; a promised breakpoint would be a promise nobody kept |
| `explicit` | Workers AI | there is no prompt cache at all |
| `explicit` with `ttl: "1h"` | Bedrock | Converse's `cachePoint` has no selectable lifetime; serving it as ~5m would be a silent degrade |
| `off` | OpenAI-compatible, Gemini, Vertex | their prompt caching cannot be disabled per request, so answering 200 would do the opposite of what was asked |

A refusal removes the route from the candidate ladder for THAT request. If
another eligible route can honour the directive, the request is served by it and
the refusing route is never dispatched to. If nothing can honour it, the caller
gets a `model_capability_unsupported` error and no upstream call is made.

`auto` is never refused, which is what makes it the right mode for a logical
model whose routes span families with different mechanisms.

## Seeing what it cost

The cache hit/miss split is reported per request, in whichever vocabulary the
ingress speaks:

| Surface | Fields |
|---|---|
| `POST /v1/chat/completions`, `POST /v1/responses` | the upstream's own `usage.prompt_tokens_details.cached_tokens` |
| `POST /v1/messages` (buffered and streamed) | `usage.cache_read_input_tokens`, and `usage.cache_creation_input_tokens` where the upstream reports a write counter at all (Anthropic does; OpenAI's automatic caching charges nothing to populate the cache and reports none) |
| metering, usage rollups, cost records | `cached_input_tokens` / `cache_write_tokens`, priced at their own rates |

The two vocabularies disagree about the headline number: OpenAI's
`prompt_tokens` INCLUDES the cached tokens, Anthropic's `input_tokens` EXCLUDES
them. A response translated from one to the other is re-expressed in the target
family's convention rather than copied, so a client never double-counts the
prompt.

A cache WRITE is not free — a 5-minute Anthropic write bills at 1.25x the fresh
input rate — which is why it is reported as its own counter rather than folded
into the prompt total. Normalizing a caching mechanism whose tokens nobody
counted would hide the cost instead of exposing it.
