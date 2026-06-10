# Agent Framework Compatibility

FerroGate is compatible with agent frameworks that can call an
OpenAI-compatible API endpoint. The gateway is not an agent runtime here: the
framework owns planning, memory, and tool loops; FerroGate owns auth, routing,
provider dispatch, policy, request evidence, token accounting, and metrics.

Use this page as the support contract for framework traffic through:

- `GET /v1/models`
- `POST /v1/chat/completions`
- `POST /v1/responses`

## Shared Wiring

All supported clients use the same three values:

```text
base_url = http://127.0.0.1:8080/v1
api_key  = <FerroGate virtual API key>
model    = <FerroGate logical model name>
```

The virtual API key must include the required scope for the route:

- `models.read` for model listing
- `chat.completions` for Chat Completions
- `responses.create` for Responses API

FerroGate rewrites the logical model to the configured provider model before
provider dispatch. Provider keys stay server-side and are never exposed to the
framework process.

## Compatibility Matrix

| Framework/client | Chat completions | Streaming | Tool/function calls | Minimal wiring |
| --- | --- | --- | --- | --- |
| AutoGen | Supported through OpenAI-compatible client configuration | Supported when the AutoGen client uses Chat Completions streaming | Partial: framework-side tool loops work; provider tool schema passthrough is blocked by #9/#17 | Set `base_url`, virtual API key, logical model |
| CrewAI | Supported through OpenAI-compatible provider settings | Supported when CrewAI delegates streaming to the configured OpenAI-compatible client | Partial: framework-side tools work; gateway-mediated provider tool calls are blocked by #9/#17 | Set OpenAI-compatible endpoint, virtual API key, logical model |
| LangChain | Supported through `ChatOpenAI` or equivalent OpenAI-compatible client | Supported for Chat Completions streaming | Partial: LangChain tool orchestration works outside the gateway; provider tool schema passthrough is blocked by #9/#17 | Set `base_url`, virtual API key, logical model |
| LlamaIndex | Supported through OpenAI-compatible LLM configuration | Supported when using the streaming Chat Completions path | Partial: framework-side tools work; provider tool schema passthrough is blocked by #9/#17 | Set OpenAI-compatible endpoint, virtual API key, logical model |
| Phidata | Supported through OpenAI-compatible model configuration | Supported when the framework uses streaming Chat Completions | Partial: framework-side tools work; provider tool schema passthrough is blocked by #9/#17 | Set OpenAI-compatible endpoint, virtual API key, logical model |
| Control Flow | Supported through OpenAI-compatible client settings | Supported when the client streams Chat Completions | Partial: framework-side task tools work; provider tool schema passthrough is blocked by #9/#17 | Set OpenAI-compatible endpoint, virtual API key, logical model |
| Custom OpenAI SDK clients | Supported | Supported for Chat Completions SSE and Responses passthrough | Partial: use provider-native body fields only where the adapter preserves them; canonical tool/multimodal support is tracked in #9/#17 | Set `base_url`, virtual API key, logical model |

## Minimal Examples

The examples below intentionally avoid framework-specific dependencies in the
FerroGate workspace. They show the client-side shape each framework must
produce: an OpenAI-compatible request to FerroGate, authenticated with a
FerroGate virtual API key and using a FerroGate logical model.

### OpenAI Python SDK

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="fg_virtual_key",
)

response = client.chat.completions.create(
    model="agent-chat",
    messages=[{"role": "user", "content": "hello"}],
)
print(response.choices[0].message.content)
```

### LangChain

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="fg_virtual_key",
    model="agent-chat",
)

print(llm.invoke("hello").content)
```

### LlamaIndex

```python
from llama_index.llms.openai import OpenAI

llm = OpenAI(
    api_base="http://127.0.0.1:8080/v1",
    api_key="fg_virtual_key",
    model="agent-chat",
)

print(llm.complete("hello"))
```

### AutoGen

```python
llm_config = {
    "config_list": [
        {
            "base_url": "http://127.0.0.1:8080/v1",
            "api_key": "fg_virtual_key",
            "model": "agent-chat",
        }
    ]
}
```

### CrewAI

```python
from crewai import LLM

llm = LLM(
    model="openai/agent-chat",
    base_url="http://127.0.0.1:8080/v1",
    api_key="fg_virtual_key",
)
```

### Phidata

```python
from phi.model.openai import OpenAIChat

model = OpenAIChat(
    id="agent-chat",
    base_url="http://127.0.0.1:8080/v1",
    api_key="fg_virtual_key",
)
```

### Control Flow

```python
import controlflow as cf
from langchain_openai import ChatOpenAI

cf.defaults.model = ChatOpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="fg_virtual_key",
    model="agent-chat",
)
```

### cURL Baseline

```bash
curl -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H 'Authorization: Bearer fg_virtual_key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"agent-chat","messages":[{"role":"user","content":"hello"}]}'
```

## Streaming

Framework streaming works when the client sends a Chat Completions request with
`"stream": true`. FerroGate forwards provider SSE chunks and returns standard
response headers including `x-request-id`, `x-trace-id`, and
`x-ferrogate-runtime`.

Responses API streaming is currently provider passthrough. Normalized Responses
events across providers are tracked separately in #10.

## Tool And Function Calls

Framework-side tools are usable because the framework can decide to run tools
locally and send ordinary model requests through FerroGate between tool turns.

Gateway-mediated provider tool/function-call normalization is not certified by
this compatibility slice. The missing pieces are tracked in:

- #9 for canonical tool and multimodal request modeling
- #17 for MCP gateway and tool access governance

Until those land, do not claim provider-agnostic tool-call portability across
OpenAI-compatible, Anthropic, Gemini, and other adapters.

## Observability Evidence

After a framework request, operators can inspect:

- `/admin/v1/request-logs` for request ID, trace ID, tenant context, route,
  logical model, provider, provider model, status, and cache status.
- `/admin/v1/metering-events` for token usage and tenant/model/provider
  settlement evidence.
- `/admin/v1/usage-aggregates` for aggregated tenant/model/provider totals.
- `/metrics` for Prometheus counters such as
  `ferrogate_model_provider_requests_total` and
  `ferrogate_model_provider_tokens_total`.

The automated smoke test
`openai_compatible_client_shape_preserves_framework_traffic_evidence` verifies
that a standard SDK-shaped Chat Completions request reaches the provider path,
uses the configured provider model, returns request/trace headers, and records
request-log plus Prometheus model/provider evidence without leaking client or
provider secrets.

