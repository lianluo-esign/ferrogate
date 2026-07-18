# LLM-Guard prompt-injection adapter — data flow, accuracy, and known limitations

Native FerroGate guardrail adapter for a **self-hosted ProtectAI LLM-Guard
API** prompt-injection scanner (`POST /analyze/prompt`). This is the
prompt-injection half of the two qualifying semantic security integrations
for issue #201.

> **Selection status.** LLM-Guard was chosen as a *sensible default*: it is
> open-source, self-hostable inside the customer's own VPC (content never
> reaches a third-party SaaS), and needs no vendor credential. The choice is
> **pending design-partner confirmation**; the `GuardrailDetector` contract
> makes swapping in a different prompt-injection vendor additive.

## Descriptor (what the adapter honestly declares)

| Field | Value |
|---|---|
| `version` | `llm-guard-prompt-injection-adapter/1+cfg.<digest>` (adapter version + threshold digest, reported on every result) |
| `supports_request` / `supports_response` | `true` / `true` |
| `supports_transform` | **`false` — detect-only.** The scanner classifies whole prompts and returns no spans, so a hit can deny or shadow-record but never surgically redact. The service's `sanitized_prompt` is deliberately ignored (vendor prompt rewriting is not span-safe). |
| `credential` | `none` (or `bearer_token` if the LLM-Guard API's token auth / a reverse proxy is configured) |
| `data_residency` | `customer_vpc` |
| `max_payload_bytes` | operator-configured; enforced before any bytes leave the gateway |
| `declared_failure_modes` | `timeout`, `unavailable`, `invalid_response`, `overloaded`, `unauthorized`, `payload_too_large`, `invalid_configuration`, `internal` |

## Data flow — every field sent to the detector

One JSON document per evaluation is POSTed to the configured
`/analyze/prompt` endpoint (wire shape lives in
`crates/ferrogate-guardrails/src/adapters/llm_guard.rs::wire`):

| Field | Content | Notes |
|---|---|---|
| `prompt` | **The in-scope segment texts, newline-joined** (selected by the check's `sources`) | Prompt/response content crossing the gateway process boundary — only to the self-hosted scanner inside the customer VPC. |

That is the entire request: **no tenant identifiers, no model/provider
names, no API keys, no metadata**. The response (`is_valid`, per-scanner risk
scores) is reduced to a verdict: `is_valid: false` from the service, or a
`PromptInjection` risk score at/above the configured local threshold, yields
a `Fail`. Evidence carries the category, the score as confidence, and an
HMAC-SHA256 fingerprint of the analyzed text (keyed by
`fingerprint_secret_ref`) — never the raw content.

## Configuration

Static config (`[[guardrails]]` rule):

```toml
[[guardrails]]
id = "prompt-injection"
name = "Prompt-injection screening via self-hosted LLM-Guard"
stage = "request"
effect = "deny"
provider = "llm_guard_prompt_injection"
provider_endpoint = "https://llm-guard.internal.example/analyze/prompt"  # customer-VPC endpoint
provider_score_threshold_percent = 50
provider_fingerprint_secret_ref = "env:GUARDRAIL_FINGERPRINT_KEY"        # required, keys evidence HMACs
# provider_secret_ref = "env:LLM_GUARD_API_TOKEN"                        # optional bearer token
```

Dynamic guardrail policies use the equivalent
`{"kind": "llm_guard_prompt_injection", ...}` detector definition.
Registration is config-gated exactly like the deterministic and
`custom_http` detectors. Private-network endpoints require the explicit
`provider_allow_private_network` opt-in, and only platform operators may
register the adapter (its fingerprint key dereferences a host secret).

## Accuracy on the bundled reference corpus (`reference/2`)

Measured by `run_detector_evaluation` over the versioned synthetic corpus,
driven through the **recorded fixture transport**
(`tests/fixtures/llm_guard_exchanges.json`), asserted exactly by
`adapters_test::llm_guard_reference_corpus_accuracy_report`:

| Metric | Value |
|---|---|
| Cases | 8 (4 malicious, 4 benign) |
| True/false positives | 3 / 1 |
| True/false negatives | 3 / 1 |
| Precision | **0.75** |
| Recall | **0.75** |
| F1 | **0.75** |
| Errors | 0 |
| Missed case | `secret-aws-key` (a leaked credential is not a prompt injection) |
| False alarm | `benign-mentions-ignore` (instruction-shaped benign text — a recorded, representative classifier false positive) |

Latency from the runner (p50/p95/max) is sub-millisecond because the
transport replays recorded fixtures in-process; a real deployment pays a
model-inference round trip per request (typically tens to hundreds of
milliseconds on CPU) — budget the policy `deadline_ms` accordingly.

## Known limitations — read before trusting the numbers

- **Fixture-driven numbers are not vendor claims.** The metrics score the
  *adapter pipeline* against recorded scanner responses on a tiny synthetic
  corpus, including one deliberately recorded false positive. They say
  nothing about LLM-Guard's true model accuracy, which varies with scanner
  version, model choice, and threshold. Re-evaluate against a live endpoint
  with a deployment-owned labelled corpus before enforcement.
- **The conformance probe verdict is scripted.** The conformance harness's
  sanitized-fail behaviour is exercised with a recorded `is_valid: false`
  reply on the credential probe; that is a contract-path fixture, not a claim
  that the PromptInjection scanner flags leaked credentials (it usually does
  not — pair with the Presidio adapter and the deterministic secret
  patterns).
- **Detect-only.** No redaction is possible; with `effect = "redact"`
  semantics a hit fails closed instead. Use `deny` or shadow mode.
- **Instruction-shaped benign text will false-alarm** (see the recorded
  `benign-mentions-ignore` case). Start in shadow mode and tune the
  threshold on real traffic before enforcing.
- **Prompt content leaves the gateway process** to the self-hosted scanner;
  treat that host as inside the sensitive-data boundary.
- **No adapter-local circuit breaker or retries** in v1; policy `on_error`
  decides fail-open vs fail-closed.
- **Shadow → enforce loop is implemented and fixture-tested.** The
  shadow-sampling → human-label comparison → scoped promotion → rollback
  workflow is a deterministic decision procedure documented in
  [`../shadow-to-enforce.md`](../shadow-to-enforce.md) and exercised end-to-end
  against recorded fixtures (`adapters_test.rs`). Only running it against real
  scanner traffic remains external (it needs a live endpoint).
