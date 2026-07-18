# Presidio adapter (DLP/PII) — data flow, accuracy, and known limitations

Native FerroGate guardrail adapter for a **self-hosted Microsoft Presidio
analyzer** (`POST /analyze`). This is the DLP/PII half of the two qualifying
semantic security integrations for issue #201.

> **Selection status.** Presidio was chosen as a *sensible default*: it is
> open-source, self-hostable inside the customer's own VPC (best possible data
> residency — content never reaches a third-party SaaS), and requires no
> vendor credential. The choice is **pending design-partner confirmation**;
> the adapter contract (`GuardrailDetector`) means swapping in a different
> DLP vendor is an additive change, not a rework.

## Descriptor (what the adapter honestly declares)

| Field | Value |
|---|---|
| `version` | `presidio-analyzer-adapter/1+cfg.<digest>` (adapter version + a digest of language/threshold/entities, reported on every result) |
| `supports_request` / `supports_response` | `true` / `true` |
| `supports_transform` | `true` — Presidio returns entity spans; each span on a mutable text segment yields a surgical `[REDACTED]` patch |
| `credential` | `none` (or `bearer_token` if a fronting reverse proxy is configured) |
| `data_residency` | `customer_vpc` — the analyzer runs inside the operator's network boundary |
| `max_payload_bytes` | operator-configured; oversized input is rejected as `payload_too_large` before any bytes leave the gateway |
| `declared_failure_modes` | `timeout`, `unavailable`, `invalid_response`, `overloaded`, `unauthorized`, `payload_too_large`, `invalid_configuration`, `internal` |

## Data flow — every field sent to the detector

For each in-scope content segment, the gateway POSTs one JSON document to the
configured `/analyze` endpoint (wire shape lives in
`crates/ferrogate-guardrails/src/adapters/presidio.rs::wire`):

| Field | Content | Notes |
|---|---|---|
| `text` | **The raw segment text** (user/system/assistant/tool content selected by the check's `sources`) | This is prompt/response content crossing the gateway process boundary — but only to the self-hosted analyzer inside the customer VPC. |
| `language` | Configured language hint (default `"en"`) | Static configuration, no request data. |
| `score_threshold` | Configured threshold (percent / 100) | Static configuration. |
| `entities` | Optional configured entity allow-list | Static configuration; omitted when unset. |

Nothing else is sent: **no tenant identifiers, no model/provider names, no
API-key material, no metadata** (unlike the generic `custom_http` detector,
which projects the full detector request context). Responses flow back as
entity spans + scores; the raw matched value is fingerprinted (HMAC-SHA256,
keyed by `fingerprint_secret_ref`) and **never stored in evidence** —
findings carry category, span, score, and fingerprint only.

Presidio reports **character** offsets (it is a Python service); the adapter
converts them to byte offsets and rejects out-of-range spans as
`invalid_response`.

## Configuration

Static config (`[[guardrails]]` rule):

```toml
[[guardrails]]
id = "pii-dlp"
name = "PII redaction via self-hosted Presidio"
stage = "response"
effect = "redact"
provider = "presidio"
provider_endpoint = "https://presidio.internal.example/analyze"   # customer-VPC endpoint
provider_language = "en"
provider_score_threshold_percent = 50
# provider_entities = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"]
provider_fingerprint_secret_ref = "env:GUARDRAIL_FINGERPRINT_KEY"  # required, keys evidence HMACs
# provider_secret_ref = "env:PRESIDIO_PROXY_TOKEN"                 # optional bearer for a reverse proxy
```

Dynamic guardrail policies use the equivalent
`{"kind": "presidio", ...}` detector definition. Registration is
config-gated exactly like the deterministic and `custom_http` detectors;
nothing runs unless an operator configures it. Private-network endpoints
require the explicit `provider_allow_private_network` opt-in, and only
platform operators (not tenant-scoped authors) may register the adapter,
because its fingerprint key dereferences a host secret.

## Accuracy on the bundled reference corpus (`reference/2`)

Measured by `run_detector_evaluation` over the versioned synthetic corpus,
driven through the **recorded fixture transport**
(`tests/fixtures/presidio_exchanges.json`), asserted exactly by
`adapters_test::presidio_reference_corpus_accuracy_report`:

| Metric | Value |
|---|---|
| Cases | 8 (4 malicious, 4 benign) |
| True/false positives | 1 / 0 |
| True/false negatives | 4 / 3 |
| Precision | **1.00** |
| Recall | **0.25** |
| F1 | **0.40** |
| Errors | 0 |
| Missed cases | `prompt-injection-override`, `prompt-injection-exfiltration`, `prompt-injection-roleplay` |

Latency from the runner (p50/p95/max) is sub-millisecond because the
transport replays recorded fixtures in-process; it characterizes adapter
overhead only, **not** network or model-inference latency of a real
deployment.

## Known limitations — read before trusting the numbers

- **Fixture-driven numbers are not vendor claims.** The recall/precision
  above score the *adapter pipeline* against recorded analyzer responses on a
  tiny synthetic corpus. They are not a measurement of Presidio's real-world
  PII accuracy, which depends on language, entity mix, and recognizer
  configuration. A deployment must re-run the evaluation against its live
  endpoint and its own labelled corpus.
- **The recall of 0.25 is by design**: Presidio is a PII engine and misses
  every prompt-injection case in the corpus. Pair it with the LLM-Guard
  prompt-injection adapter; neither substitutes for the other.
- **The AWS-key hit relies on a custom recognizer.** Stock Presidio ships no
  AWS-access-key recognizer; the recorded fixture reflects an analyzer with a
  custom `AwsAccessKeyRecognizer` loaded. Deployments wanting secret-shaped
  entities must configure such recognizers (FerroGate's deterministic
  detector also covers common secret patterns in-process).
- **Prompt/response content leaves the gateway process** (to the self-hosted
  analyzer). Residency is customer-VPC, but operators must still treat the
  analyzer host as being inside the sensitive-data boundary (its logs, its
  memory).
- **No adapter-local circuit breaker or retries** in v1; the policy layer's
  deadline plus the declared failure modes govern behaviour under outage.
  `on_error` policy (block/record/fallback-detector) decides fail-open vs
  fail-closed.
- **Shadow → enforce loop is implemented and fixture-tested.** The rollout —
  shadow-mode sampling, human-label comparison, promotion by scope, and
  rollback — is a deterministic decision procedure documented in
  [`../shadow-to-enforce.md`](../shadow-to-enforce.md) and exercised end-to-end
  against recorded fixtures (`adapters_test.rs`). Only running it against real
  analyzer traffic remains external (it needs a live endpoint).
