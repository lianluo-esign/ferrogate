/**
 * `apps/gateway` guardrail enforcement — the request-path wiring for
 * `@ferrogate/guardrails`.
 *
 * The package owns detector EXECUTION (deterministic keyword/regex/secret/JSON
 * scanning, `custom_http` with deadlines + bulkhead + circuit breaker, Presidio,
 * LLM-Guard, Workers-AI Llama-Guard, SSRF endpoint validation). This directory
 * owns everything the Rust gateway owned on top of it: policy binding, stage
 * evaluation, aggregation, enforcement selection, evidence, and the Hono seam.
 *
 * ============================================================================
 * WIRING — exactly what the integrate step adds
 * ============================================================================
 *
 * **1. `apps/gateway/src/routes/index.ts` — one line inside `createGatewayApp`,
 * directly after the contract auth guard:**
 *
 * ```ts
 * import { guardrails } from "../guardrails/index.js";
 *
 * app.use("*", contractAuth(options.deps ?? depsFromEnv));
 * app.use("*", guardrails(options.guardrails ?? guardrailDepsFromEnv));   // ADD
 * ```
 *
 * plus the option on `CreateGatewayAppOptions`:
 *
 * ```ts
 * readonly guardrails?: GuardrailMiddlewareOptions | GuardrailDepsResolver;
 * ```
 *
 * **2. `apps/gateway/src/index.ts` — supply the model→provider resolver so
 * provider-scoped policies select correctly:**
 *
 * ```ts
 * import { guardrailDepsFromEnv } from "./guardrails/index.js";
 * import { modelsFromEnv } from "./inference/index.js";
 * import { defaultAnthropicTranslator } from "./inference/index.js";
 *
 * const { app, router } = createGatewayApp({
 *   modules: GATEWAY_ROUTE_MODULES,
 *   guardrails: (env) => ({
 *     ...guardrailDepsFromEnv(env),
 *     providerForModel: (model, e) =>
 *       modelsFromEnv(e as never).resolve(model)?.provider,
 *     translateAnthropicRequest: (body) => {
 *       const translated = defaultAnthropicTranslator.toChatCompletions(body);
 *       return translated.ok ? translated.body : undefined;
 *     },
 *   }),
 * });
 * ```
 *
 * **3. `wrangler.toml` — the policy + evidence-key vars (no new binding TYPES,
 * so no `worker.ts` change and NO Durable Object is introduced by this slice):**
 *
 * ```toml
 * [vars]
 * GATEWAY_GUARDRAIL_POLICIES = "[]"      # JSON array of PolicyRevision
 * GATEWAY_GUARDRAIL_BINDINGS = "[]"      # JSON array of { policy_id, active_revision }
 * # GUARDRAIL_EVIDENCE_HMAC_KEY is a SECRET (wrangler secret put), never a var.
 * ```
 *
 * Nothing else changes. `src/worker.ts` keeps re-exporting only the default
 * handler; this slice adds no named entry-module export and no DO class.
 *
 * ============================================================================
 * FAIL POSTURE — FAIL CLOSED (verified in the Rust)
 * ============================================================================
 *
 * A detector timeout/error yields `CheckOutcome::Error`
 * (`crates/ferrogate-gateway/src/state_quota_and_policy.rs:1373`), which
 * aggregates to `AggregateOutcome::Error` and selects the policy's `on_error`
 * actions (`:539-545`). `on_error` is compiled from `provider_on_error`, whose
 * serde default is **`Block`**:
 *
 *  - `crates/ferrogate-config/src/config/types.rs:1954-1959` — `enum
 *    GuardrailProviderErrorMode { #[default] Block, Record, FallbackDetector }`
 *  - `crates/ferrogate-config/src/config/types.rs:1938` — the
 *    `GuardrailProviderRuntimeConfig::default()` field value
 *  - `crates/ferrogate-gateway/src/state.rs:6335-6342` — `Block` ⇒
 *    `PolicyAction::block("guardrail_provider_unavailable", …)`;
 *    `Record`/`FallbackDetector` ⇒ `PolicyAction::record()`
 *
 * So an unreachable, overloaded or slow detector **denies with 403
 * `guardrail_provider_unavailable`** unless the operator explicitly wrote
 * `provider_on_error = "record"` (fail open) or configured a fallback detector.
 * `validate_policy_revision` additionally refuses an empty `on_error`, so "no
 * posture" is unrepresentable.
 *
 * Three more fail-closed branches, all ported verbatim:
 *  - `redact` with no patch, or a located finding no patch covers ⇒ `deny`
 *    `guardrail_invalid_redaction` (`state_quota_and_policy.rs:1553-1567`)
 *  - evidence not recordable ⇒ `deny` `guardrail_evidence_unavailable` (`:644-646`)
 *  - `streaming = reject_streaming` on a streaming request ⇒ `deny`
 *    `guardrail_streaming_unsupported` before dispatch (`:417-484`)
 *
 * ============================================================================
 * BLOCKED HTTP SHAPE (reproduced, not invented)
 * ============================================================================
 *
 * `write_json_error(session, StatusCode::FORBIDDEN, guardrail.code,
 * guardrail.message, request_id)` — `server/chat.rs:409-417`,
 * `server/local.rs:10196-10204`:
 *
 * ```
 * HTTP/1.1 403 Forbidden
 * content-type: application/json
 *
 * {"error":{"message":"<policy action message>","type":"ferrogate_error",
 *           "code":"<policy action code>","request_id":"fg-…"}}
 * ```
 *
 * Key order is serde declaration order and is preserved. The default code is
 * `guardrail_blocked` and the default message `request blocked by guardrail
 * policy` when the policy action names neither (`state_quota_and_policy.rs:1543-1550`).
 *
 * ============================================================================
 * EVIDENCE
 * ============================================================================
 *
 * Only sanitized rows are written: verdict/action/enforcement/stage/mode,
 * per-category finding COUNTS, detector version + config digest, latency, and a
 * keyed `hmac-sha256:<hex>` `input_fingerprint` over the envelope's segment
 * fingerprints. `Finding.matched_text` never crosses this boundary — it exists
 * only inside the in-memory decision path (`inventory-policy-core.md` appendix
 * §1/§2). `test/guardrails/evidence.test.ts` asserts that on the serialized rows.
 */
export * from "./ports.js";
export * from "./binding.js";
export * from "./d1.js";
export * from "./detectors.js";
export * from "./engine.js";
export * from "./evidence.js";
export * from "./evidence-wire.js";
export * from "./evidence-d1.js";
export * from "./evidence-sink.js";
export * from "./evidence-retention.js";
export * from "./stream.js";
export * from "./middleware.js";
export * from "./config.js";
export * from "./conversation-replay.js";
