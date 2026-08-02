/**
 * `apps/mcp` admission — the barrel, and the WIRING the integrate step owns.
 *
 * ## What is already wired, with no composition-root edit
 *
 * `src/ports.ts::resolvePorts` binds {@link admissionFromEnv} in every posture
 * where `env.DB` exists, and `src/http.ts::authenticateRequest` calls it right
 * after the credential ladder, so all five authenticated MCP surfaces are
 * gated the moment this app is deployed with the control database it already
 * binds. `src/routes/index.ts` drains the request's wallet holds in a
 * `finally`. `test/admission.test.ts` drives all of it over `SELF`.
 *
 * ## THE ONE THING THE INTEGRATE STEP MUST ADD
 *
 * A counter that is per-Worker hands each surface a full quota, which is a
 * different bug from the one this slice closes
 * (`docs/rewrite/CUTOVER-READINESS.md` finding D1: "the fix needs all three
 * Workers to share ONE counter namespace"). So this app declares NO Durable
 * Object class of its own and instead binds the namespace `apps/gateway`
 * ALREADY deploys, cross-script:
 *
 * ```toml
 * # apps/mcp/wrangler.toml — ADD (nothing else in the file changes)
 * [[durable_objects.bindings]]
 * name = "RATE_LIMIT"
 * class_name = "RateLimiterDurableObject"
 * script_name = "ferrogate-gateway"
 * ```
 *
 * * `class_name` is `apps/gateway/src/ratelimit/durable-object.ts`'s exported
 *   class, re-exported from `apps/gateway/src/worker.ts`.
 * * `script_name` is what makes the namespace SHARED rather than a second,
 *   private one. `idFromName("key:k1")` then addresses the SAME instance the
 *   gateway addresses, so a credential at 60 rpm is charged one window across
 *   `/v1/chat/completions`, `/v1/mcp` and `/v1/mcp/tool/execute`.
 * * **NO `[[migrations]]` stanza is added to `apps/mcp/wrangler.toml`.** A
 *   migration belongs to the script that DEFINES the class, and that is
 *   `apps/gateway`, whose `new_sqlite_classes = ["RateLimiterDurableObject"]`
 *   already exists. Adding a second migration here would try to re-define a
 *   class this script does not own and the deploy would fail. (If a future
 *   change ever does move the class into this app, the stanza must be
 *   `new_sqlite_classes`, never `new_classes` — the latter deploys cleanly and
 *   silently gives the key-value storage backend instead of SQLite.)
 * * No `src/worker.ts` export line is needed here for the same reason: this
 *   Worker binds the class, it does not define it.
 *
 * **Until that binding exists** `limiterForEnv` falls back to the per-isolate
 * {@link InMemoryMcpRateLimiter}: the quota chain, the monthly budget, the
 * wallet balance and the no-oversell hold are all fully enforced and durable,
 * and only the RPM window is counted per isolate (so a 60 rpm cap is 60·N
 * across N isolates). That is a real, stated degradation of ONE of the five
 * legs — and still strictly better than the current state, in which none of the
 * five is enforced at all.
 */
export {
  type CounterBindings,
  type CounterWindow,
  CounterKeyNamespaceError,
  type DoRequestResult,
  DurableObjectMcpRateLimiter,
  InMemoryMcpRateLimiter,
  type McpRateLimiter,
  type RateLimitOutcome,
  type RateLimiterNamespace,
  RequestWindow,
  WINDOW_SECONDS,
  assertNamespacedCounterKey,
  counterKeyForScope,
  inMemoryLimiter,
  isNamespacedCounterKey,
  limiterForEnv,
  parseCounterKey,
  perKeyCounterKey,
  requestWindows,
  resetInMemoryCounters,
  secondsUntilWindowReset,
} from "./counters.js";

export {
  MCP_WALLET_HOLD_CREDITS,
  MCP_WALLET_HOLD_TTL_SECONDS,
  type MonthlySpendReading,
  NO_QUOTA_POLICIES,
  NO_SPEND_SOURCE,
  type QuotaPolicySnapshot,
  type QuotaPolicySource,
  type QuotaResolution,
  type QuotaSubject,
  type SpendResolution,
  type SpendSource,
  type WalletBalanceReading,
  type WalletHold,
  type WalletReserveOutcome,
  currentPeriodMonth,
  d1QuotaPolicySource,
  d1SpendSource,
  monthlyBudgetCharges,
  monthlyBudgetScope,
  resolveQuotaWindows,
  spendSourceForTenant,
  walletHoldId,
} from "./quota.js";

export {
  ADMISSION_REFUSALS,
  ADMIT_ALL,
  type AdmissionBindings,
  type AdmissionIdentity,
  type AdmissionOutcome,
  type AdmissionPort,
  type AdmissionRefusal,
  McpAdmissionGate,
  type McpAdmissionOptions,
  admissionFromEnv,
  releaseAll,
} from "./gate.js";
