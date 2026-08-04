/**
 * `apps/agent-runtime/src/admission` — the ADMISSION half of Rust's
 * `authenticate()`, ported onto this Worker.
 *
 * ```
 *  request ─▶ contractAuth ─▶ bearerAuth ─▶ deps.admission.admit() ─▶ handler
 *                                             │                        │
 *                                             │ resolveEffectiveQuota   │
 *                                             │ monthly budget          │
 *                                             │ wallet balance + hold   │
 *                                             │ requestWindows() (RPM)  │
 *                                             ▼                        ▼
 *                                        counter / D1        grant.release()
 * ```
 *
 * ## THE DEFECT THIS CLOSES
 *
 * Rust served `/v1/agent-jobs`, `/v1/agent-runs` and `/v1/agents/**` from the
 * SAME process as `/v1/chat/completions`, through the same `authenticate()` →
 * `finalize_auth` chain. Splitting the data plane into five Workers moved only
 * the CREDENTIAL half onto this app, so a key that was rate-limited and
 * budget-exhausted on the gateway was ADMITTED here — and an agent job spends
 * real provider money. The exploit was "call the other endpoint".
 *
 * ## WHAT IS IMPORTED RATHER THAN RE-WRITTEN
 *
 *  - `@ferrogate/policy` — `resolveEffectiveQuota` (the whole multi-level merge)
 *    and the SECURITY-CRITICAL `QuotaScopeSelector.counterKey`. `./keys.ts`
 *    CALLS the latter; it does not re-derive it, so this Worker cannot drift
 *    from `apps/gateway`, which matters more here than anywhere because the two
 *    are meant to share ONE counter namespace.
 *  - `@ferrogate/storage` — `D1WalletStore.reserveWalletCredits`, the
 *    mutation-tested atomic no-oversell batch, plus `periodMonthFromUnix`,
 *    `boolFromSqlite`, `optionalNumber`, `WALLET_RESERVATION_ACTIVE`.
 *
 * What is written here is the RPM window arithmetic (`./window.ts`) and the
 * counter client (`./counter.ts`), against `apps/gateway/src/ratelimit` as the
 * reference. They are not imported from that app because agent-runtime and
 * gateway are separately bundled Workers and neither may depend on the other's
 * module graph.
 *
 * ===========================================================================
 * WIRING — what the integrate step must add. NO edit inside this directory,
 * and NO edit to `src/index.ts` or `src/worker.ts` (the ladder mounts itself
 * through `resolveDeps`, which is where every other port on this Worker is
 * chosen).
 * ===========================================================================
 *
 * **THERE IS NO NEW DURABLE OBJECT CLASS, AND THAT IS THE POINT.**
 *
 * A `RateLimiterDurableObject` defined in THIS Worker would compile, deploy,
 * and pass every test while creating a SECOND, independent counter namespace —
 * handing `/v1/agent-jobs` its own full RPM quota on top of the gateway's. That
 * is a quieter version of the very bug this module closes. The counter must be
 * the gateway's, so the binding names the gateway's SCRIPT:
 *
 * ```toml
 * # apps/agent-runtime/wrangler.toml
 * [[durable_objects.bindings]]
 * name = "RATE_LIMIT"
 * class_name = "RateLimiterDurableObject"
 * script_name = "ferrogate-gateway"
 * ```
 *
 * **No lifecycle declaration belongs in this app for it.** The class is
 * introduced by the script that defines it: `apps/gateway/wrangler.toml`
 * carries `[exports.RateLimiterDurableObject]`. Adding a second lifecycle
 * declaration here would claim to define a class this script does not
 * export, and Wrangler rejects that at deploy. Deploy `ferrogate-gateway`
 * FIRST — a `script_name` binding to a script that does not exist yet fails.
 *
 * With the binding absent, `counterFromEnv` falls back to a per-isolate
 * counter: correct arithmetic, wrong blast radius. That is deliberate (see
 * `./counter.ts`) — "no limiting at all when the binding is missing" would let
 * a misconfigured deploy serve unlimited traffic silently.
 *
 * **The other two sources need NO new binding at all.** `quotaPolicySourceFromEnv`
 * reads `CONTROL_DB` and `spendSourceFromEnv` / `walletAdmissionFromEnv` read
 * `DB` — the two databases this Worker's credential authorities already use,
 * whose (commented) `[[d1_databases]]` stanzas are already written out in
 * `wrangler.toml`. Uncommenting them at deploy time turns on the quota chain,
 * the monthly budget and the wallet in the same edit.
 *
 * **DO NOT commit those D1 stanzas at development time**, and do not add a
 * `FG_DEV_QUOTA_POLICIES` entry to `[vars]` either: `vitest.config.ts` loads
 * `wrangler.toml` through `wrangler: { configPath }`, so a committed binding is
 * injected into every unit test. That is measured, not feared — the D1 stanzas
 * turned 106 of 259 tests red on a correct tree, and a committed
 * `AGENT_UPSTREAMS = "[]"` shadowed the harness catalog and broke 14 A2A tests.
 * Both are documented in place in `wrangler.toml`. The dev quota policies are
 * seeded as a miniflare binding in `vitest.config.ts` for the same reason
 * `FG_DEV_API_KEYS` is.
 * ===========================================================================
 */
export {
  type AdmissionBindings,
  type AdmissionDeps,
  type AdmissionGrant,
  type AdmissionPort,
  type AdmissionRequest,
  ADMISSION_REFUSALS,
  admissionFromEnv,
  admissionPort,
  subjectFor,
} from "./admit.js";

export {
  type CounterBindings,
  type DoRequestResult,
  type RateLimiterNamespace,
  type RequestAdmission,
  type RequestCounter,
  DurableObjectRequestCounter,
  InMemoryRequestCounter,
  counterFromEnv,
} from "./counter.js";

export {
  type CounterWindow,
  CounterKeyNamespaceError,
  assertNamespacedCounterKey,
  counterKeyForScope,
  isNamespacedCounterKey,
  parseCounterKey,
  perKeyCounterKey,
  requestWindows,
  walletCounterKey,
} from "./keys.js";

export {
  type MonthlySpendReading,
  type QuotaBindings,
  type QuotaPolicySnapshot,
  type QuotaPolicySource,
  type QuotaResolution,
  type QuotaSubject,
  type SpendBindings,
  type SpendSource,
  type WalletBalanceReading,
  NO_QUOTA_POLICIES,
  NO_SPEND_SOURCE,
  currentPeriodMonth,
  d1QuotaPolicySource,
  d1SpendSource,
  monthlyBudgetCharges,
  monthlyBudgetScope,
  quotaPolicySourceFromEnv,
  quotaPolicySourceFromVars,
  resolveQuotaWindows,
  spendSourceFromEnv,
} from "./quota.js";

export {
  type WalletAdmission,
  type WalletAdmissionBindings,
  type WalletAdmissionOptions,
  type WalletAdmissionOutcome,
  type WalletHold,
  DEFAULT_WALLET_HOLD_CREDITS,
  NO_WALLET_ADMISSION,
  WALLET_HOLD_TTL_SECONDS,
  agentRuntimeTenantHandle,
  d1WalletAdmission,
  walletAdmissionFromEnv,
  walletHoldId,
} from "./wallet.js";

export {
  WINDOW_SECONDS,
  type WindowState,
  RequestWindow,
  emptyWindow,
  secondsUntilWindowReset,
} from "./window.js";
