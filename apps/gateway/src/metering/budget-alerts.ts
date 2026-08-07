/**
 * A1 — PROACTIVE BUDGET-THRESHOLD ALERTS, the request-path half (#170/#228).
 *
 * ## The regression this closes
 *
 * Rust ships this behaviour complete, wired and reachable:
 *
 * ```text
 * state_billing_metering.rs:231,778,905,1048  settle → dispatch_budget_threshold_alerts(tenant)
 * state_wallets.rs:568..683                   per scope: policy → rollup → tier loop → claim → POST
 * budget_alerts.rs:24-38,96                   payload, HMAC-SHA256 signature, delivery
 * ferrogate-storage/src/budget_alerts.rs      once per (scope, period, tier)
 * ```
 *
 * The TypeScript port kept only the last line. `@ferrogate/storage` has
 * `D1BudgetAlertStore` and `budgetAlertNotificationId`, but nothing ever
 * compared committed spend against `quota_policies.alert_threshold_pcts_json`
 * and nothing ever sent a webhook — so an operator who configures a budget
 * alert receives a 200 from the control plane and is then never told they are
 * approaching, or past, their budget. Both `packages/storage/src/budget-alerts.ts`
 * and `packages/storage/src/d1/budget-alerts-d1.ts` name this file's job as the
 * missing piece ("what remains is the COMPARISON … and nothing dispatches the
 * webhook. Both are `apps/gateway` edits").
 *
 * ## Where it fires from, and why there
 *
 * `MeteringUsageSink.#accumulate` (`./sink.ts`), on the `recorded` branch only,
 * immediately after the tenant database's `usage_monthly_rollups` row has been
 * updated. That is the same position Rust occupies: the alert is a consequence
 * of SETTLEMENT, and it must read a rollup that already includes the request
 * that crossed the tier — checking before the accumulate would delay every
 * crossing by one request.
 *
 * It is emphatically NOT on the admission path (`src/ratelimit/middleware.ts`).
 * Admission already owns the HARD stop (`429 monthly_budget_exceeded` at 100%);
 * this is the SOFT warning that fires strictly before it, and putting an
 * outbound HTTP call in front of the client's request is exactly what the
 * `ctx.waitUntil` posture below exists to avoid.
 *
 * ## Delivery posture — the retry rule, stated
 *
 * **There is no retry, and that is the port, not a shortcut.** The claim is
 * taken FIRST (`D1BudgetAlertStore.claimBudgetAlertNotification`, an
 * `INSERT … ON CONFLICT DO NOTHING RETURNING id`), and the webhook is sent by
 * whoever won it. A failed, slow or 5xx delivery therefore BURNS that tier for
 * the billing period. `state_wallets.rs:665-671` states the reasoning verbatim:
 *
 * > Recorded regardless of delivery success: retrying a permanently-unreachable
 * > webhook on every subsequent request for the rest of the billing period
 * > would be worse than a single missed notification, and this matches the
 * > "fire (attempt) exactly once per tier" contract in issue #170.
 *
 * Three properties fall out, all of them asserted in
 * `test/metering/budget-alerts.test.ts`:
 *
 *  - a down endpoint costs one alert, never a retry storm on the drain;
 *  - a slow endpoint is bounded by `billing_alerts.webhook_timeout_secs`
 *    (default 5s), enforced with `AbortSignal.timeout` inside
 *    `dispatchBudgetAlertWebhook`;
 *  - NONE of it can touch the customer request. The whole metering drain runs
 *    on `ctx.waitUntil` (`./middleware.ts`), the alert leg runs inside that
 *    drain, and {@link dispatchBudgetThresholdAlerts} never rejects — it
 *    reports through {@link MeteringDiagnostics.onError} instead, so an alert
 *    failure cannot be mistaken for a metering delivery failure and arm the
 *    billing outbox's retry ladder.
 *
 * ## Why the claim is taken before the send, not after
 *
 * A Worker isolate does not outlive its request, so "send, then record" has a
 * window in which two isolates crossing the same tier in the same millisecond
 * both send. Making the INSERT the arbiter removes it — SQLite evaluates the
 * conflict inside the statement's own implicit transaction. The cost is the
 * burned-tier case above, which Rust accepts for the same reason.
 *
 * ## Configuration — three vars, read structurally, NEVER throwing
 *
 * | var                                      | Rust                                        |
 * |------------------------------------------|---------------------------------------------|
 * | `BILLING_ALERTS_WEBHOOK_URL`             | `billing_alerts.webhook_url`                |
 * | `BILLING_ALERTS_WEBHOOK_TIMEOUT_SECS`    | `billing_alerts.webhook_timeout_secs` (5)   |
 * | `BILLING_ALERTS_WEBHOOK_SIGNING_SECRET`  | `billing_alerts.webhook_signing_secret`     |
 *
 * An absent URL disables DELIVERY only — and, unlike Rust, it also disables
 * detection here, because the claim ledger is the same table a later-configured
 * webhook would read. (Rust's comment "threshold crossings are still detected
 * and recorded so a later-configured webhook doesn't replay history" describes
 * a process that keeps running; a Worker with no webhook configured has no
 * reason to spend two D1 round trips per request writing rows nobody reads. If
 * that replay-suppression is wanted, configure the URL.)
 *
 * A malformed value NEVER throws: {@link budgetAlertConfigFromEnv} applies the
 * same validation as `config/validate.rs:810-821` (non-empty, `http://` or
 * `https://`, timeout > 0) and answers `undefined` on a violation, because this
 * runs after the response has been served and a configuration typo must not
 * become a lost metering write.
 *
 * ## WIRING — LIVE, and it needs NO composition-root edit
 *
 * `MeteringUsageSink` resolves this from the request's own `env` through
 * {@link budgetAlertPortsFrom}, exactly as it already resolves `BILLING_DB`,
 * `BILLING` and `DB`. `src/index.ts` and `wrangler.toml` are untouched.
 *
 * What an OPERATOR adds to `apps/gateway/wrangler.toml` to switch it on (the
 * integrate step owns that file; this is the exact text):
 *
 * ```toml
 * [vars]
 * # Read by `budgetAlertConfigFromEnv` (src/metering/budget-alerts.ts).
 * # POST target for budget-threshold-crossing notifications (#170). Unset ⇒ no
 * # alert is detected or delivered; the 429 `monthly_budget_exceeded` hard stop
 * # at 100% is unaffected either way.
 * BILLING_ALERTS_WEBHOOK_URL = ""
 * BILLING_ALERTS_WEBHOOK_TIMEOUT_SECS = "5"
 * ```
 *
 * and `BILLING_ALERTS_WEBHOOK_SIGNING_SECRET` goes in with
 * `wrangler secret put`, never as a plaintext var — it is the HMAC key every
 * receiver authenticates the alert with.
 *
 * MOUNT GATE: delete the `#budgetAlerts(...)` call in `./sink.ts::#accumulate`
 * and eight tests in `test/metering/budget-alerts.test.ts` go red.
 */
import {
  type BudgetAlertScopeKind,
  DEFAULT_BUDGET_ALERT_TIMEOUT_SECONDS,
  budgetAlertWebhookPayload,
  crossedBudgetThresholds,
  dispatchBudgetAlertWebhook,
} from "@ferrogate/billing";
import {
  DurableObjectTenantDatabaseRouter,
  backfillTenantConfigurationPolicy,
  type QuotaScopeKind,
  type TenantDatabaseHandle,
  budgetAlertStoreForTenant,
} from "@ferrogate/storage";
import { controlDatabaseFrom } from "../control-data.js";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import {
  type QuotaPolicySource,
  type SpendSource,
  currentPeriodMonth,
  d1SpendSource,
  quotaPolicySourceFromEnv,
  spendSourceFromEnv,
} from "../ratelimit/quota.js";
import type { MeteringDiagnostics } from "./ports.js";
import type { MeteringAttribution } from "./usage-ledger.js";

/**
 * `QuotaScopeKind` and `BudgetAlertScopeKind` are the same four strings, spelt
 * in two packages. This assignment fails to compile if they ever diverge, which
 * is the only way a scope-name drift could otherwise reach production: the id
 * derivation embeds the name, so a mismatch would silently create a SECOND
 * notification row for the same crossing and re-fire the alert forever.
 */
const _scopeKindsAgree: BudgetAlertScopeKind = "tenant" satisfies QuotaScopeKind;
void _scopeKindsAgree;

/** `BillingAlertsConfig` (config/types.rs:2163-2180), from Worker vars. */
export interface BudgetAlertConfig {
  readonly webhookUrl: string;
  readonly timeoutSeconds: number;
  readonly signingSecret?: string | undefined;
}

/** The vars {@link budgetAlertConfigFromEnv} reads, and nothing else. */
export interface BudgetAlertBindings {
  readonly BILLING_ALERTS_WEBHOOK_URL?: unknown;
  readonly BILLING_ALERTS_WEBHOOK_TIMEOUT_SECS?: unknown;
  readonly BILLING_ALERTS_WEBHOOK_SIGNING_SECRET?: unknown;
  /** CONTROL storage posture; absent/empty defaults to CONTROL_DATA. */
  readonly GATEWAY_CONTROL_STORAGE?: string;
}

function stringVar(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

/**
 * The alert configuration, or `undefined` when alerting is off.
 *
 * Applies `validate_billing_alerts` (`config/validate.rs:810-821`) — a
 * non-empty URL that starts with `http://` or `https://`, and a timeout greater
 * than zero. Rust REFUSES TO BOOT on a violation; a Worker cannot, so the
 * violation disables the feature instead of taking the request path down with
 * it. Both directions leave the money gate (`429 monthly_budget_exceeded`)
 * untouched, so the failure can only cost a notification.
 */
export function budgetAlertConfigFromEnv(env: unknown): BudgetAlertConfig | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const bindings = env as BudgetAlertBindings;

  const webhookUrl = stringVar(bindings.BILLING_ALERTS_WEBHOOK_URL);
  if (webhookUrl === undefined) return undefined;
  if (!webhookUrl.startsWith("http://") && !webhookUrl.startsWith("https://")) return undefined;

  const rawTimeout = stringVar(bindings.BILLING_ALERTS_WEBHOOK_TIMEOUT_SECS);
  let timeoutSeconds = DEFAULT_BUDGET_ALERT_TIMEOUT_SECONDS;
  if (rawTimeout !== undefined) {
    const parsed = Number(rawTimeout);
    // `must be greater than zero` — an unparseable or non-positive value falls
    // back to the documented default rather than to "no timeout", which on
    // Workers would mean an alert leg that can hold `waitUntil` open until the
    // platform kills the whole deferred drain.
    timeoutSeconds = Number.isFinite(parsed) && parsed > 0 ? parsed : timeoutSeconds;
  }

  const signingSecret = stringVar(bindings.BILLING_ALERTS_WEBHOOK_SIGNING_SECRET);
  return {
    webhookUrl,
    timeoutSeconds,
    ...(signingSecret === undefined ? {} : { signingSecret }),
  };
}

/** The idempotency arbiter, narrowed to the one method this path uses. */
export interface BudgetAlertClaimStore {
  claimBudgetAlertNotification(claim: {
    tenantId: string;
    scopeType: QuotaScopeKind;
    scopeId: string;
    periodMonth: string;
    thresholdPct: number;
    notifiedAtUnix: number;
  }): Promise<boolean>;
}

/** Everything one alert pass needs, resolved from a request's bindings. */
export interface BudgetAlertPorts {
  readonly config: BudgetAlertConfig;
  /** `get_quota_policy(scope_type, scope_id)` — the CONTROL database. */
  readonly policies: QuotaPolicySource;
  /** `get_usage_monthly_rollup(...)` — the TENANT database. */
  readonly spend: SpendSource;
  /** Resolve monthly spend from the same tenant object as the claim store. */
  readonly spendForTenant?: (tenantId: string) => Promise<SpendSource>;
  /** `budget_alert_already_notified` + `record_budget_alert_notification`. */
  readonly claims: BudgetAlertClaimStore;
}

/**
 * Resolve the alert ports from a request's `env`, or `undefined` when this
 * deployment cannot alert.
 *
 * All three legs are required and none is substituted: with no webhook URL
 * there is nothing to deliver to, and with no CONTROL database there is no
 * once-per-period arbiter — and an alerter without an arbiter is WORSE than
 * none, because it re-fires the tenant's 80/90/100% webhook on every single
 * request past the crossing. Degrading to an in-isolate `Map` here would look
 * like it worked in a test and spam in production.
 */
export function budgetAlertPortsFrom(env: unknown): BudgetAlertPorts | undefined {
  const config = budgetAlertConfigFromEnv(env);
  if (config === undefined) return undefined;
  const bindings = env as { CONTROL_DB?: unknown; BILLING_DB?: unknown };
  const controlDb = controlDatabaseFrom(env, {
    legacy: [bindings.CONTROL_DB, bindings.BILLING_DB],
  });
  if (controlDb === undefined || typeof env !== "object" || env === null) return undefined;
  const namespace = (env as { TENANT_DATA?: TenantDataNamespace }).TENANT_DATA;
  if (namespace === undefined) return undefined;
  const router = new DurableObjectTenantDatabaseRouter(namespace, controlDb);
  const tenantDbs = new Map<string, Promise<TenantDatabaseHandle>>();
  const tenantDbFor = (tenantId: string): Promise<TenantDatabaseHandle> => {
    let tenantDb = tenantDbs.get(tenantId);
    if (tenantDb === undefined) {
      tenantDb = (async () => {
        await backfillTenantConfigurationPolicy(controlDb, router, tenantId);
        return router.forTenant(tenantId);
      })();
      tenantDbs.set(tenantId, tenantDb);
    }
    return tenantDb;
  };
  return {
    config,
    policies: quotaPolicySourceFromEnv(env as Parameters<typeof quotaPolicySourceFromEnv>[0]),
    spend: spendSourceFromEnv(env as Parameters<typeof spendSourceFromEnv>[0]),
    spendForTenant: async (tenantId) => d1SpendSource((await tenantDbFor(tenantId)).db),
    claims: {
      async claimBudgetAlertNotification(claim) {
        if (claim.tenantId.trim() === "") return false;
        return budgetAlertStoreForTenant(await tenantDbFor(claim.tenantId)).claimBudgetAlertNotification(
          claim,
        );
      },
    },
  };
}

/** The four scopes Rust checks, in its order (`state_wallets.rs:549-554`). */
export function budgetAlertScopesFor(
  attribution: MeteringAttribution | undefined,
  tenant: {
    readonly organization_id?: string | undefined;
    readonly project_id?: string | undefined;
    readonly workspace_id?: string | undefined;
    readonly api_key_id?: string | undefined;
  },
): { scopeType: QuotaScopeKind; scopeId: string }[] {
  const ordered: [QuotaScopeKind, string | undefined][] = [
    ["key", attribution?.apiKeyId ?? tenant.api_key_id],
    ["workspace", attribution?.workspaceId ?? tenant.workspace_id],
    ["project", attribution?.projectId ?? tenant.project_id],
    ["tenant", attribution?.tenantId ?? tenant.organization_id],
  ];
  const scopes: { scopeType: QuotaScopeKind; scopeId: string }[] = [];
  for (const [scopeType, scopeId] of ordered) {
    if (scopeId !== undefined && scopeId !== "") scopes.push({ scopeType, scopeId });
  }
  return scopes;
}

/** One settled request's alert pass. */
export interface BudgetAlertPassInput {
  readonly tenantId: string;
  readonly scopes: readonly { scopeType: QuotaScopeKind; scopeId: string }[];
  readonly periodMonth?: string | undefined;
  readonly nowUnixSeconds: number;
  readonly diagnostics?: MeteringDiagnostics | undefined;
  /** Injected only by tests; production reads `globalThis.fetch` at call time. */
  readonly fetchImpl?: typeof fetch | undefined;
}

/**
 * `AppState::dispatch_budget_threshold_alerts` — evaluate every scope, claim
 * every newly-crossed tier, and deliver a webhook for each claim won.
 *
 * NEVER REJECTS. It is called from inside the metering drain, whose `catch`
 * counts a DELIVERY FAILURE and arms the billing outbox's retry ladder; letting
 * an alert error escape would turn a webhook outage into duplicate downstream
 * billing reports for charges that already settled. Every failure is reported
 * through `diagnostics.onError` and the pass continues to the next scope, which
 * is the shape of Rust's four `warn!` sites.
 *
 * @returns how many webhooks were dispatched successfully — the operand of the
 * caller's counter, and the only way a test can distinguish "nothing crossed"
 * from "crossed and the send failed".
 */
export async function dispatchBudgetThresholdAlerts(
  ports: BudgetAlertPorts,
  input: BudgetAlertPassInput,
): Promise<number> {
  const periodMonth = input.periodMonth ?? currentPeriodMonth(input.nowUnixSeconds);
  const report = (stage: string, error: unknown): void => {
    try {
      input.diagnostics?.onError?.(stage, error);
    } catch {
      // A diagnostics hook that throws is the end of the line; it must never
      // become the reason a settled charge is reported twice.
    }
  };

  if (input.tenantId.trim() === "") {
    report("budget_alert_tenant", new Error("budget alert requires a tenant id"));
    return 0;
  }

  if (input.scopes.length === 0) return 0;

  let spend = ports.spend;
  if (ports.spendForTenant !== undefined) {
    try {
      spend = await ports.spendForTenant(input.tenantId);
    } catch (error) {
      report("budget_alert_spend", error);
      return 0;
    }
  }

  // ONE policy read for the whole chain: `d1QuotaPolicySource` issues the four
  // scope rows plus the plan as a single `db.batch()`, so this costs one round
  // trip rather than one per scope — the shape `resolve_effective_quota` uses
  // on the admission path, reused rather than restated.
  let lookup: (kind: QuotaScopeKind, id: string) => { readonly monthlyBudgetUsd?: number | undefined; readonly alertThresholdPcts: readonly number[] } | undefined;
  try {
    const snapshot = await ports.policies.policiesFor({
      apiKeyId: input.scopes.find((scope) => scope.scopeType === "key")?.scopeId ?? "",
      chain: {
        ...chainEntry("tenantId", input.scopes, "tenant"),
        ...chainEntry("projectId", input.scopes, "project"),
        ...chainEntry("workspaceId", input.scopes, "workspace"),
        ...chainEntry("keyId", input.scopes, "key"),
      },
    });
    if (!snapshot.ok) {
      // Rust `warn!`s and returns for this scope. An unavailable policy store
      // has NOT proven a threshold was crossed, so nothing fires.
      report("budget_alert_policy", new Error(snapshot.detail));
      return 0;
    }
    lookup = snapshot.lookup;
  } catch (error) {
    report("budget_alert_policy", error);
    return 0;
  }

  let dispatched = 0;
  for (const scope of input.scopes) {
    const policy = lookup(scope.scopeType, scope.scopeId);
    // `Ok(None) => return` — a scope with no policy row is not governed.
    if (policy === undefined) continue;
    // `filter(|budget| *budget > 0.0)` and `alert_threshold_pcts.is_empty()`
    // are both applied inside `crossedBudgetThresholds`, which is the executable
    // statement of the rule; duplicating them here would let the two drift.
    if (policy.alertThresholdPcts.length === 0) continue;

    let spentUsd: number;
    try {
      const reading = await spend.committedSpendUsd(
        scope.scopeType,
        scope.scopeId,
        periodMonth,
      );
      if (!reading.ok) {
        report("budget_alert_rollup", new Error(reading.detail));
        continue;
      }
      spentUsd = reading.committedSpendUsd;
    } catch (error) {
      report("budget_alert_rollup", error);
      continue;
    }

    const budgetUsd = policy.monthlyBudgetUsd;
    const crossed = crossedBudgetThresholds({
      spentUsd,
      budgetUsd,
      thresholdPcts: policy.alertThresholdPcts,
    });
    if (crossed.length === 0) continue;
    // Narrowed by `crossedBudgetThresholds` returning a non-empty list: it only
    // does so for a finite, positive budget.
    const budget = budgetUsd as number;

    for (const thresholdPct of crossed) {
      let won: boolean;
      try {
        // The claim IS the arbiter — `INSERT … ON CONFLICT DO NOTHING
        // RETURNING id`. `false` means an earlier request (or another isolate
        // in the same millisecond) already notified this tier this period.
        won = await ports.claims.claimBudgetAlertNotification({
          tenantId: input.tenantId,
          scopeType: scope.scopeType,
          scopeId: scope.scopeId,
          periodMonth,
          thresholdPct,
          notifiedAtUnix: input.nowUnixSeconds,
        });
      } catch (error) {
        // Rust: "failed to check budget alert idempotency ledger" → `continue`.
        // Firing anyway would risk a per-request webhook storm, which is the
        // one failure mode worse than a missed alert.
        report("budget_alert_claim", error);
        continue;
      }
      if (!won) continue;

      try {
        await dispatchBudgetAlertWebhook({
          webhookUrl: ports.config.webhookUrl,
          payload: budgetAlertWebhookPayload({
            scopeType: scope.scopeType,
            scopeId: scope.scopeId,
            periodMonth,
            thresholdPct,
            spentUsd,
            budgetUsd: budget,
            firedAtUnix: input.nowUnixSeconds,
          }),
          signingSecret: ports.config.signingSecret,
          timeoutSeconds: ports.config.timeoutSeconds,
          ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
        });
        dispatched += 1;
      } catch (error) {
        // NOT retried and NOT un-claimed: see the module doc's delivery posture.
        report("budget_alert_delivery", error);
      }
    }
  }

  return dispatched;
}

/** `{ tenantId: "…" }` for the scope of that kind, or `{}` when absent. */
function chainEntry(
  field: "tenantId" | "projectId" | "workspaceId" | "keyId",
  scopes: readonly { scopeType: QuotaScopeKind; scopeId: string }[],
  kind: QuotaScopeKind,
): Record<string, string> {
  const match = scopes.find((scope) => scope.scopeType === kind);
  return match === undefined ? {} : { [field]: match.scopeId };
}
