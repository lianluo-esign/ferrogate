/**
 * ALERT DELIVERY (#697) — the payload, the signature and the posture.
 *
 * ## Alerting is a side effect with a cost
 *
 * Every property below exists because an alert an operator learns to ignore is
 * worse than no alert: it converts a real signal into noise, and it does so
 * permanently, because nobody un-mutes a channel.
 *
 * | property | decision | why |
 * |---|---|---|
 * | transport | signed webhook POST | the mechanism this product already has for money events (#170), so an operator wires ONE receiver rather than two |
 * | authentication | HMAC-SHA256, the same scheme and the same headers as the budget alert | a second signature scheme is a second thing to get wrong, and a receiver that has to verify two is one that verifies neither |
 * | retry | NONE | see below |
 * | dedup | the episode ledger, not the sender | see `./pass.ts` |
 * | failure | reported, never thrown | a webhook outage must not stop the audit anchor and the SIEM pump that share this tick |
 *
 * ## No retry, and this one is NOT the budget alerter's argument
 *
 * `apps/gateway/src/metering/budget-alerts.ts` does not retry because it fires
 * from the request path and a retry there is a per-request storm. This fires
 * from a cron tick, so a retry would be cheap — and it still does not retry,
 * for a different reason: **the next window is the retry.** A burn-rate episode
 * that is real is still real in an hour, and the pass will notify again when
 * the cooldown elapses. Retrying inside one tick would buy minutes of latency
 * on an hour-scale signal at the cost of an unbounded outbound leg on a handler
 * the platform will kill.
 *
 * What IS lost is the first notification of a short episode when the receiver
 * happens to be down. That is stated rather than papered over, and the episode
 * row survives regardless — `GET /admin/v1/spend-anomalies` shows it with
 * `notified_count = 0`, which is how an operator finds the alerts their
 * receiver dropped.
 *
 * ## Detection does NOT require a configured webhook
 *
 * The opposite of the gateway's budget alerter, deliberately. There, an absent
 * URL disables detection too, because detecting would cost two D1 round trips
 * on every request for a row nobody reads. Here the pass is two fleet-wide
 * aggregates on a cron tick whether or not anything is delivered, and the
 * episode ledger is itself the product — an operator who has not wired a
 * receiver yet still gets the history, and gets it for the period BEFORE they
 * wired one, which is when they most need it.
 */
import {
  BUDGET_ALERT_SIGNATURE_HEADER,
  BUDGET_ALERT_TIMESTAMP_HEADER,
  DEFAULT_BUDGET_ALERT_TIMEOUT_SECONDS,
  budgetAlertSignature,
} from "@ferrogate/billing";
import type { SpendAnomalySeverity, SpendAnomalySignal } from "./detector.js";

/** Why this particular POST is happening. */
export type SpendAlertReason = "opened" | "escalated" | "still_firing";

/**
 * The wire payload.
 *
 * `snake_case` and flat, matching `budgetAlertWebhookPayload`, so one receiver
 * can parse both. `type` is what distinguishes them — a receiver that routed on
 * the presence of `threshold_pct` would break the day either payload gained a
 * field.
 *
 * Every field the detector used to decide is on it. A receiver that has to call
 * back into the admin API to find out why it was paged is one that pages a
 * human with no context.
 */
export interface SpendAnomalyWebhookPayload {
  readonly type: "spend_anomaly";
  readonly episode_id: string;
  readonly signal: SpendAnomalySignal;
  readonly severity: SpendAnomalySeverity;
  /** `opened` | `escalated` | `still_firing` — see {@link SpendAlertReason}. */
  readonly reason: SpendAlertReason;
  readonly scope_type: string;
  readonly scope_id: string;
  readonly window_start_unix: number;
  readonly window_secs: number;
  readonly windows_seen: number;
  readonly observed_usd: number;
  readonly baseline_usd: number | null;
  readonly threshold_usd: number | null;
  readonly bound_by: string | null;
  readonly projected_usd: number | null;
  readonly budget_usd: number | null;
  readonly period_month: string | null;
  /**
   * The one-line statement of WHAT THIS ALERT MEANS, carried in the payload
   * rather than left to the receiver to compose.
   *
   * #692's rule: a number presented as one thing while actually being a proxy
   * for another is worse than no number. A `spend_anomaly` webhook that arrived
   * as `{signal, severity, observed_usd}` would be read as "FerroGate says this
   * spend is wrong", which is not what it says. It says the scope is spending
   * unlike its own recent self, or that the current rate does not fit the
   * budget. The sentence travels with the alert so the reading cannot be lost
   * between here and a Slack message.
   */
  readonly means: string;
  /** Set when the pass also wrote a `spend_throttles` row. */
  readonly auto_throttled_rpm: number | null;
  readonly fired_at_unix: number;
}

/** The alert configuration, or `undefined` when this deployment cannot deliver. */
export interface SpendAlertDelivery {
  readonly webhookUrl: string;
  readonly timeoutSeconds: number;
  readonly signingSecret?: string | undefined;
}

interface SpendAlertBindings {
  readonly SPEND_ANOMALY_WEBHOOK_URL?: unknown;
  readonly SPEND_ANOMALY_WEBHOOK_TIMEOUT_SECS?: unknown;
  readonly SPEND_ANOMALY_WEBHOOK_SIGNING_SECRET?: unknown;
  /** The #170 budget-alert receiver, used when no anomaly-specific one is set. */
  readonly BILLING_ALERTS_WEBHOOK_URL?: unknown;
  readonly BILLING_ALERTS_WEBHOOK_SIGNING_SECRET?: unknown;
}

function stringVar(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

/**
 * Resolve delivery from the Worker's bindings.
 *
 * ## The fallback to `BILLING_ALERTS_WEBHOOK_URL`, and why it is not lazy
 *
 * Every deployment that already cares about spend alerts has that var set and a
 * receiver behind it. Requiring a second one would mean this feature is off on
 * every existing deployment until somebody notices it exists — which is the
 * state the issue is complaining about. `type: "spend_anomaly"` on the payload
 * is what lets the existing receiver tell the two apart, and it is on the
 * payload precisely so the fallback is safe.
 *
 * A deployment that wants them routed differently sets
 * `SPEND_ANOMALY_WEBHOOK_URL`, which wins.
 *
 * A malformed value disables DELIVERY and never throws: detection still runs
 * and the episode ledger still fills, so a configuration typo costs a webhook,
 * not the history. Validation matches `validate_billing_alerts` — non-empty,
 * `http://` or `https://`, positive timeout.
 */
export function spendAlertDeliveryFrom(env: unknown): SpendAlertDelivery | undefined {
  if (typeof env !== "object" || env === null) return undefined;

  // Every binding is read as `(env as T).NAME`, one access per name, rather
  // than through an aliased `const bindings = env as T`. `test/env-var-drift.ts`
  // derives the READ side of the wrangler.toml contract by scanning the source
  // for exactly those forms, and its docblock is explicit that a read through a
  // renamed parameter is invisible to it — so an alias here would make these
  // vars look like DEAD CONFIG on one side of the gate and like an undeclared
  // read on the other. Writing them in the form the gate can see is the cheap
  // half of keeping that gate honest.
  const anomalyUrl = stringVar((env as SpendAlertBindings).SPEND_ANOMALY_WEBHOOK_URL);
  const webhookUrl =
    anomalyUrl ?? stringVar((env as SpendAlertBindings).BILLING_ALERTS_WEBHOOK_URL);
  if (webhookUrl === undefined) return undefined;
  if (!webhookUrl.startsWith("http://") && !webhookUrl.startsWith("https://")) return undefined;

  let timeoutSeconds = DEFAULT_BUDGET_ALERT_TIMEOUT_SECONDS;
  const rawTimeout = stringVar((env as SpendAlertBindings).SPEND_ANOMALY_WEBHOOK_TIMEOUT_SECS);
  if (rawTimeout !== undefined) {
    const parsed = Number(rawTimeout);
    timeoutSeconds = Number.isFinite(parsed) && parsed > 0 ? parsed : timeoutSeconds;
  }

  // The signing secret follows the URL: a deployment that fell back to the
  // billing receiver must sign with the key that receiver already verifies, or
  // every delivery is rejected as unauthenticated. Pairing them here rather
  // than resolving each independently is what stops the mismatched combination
  // (anomaly URL + billing secret) from being reachable at all.
  //
  // Both are read into their own statement rather than inline in the ternary,
  // for the scanner reason above: the drift gate's `(env as T).NAME` pattern
  // matches greedily up to the next `;`, so two casts inside one expression are
  // seen as ONE read and the first name silently disappears from the gate's
  // read set. Two statements, two reads, and the gate sees both.
  const anomalySecret = stringVar((env as SpendAlertBindings).SPEND_ANOMALY_WEBHOOK_SIGNING_SECRET);
  const billingSecret = stringVar(
    (env as SpendAlertBindings).BILLING_ALERTS_WEBHOOK_SIGNING_SECRET,
  );
  const signingSecret = anomalyUrl !== undefined ? anomalySecret : billingSecret;

  return {
    webhookUrl,
    timeoutSeconds,
    ...(signingSecret === undefined ? {} : { signingSecret }),
  };
}

/**
 * POST one alert. REJECTS on a transport failure or a non-2xx, so the caller
 * can count a failed delivery — it is not an invitation to retry.
 */
export async function dispatchSpendAnomalyAlert(options: {
  readonly delivery: SpendAlertDelivery;
  readonly payload: SpendAnomalyWebhookPayload;
  readonly fetchImpl?: typeof fetch | undefined;
}): Promise<void> {
  const body = JSON.stringify(options.payload);
  const headers: Record<string, string> = { "content-type": "application/json" };
  const secret = options.delivery.signingSecret;
  if (secret !== undefined && secret !== "") {
    headers[BUDGET_ALERT_TIMESTAMP_HEADER] = String(options.payload.fired_at_unix);
    headers[BUDGET_ALERT_SIGNATURE_HEADER] = await budgetAlertSignature(
      secret,
      options.payload.fired_at_unix,
      body,
    );
  }

  const send = options.fetchImpl ?? globalThis.fetch;
  const response = await send(options.delivery.webhookUrl, {
    method: "POST",
    headers,
    body,
    // A receiver that accepts the connection and never answers would otherwise
    // hold the whole `scheduled` invocation open until the platform kills it,
    // taking the schedule tick, the audit anchor and the SIEM pump with it.
    signal: AbortSignal.timeout(options.delivery.timeoutSeconds * 1000),
  });
  if (!response.ok) {
    throw new Error(`spend anomaly webhook returned HTTP ${response.status}`);
  }
}

/** The `means` sentence for one alert. See {@link SpendAnomalyWebhookPayload.means}. */
export function meaningOf(
  signal: SpendAnomalySignal,
  scopeId: string,
  windowSecs: number,
): string {
  const windowLabel =
    windowSecs % 3_600 === 0 ? `${windowSecs / 3_600}h` : `${Math.round(windowSecs / 60)}m`;
  if (signal === "burn_rate_spike") {
    return (
      `In the last closed ${windowLabel} window, tenant ${scopeId} spent more than its own ` +
      "preceding baseline allows for. This says the tenant is spending unlike its own recent " +
      "self; it does not say the spend is wrong, wasteful or unauthorised."
    );
  }
  return (
    `If tenant ${scopeId} keeps spending at the rate observed in the last closed ${windowLabel} ` +
    "window, its month-to-date spend passes its configured monthly budget before the period " +
    "ends. This is a linear extrapolation of one window, not a prediction of actual spend."
  );
}
