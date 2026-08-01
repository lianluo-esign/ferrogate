/**
 * Proactive budget-threshold alerting — the PURE half (issues #170, #228).
 *
 * Clean-room port of `crates/ferrogate-gateway/src/budget_alerts.rs` (the wire
 * payload, its HMAC-SHA256 signing scheme and the outbound POST) plus the
 * threshold arithmetic that `crates/ferrogate-gateway/src/state_wallets.rs`
 * performs inline in `dispatch_budget_threshold_alerts_for_scope`.
 *
 * ## What lives here and what deliberately does not
 *
 * Everything in this file is storage-free and binding-free, which is the whole
 * contract of `@ferrogate/billing` — the durable seams live in
 * `@ferrogate/storage` and the request-path wiring lives in
 * `apps/gateway/src/metering/budget-alerts.ts`. Concretely:
 *
 * | here                              | NOT here                                        |
 * |-----------------------------------|-------------------------------------------------|
 * | which tiers a spend/budget crosses | reading `quota_policies` / `usage_monthly_rollups` |
 * | the wire payload + its field order | resolving the scope chain of a request           |
 * | the HMAC-SHA256 signature          | the once-per-period claim (`D1BudgetAlertStore`) |
 * | the POST, its timeout and headers  | `ctx.waitUntil`                                  |
 *
 * ## The signature scheme is a COMPATIBILITY SURFACE, not an implementation detail
 *
 * `budget_alerts.rs:24-38` defines it, and every operator already verifying
 * these webhooks has written the receiving half against it:
 *
 * ```text
 * X-FerroGate-Timestamp: <fired_at_unix>
 * X-FerroGate-Signature: sha256=<lowercase hex of HMAC-SHA256(secret, "<fired_at_unix>.<body>")>
 * ```
 *
 * The timestamp is bound INTO the signed material (not merely sent alongside)
 * so a receiver can reject replays; a scheme that signed the body alone would
 * verify a captured-and-resent alert forever. Changing the separator, the case
 * of the hex, the `sha256=` prefix or the header names is a silent integration
 * break — the receiver computes a different digest and drops a real alert as a
 * forgery — so all four are pinned by `test/budget-alerts.test.ts`.
 *
 * ## The JSON field ORDER is load-bearing
 *
 * The signature is computed over the serialised bytes, so the receiver must be
 * able to re-serialise the same bytes. {@link budgetAlertWebhookPayload} builds
 * the object literal in the exact declaration order of the Rust struct, and
 * `JSON.stringify` preserves insertion order for non-integer string keys, so
 * {@link budgetAlertPayloadBody} reproduces `serde_json::to_vec` byte for byte
 * for the shapes this payload can take. A `Response.json()`-style re-encode of
 * a parsed object is NOT guaranteed to, which is why the body is threaded
 * through as a string from the one place it is built.
 */

/** `payload.event` — the only value this webhook carries today. */
export const BUDGET_THRESHOLD_CROSSED_EVENT = "budget_threshold_crossed" as const;

/** `WEBHOOK_SIGNATURE_HEADER` (`budget_alerts.rs:24`). */
export const BUDGET_ALERT_SIGNATURE_HEADER = "X-FerroGate-Signature";

/** `WEBHOOK_TIMESTAMP_HEADER` (`budget_alerts.rs:26`). */
export const BUDGET_ALERT_TIMESTAMP_HEADER = "X-FerroGate-Timestamp";

/** `default_billing_alerts_webhook_timeout_secs()` (config/types.rs:2183). */
export const DEFAULT_BUDGET_ALERT_TIMEOUT_SECONDS = 5;

/**
 * `QuotaScopeKind` (`ferrogate-storage/src/lib.rs:12136`), as the wire spells
 * it. Re-declared rather than imported so this module keeps zero dependencies
 * on the storage package; `apps/gateway` pins the two against each other at
 * compile time.
 */
export type BudgetAlertScopeKind = "tenant" | "project" | "workspace" | "key";

/**
 * The wire payload — `BudgetAlertWebhookPayload` (`budget_alerts.rs:57-66`).
 *
 * Flat and self-describing on purpose: the issue calls for pluggable
 * email/Slack targets to sit behind this webhook eventually, so a receiver must
 * be able to route it (to a per-tenant Slack channel, say) with no
 * FerroGate-internal knowledge.
 */
export interface BudgetAlertWebhookPayload {
  readonly event: typeof BUDGET_THRESHOLD_CROSSED_EVENT;
  readonly scope_type: BudgetAlertScopeKind;
  readonly scope_id: string;
  readonly period_month: string;
  readonly threshold_pct: number;
  readonly spent_usd: number;
  readonly budget_usd: number;
  readonly fired_at_unix: number;
}

/** One threshold crossing, before it is turned into a payload. */
export interface BudgetAlertCrossing {
  readonly scopeType: BudgetAlertScopeKind;
  readonly scopeId: string;
  readonly periodMonth: string;
  readonly thresholdPct: number;
  readonly spentUsd: number;
  readonly budgetUsd: number;
  readonly firedAtUnix: number;
}

/**
 * `BudgetAlertWebhookPayload::new` — build the payload in the Rust struct's
 * declaration order.
 *
 * The order is not cosmetic; see the module doc. Written as a single object
 * literal (rather than assembled conditionally) so no branch can reorder it.
 */
export function budgetAlertWebhookPayload(
  crossing: BudgetAlertCrossing,
): BudgetAlertWebhookPayload {
  return {
    event: BUDGET_THRESHOLD_CROSSED_EVENT,
    scope_type: crossing.scopeType,
    scope_id: crossing.scopeId,
    period_month: crossing.periodMonth,
    threshold_pct: crossing.thresholdPct,
    spent_usd: crossing.spentUsd,
    budget_usd: crossing.budgetUsd,
    fired_at_unix: crossing.firedAtUnix,
  };
}

/** `serde_json::to_vec(payload)` — the exact bytes that get signed and sent. */
export function budgetAlertPayloadBody(payload: BudgetAlertWebhookPayload): string {
  return JSON.stringify(payload);
}

/**
 * Which of `thresholdPcts` this spend has crossed — the loop in
 * `state_wallets.rs::dispatch_budget_threshold_alerts_for_scope`.
 *
 * Three guards, each one a real Rust branch rather than defensive padding:
 *
 *  - `monthly_budget_usd.filter(|budget| *budget > 0.0)` — an absent, zero or
 *    negative budget has no percentage to be at, so NOTHING fires. Dividing by
 *    it would produce `Infinity`/`NaN` and either fire every tier at once or
 *    none, silently;
 *  - `if policy.alert_threshold_pcts.is_empty() { return; }` — a budget with no
 *    tiers configured is a THROTTLE, not an alert subscription;
 *  - `if percent_spent + f64::EPSILON < f64::from(threshold_pct) { continue; }`
 *    — the epsilon slack is what makes spending EXACTLY the tier fire it, in
 *    the face of the float error that reaching a round percentage through
 *    accumulated per-request costs always carries. `Number.EPSILON` is the same
 *    2^-52 value as `f64::EPSILON`.
 *
 * Order is preserved from the policy (Rust iterates `alert_threshold_pcts` as
 * stored), so a caller firing them in sequence produces the same order a Rust
 * deployment does.
 */
export function crossedBudgetThresholds(input: {
  readonly spentUsd: number;
  readonly budgetUsd: number | undefined;
  readonly thresholdPcts: readonly number[];
}): number[] {
  const { budgetUsd, thresholdPcts } = input;
  if (budgetUsd === undefined || !Number.isFinite(budgetUsd) || budgetUsd <= 0) return [];
  if (thresholdPcts.length === 0) return [];
  const percentSpent = (input.spentUsd / budgetUsd) * 100;
  if (!Number.isFinite(percentSpent)) return [];
  return thresholdPcts.filter((threshold) => percentSpent + Number.EPSILON >= threshold);
}

/**
 * `budget_alert_signature` (`budget_alerts.rs:33-38`) — HMAC-SHA256 over
 * `"<timestamp>.<body>"`, returned as `sha256=<lowercase hex>`.
 *
 * WebCrypto rather than a hand-rolled digest: `crypto.subtle` is available in
 * workerd, in Node ≥18 and in the browser, and its `sign` is constant-time in
 * the implementation, which a JS loop over bytes would not be.
 */
export async function budgetAlertSignature(
  secret: string,
  timestampUnix: number,
  body: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(`${timestampUnix}.${body}`));
  return `sha256=${encodeHex(new Uint8Array(mac))}`;
}

/** `encode_hex` — lowercase, two chars per byte, no separators. */
function encodeHex(bytes: Uint8Array): string {
  let encoded = "";
  for (const byte of bytes) {
    encoded += byte.toString(16).padStart(2, "0");
  }
  return encoded;
}

/**
 * The headers one delivery carries.
 *
 * `signing_secret.filter(|secret| !secret.is_empty())` — an EMPTY secret is
 * treated as absent, not as a key of length zero. Signing with `""` would
 * produce a deterministic digest anyone can forge, which is strictly worse than
 * the unsigned posture because a receiver would believe it verified something.
 */
export async function budgetAlertHeaders(
  payload: BudgetAlertWebhookPayload,
  body: string,
  signingSecret: string | undefined,
): Promise<Record<string, string>> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (signingSecret === undefined || signingSecret === "") {
    return headers;
  }
  headers[BUDGET_ALERT_TIMESTAMP_HEADER] = String(payload.fired_at_unix);
  headers[BUDGET_ALERT_SIGNATURE_HEADER] = await budgetAlertSignature(
    signingSecret,
    payload.fired_at_unix,
    body,
  );
  return headers;
}

/** What {@link dispatchBudgetAlertWebhook} needs to make one POST. */
export interface BudgetAlertDispatchOptions {
  readonly webhookUrl: string;
  readonly payload: BudgetAlertWebhookPayload;
  readonly signingSecret?: string | undefined;
  /** `billing_alerts.webhook_timeout_secs` — defaults to the Rust default, 5. */
  readonly timeoutSeconds?: number | undefined;
  /**
   * The transport. Defaults to `globalThis.fetch` read at CALL time, never
   * captured at module load, so an interceptor installed by a test (or by a
   * future outbound-egress policy) is honoured.
   */
  readonly fetchImpl?: typeof fetch | undefined;
}

/**
 * `dispatch_budget_alert_webhook` — POST the payload, with the timeout and the
 * signature headers.
 *
 * REJECTS on a transport failure and on a non-2xx response
 * (`telemetry.rs:1283`: `if !status.is_success() { bail!(...) }`). That is the
 * contract the caller depends on to COUNT a failed alert; it is emphatically
 * not an invitation to retry — see `apps/gateway/src/metering/budget-alerts.ts`
 * for why a burned tier is the correct outcome.
 */
export async function dispatchBudgetAlertWebhook(
  options: BudgetAlertDispatchOptions,
): Promise<void> {
  const body = budgetAlertPayloadBody(options.payload);
  const headers = await budgetAlertHeaders(options.payload, body, options.signingSecret);
  const timeoutSeconds = options.timeoutSeconds ?? DEFAULT_BUDGET_ALERT_TIMEOUT_SECONDS;
  const send = options.fetchImpl ?? globalThis.fetch;

  const response = await send(options.webhookUrl, {
    method: "POST",
    headers,
    body,
    // A receiver that accepts the connection and then never answers would
    // otherwise hold the isolate's `waitUntil` open until the platform kills
    // it, taking the rest of the deferred metering work with it.
    signal: AbortSignal.timeout(timeoutSeconds * 1000),
  });

  if (!response.ok) {
    throw new Error(`budget alert webhook returned HTTP ${response.status}`);
  }
}
