/**
 * `src/budget-alerts.ts` — the pure half of proactive budget-threshold
 * alerting (#170/#228).
 *
 * Two things here are COMPATIBILITY SURFACES rather than internal choices, and
 * both are pinned character by character:
 *
 *  - the HMAC-SHA256 scheme (`budget_alerts.rs:24-38`): `sha256=<lowercase hex>`
 *    over `"<fired_at_unix>.<body>"`, plus `X-FerroGate-Timestamp`. Every
 *    operator already verifying these webhooks implemented that receiver, so a
 *    divergence is a silent integration break — real alerts dropped as forgeries;
 *  - the JSON FIELD ORDER, because the signature covers the serialised bytes
 *    and the receiver must be able to reproduce them.
 *
 * The expected digest below is computed independently, with `node:crypto`'s
 * `createHmac`, rather than by calling the function under test — otherwise the
 * assertion would be the implementation restated and would pass for any scheme.
 */
import { createHmac } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  BUDGET_ALERT_SIGNATURE_HEADER,
  BUDGET_ALERT_TIMESTAMP_HEADER,
  BUDGET_THRESHOLD_CROSSED_EVENT,
  DEFAULT_BUDGET_ALERT_TIMEOUT_SECONDS,
  budgetAlertHeaders,
  budgetAlertPayloadBody,
  budgetAlertSignature,
  budgetAlertWebhookPayload,
  crossedBudgetThresholds,
  dispatchBudgetAlertWebhook,
} from "../src/budget-alerts.js";

const CROSSING = {
  scopeType: "tenant",
  scopeId: "acme",
  periodMonth: "2026-07",
  thresholdPct: 80,
  spentUsd: 81.5,
  budgetUsd: 100,
  firedAtUnix: 1_781_000_000,
} as const;

/** `hmac-sha256(secret, "<timestamp>.<body>")`, computed by a different library. */
function referenceSignature(secret: string, timestamp: number, body: string): string {
  return `sha256=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`;
}

// ---------------------------------------------------------------------------
// Threshold evaluation
// ---------------------------------------------------------------------------

describe("crossedBudgetThresholds — the tier loop in state_wallets.rs", () => {
  test("fires every tier at or below the spent percentage, in policy order", () => {
    expect(
      crossedBudgetThresholds({ spentUsd: 81.5, budgetUsd: 100, thresholdPcts: [50, 80, 90, 100] }),
    ).toEqual([50, 80]);
  });

  test("spending EXACTLY the tier fires it — the f64::EPSILON slack", () => {
    // `percent_spent + f64::EPSILON < threshold` is the SKIP condition, so an
    // exact hit fires. Without the slack, a percentage reached by accumulating
    // per-request float costs lands a hair under and the tier never fires at
    // all — the alert would silently wait for the next request.
    expect(crossedBudgetThresholds({ spentUsd: 80, budgetUsd: 100, thresholdPcts: [80] })).toEqual([
      80,
    ]);
    expect(
      crossedBudgetThresholds({ spentUsd: 0.1 + 0.2, budgetUsd: 1, thresholdPcts: [30] }),
    ).toEqual([30]);
  });

  test("a hair under the tier does NOT fire", () => {
    expect(crossedBudgetThresholds({ spentUsd: 79, budgetUsd: 100, thresholdPcts: [80] })).toEqual(
      [],
    );
  });

  test("no budget, a zero budget or a negative budget fires nothing", () => {
    // `monthly_budget_usd.filter(|budget| *budget > 0.0)`. Dividing by zero
    // would yield Infinity and fire every tier at once, on a tenant who has no
    // budget configured at all.
    for (const budgetUsd of [undefined, 0, -1, Number.NaN]) {
      expect(crossedBudgetThresholds({ spentUsd: 500, budgetUsd, thresholdPcts: [50, 80] })).toEqual(
        [],
      );
    }
  });

  test("a budget with NO tiers configured is a throttle, not an alert subscription", () => {
    expect(crossedBudgetThresholds({ spentUsd: 500, budgetUsd: 100, thresholdPcts: [] })).toEqual(
      [],
    );
  });

  test("zero spend against a real budget fires nothing (a 0 tier would be pathological)", () => {
    expect(
      crossedBudgetThresholds({ spentUsd: 0, budgetUsd: 100, thresholdPcts: [50, 80, 100] }),
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The wire payload
// ---------------------------------------------------------------------------

describe("budgetAlertWebhookPayload — BudgetAlertWebhookPayload's wire shape", () => {
  test("the field order matches the Rust struct, because the signature covers bytes", () => {
    const payload = budgetAlertWebhookPayload(CROSSING);
    expect(Object.keys(payload)).toEqual([
      "event",
      "scope_type",
      "scope_id",
      "period_month",
      "threshold_pct",
      "spent_usd",
      "budget_usd",
      "fired_at_unix",
    ]);
  });

  test("the body is exactly what serde_json::to_vec emits", () => {
    expect(budgetAlertPayloadBody(budgetAlertWebhookPayload(CROSSING))).toBe(
      '{"event":"budget_threshold_crossed","scope_type":"tenant","scope_id":"acme",' +
        '"period_month":"2026-07","threshold_pct":80,"spent_usd":81.5,"budget_usd":100,' +
        '"fired_at_unix":1781000000}',
    );
  });

  test("the event discriminator is the one the issue names", () => {
    expect(BUDGET_THRESHOLD_CROSSED_EVENT).toBe("budget_threshold_crossed");
    expect(budgetAlertWebhookPayload(CROSSING).event).toBe("budget_threshold_crossed");
  });
});

// ---------------------------------------------------------------------------
// The signature
// ---------------------------------------------------------------------------

describe("budgetAlertSignature — budget_alerts.rs:24-38", () => {
  test("matches an INDEPENDENT HMAC-SHA256 over `<timestamp>.<body>`", async () => {
    const body = budgetAlertPayloadBody(budgetAlertWebhookPayload(CROSSING));
    expect(await budgetAlertSignature("s3cr3t", CROSSING.firedAtUnix, body)).toBe(
      referenceSignature("s3cr3t", CROSSING.firedAtUnix, body),
    );
  });

  test("`sha256=` prefix, lowercase hex, 64 hex chars", async () => {
    const signature = await budgetAlertSignature("s3cr3t", 1_000, "{}");
    expect(signature).toMatch(/^sha256=[0-9a-f]{64}$/);
  });

  test("deterministic, and every input is bound into it", async () => {
    const body = '{"event":"budget_threshold_crossed"}';
    const base = await budgetAlertSignature("s3cr3t", 1_000, body);
    expect(await budgetAlertSignature("s3cr3t", 1_000, body)).toBe(base);
    // A different SECRET, a different TIMESTAMP or a different BODY must each
    // change the digest — the timestamp especially, since binding it is what
    // lets a receiver reject a captured-and-resent alert.
    expect(await budgetAlertSignature("other", 1_000, body)).not.toBe(base);
    expect(await budgetAlertSignature("s3cr3t", 1_001, body)).not.toBe(base);
    expect(await budgetAlertSignature("s3cr3t", 1_000, "tampered")).not.toBe(base);
  });

  test("the `.` separator is real — `1.2`+`3` and `1`+`23` must not collide", async () => {
    // Without a separator, HMAC over the concatenation would make
    // (timestamp=12, body="3") and (timestamp=1, body="23") identical, which is
    // a replay window disguised as a signature.
    expect(await budgetAlertSignature("s", 12, "3")).not.toBe(
      await budgetAlertSignature("s", 1, "23"),
    );
  });
});

describe("budgetAlertHeaders", () => {
  test("signed delivery carries BOTH the timestamp and the signature header", async () => {
    const payload = budgetAlertWebhookPayload(CROSSING);
    const body = budgetAlertPayloadBody(payload);
    const headers = await budgetAlertHeaders(payload, body, "s3cr3t");
    expect(headers["content-type"]).toBe("application/json");
    expect(headers[BUDGET_ALERT_TIMESTAMP_HEADER]).toBe(String(CROSSING.firedAtUnix));
    expect(headers[BUDGET_ALERT_SIGNATURE_HEADER]).toBe(
      referenceSignature("s3cr3t", CROSSING.firedAtUnix, body),
    );
  });

  test("the header names are the Rust constants", () => {
    expect(BUDGET_ALERT_SIGNATURE_HEADER).toBe("X-FerroGate-Signature");
    expect(BUDGET_ALERT_TIMESTAMP_HEADER).toBe("X-FerroGate-Timestamp");
  });

  test("an ABSENT or EMPTY secret leaves the alert unsigned, never signed with ''", async () => {
    const payload = budgetAlertWebhookPayload(CROSSING);
    const body = budgetAlertPayloadBody(payload);
    for (const secret of [undefined, ""]) {
      const headers = await budgetAlertHeaders(payload, body, secret);
      // Signing with "" produces a deterministic digest ANYONE can forge, which
      // is worse than unsigned: a receiver would believe it verified something.
      expect(headers[BUDGET_ALERT_SIGNATURE_HEADER]).toBeUndefined();
      expect(headers[BUDGET_ALERT_TIMESTAMP_HEADER]).toBeUndefined();
      expect(Object.keys(headers)).toEqual(["content-type"]);
    }
  });
});

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

describe("dispatchBudgetAlertWebhook", () => {
  test("POSTs the signed body to the configured URL", async () => {
    let seen: { url: string; init: RequestInit } | undefined;
    await dispatchBudgetAlertWebhook({
      webhookUrl: "https://alerts.example/budget",
      payload: budgetAlertWebhookPayload(CROSSING),
      signingSecret: "s3cr3t",
      fetchImpl: (async (url: unknown, init: unknown) => {
        seen = { url: String(url), init: init as RequestInit };
        return new Response("{}", { status: 200 });
      }) as unknown as typeof fetch,
    });

    expect(seen?.url).toBe("https://alerts.example/budget");
    expect(seen?.init.method).toBe("POST");
    const body = seen?.init.body as string;
    expect(body).toBe(budgetAlertPayloadBody(budgetAlertWebhookPayload(CROSSING)));
    const headers = seen?.init.headers as Record<string, string>;
    expect(headers[BUDGET_ALERT_SIGNATURE_HEADER]).toBe(
      referenceSignature("s3cr3t", CROSSING.firedAtUnix, body),
    );
    // The timeout is armed, so a receiver that accepts and then stalls cannot
    // hold the caller's `waitUntil` open indefinitely.
    expect(seen?.init.signal).toBeInstanceOf(AbortSignal);
  });

  test("REJECTS on a non-2xx — telemetry.rs:1283 `if !status.is_success() { bail! }`", async () => {
    await expect(
      dispatchBudgetAlertWebhook({
        webhookUrl: "https://alerts.example/budget",
        payload: budgetAlertWebhookPayload(CROSSING),
        fetchImpl: (async () => new Response("boom", { status: 503 })) as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/HTTP 503/);
  });

  test("REJECTS on a transport failure", async () => {
    await expect(
      dispatchBudgetAlertWebhook({
        webhookUrl: "https://alerts.example/budget",
        payload: budgetAlertWebhookPayload(CROSSING),
        fetchImpl: (async () => {
          throw new Error("connection refused");
        }) as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/connection refused/);
  });

  test("the default timeout is the Rust default", () => {
    expect(DEFAULT_BUDGET_ALERT_TIMEOUT_SECONDS).toBe(5);
  });
});
