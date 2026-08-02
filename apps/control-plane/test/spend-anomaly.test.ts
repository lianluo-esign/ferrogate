/**
 * SPEND BURN-RATE ANOMALY DETECTION AND FORECAST ALERTS (#697), driven through
 * the real `scheduled` tick against a REAL `env.DB` with the REAL committed
 * migration.
 *
 * ## The defect this file pins
 *
 * Budget alerting in this tree is a THRESHOLD ON A CUMULATIVE NUMBER:
 * `apps/gateway/src/metering/budget-alerts.ts` compares month-to-date spend
 * against `quota_policies.monthly_budget_usd` and fires at 80/90/100%. Nothing
 * models the RATE. A runaway agent loop that burns a month's budget in an hour
 * crosses 80% and 100% within minutes of each other, so the first alert an
 * operator receives is already too late to be actionable — and a tenant with no
 * budget configured gets nothing at all, because a percentage of `NULL` is
 * `NULL`.
 *
 * ## What each test is adversarial about
 *
 * The product risk here is NOT a missed anomaly, it is a FALSE one: an alert an
 * operator learns to ignore converts a real signal into noise. So more than
 * half of this file asserts SILENCE — a growing customer, a sparse tenant, a
 * brand-new tenant, a persisting episode — and the two tests that assert an
 * alert are outnumbered on purpose.
 *
 * ## Cross-Worker seam
 *
 * `request_logs` and `billing_events` are written by `apps/gateway`, a
 * different Worker with a different `wrangler.toml`, so the spend history here
 * is seeded with raw SQL through `test/d1.ts` — the same cross-Worker-seam
 * fixture `cost-records-read.test.ts` uses, and for the same reason. What these
 * fixtures hold is that the DETECTOR reads what the tables hold. That the
 * gateway writes those tables in that shape is held by
 * `apps/gateway/test/requestlog/write.test.ts` and `test/metering/*`.
 */
import { env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { ControlPlaneBindings } from "../src/ports.js";
import { runScheduledTick } from "../src/schedule/scheduled.js";
import { applySchema, db, resetD1, seedBillingEvents, seedRequestLogs } from "./d1.js";

/** One hour, the default detection window. */
const HOUR = 3_600;

/**
 * `now` for every tick: 2023-11-16T02:00:00Z, comfortably mid-month so the
 * forecast has both elapsed and remaining time to work with — a `now` on a
 * month boundary would make the projection degenerate and hide a real bug.
 */
const NOW = 1_700_100_000;

/** The window the pass evaluates: the most recent CLOSED one. */
const WINDOW_START = Math.floor(NOW / HOUR) * HOUR - HOUR;

const WEBHOOK = "https://alerts.example.com/spend";

interface DeliveredAlert {
  readonly url: string;
  readonly body: Record<string, unknown>;
}

let seedSequence = 0;

const realFetch = globalThis.fetch;
let delivered: DeliveredAlert[] = [];
let webhookStatus = 200;

/** A stand-in alert receiver installed over `globalThis.fetch`. */
function installReceiver(): void {
  delivered = [];
  webhookStatus = 200;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!url.startsWith(WEBHOOK)) return realFetch(input as RequestInfo, init);
    const raw = typeof init?.body === "string" ? init.body : "{}";
    delivered.push({ url, body: JSON.parse(raw) as Record<string, unknown> });
    return new Response("{}", { status: webhookStatus });
  }) as typeof globalThis.fetch;
}

/** The Worker bindings a tick runs against, plus the alert configuration. */
function bindings(overrides: Record<string, unknown> = {}): ControlPlaneBindings {
  return {
    ...(env as unknown as Record<string, unknown>),
    CONTROL_PLANE_STORE: undefined,
    SPEND_ANOMALY_WEBHOOK_URL: WEBHOOK,
    ...overrides,
  } as never;
}

/**
 * Seed one hour's spend for a tenant: a request log row and a priced
 * `billing_events` row carrying `cost_usd`.
 *
 * `windowIndex` counts BACKWARDS from the window under evaluation, so
 * `windowIndex = 0` is the window the pass looks at and `1..24` is the
 * baseline. Written that way because every test in this file is phrased as
 * "the last hour against the day before it".
 */
async function seedHour(
  tenant: string,
  windowIndex: number,
  costUsd: number,
  requests = 1,
): Promise<void> {
  if (costUsd === 0 && requests === 0) return;
  const start = WINDOW_START - windowIndex * HOUR + 60;
  const logs = [];
  const events = [];
  // A monotonic suffix, because a test may seed the SAME hour twice (a
  // baseline pass plus a deliberate outlier on one of its hours) and
  // `request_logs.request_id` is a primary key.
  seedSequence += 1;
  for (let n = 0; n < requests; n += 1) {
    const requestId = `req_${tenant}_${windowIndex}_${seedSequence}_${n}`;
    logs.push({ requestId, tenant, startedAtUnix: start + n, completedAtUnix: start + n });
    events.push({
      id: `be_${tenant}_${windowIndex}_${seedSequence}_${n}`,
      requestId,
      occurredAtUnix: start + n,
      event: { cost_usd: costUsd / requests, usage: { total_tokens: 100 } },
    });
  }
  await seedRequestLogs(logs);
  await seedBillingEvents(events);
}

/** A flat baseline of `usd` per hour for `windows` hours before the window. */
async function seedFlatBaseline(tenant: string, usd: number, windows = 24): Promise<void> {
  for (let index = 1; index <= windows; index += 1) {
    await seedHour(tenant, index, usd, 4);
  }
}

/** Set a tenant-scope quota policy row (the tuning surface). */
async function setPolicy(tenant: string, columns: Record<string, number | null>): Promise<void> {
  const names = Object.keys(columns);
  const assignments = names.map((name) => `${name} = excluded.${name}`).join(", ");
  await db()
    .prepare(
      `INSERT INTO quota_policies (id, scope_type, scope_id${names.map((n) => `, ${n}`).join("")})
       VALUES (?, 'tenant', ?${names.map(() => ", ?").join("")})
       ON CONFLICT (scope_type, scope_id) DO UPDATE SET ${assignments}`,
    )
    .bind(`qp_${tenant}`, tenant, ...names.map((name) => columns[name] ?? null))
    .run();
}

interface EpisodeRow {
  readonly id: string;
  readonly scope_id: string;
  readonly signal: string;
  readonly severity: string;
  readonly observed_usd: number;
  readonly baseline_usd: number | null;
  readonly threshold_usd: number | null;
  readonly bound_by: string | null;
  readonly windows_seen: number;
  readonly notified_count: number;
  readonly resolved_at_unix: number | null;
}

async function episodes(): Promise<EpisodeRow[]> {
  const rows = await db()
    .prepare("SELECT * FROM spend_anomaly_episodes ORDER BY signal, scope_id")
    .all<EpisodeRow>();
  return [...rows.results];
}

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  installReceiver();
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("burn-rate anomaly detection", () => {
  it("alerts on a runaway agent loop that a monthly threshold would miss", async () => {
    // A day of $2/hour, then $80 in one hour — 40x. The month-to-date total is
    // $128 against a $5,000 budget, i.e. 2.6%: the 80% threshold alerter is
    // silent, and stays silent for another two days while the loop runs.
    await seedFlatBaseline("acme", 2);
    await seedHour("acme", 0, 80, 40);
    await setPolicy("acme", { monthly_budget_usd: 5000 });

    const report = await runScheduledTick(bindings(), NOW);

    expect(report.spendAnomaly.evaluated).toBeGreaterThan(0);
    const open = await episodes();
    const spike = open.find((row) => row.signal === "burn_rate_spike");
    expect(spike, JSON.stringify(open)).toBeDefined();
    expect(spike?.scope_id).toBe("acme");
    expect(spike?.observed_usd).toBeCloseTo(80, 6);
    expect(spike?.baseline_usd).toBeCloseTo(2, 6);
    expect(spike?.severity).toBe("critical");
    expect(spike?.notified_count).toBe(1);

    // The webhook is the operator-visible half; an episode row nobody is told
    // about is the defect one layer in.
    expect(delivered).toHaveLength(1);
    expect(delivered[0]?.body["signal"]).toBe("burn_rate_spike");
    expect(delivered[0]?.body["scope_id"]).toBe("acme");
  });

  it("stays silent for a customer that is merely growing", async () => {
    // 3% hour on hour — a customer whose spend DOUBLES EVERY DAY, which is
    // faster than any real product grows for long. A detector that pages on
    // this is one an operator mutes within a week, and a muted detector loses
    // the runaway above as well.
    let usd = 2;
    for (let index = 24; index >= 1; index -= 1) {
      await seedHour("grower", index, usd, 4);
      usd *= 1.03;
    }
    await seedHour("grower", 0, usd, 4);

    await runScheduledTick(bindings(), NOW);

    expect(await episodes()).toEqual([]);
    expect(delivered).toEqual([]);
  });

  it("still catches a spike when yesterday's incident is in the baseline", async () => {
    // THE REASON THE BASELINE IS median/MAD AND NOT mean/stddev.
    //
    // 23 quiet hours at $2 and one $200 hour — a real incident, yesterday. The
    // mean of that baseline is $10.25 with a standard deviation of ~$40, so a
    // `mean + 3σ` detector sets its bar at ~$130 and is BLIND to today's $60
    // recurrence: one incident buys immunity from the next. The median is $2
    // and the MAD is $0 (half the baseline can be garbage before the median
    // moves), so the operator's own 4x ratio bar binds at $8 and today's $60
    // fires.
    await seedFlatBaseline("repeat", 2, 24);
    await seedHour("repeat", 7, 200, 20);
    await seedHour("repeat", 0, 60, 30);

    await runScheduledTick(bindings(), NOW);

    const open = await episodes();
    expect(open).toHaveLength(1);
    expect(open[0]?.signal).toBe("burn_rate_spike");
    expect(open[0]?.baseline_usd).toBeCloseTo(2, 6);
    // `mean + 3σ` would have been ~$130 and would have said nothing.
    expect(open[0]?.threshold_usd).toBeCloseTo(8, 6);
    expect(open[0]?.bound_by).toBe("ratio");
  });
});
