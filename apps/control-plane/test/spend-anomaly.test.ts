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
 * ## Cross-Worker seam, and WHERE the spend history lives
 *
 * `request_logs` and `billing_events` are written by `apps/gateway`, a
 * different Worker with a different `wrangler.toml`, so the spend history here
 * is seeded with raw SQL through `test/d1.ts` — the same cross-Worker-seam
 * fixture `cost-records-read.test.ts` uses, and for the same reason. What these
 * fixtures hold is that the DETECTOR reads what the tables hold. That the
 * gateway writes those tables in that shape is held by
 * `apps/gateway/test/requestlog/write.test.ts` and `test/metering/*`.
 *
 * Under per-tenant Durable Objects the detector reads the join from each
 * tenant's OWN object, not the singleton `CONTROL_DATA` facade: a tenant's
 * `billing_events` are written nowhere else, so the facade's copy has no join
 * partner and reads as zero spend (see `finops/source.ts`). So `seedHour` seeds
 * the spend into `tenantObjectDb(tenant)`, and `beforeEach` registers every
 * fixture tenant in the `tenant_databases` roster the fleet fan-out enumerates.
 * The EPISODES are authoritative in each tenant object too (no control mirror —
 * the `episodes()` helper below reads them by fanning out, like the operator
 * view does). The tuning knobs (`quota_policies`) and the `spend_throttles`
 * projection still live on the control facade, which is where the pass reads and
 * writes them.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { SPEND_ANOMALY_CLAIM_LEASE_SECS, monthBoundsUnix } from "../src/finops/pass.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { runScheduledTick } from "../src/schedule/scheduled.js";
import { FLEET_FANOUT_MAX_TENANTS } from "../src/store/tenant-fanout.js";
import { applySchema, db, resetD1, seedBillingEvents, seedRequestLogs } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";
import { registerObjectTenants, tenantObjectDb } from "./tenant-object.js";

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

const ANOMALY_TENANTS = [
  "acme",
  "grower",
  "repeat",
  "newborn",
  "sparse",
  "pennies",
  "optout",
  "stuck",
  "worse",
  "flap",
  "downstream",
  "nohook",
  "once",
  "fresh",
  "nobudget",
  "early",
  "nobrake",
  "brake",
  "mild",
  "steady",
  "scaled",
  "narrow",
  "wideband",
  "wide",
  "other",
  "noisy",
] as const;

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
  // The detector reads the join from the tenant's OWN object (its
  // `billing_events` live nowhere else), so the spend is seeded THERE — the
  // control facade's copy would have no join partner and read as zero. The
  // three-arg `seedBillingEvents` writes the tenant-object shape (NOT NULL
  // `tenant_id`); registration into the fan-out roster happens in `beforeEach`.
  const tenantDb = tenantObjectDb(tenant);
  await seedRequestLogs(logs, tenantDb);
  await seedBillingEvents(events, tenantDb, tenant);
}

/** A flat baseline of `usd` per hour for `windows` hours before the window. */
async function seedFlatBaseline(tenant: string, usd: number, windows = 24): Promise<void> {
  for (let index = 1; index <= windows; index += 1) {
    await seedHour(tenant, index, usd, 4);
  }
}

/**
 * Set a tenant-scope quota policy row (the tuning surface).
 *
 * The detector now reads its tuning from each tenant's OWN object (the
 * `quota_policies` enforcement row moved there; `finops/pass.ts` fans out over
 * the objects), so the row is seeded THERE — the control facade's copy is the
 * mirror the cutover retires and would no longer be read.
 */
async function setPolicy(tenant: string, columns: Record<string, number | null>): Promise<void> {
  const names = Object.keys(columns);
  const assignments = names.map((name) => `${name} = excluded.${name}`).join(", ");
  await tenantObjectDb(tenant)
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
  readonly window_start_unix: number;
  readonly window_secs: number;
  readonly observed_usd: number;
  readonly baseline_usd: number | null;
  readonly threshold_usd: number | null;
  readonly bound_by: string | null;
  readonly baseline_windows: number | null;
  readonly active_windows: number | null;
  readonly projected_usd: number | null;
  readonly detail_json: string | null;
  readonly windows_seen: number;
  readonly notified_count: number;
  readonly resolved_at_unix: number | null;
}

async function episodes(): Promise<EpisodeRow[]> {
  // Episodes are authoritative in — and read only from — each tenant's OWN
  // object now; the control-facade mirror was removed (see `finops/pass.ts`),
  // and the operator fleet view reads them by fanning out to the objects. So the
  // fleet assertion here assembles the same way: read each registered tenant's
  // object and concatenate. Episode ids embed the scope, so the sets are
  // disjoint across tenants and no dedup is needed; the (signal, scope_id) sort
  // reproduces the old `ORDER BY signal, scope_id`.
  const perTenant = await Promise.all(
    ANOMALY_TENANTS.map(async (tenantId) => {
      const rows = await tenantObjectDb(tenantId)
        .prepare("SELECT * FROM spend_anomaly_episodes")
        .all<EpisodeRow>();
      return rows.results;
    }),
  );
  return perTenant
    .flat()
    .sort((a, b) => a.signal.localeCompare(b.signal) || a.scope_id.localeCompare(b.scope_id));
}

interface ThrottleRow {
  readonly scope_id: string;
  readonly rpm_limit: number;
  readonly expires_at_unix: number;
  readonly episode_id: string | null;
}

async function throttles(): Promise<ThrottleRow[]> {
  const rows = await db()
    .prepare("SELECT * FROM spend_throttles ORDER BY scope_id")
    .all<ThrottleRow>();
  return [...rows.results];
}

/**
 * The throttle rows the auto-throttle SHADOW-wrote into each tenant's own
 * object, read straight off the objects (not the control facade). Proves the
 * DO-side `spend_throttles` table is populated ahead of the admission cutover.
 */
async function tenantThrottles(): Promise<ThrottleRow[]> {
  const perTenant = await Promise.all(
    ANOMALY_TENANTS.map(async (tenantId) => {
      const rows = await tenantObjectDb(tenantId)
        .prepare("SELECT * FROM spend_throttles ORDER BY scope_id")
        .all<ThrottleRow>();
      return [...rows.results];
    }),
  );
  return perTenant.flat().sort((a, b) => a.scope_id.localeCompare(b.scope_id));
}

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  // The tenant objects are addressed by `idFromName` and survive `resetD1`
  // (which only wipes the control facade), so the per-object spend history and
  // the authoritative episodes are cleared explicitly between tests.
  await Promise.all(
    ANOMALY_TENANTS.map(async (tenantId) => {
      const tenant = tenantObjectDb(tenantId);
      await tenant.batch([
        tenant.prepare("DELETE FROM spend_anomaly_episodes"),
        tenant.prepare("DELETE FROM request_logs"),
        tenant.prepare("DELETE FROM billing_events"),
        // The tuning surface now lives in the object too (`setPolicy` seeds it
        // here); a leftover row would re-tune the next test's detector.
        tenant.prepare("DELETE FROM quota_policies"),
        // The auto-throttle now shadow-writes here too; a leftover brake would
        // bleed into the next test's throttle assertions.
        tenant.prepare("DELETE FROM spend_throttles"),
      ]);
    }),
  );
  // The fleet fan-out reads the `tenant_databases` roster to know who exists;
  // `resetD1` wiped it, so the fixture tenants are re-registered as
  // durable-object tenants here (the production onboarding path writes this row
  // the moment a tenant is created).
  await registerObjectTenants(ANOMALY_TENANTS);
  installReceiver();
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("burn-rate anomaly detection", () => {
  it("reclaims an abandoned in-flight window claim", async () => {
    await seedFlatBaseline("acme", 2);
    await seedHour("acme", 0, 80, 40);
    await db()
      .prepare(
        "INSERT INTO spend_anomaly_runs " +
          "(window_start_unix, ran_at_unix, scopes_evaluated) VALUES (?, ?, -1)",
      )
      .bind(WINDOW_START, NOW - SPEND_ANOMALY_CLAIM_LEASE_SECS - 1)
      .run();

    const report = await runScheduledTick(bindings(), NOW);

    expect(report.spendAnomaly.skipped).not.toBe("already_evaluated");
    const claim = await db()
      .prepare("SELECT scopes_evaluated FROM spend_anomaly_runs WHERE window_start_unix = ?")
      .bind(WINDOW_START)
      .first<{ scopes_evaluated: number }>();
    expect(claim?.scopes_evaluated).toBeGreaterThanOrEqual(0);
  });

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

    const authoritative = await tenantObjectDb("acme")
      .prepare("SELECT id, notified_count FROM spend_anomaly_episodes")
      .all<{ id: string; notified_count: number }>();
    expect(authoritative.results).toHaveLength(1);
    expect(authoritative.results[0]?.id).toBe(spike?.id);
    expect(authoritative.results[0]?.notified_count).toBe(1);

    // THE RED LINE: the shared control facade holds NO copy of the episode. It
    // is authoritative in acme's own object and read back from there; the pass
    // no longer mirrors it to the fleet store (see `finops/pass.ts`), and the
    // operator view fans out to the objects instead. The control mirror table is
    // now GONE entirely — `0038_drop_spend_anomaly_episodes.sql` dropped it, the
    // strongest form of "no second source of truth" — so the red line is proven
    // by the table's ABSENCE, not by a count of zero over a table that exists.
    const facadeTable = await db()
      .prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name=?")
      .bind("spend_anomaly_episodes")
      .first<{ n: number }>();
    expect(facadeTable?.n).toBe(0);

    // The webhook is the operator-visible half; an episode row nobody is told
    // about is the defect one layer in.
    expect(delivered).toHaveLength(1);
    expect(delivered[0]?.body.signal).toBe("burn_rate_spike");
    expect(delivered[0]?.body.scope_id).toBe("acme");
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

describe("cold start and sparsity — the cases a naive detector gets loudest", () => {
  it("says nothing about a brand-new tenant with no baseline", async () => {
    // Four hours old, and the fourth hour is 20x the third. With an empty or
    // near-empty baseline the median is 0, the MAD is 0, every bar collapses to
    // 0 and the arithmetic makes this an INFINITE deviation. The gate decides
    // it instead: three observed windows is below `min_baseline_windows`.
    await seedHour("newborn", 3, 1, 2);
    await seedHour("newborn", 2, 1, 2);
    await seedHour("newborn", 1, 1, 2);
    await seedHour("newborn", 0, 200, 50);

    await runScheduledTick(bindings(), NOW);

    expect(await episodes()).toEqual([]);
    expect(delivered).toEqual([]);
  });

  it("says nothing about a tenant with three requests a day", async () => {
    // A full 24-window history, so the baseline COUNT gate passes — and only 4
    // of those windows have any spend at all, so there is no distribution. The
    // median is 0 and the MAD is 0; without the sparsity gate this tenant's
    // every non-zero hour is an infinite deviation, forever.
    for (const index of [19, 13, 7, 1]) {
      await seedHour("sparse", index, 0.4, 1);
    }
    // One window at the far end of the lookback, so the baseline spans the full
    // 24 windows rather than starting at the tenant's first traffic.
    await seedHour("sparse", 24, 0.4, 1);
    await seedHour("sparse", 0, 12, 3);

    await runScheduledTick(bindings(), NOW);

    expect(await episodes()).toEqual([]);
    expect(delivered).toEqual([]);
  });

  it("says nothing about a 40x spike on trivial amounts", async () => {
    // $0.02/hour becoming $0.80 is a 40x burn-rate spike by every ratio in this
    // file and is nobody's incident. The absolute floor is the third bar for
    // exactly this, and it is the single most common shape of a false positive
    // in a ratio detector.
    await seedFlatBaseline("pennies", 0.02, 24);
    await seedHour("pennies", 0, 0.8, 4);

    await runScheduledTick(bindings(), NOW);

    expect(await episodes()).toEqual([]);
    expect(delivered).toEqual([]);
  });

  it("fires on the same shape once the operator lowers the floor", async () => {
    // The tuning story, proved rather than asserted in a doc comment: the
    // silence above is a DECISION with a knob, not an inability.
    await seedFlatBaseline("pennies", 0.02, 24);
    await seedHour("pennies", 0, 0.8, 4);
    await setPolicy("pennies", { spend_anomaly_min_window_usd: 0.1 });

    await runScheduledTick(bindings(), NOW);

    const open = await episodes();
    expect(open).toHaveLength(1);
    // Still the FLOOR that binds — $0.10 is above 4x the $0.02 median — and the
    // episode says so, which is what lets the operator see that lowering the
    // floor further is the next knob rather than guessing at the ratio.
    expect(open[0]?.bound_by).toBe("floor");
    expect(open[0]?.threshold_usd).toBeCloseTo(0.1, 6);
    expect(delivered).toHaveLength(1);
  });

  it("watches nobody when the tenant opted out", async () => {
    await seedFlatBaseline("optout", 2);
    await seedHour("optout", 0, 80, 40);
    await setPolicy("optout", { spend_anomaly_enabled: 0 });

    await runScheduledTick(bindings(), NOW);

    expect(await episodes()).toEqual([]);
    expect(delivered).toEqual([]);
  });
});

describe("a persisting anomaly — six hours is 2 notifications, not 72", () => {
  /**
   * Seed a runaway that has been going for `hours` windows and run the pass for
   * each of them in order, exactly as the cron would. The baseline is seeded
   * far enough back that the earliest evaluated window still has one.
   */
  async function runawayFor(hours: number): Promise<number[]> {
    for (let index = hours; index < hours + 24; index += 1) {
      await seedHour("stuck", index, 2, 4);
    }
    for (let index = hours - 1; index >= 0; index -= 1) {
      await seedHour("stuck", index, 80, 40);
    }
    const notified: number[] = [];
    for (let index = hours - 1; index >= 0; index -= 1) {
      const report = await runScheduledTick(bindings(), NOW - index * HOUR);
      notified.push(report.spendAnomaly.notified);
    }
    return notified;
  }

  it("notifies on open and then once per cooldown, not once per window", async () => {
    // Seven consecutive hours of the same stuck loop, evaluated seven times.
    // The default cooldown is six hours, so the operator is told at hour 0 and
    // again at hour 6 — and NOT at 1, 2, 3, 4 or 5.
    const notified = await runawayFor(7);

    expect(notified).toEqual([1, 0, 0, 0, 0, 0, 1]);
    expect(delivered).toHaveLength(2);
    expect(delivered[0]?.body.reason).toBe("opened");
    expect(delivered[1]?.body.reason).toBe("still_firing");

    // ONE episode row for the whole incident, carrying how long it has run.
    const open = await episodes();
    expect(open).toHaveLength(1);
    expect(open[0]?.windows_seen).toBe(7);
    expect(open[0]?.notified_count).toBe(2);
    expect(open[0]?.resolved_at_unix).toBeNull();
  });

  it("breaks the cooldown when the severity escalates, once", async () => {
    // Hour 1 is 5x the $2 baseline (a warning), hours 0 is 40x (critical).
    // "It got worse" is new information and must not wait out the cooldown;
    // staying critical is not, and must.
    for (let index = 2; index < 26; index += 1) await seedHour("worse", index, 2, 4);
    await seedHour("worse", 1, 10, 5);
    await seedHour("worse", 0, 80, 40);

    const first = await runScheduledTick(bindings(), NOW - HOUR);
    const second = await runScheduledTick(bindings(), NOW);

    expect(first.spendAnomaly.notified).toBe(1);
    expect(second.spendAnomaly.notified).toBe(1);
    expect(delivered.map((alert) => alert.body.severity)).toEqual(["warning", "critical"]);
    expect(delivered[1]?.body.reason).toBe("escalated");
    const open = await episodes();
    expect(open[0]?.severity).toBe("critical");
    expect(open[0]?.windows_seen).toBe(2);
  });

  it("closes the episode when the window stops firing, and opens a new one later", async () => {
    for (let index = 2; index < 26; index += 1) await seedHour("flap", index, 2, 4);
    await seedHour("flap", 1, 80, 40);
    await seedHour("flap", 0, 2, 4);

    await runScheduledTick(bindings(), NOW - HOUR);
    await runScheduledTick(bindings(), NOW);

    const all = await episodes();
    expect(all).toHaveLength(1);
    expect(all[0]?.resolved_at_unix).not.toBeNull();
    // Resolution is silent: a spike that stopped is not news, and an
    // all-clear per window would double the traffic on the channel.
    expect(delivered).toHaveLength(1);
  });

  it("records the episode even when the receiver is down, with notified_count 0", async () => {
    // How an operator finds the alerts their own receiver dropped. There is no
    // retry — the next window is the retry — so a lost notification must leave
    // a visible trace or it is simply gone.
    await seedFlatBaseline("downstream", 2);
    await seedHour("downstream", 0, 80, 40);
    webhookStatus = 503;

    const report = await runScheduledTick(bindings(), NOW);

    expect(report.spendAnomaly.deliveryFailed).toBe(1);
    expect(report.spendAnomaly.notified).toBe(0);
    const open = await episodes();
    expect(open).toHaveLength(1);
    expect(open[0]?.notified_count).toBe(0);
  });

  it("detects and records with no webhook configured at all", async () => {
    // The opposite posture from the gateway's budget alerter, and deliberate:
    // an operator who has not wired a receiver yet still gets the history for
    // the period BEFORE they wired one, which is when they most need it.
    await seedFlatBaseline("nohook", 2);
    await seedHour("nohook", 0, 80, 40);

    const report = await runScheduledTick(
      bindings({ SPEND_ANOMALY_WEBHOOK_URL: undefined, BILLING_ALERTS_WEBHOOK_URL: undefined }),
      NOW,
    );

    expect(report.spendAnomaly.deliveryUnconfigured).toBe(true);
    expect(await episodes()).toHaveLength(1);
    expect(delivered).toEqual([]);
  });

  it("evaluates a window exactly once however often the cron ticks", async () => {
    await seedFlatBaseline("once", 2);
    await seedHour("once", 0, 80, 40);

    const first = await runScheduledTick(bindings(), NOW);
    // Four more ticks inside the same hour, which is what the every-minute
    // Cron Trigger actually does.
    const rest = [];
    for (let minute = 1; minute <= 4; minute += 1) {
      rest.push(await runScheduledTick(bindings(), NOW + minute * 60));
    }

    expect(first.spendAnomaly.opened).toBe(1);
    expect(rest.map((report) => report.spendAnomaly.skipped)).toEqual([
      "already_evaluated",
      "already_evaluated",
      "already_evaluated",
      "already_evaluated",
    ]);
    expect(delivered).toHaveLength(1);
    expect((await episodes())[0]?.windows_seen).toBe(1);
  });
});

describe("forecast overrun — the leg that works from a tenant's first hour", () => {
  it("alerts before the budget is hit, with no baseline at all", async () => {
    // Three hours old, so `burn_rate_spike` is `insufficient_baseline` and
    // silent. $600 already spent against a $1,000 budget with half a month
    // left: at $200/hour the budget is gone before tomorrow.
    await seedHour("fresh", 2, 200, 20);
    await seedHour("fresh", 1, 200, 20);
    await seedHour("fresh", 0, 200, 20);
    await setPolicy("fresh", { monthly_budget_usd: 1000 });

    await runScheduledTick(bindings(), NOW);

    const open = await episodes();
    expect(open).toHaveLength(1);
    expect(open[0]?.signal).toBe("forecast_overrun");
    expect(open[0]?.severity).toBe("critical");
    expect(delivered).toHaveLength(1);
    expect(delivered[0]?.body.projected_usd).toBeGreaterThan(1000);
    expect(delivered[0]?.body.budget_usd).toBe(1000);
    expect(String(delivered[0]?.body.means)).toContain("linear extrapolation");
  });

  it("says nothing about a tenant with no budget configured", async () => {
    // There is nothing to overrun. Inventing a budget would be alerting on a
    // number the operator never set — the same class of error as a borrowed
    // baseline.
    await seedHour("nobudget", 2, 200, 20);
    await seedHour("nobudget", 1, 200, 20);
    await seedHour("nobudget", 0, 200, 20);

    await runScheduledTick(bindings(), NOW);

    expect(await episodes()).toEqual([]);
  });

  it("says nothing about the first expensive request of a billing period", async () => {
    // $40 against a $100,000 budget projects to a large number and means
    // nothing at all. `forecast_min_pct` is the guard, and without it this is
    // the loudest false positive the forecast leg has.
    await seedHour("early", 0, 40, 4);
    await setPolicy("early", { monthly_budget_usd: 100_000 });

    await runScheduledTick(bindings(), NOW);

    expect(await episodes()).toEqual([]);
    expect(delivered).toEqual([]);
  });
});

describe("auto-throttle", () => {
  it("does nothing unless the tenant configured an RPM", async () => {
    await seedFlatBaseline("nobrake", 2);
    await seedHour("nobrake", 0, 80, 40);

    const report = await runScheduledTick(bindings(), NOW);

    expect(report.spendAnomaly.opened).toBe(1);
    expect(report.spendAnomaly.throttled).toBe(0);
    expect(await throttles()).toEqual([]);
  });

  it("writes an EXPIRING throttle when a critical episode opens", async () => {
    await seedFlatBaseline("brake", 2);
    await seedHour("brake", 0, 80, 40);
    await setPolicy("brake", { spend_anomaly_auto_throttle_rpm: 5 });

    const report = await runScheduledTick(bindings(), NOW);

    expect(report.spendAnomaly.throttled).toBe(1);
    const rows = await throttles();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.scope_id).toBe("brake");
    expect(rows[0]?.rpm_limit).toBe(5);
    // EXPIRING is the load-bearing half. The control plane may never run again,
    // and a throttle with nothing left to lift it is an outage whose cause is
    // invisible from the request path.
    expect(rows[0]?.expires_at_unix).toBe(NOW + 3_600);
    expect(delivered[0]?.body.auto_throttled_rpm).toBe(5);

    // The SAME row is shadow-written into the owning tenant's object, so the
    // DO-side `spend_throttles` table is already populated when the admission
    // readers are later cut over to it (the deploy-ordering invariant).
    const shadow = await tenantThrottles();
    expect(shadow).toHaveLength(1);
    expect(shadow[0]?.scope_id).toBe("brake");
    expect(shadow[0]?.rpm_limit).toBe(5);
    expect(shadow[0]?.expires_at_unix).toBe(NOW + 3_600);
  });

  it("does not throttle on a warning", async () => {
    // 5x the baseline is above the 4x ratio bar and below the 10x critical one.
    // The brake is the only leg that changes what the gateway does to live
    // traffic, and a warning is explicitly not enough to pull it.
    await seedFlatBaseline("mild", 2);
    await seedHour("mild", 0, 12, 6);
    await setPolicy("mild", { spend_anomaly_auto_throttle_rpm: 5 });

    const report = await runScheduledTick(bindings(), NOW);

    expect(report.spendAnomaly.opened).toBe(1);
    expect(report.spendAnomaly.throttled).toBe(0);
    expect(await throttles()).toEqual([]);
  });

  /**
   * THE BRAKE, ON A TENANT THAT SHOULD BE SILENT.
   *
   * Every other test in this block starts from a tenant that IS anomalous and
   * asks whether the brake was pulled. None of them can catch the failure that
   * matters most: the detector being WRONG and the brake being pulled anyway.
   * A false alert is a channel an operator learns to mute; a false throttle is
   * an outage we caused, on live traffic, for a customer who did nothing.
   *
   * The tenant here is flat $1/hour with a budget it is nowhere near — $383
   * projected against $400 — so the correct behaviour is complete silence, and
   * the assertion is that turning `spend_anomaly_auto_throttle_rpm` on does not
   * change that.
   */
  it("keeps the brake off for a steady tenant that is inside its budget", async () => {
    await seedFlatBaseline("steady", 1);
    await seedHour("steady", 0, 1, 4);
    await setPolicy("steady", {
      monthly_budget_usd: 400,
      spend_anomaly_auto_throttle_rpm: 5,
    });

    const report = await runScheduledTick(bindings(), NOW);

    // $25 month-to-date is above the 5% forecast floor, so the forecast leg DID
    // speak; it said "within budget" ($25 + $1/h * 358h = $383 < $400).
    expect(report.spendAnomaly.evaluated).toBe(1);
    // The brake first, because it is the assertion with a customer behind it.
    expect(await throttles()).toEqual([]);
    expect(report.spendAnomaly.throttled).toBe(0);
    expect(await episodes()).toEqual([]);
    expect(delivered).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The knobs, held against what they actually do
// ---------------------------------------------------------------------------

describe("the forecast is scaled by the window the observation was MEASURED over", () => {
  /**
   * The defect this pins: `observedUsd` is a sum over the FLEET bucket
   * (`readSpendBuckets`, one `GROUP BY` at `SPEND_ANOMALY_WINDOW_SECS`), and
   * dividing the remaining period by any OTHER number turns a flat tenant into
   * a critical `forecast_overrun`. The episode row already records the width the
   * observation came from, so the projection is checked against the ROW rather
   * than against a constant — the two cannot drift apart again without this
   * assertion breaking.
   */
  it("recomputes to exactly what the episode row's own window_secs implies", async () => {
    await seedHour("scaled", 2, 200, 20);
    await seedHour("scaled", 1, 200, 20);
    await seedHour("scaled", 0, 200, 20);
    await setPolicy("scaled", { monthly_budget_usd: 1_000 });

    await runScheduledTick(bindings(), NOW);

    const rows = await episodes();
    expect(rows).toHaveLength(1);
    const row = rows[0] as EpisodeRow;
    expect(row.signal).toBe("forecast_overrun");

    const detail = JSON.parse(row.detail_json ?? "{}") as Record<string, number>;
    const periodEnd = monthBoundsUnix(row.window_start_unix).endUnix;
    const remainingSecs = periodEnd - (row.window_start_unix + row.window_secs);
    const expected =
      (detail.period_spend_usd as number) + row.observed_usd * (remainingSecs / row.window_secs);

    expect(row.window_secs).toBe(HOUR);
    expect(row.projected_usd).toBeCloseTo(expected, 6);
    // …and the arithmetic really is load-bearing rather than a tautology of two
    // numbers written by the same statement: $600 spent at $200/hour with 358
    // hours of November left is $72,200.
    expect(row.projected_usd).toBeCloseTo(72_200, 6);
  });
});

describe("spend_anomaly_baseline_windows is the width of the baseline", () => {
  /**
   * The defect this pins: the column was read into `SpendAnomalyTuning` and the
   * pass then sliced the baseline from the SHIPPED DEFAULT, so an operator who
   * set it to 4 got a 24-window baseline and an episode that reported
   * `baseline_windows 24` back at them.
   *
   * The tenant below is built so the two widths disagree in the loudest
   * possible way: the last four hours are $2 and the twenty before them are
   * $80. A 4-window baseline has a median of $2 and a $8 bar, which a $12 hour
   * clears; a 24-window baseline has a median of $80 and a $320 bar, which it
   * does not come near. So `baseline_usd` alone says which width was used.
   */
  it("compares against the four windows the operator asked for, not twenty-four", async () => {
    for (let index = 5; index <= 24; index += 1) await seedHour("narrow", index, 80, 4);
    for (let index = 1; index <= 4; index += 1) await seedHour("narrow", index, 2, 4);
    await seedHour("narrow", 0, 12, 6);
    await setPolicy("narrow", {
      spend_anomaly_baseline_windows: 4,
      // The two cold-start gates default to 12 and 6, both of which a 4-window
      // baseline fails by construction. An operator narrowing the baseline has
      // to narrow these with it, and the ladder in `docs/` says so.
      spend_anomaly_min_baseline_windows: 4,
      spend_anomaly_min_active_windows: 4,
    });

    await runScheduledTick(bindings(), NOW);

    const rows = await episodes();
    expect(rows).toHaveLength(1);
    const row = rows[0] as EpisodeRow;
    expect(row.signal).toBe("burn_rate_spike");
    expect(row.baseline_usd).toBeCloseTo(2, 6);
    expect(row.threshold_usd).toBeCloseTo(8, 6);
    expect(row.bound_by).toBe("ratio");
    // The evidence the operator reads back. `24` here was the audited defect.
    expect(row.baseline_windows).toBe(4);
    expect(row.active_windows).toBe(4);
  });

  it("FETCHES as far back as the widest baseline any policy asks for", async () => {
    // Narrowing the baseline is free — the data is already in hand. WIDENING it
    // is not: the fleet bucket query has to reach further back, or the extra
    // windows are simply absent and the knob is inert again in the one
    // direction an operator most often wants it.
    //
    // Two days, opposite shapes: $80/hour on the older day, $2/hour on the
    // newer one, and a $500 hour to judge. Across 48 windows the median is $41
    // and the robust bar (MAD $39) is $214; across the 24 that a
    // default-width fetch would return it is $2 with an $8 bar. The recorded
    // `baseline_usd` therefore says which query ran.
    for (let index = 25; index <= 48; index += 1) await seedHour("wideband", index, 80, 4);
    for (let index = 1; index <= 24; index += 1) await seedHour("wideband", index, 2, 4);
    await seedHour("wideband", 0, 500, 10);
    await setPolicy("wideband", { spend_anomaly_baseline_windows: 48 });

    await runScheduledTick(bindings(), NOW);

    const rows = await episodes();
    expect(rows).toHaveLength(1);
    const row = rows[0] as EpisodeRow;
    expect(row.baseline_windows).toBe(48);
    expect(row.baseline_usd).toBeCloseTo(41, 6);
    expect(row.bound_by).toBe("robust");
    expect(row.threshold_usd).toBeCloseTo(41 + 3 * 1.4826 * 39, 6);
  });

  it("still uses twenty-four when the operator has not narrowed it", async () => {
    // The same traffic shape with no override: the $80 hours dominate the
    // median, the $12 hour is far below the bar, and NOTHING fires. Without
    // this, the test above would pass just as well against a hard-coded 4.
    for (let index = 5; index <= 24; index += 1) await seedHour("wide", index, 80, 4);
    for (let index = 1; index <= 4; index += 1) await seedHour("wide", index, 2, 4);
    await seedHour("wide", 0, 12, 6);

    await runScheduledTick(bindings(), NOW);

    expect(await episodes()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The operator's read surface
// ---------------------------------------------------------------------------

describe("GET /admin/v1/spend-anomalies", () => {
  const ACME_KEY = "spend-anomaly-acme";
  const OTHER_KEY = "spend-anomaly-other";

  interface ListBody {
    readonly object: string;
    readonly data: Record<string, unknown>[];
    readonly total: number;
  }

  async function read(secret: string, query = ""): Promise<ListBody> {
    const response = await SELF.fetch(`${BASE}/admin/v1/spend-anomalies${query}`, {
      headers: bearer(secret),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    return (await response.json()) as ListBody;
  }

  beforeEach(async () => {
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(ACME_KEY, "acme"), tenantKey(OTHER_KEY, "other")],
    });
    // Two tenants, both anomalous in the same window.
    await seedFlatBaseline("acme", 2);
    await seedHour("acme", 0, 80, 40);
    await seedFlatBaseline("other", 3);
    await seedHour("other", 0, 90, 40);
    await runScheduledTick(bindings(), NOW);
  });

  it("publishes the evidence an operator needs to answer 'why did this fire'", async () => {
    const body = await read(operatorKey.secret, "?scope_id=acme");
    const acme = body.data.find((row) => row.scope_id === "acme");
    expect(acme?.object).toBe("spend_anomaly");
    expect(acme?.status).toBe("open");
    expect(acme?.signal).toBe("burn_rate_spike");
    expect(acme?.severity).toBe("critical");
    expect(acme?.baseline_usd).toBeCloseTo(2, 6);
    expect(acme?.threshold_usd).toBeCloseTo(8, 6);
    expect(acme?.bound_by).toBe("ratio");
    expect(acme?.baseline_windows).toBe(24);
    expect(acme?.active_windows).toBe(24);
    // The two numbers that make the episode model legible side by side.
    expect(acme?.windows_seen).toBe(1);
    expect(acme?.notified_count).toBe(1);
  });

  it("fences a tenant to its own episodes, and counts only what it may see", async () => {
    // An episode names a customer and their hourly burn. A leak here is a
    // competitive-intelligence leak, not merely a privacy one.
    const operator = await read(operatorKey.secret);
    expect(operator.total).toBe(2);
    expect(operator.data.map((row) => row.scope_id).sort()).toEqual(["acme", "other"]);

    const acme = await read(ACME_KEY);
    expect(acme.total).toBe(1);
    expect(acme.data.map((row) => row.scope_id)).toEqual(["acme"]);

    const other = await read(OTHER_KEY);
    expect(other.total).toBe(1);
    expect(other.data.map((row) => row.scope_id)).toEqual(["other"]);
  });

  it("cannot be widened by asking for someone else's tenant", async () => {
    // The `?scope_id=` filter is AND-ed with the fence, never a replacement for
    // it — a filter that REPLACED the fence would be a one-parameter
    // cross-tenant read of the most sensitive report in the product.
    const acme = await read(ACME_KEY, "?scope_id=other");
    expect(acme.total).toBe(0);
    expect(acme.data).toEqual([]);

    // …and it really is a working filter for the operator, so the empty set
    // above is the fence biting rather than the parameter being ignored.
    const operator = await read(operatorKey.secret, "?scope_id=other");
    expect(operator.data.map((row) => row.scope_id)).toEqual(["other"]);
  });

  it("separates the incident view from the history", async () => {
    expect((await read(operatorKey.secret, "?status=open")).total).toBe(2);
    expect((await read(operatorKey.secret, "?status=resolved")).total).toBe(0);
    expect((await read(operatorKey.secret, "?signal=forecast_overrun")).total).toBe(0);
    expect((await read(operatorKey.secret, "?severity=critical")).total).toBe(2);
  });

  it("bounds a fleet read to a roster page and reports whether more remain", async () => {
    // A fleet read is a live fan-out over the tenant OBJECTS — there is no
    // shared table to scan — so the response carries the roster page an operator
    // walks with `?tenant_offset=`. Every registered tenant fits under one page
    // here, so the whole roster is covered in one request and nothing remains.
    const response = await SELF.fetch(`${BASE}/admin/v1/spend-anomalies`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    const body = (await response.json()) as ListBody & {
      readonly tenant_page: {
        readonly offset: number;
        readonly limit: number;
        readonly total: number;
        readonly has_more: boolean;
      };
    };
    expect(body.tenant_page.offset).toBe(0);
    expect(body.tenant_page.limit).toBe(FLEET_FANOUT_MAX_TENANTS);
    expect(body.tenant_page.total).toBe(ANOMALY_TENANTS.length);
    expect(body.tenant_page.has_more).toBe(false);
    // The two anomalous tenants are found by reading their objects, not a mirror.
    expect(body.total).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Tuning through the surface an operator actually has
// ---------------------------------------------------------------------------

describe("PUT /admin/v1/quota-policies/tenant/{id} tunes the detector", () => {
  /**
   * The gap this closes, stated because the tree has shipped it before: #692's
   * `online_eval_*` opt-in columns are read by the gateway and settable through
   * NO admin operation at all, because `projectQuotaPolicy` writes a fixed
   * column list nobody extended. A knob an operator cannot turn is not a knob,
   * and "it is tunable" would be a claim with nothing behind it.
   */
  beforeEach(() => {
    arm({ store: "d1", staticKeys: [operatorKey] });
  });

  /** `POST /admin/v1/quota-policies` — the create leg of the same group. */
  async function putPolicy(body: Record<string, unknown>): Promise<Response> {
    return await SELF.fetch(`${BASE}/admin/v1/quota-policies`, {
      method: "POST",
      headers: { ...bearer(operatorKey.secret), "content-type": "application/json" },
      body: JSON.stringify({ scope_type: "tenant", scope_id: "noisy", ...body }),
    });
  }

  it("carries the tuning through to the row the detector reads", async () => {
    const response = await putPolicy({ spend_anomaly_ratio: 100, spend_anomaly_min_window_usd: 5 });
    expect(response.status, await response.clone().text()).toBe(201);

    // A tenant whose 40x spike now sits UNDER its own 100x bar.
    await seedFlatBaseline("noisy", 2);
    await seedHour("noisy", 0, 80, 40);
    await runScheduledTick(bindings(), NOW);

    expect(await episodes()).toEqual([]);
  });

  it("refuses a baseline wider than the pass is willing to fetch", async () => {
    // The pass widens ONE fleet query to the largest baseline any policy holds,
    // so a stray `1000` here is not this tenant's problem — it is every
    // tenant's, as a `request_logs` scan back to six weeks ago on every tick.
    // `tuningFromRow` also falls back above the bound, but a 201 followed by
    // silent clamping is the "operator believes they tuned something" shape
    // this whole slice was bounced for.
    const response = await putPolicy({ spend_anomaly_baseline_windows: 1_000 });
    expect(response.status, await response.clone().text()).toBe(400);
    expect(await response.text()).toContain("spend_anomaly_baseline_windows");
  });

  it("refuses a tuning value that is not a number instead of silently defaulting", async () => {
    // `adminRecordSchema` is a Zod `passthrough()`, so without the explicit
    // field this would be ACCEPTED, projected as NULL, and fall back to 4x — an
    // operator who believes they raised the bar, still at the default, holding
    // a 200.
    const response = await putPolicy({ spend_anomaly_ratio: "one hundred" });
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("spend_anomaly_ratio");
  });
});
