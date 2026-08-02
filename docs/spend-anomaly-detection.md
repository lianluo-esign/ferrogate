# Spend anomaly detection and forecast alerts

*Issue #697. Implementation: `apps/control-plane/src/finops/`, migration
`sql/d1-ts/control/0010_spend_anomaly.sql`, read surface
`GET /admin/v1/spend-anomalies`, enforcement
`apps/{gateway,mcp,agent-runtime}/src/**/quota.ts`.*

---

## The problem this is for

Budget alerting before this was a **threshold on a cumulative number**: the
gateway compared month-to-date spend against
`quota_policies.monthly_budget_usd` and fired a webhook at 80 / 90 / 100 %
(#170). A runaway agent loop crosses 80 % and 100 % within minutes of each
other, so the first notification an operator receives is already too late to be
actionable — and a tenant with no budget configured got nothing at all, because
a percentage of `NULL` is `NULL`.

Nothing modelled the **rate**. #677 made per-request cost queryable; nobody was
watching it.

---

## What an alert MEANS

Read this before acting on one. #692 established the rule that a number
presented as one thing while actually being a proxy for another is worse than
no number; the same discipline applies to an alert.

### `burn_rate_spike`

> In the closed window `[window_start_unix, +window_secs)`, this tenant's
> **priced** spend was `observed_usd`, which exceeded `threshold_usd` — a
> threshold derived from this tenant's **own** preceding windows, by the leg
> named in `bound_by`.

It does **not** say the spend was wrong, wasteful, unauthorised, or that a loop
is running. It says the tenant is spending unlike its own recent self. The
judgement stays with the operator; the alert is what makes the judgement
possible before the invoice does.

### `forecast_overrun`

> If this tenant keeps spending at the rate observed in that same closed
> window, month-to-date spend reaches `projected_usd` by the end of the billing
> period, which is over `budget_usd`.

It is a **linear extrapolation of one window**, not a model. It claims "the
current rate does not fit the budget" — which is still a true and actionable
claim when the rate later falls, because it was a fact about that rate. It does
**not** predict what the tenant will actually spend.

Both sentences travel with the webhook, in its `means` field, so the reading
cannot be lost between the detector and a Slack message.

---

## What neither signal can catch

Stated so nobody buys the wrong instrument. Each is asserted in
`apps/control-plane/test/spend-detector-units.test.ts`, not merely written here.

| blind spot | why | what covers it |
|---|---|---|
| a runaway that was **already running** when the baseline was collected | it *becomes* the baseline; deviation-from-self is structurally blind to a level shift older than its lookback | `forecast_overrun`, and only for a tenant with a budget |
| a **slow creep** — 5 %/day compounding | never deviates from its own recent past by enough to bind | `forecast_overrun`, same caveat |
| a **burst shorter than the window** | $400 in one minute of a $2,000 hour is not distinguishable from the hour | nothing here; shorten `spend_anomaly_window_secs` and accept the noise |
| anything for a tenant below the cold-start gates | deliberate silence — see below | the invoice |
| spend that is metered but **not priced** (#663) | contributes nothing to `observed_usd` | nothing; the failure direction is *quieter*, never louder |

---

## How the burn-rate signal decides

Three bars, **all** of which a window must clear. The threshold is their `max`
and the episode records which one bound.

| bar | value | the false positive it exists to stop |
|---|---|---|
| `ratio` | `median × spend_anomaly_ratio` | ordinary variance around a stable rate |
| `robust` | `median + 3 × 1.4826 × MAD` | a tenant whose normal *is* spiky — its MAD is large, so its bar is high |
| `floor` | `spend_anomaly_min_window_usd` | $0.02 → $0.80 is a 40× spike and is nobody's incident |

**Median and MAD, never mean and standard deviation.** One previous spike
inflates both the mean and the sigma, so a z-score detector is blind to the
*second* occurrence of a repeating problem. The median has a 50 % breakdown
point. This is load-bearing rather than stylistic:
`test/spend-anomaly.test.ts` has a test ("still catches a spike when
yesterday's incident is in the baseline") that goes red the moment the baseline
becomes a mean.

Severity escalates on the **ratio** bar only. A tenant with a huge MAD can
clear a very high robust bar with an unremarkable multiple of its own median,
and paging `critical` for ordinary burstiness is how a channel gets muted.

---

## Cold start and sparsity

The case a naive implementation gets loudest and most wrong. With no history
the median is 0, the MAD is 0, every bar collapses to 0, and a new tenant's
first dollar is an infinite deviation. Three gates decide it instead of letting
the arithmetic decide:

1. `observed_windows ≥ spend_anomaly_min_baseline_windows` (default 12 of 24),
   else `insufficient_baseline` and **silence**;
2. `active_windows ≥ spend_anomaly_min_active_windows` (default 6) — the
   sparsity gate. A tenant with three requests a day has ~3 non-zero hours in
   24 and no distribution at all;
3. the absolute floor above.

A zero-spend window **counts as observed** and **does not count as active**.
"This tenant spent nothing that hour" is a real fact about their traffic shape.

**The default for a brand-new tenant is therefore: the baseline leg is SILENT,
and the forecast leg is not** — because the forecast is anchored on a number
the operator set rather than on history that does not exist yet. Nothing
fabricates a fleet-wide default baseline; a borrowed baseline would produce
alerts about a distribution the tenant never had.

---

## Alerting is a side effect with a cost

### Episodes, not detections

The ledger holds **one row per episode**, not per detection. An episode opens
on the first window that fires, absorbs every consecutive window that keeps
firing, and closes on the first that does not.

A notification is delivered when, and only when:

1. the episode **opens** — new information;
2. the severity **escalates past the episode's peak** — "warning → critical" is
   news, and an operator wants it immediately;
3. `spend_anomaly_cooldown_secs` (default **6 h**) has elapsed since the last
   notification and it is **still** firing — a heartbeat, not a repeat.

**Six hours of a stuck loop at the defaults is 2 notifications, not 72.**
De-escalation and resolution are silent.

Escalation is measured against the episode's `peak_severity`, not its previous
severity, so a flapping incident cannot page on every window.

### Delivery

A signed webhook POST — HMAC-SHA256, the same scheme and headers as the #170
budget alert, so one receiver verifies both. `type: "spend_anomaly"` is what
tells them apart.

**There is no retry.** The next window is the retry: a real episode is still
real in an hour, and the pass will notify again when the cooldown elapses.
What is lost is the first notification of a short episode when the receiver
happens to be down — and that loss is *visible*, because the episode row
survives with `notified_count = 0`, which is exactly the query for "what did my
receiver drop".

**Detection does not require a configured webhook.** The pass is two
fleet-wide aggregate queries on a cron tick whether or not anything is
delivered, and the ledger is itself the product — an operator who has not wired
a receiver yet still gets the history for the period *before* they wired one.

---

## How an operator tunes it

Everything rides the tenant's quota policy, so tuning is one call:

```
PUT /admin/v1/quota-policies/tenant/{tenant_id}
{ "spend_anomaly_ratio": 8, "spend_anomaly_min_window_usd": 25 }
```

| complaint | knob |
|---|---|
| "it fires on our nightly batch" | `spend_anomaly_ratio` up, or `spend_anomaly_window_secs` up to cover the batch |
| "it fires on trivial amounts" | `spend_anomaly_min_window_usd` up |
| "it pages too often for one incident" | `spend_anomaly_cooldown_secs` up |
| "the forecast fires at the start of a month" | `spend_anomaly_forecast_min_pct` up |
| "we do not want this tenant watched at all" | `spend_anomaly_enabled = 0` |

`bound_by` on every episode answers the first column, so the right knob is
readable off the row rather than guessed.

Detection is **on by default** for every tenant. The asymmetry with #692's
opt-in evaluation is deliberate: evaluation copies a customer's traffic to a
third party and needs consent, while this reads money the platform already
recorded and tells the platform's own operator about it.

---

## Auto-throttle

Off unless `spend_anomaly_auto_throttle_rpm` is set — it is the only leg that
changes what the gateway does to a customer's live traffic.

When a **critical** episode opens for a tenant that configured it, the pass
writes a `spend_throttles` row. All three admission enforcers (gateway, MCP,
agent-runtime) read that table in the `db.batch()` they already issue for the
quota chain, so it costs one statement and no extra round trip.

Two properties make it safe for an *automated* writer to touch a table the
request path reads:

- **it can only ever NARROW.** It contributes one field, `rpm_limit`, as a
  `min` against whatever the operator configured. It cannot raise a limit,
  enable a disabled scope, widen a model allowlist or grant a budget. The worst
  a detector bug can do is refuse traffic — loud, recoverable, self-expiring.
- **every row EXPIRES** (`spend_anomaly_throttle_ttl_secs`, default 1 h),
  filtered in SQL on every read rather than swept by a job. A throttle whose
  lifting depends on a cron that may never run again is a throttle that
  outlives its incident forever, with nothing on the request path saying why.

The table is registered as an authority of the `admission` control in
`apps/gateway/test/fleet-control-matrix.test.ts` §3, which is what forces all
three enforcers to read it — a throttle enforced in only one of them is one a
caller routes around by using a different surface.

---

## Cost and cadence

The pass rides the existing every-minute Cron Trigger
(`apps/control-plane/wrangler.toml`, `[triggers] crons`). The detection window
is an hour, so 59 of 60 ticks do nothing but one `INSERT OR IGNORE` into
`spend_anomaly_runs` — the single-flight claim.

The winner issues **two aggregate queries for the whole fleet** (windowed spend
and month-to-date spend, both `GROUP BY tenant`, both driving from
`idx_request_logs_tenant_started`) plus one read of the tenant-scope quota
policies. It does not fan out per tenant, which is what makes watching everyone
by default affordable.

That single-flight claim is also what makes the cooldown check safe: reading
"when did we last notify" and then deciding is a race in general, but behind
the claim there is exactly one evaluator per window. **That reasoning does not
survive being moved to the request path.**

---

## Where the numbers come from

There is no new counter and no new writer. Every figure is
`SUM(billing_events.event_json -> cost_usd)` joined to `request_logs` — the
same documents `D1LedgerStore.record` wrote in the same batch as the
`billing_ledger` row, i.e. #677's chargeback join grouped by hour instead of by
request.

A detector that alerted on a number the invoice does not agree with would be
the worst possible version of this feature.

The query is driven from `request_logs`, whose `tenant` column carries the
authenticated tenant, because `billing_events` has no tenant column of its own.
The cost of that direction is #677's, stated the same way: a `billing_events`
row whose request log has aged past retention contributes nothing, so the
detector under-observes rather than attributing a charge to nobody.

---

## Environment

| var | meaning |
|---|---|
| `SPEND_ANOMALY_WEBHOOK_URL` | delivery target. Unset ⇒ falls back to `BILLING_ALERTS_WEBHOOK_URL` |
| `SPEND_ANOMALY_WEBHOOK_TIMEOUT_SECS` | default 5 |
| `SPEND_ANOMALY_WEBHOOK_SIGNING_SECRET` | `wrangler secret put`, never `[vars]`. Falls back to `BILLING_ALERTS_WEBHOOK_SIGNING_SECRET` when the URL did |

A malformed value disables **delivery** and nothing else: a configuration typo
must cost a webhook, never the detection history.
