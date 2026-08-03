-- ===========================================================================
-- Spend burn-rate anomaly detection, forecast alerts and auto-throttle (#697)
--
-- ## What was wrong
--
-- Budget alerting was a THRESHOLD ON A CUMULATIVE NUMBER: month-to-date spend
-- against `quota_policies.monthly_budget_usd`, fired at
-- `alert_threshold_pcts_json` (#170). A runaway agent loop crosses 80% and 100%
-- within minutes of each other, so the first notification is already too late,
-- and a tenant with no `monthly_budget_usd` gets nothing at all — a percentage
-- of NULL is NULL. Nothing anywhere modelled the RATE.
--
-- ## WHAT AN ALERT FROM THIS TABLE MEANS — read this before acting on one
--
-- #692 established the rule that a number presented as one thing while actually
-- being a proxy for another is worse than no number. The same applies here, so
-- the meaning is written next to the storage rather than only in the code that
-- fills it.
--
-- A `burn_rate_spike` row means EXACTLY:
--
--   > in the closed window [window_start_unix, +window_secs), this scope's
--   > PRICED spend was `observed_usd`, which exceeded `threshold_usd` — a
--   > threshold derived from this scope's OWN preceding `baseline_windows`
--   > windows, by the leg named in `bound_by`.
--
-- It does NOT mean the spend was wrong, wasteful, unauthorised, or that a loop
-- is running. It means the scope is spending unlike its own recent self. The
-- judgement stays with the operator; this row is the thing that makes the
-- judgement possible before the invoice does.
--
-- A `forecast_overrun` row means EXACTLY:
--
--   > if this scope keeps spending at the rate observed in that same closed
--   > window, month-to-date spend reaches `projected_usd` by the end of the
--   > billing period, which is over `budget_usd`.
--
-- It is a LINEAR EXTRAPOLATION OF ONE WINDOW, not a model. It says "the current
-- rate does not fit the budget", which is the actionable claim; it does not
-- predict what the tenant will actually spend, and it will be wrong whenever
-- the rate changes — which for bursty agent traffic is most of the time.
--
-- ## WHAT NEITHER SIGNAL CAN CATCH, stated so nobody buys the wrong thing
--
--  1. A runaway that was ALREADY running when the baseline was collected. It
--     becomes the baseline. Deviation-from-self is structurally blind to a
--     level shift older than its lookback; `forecast_overrun` is the backstop,
--     and only for a scope with a budget configured.
--  2. A slow creep — 5%/day compounding never deviates from its own recent
--     past by enough to bind, and lands the same runaway bill a month later.
--     `forecast_overrun` is again the only leg that sees it.
--  3. A burst SHORTER than `window_secs`. A $400 minute inside an otherwise
--     idle hour is averaged into a $400 hour, which is caught; a $400 minute
--     inside a $2,000 hour is not distinguishable from the hour.
--  4. Anything a scope with no budget and no baseline does. See the cold-start
--     rules below: the answer there is deliberate SILENCE, not a guess.
--  5. Spend that is metered but NOT PRICED (#663 leaves a durable row with no
--     `cost_usd`). It contributes nothing to `observed_usd`, so a pricing gap
--     makes this detector quieter, never louder. That direction is chosen: the
--     alternative is alerting on an unknown.
--
-- ## Why the CONTROL database
--
-- The same rule `0004_guardrail_evaluations.sql` and `0009_online_eval.sql` set
-- out. The read that matters is #677's join — `request_logs` (whose `tenant`
-- column is the authenticated tenant) against `billing_events` (whose
-- `cost_usd` is what the ledger billed) — and that is a single-database query
-- here and an impossible one across per-tenant databases, because D1 has no
-- read spanning two databases. The detector derives its numbers from the SAME
-- documents `billing_ledger` was written from, so it can never disagree with
-- the invoice about what a request cost.
--
-- ## The tuning ride on `quota_policies`
--
-- Same table, same argument as #678's attribution tags, #681's residency and
-- #692's evaluation opt-in: it is already the per-scope governance row, already
-- has RBAC, already carries the #185 scoped-authorization rule, and already
-- holds `monthly_budget_usd`, which is the number the forecast leg is measured
-- against. A second policy table for the same money would be a second thing to
-- keep in sync.
--
-- Only `scope_type = 'tenant'` is consulted. A per-key baseline is thinner than
-- a per-tenant one by exactly the factor that turns a distribution into noise,
-- and a detector whose false-positive rate rises with the number of scopes it
-- watches is a detector that gets muted. `apps/control-plane/src/finops/`
-- states this and what it costs.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- Tuning. Every column is NULLABLE and every reader has a documented default,
-- so applying this migration changes the behaviour of nothing that was already
-- configured — and an operator tunes by writing ONE row, through the
-- `PUT /admin/v1/quota-policies/tenant/{id}` operation that already exists.
-- ---------------------------------------------------------------------------

-- The OPT-OUT. Default 1 (watching), unlike #692's evaluation opt-in, and the
-- asymmetry is deliberate: evaluation copies a customer's traffic to a third
-- party and needs consent, while this reads money the platform already recorded
-- and tells the platform's own operator about it. The issue's premise is that
-- nobody is watching; shipping it off by default would leave that true.
--
-- Detection is cheap enough to justify that: TWO aggregate queries per pass for
-- the WHOLE fleet, not per tenant.
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_enabled INTEGER NOT NULL DEFAULT 1;

-- There is deliberately NO `spend_anomaly_window_secs` column.
--
-- The window a rate is measured over is a FLEET constant
-- (`SPEND_ANOMALY_WINDOW_SECS`, 3600), because the pass buckets everybody with
-- one `GROUP BY`, aligns everybody on one grid and claims one `window_start_unix`
-- in `spend_anomaly_runs`. A per-scope width needs all three per distinct
-- width, which is the fan-out that would make watching every tenant by default
-- unaffordable — and a column that changed only ONE term of the arithmetic is
-- strictly worse than no column: it was shipped in an earlier revision of this
-- migration and, set to 600, turned a flat $1/hour tenant $25 into a `critical`
-- `forecast_overrun` projecting $2,173 that pulled its own auto-throttle.
-- `apps/control-plane/src/finops/detector.ts` carries the full account.

-- How many preceding windows form the baseline. Default 24 — one day, so a
-- scope is compared against its own daily shape rather than against a
-- fleet-wide notion of normal it never agreed to. Bounded at 168 (one week of
-- hourly windows): the pass widens its fleet bucket query to the LARGEST value
-- any policy holds, so an out-of-range value here would be one tenant making
-- every pass scan `request_logs` for everybody. Out of range falls back to 24.
--
-- Narrowing this does NOT relax `spend_anomaly_min_baseline_windows` (12) or
-- `spend_anomaly_min_active_windows` (6) with it: a 4-window baseline fails
-- both cold-start gates by construction and the burn-rate leg stays SILENT
-- until those are lowered too. That is deliberate — the gates exist so a thin
-- baseline is not treated as a distribution — but it means this knob is set in
-- company, not alone.
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_baseline_windows INTEGER;

-- COLD START, part 1: how many of those windows must actually have been
-- OBSERVED before the baseline leg may speak. Default 12. Below it the decision
-- is `insufficient_baseline` and nothing fires — NOT "treat the missing history
-- as zero", which is the arithmetic a naive implementation lets decide for it
-- and which makes every new tenant's first dollar an infinite ratio.
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_min_baseline_windows INTEGER;

-- COLD START, part 2 — SPARSITY: how many baseline windows must be NON-ZERO.
-- Default 6. A tenant with three requests a day has no distribution: its median
-- and its MAD are both zero, so every threshold collapses to zero and every
-- dollar is an infinite deviation. This is the gate that answers that case
-- deliberately instead of letting the division do it.
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_min_active_windows INTEGER;

-- THE ABSOLUTE FLOOR. Default 1.0 USD. No burn-rate alert ever fires for a
-- window that spent less than this, whatever the ratio. $0.02 -> $0.80 is a
-- 40x spike and is not worth waking anyone for; it is also the single most
-- common shape of a false positive in a ratio detector.
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_min_window_usd REAL;

-- The operator's sensitivity knob: the multiple of the baseline MEDIAN a window
-- must exceed. Default 4.0 for `warning`, 10.0 for `critical`. Raise the first
-- when a tenant is bursty by nature; that is the intended response to a noisy
-- alert, and it is one UPDATE.
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_ratio REAL;
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_critical_ratio REAL;

-- DEDUPLICATION. Default 21600 (6 hours). An episode that persists notifies on
-- open, on every severity escalation, and then at most once per this interval —
-- so six hours of a stuck loop is 2 notifications, not 72. Repeating an alert
-- every five minutes is how a page gets muted, which converts the next real
-- alert into noise too.
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_cooldown_secs INTEGER;

-- FORECAST GUARD: month-to-date spend must already be at least this percent of
-- the budget before the forecast leg may speak. Default 5.0. Without it, the
-- first expensive request of a new billing period extrapolates to a number with
-- no information in it — the classic "your $3 lunch projects to $90,000/year".
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_forecast_min_pct REAL;

-- AUTO-THROTTLE, off unless set. The RPM ceiling written into `spend_throttles`
-- when a CRITICAL episode opens. NULL means the detector only ever observes and
-- notifies — which is the right default, because this is the one leg that
-- changes what the gateway does to a customer's live traffic.
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_auto_throttle_rpm INTEGER;

-- How long an auto-throttle lasts. Default 3600. It EXPIRES rather than
-- persisting, and that is load-bearing: the control plane may never run again,
-- and a throttle that outlives the incident with nothing left to lift it is an
-- outage whose cause is invisible from the request path.
ALTER TABLE quota_policies ADD COLUMN spend_anomaly_throttle_ttl_secs INTEGER;

-- ---------------------------------------------------------------------------
-- The episode ledger.
--
-- ONE ROW PER EPISODE, not one per detection. An episode opens the first window
-- a signal fires for a scope, absorbs every consecutive window that keeps
-- firing (`windows_seen`, `last_seen_unix`, `peak_severity`), and CLOSES the
-- first window that does not (`resolved_at_unix`). A later detection opens a
-- new one.
--
-- Recording every detection instead would make the operator's "what is
-- happening right now" question a GROUP BY over a table that grows once per
-- window per scope forever, and would put the notification count and the
-- detection count in the same column — which is exactly the conflation that
-- turns a six-hour incident into 72 pages.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS spend_anomaly_episodes (
    -- `{scope_type}:{scope_id}:{signal}:{opened_window_start}`. Deterministic so
    -- an interrupted pass that re-runs the same window re-derives the same id
    -- and its INSERT conflicts instead of forking a second episode.
    id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    -- `burn_rate_spike` | `forecast_overrun`. Two signals, never merged into one
    -- "anomaly": they answer different questions, have different blind spots
    -- and are tuned by different columns, and an operator who cannot tell which
    -- one fired cannot act on either.
    signal TEXT NOT NULL,
    -- `warning` | `critical`, as of `last_seen_unix`.
    severity TEXT NOT NULL,
    -- The worst severity this episode ever reached. The notification rule reads
    -- THIS, not `severity`: an episode that escalated to critical and fell back
    -- to warning must not re-notify as a fresh critical when it climbs again
    -- inside the same cooldown.
    peak_severity TEXT NOT NULL,
    window_start_unix INTEGER NOT NULL,
    window_secs INTEGER NOT NULL,
    opened_at_unix INTEGER NOT NULL,
    last_seen_unix INTEGER NOT NULL,
    resolved_at_unix INTEGER,
    windows_seen INTEGER NOT NULL DEFAULT 1,
    notified_count INTEGER NOT NULL DEFAULT 0,
    last_notified_unix INTEGER,
    -- The evidence, so an operator can answer "why did this fire" from the row
    -- alone. A detector whose decision cannot be reconstructed is one nobody
    -- can tune, and an untunable detector is a muted one.
    observed_usd REAL NOT NULL,
    baseline_usd REAL,
    threshold_usd REAL,
    -- `ratio` | `robust` | `floor` | `forecast` — WHICH bar bound. Three bars
    -- guard the burn-rate leg and the answer to a complaint about a false
    -- positive is different for each, so the row says which one it was.
    bound_by TEXT,
    baseline_windows INTEGER,
    active_windows INTEGER,
    projected_usd REAL,
    budget_usd REAL,
    period_month TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}'
);

-- THE ARBITER. At most one OPEN episode per (scope, signal) — a partial unique
-- index, so resolved episodes accumulate freely as history while the open one
-- is unique. `INSERT ... ON CONFLICT DO NOTHING` against it is what makes a
-- re-run of the same window idempotent rather than a second page.
CREATE UNIQUE INDEX IF NOT EXISTS idx_spend_anomaly_open
    ON spend_anomaly_episodes(scope_type, scope_id, signal)
    WHERE resolved_at_unix IS NULL;

-- The operator's read: newest first, optionally fenced to one tenant.
CREATE INDEX IF NOT EXISTS idx_spend_anomaly_scope_seen
    ON spend_anomaly_episodes(scope_id, last_seen_unix);

CREATE INDEX IF NOT EXISTS idx_spend_anomaly_seen
    ON spend_anomaly_episodes(last_seen_unix);

-- ---------------------------------------------------------------------------
-- Single-flight for the pass.
--
-- The Cron Trigger ticks every minute (`[triggers] crons = ["* * * * *"]`) and
-- the detection window is an hour, so 59 of every 60 ticks have nothing to do.
-- `INSERT OR IGNORE` on the window start is the claim: the winner evaluates,
-- everyone else returns `already_evaluated` after ONE write.
--
-- It is also what makes the cooldown check safe. Reading "when did we last
-- notify" and then inserting is a race on the request path; behind this claim
-- there is exactly one evaluator per window, so it is not one here. That
-- reasoning does not survive being moved to the gateway, which is why it is
-- written down.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS spend_anomaly_runs (
    window_start_unix INTEGER PRIMARY KEY,
    ran_at_unix INTEGER NOT NULL,
    scopes_evaluated INTEGER NOT NULL DEFAULT 0,
    episodes_opened INTEGER NOT NULL DEFAULT 0,
    notifications_sent INTEGER NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------------------
-- Auto-throttle.
--
-- Read by the GATEWAY on the admission path, in the same `db.batch()` that
-- already fetches the quota chain (`apps/gateway/src/ratelimit/quota.ts`), so
-- it costs one extra statement and no extra round trip. It is overlaid onto the
-- resolved quota as a `min` against `rpm_limit`, which means it can only ever
-- NARROW a limit — a throttle row can never widen, enable, or grant anything.
--
-- `expires_at_unix` is compared on every read rather than swept: a throttle
-- whose lifting depends on a background job that may not run is a throttle that
-- can outlive its incident forever.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS spend_throttles (
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    rpm_limit INTEGER NOT NULL,
    -- Free text for the operator reading `GET /admin/v1/spend-anomalies`; the
    -- machine-readable link is `episode_id`.
    reason TEXT NOT NULL,
    episode_id TEXT,
    created_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    PRIMARY KEY (scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_spend_throttles_expiry
    ON spend_throttles(expires_at_unix);
