-- ===========================================================================
-- Outcome metrics for canary and shadow splits (#693)
--
-- `packages/routing` splits traffic — a sticky canary percentage and a budgeted
-- shadow mirror — and until this migration nothing recorded WHICH ARM served a
-- request. Cost (#677), latency and status (#664) and eval scores (#692) all
-- existed per request and none of them could be grouped by arm, so "is the
-- canary better" was unanswerable from data the product already held.
--
-- Three changes, and the third is the one that could not be avoided.
--
-- ## 1. `request_logs` learns the arm
--
-- Which arm served a request is a DECISION FACT about that request, and
-- `request_logs` is the per-decision record — the same argument #691 made for
-- the delegation columns. Putting the arm here means the operational half of an
-- experiment (requests, error rate, latency) is a `GROUP BY` over a table that
-- already exists, already carries the tenant fence, and is already written on
-- every request including the refused ones.
--
-- Both columns are NULL for every request not in an experiment, which is almost
-- all of them.
--
-- ## 2. `online_eval_scores` learns the arm
--
-- The QUALITY half. #692's score row already carries `judge_model` and
-- `criterion_id`, which are the two axes a comparison may not cross; adding the
-- arm makes "same judge, same criterion, two arms" a single grouped read:
--
-- ```sql
-- SELECT experiment_arm, judge_model, criterion_id,
--        COUNT(*) AS n, SUM(score) AS total, SUM(score*score) AS total_sq
--   FROM online_eval_scores
--  WHERE experiment_id = ?1 AND tenant = ?2 AND scored_at_unix >= ?3
--  GROUP BY experiment_arm, judge_model, criterion_id;
-- ```
--
-- The grouping is the enforcement. `packages/routing/src/experiment.ts`
-- pairs arms only INSIDE one `(judge_model, criterion_id)` group, so two arms
-- scored by different judges have no shared group and cannot be subtracted —
-- they are reported incomparable instead. A schema that stored a single
-- `mean_score` per arm would have made that check impossible to write.
--
-- ## 3. `experiment_shadow_legs` — the arm that has no request log
--
-- A shadow mirror's response is NEVER delivered. It is not a client request, it
-- gets no `request_logs` row, and it must not get one: every count, latency
-- percentile and SIEM export over that table would silently start including
-- responses no customer ever received. So the shadow arm needs its own table,
-- and this is it — one row per mirrored dispatch, with the same operational
-- facts the request log carries for the served arms so the two can be reported
-- side by side without treating the arms asymmetrically.
--
-- ### WHO IS CHARGED, and why the column is not a column
--
-- There is no `charged_to` column here, and that is deliberate. The answer is a
-- function of the ARM — `armChargedTo` in `packages/routing/src/experiment.ts`
-- — so a shadow leg cannot be recorded as tenant-charged by any writer, and a
-- report cannot show shadow spend as if it landed on a customer's invoice. The
-- gateway backs that structurally: `inference/shadow.ts` has no code path to
-- `deps.usage.record`, to `billing_ledger`, to the billing outbox or to the TPM
-- governor, so a mirror cannot bill the tenant even by accident. The provider
-- still invoices the OPERATOR for these tokens; `cost_usd` here is that
-- operator-side cost, priced from the shadow route's own registry rates by the
-- same `routePriceSettledCostUsd` the served path settles with.
--
-- ### What is NOT stored
--
-- No prompt text and no completion text, exactly as `0009_online_eval.sql`
-- refuses them. The mirrored prompt exists only in flight. A shadow leg that is
-- also SCORED files its score in `online_eval_scores` under `leg_id` as the
-- `request_id`, with `experiment_arm = 'shadow'` — see the column comment
-- there. And a zero-data-retention tenant is never mirrored at all (#681,
-- `shadowMirrorFor`) and never sampled at all (#692,
-- `onlineEvalSamplingDecision`), so neither row exists for one.
-- ===========================================================================

ALTER TABLE request_logs ADD COLUMN experiment_id TEXT;
ALTER TABLE request_logs ADD COLUMN experiment_arm TEXT;

-- The operational aggregate: one experiment, arm-grouped, time-bounded.
CREATE INDEX IF NOT EXISTS idx_request_logs_experiment
    ON request_logs(experiment_id, experiment_arm, started_at_unix DESC);

ALTER TABLE online_eval_scores ADD COLUMN experiment_id TEXT;
-- `control` | `canary` | `shadow`. NULL for a score taken outside an
-- experiment, which is most of them.
ALTER TABLE online_eval_scores ADD COLUMN experiment_arm TEXT;

-- The quality aggregate. `judge_model` and `criterion_id` lead the arm on
-- purpose: they are the axes the comparison may not cross, so they are the ones
-- the grouped read must be able to walk without a scan.
CREATE INDEX IF NOT EXISTS idx_online_eval_scores_experiment
    ON online_eval_scores(experiment_id, criterion_id, judge_model, experiment_arm);

CREATE TABLE IF NOT EXISTS experiment_shadow_legs (
    -- `{client_request_id}~shadow`. DERIVED rather than random so a redelivered
    -- or retried mirror overwrites its own row instead of inflating the arm's
    -- sample — the same arbiter role `(request_id, criterion_id)` plays in
    -- `online_eval_scores`. It is also the id a shadow-arm SCORE is filed
    -- under, which is what keeps the score store single.
    leg_id            TEXT    NOT NULL PRIMARY KEY,
    -- The id the CLIENT was told for the request this mirrored. The join back
    -- to the served arm, and the reason the two arms are a PAIRED sample: both
    -- legs answered the same prompt.
    client_request_id TEXT    NOT NULL,
    experiment_id     TEXT    NOT NULL,
    tenant            TEXT    NOT NULL,
    project           TEXT,
    workspace         TEXT,
    api_key_id        TEXT,
    logical_model     TEXT    NOT NULL,
    provider          TEXT    NOT NULL,
    provider_model    TEXT    NOT NULL,
    -- The provider's status, or NULL when the mirror never got one (a transport
    -- failure, an adapter refusal, or a budget refusal recorded as a skip).
    status_code       INTEGER,
    -- Why the mirror produced no response: `shadow_budget_exhausted`,
    -- `provider_dispatch_error`, `adapter_refused`, … A leg that was refused
    -- before dispatch is still recorded, because an arm whose failures are
    -- invisible looks healthier than the served arm it is being compared to.
    error_code        TEXT,
    latency_ms        INTEGER,
    prompt_tokens     INTEGER,
    completion_tokens INTEGER,
    total_tokens      INTEGER,
    -- OPERATOR-side cost. See the header: nobody is billed for this row.
    cost_usd          REAL,
    observed_at_unix  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_experiment_shadow_legs_experiment
    ON experiment_shadow_legs(experiment_id, observed_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_experiment_shadow_legs_tenant
    ON experiment_shadow_legs(tenant, observed_at_unix DESC);
