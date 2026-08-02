-- ===========================================================================
-- `online_eval_scores` + `online_eval_regressions`, and the per-tenant OPT-IN
-- on `quota_policies` — online evaluation of sampled production traffic (#692)
--
-- ## What lands here, and what a row MEANS
--
-- One row per (request, criterion) for the fraction of traffic a tenant asked
-- to have evaluated. The row is NOT a measurement of correctness — there is no
-- ground truth in production, and if there were, the gateway would have served
-- it. A row says exactly:
--
--   > the judge model `judge_model`, shown this prompt and this response and
--   > asked criterion `criterion_id`, answered `score` at `scored_at_unix`.
--
-- That supports a RELATIVE comparison between two populations scored by the
-- same judge under the same criterion — before/after a model swap, canary vs
-- control — and nothing else. `apps/gateway/src/evals/policy.ts` states the
-- full reading, including what an operator must not conclude. It is written
-- there and repeated here because a schema outlives the code that fills it.
--
-- ## Why the CONTROL database
--
-- The same rule `0004_guardrail_evaluations.sql` sets out: these are single
-- global tables scanned time-ordered ACROSS tenants, their `tenant` column is a
-- composite storage key rather than a routing key, and the read that matters —
-- score joined to per-request COST (#677, `billing_events`) — is a
-- single-database query here and an impossible one in a per-tenant database,
-- because D1 has no read spanning two databases.
--
-- ## What is NOT stored, and this is the load-bearing part
--
-- **No prompt text and no completion text.** The captured content exists only
-- in flight: it is put on the Queue, shown to the judge, and dropped when the
-- consumer finishes. What survives is a number, the judge's one-sentence
-- reason, and the ids needed to join back. This is deliberate and it is what
-- keeps the durable footprint of this feature comparable to the request log's:
-- a durable copy of every sampled prompt would be a body archive, which is a
-- different product decision with its own residency, retention and redaction
-- questions (`requestlog/index.ts` refuses the same thing for the same reason).
--
-- `rationale` is the one field derived from content. It is the judge's own
-- sentence, bounded to 400 characters by the writer, and it is stored because a
-- score nobody can interrogate is a score nobody should act on. A tenant that
-- cannot accept even that must not opt in — and a ZERO-DATA-RETENTION tenant
-- (#681) is never sampled at all, which is enforced in
-- `evals/policy.ts::onlineEvalSamplingDecision` before any capture happens.
--
-- ## The opt-in columns ride `quota_policies`
--
-- Same table, same argument as #678's attribution tags and #681's residency:
-- it is already the per-scope governance row, already has RBAC, already carries
-- the #185 scoped-authorization rule, and is already read on the admission
-- path. Only `scope_type = 'tenant'` is consulted — consent to have traffic
-- copied to a judge belongs to the legal entity, and a project-scoped row that
-- widened it would be consent given by somebody who cannot give it.
--
-- Every column is NULLABLE or defaults OFF. Applying this migration changes the
-- behaviour of exactly nothing: with `online_eval_enabled = 0` (the default)
-- `evals/source.ts` reads the row as "this tenant did not opt in".
-- ===========================================================================

ALTER TABLE quota_policies ADD COLUMN online_eval_enabled INTEGER NOT NULL DEFAULT 0;
-- Fraction of the sampling unit to evaluate, in [0, 1]. NULL is refused by the
-- reader for an ENABLED row rather than defaulted: a tenant that switched
-- evaluation on and did not say how much of their traffic to copy has not
-- expressed a policy, and picking one for them is the decision this whole
-- slice exists to avoid making on their behalf.
ALTER TABLE quota_policies ADD COLUMN online_eval_sample_rate REAL;
-- `'request'` (default, per-request buckets) or `'conversation'` (whole
-- conversations in or out, which is the only unit that can compare a
-- conversation against itself).
ALTER TABLE quota_policies ADD COLUMN online_eval_sampling_unit TEXT;
-- The measuring instrument. Required for an enabled row: choosing a judge for
-- the tenant would make the meaning of their scores depend on a default they
-- never agreed to, and would change it silently the day the default changed.
ALTER TABLE quota_policies ADD COLUMN online_eval_judge_model TEXT;
-- JSON array of `{ "id": "...", "definition": "..." }`. The `id` is the series
-- key a trend is read along; the `definition` is what the judge is literally
-- asked. A criterion with no definition is refused by the reader — it would
-- produce a column named `helpfulness` with nothing anywhere recording what
-- was actually asked.
ALTER TABLE quota_policies ADD COLUMN online_eval_criteria_json TEXT;
-- How far the mean may fall between windows before a regression is recorded,
-- and how many scored samples each window needs first. Per TENANT because the
-- noise floor of a judge depends on the criteria wording, which is theirs.
ALTER TABLE quota_policies ADD COLUMN online_eval_regression_drop REAL;
ALTER TABLE quota_policies ADD COLUMN online_eval_regression_min_samples INTEGER;

CREATE TABLE IF NOT EXISTS online_eval_scores (
    -- The id the CLIENT was told (`x-request-id`), which is the id #664's
    -- request log and #677's cost row are both filed under. This is the join.
    request_id           TEXT    NOT NULL,
    -- The tenant's own criterion id. Renaming a criterion starts a NEW series
    -- rather than continuing the old one, which is correct: a renamed
    -- criterion is usually a re-worded one, and that is a different
    -- instrument.
    criterion_id         TEXT    NOT NULL,
    tenant               TEXT    NOT NULL,
    project              TEXT,
    workspace            TEXT,
    api_key_id           TEXT,
    agent_run_id         TEXT,
    operation_id         TEXT,
    provider             TEXT,
    -- Denormalised from the request on purpose: the trend query must be
    -- answerable WITHOUT joining a large table, and a score row should record
    -- the model as it was at scoring time.
    logical_model        TEXT,
    provider_model       TEXT,
    -- The bucket key — the request id, or the conversation. Scores of one
    -- conversation share it, which is what makes a per-conversation mean a
    -- `GROUP BY` rather than a reconstruction.
    sampling_key         TEXT    NOT NULL,
    sampling_unit        TEXT    NOT NULL,
    -- The rate IN FORCE when this row was sampled. Stored per row because it
    -- changes, and a population weighted by a rate read at query time would be
    -- weighted by the wrong one for every row sampled before the change.
    sample_rate          REAL    NOT NULL,
    judge_model          TEXT    NOT NULL,
    -- [0, 1]. Never clamped by the writer: a judge that answered outside the
    -- scale did not follow the rubric, and its verdict is dropped whole rather
    -- than repaired into a plausible number.
    score                REAL    NOT NULL,
    rationale            TEXT,
    -- The judge did not see the whole exchange. A reader comparing truncated
    -- and untruncated populations needs to be able to exclude these.
    prompt_truncated     INTEGER NOT NULL DEFAULT 0,
    completion_truncated INTEGER NOT NULL DEFAULT 0,
    scored_at_unix       INTEGER NOT NULL,
    -- One score per (request, criterion). This is also the arbiter that makes
    -- Queues' at-least-once redelivery safe: a re-judged sample REPLACES its
    -- earlier score instead of doubling the sample, and a doubled sample
    -- silently over-weights whichever requests happened to be redelivered.
    PRIMARY KEY (request_id, criterion_id)
);

-- The trend read: one tenant, one criterion, time-ordered. Without the leading
-- `tenant` the window aggregate would scan an append-heavy table.
CREATE INDEX IF NOT EXISTS idx_online_eval_scores_trend
    ON online_eval_scores(tenant, criterion_id, scored_at_unix DESC);

-- The "did quality move with cost, by model" read.
CREATE INDEX IF NOT EXISTS idx_online_eval_scores_model
    ON online_eval_scores(tenant, logical_model, scored_at_unix DESC);

-- One conversation's scores, for the unit that exists to make that possible.
CREATE INDEX IF NOT EXISTS idx_online_eval_scores_sampling_key
    ON online_eval_scores(tenant, sampling_key);

CREATE TABLE IF NOT EXISTS online_eval_regressions (
    -- `{tenant}:{criterion}:{judge}:{model}:{window_start}` — the CLAIM. The
    -- insert is the arbiter (see `evals/d1.ts`), so one sustained regression
    -- alerts once per window instead of on every cron tick for a week.
    claim_key          TEXT    NOT NULL PRIMARY KEY,
    tenant             TEXT    NOT NULL,
    criterion_id       TEXT    NOT NULL,
    judge_model        TEXT    NOT NULL,
    logical_model      TEXT,
    baseline_mean      REAL    NOT NULL,
    baseline_count     INTEGER NOT NULL,
    recent_mean        REAL    NOT NULL,
    recent_count       INTEGER NOT NULL,
    drop_amount        REAL    NOT NULL,
    detected_at_unix   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_online_eval_regressions_tenant
    ON online_eval_regressions(tenant, detected_at_unix DESC);
