-- ===========================================================================
-- Cached / cache-write / reasoning token columns on the usage rollups (#667)
--
-- Before this migration the rollups carried prompt/completion/total only, so a
-- tenant on Anthropic prompt caching or a reasoning model could see WHAT it
-- spent but not WHY: the cached-read discount and the reasoning premium were
-- already priced into `cost_usd` and nowhere else, which makes an unexpected
-- invoice unexplainable from the tables the report API reads.
--
-- ## Why ALTER, and why the defaults are what they are
--
-- `ADD COLUMN ... NOT NULL DEFAULT 0` is the one schema change SQLite applies
-- without rewriting the table, and it is safe on a live rollup: every existing
-- row means "no cached or reasoning tokens were recorded for this period", and
-- `0` states exactly that. It is also the value the accumulate adds to, so the
-- `existing + excluded` upsert keeps working on rows written before this
-- migration ran.
--
-- These are SUBSETS of the columns beside them, never additions — the same
-- invariant `@ferrogate/billing`'s `TokenUsage` documents:
--
--     cached_input_tokens <= prompt_tokens
--     cache_write_tokens  <= prompt_tokens   (disjoint from cached_input_tokens)
--     reasoning_tokens    <= completion_tokens
--
-- so `SUM(total_tokens)` is unchanged by this migration and no existing budget
-- read shifts. Deliberately NOT enforced with a CHECK: these are ACCUMULATED
-- columns, and a per-row CHECK on a running sum would compare this month's
-- cached total against this month's prompt total across many requests, which
-- says nothing useful and would fail closed on a single provider that
-- mis-reported once. The clamp that matters is per-request and lives in
-- `estimateCost` (`packages/billing/src/usage.ts`), where a cached count larger
-- than the prompt count is truncated before it can produce a negative charge.
--
-- No index is added: nothing filters or joins on these columns, they are read
-- as part of a row already located by its primary key or by the existing
-- scope/period indexes.
-- ===========================================================================

ALTER TABLE usage_aggregate_rollups ADD COLUMN cached_input_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_aggregate_rollups ADD COLUMN cache_write_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_aggregate_rollups ADD COLUMN reasoning_tokens INTEGER NOT NULL DEFAULT 0;

ALTER TABLE usage_monthly_rollups ADD COLUMN cached_input_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_monthly_rollups ADD COLUMN cache_write_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_monthly_rollups ADD COLUMN reasoning_tokens INTEGER NOT NULL DEFAULT 0;
