-- ===========================================================================
-- Bilingual display fields for billing groups (中英双语展示)
--
-- The operator-configured `name`/`description` were single-language: whatever
-- the operator typed in the Polaris console was shown verbatim to every Vega
-- customer, so a customer running the Vega frontend in Chinese still saw the
-- English group name (and vice versa). The customer surface localizes its
-- CHROME (column headers, labels) but never these DATA values, so they could
-- not follow the language toggle.
--
-- These two nullable columns carry the Chinese variant alongside the existing
-- canonical string. `name`/`description` stay the DEFAULT/fallback (and `name`
-- keeps its UNIQUE index — identity is still one canonical string per group);
-- `name_zh`/`description_zh` are the localized overlay the customer frontend
-- picks when its locale is `zh-CN`, falling back to the canonical column when a
-- variant was left blank. Additive and nullable, so every pre-0044 row is a
-- valid "English only, no Chinese variant" group with no backfill.
--
-- Flat per-locale columns (not a JSON blob) by the operator's explicit choice:
-- exactly two display languages are in scope (en + zh-CN), and a plain column
-- is trivially indexable/searchable and needs no parse.
-- ===========================================================================

ALTER TABLE platform_billing_groups ADD COLUMN name_zh TEXT;
ALTER TABLE platform_billing_groups ADD COLUMN description_zh TEXT;
