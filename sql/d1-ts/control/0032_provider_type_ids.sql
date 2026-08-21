-- Stable product provider families for dashboard filtering.
--
-- `kind` is the protocol adapter and is intentionally insufficient here:
-- OpenAI, DeepSeek and MiniMax can all use `openai-compatible`. The separate
-- type id is the business identity shared by Polaris, Vega and the control
-- plane. Existing rows are backfilled conservatively from their canonical kind.

ALTER TABLE platform_provider_channels ADD COLUMN provider_type_id TEXT;

UPDATE platform_provider_channels
   SET provider_type_id = CASE lower(trim(kind))
       WHEN 'anthropic' THEN 'anthropic'
       WHEN 'gemini' THEN 'gemini'
       WHEN 'vertex' THEN 'gemini'
       WHEN 'grok' THEN 'grok'
       WHEN 'openai-compatible' THEN 'openai'
       WHEN 'openrouter' THEN 'openai'
       WHEN 'azure-openai' THEN 'openai'
       ELSE NULL
   END
 WHERE provider_type_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_platform_provider_channels_type
    ON platform_provider_channels (provider_type_id, enabled);

ALTER TABLE platform_billing_groups ADD COLUMN provider_type_id TEXT;

UPDATE platform_billing_groups
   SET provider_type_id = (
       SELECT p.provider_type_id
         FROM platform_billing_group_providers AS edge
         JOIN platform_provider_channels AS p ON p.id = edge.provider_id
        WHERE edge.group_id = platform_billing_groups.id
          AND p.provider_type_id IS NOT NULL
        ORDER BY edge.provider_id
        LIMIT 1
   )
 WHERE provider_type_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_platform_billing_groups_type
    ON platform_billing_groups (provider_type_id, enabled);

-- Force the shared-config fan-out to republish the newly typed projection.
INSERT OR IGNORE INTO platform_billing_group_revisions (id, revision, updated_at_unix)
VALUES (1, 1, unixepoch());
UPDATE platform_billing_group_revisions
   SET revision = revision + 1,
       updated_at_unix = unixepoch()
 WHERE id = 1;
