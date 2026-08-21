-- Repair legacy provider families that migration 0032 could not infer.
--
-- This is a new migration rather than an edit to 0032 because production may
-- already have recorded 0032 as applied. Only NULL values are filled; explicit
-- operator choices remain authoritative.

UPDATE platform_provider_channels
   SET provider_type_id = CASE lower(trim(kind))
       WHEN 'anthropic' THEN 'anthropic'
       WHEN 'claude' THEN 'anthropic'
       WHEN 'gemini' THEN 'gemini'
       WHEN 'google' THEN 'gemini'
       WHEN 'google-gemini' THEN 'gemini'
       WHEN 'google_gemini' THEN 'gemini'
       WHEN 'vertex' THEN 'gemini'
       WHEN 'vertex-ai' THEN 'gemini'
       WHEN 'grok' THEN 'grok'
       WHEN 'xai' THEN 'grok'
       WHEN 'deepseek' THEN 'deepseek'
       WHEN 'minimax' THEN 'minimax'
       WHEN 'openai' THEN 'openai'
       WHEN 'openai-compatible' THEN 'openai'
       WHEN 'openrouter' THEN 'openai'
       WHEN 'azure' THEN 'openai'
       WHEN 'azure-openai' THEN 'openai'
       ELSE NULL
   END
 WHERE provider_type_id IS NULL;

-- Infer a legacy group's type only when every typed bound provider agrees.
-- Mixed or still-untyped groups stay NULL and remain unavailable to tenants
-- until an operator resolves the ambiguity explicitly.
UPDATE platform_billing_groups
   SET provider_type_id = (
       SELECT MIN(provider.provider_type_id)
         FROM platform_billing_group_providers AS edge
         JOIN platform_provider_channels AS provider ON provider.id = edge.provider_id
        WHERE edge.group_id = platform_billing_groups.id
          AND provider.provider_type_id IS NOT NULL
   )
 WHERE provider_type_id IS NULL
   AND 1 = (
       SELECT COUNT(DISTINCT provider.provider_type_id)
         FROM platform_billing_group_providers AS edge
         JOIN platform_provider_channels AS provider ON provider.id = edge.provider_id
        WHERE edge.group_id = platform_billing_groups.id
          AND provider.provider_type_id IS NOT NULL
   );

-- Republish repaired type ids to every tenant's read-only mirror.
INSERT OR IGNORE INTO platform_billing_group_revisions (id, revision, updated_at_unix)
VALUES (1, 1, unixepoch());
UPDATE platform_billing_group_revisions
   SET revision = revision + 1,
       updated_at_unix = unixepoch()
 WHERE id = 1;
