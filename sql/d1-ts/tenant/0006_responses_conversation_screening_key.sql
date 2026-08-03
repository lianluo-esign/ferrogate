-- The credential under which this turn's guardrail screening was decided.
-- Existing rows remain NULL and are therefore treated as foreign by any keyed
-- continuation, which re-screens them rather than trusting unattributed text.
ALTER TABLE responses_conversations ADD COLUMN screening_api_key_id TEXT;
