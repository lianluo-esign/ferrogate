-- Canonical identity of every active guardrail policy revision selected when
-- this turn was screened. Existing rows remain NULL and are therefore always
-- re-screened: unknown policy attribution must never be trusted as equivalent.
ALTER TABLE responses_conversations ADD COLUMN screening_policy_revision TEXT;
