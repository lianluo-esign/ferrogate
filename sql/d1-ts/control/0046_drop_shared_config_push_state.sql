-- Announcement mutations and tenant provisioning no longer fan platform
-- configuration out to tenant objects. No fleet delivery cursor is needed.
-- The authoritative platform tables and their revisions remain in CONTROL_DATA.
DROP TABLE IF EXISTS shared_config_push_state;
