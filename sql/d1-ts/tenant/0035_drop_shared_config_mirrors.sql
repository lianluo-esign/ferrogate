-- Platform configuration is owned by CONTROL_DATA. Billing groups already
-- read the platform authority / shared KV cache, and announcement fan-out is
-- retired. Remove the redundant copies when each tenant object next wakes.
-- None of these tables owns tenant-authored data.
DROP TABLE IF EXISTS shared_announcements;
DROP TABLE IF EXISTS shared_billing_groups;
DROP TABLE IF EXISTS shared_config_cursor;
