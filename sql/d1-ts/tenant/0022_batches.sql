-- ===========================================================================
-- Tenant-scoped OpenAI-compatible batch jobs (#698, slice 1)
--
-- This migration creates the durable API/state surface only. Slice 2 will
-- claim validating jobs, execute JSONL lines, and publish output/error files.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS batches (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    input_file_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    completion_window TEXT NOT NULL CHECK (completion_window = '24h'),
    status TEXT NOT NULL CHECK (
        status IN (
            'validating', 'in_progress', 'finalizing', 'completed',
            'failed', 'expired', 'cancelling', 'cancelled'
        )
    ),
    output_file_id TEXT,
    error_file_id TEXT,
    request_counts_json TEXT NOT NULL DEFAULT '{"total":0,"completed":0,"failed":0}'
        CHECK (json_valid(request_counts_json) = 1),
    metadata_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(metadata_json) = 1),
    created_at_unix INTEGER NOT NULL,
    in_progress_at_unix INTEGER,
    finalizing_at_unix INTEGER,
    completed_at_unix INTEGER,
    failed_at_unix INTEGER,
    expired_at_unix INTEGER,
    cancelling_at_unix INTEGER,
    cancelled_at_unix INTEGER,
    expires_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tenant_batches_created
    ON batches(tenant_id, created_at_unix DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_batches_status
    ON batches(tenant_id, status, created_at_unix ASC, id ASC);
