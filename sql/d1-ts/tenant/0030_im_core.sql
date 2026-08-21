-- Tenant-local IM core.
--
-- The support chat is the first caller, but the schema is deliberately not a
-- support-ticket schema. `kind` separates platform support, tenant-internal
-- rooms and future AI-agent conversations while keeping one durable message
-- history and participant/read-cursor model inside the tenant's own DO.

CREATE TABLE IF NOT EXISTS im_conversations (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('support', 'tenant_internal', 'ai_agent')),
    title             TEXT,
    status            TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed', 'archived')),
    created_by_type   TEXT NOT NULL CHECK (created_by_type IN ('tenant_user', 'platform_operator', 'ai_agent', 'system')),
    created_by_id     TEXT NOT NULL,
    metadata_json     TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json) = 1),
    created_at_unix   INTEGER NOT NULL,
    updated_at_unix   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_im_conversations_kind_updated
    ON im_conversations(kind, updated_at_unix DESC);

CREATE TABLE IF NOT EXISTS im_conversation_participants (
    conversation_id   TEXT NOT NULL REFERENCES im_conversations(id) ON DELETE CASCADE,
    participant_type  TEXT NOT NULL CHECK (participant_type IN ('tenant_user', 'platform_operator', 'ai_agent', 'system')),
    participant_id    TEXT NOT NULL,
    role              TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member', 'operator', 'agent')),
    joined_at_unix    INTEGER NOT NULL,
    last_read_seq     INTEGER NOT NULL DEFAULT 0,
    updated_at_unix   INTEGER NOT NULL,
    PRIMARY KEY (conversation_id, participant_type, participant_id)
);

CREATE INDEX IF NOT EXISTS idx_im_participants_identity
    ON im_conversation_participants(participant_type, participant_id, updated_at_unix DESC);

CREATE TABLE IF NOT EXISTS im_messages (
    seq               INTEGER PRIMARY KEY,
    id                TEXT NOT NULL UNIQUE,
    conversation_id   TEXT NOT NULL REFERENCES im_conversations(id) ON DELETE CASCADE,
    sender_type       TEXT NOT NULL CHECK (sender_type IN ('tenant_user', 'platform_operator', 'ai_agent', 'system')),
    sender_id         TEXT NOT NULL,
    sender_name       TEXT,
    content_type      TEXT NOT NULL DEFAULT 'text' CHECK (content_type IN ('text', 'markdown', 'system_event')),
    body              TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 16000),
    metadata_json     TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json) = 1),
    created_at_unix   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_im_messages_conversation_seq
    ON im_messages(conversation_id, seq ASC);
