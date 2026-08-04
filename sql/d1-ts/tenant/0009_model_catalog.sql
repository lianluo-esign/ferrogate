-- ===========================================================================
-- Tenant model catalog v2 (#811)
--
-- `0008_model_catalog.sql` moved the default rate card into tenant storage,
-- but its one-row-per-model shape could not represent multiple upstream
-- channels or prices. This migration replaces that shape with a logical model,
-- provider channels, and priced offerings. An offering owns the price because
-- the same logical model can cost different amounts on different channels.
--
-- `tenant_id` remains on the catalog graph even though Durable Object tenants
-- are physically isolated. The shared-development and legacy routers can put
-- more than one tenant in one database, so every key and foreign-key edge is
-- tenant-qualified. The Durable Object topology still gets the physical
-- boundary and #819's object-identity guard.
--
-- The old table is converted before it is removed. Its cache multipliers are
-- materialized into absolute per-million offering prices: the new schema is
-- consumed by routing and billing, which need the rate rather than a second
-- multiplier calculation. `source` is retained on the offering so the
-- provisioning seed can distinguish platform rows from tenant edits.
-- ===========================================================================

-- Keep the legacy source relation available on a literal re-apply. On the
-- first run 0008 already created it and its rows are preserved; after the
-- first run this creates an empty source so the conversion SELECTs remain
-- valid, then the final DROP removes it again. The migration ledger normally
-- prevents a second execution, but this makes the SQL itself idempotent too.
CREATE TABLE IF NOT EXISTS model_catalog (
    tenant_id TEXT NOT NULL,
    model TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '*',
    provider_model TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    input_price_per_1m REAL NOT NULL DEFAULT 0,
    output_price_per_1m REAL NOT NULL DEFAULT 0,
    cached_input_multiplier REAL,
    cache_write_multiplier REAL,
    audio_second_price_per_1m REAL,
    audio_character_price_per_1m REAL,
    source TEXT NOT NULL DEFAULT 'platform_seed',
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, model)
);

CREATE TABLE IF NOT EXISTS tenant_database_identity (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    tenant_id             TEXT    NOT NULL,
    control_database_uuid TEXT,
    provisioned_at_unix   INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS provider_channels (
    id                          TEXT PRIMARY KEY,
    tenant_id                   TEXT NOT NULL,
    name                        TEXT NOT NULL,
    kind                        TEXT NOT NULL,
    base_url                    TEXT NOT NULL,
    api_key_var                 TEXT,
    byok_alias                  TEXT,
    auth_scheme                 TEXT CHECK (auth_scheme IN ('bearer', 'x-api-key')),
    region                      TEXT,
    zero_data_retention         INTEGER CHECK (zero_data_retention IN (0, 1)),
    openrouter_http_referer     TEXT,
    openrouter_x_title          TEXT,
    cloudflare_ai_gateway_json  TEXT,
    enabled                     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at_unix             INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix             INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_provider_channels_kind
    ON provider_channels (tenant_id, kind, enabled);

CREATE TABLE IF NOT EXISTS catalog_models (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    name              TEXT NOT NULL,
    family            TEXT,
    owned_by          TEXT,
    capabilities_json TEXT    NOT NULL DEFAULT '[]',
    context_window    INTEGER CHECK (context_window IS NULL OR context_window > 0),
    routing_strategy  TEXT    NOT NULL DEFAULT 'priority'
                      CHECK (routing_strategy IN
                             ('priority', 'lowest_cost', 'lowest_latency', 'balanced')),
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at_unix   INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix   INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS catalog_model_offerings (
    id                           TEXT PRIMARY KEY,
    tenant_id                    TEXT NOT NULL,
    model_id                     TEXT NOT NULL,
    provider_id                  TEXT NOT NULL,
    upstream_model_id            TEXT NOT NULL,
    role                         TEXT NOT NULL DEFAULT 'fallback'
                                 CHECK (role IN ('primary', 'fallback', 'canary', 'shadow')),
    priority                     INTEGER NOT NULL DEFAULT 100,
    weight                       INTEGER NOT NULL DEFAULT 1,
    canary_percent               INTEGER CHECK (canary_percent BETWEEN 0 AND 100),
    shadow_percent               INTEGER CHECK (shadow_percent BETWEEN 0 AND 100),
    shadow_max_requests          INTEGER,
    capabilities_json            TEXT,
    context_window               INTEGER,
    region                       TEXT,
    zero_data_retention          INTEGER CHECK (zero_data_retention IN (0, 1)),
    input_price_per_1m           REAL CHECK (input_price_per_1m >= 0),
    output_price_per_1m          REAL CHECK (output_price_per_1m >= 0),
    cached_input_price_per_1m    REAL CHECK (cached_input_price_per_1m >= 0),
    cache_write_price_per_1m     REAL CHECK (cache_write_price_per_1m >= 0),
    reasoning_price_per_1m       REAL CHECK (reasoning_price_per_1m >= 0),
    audio_second_price_per_1m    REAL CHECK (audio_second_price_per_1m >= 0),
    audio_character_price_per_1m REAL CHECK (audio_character_price_per_1m >= 0),
    currency                     TEXT    NOT NULL DEFAULT 'USD',
    source                       TEXT    NOT NULL DEFAULT 'platform_seed',
    enabled                      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at_unix              INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix              INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, model_id)
      REFERENCES catalog_models (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, provider_id)
      REFERENCES provider_channels (tenant_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_catalog_offerings_binding
    ON catalog_model_offerings (tenant_id, model_id, provider_id, upstream_model_id);

CREATE UNIQUE INDEX IF NOT EXISTS ux_catalog_offerings_primary
    ON catalog_model_offerings (tenant_id, model_id) WHERE role = 'primary';

CREATE UNIQUE INDEX IF NOT EXISTS ux_catalog_offerings_canary
    ON catalog_model_offerings (tenant_id, model_id) WHERE role = 'canary';

CREATE UNIQUE INDEX IF NOT EXISTS ux_catalog_offerings_shadow
    ON catalog_model_offerings (tenant_id, model_id) WHERE role = 'shadow';

CREATE INDEX IF NOT EXISTS idx_catalog_offerings_model_order
    ON catalog_model_offerings (tenant_id, model_id, priority ASC, weight DESC);

CREATE INDEX IF NOT EXISTS idx_catalog_offerings_provider
    ON catalog_model_offerings (tenant_id, provider_id);

CREATE TABLE IF NOT EXISTS catalog_revisions (
    tenant_id       TEXT    NOT NULL,
    id              INTEGER NOT NULL CHECK (id = 1),
    revision        INTEGER NOT NULL DEFAULT 1,
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- Convert rows written by the 0008 provisioning seed before retiring its table.
-- A `*` provider is a deliberate platform-routing channel: it carries no
-- credential and is resolved against the env fallback until #812 supplies the
-- tenant catalog loader. Non-wildcard legacy values are preserved as named
-- legacy channels because 0008 did not have endpoint metadata to recover.
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO provider_channels
    (id, tenant_id, name, kind, base_url, created_at_unix, updated_at_unix)
SELECT tenant_id || ':' || provider,
       tenant_id,
       CASE WHEN provider = '*' THEN 'platform-default' ELSE provider END,
       CASE WHEN provider = '*' THEN 'platform' ELSE provider END,
       CASE WHEN provider = '*' THEN 'platform://default' ELSE 'platform://legacy' END,
       MIN(created_at_unix),
       MAX(updated_at_unix)
  FROM model_catalog
 GROUP BY tenant_id, provider;

INSERT OR IGNORE INTO catalog_models
    (id, tenant_id, name, owned_by, enabled, created_at_unix, updated_at_unix)
SELECT tenant_id || ':model:' || model,
       tenant_id,
       model,
       provider,
       enabled,
       created_at_unix,
       updated_at_unix
  FROM model_catalog;

INSERT OR IGNORE INTO catalog_model_offerings
    (id, tenant_id, model_id, provider_id, upstream_model_id, role, priority,
     input_price_per_1m, output_price_per_1m, cached_input_price_per_1m,
     cache_write_price_per_1m, audio_second_price_per_1m,
     audio_character_price_per_1m, currency, source, enabled,
     created_at_unix, updated_at_unix)
SELECT tenant_id || ':offering:' || model,
       tenant_id,
       tenant_id || ':model:' || model,
       tenant_id || ':' || provider,
       provider_model,
       'primary',
       0,
       input_price_per_1m,
       output_price_per_1m,
       CASE WHEN cached_input_multiplier IS NULL
            THEN NULL ELSE input_price_per_1m * cached_input_multiplier END,
       CASE WHEN cache_write_multiplier IS NULL
            THEN NULL ELSE input_price_per_1m * cache_write_multiplier END,
       audio_second_price_per_1m,
       audio_character_price_per_1m,
       'USD',
       source,
       enabled,
       created_at_unix,
       updated_at_unix
  FROM model_catalog;

INSERT OR IGNORE INTO catalog_revisions (tenant_id, id, revision, updated_at_unix)
SELECT tenant_id, 1, 1, MAX(updated_at_unix)
  FROM model_catalog
 GROUP BY tenant_id;

-- A physical D1/DO database has one identity. Do not invent one in a shared
-- database that contains multiple legacy tenant ids; #819 supplies the object
-- identity at first touch and the tenant-qualified catalog rows remain valid.
INSERT OR IGNORE INTO tenant_database_identity (id, tenant_id)
SELECT 1, MIN(tenant_id)
  FROM model_catalog
HAVING COUNT(DISTINCT tenant_id) = 1;

DROP TABLE IF EXISTS model_catalog;
