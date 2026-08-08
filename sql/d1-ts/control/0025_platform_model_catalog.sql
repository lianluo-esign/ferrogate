-- ===========================================================================
-- Platform model catalog (#889, epic #810)
--
-- The platform default catalog — the providers, models and rate card a new
-- tenant is seeded from — has had no storage row anywhere: it lived in
-- `GATEWAY_PROVIDERS`/`GATEWAY_MODELS` env JSON and in
-- `PriceBook.withDefaultRateCard()`. A platform operator could not CRUD it,
-- audit it, or roll it back. These tables give it the same shape the tenants
-- already have, in the one database the platform itself owns.
--
-- This is the tenant v2 graph (`sql/d1-ts/tenant/0009_model_catalog.sql`)
-- MINUS `tenant_id`. The tenant tables carry a tenant column because a shared
-- or legacy router can put several tenants in one database; the CONTROL
-- database has exactly one occupant — the platform — so a platform column
-- would be a constant, and every key here is the plain key the tenant version
-- had to qualify.
--
-- The names are `platform_`-prefixed rather than reusing `provider_channels`
-- etc. because `packages/storage/test/d1/schema.test.ts` asserts the control
-- and tenant table families do not overlap: a shared name would make "a
-- tenant database must not contain control-only tables" unprovable, and a
-- control-plane query that forgot which database it was on would silently
-- read the wrong catalog rather than fail.
--
-- Deliberately NOT mirrored from 0009: its 0008 conversion block, and the
-- `kind = 'platform'` channel that block inserts. `'platform'` on the tenant
-- side is an indirection *into* this catalog; a row here pointing at itself
-- would be a cycle, so `canonicalProviderKind` rejecting it at the API edge is
-- the intended behaviour and there is nothing to convert — these tables start
-- empty and are filled by the admin surface.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS platform_provider_channels (
    id                          TEXT PRIMARY KEY,
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
    UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS idx_platform_provider_channels_kind
    ON platform_provider_channels (kind, enabled);

CREATE TABLE IF NOT EXISTS platform_catalog_models (
    id                TEXT PRIMARY KEY,
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
    UNIQUE (name)
);

-- The offering owns the price, for the same reason it does on the tenant side:
-- the same logical model costs different amounts on different channels.
CREATE TABLE IF NOT EXISTS platform_catalog_offerings (
    id                           TEXT PRIMARY KEY,
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
    FOREIGN KEY (model_id)
      REFERENCES platform_catalog_models (id) ON DELETE CASCADE,
    FOREIGN KEY (provider_id)
      REFERENCES platform_provider_channels (id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_platform_catalog_offerings_binding
    ON platform_catalog_offerings (model_id, provider_id, upstream_model_id);

-- Role arity: at most one primary, one canary and one shadow per model. A
-- second `fallback` is legal and is ordered by (priority, weight).
CREATE UNIQUE INDEX IF NOT EXISTS ux_platform_catalog_offerings_primary
    ON platform_catalog_offerings (model_id) WHERE role = 'primary';

CREATE UNIQUE INDEX IF NOT EXISTS ux_platform_catalog_offerings_canary
    ON platform_catalog_offerings (model_id) WHERE role = 'canary';

CREATE UNIQUE INDEX IF NOT EXISTS ux_platform_catalog_offerings_shadow
    ON platform_catalog_offerings (model_id) WHERE role = 'shadow';

CREATE INDEX IF NOT EXISTS idx_platform_catalog_offerings_model_order
    ON platform_catalog_offerings (model_id, priority ASC, weight DESC);

CREATE INDEX IF NOT EXISTS idx_platform_catalog_offerings_provider
    ON platform_catalog_offerings (provider_id);

-- The single-row revision stamp. One catalog, one monotone revision: readers
-- (#890's seeder, #891's gateway loader) compare it to decide whether their
-- cached copy is stale, and every write in `PlatformModelCatalogStore` bumps
-- it inside the same batch as the mutation.
CREATE TABLE IF NOT EXISTS platform_catalog_revisions (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    revision        INTEGER NOT NULL DEFAULT 1,
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);
