-- Public model pricing is independent from provider routes. An offering binds
-- to one logical public model price, while the selected source and rates can be
-- changed without rewriting every provider route that uses it.
CREATE TABLE IF NOT EXISTS platform_model_prices (
    id                           TEXT PRIMARY KEY,
    model_key                    TEXT NOT NULL UNIQUE,
    name                         TEXT NOT NULL,
    aliases_json                 TEXT NOT NULL DEFAULT '[]',
    source_type                  TEXT NOT NULL DEFAULT 'manual',
    source_provider_id           TEXT,
    source_provider_name         TEXT,
    input_price_per_1m           REAL CHECK (input_price_per_1m >= 0),
    output_price_per_1m          REAL CHECK (output_price_per_1m >= 0),
    cached_input_price_per_1m    REAL CHECK (cached_input_price_per_1m >= 0),
    cache_write_price_per_1m     REAL CHECK (cache_write_price_per_1m >= 0),
    reasoning_price_per_1m       REAL CHECK (reasoning_price_per_1m >= 0),
    audio_second_price_per_1m    REAL CHECK (audio_second_price_per_1m >= 0),
    audio_character_price_per_1m REAL CHECK (audio_character_price_per_1m >= 0),
    currency                     TEXT NOT NULL DEFAULT 'USD',
    enabled                      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at_unix              INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix              INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_platform_model_prices_source
    ON platform_model_prices (source_provider_id, enabled, model_key);

ALTER TABLE platform_provider_channels
    ADD COLUMN cost_multiplier REAL NOT NULL DEFAULT 1 CHECK (cost_multiplier >= 0);

ALTER TABLE platform_catalog_offerings ADD COLUMN pricing_model_id TEXT;

CREATE INDEX IF NOT EXISTS idx_platform_catalog_offerings_pricing_model
    ON platform_catalog_offerings (pricing_model_id);
