-- ===========================================================================
-- `model_catalog` + `tenant_provisioning_marks` — the tenant's OWN model list,
-- and the one-shot ledger that keeps re-provisioning from rewriting it (#820)
--
-- ## Why a tenant needs a catalog of its own at all
--
-- This header used to claim that a tenant with an empty catalog answers
-- `400 model_not_found` on every inference request, attributing that to
-- `buildModelCatalog`'s fail-closed posture. THAT WAS FALSE, and it was the
-- stated justification for this whole migration and for the mandatory seed.
-- `buildModelCatalog` (`apps/gateway/src/inference/catalog.ts`) is handed rows
-- parsed from the `GATEWAY_PROVIDERS` / `GATEWAY_MODELS` config VARS by
-- `modelCatalogFromEnv`; it never opens a database, and it has never read this
-- table. Nothing in `apps/<app>/src` reads this table at all today.
--
-- The honest reason it exists: per-tenant model visibility and per-tenant
-- pricing need a per-tenant row, and the design doc
-- (`docs/design/per-tenant-durable-object-storage-2026-08.md`) names the catalog
-- as something a tenant object can cache in memory across requests once a
-- resolver reads it. Seeding at provisioning time is cheap — 16 rows, once —
-- and means the table is already populated when that reader lands, instead of
-- needing a fleet-wide backfill over objects a namespace cannot enumerate.
-- Seeding EARLY is the argument. "The tenant is dead on arrival" was not true.
--
-- ## Seeded ONCE, then the tenant owns it
--
-- The seed content is a COPY of the platform default rate card
-- (`packages/billing/src/pricing.ts::withDefaultRateCard`), taken at the moment
-- this tenant was provisioned. It is deliberately a copy and not a view:
--
--   * a platform price edit must NOT silently re-price a tenant that has
--     already been quoted, and
--   * a tenant that disables `claude-opus-4` or re-prices `gpt-4o` must not
--     have that edit reverted by the next re-provision, a redeploy, or a
--     resumed half-provisioning.
--
-- The mechanism for the second half is `tenant_provisioning_marks`, NOT
-- `INSERT OR IGNORE` on this table. `INSERT OR IGNORE` protects an EDITED row
-- and silently resurrects a DELETED one, so a tenant that removed a model would
-- find it back after the next resume — an edit reverted by a background job is
-- the failure mode this whole table exists to avoid. The mark says "the seed
-- step has run for this tenant", which is a fact about the STEP rather than
-- about any row, so it stays true however the rows are later edited.
--
-- ## Why the mark lives HERE and not only in the control database
--
-- Recording provisioning state spans two stores — `tenant_databases` in the
-- control D1 and this object — and they cannot be one transaction. If the only
-- "already seeded" record were the control row, then losing or resetting that
-- row (a restore, a re-registration, a migration that rebuilt the table — this
-- slice ships one) would re-seed a live tenant over its own edits. The mark is
-- written inside the same object it describes, so the object can always answer
-- for itself; the control row is the operator-visible PROJECTION of that
-- answer, and `tenant-provisioning.ts` treats a disagreement as "resume", never
-- as "re-seed".
--
-- ## Prices: USD per 1M units, as REAL
--
-- The same unit and the same type `packages/billing`'s `ModelPrice` carries, so
-- a row decodes into a `PriceEntry` without a scale conversion. Credits (which
-- can exceed 2^53 and cross as decimal strings — `src/credits.ts`) are a
-- different quantity entirely and do not appear here: a rate is a small number
-- with fractional cents, a balance is an exact integer count.
--
-- Cache rates are MULTIPLIERS of the row's own input rate, exactly as #667
-- states them on the rate card, and are NULLABLE with no default: a NULL means
-- "this entry states no cache rate", which prices cached tokens at the ordinary
-- input rate. A `0.0` default would price them free, which is the one direction
-- a billing default must never fail in.
--
-- ## No FOREIGN KEY, no CHECK
--
-- The dialect rules inherited from `0001_init_tenant.sql`: D1 does not enforce
-- foreign keys by default, so a declared one reads as an enforced constraint
-- and is not one, and descriptive enumerations are validated by the writer and
-- again by the reader.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS model_catalog (
    -- Carried on every row for the reason every other table in this database
    -- carries it, and it is NOT redundant with the object: under
    -- `GATEWAY_TENANT_DB_ROUTING = "shared_development"` (and under the legacy
    -- `off`) ONE physical database holds many tenants and this predicate IS the
    -- isolation. A catalog keyed on `model` alone would let the second tenant
    -- seeded into a shared database silently inherit the first tenant's prices —
    -- and every `INSERT OR IGNORE` in the seeder would report success while
    -- doing it.
    tenant_id TEXT NOT NULL,
    -- The LOGICAL model name a client sends, and this tenant's own key for it.
    model TEXT NOT NULL,
    -- The provider that serves it. `'*'` means "whatever provider the platform
    -- routes this model to", which is how the seeded rate card states every one
    -- of its entries — the card prices a MODEL, and the physical provider
    -- behind it is a routing decision the gateway makes per request.
    provider TEXT NOT NULL DEFAULT '*',
    -- The id actually put on the upstream wire. Seeded equal to `model`; an
    -- operator re-points it to move a logical name onto a different physical
    -- model without a client change, which is the entire point of the registry
    -- indirection (see `apps/gateway/src/inference/catalog.ts`).
    provider_model TEXT NOT NULL,
    -- 0 disables the row WITHOUT deleting it, so a tenant can turn a model off
    -- and keep the price it negotiated. A deleted row and a disabled row are
    -- different statements and the seed step must be able to tell them apart.
    enabled INTEGER NOT NULL DEFAULT 1,
    -- USD per 1M tokens. Both NOT NULL: an entry that prices nothing is how a
    -- row comes to bill zero, and `estimateCost` cannot tell "free" from
    -- "unpriced" once the value is in the column.
    input_price_per_1m REAL NOT NULL DEFAULT 0,
    output_price_per_1m REAL NOT NULL DEFAULT 0,
    -- Ratios of `input_price_per_1m` (#667). NULL = this entry states none.
    cached_input_multiplier REAL,
    cache_write_multiplier REAL,
    -- The audio surface (#703). NULL = this entry does not price that unit, so
    -- a row carrying an audio quantity it does not price is still
    -- `price_not_found` rather than silently free.
    audio_second_price_per_1m REAL,
    audio_character_price_per_1m REAL,
    -- `'platform_seed'` for a row this tenant never touched, `'tenant'` once an
    -- operator has written it. Carried so an operator can see at a glance which
    -- half of the catalog is still the default card, and so a future
    -- platform-card refresh has a legible answer to "which rows may I touch".
    -- It is descriptive, not enforced: nothing in this repo refuses a write on
    -- the strength of it today, and pretending otherwise with a CHECK would
    -- imply a policy that does not exist.
    source TEXT NOT NULL DEFAULT 'platform_seed',
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    -- Composite, and in this order: `(tenant_id, model)` is both the uniqueness
    -- rule (the Rust registry refused to boot on a duplicate model name — a
    -- table that can hold two rows for one name has already lost that property)
    -- and the exact seek every lookup performs.
    PRIMARY KEY (tenant_id, model)
);

-- The "what does this tenant have from provider X" read. The primary key already
-- covers the by-name lookup, and there is deliberately no index on `enabled`: a
-- tenant's whole catalog is tens of rows, so a partial index would cost a write
-- on every seeded row to save the scan of a page.
CREATE INDEX IF NOT EXISTS idx_model_catalog_provider
    ON model_catalog(tenant_id, provider, model);

CREATE TABLE IF NOT EXISTS tenant_provisioning_marks (
    tenant_id TEXT NOT NULL,
    -- The step's name, e.g. `model_catalog_seed`. Ordinary text rather than a
    -- CHECKed enum: the set of provisioning steps grows, and a CHECK here would
    -- make adding one a schema migration on every tenant object.
    mark TEXT NOT NULL,
    -- What the step recorded about itself. Free-form and small — a version, a
    -- row count, a card fingerprint — so an operator can tell WHICH seed ran
    -- without a second table.
    detail TEXT NOT NULL DEFAULT '',
    applied_at_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, mark)
);
