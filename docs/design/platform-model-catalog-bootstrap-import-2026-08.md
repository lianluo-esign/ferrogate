# Platform model catalog — bootstrap import (#892, epic #810)

## What it does

`POST /admin/v1/config/import-model-catalog` (platform-operator only) parses the
deployment's `GATEWAY_PROVIDERS` / `GATEWAY_MODELS` env tables with the SAME
`modelCatalogInputsFromEnv` the data plane uses, and writes them into the
platform catalog (`platform_provider_channels` / `platform_catalog_models` /
`platform_catalog_offerings`) as real provider/model/offering rows, plus one
revision bump and one audit row. `PriceBook.withDefaultRateCard()` is imported as
`platform`-kind priced offerings on a single `platform-default` channel.

The import is **idempotent and re-runnable**: every row has a deterministic id
derived from its natural key (`platform:provider:<name>`,
`platform:model:<name>`, `platform:offering:<model>:<provider>:<upstream>`) and is
written `INSERT OR IGNORE`. A re-run inserts nothing and only advances the
revision. The response reports `attempted` / `inserted` / `counts` per table.

## Deploy order

1. **Import.** Run the operation with the deployment's current
   `GATEWAY_PROVIDERS` / `GATEWAY_MODELS` in the request body (or, if the
   operator chose to bind them on the control-plane Worker, with an empty body).
2. **Verify counts.** The response's `counts` are the totals; an operator can
   also confirm directly:

   ```sql
   SELECT
     (SELECT COUNT(*) FROM platform_provider_channels) AS providers,
     (SELECT COUNT(*) FROM platform_catalog_models)    AS models,
     (SELECT COUNT(*) FROM platform_catalog_offerings) AS offerings;
   ```

   and cross-check against the env pair (`GET /admin/v1/providers` /
   `/models` with no `tenant_id` now serve the platform catalog once adopted,
   and `--platform` on the CLI catalog surface reports the same).
3. **Later — env tables MAY be emptied.** Once the counts are confirmed and the
   gateway is serving the managed catalog (platform rows present ⇒ authoritative,
   `apps/gateway/src/inference/route-module.ts`), the `GATEWAY_PROVIDERS` /
   `GATEWAY_MODELS` vars may be emptied. **This is a DEFERRED follow-up**
   (Zero-D1-S5-style, see `docs/design/zero-d1-control-object-2026-08.md` §4 S5)
   and is NOT part of #892: this slice does not touch env handling, and the
   gateway still falls back to the env tables whenever the platform catalog is
   empty. Actually deleting the env-var handling is reserved for a separate,
   named issue.

Rollback is "empty the platform catalog" (the gateway falls back to env) plus the
existing `GATEWAY_CONTROL_STORAGE` escape hatch.

## The `platform`-kind price rows, and why the loaders exclude them

The default rate card prices a MODEL, not a channel (its provider is the wildcard
`"*"`). Mirroring the tenant migration `sql/d1-ts/tenant/0009_model_catalog.sql`,
each rate-card entry becomes one priced primary offering on a single
`platform-default` channel of kind `'platform'` (`platform://default`). These rows
carry PRICES but no physical upstream, so they are NOT routable legs:

- `apps/gateway/src/inference/platform-catalog.ts::buildPlatformCatalog` excludes
  `kind = 'platform'` rows before projecting to physical routes. Feeding one to
  the shared projection's `provider_kind === "platform"` arm (which resolves a
  tenant-side indirection against an env registry the platform loader runs empty)
  would fail the WHOLE platform build with a deployment-wide 503.
- `PlatformModelCatalogStore.exportForSeed` (#891) excludes them, so a seeded
  tenant never inherits a channel it cannot route through — keeping the "real
  channels stay real" invariant `seedTenantModelCatalogFromGraph` is built on.

This revisits the `0025_platform_model_catalog.sql` header's note that the
platform tables would carry no `kind = 'platform'` rows: #889 left the tables
empty for the admin surface to fill, and #892 is the surface that fills them —
including the rate card, as the issue scopes. The two loaders excluding the
price rows is what keeps that safe. `#889`'s per-row admin CRUD still rejects a
`platform` kind at the write edge; only this bulk import lays the price rows down.

## `withDefaultRateCard()` consumers (a note, not a rename)

After this lands, the compiled-in `PriceBook.withDefaultRateCard()` has exactly
two runtime consumers:

1. the legacy `rate_card` settlement mode
   (`apps/gateway/src/metering/sink.ts`), which still prices against the
   compiled card — the import does NOT redirect settlement to the catalog; and
2. this import, which snapshots the card into the platform catalog for
   completeness and operator visibility.

Per the Zero-D1 doc's discipline, renames of the card are reserved for a separate
pure-refactor issue; this slice adds the second consumer and states the fact.
