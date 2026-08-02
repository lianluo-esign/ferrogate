-- Issue #682 — per-tenant BYOK: the alias table.
--
-- THIS TABLE IS THE WHOLE POINT OF THE FEATURE. Provider credentials used to be
-- reachable only through deploy-time Worker bindings, so a tenant could not
-- bring its own negotiated provider agreement and a key rotation meant a
-- `wrangler deploy`. Cloudflare Secrets Store bindings are resolved at deploy
-- time and `[[secrets_store_secrets]]`'s `get()` takes no argument, so there is
-- no runtime selection among bindings — which means an alias scheme built on
-- bindings would need one binding per tenant, i.e. exactly the deploy-per-tenant
-- problem #682 exists to remove.
--
-- So the BINDING SET stays fixed (one fleet-wide `FERROGATE_BYOK_MASTER_KEY`,
-- plus one more only when that master key is itself rotated) and the
-- tenant-visible mapping lives HERE, as rows. Onboarding a tenant is an INSERT.
-- Rotating their credential is an UPDATE. Neither is a deploy.
--
-- ## CONTROL database, not tenant
--
-- Deliberate. The gateway must resolve an alias BEFORE it has done anything
-- tenant-database-shaped, and `GATEWAY_TENANT_DB_ROUTING` may be `off` in a
-- deployment that still wants BYOK. Putting the table on the control database
-- also keeps the alias namespace uniqueness check (`PRIMARY KEY (tenant_id,
-- alias)`) meaningful across every routing mode.
--
-- ## What is and is not stored
--
--   * `ciphertext` / `iv` / `key_version` — AES-256-GCM, sealed by
--     `@ferrogate/secrets`'s `sealTenantCredential`. The additional
--     authenticated data is `(tenant_id, alias)`, so a row copied into another
--     tenant's partition does not decrypt: the SQL fence and the crypto fence
--     are independent, and neither is load-bearing alone.
--   * `last4` — the last four characters of the credential, so an operator can
--     confirm WHICH key is installed without the API ever returning the key.
--     Four characters is the industry norm (Stripe, OpenAI, AWS console) and is
--     far too little to help an attacker who does not already have the key.
--   * The PLAINTEXT is never stored, never returned by a read, and never logged.
--
-- `revoked_at_unix` is a tombstone rather than a DELETE so that an audit can
-- still answer "which alias was in use on that date"; the request path filters
-- on it, so a revoked alias resolves to nothing from the instant it is set.
CREATE TABLE IF NOT EXISTS tenant_provider_credentials (
  tenant_id        TEXT    NOT NULL,
  alias            TEXT    NOT NULL,
  -- `[[providers]].name` this credential authenticates against. The gateway
  -- applies a BYOK credential ONLY to routes whose provider matches, so an
  -- alias registered for `openai` can never be presented to `anthropic`.
  provider         TEXT    NOT NULL,
  key_version      INTEGER NOT NULL,
  iv               TEXT    NOT NULL,
  ciphertext       TEXT    NOT NULL,
  last4            TEXT    NOT NULL,
  created_at_unix  INTEGER NOT NULL,
  -- Bumped on every rotation; surfaced so a tenant can confirm a rotation took.
  rotated_at_unix  INTEGER NOT NULL,
  revoked_at_unix  INTEGER,
  PRIMARY KEY (tenant_id, alias)
);

-- The listing read is always tenant-scoped, and so is the index. There is
-- deliberately NO index that leads with `alias`: a lookup by alias alone is not
-- an operation this table supports, and an index that made one fast would be an
-- invitation to write it.
CREATE INDEX IF NOT EXISTS idx_tenant_provider_credentials_tenant
  ON tenant_provider_credentials (tenant_id, provider);
