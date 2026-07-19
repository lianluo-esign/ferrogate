# Private asset-bucket migration runbook (issue #259)

Operator steps to flip the live Supabase `ferrogate` storage bucket from
`public: true` to private, once the gateway large-file code path (issue
#259) is deployed. **The code path must ship first**; this runbook is the
operational sequence that depends on it. Nothing here is executed
automatically — no live bucket is flipped by the gateway.

## What the code path already provides

Deployed in #259 (`crates/ferrogate-cli/src/gateway/asset_presign.rs`,
`asset_bucket.rs`, `ferrogate-providers::presign_sigv4_query`):

- **Presigned upload** — `POST /v1/assets/presign/upload/{asset_type}/{name}/{version}`
  authorizes (virtual-key `assets.write` + StoredPlan/role asset-hosting
  entitlement + tenant scoping), enforces the per-object ceiling and the
  cumulative tenant `asset_storage_quota_bytes`, audits, and returns a
  short-TTL SigV4 query-string presigned `PUT` URL. Bytes go straight to
  the bucket, bypassing the Pingora hot path.
- **Commit** — `POST /v1/assets/presign/commit/{asset_type}/{name}/{version}`
  verifies the committed object's size (HEAD) and sha256 (fetch) against
  the registered intent, re-runs the `asset_security` supply-chain checks
  against the committed bytes, and **fails closed by deleting the object**
  on any violation. Only then is the `stored_assets` row written (the
  asset becomes visible), with quota counted at commit.
- **Presigned download** — `GET /v1/assets/presign/download/{asset_type}/{name}/{version}`
  returns a short-TTL presigned `GET` URL plus the object's `sha256` and
  `size_bytes` so the agent can verify the bytes it fetches directly.

All reads for bucket-backed objects can therefore go through
gateway-issued presigned GETs — **the public bucket URL is no longer
required for correctness.**

## TTL / ceiling configuration

`[asset_bucket]` in the gateway config:

- `presign_ttl_secs` — TTL for issued URLs. Bounded to `[1, 604800]` (S3's
  7-day max); defaults to `900` (15 min).
- `presign_max_object_bytes` — per-object size ceiling for the presigned
  path; defaults to 5 GiB. Independent of the tenant-wide
  `asset_storage_quota_bytes`.

## Migration sequence (operator-run, not automated)

1. **Deploy** the #259 gateway build and confirm presigned upload → commit
   → download works end-to-end against the current (still-public) bucket.
2. **Inventory** existing objects. All live objects are addressed by the
   `stored_assets.storage_uri` key, so no key rewrite is needed — the same
   keys are reachable via presigned GET once the bucket is private.
3. **Flip** the `ferrogate` bucket to `public: false` in the Supabase
   dashboard / Storage API.
4. **Verify**:
   - A gateway-issued presigned `GET` still returns the object bytes.
   - A direct, unsigned fetch of a bucket object URL now returns `4xx`
     (the security-gap closure this migration exists for).
5. **`dev-migration` bucket** — review separately; keep public only if a
   documented non-tenant use requires it, otherwise flip it too.

## Rollback

Re-flip the bucket to `public: true`. The gateway keeps working either way
(it never depends on public access); the only observable change is that
unsigned direct fetches succeed again.
