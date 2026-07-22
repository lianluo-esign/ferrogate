# Private asset-bucket migration runbook (issue #259)

Operator steps to flip the live Supabase `ferrogate` storage bucket from
`public: true` to private, once the hardened gateway large-file path (issues
#259 and #338) is deployed. **The code path must ship first**; this runbook is
the operational sequence that depends on it. Nothing here is executed
automatically; no live bucket is flipped by the gateway.

## What the code path already provides

Implemented by `crates/ferrogate-cli/src/gateway/asset_presign.rs`,
`asset_bucket.rs`, and `ferrogate-providers::presign_sigv4_query`:

- **Presigned upload** - `POST /v1/assets/presign/upload/{asset_type}/{name}/{version}`
  authorizes (virtual-key `assets.write` + StoredPlan/role asset-hosting
  entitlement + tenant scoping), enforces the per-object ceiling and the
  cumulative tenant `asset_storage_quota_bytes`, audits, and returns a
  short-TTL SigV4 `PUT` URL plus a unique opaque `upload_id`. Each intent uses
  a separate staging object bound to the tenant, logical asset identity,
  declared size, and SHA-256. The response `key` is the logical asset ID, not a
  bucket key. Bytes go straight to staging, bypassing the Pingora hot path.
- **Commit** - `POST /v1/assets/presign/commit/{asset_type}/{name}/{version}`
  requires that `upload_id`, verifies the staging object's size (HEAD) and
  SHA-256 (fetch), and applies the built-in content/type checks. It then copies
  verified bytes to a new internal immutable final key and conditionally
  creates the `stored_assets` metadata row. That key is never a client `PUT`
  target and is not serialized in list, manifest, or standalone response
  fields. An authorized presigned download URL necessarily contains its path.
  Only the metadata create makes the asset visible and counts it toward quota.
- **Presigned download** - `GET /v1/assets/presign/download/{asset_type}/{name}/{version}`
  returns a short-TTL presigned `GET` URL plus the object's `sha256` and
  `size_bytes` so the agent can verify the bytes it fetches directly.

The presigned commit path does **not** provide full parity with inline publish
supply-chain policy. It does not run detached-signature, approval, or pluggable
scanner checks. Deployments that require those controls must keep such assets
on the inline path or add equivalent commit-path enforcement before migration.

All reads for bucket-backed objects can go through gateway-issued presigned
GETs, so the public bucket URL is no longer required for correctness.

## Replay, retry, and cleanup behavior

- A new intent always receives a new `upload_id` and staging object. It cannot
  overwrite a live final object, even when the logical version is the same.
- Repeating commit with the same `upload_id` and matching metadata returns the
  already-created asset, including after successful staging cleanup. A
  different `upload_id` for an existing immutable version returns
  `409 asset_version_immutable`, even when the claimed checksum matches.
- Definitive size, hash, content, quota, or immutable-conflict rejection cleans
  only objects owned by the losing intent, best-effort, and never deletes the
  winner's `storage_uri`. A transport or storage failure can have an unknown
  object-write outcome; in that case the gateway preserves this attempt's
  staging and any final candidate, returns `503 asset_bucket_unavailable`, and
  leaves retry or GC to resolve it instead of guessing that the write failed.
- After a confirmed metadata create, staging deletion is best-effort. If the
  repository create may have committed but its response cannot be proven, the
  gateway returns `503 asset_commit_outcome_unknown` and deliberately preserves
  both staging and final objects. Retry with the same `upload_id`; do not treat
  an immediate registry reread as proof that the original create failed.

Best-effort cleanup is backed by the existing `[asset_lifecycle]` orphan GC,
which can discover aged staging objects and unreferenced final candidates by
comparing the bucket with `stored_assets.storage_uri`. It is conservative and
off by default: `asset_lifecycle.enabled = false` and `gc_enabled = false`.
When enabled, `dry_run = true` is the default, `gc_grace_secs = 86400`, and at
most 100 objects are deleted per tick. Operators should first enable lifecycle
and GC in dry-run mode, inspect the reported candidates, then explicitly set
`dry_run = false`. There is no guaranteed automatic orphan deletion under the
default configuration.

The internal namespaces make the ownership boundary explicit: staging objects
live under `.ferrogate/staging/` with a digest bound to logical identity,
`upload_id`, size, and SHA-256; final objects live under
`.ferrogate/objects/<intent-digest>/obj_<random-128-bit-hex>`. Clients must not
construct either key. The upload URL encapsulates staging access, and an
authorized download URL encapsulates final-object access.

## TTL / ceiling configuration

`[asset_bucket]` in the gateway config:

- `presign_ttl_secs` — TTL for issued URLs. Bounded to `[1, 604800]` (S3's
  7-day max); defaults to `900` (15 min).
- `presign_max_object_bytes` — per-object size ceiling for the presigned
  path; defaults to 5 GiB. Independent of the tenant-wide
  `asset_storage_quota_bytes`.

## Migration sequence (operator-run, not automated)

1. **Deploy** the #338 hardened gateway build and confirm presigned upload ->
   commit -> download works end-to-end against the current (still-public)
   bucket.
2. **Upgrade upload clients** to persist the returned `upload_id` and include
   it in the commit request. Old clients that omit it fail request validation.
3. **Inventory** existing objects. All live objects are addressed by the
   `stored_assets.storage_uri` key, so no key rewrite is needed. Existing keys
   remain valid; new presigned commits store their internal final keys there.
4. **Flip** the `ferrogate` bucket to `public: false` in the Supabase
   dashboard / Storage API.
5. **Verify**:
   - A gateway-issued presigned `GET` still returns the object bytes.
   - A direct, unsigned fetch of a bucket object URL now returns `4xx`
     (the security-gap closure this migration exists for).
6. **`dev-migration` bucket** - review separately; keep public only if a
   documented non-tenant use requires it, otherwise flip it too.

## Rollback

Re-flip the bucket to `public: true`. The gateway keeps working either way
(it never depends on public access); the only observable change is that
unsigned direct fetches succeed again.
