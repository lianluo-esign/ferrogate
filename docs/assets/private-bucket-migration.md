# Private storage-bucket migration (#259, slice 3/7)

Runbook for flipping the Supabase Storage `ferrogate` bucket from **public** to
**private** so tenant isolation is enforced at the storage layer, not only at the
gateway API layer. Pairs with the #259 code work (gateway-issued presigned
GET/PUT + private read path).

## Why

Today the `ferrogate` bucket is `public: true`. The gateway enforces tenant
scoping on `/v1/assets/*`, but anyone who learns an object path can read it
directly from the public Storage URL, **bypassing** gateway authz. That is a
security gap. After migration, every read/write goes through a short-TTL,
gateway-authorized presigned URL (or a gateway-proxied stream).

## Current live state (audited 2026-07-19, project `wpgzljfyunypmuacyesv`)

| bucket | public | objects | bytes | notes |
|---|---|---|---|---|
| `ferrogate` | **true** | 1 | ~59 KB | asset content bucket — **flip to private** |
| `dev-migration` | true | 1 | ~83 KB | review separately; keep public only if a documented dev need exists |

Both hold a single test object, so the migration has **negligible existing-object
impact** — no bulk re-keying or data movement required.

## Preconditions (code must land first)

The bucket flip is **safe only after** the #259 gateway code is deployed:
- Download path issues gateway-authorized presigned GETs (or proxies the stream);
  no code path relies on the anonymous public URL.
- Upload path uses presigned PUT + commit (HEAD size/sha256 verify) — see #259.
Do NOT flip the bucket before that code is live, or existing/authenticated
downloads that assume public URLs will break.

## Migration steps

1. **Snapshot / note** the current object inventory (above) for rollback.
2. **Deploy** the #259 gateway build (presigned read/write path).
3. **Flip `ferrogate` to private** — either the Supabase dashboard (Storage →
   bucket → make private) or the management API / `update_storage_config`
   equivalent. Optionally set a `file_size_limit` aligned with the per-plan
   ceiling (#259 scope item 2); it is currently unset (null).
4. **Verify**:
   - Anonymous `GET https://<project>.supabase.co/storage/v1/object/public/ferrogate/<path>`
     now returns 400/403 (no longer served).
   - Gateway `/v1/assets/*` download still works (issues a presigned GET).
   - A cross-tenant key cannot obtain a presigned URL for another tenant's object.
5. **`dev-migration`**: decide keep-public (documented dev reason) or also flip.

## Rollback

Re-flip the bucket to public via the same surface. With only 1 object and no
re-keying, rollback is immediate and lossless. Keep it public only as a temporary
measure while diagnosing a presigned-path regression.

## Not done autonomously

Flipping a production bucket's visibility is an outward-facing, hard-to-reverse
security change and is **gated on operator sign-off** — it is intentionally not
performed by tooling/agents. This runbook is the plan; execution is a human step
once the #259 code is verified in place.
