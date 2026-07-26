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
  entitlement + tenant scoping), preflights the declared per-object size and
  cumulative tenant `asset_storage_quota_bytes`, audits, and returns a
  short-TTL SigV4 `PUT` URL plus a unique opaque `upload_id`. Each intent uses
  a separate staging object bound to the tenant, logical asset identity,
  declared size, and SHA-256. The response `key` is the logical asset ID, not a
  bucket key. Bytes go straight to staging, bypassing the Pingora hot path.
  The URL is **bound** to the declared size and SHA-256 (#368); the response's
  `required_headers` must be sent verbatim on the `PUT`. See "Upload contract
  the integrator MUST honor" below.
- **Abort** - `POST /v1/assets/presign/abort/{asset_type}/{name}/{version}`
  releases an intent that will never be committed, *attempting* to delete its
  staging object immediately instead of leaving it to the orphan GC (#368). The
  attempt can be refused by the bucket, so the response reports what actually
  happened in `staging_reclamation` (`not_staged` / `removed` /
  `removal_failed`), never what it intended.
- **Commit** - `POST /v1/assets/presign/commit/{asset_type}/{name}/{version}`
  requires that `upload_id`, verifies the staging object's size (HEAD) and
  SHA-256, and applies the built-in content/type checks. It then copies
  verified bytes to a new internal immutable final key and conditionally
  creates the `stored_assets` metadata row. That key is never a client `PUT`
  target and is not serialized in list, manifest, or standalone response
  fields. An authorized presigned download URL necessarily contains its path.
  Only the metadata create makes the asset visible and counts it toward quota.
- **Presigned download** - `GET /v1/assets/presign/download/{asset_type}/{name}/{version}`
  returns a short-TTL presigned `GET` URL plus the object's `sha256` and
  `size_bytes` so the agent can verify the bytes it fetches directly.

The presigned commit path **does** run the same supply-chain screening service
as the inline push (`asset_security::screen_asset_push`, added in #366):
detached-signature verification, the cross-tenant publish approval gate, the
pluggable malware scanner, and the pending/quarantined store-but-withhold
states. The commit body carries `signature` / `signature_format` /
`signature_key_id` / `visibility` / `approval_id`, mirroring the inline path's
`x-asset-signature*` / `x-asset-visibility` / `x-asset-approval-id` headers
one-for-one. There is no supply-chain reason to keep signed or approval-gated
assets off the presigned path.

The one parity limit is a **memory** limit, not a policy one, and it is stated
in full under "Large objects and the gateway memory bound" below: above
`[asset_bucket].max_gateway_buffer_bytes` the gateway never holds the object,
so whole-file controls that need the bytes (detached-signature verification,
out-of-process scanner backends, `mcp_manifest` transport parsing) cannot run
and the commit **fails closed** rather than skipping them.

All reads for bucket-backed objects can go through gateway-issued presigned
GETs, so the public bucket URL is no longer required for correctness.

## Large objects and the gateway memory bound

Object bytes never traverse the gateway on the upload or download legs -- those
are direct client-to-bucket transfers over presigned URLs. The commit leg is
different: the gateway has to read the staged object back to verify its SHA-256
and screen it before publishing. `[asset_bucket].max_gateway_buffer_bytes`
(default 10 MiB) is the ceiling on how much of an object it will hold while
doing that, and it splits the commit into two behaviors:

- **At or below the bound** — the object is buffered and screened at full
  fidelity. Unchanged behavior.
- **Above the bound** — the object is verified and copied to its final key in a
  single streaming pass: fixed-size chunks feed an incremental SHA-256 and an
  incremental malware-signature screen (with a carry window across chunk
  boundaries, so a signature cannot hide on a boundary) and are handed straight
  to the final `PUT`. Resident cost is one HTTP chunk regardless of object
  size. A mismatch deletes the final candidate **and** the staging object and
  returns the same `422` the buffered path returns; the final key is fresh
  128-bit randomness that no published row references, so unverified bytes are
  never reachable.

Three controls cannot be answered from a stream, and each fails closed rather
than degrading:

| Control | Above the bound |
|---|---|
| Detached publisher signature | `422 asset_signature_requires_buffering`. Never downgraded to "unsigned" — that would void a signing requirement for exactly the largest artifacts. |
| Out-of-process scanner (ClamAV / HTTP backend) | Stored `pending_scan`: **invisible and not downloadable** until an out-of-band scan promotes it. Never treated as clean. The built-in offline signature scan still runs over every byte. |
| `mcp_manifest` transport | `422 asset_rejected`. The `stdio` check needs the whole JSON document, and an unchecked `stdio` manifest makes a *consuming* agent's MCP client spawn an arbitrary local process. |

Raise `max_gateway_buffer_bytes` to re-enable those controls for larger objects
and accept the proportional memory cost explicitly. Note the cost is per
in-flight commit and there is no cap on concurrent commits, so
`max_gateway_buffer_bytes x expected concurrency` is the number to size against.

The **registry pull** (`GET /v1/assets/{asset_type}/{name}/{version}`) serves
from a full in-memory copy, so it refuses a bucket-backed object above the same
bound with `413 asset_too_large_for_inline_pull` and names the presigned
download endpoint in the message. Large objects are pulled the way they were
pushed: directly from the bucket.

Bucket transport failures are reported to callers as a generic
`503 asset_bucket_unavailable` with the diagnostic detail (including the
internal object key) written to the gateway log against the response's
`request_id`. The underlying HTTP error's text embeds the request URL, so
returning it verbatim would publish the internal final key and the bucket
endpoint — the thing this runbook promises never appears in a response.

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
- `max_gateway_buffer_bytes` — the largest object the gateway will hold in
  memory for an asset operation; defaults to 10 MiB (the inline-push cap, so an
  inline-stored asset is never affected). This is the bound
  `presign_max_object_bytes` is **not**: the ceiling caps how large an object
  may be, this caps how much of one is ever resident. See "Large objects and
  the gateway memory bound" above.

`presign_ttl_secs` is the **URL expiry**: it is signed into `X-Amz-Expires`, so
the bucket itself refuses a late `PUT` and the client must register a new
intent. It is echoed as `expires_in_seconds` on the intent response.
`presign_max_object_bytes` is echoed as `max_object_bytes`, tightened to the
tenant's per-object ceiling and cumulative quota, so a client can fail fast.

## Upload contract the integrator MUST honor (#368)

The presigned `PUT` authorization is **bound** to the declared content length
and payload checksum. `content-length` and `x-amz-content-sha256` are SigV4
`SignedHeaders` of `upload_url`, and the canonical request's payload-hash line
carries the declared SHA-256 rather than `UNSIGNED-PAYLOAD`. Changing either
value, or omitting either header, invalidates the signature: the bucket rejects
the request with `403` **before** storing bytes. This is bucket-enforced, not a
commit-time admission control.

Integrators must therefore:

1. **Send `required_headers` verbatim.** The intent response returns them as an
   exact header-name -> value map. A client that sends only `Content-Type` gets
   a `403` from any real S3-compatible bucket.
2. **In a browser, do not set `content-length` yourself.** The Fetch spec
   forbids it; the browser derives it from the body, which is the signed value
   as long as the body is exactly `size_bytes` long. Send
   `x-amz-content-sha256` explicitly. Non-browser clients should send both.
3. **Allow the header through CORS.** A browser preflights the `PUT`, so the
   bucket's CORS policy must include `x-amz-content-sha256` in
   `Access-Control-Allow-Headers` (alongside `content-type`) with `PUT` in
   `Access-Control-Allow-Methods`. Without it the preflight fails and the upload
   never starts. On Supabase this is the bucket's CORS configuration; on AWS S3
   it is the bucket CORS rule.
4. **Upload in a single `PUT`.** `upload_protocol` is always `single_put`.
   Multipart is deliberately unsupported: S3 signs each part separately, so one
   presigned authorization cannot bind the whole object's length and checksum —
   exactly the invariant this endpoint exists to enforce. The per-object ceiling
   keeps objects inside what a single `PUT` accepts.
5. **Abort an intent you will not commit.**
   `POST /v1/assets/presign/abort/{asset_type}/{name}/{version}` with the
   intent's `upload_id`, `size_bytes` and `sha256` releases it: any staging
   object is deleted immediately instead of waiting for the lifecycle GC.
   **Read `staging_reclamation`, not just the HTTP status** — the delete can be
   refused by the bucket, and the abort still returns `200` because the intent
   *was* released. `removal_failed` means the bytes still count against the
   tenant's quota until the lifecycle GC collects them; `staging_object_removed`
   is `true` only for a delete the bucket confirmed, and the outcome is
   `aborted_reclaim_failed`. Pass `"reason": "bucket_rejected"` **only** when
   the direct `PUT` itself came back non-2xx — see the evidence table below for
   why over-claiming it corrupts an operator signal. Already committed uploads
   return `409` — abort is never a way to delete a published immutable version.
6. **Do not rely on the staging object's metadata.** `content-type` and user
   metadata are not signed, so a URL holder can choose them on the staging
   object. This is not exploitable: staging objects are never served (reads are
   gateway-issued presigned `GET`s of *final* keys) and the gateway writes the
   final object with its own content type after validation.

### What the rejection evidence does and does not prove

The gateway is **not in the direct `PUT`'s path**, so it cannot observe a bucket
refusal first-hand. Read the audit outcomes and the
`ferrogate_asset_presign_*` counters with that in mind:

| Class | Evidence | Metric |
|---|---|---|
| `rejected_intent` | Gateway-observed preflight refusal (ceiling/quota). | `ferrogate_asset_presign_rejected_total{stage="intent"}` |
| `rejected_bucket` | **Caller-asserted** at abort, with only a negative consistency check (the gateway finds no object under the staging key). A contradicted claim is downgraded to `aborted`. **Not an independent observation and not a security signal on its own**: any holder of `assets.write` can register an intent, upload nothing, and abort with `reason=bucket_rejected` to increment this counter at will. Read it as "clients reporting bucket refusals", against `intents_issued`. | `ferrogate_asset_presign_rejected_total{stage="bucket"}` |
| `rejected_commit` | Gateway-observed over the staged bytes (size/hash/content/screening/quota). | `ferrogate_asset_presign_rejected_total{stage="commit"}` |
| `staging_missing` | Commit found nothing staged. **Ambiguous**: never attempted, URL expired, or bucket-refused. Deliberately not counted as a bucket rejection. | `ferrogate_asset_presign_staging_missing_total` |
| `aborted` | Client released the intent. Counts the release, not the reclamation. | `ferrogate_asset_presign_aborted_total` |
| `aborted_reclaim_failed` | The abort found staged bytes and the bucket refused to delete them, so the promised immediate reclamation did **not** happen and the bytes still hold quota. Gateway-observed. Alert on this: non-zero means the abort surface is issuing promises the bucket is not honoring. | `ferrogate_asset_presign_abort_reclaim_failed_total` |
| orphan GC | Lifecycle sweeper deleted an aged staging/unreferenced object (`asset.gc.delete`). | `ferrogate_asset_lifecycle_pruned_total` |

Fully independent proof of a bucket refusal would require bucket access logs,
which no configured S3-compatible backend exposes to the gateway today. A client
that is refused and simply walks away contributes at most a `staging_missing` at
commit time, or nothing at all.

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
   - A presigned `PUT` that omits `x-amz-content-sha256` returns `403`, and one
     that sends `required_headers` verbatim succeeds (#368). If browser uploads
     are in scope, confirm the bucket CORS policy allows that header first.
6. **`dev-migration` bucket** - review separately; keep public only if a
   documented non-tenant use requires it, otherwise flip it too.

## Rollback

Re-flip the bucket to `public: true`. The gateway keeps working either way
(it never depends on public access); the only observable change is that
unsigned direct fetches succeed again.
