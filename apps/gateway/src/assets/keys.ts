/**
 * Deterministic, tenant-isolated R2 key layout for `/v1/assets/**`, plus the
 * durable row identities the metadata store keys on.
 *
 * Clean-room port of the Rust key/identity helpers:
 *  - `ferrogate_storage::{stored_asset_id, stored_asset_variant_id, asset_channel_id}`
 *  - `server::asset_presign::{staging_object_key, final_object_prefix, new_final_object_key}`
 *
 * ## Why the layout changed shape (and what is preserved)
 *
 * The Rust bucket keys were *digest* keys —
 * `.ferrogate/objects/{sha256(id|upload_id)}/obj_{rand}` — which hide the
 * tenant inside an opaque hash. Isolation was therefore an *implicit*
 * property of the digest input and could not be checked by looking at a key.
 *
 * On R2 the layout is made explicit instead: **every** object key starts with
 * `assets/v1/t/{tenant}/`, so
 *  - a tenant's objects live under one prefix (`r2.list({ prefix })` per tenant),
 *  - {@link assertKeyBelongsToTenant} is a real, cheap, fail-closed guard the
 *    service runs before every read/write/presign, and
 *  - a key from tenant B is *structurally* rejected for tenant A rather than
 *    merely being unguessable.
 *
 * Preserved from the Rust layout:
 *  - the staging key is **server-derived** from `(asset id, upload_id,
 *    size_bytes, sha256)`, so a caller cannot name — and therefore cannot
 *    abort or overwrite — an upload it did not register (Rust issue #368);
 *  - the final object name carries 128 bits of fresh randomness under an
 *    intent-derived prefix, so two concurrent first pushes of the same version
 *    can never clobber each other's bytes (Rust issue #369);
 *  - a committed object is never written under a client-chosen key.
 *
 * Every path segment is percent-encoded, so the layout round-trips through
 * {@link parseAssetObjectKey} even when a tenant id / name / version contains
 * `/`, `%`, or other reserved bytes (the static-site per-file addressing of
 * Rust issue #398 puts a whole nested file path in the `{version}` segment).
 */
import { randomHex128 } from "./hash.js";

/** Root of every asset object key. Versioned so a future layout can coexist. */
export const ASSET_KEY_ROOT = "assets/v1";

/** Marker segment for "the default (no-platform) variant". */
export const DEFAULT_VARIANT_SEGMENT = "_";

/** The logical address of one immutable asset artifact. */
export interface AssetObjectRef {
  readonly tenantId: string;
  readonly assetType: string;
  readonly name: string;
  readonly version: string;
  /** Platform/arch variant; `""` is the default artifact. */
  readonly variant: string;
}

/**
 * Percent-encode one key segment. `encodeURIComponent` already escapes `/`
 * (→ `%2F`) and `%` (→ `%25`), which is exactly what makes the layout
 * unambiguously parseable; `!'()*` are additionally escaped so the encoding is
 * a strict RFC-3986 unreserved-set encoding and therefore stable.
 */
export function encodeKeySegment(segment: string): string {
  return encodeURIComponent(segment).replace(
    /[!'()*]/g,
    (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/** Inverse of {@link encodeKeySegment}. */
export function decodeKeySegment(segment: string): string {
  return decodeURIComponent(segment);
}

/** `assets/v1/t/{tenant}/` — everything this tenant owns lives below here. */
export function tenantKeyPrefix(tenantId: string): string {
  return `${ASSET_KEY_ROOT}/t/${encodeKeySegment(tenantId)}/`;
}

/** `assets/v1/t/{tenant}/obj/{type}/{name}/{version}/{variant}/`. */
export function assetObjectPrefix(ref: AssetObjectRef): string {
  const variant = ref.variant === "" ? DEFAULT_VARIANT_SEGMENT : encodeKeySegment(ref.variant);
  return (
    `${tenantKeyPrefix(ref.tenantId)}obj/` +
    `${encodeKeySegment(ref.assetType)}/${encodeKeySegment(ref.name)}/` +
    `${encodeKeySegment(ref.version)}/${variant}/`
  );
}

/**
 * A fresh, unique object key for one publish attempt (Rust
 * `new_final_object_key`). Never derived from client input alone: the
 * `obj_{128-bit random}` suffix means a losing concurrent attempt can only
 * ever clean up the bytes *it* wrote.
 */
export function newAssetObjectKey(ref: AssetObjectRef): string {
  return `${assetObjectPrefix(ref)}obj_${randomHex128()}`;
}

/**
 * The R2 key of ONE file inside an expanded `static_site` bundle (issue #736).
 *
 * `…/{version}/{variant}/bundle/{percent-encoded path}` — one extra segment
 * under the SAME per-version prefix the single-object layout already uses, so a
 * bundle's files are inside the version's own prefix and inside the tenant's
 * own prefix, and {@link assertKeyBelongsToTenant} guards them with no new
 * rule.
 *
 * The whole relative path is ONE encoded segment rather than a nested path.
 * That is deliberate and is a defence in depth behind
 * `bundle.ts::bundlePathRejection`: `encodeKeySegment` turns `/` into `%2F` and
 * `.` stays literal but can no longer act as a separator, so even a path that
 * somehow reached here with a `..` in it addresses a key literally named
 * `..%2Fx` rather than escaping the prefix. There is no path arithmetic on the
 * key side at all.
 */
export function bundleFileObjectKey(ref: AssetObjectRef, path: string): string {
  return `${assetObjectPrefix(ref)}bundle/${encodeKeySegment(path)}`;
}

/**
 * Prefix of every final object one presigned upload could ever produce (Rust
 * `final_object_prefix`).
 *
 * The upload id is folded into the object NAME rather than into a new path
 * segment, so {@link parseAssetObjectKey} still round-trips a commit key. That
 * prefix is what makes the commit idempotent without trusting the client: an
 * already-published row is recognized as "this same upload's" purely by whether
 * its `storage_uri` starts here, so a retry of an identical commit returns the
 * winner instead of a spurious `asset_version_immutable`, while a *different*
 * upload's commit onto the same version is still refused.
 */
export function commitObjectKeyPrefix(ref: AssetObjectRef, uploadId: string): string {
  return `${assetObjectPrefix(ref)}obj_${encodeKeySegment(uploadId)}_`;
}

/**
 * A fresh final key for one presigned commit. Carries 128 bits of randomness
 * under the upload-derived prefix, so a losing concurrent commit can only ever
 * clean up the bytes IT wrote (Rust `new_final_object_key`, issue #369).
 */
export function newCommitObjectKey(ref: AssetObjectRef, uploadId: string): string {
  return `${commitObjectKeyPrefix(ref, uploadId)}${randomHex128()}`;
}

/**
 * The staging key a presigned upload PUTs to (Rust `staging_object_key`).
 *
 * Server-derived from the three declarations the intent registered, so the
 * same `(upload_id, size_bytes, sha256)` triple is required to name it at
 * commit or abort time. Deterministic and synchronous — no digest needed,
 * because the tenant prefix already isolates it and the triple already binds
 * it to one registered intent.
 */
export function stagingObjectKey(
  ref: AssetObjectRef,
  uploadId: string,
  sizeBytes: number,
  sha256: string,
): string {
  const scope = `${encodeKeySegment(ref.assetType)}.${encodeKeySegment(ref.name)}.${encodeKeySegment(ref.version)}`;
  return (
    `${tenantKeyPrefix(ref.tenantId)}staging/${encodeKeySegment(uploadId)}/` +
    `${scope}/${sizeBytes}-${sha256.toLowerCase()}`
  );
}

/**
 * Parse an object key back to its logical address. Returns `null` for a key
 * that is not an asset object key (staging keys included — they are not
 * addressable artifacts).
 */
export function parseAssetObjectKey(key: string): AssetObjectRef | null {
  const parts = key.split("/");
  // assets / v1 / t / {tenant} / obj / {type} / {name} / {version} / {variant} / obj_xxx
  if (parts.length !== 10) return null;
  const [root, layout, t, tenant, obj, type, name, version, variant, leaf] = parts;
  if (root !== "assets" || layout !== "v1" || t !== "t" || obj !== "obj") {
    return null;
  }
  if (!leaf?.startsWith("obj_")) return null;
  if (
    tenant === undefined ||
    type === undefined ||
    name === undefined ||
    version === undefined ||
    variant === undefined
  ) {
    return null;
  }
  try {
    return {
      tenantId: decodeKeySegment(tenant),
      assetType: decodeKeySegment(type),
      name: decodeKeySegment(name),
      version: decodeKeySegment(version),
      variant: variant === DEFAULT_VARIANT_SEGMENT ? "" : decodeKeySegment(variant),
    };
  } catch {
    return null;
  }
}

/** True when `key` lies inside `tenantId`'s prefix. Fail-closed on garbage. */
export function keyBelongsToTenant(key: string, tenantId: string): boolean {
  if (key.includes("..")) return false;
  return key.startsWith(tenantKeyPrefix(tenantId));
}

/**
 * The one cross-tenant guard. Every service path that touches object storage —
 * read, write, delete, presign — runs this on the key BEFORE the bucket call,
 * so a `storage_uri` that somehow references another tenant's prefix (a
 * corrupted row, a hand-crafted id) is refused rather than served.
 */
export function assertKeyBelongsToTenant(key: string, tenantId: string): void {
  if (!keyBelongsToTenant(key, tenantId)) {
    throw new CrossTenantKeyError(key, tenantId);
  }
}

/** Thrown by {@link assertKeyBelongsToTenant}; mapped to a 404 by the service. */
export class CrossTenantKeyError extends Error {
  override readonly name = "CrossTenantKeyError";
  readonly key: string;
  readonly tenantId: string;

  constructor(key: string, tenantId: string) {
    super("asset object key does not belong to the calling tenant");
    this.key = key;
    this.tenantId = tenantId;
  }
}

// ---------------------------------------------------------------------------
// Durable row identities (metadata store keys).
// ---------------------------------------------------------------------------

/**
 * Deterministic id for an asset row so a create is naturally idempotent per
 * `(tenant_id, asset_type, name, version)` — Rust `stored_asset_id`.
 */
export function storedAssetId(
  tenantId: string,
  assetType: string,
  name: string,
  version: string,
): string {
  return `${tenantId}:${assetType}:${name}:${version}`;
}

/**
 * Variant-aware asset id — Rust `stored_asset_variant_id`. The default (empty)
 * variant keeps the historical {@link storedAssetId} shape; a platform variant
 * appends `:v:{variant}` so several artifacts of one `{name}/{version}`
 * coexist under distinct ids.
 */
export function storedAssetVariantId(
  tenantId: string,
  assetType: string,
  name: string,
  version: string,
  variant: string,
): string {
  const base = storedAssetId(tenantId, assetType, name, version);
  return variant === "" ? base : `${base}:v:${variant}`;
}

/** Deterministic id for a channel pointer — Rust `asset_channel_id`. */
export function assetChannelId(
  tenantId: string,
  assetType: string,
  name: string,
  channel: string,
): string {
  return `${tenantId}:${assetType}:${name}:${channel}`;
}

/** A fresh presigned-upload id — Rust `new_upload_id` (`upl_` + 32 hex). */
export function newUploadId(): string {
  return `upl_${randomHex128()}`;
}

/** True for a well-formed upload id — Rust `is_upload_id`. */
export function isUploadId(value: string): boolean {
  return /^upl_[0-9a-f]{32}$/.test(value);
}
