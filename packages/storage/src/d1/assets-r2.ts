/**
 * `R2AssetBlobStore` + `commitAssetWithBlob` — the R2 half of the static-asset
 * surface (inventory-data-billing §1.7, inventory-request-path §1.6 "Object
 * storage", issues #176/#259/#260/#371).
 *
 * ## What moved, and why it had to
 *
 * The Rust `stored_assets` row carried the artifact bytes INLINE (≤10 MiB,
 * base64) because the D1 HTTP proxy bound every parameter as TEXT — there was
 * no object store in that path. Running inside a Worker with R2 available,
 * inventory §1.7 is explicit that the inline BYTEA moves to R2, so the row
 * keeps only `content_hash` / `size_bytes` / `storage_uri`, which is exactly
 * what the quota-admission guard reads (it never touched the bytes).
 *
 * ## There is NO transaction spanning R2 and D1 — so ordering IS the protocol
 *
 * R2 and D1 are separate services with separate durability. `batch()` cannot
 * include an object put, and there is no two-phase commit between them. The
 * only correct arrangement is therefore an ordering rule, and it is
 * {@link commitAssetWithBlob}:
 *
 *   1. **put the object first.** A crash here leaves an orphan object: it costs
 *      storage and is swept by {@link R2AssetBlobStore.deleteOrphans}, but it is
 *      never *served*, because nothing can name it — resolution goes through
 *      the row.
 *   2. **then insert the row** (through the caller's quota-admission guard).
 *   3. **on a failed or refused insert, delete the object.** Compensation, not
 *      rollback: it is best-effort, and a failure to compensate degrades to
 *      case 1's orphan.
 *
 * The reverse order (row first) is NOT equivalent and must never be used: it
 * publishes a resolvable asset whose bytes do not exist yet, so a download
 * between the two writes 404s on an asset the API says is `visible`.
 *
 * ## Content addressing
 *
 * {@link assetObjectKey} derives the object key from
 * `tenant / assetType / name / version / variant / contentHash`. Including the
 * hash makes a re-push of identical bytes idempotent at the object layer, and
 * makes a byte-level divergence a DIFFERENT key rather than an overwrite of a
 * published artifact.
 */

import type { StoredAsset } from "../assets.js";
import { StorageError } from "../errors.js";

/** Percent-encode a key segment so `/` in a name cannot forge a key path. */
function segment(value: string): string {
  return encodeURIComponent(value);
}

/**
 * The deterministic R2 object key for one asset, and the value written to
 * `stored_assets.storage_uri`.
 *
 * `variant` is part of the row identity (`UNIQUE (tenant_id, asset_type, name,
 * version, variant)`), so it is part of the key; the empty default variant is
 * spelled `_` rather than collapsing to an empty segment, which would make
 * `a//b` and `a/b` the same key.
 */
export function assetObjectKey(asset: {
  tenantId: string;
  assetType: string;
  name: string;
  version: string;
  variant: string;
  contentHash: string;
}): string {
  return [
    "assets",
    segment(asset.tenantId),
    segment(asset.assetType),
    segment(asset.name),
    segment(asset.version),
    segment(asset.variant === "" ? "_" : asset.variant),
    segment(asset.contentHash),
  ].join("/");
}

/** An asset's bytes plus the metadata R2 records alongside them. */
export interface AssetBlob {
  body: Uint8Array;
  contentType: string;
  contentHash: string;
}

/** The R2 object store for asset artifact bytes. */
export class R2AssetBlobStore {
  constructor(private readonly bucket: R2Bucket) {}

  /**
   * Write the artifact bytes. Returns the key to record in
   * `stored_assets.storage_uri`.
   *
   * `httpMetadata.contentType` is set so a signed/streamed download serves the
   * declared type without the Worker having to re-attach it, and `contentHash`
   * is stored as custom metadata so an integrity check needs no D1 read.
   */
  async put(
    asset: {
      tenantId: string;
      assetType: string;
      name: string;
      version: string;
      variant: string;
      contentHash: string;
    },
    blob: AssetBlob,
  ): Promise<string> {
    const key = assetObjectKey(asset);
    try {
      await this.bucket.put(key, blob.body as unknown as ArrayBuffer | ArrayBufferView, {
        httpMetadata: { contentType: blob.contentType },
        customMetadata: { contentHash: blob.contentHash },
      });
    } catch (error) {
      throw StorageError.runtime(
        `cloudflare r2: writing asset object ${key} failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    return key;
  }

  /** Read the artifact bytes back, or `undefined` when the object is absent. */
  async get(storageUri: string): Promise<AssetBlob | undefined> {
    let object: R2ObjectBody | null;
    try {
      object = await this.bucket.get(storageUri);
    } catch (error) {
      throw StorageError.runtime(
        `cloudflare r2: reading asset object ${storageUri} failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    if (object === null) return undefined;
    return {
      body: new Uint8Array(await object.arrayBuffer()),
      contentType: object.httpMetadata?.contentType ?? "application/octet-stream",
      contentHash: object.customMetadata?.contentHash ?? "",
    };
  }

  /** Whether the object exists, without transferring the body. */
  async exists(storageUri: string): Promise<boolean> {
    return (await this.bucket.head(storageUri)) !== null;
  }

  /** Delete one object. Idempotent — deleting an absent key is not an error. */
  async delete(storageUri: string): Promise<void> {
    try {
      await this.bucket.delete(storageUri);
    } catch (error) {
      throw StorageError.runtime(
        `cloudflare r2: deleting asset object ${storageUri} failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  /**
   * Delete objects under an asset's prefix that no `storage_uri` in
   * `liveStorageUris` names — the sweep for step-1 orphans (a crash between the
   * object put and the row insert) and for superseded content hashes.
   *
   * Fail-safe by construction: an empty `prefix` is refused, because an
   * accidental empty prefix plus an empty live set deletes the whole bucket.
   */
  async deleteOrphans(prefix: string, liveStorageUris: Iterable<string>): Promise<string[]> {
    if (prefix.trim() === "") {
      throw StorageError.runtime(
        "deleteOrphans requires a non-empty prefix; an empty prefix would sweep the bucket",
      );
    }
    const live = new Set(liveStorageUris);
    const deleted: string[] = [];
    let cursor: string | undefined;
    do {
      const listing: R2Objects = await this.bucket.list(
        cursor === undefined ? { prefix } : { prefix, cursor },
      );
      for (const object of listing.objects) {
        if (!live.has(object.key)) {
          await this.bucket.delete(object.key);
          deleted.push(object.key);
        }
      }
      cursor = listing.truncated ? listing.cursor : undefined;
    } while (cursor !== undefined);
    return deleted.sort();
  }
}

/**
 * Result of {@link commitAssetWithBlob}: whatever the caller's row-commit step
 * returned, plus the key that was written (and, when the row step refused, kept
 * or compensated).
 */
export interface AssetCommit<T> {
  outcome: T;
  storageUri: string;
  /** `true` when the row step refused/failed and the object was compensated. */
  compensated: boolean;
}

/**
 * Run the object-then-row commit protocol for one asset.
 *
 * `commitRow` receives the `storage_uri` to record and returns the caller's own
 * outcome (typically the quota-admission classification). `accepted` decides
 * whether that outcome kept the object: an `over_quota` refusal did NOT, so the
 * object is compensated away rather than left orphaned.
 *
 * A throw from `commitRow` compensates and re-throws, so a caller never loses
 * the error and never keeps the bytes for a row that does not exist.
 */
export async function commitAssetWithBlob<T>(
  blobs: R2AssetBlobStore,
  asset: Pick<
    StoredAsset,
    "tenantId" | "assetType" | "name" | "version" | "variant" | "contentHash"
  >,
  blob: AssetBlob,
  commitRow: (storageUri: string) => Promise<T>,
  accepted: (outcome: T) => boolean,
): Promise<AssetCommit<T>> {
  // 1. Object FIRST. An orphan costs storage; the reverse order publishes a
  //    resolvable asset whose bytes do not exist.
  const storageUri = await blobs.put(asset, blob);

  let outcome: T;
  try {
    // 2. Row.
    outcome = await commitRow(storageUri);
  } catch (error) {
    // 3. Compensate, then surface the original failure unchanged.
    await blobs.delete(storageUri).catch(() => undefined);
    throw error;
  }

  if (!accepted(outcome)) {
    await blobs.delete(storageUri).catch(() => undefined);
    return { outcome, storageUri, compensated: true };
  }
  return { outcome, storageUri, compensated: false };
}
