/**
 * The R2-backed, BY-REFERENCE ingress for the two audio uploads — the
 * "with R2 for large uploads" half of issue #703.
 *
 * ## The problem it actually solves, stated exactly
 *
 * `readAudioUpload`'s inline ceiling is NOT a memory optimisation waiting to be
 * undone. It is the only correct answer to an unbounded request body: a
 * `Content-Length` can lie, a chunked upload declares nothing at all, and the
 * only defence is to stop pulling from the stream. Nothing about R2 changes
 * that, and nothing here weakens it — the inline path is untouched.
 *
 * What R2 changes is where the bytes come from. When the caller has already
 * PUT the recording to the bucket — out of band, straight to R2's S3 API
 * through the presigned-upload flow `/v1/assets/presign/upload/**` publishes,
 * resumable, never through this Worker — three things become true that are not
 * true of an inline upload:
 *
 *  1. **the size is MEASURED, not asserted.** `stored_assets.size_bytes` is
 *     what the commit step recorded for bytes R2 actually holds. A request over
 *     the ceiling is therefore refused from METADATA ALONE, before a single
 *     byte is read — which the inline path cannot do, because there the only
 *     size available before reading is one the client wrote.
 *  2. **the Worker never carries the upload.** A 40 MiB recording crossing a
 *     mobile link is an S3 multipart PUT against R2, not a single shot through
 *     an isolate with a request timeout.
 *  3. **the same object can be read again.** A retry, a second model, a
 *     translation of the recording you already transcribed — none of them
 *     re-uploads.
 *
 * So the ceiling on THIS path is a different number for a different reason, and
 * it is set by isolate memory rather than by ingest risk. See
 * {@link MAX_AUDIO_REFERENCE_BYTES} for the arithmetic and for what is still
 * bounded.
 *
 * ## Why it reuses the asset registry rather than inventing an upload surface
 *
 * There is already exactly one way to get large bytes into this deployment's
 * bucket, with an entitlement check, a storage quota, a malware scan (#366), a
 * signature policy, a yank switch and a tenant-prefixed key layout whose
 * isolation is checkable by LOOKING at the key. A second audio-only upload
 * endpoint would have had to re-earn all of it, and would have failed to: the
 * interesting question is not "can I store bytes" but "may THIS caller read
 * THESE bytes, and have they been screened yet". Both answers already exist in
 * `stored_assets`, so this module asks them rather than restating them.
 *
 * A consequence worth naming: a recording that is `pending_scan` or
 * `quarantined` is NOT transcribable. Reading around the scan gate would have
 * made #366 decorative — upload the file, get it flagged, transcribe it anyway.
 */

import { assetMetadataStoreFromEnv } from "../assets/d1.js";
import { CrossTenantKeyError, assertKeyBelongsToTenant, storedAssetId } from "../assets/keys.js";
import { type AssetMetadataStore, type AssetObjectStore, isDownloadable } from "../assets/ports.js";
import { type InferenceRejection, reject } from "./errors.js";
import type { AudioUploadFile } from "./schemas.js";

/**
 * The logical address of a stored recording, as a caller writes it in the
 * `file_ref` form field: `"{asset_type}/{name}/{version}"`.
 *
 * It is the SAME coordinate the presign flow addresses
 * (`POST /v1/assets/presign/upload/{asset_type}/{name}/{version}`), so a caller
 * that just published a recording already holds every part of it and needs no
 * new identifier — and, more importantly, cannot name an object it did not
 * publish, because the tenant half of the address is taken from the credential
 * rather than from the request.
 */
export interface AudioObjectReference {
  readonly assetType: string;
  readonly name: string;
  readonly version: string;
}

/**
 * Parse a `file_ref` field. `null` for anything that is not exactly three
 * non-empty segments.
 *
 * There is deliberately no normalisation, no `..` resolution and no percent
 * decoding here: a segment containing `/` simply produces the wrong number of
 * parts and is refused. The key layout does its own encoding
 * (`encodeKeySegment`), so a `..` that somehow arrived would address a key
 * literally named `..` inside the tenant's own prefix rather than escaping it —
 * but refusing it at the door is cheaper than relying on that, and it gives the
 * caller a 400 that names their mistake.
 */
export function parseAudioObjectReference(value: string): AudioObjectReference | null {
  const parts = value.split("/");
  if (parts.length !== 3) return null;
  const [assetType, name, version] = parts;
  if (
    assetType === undefined ||
    name === undefined ||
    version === undefined ||
    assetType === "" ||
    name === "" ||
    version === "" ||
    assetType === "." ||
    assetType === ".." ||
    name === "." ||
    name === ".." ||
    version === "." ||
    version === ".."
  ) {
    return null;
  }
  return { assetType, name, version };
}

/**
 * Resolves a `file_ref` to the recording's bytes, or to the rejection that
 * explains why it will not.
 *
 * A PORT rather than a concrete class because the composition root wires it
 * from `env.ASSETS` + `env.DB` while every handler test injects its own — the
 * same shape `circuit` / `shadowBudget` / `byok` already use.
 */
export interface AudioObjectSource {
  open(
    tenantId: string,
    reference: AudioObjectReference,
    maxBytes: number,
  ): Promise<AudioUploadFile | InferenceRejection>;
}

/**
 * The refusal a deployment with NO object store gets.
 *
 * 503 and not 400: the caller's request is well formed and would be served on a
 * deployment that bound `ASSETS`. Answering "no file part" would name the
 * caller as the fault for an operator's missing binding, and would send them
 * hunting through their own code.
 */
export const NO_AUDIO_OBJECTS: AudioObjectSource = {
  async open(): Promise<InferenceRejection> {
    return reject(
      503,
      "audio_reference_unavailable",
      "this deployment has no object store bound, so an audio file_ref cannot be resolved",
    );
  },
};

export interface StoredAssetAudioObjectsDeps {
  readonly metadata: AssetMetadataStore;
  readonly objects: AssetObjectStore;
}

/**
 * The production {@link AudioObjectSource}: the asset registry for the address
 * and the guards, R2 for the bytes.
 *
 * The ORDER of the checks below is the substantive part, because each one is
 * cheaper than the next and each one is a refusal that must not pay for the
 * ones after it:
 *
 *  1. the row, keyed by an id DERIVED from the caller's own tenant. A caller
 *     cannot address another tenant's row at all — `storedAssetId` folds the
 *     tenant in, so tenant A asking for tenant B's `recording/meeting/1.0.0`
 *     computes an id that does not exist. This is the isolation; the two checks
 *     below it are defence in depth behind it, not the mechanism.
 *  2. the key's tenant prefix, via the SAME `assertKeyBelongsToTenant` the
 *     asset service runs before every read. Structural, cheap, fail-closed.
 *  3. the screening state — `visible` and not yanked. See the module header.
 *  4. the SIZE, from the row. This is the one that has to happen before the R2
 *     read, and it is the reason the by-reference ceiling can be higher than
 *     the inline one at all.
 *  5. only now, the bytes.
 */
export function storedAssetAudioObjects(deps: StoredAssetAudioObjectsDeps): AudioObjectSource {
  return {
    async open(
      tenantId: string,
      reference: AudioObjectReference,
      maxBytes: number,
    ): Promise<AudioUploadFile | InferenceRejection> {
      const id = storedAssetId(tenantId, reference.assetType, reference.name, reference.version);
      const asset = await deps.metadata.getAsset(id);
      // `tenant_id` is re-checked even though the id derives from it: an
      // operator-supplied metadata store is a port, and a port that answered a
      // row for the wrong tenant would otherwise be trusted.
      if (asset === null || asset.tenant_id !== tenantId || asset.storage_uri === "") {
        return notFound(reference);
      }
      try {
        assertKeyBelongsToTenant(asset.storage_uri, tenantId);
      } catch (error) {
        if (error instanceof CrossTenantKeyError) {
          // Not a 403: telling a caller "that object exists but is not yours"
          // is an existence oracle over another tenant's namespace.
          return notFound(reference);
        }
        throw error;
      }
      if (asset.yanked || !isDownloadable(asset.visibility)) {
        return reject(
          409,
          "audio_reference_not_readable",
          `stored recording '${referenceLabel(reference)}' is ${
            asset.yanked ? "yanked" : asset.visibility
          } and cannot be transcribed`,
        );
      }
      if (asset.size_bytes > maxBytes) {
        // Refused on the SIZE THE OBJECT STORE RECORDED, before any read. The
        // whole point of the by-reference path.
        return reject(
          413,
          "payload_too_large",
          `stored recording '${referenceLabel(reference)}' is ${asset.size_bytes} bytes, above the ${maxBytes}-byte by-reference ceiling`,
        );
      }
      const object = await deps.objects.get(asset.storage_uri);
      if (object === null) {
        return reject(
          503,
          "storage_unavailable",
          `the bytes of stored recording '${referenceLabel(reference)}' are missing from the object bucket`,
        );
      }
      const bytes = new Uint8Array(await object.arrayBuffer());
      if (bytes.byteLength === 0) {
        return reject(
          400,
          "invalid_request",
          `stored recording '${referenceLabel(reference)}' is empty`,
        );
      }
      if (bytes.byteLength > maxBytes) {
        // The row and the bucket disagreed — a partially-committed object, or a
        // registry an operator edited. The bytes win, and they are dropped
        // rather than dispatched: the ceiling is a memory bound, so a figure it
        // was checked against and then exceeded is not a bound at all.
        return reject(
          413,
          "payload_too_large",
          `stored recording '${referenceLabel(reference)}' is ${bytes.byteLength} bytes, above the ${maxBytes}-byte by-reference ceiling`,
        );
      }
      return {
        bytes,
        filename: `${reference.name}-${reference.version}`,
        contentType: asset.content_type === "" ? "application/octet-stream" : asset.content_type,
      };
    },
  };
}

function referenceLabel(reference: AudioObjectReference): string {
  return `${reference.assetType}/${reference.name}/${reference.version}`;
}

function notFound(reference: AudioObjectReference): InferenceRejection {
  return reject(
    404,
    "audio_reference_not_found",
    `no stored recording '${referenceLabel(reference)}' is published for this tenant`,
  );
}

/** The bindings {@link audioObjectsFromEnv} reads. */
export interface AudioObjectBindings {
  /** `[[r2_buckets]] binding = "ASSETS"` — the same bucket `/v1/assets/**` uses. */
  readonly ASSETS?: unknown;
}

/**
 * Worker bindings → the audio object source.
 *
 * BOTH halves are required, and the conjunction is the point: the registry
 * without the bucket resolves an address to bytes nobody holds, and the bucket
 * without the registry has no tenant guard, no screening state and no size to
 * check before reading. Either alone is worse than neither, so a partial
 * binding answers {@link NO_AUDIO_OBJECTS} — 503, fail closed.
 */
export function audioObjectsFromEnv(env: Record<string, unknown>): AudioObjectSource {
  const objects = env.ASSETS;
  const metadata = assetMetadataStoreFromEnv(env);
  if (metadata === null || !isAssetObjectStore(objects)) {
    return NO_AUDIO_OBJECTS;
  }
  return storedAssetAudioObjects({ metadata, objects });
}

/** Structural check for a live `R2Bucket`; the port is deliberately R2-shaped. */
function isAssetObjectStore(value: unknown): value is AssetObjectStore {
  const candidate = value as Partial<AssetObjectStore> | null | undefined;
  return (
    typeof candidate === "object" &&
    candidate !== null &&
    typeof candidate.get === "function" &&
    typeof candidate.put === "function"
  );
}
