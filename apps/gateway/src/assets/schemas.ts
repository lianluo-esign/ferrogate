/**
 * Zod schemas for every `/v1/assets/**` boundary: path params, query params,
 * control bodies, and the response DTOs.
 *
 * Clean-room port of the Rust request/response types in
 * `crates/ferrogate-gateway/src/responses.rs` (`AssetSummary`,
 * `WithheldAssetSummary`, `AssetStorageSummary`, `AssetManifest*`,
 * `AssetChannel*`, `AssetVisibilityPromotion*`, `AssetMutationResponse`) and the
 * control bodies in `server/asset_presign.rs`
 * (`PresignUploadIntentRequest`, `PresignCommitRequest`, `PresignAbortRequest`).
 *
 * The presign control bodies are `.strict()` because the Rust ones carried
 * `#[serde(deny_unknown_fields)]` — a typo'd screening field must fail loudly
 * rather than silently skip a control.
 */
import { z } from "zod";

// ---------------------------------------------------------------------------
// Path + query params
// ---------------------------------------------------------------------------

/**
 * One address segment. Bounded and control-character-free, but otherwise
 * permissive: the Rust `{version}` segment doubles as the per-file static-site
 * address (issue #398), so it may legitimately contain a decoded `/`.
 */
const addressSegment = z
  .string()
  .min(1)
  .max(512)
  // Matching control characters IS the point: this segment becomes an object
  // key and a response header value, so a raw CR/LF or NUL must be refused
  // rather than smuggled into either.
  // biome-ignore lint/suspicious/noControlCharactersInRegex: see above
  .refine((value) => !/[\u0000-\u001f\u007f]/.test(value), {
    message: "must not contain control characters",
  });

/** Reserved literals that can never be an `{asset_type}` family. */
export const RESERVED_ASSET_TYPE_SEGMENTS = ["storage", "withheld", "presign"] as const;

export const assetTypeSchema = addressSegment.refine(
  (value) => !(RESERVED_ASSET_TYPE_SEGMENTS as readonly string[]).includes(value),
  { message: "reserved asset_type segment" },
);

export const assetNameSchema = addressSegment;
export const assetVersionSchema = addressSegment;
export const assetChannelSchema = addressSegment;

/** `/v1/assets/{asset_type}` */
export const assetTypeParamsSchema = z.object({
  asset_type: assetTypeSchema,
});

/** `/v1/assets/{asset_type}/{name}/…` */
export const assetNameParamsSchema = z.object({
  asset_type: assetTypeSchema,
  name: assetNameSchema,
});

/** `/v1/assets/{asset_type}/{name}/{version}[/…]` */
export const assetVersionParamsSchema = z.object({
  asset_type: assetTypeSchema,
  name: assetNameSchema,
  version: assetVersionSchema,
});

/** `/v1/assets/{asset_type}/{name}/channels/{channel}` */
export const assetChannelParamsSchema = z.object({
  asset_type: assetTypeSchema,
  name: assetNameSchema,
  channel: assetChannelSchema,
});

/** `?platform=` — the platform/arch variant selector (Rust issue #260). */
export const platformQuerySchema = z.object({
  platform: z.string().min(1).max(128).optional(),
});

/**
 * `?platform=` plus `?path=` — the pull query.
 *
 * `path` selects one file of an expanded `static_site` bundle (#736). It is NOT
 * a new operation and NOT a second way to resolve a version: the reference in
 * the URL still resolves through the one registry path, and `path` only narrows
 * which bytes of the artifact that resolution chose are served. The bound is
 * generous but finite; `bundle.ts::bundlePathRejection` owns the real grammar.
 */
export const pullQuerySchema = z.object({
  platform: z.string().min(1).max(128).optional(),
  path: z.string().min(1).max(512).optional(),
});

/** `?version=` — the target of a channel move. */
export const channelMoveQuerySchema = z.object({
  version: assetVersionSchema,
});

/** `?channel=` — the optional same-request channel move on a push. */
export const pushQuerySchema = z.object({
  platform: z.string().min(1).max(128).optional(),
  channel: assetChannelSchema.optional(),
});

/** Shared admin-list narrowing on the withheld listing. */
export const withheldQuerySchema = z.object({
  asset_type: z.string().min(1).max(512).optional(),
  search: z.string().max(512).optional(),
  offset: z.coerce.number().int().min(0).optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
});

// ---------------------------------------------------------------------------
// Control bodies
// ---------------------------------------------------------------------------

const sha256Hex = z.string().regex(/^[0-9a-fA-F]{64}$/, "must be a 64-character hex sha256");

const uploadId = z.string().regex(/^upl_[0-9a-f]{32}$/, "must be a gateway-issued upload id");

const positiveSize = z.number().int().positive();

/** `POST /v1/assets/presign/upload/…` — Rust `PresignUploadIntentRequest`. */
export const presignUploadIntentRequestSchema = z
  .object({
    size_bytes: positiveSize,
    sha256: sha256Hex,
  })
  .strict();
export type PresignUploadIntentRequest = z.infer<typeof presignUploadIntentRequestSchema>;

/** `POST /v1/assets/presign/commit/…` — Rust `PresignCommitRequest`. */
export const presignCommitRequestSchema = z
  .object({
    upload_id: uploadId,
    size_bytes: positiveSize,
    sha256: sha256Hex,
    content_type: z.string().min(1).max(255).optional(),
    // #366 screening inputs — mirror the inline path's `x-asset-*` headers
    // one-for-one: one shared contract, two transports.
    signature: z.string().optional(),
    signature_format: z.string().optional(),
    signature_key_id: z.string().optional(),
    visibility: z.string().optional(),
    approval_id: z.string().optional(),
  })
  .strict();
export type PresignCommitRequest = z.infer<typeof presignCommitRequestSchema>;

/** `POST /v1/assets/presign/abort/…` — Rust `PresignAbortRequest`. */
export const presignAbortRequestSchema = z
  .object({
    upload_id: uploadId,
    size_bytes: positiveSize,
    sha256: sha256Hex,
    /**
     * Why the intent is being released. An absent or unrecognized value
     * degrades to `abandoned` — the claim that costs the least evidence —
     * never UP to `bucket_rejected` (Rust `AbortReason::parse`).
     */
    reason: z.string().optional(),
  })
  .strict();
export type PresignAbortRequest = z.infer<typeof presignAbortRequestSchema>;

/** `POST /v1/assets/{…}/{version}/visibility` — Rust `AssetVisibilityPromotionRequest`. */
export const assetVisibilityPromotionRequestSchema = z.object({
  scan_outcome: z.string(),
  evidence: z.string().default(""),
  scanner: z.string().optional(),
});
export type AssetVisibilityPromotionRequest = z.infer<typeof assetVisibilityPromotionRequestSchema>;

// ---------------------------------------------------------------------------
// Response DTOs
// ---------------------------------------------------------------------------

/** Rust `AssetSummary` (with the #528 flattened `visibility`). */
export const assetSummarySchema = z.object({
  id: z.string(),
  asset_type: z.string(),
  name: z.string(),
  version: z.string(),
  content_type: z.string(),
  content_hash: z.string(),
  size_bytes: z.number(),
  /** `true` when the bytes live in object storage rather than inline. */
  storage_backed: z.boolean(),
  visibility: z.enum(["visible", "pending_scan", "quarantined"]),
  created_at_unix: z.number(),
  updated_at_unix: z.number(),
});
export type AssetSummary = z.infer<typeof assetSummarySchema>;

/** Rust `WithheldAssetSummary` — the flattened summary + screening evidence. */
export const withheldAssetSummarySchema = assetSummarySchema.extend({
  screening_evidence: z.string().optional(),
});
export type WithheldAssetSummary = z.infer<typeof withheldAssetSummarySchema>;

/** Rust `AdminList<T>` / `AdminPage<T>`. */
export function adminListSchema<T extends z.ZodTypeAny>(item: T) {
  return z.object({
    object: z.literal("list"),
    data: z.array(item),
    total: z.number().optional(),
    offset: z.number().optional(),
    limit: z.number().optional(),
  });
}

/** Rust `AssetPresignedUploadConstraints`. */
export const assetPresignedUploadConstraintsSchema = z.object({
  enabled: z.boolean(),
  max_object_bytes: z.number().optional(),
  url_ttl_seconds: z.number().optional(),
});

/** Rust `AssetStorageSummary`. */
export const assetStorageSummarySchema = z.object({
  object: z.literal("asset_storage_summary"),
  used_bytes: z.number(),
  quota_bytes: z.number().optional(),
  remaining_bytes: z.number().optional(),
  inline_upload_max_bytes: z.number(),
  presigned_upload: assetPresignedUploadConstraintsSchema,
});
export type AssetStorageSummary = z.infer<typeof assetStorageSummarySchema>;

/** Rust `AssetChannelSummary`. */
export const assetChannelSummarySchema = z.object({
  channel: z.string(),
  version: z.string(),
  updated_at_unix: z.number(),
});
export type AssetChannelSummary = z.infer<typeof assetChannelSummarySchema>;

/** Rust `AssetChannelMutationResponse`. */
export const assetChannelMutationResponseSchema = z.object({
  object: z.literal("asset_channel"),
  asset_type: z.string(),
  name: z.string(),
  channel: assetChannelSummarySchema,
});

/** Rust `AssetManifestVariant`. */
export const assetManifestVariantSchema = z.object({
  variant: z.string(),
  content_type: z.string(),
  content_hash: z.string(),
  size_bytes: z.number(),
  storage_backed: z.boolean(),
});

/** Rust `AssetManifestVersion`. */
export const assetManifestVersionSchema = z.object({
  version: z.string(),
  yanked: z.boolean(),
  variants: z.array(assetManifestVariantSchema),
});

/** Rust `AssetManifest`. */
export const assetManifestSchema = z.object({
  object: z.literal("asset_manifest"),
  asset_type: z.string(),
  name: z.string(),
  channels: z.array(assetChannelSummarySchema),
  versions: z.array(assetManifestVersionSchema),
});
export type AssetManifest = z.infer<typeof assetManifestSchema>;

/** Rust `AssetMutationResponse` (200 visible / 202 withheld — issue #528). */
export const assetMutationResponseSchema = z.object({
  object: z.literal("asset"),
  asset: assetSummarySchema,
});

/** Rust `AssetVisibilityPromotionResponse`. */
export const assetVisibilityPromotionResponseSchema = z.object({
  object: z.literal("asset.visibility_promotion"),
  id: z.string(),
  visibility: z.enum(["visible", "quarantined"]),
  scan_outcome: z.enum(["visible", "quarantined"]),
  asset: assetSummarySchema,
});

/** Rust `AdminDeleteResponse`. */
export const adminDeleteResponseSchema = z.object({
  object: z.string(),
  id: z.string(),
  deleted: z.boolean(),
});

/** Rust `PresignUploadIntentResponse`. */
export const presignUploadIntentResponseSchema = z.object({
  object: z.literal("asset_upload_intent"),
  key: z.string(),
  upload_id: z.string(),
  upload_url: z.string(),
  method: z.literal("PUT"),
  expires_in_seconds: z.number(),
  size_bytes: z.number(),
  sha256: z.string(),
  required_headers: z.record(z.string()),
  max_object_bytes: z.number(),
  /** Named protocol, so multipart can arrive as an additive enum value. */
  upload_protocol: z.literal("single_put"),
});

/** Rust `PresignAbortResponse`. */
export const presignAbortResponseSchema = z.object({
  object: z.literal("asset_upload_abort"),
  upload_id: z.string(),
  /** True ONLY when bytes existed AND the bucket confirmed their deletion. */
  staging_object_removed: z.boolean(),
  staging_reclamation: z.enum(["not_staged", "removed", "removal_failed"]),
  outcome: z.enum(["aborted", "aborted_reclaim_failed", "rejected_bucket"]),
});

/** Rust `PresignDownloadResponse`. */
export const presignDownloadResponseSchema = z.object({
  object: z.literal("asset_download_url"),
  download_url: z.string(),
  method: z.literal("GET"),
  expires_in_seconds: z.number(),
  sha256: z.string(),
  size_bytes: z.number(),
  content_type: z.string(),
});

/** The gateway-wide error envelope — Rust `write_json_error`. */
export const errorEnvelopeSchema = z.object({
  error: z.object({
    message: z.string(),
    type: z.literal("ferrogate_error"),
    code: z.string(),
    request_id: z.string().optional(),
  }),
});
export type ErrorEnvelope = z.infer<typeof errorEnvelopeSchema>;
