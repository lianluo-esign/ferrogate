/**
 * Shared fixtures for the asset suites.
 *
 * Everything is the real production code path except the two things that
 * cannot exist offline: the S3 presigner (no bucket credentials) and the wall
 * clock. The object store is the R2-shaped in-memory port, so the same
 * `service.ts` that runs against an `R2Bucket` binding runs here unchanged.
 */
import {
  type AssetCaller,
  type AssetObjectPutOptions,
  type AssetPresigner,
  type AssetScreener,
  type AssetScreeningRequest,
  type AssetScreeningVerdict,
  BuiltinEicarScreener,
  InMemoryAssetAuditSink,
  InMemoryAssetMetadataStore,
  InMemoryAssetObjectStore,
  type PresignedUpload,
} from "../../src/assets/ports.js";
import {
  type AssetLimits,
  type AssetRequestContext,
  AssetService,
} from "../../src/assets/service.js";

/** Deterministic presigner: no network, no credentials, stable URLs. */
export class FakePresigner implements AssetPresigner {
  readonly puts: { key: string; sizeBytes: number; sha256: string }[] = [];
  readonly gets: string[] = [];

  async presignPut(
    key: string,
    expiresSeconds: number,
    nowUnix: number,
    sizeBytes: number,
    contentSha256Hex: string,
  ): Promise<PresignedUpload> {
    this.puts.push({ key, sizeBytes, sha256: contentSha256Hex });
    return {
      url: `https://bucket.test/${key}?X-Amz-Expires=${expiresSeconds}&X-Amz-Date=${nowUnix}`,
      requiredHeaders: {
        "content-length": String(sizeBytes),
        "x-amz-content-sha256": contentSha256Hex,
      },
    };
  }

  async presignGet(key: string, expiresSeconds: number, nowUnix: number): Promise<string> {
    this.gets.push(key);
    return `https://bucket.test/${key}?X-Amz-Expires=${expiresSeconds}&X-Amz-Date=${nowUnix}`;
  }
}

/** An object store whose DELETE always refuses — the `removal_failed` arm. */
export class UndeletableObjectStore extends InMemoryAssetObjectStore {
  override async delete(): Promise<void> {
    throw new Error("bucket refused the delete");
  }
}

/** A screener that parks everything in `pending_scan` (async-scan posture). */
export class PendingScreener implements AssetScreener {
  async screen(request: AssetScreeningRequest): Promise<AssetScreeningVerdict> {
    return {
      visibility: "pending_scan",
      auditDetail: "scan=deferred signature=absent approval=not_required",
      manifest: { scanner: "deferred", sha256: request.contentSha256 },
    };
  }
}

export interface Harness {
  readonly service: AssetService;
  readonly objects: InMemoryAssetObjectStore;
  readonly metadata: InMemoryAssetMetadataStore;
  readonly audit: InMemoryAssetAuditSink;
  readonly presigner: FakePresigner;
  /** Advance the injected clock. */
  tick(seconds?: number): void;
  now(): number;
}

export interface HarnessOptions {
  readonly limits?: Partial<AssetLimits>;
  readonly screener?: AssetScreener;
  readonly objects?: InMemoryAssetObjectStore;
}

export const START_UNIX = 1_700_000_000;

export function harness(options: HarnessOptions = {}): Harness {
  const objects = options.objects ?? new InMemoryAssetObjectStore();
  const metadata = new InMemoryAssetMetadataStore();
  const audit = new InMemoryAssetAuditSink();
  const presigner = new FakePresigner();
  let clock = START_UNIX;
  const service = new AssetService({
    objects,
    metadata,
    presigner,
    screener: options.screener ?? new BuiltinEicarScreener(),
    audit,
    limits: { presignEnabled: true, presignTtlSeconds: 900, ...(options.limits ?? {}) },
    now: () => clock,
  });
  return {
    service,
    objects,
    metadata,
    audit,
    presigner,
    tick: (seconds = 1) => {
      clock += seconds;
    },
    now: () => clock,
  };
}

/** A tenant-attributed caller that may host assets. */
export function callerFor(tenantId: string, overrides: Partial<AssetCaller> = {}): AssetCaller {
  return {
    tenantId,
    scopes: ["assets.read", "assets.write"],
    assetHostingEnabled: true,
    ...overrides,
  };
}

export const CTX: AssetRequestContext = { requestId: "req_test" };

export function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function decode(value: Uint8Array | null): string {
  return value === null ? "" : new TextDecoder().decode(value);
}

/** Put raw bytes into the store the way a client's direct PUT would. */
export async function stage(
  store: InMemoryAssetObjectStore,
  key: string,
  content: Uint8Array,
  options?: AssetObjectPutOptions,
): Promise<void> {
  await store.put(
    key,
    content.buffer.slice(
      content.byteOffset,
      content.byteOffset + content.byteLength,
    ) as ArrayBuffer,
    options,
  );
}
