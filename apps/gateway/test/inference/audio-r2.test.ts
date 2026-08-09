/**
 * "with R2 for large uploads" — the by-reference ingress for
 * `POST /v1/audio/{transcriptions,translations}` (issue #703).
 *
 * ## What this leg is for, and what it deliberately is not
 *
 * The inline ceiling (`MAX_AUDIO_UPLOAD_BYTES`) is not a memory optimisation
 * waiting to be undone — it is the only correct answer to an UNBOUNDED REQUEST
 * BODY, because a `Content-Length` can lie and a chunked upload declares
 * nothing at all. Nothing about R2 changes that, and `readAudioUpload` still
 * aborts the read the moment the cap is crossed.
 *
 * What R2 changes is the shape of the problem. When the bytes are already in
 * the bucket the caller uploaded them DIRECTLY (a presigned PUT on R2's S3 API,
 * out of band, resumable, never through this Worker), and the object store
 * reports the EXACT size before a byte is allocated. A number the platform
 * measured is a completely different input from a number the client asserted —
 * so the by-reference path can carry its own, much higher ceiling and refuse
 * above it without reading anything, which the inline path structurally cannot.
 *
 * The tests below therefore pin four properties, in this order of importance:
 *
 *  1. an object ABOVE the inline ceiling is transcribed by reference, and the
 *     byte-identical inline upload is still 413. That is the user-facing claim:
 *     the 90-minute recording works.
 *  2. the oversized case is refused on METADATA ALONE — R2 is never read. It is
 *     proved by pointing the row at a key that does not exist in the bucket: if
 *     anything read it the answer would be `storage_unavailable`, not 413.
 *  3. tenant isolation. Tenant B's object is unreachable to tenant A, and the
 *     guard is the SAME `assertKeyBelongsToTenant` the asset service runs.
 *  4. the screening state of the stored object is honoured — a quarantined or
 *     yanked recording is not transcribable. #366's malware gate would be a
 *     decoration if a second ingress read the bytes around it.
 *
 * `env.ASSETS` is the real R2 binding under `@cloudflare/vitest-pool-workers`
 * (miniflare's R2, real workerd, no credentials, no network), and `env.DB` is
 * the real tenant D1 with the committed migration applied by `test/setup-d1.ts`.
 * Nothing about the object store or the registry is a double here.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { D1AssetMetadataStore } from "../../src/assets/d1.js";
import { newAssetObjectKey, storedAssetId } from "../../src/assets/keys.js";
import type {
  AssetMetadataStore,
  AssetObjectStore,
  AssetVisibility,
  StoredAsset,
} from "../../src/assets/ports.js";
import {
  MAX_AUDIO_REFERENCE_BYTES,
  MAX_AUDIO_UPLOAD_BYTES,
  type PhysicalRoute,
  fetchDispatcher,
  storedAssetAudioObjects,
  workersAiDispatcher,
} from "../../src/inference/index.js";
import { seedTenantRosterRows, tenantObjectDb } from "../tenant-object.js";
import { ALL_ROUTES, errorBody, harness, tenantCaller } from "./fixtures.js";

const BASE = "https://gw.test";
const TENANT = "tenant_audio_a";
const OTHER_TENANT = "tenant_audio_b";

const WHISPER_ROUTE: PhysicalRoute = {
  logicalModel: "whisper-model",
  provider: "cf-ai",
  providerModel: "@cf/openai/whisper-large-v3-turbo",
  providerKind: "workers-ai",
  baseUrl: "https://api.cloudflare.com/client/v4/accounts/acct_placeholder/ai",
  enabled: true,
  capabilities: ["transcription"],
  audioSecondPricePer1m: 100,
};

const ROUTES: readonly PhysicalRoute[] = [...ALL_ROUTES, WHISPER_ROUTE];

/**
 * The REAL bindings. `env` is typed from the generated `Env` and neither of
 * these is on it, so they are read the same way `test/setup-d1.ts` reads `DB` —
 * through one cast, at one place.
 */
interface AudioTestBindings {
  readonly ASSETS: AssetObjectStore;
  readonly DB: D1Database;
}
const bindings = env as unknown as AudioTestBindings;
const objects = bindings.ASSETS;
const metadata = new D1AssetMetadataStore(bindings.DB);

/** Deterministic "audio" of a given size. */
function audioBytes(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i += 1) bytes[i] = i % 251;
  return bytes;
}

interface SeedOptions {
  readonly tenantId?: string;
  readonly name?: string;
  readonly bytes?: Uint8Array | null;
  /** Overrides the row's declared size WITHOUT writing that many bytes. */
  readonly declaredSize?: number;
  readonly visibility?: AssetVisibility;
  readonly yanked?: boolean;
  readonly metadataStore?: AssetMetadataStore;
}

/**
 * Publish one recording the way the presign flow does: bytes under the tenant's
 * own R2 prefix, one `stored_assets` row addressing them.
 *
 * `bytes: null` writes the ROW and no object, which is what proves a refusal
 * happened before any read.
 */
async function seedRecording(options: SeedOptions = {}): Promise<StoredAsset> {
  const tenantId = options.tenantId ?? TENANT;
  const name = options.name ?? "meeting";
  const version = "1.0.0";
  const ref = { tenantId, assetType: "recording", name, version, variant: "" };
  const key = newAssetObjectKey(ref);
  const bytes = options.bytes === undefined ? audioBytes(64) : options.bytes;
  if (bytes !== null) {
    await objects.put(key, bytes as unknown as ArrayBuffer, {
      httpMetadata: { contentType: "audio/wav" },
    });
  }
  const asset: StoredAsset = {
    id: storedAssetId(tenantId, "recording", name, version),
    tenant_id: tenantId,
    asset_type: "recording",
    name,
    version,
    content_type: "audio/wav",
    content_hash: "0".repeat(64),
    size_bytes: options.declaredSize ?? bytes?.byteLength ?? 0,
    storage_uri: key,
    variant: "",
    yanked: options.yanked ?? false,
    visibility: options.visibility ?? "visible",
    created_at_unix: 0,
    updated_at_unix: 0,
  };
  await (options.metadataStore ?? metadata).createAssetWithinQuota(asset, undefined);
  return asset;
}

/**
 * The gateway, with the REAL R2-backed source wired on the real bindings.
 *
 * The `AI` dispatcher is passed explicitly because `harness()` drives the inner
 * router with `app.request(...)`, which carries no bindings — so
 * `dispatcherFromEnv` would find no `env.AI` and every Workers AI route would
 * answer 503 for a reason that has nothing to do with this leg.
 */
function audioHarness(limits: Record<string, number> = {}): ReturnType<typeof harness> {
  return harness(
    {
      caller: tenantCaller(TENANT),
      audioObjects: storedAssetAudioObjects({ metadata, objects }),
      dispatcher: workersAiDispatcher(ai, fetchDispatcher),
      limits,
    },
    ROUTES,
  );
}

/** A by-reference transcription request. Multipart, but with no `file` part. */
function transcribeByRef(
  h: ReturnType<typeof harness>,
  fileRef: string,
  path = "/v1/audio/transcriptions",
): Promise<Response> {
  const form = new FormData();
  form.append("model", "whisper-model");
  form.append("file_ref", fileRef);
  return Promise.resolve(h.router.request(`${BASE}${path}`, { method: "POST", body: form }));
}

/** The same recording as an INLINE upload, for the side-by-side comparison. */
function transcribeInline(h: ReturnType<typeof harness>, bytes: Uint8Array): Promise<Response> {
  const form = new FormData();
  form.append("model", "whisper-model");
  form.append("file", new Blob([bytes as unknown as ArrayBuffer], { type: "audio/wav" }), "m.wav");
  return Promise.resolve(
    h.router.request(`${BASE}/v1/audio/transcriptions`, { method: "POST", body: form }),
  );
}

class RecordingAi {
  readonly runs: { model: string; input: Record<string, unknown> }[] = [];
  async run(model: string, input: Record<string, unknown>): Promise<unknown> {
    this.runs.push({ model, input });
    return { text: "the transcript" };
  }
}

let ai: RecordingAi;

beforeEach(async () => {
  ai = new RecordingAi();
  (env as unknown as Record<string, unknown>).AI = ai;
  await bindings.DB.exec("DELETE FROM stored_assets");
  for (const tenantId of [TENANT, OTHER_TENANT]) {
    const tenant = tenantObjectDb(tenantId);
    await tenant.batch([
      tenant.prepare("DELETE FROM asset_bundle_files"),
      tenant.prepare("DELETE FROM asset_channels"),
      tenant.prepare("DELETE FROM stored_assets"),
    ]);
  }
});

describe("the by-reference ceiling is a different number for a different reason", () => {
  it("is higher than the inline ceiling, and both are stated", () => {
    // The relationship IS the claim: a caller refused inline has somewhere to
    // go. If these were equal the by-reference path would buy nothing at all.
    expect(MAX_AUDIO_REFERENCE_BYTES).toBeGreaterThan(MAX_AUDIO_UPLOAD_BYTES);
  });
});

describe("an upload ABOVE the inline ceiling is transcribed by reference", () => {
  it("413s inline and 200s by reference, on the very same bytes", async () => {
    // The inline ceiling is lowered so the property is provable without moving
    // 26 MiB through a test isolate. What is asserted is the RELATIONSHIP —
    // over the inline cap, under the reference cap — and it is the same
    // relationship a 30 MiB recording has against the SHIPPED constants, which
    // the test above pins against each other.
    const bytes = audioBytes(4096);
    const asset = await seedRecording({ bytes });
    // 512 comfortably holds the by-reference request's own multipart body (two
    // short text fields) and comfortably refuses the 4 KiB inline one. The
    // inline ceiling bounds the WHOLE request body, which is exactly why the
    // by-reference request stays under it while carrying a far bigger recording.
    const h = audioHarness({ audioUploadMaxBytes: 512, audioReferenceMaxBytes: 65_536 });

    const refused = await transcribeInline(h, bytes);
    expect(refused.status).toBe(413);
    expect((await errorBody(refused)).error.code).toBe("payload_too_large");

    const served = await transcribeByRef(h, `recording/${asset.name}/${asset.version}`);
    expect(served.status).toBe(200);
    expect(await served.json()).toEqual({ text: "the transcript" });
    // The provider really saw the recording's bytes, not an empty part.
    expect(typeof ai.runs.at(-1)?.input.audio).toBe("string");
    expect((ai.runs.at(-1)?.input.audio as string).length).toBeGreaterThan(0);
  });

  it("meters the reference upload on the same rail as an inline one", async () => {
    const asset = await seedRecording({ bytes: audioBytes(128) });
    const h = audioHarness();
    const res = await transcribeByRef(h, `recording/${asset.name}/${asset.version}`);
    expect(res.status).toBe(200);
    expect(h.usage.last).toMatchObject({
      route: "openai.audio.transcriptions",
      logicalModel: "whisper-model",
      audioSecondPricePer1m: 100,
    });
  });

  it("serves a TRANSLATION by reference too", async () => {
    const asset = await seedRecording({ bytes: audioBytes(128) });
    const h = audioHarness();
    const res = await transcribeByRef(
      h,
      `recording/${asset.name}/${asset.version}`,
      "/v1/audio/translations",
    );
    expect(res.status).toBe(200);
    expect(ai.runs.at(-1)?.input.task).toBe("translate");
  });
});

describe("the reference ceiling is enforced BEFORE R2 is read", () => {
  it("413s on the object store's own size, with no object in the bucket at all", async () => {
    // `bytes: null` writes the row and NO object. If the ceiling were checked
    // after the read this would be `storage_unavailable`; 413 is only reachable
    // if the size decided it first. That is the whole difference between a
    // measured size and a declared one.
    const asset = await seedRecording({ bytes: null, declaredSize: 10_000 });
    const h = audioHarness({ audioReferenceMaxBytes: 4096 });
    const res = await transcribeByRef(h, `recording/${asset.name}/${asset.version}`);
    expect(res.status).toBe(413);
    expect((await errorBody(res)).error.code).toBe("payload_too_large");
    // Nothing was dispatched either.
    expect(ai.runs.length).toBe(0);
  });

  it("503s — not 413 — when the row is in range but the object is missing", async () => {
    // The companion case. Without it the test above would also pass for an
    // implementation that refuses every reference for the wrong reason.
    const asset = await seedRecording({ bytes: null, declaredSize: 64 });
    const h = audioHarness();
    const res = await transcribeByRef(h, `recording/${asset.name}/${asset.version}`);
    expect(res.status).toBe(503);
    expect(ai.runs.length).toBe(0);
  });
});

describe("a reference cannot cross a tenant boundary", () => {
  it("refuses another tenant's recording, by the same name and version", async () => {
    // Tenant B publishes; tenant A asks for the identical coordinate. There is
    // nothing to guess here — the coordinate is the one the attacker would try
    // first, and the answer must not depend on it being unguessable.
    const asset = await seedRecording({ tenantId: OTHER_TENANT, bytes: audioBytes(64) });
    const h = audioHarness();
    const res = await transcribeByRef(h, `recording/${asset.name}/${asset.version}`);
    expect(res.status).toBe(404);
    expect(ai.runs.length).toBe(0);
  });

  it("refuses a row whose storage_uri points OUT of the tenant's own prefix", async () => {
    // The registry row is what the id lookup trusts, so this is the case that
    // makes `assertKeyBelongsToTenant` load-bearing rather than decorative: a
    // row under tenant A's id whose `storage_uri` addresses tenant B's key —
    // reachable through a corrupted registry, an operator's manual edit, or any
    // future write path that derives a key from something other than the
    // caller. Without the guard the id check alone would happily read it.
    const victim = {
      tenantId: OTHER_TENANT,
      assetType: "recording",
      name: "secret",
      version: "1.0.0",
      variant: "",
    };
    const foreignKey = newAssetObjectKey(victim);
    await objects.put(foreignKey, audioBytes(64) as unknown as ArrayBuffer, {
      httpMetadata: { contentType: "audio/wav" },
    });
    await metadata.createAssetWithinQuota(
      {
        id: storedAssetId(TENANT, "recording", "borrowed", "1.0.0"),
        tenant_id: TENANT,
        asset_type: "recording",
        name: "borrowed",
        version: "1.0.0",
        content_type: "audio/wav",
        content_hash: "0".repeat(64),
        size_bytes: 64,
        // Tenant A's row, tenant B's bytes.
        storage_uri: foreignKey,
        variant: "",
        yanked: false,
        visibility: "visible",
        created_at_unix: 0,
        updated_at_unix: 0,
      },
      undefined,
    );
    const h = audioHarness();
    const res = await transcribeByRef(h, "recording/borrowed/1.0.0");
    expect(res.status).toBe(404);
    expect(ai.runs.length).toBe(0);
  });

  it("refuses a coordinate whose path segments try to walk out of the prefix", async () => {
    const h = audioHarness();
    const res = await transcribeByRef(h, `recording/../../${OTHER_TENANT}/meeting/1.0.0`);
    expect(res.status).toBe(400);
    expect(ai.runs.length).toBe(0);
  });
});

describe("the stored object's screening state is honoured", () => {
  it("refuses a QUARANTINED recording", async () => {
    // #366's malware gate. A second ingress that read the bytes around it would
    // make the quarantine decorative — the attacker uploads the file, it is
    // flagged, and they transcribe it anyway.
    const asset = await seedRecording({ bytes: audioBytes(64), visibility: "quarantined" });
    const h = audioHarness();
    const res = await transcribeByRef(h, `recording/${asset.name}/${asset.version}`);
    expect(res.status).toBe(409);
    expect(ai.runs.length).toBe(0);
  });

  it("refuses a recording still PENDING SCAN", async () => {
    const asset = await seedRecording({ bytes: audioBytes(64), visibility: "pending_scan" });
    const h = audioHarness();
    const res = await transcribeByRef(h, `recording/${asset.name}/${asset.version}`);
    expect(res.status).toBe(409);
    expect(ai.runs.length).toBe(0);
  });

  it("refuses a YANKED recording", async () => {
    const asset = await seedRecording({ bytes: audioBytes(64), yanked: true });
    const h = audioHarness();
    const res = await transcribeByRef(h, `recording/${asset.name}/${asset.version}`);
    expect(res.status).toBe(409);
    expect(ai.runs.length).toBe(0);
  });
});

describe("the two ingresses are exclusive and each is still validated", () => {
  it("400s a request carrying BOTH a file part and a file_ref", async () => {
    // Ambiguity is a caller bug, and picking one silently is how a caller ends
    // up billed for transcribing something other than what they attached.
    const asset = await seedRecording({ bytes: audioBytes(64) });
    const form = new FormData();
    form.append("model", "whisper-model");
    form.append("file_ref", `recording/${asset.name}/${asset.version}`);
    form.append("file", new Blob([audioBytes(8) as unknown as ArrayBuffer]), "m.wav");
    const res = await audioHarness().router.request(`${BASE}/v1/audio/transcriptions`, {
      method: "POST",
      body: form,
    });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("invalid_request");
  });

  it("404s a reference to a recording that was never published", async () => {
    const h = audioHarness();
    const res = await transcribeByRef(h, "recording/never-published/9.9.9");
    expect(res.status).toBe(404);
    expect(ai.runs.length).toBe(0);
  });

  it("400s a malformed coordinate", async () => {
    const h = audioHarness();
    const res = await transcribeByRef(h, "not-a-coordinate");
    expect(res.status).toBe(400);
    expect(ai.runs.length).toBe(0);
  });

  it("503s a reference when the deployment has no object store bound", async () => {
    // Fail CLOSED. A deployment with no `ASSETS` binding must refuse the
    // reference, never fall back to "no file part" (400) — which would name the
    // caller's request as the fault for an operator's missing binding.
    const asset = await seedRecording({ bytes: audioBytes(64) });
    const h = harness(
      { caller: tenantCaller(TENANT), dispatcher: workersAiDispatcher(ai, fetchDispatcher) },
      ROUTES,
    );
    const res = await transcribeByRef(h, `recording/${asset.name}/${asset.version}`);
    expect(res.status).toBe(503);
  });
});

/**
 * The composition root. Everything above drives the inner router with an
 * injected source, so it would all stay green on a Worker that never wires one
 * — which is exactly the "fully implemented, never reachable" defect this repo
 * keeps finding. This one goes through `SELF.fetch` → `src/worker.ts` →
 * `createGatewayApp` against the committed `wrangler.toml`, so what it proves
 * is that the request-scoped audio source finds `env.ASSETS` and the
 * authenticated tenant object's metadata on the deployed binding set.
 */
describe("the deployed Worker resolves a file_ref from its own bindings", () => {
  const KEYS = JSON.stringify([
    { key: "fg_audio_ref", id: "key_audio_ref", tenant_id: TENANT, scopes: [] },
  ]);
  const MODELS = JSON.stringify([
    {
      name: "edge-whisper",
      provider: "cf-ai",
      provider_model: "@cf/openai/whisper-large-v3-turbo",
      capabilities: ["transcription"],
    },
  ]);
  const PROVIDERS = JSON.stringify([
    {
      name: "cf-ai",
      kind: "workers-ai",
      base_url: "https://api.cloudflare.com/client/v4/accounts/acct_placeholder/ai",
    },
  ]);
  const OVERRIDES: Record<string, unknown> = {
    GATEWAY_PROVIDERS: PROVIDERS,
    GATEWAY_MODELS: MODELS,
    GATEWAY_NATIVE_API_KEYS: KEYS,
  };
  const ORIGINAL: Record<string, unknown> = {};
  const mutable = env as unknown as Record<string, unknown>;

  beforeAll(async () => {
    for (const [name, value] of Object.entries(OVERRIDES)) {
      ORIGINAL[name] = mutable[name];
      mutable[name] = value;
    }
    // Roster rows for the audio tenants: the deployed Worker routes every
    // authenticated request through the dispatching tenant router, and a tenant
    // absent from `tenant_databases` falls to the native-binding arm — a 503
    // before the audio handler is ever reached.
    await seedTenantRosterRows([TENANT, OTHER_TENANT]);
  });
  afterAll(() => {
    for (const [name, value] of Object.entries(ORIGINAL)) {
      mutable[name] = value;
    }
  });

  function post(fileRef: string): Promise<Response> {
    const form = new FormData();
    form.append("model", "edge-whisper");
    form.append("file_ref", fileRef);
    return SELF.fetch(`${BASE}/v1/audio/transcriptions`, {
      method: "POST",
      headers: { authorization: "Bearer fg_audio_ref" },
      body: form,
    });
  }

  function productionMetadata(tenantId: string): AssetMetadataStore {
    return new D1AssetMetadataStore(tenantObjectDb(tenantId) as never);
  }

  it("transcribes a recording it was never sent the bytes of", async () => {
    const asset = await seedRecording({
      bytes: audioBytes(96),
      metadataStore: productionMetadata(TENANT),
    });
    const res = await post(`recording/${asset.name}/${asset.version}`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ text: "the transcript" });
    // The bytes came out of R2, not out of the request: the request carried two
    // short text fields and nothing else.
    expect(typeof ai.runs.at(-1)?.input.audio).toBe("string");
  });

  it("refuses another tenant's recording through the deployed guard too", async () => {
    const asset = await seedRecording({
      tenantId: OTHER_TENANT,
      bytes: audioBytes(96),
      metadataStore: productionMetadata(OTHER_TENANT),
    });
    const res = await post(`recording/${asset.name}/${asset.version}`);
    expect(res.status).toBe(404);
  });
});
