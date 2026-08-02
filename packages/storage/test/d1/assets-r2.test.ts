/**
 * The asset object store and the object-then-row commit protocol, against a
 * REAL R2 bucket and a REAL D1 database in `workerd`.
 *
 * The property that matters is one that no fake can express: R2 and D1 are two
 * services with NO shared transaction, so the correctness of an asset push is
 * entirely a question of ORDER and of compensation. These tests drive the two
 * crash points (after the object, after the row) and both refusal paths.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  R2AssetBlobStore,
  StorageError,
  assetObjectKey,
  classifyAssetQuotaAdmission,
  commitAssetWithBlob,
  type AssetQuotaAdmission,
} from "../../src/index.js";
import { TENANT_A } from "./harness.js";

declare global {
  namespace Cloudflare {
    interface Env {
      ASSETS_BUCKET: R2Bucket;
    }
  }
}

const NOW = 1_784_073_600;
const BYTES = new TextEncoder().encode("#!/bin/sh\necho ferrogate\n");

const ASSET = {
  tenantId: TENANT_A,
  assetType: "skill",
  name: "deploy",
  version: "1.2.3",
  variant: "",
  contentHash: "sha256:abc123",
};

let blobs: R2AssetBlobStore;

beforeAll(async () => {
  await applyD1Migrations(env.TENANT_DB_A, env.TENANT_MIGRATIONS);
  blobs = new R2AssetBlobStore(env.ASSETS_BUCKET);
});

beforeEach(async () => {
  await env.TENANT_DB_A.prepare("DELETE FROM stored_assets").run();
  const listing = await env.ASSETS_BUCKET.list();
  for (const object of listing.objects) await env.ASSETS_BUCKET.delete(object.key);
});

/** The caller's row step: the quota-admission guard, on real D1. */
async function insertRow(
  storageUri: string,
  sizeBytes: number,
  quotaBytes: number | undefined,
  id = "asset_1",
): Promise<AssetQuotaAdmission> {
  const usedRow = await env.TENANT_DB_A.prepare(
    "SELECT coalesce(sum(size_bytes), 0) AS used FROM stored_assets WHERE tenant_id = ?",
  )
    .bind(ASSET.tenantId)
    .first<{ used: number }>();
  const used = Number(usedRow?.used ?? 0);
  const quotaOk = quotaBytes === undefined || used + sizeBytes <= quotaBytes;

  const existsRow = await env.TENANT_DB_A.prepare(
    "SELECT 1 AS present FROM stored_assets WHERE id = ?",
  )
    .bind(id)
    .first<{ present: number }>();
  const idExists = existsRow !== null;

  let inserted = false;
  if (quotaOk && !idExists) {
    const result = await env.TENANT_DB_A.prepare(
      "INSERT INTO stored_assets (id, tenant_id, asset_type, name, version, content_type, " +
        "content_hash, size_bytes, created_at_unix, updated_at_unix, storage_uri, variant) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING RETURNING id",
    )
      .bind(
        id,
        ASSET.tenantId,
        ASSET.assetType,
        ASSET.name,
        ASSET.version,
        "application/octet-stream",
        ASSET.contentHash,
        sizeBytes,
        NOW,
        NOW,
        storageUri,
        ASSET.variant,
      )
      .all<{ id: string }>();
    inserted = result.results.length > 0;
  }
  return classifyAssetQuotaAdmission(
    inserted,
    idExists,
    quotaOk,
    used,
    sizeBytes,
    quotaBytes,
  );
}

const admitted = (o: AssetQuotaAdmission): boolean => o.kind === "admitted";

describe("assetObjectKey", () => {
  test("is content-addressed and includes every identity column", () => {
    expect(assetObjectKey(ASSET)).toBe("assets/tenant_a/skill/deploy/1.2.3/_/sha256%3Aabc123");
  });

  test("a different variant is a DIFFERENT key (variant is part of row identity)", () => {
    expect(assetObjectKey({ ...ASSET, variant: "linux-arm64" })).not.toBe(assetObjectKey(ASSET));
  });

  test("a different content hash is a different key, so a push cannot overwrite bytes", () => {
    expect(assetObjectKey({ ...ASSET, contentHash: "sha256:zzz" })).not.toBe(
      assetObjectKey(ASSET),
    );
  });

  test("a `/` inside a name cannot forge a key path", () => {
    const key = assetObjectKey({ ...ASSET, name: "../../etc/passwd" });
    expect(key.split("/").length).toBe(assetObjectKey(ASSET).split("/").length);
    expect(key).toContain("%2F");
  });

  test("the empty default variant is a real segment, not a collapsed one", () => {
    // `a//b` and `a/b` would otherwise be the same object.
    expect(assetObjectKey(ASSET)).toContain("/_/");
  });
});

describe("R2AssetBlobStore", () => {
  test("round-trips bytes, content type and hash", async () => {
    const key = await blobs.put(ASSET, {
      body: BYTES,
      contentType: "application/x-sh",
      contentHash: ASSET.contentHash,
    });
    const read = await blobs.get(key);
    expect(read?.body).toEqual(BYTES);
    expect(read?.contentType).toBe("application/x-sh");
    expect(read?.contentHash).toBe(ASSET.contentHash);
  });

  test("an absent object reads back as undefined, not as empty bytes", async () => {
    expect(await blobs.get("assets/nope")).toBeUndefined();
    expect(await blobs.exists("assets/nope")).toBe(false);
  });

  test("delete is idempotent", async () => {
    const key = await blobs.put(ASSET, {
      body: BYTES,
      contentType: "text/plain",
      contentHash: ASSET.contentHash,
    });
    await blobs.delete(key);
    await blobs.delete(key);
    expect(await blobs.exists(key)).toBe(false);
  });

  test("deleteOrphans removes only objects no live storage_uri names", async () => {
    const live = await blobs.put(ASSET, {
      body: BYTES,
      contentType: "text/plain",
      contentHash: ASSET.contentHash,
    });
    const orphan = await blobs.put(
      { ...ASSET, contentHash: "sha256:stale" },
      { body: BYTES, contentType: "text/plain", contentHash: "sha256:stale" },
    );
    expect(await blobs.deleteOrphans("assets/", [live])).toEqual([orphan]);
    expect(await blobs.exists(live)).toBe(true);
    expect(await blobs.exists(orphan)).toBe(false);
  });

  test("deleteOrphans REFUSES an empty prefix", async () => {
    // An empty prefix plus an empty live set would sweep the whole bucket.
    await expect(blobs.deleteOrphans("", [])).rejects.toThrow(StorageError);
    await expect(blobs.deleteOrphans("   ", [])).rejects.toThrow(StorageError);
  });
});

describe("commitAssetWithBlob — the object-then-row protocol", () => {
  test("on success the object exists AND the row names it", async () => {
    const commit = await commitAssetWithBlob(
      blobs,
      ASSET,
      { body: BYTES, contentType: "text/plain", contentHash: ASSET.contentHash },
      (uri) => insertRow(uri, BYTES.length, undefined),
      admitted,
    );
    expect(commit.outcome.kind).toBe("admitted");
    expect(commit.compensated).toBe(false);
    expect(await blobs.exists(commit.storageUri)).toBe(true);
    const row = await env.TENANT_DB_A.prepare(
      "SELECT storage_uri FROM stored_assets WHERE id = 'asset_1'",
    ).first<{ storage_uri: string }>();
    expect(row?.storage_uri).toBe(commit.storageUri);
  });

  test("the object is written BEFORE the row, never after", async () => {
    let objectExistedWhenRowRan = false;
    await commitAssetWithBlob(
      blobs,
      ASSET,
      { body: BYTES, contentType: "text/plain", contentHash: ASSET.contentHash },
      async (uri) => {
        // If this ever reads false, the protocol has been inverted and a
        // download racing the push would 404 on a `visible` asset.
        objectExistedWhenRowRan = await blobs.exists(uri);
        return insertRow(uri, BYTES.length, undefined);
      },
      admitted,
    );
    expect(objectExistedWhenRowRan).toBe(true);
  });

  test("an over-quota REFUSAL compensates the object away", async () => {
    const commit = await commitAssetWithBlob(
      blobs,
      ASSET,
      { body: BYTES, contentType: "text/plain", contentHash: ASSET.contentHash },
      (uri) => insertRow(uri, BYTES.length, 1),
      admitted,
    );
    expect(commit.outcome.kind).toBe("over_quota");
    expect(commit.compensated).toBe(true);
    // No orphan: a refused push must not consume the quota it was refused for.
    expect(await blobs.exists(commit.storageUri)).toBe(false);
    expect(
      await env.TENANT_DB_A.prepare("SELECT count(*) AS n FROM stored_assets").first<{
        n: number;
      }>(),
    ).toEqual({ n: 0 });
  });

  test("a THROWING row step compensates and re-throws the original error", async () => {
    const boom = new Error("d1 exploded");
    let key = "";
    await expect(
      commitAssetWithBlob(
        blobs,
        ASSET,
        { body: BYTES, contentType: "text/plain", contentHash: ASSET.contentHash },
        async (uri) => {
          key = uri;
          throw boom;
        },
        admitted,
      ),
    ).rejects.toBe(boom);
    expect(key).not.toBe("");
    expect(await blobs.exists(key)).toBe(false);
  });

  test("an already_exists replay keeps the object (the bytes are still the live ones)", async () => {
    await commitAssetWithBlob(
      blobs,
      ASSET,
      { body: BYTES, contentType: "text/plain", contentHash: ASSET.contentHash },
      (uri) => insertRow(uri, BYTES.length, undefined),
      admitted,
    );
    const replay = await commitAssetWithBlob(
      blobs,
      ASSET,
      { body: BYTES, contentType: "text/plain", contentHash: ASSET.contentHash },
      (uri) => insertRow(uri, BYTES.length, undefined),
      (o) => o.kind === "admitted" || o.kind === "already_exists",
    );
    expect(replay.outcome.kind).toBe("already_exists");
    expect(replay.compensated).toBe(false);
    // Content-addressed: the replay wrote the SAME key, so compensating it
    // would have deleted the live artifact.
    expect(replay.storageUri).toBe(assetObjectKey(ASSET));
    expect(await blobs.exists(replay.storageUri)).toBe(true);
  });
});

describe("the R2↔D1 platform limit these tests pin", () => {
  test("an R2 put cannot be enrolled in a D1 batch", async () => {
    // There is no API to do it at all: `batch()` takes D1PreparedStatements and
    // nothing else. The compile-time absence IS the limit; this asserts the
    // runtime consequence — a crash between the two writes leaves an orphan
    // object, which is the failure mode `deleteOrphans` exists to sweep.
    const key = await blobs.put(ASSET, {
      body: BYTES,
      contentType: "text/plain",
      contentHash: ASSET.contentHash,
    });
    // Simulated crash: the row insert never happens.
    expect(await blobs.exists(key)).toBe(true);
    const rows = await env.TENANT_DB_A.prepare(
      "SELECT count(*) AS n FROM stored_assets",
    ).first<{ n: number }>();
    expect(Number(rows?.n)).toBe(0);
    // The orphan is invisible to every read path (they go through the row) and
    // is reclaimable.
    expect(await blobs.deleteOrphans("assets/", [])).toEqual([key]);
  });
});
