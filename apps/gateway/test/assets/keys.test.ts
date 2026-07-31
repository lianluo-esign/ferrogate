/**
 * The R2 key layout: deterministic, parseable, and tenant-isolated by
 * CONSTRUCTION rather than by obscurity.
 *
 * These are the assertions that make `assertKeyBelongsToTenant` a real guard
 * instead of a comment: if any builder below could ever emit a key outside its
 * tenant's prefix, the service's cross-tenant check would be checking nothing.
 */
import { describe, expect, test } from "vitest";
import {
  ASSET_KEY_ROOT,
  CrossTenantKeyError,
  assertKeyBelongsToTenant,
  assetChannelId,
  assetObjectPrefix,
  commitObjectKeyPrefix,
  isUploadId,
  keyBelongsToTenant,
  newAssetObjectKey,
  newCommitObjectKey,
  newUploadId,
  parseAssetObjectKey,
  stagingObjectKey,
  storedAssetId,
  storedAssetVariantId,
  tenantKeyPrefix,
} from "../../src/assets/keys.js";

const ref = {
  tenantId: "tenant_a",
  assetType: "cli",
  name: "ferrogate",
  version: "1.2.3",
  variant: "",
} as const;

describe("tenant isolation is structural", () => {
  test("every builder emits a key under the tenant's own prefix", () => {
    const prefix = tenantKeyPrefix("tenant_a");
    expect(prefix).toBe(`${ASSET_KEY_ROOT}/t/tenant_a/`);
    for (const key of [
      newAssetObjectKey(ref),
      newCommitObjectKey(ref, "upl_00112233445566778899aabbccddeeff"),
      stagingObjectKey(ref, "upl_00112233445566778899aabbccddeeff", 10, "a".repeat(64)),
      assetObjectPrefix(ref),
    ]) {
      expect(key.startsWith(prefix)).toBe(true);
      expect(keyBelongsToTenant(key, "tenant_a")).toBe(true);
      expect(keyBelongsToTenant(key, "tenant_b")).toBe(false);
    }
  });

  test("tenant B's key is refused for tenant A", () => {
    const foreign = newAssetObjectKey({ ...ref, tenantId: "tenant_b" });
    expect(() => assertKeyBelongsToTenant(foreign, "tenant_a")).toThrow(CrossTenantKeyError);
    expect(() => assertKeyBelongsToTenant(foreign, "tenant_b")).not.toThrow();
  });

  test("a tenant id that is a prefix of another cannot borrow its keys", () => {
    // `tenant` vs `tenant_a`: the trailing `/` in the prefix is what stops
    // `assets/v1/t/tenant_a/...` from being read as tenant `tenant`'s.
    const key = newAssetObjectKey({ ...ref, tenantId: "tenant_a" });
    expect(keyBelongsToTenant(key, "tenant")).toBe(false);
  });

  test("a traversal-shaped key is refused outright", () => {
    expect(keyBelongsToTenant(`${tenantKeyPrefix("tenant_a")}../tenant_b/x`, "tenant_a")).toBe(
      false,
    );
  });
});

describe("round-tripping", () => {
  test("an object key parses back to its logical address", () => {
    const key = newAssetObjectKey(ref);
    expect(parseAssetObjectKey(key)).toEqual(ref);
  });

  test("segments containing / and % survive the round trip", () => {
    // Rust issue #398 puts a whole nested file path in the `{version}` segment.
    const nested = {
      tenantId: "tenant/a%b",
      assetType: "static_site",
      name: "docs",
      version: "assets/img/logo (1).png",
      variant: "linux/amd64",
    };
    const key = newAssetObjectKey(nested);
    expect(parseAssetObjectKey(key)).toEqual(nested);
    expect(keyBelongsToTenant(key, "tenant/a%b")).toBe(true);
    expect(keyBelongsToTenant(key, "tenant")).toBe(false);
  });

  test("a staging key is not an addressable artifact", () => {
    const key = stagingObjectKey(ref, newUploadId(), 5, "b".repeat(64));
    expect(parseAssetObjectKey(key)).toBeNull();
  });
});

describe("upload binding", () => {
  test("the staging key is server-derived from the registered triple", () => {
    const uploadId = "upl_00112233445566778899aabbccddeeff";
    const a = stagingObjectKey(ref, uploadId, 1024, "C".repeat(64));
    const b = stagingObjectKey(ref, uploadId, 1024, "c".repeat(64));
    // The sha is lower-cased into the key, so the same declaration names the
    // same object regardless of the caller's hex casing.
    expect(a).toBe(b);
    // A different declaration names a DIFFERENT object, which is what stops a
    // caller aborting or overwriting an upload it never registered.
    expect(stagingObjectKey(ref, uploadId, 1025, "c".repeat(64))).not.toBe(a);
    expect(stagingObjectKey(ref, newUploadId(), 1024, "c".repeat(64))).not.toBe(a);
  });

  test("commit keys are unique per attempt but share an upload-derived prefix", () => {
    const uploadId = newUploadId();
    const first = newCommitObjectKey(ref, uploadId);
    const second = newCommitObjectKey(ref, uploadId);
    expect(first).not.toBe(second);
    const prefix = commitObjectKeyPrefix(ref, uploadId);
    expect(first.startsWith(prefix)).toBe(true);
    expect(second.startsWith(prefix)).toBe(true);
    // A different upload never shares the prefix, so an already-published row
    // can be attributed to exactly one upload.
    expect(newCommitObjectKey(ref, newUploadId()).startsWith(prefix)).toBe(false);
  });

  test("upload ids are well-formed and unique", () => {
    const a = newUploadId();
    const b = newUploadId();
    expect(isUploadId(a)).toBe(true);
    expect(a).not.toBe(b);
    expect(isUploadId("upl_short")).toBe(false);
    expect(isUploadId("00112233445566778899aabbccddeeff")).toBe(false);
  });
});

describe("row identities", () => {
  test("the default variant keeps the historical id shape", () => {
    expect(storedAssetVariantId("t", "cli", "fg", "1.0.0", "")).toBe(
      storedAssetId("t", "cli", "fg", "1.0.0"),
    );
  });

  test("a platform variant gets its own id", () => {
    expect(storedAssetVariantId("t", "cli", "fg", "1.0.0", "linux-x64")).toBe(
      "t:cli:fg:1.0.0:v:linux-x64",
    );
  });

  test("channel ids are tenant-scoped", () => {
    expect(assetChannelId("tenant_a", "cli", "fg", "stable")).not.toBe(
      assetChannelId("tenant_b", "cli", "fg", "stable"),
    );
  });
});
