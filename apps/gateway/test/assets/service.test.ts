/**
 * The asset service's load-bearing invariants, asserted against storage.
 *
 * Each `describe` below names one property the Rust tree paid for with a
 * dedicated issue, and each test is written so that DELETING the code that
 * enforces it turns the test red — the failure mode this repo has had before is
 * a green suite over correct code that does not hold it.
 */
import { describe, expect, test } from "vitest";
import { sha256Hex } from "../../src/assets/hash.js";
import {
  commitObjectKeyPrefix,
  newAssetObjectKey,
  stagingObjectKey,
  storedAssetId,
  tenantKeyPrefix,
} from "../../src/assets/keys.js";
import {
  type AssetBundleScreeningRequest,
  type AssetBundleScreeningVerdict,
  type AssetScreener,
  BuiltinEicarScreener,
  type StoredAsset,
} from "../../src/assets/ports.js";
import { buildTar, gzip } from "./archives.js";
import {
  CTX,
  PendingScreener,
  UndeletableObjectStore,
  bytes,
  callerFor,
  decode,
  harness,
  stage,
} from "./helpers.js";

const A = callerFor("tenant_a");
const B = callerFor("tenant_b");
const CLI = { assetType: "cli", name: "ferrogate" } as const;

function ref(version: string, variant?: string) {
  return { ...CLI, version, ...(variant === undefined ? {} : { variant }) };
}

async function push(
  h: ReturnType<typeof harness>,
  caller = A,
  version = "1.0.0",
  body = `payload ${version}`,
  extra: { variant?: string; channel?: string; contentType?: string } = {},
) {
  return h.service.putAsset(
    caller,
    ref(version, extra.variant),
    {
      content: bytes(body),
      contentType: extra.contentType ?? "application/octet-stream",
      channel: extra.channel,
    },
    CTX,
  );
}

function pull(h: ReturnType<typeof harness>, caller = A, reference = "1.0.0", platform?: string) {
  return h.service.pullAsset(caller, { ...CLI, reference }, { headers: new Headers(), platform });
}

// ---------------------------------------------------------------------------

describe("version immutability (#260/#369)", () => {
  test("a republished version is refused and the ORIGINAL bytes survive", async () => {
    const h = harness();
    expect((await push(h, A, "1.0.0", "first")).status).toBe(200);

    const republish = await push(h, A, "1.0.0", "second");
    expect(republish.ok).toBe(false);
    if (republish.ok) throw new Error("unreachable");
    expect(republish.status).toBe(409);
    expect(republish.code).toBe("asset_version_immutable");

    // The claim is not "the second call returned 409" — it is "the published
    // bytes are the ones the FIRST push wrote". A pull proves it.
    const pulled = await pull(h);
    expect(pulled.ok).toBe(true);
    if (!pulled.ok) throw new Error("unreachable");
    expect(decode(pulled.bytes)).toBe("first");
    // ...and no orphan candidate was left behind by the refused attempt.
    expect(h.objects.objects.size).toBe(1);
  });

  test("a different platform variant of the same version is NOT a republish", async () => {
    const h = harness();
    expect((await push(h, A, "1.0.0", "generic")).status).toBe(200);
    expect((await push(h, A, "1.0.0", "linux", { variant: "linux-x64" })).status).toBe(200);
    const manifest = await h.service.manifest(A, CLI);
    expect(manifest.ok).toBe(true);
    if (!manifest.ok) throw new Error("unreachable");
    expect(manifest.body.versions).toHaveLength(1);
    expect(manifest.body.versions[0]?.variants.map((v) => v.variant)).toEqual(["", "linux-x64"]);
  });

  test("delete releases the version for republication", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "first");
    const deleted = await h.service.deleteAsset(A, ref("1.0.0"), CTX);
    expect(deleted.status).toBe(200);
    // The bucket object went with the row rather than being orphaned.
    expect(h.objects.objects.size).toBe(0);
    expect((await push(h, A, "1.0.0", "second")).status).toBe(200);
    const pulled = await pull(h);
    if (!pulled.ok) throw new Error("unreachable");
    expect(decode(pulled.bytes)).toBe("second");
  });

  test("concurrent first pushes cannot clobber each other's bytes", async () => {
    // Two attempts write to two DISTINCT candidate keys (#369); the atomic
    // create picks one winner and the loser's candidate is reclaimed.
    const h = harness();
    const [first, second] = await Promise.all([
      push(h, A, "2.0.0", "attempt-one"),
      push(h, A, "2.0.0", "attempt-two"),
    ]);
    const statuses = [first.status, second.status].sort();
    expect(statuses).toEqual([200, 409]);
    expect(h.objects.objects.size).toBe(1);
    const pulled = await pull(h, A, "2.0.0");
    if (!pulled.ok) throw new Error("unreachable");
    // Whichever attempt won, the served bytes are the ones ITS row references.
    const row = await h.metadata.getAsset(storedAssetId("tenant_a", "cli", "ferrogate", "2.0.0"));
    expect(await sha256Hex(pulled.bytes ?? new Uint8Array())).toBe(row?.content_hash);
  });
});

// ---------------------------------------------------------------------------

describe("channel resolution (#260)", () => {
  test("a channel pointer resolves to its target, not to the newest version", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "v1");
    await push(h, A, "2.0.0", "v2");
    expect((await h.service.putChannel(A, CLI, "stable", "1.0.0", CTX)).status).toBe(200);

    const pulled = await pull(h, A, "stable");
    if (!pulled.ok) throw new Error("unreachable");
    expect(decode(pulled.bytes)).toBe("v1");
    expect(pulled.headers["x-ferrogate-asset-version"]).toBe("1.0.0");
    expect(pulled.headers["x-ferrogate-asset-resolved"]).toBe("channel=stable;version=1.0.0");
  });

  test("the implicit `latest` channel is the highest non-yanked semver", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "v1");
    await push(h, A, "1.10.0", "v110");
    await push(h, A, "1.9.0", "v19");
    const pulled = await pull(h, A, "latest");
    if (!pulled.ok) throw new Error("unreachable");
    // 1.10.0 > 1.9.0 numerically; a lexical sort would answer "v19".
    expect(decode(pulled.bytes)).toBe("v110");
  });

  test("a semver range resolves to the highest match", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "v100");
    await push(h, A, "1.4.2", "v142");
    await push(h, A, "2.0.0", "v200");
    const pulled = await pull(h, A, "^1.0");
    if (!pulled.ok) throw new Error("unreachable");
    expect(decode(pulled.bytes)).toBe("v142");
    expect(pulled.headers["x-ferrogate-asset-resolved"]).toBe("range=^1.0;version=1.4.2");
  });

  test("a channel cannot be pointed at a version that does not resolve", async () => {
    const h = harness();
    await push(h, A, "1.0.0");
    const missing = await h.service.putChannel(A, CLI, "stable", "9.9.9", CTX);
    expect(missing.ok).toBe(false);
    if (missing.ok) throw new Error("unreachable");
    expect(missing.status).toBe(404);
    expect(missing.code).toBe("channel_target_not_found");
    // Nothing was written: the channel list is still empty.
    const channels = await h.service.listChannels(A, CLI);
    if (!channels.ok) throw new Error("unreachable");
    expect(channels.body.data).toHaveLength(0);
  });

  test("a channel move without ?version= is a 400, not a silent no-op", async () => {
    const h = harness();
    await push(h, A, "1.0.0");
    const missing = await h.service.putChannel(A, CLI, "stable", undefined, CTX);
    if (missing.ok) throw new Error("unreachable");
    expect(missing.status).toBe(400);
    expect(missing.code).toBe("channel_target_required");
  });

  test("deleting a channel frees the version it pinned", async () => {
    const h = harness();
    await push(h, A, "1.0.0");
    await h.service.putChannel(A, CLI, "stable", "1.0.0", CTX);
    const blocked = await h.service.deleteAsset(A, ref("1.0.0"), CTX);
    if (blocked.ok) throw new Error("unreachable");
    expect(blocked.status).toBe(409);
    expect(blocked.code).toBe("asset_version_referenced");

    expect((await h.service.deleteChannel(A, CLI, "stable", CTX)).status).toBe(200);
    expect((await h.service.deleteAsset(A, ref("1.0.0"), CTX)).status).toBe(200);
  });

  test("deleting an unknown channel is a 404", async () => {
    const h = harness();
    const gone = await h.service.deleteChannel(A, CLI, "nope", CTX);
    if (gone.ok) throw new Error("unreachable");
    expect(gone.status).toBe(404);
    expect(gone.code).toBe("channel_not_found");
  });

  test("a push may move a channel in the same request", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "v1");
    expect((await push(h, A, "2.0.0", "v2", { channel: "stable" })).status).toBe(200);
    const pulled = await pull(h, A, "stable");
    if (!pulled.ok) throw new Error("unreachable");
    expect(decode(pulled.bytes)).toBe("v2");
  });
});

// ---------------------------------------------------------------------------

describe("yank (#260/#367)", () => {
  test("a yanked version drops out of channel/latest/range resolution", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "v1");
    await push(h, A, "2.0.0", "v2");

    // Baseline: `latest` and `^1` both see 2.0.0 / 1.0.0 as they should.
    const before = await pull(h, A, "latest");
    if (!before.ok) throw new Error("unreachable");
    expect(decode(before.bytes)).toBe("v2");

    expect((await h.service.setVersionYank(A, ref("2.0.0"), true, CTX)).status).toBe(200);

    const after = await pull(h, A, "latest");
    if (!after.ok) throw new Error("unreachable");
    expect(decode(after.bytes)).toBe("v1");
    expect(after.headers["x-ferrogate-asset-version"]).toBe("1.0.0");

    const ranged = await pull(h, A, "^2.0");
    expect(ranged.ok).toBe(false);
    if (ranged.ok) throw new Error("unreachable");
    expect(ranged.status).toBe(404);
    expect(ranged.code).toBe("asset_not_found");
  });

  test("a yanked version is STILL fetchable by exact version, with a warning", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "v1");
    await push(h, A, "2.0.0", "v2");
    await h.service.setVersionYank(A, ref("2.0.0"), true, CTX);

    const exact = await pull(h, A, "2.0.0");
    expect(exact.ok).toBe(true);
    if (!exact.ok) throw new Error("unreachable");
    expect(exact.status).toBe(200);
    // The whole point of yank: an existing pin keeps working.
    expect(decode(exact.bytes)).toBe("v2");
    expect(exact.headers["x-ferrogate-asset-yanked"]).toBe("true");
    expect(exact.headers.warning).toContain("is yanked");
    expect(exact.headers["x-ferrogate-asset-resolved"]).toBe("exact=2.0.0");
  });

  test("a version a channel still points at cannot be yanked", async () => {
    const h = harness();
    await push(h, A, "1.0.0");
    await h.service.putChannel(A, CLI, "stable", "1.0.0", CTX);
    const refused = await h.service.setVersionYank(A, ref("1.0.0"), true, CTX);
    if (refused.ok) throw new Error("unreachable");
    expect(refused.status).toBe(409);
    expect(refused.code).toBe("asset_version_referenced");
    // Fail-closed: the version is still resolvable, so the channel is not stranded.
    const pulled = await pull(h, A, "stable");
    expect(pulled.ok).toBe(true);
  });

  test("a channel cannot be moved ONTO a yanked version", async () => {
    const h = harness();
    await push(h, A, "1.0.0");
    await push(h, A, "2.0.0");
    await h.service.setVersionYank(A, ref("2.0.0"), true, CTX);
    const refused = await h.service.putChannel(A, CLI, "stable", "2.0.0", CTX);
    if (refused.ok) throw new Error("unreachable");
    expect(refused.code).toBe("channel_target_not_found");
  });

  test("unyank restores resolvability", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "v1");
    await push(h, A, "2.0.0", "v2");
    await h.service.setVersionYank(A, ref("2.0.0"), true, CTX);
    expect((await h.service.setVersionYank(A, ref("2.0.0"), false, CTX)).status).toBe(200);
    const pulled = await pull(h, A, "latest");
    if (!pulled.ok) throw new Error("unreachable");
    expect(decode(pulled.bytes)).toBe("v2");
  });

  test("yanking an unknown version is a 404", async () => {
    const h = harness();
    const missing = await h.service.setVersionYank(A, ref("0.0.1"), true, CTX);
    if (missing.ok) throw new Error("unreachable");
    expect(missing.status).toBe(404);
    expect(missing.code).toBe("asset_not_found");
  });

  test("the manifest reports the yank flag", async () => {
    const h = harness();
    await push(h, A, "1.0.0");
    await push(h, A, "2.0.0");
    await h.service.setVersionYank(A, ref("1.0.0"), true, CTX);
    const manifest = await h.service.manifest(A, CLI);
    if (!manifest.ok) throw new Error("unreachable");
    // Newest first.
    expect(manifest.body.versions.map((v) => [v.version, v.yanked])).toEqual([
      ["2.0.0", false],
      ["1.0.0", true],
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("cross-tenant isolation", () => {
  test("tenant B cannot see, resolve, or download tenant A's asset", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "secret");

    const listed = await h.service.listAssets(B);
    if (!listed.ok) throw new Error("unreachable");
    expect(listed.body.data).toHaveLength(0);

    const pulled = await pull(h, B, "1.0.0");
    if (pulled.ok) throw new Error("tenant B resolved tenant A's asset");
    expect(pulled.status).toBe(404);

    const manifest = await h.service.manifest(B, CLI);
    if (manifest.ok) throw new Error("tenant B read tenant A's manifest");
    expect(manifest.status).toBe(404);

    const download = await h.service.downloadUrl(B, ref("1.0.0"), CTX);
    if (download.ok) throw new Error("tenant B presigned tenant A's object");
    expect(download.status).toBe(404);
  });

  test("a row in B's store that POINTS at A's object key is refused", async () => {
    // The listing filters are not the isolation guarantee — the key guard is.
    // This forges exactly what a corrupted row or a hand-crafted id would look
    // like, and requires the guard (not the filter) to stop it.
    const h = harness();
    await push(h, A, "1.0.0", "secret");
    const victim = await h.metadata.getAsset(
      storedAssetId("tenant_a", "cli", "ferrogate", "1.0.0"),
    );
    expect(victim).not.toBeNull();
    const stolen: StoredAsset = {
      ...(victim as StoredAsset),
      id: storedAssetId("tenant_b", "cli", "ferrogate", "1.0.0"),
      tenant_id: "tenant_b",
    };
    expect(stolen.storage_uri.startsWith(tenantKeyPrefix("tenant_a"))).toBe(true);
    h.metadata.assets.set(stolen.id, stolen);

    const pulled = await pull(h, B, "1.0.0");
    if (pulled.ok) throw new Error("the cross-tenant key guard did not fire");
    expect(pulled.status).toBe(404);
    expect(pulled.code).toBe("asset_not_found");

    const download = await h.service.downloadUrl(B, ref("1.0.0"), CTX);
    if (download.ok) throw new Error("a presigned URL was minted over another tenant's key");
    expect(download.status).toBe(404);
    // No signature was ever produced for the foreign key.
    expect(h.presigner.gets).toHaveLength(0);
  });

  test("both tenants may publish the same asset coordinates independently", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "a-bytes");
    await push(h, B, "1.0.0", "b-bytes");
    const fromA = await pull(h, A, "1.0.0");
    const fromB = await pull(h, B, "1.0.0");
    if (!fromA.ok || !fromB.ok) throw new Error("unreachable");
    expect(decode(fromA.bytes)).toBe("a-bytes");
    expect(decode(fromB.bytes)).toBe("b-bytes");
    expect(h.objects.objects.size).toBe(2);
  });

  test("a credential with no tenant attribution is refused", async () => {
    const h = harness();
    const anonymous = callerFor("");
    const listed = await h.service.listAssets(anonymous);
    if (listed.ok) throw new Error("unreachable");
    expect(listed.status).toBe(403);
    expect(listed.code).toBe("tenant_required");
  });
});

// ---------------------------------------------------------------------------

describe("presigned upload lifecycle (#259/#368)", () => {
  const CONTENT = "large-object-bytes";

  async function intent(h: ReturnType<typeof harness>, caller = A, version = "3.0.0") {
    const sha256 = await sha256Hex(bytes(CONTENT));
    const result = await h.service.createUploadIntent(
      caller,
      ref(version),
      { size_bytes: bytes(CONTENT).byteLength, sha256 },
      CTX,
    );
    return { result, sha256, size: bytes(CONTENT).byteLength };
  }

  test("an intent binds the URL to the declared size and checksum", async () => {
    const h = harness();
    const { result, sha256, size } = await intent(h);
    if (!result.ok) throw new Error("unreachable");
    const body = result.body as Record<string, unknown>;
    expect(body.object).toBe("asset_upload_intent");
    expect(body.upload_protocol).toBe("single_put");
    expect(body.method).toBe("PUT");
    expect(body.expires_in_seconds).toBe(900);
    // #368: the two headers the bucket re-signs against.
    expect(body.required_headers).toEqual({
      "content-length": String(size),
      "x-amz-content-sha256": sha256,
    });
    expect(h.presigner.puts).toHaveLength(1);
    // The staging key is server-derived, never client-named.
    expect(h.presigner.puts[0]?.key).toBe(
      stagingObjectKey(
        {
          tenantId: "tenant_a",
          assetType: "cli",
          name: "ferrogate",
          version: "3.0.0",
          variant: "",
        },
        String(body.upload_id),
        size,
        sha256,
      ),
    );
  });

  test("committing without staged bytes is `asset_not_uploaded`, never a bucket rejection", async () => {
    const h = harness();
    const { result, sha256, size } = await intent(h);
    if (!result.ok) throw new Error("unreachable");
    const uploadId = String((result.body as Record<string, unknown>).upload_id);

    const commit = await h.service.commitUpload(
      A,
      ref("3.0.0"),
      { upload_id: uploadId, size_bytes: size, sha256 },
      CTX,
    );
    if (commit.ok) throw new Error("unreachable");
    expect(commit.status).toBe(404);
    expect(commit.code).toBe("asset_not_uploaded");
    // Evidence discipline: absence is audited `staging_missing`, NOT
    // `rejected_bucket` — the gateway never observed the direct PUT.
    const outcomes = h.audit.events.map((event) => event.outcome);
    expect(outcomes).toContain("staging_missing");
    expect(outcomes).not.toContain("rejected_bucket");
  });

  test("a full commit publishes the asset and reclaims staging", async () => {
    const h = harness();
    const { result, sha256, size } = await intent(h);
    if (!result.ok) throw new Error("unreachable");
    const uploadId = String((result.body as Record<string, unknown>).upload_id);
    const stagingKey = h.presigner.puts[0]?.key as string;
    await stage(h.objects, stagingKey, bytes(CONTENT));

    const commit = await h.service.commitUpload(
      A,
      ref("3.0.0"),
      { upload_id: uploadId, size_bytes: size, sha256, content_type: "application/zip" },
      CTX,
    );
    expect(commit.ok).toBe(true);
    if (!commit.ok) throw new Error("unreachable");
    expect(commit.status).toBe(200);

    // Staging is gone, the final object is under the tenant's own prefix and
    // under the upload-derived name.
    expect(h.objects.objects.has(stagingKey)).toBe(false);
    const row = await h.metadata.getAsset(storedAssetId("tenant_a", "cli", "ferrogate", "3.0.0"));
    expect(row?.content_hash).toBe(sha256);
    expect(row?.content_type).toBe("application/zip");
    expect(row?.storage_uri.startsWith(tenantKeyPrefix("tenant_a"))).toBe(true);
    expect(
      row?.storage_uri.startsWith(
        commitObjectKeyPrefix(
          {
            tenantId: "tenant_a",
            assetType: "cli",
            name: "ferrogate",
            version: "3.0.0",
            variant: "",
          },
          uploadId,
        ),
      ),
    ).toBe(true);
    // The committed object is readable through the ordinary pull path.
    const pulled = await pull(h, A, "3.0.0");
    if (!pulled.ok) throw new Error("unreachable");
    expect(decode(pulled.bytes)).toBe(CONTENT);
  });

  test("a presigned skill archive is screened before the final object is committed", async () => {
    const inner = new BuiltinEicarScreener();
    let screenedPaths: readonly string[] = [];
    const screener: AssetScreener = {
      screen: (request) => inner.screen(request),
      async screenBundleFiles(
        request: AssetBundleScreeningRequest,
      ): Promise<AssetBundleScreeningVerdict> {
        screenedPaths = request.files.map((file) => file.path);
        return {
          visibility: "quarantined",
          auditDetail: "guardrail=blocked(rule=skill_probe at=SKILL.md)",
        };
      },
    };
    const h = harness({ screener });
    const archive = await gzip(buildTar([{ name: "SKILL.md", body: "skill instructions" }]));
    const skillRef = { assetType: "skill_bundle", name: "presigned", version: "1.0.0" };
    const sha256 = await sha256Hex(archive);
    const intentResult = await h.service.createUploadIntent(
      A,
      skillRef,
      { size_bytes: archive.byteLength, sha256 },
      CTX,
    );
    if (!intentResult.ok) throw new Error("unreachable");
    const uploadId = String((intentResult.body as Record<string, unknown>).upload_id);
    const stagingKey = h.presigner.puts[0]?.key;
    if (stagingKey === undefined) throw new Error("missing staging key");
    await stage(h.objects, stagingKey, archive);

    const commit = await h.service.commitUpload(
      A,
      skillRef,
      {
        upload_id: uploadId,
        size_bytes: archive.byteLength,
        sha256,
        content_type: "application/gzip",
      },
      CTX,
    );

    expect(commit.ok).toBe(true);
    expect(commit.status).toBe(202);
    expect(screenedPaths).toEqual(["SKILL.md"]);
    const pulled = await h.service.pullAsset(
      A,
      { assetType: skillRef.assetType, name: skillRef.name, reference: skillRef.version },
      { headers: new Headers() },
    );
    expect(pulled.ok).toBe(false);
    if (pulled.ok) throw new Error("unreachable");
    expect(pulled.status).toBe(404);
  });

  test("a re-commit of the same upload is idempotent", async () => {
    const h = harness();
    const { result, sha256, size } = await intent(h);
    if (!result.ok) throw new Error("unreachable");
    const uploadId = String((result.body as Record<string, unknown>).upload_id);
    await stage(h.objects, h.presigner.puts[0]?.key as string, bytes(CONTENT));
    const request = { upload_id: uploadId, size_bytes: size, sha256 };
    const first = await h.service.commitUpload(A, ref("3.0.0"), request, CTX);
    const second = await h.service.commitUpload(A, ref("3.0.0"), request, CTX);
    expect(first.ok && second.ok).toBe(true);
    if (!first.ok || !second.ok) throw new Error("unreachable");
    expect(second.status).toBe(first.status);
    expect(second.body).toEqual(first.body);
  });

  test("a DIFFERENT upload cannot overwrite an already-committed version", async () => {
    const h = harness();
    const first = await intent(h);
    if (!first.result.ok) throw new Error("unreachable");
    const firstUpload = String((first.result.body as Record<string, unknown>).upload_id);
    await stage(h.objects, h.presigner.puts[0]?.key as string, bytes(CONTENT));
    await h.service.commitUpload(
      A,
      ref("3.0.0"),
      { upload_id: firstUpload, size_bytes: first.size, sha256: first.sha256 },
      CTX,
    );

    const otherUpload = "upl_00112233445566778899aabbccddeeff";
    const otherKey = stagingObjectKey(
      { tenantId: "tenant_a", assetType: "cli", name: "ferrogate", version: "3.0.0", variant: "" },
      otherUpload,
      first.size,
      first.sha256,
    );
    await stage(h.objects, otherKey, bytes(CONTENT));
    const clobber = await h.service.commitUpload(
      A,
      ref("3.0.0"),
      { upload_id: otherUpload, size_bytes: first.size, sha256: first.sha256 },
      CTX,
    );
    if (clobber.ok) throw new Error("a second upload committed over an immutable version");
    expect(clobber.status).toBe(409);
    expect(clobber.code).toBe("asset_version_immutable");
    // The rejected upload's staging bytes were reclaimed, not left to rot.
    expect(h.objects.objects.has(otherKey)).toBe(false);
  });

  test("a size mismatch is a 422 and the staged bytes are destroyed", async () => {
    const h = harness();
    const { result, sha256, size } = await intent(h);
    if (!result.ok) throw new Error("unreachable");
    const uploadId = String((result.body as Record<string, unknown>).upload_id);
    const stagingKey = h.presigner.puts[0]?.key as string;
    await stage(h.objects, stagingKey, bytes(`${CONTENT}-extra`));

    const commit = await h.service.commitUpload(
      A,
      ref("3.0.0"),
      { upload_id: uploadId, size_bytes: size, sha256 },
      CTX,
    );
    if (commit.ok) throw new Error("unreachable");
    expect(commit.status).toBe(422);
    expect(commit.code).toBe("asset_commit_size_mismatch");
    expect(h.objects.objects.has(stagingKey)).toBe(false);
    expect(
      await h.metadata.getAsset(storedAssetId("tenant_a", "cli", "ferrogate", "3.0.0")),
    ).toBeNull();
  });

  test("same size, different bytes is a hash mismatch", async () => {
    const h = harness();
    const { result, sha256, size } = await intent(h);
    if (!result.ok) throw new Error("unreachable");
    const uploadId = String((result.body as Record<string, unknown>).upload_id);
    const stagingKey = h.presigner.puts[0]?.key as string;
    // Byte substitution that preserves the declared length.
    await stage(h.objects, stagingKey, bytes("X".repeat(CONTENT.length)));

    const commit = await h.service.commitUpload(
      A,
      ref("3.0.0"),
      { upload_id: uploadId, size_bytes: size, sha256 },
      CTX,
    );
    if (commit.ok) throw new Error("unreachable");
    expect(commit.status).toBe(422);
    expect(commit.code).toBe("asset_commit_hash_mismatch");
    expect(h.objects.objects.has(stagingKey)).toBe(false);
  });

  test("abort with nothing staged corroborates a claimed bucket rejection", async () => {
    const h = harness();
    const { result, sha256, size } = await intent(h);
    if (!result.ok) throw new Error("unreachable");
    const uploadId = String((result.body as Record<string, unknown>).upload_id);

    const abort = await h.service.abortUpload(
      A,
      ref("3.0.0"),
      { upload_id: uploadId, size_bytes: size, sha256, reason: "bucket_rejected" },
      CTX,
    );
    if (!abort.ok) throw new Error("unreachable");
    expect(abort.body).toMatchObject({
      object: "asset_upload_abort",
      upload_id: uploadId,
      staging_object_removed: false,
      staging_reclamation: "not_staged",
      outcome: "rejected_bucket",
    });
  });

  test("a bucket-rejection claim contradicted by staged bytes is downgraded", async () => {
    const h = harness();
    const { result, sha256, size } = await intent(h);
    if (!result.ok) throw new Error("unreachable");
    const uploadId = String((result.body as Record<string, unknown>).upload_id);
    const stagingKey = h.presigner.puts[0]?.key as string;
    await stage(h.objects, stagingKey, bytes(CONTENT));

    const abort = await h.service.abortUpload(
      A,
      ref("3.0.0"),
      { upload_id: uploadId, size_bytes: size, sha256, reason: "bucket_rejected" },
      CTX,
    );
    if (!abort.ok) throw new Error("unreachable");
    // The bucket ACCEPTED the PUT, so the claim is evidence-free and is
    // recorded as a plain abort. The bytes are reclaimed.
    expect(abort.body).toMatchObject({
      staging_object_removed: true,
      staging_reclamation: "removed",
      outcome: "aborted",
    });
    expect(h.objects.objects.has(stagingKey)).toBe(false);
  });

  test("a refused delete is reported as a FAILED reclamation, never a success", async () => {
    const store = new UndeletableObjectStore();
    const h = harness({ objects: store });
    const sha256 = await sha256Hex(bytes(CONTENT));
    const size = bytes(CONTENT).byteLength;
    const result = await h.service.createUploadIntent(
      A,
      ref("3.0.0"),
      { size_bytes: size, sha256 },
      CTX,
    );
    if (!result.ok) throw new Error("unreachable");
    const uploadId = String((result.body as Record<string, unknown>).upload_id);
    await stage(store, h.presigner.puts[0]?.key as string, bytes(CONTENT));

    const abort = await h.service.abortUpload(
      A,
      ref("3.0.0"),
      { upload_id: uploadId, size_bytes: size, sha256 },
      CTX,
    );
    if (!abort.ok) throw new Error("unreachable");
    expect(abort.body).toMatchObject({
      staging_object_removed: false,
      staging_reclamation: "removal_failed",
      outcome: "aborted_reclaim_failed",
    });
  });

  test("an already-committed upload cannot be aborted", async () => {
    const h = harness();
    const { result, sha256, size } = await intent(h);
    if (!result.ok) throw new Error("unreachable");
    const uploadId = String((result.body as Record<string, unknown>).upload_id);
    await stage(h.objects, h.presigner.puts[0]?.key as string, bytes(CONTENT));
    await h.service.commitUpload(
      A,
      ref("3.0.0"),
      { upload_id: uploadId, size_bytes: size, sha256 },
      CTX,
    );

    const abort = await h.service.abortUpload(
      A,
      ref("3.0.0"),
      { upload_id: uploadId, size_bytes: size, sha256 },
      CTX,
    );
    if (abort.ok) throw new Error("an abort deleted a committed upload's object");
    expect(abort.status).toBe(409);
    expect(abort.code).toBe("asset_upload_already_committed");
    // The published bytes are untouched.
    const pulled = await pull(h, A, "3.0.0");
    expect(pulled.ok).toBe(true);
  });

  test("an intent for an already-published version is refused", async () => {
    const h = harness();
    await push(h, A, "3.0.0");
    const { result } = await intent(h);
    if (result.ok) throw new Error("unreachable");
    expect(result.status).toBe(409);
    expect(result.code).toBe("asset_version_immutable");
  });

  test("the whole presign family degrades to 503 with no bucket configured", async () => {
    const h = harness({ limits: { presignEnabled: false } });
    const sha256 = await sha256Hex(bytes(CONTENT));
    const size = bytes(CONTENT).byteLength;
    const uploadId = "upl_00112233445566778899aabbccddeeff";
    for (const result of [
      await h.service.createUploadIntent(A, ref("3.0.0"), { size_bytes: size, sha256 }, CTX),
      await h.service.commitUpload(
        A,
        ref("3.0.0"),
        { upload_id: uploadId, size_bytes: size, sha256 },
        CTX,
      ),
      await h.service.abortUpload(
        A,
        ref("3.0.0"),
        { upload_id: uploadId, size_bytes: size, sha256 },
        CTX,
      ),
    ]) {
      if (result.ok) throw new Error("unreachable");
      expect(result.status).toBe(503);
      expect(result.code).toBe("asset_bucket_unavailable");
    }
  });
});

// ---------------------------------------------------------------------------

describe("presigned download", () => {
  test("a published asset yields a signed URL plus its verification metadata", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "payload");
    const result = await h.service.downloadUrl(A, ref("1.0.0"), CTX);
    if (!result.ok) throw new Error("unreachable");
    const body = result.body as Record<string, unknown>;
    expect(body.object).toBe("asset_download_url");
    expect(body.method).toBe("GET");
    expect(body.expires_in_seconds).toBe(900);
    expect(body.sha256).toBe(await sha256Hex(bytes("payload")));
    expect(String(body.download_url)).toContain(tenantKeyPrefix("tenant_a"));
  });

  test("a withheld asset is a 404 here, exactly as on the pull path", async () => {
    const h = harness({ screener: new PendingScreener() });
    expect((await push(h, A, "1.0.0")).status).toBe(202);
    const result = await h.service.downloadUrl(A, ref("1.0.0"), CTX);
    if (result.ok) throw new Error("a withheld asset was presigned for download");
    expect(result.status).toBe(404);
    expect(result.code).toBe("asset_not_found");
  });

  test("the download path does NOT require the hosting entitlement", async () => {
    // Rust `authorize_asset(require_hosting: false)`: a lapsed plan stops new
    // publishes without stranding what the tenant already published.
    const h = harness();
    await push(h, A, "1.0.0");
    const lapsed = callerFor("tenant_a", { assetHostingEnabled: false });
    expect((await h.service.downloadUrl(lapsed, ref("1.0.0"), CTX)).ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------

describe("screening + withholding (#366/#378/#379)", () => {
  const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

  test("an infected push is stored 202 and withheld from every read surface", async () => {
    const h = harness();
    const pushed = await push(h, A, "1.0.0", EICAR);
    if (!pushed.ok) throw new Error("unreachable");
    // Stored — the version is claimed — but NOT serving.
    expect(pushed.status).toBe(202);
    expect(pushed.body.asset.visibility).toBe("quarantined");

    const listed = await h.service.listAssets(A);
    if (!listed.ok) throw new Error("unreachable");
    expect(listed.body.data).toHaveLength(0);

    const manifest = await h.service.manifest(A, CLI);
    if (manifest.ok) throw new Error("a quarantined asset appeared in the manifest");
    expect(manifest.status).toBe(404);

    const pulled = await pull(h, A, "1.0.0");
    if (pulled.ok) throw new Error("a quarantined asset was served");
    expect(pulled.status).toBe(404);
  });

  test("the withheld listing surfaces the row and its screening evidence", async () => {
    const h = harness();
    await push(h, A, "1.0.0", EICAR);
    const withheld = await h.service.listWithheldAssets(A);
    if (!withheld.ok) throw new Error("unreachable");
    expect(withheld.body.data).toHaveLength(1);
    const row = withheld.body.data[0];
    expect(row?.visibility).toBe("quarantined");
    expect(row?.screening_evidence).toContain("scan=infected(eicar)");
  });

  test("the withheld listing is tenant-scoped", async () => {
    const h = harness();
    await push(h, A, "1.0.0", EICAR);
    const other = await h.service.listWithheldAssets(B);
    if (!other.ok) throw new Error("unreachable");
    expect(other.body.data).toHaveLength(0);
  });

  test("promotion flips pending_scan to visible and makes the asset resolvable", async () => {
    const h = harness({ screener: new PendingScreener() });
    expect((await push(h, A, "1.0.0", "payload")).status).toBe(202);
    expect((await pull(h, A, "1.0.0")).ok).toBe(false);

    const promoted = await h.service.promoteVisibility(
      A,
      ref("1.0.0"),
      { scan_outcome: "clean", evidence: "clamav 0.103 clean at 2026-07-31" },
      CTX,
    );
    if (!promoted.ok) throw new Error("unreachable");
    expect(promoted.status).toBe(200);
    const pulled = await pull(h, A, "1.0.0");
    if (!pulled.ok) throw new Error("unreachable");
    expect(decode(pulled.bytes)).toBe("payload");
  });

  test("an unknown verdict never promotes", async () => {
    const h = harness({ screener: new PendingScreener() });
    await push(h, A, "1.0.0");
    const result = await h.service.promoteVisibility(
      A,
      ref("1.0.0"),
      { scan_outcome: "probably-fine", evidence: "a hunch" },
      CTX,
    );
    if (result.ok) throw new Error("an unknown verdict promoted an asset");
    expect(result.status).toBe(400);
    expect(result.code).toBe("invalid_scan_outcome");
    expect((await pull(h, A, "1.0.0")).ok).toBe(false);
  });

  test("evidence is mandatory", async () => {
    const h = harness({ screener: new PendingScreener() });
    await push(h, A, "1.0.0");
    const result = await h.service.promoteVisibility(
      A,
      ref("1.0.0"),
      { scan_outcome: "clean", evidence: "   " },
      CTX,
    );
    if (result.ok) throw new Error("unreachable");
    expect(result.status).toBe(400);
    expect(result.code).toBe("missing_scan_evidence");
  });

  test("a non-pending asset cannot be promoted", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "clean payload");
    const result = await h.service.promoteVisibility(
      A,
      ref("1.0.0"),
      { scan_outcome: "clean", evidence: "rescan" },
      CTX,
    );
    if (result.ok) throw new Error("unreachable");
    expect(result.status).toBe(409);
    expect(result.code).toBe("asset_not_pending_scan");
  });

  test("a channel cannot be moved onto a withheld version", async () => {
    const h = harness({ screener: new PendingScreener() });
    await push(h, A, "1.0.0");
    const result = await h.service.putChannel(A, CLI, "stable", "1.0.0", CTX);
    if (result.ok) throw new Error("a channel pointed at a version nothing will serve");
    expect(result.code).toBe("channel_target_not_found");
  });
});

// ---------------------------------------------------------------------------

describe("quotas + entitlements", () => {
  test("a push that would exceed the tenant quota is refused atomically", async () => {
    const h = harness();
    const bounded = callerFor("tenant_a", { assetStorageQuotaBytes: 20 });
    expect((await push(h, bounded, "1.0.0", "0123456789")).status).toBe(200);
    const over = await push(h, bounded, "2.0.0", "0123456789ABCDEF");
    if (over.ok) throw new Error("unreachable");
    expect(over.status).toBe(403);
    expect(over.code).toBe("asset_storage_quota_exceeded");
    // The refused push left no candidate object behind.
    expect(h.objects.objects.size).toBe(1);
  });

  test("an oversized inline push is 413 before anything is stored", async () => {
    const h = harness({ limits: { inlineMaxBytes: 8 } });
    const over = await push(h, A, "1.0.0", "0123456789");
    if (over.ok) throw new Error("unreachable");
    expect(over.status).toBe(413);
    expect(over.code).toBe("payload_too_large");
    expect(h.objects.objects.size).toBe(0);
  });

  test("an over-ceiling intent is refused at preflight", async () => {
    const h = harness({ limits: { presignMaxObjectBytes: 16 } });
    const result = await h.service.createUploadIntent(
      A,
      ref("1.0.0"),
      { size_bytes: 64, sha256: "a".repeat(64) },
      CTX,
    );
    if (result.ok) throw new Error("unreachable");
    expect(result.status).toBe(413);
    expect(h.audit.events.map((event) => event.outcome)).toContain("rejected_intent");
    // No URL was ever signed.
    expect(h.presigner.puts).toHaveLength(0);
  });

  test("a tenant without the hosting entitlement may read but not write", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "payload");
    const lapsed = callerFor("tenant_a", { assetHostingEnabled: false });

    const blocked = await push(h, lapsed, "2.0.0");
    if (blocked.ok) throw new Error("unreachable");
    expect(blocked.status).toBe(403);
    expect(blocked.code).toBe("asset_hosting_disabled");

    expect((await h.service.listAssets(lapsed)).ok).toBe(true);
    expect((await pull(h, lapsed, "1.0.0")).ok).toBe(true);
    expect((await h.service.manifest(lapsed, CLI)).ok).toBe(true);
  });

  test("the storage summary reports the PLAN-EFFECTIVE ceilings", async () => {
    const h = harness({ limits: { presignMaxObjectBytes: 1_000_000, inlineMaxBytes: 500 } });
    const bounded = callerFor("tenant_a", {
      assetStorageQuotaBytes: 900,
      assetMaxObjectBytes: 300,
    });
    await push(h, bounded, "1.0.0", "0123456789");
    const summary = await h.service.storageSummary(bounded);
    if (!summary.ok) throw new Error("unreachable");
    expect(summary.body.used_bytes).toBe(10);
    expect(summary.body.quota_bytes).toBe(900);
    expect(summary.body.remaining_bytes).toBe(890);
    // min(global 1_000_000, per-object 300, quota 900) = 300.
    expect(summary.body.presigned_upload).toEqual({
      enabled: true,
      max_object_bytes: 300,
      url_ttl_seconds: 900,
    });
    // min(inline 500, per-object 300, quota 900) = 300.
    expect(summary.body.inline_upload_max_bytes).toBe(300);
  });

  test("with no bucket the summary says the presigned path is off", async () => {
    const h = harness({ limits: { presignEnabled: false } });
    const summary = await h.service.storageSummary(A);
    if (!summary.ok) throw new Error("unreachable");
    expect(summary.body.presigned_upload).toEqual({ enabled: false });
  });
});

// ---------------------------------------------------------------------------

describe("pull transport semantics (#258/#301)", () => {
  test("a matching If-None-Match short-circuits to 304 with the resolution headers", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "payload");
    const first = await pull(h, A, "1.0.0");
    if (!first.ok) throw new Error("unreachable");
    const etag = first.headers.etag as string;
    expect(etag).toBe(`"${await sha256Hex(bytes("payload"))}"`);

    const revalidated = await h.service.pullAsset(
      A,
      { ...CLI, reference: "1.0.0" },
      { headers: new Headers({ "if-none-match": etag }) },
    );
    if (!revalidated.ok) throw new Error("unreachable");
    expect(revalidated.status).toBe(304);
    expect(revalidated.bytes).toBeNull();
    // The #260 resolution metadata survives the short-circuit.
    expect(revalidated.headers["x-ferrogate-asset-resolved"]).toBe("exact=1.0.0");
  });

  test("a byte range answers 206 with the right slice", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "0123456789");
    const ranged = await h.service.pullAsset(
      A,
      { ...CLI, reference: "1.0.0" },
      { headers: new Headers({ range: "bytes=2-5" }) },
    );
    if (!ranged.ok) throw new Error("unreachable");
    expect(ranged.status).toBe(206);
    expect(decode(ranged.bytes)).toBe("2345");
    expect(ranged.headers["content-range"]).toBe("bytes 2-5/10");
  });

  test("an unsatisfiable range answers 416", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "0123456789");
    const ranged = await h.service.pullAsset(
      A,
      { ...CLI, reference: "1.0.0" },
      { headers: new Headers({ range: "bytes=99-" }) },
    );
    if (!ranged.ok) throw new Error("unreachable");
    expect(ranged.status).toBe(416);
    expect(ranged.headers["content-range"]).toBe("bytes */10");
  });

  test("corrupted stored bytes fail the read rather than being served", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "payload");
    const row = await h.metadata.getAsset(storedAssetId("tenant_a", "cli", "ferrogate", "1.0.0"));
    // Simulate storage-layer corruption/tampering under the same key.
    await stage(h.objects, row?.storage_uri as string, bytes("tampered"));
    const pulled = await pull(h, A, "1.0.0");
    if (pulled.ok) throw new Error("tampered bytes were served");
    expect(pulled.status).toBe(500);
    expect(pulled.code).toBe("asset_integrity_check_failed");
  });

  test("an object above the inline read budget names the presigned download", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "0123456789");
    // Shrink the budget after publication, as a config reload would.
    const tight = harness({ limits: { inlineMaxBytes: 4 } });
    for (const [key, value] of h.objects.objects) tight.objects.objects.set(key, value);
    for (const [key, value] of h.metadata.assets) tight.metadata.assets.set(key, value);
    const pulled = await tight.service.pullAsset(
      A,
      { ...CLI, reference: "1.0.0" },
      { headers: new Headers() },
    );
    if (pulled.ok) throw new Error("unreachable");
    expect(pulled.status).toBe(413);
    expect(pulled.code).toBe("asset_too_large_for_inline_pull");
  });

  test("a missing bucket object is a storage failure, not a 200 with no bytes", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "payload");
    h.objects.objects.clear();
    const pulled = await pull(h, A, "1.0.0");
    if (pulled.ok) throw new Error("unreachable");
    expect(pulled.status).toBe(503);
    expect(pulled.code).toBe("storage_unavailable");
  });
});

// ---------------------------------------------------------------------------

describe("platform variants (#260)", () => {
  test("an ambiguous version demands ?platform=", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "linux", { variant: "linux-x64" });
    await push(h, A, "1.0.0", "darwin", { variant: "darwin-arm64" });
    const ambiguous = await pull(h, A, "1.0.0");
    if (ambiguous.ok) throw new Error("unreachable");
    expect(ambiguous.status).toBe(400);
    expect(ambiguous.code).toBe("asset_variant_required");

    const selected = await pull(h, A, "1.0.0", "darwin-arm64");
    if (!selected.ok) throw new Error("unreachable");
    expect(decode(selected.bytes)).toBe("darwin");
    expect(selected.headers["x-ferrogate-asset-variant"]).toBe("darwin-arm64");
  });

  test("an unknown platform is a 404, never a silent fallback", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "linux", { variant: "linux-x64" });
    const missing = await pull(h, A, "1.0.0", "windows-x64");
    if (missing.ok) throw new Error("a wrong-platform binary was served");
    expect(missing.status).toBe(404);
    expect(missing.code).toBe("asset_variant_not_found");
  });

  test("the default artifact wins when no platform is requested", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "generic");
    await push(h, A, "1.0.0", "linux", { variant: "linux-x64" });
    const pulled = await pull(h, A, "1.0.0");
    if (!pulled.ok) throw new Error("unreachable");
    expect(decode(pulled.bytes)).toBe("generic");
  });

  test("deleting one variant leaves the other resolvable", async () => {
    const h = harness();
    await push(h, A, "1.0.0", "linux", { variant: "linux-x64" });
    await push(h, A, "1.0.0", "darwin", { variant: "darwin-arm64" });
    await h.service.putChannel(A, CLI, "stable", "1.0.0", CTX);
    // A channel references the version, but another variant still resolves it.
    expect((await h.service.deleteAsset(A, ref("1.0.0", "linux-x64"), CTX)).status).toBe(200);
    const pulled = await pull(h, A, "stable");
    if (!pulled.ok) throw new Error("unreachable");
    expect(decode(pulled.bytes)).toBe("darwin");
    // Removing the LAST one would strand the channel, so it is refused.
    const last = await h.service.deleteAsset(A, ref("1.0.0", "darwin-arm64"), CTX);
    if (last.ok) throw new Error("the last resolvable variant of a pinned version was deleted");
    expect(last.code).toBe("asset_version_referenced");
  });
});

// ---------------------------------------------------------------------------

describe("listing + audit", () => {
  test("listing narrows by asset type", async () => {
    const h = harness();
    await push(h, A, "1.0.0");
    await h.service.putAsset(
      A,
      { assetType: "skill", name: "summarize", version: "1.0.0" },
      { content: bytes("skill"), contentType: "application/json" },
      CTX,
    );
    const all = await h.service.listAssets(A);
    const cli = await h.service.listAssets(A, "cli");
    if (!all.ok || !cli.ok) throw new Error("unreachable");
    expect(all.body.data).toHaveLength(2);
    expect(cli.body.data.map((row) => row.asset_type)).toEqual(["cli"]);
  });

  test("the withheld listing paginates and searches", async () => {
    const h = harness({ screener: new PendingScreener() });
    for (const version of ["1.0.0", "1.1.0", "1.2.0"]) await push(h, A, version);
    const page = await h.service.listWithheldAssets(A, { offset: 1, limit: 1 });
    if (!page.ok) throw new Error("unreachable");
    expect(page.body.total).toBe(3);
    expect(page.body.data).toHaveLength(1);

    const searched = await h.service.listWithheldAssets(A, { search: "1.2.0" });
    if (!searched.ok) throw new Error("unreachable");
    expect(searched.body.data.map((row) => row.version)).toEqual(["1.2.0"]);
  });

  test("audit rows carry the tenant, request id and agent run id", async () => {
    const h = harness();
    await h.service.putAsset(
      A,
      ref("1.0.0"),
      { content: bytes("payload") },
      { requestId: "req_42", agentRunId: "run_7" },
    );
    const committed = h.audit.events.find((event) => event.outcome === "committed");
    expect(committed).toMatchObject({
      action: "asset.push",
      tenantId: "tenant_a",
      requestId: "req_42",
      agentRunId: "run_7",
    });
  });
});

// ---------------------------------------------------------------------------

describe("key layout under real pushes", () => {
  test("every object a push writes lands under the pushing tenant's prefix", async () => {
    const h = harness();
    await push(h, A, "1.0.0");
    await push(h, B, "1.0.0");
    const keys = [...h.objects.objects.keys()];
    expect(keys.filter((key) => key.startsWith(tenantKeyPrefix("tenant_a")))).toHaveLength(1);
    expect(keys.filter((key) => key.startsWith(tenantKeyPrefix("tenant_b")))).toHaveLength(1);
    // And the key is not the deterministic row id — it carries per-attempt
    // randomness (#369), so two pushes can never name the same object.
    const sample = newAssetObjectKey({
      tenantId: "tenant_a",
      assetType: "cli",
      name: "ferrogate",
      version: "1.0.0",
      variant: "",
    });
    expect(keys).not.toContain(sample);
  });
});
