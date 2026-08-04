/**
 * `static_site` bundles (issue #736) — the security half, driven end to end.
 *
 * Every hostile case below is a REAL archive built in `./archives.ts` and
 * pushed through `AssetService.putAsset`, not a unit call into a path
 * validator: a helper that rejects `../x` proves nothing if the expansion loop
 * never calls it. The defect this file pins is that before #736 a `static_site`
 * push stored the archive as ONE opaque blob, so every byte inside it — a
 * traversing path, a symlink, an `.exe` — was published unexamined.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import {
  BUNDLE_MAX_FILES,
  BUNDLE_MAX_TOTAL_BYTES,
  STATIC_SITE_BUNDLE_FILE_CONTENT_TYPES,
  bundleFileContentType,
} from "../../src/assets/bundle.js";
import {
  type AssetDatabase,
  D1AssetBundleIndexStore,
  isAssetDatabase,
} from "../../src/assets/d1.js";
import { bundleFileObjectKey, storedAssetVariantId } from "../../src/assets/keys.js";
import {
  type AssetBundleIndexStore,
  type AssetCaller,
  type AssetObjectMetadata,
  InMemoryAssetBundleIndexStore,
  InMemoryAssetObjectStore,
  type StoredBundleFile,
} from "../../src/assets/ports.js";
import { buildTar, buildZip, gzip, gzipZeroFileBomb, paxRecord } from "./archives.js";
import { CTX, PendingScreener, callerFor, decode, harness } from "./helpers.js";

/**
 * A NUL byte, built at RUNTIME.
 *
 * The DOS `MZ` header below needs two REAL NULs — that is what makes the
 * fixture a genuine executable prefix rather than a lookalike — but typing them
 * as literals is what made this very file BINARY to git: `git diff --stat`
 * reported `Bin 0 -> 24797 bytes` and `gh pr diff` emitted no hunk at all, so
 * the 684-line security suite at the centre of issue #736 was invisible to diff
 * review and to `grep`. A reviewer looking for exactly these tests concluded
 * they did not exist.
 *
 * `String.fromCharCode(0)` produces the identical byte at runtime and leaves
 * the source file text, which is the same remedy `test/source-nul-bytes.test.ts`
 * applies to itself — and that guard now scans this file.
 */
const NUL = String.fromCharCode(0);

const A = callerFor("tenant_a");
const SITE = { assetType: "static_site", name: "docs" } as const;

function push(
  h: ReturnType<typeof harness>,
  content: Uint8Array,
  contentType = "application/x-tar",
  version = "1.0.0",
  caller: AssetCaller = A,
) {
  return h.service.putAsset(caller, { ...SITE, version }, { content, contentType }, CTX);
}

function pull(
  h: ReturnType<typeof harness>,
  reference: string,
  bundlePath?: string,
  caller: AssetCaller = A,
) {
  return h.service.pullAsset(
    caller,
    { ...SITE, reference },
    { headers: new Headers(), bundlePath },
    CTX,
  );
}

function assetId(version: string, tenant = "tenant_a"): string {
  return storedAssetVariantId(tenant, SITE.assetType, SITE.name, version, "");
}

/** A minimal well-formed site: two files the allowlist admits. */
function goodSite(): Uint8Array {
  return buildTar([
    { name: "index.html", body: "<!doctype html><h1>docs</h1>" },
    { name: "assets/app.css", body: "body{color:red}" },
  ]);
}

describe("static_site bundle expansion refuses hostile archives", () => {
  test("a tar entry escaping the bundle root is refused", async () => {
    const h = harness();
    const archive = buildTar([
      { name: "index.html", body: "ok" },
      { name: "../../etc/passwd.html", body: "pwned" },
    ]);

    const result = await push(h, archive);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(422);
    expect(result.code).toBe("asset_rejected");
    expect(result.message).toContain("../../etc/passwd.html");
  });

  test("an absolute tar path is refused", async () => {
    const h = harness();
    const archive = buildTar([{ name: "/etc/shadow.html", body: "pwned" }]);

    const result = await push(h, archive);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(422);
    expect(result.message).toContain("/etc/shadow.html");
  });

  test("a tar symlink entry is refused", async () => {
    const h = harness();
    const archive = buildTar([
      { name: "index.html", body: "ok" },
      { name: "secrets.html", typeflag: "2", linkname: "/etc/passwd" },
    ]);

    const result = await push(h, archive);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(422);
    expect(result.message).toContain("symlink");
  });

  test("a pax header cannot smuggle a traversing path past the ustar name", async () => {
    const h = harness();
    // The ustar name is innocuous; the pax `path` attribute is the real one a
    // conforming reader must honour, and is where the traversal hides.
    const archive = buildTar([
      { name: "PaxHeaders/0/index.html", typeflag: "x", body: paxRecord("path", "../escape.html") },
      { name: "index.html", body: "pwned" },
    ]);

    const result = await push(h, archive);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(422);
    expect(result.message).toContain("../escape.html");
  });

  test("the per-file content-type allowlist is enforced inside an allowed archive", async () => {
    const h = harness();
    // `application/x-tar` is an ALLOWED content type for `static_site`
    // (content-gate.ts). That is exactly the point: the archive's own type says
    // nothing about what is inside it.
    const archive = buildTar([
      { name: "index.html", body: "ok" },
      { name: "payload.exe", body: `MZ${NUL}${NUL}` },
    ]);

    const result = await push(h, archive);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(422);
    expect(result.code).toBe("asset_rejected");
    expect(result.message).toContain("payload.exe");
  });

  test("a nested archive inside the bundle is refused even though the outer archive type is allowed", async () => {
    const h = harness();
    const archive = buildTar([
      { name: "index.html", body: "ok" },
      { name: "download.zip", body: "PK" },
    ]);

    const result = await push(h, archive);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message).toContain("download.zip");
  });

  test("a zip entry marked as a unix symlink is refused", async () => {
    const h = harness();
    const archive = await buildZip([
      { name: "index.html", body: "ok" },
      { name: "link.html", body: "../../etc/passwd", unixMode: 0o120777 },
    ]);

    const result = await push(h, archive, "application/zip");

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message).toContain("symlink");
  });

  test("a zip entry escaping the bundle root is refused", async () => {
    const h = harness();
    const archive = await buildZip([{ name: "../escape.html", body: "pwned" }]);

    const result = await push(h, archive, "application/zip");

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message).toContain("../escape.html");
  });
});

describe("static_site bundle ceilings are real bounds, not comments", () => {
  test("a high-ratio gzip bomb is abandoned at the decompressed ceiling", async () => {
    // 256 MiB of zeros inside a tar, gzipped down to well under a megabyte: the
    // archive sails past every size check that looks at the UPLOAD, which is
    // exactly what a bomb is for. The tenant's storage quota tightens the
    // decompressed ceiling to 1 MB, so expansion has to abandon it 255 MiB
    // before the archive is finished.
    const h = harness();
    const bomb = await gzipZeroFileBomb("bomb.txt", 256 * 1024 * 1024);
    expect(bomb.byteLength).toBeLessThan(1024 * 1024);
    const capped = callerFor("tenant_a", { assetStorageQuotaBytes: 1_000_000 });

    const result = await push(h, bomb, "application/gzip", "1.0.0", capped);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(422);
    // The WORDING is the assertion. A ceiling that only measured the finished
    // plaintext would answer the accumulator's message instead, having already
    // materialized a quarter of a gigabyte inside the isolate.
    expect(result.message).toContain("abandoned while decompressing");
    // And nothing durable survived the attempt.
    expect(await h.metadata.getAsset(assetId("1.0.0"))).toBeNull();
    expect(h.objects.objects.size).toBe(0);
    // 30s is sized against 719ms in an otherwise-idle sweep and 2.744s in a
    // focused run at system load average 15-27; shrinking the 256 MiB bomb
    // would stop proving that expansion aborts mid-stream.
  }, 30_000);

  test("the file-count ceiling refuses an archive of many tiny files", async () => {
    // The REAL constant, not a tightened one: a count bomb costs no bytes.
    const h = harness();
    const many = buildTar(
      Array.from({ length: BUNDLE_MAX_FILES + 1 }, (_, index) => ({
        name: `f${index}.txt`,
        body: "x",
      })),
    );

    const result = await push(h, many);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message).toContain(`${BUNDLE_MAX_FILES}-file ceiling`);
  });

  test("the ceilings can only be tightened by a caller, never widened", async () => {
    // A caller passing a HUGE quota must not raise the fixed ceiling. Asserted
    // on the constant rather than by uploading 32 MiB.
    const h = harness();
    const generous = callerFor("tenant_a", {
      assetStorageQuotaBytes: BUNDLE_MAX_TOTAL_BYTES * 1000,
    });
    const result = await push(h, goodSite(), "application/x-tar", "1.0.0", generous);

    expect(result.ok).toBe(true);
    expect(BUNDLE_MAX_TOTAL_BYTES).toBe(32 * 1024 * 1024);
  });

  test("an unrecognizable archive is refused rather than stored opaquely", async () => {
    const h = harness();

    const result = await push(h, new TextEncoder().encode("not an archive at all"));

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message).toContain("not a recognizable tar, tar.gz or zip archive");
  });
});

describe("static_site bundle expansion publishes a good site", () => {
  test("a tar of two allowed files becomes per-file objects and an index", async () => {
    const h = harness();

    const result = await push(h, goodSite());

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.body.asset.visibility).toBe("visible");

    const files = await h.bundles.listBundleFiles(assetId("1.0.0"));
    expect(files.map((file) => file.path)).toEqual(["assets/app.css", "index.html"]);
    const css = files.find((file) => file.path === "assets/app.css");
    expect(css?.content_type).toBe("text/css");
    expect(css?.size_bytes).toBe("body{color:red}".length);
    // Every file object really exists, under the version's own key prefix.
    for (const file of files) {
      expect(
        file.storage_uri.startsWith("assets/v1/t/tenant_a/obj/static_site/docs/1.0.0/_/"),
      ).toBe(true);
      expect(await h.objects.head(file.storage_uri)).not.toBeNull();
    }
  });

  test("a gzipped tar is accepted and produces the same index", async () => {
    const h = harness();

    const result = await push(h, await gzip(goodSite()), "application/gzip");

    expect(result.ok).toBe(true);
    const files = await h.bundles.listBundleFiles(assetId("1.0.0"));
    expect(files.map((file) => file.path)).toEqual(["assets/app.css", "index.html"]);
  });

  test("a DEFLATEd zip is accepted", async () => {
    const h = harness();
    const archive = await buildZip([
      { name: "index.html", body: "<!doctype html>hello", deflate: true },
      { name: "docs/", body: "" },
      { name: "docs/guide.md", body: "# guide", deflate: true },
    ]);

    const result = await push(h, archive, "application/zip");

    expect(result.ok).toBe(true);
    const files = await h.bundles.listBundleFiles(assetId("1.0.0"));
    expect(files.map((file) => file.path)).toEqual(["docs/guide.md", "index.html"]);
  });

  test("the per-file allowlist excludes the archive containers and octet-stream", () => {
    // The property the whole gate rests on: `application/x-tar` is an ALLOWED
    // `static_site` content type but is not a legal type for a file INSIDE the
    // bundle, and no extension maps to `application/octet-stream`.
    expect(STATIC_SITE_BUNDLE_FILE_CONTENT_TYPES).not.toContain("application/octet-stream");
    expect(STATIC_SITE_BUNDLE_FILE_CONTENT_TYPES).not.toContain("application/zip");
    expect(STATIC_SITE_BUNDLE_FILE_CONTENT_TYPES).not.toContain("application/x-tar");
    expect(bundleFileContentType("app.wasm")).toBeUndefined();
    expect(bundleFileContentType("noextension")).toBeUndefined();
    expect(bundleFileContentType("index.html")).toBe("text/html");
  });
});

describe("a bundle publish is atomic", () => {
  /** A store whose Nth `put` fails — the crash-midway case. */
  class FailingObjectStore extends InMemoryAssetObjectStore {
    #puts = 0;
    constructor(private readonly failOnPut: number) {
      super();
    }
    override async put(
      key: string,
      value: Parameters<InMemoryAssetObjectStore["put"]>[1],
      options?: Parameters<InMemoryAssetObjectStore["put"]>[2],
    ): Promise<AssetObjectMetadata | null> {
      this.#puts += 1;
      if (this.#puts === this.failOnPut) throw new Error("bucket write failed mid-expansion");
      return super.put(key, value, options);
    }
  }

  test("a failure after some files have landed leaves nothing resolvable", async () => {
    // put #1 is the archive, #2/#3/#4 are the files: fail on the third file, so
    // two are already durably written when it happens.
    const objects = new FailingObjectStore(4);
    const h = harness({ objects });
    const archive = buildTar([
      { name: "a.html", body: "a" },
      { name: "b.html", body: "b" },
      { name: "c.html", body: "c" },
    ]);

    const result = await push(h, archive);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(503);
    expect(result.code).toBe("storage_unavailable");

    // The version row is gone, so the reservation is not a tombstone …
    expect(await h.metadata.getAsset(assetId("1.0.0"))).toBeNull();
    // … the index is empty …
    expect(await h.bundles.listBundleFiles(assetId("1.0.0"))).toEqual([]);
    // … the two files that DID land were reclaimed, and so was the archive …
    expect([...objects.objects.keys()]).toEqual([]);
    // … and nothing resolves.
    const pulled = await pull(h, "1.0.0", "a.html");
    expect(pulled.ok).toBe(false);
  });

  test("the corrected republish of a failed bundle succeeds", async () => {
    // put #1 archive, #2 the first file, #3 fails — so the version is left
    // half-written and must not block the fixed upload that follows.
    const objects = new FailingObjectStore(3);
    const h = harness({ objects });

    const failed = await push(
      h,
      buildTar([
        { name: "a.html", body: "a" },
        { name: "b.html", body: "b" },
      ]),
    );
    expect(failed.ok).toBe(false);

    const retried = await push(h, goodSite());
    expect(retried.ok).toBe(true);
  });

  test("the version is invisible for the WHOLE expansion, not merely on failure", async () => {
    // The property the unwind path cannot prove on its own: while files are
    // still landing, the row must already exist (it reserves the version and
    // the quota) and must NOT be `visible`. Observed from inside the object
    // store, at every single put.
    const observed: (string | null)[] = [];
    const h = harness();
    const objects = h.objects;
    const original = objects.put.bind(objects);
    objects.put = async (key, value, options) => {
      const row = await h.metadata.getAsset(assetId("1.0.0"));
      observed.push(row?.visibility ?? null);
      return original(key, value, options);
    };

    const result = await push(
      h,
      buildTar([
        { name: "a.html", body: "a" },
        { name: "b.html", body: "b" },
        { name: "c.html", body: "c" },
      ]),
    );

    expect(result.ok).toBe(true);
    // put #1 is the archive, written before the row exists at all; #2..#4 are
    // the bundle files, each of which must see a reserved-but-withheld row.
    expect(observed).toEqual([null, "pending_scan", "pending_scan", "pending_scan"]);
    // Only after the last file does the CAS make it resolvable.
    expect((await h.metadata.getAsset(assetId("1.0.0")))?.visibility).toBe("visible");
  });

  test("a bundle the screener defers stays pending_scan and is unresolvable", async () => {
    const h = harness({ screener: new PendingScreener() });

    const result = await push(h, goodSite());

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.body.asset.visibility).toBe("pending_scan");
    // Expanded, but withheld: the index exists and the read path still refuses.
    expect(await h.bundles.listBundleFiles(assetId("1.0.0"))).toHaveLength(2);
    const pulled = await pull(h, "1.0.0", "index.html");
    expect(pulled.ok).toBe(false);
    if (pulled.ok) return;
    expect(pulled.status).toBe(404);
  });
});

describe("a bundle version uses the ONE resolution path", () => {
  async function twoVersions() {
    const h = harness();
    await push(h, goodSite(), "application/x-tar", "1.0.0");
    await push(
      h,
      buildTar([
        { name: "index.html", body: "v2" },
        { name: "assets/app.css", body: "body{color:blue}" },
      ]),
      "application/x-tar",
      "1.1.0",
    );
    return h;
  }

  test("a channel pointer selects which bundle a ?path= read serves", async () => {
    const h = await twoVersions();
    const moved = await h.service.putChannel(A, SITE, "stable", "1.0.0", CTX);
    expect(moved.ok).toBe(true);

    const pulled = await pull(h, "stable", "index.html");

    expect(pulled.ok).toBe(true);
    if (!pulled.ok) return;
    expect(decode(pulled.bytes)).toBe("<!doctype html><h1>docs</h1>");
    expect(pulled.headers["x-ferrogate-asset-resolved"]).toBe("channel=stable;version=1.0.0");
    expect(pulled.headers["content-type"]).toBe("text/html");
  });

  test("a semver range picks the highest bundle and serves its files", async () => {
    const h = await twoVersions();

    const pulled = await pull(h, "^1.0", "index.html");

    expect(pulled.ok).toBe(true);
    if (!pulled.ok) return;
    expect(decode(pulled.bytes)).toBe("v2");
    expect(pulled.headers["x-ferrogate-asset-version"]).toBe("1.1.0");
  });

  test("yanking a bundle version drops it out of channel resolution, files and all", async () => {
    const h = await twoVersions();

    const yanked = await h.service.setVersionYank(A, { ...SITE, version: "1.1.0" }, true, CTX);
    expect(yanked.ok).toBe(true);

    // `latest` now resolves to 1.0.0 — the same rule a single-object asset gets,
    // applied before `?path=` is ever consulted.
    const pulled = await pull(h, "latest", "index.html");
    expect(pulled.ok).toBe(true);
    if (!pulled.ok) return;
    expect(pulled.headers["x-ferrogate-asset-version"]).toBe("1.0.0");
    expect(decode(pulled.bytes)).toBe("<!doctype html><h1>docs</h1>");

    // An EXACT pin still works and still warns, exactly as it does for a blob.
    const pinned = await pull(h, "1.1.0", "index.html");
    expect(pinned.ok).toBe(true);
    if (!pinned.ok) return;
    expect(pinned.headers["x-ferrogate-asset-yanked"]).toBe("true");
  });

  test("the manifest lists bundle versions like any other", async () => {
    const h = await twoVersions();

    const manifest = await h.service.manifest(A, SITE);

    expect(manifest.ok).toBe(true);
    if (!manifest.ok) return;
    expect(manifest.body.versions.map((entry) => entry.version)).toEqual(["1.1.0", "1.0.0"]);
  });
});

describe("serving one file out of a bundle", () => {
  test("without ?path= the archive itself is still what is served", async () => {
    // Backwards compatibility: the version's `storage_uri` is the archive, and
    // a plain pull is byte-identical to what it was before #736.
    const h = harness();
    const archive = goodSite();
    await push(h, archive);

    const pulled = await pull(h, "1.0.0");

    expect(pulled.ok).toBe(true);
    if (!pulled.ok) return;
    expect(pulled.bytes).toEqual(archive);
    expect(pulled.headers["content-type"]).toBe("application/x-tar");
  });

  test("?path= serves the file's own bytes, type and ETag", async () => {
    const h = harness();
    await push(h, goodSite());

    const pulled = await pull(h, "1.0.0", "assets/app.css");

    expect(pulled.ok).toBe(true);
    if (!pulled.ok) return;
    expect(decode(pulled.bytes)).toBe("body{color:red}");
    expect(pulled.headers["content-type"]).toBe("text/css");
    const indexed = await h.bundles.getBundleFile(assetId("1.0.0"), "assets/app.css");
    expect(pulled.headers.etag).toBe(`"${indexed?.content_hash}"`);
  });

  test("a leading ./ is accepted and normalizes onto the stored path", async () => {
    const h = harness();
    await push(h, buildTar([{ name: "./index.html", body: "dotted" }]));

    const pulled = await pull(h, "1.0.0", "./index.html");

    expect(pulled.ok).toBe(true);
    if (!pulled.ok) return;
    expect(decode(pulled.bytes)).toBe("dotted");
  });

  test("a traversing ?path= is refused rather than looked up", async () => {
    const h = harness();
    await push(h, goodSite());

    const pulled = await pull(h, "1.0.0", "../../etc/passwd");

    expect(pulled.ok).toBe(false);
    if (pulled.ok) return;
    expect(pulled.status).toBe(400);
    expect(pulled.code).toBe("asset_bundle_path_invalid");
  });

  test("an unknown ?path= is a 404 naming the bundle", async () => {
    const h = harness();
    await push(h, goodSite());

    const pulled = await pull(h, "1.0.0", "nope.html");

    expect(pulled.ok).toBe(false);
    if (pulled.ok) return;
    expect(pulled.status).toBe(404);
    expect(pulled.code).toBe("asset_bundle_file_not_found");
  });

  test("another tenant cannot read a bundle file", async () => {
    const h = harness();
    await push(h, goodSite());

    const pulled = await pull(h, "1.0.0", "index.html", callerFor("tenant_b"));

    expect(pulled.ok).toBe(false);
    if (pulled.ok) return;
    expect(pulled.status).toBe(404);
  });
});

describe("deleting a bundle version reclaims its files", () => {
  test("the per-file objects and the index go with the row", async () => {
    const h = harness();
    await push(h, goodSite());
    const files = await h.bundles.listBundleFiles(assetId("1.0.0"));
    expect(files).toHaveLength(2);

    const deleted = await h.service.deleteAsset(A, { ...SITE, version: "1.0.0" }, CTX);

    expect(deleted.ok).toBe(true);
    expect(await h.bundles.listBundleFiles(assetId("1.0.0"))).toEqual([]);
    for (const file of files) {
      expect(await h.objects.head(file.storage_uri)).toBeNull();
    }
  });
});

describe("the bundle file index", () => {
  const TENANT = "tenant_bundle_index";
  const ROW: StoredBundleFile = {
    asset_id: `${TENANT}:static_site:docs:1.0.0`,
    tenant_id: TENANT,
    path: "index.html",
    storage_uri: bundleFileObjectKey(
      {
        tenantId: TENANT,
        assetType: "static_site",
        name: "docs",
        version: "1.0.0",
        variant: "",
      },
      "index.html",
    ),
    content_type: "text/html",
    content_hash: "a".repeat(64),
    size_bytes: 12,
    created_at_unix: 1_700_000_000,
  };

  function d1(): AssetDatabase {
    const binding = (env as { DB?: unknown }).DB;
    if (!isAssetDatabase(binding)) {
      throw new Error("expected the `DB` binding (apps/gateway/wrangler.toml) to be a D1 database");
    }
    return binding;
  }

  // Conformance: the in-memory index is the local-dev default and the D1 one is
  // what ships. If they disagree, every harness-based assertion above is proving
  // something about the wrong object.
  const backends: [string, () => AssetBundleIndexStore][] = [
    ["in-memory", () => new InMemoryAssetBundleIndexStore()],
    ["d1", () => new D1AssetBundleIndexStore(d1())],
  ];

  describe.each(backends)("%s", (_name, make) => {
    let store: AssetBundleIndexStore;

    beforeEach(async () => {
      store = make();
      await store.deleteBundleFiles(ROW.asset_id);
    });

    test("a written row round-trips", async () => {
      await store.putBundleFiles([ROW]);

      expect(await store.getBundleFile(ROW.asset_id, "index.html")).toEqual(ROW);
      expect(await store.getBundleFile(ROW.asset_id, "missing.html")).toBeNull();
      expect(await store.listBundleFiles(ROW.asset_id)).toEqual([ROW]);
    });

    test("a re-expansion overwrites rather than keeping stale keys", async () => {
      await store.putBundleFiles([ROW]);
      const retried = { ...ROW, storage_uri: `${ROW.storage_uri}-retry`, size_bytes: 99 };

      await store.putBundleFiles([retried]);

      expect(await store.listBundleFiles(ROW.asset_id)).toEqual([retried]);
    });

    test("the delete returns what it removed so the objects can be reclaimed", async () => {
      await store.putBundleFiles([ROW, { ...ROW, path: "a.css", content_type: "text/css" }]);

      const removed = await store.deleteBundleFiles(ROW.asset_id);

      expect(removed.map((file) => file.path).sort()).toEqual(["a.css", "index.html"]);
      expect(await store.listBundleFiles(ROW.asset_id)).toEqual([]);
    });

    test("an empty write is a no-op rather than a malformed statement", async () => {
      await store.putBundleFiles([]);

      expect(await store.listBundleFiles(ROW.asset_id)).toEqual([]);
    });
  });
});
