/**
 * The 18 asset operations driven over real HTTP through the real gateway app:
 * the contract-driven router, the contract-driven auth middleware, and the
 * uniform error envelope, with only the object store and the presigner
 * substituted (no bucket exists offline).
 *
 * `SELF.fetch` is not used here on purpose: these cases need a substituted
 * object store, presigner and entitlement table, which the deployed Worker's
 * bindings do not provide offline. The suite therefore assembles the same app
 * the shell assembles — `createGatewayApp({ modules: [assetRouteModule(...)] })`
 * — and drives it with `app.request`. That the SHELL really mounts this module
 * is proved separately, over `SELF.fetch`, in `test/contract.test.ts`.
 */
import { describe, expect, test } from "vitest";
import { ORDERED_ASSET_OPERATION_IDS, assetRouteModule } from "../../src/assets/handlers.js";
import { sha256Hex } from "../../src/assets/hash.js";
import { stagingObjectKey } from "../../src/assets/keys.js";
import { ASSET_OPERATION_IDS, createGatewayApp } from "../../src/routes/index.js";
import { FakePresigner, bytes, harness, stage } from "./helpers.js";

/**
 * Read a response body as text WITHOUT `Response.text()`, which warns in
 * `workerd` for a non-text `content-type` — asset bodies are
 * `application/octet-stream` by design.
 */
async function textOf(response: Response): Promise<string> {
  return new TextDecoder().decode(await response.arrayBuffer());
}

/**
 * Two tenants, three credentials. `fg_assets_ro` is scoped `assets.read` only,
 * so the middleware — not this module — is what turns a write into a 403.
 */
const ENV = {
  GATEWAY_NATIVE_API_KEYS: JSON.stringify([
    {
      key: "fg_assets_rw",
      id: "key_rw",
      tenant_id: "tenant_a",
      scopes: ["assets.read", "assets.write"],
    },
    { key: "fg_assets_ro", id: "key_ro", tenant_id: "tenant_a", scopes: ["assets.read"] },
    {
      key: "fg_tenant_b",
      id: "key_b",
      tenant_id: "tenant_b",
      scopes: ["assets.read", "assets.write"],
    },
    // Tenant C authenticates and is fully scoped, but hosts nothing.
    {
      key: "fg_tenant_c",
      id: "key_c",
      tenant_id: "tenant_c",
      scopes: ["assets.read", "assets.write"],
    },
  ]),
  ASSET_ENTITLEMENTS: JSON.stringify({
    tenant_a: { asset_hosting_enabled: true },
    tenant_b: { asset_hosting_enabled: true },
    tenant_c: { asset_hosting_enabled: false },
  }),
};

function gateway(options: { presign?: boolean } = {}) {
  const h = harness({ limits: { presignEnabled: options.presign ?? false } });
  const presigner = new FakePresigner();
  const { app, router } = createGatewayApp({
    modules: [
      assetRouteModule({
        deps: {
          objects: h.objects,
          metadata: h.metadata,
          audit: h.audit,
          presigner,
          limits: { presignEnabled: options.presign ?? false, presignTtlSeconds: 900 },
        },
      }),
    ],
  });
  const call = (
    path: string,
    init: RequestInit & { token?: string | null } = {},
  ): Promise<Response> => {
    const { token = "fg_assets_rw", headers, ...rest } = init;
    const merged = new Headers(headers);
    if (token !== null) merged.set("authorization", `Bearer ${token}`);
    return Promise.resolve(
      app.request(`https://gw.test${path}`, { ...rest, headers: merged }, ENV),
    );
  };
  // `presigner` after the spread: the harness carries its own, and the app is
  // wired with THIS one, so the test must observe the one it wired.
  return { app, router, call, ...h, presigner };
}

const PAYLOAD = "the-artifact-bytes";

async function publish(
  call: ReturnType<typeof gateway>["call"],
  version = "1.0.0",
  body = PAYLOAD,
  query = "",
): Promise<Response> {
  return call(`/v1/assets/cli/ferrogate/${version}${query}`, {
    method: "PUT",
    body,
    headers: { "content-type": "application/octet-stream" },
  });
}

// ---------------------------------------------------------------------------

describe("contract wiring", () => {
  test("the module mounts exactly the 18 contract asset operations", () => {
    const { router } = gateway();
    expect([...ORDERED_ASSET_OPERATION_IDS].sort()).toEqual([...ASSET_OPERATION_IDS].sort());
    const registered = router.registeredOperationIds();
    for (const id of ASSET_OPERATION_IDS) expect(registered).toContain(id);
  });
});

describe("auth is the middleware's job, not this module's", () => {
  test("no credential is 401 in the uniform envelope", async () => {
    const { call } = gateway();
    const response = await call("/v1/assets", { token: null });
    expect(response.status).toBe(401);
    const body = (await response.json()) as { error: { code: string; type: string } };
    expect(body.error.type).toBe("ferrogate_error");
    expect(body.error.code).toBe("missing_api_key");
    expect(response.headers.get("www-authenticate")).toContain("Bearer");
  });

  test("an under-scoped credential is 403 on a write, 200 on a read", async () => {
    const { call } = gateway();
    await publish(call);
    expect((await call("/v1/assets", { token: "fg_assets_ro" })).status).toBe(200);
    const denied = await publish(
      (path, init) => call(path, { ...init, token: "fg_assets_ro" }),
      "2.0.0",
    );
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as { error: { code: string } }).error.code).toBe("scope_denied");
  });

  test("every response carries the request id", async () => {
    const { call } = gateway();
    const response = await call("/v1/assets", { headers: { "x-request-id": "req_abc" } });
    expect(response.headers.get("x-request-id")).toBe("req_abc");
    expect(response.headers.get("x-trace-id")).toBe("req_abc");
  });
});

describe("push / pull over HTTP", () => {
  test("a push then a pull round-trips the bytes with caching validators", async () => {
    const { call } = gateway();
    const pushed = await publish(call);
    expect(pushed.status).toBe(200);
    expect(((await pushed.json()) as { object: string }).object).toBe("asset");

    const pulled = await call("/v1/assets/cli/ferrogate/1.0.0");
    expect(pulled.status).toBe(200);
    expect(await textOf(pulled)).toBe(PAYLOAD);
    expect(pulled.headers.get("etag")).toBe(`"${await sha256Hex(bytes(PAYLOAD))}"`);
    expect(pulled.headers.get("cache-control")).toBe("private, max-age=0, must-revalidate");
    expect(pulled.headers.get("x-ferrogate-asset-resolved")).toBe("exact=1.0.0");
  });

  test("a conditional re-pull short-circuits to 304 with no body", async () => {
    const { call } = gateway();
    await publish(call);
    const first = await call("/v1/assets/cli/ferrogate/1.0.0");
    const etag = first.headers.get("etag") as string;
    const revalidated = await call("/v1/assets/cli/ferrogate/1.0.0", {
      headers: { "if-none-match": etag },
    });
    expect(revalidated.status).toBe(304);
    expect(await textOf(revalidated)).toBe("");
  });

  test("a republish is 409 in the envelope and does not change the bytes", async () => {
    const { call } = gateway();
    await publish(call, "1.0.0", "first");
    const again = await publish(call, "1.0.0", "second");
    expect(again.status).toBe(409);
    expect(((await again.json()) as { error: { code: string } }).error.code).toBe(
      "asset_version_immutable",
    );
    expect(await textOf(await call("/v1/assets/cli/ferrogate/1.0.0"))).toBe("first");
  });

  test("an unresolvable reference is 404", async () => {
    const { call } = gateway();
    await publish(call);
    const missing = await call("/v1/assets/cli/ferrogate/9.9.9");
    expect(missing.status).toBe(404);
    expect(((await missing.json()) as { error: { code: string } }).error.code).toBe(
      "asset_not_found",
    );
  });

  test("a tenant without the hosting entitlement is 403 on a push", async () => {
    const { call } = gateway();
    const denied = await call("/v1/assets/cli/ferrogate/1.0.0", {
      method: "PUT",
      body: PAYLOAD,
      token: "fg_tenant_c",
    });
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as { error: { code: string } }).error.code).toBe(
      "asset_hosting_disabled",
    );
  });
});

describe("route precedence — reserved literals beat the generic arms", () => {
  test("GET /v1/assets/withheld is the withheld view, not a family listing", async () => {
    const { call } = gateway();
    // An EICAR push is stored but withheld, so the two views disagree — which
    // is what makes this assertion able to tell them apart at all.
    await publish(
      call,
      "1.0.0",
      "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    );
    const withheld = await call("/v1/assets/withheld");
    expect(withheld.status).toBe(200);
    const body = (await withheld.json()) as {
      object: string;
      data: { version: string; visibility: string; screening_evidence?: string }[];
    };
    expect(body.object).toBe("list");
    expect(body.data).toHaveLength(1);
    expect(body.data[0]?.visibility).toBe("quarantined");
    // If `:asset_type` had won the match, this would be an empty family listing.
    expect(body.data[0]?.screening_evidence).toContain("eicar");
  });

  test("GET /v1/assets/storage/summary is the operator view", async () => {
    const { call } = gateway();
    await publish(call);
    const response = await call("/v1/assets/storage/summary");
    expect(response.status).toBe(200);
    const body = (await response.json()) as { object: string; used_bytes: number };
    expect(body.object).toBe("asset_storage_summary");
    expect(body.used_bytes).toBe(PAYLOAD.length);
  });

  test("GET /v1/assets/{type}/{name}/manifest is the manifest, not a version pull", async () => {
    const { call } = gateway();
    await publish(call, "1.0.0");
    await publish(call, "2.0.0");
    const response = await call("/v1/assets/cli/ferrogate/manifest");
    expect(response.status).toBe(200);
    const body = (await response.json()) as { object: string; versions: { version: string }[] };
    expect(body.object).toBe("asset_manifest");
    expect(body.versions.map((entry) => entry.version)).toEqual(["2.0.0", "1.0.0"]);
  });

  test("DELETE .../channels/{channel} is a channel delete, not an unyank", async () => {
    const { call } = gateway();
    await publish(call, "1.0.0");
    expect(
      (await call("/v1/assets/cli/ferrogate/channels/yank?version=1.0.0", { method: "PUT" }))
        .status,
    ).toBe(200);
    const deleted = await call("/v1/assets/cli/ferrogate/channels/yank", { method: "DELETE" });
    expect(deleted.status).toBe(200);
    expect(((await deleted.json()) as { object: string }).object).toBe("asset_channel");
  });
});

describe("channels, yank and visibility over HTTP", () => {
  test("a channel move resolves a pull by channel name", async () => {
    const { call } = gateway();
    await publish(call, "1.0.0", "v1");
    await publish(call, "2.0.0", "v2");
    const moved = await call("/v1/assets/cli/ferrogate/channels/stable?version=1.0.0", {
      method: "PUT",
    });
    expect(moved.status).toBe(200);
    const pulled = await call("/v1/assets/cli/ferrogate/stable");
    expect(await textOf(pulled)).toBe("v1");
    expect(pulled.headers.get("x-ferrogate-asset-resolved")).toBe("channel=stable;version=1.0.0");

    const listed = await call("/v1/assets/cli/ferrogate/channels");
    const body = (await listed.json()) as { data: { channel: string; version: string }[] };
    expect(body.data).toEqual([
      { channel: "stable", version: "1.0.0", updated_at_unix: expect.any(Number) },
    ]);
  });

  test("a channel move without ?version= is 400", async () => {
    const { call } = gateway();
    await publish(call);
    const response = await call("/v1/assets/cli/ferrogate/channels/stable", { method: "PUT" });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "channel_target_required",
    );
  });

  test("yank then unyank flips channel resolution while the exact pin survives", async () => {
    const { call } = gateway();
    await publish(call, "1.0.0", "v1");
    await publish(call, "2.0.0", "v2");

    expect((await call("/v1/assets/cli/ferrogate/2.0.0/yank", { method: "POST" })).status).toBe(
      200,
    );
    expect(await textOf(await call("/v1/assets/cli/ferrogate/latest"))).toBe("v1");
    const exact = await call("/v1/assets/cli/ferrogate/2.0.0");
    expect(exact.status).toBe(200);
    expect(await textOf(exact)).toBe("v2");
    expect(exact.headers.get("x-ferrogate-asset-yanked")).toBe("true");

    expect((await call("/v1/assets/cli/ferrogate/2.0.0/yank", { method: "DELETE" })).status).toBe(
      200,
    );
    expect(await textOf(await call("/v1/assets/cli/ferrogate/latest"))).toBe("v2");
  });

  test("a visibility promotion with an unknown verdict is 400", async () => {
    const { call } = gateway();
    await publish(call);
    const response = await call("/v1/assets/cli/ferrogate/1.0.0/visibility", {
      method: "POST",
      body: JSON.stringify({ scan_outcome: "maybe", evidence: "hunch" }),
      headers: { "content-type": "application/json" },
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "invalid_scan_outcome",
    );
  });

  test("a malformed control body is 400, not a 500", async () => {
    const { call } = gateway();
    const response = await call("/v1/assets/cli/ferrogate/1.0.0/visibility", {
      method: "POST",
      body: "{not json",
      headers: { "content-type": "application/json" },
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "invalid_request_body",
    );
  });

  test("an unknown field in a presign control body is rejected, not ignored", async () => {
    const { call } = gateway({ presign: true });
    const response = await call("/v1/assets/presign/upload/cli/ferrogate/1.0.0", {
      method: "POST",
      body: JSON.stringify({ size_bytes: 10, sha256: "a".repeat(64), skip_scan: true }),
      headers: { "content-type": "application/json" },
    });
    // A typo'd screening field must fail loudly rather than silently skipping
    // a control (Rust `deny_unknown_fields`).
    expect(response.status).toBe(400);
  });
});

describe("cross-tenant isolation over HTTP", () => {
  test("tenant B cannot list, pull, or presign tenant A's asset", async () => {
    const { call } = gateway({ presign: true });
    await publish(call);

    const listed = await call("/v1/assets", { token: "fg_tenant_b" });
    expect(((await listed.json()) as { data: unknown[] }).data).toHaveLength(0);

    expect((await call("/v1/assets/cli/ferrogate/1.0.0", { token: "fg_tenant_b" })).status).toBe(
      404,
    );
    expect((await call("/v1/assets/cli/ferrogate/manifest", { token: "fg_tenant_b" })).status).toBe(
      404,
    );
    expect(
      (await call("/v1/assets/presign/download/cli/ferrogate/1.0.0", { token: "fg_tenant_b" }))
        .status,
    ).toBe(404);
  });

  test("tenant B may publish the same coordinates without touching A's bytes", async () => {
    const { call } = gateway();
    await publish(call, "1.0.0", "a-bytes");
    const pushed = await call("/v1/assets/cli/ferrogate/1.0.0", {
      method: "PUT",
      body: "b-bytes",
      token: "fg_tenant_b",
    });
    expect(pushed.status).toBe(200);
    expect(await textOf(await call("/v1/assets/cli/ferrogate/1.0.0"))).toBe("a-bytes");
    expect(
      await textOf(await call("/v1/assets/cli/ferrogate/1.0.0", { token: "fg_tenant_b" })),
    ).toBe("b-bytes");
  });
});

describe("presign family over HTTP", () => {
  test("with no bucket configured the whole family is 503", async () => {
    const { call } = gateway({ presign: false });
    const response = await call("/v1/assets/presign/upload/cli/ferrogate/1.0.0", {
      method: "POST",
      body: JSON.stringify({ size_bytes: 10, sha256: "a".repeat(64) }),
      headers: { "content-type": "application/json" },
    });
    expect(response.status).toBe(503);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "asset_bucket_unavailable",
    );
  });

  test("intent → direct PUT → commit → download URL", async () => {
    const { call, objects } = gateway({ presign: true });
    const sha256 = await sha256Hex(bytes(PAYLOAD));
    const size = bytes(PAYLOAD).byteLength;

    const intent = await call("/v1/assets/presign/upload/cli/ferrogate/4.0.0", {
      method: "POST",
      body: JSON.stringify({ size_bytes: size, sha256 }),
      headers: { "content-type": "application/json" },
    });
    expect(intent.status).toBe(200);
    const issued = (await intent.json()) as {
      upload_id: string;
      upload_url: string;
      required_headers: Record<string, string>;
      upload_protocol: string;
    };
    expect(issued.upload_protocol).toBe("single_put");
    expect(issued.required_headers["x-amz-content-sha256"]).toBe(sha256);

    // The client's direct PUT. Its destination is server-derived, so the test
    // can only reach it by deriving the same key the gateway did.
    await stage(
      objects,
      stagingObjectKey(
        {
          tenantId: "tenant_a",
          assetType: "cli",
          name: "ferrogate",
          version: "4.0.0",
          variant: "",
        },
        issued.upload_id,
        size,
        sha256,
      ),
      bytes(PAYLOAD),
    );

    const commit = await call("/v1/assets/presign/commit/cli/ferrogate/4.0.0", {
      method: "POST",
      body: JSON.stringify({ upload_id: issued.upload_id, size_bytes: size, sha256 }),
      headers: { "content-type": "application/json" },
    });
    expect(commit.status).toBe(200);

    const download = await call("/v1/assets/presign/download/cli/ferrogate/4.0.0");
    expect(download.status).toBe(200);
    const url = (await download.json()) as { download_url: string; sha256: string };
    expect(url.sha256).toBe(sha256);
    expect(url.download_url).toContain("assets/v1/t/tenant_a/");

    // The committed object is also reachable through the ordinary pull.
    expect(await textOf(await call("/v1/assets/cli/ferrogate/4.0.0"))).toBe(PAYLOAD);
  });

  test("an abort with nothing staged reports the tri-state honestly", async () => {
    const { call } = gateway({ presign: true });
    const sha256 = await sha256Hex(bytes(PAYLOAD));
    const intent = await call("/v1/assets/presign/upload/cli/ferrogate/4.0.0", {
      method: "POST",
      body: JSON.stringify({ size_bytes: bytes(PAYLOAD).byteLength, sha256 }),
      headers: { "content-type": "application/json" },
    });
    const { upload_id: uploadId } = (await intent.json()) as { upload_id: string };

    const abort = await call("/v1/assets/presign/abort/cli/ferrogate/4.0.0", {
      method: "POST",
      body: JSON.stringify({
        upload_id: uploadId,
        size_bytes: bytes(PAYLOAD).byteLength,
        sha256,
        reason: "bucket_rejected",
      }),
      headers: { "content-type": "application/json" },
    });
    expect(abort.status).toBe(200);
    expect(await abort.json()).toMatchObject({
      object: "asset_upload_abort",
      staging_object_removed: false,
      staging_reclamation: "not_staged",
      outcome: "rejected_bucket",
    });
  });

  test("a client-named upload id is rejected by shape", async () => {
    const { call } = gateway({ presign: true });
    const response = await call("/v1/assets/presign/commit/cli/ferrogate/4.0.0", {
      method: "POST",
      body: JSON.stringify({
        upload_id: "my-own-upload",
        size_bytes: 4,
        sha256: "a".repeat(64),
      }),
      headers: { "content-type": "application/json" },
    });
    expect(response.status).toBe(400);
  });
});
