/**
 * OpenAI-compatible Files API coverage over the same contract-driven gateway
 * app and asset ports used by the `/v1/assets` route suite.
 */
import { describe, expect, test } from "vitest";

import { assetRouteModule } from "../src/assets/handlers.js";
import { createGatewayApp } from "../src/routes/index.js";
import { harness } from "./assets/helpers.js";

const ENV = {
  GATEWAY_NATIVE_API_KEYS: JSON.stringify([
    {
      key: "fg_files_rw",
      id: "key_files_rw",
      tenant_id: "tenant_files",
      scopes: ["assets.read", "assets.write"],
    },
    {
      key: "fg_files_ro",
      id: "key_files_ro",
      tenant_id: "tenant_files",
      scopes: ["assets.read"],
    },
    {
      key: "fg_files_no_host",
      id: "key_files_no_host",
      tenant_id: "tenant_files_no_host",
      scopes: ["assets.read", "assets.write"],
    },
    {
      key: "fg_files_other",
      id: "key_files_other",
      tenant_id: "tenant_files_other",
      scopes: ["assets.read", "assets.write"],
    },
    {
      key: "fg_files_quota",
      id: "key_files_quota",
      tenant_id: "tenant_files_quota",
      scopes: ["assets.read", "assets.write"],
    },
  ]),
  ASSET_ENTITLEMENTS: JSON.stringify({
    tenant_files: { asset_hosting_enabled: true },
    tenant_files_no_host: { asset_hosting_enabled: false },
    tenant_files_other: { asset_hosting_enabled: true },
    tenant_files_quota: { asset_hosting_enabled: true, asset_storage_quota_bytes: 5 },
  }),
};

function fileForm(
  contents = "hello files",
  filename = "notes.txt",
  purpose = "assistants",
): FormData {
  const form = new FormData();
  form.set("purpose", purpose);
  form.set("file", new Blob([contents], { type: "text/plain" }), filename);
  return form;
}

function gateway() {
  const h = harness();
  const { app } = createGatewayApp({
    modules: [
      assetRouteModule({
        deps: {
          objects: h.objects,
          metadata: h.metadata,
          audit: h.audit,
          presigner: h.presigner,
          limits: { presignEnabled: true, presignTtlSeconds: 900 },
        },
      }),
    ],
  });

  const call = (
    path: string,
    init: RequestInit & { token?: string | null } = {},
  ): Promise<Response> => {
    const { token = "fg_files_rw", headers, ...rest } = init;
    const merged = new Headers(headers);
    if (token !== null) merged.set("authorization", `Bearer ${token}`);
    return Promise.resolve(app.request(`https://gw.test${path}`, { ...rest, headers: merged }, ENV));
  };

  return { call };
}

interface FileObject {
  id: string;
  object: string;
  bytes: number;
  created_at: number;
  filename: string;
  purpose: string;
  status: string;
  status_details: string | null;
}

describe("OpenAI-compatible Files API", () => {
  test("uploads, retrieves, lists, reads content, and deletes an asset-backed file", async () => {
    const { call } = gateway();

    const created = await call("/v1/files", {
      method: "POST",
      body: fileForm(),
    });
    expect(created.status).toBe(200);
    const file = (await created.json()) as FileObject;
    expect(file).toMatchObject({
      object: "file",
      bytes: 11,
      filename: "notes.txt",
      purpose: "assistants",
      status: "processed",
      status_details: null,
      created_at: expect.any(Number),
    });
    expect(file.id).toMatch(/^file-/);

    const listed = await call("/v1/files?purpose=assistants");
    expect(listed.status).toBe(200);
    expect(await listed.json()).toMatchObject({
      object: "list",
      data: [expect.objectContaining({ id: file.id, filename: "notes.txt" })],
      has_more: false,
    });

    const retrieved = await call(`/v1/files/${file.id}`);
    expect(retrieved.status).toBe(200);
    expect(await retrieved.json()).toEqual(file);

    const content = await call(`/v1/files/${file.id}/content`);
    expect(content.status).toBe(200);
    expect(content.headers.get("content-type")).toBe("text/plain");
    expect(await content.text()).toBe("hello files");

    const deleted = await call(`/v1/files/${file.id}`, { method: "DELETE" });
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({ id: file.id, object: "file", deleted: true });

    const missing = await call(`/v1/files/${file.id}`);
    expect(missing.status).toBe(404);
  });

  test("preserves asset scope and hosting gates for file writes", async () => {
    const { call } = gateway();

    const missingWriteScope = await call("/v1/files", {
      method: "POST",
      token: "fg_files_ro",
      body: fileForm(),
    });
    expect(missingWriteScope.status).toBe(403);
    expect((await missingWriteScope.json() as { error: { code: string } }).error.code).toBe(
      "scope_denied",
    );

    const missingHosting = await call("/v1/files", {
      method: "POST",
      token: "fg_files_no_host",
      body: fileForm(),
    });
    expect(missingHosting.status).toBe(403);
    expect((await missingHosting.json() as { error: { code: string } }).error.code).toBe(
      "asset_hosting_disabled",
    );
  });

  test("keeps file content and deletion tenant-scoped", async () => {
    const { call } = gateway();

    const created = await call("/v1/files", {
      method: "POST",
      body: fileForm("tenant-owned content"),
    });
    expect(created.status).toBe(200);
    const file = (await created.json()) as FileObject;

    const otherContent = await call(`/v1/files/${file.id}/content`, {
      token: "fg_files_other",
    });
    expect(otherContent.status).toBe(404);

    const otherDelete = await call(`/v1/files/${file.id}`, {
      method: "DELETE",
      token: "fg_files_other",
    });
    expect(otherDelete.status).toBe(404);

    const ownerContent = await call(`/v1/files/${file.id}/content`);
    expect(ownerContent.status).toBe(200);
    expect(await ownerContent.text()).toBe("tenant-owned content");
  });

  test("preserves asset quota and screening state", async () => {
    const { call } = gateway();

    const overQuota = await call("/v1/files", {
      method: "POST",
      token: "fg_files_quota",
      body: fileForm("too large"),
    });
    expect(overQuota.status).toBe(403);
    expect((await overQuota.json() as { error: { code: string } }).error.code).toBe(
      "asset_storage_quota_exceeded",
    );

    const screened = await call("/v1/files", {
      method: "POST",
      body: fileForm(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        "infected.txt",
      ),
    });
    expect(screened.status).toBe(202);
    const file = (await screened.json()) as FileObject;
    expect(file.status).toBe("error");

    const content = await call(`/v1/files/${file.id}/content`);
    expect(content.status).toBe(404);
  });
});
