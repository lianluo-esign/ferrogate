import { MemoryBatchStore } from "@ferrogate/storage";
/** Focused `/v1/batches` lifecycle and isolation coverage for slice 1. */
import { describe, expect, test } from "vitest";
import { assetRouteModule, buildAssetService } from "../src/assets/index.js";
import { InMemoryAssetMetadataStore } from "../src/assets/ports.js";
import { batchRouteModule } from "../src/batch/index.js";
import { createGatewayApp } from "../src/routes/index.js";

const START_UNIX = 1_700_000_000;

const ENV = {
  GATEWAY_NATIVE_API_KEYS: JSON.stringify([
    {
      key: "fg_batch_a",
      id: "key_batch_a",
      tenant_id: "tenant_batch_a",
      scopes: ["assets.read", "assets.write"],
    },
    {
      key: "fg_batch_b",
      id: "key_batch_b",
      tenant_id: "tenant_batch_b",
      scopes: ["assets.read", "assets.write"],
    },
  ]),
  ASSET_ENTITLEMENTS: JSON.stringify({
    tenant_batch_a: { asset_hosting_enabled: true },
    tenant_batch_b: { asset_hosting_enabled: true },
  }),
};

interface BatchResponse {
  id: string;
  object: string;
  endpoint: string;
  errors: null;
  input_file_id: string;
  completion_window: string;
  status: string;
  output_file_id: string | null;
  error_file_id: string | null;
  created_at: number;
  in_progress_at: number | null;
  expires_at: number;
  finalizing_at: number | null;
  completed_at: number | null;
  failed_at: number | null;
  expired_at: number | null;
  cancelling_at: number | null;
  cancelled_at: number | null;
  request_counts: { total: number; completed: number; failed: number };
  metadata: Record<string, string>;
}

function fileForm(contents = "batch input", filename = "batch.jsonl"): FormData {
  const form = new FormData();
  form.set("purpose", "batch");
  form.set("file", new Blob([contents], { type: "application/jsonl" }), filename);
  return form;
}

function gateway() {
  let clock = START_UNIX;
  const metadata = new InMemoryAssetMetadataStore();
  const files = buildAssetService({ metadata, now: () => clock });
  const batches = new MemoryBatchStore();
  const { app, router } = createGatewayApp({
    modules: [
      assetRouteModule({ service: files }),
      batchRouteModule({ store: batches, fileService: files, now: () => clock }),
    ],
  });

  const call = (
    path: string,
    init: RequestInit & { token?: string | null } = {},
  ): Promise<Response> => {
    const { token = "fg_batch_a", headers, ...rest } = init;
    const merged = new Headers(headers);
    if (token !== null) merged.set("authorization", `Bearer ${token}`);
    return Promise.resolve(
      app.request(`https://gw.test${path}`, { ...rest, headers: merged }, ENV),
    );
  };

  return {
    app,
    router,
    call,
    advance(seconds: number): void {
      clock += seconds;
    },
  };
}

async function createFile(call: ReturnType<typeof gateway>["call"]): Promise<string> {
  const response = await call("/v1/files", {
    method: "POST",
    body: fileForm(),
  });
  expect(response.status).toBe(200);
  return ((await response.json()) as { id: string }).id;
}

async function errorCode(response: Response): Promise<string> {
  const body = (await response.json()) as { error: { code: string } };
  return body.error.code;
}

describe("batch route module wiring", () => {
  test("registers the four contract operations", () => {
    const { router } = gateway();
    expect(router.registeredOperationIds()).toEqual(
      expect.arrayContaining(["createBatch", "retrieveBatch", "listBatches", "cancelBatch"]),
    );
  });
});

describe("OpenAI-compatible batch lifecycle", () => {
  test("creates, retrieves, lists, and cancels a batch with durable-state timestamps", async () => {
    const fixture = gateway();
    const inputFileId = await createFile(fixture.call);
    fixture.advance(10);

    const createdResponse = await fixture.call("/v1/batches", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        input_file_id: inputFileId,
        endpoint: "/v1/chat/completions",
        completion_window: "24h",
        metadata: { job: "lifecycle" },
      }),
    });
    expect(createdResponse.status).toBe(200);
    const created = (await createdResponse.json()) as BatchResponse;
    expect(created).toMatchObject({
      id: expect.stringMatching(/^batch_[0-9a-f]+$/),
      object: "batch",
      endpoint: "/v1/chat/completions",
      errors: null,
      input_file_id: inputFileId,
      completion_window: "24h",
      status: "validating",
      output_file_id: null,
      error_file_id: null,
      created_at: START_UNIX + 10,
      expires_at: START_UNIX + 10 + 24 * 60 * 60,
      in_progress_at: null,
      finalizing_at: null,
      completed_at: null,
      failed_at: null,
      expired_at: null,
      cancelling_at: null,
      cancelled_at: null,
      request_counts: { total: 0, completed: 0, failed: 0 },
      metadata: { job: "lifecycle" },
    });

    const retrievedResponse = await fixture.call(`/v1/batches/${created.id}`);
    expect(retrievedResponse.status).toBe(200);
    expect(await retrievedResponse.json()).toEqual(created);

    const listedResponse = await fixture.call("/v1/batches?limit=10");
    expect(listedResponse.status).toBe(200);
    expect(await listedResponse.json()).toEqual({
      object: "list",
      data: [created],
      has_more: false,
    });

    fixture.advance(5);
    const cancelledResponse = await fixture.call(`/v1/batches/${created.id}/cancel`, {
      method: "POST",
    });
    expect(cancelledResponse.status).toBe(200);
    const cancelled = (await cancelledResponse.json()) as BatchResponse;
    expect(cancelled).toMatchObject({
      ...created,
      status: "cancelled",
      cancelling_at: START_UNIX + 15,
      cancelled_at: START_UNIX + 15,
    });

    const listedAfterCancel = await fixture.call("/v1/batches");
    expect(((await listedAfterCancel.json()) as { data: BatchResponse[] }).data[0]).toEqual(
      cancelled,
    );
  });

  test("rejects a missing input file without creating a row", async () => {
    const fixture = gateway();
    const missing = await fixture.call("/v1/batches", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        input_file_id: "file-does-not-exist",
        endpoint: "/v1/embeddings",
        completion_window: "24h",
      }),
    });
    expect(missing.status).toBe(404);
    expect(await errorCode(missing)).toBe("not_found");

    const listed = await fixture.call("/v1/batches");
    expect(await listed.json()).toEqual({ object: "list", data: [], has_more: false });
  });

  test("rejects endpoints outside the served set and non-24h windows", async () => {
    const fixture = gateway();
    const inputFileId = await createFile(fixture.call);
    const rejectedEndpoint = await fixture.call("/v1/batches", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        input_file_id: inputFileId,
        endpoint: "/v1/responses",
        completion_window: "24h",
      }),
    });
    expect(rejectedEndpoint.status).toBe(400);
    expect(await errorCode(rejectedEndpoint)).toBe("invalid_request");

    // #698 slice 2 narrowed the set: the executor has no legacy completions
    // operation, so a batch it could never run is refused at creation instead
    // of sitting at `validating` until its 24-hour window expires.
    const legacyCompletions = await fixture.call("/v1/batches", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        input_file_id: inputFileId,
        endpoint: "/v1/completions",
        completion_window: "24h",
      }),
    });
    expect(legacyCompletions.status).toBe(400);
    expect(await errorCode(legacyCompletions)).toBe("invalid_request");

    const rejectedWindow = await fixture.call("/v1/batches", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        input_file_id: inputFileId,
        endpoint: "/v1/embeddings",
        completion_window: "48h",
      }),
    });
    expect(rejectedWindow.status).toBe(400);
    expect(await errorCode(rejectedWindow)).toBe("invalid_request");

    const listed = await fixture.call("/v1/batches");
    expect(await listed.json()).toEqual({ object: "list", data: [], has_more: false });
  });
});

describe("batch tenant isolation", () => {
  test("tenant B cannot retrieve tenant A's batch", async () => {
    const fixture = gateway();
    const inputFileId = await createFile(fixture.call);
    const createdResponse = await fixture.call("/v1/batches", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        input_file_id: inputFileId,
        endpoint: "/v1/chat/completions",
        completion_window: "24h",
      }),
    });
    const created = (await createdResponse.json()) as BatchResponse;

    const otherTenant = await fixture.call(`/v1/batches/${created.id}`, {
      token: "fg_batch_b",
    });
    expect(otherTenant.status).toBe(404);
    expect(await errorCode(otherTenant)).toBe("not_found");
  });
});
