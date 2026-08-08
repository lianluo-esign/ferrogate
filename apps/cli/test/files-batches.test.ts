/**
 * The OpenAI-compatible `files` and `batches` ctl groups (#698 / #899).
 *
 * These are the nine operations the #698 integration reviewed-excluded because
 * two of them needed grammar the CLI did not have: `createFile` is a multipart
 * byte UPLOAD and `getFileContent` is a byte DOWNLOAD to a path. Every test here
 * asserts the exact request the verb builds (method + path + query + multipart
 * fields + downloaded bytes), so an inverted mapping — wrong path, dropped
 * bytes, a misnamed form field — turns a green test red.
 */
import { describe, expect, test } from "vitest";
import type { ContextStore } from "../src/context.js";
import { main } from "../src/index.js";
import { createTestRuntime, ok } from "./helpers.js";

const STORE: ContextStore = {
  contexts: [
    {
      name: "prod",
      endpoint: "https://cp.example",
      tlsInsecureSkipVerify: false,
      auth: { kind: "env", var: "TOK" },
    },
  ],
  current: "prod",
};

const ENV = { TOK: "bearer-value" };

describe("files reads and deletes", () => {
  test("list is a collection GET on /v1/files", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /v1/files": ok({ data: [{ id: "file-1" }], object: "list" }) },
    });
    expect(await main(["ctl", "files", "list", "--output", "json"], runtime)).toBe(0);
    const request = runtime.client.requests[0];
    expect(request?.spec.method).toBe("GET");
    expect(request?.spec.path).toBe("/v1/files");
    expect(JSON.parse(runtime.stdout())).toEqual({ data: [{ id: "file-1" }], object: "list" });
  });

  test("get addresses one file by id", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /v1/files/file-abc": ok({ id: "file-abc", object: "file" }) },
    });
    expect(await main(["ctl", "files", "get", "file-abc"], runtime)).toBe(0);
    expect(runtime.client.requests[0]?.spec.path).toBe("/v1/files/file-abc");
    expect(runtime.client.requests[0]?.spec.method).toBe("GET");
  });

  test("delete is a mutating DELETE that emits a receipt", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "DELETE /v1/files/file-abc": ok({ id: "file-abc", deleted: true }) },
    });
    expect(await main(["ctl", "files", "delete", "file-abc", "--output", "json"], runtime)).toBe(0);
    expect(runtime.client.requests[0]?.spec.method).toBe("DELETE");
    expect(runtime.client.requests[0]?.spec.path).toBe("/v1/files/file-abc");
    const receipt = JSON.parse(runtime.stdout());
    expect(receipt.object).toBe("mutation_receipt");
    expect(receipt.operation_id.value).toBe("deleteFile");
    expect(receipt.verb).toBe("delete");
  });
});

describe("createFile multipart upload", () => {
  test("uploads the file bytes and the purpose form field, and emits a receipt", async () => {
    const contents = '{"custom_id":"a"}\n';
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      files: { "batch-input.jsonl": contents },
      script: {
        "POST /v1/files": {
          status: 200,
          body: { id: "file-new", object: "file", purpose: "batch" },
          requestId: "req-up",
        },
      },
    });
    const code = await main(
      [
        "ctl",
        "files",
        "create",
        "--input-file",
        "batch-input.jsonl",
        "--purpose",
        "batch",
        "--output",
        "json",
      ],
      runtime,
    );
    expect(code).toBe(0);

    const spec = runtime.client.requests[0]?.spec;
    expect(spec?.method).toBe("POST");
    expect(spec?.path).toBe("/v1/files");
    // No JSON body: this is a multipart upload, not a document.
    expect(spec?.body).toBeUndefined();
    expect(spec?.upload?.file.fieldName).toBe("file");
    expect(spec?.upload?.file.filename).toBe("batch-input.jsonl");
    expect([...(spec?.upload?.file.bytes ?? [])]).toEqual([...new TextEncoder().encode(contents)]);
    expect(spec?.upload?.fields).toEqual([["purpose", "batch"]]);

    const receipt = JSON.parse(runtime.stdout());
    expect(receipt.object).toBe("mutation_receipt");
    expect(receipt.operation_id.value).toBe("createFile");
    expect(receipt.outcome).toBe("applied");
    expect(receipt.correlation.request_id.value).toBe("req-up");
  });

  test("refuses when --input-file is missing", async () => {
    const runtime = createTestRuntime({ store: STORE, env: ENV });
    expect(await main(["ctl", "files", "create", "--purpose", "batch"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("--input-file");
    expect(runtime.client.requests).toHaveLength(0);
  });

  test("refuses when the required --purpose form field is missing", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      files: { "in.jsonl": "x" },
    });
    expect(await main(["ctl", "files", "create", "--input-file", "in.jsonl"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("--purpose is required");
    expect(runtime.client.requests).toHaveLength(0);
  });
});

describe("getFileContent byte download", () => {
  test("downloads raw bytes to stdout and asks for the octet-stream media type", async () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 255]);
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /v1/files/file-x/content": { status: 200, bytes } },
    });
    expect(await main(["ctl", "files", "download", "file-x"], runtime)).toBe(0);
    expect(runtime.stdoutBytes()[0]).toEqual(bytes);
    expect(runtime.client.requests[0]?.mediaType).toBe("application/octet-stream");
    expect(runtime.client.requests[0]?.spec.path).toBe("/v1/files/file-x/content");
  });

  test("--output-file writes the bytes to a path instead of stdout", async () => {
    const bytes = new Uint8Array([9, 8, 7, 6]);
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /v1/files/file-x/content": { status: 200, bytes } },
    });
    expect(
      await main(["ctl", "files", "download", "file-x", "--output-file", "out.bin"], runtime),
    ).toBe(0);
    // Nothing goes to stdout when a destination is given...
    expect(runtime.stdoutBytes()).toHaveLength(0);
    // ...and the file holds the exact bytes.
    expect(await runtime.io.readFileBytes("out.bin")).toEqual(bytes);
    expect(runtime.stderr()).toContain("wrote 4 bytes to out.bin");
  });
});

describe("batches", () => {
  test("list is a collection GET on /v1/batches", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /v1/batches": ok({ data: [], object: "list" }) },
    });
    expect(await main(["ctl", "batches", "list"], runtime)).toBe(0);
    expect(runtime.client.requests[0]?.spec.path).toBe("/v1/batches");
    expect(runtime.client.requests[0]?.spec.method).toBe("GET");
  });

  test("create POSTs the JSON document referencing an input_file_id", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "POST /v1/batches": { status: 200, body: { id: "batch_1", status: "validating" } },
      },
    });
    const body = {
      input_file_id: "file-new",
      endpoint: "/v1/chat/completions",
      completion_window: "24h",
    };
    expect(
      await main(
        ["ctl", "batches", "create", "--data", JSON.stringify(body), "--output", "json"],
        runtime,
      ),
    ).toBe(0);
    const spec = runtime.client.requests[0]?.spec;
    expect(spec?.method).toBe("POST");
    expect(spec?.path).toBe("/v1/batches");
    expect(spec?.body).toEqual(body);
    const receipt = JSON.parse(runtime.stdout());
    expect(receipt.operation_id.value).toBe("createBatch");
  });

  test("get retrieves one batch by id", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "GET /v1/batches/batch_1": ok({ id: "batch_1", output_file_id: "file-out" }),
      },
    });
    expect(await main(["ctl", "batches", "get", "batch_1"], runtime)).toBe(0);
    expect(runtime.client.requests[0]?.spec.method).toBe("GET");
    expect(runtime.client.requests[0]?.spec.path).toBe("/v1/batches/batch_1");
  });

  test("cancel POSTs the cancel action and emits a receipt", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "POST /v1/batches/batch_1/cancel": ok({ id: "batch_1", status: "cancelling" }),
      },
    });
    expect(await main(["ctl", "batches", "cancel", "batch_1", "--output", "json"], runtime)).toBe(
      0,
    );
    expect(runtime.client.requests[0]?.spec.method).toBe("POST");
    expect(runtime.client.requests[0]?.spec.path).toBe("/v1/batches/batch_1/cancel");
    const receipt = JSON.parse(runtime.stdout());
    expect(receipt.operation_id.value).toBe("cancelBatch");
    expect(receipt.verb).toBe("cancel");
  });
});
