import { SELF, env } from "cloudflare:test";
import { expect, it, vi } from "vitest";
import { gatewayQueue } from "../src/index.js";

it("refuses batch APIs through the deployed worker before reading files or creating jobs", async () => {
  for (const [method, path] of [
    ["POST", "/v1/batches"],
    ["GET", "/v1/batches"],
    ["GET", "/v1/batches/retired"],
    ["POST", "/v1/batches/retired/cancel"],
  ] as const) {
    const response = await SELF.fetch(`https://gateway.test${path}`, {
      method,
      headers: { authorization: "Bearer fg_root", "content-type": "application/json" },
      ...(method === "POST" ? { body: "{}" } : {}),
    });
    expect(response.status).toBe(410);
    expect(await response.json()).toMatchObject({ error: { code: "feature_retired" } });
  }
});

it("keeps the authentication boundary on retired batch endpoints", async () => {
  expect((await SELF.fetch("https://gateway.test/v1/batches")).status).toBe(401);
});

it("acks a late batch message without executing a task or re-enqueuing", async () => {
  const ack = vi.fn();
  const retryAll = vi.fn();
  const send = vi.fn();
  await gatewayQueue(
    {
      messages: [
        { body: { object: "batch.job", tenant_id: "tenant_a", batch_id: "retired" }, ack },
      ],
      retryAll,
    },
    { ...env, BATCH_JOBS: { send, sendBatch: send } },
  );
  expect(ack).toHaveBeenCalledOnce();
  expect(retryAll).not.toHaveBeenCalled();
  expect(send).not.toHaveBeenCalled();
});
