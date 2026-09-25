import { env } from "cloudflare:test";
import { expect, it, vi } from "vitest";
import { GATEWAY_MIDDLEWARE, gatewayQueue } from "../../src/index.js";
it("has no automatic evaluation sampler in the deployed chain", () => {
  expect(GATEWAY_MIDDLEWARE.map((fn) => fn.name)).not.toContain("onlineEvaluationMiddleware");
});
it("acknowledges retired and unknown queue messages without interpreting them as request logs", async () => {
  const ack = vi.fn();
  const retryAll = vi.fn();
  await gatewayQueue(
    {
      queue: "ferrogate-online-eval",
      messages: [{ body: { object: "online_eval_sample", prompt: "retired" }, ack }],
      retryAll,
    },
    env,
  );
  expect(ack).toHaveBeenCalledOnce();
  expect(retryAll).not.toHaveBeenCalled();
});
