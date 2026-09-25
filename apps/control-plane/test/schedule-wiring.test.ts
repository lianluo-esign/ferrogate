import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, expect, it } from "vitest";
import { applySchema, rawDocument, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey } from "./harness.js";
beforeAll(applySchema);
beforeEach(async () => {
  await resetD1();
  arm({ store: "d1", staticKeys: [operatorKey] });
});
it("refuses all retired schedule operations without persisting or dispatching", async () => {
  for (const [method, path] of [
    ["GET", ""],
    ["POST", ""],
    ["GET", "/retired"],
    ["PUT", "/retired"],
    ["PATCH", "/retired"],
    ["DELETE", "/retired"],
    ["GET", "/retired/fires"],
    ["POST", "/retired/run-now"],
  ] as const) {
    const res = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules${path}`,
      method === "GET"
        ? { headers: bearer(operatorKey.secret) }
        : jsonRequest(operatorKey.secret, method, {
            id: "retired",
            spec_kind: "interval",
            interval_secs: 60,
          }),
    );
    expect(res.status).toBe(410);
    expect(await res.json()).toMatchObject({ error: { code: "feature_retired" } });
  }
  expect(await rawDocument("agent-schedules", "retired")).toBeNull();
});
