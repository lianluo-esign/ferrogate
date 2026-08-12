/**
 * `ctl billing-groups …` + `ctl providers sync-models` request construction
 * (#942/#944, epic #941). The parity gate proves the verbs are BOUND to the
 * right operationIds; these tests prove each verb BUILDS the right request —
 * especially the two-segment provider-binding sub-resource, whose "providers"
 * segment is injected between the group id and the provider id.
 */
import { describe, expect, test } from "vitest";
import type { ContextStore } from "../src/context.js";
import { main } from "../src/index.js";
import { createTestRuntime } from "./helpers.js";

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

describe("ctl billing-groups", () => {
  test("add posts to the collection", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "POST /admin/v1/billing-groups": { status: 201, body: { id: "g1" }, requestId: "r1" },
      },
    });
    expect(
      await main(
        ["ctl", "billing-groups", "add", "--data", '{"name":"anthropic","multiplier":1.5}'],
        runtime,
      ),
    ).toBe(0);
    expect(runtime.client.requests[0]?.spec.method).toBe("POST");
    expect(runtime.client.requests[0]?.spec.path).toBe("/admin/v1/billing-groups");
  });

  test("update patches the group by id", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "PATCH /admin/v1/billing-groups/g1": { status: 200, body: { id: "g1" }, requestId: "r" },
      },
    });
    expect(
      await main(["ctl", "billing-groups", "update", "g1", "--data", '{"multiplier":2}'], runtime),
    ).toBe(0);
    expect(runtime.client.requests[0]?.spec.method).toBe("PATCH");
    expect(runtime.client.requests[0]?.spec.path).toBe("/admin/v1/billing-groups/g1");
  });

  test("bind-provider PUTs the nested provider sub-resource", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "PUT /admin/v1/billing-groups/g1/providers/prov1": {
          status: 200,
          body: { id: "g1" },
          requestId: "r",
        },
      },
    });
    expect(await main(["ctl", "billing-groups", "bind-provider", "g1", "prov1"], runtime)).toBe(0);
    expect(runtime.client.requests[0]?.spec.method).toBe("PUT");
    expect(runtime.client.requests[0]?.spec.path).toBe(
      "/admin/v1/billing-groups/g1/providers/prov1",
    );
  });

  test("unbind-provider DELETEs the nested provider sub-resource", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "DELETE /admin/v1/billing-groups/g1/providers/prov1": {
          status: 200,
          body: { id: "g1" },
          requestId: "r",
        },
      },
    });
    expect(await main(["ctl", "billing-groups", "unbind-provider", "g1", "prov1"], runtime)).toBe(
      0,
    );
    expect(runtime.client.requests[0]?.spec.method).toBe("DELETE");
    expect(runtime.client.requests[0]?.spec.path).toBe(
      "/admin/v1/billing-groups/g1/providers/prov1",
    );
  });

  test("bind-provider without the provider id is a usage error, not a group-level write", async () => {
    const runtime = createTestRuntime({ store: STORE, env: ENV, script: {} });
    // 2 required segments; one given → usage error (exit 2), no request issued.
    expect(await main(["ctl", "billing-groups", "bind-provider", "g1"], runtime)).toBe(2);
    expect(runtime.client.requests).toHaveLength(0);
  });
});

describe("ctl providers sync-models", () => {
  test("posts to the provider's sync-models action", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "POST /admin/v1/providers/prov1/sync-models": {
          status: 200,
          body: { added: 3, updated: 0, skipped: 1 },
          requestId: "r",
        },
      },
    });
    expect(await main(["ctl", "providers", "sync-models", "prov1"], runtime)).toBe(0);
    expect(runtime.client.requests[0]?.spec.method).toBe("POST");
    expect(runtime.client.requests[0]?.spec.path).toBe("/admin/v1/providers/prov1/sync-models");
  });
});
