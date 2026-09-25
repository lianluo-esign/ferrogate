import { SELF, env } from "cloudflare:test";
import { DurableObjectD1Database } from "@ferrogate/storage";
import { expect, it, vi } from "vitest";

// This same probe can run on the pre-change checkout. It measures local
// workerd, never the provider network; it is not a production latency promise.
it("reports local authenticated request latency and config RPC counts", async ({ annotate }) => {
  const kv = (env as unknown as { PLATFORM_CONFIG: KVNamespace }).PLATFORM_CONFIG;
  await kv.put(
    "platform-config:quota-plans:v1",
    JSON.stringify({
      schema_version: 1,
      published_at_ms: Date.now(),
      plans: [],
      tenants: [{ id: "tenant_a", plan_id: "" }],
    }),
  );
  const get = () =>
    SELF.fetch("https://gateway.test/v1/models", {
      headers: { Authorization: "Bearer fg_tenant_unscoped" },
    });
  const query = vi.spyOn(DurableObjectD1Database.prototype, "runStatement");
  const batch = vi.spyOn(DurableObjectD1Database.prototype, "batch");
  try {
    const times: number[] = [];
    for (let i = 0; i < 40; i++) {
      const started = performance.now();
      const response = await get();
      expect(response.status).toBe(200);
      await response.arrayBuffer();
      times.push(performance.now() - started);
    }
    const batches = batch.mock.calls.map(([statements]) =>
      statements.map(
        (statement) => (statement as unknown as { plan(): { sql: string } }).plan().sql,
      ),
    );
    const warm = times.slice(1).sort((a, b) => a - b);
    await annotate(
      JSON.stringify({
        requests: times.length,
        coldMs: times[0],
        warmP50Ms: warm[Math.floor(warm.length * 0.5)],
        warmP95Ms: warm[Math.floor(warm.length * 0.95)],
        configRpc: {
          schemaProbes: query.mock.calls.filter(
            ([statement]) =>
              statement.sql.includes("sqlite_master") &&
              statement.params?.includes("spend_throttles"),
          ).length,
          quotaBatches: batches.filter((statements) =>
            statements.some((sql) => sql.includes("FROM quota_policies")),
          ).length,
          planBatches: batches.filter((statements) =>
            statements.some((sql) => sql.includes("FROM plans p JOIN tenants")),
          ).length,
        },
      }),
      "performance",
    );
  } finally {
    query.mockRestore();
    batch.mockRestore();
  }
});
