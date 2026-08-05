import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { sweepManagedIsolationEvidence } from "../src/managed-evidence-projection.js";
import { resolverForEnv } from "../src/tenancy/index.js";
import { tenantObjectDb } from "./tenant-object.js";

const TENANT = "tenant_managed_evidence_repair";

beforeEach(async () => {
  const control = (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB;
  const tenant = tenantObjectDb(TENANT);
  await control.prepare("DELETE FROM managed_worker_isolation_evidence").run();
  await tenant.prepare("DELETE FROM managed_worker_isolation_evidence").run();
});

describe("managed isolation evidence projection repair", () => {
  it("rebuilds control evidence from the tenant object", async () => {
    const control = (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB;
    await tenantObjectDb(TENANT)
      .prepare(
        "INSERT INTO managed_worker_isolation_evidence (id, occurred_at_unix, evidence_json) " +
          "VALUES (?, ?, ?)",
      )
      .bind("managed:session:run", 100, '{"backend":"firecracker"}')
      .run();

    const bindings = env as unknown as Parameters<typeof resolverForEnv>[0];
    await sweepManagedIsolationEvidence(
      bindings,
      resolverForEnv(bindings).router,
      [TENANT],
    );

    const row = await control
      .prepare(
        "SELECT id, tenant, evidence_json FROM managed_worker_isolation_evidence " +
          "WHERE tenant = ?",
      )
      .bind(TENANT)
      .first();
    expect(row).toEqual({
      id: "managed:session:run",
      tenant: TENANT,
      evidence_json: '{"backend":"firecracker"}',
    });
  });

  it("pages through every evidence row instead of repeating the first page", async () => {
    const tenant = tenantObjectDb(TENANT);
    await tenant.batch(
      Array.from({ length: 3 }, (_, index) =>
        tenant
          .prepare(
            "INSERT INTO managed_worker_isolation_evidence (id, occurred_at_unix, evidence_json) " +
              "VALUES (?, ?, ?)",
          )
          .bind(`managed:session:run-${index}`, 100 + index, JSON.stringify({ index })),
      ),
    );

    const bindings = env as unknown as Parameters<typeof resolverForEnv>[0];
    await sweepManagedIsolationEvidence(
      bindings,
      resolverForEnv(bindings).router,
      [TENANT],
      2,
    );

    const control = (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB;
    const count = await control
      .prepare("SELECT COUNT(*) AS count FROM managed_worker_isolation_evidence WHERE tenant = ?")
      .bind(TENANT)
      .first<{ count: number }>();
    expect(count).toEqual({ count: 3 });
  });
});
