import { env } from "cloudflare:test";
import { beforeAll, describe, expect, test } from "vitest";
import {
  EXPECTED_THROUGHPUT_PATHS,
  type TenantThroughputReport,
  assertCompleteThroughputReport,
  runTenantThroughputHarness,
} from "./tenant-throughput-harness.js";

declare global {
  namespace Cloudflare {
    interface Env {
      TENANT_DATA: import("../../src/tenant-data-object.js").TenantDataNamespace;
    }
  }
}

const TENANT_ID = "tenant_throughput_issue_829";

let report: TenantThroughputReport;

beforeAll(async () => {
  report = await runTenantThroughputHarness(env.TENANT_DATA, TENANT_ID);
});

describe("single-tenant Durable Object throughput harness", () => {
  test("executes every real request path and returns complete metrics", () => {
    assertCompleteThroughputReport(report);

    expect(Object.keys(report.paths).sort()).toEqual([...EXPECTED_THROUGHPUT_PATHS].sort());
    expect(report.totalInferenceEvents).toBeGreaterThan(0);
    expect(report.totalStorageOperations).toBe(report.totalInferenceEvents * 5);
    expect(report.rowEvidence.requestLogs).toBe(report.totalInferenceEvents);
    expect(report.rowEvidence.walletReservations).toBe(report.totalInferenceEvents);

    console.log(`TENANT_THROUGHPUT_METRICS ${JSON.stringify(report)}`);
  }, 30_000);

  test("fails structurally when a driven path is silently skipped", () => {
    const skipped = {
      ...report,
      paths: {
        ...report.paths,
        requestLogWrite: {
          ...report.paths.requestLogWrite,
          opCount: 0,
        },
      },
    } as TenantThroughputReport;

    expect(() => assertCompleteThroughputReport(skipped)).toThrow(/requestLogWrite/);
  });
});
