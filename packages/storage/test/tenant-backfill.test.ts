import { describe, expect, test } from "vitest";
import {
  TENANT_BACKFILL_TABLES,
  assertTenantMigrationTransition,
  checksumRows,
  compareTableReceipts,
  type TenantTableReceipt,
} from "../src/tenant-backfill.js";

describe("tenant backfill contract", () => {
  test("manifests the current tenant schema without object-owned metadata", () => {
    const names = TENANT_BACKFILL_TABLES.map((table) => table.name);

    expect(new Set(names).size).toBe(names.length);
    expect(names.length).toBeGreaterThanOrEqual(60);
    expect(names).toContain("wallets");
    expect(names).toContain("wallet_reservations");
    expect(names).toContain("wallet_settlements");
    expect(names).toContain("usage_monthly_rollups");
    expect(names).toContain("usage_aggregate_rollups");
    expect(names).toContain("usage_metadata_rollups");
    expect(names).toContain("agent_cost_burn");
    expect(names).not.toContain("storage_schema_migrations");
    expect(names).not.toContain("tenant_provisioning_marks");
    expect(names).not.toContain("model_catalog");
  });

  test("only permits the documented forward and rollback transitions", () => {
    expect(() => assertTenantMigrationTransition("shared", "copying")).not.toThrow();
    expect(() => assertTenantMigrationTransition("copying", "verifying")).not.toThrow();
    expect(() => assertTenantMigrationTransition("verifying", "cut")).not.toThrow();
    expect(() => assertTenantMigrationTransition("cut", "done")).not.toThrow();
    expect(() => assertTenantMigrationTransition("cut", "shared")).not.toThrow();

    expect(() => assertTenantMigrationTransition("shared", "cut")).toThrow(/shared.*copying/);
    expect(() => assertTenantMigrationTransition("copying", "cut")).toThrow(/verifying/);
    expect(() => assertTenantMigrationTransition("done", "shared")).toThrow(/terminal/);
  });

  test("checksum is deterministic over canonical row order and value types", async () => {
    const first = await checksumRows(
      [
        { id: "b", amount: "2", optional: null },
        { id: "a", amount: "1", optional: 0 },
      ],
      ["id", "amount", "optional"],
    );
    const second = await checksumRows(
      [
        { id: "a", amount: "1", optional: 0 },
        { id: "b", amount: "2", optional: null },
      ],
      ["id", "amount", "optional"],
    );

    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
  });

  test("verification reports an omitted table instead of allowing cutover", () => {
    const source: TenantTableReceipt[] = [
      { table: "wallets", rowCount: 1, checksum: "a" },
      { table: "wallet_reservations", rowCount: 1, checksum: "b" },
    ];
    const destination: TenantTableReceipt[] = [{ table: "wallets", rowCount: 1, checksum: "a" }];

    expect(compareTableReceipts(source, destination)).toEqual({
      ok: false,
      mismatches: [
        {
          table: "wallet_reservations",
          reason: "missing_destination",
          source: { table: "wallet_reservations", rowCount: 1, checksum: "b" },
        },
      ],
    });
  });
});
