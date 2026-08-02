/**
 * The THIRD reference-guarded delete (inventory-data-billing §1.5.7): an asset
 * variant may only be deleted while no `asset_channels` pointer resolves to its
 * version.
 *
 * As with the project/workspace pair, the claim that needs REAL D1 is not "a
 * referenced variant is refused" — it is that the check and the delete are ONE
 * statement, so a channel published a microsecond after a caller would have
 * "checked" still blocks the delete. The interleaving test at the bottom is the
 * reason this file uses SQLite rather than a fake.
 *
 * Why it matters: a deleted variant that `latest` or `stable` still names is a
 * dangling pointer, and every subsequent pull on that channel resolves to a
 * version whose bytes are gone — a 404 on a name the operator believes is
 * published.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  D1ReferenceGuardedDeletes,
  DELETE_ASSET_VARIANT_IF_UNREFERENCED_SQL,
  type TenantDatabaseHandle,
  assetVariantDeleteOutcomeFromReferences,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, setupDatabases } from "./harness.js";

const NOW = 1_700_000_000;

let handleA: TenantDatabaseHandle;
let handleB: TenantDatabaseHandle;

beforeAll(async () => {
  const router = await setupDatabases();
  handleA = await router.forTenant(TENANT_A);
  handleB = await router.forTenant(TENANT_B);
});

async function clear(db: D1Database): Promise<void> {
  await db.batch([
    db.prepare("DELETE FROM asset_channels"),
    db.prepare("DELETE FROM stored_assets"),
  ]);
}

beforeEach(async () => {
  await clear(env.TENANT_DB_A);
  await clear(env.TENANT_DB_B);
});

async function seedVariant(
  db: D1Database,
  id: string,
  options: { tenantId?: string; name?: string; version?: string; variant?: string } = {},
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO stored_assets (id, tenant_id, asset_type, name, version, content_type, " +
        " content_hash, size_bytes, created_at_unix, updated_at_unix, variant) " +
        "VALUES (?, ?, 'cli_tool', ?, ?, 'application/octet-stream', ?, 10, ?, ?, ?)",
    )
    .bind(
      id,
      options.tenantId ?? TENANT_A,
      options.name ?? "deploy",
      options.version ?? "1.0.0",
      "a".repeat(64),
      NOW,
      NOW,
      options.variant ?? "",
    )
    .run();
}

async function seedChannel(
  db: D1Database,
  channel: string,
  options: { tenantId?: string; name?: string; version?: string } = {},
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO asset_channels (id, tenant_id, asset_type, name, channel, version, " +
        " updated_at_unix) VALUES (?, ?, 'cli_tool', ?, ?, ?, ?)",
    )
    .bind(
      `${options.tenantId ?? TENANT_A}:cli_tool:${options.name ?? "deploy"}:${channel}`,
      options.tenantId ?? TENANT_A,
      options.name ?? "deploy",
      channel,
      options.version ?? "1.0.0",
      NOW,
    )
    .run();
}

async function variantExists(db: D1Database, id: string): Promise<boolean> {
  const row = await db.prepare("SELECT id FROM stored_assets WHERE id = ?").bind(id).first();
  return row !== null;
}

describe("assetVariantDeleteOutcomeFromReferences — the decision rule", () => {
  test("an absent variant is not_found, even while a channel names its version", () => {
    // The dangling pointer is a different defect; reporting `referenced` would
    // suggest a retry that can never succeed.
    expect(assetVariantDeleteOutcomeFromReferences({ present: 0, channels: ["latest"] })).toEqual({
      kind: "not_found",
    });
  });

  test("a present, unreferenced variant is deleted", () => {
    expect(assetVariantDeleteOutcomeFromReferences({ present: 1, channels: [] })).toEqual({
      kind: "deleted",
    });
  });

  test("a referenced variant names the blocking channels", () => {
    expect(
      assetVariantDeleteOutcomeFromReferences({ present: 1, channels: ["latest", "stable"] }),
    ).toEqual({ kind: "referenced", channels: ["latest", "stable"] });
  });
});

describe("D1ReferenceGuardedDeletes.deleteAssetVariantIfUnreferenced", () => {
  test("deletes a variant no channel points at", async () => {
    await seedVariant(env.TENANT_DB_A, "as_free");
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteAssetVariantIfUnreferenced("as_free"),
    ).toEqual({ kind: "deleted" });
    expect(await variantExists(env.TENANT_DB_A, "as_free")).toBe(false);
  });

  test("refuses a variant `latest` still resolves to, and names the channel", async () => {
    await seedVariant(env.TENANT_DB_A, "as_held");
    await seedChannel(env.TENANT_DB_A, "latest");
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteAssetVariantIfUnreferenced("as_held"),
    ).toEqual({ kind: "referenced", channels: ["latest"] });
    // The refusal has to be REAL, not just a label on a completed delete.
    expect(await variantExists(env.TENANT_DB_A, "as_held")).toBe(true);
  });

  test("names every blocking channel, in a stable order", async () => {
    await seedVariant(env.TENANT_DB_A, "as_two");
    await seedChannel(env.TENANT_DB_A, "stable");
    await seedChannel(env.TENANT_DB_A, "latest");
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteAssetVariantIfUnreferenced("as_two"),
    ).toEqual({ kind: "referenced", channels: ["latest", "stable"] });
  });

  test("an unknown id is not_found", async () => {
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteAssetVariantIfUnreferenced("nope"),
    ).toEqual({ kind: "not_found" });
  });

  test("a channel on a DIFFERENT version does not block this one", async () => {
    await seedVariant(env.TENANT_DB_A, "as_v1", { version: "1.0.0" });
    await seedChannel(env.TENANT_DB_A, "latest", { version: "2.0.0" });
    // The control for the refusal above: same table, same asset name, and the
    // delete proceeds purely because the versions differ.
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteAssetVariantIfUnreferenced("as_v1"),
    ).toEqual({ kind: "deleted" });
  });

  test("a channel on a different asset NAME does not block this one", async () => {
    await seedVariant(env.TENANT_DB_A, "as_deploy", { name: "deploy" });
    await seedChannel(env.TENANT_DB_A, "latest", { name: "other" });
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteAssetVariantIfUnreferenced("as_deploy"),
    ).toEqual({ kind: "deleted" });
  });

  test("a channel in ANOTHER tenant's database cannot block a delete", async () => {
    await seedVariant(env.TENANT_DB_A, "as_iso");
    await seedVariant(env.TENANT_DB_B, "as_iso");
    await seedChannel(env.TENANT_DB_B, "latest");
    // Tenant B holds the pointer; tenant A's delete must not see it.
    expect(
      await new D1ReferenceGuardedDeletes(handleA).deleteAssetVariantIfUnreferenced("as_iso"),
    ).toEqual({ kind: "deleted" });
    expect(
      await new D1ReferenceGuardedDeletes(handleB).deleteAssetVariantIfUnreferenced("as_iso"),
    ).toEqual({ kind: "referenced", channels: ["latest"] });
  });

  test("a channel published mid-flight still blocks the delete", async () => {
    await seedVariant(env.TENANT_DB_A, "as_race");
    let injected = false;

    // A handle whose `run()` publishes `latest` IMMEDIATELY BEFORE the guarded
    // DELETE executes — the exact window a check-then-delete would lose.
    const racing: TenantDatabaseHandle = {
      ...handleA,
      db: {
        prepare(sql: string) {
          const statement = env.TENANT_DB_A.prepare(sql);
          return {
            bind(...values: unknown[]) {
              const bound = statement.bind(...values);
              return {
                async run() {
                  if (sql === DELETE_ASSET_VARIANT_IF_UNREFERENCED_SQL && !injected) {
                    injected = true;
                    await seedChannel(env.TENANT_DB_A, "latest");
                  }
                  return bound.run();
                },
                first: bound.first.bind(bound),
                all: bound.all.bind(bound),
                raw: bound.raw.bind(bound),
              } as unknown as D1PreparedStatement;
            },
          } as unknown as D1PreparedStatement;
        },
      } as unknown as D1Database,
    };

    const outcome = await new D1ReferenceGuardedDeletes(racing).deleteAssetVariantIfUnreferenced(
      "as_race",
    );
    expect(injected).toBe(true);
    expect(outcome).toEqual({ kind: "referenced", channels: ["latest"] });
    // Check-then-delete would have reported `deleted` and orphaned `latest`.
    expect(await variantExists(env.TENANT_DB_A, "as_race")).toBe(true);
  });
});
