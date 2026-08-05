/**
 * Pins for the `@ferrogate/storage` behaviors KEPT as PORT-TODO markers because
 * the Cloudflare platform cannot express the Rust behavior.
 *
 * A kept marker without a test is a claim; these are the tests that make each
 * one falsifiable. If a future Cloudflare release closes one of these gaps, the
 * corresponding assertion here fails and points at the marker to delete.
 *
 * The two D1-runtime limits (no cross-database transaction; no R2↔D1
 * transaction) are pinned where they can actually be exercised, in
 * `test/d1/usage-d1.test.ts` and `test/d1/assets-r2.test.ts` — they need a real
 * binding to mean anything.
 */
import { describe, expect, test } from "vitest";
import {
  D1_BINDING_STRATEGIES,
  DEFAULT_POOL_ACQUIRE_TIMEOUT_MILLIS,
  DEFAULT_POSTGRES_POOL_SIZE,
  type PostgresStorageConfig,
  memoryProviderConfig,
  providerIsDurable,
} from "../src/index.js";

describe("PLATFORM LIMIT — a Worker cannot hold a warm connection pool (§1.6)", () => {
  /**
   * `PostgresStorageConfig` is retained as an INERT migration-tool shape. The
   * point of these assertions is that it is a plain data record with no
   * behavior: there is nothing here that opens, recycles, or waits on a
   * connection, because a Worker isolate has no lifetime in which to hold one.
   */
  test("the Rust defaults are preserved verbatim for a migration tool to read", () => {
    expect(DEFAULT_POSTGRES_POOL_SIZE).toBe(4);
    expect(DEFAULT_POOL_ACQUIRE_TIMEOUT_MILLIS).toBe(1000);
  });

  test("the config is a data shape only — no acquire, no pool, no client", () => {
    const config: PostgresStorageConfig = {
      dsn: "postgresql://user:pw@db.example.com:5432/ferrogate",
      poolSize: DEFAULT_POSTGRES_POOL_SIZE,
      poolAcquireTimeoutMillis: DEFAULT_POOL_ACQUIRE_TIMEOUT_MILLIS,
      tlsMode: "verify_full",
      connectTimeoutSecs: 5,
      statementTimeoutMillis: 30_000,
      searchPath: ["public"],
    };
    // Nothing in this package consumes `poolSize` — the field exists so a
    // Supabase→D1 migration tool can read a Rust-era config, and for no other
    // reason. If a pool ever became implementable, this module would grow a
    // function that takes this config, and this assertion would be the place
    // that notices.
    expect(Object.keys(config).sort()).toEqual([
      "connectTimeoutSecs",
      "dsn",
      "poolAcquireTimeoutMillis",
      "poolSize",
      "searchPath",
      "statementTimeoutMillis",
      "tlsMode",
    ]);
  });

  test("D1 is the durable backend the port actually deploys", () => {
    expect(providerIsDurable("cloudflare_d1")).toBe(true);
    expect(providerIsDurable("memory")).toBe(false);
    expect(memoryProviderConfig()).toEqual({ kind: "memory", required: false });
  });
});

describe("PLATFORM LIMIT — supported tenant storage strategies", () => {
  test("the strategy table names exactly the supported backends", () => {
    expect(Object.keys(D1_BINDING_STRATEGIES).sort()).toEqual([
      "durable_object",
      "native_binding",
      "shared_development",
    ]);
    expect(D1_BINDING_STRATEGIES.native_binding.atomicBatch).toBe(true);
    expect(D1_BINDING_STRATEGIES.durable_object.atomicBatch).toBe(true);
    expect(D1_BINDING_STRATEGIES.shared_development.atomicBatch).toBe(true);
  });

  test("exactly one production strategy is both deploy-free and money-safe: durable_object", () => {
    expect(
      Object.entries(D1_BINDING_STRATEGIES)
        .filter(
          ([name, s]) =>
            name !== "shared_development" && s.atomicBatch && !s.requiresDeployPerTenant,
        )
        .map(([name]) => name),
    ).toEqual(["durable_object"]);
    expect(D1_BINDING_STRATEGIES.durable_object.returning).toBe(true);
    expect(D1_BINDING_STRATEGIES.durable_object.extraNetworkHop).toBe(true);
  });
});
