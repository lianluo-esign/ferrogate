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
  DEFAULT_POOL_ACQUIRE_TIMEOUT_MILLIS,
  DEFAULT_POSTGRES_POOL_SIZE,
  D1RestTenantDatabaseRouter,
  D1_BINDING_STRATEGIES,
  StorageError,
  memoryProviderConfig,
  providerIsDurable,
  type PostgresStorageConfig,
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

describe("PLATFORM LIMIT — no runtime bind-by-uuid for D1 (§1.7)", () => {
  /**
   * Bindings resolve at DEPLOY time; `env` is an ordinary object, so the
   * approximation is a runtime lookup by NAME over a deploy-time-declared set
   * (`EnvBindingTenantDatabaseRouter`). The D1 REST query API is the only
   * runtime-uuid-addressable surface, and it provides neither atomic `batch()`
   * nor `RETURNING` — so it is declared and REFUSED rather than stubbed.
   */
  test("the REST strategy lacks EXACTLY ONE money-path primitive: atomic batch", () => {
    expect(D1_BINDING_STRATEGIES.rest.atomicBatch).toBe(false);
    // CORRECTED from `false`. `RETURNING` is NOT the missing piece — the D1
    // /query response carries `results` per statement, which is where a
    // RETURNING clause's rows land, and `D1RestDatabase` reads exactly that
    // (proved end-to-end in `test/d1/rest-transport.test.ts`). Pinning `false`
    // here taught the opposite of the safe design: an engineer who believes a
    // single guarded `UPDATE … RETURNING` cannot report its own guard over REST
    // reaches for SELECT-then-UPDATE, which IS the race.
    expect(D1_BINDING_STRATEGIES.rest.returning).toBe(true);
    // …and it is the ONLY strategy with no deploy-time coupling, which is
    // exactly why it keeps being tempting.
    expect(D1_BINDING_STRATEGIES.rest.requiresDeployPerTenant).toBe(false);
    expect(D1_BINDING_STRATEGIES.native_binding.atomicBatch).toBe(true);
    expect(D1_BINDING_STRATEGIES.native_binding.requiresDeployPerTenant).toBe(true);
    // The ONLY strategy that is both deploy-free and money-safe would be one
    // with atomicBatch AND !requiresDeployPerTenant. There is none; if one ever
    // appears, this is the assertion that fails and sends a reader to the
    // `rest` entry's OPEN QUESTION.
    expect(
      Object.values(D1_BINDING_STRATEGIES).filter(
        (s) => s.atomicBatch && !s.requiresDeployPerTenant,
      ),
    ).toEqual([]);
  });

  test("the strict REST router THROWS rather than serving a non-atomic write path", async () => {
    const router = new D1RestTenantDatabaseRouter({} as unknown as D1Database, {
      accountId: "acct_1",
      apiTokenRef: "env://CF_API_TOKEN",
    });
    const error = await router.forTenant("acme").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StorageError);
    // A stub that "worked" for reads and silently lost atomicity on writes is
    // the more dangerous artifact; the refusal must name the primitive that is
    // ACTUALLY missing and must not smear the one that is not.
    expect((error as StorageError).message).toContain("no transaction envelope");
    expect((error as StorageError).message).toContain("NonAtomicD1RestTenantDatabaseRouter");
    expect((error as StorageError).message).not.toContain("neither atomic batch() nor RETURNING");
  });
});
