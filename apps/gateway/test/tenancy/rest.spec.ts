/**
 * The D1 **REST** strategy — the only one with no deploy-time coupling, and the
 * only one that cannot serve the money paths.
 *
 * These specs pin the atomicity table in
 * `packages/storage/src/tenant-rest.ts`: single statements (including a guarded
 * `UPDATE … RETURNING`) go through and their rows come back; `batch()` is
 * REFUSED; and a REST handle reports `supportsAtomicBatch: false` so
 * `requireAtomicBatch` — which every guarded write in `@ferrogate/storage`
 * calls first — turns the wallet no-oversell reserve into an error rather than
 * into a non-atomic read-then-write.
 *
 * `fetch` is injected, so nothing here touches the network or the live
 * Cloudflare account (LOCAL-FIRST). What is being tested is the transport's
 * shape and its refusals, which is exactly the part that has no local D1
 * equivalent.
 */
import { env } from "cloudflare:test";
import {
  D1RestDatabase,
  D1_REST_API_BASE,
  NonAtomicD1RestTenantDatabaseRouter,
  requireAtomicBatch,
} from "@ferrogate/storage";
import { beforeAll, describe, expect, test } from "vitest";
import { TENANT_ACME, TENANT_GHOST, setupTenancy, walletFor } from "./setup.js";

beforeAll(setupTenancy);

interface Call {
  url: string;
  authorization: string | null;
  body: { sql: string; params: unknown[] };
}

/** A fake D1 query API that records what it was asked, and answers `rows`. */
function recordingFetch(rows: unknown[]): { calls: Call[]; fetch: typeof fetch } {
  const calls: Call[] = [];
  const fetchLike = async (input: string, init?: RequestInit) => {
    const headers = new Headers(init?.headers as HeadersInit);
    calls.push({
      url: input,
      authorization: headers.get("authorization"),
      body: JSON.parse(String(init?.body)),
    });
    return new Response(
      JSON.stringify({
        success: true,
        errors: [],
        result: [{ results: rows, success: true, meta: { changes: rows.length } }],
      }),
      { headers: { "content-type": "application/json" } },
    );
  };
  return { calls, fetch: fetchLike as unknown as typeof fetch };
}

describe("D1RestDatabase — what the query API CAN do", () => {
  test("addresses the database by RUNTIME uuid and bearer-authenticates", async () => {
    const { calls, fetch } = recordingFetch([{ tenant_id: TENANT_ACME, balance_credits: 42 }]);
    const db = new D1RestDatabase("uuid-acme", {
      accountId: "acct_9",
      apiToken: "tok_9",
      fetch,
    }).asD1Database();

    const row = await db
      .prepare("SELECT tenant_id, balance_credits FROM wallets WHERE tenant_id = ?")
      .bind(TENANT_ACME)
      .first<{ balance_credits: number }>();

    expect(row?.balance_credits).toBe(42);
    expect(calls).toHaveLength(1);
    // The whole reason this strategy exists: the database is chosen at RUNTIME
    // from a uuid, with no `[[d1_databases]]` stanza and no redeploy.
    expect(calls[0]?.url).toBe(`${D1_REST_API_BASE}/accounts/acct_9/d1/database/uuid-acme/query`);
    expect(calls[0]?.authorization).toBe("Bearer tok_9");
    expect(calls[0]?.body.params).toEqual([TENANT_ACME]);
  });

  test("a single guarded UPDATE … RETURNING is atomic AND its rows come back", async () => {
    // One statement is its own implicit transaction in SQLite, so a CAS still
    // holds over REST — and unlike the pre-`d1-proxy` Rust marshalling, the
    // RETURNING rows are not lost.
    const { calls, fetch } = recordingFetch([{ id: "res_1" }]);
    const db = new D1RestDatabase("uuid-acme", {
      accountId: "a",
      apiToken: "t",
      fetch,
    }).asD1Database();

    const result = await db
      .prepare("UPDATE wallet_reservations SET status = ? WHERE id = ? AND status = ? RETURNING id")
      .bind("released", "res_1", "active")
      .all<{ id: string }>();

    expect(result.results).toEqual([{ id: "res_1" }]);
    expect(calls[0]?.body.sql).toContain("RETURNING id");
  });

  test("an API error is an error, not an empty result set", async () => {
    const failing = (async () =>
      new Response(JSON.stringify({ success: false, errors: [{ code: 7502, message: "nope" }] }), {
        status: 400,
        headers: { "content-type": "application/json" },
      })) as unknown as typeof fetch;
    const db = new D1RestDatabase("uuid-acme", {
      accountId: "a",
      apiToken: "t",
      fetch: failing,
    }).asD1Database();

    // Returning `[]` here would make a failed read look like "no rows", which
    // on a guarded write is indistinguishable from "the guard refused".
    await expect(db.prepare("SELECT 1").all()).rejects.toThrow(/7502: nope/);
  });
});

describe("D1RestDatabase — what it MUST refuse", () => {
  test("batch() is refused, naming the oversell it would cause", async () => {
    const { fetch } = recordingFetch([]);
    const db = new D1RestDatabase("uuid-acme", {
      accountId: "a",
      apiToken: "t",
      fetch,
    }).asD1Database();

    await expect(db.batch([db.prepare("INSERT INTO wallets DEFAULT VALUES")])).rejects.toThrow(
      /no transaction envelope/,
    );
  });

  test("a REST handle is refused by requireAtomicBatch, so the money paths cannot run", async () => {
    const router = new NonAtomicD1RestTenantDatabaseRouter(env.CONTROL_DB, {
      accountId: "acct_9",
      apiToken: "tok_9",
      fetch: recordingFetch([]).fetch as unknown as (
        input: string,
        init?: RequestInit,
      ) => Promise<Response>,
    });
    const handle = await router.forTenant(TENANT_ACME);

    expect(handle.source).toBe("rest");
    expect(handle.databaseUuid).toBe("11111111-1111-4111-8111-111111111111");
    // THE fail-closed expression of the REST limitation.
    expect(handle.supportsAtomicBatch).toBe(false);
    expect(() => requireAtomicBatch(handle, "reserve_wallet_credits")).toThrow(
      /requires atomic batch\(\)\+RETURNING/,
    );
  });

  test("the REST router still fails closed on an unregistered tenant", async () => {
    const router = new NonAtomicD1RestTenantDatabaseRouter(env.CONTROL_DB, {
      accountId: "acct_9",
      apiToken: "tok_9",
      fetch: recordingFetch([]).fetch as unknown as (
        input: string,
        init?: RequestInit,
      ) => Promise<Response>,
    });
    await expect(router.forTenant(TENANT_GHOST)).rejects.toThrow(/no provisioned D1 database/);
    await expect(router.forTenant("")).rejects.toThrow(/non-empty tenant id/);
  });

  test("it refuses to route at all without an account id and token", async () => {
    const router = new NonAtomicD1RestTenantDatabaseRouter(env.CONTROL_DB, {
      accountId: "",
      apiToken: "",
    });
    await expect(router.forTenant(TENANT_ACME)).rejects.toThrow(/account id and an API token/);
  });

  test("the registry read is a CONTROL-database read, so enumeration still works", async () => {
    const router = new NonAtomicD1RestTenantDatabaseRouter(env.CONTROL_DB, {
      accountId: "a",
      apiToken: "t",
    });
    expect(await router.provisionedTenants()).toContain(TENANT_ACME);
    expect(router.control()).toBe(env.CONTROL_DB);
    // The shape of the wallet row this transport may NOT write atomically —
    // referenced so the fixture cannot rot away from the money path it names.
    expect(walletFor(TENANT_ACME, 1).tenantId).toBe(TENANT_ACME);
  });
});
