/**
 * `D1RestDatabase` must honour Cloudflare's retry contract.
 *
 * `cf-crate-assessment.md` §S4 records the one live-path consequence of the
 * unported `ferrogate-cloudflare` crate: this class is on the REQUEST path for
 * any deployment whose tenant fleet exceeds the Worker binding budget, and it
 * had no retry, no backoff and no `Retry-After` handling. Cloudflare's global
 * API limit is ~1,200 requests / 5 min / user, so one 429 — or one transient
 * 502 from the edge — became a hard, user-visible `StorageError` on a read that
 * would have succeeded a second later.
 *
 * The schedule under test is the Rust `ferrogate_cloudflare::RetryPolicy`
 * (`client.rs:148-170`), now ported to `@ferrogate/cloudflare`: 4 retries, 1s
 * base, 60s cap, the server's `Retry-After` wins when present, and NO jitter —
 * deterministic on purpose so the exact sleep sequence is assertable with an
 * injected clock rather than merely "it eventually retried".
 *
 * `fetch` and the clock are both INJECTED: no network, no real sleeps, no live
 * Cloudflare account.
 */
import { describe, expect, test } from "vitest";
import { D1RestDatabase, StorageError } from "../../src/index.js";

/** A scripted D1 query API: one scripted response per call, in order. */
function scriptedFetch(script: readonly Response[]): {
  calls: number;
  fetch: (input: string, init?: RequestInit) => Promise<Response>;
} {
  const state = { calls: 0 };
  return {
    get calls() {
      return state.calls;
    },
    fetch: async () => {
      const response = script[state.calls];
      state.calls += 1;
      if (response === undefined) {
        throw new Error(`D1 REST fake ran out of scripted responses at call ${state.calls}`);
      }
      return response.clone();
    },
  };
}

function ok(rows: unknown[]): Response {
  return new Response(
    JSON.stringify({
      success: true,
      errors: [],
      result: [{ results: rows, success: true, meta: { changes: rows.length } }],
    }),
    { headers: { "content-type": "application/json" } },
  );
}

function rateLimited(retryAfterSeconds?: number): Response {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (retryAfterSeconds !== undefined) headers["retry-after"] = String(retryAfterSeconds);
  return new Response(
    JSON.stringify({ success: false, errors: [{ code: 10058, message: "TooManyRequests" }] }),
    { status: 429, headers },
  );
}

function badGateway(): Response {
  return new Response(JSON.stringify({ success: false, errors: [] }), {
    status: 502,
    headers: { "content-type": "application/json" },
  });
}

describe("D1 REST transport — retry on Cloudflare 429 / 5xx", () => {
  test("a 429 followed by a 200 resolves instead of throwing", async () => {
    const slept: number[] = [];
    const { fetch } = scriptedFetch([rateLimited(), ok([{ id: "row_1" }])]);
    const db = new D1RestDatabase("db-uuid-1", {
      accountId: "acct",
      apiToken: "tok",
      fetch,
      sleep: async (ms) => {
        slept.push(ms);
      },
    });

    const row = await db.prepare("SELECT 1").first();

    expect(row).toEqual({ id: "row_1" });
    // First retry of the deterministic schedule: base_backoff * 2^0 = 1s.
    expect(slept).toEqual([1000]);
  });

  test("the server's Retry-After wins over the exponential schedule", async () => {
    const slept: number[] = [];
    const { fetch } = scriptedFetch([rateLimited(7), ok([])]);
    const db = new D1RestDatabase("db-uuid-2", {
      accountId: "acct",
      apiToken: "tok",
      fetch,
      sleep: async (ms) => {
        slept.push(ms);
      },
    });

    await db.prepare("SELECT 1").all();

    expect(slept).toEqual([7000]);
  });

  test("a transient 502 is retried; the exhausted budget is 4 retries = 5 calls", async () => {
    const slept: number[] = [];
    const script = [badGateway(), badGateway(), badGateway(), badGateway(), badGateway()];
    const fake = scriptedFetch(script);
    const db = new D1RestDatabase("db-uuid-3", {
      accountId: "acct",
      apiToken: "tok",
      fetch: fake.fetch,
      sleep: async (ms) => {
        slept.push(ms);
      },
    });

    await expect(db.prepare("SELECT 1").all()).rejects.toBeInstanceOf(StorageError);

    // 1 initial attempt + max_retries(4) = 5 transport calls, and the exact
    // deterministic doubling schedule in between.
    expect(fake.calls).toBe(5);
    expect(slept).toEqual([1000, 2000, 4000, 8000]);
  });

  test("a 502 on an INSERT is NOT retried — the write may already have applied", async () => {
    // The query API POSTs every statement, so a 5xx is AMBIGUOUS. Re-issuing an
    // INSERT on that evidence is a duplicate write. This is the same class of
    // harm that makes the R2 token mint non-retryable upstream.
    const slept: number[] = [];
    const fake = scriptedFetch([badGateway(), ok([])]);
    const db = new D1RestDatabase("db-uuid-w1", {
      accountId: "acct",
      apiToken: "tok",
      fetch: fake.fetch,
      sleep: async (ms) => {
        slept.push(ms);
      },
    });

    await expect(
      db.prepare("INSERT INTO ledger (id, cents) VALUES (?, ?)").bind("a", 1).run(),
    ).rejects.toBeInstanceOf(StorageError);
    expect(fake.calls).toBe(1);
    expect(slept).toEqual([]);
  });

  test("a 429 on an INSERT IS retried — a rate limit never reached the database", async () => {
    const fake = scriptedFetch([rateLimited(), ok([])]);
    const db = new D1RestDatabase("db-uuid-w2", {
      accountId: "acct",
      apiToken: "tok",
      fetch: fake.fetch,
      sleep: async () => {},
    });

    await expect(
      db.prepare("INSERT INTO ledger (id) VALUES (?)").bind("a").run(),
    ).resolves.toBeDefined();
    expect(fake.calls).toBe(2);
  });

  test("a 5xx is not retried for any statement that is not provably read-only", async () => {
    for (const sql of [
      "UPDATE wallets SET cents = cents - 1 WHERE id = ?",
      "DELETE FROM sessions WHERE id = ?",
      "UPDATE w SET c = c - 1 WHERE id = ? RETURNING c",
      "SELECT 1; DELETE FROM sessions",
      "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x",
      "  select 1 ; update t set a = 1 ",
    ]) {
      const fake = scriptedFetch([badGateway(), ok([])]);
      const db = new D1RestDatabase("db-uuid-w3", {
        accountId: "acct",
        apiToken: "tok",
        fetch: fake.fetch,
        sleep: async () => {},
      });
      await expect(db.prepare(sql).all()).rejects.toBeInstanceOf(StorageError);
      expect(fake.calls, `expected no retry for: ${sql}`).toBe(1);
    }
  });

  test("a 5xx IS retried for a plain SELECT, including a trailing semicolon", async () => {
    for (const sql of ["SELECT * FROM t WHERE id = ?", "  select a from b ;  "]) {
      const fake = scriptedFetch([badGateway(), ok([{ a: 1 }])]);
      const db = new D1RestDatabase("db-uuid-w4", {
        accountId: "acct",
        apiToken: "tok",
        fetch: fake.fetch,
        sleep: async () => {},
      });
      await expect(db.prepare(sql).all()).resolves.toBeDefined();
      expect(fake.calls, `expected a retry for: ${sql}`).toBe(2);
    }
  });

  test("a 400 is NOT retried — a client error can never succeed on replay", async () => {
    const slept: number[] = [];
    const fake = scriptedFetch([
      new Response(
        JSON.stringify({ success: false, errors: [{ code: 7500, message: "bad SQL" }] }),
        { status: 400, headers: { "content-type": "application/json" } },
      ),
    ]);
    const db = new D1RestDatabase("db-uuid-4", {
      accountId: "acct",
      apiToken: "tok",
      fetch: fake.fetch,
      sleep: async (ms) => {
        slept.push(ms);
      },
    });

    await expect(db.prepare("SELECT 1").all()).rejects.toBeInstanceOf(StorageError);
    expect(fake.calls).toBe(1);
    expect(slept).toEqual([]);
  });
});
