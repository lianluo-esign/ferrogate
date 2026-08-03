/**
 * The executable half of the corrected `D1_BINDING_STRATEGIES.rest` record.
 *
 * `rest.returning` was pinned `false` in TWO tests in this package while
 * `src/tenant-rest.ts` — the transport that actually speaks to the D1 HTTP
 * query API — implemented and documented the opposite, and
 * `apps/gateway/test/tenancy/rest.spec.ts` proved the opposite. Two green
 * suites, contradicting each other, about a money-path primitive.
 *
 * The Cloudflare `/query` response is
 * `{ result: [{ results, success, meta }, …] }` — one entry per statement, and
 * `results` is where a `RETURNING` clause's rows land. So `RETURNING` is not
 * what REST lacks; a multi-statement transaction envelope is. Getting this
 * backwards is expensive in the dangerous direction: an engineer who believes a
 * single guarded `UPDATE … WHERE <cas> RETURNING` cannot report whether its
 * guard held will replace it with SELECT-then-UPDATE, and that read-then-write
 * IS the oversell the whole no-oversell design exists to prevent.
 *
 * These tests live in the D1 suite (real `workerd`) rather than the pure suite
 * so the transport is exercised in the runtime it ships in. `fetch` is INJECTED
 * — nothing here touches the network or the live Cloudflare account, per the
 * LOCAL-FIRST rule. What is under test is the transport's own contract: which
 * primitives it surfaces and which it refuses. The remote's semantics are not,
 * and cannot be, asserted from here — see the OPEN QUESTION on the `rest` entry
 * in `src/tenant-router.ts`.
 */
import { describe, expect, test } from "vitest";
import {
  D1RestDatabase,
  D1_BINDING_STRATEGIES,
  D1_REST_API_BASE,
  StorageError,
} from "../../src/index.js";

interface Recorded {
  url: string;
  authorization: string | null;
  body: { sql: string; params: unknown[] };
}

/** A fake D1 query API shaped exactly like Cloudflare's documented envelope. */
function recordingFetch(rows: unknown[]): {
  calls: Recorded[];
  fetch: (input: string, init?: RequestInit) => Promise<Response>;
} {
  const calls: Recorded[] = [];
  return {
    calls,
    fetch: async (input, init) => {
      const headers = new Headers(init?.headers as HeadersInit);
      calls.push({
        url: input,
        authorization: headers.get("authorization"),
        body: JSON.parse(String(init?.body)) as { sql: string; params: unknown[] },
      });
      return new Response(
        JSON.stringify({
          success: true,
          errors: [],
          result: [{ results: rows, success: true, meta: { changes: rows.length } }],
        }),
        { headers: { "content-type": "application/json" } },
      );
    },
  };
}

describe("D1 REST transport — RETURNING is NOT the missing primitive", () => {
  test("a guarded UPDATE … RETURNING reports its guard through the REST transport", async () => {
    const { calls, fetch } = recordingFetch([{ id: "res_1", status: "released" }]);
    const db = new D1RestDatabase("uuid-acme", {
      accountId: "acct_1",
      apiToken: "tok_1",
      fetch,
    }).asD1Database();

    const won = await db
      .prepare(
        "UPDATE wallet_reservations SET status = 'released' WHERE id = ? AND status = 'active' " +
          "RETURNING id, status",
      )
      .bind("res_1")
      .first<{ id: string; status: string }>();

    // THE point: the row comes back, so `won !== null` is a usable CAS verdict
    // over REST. This is what `D1_BINDING_STRATEGIES.rest.returning` records.
    expect(won).toEqual({ id: "res_1", status: "released" });
    expect(D1_BINDING_STRATEGIES.rest.returning).toBe(true);
    expect(calls[0]?.body.sql).toContain("RETURNING id, status");
    expect(calls[0]?.url).toBe(`${D1_REST_API_BASE}/accounts/acct_1/d1/database/uuid-acme/query`);
    expect(calls[0]?.authorization).toBe("Bearer tok_1");
  });

  test("an EMPTY RETURNING set is distinguishable from a row — the refusal signal", async () => {
    // Half of the no-oversell design is that an empty `RETURNING` set means the
    // in-statement guard refused. If the transport collapsed "no rows" into the
    // same shape as "one row", every guarded write over REST would read as a
    // win and the CAS would be decorative.
    const { fetch } = recordingFetch([]);
    const db = new D1RestDatabase("uuid-acme", {
      accountId: "a",
      apiToken: "t",
      fetch,
    }).asD1Database();

    const lost = await db
      .prepare("UPDATE wallet_reservations SET status = 'released' WHERE id = ? RETURNING id")
      .bind("res_missing")
      .first<{ id: string }>();
    expect(lost).toBeNull();
  });
});

describe("D1 REST transport — the primitive that IS missing", () => {
  test("batch() is refused, and the refusal names the transaction envelope", async () => {
    const { calls, fetch } = recordingFetch([]);
    const db = new D1RestDatabase("uuid-acme", {
      accountId: "a",
      apiToken: "t",
      fetch,
    }).asD1Database();

    const error = await db
      .batch([db.prepare("UPDATE wallets SET balance_credits = balance_credits - 1")])
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(StorageError);
    expect((error as StorageError).message).toContain("no");
    expect((error as StorageError).message).toContain("transaction envelope");
    // Refused BEFORE the wire: a batch that got half-issued and then threw
    // would be the torn write the refusal exists to prevent.
    expect(calls).toEqual([]);
    expect(D1_BINDING_STRATEGIES.rest.atomicBatch).toBe(false);
  });
});
