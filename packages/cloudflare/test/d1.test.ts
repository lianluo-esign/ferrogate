/**
 * D1 database LIFECYCLE (slice S5) — ported from
 * `crates/ferrogate-cloudflare/src/d1.rs:159-219`.
 *
 * `cutover-parity-libraries.md` §6.1 classified ALL of `d1.rs` as "superseded
 * by the native D1 binding". That is true for the `/query` endpoint and FALSE
 * for the lifecycle endpoints: **no binding can create a D1 database**, for the
 * same reason no binding can create an R2 bucket. FerroGate's design is one D1
 * database per tenant, so the missing half is not cosmetic — without it,
 * onboarding a tenant is a manual `wrangler d1 create` plus a hand-written
 * `INSERT INTO tenant_databases`.
 *
 * The `/query` endpoint is deliberately NOT ported here: `@ferrogate/storage`'s
 * `D1RestDatabase` already implements it, is tested against a real `workerd`,
 * and a second copy is exactly the duplication this package exists to end.
 *
 * D1's list is PAGE-NUMBERED (`page`/`per_page`), not cursor-paginated like
 * R2's. Both dialects have to be walked, and getting them confused silently
 * returns page 1.
 */
import { describe, expect, test } from "vitest";
import { CloudflareClient, EnvTokenResolver } from "../src/client.js";
import { D1LifecycleClient } from "../src/d1.js";
import { RecordingClock, ScriptedTransport, errorResponse, okResponse } from "./support.js";

function d1(transport: ScriptedTransport) {
  return new D1LifecycleClient(
    new CloudflareClient({
      config: { accountId: "acct_123", tokenReference: "inline-token" },
      resolver: new EnvTokenResolver({}),
      transport,
      clock: new RecordingClock(),
    }),
  );
}

describe("createDatabase", () => {
  test("posts to the account d1/database collection and returns the uuid", async () => {
    const transport = new ScriptedTransport([
      okResponse({ uuid: "db-uuid-1", name: "ferrogate-tenant-acme", version: "production" }),
    ]);
    const database = await d1(transport).createDatabase({ name: "ferrogate-tenant-acme" });
    expect(database.uuid).toBe("db-uuid-1");
    expect(transport.requests[0]?.method).toBe("POST");
    expect(transport.requests[0]?.url).toBe(
      "https://api.cloudflare.com/client/v4/accounts/acct_123/d1/database",
    );
    expect(JSON.parse(transport.requests[0]?.body ?? "{}")).toEqual({
      name: "ferrogate-tenant-acme",
    });
  });

  test("carries primary_location_hint and jurisdiction when set, and omits them otherwise", async () => {
    const transport = new ScriptedTransport([okResponse({ uuid: "u" })]);
    await d1(transport).createDatabase({
      name: "n",
      primaryLocationHint: "weur",
      jurisdiction: "eu",
    });
    expect(JSON.parse(transport.requests[0]?.body ?? "{}")).toEqual({
      name: "n",
      primary_location_hint: "weur",
      jurisdiction: "eu",
    });
  });

  test("an empty name is refused BEFORE any request", async () => {
    const transport = new ScriptedTransport([]);
    await expect(d1(transport).createDatabase({ name: "" })).rejects.toThrowError(
      /cloudflare config error/,
    );
    expect(transport.callCount).toBe(0);
  });
});

describe("listDatabases — the page walk", () => {
  test("stops as soon as a page returns fewer rows than per_page", async () => {
    const transport = new ScriptedTransport([okResponse([{ uuid: "a" }, { uuid: "b" }])]);
    const databases = await d1(transport).listDatabases();
    expect(databases.map((db) => db.uuid)).toEqual(["a", "b"]);
    expect(transport.callCount).toBe(1);
    expect(transport.requests[0]?.url).toContain("per_page=1000");
    expect(transport.requests[0]?.url).toContain("page=1");
  });

  test("walks to page 2 when page 1 comes back exactly full", async () => {
    const full = Array.from({ length: 1000 }, (_, i) => ({ uuid: `db-${i}` }));
    const transport = new ScriptedTransport([okResponse(full), okResponse([{ uuid: "last" }])]);
    const databases = await d1(transport).listDatabases();
    expect(databases).toHaveLength(1001);
    expect(transport.callCount).toBe(2);
    expect(transport.requests[1]?.url).toContain("page=2");
  });

  test("an empty account yields an empty list, not an error", async () => {
    const transport = new ScriptedTransport([okResponse([])]);
    expect(await d1(transport).listDatabases()).toEqual([]);
  });
});

describe("getDatabase", () => {
  test("GETs the uuid-addressed database", async () => {
    const transport = new ScriptedTransport([okResponse({ uuid: "db-1", name: "n" })]);
    expect((await d1(transport).getDatabase("db-1")).name).toBe("n");
    expect(transport.requests[0]?.method).toBe("GET");
    expect(transport.requests[0]?.url).toContain("/d1/database/db-1");
  });
});

describe("deleteDatabase", () => {
  test("DELETEs the uuid-addressed database", async () => {
    const transport = new ScriptedTransport([okResponse(null)]);
    await d1(transport).deleteDatabase("db-1");
    expect(transport.requests[0]?.method).toBe("DELETE");
    expect(transport.requests[0]?.url).toContain("/d1/database/db-1");
  });
});

describe("path-segment safety", () => {
  test("a database id that could escape the path segment is refused before any request", async () => {
    const transport = new ScriptedTransport([]);
    const client = d1(transport);
    for (const id of ["", "../accounts", "a/b", "a?x=1", "a b", "a_b"]) {
      await expect(client.getDatabase(id)).rejects.toThrowError(/cloudflare config error/);
      await expect(client.deleteDatabase(id)).rejects.toThrowError(/cloudflare config error/);
    }
    expect(transport.callCount).toBe(0);
  });

  test("a real Cloudflare uuid (hex + hyphens) is accepted", async () => {
    const transport = new ScriptedTransport([okResponse({ uuid: "x" })]);
    await expect(
      d1(transport).getDatabase("f5c9c9ab-1c2d-4e5f-8a9b-0c1d2e3f4a5b"),
    ).resolves.toBeDefined();
  });
});

describe("the query endpoint is deliberately NOT here", () => {
  test("D1LifecycleClient exposes no query method", () => {
    const transport = new ScriptedTransport([]);
    expect((d1(transport) as unknown as Record<string, unknown>).query).toBeUndefined();
  });
});

describe("error mapping flows through the shared client", () => {
  test("an under-scoped token names the D1 permission group to grant", async () => {
    const transport = new ScriptedTransport([
      errorResponse(403, [{ code: 9109, message: "Unauthorized to access requested resource" }]),
    ]);
    const error = await d1(transport)
      .createDatabase({ name: "n" })
      .then(
        () => undefined,
        (e: { kind: string; message: string }) => e,
      );
    expect(error?.kind).toBe("missing_scope");
    expect(error?.message).toContain("D1");
  });
});
