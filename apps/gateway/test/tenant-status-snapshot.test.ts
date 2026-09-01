/**
 * The `tenants.status` KV fast-path (`src/tenant-status-snapshot.ts` +
 * `D1LifecycleRowSource`'s KV-first tenant read).
 *
 * The point under test is the ADMISSION-SAFETY invariant: the snapshot may only
 * ever let an ACTIVE tenant skip a control read it would have passed anyway, and
 * every other outcome — a non-active status, an unknown id, a malformed/absent
 * blob, a KV that throws — MUST fall through to the unchanged control read, which
 * stays the deny authority. These are pure stubs (a fake control DB that counts
 * its reads, a fake KV), so the branch logic is proven without a live binding.
 */
import { describe, expect, it } from "vitest";

import { D1LifecycleRowSource } from "../src/adapters.js";
import {
  TENANT_STATUS_SNAPSHOT_KEY,
  type TenantStatusSnapshot,
  parseTenantStatusSnapshot,
  readTenantStatusSnapshot,
  tenantStatusMapFromRows,
} from "../src/tenant-status-snapshot.js";

/** A control-DB double that records how many `.first()` reads it served. */
function fakeControl(first: () => Promise<unknown>) {
  let reads = 0;
  const db = {
    prepare(_sql: string) {
      return {
        bind(..._values: unknown[]) {
          return {
            first() {
              reads += 1;
              return first();
            },
          };
        },
      };
    },
  };
  return { db, reads: () => reads };
}

/** A KV `get` double returning a fixed payload (or throwing). */
function fakeKv(payload: string | null | (() => never)) {
  let gets = 0;
  return {
    kv: {
      get(_key: string, _options?: { cacheTtl?: number }): Promise<string | null> {
        gets += 1;
        if (typeof payload === "function") return Promise.resolve(payload());
        return Promise.resolve(payload);
      },
    },
    gets: () => gets,
  };
}

function snapshotJson(statuses: Record<string, string>): string {
  const snapshot: TenantStatusSnapshot = {
    schema_version: 1,
    published_at_unix: 1_700_000_000,
    statuses,
  };
  return JSON.stringify(snapshot);
}

describe("tenantStatusMapFromRows", () => {
  it("stores a NULL/absent status as the empty string (the fail-open default)", () => {
    const map = tenantStatusMapFromRows([
      { id: "t1", status: "active" },
      { id: "t2", status: null },
      { id: "t3", status: "suspended" },
    ]);
    expect(map).toEqual({ t1: "active", t2: "", t3: "suspended" });
  });

  it("skips a blank or non-string id rather than keying an empty tenant", () => {
    const map = tenantStatusMapFromRows([
      { id: "", status: "active" },
      { id: "t1", status: "active" },
    ]);
    expect(map).toEqual({ t1: "active" });
  });
});

describe("parseTenantStatusSnapshot", () => {
  it("accepts a well-formed snapshot", () => {
    expect(parseTenantStatusSnapshot(snapshotJson({ t1: "active" }))).toEqual({
      schema_version: 1,
      published_at_unix: 1_700_000_000,
      statuses: { t1: "active" },
    });
  });

  it("rejects a wrong schema version, a non-object map, or malformed JSON", () => {
    expect(
      parseTenantStatusSnapshot(JSON.stringify({ schema_version: 2, statuses: {} })),
    ).toBeNull();
    expect(
      parseTenantStatusSnapshot(
        JSON.stringify({ schema_version: 1, published_at_unix: 1, statuses: [] }),
      ),
    ).toBeNull();
    expect(parseTenantStatusSnapshot("{ not json")).toBeNull();
  });
});

describe("readTenantStatusSnapshot", () => {
  it("reads the shared key with a short cache TTL", async () => {
    const seen: Array<[string, unknown]> = [];
    const kv = {
      get(key: string, options?: { cacheTtl?: number }): Promise<string | null> {
        seen.push([key, options]);
        return Promise.resolve(snapshotJson({ t1: "active" }));
      },
    };
    const snapshot = await readTenantStatusSnapshot(kv);
    expect(snapshot?.statuses).toEqual({ t1: "active" });
    expect(seen).toEqual([[TENANT_STATUS_SNAPSHOT_KEY, { cacheTtl: 30 }]]);
  });

  it("folds an absent, malformed, or throwing read to null", async () => {
    expect(await readTenantStatusSnapshot(fakeKv(null).kv)).toBeNull();
    expect(await readTenantStatusSnapshot(fakeKv("{bad").kv)).toBeNull();
    expect(
      await readTenantStatusSnapshot(
        fakeKv(() => {
          throw new Error("kv down");
        }).kv,
      ),
    ).toBeNull();
  });
});

describe("D1LifecycleRowSource.tenantRow with the KV fast path", () => {
  it("trusts an ACTIVE snapshot entry and skips the control read entirely", async () => {
    const control = fakeControl(() => Promise.resolve({ id: "t1", status: "suspended" }));
    const kv = fakeKv(snapshotJson({ t1: "active" }));
    const source = new D1LifecycleRowSource(control.db, undefined, kv.kv);

    const row = await source.tenantRow("t1");

    expect(row).toEqual({ id: "t1", status: "active", tenant_id: null, project_id: null });
    // The snapshot said active, so the (deliberately contradictory) control row
    // is NEVER consulted — that is the per-request read the flip removes.
    expect(control.reads()).toBe(0);
    expect(kv.gets()).toBe(1);
  });

  it("treats a blank snapshot status as active (the #514 fail-open default)", async () => {
    const control = fakeControl(() => Promise.resolve({ id: "t1", status: "suspended" }));
    const kv = fakeKv(snapshotJson({ t1: "" }));
    const source = new D1LifecycleRowSource(control.db, undefined, kv.kv);

    const row = await source.tenantRow("t1");

    expect(row).toEqual({ id: "t1", status: "", tenant_id: null, project_id: null });
    expect(control.reads()).toBe(0);
  });

  it("falls back to the control read when the snapshot marks the tenant NON-active", async () => {
    const control = fakeControl(() => Promise.resolve({ id: "t1", status: "active" }));
    const kv = fakeKv(snapshotJson({ t1: "suspended" }));
    const source = new D1LifecycleRowSource(control.db, undefined, kv.kv);

    const row = await source.tenantRow("t1");

    // The deny direction is authoritative: a non-active snapshot is confirmed
    // against control, which here says the tenant was already re-activated.
    expect(row?.status).toBe("active");
    expect(control.reads()).toBe(1);
  });

  it("falls back to the control read for a tenant the snapshot does not name", async () => {
    const control = fakeControl(() => Promise.resolve({ id: "t9", status: "suspended" }));
    const kv = fakeKv(snapshotJson({ t1: "active" }));
    const source = new D1LifecycleRowSource(control.db, undefined, kv.kv);

    const row = await source.tenantRow("t9");

    expect(row?.status).toBe("suspended");
    expect(control.reads()).toBe(1);
  });

  it("falls back to the control read when the snapshot is absent", async () => {
    const control = fakeControl(() => Promise.resolve({ id: "t1", status: "suspended" }));
    const kv = fakeKv(null);
    const source = new D1LifecycleRowSource(control.db, undefined, kv.kv);

    const row = await source.tenantRow("t1");

    expect(row?.status).toBe("suspended");
    expect(control.reads()).toBe(1);
  });

  it("is byte-for-byte the pure control read when no KV is wired (gate OFF)", async () => {
    const control = fakeControl(() => Promise.resolve({ id: "t1", status: "suspended" }));
    const source = new D1LifecycleRowSource(control.db, undefined);

    const row = await source.tenantRow("t1");

    expect(row?.status).toBe("suspended");
    expect(control.reads()).toBe(1);
  });

  it("propagates a control outage (throw) when the snapshot cannot answer", async () => {
    const control = fakeControl(() => Promise.reject(new Error("control down")));
    const kv = fakeKv(null);
    const source = new D1LifecycleRowSource(control.db, undefined, kv.kv);

    await expect(source.tenantRow("t1")).rejects.toThrow("control down");
  });
});
