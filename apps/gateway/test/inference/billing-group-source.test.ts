/**
 * The data-plane read of the billing-group multipliers #942 gave a home in the
 * CONTROL database, in its two source shapes:
 *
 *  - `ControlDataPlatformBillingGroupSource` (#945) — the direct control read,
 *    still the fallback; and
 *  - `KvFirstBillingGroupSource` (#961) — the production source, which prefers
 *    the account-global `PLATFORM_CONFIG` KV snapshot the control plane
 *    republishes on every mutation, and defers to the control read only for a
 *    group absent from the snapshot (freshly created inside the cache window).
 *
 * Hermetic unit tests against a fake control database and a fake KV (no
 * workerd): a read that FAILS OPEN to `1.0` on every axis a money path must
 * survive — no backend, a missing/rolled-back table, an absent group, a DISABLED
 * group, a garbage multiplier, and an outright read error — while honouring a `0`
 * multiplier only for an ENABLED comp group.
 *
 * The file mutates state on shared objects and re-reads: every assertion FAILS
 * if the behavior is inverted (a cached failure, a swallowed disabled flag, an
 * ignored revision bump, a snapshot miss billed as 1.0 instead of falling back).
 */
import { describe, expect, it } from "vitest";
import {
  ControlDataPlatformBillingGroupSource,
  KvFirstBillingGroupSource,
  PLATFORM_BILLING_GROUP_SNAPSHOT_KEY,
  type PlatformBillingGroupSnapshot,
  type PlatformBillingGroupSnapshotRow,
} from "../../src/inference/billing-group-source.js";
import type { InferenceBindings, PlatformBillingGroupSource } from "../../src/inference/ports.js";
import { controlNamespaceOverD1 } from "../support/control-namespace.js";

interface GroupRow {
  readonly id: string;
  readonly multiplier: number | string | null;
  readonly enabled: number | string | null;
  readonly provider_id?: string | null;
}

interface FakeDatabase {
  db: D1Database;
  revision: number | null;
  rows: GroupRow[];
  revisionReads: number;
  groupReads: number;
  failRevision: boolean;
  failGroups: boolean;
  missing: boolean;
}

/**
 * One fake control database. The CONTROL_DATA facade routes both `.first()`
 * (revision) and `.all()` (groups) through one object `query` (an `.all()` on
 * this fake), so the revision read is disambiguated by SQL — its statement
 * mentions `platform_billing_group_revisions`.
 */
function fakeDb(rows: GroupRow[], revision: number | null = 1): FakeDatabase {
  const state: FakeDatabase = {
    db: undefined as unknown as D1Database,
    revision,
    rows,
    revisionReads: 0,
    groupReads: 0,
    failRevision: false,
    failGroups: false,
    missing: false,
  };
  const revisionResult = (): unknown[] => {
    state.revisionReads += 1;
    if (state.missing) {
      throw new Error("D1_ERROR: no such table: main.platform_billing_group_revisions");
    }
    if (state.failRevision) throw new Error("revision backend unavailable");
    return state.revision === null ? [] : [{ revision: state.revision }];
  };
  const groupResult = (): unknown[] => {
    state.groupReads += 1;
    if (state.missing) {
      throw new Error("D1_ERROR: no such table: main.platform_billing_groups");
    }
    if (state.failGroups) throw new Error("group backend unavailable");
    return state.rows;
  };
  const chainFor = (sql: string) => ({
    bind() {
      return chainFor(sql);
    },
    async first<T>() {
      return (revisionResult()[0] ?? null) as T;
    },
    async all<T>() {
      const isRevision = sql.includes("platform_billing_group_revisions");
      return { results: (isRevision ? revisionResult() : groupResult()) as T[] };
    },
  });
  state.db = { prepare: (sql: string) => chainFor(sql) } as unknown as D1Database;
  return state;
}

function controlEnv(db: FakeDatabase): InferenceBindings {
  return { CONTROL_DATA: controlNamespaceOverD1(db.db) } as unknown as InferenceBindings;
}

describe("ControlDataPlatformBillingGroupSource", () => {
  it("returns the multiplier of an enabled group", async () => {
    const db = fakeDb([{ id: "premium", multiplier: 1.5, enabled: 1 }]);
    const source = new ControlDataPlatformBillingGroupSource();

    expect(await source.multiplierForGroup(controlEnv(db), "premium")).toBe(1.5);
  });

  it("honours a 0 multiplier for an ENABLED comp group", async () => {
    const db = fakeDb([{ id: "comp", multiplier: 0, enabled: 1 }]);
    const source = new ControlDataPlatformBillingGroupSource();

    expect(await source.multiplierForGroup(controlEnv(db), "comp")).toBe(0);
  });

  it("returns the exact provider ids bound to an enabled group", async () => {
    const db = fakeDb([
      { id: "premium", multiplier: 1.5, enabled: 1, provider_id: "provider-a" },
      { id: "premium", multiplier: 1.5, enabled: 1, provider_id: "provider-b" },
    ]);
    const source = new ControlDataPlatformBillingGroupSource();

    expect(await source.routingForGroup(controlEnv(db), "premium")).toEqual({
      providerIds: ["provider-a", "provider-b"],
    });
  });

  it("fails closed for missing and disabled group routing", async () => {
    const db = fakeDb([{ id: "off", multiplier: 1, enabled: 0, provider_id: "provider-a" }]);
    const source = new ControlDataPlatformBillingGroupSource();
    const env = controlEnv(db);

    expect(await source.routingForGroup(env, "off")).toBeNull();
    expect(await source.routingForGroup(env, "missing")).toBeNull();
  });

  it("fails open to 1.0 for a DISABLED group (never the comp 0)", async () => {
    const db = fakeDb([{ id: "off", multiplier: 0, enabled: 0 }]);
    const source = new ControlDataPlatformBillingGroupSource();

    // Inverting the enabled check would settle this at the comp 0 and red this.
    expect(await source.multiplierForGroup(controlEnv(db), "off")).toBe(1);
  });

  it("fails open to 1.0 for an absent/dangling group id", async () => {
    const db = fakeDb([{ id: "premium", multiplier: 1.5, enabled: 1 }]);
    const source = new ControlDataPlatformBillingGroupSource();

    expect(await source.multiplierForGroup(controlEnv(db), "no-such-group")).toBe(1);
  });

  it("fails open to 1.0 for a garbage (negative / NaN) multiplier", async () => {
    const db = fakeDb([
      { id: "neg", multiplier: -2, enabled: 1 },
      { id: "nan", multiplier: "oops", enabled: 1 },
    ]);
    const source = new ControlDataPlatformBillingGroupSource();

    expect(await source.multiplierForGroup(controlEnv(db), "neg")).toBe(1);
    expect(await source.multiplierForGroup(controlEnv(db), "nan")).toBe(1);
  });

  it("fails open to 1.0 when the group id is undefined (no group bound)", async () => {
    const db = fakeDb([{ id: "premium", multiplier: 1.5, enabled: 1 }]);
    const source = new ControlDataPlatformBillingGroupSource();

    expect(await source.multiplierForGroup(controlEnv(db), undefined)).toBe(1);
    // A key with no group never touches the control database.
    expect(db.revisionReads).toBe(0);
  });

  it("fails open to 1.0 when no control database is bound", async () => {
    const source = new ControlDataPlatformBillingGroupSource();

    expect(await source.multiplierForGroup({} as InferenceBindings, "premium")).toBe(1);
  });

  it("fails open to 1.0 when the table is not migrated, and never caches it", async () => {
    const db = fakeDb([{ id: "premium", multiplier: 1.5, enabled: 1 }]);
    db.missing = true;
    const source = new ControlDataPlatformBillingGroupSource();
    // ONE env object, so the WeakMap cache key is stable and "never caches the
    // failure" is actually under test.
    const env = controlEnv(db);

    expect(await source.multiplierForGroup(env, "premium")).toBe(1);
    // The table appears (migration lands): the next read must SEE it, proving the
    // failure was not cached.
    db.missing = false;
    expect(await source.multiplierForGroup(env, "premium")).toBe(1.5);
  });

  it("fails open to 1.0 on a read error, and never caches it", async () => {
    const db = fakeDb([{ id: "premium", multiplier: 1.5, enabled: 1 }]);
    db.failRevision = true;
    const source = new ControlDataPlatformBillingGroupSource();
    const env = controlEnv(db);

    expect(await source.multiplierForGroup(env, "premium")).toBe(1);
    db.failRevision = false;
    expect(await source.multiplierForGroup(env, "premium")).toBe(1.5);
  });

  it("fails open to 1.0 on an unrecognized control-storage posture (no throw)", async () => {
    const db = fakeDb([{ id: "premium", multiplier: 1.5, enabled: 1 }]);
    const env = {
      CONTROL_DATA: controlNamespaceOverD1(db.db),
      GATEWAY_CONTROL_STORAGE: "bogus",
    } as unknown as InferenceBindings;
    const source = new ControlDataPlatformBillingGroupSource();

    // `controlDatabaseFrom` throws HttpError(503) here; a money path swallows it.
    expect(await source.multiplierForGroup(env, "premium")).toBe(1);
  });

  it("serves a cached snapshot until the revision bumps", async () => {
    const db = fakeDb([{ id: "premium", multiplier: 1.5, enabled: 1 }]);
    const source = new ControlDataPlatformBillingGroupSource();
    // The per-env cache is keyed by env-object identity, so the SAME object is
    // reused across reads — a fresh object each call would defeat the cache.
    const env = controlEnv(db);

    expect(await source.multiplierForGroup(env, "premium")).toBe(1.5);
    const groupReadsAfterFirst = db.groupReads;

    // A stale edit that did NOT bump the revision is not observed (cache hit).
    db.rows = [{ id: "premium", multiplier: 3, enabled: 1 }];
    expect(await source.multiplierForGroup(env, "premium")).toBe(1.5);
    expect(db.groupReads).toBe(groupReadsAfterFirst);

    // Bumping the revision re-reads the table.
    db.revision = 2;
    expect(await source.multiplierForGroup(env, "premium")).toBe(3);
    expect(db.groupReads).toBe(groupReadsAfterFirst + 1);
  });
});

/** A fallback that records every call and answers a sentinel, so the KV-first
 *  decision (snapshot hit vs control fallback) is observable. */
function recordingFallback(answer: number): {
  source: PlatformBillingGroupSource;
  calls: Array<{ groupId: string | undefined; tenantId: string | undefined }>;
} {
  const calls: Array<{ groupId: string | undefined; tenantId: string | undefined }> = [];
  const source: PlatformBillingGroupSource = {
    async multiplierForGroup(_env, groupId, tenantId) {
      calls.push({ groupId, tenantId });
      return answer;
    },
  };
  return { source, calls };
}

interface FakeKv {
  kv: KVNamespace;
  reads: number;
  value: string | null;
  fail: boolean;
}

/**
 * A fake `PLATFORM_CONFIG` KV holding the single billing-group snapshot key.
 * `value` is the raw stored string (or `null` for "never published"); `fail`
 * makes `get` throw (a KV blip). `reads` counts `get`s so the per-env TTL cache
 * is observable.
 */
function fakeKv(value: string | null): FakeKv {
  const state: FakeKv = { kv: undefined as unknown as KVNamespace, reads: 0, value, fail: false };
  state.kv = {
    async get(key: string) {
      state.reads += 1;
      if (key !== PLATFORM_BILLING_GROUP_SNAPSHOT_KEY) return null;
      if (state.fail) throw new Error("kv unavailable");
      return state.value;
    },
  } as unknown as KVNamespace;
  return state;
}

function snapshotJson(
  groups: readonly PlatformBillingGroupSnapshotRow[],
  revision = 1,
): string {
  const snapshot: PlatformBillingGroupSnapshot = {
    schema_version: 1,
    revision,
    published_at_unix: 1700,
    groups,
  };
  return JSON.stringify(snapshot);
}

function kvEnv(kv: FakeKv): InferenceBindings {
  return { PLATFORM_CONFIG: kv.kv } as unknown as InferenceBindings;
}

describe("KvFirstBillingGroupSource", () => {
  it("serves the snapshot multiplier when the group is present (authoritative)", async () => {
    const kv = fakeKv(snapshotJson([{ id: "premium", multiplier: 1.5, enabled: true, provider_ids: [] }]));
    const fallback = recordingFallback(99);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    expect(await source.multiplierForGroup(kvEnv(kv), "premium", "tnt-1")).toBe(1.5);
    // A snapshot hit never pays the cross-region control read.
    expect(fallback.calls).toHaveLength(0);
  });

  it("honours an ENABLED comp 0 from the snapshot", async () => {
    const kv = fakeKv(snapshotJson([{ id: "comp", multiplier: 0, enabled: true, provider_ids: [] }]));
    const fallback = recordingFallback(99);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    expect(await source.multiplierForGroup(kvEnv(kv), "comp", "tnt-1")).toBe(0);
    expect(fallback.calls).toHaveLength(0);
  });

  it("reads routing provider ids from the snapshot", async () => {
    const kv = fakeKv(
      snapshotJson([
        { id: "premium", multiplier: 1.5, enabled: true, provider_ids: ["provider-a", "provider-b"] },
      ]),
    );
    const fallback = recordingFallback(99);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    expect(await source.routingForGroup(kvEnv(kv), "premium", "tnt-1")).toEqual({
      providerIds: ["provider-a", "provider-b"],
    });
    expect(fallback.calls).toHaveLength(0);
  });

  it("reads a DISABLED snapshot row as the official 1.0 (never the comp 0)", async () => {
    const kv = fakeKv(snapshotJson([{ id: "off", multiplier: 0, enabled: false, provider_ids: [] }]));
    const fallback = recordingFallback(99);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    // A present-but-disabled row is authoritative → 1.0, WITHOUT a control read.
    expect(await source.multiplierForGroup(kvEnv(kv), "off", "tnt-1")).toBe(1);
    expect(await source.routingForGroup(kvEnv(kv), "off", "tnt-1")).toBeNull();
    expect(fallback.calls).toHaveLength(0);
  });

  it("reads a malformed snapshot multiplier as the official 1.0", async () => {
    // A non-numeric multiplier survived into the snapshot: present, enabled, but
    // unparseable → the money path bills the official price, not a throw.
    const kv = fakeKv(
      snapshotJson([
        { id: "bad", multiplier: "oops" as unknown as number, enabled: true, provider_ids: [] },
      ]),
    );
    const fallback = recordingFallback(99);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    expect(await source.multiplierForGroup(kvEnv(kv), "bad", "tnt-1")).toBe(1);
    expect(fallback.calls).toHaveLength(0);
  });

  it("falls back to control when the group is ABSENT from the snapshot (freshly created)", async () => {
    const kv = fakeKv(snapshotJson([{ id: "premium", multiplier: 1.5, enabled: true, provider_ids: [] }]));
    const fallback = recordingFallback(2.5);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    // The cache-window gap: an operator's brand-new group not yet in the read
    // snapshot must be read from control, not mis-billed as 1.0.
    expect(await source.multiplierForGroup(kvEnv(kv), "fresh", "tnt-1")).toBe(2.5);
    expect(fallback.calls).toEqual([{ groupId: "fresh", tenantId: "tnt-1" }]);
  });

  it("falls back to control when no KV binding is configured", async () => {
    const fallback = recordingFallback(2.5);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    expect(await source.multiplierForGroup({} as InferenceBindings, "premium", "tnt-1")).toBe(2.5);
    expect(fallback.calls).toEqual([{ groupId: "premium", tenantId: "tnt-1" }]);
  });

  it("falls back to control when the snapshot was never published (KV miss)", async () => {
    const kv = fakeKv(null);
    const fallback = recordingFallback(2.5);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    expect(await source.multiplierForGroup(kvEnv(kv), "premium", "tnt-1")).toBe(2.5);
    expect(fallback.calls).toEqual([{ groupId: "premium", tenantId: "tnt-1" }]);
  });

  it("falls back to control on a malformed snapshot value (no prior good snapshot)", async () => {
    const kv = fakeKv("{not valid json");
    const fallback = recordingFallback(2.5);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    expect(await source.multiplierForGroup(kvEnv(kv), "premium", "tnt-1")).toBe(2.5);
    expect(fallback.calls).toEqual([{ groupId: "premium", tenantId: "tnt-1" }]);
  });

  it("falls back to control on a KV read error (never billed from the blip)", async () => {
    const kv = fakeKv(snapshotJson([{ id: "premium", multiplier: 1.5, enabled: true, provider_ids: [] }]));
    kv.fail = true;
    const fallback = recordingFallback(2.5);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    expect(await source.multiplierForGroup(kvEnv(kv), "premium", "tnt-1")).toBe(2.5);
    expect(fallback.calls).toEqual([{ groupId: "premium", tenantId: "tnt-1" }]);
  });

  it("short-circuits to 1.0 for an unbound group, touching neither KV nor control", async () => {
    const kv = fakeKv(snapshotJson([{ id: "premium", multiplier: 1.5, enabled: true, provider_ids: [] }]));
    const fallback = recordingFallback(2.5);
    const source = new KvFirstBillingGroupSource({ fallback: fallback.source });

    expect(await source.multiplierForGroup(kvEnv(kv), undefined, "tnt-1")).toBe(1);
    expect(kv.reads).toBe(0);
    expect(fallback.calls).toHaveLength(0);
  });

  it("serves the cached snapshot within its TTL, re-reading KV only after expiry", async () => {
    const kv = fakeKv(snapshotJson([{ id: "premium", multiplier: 1.5, enabled: true, provider_ids: [] }]));
    let clock = 0;
    const source = new KvFirstBillingGroupSource({
      fallback: recordingFallback(99).source,
      ttlMs: 30_000,
      now: () => clock,
    });
    const env = kvEnv(kv);

    expect(await source.multiplierForGroup(env, "premium")).toBe(1.5);
    expect(kv.reads).toBe(1);

    // A later value edit within the TTL is not observed: one KV read serves both.
    kv.value = snapshotJson([{ id: "premium", multiplier: 3, enabled: true, provider_ids: [] }], 2);
    clock = 29_999;
    expect(await source.multiplierForGroup(env, "premium")).toBe(1.5);
    expect(kv.reads).toBe(1);

    // Past the TTL the snapshot is re-read and the new multiplier surfaces.
    clock = 30_001;
    expect(await source.multiplierForGroup(env, "premium")).toBe(3);
    expect(kv.reads).toBe(2);
  });
});
