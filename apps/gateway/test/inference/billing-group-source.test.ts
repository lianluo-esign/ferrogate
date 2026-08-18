/**
 * `ControlDataPlatformBillingGroupSource` (#945) — the data-plane read of the
 * billing-group multipliers #942 gave a home in the CONTROL database.
 *
 * Hermetic unit tests against a fake control database (no workerd): a
 * revision-gated, per-env cached read that FAILS OPEN to `1.0` on every axis a
 * money path must survive — no control database, a missing/rolled-back table, an
 * absent group, a DISABLED group, a garbage multiplier, and an outright read
 * error — while honouring a `0` multiplier only for an ENABLED comp group.
 *
 * The file mutates `db.rows`/`db.revision`/`db.fail` on a shared state object
 * and re-reads: every assertion FAILS if the behavior is inverted (a cached
 * failure, a swallowed disabled flag, an ignored revision bump).
 */
import { describe, expect, it } from "vitest";
import {
  ControlDataPlatformBillingGroupSource,
  MirrorFirstBillingGroupSource,
} from "../../src/inference/billing-group-source.js";
import type { InferenceBindings, PlatformBillingGroupSource } from "../../src/inference/ports.js";
import type { TenantDatabaseResolver } from "../../src/tenancy/index.js";
import { controlNamespaceOverD1 } from "../support/control-namespace.js";

interface GroupRow {
  readonly id: string;
  readonly multiplier: number | string | null;
  readonly enabled: number | string | null;
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

/** One tenant's `shared_billing_groups` mirror, addressed by tenant id. */
interface MirrorRow {
  readonly multiplier: number | string | null;
  readonly enabled: number | string | null;
}

interface FakeMirror {
  resolverFor: () => TenantDatabaseResolver;
  reads: string[];
  fail: boolean;
  missing: boolean;
}

/**
 * A fake tenant resolver whose `forTenant` yields a handle whose `db` answers the
 * single-group mirror SELECT. `fail` makes `forTenant` reject (unreachable object);
 * `missing` makes the SELECT throw (mirror table not migrated). Both must defer to
 * the fallback, never bill.
 */
function fakeMirror(rowsByTenant: Record<string, Record<string, MirrorRow>>): FakeMirror {
  const state: FakeMirror = {
    resolverFor: () => resolver,
    reads: [],
    fail: false,
    missing: false,
  };
  const dbFor = (tenantId: string): D1Database => {
    const chainFor = (groupId: string) => ({
      async first<T>() {
        state.reads.push(`${tenantId}:${groupId}`);
        if (state.missing) throw new Error("D1_ERROR: no such table: main.shared_billing_groups");
        const row = rowsByTenant[tenantId]?.[groupId];
        return (row ?? null) as T;
      },
    });
    return {
      prepare: () => ({
        bind: (groupId: string) => chainFor(groupId),
      }),
    } as unknown as D1Database;
  };
  const resolver = {
    async forTenant(tenantId: string) {
      if (state.fail) throw new Error("tenant object unreachable");
      return { db: dbFor(tenantId) };
    },
  } as unknown as TenantDatabaseResolver;
  return state;
}

/** A fallback that records every call and answers a sentinel, so the mirror-first
 *  decision (mirror hit vs fallback) is observable. */
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

describe("MirrorFirstBillingGroupSource", () => {
  const env = {} as InferenceBindings;

  it("serves the tenant mirror when the group row is present (authoritative)", async () => {
    const mirror = fakeMirror({ "tnt-1": { premium: { multiplier: 1.5, enabled: 1 } } });
    const fallback = recordingFallback(99);
    const source = new MirrorFirstBillingGroupSource({
      fallback: fallback.source,
      resolverFor: mirror.resolverFor,
    });

    expect(await source.multiplierForGroup(env, "premium", "tnt-1")).toBe(1.5);
    // A mirror hit never pays the cross-region control read.
    expect(fallback.calls).toHaveLength(0);
    expect(mirror.reads).toEqual(["tnt-1:premium"]);
  });

  it("honours an ENABLED comp 0 from the mirror", async () => {
    const mirror = fakeMirror({ "tnt-1": { comp: { multiplier: 0, enabled: 1 } } });
    const fallback = recordingFallback(99);
    const source = new MirrorFirstBillingGroupSource({
      fallback: fallback.source,
      resolverFor: mirror.resolverFor,
    });

    expect(await source.multiplierForGroup(env, "comp", "tnt-1")).toBe(0);
    expect(fallback.calls).toHaveLength(0);
  });

  it("reads a DISABLED mirror row as the official 1.0 (never the comp 0)", async () => {
    const mirror = fakeMirror({ "tnt-1": { off: { multiplier: 0, enabled: 0 } } });
    const fallback = recordingFallback(99);
    const source = new MirrorFirstBillingGroupSource({
      fallback: fallback.source,
      resolverFor: mirror.resolverFor,
    });

    // A present-but-disabled row is authoritative → 1.0, WITHOUT a control read.
    expect(await source.multiplierForGroup(env, "off", "tnt-1")).toBe(1);
    expect(fallback.calls).toHaveLength(0);
  });

  it("reads a malformed mirror multiplier as the official 1.0", async () => {
    const mirror = fakeMirror({ "tnt-1": { bad: { multiplier: "oops", enabled: 1 } } });
    const fallback = recordingFallback(99);
    const source = new MirrorFirstBillingGroupSource({
      fallback: fallback.source,
      resolverFor: mirror.resolverFor,
    });

    expect(await source.multiplierForGroup(env, "bad", "tnt-1")).toBe(1);
    expect(fallback.calls).toHaveLength(0);
  });

  it("falls back to control when the group is ABSENT from the mirror (not synced yet)", async () => {
    const mirror = fakeMirror({ "tnt-1": {} });
    const fallback = recordingFallback(2.5);
    const source = new MirrorFirstBillingGroupSource({
      fallback: fallback.source,
      resolverFor: mirror.resolverFor,
    });

    // The sync-window gap: an operator's brand-new group the tenant has not
    // mirrored yet must be read from control, not mis-billed as 1.0.
    expect(await source.multiplierForGroup(env, "fresh", "tnt-1")).toBe(2.5);
    expect(fallback.calls).toEqual([{ groupId: "fresh", tenantId: "tnt-1" }]);
  });

  it("falls back to control when the tenant object is unreachable", async () => {
    const mirror = fakeMirror({ "tnt-1": { premium: { multiplier: 1.5, enabled: 1 } } });
    mirror.fail = true;
    const fallback = recordingFallback(2.5);
    const source = new MirrorFirstBillingGroupSource({
      fallback: fallback.source,
      resolverFor: mirror.resolverFor,
    });

    expect(await source.multiplierForGroup(env, "premium", "tnt-1")).toBe(2.5);
    expect(fallback.calls).toEqual([{ groupId: "premium", tenantId: "tnt-1" }]);
  });

  it("falls back to control when the mirror table is not migrated", async () => {
    const mirror = fakeMirror({ "tnt-1": { premium: { multiplier: 1.5, enabled: 1 } } });
    mirror.missing = true;
    const fallback = recordingFallback(2.5);
    const source = new MirrorFirstBillingGroupSource({
      fallback: fallback.source,
      resolverFor: mirror.resolverFor,
    });

    expect(await source.multiplierForGroup(env, "premium", "tnt-1")).toBe(2.5);
    expect(fallback.calls).toEqual([{ groupId: "premium", tenantId: "tnt-1" }]);
  });

  it("falls back to control (never touches a mirror) when no tenant id is known", async () => {
    const mirror = fakeMirror({ "tnt-1": { premium: { multiplier: 1.5, enabled: 1 } } });
    const fallback = recordingFallback(2.5);
    const source = new MirrorFirstBillingGroupSource({
      fallback: fallback.source,
      resolverFor: mirror.resolverFor,
    });

    // A platform-operator caller has no tenant mirror.
    expect(await source.multiplierForGroup(env, "premium", undefined)).toBe(2.5);
    expect(mirror.reads).toHaveLength(0);
    expect(fallback.calls).toEqual([{ groupId: "premium", tenantId: undefined }]);
  });

  it("short-circuits to 1.0 for an unbound group, touching neither mirror nor control", async () => {
    const mirror = fakeMirror({ "tnt-1": { premium: { multiplier: 1.5, enabled: 1 } } });
    const fallback = recordingFallback(2.5);
    const source = new MirrorFirstBillingGroupSource({
      fallback: fallback.source,
      resolverFor: mirror.resolverFor,
    });

    expect(await source.multiplierForGroup(env, undefined, "tnt-1")).toBe(1);
    expect(mirror.reads).toHaveLength(0);
    expect(fallback.calls).toHaveLength(0);
  });
});
