/**
 * Zero-D1 S6 (#882): the KV projection of `api_key_directory`, and the HOP-1
 * READ-AHEAD it feeds in {@link D1TwoHopApiKeyDirectory}.
 *
 * Two layers are pinned here, both PURE (no `workerd`, no real KV):
 *
 *  1. {@link KvApiKeyDirectoryProjection} over a fake KV — the round trip, the
 *     "a corrupt entry is a MISS" rule, and the `expirationTtl` floor.
 *  2. the read-ahead wired into the two-hop resolver, over a fake control DB, a
 *     fake tenant router and a spying projection — where the four invariants the
 *     slice must hold are asserted directly at the seam:
 *
 *       (a) POSITIVE ONLY — an unknown key is never written to KV;
 *       (b) a control-object OUTAGE is `unavailable` (→503), never masked by KV;
 *       (c) a KV-served routing row STILL runs HOP 2 + the lifecycle checks;
 *       (d) a KV read failure falls through to the authoritative RPC.
 */
import { describe, expect, test } from "vitest";
import {
  type ApiKeyDirectoryProjection,
  type ApiKeyDirectoryRow,
  D1TwoHopApiKeyDirectory,
  KEY_DIRECTORY_PROJECTION_PREFIX,
  KV_MIN_EXPIRATION_TTL_SECONDS,
  type KeyDirectoryKv,
  KvApiKeyDirectoryProjection,
  StorageError,
  type TenantApiKeyRow,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
  keyDirectoryProjectionKey,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

interface PutCall {
  readonly key: string;
  readonly value: string;
  readonly expirationTtl?: number;
}

/** An in-memory KV that records every put, so the TTL floor is observable. */
class FakeKv implements KeyDirectoryKv {
  readonly store = new Map<string, string>();
  readonly puts: PutCall[] = [];

  async get(key: string, _type: "text"): Promise<string | null> {
    return this.store.get(key) ?? null;
  }
  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    this.puts.push({ key, value, expirationTtl: options?.expirationTtl });
    this.store.set(key, value);
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

const DIR: ApiKeyDirectoryRow = {
  id: "key_1",
  tenant_id: "tenant_a",
  project_id: "proj_a",
  workspace_id: "ws_a",
  enabled: 1,
  expires_at_unix: null,
  revoked_at_unix: null,
};

function tenantRow(overrides: Partial<TenantApiKeyRow> = {}): TenantApiKeyRow {
  return {
    id: "key_1",
    tenant_id: "tenant_a",
    project_id: "proj_a",
    workspace_id: "ws_a",
    name: "k",
    key_prefix: "fg_",
    key_hash: "sha256:h",
    last4: "abcd",
    enabled: 1,
    scopes_json: "[]",
    allowed_models_json: "[]",
    allowed_providers_json: "[]",
    monthly_token_budget: null,
    request_limit_per_minute: null,
    expires_at_unix: null,
    revoked_at_unix: null,
    attribution_tags_json: "{}",
    ...overrides,
  };
}

/** A tenant D1 handle whose single `.first()` is driven by `handler(boundArg)`. */
function fakeDb(handler: (bound: string) => unknown): { db: D1Database } {
  const db = {
    prepare(_sql: string) {
      let bound = "";
      const stmt = {
        bind(arg: string) {
          bound = arg;
          return stmt;
        },
        async first<T>(): Promise<T | null> {
          return handler(bound) as T | null;
        },
      };
      return stmt;
    },
  } as unknown as D1Database;
  return { db };
}

function controlDb(handler: (bound: string) => unknown): { db: D1Database; count: () => number } {
  let prepares = 0;
  const db = {
    prepare(_sql: string) {
      prepares += 1;
      let bound = "";
      const stmt = {
        bind(arg: string) {
          bound = arg;
          return stmt;
        },
        async first<T>(): Promise<T | null> {
          return handler(bound) as T | null;
        },
      };
      return stmt;
    },
  } as unknown as D1Database;
  return { db, count: () => prepares };
}

function tenantRouter(dbByTenant: Record<string, D1Database>): TenantDatabaseRouter {
  return {
    control() {
      throw new Error("unused");
    },
    async forTenant(tenantId: string): Promise<TenantDatabaseHandle> {
      const db = dbByTenant[tenantId];
      if (db === undefined) throw new StorageError("not_found", `no db for ${tenantId}`);
      return { tenantId, db, source: "durable_object", supportsAtomicBatch: true };
    },
  } as unknown as TenantDatabaseRouter;
}

/** A projection that records every call, over an optional backing map. */
class SpyProjection implements ApiKeyDirectoryProjection {
  readonly reads: string[] = [];
  readonly writes: { keyHash: string; row: ApiKeyDirectoryRow }[] = [];
  readonly deletes: string[] = [];
  #store = new Map<string, ApiKeyDirectoryRow>();
  #throwOnRead = false;

  constructor(options: { seed?: Record<string, ApiKeyDirectoryRow>; throwOnRead?: boolean } = {}) {
    for (const [k, v] of Object.entries(options.seed ?? {})) this.#store.set(k, v);
    this.#throwOnRead = options.throwOnRead ?? false;
  }
  async read(keyHash: string): Promise<ApiKeyDirectoryRow | null> {
    this.reads.push(keyHash);
    if (this.#throwOnRead) throw new Error("kv down");
    return this.#store.get(keyHash) ?? null;
  }
  async write(keyHash: string, row: ApiKeyDirectoryRow): Promise<void> {
    this.writes.push({ keyHash, row });
    this.#store.set(keyHash, row);
  }
  async delete(keyHash: string): Promise<void> {
    this.deletes.push(keyHash);
    this.#store.delete(keyHash);
  }
}

// ---------------------------------------------------------------------------
// KvApiKeyDirectoryProjection
// ---------------------------------------------------------------------------

describe("KvApiKeyDirectoryProjection", () => {
  test("write then read round-trips the exact directory columns", async () => {
    const kv = new FakeKv();
    const projection = new KvApiKeyDirectoryProjection(kv);
    await projection.write("sha256:h", DIR);
    expect(await projection.read("sha256:h")).toEqual(DIR);
  });

  test("keys under the namespaced prefix, derived from the key_hash", async () => {
    const kv = new FakeKv();
    await new KvApiKeyDirectoryProjection(kv).write("sha256:h", DIR);
    expect(kv.puts[0]?.key).toBe(`${KEY_DIRECTORY_PROJECTION_PREFIX}sha256:h`);
    expect(kv.puts[0]?.key).toBe(keyDirectoryProjectionKey("sha256:h"));
  });

  test("an absent entry reads as null (a miss, not an error)", async () => {
    expect(await new KvApiKeyDirectoryProjection(new FakeKv()).read("sha256:missing")).toBeNull();
  });

  test("a corrupt / unparseable entry reads as null — fail closed to the RPC", async () => {
    const kv = new FakeKv();
    kv.store.set(keyDirectoryProjectionKey("sha256:h"), "{not json");
    expect(await new KvApiKeyDirectoryProjection(kv).read("sha256:h")).toBeNull();
  });

  test("a shape-invalid entry reads as null (missing tenant_id)", async () => {
    const kv = new FakeKv();
    kv.store.set(keyDirectoryProjectionKey("sha256:h"), JSON.stringify({ id: "x", enabled: 1 }));
    expect(await new KvApiKeyDirectoryProjection(kv).read("sha256:h")).toBeNull();
  });

  test("delete removes the entry", async () => {
    const kv = new FakeKv();
    const p = new KvApiKeyDirectoryProjection(kv);
    await p.write("sha256:h", DIR);
    await p.delete("sha256:h");
    expect(await p.read("sha256:h")).toBeNull();
  });

  test("the 30s intent is clamped up to the KV 60s expirationTtl floor", async () => {
    const kv = new FakeKv();
    await new KvApiKeyDirectoryProjection(kv, { ttlSeconds: 30 }).write("sha256:h", DIR);
    expect(kv.puts[0]?.expirationTtl).toBe(KV_MIN_EXPIRATION_TTL_SECONDS);
    expect(kv.puts[0]?.expirationTtl).toBeGreaterThanOrEqual(60);
  });

  test("a TTL above the floor is honoured", async () => {
    const kv = new FakeKv();
    await new KvApiKeyDirectoryProjection(kv, { ttlSeconds: 120 }).write("sha256:h", DIR);
    expect(kv.puts[0]?.expirationTtl).toBe(120);
  });
});

// ---------------------------------------------------------------------------
// Read-ahead wired into D1TwoHopApiKeyDirectory
// ---------------------------------------------------------------------------

const HASH = "sha256:h";

describe("HOP-1 read-ahead over the KV projection", () => {
  test("a KV HIT serves the routing row WITHOUT the control-object RPC, then still runs HOP 2", async () => {
    // The control object would return NULL — proving the routing row came from KV.
    const control = controlDb(() => null);
    const tenant = fakeDb(() => tenantRow());
    const projection = new SpyProjection({ seed: { [HASH]: DIR } });
    const resolver = new D1TwoHopApiKeyDirectory(
      control.db,
      tenantRouter({ tenant_a: tenant.db }),
      {
        projection,
      },
    );

    const result = await resolver.resolve(HASH);

    expect(result.kind).toBe("resolved");
    // HOP 1 did NOT hit the control object…
    expect(control.count()).toBe(0);
    // …but HOP 2 (the tenant read) DID run — a KV hit is not a shortcut past it.
    expect(projection.reads).toEqual([HASH]);
  });

  test("(c) a KV-served row is still AUTHORIZED by HOP 2 — a revoked tenant row denies", async () => {
    const control = controlDb(() => null);
    const tenant = fakeDb(() => tenantRow({ revoked_at_unix: 1 }));
    const projection = new SpyProjection({ seed: { [HASH]: DIR } });
    const resolver = new D1TwoHopApiKeyDirectory(
      control.db,
      tenantRouter({ tenant_a: tenant.db }),
      {
        projection,
      },
    );

    expect(await resolver.resolve(HASH)).toEqual({ kind: "suspended", reason: "revoked" });
  });

  test("a KV-served row whose DIRECTORY lifecycle is retired denies before HOP 2", async () => {
    const control = controlDb(() => null);
    const tenant = fakeDb(() => tenantRow());
    const disabled: ApiKeyDirectoryRow = { ...DIR, enabled: 0 };
    const projection = new SpyProjection({ seed: { [HASH]: disabled } });
    const resolver = new D1TwoHopApiKeyDirectory(
      control.db,
      tenantRouter({ tenant_a: tenant.db }),
      {
        projection,
      },
    );

    expect(await resolver.resolve(HASH)).toEqual({ kind: "suspended", reason: "disabled" });
  });

  test("a KV MISS falls through to the RPC and POPULATES KV with the resolved row", async () => {
    const control = controlDb(() => DIR);
    const tenant = fakeDb(() => tenantRow());
    const projection = new SpyProjection();
    const resolver = new D1TwoHopApiKeyDirectory(
      control.db,
      tenantRouter({ tenant_a: tenant.db }),
      {
        projection,
      },
    );

    const result = await resolver.resolve(HASH);

    expect(result.kind).toBe("resolved");
    expect(control.count()).toBe(1); // the RPC ran on the miss
    expect(projection.writes).toEqual([{ keyHash: HASH, row: DIR }]);
  });

  test("(a) POSITIVE ONLY — an unknown key (no directory row) is NEVER written to KV", async () => {
    const control = controlDb(() => null); // no directory row
    const projection = new SpyProjection();
    const resolver = new D1TwoHopApiKeyDirectory(control.db, tenantRouter({}), { projection });

    expect(await resolver.resolve(HASH)).toEqual({ kind: "no_directory_row" });
    expect(projection.writes).toEqual([]); // a miss is never seeded as a hit
  });

  test("(b) a control-object OUTAGE is `unavailable` even with the projection present", async () => {
    const control = controlDb(() => {
      throw new Error("control object unreachable");
    });
    const projection = new SpyProjection(); // KV MISS for this key
    const resolver = new D1TwoHopApiKeyDirectory(control.db, tenantRouter({}), { projection });

    const result = await resolver.resolve(HASH);
    expect(result.kind).toBe("unavailable");
    // The outage was NOT rewritten into a miss/allow, and nothing was cached.
    expect(projection.writes).toEqual([]);
  });

  test("(d) a KV READ failure falls through to the authoritative RPC", async () => {
    const control = controlDb(() => DIR);
    const tenant = fakeDb(() => tenantRow());
    const projection = new SpyProjection({ throwOnRead: true });
    const resolver = new D1TwoHopApiKeyDirectory(
      control.db,
      tenantRouter({ tenant_a: tenant.db }),
      {
        projection,
      },
    );

    const result = await resolver.resolve(HASH);
    expect(result.kind).toBe("resolved");
    expect(control.count()).toBe(1); // the RPC was consulted despite the KV error
  });

  test("(d) a KV read failure does not mask a control-object outage", async () => {
    const control = controlDb(() => {
      throw new Error("down");
    });
    const projection = new SpyProjection({ throwOnRead: true });
    const resolver = new D1TwoHopApiKeyDirectory(control.db, tenantRouter({}), { projection });

    expect((await resolver.resolve(HASH)).kind).toBe("unavailable");
  });

  test("cross-tenant: a KV routing row resolves HOP 2 against ITS OWN tenant only", async () => {
    // The KV row names tenant_a. The router has BOTH tenants, and only tenant_a's
    // db holds the key row; tenant_b's would answer for a different key entirely.
    const control = controlDb(() => null);
    const dbA = fakeDb(() => tenantRow({ tenant_id: "tenant_a" }));
    const dbB = fakeDb(() => tenantRow({ id: "other", tenant_id: "tenant_b" }));
    const projection = new SpyProjection({ seed: { [HASH]: { ...DIR, tenant_id: "tenant_a" } } });
    const resolver = new D1TwoHopApiKeyDirectory(
      control.db,
      tenantRouter({ tenant_a: dbA.db, tenant_b: dbB.db }),
      { projection },
    );

    const result = await resolver.resolve(HASH);
    expect(result.kind).toBe("resolved");
    if (result.kind === "resolved") {
      expect(result.directory.tenant_id).toBe("tenant_a");
      expect(result.row.tenant_id).toBe("tenant_a");
    }
  });
});
