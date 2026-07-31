/**
 * `D1GuardrailPolicyStore` — the durable half of the guardrail policy binding.
 *
 * Run against the REAL `CONTROL_DB` binding and the REAL
 * `guardrail_policy_revisions` / `guardrail_policy_bindings` DDL from
 * `sql/d1-ts/control/0001_init_control.sql` (applied by `test/setup-d1.ts`).
 * Nothing is doubled — the CAS conflicts below are produced by a second writer
 * really losing the `WHERE generation = ?` race in SQLite, not by a mock.
 *
 * The first block is a SHARED decision table: the same assertions are run
 * against `InMemoryGuardrailPolicyStore` and `D1GuardrailPolicyStore`, so a
 * change to one that is not made to the other fails here rather than in
 * production. `test/guardrails/binding.test.ts` keeps its own, deeper in-memory
 * coverage; this file exists to hold the two implementations together.
 */
import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  type CasResult,
  D1GuardrailPolicyStore,
  type GuardrailDatabase,
  type GuardrailPolicyBinding,
  InMemoryGuardrailPolicyStore,
  guardrailDepsFromEnv,
  loadGuardrailPolicyStore,
} from "../../src/guardrails/index.js";
import type { PolicyRevision } from "@ferrogate/guardrails";
import { FINGERPRINT_SECRET_REF, secretScanPolicy } from "./fixtures.js";

const bindings = env as unknown as Record<string, unknown>;

function controlDb(): D1Database {
  const binding = bindings.CONTROL_DB as D1Database | undefined;
  if (binding === undefined) {
    throw new Error(
      "guardrail d1 tests expect the `CONTROL_DB` binding (apps/gateway/wrangler.toml).",
    );
  }
  return binding;
}

function durableStore(): D1GuardrailPolicyStore {
  return new D1GuardrailPolicyStore(controlDb() as unknown as GuardrailDatabase);
}

function revision(policyId: string, number_: number): PolicyRevision {
  const policy = secretScanPolicy({ policyId });
  policy.revision = number_;
  return policy;
}

async function resetPolicyTables(): Promise<void> {
  const db = controlDb();
  await db.batch([
    db.prepare("DELETE FROM guardrail_policy_bindings"),
    db.prepare("DELETE FROM guardrail_policy_revisions"),
  ]);
}

beforeEach(resetPolicyTables);
afterEach(resetPolicyTables);

// ---------------------------------------------------------------------------
// The shared decision table
// ---------------------------------------------------------------------------

/**
 * The two stores, behind one async facade, so a single body can drive both.
 * The in-memory methods are sync; `await` on a non-promise is a no-op, which is
 * exactly why this comparison is legible.
 */
interface StoreUnderTest {
  readonly name: string;
  put(revision: PolicyRevision): Promise<void>;
  binding(policyId: string): Promise<GuardrailPolicyBinding | undefined>;
  activate(
    policyId: string,
    revision: number,
    expectedGeneration: number,
    updatedBy: string,
  ): Promise<CasResult>;
  archive(policyId: string, expectedGeneration: number, updatedBy: string): Promise<CasResult>;
  restore(
    policyId: string,
    revision: number,
    expectedGeneration: number,
    updatedBy: string,
  ): Promise<CasResult>;
}

function inMemoryUnderTest(): StoreUnderTest {
  const store = new InMemoryGuardrailPolicyStore();
  return {
    name: "InMemoryGuardrailPolicyStore",
    put: async (r) => store.putRevision(r),
    binding: async (id) => store.getBinding(id),
    activate: async (...args) => store.activate(...args),
    archive: async (...args) => store.archive(...args),
    restore: async (...args) => store.restore(...args),
  };
}

function d1UnderTest(): StoreUnderTest {
  const store = durableStore();
  return {
    name: "D1GuardrailPolicyStore",
    put: (r) => store.putRevision(r),
    binding: (id) => store.getBinding(id),
    activate: (...args) => store.activate(...args),
    archive: (...args) => store.archive(...args),
    restore: (...args) => store.restore(...args),
  };
}

for (const build of [inMemoryUnderTest, d1UnderTest]) {
  describe(`${build().name} — the guardrail binding decision table`, () => {
    test("activate on a fresh binding uses generation 0 and bumps to 1", async () => {
      const store = build();
      await store.put(revision("p", 1));
      const result = await store.activate("p", 1, 0, "alice");
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.binding.activeRevision).toBe(1);
        expect(result.binding.generation).toBe(1);
      }
    });

    test("a stale generation is a CONFLICT, not a silent overwrite", async () => {
      const store = build();
      await store.put(revision("p", 1));
      await store.put(revision("p", 2));
      expect((await store.activate("p", 1, 0, "alice")).ok).toBe(true);
      // A concurrent writer that read generation 0 before alice committed.
      const lost = await store.activate("p", 2, 0, "bob");
      expect(lost.ok).toBe(false);
      // …and the loser changed NOTHING. A CAS that reports a conflict but has
      // already written is worse than no CAS at all.
      expect((await store.binding("p"))?.activeRevision).toBe(1);
      expect((await store.binding("p"))?.generation).toBe(1);
    });

    test("activating a revision that does not exist is refused", async () => {
      const store = build();
      await store.put(revision("p", 1));
      const result = await store.activate("p", 7, 0, "alice");
      expect(result.ok).toBe(false);
      expect((await store.binding("p"))).toBeUndefined();
    });

    test("archive retires the active revision and remembers it", async () => {
      const store = build();
      await store.put(revision("p", 1));
      await store.activate("p", 1, 0, "alice");
      const archived = await store.archive("p", 1, "alice");
      expect(archived.ok).toBe(true);
      const binding = await store.binding("p");
      expect(binding?.activeRevision).toBeNull();
      expect(binding?.archivedRevisions).toEqual([1]);
      expect(binding?.generation).toBe(2);
    });

    test("archiving with no active revision is refused", async () => {
      const store = build();
      await store.put(revision("p", 1));
      expect((await store.archive("p", 0, "alice")).ok).toBe(false);
    });

    test("restore brings an archived revision back and archives the outgoing one", async () => {
      const store = build();
      await store.put(revision("p", 1));
      await store.put(revision("p", 2));
      await store.activate("p", 1, 0, "alice");
      await store.archive("p", 1, "alice");
      await store.activate("p", 2, 2, "alice");
      const restored = await store.restore("p", 1, 3, "bob");
      expect(restored.ok).toBe(true);
      const binding = await store.binding("p");
      expect(binding?.activeRevision).toBe(1);
      expect(binding?.archivedRevisions).toEqual([2]);
      expect(binding?.updatedBy).toBe("bob");
    });

    test("restoring a revision that was never archived is refused", async () => {
      const store = build();
      await store.put(revision("p", 1));
      await store.put(revision("p", 2));
      await store.activate("p", 1, 0, "alice");
      expect((await store.restore("p", 2, 1, "bob")).ok).toBe(false);
    });

    test("revisions are immutable — the same (policy_id, revision) twice is refused", async () => {
      const store = build();
      await store.put(revision("p", 1));
      await expect(store.put(revision("p", 1))).rejects.toThrow(/immutable/);
    });

    test("an invalid revision never reaches storage", async () => {
      const store = build();
      const broken = revision("p", 1);
      broken.on_error = [];
      await expect(store.put(broken)).rejects.toThrow(/on_error/);
      expect((await store.binding("p"))).toBeUndefined();
    });
  });
}

// ---------------------------------------------------------------------------
// Durable-only behaviour
// ---------------------------------------------------------------------------

describe("D1GuardrailPolicyStore — durability", () => {
  test("a second store instance reads back what the first committed", async () => {
    // The whole point of the durable half: an isolate that did not do the write
    // still sees it. `InMemoryGuardrailPolicyStore` cannot pass this.
    await durableStore().putRevision(revision("p", 1));
    await durableStore().activate("p", 1, 0, "alice");

    const fresh = durableStore();
    expect((await fresh.getBinding("p"))?.activeRevision).toBe(1);
    expect(await fresh.listRevisions("p")).toHaveLength(1);
  });

  test("the CAS is decided by SQLite, not by the read", async () => {
    // Both writers read generation 1, then both write. The `WHERE generation =
    // ?` predicate is what makes exactly one of them land — this is the test
    // that would still pass if the pre-read were deleted, and would fail if the
    // guard were.
    await durableStore().putRevision(revision("p", 1));
    await durableStore().putRevision(revision("p", 2));
    await durableStore().activate("p", 1, 0, "alice");

    const results = await Promise.all([
      durableStore().activate("p", 2, 1, "bob"),
      durableStore().activate("p", 1, 1, "carol"),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect((await durableStore().getBinding("p"))?.generation).toBe(2);
  });

  test("a lost UPDATE race is reported as a conflict, never as success", async () => {
    // Forced rather than raced: the row is moved out from under a store that
    // has already read it, so the write matches zero rows.
    await durableStore().putRevision(revision("p", 1));
    await durableStore().putRevision(revision("p", 2));
    await durableStore().activate("p", 1, 0, "alice");

    const store = new D1GuardrailPolicyStore({
      prepare(sql: string) {
        const inner = (controlDb() as unknown as GuardrailDatabase).prepare(sql);
        if (!sql.startsWith("UPDATE")) return inner;
        return {
          bind: (...values: unknown[]) => ({
            all: async () => {
              // Somebody else commits between our read and our write.
              await durableStore().activate("p", 2, 1, "mallory");
              return inner.bind(...values).all();
            },
            run: () => inner.bind(...values).run(),
            bind: () => inner.bind(...values),
          }),
          all: () => inner.all(),
          run: () => inner.run(),
        } as never;
      },
    });

    const result = await store.activate("p", 2, 1, "bob");
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.detail).toContain("changed concurrently");
    // Mallory's write is the one that stands.
    expect((await durableStore().getBinding("p"))?.updatedBy).toBe("mallory");
  });

  test("a corrupt binding_json loses the archive list, never the active pointer", async () => {
    await durableStore().putRevision(revision("p", 1));
    await durableStore().activate("p", 1, 0, "alice");
    await controlDb()
      .prepare("UPDATE guardrail_policy_bindings SET binding_json = '{not json' WHERE policy_id = ?")
      .bind("p")
      .run();

    const binding = await durableStore().getBinding("p");
    // Taking a policy OFFLINE because a cosmetic field failed to parse would be
    // the worst possible reading of "fail closed".
    expect(binding?.activeRevision).toBe(1);
    expect(binding?.generation).toBe(1);
    expect(binding?.archivedRevisions).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The snapshot the request path compiles
// ---------------------------------------------------------------------------

describe("loadGuardrailPolicyStore", () => {
  test("projects the durable active binding into the synchronous store", async () => {
    await durableStore().putRevision(revision("durable", 1));
    await durableStore().activate("durable", 1, 0, "control_plane");

    const projected = await loadGuardrailPolicyStore(durableStore());
    expect(projected.getBinding("durable")?.activeRevision).toBe(1);
    expect(projected.listRevisions("durable")).toHaveLength(1);
  });

  test("is ADDITIVE to the config seed — a var policy survives a durable one", async () => {
    await durableStore().putRevision(revision("durable", 1));
    await durableStore().activate("durable", 1, 0, "control_plane");

    const seed = new InMemoryGuardrailPolicyStore();
    seed.putRevision(revision("from_var", 1));
    seed.activate("from_var", 1, 0, "worker_var");

    const projected = await loadGuardrailPolicyStore(durableStore(), seed);
    expect(projected.listBindings().map((b) => b.policyId).sort()).toEqual([
      "durable",
      "from_var",
    ]);
  });

  test("skips a binding whose revision text is not in the snapshot", async () => {
    // Activating a policy whose rules cannot be read back would screen with
    // rules nobody can inspect. It is dropped, never faked.
    await durableStore().putRevision(revision("p", 1));
    await durableStore().activate("p", 1, 0, "control_plane");
    await controlDb().prepare("DELETE FROM guardrail_policy_revisions").run();

    const projected = await loadGuardrailPolicyStore(durableStore());
    expect(projected.listBindings()).toEqual([]);
  });

  test("an ARCHIVED policy is not compiled", async () => {
    await durableStore().putRevision(revision("p", 1));
    await durableStore().activate("p", 1, 0, "control_plane");
    await durableStore().archive("p", 1, "control_plane");

    const projected = await loadGuardrailPolicyStore(durableStore());
    expect(projected.getBinding("p")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The mount
// ---------------------------------------------------------------------------

describe("guardrailDepsFromEnv reads the durable tables", () => {
  test("returns a PROMISE when CONTROL_DB is bound, a value when it is not", async () => {
    const withBinding = guardrailDepsFromEnv({ ...bindings });
    expect(withBinding).toBeInstanceOf(Promise);
    // Removing `D1GuardrailPolicyStore.fromEnv` from `guardrailDepsFromEnv`, or
    // the `[[d1_databases]] CONTROL_DB` block from wrangler.toml, turns this red
    // while every store test above stays green.
    const withoutBinding = guardrailDepsFromEnv({ CONTROL_DB: undefined });
    expect(withoutBinding).not.toBeInstanceOf(Promise);
  });

  test("a durably-activated policy is in the compiled source the middleware gets", async () => {
    await durableStore().putRevision(revision("durable_policy", 1));
    await durableStore().activate("durable_policy", 1, 0, "control_plane");

    const options = await guardrailDepsFromEnv({
      ...bindings,
      // The fingerprint secret the fixture policy's detector resolves.
      [FINGERPRINT_SECRET_REF]: "test-fingerprint-key",
      // Deliberately EMPTY: the policy below can only have come from D1.
      GATEWAY_GUARDRAIL_POLICIES: "[]",
    });
    const selected = options.policies.policiesFor({});
    expect(selected.map((runtime) => runtime.revision.policy_id)).toEqual(["durable_policy"]);
    expect(selected[0]?.checks.length).toBeGreaterThan(0);
  });

  test("a durable read failure REJECTS rather than screening with no policies", async () => {
    // Fail-closed: an engine compiled from a half-read policy set would pass
    // content a policy was supposed to block, with nothing in the response to
    // say so.
    const failing = {
      prepare(): never {
        throw new Error("D1_ERROR: control database is unreachable");
      },
    };
    await expect(guardrailDepsFromEnv({ CONTROL_DB: failing })).rejects.toThrow(/unreachable/);
  });
});
