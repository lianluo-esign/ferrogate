import { beforeEach, describe, expect, test } from "vitest";
import {
  GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE,
  MemoryGuardrailBindingStore,
  StorageError,
  type StoredGuardrailPolicyRevision,
  isGuardrailPolicyBindingCasConflict,
} from "../src/index.js";

function rev(policyId: string, revision: number): StoredGuardrailPolicyRevision {
  return {
    id: `${policyId}@${revision}`,
    policyId,
    revision,
    policyJson: "{}",
    createdAtUnix: 0,
    createdBy: "tester",
  };
}

describe("MemoryGuardrailBindingStore — generation-guarded CAS (§1.5.5)", () => {
  let store: MemoryGuardrailBindingStore;
  beforeEach(() => {
    store = new MemoryGuardrailBindingStore();
    store.upsertRevision(rev("p", 1));
    store.upsertRevision(rev("p", 2));
  });

  test("activating a revision bumps generation and archives the prior active", () => {
    const first = store.activateGuardrailPolicyRevision("p", 1, "u", 10, false);
    expect(first.current.activeRevision).toBe(1);
    expect(first.current.generation).toBe(1);
    const second = store.activateGuardrailPolicyRevision("p", 2, "u", 20, false);
    expect(second.current.activeRevision).toBe(2);
    expect(second.current.archivedRevisions).toContain(1);
    expect(second.current.generation).toBe(2);
  });

  test("activating an unknown revision is not_found", () => {
    expect(() => store.activateGuardrailPolicyRevision("p", 99, "u", 0, false)).toThrowError(
      StorageError,
    );
  });

  test("the ACTIVE revision cannot be archived", () => {
    store.activateGuardrailPolicyRevision("p", 1, "u", 0, false);
    expect(() => store.archiveGuardrailPolicyRevision("p", 1, "u", 1)).toThrowError(StorageError);
  });

  test("rollbackOnly requires the revision to already be archived", () => {
    store.activateGuardrailPolicyRevision("p", 1, "u", 0, false); // 1 active
    store.activateGuardrailPolicyRevision("p", 2, "u", 1, false); // 2 active, 1 archived
    // rollback to the archived 1 is allowed:
    expect(store.activateGuardrailPolicyRevision("p", 1, "u", 2, true).current.activeRevision).toBe(
      1,
    );
  });

  test("restore fails closed when the generation moved since read (CAS conflict)", () => {
    const t = store.activateGuardrailPolicyRevision("p", 1, "u", 0, false); // generation now 1
    try {
      // caller thinks generation is still 0 → lost update
      store.restoreGuardrailPolicyBinding("p", 0, t.current);
      throw new Error("expected conflict");
    } catch (err) {
      expect(isGuardrailPolicyBindingCasConflict(err)).toBe(true);
      expect((err as StorageError).data.detail).toBe(GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE);
    }
  });

  test("restore with the matching generation lands and bumps generation", () => {
    const t = store.activateGuardrailPolicyRevision("p", 1, "u", 0, false); // generation 1
    store.restoreGuardrailPolicyBinding("p", 1, { ...t.current });
    expect(store.getBinding("p")?.generation).toBe(2);
  });
});
