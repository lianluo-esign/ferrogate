/**
 * The policy binding and its generation-guarded CAS.
 *
 * `docs/legacy/inventory-data-billing.md` atomicity rule 5: `activate`/
 * `archive`/`restore` are `UPDATE ... WHERE generation = ? ... RETURNING
 * policy_id` on the single mutable `guardrail_policy_bindings` row; an empty
 * RETURNING is a lost update and must surface as a typed `Conflict`. D1 has no
 * `SELECT ... FOR UPDATE`, so this guard IS the concurrency control.
 */
import { describe, expect, test } from "vitest";
import {
  InMemoryGuardrailPolicyStore,
  guardrailPolicySourceFromEnv,
  policySourceFromStore,
} from "../../src/guardrails/index.js";
import { FINGERPRINT_SECRET_REF, TEST_SECRETS, secretScanPolicy } from "./fixtures.js";

function storeWithTwoRevisions(): InMemoryGuardrailPolicyStore {
  const store = new InMemoryGuardrailPolicyStore();
  store.putRevision(secretScanPolicy({ policyId: "p" }));
  const second = secretScanPolicy({ policyId: "p" });
  second.revision = 2;
  store.putRevision(second);
  return store;
}

describe("revisions are immutable", () => {
  test("re-putting the same (policy_id, revision) is refused", () => {
    const store = new InMemoryGuardrailPolicyStore();
    store.putRevision(secretScanPolicy({ policyId: "p" }));
    expect(() => store.putRevision(secretScanPolicy({ policyId: "p" }))).toThrow(
      /revisions are immutable/,
    );
  });

  test("an invalid revision is refused at write time", () => {
    const store = new InMemoryGuardrailPolicyStore();
    const broken = secretScanPolicy({ policyId: "p" });
    broken.on_error = [];
    expect(() => store.putRevision(broken)).toThrow(/on_error/);
  });
});

describe("generation-guarded CAS", () => {
  test("activate on a fresh binding uses generation 0 and bumps to 1", () => {
    const store = storeWithTwoRevisions();
    const result = store.activate("p", 1, 0, "alice");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.binding.activeRevision).toBe(1);
      expect(result.binding.generation).toBe(1);
    }
  });

  test("a stale generation is a CONFLICT, not a silent overwrite", () => {
    const store = storeWithTwoRevisions();
    expect(store.activate("p", 1, 0, "alice").ok).toBe(true);
    // A concurrent writer that read generation 0 before alice committed.
    const lost = store.activate("p", 2, 0, "bob");
    expect(lost.ok).toBe(false);
    expect(store.getBinding("p")?.activeRevision).toBe(1);
  });

  test("the winner of a concurrent activate/archive race is the one holding the generation", () => {
    const store = storeWithTwoRevisions();
    store.activate("p", 1, 0, "alice");
    const generation = store.getBinding("p")?.generation ?? -1;
    expect(store.archive("p", generation, "alice").ok).toBe(true);
    // bob still holds the pre-archive generation.
    expect(store.activate("p", 2, generation, "bob").ok).toBe(false);
    expect(store.getBinding("p")?.activeRevision).toBeNull();
  });

  test("archive moves the active revision to the archived set", () => {
    const store = storeWithTwoRevisions();
    store.activate("p", 1, 0, "alice");
    const archived = store.archive("p", 1, "alice");
    expect(archived.ok).toBe(true);
    if (archived.ok) {
      expect(archived.binding.activeRevision).toBeNull();
      expect(archived.binding.archivedRevisions).toEqual([1]);
    }
  });

  test("restore brings an archived revision back and archives the incumbent", () => {
    const store = storeWithTwoRevisions();
    store.activate("p", 1, 0, "alice");
    store.archive("p", 1, "alice");
    store.activate("p", 2, 2, "alice");
    const restored = store.restore("p", 1, 3, "alice");
    expect(restored.ok).toBe(true);
    if (restored.ok) {
      expect(restored.binding.activeRevision).toBe(1);
      expect(restored.binding.archivedRevisions).toEqual([2]);
    }
  });

  test("activating a revision that does not exist is refused", () => {
    const store = storeWithTwoRevisions();
    expect(store.activate("p", 99, 0, "alice").ok).toBe(false);
  });

  test("restoring a revision that was never archived is refused", () => {
    const store = storeWithTwoRevisions();
    store.activate("p", 1, 0, "alice");
    expect(store.restore("p", 2, 1, "alice").ok).toBe(false);
  });
});

describe("binding -> policy source", () => {
  test("only the ACTIVE revision is evaluated", () => {
    const store = storeWithTwoRevisions();
    store.activate("p", 2, 0, "alice");
    const source = policySourceFromStore(store, { secrets: TEST_SECRETS });
    const selected = source.policiesFor({ organization_id: "tenant_a" });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.revision.revision).toBe(2);
  });

  test("an archived policy evaluates nothing", () => {
    const store = storeWithTwoRevisions();
    store.activate("p", 1, 0, "alice");
    store.archive("p", 1, "alice");
    const source = policySourceFromStore(store, { secrets: TEST_SECRETS });
    expect(source.policiesFor({ organization_id: "tenant_a" })).toHaveLength(0);
  });

  test("scope selection filters by tenant", () => {
    const store = new InMemoryGuardrailPolicyStore();
    store.putRevision(
      secretScanPolicy({ policyId: "scoped", scope: { organization_ids: ["tenant_b"] } }),
    );
    store.activate("scoped", 1, 0, "alice");
    const source = policySourceFromStore(store, { secrets: TEST_SECRETS });
    expect(source.policiesFor({ organization_id: "tenant_a" })).toHaveLength(0);
    expect(source.policiesFor({ organization_id: "tenant_b" })).toHaveLength(1);
  });
});

describe("worker-var configuration", () => {
  const env = () => ({
    GATEWAY_GUARDRAIL_POLICIES: JSON.stringify([secretScanPolicy({ policyId: "from-var" })]),
    [FINGERPRINT_SECRET_REF]: "test-fingerprint-key",
  });

  test("policies declared in the var are active by default", () => {
    const source = guardrailPolicySourceFromEnv(env());
    expect(source.policiesFor({ organization_id: "tenant_a" })).toHaveLength(1);
  });

  test("an explicit binding var selects which revision is live", () => {
    const source = guardrailPolicySourceFromEnv({
      ...env(),
      GATEWAY_GUARDRAIL_BINDINGS: JSON.stringify([{ policy_id: "from-var", active_revision: 1 }]),
    });
    expect(source.policiesFor({ organization_id: "tenant_a" })).toHaveLength(1);
  });

  test("no policy var means no policies at all", () => {
    expect(guardrailPolicySourceFromEnv({}).policiesFor({})).toHaveLength(0);
  });

  test("a malformed policy document is a HARD failure, never a silent skip", () => {
    expect(() => guardrailPolicySourceFromEnv({ GATEWAY_GUARDRAIL_POLICIES: "{not json" })).toThrow(
      /not valid JSON/,
    );
    expect(() =>
      guardrailPolicySourceFromEnv({
        GATEWAY_GUARDRAIL_POLICIES: JSON.stringify([{ name: "missing everything" }]),
      }),
    ).toThrow();
  });

  test("a detector whose fingerprint secret does not resolve is a HARD failure", () => {
    // An unresolved key would otherwise mean UNKEYED (reversible) evidence
    // fingerprints — inventory appendix §2 forbids that.
    expect(() =>
      guardrailPolicySourceFromEnv({
        GATEWAY_GUARDRAIL_POLICIES: JSON.stringify([secretScanPolicy({ policyId: "p" })]),
      }),
    ).toThrow(/did not resolve/);
  });
});
