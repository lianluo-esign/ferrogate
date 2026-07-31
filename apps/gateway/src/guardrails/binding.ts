/**
 * The guardrail POLICY BINDING — which revision of a policy is live, and the
 * generation-guarded compare-and-swap that moves it.
 *
 * Clean-room port of the two Rust tables
 * (`docs/legacy/inventory-data-billing.md` §"guardrail_policy_revisions" /
 * §"guardrail_policy_bindings", and atomicity rule 5):
 *
 * - `guardrail_policy_revisions` — `PK(policy_id, revision CHECK>0)`,
 *   `immutable_id UNIQUE`, `policy_json`. **Immutable content.** A revision is
 *   never edited; a change is a new revision.
 * - `guardrail_policy_bindings` — `policy_id PK, active_revision?,
 *   archived_revisions_json, updated_by, generation BIGINT CHECK>=0`. The single
 *   MUTABLE row. `activate`/`archive`/`restore` are
 *   `UPDATE/INSERT/DELETE ... WHERE generation = ? ... RETURNING policy_id`;
 *   an empty RETURNING is a lost update and surfaces as a typed CAS
 *   `Conflict` (`GUARDRAIL_POLICY_BINDING_{INSERT,UPDATE,DELETE}_CAS_SQL`).
 *
 * D1 is SQLite and has no `SELECT ... FOR UPDATE`, so the generation guard is
 * not an optimization here — it IS the concurrency control. This module keeps
 * the algorithm in pure TS behind {@link GuardrailPolicyStore} so the D1-backed
 * implementation is a one-method swap and the CAS semantics stay testable
 * offline.
 *
 * Reading the binding is what turns "the tenant/key on this request" into "the
 * policies to evaluate": {@link defaultPolicySource} resolves each binding's
 * `active_revision`, compiles its checks once, and hands the engine the subset
 * whose `scope` matches — in `selectPolicyRevisions` order.
 */
import {
  type PolicyRevision,
  type PolicySelectionContext,
  administrativeRank,
  immutableId,
  scopeMatches,
  validatePolicyRevision,
} from "@ferrogate/guardrails";
import { compilePolicyChecks } from "./detectors.js";
import type { DetectorBuildContext } from "./detectors.js";
import type { GuardrailPolicyRuntime, GuardrailPolicySource } from "./ports.js";

/** The single mutable pointer row. */
export interface GuardrailPolicyBinding {
  readonly policyId: string;
  /** `null` when the policy has no live revision (never activated / archived). */
  readonly activeRevision: number | null;
  readonly archivedRevisions: readonly number[];
  readonly updatedBy: string;
  /** Monotonic CAS token. `>= 0`; incremented on every successful write. */
  readonly generation: number;
}

/** `Result<_, StorageError::Conflict>` for the three binding mutations. */
export type CasResult =
  | { readonly ok: true; readonly binding: GuardrailPolicyBinding }
  | { readonly ok: false; readonly conflict: true; readonly detail: string };

function conflict(detail: string): CasResult {
  return { ok: false, conflict: true, detail };
}

/** Revision store + binding store. `activate`/`archive`/`restore` are CAS. */
export interface GuardrailPolicyStore {
  /** Append an immutable revision. Rejects a duplicate `(policy_id, revision)`. */
  putRevision(revision: PolicyRevision): void;
  listRevisions(policyId: string): readonly PolicyRevision[];
  getBinding(policyId: string): GuardrailPolicyBinding | undefined;
  listBindings(): readonly GuardrailPolicyBinding[];
  /** Point the binding at `revision`, guarded on `expectedGeneration`. */
  activate(
    policyId: string,
    revision: number,
    expectedGeneration: number,
    updatedBy: string,
  ): CasResult;
  /** Retire the active revision (binding keeps existing, `active_revision` null). */
  archive(policyId: string, expectedGeneration: number, updatedBy: string): CasResult;
  /** Bring an archived revision back to active. */
  restore(
    policyId: string,
    revision: number,
    expectedGeneration: number,
    updatedBy: string,
  ): CasResult;
}

/**
 * In-isolate {@link GuardrailPolicyStore}.
 *
 * PORT-TODO(inventory-data-billing §"Guardrail binding CAS"): the durable
 * implementation is D1 — `UPDATE guardrail_policy_bindings SET ... WHERE
 * policy_id = ? AND generation = ? RETURNING policy_id`, empty result ⇒
 * {@link conflict}. The algorithm below is byte-for-byte the same decision
 * table so the swap is mechanical; a Worker isolate is not a durability
 * boundary, so this variant is for config-driven policies and tests.
 *
 * NOT a platform limit, and no longer blocked on a schema. As of this wave the
 * two tables EXIST (`guardrail_policy_revisions` / `guardrail_policy_bindings`,
 * `sql/d1-ts/control/0001_init_control.sql` — the CONTROL database, which this
 * Worker already binds as `BILLING_DB`), and `@ferrogate/storage` already ships
 * the shared pure transition builders + the CAS conflict predicate
 * (`nextGuardrailActivationBinding`, `nextGuardrailArchiveBinding`,
 * `isGuardrailPolicyBindingCasConflict`). What is missing is exactly one class,
 * `D1GuardrailPolicyStore implements GuardrailPolicyStore`, and the composition
 * line that passes the binding — and the binding is named for metering today, so
 * landing this should introduce a purpose-named `CONTROL_DB` alias in
 * `wrangler.toml` rather than reading guardrail policy out of `BILLING_DB`.
 */
export class InMemoryGuardrailPolicyStore implements GuardrailPolicyStore {
  readonly #revisions = new Map<string, PolicyRevision>();
  readonly #bindings = new Map<string, GuardrailPolicyBinding>();

  putRevision(revision: PolicyRevision): void {
    validatePolicyRevision(revision);
    const key = immutableId(revision);
    if (this.#revisions.has(key)) {
      throw new Error(`guardrail policy revision ${key} already exists (revisions are immutable)`);
    }
    this.#revisions.set(key, revision);
  }

  listRevisions(policyId: string): readonly PolicyRevision[] {
    return [...this.#revisions.values()]
      .filter((r) => r.policy_id === policyId)
      .sort((a, b) => a.revision - b.revision);
  }

  revision(policyId: string, revision: number): PolicyRevision | undefined {
    return this.#revisions.get(`${policyId}@${revision}`);
  }

  getBinding(policyId: string): GuardrailPolicyBinding | undefined {
    return this.#bindings.get(policyId);
  }

  listBindings(): readonly GuardrailPolicyBinding[] {
    return [...this.#bindings.values()].sort((a, b) => (a.policyId < b.policyId ? -1 : 1));
  }

  #cas(
    policyId: string,
    expectedGeneration: number,
    next: (current: GuardrailPolicyBinding) => GuardrailPolicyBinding | { error: string },
  ): CasResult {
    const current = this.#bindings.get(policyId) ?? {
      policyId,
      activeRevision: null,
      archivedRevisions: [],
      updatedBy: "",
      // A binding that does not exist yet is generation 0 — the INSERT CAS.
      generation: 0,
    };
    if (current.generation !== expectedGeneration) {
      return conflict(
        `guardrail policy binding ${policyId} generation is ${current.generation}, not ${expectedGeneration}`,
      );
    }
    const proposed = next(current);
    if ("error" in proposed) {
      return conflict(proposed.error);
    }
    const committed: GuardrailPolicyBinding = {
      ...proposed,
      generation: current.generation + 1,
    };
    this.#bindings.set(policyId, committed);
    return { ok: true, binding: committed };
  }

  activate(
    policyId: string,
    revision: number,
    expectedGeneration: number,
    updatedBy: string,
  ): CasResult {
    return this.#cas(policyId, expectedGeneration, (current) => {
      if (this.revision(policyId, revision) === undefined) {
        return { error: `guardrail policy revision ${policyId}@${revision} does not exist` };
      }
      return {
        policyId,
        activeRevision: revision,
        archivedRevisions: current.archivedRevisions.filter((r) => r !== revision),
        updatedBy,
        generation: current.generation,
      };
    });
  }

  archive(policyId: string, expectedGeneration: number, updatedBy: string): CasResult {
    return this.#cas(policyId, expectedGeneration, (current) => {
      if (current.activeRevision === null) {
        return { error: `guardrail policy ${policyId} has no active revision to archive` };
      }
      return {
        policyId,
        activeRevision: null,
        archivedRevisions: [...current.archivedRevisions, current.activeRevision].sort(
          (a, b) => a - b,
        ),
        updatedBy,
        generation: current.generation,
      };
    });
  }

  restore(
    policyId: string,
    revision: number,
    expectedGeneration: number,
    updatedBy: string,
  ): CasResult {
    return this.#cas(policyId, expectedGeneration, (current) => {
      if (!current.archivedRevisions.includes(revision)) {
        return { error: `guardrail policy revision ${policyId}@${revision} is not archived` };
      }
      const archived = current.archivedRevisions.filter((r) => r !== revision);
      if (current.activeRevision !== null) {
        archived.push(current.activeRevision);
        archived.sort((a, b) => a - b);
      }
      return {
        policyId,
        activeRevision: revision,
        archivedRevisions: archived,
        updatedBy,
        generation: current.generation,
      };
    });
  }
}

// ---------------------------------------------------------------------------
// Store -> GuardrailPolicySource
// ---------------------------------------------------------------------------

/**
 * Resolve every binding's ACTIVE revision, compile it once, and answer scope
 * queries from the compiled set.
 *
 * Compilation is done eagerly at construction so a detector-configuration error
 * is a startup failure, not a per-request one, and so the semaphore + circuit
 * state inside a `CustomHttpDetector` is shared across requests in the isolate
 * (the Rust held one `Arc<dyn GuardrailDetector>` per check in `AppState`).
 */
export function policySourceFromStore(
  store: GuardrailPolicyStore,
  context: DetectorBuildContext = {},
): GuardrailPolicySource {
  const runtimes: GuardrailPolicyRuntime[] = [];
  for (const binding of store.listBindings()) {
    if (binding.activeRevision === null) {
      continue;
    }
    const revision = store
      .listRevisions(binding.policyId)
      .find((r) => r.revision === binding.activeRevision);
    if (revision === undefined) {
      continue;
    }
    runtimes.push({ revision, checks: compilePolicyChecks(revision, context) });
  }
  return policySourceFromRuntimes(runtimes);
}

/** A {@link GuardrailPolicySource} over an already-compiled set. */
export function policySourceFromRuntimes(
  runtimes: readonly GuardrailPolicyRuntime[],
): GuardrailPolicySource {
  // `selectPolicyRevisions` order: (administrative_rank, policy_id, revision).
  const ordered = [...runtimes].sort((a, b) => {
    const rank = administrativeRank(a.revision.scope) - administrativeRank(b.revision.scope);
    if (rank !== 0) {
      return rank;
    }
    if (a.revision.policy_id !== b.revision.policy_id) {
      return a.revision.policy_id < b.revision.policy_id ? -1 : 1;
    }
    return a.revision.revision - b.revision.revision;
  });
  return {
    policiesFor(selection: PolicySelectionContext): readonly GuardrailPolicyRuntime[] {
      return ordered.filter((runtime) => scopeMatches(runtime.revision.scope, selection));
    },
  };
}

/** A source with no policies — guardrails configured off. */
export const emptyPolicySource: GuardrailPolicySource = {
  policiesFor: () => [],
};
