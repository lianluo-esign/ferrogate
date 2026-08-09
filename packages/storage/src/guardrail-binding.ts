/**
 * Guardrail policy revisions (immutable) + the single mutable binding pointer
 * with generation-guarded CAS (ports the guardrail surface from
 * `ferrogate-storage::lib`).
 *
 * Correctness proof (inventory §1.5.5): `activate` / `archive` / `restore` are
 * compare-and-swaps on the one `guardrail_policy_bindings` row, guarded by a
 * monotonic `generation`. A lost update (generation moved since read) surfaces as
 * a typed CAS conflict. The pure transition builders below are shared verbatim by
 * every backend so their truth tables cannot drift.
 */
import { StorageError } from "./errors.js";
import { guardrailPolicyRevisionId } from "./ids.js";

/** The exact conflict message that marks a guardrail-binding CAS loss. */
export const GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE =
  "guardrail policy binding changed concurrently";

/** Whether an error is the guardrail-binding CAS conflict (ports the Rust helper). */
export function isGuardrailPolicyBindingCasConflict(error: unknown): boolean {
  return (
    error instanceof StorageError &&
    error.kind === "conflict" &&
    error.data.detail === GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE
  );
}

export interface StoredGuardrailPolicyRevision {
  id: string;
  policyId: string;
  revision: number;
  policyJson: string;
  createdAtUnix: number;
  createdBy: string;
}

export interface StoredGuardrailPolicyBinding {
  policyId: string;
  activeRevision?: number;
  archivedRevisions: number[];
  updatedAtUnix: number;
  updatedBy: string;
  generation: number;
}

export interface GuardrailPolicyBindingTransition {
  previous?: StoredGuardrailPolicyBinding;
  current: StoredGuardrailPolicyBinding;
}

/** Next generation, guarding against overflow (ports `next_guardrail_binding_generation`). */
export function nextGuardrailBindingGeneration(generation: number): number {
  const next = generation + 1;
  if (!Number.isSafeInteger(next)) {
    throw StorageError.serialization("guardrail policy binding generation is exhausted");
  }
  return next;
}

/**
 * Build the binding that results from activating `revision` (ports
 * `next_guardrail_activation_binding`). The currently-active revision (if any and
 * distinct) is pushed to `archivedRevisions`; the newly-active one is removed
 * from the archive; `rollbackOnly` requires the revision to already be archived.
 */
export function nextGuardrailActivationBinding(
  previous: StoredGuardrailPolicyBinding | undefined,
  policyId: string,
  revision: number,
  updatedBy: string,
  updatedAtUnix: number,
  rollbackOnly: boolean,
): StoredGuardrailPolicyBinding {
  if (rollbackOnly && !previous?.archivedRevisions.includes(revision)) {
    throw StorageError.conflict(
      `guardrail policy revision ${guardrailPolicyRevisionId(policyId, revision)} is not archived and cannot be rolled back`,
    );
  }
  let archived = previous ? [...previous.archivedRevisions] : [];
  const activeRevision = previous?.activeRevision;
  if (
    activeRevision !== undefined &&
    activeRevision !== revision &&
    !archived.includes(activeRevision)
  ) {
    archived.push(activeRevision);
  }
  archived = archived.filter((r) => r !== revision);
  archived = dedupSorted(archived);
  return {
    policyId,
    activeRevision: revision,
    archivedRevisions: archived,
    updatedAtUnix,
    updatedBy,
    generation: nextGuardrailBindingGeneration(previous?.generation ?? 0),
  };
}

/**
 * Build the binding that results from archiving `revision` (ports
 * `next_guardrail_archive_binding`). The ACTIVE revision cannot be archived
 * (conflict); the active pointer is otherwise unchanged.
 */
export function nextGuardrailArchiveBinding(
  previous: StoredGuardrailPolicyBinding | undefined,
  policyId: string,
  revision: number,
  updatedBy: string,
  updatedAtUnix: number,
): StoredGuardrailPolicyBinding {
  if (previous?.activeRevision === revision) {
    throw StorageError.conflict(
      `active guardrail policy revision ${guardrailPolicyRevisionId(policyId, revision)} cannot be archived`,
    );
  }
  let archived = previous ? [...previous.archivedRevisions] : [];
  if (!archived.includes(revision)) archived.push(revision);
  archived = dedupSorted(archived);
  return {
    policyId,
    activeRevision: previous?.activeRevision,
    archivedRevisions: archived,
    updatedAtUnix,
    updatedBy,
    generation: nextGuardrailBindingGeneration(previous?.generation ?? 0),
  };
}

function dedupSorted(values: number[]): number[] {
  return [...new Set(values)].sort((a, b) => a - b);
}

/** Reference in-memory backend for guardrail revisions + the generation-guarded binding. */
export class MemoryGuardrailBindingStore {
  private readonly revisions = new Map<string, StoredGuardrailPolicyRevision>();
  private readonly bindings = new Map<string, StoredGuardrailPolicyBinding>();

  upsertRevision(revision: StoredGuardrailPolicyRevision): void {
    this.revisions.set(revision.id, { ...revision });
  }

  getRevision(policyId: string, revision: number): StoredGuardrailPolicyRevision | undefined {
    const r = this.revisions.get(guardrailPolicyRevisionId(policyId, revision));
    return r ? { ...r } : undefined;
  }

  getBinding(policyId: string): StoredGuardrailPolicyBinding | undefined {
    const b = this.bindings.get(policyId);
    return b ? cloneBinding(b) : undefined;
  }

  listBindings(): StoredGuardrailPolicyBinding[] {
    return [...this.bindings.values()]
      .map(cloneBinding)
      .sort((a, b) => a.policyId.localeCompare(b.policyId));
  }

  activateGuardrailPolicyRevision(
    policyId: string,
    revision: number,
    updatedBy: string,
    updatedAtUnix: number,
    rollbackOnly: boolean,
  ): GuardrailPolicyBindingTransition {
    if (!this.getRevision(policyId, revision)) {
      throw StorageError.notFound(
        `guardrail policy revision ${guardrailPolicyRevisionId(policyId, revision)}`,
      );
    }
    const previous = this.getBinding(policyId);
    const current = nextGuardrailActivationBinding(
      previous,
      policyId,
      revision,
      updatedBy,
      updatedAtUnix,
      rollbackOnly,
    );
    this.bindings.set(policyId, cloneBinding(current));
    return { previous, current };
  }

  archiveGuardrailPolicyRevision(
    policyId: string,
    revision: number,
    updatedBy: string,
    updatedAtUnix: number,
  ): GuardrailPolicyBindingTransition {
    if (!this.getRevision(policyId, revision)) {
      throw StorageError.notFound(
        `guardrail policy revision ${guardrailPolicyRevisionId(policyId, revision)}`,
      );
    }
    const previous = this.getBinding(policyId);
    const current = nextGuardrailArchiveBinding(
      previous,
      policyId,
      revision,
      updatedBy,
      updatedAtUnix,
    );
    this.bindings.set(policyId, cloneBinding(current));
    return { previous, current };
  }

  /**
   * Generation-guarded restore/rollback of the whole binding row (ports
   * `restore_guardrail_policy_binding`): the write lands only if the current
   * generation equals `expectedGeneration`, else a CAS conflict. `binding`
   * undefined deletes the row.
   */
  restoreGuardrailPolicyBinding(
    policyId: string,
    expectedGeneration: number | undefined,
    binding: StoredGuardrailPolicyBinding | undefined,
  ): void {
    const currentGeneration = this.bindings.get(policyId)?.generation;
    if (currentGeneration !== expectedGeneration) {
      throw StorageError.conflict(GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE);
    }
    if (binding) {
      const stored = cloneBinding(binding);
      stored.generation = nextGuardrailBindingGeneration(expectedGeneration ?? 0);
      this.bindings.set(policyId, stored);
    } else {
      this.bindings.delete(policyId);
    }
  }
}

function cloneBinding(b: StoredGuardrailPolicyBinding): StoredGuardrailPolicyBinding {
  return { ...b, archivedRevisions: [...b.archivedRevisions] };
}
