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
  ALL_CONTENT_SOURCES,
  DetectorError,
  type GuardrailDetector,
  type PolicyRevision,
  type PolicySelectionContext,
  administrativeRank,
  immutableId,
  scopeMatches,
  validatePolicyRevision,
} from "@ferrogate/guardrails";
import { compilePolicyChecks } from "./detectors.js";
import type { DetectorBuildContext } from "./detectors.js";
import type {
  GuardrailCheckRuntime,
  GuardrailPolicyRuntime,
  GuardrailPolicySource,
} from "./ports.js";

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
 * In-isolate {@link GuardrailPolicyStore} — and the decision table the DURABLE
 * store obeys too.
 *
 * The durable half landed in `./d1.ts`: {@link D1GuardrailPolicyStore} over the
 * `CONTROL_DB` binding, with the CAS expressed as
 * `UPDATE guardrail_policy_bindings SET … WHERE policy_id = ? AND generation = ?
 * RETURNING policy_id` and an empty `RETURNING` set as the {@link conflict}.
 * `test/guardrails/d1.test.ts` runs BOTH stores through the same decision-table
 * assertions so the two cannot drift.
 *
 * This class did NOT become a test double. It is what the request path compiles:
 * `policySourceFromStore` is synchronous (detectors are compiled eagerly, once,
 * so a configuration error is a startup failure and a `CustomHttpDetector`'s
 * bulkhead state is shared across the isolate), and `loadGuardrailPolicyStore`
 * projects the durable snapshot into an instance of this class once per isolate.
 * That is the Workers shape of the Rust gateway rebuilding
 * `AppState.guardrail_policies` on reload rather than reading Supabase per
 * request.
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
 * A check that cannot be evaluated because its policy did not COMPILE.
 *
 * Not a placeholder and not a disabled check: it is `enabled`, it is selected,
 * and every evaluation raises `DetectorError(unavailable)`. The engine turns
 * that into `CheckOutcome::Error` → `AggregateOutcome::Error` → the revision's
 * `on_error` actions, which `validatePolicyRevision` forbids from being empty
 * and which default to `block`.
 *
 * That is what "fail this policy CLOSED" means here, and the alternative is the
 * trap: DROPPING an uncompilable policy from the source would leave the traffic
 * it fences screened by nothing at all, silently, with every suite green — the
 * fail-OPEN direction, and the exact defect class this wave is closing
 * elsewhere.
 */
function uncompilableCheck(policyId: string, detail: string): GuardrailCheckRuntime {
  const id = `${policyId}:uncompilable`;
  const detector: GuardrailDetector = {
    descriptor: () => ({
      id,
      version: "uncompilable",
      supports_request: true,
      supports_response: true,
      supports_transform: false,
      supported_sources: [...ALL_CONTENT_SOURCES],
      credential: "none",
      data_residency: "in_repo",
      max_payload_bytes: 0,
      declared_failure_modes: ["unavailable"],
    }),
    health: () => ({
      circuit_open: true,
      consecutive_failures: 1,
      in_flight: 0,
      request_total: 0,
      success_total: 0,
      failure_total: 1,
    }),
    evaluate: () =>
      Promise.reject(
        DetectorError.new(
          "unavailable",
          `guardrail policy ${policyId} could not be compiled: ${detail}`,
        ),
      ),
  };
  return {
    id,
    enabled: true,
    stage: "request",
    sources: [...ALL_CONTENT_SOURCES],
    detector,
    detectorId: "uncompilable",
    detectorConfigDigest: "uncompilable",
  };
}

export interface PolicySourceOptions {
  /**
   * Policies whose compilation failure must NOT take the boot down.
   *
   * Empty by DEFAULT, and that polarity is the whole safety of this option: an
   * uncompilable policy is a hard startup failure unless someone has named it,
   * so nothing becomes silently survivable by omission.
   *
   * `guardrails/config.ts` fills it with exactly the policy ids
   * {@link loadGuardrailPolicyStore} read out of the DURABLE control tables.
   * Those are runtime input written by another Worker; a policy declared in
   * THIS deployment's own `GATEWAY_GUARDRAIL_POLICIES` var is not, and stays a
   * hard failure — an operator who mistypes a `fingerprint_secret_ref` in their
   * deploy config must be told at boot, not left with a policy that refuses
   * every request (`test/guardrails/binding.test.ts`, "a detector whose
   * fingerprint secret does not resolve is a HARD failure").
   */
  readonly failClosedPolicyIds?: ReadonlySet<string> | undefined;
}

/**
 * Resolve every binding's ACTIVE revision, compile it once, and answer scope
 * queries from the compiled set.
 *
 * Compilation is eager at construction so a detector-configuration error
 * surfaces at startup rather than per-request, and so the semaphore + circuit
 * state inside a `CustomHttpDetector` is shared across requests in the isolate
 * (the Rust held one `Arc<dyn GuardrailDetector>` per check in `AppState`).
 *
 * ## Why the `try` is here, and why it is not a loosening
 *
 * Until wave 17 this function had no `catch`, and that was the stated reason
 * `apps/control-plane` was not allowed to project its guardrail revisions at
 * all: ONE row the gateway could not compile took the WHOLE guardrail source
 * down at boot — `guardrailDepsFromEnv` lets the throw propagate, so every
 * request answers 503, including the ones no guardrail policy applies to.
 *
 * Admission is now tightened at the source (`@ferrogate/guardrails`'
 * `admitPolicyRevision`, run by the control plane on both create operations and
 * again before an activate), so a NEW unenforceable revision cannot reach the
 * table. Two classes remain and neither is reachable from admission:
 *
 *  - rows written BEFORE the tightening;
 *  - a revision whose `secret_ref` / `fingerprint_secret_ref` is well-formed but
 *    resolves to nothing in THIS Worker's bindings. The control plane cannot see
 *    the gateway's secrets, so it can only check the ref is non-empty.
 *
 * For those — and ONLY those, see {@link PolicySourceOptions.failClosedPolicyIds}
 * — the blast radius is reduced from "the fleet" to "this policy", and the
 * policy that failed still refuses (see {@link uncompilableCheck}).
 */
export function policySourceFromStore(
  store: GuardrailPolicyStore,
  context: DetectorBuildContext = {},
  options: PolicySourceOptions = {},
): GuardrailPolicySource {
  const failClosed = options.failClosedPolicyIds;
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
    try {
      runtimes.push({ revision, checks: compilePolicyChecks(revision, context) });
    } catch (error) {
      if (failClosed === undefined || !failClosed.has(binding.policyId)) {
        throw error;
      }
      runtimes.push({
        revision,
        checks: [
          uncompilableCheck(
            binding.policyId,
            error instanceof Error ? error.message : String(error),
          ),
        ],
      });
    }
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
