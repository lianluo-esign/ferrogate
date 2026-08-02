/**
 * The WRITE half of `guardrail_policy` — the two TYPED tables the data plane
 * actually enforces from.
 *
 * ## What this closes
 *
 * `apps/gateway` resolves the guardrail policies it applies from
 * `guardrail_policy_revisions(policy_id, revision, immutable_id, created_by,
 * revision_json)` and `guardrail_policy_bindings(policy_id, active_revision,
 * generation, binding_json)` in the CONTROL database
 * (`apps/gateway/src/guardrails/d1.ts::D1GuardrailPolicyStore`, projected into
 * the request path by `loadGuardrailPolicyStore` +
 * `policySourceFromStore`). **No TypeScript in this repo wrote either table.**
 * All ten `guardrail_policy` operations stored a `control_plane_resources`
 * document and stopped, so `POST /admin/v1/guardrail-policies` +
 * `POST …/activate` produced a complete, audited, RBAC-gated revision history
 * that **no request was ever evaluated against**, and `…/rollback` moved a
 * pointer the gateway does not read.
 *
 * Same defect class as the RBAC write half and the self-hosted-worker registry:
 * the reader mounted, the data path into it absent, both sides green because
 * each was tested against its own fixture.
 *
 * ## Why the SQL is restated here rather than imported
 *
 * `apps/control-plane` and `apps/gateway` are sibling workspaces; neither
 * depends on the other, and adding a dependency between two composition roots
 * to share four statements would be worse than the duplication. Every statement
 * below is a verbatim copy of its twin in `apps/gateway/src/guardrails/d1.ts`
 * and is named after it. The join that keeps them honest is behavioural, not
 * textual: `apps/control-plane/test/guardrail-write-half.test.ts` reads the rows
 * back with the GATEWAY's own `SELECT`s and re-validates `revision_json` with
 * the same `@ferrogate/guardrails` calls the gateway's `putRevision` makes,
 * and `apps/gateway/test/guardrails/control-plane-projection.test.ts` proves
 * rows of that shape compile and block a request.
 *
 * ## The CAS is the concurrency control, not an optimization
 *
 * D1 is SQLite: no `SELECT … FOR UPDATE`, and a Worker cannot hold a
 * transaction across an `await`. Every binding mutation is read-then-guarded-
 * write on `WHERE policy_id = ? AND generation = ?`, and an EMPTY `RETURNING`
 * set is a lost update, reported as a typed conflict and never silently
 * re-based. That is the same guard `apps/gateway`'s store uses, so two racing
 * activations — one from each Worker — cannot both win.
 *
 * ## Ordering: which leg goes first, and why it is the OPPOSITE of RBAC
 *
 * A tenant-role binding is a GRANT: the typed row must land LAST on create and
 * FIRST on delete, so a crash leaves the caller with LESS access. A guardrail
 * binding is the inverse — it is a RESTRICTION, and the failure that matters is
 * an operator being told content is screened when it is not.
 *
 * | operation | first | second | residue after a crash between them |
 * |---|---|---|---|
 * | create revision | document | typed revision row | a revision the operator can see that cannot yet be activated; `activate` re-projects it, so it self-heals |
 * | activate / rollback | typed BINDING row | document | guardrails enforcing a revision the document does not yet show as active — over-enforcement, visible as denials |
 * | archive the ACTIVE revision | document | clear the binding | archived in the document, still enforcing — over-enforcement again |
 *
 * Both residues over-enforce. Neither leaves an operator believing content is
 * screened while it is not, which is the only direction that is not survivable.
 */
import { type PolicyRevision, immutableId } from "@ferrogate/guardrails";

/** The two typed tables. `sql/d1-ts/control/0001_init_control.sql`. */
export const GUARDRAIL_REVISIONS_TABLE = "guardrail_policy_revisions";
export const GUARDRAIL_BINDINGS_TABLE = "guardrail_policy_bindings";

// ---------------------------------------------------------------------------
// SQL — verbatim twins of `apps/gateway/src/guardrails/d1.ts`
// ---------------------------------------------------------------------------

/**
 * Revisions are IMMUTABLE. `DO NOTHING` + an empty `RETURNING` detects a
 * duplicate `(policy_id, revision)` without a read-then-write race; an
 * `INSERT OR REPLACE` here would silently rewrite history.
 */
export const GUARDRAIL_REVISION_INSERT_SQL =
  `INSERT INTO ${GUARDRAIL_REVISIONS_TABLE} ` +
  "(policy_id, revision, immutable_id, created_at_unix, created_by, revision_json) " +
  "VALUES (?1, ?2, ?3, ?4, ?5, ?6) " +
  "ON CONFLICT (policy_id, revision) DO NOTHING " +
  "RETURNING policy_id";

export const GUARDRAIL_BINDING_SELECT_SQL =
  "SELECT policy_id, active_revision, generation, binding_json " +
  `FROM ${GUARDRAIL_BINDINGS_TABLE} WHERE policy_id = ?1`;

/** The INSERT arm of the CAS: only when no row exists yet (generation 0). */
export const GUARDRAIL_BINDING_INSERT_CAS_SQL =
  `INSERT INTO ${GUARDRAIL_BINDINGS_TABLE} ` +
  "(policy_id, active_revision, updated_at_unix, generation, binding_json) " +
  "SELECT ?1, ?2, ?3, ?4, ?5 " +
  `WHERE NOT EXISTS (SELECT 1 FROM ${GUARDRAIL_BINDINGS_TABLE} WHERE policy_id = ?1) ` +
  "RETURNING policy_id";

/** The UPDATE arm of the CAS. An empty `RETURNING` set is the lost update. */
export const GUARDRAIL_BINDING_UPDATE_CAS_SQL =
  `UPDATE ${GUARDRAIL_BINDINGS_TABLE} ` +
  "SET active_revision = ?2, updated_at_unix = ?3, generation = ?4, binding_json = ?5 " +
  "WHERE policy_id = ?1 AND generation = ?6 " +
  "RETURNING policy_id";

// ---------------------------------------------------------------------------
// Revisions
// ---------------------------------------------------------------------------

/**
 * Append the immutable revision row the gateway compiles.
 *
 * IDEMPOTENT by design: a conflicting `(policy_id, revision)` is the SAME
 * immutable revision (the pair is the `immutable_id`), so `DO NOTHING` is not a
 * lost write, it is a re-projection. That is what lets `activate` repair a
 * revision whose document write succeeded and whose typed row did not.
 */
export async function projectGuardrailRevision(
  db: D1Database,
  revision: PolicyRevision,
  nowUnix: number,
): Promise<void> {
  await db
    .prepare(GUARDRAIL_REVISION_INSERT_SQL)
    .bind(
      revision.policy_id,
      revision.revision,
      immutableId(revision),
      revision.created_at_unix === 0 ? nowUnix : revision.created_at_unix,
      revision.created_by,
      JSON.stringify(revision),
    )
    .all();
}

// ---------------------------------------------------------------------------
// The binding CAS
// ---------------------------------------------------------------------------

export type GuardrailBindingOutcome =
  | { readonly ok: true; readonly generation: number }
  | { readonly ok: false; readonly conflict: string };

interface BindingRow {
  readonly policy_id: string;
  readonly active_revision: number | null;
  readonly generation: number;
  readonly binding_json: string;
}

interface BindingState {
  readonly activeRevision: number | null;
  readonly archivedRevisions: number[];
  readonly generation: number;
}

function bindingState(row: BindingRow | null): BindingState {
  if (row === null) {
    // A binding that does not exist yet is generation 0 — the INSERT arm.
    return { activeRevision: null, archivedRevisions: [], generation: 0 };
  }
  let archived: number[] = [];
  try {
    const parsed: unknown = JSON.parse(row.binding_json);
    if (typeof parsed === "object" && parsed !== null) {
      const list = (parsed as { archived_revisions?: unknown }).archived_revisions;
      if (Array.isArray(list)) {
        archived = list.filter((value): value is number => typeof value === "number");
      }
    }
  } catch {
    // A corrupt document loses the ARCHIVE LIST, never the active pointer or
    // the generation — those are real columns. Same posture as the reader's
    // `bindingFromRow`.
  }
  return {
    activeRevision: typeof row.active_revision === "number" ? row.active_revision : null,
    archivedRevisions: [...archived].sort((a, b) => a - b),
    generation: typeof row.generation === "number" ? row.generation : 0,
  };
}

async function readBinding(db: D1Database, policyId: string): Promise<BindingState> {
  const row = await db.prepare(GUARDRAIL_BINDING_SELECT_SQL).bind(policyId).first<BindingRow>();
  return bindingState(row ?? null);
}

async function commitBinding(
  db: D1Database,
  policyId: string,
  current: BindingState,
  next: { activeRevision: number | null; archivedRevisions: number[] },
  updatedBy: string,
  nowUnix: number,
): Promise<GuardrailBindingOutcome> {
  const generation = current.generation + 1;
  const document = JSON.stringify({
    archived_revisions: next.archivedRevisions,
    updated_by: updatedBy,
  });
  const written =
    current.generation === 0
      ? await db
          .prepare(GUARDRAIL_BINDING_INSERT_CAS_SQL)
          .bind(policyId, next.activeRevision, nowUnix, generation, document)
          .all()
      : await db
          .prepare(GUARDRAIL_BINDING_UPDATE_CAS_SQL)
          .bind(
            policyId,
            next.activeRevision,
            nowUnix,
            generation,
            document,
            current.generation,
          )
          .all();
  if ((written.results ?? []).length === 0) {
    // The row moved between the read and the write. Never retried here:
    // whoever asked for generation N wanted the state they read, and silently
    // re-basing onto someone else's write is the lost update this guard exists
    // to make impossible.
    return {
      ok: false,
      conflict:
        `guardrail policy binding ${policyId} changed concurrently ` +
        `(expected generation ${current.generation})`,
    };
  }
  return { ok: true, generation };
}

/** Point the live binding at `revision`, under the generation guard. */
export async function projectGuardrailActivation(
  db: D1Database,
  policyId: string,
  revision: number,
  updatedBy: string,
  nowUnix: number,
): Promise<GuardrailBindingOutcome> {
  const current = await readBinding(db, policyId);
  return commitBinding(
    db,
    policyId,
    current,
    {
      activeRevision: revision,
      archivedRevisions: current.archivedRevisions.filter((value) => value !== revision),
    },
    updatedBy,
    nowUnix,
  );
}

/**
 * Retire `revision` from the live binding.
 *
 * A no-op when the binding does not point at it: archiving revision 3 while 4 is
 * live must not silently switch the policy off. Only the ACTIVE revision's
 * archive clears the enforcement pointer, which is the residue an operator who
 * was told "archived" must not be left enforcing.
 */
export async function projectGuardrailArchive(
  db: D1Database,
  policyId: string,
  revision: number,
  updatedBy: string,
  nowUnix: number,
): Promise<GuardrailBindingOutcome> {
  const current = await readBinding(db, policyId);
  if (current.generation === 0 || current.activeRevision !== revision) {
    return { ok: true, generation: current.generation };
  }
  return commitBinding(
    db,
    policyId,
    current,
    {
      activeRevision: null,
      archivedRevisions: [...current.archivedRevisions, revision].sort((a, b) => a - b),
    },
    updatedBy,
    nowUnix,
  );
}
