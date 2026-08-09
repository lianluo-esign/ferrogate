/**
 * The DURABLE guardrail policy store — `guardrail_policy_revisions` +
 * `guardrail_policy_bindings` on the CONTROL D1.
 *
 * `binding.ts` owns the decision table (which revision an `activate` /
 * `archive` / `restore` leaves live, and when a generation mismatch is a lost
 * update). This file owns nothing but the ROW I/O for that same table, so the
 * two implementations cannot drift: `test/guardrails/d1.test.ts` runs the
 * durable store through the very assertions `InMemoryGuardrailPolicyStore`
 * answers in `test/guardrails/binding.test.ts`.
 *
 * ## Why the interface is a separate ASYNC one
 *
 * {@link GuardrailPolicyStore} is synchronous, and it has to be: it is read on
 * the request path by `policySourceFromStore`, which compiles detectors eagerly.
 * D1 is async, so `D1GuardrailPolicyStore implements GuardrailPolicyStore` is
 * not expressible — the marker this file closed claimed "exactly one class" was
 * missing, and was wrong about that. {@link AsyncGuardrailPolicyStore} is the same
 * method set returning promises, and {@link loadGuardrailPolicyStore} projects a
 * durable snapshot into the synchronous in-memory store the request path already
 * knows how to compile. The snapshot is taken ONCE PER ISOLATE (memoized on the
 * `env` object by `config.ts`), which is the Workers equivalent of the Rust
 * gateway rebuilding `AppState.guardrail_policies` on config reload rather than
 * re-reading Supabase per request.
 *
 * ## The CAS is the concurrency control, not an optimization
 *
 * D1 is SQLite: there is no `SELECT … FOR UPDATE`, and a Worker cannot hold a
 * transaction open across an `await`. Every mutation below is therefore a
 * read-then-guarded-write:
 *
 *   UPDATE guardrail_policy_bindings SET … WHERE policy_id = ? AND generation = ?
 *   RETURNING policy_id
 *
 * and an EMPTY `RETURNING` set is the lost update — reported as the same typed
 * {@link CasResult} conflict the in-memory store returns. The first write for a
 * policy is the INSERT arm, guarded by `WHERE NOT EXISTS`, so two concurrent
 * "create the binding" calls cannot both win.
 *
 * `archived_revisions` has no column of its own in
 * `sql/d1-ts/control/0001_init_control.sql` — the table carries `policy_id`,
 * `active_revision`, `updated_at_unix`, `generation` and `binding_json`, so the
 * archive list and `updated_by` travel in `binding_json`. `active_revision` and
 * `generation` stay real columns because the CAS predicate and the read path
 * index on them.
 */
import {
  type PolicyRevision,
  immutableId,
  policyRevisionSchema,
  validatePolicyRevision,
} from "@ferrogate/guardrails";
import { controlDatabaseFrom } from "../control-data.js";
import {
  type CasResult,
  type GuardrailPolicyBinding,
  InMemoryGuardrailPolicyStore,
} from "./binding.js";

// ---------------------------------------------------------------------------
// The narrow database port
// ---------------------------------------------------------------------------

/** One row, as D1 hands it back. */
type Row = Record<string, unknown>;

/**
 * The subset of `D1Database` this store reads. A live binding satisfies it
 * structurally, so nothing is cast at the composition root and nothing wraps
 * the binding.
 */
export interface GuardrailDatabase {
  prepare(sql: string): GuardrailStatement;
}

export interface GuardrailStatement {
  bind(...values: unknown[]): GuardrailStatement;
  all(): Promise<{ results?: Row[] | null }>;
  run(): Promise<unknown>;
}

function isGuardrailDatabase(value: unknown): value is GuardrailDatabase {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as GuardrailDatabase).prepare === "function"
  );
}

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

/** Exported so a test can pin the statements rather than restate them. */
export const GUARDRAIL_REVISION_INSERT_SQL =
  "INSERT INTO guardrail_policy_revisions " +
  "(policy_id, revision, immutable_id, created_at_unix, created_by, revision_json) " +
  "VALUES (?1, ?2, ?3, ?4, ?5, ?6) " +
  // Revisions are IMMUTABLE. `DO NOTHING` + an empty `RETURNING` is how a
  // duplicate `(policy_id, revision)` is detected without a read-then-write
  // race — an `INSERT OR REPLACE` here would silently rewrite history.
  "ON CONFLICT (policy_id, revision) DO NOTHING " +
  "RETURNING policy_id";

export const GUARDRAIL_REVISION_LIST_SQL =
  "SELECT revision_json FROM guardrail_policy_revisions " +
  "WHERE policy_id = ?1 ORDER BY revision ASC";

export const GUARDRAIL_REVISION_LIST_ALL_SQL =
  "SELECT revision_json FROM guardrail_policy_revisions ORDER BY policy_id ASC, revision ASC";

export const GUARDRAIL_BINDING_SELECT_SQL =
  "SELECT policy_id, active_revision, generation, binding_json " +
  "FROM guardrail_policy_bindings WHERE policy_id = ?1";

export const GUARDRAIL_BINDING_LIST_SQL =
  "SELECT policy_id, active_revision, generation, binding_json " +
  "FROM guardrail_policy_bindings ORDER BY policy_id ASC";

/** The INSERT arm of the CAS: only when no row exists yet (generation 0). */
export const GUARDRAIL_BINDING_INSERT_CAS_SQL =
  "INSERT INTO guardrail_policy_bindings " +
  "(policy_id, active_revision, updated_at_unix, generation, binding_json) " +
  "SELECT ?1, ?2, ?3, ?4, ?5 " +
  "WHERE NOT EXISTS (SELECT 1 FROM guardrail_policy_bindings WHERE policy_id = ?1) " +
  "RETURNING policy_id";

/** The UPDATE arm of the CAS. An empty `RETURNING` set is the lost update. */
export const GUARDRAIL_BINDING_UPDATE_CAS_SQL =
  "UPDATE guardrail_policy_bindings " +
  "SET active_revision = ?2, updated_at_unix = ?3, generation = ?4, binding_json = ?5 " +
  "WHERE policy_id = ?1 AND generation = ?6 " +
  "RETURNING policy_id";

// ---------------------------------------------------------------------------
// The async store
// ---------------------------------------------------------------------------

/**
 * {@link GuardrailPolicyStore}, method for method, returning promises.
 *
 * Deliberately NOT `GuardrailPolicyStore & { … }`: the two cannot be unified,
 * and pretending otherwise is what would let a durable call be `await`-less at
 * a call site and silently succeed.
 */
export interface AsyncGuardrailPolicyStore {
  putRevision(revision: PolicyRevision, createdBy?: string): Promise<void>;
  listRevisions(policyId: string): Promise<readonly PolicyRevision[]>;
  getBinding(policyId: string): Promise<GuardrailPolicyBinding | undefined>;
  listBindings(): Promise<readonly GuardrailPolicyBinding[]>;
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

function conflict(detail: string): CasResult {
  return { ok: false, conflict: true, detail };
}

/** The `binding_json` half of a binding row. */
interface BindingDocument {
  readonly archived_revisions?: unknown;
  readonly updated_by?: unknown;
}

function bindingFromRow(row: Row): GuardrailPolicyBinding {
  let document: BindingDocument = {};
  const raw = row.binding_json;
  if (typeof raw === "string") {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed === "object" && parsed !== null) {
        document = parsed as BindingDocument;
      }
    } catch {
      // A corrupt document loses the ARCHIVE LIST, never the active pointer or
      // the generation — those are real columns. Failing the whole read here
      // would take a policy offline because of a cosmetic field.
    }
  }
  const archived = Array.isArray(document.archived_revisions)
    ? document.archived_revisions.filter((value): value is number => typeof value === "number")
    : [];
  const active = row.active_revision;
  return {
    policyId: String(row.policy_id),
    activeRevision: typeof active === "number" ? active : null,
    archivedRevisions: [...archived].sort((a, b) => a - b),
    updatedBy: typeof document.updated_by === "string" ? document.updated_by : "",
    generation: typeof row.generation === "number" ? row.generation : 0,
  };
}

function bindingDocument(binding: GuardrailPolicyBinding): string {
  return JSON.stringify({
    archived_revisions: binding.archivedRevisions,
    updated_by: binding.updatedBy,
  });
}

function revisionFromRow(row: Row): PolicyRevision | undefined {
  const raw = row.revision_json;
  if (typeof raw !== "string") return undefined;
  try {
    const parsed = policyRevisionSchema.safeParse(JSON.parse(raw));
    return parsed.success ? (parsed.data as PolicyRevision) : undefined;
  } catch {
    return undefined;
  }
}

/** Row I/O for the guardrail policy tables. The decision table is `binding.ts`'s. */
export class D1GuardrailPolicyStore implements AsyncGuardrailPolicyStore {
  readonly #db: GuardrailDatabase;
  readonly #now: () => number;

  constructor(db: GuardrailDatabase, options: { now?: () => number } = {}) {
    this.#db = db;
    this.#now = options.now ?? ((): number => Math.floor(Date.now() / 1000));
  }

  /** `null` when `CONTROL_DB` is unbound, so the caller keeps its config path. */
  static fromEnv(
    env: Record<string, unknown>,
    options: { now?: () => number } = {},
  ): D1GuardrailPolicyStore | null {
    const binding = controlDatabaseFrom(env);
    return isGuardrailDatabase(binding) ? new D1GuardrailPolicyStore(binding, options) : null;
  }

  async putRevision(revision: PolicyRevision, createdBy = "control_plane"): Promise<void> {
    // Same gate, same order as the in-memory store: a malformed revision never
    // reaches storage, so an invalid policy cannot be resurrected by a reload.
    validatePolicyRevision(revision);
    const inserted = await this.#db
      .prepare(GUARDRAIL_REVISION_INSERT_SQL)
      .bind(
        revision.policy_id,
        revision.revision,
        immutableId(revision),
        this.#now(),
        createdBy,
        JSON.stringify(revision),
      )
      .all();
    if ((inserted.results ?? []).length === 0) {
      throw new Error(
        `guardrail policy revision ${immutableId(revision)} already exists (revisions are immutable)`,
      );
    }
  }

  async listRevisions(policyId: string): Promise<readonly PolicyRevision[]> {
    const rows = await this.#db.prepare(GUARDRAIL_REVISION_LIST_SQL).bind(policyId).all();
    return (rows.results ?? [])
      .map(revisionFromRow)
      .filter((revision): revision is PolicyRevision => revision !== undefined);
  }

  /** Every revision of every policy, for the snapshot loader. */
  async listAllRevisions(): Promise<readonly PolicyRevision[]> {
    const rows = await this.#db.prepare(GUARDRAIL_REVISION_LIST_ALL_SQL).all();
    return (rows.results ?? [])
      .map(revisionFromRow)
      .filter((revision): revision is PolicyRevision => revision !== undefined);
  }

  async getBinding(policyId: string): Promise<GuardrailPolicyBinding | undefined> {
    const rows = await this.#db.prepare(GUARDRAIL_BINDING_SELECT_SQL).bind(policyId).all();
    const row = (rows.results ?? [])[0];
    return row === undefined ? undefined : bindingFromRow(row);
  }

  async listBindings(): Promise<readonly GuardrailPolicyBinding[]> {
    const rows = await this.#db.prepare(GUARDRAIL_BINDING_LIST_SQL).all();
    return (rows.results ?? []).map(bindingFromRow);
  }

  async activate(
    policyId: string,
    revision: number,
    expectedGeneration: number,
    updatedBy: string,
  ): Promise<CasResult> {
    const revisions = await this.listRevisions(policyId);
    if (!revisions.some((candidate) => candidate.revision === revision)) {
      return conflict(`guardrail policy revision ${policyId}@${revision} does not exist`);
    }
    return this.#cas(policyId, expectedGeneration, (current) => ({
      policyId,
      activeRevision: revision,
      archivedRevisions: current.archivedRevisions.filter((r) => r !== revision),
      updatedBy,
      generation: current.generation,
    }));
  }

  async archive(
    policyId: string,
    expectedGeneration: number,
    updatedBy: string,
  ): Promise<CasResult> {
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

  async restore(
    policyId: string,
    revision: number,
    expectedGeneration: number,
    updatedBy: string,
  ): Promise<CasResult> {
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

  /**
   * Read the row, apply the pure transition, write it back under the guard.
   *
   * The read is NOT the safety mechanism — the `WHERE generation = ?` is. A
   * competing writer that lands between the two makes the write match zero rows
   * and this returns the conflict, which is exactly the in-memory store's
   * "generation is X, not Y" outcome.
   */
  async #cas(
    policyId: string,
    expectedGeneration: number,
    next: (current: GuardrailPolicyBinding) => GuardrailPolicyBinding | { error: string },
  ): Promise<CasResult> {
    const current = (await this.getBinding(policyId)) ?? {
      policyId,
      activeRevision: null,
      archivedRevisions: [],
      updatedBy: "",
      // A binding that does not exist yet is generation 0 — the INSERT arm.
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

    const now = this.#now();
    const written =
      expectedGeneration === 0
        ? await this.#db
            .prepare(GUARDRAIL_BINDING_INSERT_CAS_SQL)
            .bind(
              policyId,
              committed.activeRevision,
              now,
              committed.generation,
              bindingDocument(committed),
            )
            .all()
        : await this.#db
            .prepare(GUARDRAIL_BINDING_UPDATE_CAS_SQL)
            .bind(
              policyId,
              committed.activeRevision,
              now,
              committed.generation,
              bindingDocument(committed),
              expectedGeneration,
            )
            .all();

    if ((written.results ?? []).length === 0) {
      // The row moved between the read and the write. Reported as a conflict,
      // never retried here: whoever asked for generation N wanted the state
      // they read, and silently re-basing onto someone else's write is the lost
      // update this guard exists to make impossible.
      return conflict(
        `guardrail policy binding ${policyId} changed concurrently (expected generation ${expectedGeneration})`,
      );
    }
    return { ok: true, binding: committed };
  }
}

// ---------------------------------------------------------------------------
// Durable snapshot -> the synchronous request-path store
// ---------------------------------------------------------------------------

/**
 * Project the durable tables into the synchronous store the request path
 * compiles.
 *
 * `seed` is the store the CONFIG vars already built, so the durable rows are
 * ADDITIVE to `GATEWAY_GUARDRAIL_POLICIES` rather than replacing it — a policy
 * declared in configuration keeps applying when the control plane has none, and
 * both are screened when both exist. Ordering between them is not a question
 * the source can be asked: `policySourceFromRuntimes` sorts by
 * `(administrative_rank, policy_id, revision)`, never by insertion.
 *
 * A revision the durable table holds that the seed ALSO holds is skipped rather
 * than re-inserted: revisions are immutable and identical by `immutable_id`, so
 * the duplicate is not a conflict to report, it is the same policy twice.
 *
 * Throws on a database failure. That is deliberate and it is the fail-CLOSED
 * direction: `guardrails()` builds the engine from this, and an engine built
 * from a half-read policy set would screen with policies silently missing. The
 * caller (`guardrailDepsFromEnv`) lets it propagate, so the request answers 503
 * rather than passing unscreened content to a provider.
 *
 * `options.onDurablePolicy` is called once per policy id this function took
 * from the DURABLE tables. It exists so the caller can tell those apart from
 * the ones the seed (the config vars) already held, which is the discriminator
 * `policySourceFromStore`'s `failClosedPolicyIds` needs: a durable row is
 * another Worker's runtime input and must not be able to fail this Worker's
 * boot, while a policy in this deployment's own configuration still must.
 */
export interface LoadGuardrailPolicyStoreOptions {
  readonly onDurablePolicy?: ((policyId: string) => void) | undefined;
}

export async function loadGuardrailPolicyStore(
  store: Pick<D1GuardrailPolicyStore, "listAllRevisions" | "listBindings">,
  seed: InMemoryGuardrailPolicyStore = new InMemoryGuardrailPolicyStore(),
  options: LoadGuardrailPolicyStoreOptions = {},
): Promise<InMemoryGuardrailPolicyStore> {
  const revisions = await store.listAllRevisions();
  for (const revision of revisions) {
    if (seed.revision(revision.policy_id, revision.revision) !== undefined) {
      continue;
    }
    try {
      seed.putRevision(revision);
    } catch {
      // `putRevision` runs `validatePolicyRevision`, and a row written before
      // `apps/control-plane` tightened admission can fail it. Skipping ONE row
      // rather than throwing is what keeps a legacy document from taking the
      // whole guardrail source — and therefore every request — down at boot;
      // this loop is reached from `guardrailDepsFromEnv`, which lets a throw
      // propagate into a 503.
      //
      // Skipping is NOT fail-open: the binding loop below refuses to activate a
      // revision the snapshot does not have, so the policy has no live text and
      // no request is told it was screened. A policy that DOES load and merely
      // fails to COMPILE is the other case, and `binding.ts` keeps that one
      // selected and failing closed rather than dropping it.
    }
  }

  for (const binding of await store.listBindings()) {
    if (binding.activeRevision === null) {
      continue;
    }
    if (seed.revision(binding.policyId, binding.activeRevision) === undefined) {
      // The binding points at a revision this snapshot does not have. Skipped,
      // never faked: activating a policy whose text is unknown would screen
      // with rules nobody can read back.
      continue;
    }
    const current = seed.getBinding(binding.policyId);
    const result = seed.activate(
      binding.policyId,
      binding.activeRevision,
      current?.generation ?? 0,
      binding.updatedBy,
    );
    if (!result.ok) {
      throw new Error(
        `guardrail policy binding ${binding.policyId}@${binding.activeRevision} could not be projected: ${result.detail}`,
      );
    }
    // Reported only for a binding this function actually made live from the
    // durable tables — after the activate, so a skipped one is never claimed.
    options.onDurablePolicy?.(binding.policyId);
  }
  return seed;
}
