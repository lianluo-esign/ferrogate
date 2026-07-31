/**
 * Reference-guarded deletes for projects and workspaces (inventory
 * §1.5.7, issue #328 finding 4) — the TOCTOU-closing half of "delete a project".
 *
 * ## What the guard is for
 *
 * `deleteProject` is an unconditional delete. `deleteProjectIfUnreferenced` is
 * the one an operator-facing API must call: it refuses when a workspace or a
 * virtual API key still points at the project, and reports HOW MANY of each so
 * the caller can say what is in the way.
 *
 * The naive shape — count the references, then delete if the count was zero —
 * is a **time-of-check/time-of-use race**: a workspace created between the two
 * statements is orphaned by a delete that was authorized against a stale count,
 * and an orphaned workspace's api-keys keep authenticating against a project
 * that no longer exists. Postgres closed the window with `SELECT ... FOR
 * UPDATE` on the parent row. D1/SQLite has no row lock, so the durable twin
 * (`./d1/references-d1.ts`) closes it a different way: the guard is a
 * `NOT EXISTS` subquery **inside the DELETE statement**, and SQLite evaluates
 * it against committed state at execution time inside the statement's implicit
 * transaction. There is no window because there is no second statement.
 *
 * This module holds the parts that are pure: the outcome alphabet, and the one
 * copy of the not-found/referenced/deleted rule that both the in-memory
 * reference backend below and the D1 twin's diagnostic read consult. The rule
 * lives here once so the two backends cannot drift into disagreeing about what
 * "referenced" means.
 *
 * ## Which database
 *
 * `projects`, `workspaces` and `api_keys` are all TENANT-database tables
 * (`sql/d1-ts/tenant/0001_init_tenant.sql`), so the guard and its subqueries
 * are in one database and the atomicity is real — unlike the usage/billing
 * claim pair, which straddles control and tenant (see `./d1/usage-d1.ts`).
 *
 * §1.5.7 names THREE reference-guarded deletes and all three are now here. The
 * third — "delete an asset variant only while no `asset_channels` pointer
 * resolves to it" — is {@link assetVariantDeleteOutcomeFromReferences} with
 * `D1ReferenceGuardedDeletes.deleteAssetVariantIfUnreferenced` as its durable
 * half, in the same single-statement shape as the two above. Without it,
 * deleting a variant that `latest` or `stable` still points at leaves a dangling
 * channel, and every subsequent pull on that channel resolves to a version whose
 * bytes are gone — a 404 on a name the operator believes is published.
 *
 * CLOSED — former marker inventory-data-billing §1.4.6 `asset_channels` write
 * path — the thing this guard guards now WRITES.
 * {@link ./d1/assets-d1.js D1AssetMetadataStore} inserts `asset_channels` rows
 * via `upsertAssetChannel` and the guarded `moveAssetChannelIfResolvable`, so
 * the REFUSAL arm is no longer reachable only from a hand-seeded table: the
 * end-to-end test in `test/d1/assets-d1.test.ts` publishes a version, MOVES a
 * channel onto it through the production write path, and then asserts
 * `deleteAssetVariantIfUnreferenced` refuses and NAMES that channel.
 *
 * The two guards are deliberately complementary and both directions are pinned:
 * this one refuses to delete a variant a channel names, and
 * `setAssetVersionYank` refuses to yank a version a channel names.
 */

/** Reference counts observed for a project id in one database. */
export interface ProjectReferenceCounts {
  /** `1` when the project row exists, `0` when it does not. */
  present: number;
  /** Workspaces whose `project_id` is this project. */
  workspaces: number;
  /** Virtual (native) API keys whose `project_id` is this project. */
  virtualKeys: number;
}

/** Reference counts observed for a workspace id in one database. */
export interface WorkspaceReferenceCounts {
  present: number;
  /** Virtual (native) API keys whose `workspace_id` is this workspace. */
  virtualKeys: number;
}

/**
 * Outcome of a reference-guarded project delete (ports `DeleteProjectOutcome`).
 *
 * `referenced` carries the counts rather than a bare refusal because the caller
 * renders them: "3 workspaces and 1 API key still reference this project".
 */
export type DeleteProjectOutcome =
  | { kind: "deleted" }
  | { kind: "not_found" }
  | { kind: "referenced"; workspaces: number; virtualKeys: number };

/** Outcome of a reference-guarded workspace delete (`DeleteWorkspaceOutcome`). */
export type DeleteWorkspaceOutcome =
  | { kind: "deleted" }
  | { kind: "not_found" }
  | { kind: "referenced"; virtualKeys: number };

/**
 * Which channel pointers still resolve to one asset variant.
 *
 * `channels` carries the NAMES rather than a count because the caller renders
 * them — "`latest` and `stable` still point at this version" is actionable,
 * "2 references" is not.
 */
export interface AssetVariantReferences {
  /** `1` when the variant row exists, `0` when it does not. */
  present: number;
  /** Channels (`latest`, `stable`, …) resolving to this exact version. */
  channels: readonly string[];
}

/** Outcome of a reference-guarded asset-variant delete (`§1.5.7`). */
export type DeleteAssetVariantOutcome =
  | { kind: "deleted" }
  | { kind: "not_found" }
  | { kind: "referenced"; channels: readonly string[] };

/**
 * See {@link projectDeleteOutcomeFromCounts} — the same rule, third resource.
 *
 * A missing variant is `not_found` even when a channel still names its version,
 * because there is nothing left to delete; reporting `referenced` would suggest
 * a retry that can never succeed. That dangling pointer is a separate defect
 * for the channel writer to resolve, not something this delete can fix.
 */
export function assetVariantDeleteOutcomeFromReferences(
  references: AssetVariantReferences,
): DeleteAssetVariantOutcome {
  if (references.present <= 0) return { kind: "not_found" };
  if (references.channels.length > 0) {
    return { kind: "referenced", channels: [...references.channels] };
  }
  return { kind: "deleted" };
}

/**
 * The single copy of the decision rule, applied to counts read from one
 * database. Order matters: a MISSING project is `not_found` even if rows
 * elsewhere still carry its id, because there is nothing to delete and
 * reporting "referenced" would suggest a retry that can never succeed.
 */
export function projectDeleteOutcomeFromCounts(
  counts: ProjectReferenceCounts,
): DeleteProjectOutcome {
  if (counts.present <= 0) return { kind: "not_found" };
  const workspaces = Math.max(0, counts.workspaces);
  const virtualKeys = Math.max(0, counts.virtualKeys);
  if (workspaces > 0 || virtualKeys > 0) {
    return { kind: "referenced", workspaces, virtualKeys };
  }
  return { kind: "deleted" };
}

/** See {@link projectDeleteOutcomeFromCounts}. */
export function workspaceDeleteOutcomeFromCounts(
  counts: WorkspaceReferenceCounts,
): DeleteWorkspaceOutcome {
  if (counts.present <= 0) return { kind: "not_found" };
  const virtualKeys = Math.max(0, counts.virtualKeys);
  if (virtualKeys > 0) return { kind: "referenced", virtualKeys };
  return { kind: "deleted" };
}

/** The minimal project identity this algorithm needs. */
export interface ProjectRef {
  id: string;
}
/** The minimal workspace identity this algorithm needs. */
export interface WorkspaceRef {
  id: string;
  projectId: string;
}
/** The minimal virtual-key identity this algorithm needs. */
export interface ApiKeyRef {
  id: string;
  projectId: string;
  workspaceId: string;
}

/**
 * The in-memory reference backend — the read-modify-write baseline the D1 twin
 * must match observably.
 *
 * Rust gets its atomicity here from running the whole check-then-delete inside
 * the caller's `Mutex`; the single JS thread does the same, since nothing
 * awaits between the count and the removal. That is precisely why this backend
 * cannot, on its own, prove the durable one is safe: it is atomic for a reason
 * that does not exist in D1. `test/d1/references-d1.test.ts` carries the proof
 * that matters, by interleaving a reference insert into the durable path.
 */
export class MemoryReferenceGuardedDeletes {
  readonly #projects = new Map<string, ProjectRef>();
  readonly #workspaces = new Map<string, WorkspaceRef>();
  readonly #apiKeys = new Map<string, ApiKeyRef>();

  addProject(project: ProjectRef): void {
    this.#projects.set(project.id, { ...project });
  }
  addWorkspace(workspace: WorkspaceRef): void {
    this.#workspaces.set(workspace.id, { ...workspace });
  }
  addApiKey(key: ApiKeyRef): void {
    this.#apiKeys.set(key.id, { ...key });
  }

  hasProject(id: string): boolean {
    return this.#projects.has(id);
  }
  hasWorkspace(id: string): boolean {
    return this.#workspaces.has(id);
  }

  projectReferenceCounts(id: string): ProjectReferenceCounts {
    let workspaces = 0;
    for (const workspace of this.#workspaces.values()) {
      if (workspace.projectId === id) workspaces += 1;
    }
    let virtualKeys = 0;
    for (const key of this.#apiKeys.values()) {
      if (key.projectId === id) virtualKeys += 1;
    }
    return { present: this.#projects.has(id) ? 1 : 0, workspaces, virtualKeys };
  }

  workspaceReferenceCounts(id: string): WorkspaceReferenceCounts {
    let virtualKeys = 0;
    for (const key of this.#apiKeys.values()) {
      if (key.workspaceId === id) virtualKeys += 1;
    }
    return { present: this.#workspaces.has(id) ? 1 : 0, virtualKeys };
  }

  /** Delete the project only if nothing references it. */
  deleteProjectIfUnreferenced(id: string): DeleteProjectOutcome {
    const outcome = projectDeleteOutcomeFromCounts(this.projectReferenceCounts(id));
    if (outcome.kind === "deleted") this.#projects.delete(id);
    return outcome;
  }

  /** Delete the workspace only if no virtual key references it. */
  deleteWorkspaceIfUnreferenced(id: string): DeleteWorkspaceOutcome {
    const outcome = workspaceDeleteOutcomeFromCounts(this.workspaceReferenceCounts(id));
    if (outcome.kind === "deleted") this.#workspaces.delete(id);
    return outcome;
  }
}
