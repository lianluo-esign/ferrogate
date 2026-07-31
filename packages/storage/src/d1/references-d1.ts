/**
 * `D1ReferenceGuardedDeletes` — the durable twin of `../references.ts`
 * (inventory §1.5.7, issue #328 finding 4).
 *
 * ## The guard is INSIDE the DELETE, and that is the entire design
 *
 * Postgres closed the check/delete race with `SELECT ... FOR UPDATE` on the
 * parent row. D1/SQLite has no row lock, so the port does not lock — it makes
 * the check and the delete the SAME statement:
 *
 * ```sql
 * DELETE FROM projects WHERE id = ?
 *   AND NOT EXISTS (SELECT 1 FROM workspaces WHERE project_id = ?)
 *   AND NOT EXISTS (SELECT 1 FROM api_keys   WHERE project_id = ?)
 * ```
 *
 * The `NOT EXISTS` subqueries are evaluated by SQLite at execution time, inside
 * the statement's own implicit transaction, against committed state. A
 * workspace inserted a microsecond earlier is therefore seen by the guard —
 * there is no window between check and use, because there is no second
 * statement. `changes()` (`meta.changes`) reports whether the guard held: `> 0`
 * means the row was unreferenced and is now gone; `0` means either "referenced"
 * or "was not there", which the SECOND (diagnostic, read-only) statement then
 * distinguishes.
 *
 * That second read is deliberately NOT part of the decision. It runs only after
 * the delete has already declined, it only labels a refusal that already
 * happened, and a row that changed underneath it can at worst make the reported
 * counts stale — never delete something it should not have. Folding the counts
 * into the decision is exactly the TOCTOU bug this class exists to avoid.
 *
 * ## Why no `batch()`
 *
 * A batch would be one transaction, but it would not add safety here: the guard
 * is already atomic within its single statement, and the diagnostic read must
 * be conditional on the delete's outcome, which a batch (all statements
 * submitted up front) cannot express. `requireAtomicBatch` is therefore NOT
 * asserted — this operation is safe on any handle that can run one statement.
 *
 * ## Which database
 *
 * `projects`, `workspaces` and `api_keys` are all in the TENANT database, so
 * every subquery is local and the atomicity is genuine. Contrast
 * `./usage-d1.ts`, whose claim/accumulate pair straddles two databases and
 * therefore CANNOT be made atomic on this platform.
 */
import {
  type DeleteAssetVariantOutcome,
  type DeleteProjectOutcome,
  type DeleteWorkspaceOutcome,
  assetVariantDeleteOutcomeFromReferences,
  projectDeleteOutcomeFromCounts,
  workspaceDeleteOutcomeFromCounts,
} from "../references.js";
import type { TenantDatabaseHandle } from "../tenant-router.js";
import { d1Error } from "./rows.js";

/** The guarded project delete. Ported verbatim from the Rust D1 backend. */
export const DELETE_PROJECT_IF_UNREFERENCED_SQL =
  "DELETE FROM projects WHERE id = ? " +
  "AND NOT EXISTS (SELECT 1 FROM workspaces WHERE project_id = ?) " +
  "AND NOT EXISTS (SELECT 1 FROM api_keys WHERE project_id = ?)";

/** The diagnostic read that labels a refusal (never decides one). */
export const PROJECT_REFERENCE_COUNTS_SQL =
  "SELECT (SELECT COUNT(*) FROM projects WHERE id = ?) AS present, " +
  "(SELECT COUNT(*) FROM workspaces WHERE project_id = ?) AS workspaces, " +
  "(SELECT COUNT(*) FROM api_keys WHERE project_id = ?) AS virtual_keys";

/** The guarded workspace delete. */
export const DELETE_WORKSPACE_IF_UNREFERENCED_SQL =
  "DELETE FROM workspaces WHERE id = ? " +
  "AND NOT EXISTS (SELECT 1 FROM api_keys WHERE workspace_id = ?)";

/** The diagnostic read for a refused workspace delete. */
export const WORKSPACE_REFERENCE_COUNTS_SQL =
  "SELECT (SELECT COUNT(*) FROM workspaces WHERE id = ?) AS present, " +
  "(SELECT COUNT(*) FROM api_keys WHERE workspace_id = ?) AS virtual_keys";

/**
 * The guarded asset-variant delete (§1.5.7, third of three).
 *
 * The correlated subquery matches a channel pointer to this exact variant by
 * its `(tenant, asset_type, name, version)` identity — read off the row being
 * deleted, NOT from caller-supplied parameters. Taking them from the caller
 * would let a wrong tuple make the guard vacuously true and delete a version a
 * channel still publishes; `stored_assets.id` is the only input.
 *
 * `variant` is deliberately NOT part of the match. `asset_channels` points at a
 * `(name, channel) -> version` and carries no variant column, so a channel that
 * resolves to a version blocks EVERY variant row of that version. That is the
 * conservative direction: refusing a delete that might have been safe costs an
 * operator one message, permitting one that was not costs a published 404.
 */
export const DELETE_ASSET_VARIANT_IF_UNREFERENCED_SQL =
  "DELETE FROM stored_assets WHERE id = ? " +
  "AND NOT EXISTS (SELECT 1 FROM asset_channels c " +
  "                 JOIN stored_assets a ON a.id = stored_assets.id " +
  "                WHERE c.tenant_id = a.tenant_id " +
  "                  AND c.asset_type = a.asset_type " +
  "                  AND c.name = a.name " +
  "                  AND c.version = a.version)";

/** The diagnostic read that NAMES the channels blocking a refused delete. */
export const ASSET_VARIANT_CHANNELS_SQL =
  "SELECT c.channel AS channel FROM stored_assets a " +
  "LEFT JOIN asset_channels c " +
  "  ON c.tenant_id = a.tenant_id AND c.asset_type = a.asset_type " +
  " AND c.name = a.name AND c.version = a.version " +
  "WHERE a.id = ? ORDER BY c.channel";

function changes(result: D1Response): number {
  const meta = result.meta as { changes?: number } | undefined;
  return meta?.changes ?? 0;
}

export class D1ReferenceGuardedDeletes {
  private readonly db: D1Database;

  constructor(handle: TenantDatabaseHandle) {
    this.db = handle.db;
  }

  /**
   * Delete a project only if no workspace and no virtual API key reference it.
   * Returns `deleted` / `not_found` / `referenced` with the blocking counts.
   */
  async deleteProjectIfUnreferenced(id: string): Promise<DeleteProjectOutcome> {
    try {
      const guarded = await this.db
        .prepare(DELETE_PROJECT_IF_UNREFERENCED_SQL)
        .bind(id, id, id)
        .run();
      if (changes(guarded) > 0) return { kind: "deleted" };

      const row = await this.db
        .prepare(PROJECT_REFERENCE_COUNTS_SQL)
        .bind(id, id, id)
        .first<{ present: number; workspaces: number; virtual_keys: number }>();
      if (row === null) return { kind: "not_found" };
      const outcome = projectDeleteOutcomeFromCounts({
        present: Number(row.present),
        workspaces: Number(row.workspaces),
        virtualKeys: Number(row.virtual_keys),
      });
      // The guard already refused, so `deleted` cannot be the honest label here:
      // it would mean the row became unreferenced between the two statements,
      // and reporting a deletion that did not happen is worse than a retry.
      return outcome.kind === "deleted"
        ? { kind: "referenced", workspaces: 0, virtualKeys: 0 }
        : outcome;
    } catch (error) {
      throw d1Error("delete_project_if_unreferenced", error);
    }
  }

  /** Delete a workspace only if no virtual API key references it. */
  async deleteWorkspaceIfUnreferenced(id: string): Promise<DeleteWorkspaceOutcome> {
    try {
      const guarded = await this.db
        .prepare(DELETE_WORKSPACE_IF_UNREFERENCED_SQL)
        .bind(id, id)
        .run();
      if (changes(guarded) > 0) return { kind: "deleted" };

      const row = await this.db
        .prepare(WORKSPACE_REFERENCE_COUNTS_SQL)
        .bind(id, id)
        .first<{ present: number; virtual_keys: number }>();
      if (row === null) return { kind: "not_found" };
      const outcome = workspaceDeleteOutcomeFromCounts({
        present: Number(row.present),
        virtualKeys: Number(row.virtual_keys),
      });
      return outcome.kind === "deleted" ? { kind: "referenced", virtualKeys: 0 } : outcome;
    } catch (error) {
      throw d1Error("delete_workspace_if_unreferenced", error);
    }
  }

  /**
   * Delete an asset variant only while no `asset_channels` pointer resolves to
   * its version (§1.5.7, third of three).
   *
   * Same shape as the two above, for the same reason: the check is INSIDE the
   * DELETE, so a channel moved onto this version a microsecond earlier is seen
   * by the guard. A `SELECT` then `DELETE` would let a publish land in the
   * window and leave `latest` pointing at bytes that no longer exist.
   */
  async deleteAssetVariantIfUnreferenced(id: string): Promise<DeleteAssetVariantOutcome> {
    try {
      const guarded = await this.db
        .prepare(DELETE_ASSET_VARIANT_IF_UNREFERENCED_SQL)
        .bind(id)
        .run();
      if (changes(guarded) > 0) return { kind: "deleted" };

      const rows = await this.db
        .prepare(ASSET_VARIANT_CHANNELS_SQL)
        .bind(id)
        .all<{ channel: string | null }>();
      // No rows at all means the variant itself is gone — the LEFT JOIN yields
      // one row per existing variant even when it has no channel.
      if (rows.results.length === 0) return { kind: "not_found" };
      const channels = rows.results
        .map((row) => row.channel)
        .filter((channel): channel is string => channel !== null);
      const outcome = assetVariantDeleteOutcomeFromReferences({ present: 1, channels });
      // The guard already refused, so `deleted` cannot be the honest label: it
      // would mean the last pointer moved away between the two statements, and
      // reporting a deletion that did not happen is worse than a retry.
      return outcome.kind === "deleted" ? { kind: "referenced", channels: [] } : outcome;
    } catch (error) {
      throw d1Error("delete_asset_variant_if_unreferenced", error);
    }
  }
}
