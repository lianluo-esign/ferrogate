/**
 * Contract group `guardrail_policy` (10 operations) — the ONLY group in this app
 * whose operations carry an `rbac_action`, and the only one with immutable
 * revisions.
 *
 * ```
 *   GET  /admin/v1/guardrail-policies                              guardrails.policy.read
 *   POST /admin/v1/guardrail-policies                              guardrails.policy.create_revision
 *   GET  /admin/v1/guardrail-policies/{policy_id}                  guardrails.policy.read
 *   GET  /admin/v1/guardrail-policies/{policy_id}/revisions        guardrails.policy.read
 *   POST /admin/v1/guardrail-policies/{policy_id}/revisions        guardrails.policy.create_revision
 *   GET  /admin/v1/guardrail-policies/{policy_id}/revisions/{rev}  guardrails.policy.read
 *   DEL  /admin/v1/guardrail-policies/{policy_id}/revisions/{rev}  guardrails.policy.archive
 *   POST /admin/v1/guardrail-policies/{policy_id}/activate         guardrails.policy.activate
 *   POST /admin/v1/guardrail-policies/{policy_id}/rollback         guardrails.policy.rollback
 *   POST /admin/v1/guardrail-policies/{policy_id}/dry-run          guardrails.policy.dry_run
 * ```
 *
 * The RBAC gate itself is NOT written here — the table-driven middleware reads
 * `rbac_action` off the contract and enforces it for all ten, exactly as Rust's
 * `require_guardrail_auth` does (platform operator waved through, tenant caller
 * must clear its tenant's grant, unavailable RBAC store → 503, never allow).
 * Re-implementing it per handler is how the ten drift apart.
 *
 * Two Rust semantics preserved in the bodies:
 *
 *  - **Revisions are immutable and monotonic.** A new revision is always
 *    `max(existing) + 1`; there is no PUT/PATCH on a revision. `archive` marks
 *    a revision archived; it does not renumber or delete history.
 *  - **`dry-run` never mutates.** It reports what the selected revision WOULD
 *    do for a given stage/context, which is why it is the one `admin.read`
 *    operation among the POSTs (`GuardrailPermission::DryRun → "admin.read"`).
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { StoreRecord } from "../ports.js";
import { adminDeleted, listResponse, parseListQuery } from "../responses.js";
import { type GroupModule, crudGroup, json, pathParam, readJson, scopeOf } from "./resource.js";

const POLICIES = "guardrail-policies";
const REVISIONS = "guardrail-policy-revisions";

/** Rust `DetectorStage`. */
export const DETECTOR_STAGES = ["input", "output", "tool"] as const;

export const guardrailRevisionSchema = z
  .object({
    policy_id: z.string().trim().min(1).optional(),
    detectors: z.array(z.record(z.unknown())).optional(),
    on_pass: z.array(z.record(z.unknown())).optional(),
    on_fail: z.array(z.record(z.unknown())).optional(),
    on_error: z.array(z.record(z.unknown())).optional(),
  })
  .passthrough();

/** Rust `RevisionSelection { revision: u32 }` (`deny_unknown_fields`). */
export const revisionSelectionSchema = z.object({ revision: z.number().int().min(0) }).strict();

/** Rust `RollbackSelection { revision: Option<u32> }` (`deny_unknown_fields`). */
export const rollbackSelectionSchema = z
  .object({ revision: z.number().int().min(0).optional() })
  .strict();

/** Rust `GuardrailDryRunRequest`. */
export const dryRunRequestSchema = z
  .object({
    revision: z.number().int().min(0).optional(),
    stage: z.enum(DETECTOR_STAGES),
    organization_id: z.string().optional(),
    project_id: z.string().optional(),
    workspace_id: z.string().optional(),
    api_key_id: z.string().optional(),
    service_account_id: z.string().optional(),
    gateway_config_id: z.string().optional(),
    model: z.string().optional(),
    provider: z.string().optional(),
    text: z.string().default(""),
  })
  .strict();

/** `(policy_id, revision)` flattened to the store's string id. */
function revisionId(policyId: string, revision: number): string {
  return `${policyId}@${revision}`;
}

function revisionNumber(record: StoreRecord): number {
  const value = record.revision;
  return typeof value === "number" ? value : 0;
}

/** Parse the `{revision}` path segment. Non-numeric names no revision → 404. */
function readRevisionParam(revision: string, policyId: string): number {
  const parsed = Number.parseInt(revision, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new HttpError(
      404,
      "not_found",
      `guardrail policy ${policyId} revision ${revision} not found`,
    );
  }
  return parsed;
}

export const guardrailPolicyRoutes: GroupModule = crudGroup("guardrail_policy", [], {
  /** Every policy's current head revision. */
  listGuardrailPolicyRevisions: async (c) => {
    const deps = c.get("deps");
    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
    const page = await deps.store.list(POLICIES, scopeOf(c), query);
    return json(c, 200, listResponse(page, query));
  },

  /** Create a policy and its revision 1 in one call. */
  createGuardrailPolicyRevision: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const body = await readJson(c, guardrailRevisionSchema);
    const policyId =
      typeof body.policy_id === "string" && body.policy_id.trim() !== ""
        ? body.policy_id.trim()
        : crypto.randomUUID();

    const revision = 1;
    const stored = await deps.store.create(REVISIONS, scope, {
      ...body,
      id: revisionId(policyId, revision),
      policy_id: policyId,
      revision,
      status: "draft",
    });
    const existingPolicy = await deps.store.get(POLICIES, scope, policyId);
    if (existingPolicy === null) {
      await deps.store.create(POLICIES, scope, {
        id: policyId,
        policy_id: policyId,
        head_revision: revision,
        active_revision: null,
      });
    } else {
      await deps.store.merge(POLICIES, scope, policyId, { head_revision: revision });
    }
    return json(c, 201, { object: "guardrail_policy_revision", policy: stored });
  },

  /** The policy's head/active revision view. */
  listGuardrailPolicyRevisionsByPolicy: async (c) => {
    const deps = c.get("deps");
    const policyId = pathParam(c, "policy_id");
    const record = await deps.store.get(POLICIES, scopeOf(c), policyId);
    if (record === null) {
      throw new HttpError(404, "not_found", `guardrail policy ${policyId} not found`);
    }
    return json(c, 200, { object: "guardrail_policy_revision", policy: record });
  },

  listGuardrailPolicyRevisionHistory: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const policyId = pathParam(c, "policy_id");
    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
    const scoped = { ...query, filters: { ...query.filters, policy_id: policyId } };
    const page = await deps.store.list(REVISIONS, scope, scoped);
    return json(c, 200, listResponse(page, scoped));
  },

  /** A new revision is always `max(existing) + 1` — monotonic and immutable. */
  createNextGuardrailPolicyRevision: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const policyId = pathParam(c, "policy_id");
    const body = await readJson(c, guardrailRevisionSchema);

    const history = await deps.store.list(REVISIONS, scope, {
      offset: 0,
      limit: Number.MAX_SAFE_INTEGER,
      paginate: false,
      search: null,
      filters: { policy_id: policyId },
    });
    const next = history.items.reduce((max, item) => Math.max(max, revisionNumber(item)), 0) + 1;

    const stored = await deps.store.create(REVISIONS, scope, {
      ...body,
      id: revisionId(policyId, next),
      policy_id: policyId,
      revision: next,
      status: "draft",
    });
    await deps.store.merge(POLICIES, scope, policyId, { head_revision: next });
    return json(c, 201, { object: "guardrail_policy_revision", policy: stored });
  },

  getGuardrailPolicyRevision: async (c) => {
    const deps = c.get("deps");
    const policyId = pathParam(c, "policy_id");
    const revision = readRevisionParam(pathParam(c, "revision"), policyId);
    const record = await deps.store.get(REVISIONS, scopeOf(c), revisionId(policyId, revision));
    if (record === null) {
      throw new HttpError(
        404,
        "not_found",
        `guardrail policy ${policyId} revision ${revision} not found`,
      );
    }
    return json(c, 200, { object: "guardrail_policy_revision", policy: record });
  },

  /** Archive marks the revision; it never renumbers or drops history. */
  archiveGuardrailPolicyRevision: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const policyId = pathParam(c, "policy_id");
    const revision = readRevisionParam(pathParam(c, "revision"), policyId);
    const id = revisionId(policyId, revision);
    const archived = await deps.store.merge(REVISIONS, scope, id, {
      status: "archived",
      archived_at: Math.floor(Date.now() / 1000),
    });
    if (archived === null) {
      throw new HttpError(
        404,
        "not_found",
        `guardrail policy ${policyId} revision ${revision} not found`,
      );
    }
    return json(c, 200, adminDeleted("guardrail_policy_revision", id));
  },

  activateGuardrailPolicyRevision: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const policyId = pathParam(c, "policy_id");
    const { revision } = await readJson(c, revisionSelectionSchema);
    const target = await deps.store.get(REVISIONS, scope, revisionId(policyId, revision));
    if (target === null) {
      throw new HttpError(
        404,
        "not_found",
        `guardrail policy ${policyId} revision ${revision} not found`,
      );
    }
    await deps.store.merge(REVISIONS, scope, revisionId(policyId, revision), { status: "active" });
    const policy = await deps.store.merge(POLICIES, scope, policyId, {
      active_revision: revision,
      activated_at: Math.floor(Date.now() / 1000),
    });
    if (policy === null) {
      throw new HttpError(404, "not_found", `guardrail policy ${policyId} not found`);
    }
    return json(c, 200, { object: "guardrail_policy_revision", policy });
  },

  /**
   * Roll back to an explicit revision, or — when the body omits it (Rust
   * `RollbackSelection { revision: Option<u32> }`) — to the highest revision
   * below the active one.
   */
  rollbackGuardrailPolicyRevision: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const policyId = pathParam(c, "policy_id");
    const selection = await readJson(c, rollbackSelectionSchema);

    const policy = await deps.store.get(POLICIES, scope, policyId);
    if (policy === null) {
      throw new HttpError(404, "not_found", `guardrail policy ${policyId} not found`);
    }

    let target = selection.revision;
    if (target === undefined) {
      const active = typeof policy.active_revision === "number" ? policy.active_revision : 0;
      const history = await deps.store.list(REVISIONS, scope, {
        offset: 0,
        limit: Number.MAX_SAFE_INTEGER,
        paginate: false,
        search: null,
        filters: { policy_id: policyId },
      });
      const previous = history.items
        .map(revisionNumber)
        .filter((value) => value < active)
        .reduce((max, value) => Math.max(max, value), 0);
      if (previous === 0) {
        throw new HttpError(
          409,
          "conflict",
          `guardrail policy ${policyId} has no earlier revision to roll back to`,
        );
      }
      target = previous;
    }

    if ((await deps.store.get(REVISIONS, scope, revisionId(policyId, target))) === null) {
      throw new HttpError(
        404,
        "not_found",
        `guardrail policy ${policyId} revision ${target} not found`,
      );
    }
    const rolled = await deps.store.merge(POLICIES, scope, policyId, {
      active_revision: target,
      rolled_back_at: Math.floor(Date.now() / 1000),
    });
    return json(c, 200, { object: "guardrail_policy_revision", policy: rolled });
  },

  /**
   * Evaluate a revision against a supplied context WITHOUT mutating anything —
   * the reason this POST is `admin.read` rather than `admin.write`.
   *
   * PORT-TODO(inventory-policy-core §guardrails): run the real detector chain
   * through `@ferrogate/guardrails` once that package lands. Until then the
   * response reports the selection outcome (which revision would be chosen for
   * the given stage/context) and an empty check list, and — critically — still
   * dispatches nothing: `provider_dispatched`/`external_action_dispatched` stay
   * false, matching Rust's `GuardrailDryRunResponse`.
   */
  dryRunGuardrailPolicyRevision: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const policyId = pathParam(c, "policy_id");
    const request = await readJson(c, dryRunRequestSchema);

    const policy = await deps.store.get(POLICIES, scope, policyId);
    if (policy === null) {
      throw new HttpError(404, "not_found", `guardrail policy ${policyId} not found`);
    }
    const selected =
      request.revision ??
      (typeof policy.active_revision === "number" ? policy.active_revision : null);
    if (selected === null) {
      throw new HttpError(409, "conflict", `guardrail policy ${policyId} has no active revision`);
    }
    const revision = await deps.store.get(REVISIONS, scope, revisionId(policyId, selected));
    if (revision === null) {
      throw new HttpError(
        404,
        "not_found",
        `guardrail policy ${policyId} revision ${selected} not found`,
      );
    }

    return json(c, 200, {
      object: "guardrail_dry_run",
      policy_revision: revisionId(policyId, selected),
      selected: true,
      result: "pass",
      checks: [],
      on_pass: revision.on_pass ?? [],
      on_fail: revision.on_fail ?? [],
      on_error: revision.on_error ?? [],
      provider_dispatched: false,
      external_action_dispatched: false,
      stage: request.stage,
    });
  },
});
