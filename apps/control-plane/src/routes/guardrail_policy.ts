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
import {
  type CheckBinding,
  type DetectorDefinition,
  type PolicyRevision,
  type PolicyScopeSelector,
  type PolicySelectionContext,
  admitPolicyRevision,
  byteLen,
  checkBindingSchema,
  policyRevisionSchema,
  policyScopeSelectorSchema,
  scopeMatches,
} from "@ferrogate/guardrails";
import type { Context } from "hono";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { ControlPlaneEnv, StoreRecord } from "../ports.js";
import { adminDeleted, listResponse, parseListQuery } from "../responses.js";
import {
  projectGuardrailActivation,
  projectGuardrailArchive,
  projectGuardrailRevision,
} from "../store/guardrail_registry.js";
import { type GroupModule, crudGroup, json, pathParam, readJson, scopeOf } from "./resource.js";

const POLICIES = "guardrail-policies";
const REVISIONS = "guardrail-policy-revisions";

/**
 * Rust `DetectorStage` (`crates/ferrogate-guardrails/src/contract.rs`), which is
 * `Request | Response` and nothing else — the same two values
 * `@ferrogate/guardrails`' `detectorStageSchema` carries and the same two the
 * committed contract document's `GuardrailPolicyDryRunRequest.stage` enumerates.
 *
 * An earlier wave of this port spelled these `input`/`output`/`tool`, which is
 * not a stage vocabulary that exists anywhere in the reference: a check is bound
 * to a stage with `check.stage`, and a dry-run filters `checks` by it, so a
 * request naming `input` could never match a stored check and the endpoint
 * silently reported an empty check list for every policy.
 */
export const DETECTOR_STAGES = ["request", "response"] as const;

/**
 * The create-revision request body: Rust's `PolicyRevision` itself, which is
 * `#[serde(deny_unknown_fields)]` — so `@ferrogate/guardrails`' `.strict()`
 * twin IS the body schema, not an approximation of it.
 *
 * **This is a behaviour change and it is the point of the slice.** The previous
 * schema made `checks`, `on_pass`, `on_fail`, `on_error` optional, had no
 * `name`, and was `.passthrough()` — so `{"policy_id":"gp1","detectors":[]}`
 * was a `201`. It cannot be one: `detectors` is not a field of Rust's
 * `PolicyRevision` at all, and a document with no `name`/`checks`/actions is
 * one the data plane could never enforce. A shape failure here is Rust's SERDE
 * leg (`read_guardrail_body` → `400 invalid_request_body`, with the field path
 * `readJson` attaches); a document that PARSES but cannot be enforced is the
 * `validate()`/compile leg and is `400 invalid_guardrail_policy` — see
 * {@link admitRevision}.
 *
 * `policy_id`, `revision`, `created_at_unix` and `created_by` are accepted here
 * because Rust accepts them (`#[serde(default)]`), and then overwritten by the
 * server exactly as Rust overwrites them.
 */
export const guardrailRevisionSchema = policyRevisionSchema;

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

// ---------------------------------------------------------------------------
// Dry-run evaluation (Rust `dry_run_check` / `detector_kind`)
// ---------------------------------------------------------------------------

/** Rust `GuardrailDryRunCheck`. */
export interface DryRunCheck {
  readonly id: string;
  readonly detector: string;
  readonly result: "pass" | "fail" | "disabled" | "not_executed";
}

/** Rust `detector_kind` — the wire name of a detector definition's variant. */
function detectorKind(detector: DetectorDefinition): string {
  return detector.kind;
}

/**
 * Rust `dry_run_check`, clean-room.
 *
 * The three outcomes that are NOT a real evaluation are the point of the
 * endpoint, not a shortcut:
 *
 *  - `disabled`     — the binding is switched off, so nothing runs.
 *  - `not_executed` — the detector is a REMOTE one (`custom_http`, `presidio`,
 *    `llm_guard_prompt_injection`, `workers_ai_llama_guard`), or a `local` one
 *    whose evaluation needs the request document rather than the supplied text
 *    (`json` / `request` constraints, or built-in `secret_patterns`, which also
 *    dereference a host secret for keyed evidence). A dry-run must not dispatch
 *    to a detector endpoint or resolve a secret — that is exactly what the
 *    `provider_dispatched` / `external_action_dispatched` `false` pair on the
 *    response asserts, and what `result: "planned"` means.
 *  - otherwise the plain keyword / regex / size constraints of the `local`
 *    detector are evaluated against `text` and answer `pass` / `fail`.
 *
 * `max_input_bytes` is compared against the UTF-8 BYTE length (Rust `str::len()`
 * is bytes), via `@ferrogate/guardrails`' `byteLen` — `text.length` would count
 * UTF-16 code units and let a multi-byte payload slip under a byte cap.
 *
 * PLATFORM NOTE (workerd): Rust matches with the `regex` crate, which is
 * linear-time by construction. `RegExp` is a backtracking engine and workerd
 * exposes no linear-time alternative and no way to time-bound a synchronous
 * match, so a pathological stored pattern costs more here than it does in Rust.
 * The blast radius is bounded by the fact that both the pattern and the text
 * come from an already-authenticated `admin.read` caller.
 */
function dryRunCheck(check: CheckBinding, text: string): DryRunCheck {
  const detector = detectorKind(check.detector);
  if (!check.enabled) return { id: check.id, detector, result: "disabled" };
  if (check.detector.kind !== "local") return { id: check.id, detector, result: "not_executed" };

  const local = check.detector;
  if (local.json !== undefined || local.request !== undefined || local.secret_patterns.length > 0) {
    return { id: check.id, detector, result: "not_executed" };
  }

  const maxInputBytes = local.max_input_bytes;
  const matched =
    (maxInputBytes !== null && maxInputBytes !== undefined && byteLen(text) > maxInputBytes) ||
    local.keywords.some((keyword) => text.includes(keyword)) ||
    local.regex.some((pattern) => {
      // Rust: `Regex::new(pattern).is_ok_and(|c| c.is_match(text))` — a pattern
      // that does not compile does not match, it does not abort the dry-run.
      try {
        return new RegExp(pattern).test(text);
      } catch {
        return false;
      }
    });
  return { id: check.id, detector, result: matched ? "fail" : "pass" };
}

/**
 * The stored revision document's `checks`, parsed with the authoritative
 * `@ferrogate/guardrails` `checkBindingSchema`.
 *
 * A check the schema refuses is reported as `not_executed` rather than dropped:
 * "this revision has a check I cannot evaluate" and "this revision has no such
 * check" are different facts, and only the first one is true. Silently omitting
 * it would let an operator read a clean dry-run for a policy that has an
 * unevaluable binding in it.
 */
function parseChecks(record: StoreRecord): { checks: CheckBinding[]; unparsed: DryRunCheck[] } {
  const raw = record.checks;
  if (!Array.isArray(raw)) return { checks: [], unparsed: [] };
  const checks: CheckBinding[] = [];
  const unparsed: DryRunCheck[] = [];
  for (const [index, entry] of raw.entries()) {
    const parsed = checkBindingSchema.safeParse(entry);
    if (parsed.success) {
      checks.push(parsed.data as CheckBinding);
      continue;
    }
    const id =
      typeof entry === "object" &&
      entry !== null &&
      typeof (entry as { id?: unknown }).id === "string"
        ? (entry as { id: string }).id
        : `#${index}`;
    unparsed.push({ id, detector: "unparseable", result: "not_executed" });
  }
  return { checks, unparsed };
}

/**
 * The stored revision's `scope`, parsed with `policyScopeSelectorSchema`.
 *
 * A revision with NO `scope` is unfenced and matches every selection context,
 * which is `PolicyScopeSelector::default()` in Rust. A revision whose `scope` is
 * present but MALFORMED is fail-closed to "matches nothing": a dry-run that
 * claimed an unparseable fence applies would be the misleading answer, and this
 * is the direction that cannot leak another tenant's policy into a selection.
 */
function parseScope(record: StoreRecord): PolicyScopeSelector | null {
  const empty: PolicyScopeSelector = {
    tenant_ids: [],
    organization_ids: [],
    project_ids: [],
    workspace_ids: [],
    api_key_ids: [],
    gateway_config_ids: [],
    models: [],
    providers: [],
  };
  if (record.scope === undefined || record.scope === null) return empty;
  const parsed = policyScopeSelectorSchema.safeParse(record.scope);
  return parsed.success ? (parsed.data as PolicyScopeSelector) : null;
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

// ---------------------------------------------------------------------------
// Admission + projection (the write half)
// ---------------------------------------------------------------------------

/**
 * The `PolicyRevision` fields, so a STORED document can be read back as a
 * revision candidate without its control-plane bookkeeping (`id`, `status`,
 * `archived_at`, `tenant_id`) tripping the `.strict()` schema.
 *
 * A picked field list rather than a delete list on purpose: a bookkeeping field
 * added later must not silently become part of the revision the data plane
 * compiles.
 */
const REVISION_FIELDS = [
  "policy_id",
  "revision",
  "name",
  "description",
  "enforced",
  "scope",
  "checks",
  "aggregation",
  "execution",
  "mode",
  "streaming",
  "on_pass",
  "on_fail",
  "on_error",
  "deadline_ms",
  "created_at_unix",
  "created_by",
] as const;

function revisionFieldsOf(record: StoreRecord): Record<string, unknown> {
  const candidate: Record<string, unknown> = {};
  for (const field of REVISION_FIELDS) {
    if (record[field] !== undefined) candidate[field] = record[field];
  }
  return candidate;
}

/**
 * Rust `auth.api_key_id.unwrap_or("platform_operator")` — the `created_by`
 * `validatePolicyRevision` requires to be non-empty.
 */
function createdBy(c: Context<ControlPlaneEnv>): string {
  const subject = c.get("auth")?.subject;
  return subject !== null && subject !== undefined && subject.trim() !== ""
    ? subject
    : "platform_operator";
}

/**
 * The create-time compile gate — the reason this group's write half could not
 * be closed until now, closed by tightening admission rather than loosening
 * compilation.
 *
 * `apps/gateway/src/guardrails/binding.ts::policySourceFromStore` compiles every
 * active revision EAGERLY, once, at construction. A revision it cannot compile
 * is therefore not a per-request failure — it is a boot failure for the whole
 * guardrail source. Rust makes the identical trade in the identical place:
 * `state.rs::create_guardrail_policy_revision` calls
 * `build_guardrail_policy_runtime(revision, ..)?` BEFORE inserting, and the
 * handler renders the failure as `400 invalid_guardrail_policy`
 * (`server/guardrail_policies.rs::write_guardrail_error`, `None =>`).
 *
 * `admitPolicyRevision` lives in `@ferrogate/guardrails` and is nothing but
 * `policyRevisionSchema` + `validatePolicyRevision` — the SAME pair the
 * gateway's `putRevision` runs on its boot path — plus the field path. There is
 * no second validator to drift.
 *
 * What it cannot cover, by construction: `buildDetector` also resolves
 * `secret_ref` / `fingerprint_secret_ref` against the GATEWAY's Worker
 * bindings, which this Worker cannot see. That residue is handled on the other
 * side, by `policySourceFromStore` failing that ONE policy closed instead of
 * failing the boot.
 */
function admitRevision(
  candidate: Record<string, unknown>,
  options: { shapeCode?: string } = {},
): PolicyRevision {
  const admission = admitPolicyRevision(candidate, options);
  if (!admission.ok) {
    throw new HttpError(400, admission.error.code, admission.error.detail);
  }
  return admission.revision;
}

/**
 * Publish `revision` as the policy's live binding — the ONE row the data plane
 * enforces from — before the documents are touched.
 *
 * Three things happen here and the order is load-bearing:
 *
 *  1. **The stored document is re-admitted.** Admission was tightened at
 *     create, but revisions written BEFORE the tightening are still in the
 *     document store, and activating one would publish a revision the gateway
 *     cannot compile. Refused as `400 invalid_guardrail_policy`, exactly as a
 *     fresh unenforceable body is.
 *  2. **The immutable revision row is re-projected.** `INSERT … ON CONFLICT DO
 *     NOTHING`, so this is a no-op for a revision whose create already projected
 *     it and a repair for one whose typed write did not land. Without it a
 *     binding could point at a revision the gateway has no text for, which
 *     `loadGuardrailPolicyStore` skips — a policy that reads as active and
 *     screens nothing.
 *  3. **The binding CAS.** A lost update is a typed `409`, never a silent
 *     re-base onto the winner's state.
 *
 * The projection precedes the document merge because a guardrail is a
 * RESTRICTION: a crash between them leaves the data plane enforcing a revision
 * the document does not yet show as active (over-enforcement, visible as
 * denials), rather than an operator being told content is screened when it is
 * not.
 */
async function activateProjection(
  c: Context<ControlPlaneEnv>,
  policyId: string,
  revision: number,
  record: StoreRecord,
): Promise<void> {
  const db = c.get("deps").controlDatabase;
  if (db === null) return;
  const admitted = admitRevision(
    { ...revisionFieldsOf(record), policy_id: policyId, revision },
    // No request body carries this one — it came out of the store — so both
    // legs report Rust's stored-revision code rather than blaming the caller's
    // (valid) `{"revision": N}` selection.
    { shapeCode: "invalid_guardrail_policy" },
  );
  const nowUnix = Math.floor(Date.now() / 1000);
  await projectGuardrailRevision(db, admitted, nowUnix);
  const outcome = await projectGuardrailActivation(db, policyId, revision, createdBy(c), nowUnix);
  if (!outcome.ok) {
    throw new HttpError(409, "guardrail_policy_conflict", outcome.conflict);
  }
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
    const nowUnix = Math.floor(Date.now() / 1000);
    // Admission BEFORE the store touch: a refusal must leave no document
    // behind, or the very row this gate exists to keep out of the enforcement
    // table would still be sitting in the document store waiting for someone to
    // activate it.
    const admitted = admitRevision({
      ...body,
      policy_id: policyId,
      revision,
      created_at_unix: nowUnix,
      created_by: createdBy(c),
    });

    const stored = await deps.store.create(REVISIONS, scope, {
      ...admitted,
      id: revisionId(policyId, revision),
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
    // Document first, then the immutable enforcement row: a crash between them
    // leaves a revision the operator can SEE but cannot yet activate, and
    // `activate` re-projects it, so it heals. See `store/guardrail_registry.ts`.
    const db = deps.controlDatabase;
    if (db !== null) {
      await projectGuardrailRevision(db, admitted, nowUnix);
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

    // Rust: a body that names a DIFFERENT policy is a typed refusal, not a
    // silent overwrite by the path segment.
    if (body.policy_id.trim() !== "" && body.policy_id.trim() !== policyId) {
      throw new HttpError(
        400,
        "guardrail_policy_id_mismatch",
        "body policy_id must match the path",
      );
    }

    const history = await deps.store.list(REVISIONS, scope, {
      offset: 0,
      limit: Number.MAX_SAFE_INTEGER,
      paginate: false,
      search: null,
      filters: { policy_id: policyId },
    });
    const next = history.items.reduce((max, item) => Math.max(max, revisionNumber(item)), 0) + 1;
    const nowUnix = Math.floor(Date.now() / 1000);
    const admitted = admitRevision({
      ...body,
      policy_id: policyId,
      revision: next,
      created_at_unix: nowUnix,
      created_by: createdBy(c),
    });

    const stored = await deps.store.create(REVISIONS, scope, {
      ...admitted,
      id: revisionId(policyId, next),
      status: "draft",
    });
    await deps.store.merge(POLICIES, scope, policyId, { head_revision: next });
    const db = deps.controlDatabase;
    if (db !== null) {
      await projectGuardrailRevision(db, admitted, nowUnix);
    }
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
    const nowUnix = Math.floor(Date.now() / 1000);
    const archived = await deps.store.merge(REVISIONS, scope, id, {
      status: "archived",
      archived_at: nowUnix,
    });
    if (archived === null) {
      throw new HttpError(
        404,
        "not_found",
        `guardrail policy ${policyId} revision ${revision} not found`,
      );
    }
    // Document first, then the enforcement pointer. The operator has been told
    // the revision is archived; a residual `active_revision` would mean the data
    // plane is still applying it on every request.
    const db = deps.controlDatabase;
    if (db !== null) {
      const outcome = await projectGuardrailArchive(db, policyId, revision, createdBy(c), nowUnix);
      if (!outcome.ok) {
        throw new HttpError(409, "guardrail_policy_conflict", outcome.conflict);
      }
      await deps.store.merge(POLICIES, scope, policyId, { active_revision: null });
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
    await activateProjection(c, policyId, revision, target);
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

    const targetRecord = await deps.store.get(REVISIONS, scope, revisionId(policyId, target));
    if (targetRecord === null) {
      throw new HttpError(
        404,
        "not_found",
        `guardrail policy ${policyId} revision ${target} not found`,
      );
    }
    await activateProjection(c, policyId, target, targetRecord);
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
   * Clean-room port of Rust `handle_guardrail_policy_dry_run` +
   * `dry_run_check`. Three things it now actually does, which the placeholder
   * did not:
   *
   *  1. **Selection is computed, not asserted.** `selected` is
   *     `@ferrogate/guardrails`' `scopeMatches(revision.scope, context)` over
   *     the request's tenancy/model/provider selectors — the same function the
   *     data plane selects revisions with. The placeholder hard-coded `true`,
   *     which told an operator a policy applied to a context it is fenced out
   *     of.
   *  2. **Checks are evaluated.** Every `check` whose `stage` equals the
   *     requested stage is reported as `pass`/`fail`/`disabled`/`not_executed`
   *     (see {@link dryRunCheck}). The placeholder always answered `[]`, i.e.
   *     "this policy has no checks", for every policy.
   *  3. **#515: only a DECLARED platform operator may name the tenant the
   *     policy is evaluated against.** A tenant-scoped caller that puts a
   *     different `organization_id` in the body is `403
   *     guardrail_policy_scope_denied`; read off "whoever omitted the field",
   *     an unclassified credential could otherwise pick any tenant it liked and
   *     have that become the selection context.
   *
   * It still dispatches nothing — `result` is the literal `"planned"` and
   * `provider_dispatched`/`external_action_dispatched` are `false`, matching
   * Rust's `GuardrailDryRunResponse` and the committed
   * `GuardrailPolicyDryRunResponse` contract schema.
   */
  dryRunGuardrailPolicyRevision: async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const policyId = pathParam(c, "policy_id");
    const request = await readJson(c, dryRunRequestSchema);

    // #515, before anything is read: the body may not re-point the selection at
    // another tenant.
    if (
      scope.kind === "tenant" &&
      request.organization_id !== undefined &&
      request.organization_id !== scope.tenantId
    ) {
      throw new HttpError(
        403,
        "guardrail_policy_scope_denied",
        "the Guardrail policy must be explicitly scoped to the caller's tenant",
      );
    }

    const policy = await deps.store.get(POLICIES, scope, policyId);
    if (policy === null) {
      throw new HttpError(404, "not_found", `guardrail policy ${policyId} not found`);
    }
    const target =
      request.revision ??
      (typeof policy.active_revision === "number" ? policy.active_revision : null);
    if (target === null) {
      throw new HttpError(409, "conflict", `guardrail policy ${policyId} has no active revision`);
    }
    const revision = await deps.store.get(REVISIONS, scope, revisionId(policyId, target));
    if (revision === null) {
      throw new HttpError(
        404,
        "not_found",
        `guardrail policy ${policyId} revision ${target} not found`,
      );
    }

    const selection: PolicySelectionContext = {
      // Platform operator: whatever the body named (or nothing). Tenant caller:
      // its OWN tenant, never the body's — the guard above already refused a
      // body that disagreed, so this cannot silently override an explicit ask.
      ...(scope.kind === "platform_operator"
        ? request.organization_id === undefined
          ? {}
          : { organization_id: request.organization_id }
        : { organization_id: scope.tenantId }),
      ...(request.project_id === undefined ? {} : { project_id: request.project_id }),
      ...(request.workspace_id === undefined ? {} : { workspace_id: request.workspace_id }),
      ...(request.api_key_id === undefined ? {} : { api_key_id: request.api_key_id }),
      ...(request.service_account_id === undefined
        ? {}
        : { service_account_id: request.service_account_id }),
      ...(request.gateway_config_id === undefined
        ? {}
        : { gateway_config_id: request.gateway_config_id }),
      ...(request.model === undefined ? {} : { model: request.model }),
      ...(request.provider === undefined ? {} : { provider: request.provider }),
    };

    const revisionScope = parseScope(revision);
    const selected = revisionScope !== null && scopeMatches(revisionScope, selection);
    const { checks, unparsed } = parseChecks(revision);
    // Rust: an UNSELECTED revision reports no checks at all — it would not run,
    // so reporting per-check outcomes for it would be reporting a plan that is
    // never executed.
    const reported: DryRunCheck[] = selected
      ? [
          ...checks
            .filter((check) => check.stage === request.stage)
            .map((check) => dryRunCheck(check, request.text)),
          ...unparsed,
        ]
      : [];

    return json(c, 200, {
      object: "guardrail_policy_dry_run",
      policy_revision: revisionId(policyId, target),
      selected,
      // Not a verdict: the dry-run PLANS, it does not enforce.
      result: "planned",
      checks: reported,
      on_pass: revision.on_pass ?? [],
      on_fail: revision.on_fail ?? [],
      on_error: revision.on_error ?? [],
      provider_dispatched: false,
      external_action_dispatched: false,
      stage: request.stage,
    });
  },
});
