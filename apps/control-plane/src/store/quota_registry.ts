/**
 * The WRITE half of the quota chain — `plans`, `quota_policies` and `tenants`
 * in the CONTROL database.
 *
 * ## What this closes
 *
 * `apps/gateway/src/ratelimit/quota.ts`'s `d1QuotaPolicySource` is the data
 * plane's admission gate: on EVERY authenticated request it issues one
 * `db.batch()` against the control database —
 *
 * ```sql
 * SELECT <16 columns> FROM quota_policies
 *   WHERE (scope_type = ? AND scope_id = ?) OR …          -- tenant→project→workspace→key
 * SELECT p.* FROM plans p JOIN tenants t ON t.plan_id = p.id WHERE t.id = ?
 * ```
 *
 * — and merges the result with `@ferrogate/policy`'s `resolveEffectiveQuota`.
 * `quotaPolicySourceFromEnv` selects it whenever `CONTROL_DB`/`BILLING_DB` is
 * bound, which is the production posture.
 *
 * **No TypeScript in this repo wrote any of those three tables.** The admin
 * surface here stored `POST /admin/v1/plans` and `POST /admin/v1/quota-policies`
 * as `control_plane_resources` DOCUMENTS and stopped there, so on every
 * deployment the gateway's policy leg returned zero rows and its plan leg
 * missed the join. The consequence is not a missing feature — it is the
 * limiter's failure direction inverted: `resolveEffectiveQuota` over an empty
 * chain yields NO rpm cap, NO tpm cap, NO monthly budget and NO model
 * allowlist, so every operator-configured limit was silently UNLIMITED while
 * `GET /admin/v1/tenant-accounts/{id}/resolved-defaults` (which reads the
 * documents) reported the configured numbers back. "The console says 60 rpm and
 * the gateway enforces none" is exactly the divergence
 * `getTenantResolvedDefaults` was written to prevent, one layer down.
 *
 * Same defect class as the MCP server catalog and the self-hosted-worker
 * registry: the reader mounted, the data path into it absent, every suite
 * green because each side was tested against its own fixture.
 *
 * ## Why the write belongs here
 *
 * `apps/control-plane` owns `env.DB`, and `env.DB` IS the control database the
 * gateway binds as `CONTROL_DB`/`BILLING_DB` (see `docs/rewrite/CLOUD-VERIFICATION.md`
 * §2(a): both gateway stanzas carry "uuid of the **control** database"). This is
 * the app where a plan, a quota policy and a tenant account are MINTED, so it is
 * the app that owes the typed rows — exactly as `store/tenancy.ts` owes
 * `projects`/`workspaces` to a tenant database and `store/worker_registry.ts`
 * owes `self_hosted_worker_registrations` to this one.
 *
 * ## One decode, so the two surfaces cannot drift
 *
 * {@link storedPlan} and {@link storedQuotaPolicy} are the document → value-type
 * decoders `getTenantResolvedDefaults` already used (they moved here from
 * `routes/tenant_hierarchy.ts`, which re-exports them). The projections below
 * are built FROM those same values, so the row the gateway reads decodes to the
 * value the admin surface reports. A second, hand-written document→column
 * mapping is precisely how the two would come to disagree.
 *
 * ## Ordering, and what a crash between the legs leaves
 *
 * The document (in `control_plane_resources`) and the typed row are two
 * statements. They are in the SAME database, but the document write is the
 * store's and the projection is the route's, so they are not one `batch()`:
 *
 * | path | order | a crash in between leaves |
 * |---|---|---|
 * | create / replace / patch | document, then the typed row | a configured limit the operator can see that is not yet enforced — identical to the state one millisecond before the projection, and healed idempotently by the next PUT/PATCH of the same row. It cannot fabricate a TIGHTER limit than the operator asked for. |
 * | delete | document, then the typed row | an enforcement row with no document: the limit keeps biting and the operator cannot see it. That is the CLOSED direction, and it is the one a limiter must fail in. |
 *
 * The inverse delete ordering is the tempting one and it is wrong: removing the
 * enforcement row first and then crashing leaves a policy the console still
 * lists and the gateway no longer applies — a limit that reports itself as
 * present while admitting unlimited traffic.
 *
 * ## `plan_id` when no plan is assigned
 *
 * `tenants.plan_id` is `NOT NULL DEFAULT 'free'`. A tenant account document that
 * names no plan must NOT be projected as `'free'`: if a plan with that id
 * exists, the gateway would apply its floor to a tenant the operator never put
 * on it, and `getTenantResolvedDefaults` (which reports `plan_id: null`) would
 * disagree with the enforcement. {@link NO_PLAN_ID} is written instead — the
 * empty string, which `plans.id` can never hold (`createHandler` mints a UUID
 * for a blank id and `pathParamSchema` refuses one), so the gateway's
 * `JOIN … ON t.plan_id = p.id` simply misses. A missed join is exactly Rust's
 * behaviour for a dangling `plan_id`: no plan, therefore no floor — the same
 * answer the document path gives.
 */
import type { QuotaScopeKind, StoredPlan, StoredQuotaPolicy } from "@ferrogate/policy";
import { StorageError, validateQuotaPolicy } from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";
import type { StoreRecord } from "../ports.js";

/** The three typed tables in `sql/d1-ts/control/0001_init_control.sql`. */
export const PLANS_TABLE = "plans";
export const QUOTA_POLICIES_TABLE = "quota_policies";
export const TENANTS_TABLE = "tenants";

/**
 * The `tenants.plan_id` written for a tenant account with no plan assignment.
 *
 * `NOT NULL` forbids the honest `NULL`, so this stands in for it: no row in
 * `plans` can carry the empty id, so the gateway's plan join misses and the
 * tenant gets no floor. See the module docblock.
 */
export const NO_PLAN_ID = "";

// ---------------------------------------------------------------------------
// Document → value type (moved from `routes/tenant_hierarchy.ts`)
// ---------------------------------------------------------------------------
//
// The field names below are the COLUMN names of `quota_policies` / `plans` in
// `sql/d1-ts/control/0001_init_control.sql`, not names invented here: the admin
// documents this app stores are the same shape those tables hold, so a document
// written through `POST /admin/v1/quota-policies` and a row projected out of
// `quota_policies` read identically. `@ferrogate/policy` is camelCase (it is the
// Rust value type, not the wire/row shape), so this is the one place the two
// vocabularies meet.

function optionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

/** `quota_policies` row/document → `StoredQuotaPolicy`. */
export function storedQuotaPolicy(
  record: StoreRecord,
  scopeType: QuotaScopeKind,
  scopeId: string,
): StoredQuotaPolicy {
  return {
    id: record.id,
    scopeType,
    scopeId,
    modelAllowlist: stringArray(record.model_allowlist),
    rpmLimit: optionalNumber(record.rpm_limit),
    tpmLimit: optionalNumber(record.tpm_limit),
    monthlyBudgetUsd: optionalNumber(record.monthly_budget_usd),
    assetStorageQuotaBytes: optionalNumber(record.asset_storage_quota_bytes),
    assetMaxObjectBytes: optionalNumber(record.asset_max_object_bytes),
    agentCostBudgetUsd: optionalNumber(record.agent_cost_budget_usd),
    alertThresholdPcts: Array.isArray(record.alert_threshold_pcts)
      ? record.alert_threshold_pcts.filter((pct): pct is number => typeof pct === "number")
      : [],
    // ABSENT means "this scope does not restrict", which is NOT the same as
    // `enabled = false` (a hard deny for the whole chain). Only an explicit
    // `false` disables.
    enabled: record.enabled !== false,
    createdAtUnix: optionalNumber(record.created_at) ?? 0,
    updatedAtUnix: optionalNumber(record.updated_at) ?? 0,
    monthlyEgressBytesBudget: optionalNumber(record.monthly_egress_bytes_budget),
    downloadRpmLimit: optionalNumber(record.download_rpm_limit),
  };
}

/** `plans` row/document → `StoredPlan` (the merge FLOOR, issue #168). */
export function storedPlan(record: StoreRecord): StoredPlan {
  return {
    id: record.id,
    name: typeof record.name === "string" ? record.name : record.id,
    slug: typeof record.slug === "string" ? record.slug : record.id,
    mcpEnabled: record.mcp_enabled === true,
    selfHostedWorkersEnabled: record.self_hosted_workers_enabled === true,
    adminConsoleSeats: optionalNumber(record.admin_console_seats),
    defaultModelAllowlist: stringArray(record.default_model_allowlist),
    defaultRpmLimit: optionalNumber(record.default_rpm_limit),
    defaultTpmLimit: optionalNumber(record.default_tpm_limit),
    defaultMonthlyBudgetUsd: optionalNumber(record.default_monthly_budget_usd),
    createdAtUnix: optionalNumber(record.created_at) ?? 0,
    updatedAtUnix: optionalNumber(record.updated_at) ?? 0,
    assetHostingEnabled: record.asset_hosting_enabled === true,
    defaultAssetStorageQuotaBytes: optionalNumber(record.default_asset_storage_quota_bytes),
    defaultAssetMaxObjectBytes: optionalNumber(record.default_asset_max_object_bytes),
    defaultAgentCostBudgetUsd: optionalNumber(record.default_agent_cost_budget_usd),
    defaultMonthlyEgressBytesBudget: optionalNumber(record.default_monthly_egress_bytes_budget),
    defaultDownloadRpmLimit: optionalNumber(record.default_download_rpm_limit),
    extensionToolsEnabled: record.extension_tools_enabled === true,
  };
}

// ---------------------------------------------------------------------------
// Column encoding
// ---------------------------------------------------------------------------

/** `undefined` → SQL `NULL`; D1 binds `null`, never `undefined`. */
function nullable(value: number | undefined): number | null {
  return value === undefined ? null : value;
}

/** SQLite has no boolean; the reader's `boolFromSqlite` expects 0/1. */
function bit(value: boolean): number {
  return value ? 1 : 0;
}

/**
 * A `NOT NULL UNIQUE` slug.
 *
 * The operator's own `slug` when they supplied one, otherwise the row id — the
 * SAME fallback {@link storedPlan} reports, so the admin view and the projected
 * row never name the row differently. The id is a primary key, so the fallback
 * cannot collide; an explicitly supplied duplicate can, and that surfaces as a
 * 409 rather than a 500 (see {@link projectionConflict}).
 */
function slugOf(record: StoreRecord, id: string): string {
  const slug = record.slug;
  return typeof slug === "string" && slug.trim() !== "" ? slug.trim() : id;
}

function text(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

/**
 * `required_tags` on a quota-policy document → the `required_tags_json` column
 * (#678). Non-strings and blanks are dropped, so a malformed entry cannot
 * become a tag name no caller can ever supply.
 */
function requiredTagsOf(record: StoreRecord): string[] {
  const raw = record.required_tags;
  if (!Array.isArray(raw)) return [];
  return [
    ...new Set(
      raw
        .filter((tag): tag is string => typeof tag === "string")
        .map((tag) => tag.trim())
        .filter((tag) => tag !== ""),
    ),
  ];
}

/**
 * `on_missing_tags` → the column, or SQL `NULL`.
 *
 * NULL is "this tenant is not enforced", and it is what an unrecognised value
 * projects to as well: half a policy is not a policy, and the gateway reader
 * (`attribution/policy.ts::parseMissingTagAction`) makes the same judgement
 * from the other side. The route schema already refuses anything but the two
 * spellings, so this arm is defence in depth for a document written before the
 * field existed.
 */
function missingTagActionOf(record: StoreRecord): string | null {
  const raw = record.on_missing_tags;
  return raw === "reject" || raw === "default_from_key" ? raw : null;
}

function residencyRegionsOf(record: StoreRecord): string[] {
  const raw = record.residency_regions;
  if (!Array.isArray(raw)) return [];
  return [
    ...new Set(
      raw
        .filter((region): region is string => typeof region === "string")
        .map((region) => region.trim())
        .filter((region) => region !== ""),
    ),
  ];
}

function zeroDataRetentionOf(record: StoreRecord): number {
  return record.require_zero_data_retention === true ? 1 : 0;
}

function logResidencyOf(record: StoreRecord): string | null {
  return record.log_residency === "in_region" || record.log_residency === "unconstrained"
    ? record.log_residency
    : null;
}

/**
 * The `spend_anomaly_*` numeric tuning fields, in COLUMN ORDER (#697).
 *
 * One list drives both the column list and the bind sequence, so a field cannot
 * be accepted by the route and then silently dropped on the way to the table —
 * which is exactly what happened to #692's `online_eval_*` opt-in columns:
 * shipped, read by the gateway, and settable through no operation at all.
 */
export const SPEND_ANOMALY_TUNING_FIELDS = [
  "spend_anomaly_baseline_windows",
  "spend_anomaly_min_baseline_windows",
  "spend_anomaly_min_active_windows",
  "spend_anomaly_min_window_usd",
  "spend_anomaly_ratio",
  "spend_anomaly_critical_ratio",
  "spend_anomaly_cooldown_secs",
  "spend_anomaly_forecast_min_pct",
  "spend_anomaly_auto_throttle_rpm",
  "spend_anomaly_throttle_ttl_secs",
] as const;

/**
 * `spend_anomaly_enabled` is `NOT NULL DEFAULT 1` — the detector watches every
 * tenant unless one opts out — so an omitted field projects as `1`, not as
 * `NULL`. Only an explicit `false`/`0` switches it off, the same rule
 * {@link storedQuotaPolicy} applies to `enabled`.
 */
function spendAnomalyEnabledOf(record: StoreRecord): number {
  const raw = record.spend_anomaly_enabled;
  return raw === false || raw === 0 ? 0 : 1;
}

/**
 * A UNIQUE-constraint failure on a projection is the operator's conflict, not
 * an internal error: two plans cannot share a slug. Anything else is re-thrown
 * unchanged so a real fault is not disguised as a 409.
 */
function projectionConflict(object: string, id: string, error: unknown): never {
  const message = error instanceof Error ? error.message : String(error);
  if (/UNIQUE constraint failed/i.test(message)) {
    throw new HttpError(
      409,
      "conflict",
      `${object} ${id} conflicts with an existing row: ${message}`,
    );
  }
  throw error;
}

// ---------------------------------------------------------------------------
// The projections
// ---------------------------------------------------------------------------

/**
 * Project a `plans` admin document into the typed `plans` row the gateway's
 * plan-floor join reads.
 *
 * `INSERT … ON CONFLICT (id) DO UPDATE` because PUT/PATCH must carry every
 * default through to the row, and because a retried create must not fail on the
 * leg the document write already accepted. `created_at_unix` is left alone on
 * update: a plan's creation time is not re-stamped by an edit.
 */
export async function projectPlan(
  db: D1Database,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  const plan = storedPlan(record);
  const id = String(record.id);
  try {
    await db
      .prepare(
        `INSERT INTO ${PLANS_TABLE} (
           id, name, slug, mcp_enabled, self_hosted_workers_enabled, admin_console_seats,
           default_model_allowlist_json, default_rpm_limit, default_tpm_limit,
           default_monthly_budget_usd, created_at_unix, updated_at_unix,
           asset_hosting_enabled, default_asset_storage_quota_bytes, extension_tools_enabled,
           default_monthly_egress_bytes_budget, default_download_rpm_limit,
           default_asset_max_object_bytes, default_agent_cost_budget_usd
         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           name = excluded.name,
           slug = excluded.slug,
           mcp_enabled = excluded.mcp_enabled,
           self_hosted_workers_enabled = excluded.self_hosted_workers_enabled,
           admin_console_seats = excluded.admin_console_seats,
           default_model_allowlist_json = excluded.default_model_allowlist_json,
           default_rpm_limit = excluded.default_rpm_limit,
           default_tpm_limit = excluded.default_tpm_limit,
           default_monthly_budget_usd = excluded.default_monthly_budget_usd,
           updated_at_unix = excluded.updated_at_unix,
           asset_hosting_enabled = excluded.asset_hosting_enabled,
           default_asset_storage_quota_bytes = excluded.default_asset_storage_quota_bytes,
           extension_tools_enabled = excluded.extension_tools_enabled,
           default_monthly_egress_bytes_budget = excluded.default_monthly_egress_bytes_budget,
           default_download_rpm_limit = excluded.default_download_rpm_limit,
           default_asset_max_object_bytes = excluded.default_asset_max_object_bytes,
           default_agent_cost_budget_usd = excluded.default_agent_cost_budget_usd`,
      )
      .bind(
        id,
        text(record.name, id),
        slugOf(record, id),
        bit(plan.mcpEnabled),
        bit(plan.selfHostedWorkersEnabled),
        nullable(plan.adminConsoleSeats),
        JSON.stringify(plan.defaultModelAllowlist),
        nullable(plan.defaultRpmLimit),
        nullable(plan.defaultTpmLimit),
        nullable(plan.defaultMonthlyBudgetUsd),
        nowUnix,
        nowUnix,
        bit(plan.assetHostingEnabled),
        nullable(plan.defaultAssetStorageQuotaBytes),
        bit(plan.extensionToolsEnabled),
        nullable(plan.defaultMonthlyEgressBytesBudget),
        nullable(plan.defaultDownloadRpmLimit),
        nullable(plan.defaultAssetMaxObjectBytes),
        nullable(plan.defaultAgentCostBudgetUsd),
      )
      .run();
  } catch (error) {
    projectionConflict("plan", id, error);
  }
}

/**
 * Project a `tenant-accounts` admin document into the typed `tenants` row.
 *
 * Only two of its columns are load-bearing for the data plane — `id` and
 * `plan_id`, the two the gateway's `JOIN plans p ON t.plan_id = p.id` traverses
 * — but `name`/`slug`/`status` are `NOT NULL`, so they are carried faithfully
 * rather than stubbed.
 */
export async function projectTenantAccount(
  db: D1Database,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  const id = String(record.id);
  const planId = record.plan_id;
  try {
    await db
      .prepare(
        // `document_json` carries the WHOLE admin document verbatim so the
        // operator LIST (`GET /admin/v1/tenant-accounts`) is served from ONE
        // control-DO query instead of a per-tenant Durable Object fan-out (#75).
        // The typed columns above stay authoritative for the data plane's
        // `JOIN plans`; the reader (`split.ts` `#listTenantAccountsMirror`) reads
        // this column back with a plain `JSON.parse`, so the listed row is
        // byte-identical to what the tenant object returns. `record` is the same
        // stored object the tenant DO persisted at every sync site, so no field
        // is lost (incl. `plan_effective_at` from `assignTenantPlan`).
        `INSERT INTO ${TENANTS_TABLE}
           (id, name, slug, status, plan_id, created_at_unix, updated_at_unix, document_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           name = excluded.name,
           slug = excluded.slug,
           status = excluded.status,
           plan_id = excluded.plan_id,
           updated_at_unix = excluded.updated_at_unix,
           document_json = excluded.document_json`,
      )
      .bind(
        id,
        text(record.name, id),
        slugOf(record, id),
        text(record.status, "active"),
        typeof planId === "string" && planId.trim() !== "" ? planId.trim() : NO_PLAN_ID,
        nowUnix,
        nowUnix,
        JSON.stringify(record),
      )
      .run();
  } catch (error) {
    projectionConflict("tenant_account", id, error);
  }
}

/**
 * Project a `quota-policies` admin document into the typed `quota_policies` row
 * the gateway's admission gate reads on every authenticated request.
 *
 * `validateQuotaPolicy` (`@ferrogate/storage`, the port of Rust
 * `validate_quota_policy`) runs FIRST and refuses with a `400`: the two asset
 * byte ceilings are tenant-only because stored assets and their usage are
 * tenant-owned, and a project-scoped row carrying one is a policy the Rust
 * storage layer would never have accepted. Refusing at the boundary is the
 * honest answer — dropping the two columns instead would silently store a
 * WIDER policy than the operator asked for.
 *
 * The conflict target is `id`, which the routes derive as `scope_type:scope_id`
 * (`quotaPolicyId`), so it and the table's `UNIQUE (scope_type, scope_id)` are
 * the same key by construction and cannot disagree.
 */
export async function projectQuotaPolicy(
  db: D1Database,
  record: StoreRecord,
  scopeType: QuotaScopeKind,
  scopeId: string,
  nowUnix: number,
): Promise<void> {
  const policy = storedQuotaPolicy(record, scopeType, scopeId);
  const id = String(record.id);
  try {
    validateQuotaPolicy(policy);
  } catch (error) {
    if (error instanceof StorageError) {
      throw new HttpError(400, "invalid_request_body", error.message);
    }
    throw error;
  }
  try {
    await db
      .prepare(
        `INSERT INTO ${QUOTA_POLICIES_TABLE} (
           id, scope_type, scope_id, model_allowlist_json, rpm_limit, tpm_limit,
           monthly_budget_usd, enabled, created_at_unix, updated_at_unix,
           alert_threshold_pcts_json, asset_storage_quota_bytes,
           monthly_egress_bytes_budget, download_rpm_limit, asset_max_object_bytes,
           agent_cost_budget_usd, required_tags_json, on_missing_tags,
           residency_regions_json, require_zero_data_retention, log_residency,
           spend_anomaly_enabled, ${SPEND_ANOMALY_TUNING_FIELDS.join(", ")}
         )
         VALUES (${Array.from({ length: 22 }, () => "?").join(", ")}${SPEND_ANOMALY_TUNING_FIELDS.map(
           () => ", ?",
         ).join("")})
         ON CONFLICT (id) DO UPDATE SET
           scope_type = excluded.scope_type,
           scope_id = excluded.scope_id,
           model_allowlist_json = excluded.model_allowlist_json,
           rpm_limit = excluded.rpm_limit,
           tpm_limit = excluded.tpm_limit,
           monthly_budget_usd = excluded.monthly_budget_usd,
           enabled = excluded.enabled,
           updated_at_unix = excluded.updated_at_unix,
           alert_threshold_pcts_json = excluded.alert_threshold_pcts_json,
           asset_storage_quota_bytes = excluded.asset_storage_quota_bytes,
           monthly_egress_bytes_budget = excluded.monthly_egress_bytes_budget,
           download_rpm_limit = excluded.download_rpm_limit,
           asset_max_object_bytes = excluded.asset_max_object_bytes,
           agent_cost_budget_usd = excluded.agent_cost_budget_usd,
           required_tags_json = excluded.required_tags_json,
           on_missing_tags = excluded.on_missing_tags,
           residency_regions_json = excluded.residency_regions_json,
           require_zero_data_retention = excluded.require_zero_data_retention,
           log_residency = excluded.log_residency,
           spend_anomaly_enabled = excluded.spend_anomaly_enabled,
           ${SPEND_ANOMALY_TUNING_FIELDS.map((field) => `${field} = excluded.${field}`).join(
             ",\n           ",
           )}`,
      )
      .bind(
        id,
        policy.scopeType,
        policy.scopeId,
        JSON.stringify(policy.modelAllowlist),
        nullable(policy.rpmLimit),
        nullable(policy.tpmLimit),
        nullable(policy.monthlyBudgetUsd),
        bit(policy.enabled),
        nowUnix,
        nowUnix,
        JSON.stringify(policy.alertThresholdPcts),
        nullable(policy.assetStorageQuotaBytes),
        nullable(policy.monthlyEgressBytesBudget),
        nullable(policy.downloadRpmLimit),
        nullable(policy.assetMaxObjectBytes),
        nullable(policy.agentCostBudgetUsd),
        // #678. Read off the DOCUMENT rather than through `StoredQuotaPolicy`,
        // because attribution is not part of the quota MERGE: `@ferrogate/policy`
        // resolves rpm/tpm/budget across the tenant→project→workspace→key chain,
        // and an attribution requirement is read at the tenant scope only (see
        // `apps/gateway/src/attribution/source.ts`). Threading it through the
        // merge value type would imply a chain semantic nothing implements.
        JSON.stringify(requiredTagsOf(record)),
        missingTagActionOf(record),
        JSON.stringify(residencyRegionsOf(record)),
        zeroDataRetentionOf(record),
        logResidencyOf(record),
        // #697. Read off the DOCUMENT for the same reason #678's tags are: the
        // spend-anomaly tuning is not part of the quota MERGE — the detector
        // reads the TENANT-scope row only (`finops/pass.ts`), and threading
        // these through `StoredQuotaPolicy` would imply a min-across-the-chain
        // semantic nothing implements and that would be meaningless anyway (the
        // tightest of two cooldowns is not a merge of them).
        //
        // ABSENT means "use the documented default", not "off", which is why
        // every numeric field goes in as `NULL` rather than a substituted
        // number: the defaults live in `finops/detector.ts` alone, and a copy
        // baked in here would be the one that drifts.
        spendAnomalyEnabledOf(record),
        ...SPEND_ANOMALY_TUNING_FIELDS.map((field) => optionalNumber(record[field]) ?? null),
      )
      .run();
  } catch (error) {
    projectionConflict("quota_policy", id, error);
  }
}

/**
 * Remove the typed enforcement row when the policy document is deleted.
 *
 * Keyed on `(scope_type, scope_id)` rather than on the flattened id, because
 * that pair is what the gateway's predicate matches — deleting by a
 * re-derived id would leave a row behind if the two spellings ever diverged.
 */
export async function deleteQuotaPolicyRow(
  db: D1Database,
  scopeType: QuotaScopeKind,
  scopeId: string,
): Promise<void> {
  await db
    .prepare(`DELETE FROM ${QUOTA_POLICIES_TABLE} WHERE scope_type = ? AND scope_id = ?`)
    .bind(scopeType, scopeId)
    .run();
}
