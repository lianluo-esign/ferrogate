import type { TenantDatabaseRouter } from "@ferrogate/storage";
import { canonicalProviderKind } from "../../../gateway/src/inference/adapters.js";
import type { CallerScope, StoreRecord } from "../ports.js";
import { type AuditAction, appendControlPlaneAudit, controlPlaneAuditJson } from "./d1.js";

export class TenantCatalogNotFoundError extends Error {
  override readonly name = "TenantCatalogNotFoundError";
}

export class TenantCatalogConflictError extends Error {
  override readonly name = "TenantCatalogConflictError";
}

export class TenantCatalogValidationError extends Error {
  override readonly name = "TenantCatalogValidationError";
}

export interface ProviderChannelInput {
  readonly id: string;
  readonly name: string;
  /** Stable product family. Platform providers persist it separately from adapter `kind`. */
  readonly provider_type_id?: string;
  readonly kind: string;
  readonly base_url: string;
  readonly api_key_var?: string | null;
  readonly byok_alias?: string | null;
  readonly auth_scheme?: "bearer" | "x-api-key" | null;
  readonly region?: string | null;
  readonly zero_data_retention?: boolean | null;
  readonly openrouter_http_referer?: string | null;
  readonly openrouter_x_title?: string | null;
  readonly cloudflare_ai_gateway?: unknown;
  readonly enabled?: boolean;
}

export interface ModelCatalogInput {
  readonly id: string;
  readonly name: string;
  readonly family?: string | null;
  readonly owned_by?: string | null;
  readonly capabilities?: readonly string[];
  readonly context_window?: number | null;
  readonly routing_strategy?: "priority" | "lowest_cost" | "lowest_latency" | "balanced";
  readonly enabled?: boolean;
}

export interface ModelOfferingInput {
  readonly id: string;
  readonly provider_id: string;
  readonly upstream_model_id: string;
  readonly role?: "primary" | "fallback" | "canary" | "shadow";
  readonly priority?: number;
  readonly weight?: number;
  readonly canary_percent?: number | null;
  readonly shadow_percent?: number | null;
  readonly shadow_max_requests?: number | null;
  readonly capabilities?: readonly string[] | null;
  readonly context_window?: number | null;
  readonly region?: string | null;
  readonly zero_data_retention?: boolean | null;
  readonly input_price_per_1m?: number | null;
  readonly output_price_per_1m?: number | null;
  readonly cached_input_price_per_1m?: number | null;
  readonly cache_write_price_per_1m?: number | null;
  readonly reasoning_price_per_1m?: number | null;
  readonly audio_second_price_per_1m?: number | null;
  readonly audio_character_price_per_1m?: number | null;
  readonly currency?: string;
  readonly source?: string;
  readonly enabled?: boolean;
}

interface ProviderRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly name: string;
  readonly kind: string;
  readonly base_url: string;
  readonly api_key_var: string | null;
  readonly byok_alias: string | null;
  readonly auth_scheme: string | null;
  readonly region: string | null;
  readonly zero_data_retention: number | null;
  readonly openrouter_http_referer: string | null;
  readonly openrouter_x_title: string | null;
  readonly cloudflare_ai_gateway_json: string | null;
  readonly enabled: number;
}

interface ModelRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly name: string;
  readonly family: string | null;
  readonly owned_by: string | null;
  readonly capabilities_json: string;
  readonly context_window: number | null;
  readonly routing_strategy: string;
  readonly enabled: number;
}

interface OfferingRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly model_id: string;
  readonly provider_id: string;
  readonly provider_name: string | null;
  readonly upstream_model_id: string;
  readonly role: string;
  readonly priority: number;
  readonly weight: number;
  readonly canary_percent: number | null;
  readonly shadow_percent: number | null;
  readonly shadow_max_requests: number | null;
  readonly capabilities_json: string | null;
  readonly context_window: number | null;
  readonly region: string | null;
  readonly zero_data_retention: number | null;
  readonly input_price_per_1m: number | null;
  readonly output_price_per_1m: number | null;
  readonly cached_input_price_per_1m: number | null;
  readonly cache_write_price_per_1m: number | null;
  readonly reasoning_price_per_1m: number | null;
  readonly audio_second_price_per_1m: number | null;
  readonly audio_character_price_per_1m: number | null;
  readonly currency: string;
  readonly source: string;
  readonly enabled: number;
}

interface CatalogAuditOutboxRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly revision: number | string;
  readonly action: AuditAction;
  readonly collection: string;
  readonly record_json: string;
  readonly audit_json: string;
  readonly request_id: string;
  readonly actor_scope: string;
  readonly actor_tenant_id: string | null;
}

export interface TenantCatalogAuditSweepReport {
  readonly scanned: number;
  readonly reconciled: number;
  readonly failed: number;
  readonly skipped: "control_database_unavailable" | "cadence_skipped" | null;
}

export interface TenantModelCatalogStoreOptions {
  readonly db: D1Database;
  readonly controlDatabase: D1Database;
  readonly requestId?: string | null;
}

type CatalogRecord = StoreRecord;
type UpdateField = readonly [string, string | number | null];

const PROVIDER_SELECT = `
  SELECT id, tenant_id, name, kind, base_url, api_key_var, byok_alias,
         auth_scheme, region, zero_data_retention, openrouter_http_referer,
         openrouter_x_title, cloudflare_ai_gateway_json, enabled
    FROM provider_channels`;

const MODEL_SELECT = `
  SELECT id, tenant_id, name, family, owned_by, capabilities_json,
         context_window, routing_strategy, enabled
    FROM catalog_models`;

const OFFERING_SELECT = `
  SELECT o.id, o.tenant_id, o.model_id, o.provider_id, p.name AS provider_name,
         o.upstream_model_id, o.role, o.priority, o.weight, o.canary_percent,
         o.shadow_percent, o.shadow_max_requests, o.capabilities_json,
         o.context_window, o.region, o.zero_data_retention,
         o.input_price_per_1m, o.output_price_per_1m,
         o.cached_input_price_per_1m, o.cache_write_price_per_1m,
         o.reasoning_price_per_1m, o.audio_second_price_per_1m,
         o.audio_character_price_per_1m, o.currency, o.source, o.enabled
    FROM catalog_model_offerings o
    LEFT JOIN provider_channels p
      ON p.tenant_id = o.tenant_id AND p.id = o.provider_id`;

/** Deliver durable catalog audit entries and remove only successfully delivered rows. */
export async function reconcileTenantCatalogAudit(
  db: D1Database,
  controlDatabase: D1Database,
  tenantId: string,
): Promise<void> {
  const pending = await db
    .prepare(
      `SELECT id, tenant_id, revision, action, collection, record_json, audit_json,
              request_id, actor_scope, actor_tenant_id
         FROM catalog_audit_outbox
        WHERE tenant_id = ?
        ORDER BY revision ASC, id ASC`,
    )
    .bind(tenantId)
    .all<CatalogAuditOutboxRow>();

  for (const row of pending.results) {
    try {
      const record = JSON.parse(row.record_json) as StoreRecord;
      const scope: CallerScope =
        row.actor_scope === "tenant" && row.actor_tenant_id !== null
          ? { kind: "tenant", tenantId: row.actor_tenant_id }
          : { kind: "platform_operator" };
      await appendControlPlaneAudit(controlDatabase, {
        action: row.action,
        collection: row.collection,
        record,
        revision: Number(row.revision),
        scope,
        requestId: row.request_id,
        auditJson: row.audit_json,
        newId: () => row.id,
      });
      await db
        .prepare("DELETE FROM catalog_audit_outbox WHERE tenant_id = ? AND id = ?")
        .bind(tenantId, row.id)
        .run();
    } catch (error) {
      await db
        .prepare(
          "UPDATE catalog_audit_outbox SET attempt_count = attempt_count + 1 WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenantId, row.id)
        .run()
        .catch(() => undefined);
      throw error;
    }
  }
}

/** Reconcile every provisioned tenant so delivery does not depend on a write. */
export async function reconcileProvisionedTenantCatalogAudits(
  router: TenantDatabaseRouter,
  controlDatabase: D1Database,
): Promise<TenantCatalogAuditSweepReport> {
  let tenantIds: readonly string[];
  try {
    tenantIds = await router.provisionedTenants();
  } catch (error) {
    console.warn("control-plane: tenant catalog audit roster lookup failed", error);
    return { scanned: 0, reconciled: 0, failed: 1, skipped: null };
  }

  let reconciled = 0;
  let failed = 0;
  for (const tenantId of tenantIds) {
    try {
      const handle = await router.forTenant(tenantId);
      await reconcileTenantCatalogAudit(handle.db, controlDatabase, tenantId);
      reconciled += 1;
    } catch (error) {
      failed += 1;
      console.warn(
        `control-plane: tenant catalog audit reconciliation failed for ${tenantId}`,
        error,
      );
    }
  }
  return { scanned: tenantIds.length, reconciled, failed, skipped: null };
}

export function hasOwn(input: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(input, key);
}

export function boolValue(value: number | boolean | null | undefined, fallback = false): boolean {
  if (value === null || value === undefined) return fallback;
  return value === true || value === 1;
}

export function boolSql(
  value: boolean | null | undefined,
  fallback: number | null = 1,
): number | null {
  if (value === null) return null;
  if (value === undefined) return fallback;
  return value ? 1 : 0;
}

export function providerCompatibility(kind: string): "openai-compatible" | "dedicated" {
  return canonicalProviderKind(kind) === "openai-compatible" ? "openai-compatible" : "dedicated";
}

export function jsonArray(value: unknown, field: string, fallback = "[]"): string {
  if (value === undefined) return fallback;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new TenantCatalogValidationError(`${field} must be an array of strings`);
  }
  return JSON.stringify(value);
}

export function parsedArray(value: string | null): readonly string[] {
  if (value === null || value === "") return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) && parsed.every((item) => typeof item === "string") ? parsed : [];
  } catch {
    return [];
  }
}

export function isConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /constraint|unique|foreign key|check failed/i.test(message);
}

export function urlIsValid(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

function providerRecord(row: ProviderRow): CatalogRecord {
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    name: row.name,
    kind: row.kind,
    compatibility: providerCompatibility(row.kind),
    base_url: row.base_url,
    has_api_key: Boolean(row.api_key_var || row.byok_alias),
    byok_alias: row.byok_alias,
    auth_scheme: row.auth_scheme,
    region: row.region,
    zero_data_retention: boolValue(row.zero_data_retention),
    openrouter_http_referer: row.openrouter_http_referer,
    openrouter_x_title: row.openrouter_x_title,
    cloudflare_ai_gateway: row.cloudflare_ai_gateway_json
      ? JSON.parse(row.cloudflare_ai_gateway_json)
      : null,
    enabled: boolValue(row.enabled, true),
  };
}

function offeringRecord(row: OfferingRow): CatalogRecord {
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    model_id: row.model_id,
    provider_id: row.provider_id,
    provider: row.provider_name,
    upstream_model_id: row.upstream_model_id,
    role: row.role,
    priority: row.priority,
    weight: row.weight,
    canary_percent: row.canary_percent,
    shadow_percent: row.shadow_percent,
    shadow_max_requests: row.shadow_max_requests,
    capabilities: parsedArray(row.capabilities_json),
    context_window: row.context_window,
    region: row.region,
    zero_data_retention: boolValue(row.zero_data_retention),
    input_price_per_1m: row.input_price_per_1m,
    output_price_per_1m: row.output_price_per_1m,
    cached_input_price_per_1m: row.cached_input_price_per_1m,
    cache_write_price_per_1m: row.cache_write_price_per_1m,
    reasoning_price_per_1m: row.reasoning_price_per_1m,
    audio_second_price_per_1m: row.audio_second_price_per_1m,
    audio_character_price_per_1m: row.audio_character_price_per_1m,
    currency: row.currency,
    source: row.source,
    enabled: boolValue(row.enabled, true),
  };
}

function routeRecord(row: OfferingRow): CatalogRecord {
  return {
    id: row.id,
    provider: row.provider_name,
    provider_model: row.upstream_model_id,
    capabilities: parsedArray(row.capabilities_json),
    priority: row.priority,
    weight: row.weight,
    input_price_per_1m: row.input_price_per_1m,
    output_price_per_1m: row.output_price_per_1m,
    cached_input_price_per_1m: row.cached_input_price_per_1m,
    cache_write_price_per_1m: row.cache_write_price_per_1m,
    reasoning_price_per_1m: row.reasoning_price_per_1m,
    audio_second_price_per_1m: row.audio_second_price_per_1m,
    audio_character_price_per_1m: row.audio_character_price_per_1m,
  };
}

function modelRecord(row: ModelRow, offerings: readonly OfferingRow[]): CatalogRecord {
  const primary = offerings.find((offering) => offering.role === "primary") ?? offerings[0];
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    name: row.name,
    family: row.family,
    owned_by: row.owned_by,
    capabilities: parsedArray(row.capabilities_json),
    context_window: row.context_window,
    routing_strategy: row.routing_strategy,
    enabled: boolValue(row.enabled, true),
    provider: primary?.provider_name ?? null,
    provider_model: primary?.upstream_model_id ?? null,
    fallbacks: offerings.filter((offering) => offering.role === "fallback").map(routeRecord),
    offerings: offerings.map(offeringRecord),
  };
}

function updateStatement(
  db: D1Database,
  table: string,
  fields: readonly UpdateField[],
  tenantId: string,
  id: string,
  now: number,
  ignoreConflicts = false,
): D1PreparedStatement {
  const assignments = fields.map(([column]) => `${column} = ?`).join(", ");
  const verb = ignoreConflicts ? "UPDATE OR IGNORE" : "UPDATE";
  return db
    .prepare(
      `${verb} ${table}
          SET ${assignments}, updated_at_unix = ?
        WHERE tenant_id = ? AND id = ?`,
    )
    .bind(...fields.map(([, value]) => value), now, tenantId, id);
}

export class TenantModelCatalogStore {
  readonly #db: D1Database;
  readonly #controlDatabase: D1Database;
  readonly #requestId: string;

  constructor(options: TenantModelCatalogStoreOptions) {
    this.#db = options.db;
    this.#controlDatabase = options.controlDatabase;
    this.#requestId = options.requestId ?? "";
  }

  async listProviders(tenantId: string): Promise<readonly CatalogRecord[]> {
    const result = await this.#db
      .prepare(`${PROVIDER_SELECT} WHERE tenant_id = ? ORDER BY created_at_unix ASC, id ASC`)
      .bind(tenantId)
      .all<ProviderRow>();
    return result.results.map(providerRecord);
  }

  async getProvider(tenantId: string, id: string): Promise<CatalogRecord | null> {
    const row = await this.#providerRow(tenantId, id);
    return row === null ? null : providerRecord(row);
  }

  async createProvider(
    tenantId: string,
    scope: CallerScope,
    input: ProviderChannelInput,
  ): Promise<CatalogRecord> {
    const normalized = this.#validateProvider(input);
    const now = Math.floor(Date.now() / 1000);
    await this.#commit(
      tenantId,
      scope,
      "create",
      "providers",
      { id: input.id, tenant_id: tenantId },
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO provider_channels
             (id, tenant_id, name, kind, base_url, api_key_var, byok_alias,
              auth_scheme, region, zero_data_retention, openrouter_http_referer,
              openrouter_x_title, cloudflare_ai_gateway_json, enabled,
              created_at_unix, updated_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          input.id,
          tenantId,
          normalized.name,
          normalized.kind,
          normalized.base_url,
          input.api_key_var ?? null,
          input.byok_alias ?? null,
          input.auth_scheme ?? null,
          input.region ?? null,
          boolSql(input.zero_data_retention, null),
          input.openrouter_http_referer ?? null,
          input.openrouter_x_title ?? null,
          input.cloudflare_ai_gateway === undefined || input.cloudflare_ai_gateway === null
            ? null
            : JSON.stringify(input.cloudflare_ai_gateway),
          boolSql(input.enabled),
          now,
          now,
        ),
      true,
    );
    const stored = await this.getProvider(tenantId, input.id);
    if (stored === null) throw new Error(`provider ${input.id} disappeared after create`);
    return stored;
  }

  async updateProvider(
    tenantId: string,
    scope: CallerScope,
    id: string,
    input: Partial<ProviderChannelInput>,
    action: "replace" | "merge",
  ): Promise<CatalogRecord | null> {
    const current = await this.#providerRow(tenantId, id);
    if (current === null) return null;
    const fields: UpdateField[] = [];
    if (action === "replace") {
      const name = this.#requiredText(input.name ?? current.name, "name");
      const kind = canonicalProviderKind(input.kind ?? current.kind);
      if (kind === null) {
        throw new TenantCatalogValidationError(`unsupported provider kind: ${input.kind}`);
      }
      const baseUrl = this.#requiredText(input.base_url ?? current.base_url, "base_url");
      if (!urlIsValid(baseUrl)) throw new TenantCatalogValidationError("base_url must be a URL");
      fields.push(["name", name], ["kind", kind], ["base_url", baseUrl]);
      fields.push(["api_key_var", input.api_key_var ?? null]);
      fields.push(["byok_alias", input.byok_alias ?? null]);
      fields.push(["auth_scheme", input.auth_scheme ?? null]);
      fields.push(["region", input.region ?? null]);
      fields.push(["zero_data_retention", boolSql(input.zero_data_retention, null)]);
      fields.push(["openrouter_http_referer", input.openrouter_http_referer ?? null]);
      fields.push(["openrouter_x_title", input.openrouter_x_title ?? null]);
      fields.push([
        "cloudflare_ai_gateway_json",
        input.cloudflare_ai_gateway === undefined || input.cloudflare_ai_gateway === null
          ? null
          : JSON.stringify(input.cloudflare_ai_gateway),
      ]);
      fields.push(["enabled", boolSql(input.enabled)]);
    } else {
      if (input.name !== undefined) fields.push(["name", this.#requiredText(input.name, "name")]);
      if (input.kind !== undefined) {
        const kind = canonicalProviderKind(input.kind);
        if (kind === null)
          throw new TenantCatalogValidationError(`unsupported provider kind: ${input.kind}`);
        fields.push(["kind", kind]);
      }
      if (input.base_url !== undefined) {
        const baseUrl = this.#requiredText(input.base_url, "base_url");
        if (!urlIsValid(baseUrl)) throw new TenantCatalogValidationError("base_url must be a URL");
        fields.push(["base_url", baseUrl]);
      }
      if (hasOwn(input, "api_key_var")) fields.push(["api_key_var", input.api_key_var ?? null]);
      if (hasOwn(input, "byok_alias")) fields.push(["byok_alias", input.byok_alias ?? null]);
      if (hasOwn(input, "auth_scheme")) fields.push(["auth_scheme", input.auth_scheme ?? null]);
      if (hasOwn(input, "region")) fields.push(["region", input.region ?? null]);
      if (hasOwn(input, "zero_data_retention")) {
        fields.push(["zero_data_retention", boolSql(input.zero_data_retention, null)]);
      }
      if (hasOwn(input, "openrouter_http_referer")) {
        fields.push(["openrouter_http_referer", input.openrouter_http_referer ?? null]);
      }
      if (hasOwn(input, "openrouter_x_title")) {
        fields.push(["openrouter_x_title", input.openrouter_x_title ?? null]);
      }
      if (hasOwn(input, "cloudflare_ai_gateway")) {
        fields.push([
          "cloudflare_ai_gateway_json",
          input.cloudflare_ai_gateway === undefined || input.cloudflare_ai_gateway === null
            ? null
            : JSON.stringify(input.cloudflare_ai_gateway),
        ]);
      }
      if (input.enabled !== undefined) fields.push(["enabled", boolSql(input.enabled)]);
    }
    if (fields.length === 0) fields.push(["name", current.name]);
    const changed = await this.#commit(
      tenantId,
      scope,
      action,
      "providers",
      { id, tenant_id: tenantId },
      updateStatement(
        this.#db,
        "provider_channels",
        fields,
        tenantId,
        id,
        Math.floor(Date.now() / 1000),
        true,
      ),
      true,
    );
    return changed ? this.getProvider(tenantId, id) : null;
  }

  async deleteProvider(tenantId: string, scope: CallerScope, id: string): Promise<boolean> {
    if ((await this.#providerRow(tenantId, id)) === null) return false;
    const live = await this.#db
      .prepare(
        "SELECT 1 AS present FROM catalog_model_offerings WHERE tenant_id = ? AND provider_id = ? LIMIT 1",
      )
      .bind(tenantId, id)
      .first<{ present: number }>();
    if (live !== null) throw new TenantCatalogConflictError(`provider ${id} has live offerings`);
    const deleted = await this.#commit(
      tenantId,
      scope,
      "remove",
      "providers",
      { id, tenant_id: tenantId },
      this.#db
        .prepare(
          `DELETE FROM provider_channels
            WHERE tenant_id = ? AND id = ?
              AND NOT EXISTS (
                SELECT 1 FROM catalog_model_offerings
                 WHERE tenant_id = ? AND provider_id = ?
              )`,
        )
        .bind(tenantId, id, tenantId, id),
    );
    if (deleted) return true;

    // The preflight and guarded DELETE are deliberately separate reads around
    // one atomic batch. If an offering appeared in that window, the guarded
    // DELETE is a no-op and must still be reported as a live-reference conflict.
    if ((await this.#providerRow(tenantId, id)) === null) return false;
    const liveAfter = await this.#db
      .prepare(
        "SELECT 1 AS present FROM catalog_model_offerings WHERE tenant_id = ? AND provider_id = ? LIMIT 1",
      )
      .bind(tenantId, id)
      .first<{ present: number }>();
    throw new TenantCatalogConflictError(
      liveAfter === null
        ? `provider ${id} could not be deleted`
        : `provider ${id} has live offerings`,
    );
  }

  async #providerRow(tenantId: string, id: string): Promise<ProviderRow | null> {
    return this.#db
      .prepare(`${PROVIDER_SELECT} WHERE tenant_id = ? AND id = ?`)
      .bind(tenantId, id)
      .first<ProviderRow>();
  }

  #requiredText(value: string, field: string): string {
    if (typeof value !== "string" || value.trim() === "") {
      throw new TenantCatalogValidationError(`${field} is required`);
    }
    return value.trim();
  }

  #validateProvider(input: ProviderChannelInput): { name: string; kind: string; base_url: string } {
    const name = this.#requiredText(input.name, "name");
    const baseUrl = this.#requiredText(input.base_url, "base_url");
    if (!urlIsValid(baseUrl)) throw new TenantCatalogValidationError("base_url must be a URL");
    const kind = canonicalProviderKind(input.kind);
    if (kind === null)
      throw new TenantCatalogValidationError(`unsupported provider kind: ${input.kind}`);
    return { name, kind, base_url: baseUrl };
  }

  async listModels(tenantId: string): Promise<readonly CatalogRecord[]> {
    const [models, offerings] = await Promise.all([
      this.#db
        .prepare(`${MODEL_SELECT} WHERE tenant_id = ? ORDER BY created_at_unix ASC, id ASC`)
        .bind(tenantId)
        .all<ModelRow>(),
      this.#offeringRows(tenantId),
    ]);
    const byModel = new Map<string, OfferingRow[]>();
    for (const offering of offerings) {
      const group = byModel.get(offering.model_id);
      if (group === undefined) byModel.set(offering.model_id, [offering]);
      else group.push(offering);
    }
    return models.results.map((model) => modelRecord(model, byModel.get(model.id) ?? []));
  }

  async getModel(tenantId: string, id: string): Promise<CatalogRecord | null> {
    const row = await this.#modelRow(tenantId, id);
    return row === null ? null : modelRecord(row, await this.#offeringRows(tenantId, id));
  }

  async createModel(
    tenantId: string,
    scope: CallerScope,
    input: ModelCatalogInput,
  ): Promise<CatalogRecord> {
    const normalized = this.#validateModel(input);
    const now = Math.floor(Date.now() / 1000);
    await this.#commit(
      tenantId,
      scope,
      "create",
      "models",
      { id: input.id, tenant_id: tenantId },
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO catalog_models
             (id, tenant_id, name, family, owned_by, capabilities_json,
              context_window, routing_strategy, enabled, created_at_unix, updated_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          input.id,
          tenantId,
          normalized.name,
          input.family ?? null,
          input.owned_by ?? null,
          jsonArray(input.capabilities, "capabilities"),
          input.context_window ?? null,
          input.routing_strategy ?? "priority",
          boolSql(input.enabled),
          now,
          now,
        ),
      true,
    );
    const stored = await this.getModel(tenantId, input.id);
    if (stored === null) throw new Error(`model ${input.id} disappeared after create`);
    return stored;
  }

  async updateModel(
    tenantId: string,
    scope: CallerScope,
    id: string,
    input: Partial<ModelCatalogInput>,
    action: "replace" | "merge",
  ): Promise<CatalogRecord | null> {
    const current = await this.#modelRow(tenantId, id);
    if (current === null) return null;
    const fields: UpdateField[] = [];
    if (action === "replace") {
      const contextWindow = input.context_window ?? null;
      if (contextWindow !== null && (!Number.isInteger(contextWindow) || contextWindow <= 0)) {
        throw new TenantCatalogValidationError("context_window must be a positive integer");
      }
      fields.push(
        ["name", this.#requiredText(input.name ?? current.name, "name")],
        ["family", input.family ?? null],
        ["owned_by", input.owned_by ?? null],
        ["capabilities_json", jsonArray(input.capabilities, "capabilities")],
        ["context_window", contextWindow],
        ["routing_strategy", input.routing_strategy ?? "priority"],
        ["enabled", boolSql(input.enabled)],
      );
    } else {
      if (input.name !== undefined) fields.push(["name", this.#requiredText(input.name, "name")]);
      if (input.family !== undefined) fields.push(["family", input.family ?? null]);
      if (input.owned_by !== undefined) fields.push(["owned_by", input.owned_by ?? null]);
      if (input.capabilities !== undefined) {
        fields.push(["capabilities_json", jsonArray(input.capabilities, "capabilities")]);
      }
      if (input.context_window !== undefined) {
        if (
          input.context_window !== null &&
          (!Number.isInteger(input.context_window) || input.context_window <= 0)
        ) {
          throw new TenantCatalogValidationError("context_window must be a positive integer");
        }
        fields.push(["context_window", input.context_window]);
      }
      if (input.routing_strategy !== undefined)
        fields.push(["routing_strategy", input.routing_strategy]);
      if (input.enabled !== undefined) fields.push(["enabled", boolSql(input.enabled)]);
    }
    if (fields.length === 0) fields.push(["name", current.name]);
    const changed = await this.#commit(
      tenantId,
      scope,
      action,
      "models",
      { id, tenant_id: tenantId },
      updateStatement(
        this.#db,
        "catalog_models",
        fields,
        tenantId,
        id,
        Math.floor(Date.now() / 1000),
        true,
      ),
      true,
    );
    return changed ? this.getModel(tenantId, id) : null;
  }

  async deleteModel(tenantId: string, scope: CallerScope, id: string): Promise<boolean> {
    if ((await this.#modelRow(tenantId, id)) === null) return false;
    return this.#commit(
      tenantId,
      scope,
      "remove",
      "models",
      { id, tenant_id: tenantId },
      this.#db
        .prepare("DELETE FROM catalog_models WHERE tenant_id = ? AND id = ?")
        .bind(tenantId, id),
    );
  }

  async #modelRow(tenantId: string, id: string): Promise<ModelRow | null> {
    return this.#db
      .prepare(`${MODEL_SELECT} WHERE tenant_id = ? AND id = ?`)
      .bind(tenantId, id)
      .first<ModelRow>();
  }

  #validateModel(input: ModelCatalogInput): { name: string } {
    const name = this.#requiredText(input.name, "name");
    if (
      input.context_window !== undefined &&
      input.context_window !== null &&
      (!Number.isInteger(input.context_window) || input.context_window <= 0)
    ) {
      throw new TenantCatalogValidationError("context_window must be a positive integer");
    }
    return { name };
  }

  async listOfferings(tenantId: string, modelId: string): Promise<readonly CatalogRecord[]> {
    if ((await this.#modelRow(tenantId, modelId)) === null) {
      throw new TenantCatalogNotFoundError(`model ${modelId} not found`);
    }
    return (await this.#offeringRows(tenantId, modelId)).map(offeringRecord);
  }

  async createOffering(
    tenantId: string,
    scope: CallerScope,
    modelId: string,
    input: ModelOfferingInput,
  ): Promise<CatalogRecord> {
    await this.#requireModelAndProvider(tenantId, modelId, input.provider_id);
    const values = this.#validatedOffering(input);
    const now = Math.floor(Date.now() / 1000);
    await this.#commit(
      tenantId,
      scope,
      "create",
      "offerings",
      { id: input.id, tenant_id: tenantId },
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO catalog_model_offerings
             (id, tenant_id, model_id, provider_id, upstream_model_id, role,
              priority, weight, canary_percent, shadow_percent, shadow_max_requests,
              capabilities_json, context_window, region, zero_data_retention,
              input_price_per_1m, output_price_per_1m, cached_input_price_per_1m,
              cache_write_price_per_1m, reasoning_price_per_1m,
              audio_second_price_per_1m, audio_character_price_per_1m,
              currency, source, enabled, created_at_unix, updated_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          input.id,
          tenantId,
          modelId,
          input.provider_id,
          input.upstream_model_id,
          values.role,
          values.priority,
          values.weight,
          values.canary_percent,
          values.shadow_percent,
          values.shadow_max_requests,
          input.capabilities === undefined || input.capabilities === null
            ? null
            : jsonArray(input.capabilities, "capabilities"),
          input.context_window ?? null,
          input.region ?? null,
          boolSql(input.zero_data_retention, null),
          input.input_price_per_1m ?? null,
          input.output_price_per_1m ?? null,
          input.cached_input_price_per_1m ?? null,
          input.cache_write_price_per_1m ?? null,
          input.reasoning_price_per_1m ?? null,
          input.audio_second_price_per_1m ?? null,
          input.audio_character_price_per_1m ?? null,
          input.currency ?? "USD",
          input.source ?? "admin",
          boolSql(input.enabled),
          now,
          now,
        ),
      true,
    );
    const stored = await this.#offeringRow(tenantId, modelId, input.id);
    if (stored === null) throw new Error(`offering ${input.id} disappeared after create`);
    return offeringRecord(stored);
  }

  async updateOffering(
    tenantId: string,
    scope: CallerScope,
    modelId: string,
    id: string,
    input: Partial<ModelOfferingInput>,
    action: "replace" | "merge",
  ): Promise<CatalogRecord | null> {
    const current = await this.#offeringRow(tenantId, modelId, id);
    if (current === null) return null;
    const replacing = action === "replace";
    const role: NonNullable<ModelOfferingInput["role"]> =
      input.role ??
      (replacing ? "fallback" : (current.role as NonNullable<ModelOfferingInput["role"]>));
    const canaryPercent = hasOwn(input, "canary_percent")
      ? input.canary_percent
      : replacing
        ? null
        : current.canary_percent;
    const shadowPercent = hasOwn(input, "shadow_percent")
      ? input.shadow_percent
      : replacing
        ? null
        : current.shadow_percent;
    this.#validateOffering({
      role,
      canary_percent: canaryPercent,
      shadow_percent: shadowPercent,
    });
    if (
      input.provider_id !== undefined &&
      (await this.#providerRow(tenantId, input.provider_id)) === null
    ) {
      throw new TenantCatalogNotFoundError(`provider ${input.provider_id} not found`);
    }
    const fields: UpdateField[] = [];
    if (replacing) {
      fields.push(
        ["provider_id", input.provider_id ?? current.provider_id],
        ["upstream_model_id", input.upstream_model_id ?? current.upstream_model_id],
        ["role", role],
        ["priority", input.priority ?? 100],
        ["weight", input.weight ?? 1],
        ["canary_percent", canaryPercent ?? null],
        ["shadow_percent", shadowPercent ?? null],
        ["shadow_max_requests", input.shadow_max_requests ?? null],
        [
          "capabilities_json",
          input.capabilities === undefined || input.capabilities === null
            ? null
            : jsonArray(input.capabilities, "capabilities"),
        ],
        ["context_window", input.context_window ?? null],
        ["region", input.region ?? null],
        ["zero_data_retention", boolSql(input.zero_data_retention, null)],
      );
      for (const column of [
        "input_price_per_1m",
        "output_price_per_1m",
        "cached_input_price_per_1m",
        "cache_write_price_per_1m",
        "reasoning_price_per_1m",
        "audio_second_price_per_1m",
        "audio_character_price_per_1m",
      ] as const) {
        fields.push([column, input[column] ?? null]);
      }
      fields.push(["currency", input.currency ?? "USD"]);
      fields.push(["source", input.source ?? "admin"]);
      fields.push(["enabled", boolSql(input.enabled)]);
    }
    const push = (column: string, value: string | number | null | undefined): void => {
      if (!replacing && value !== undefined) fields.push([column, value]);
    };
    push("provider_id", input.provider_id);
    push("upstream_model_id", input.upstream_model_id);
    push("role", input.role);
    push("priority", input.priority);
    push("weight", input.weight);
    if (!replacing && hasOwn(input, "canary_percent")) push("canary_percent", input.canary_percent);
    if (!replacing && hasOwn(input, "shadow_percent")) push("shadow_percent", input.shadow_percent);
    if (!replacing && hasOwn(input, "shadow_max_requests"))
      push("shadow_max_requests", input.shadow_max_requests);
    if (!replacing && input.capabilities !== undefined) {
      fields.push([
        "capabilities_json",
        input.capabilities === null ? null : jsonArray(input.capabilities, "capabilities"),
      ]);
    }
    push("context_window", input.context_window);
    push("region", input.region);
    if (!replacing && hasOwn(input, "zero_data_retention")) {
      fields.push(["zero_data_retention", boolSql(input.zero_data_retention, null)]);
    }
    for (const column of [
      "input_price_per_1m",
      "output_price_per_1m",
      "cached_input_price_per_1m",
      "cache_write_price_per_1m",
      "reasoning_price_per_1m",
      "audio_second_price_per_1m",
      "audio_character_price_per_1m",
    ] as const) {
      if (!replacing && hasOwn(input, column)) fields.push([column, input[column] ?? null]);
    }
    push("currency", input.currency);
    push("source", input.source);
    if (!replacing && input.enabled !== undefined) fields.push(["enabled", boolSql(input.enabled)]);
    if (fields.length === 0) fields.push(["upstream_model_id", current.upstream_model_id]);
    const changed = await this.#commit(
      tenantId,
      scope,
      action,
      "offerings",
      { id, tenant_id: tenantId },
      updateStatement(
        this.#db,
        "catalog_model_offerings",
        fields,
        tenantId,
        id,
        Math.floor(Date.now() / 1000),
        true,
      ),
      true,
    );
    return changed ? this.getOffering(tenantId, modelId, id) : null;
  }

  async deleteOffering(
    tenantId: string,
    scope: CallerScope,
    modelId: string,
    id: string,
  ): Promise<boolean> {
    if ((await this.#offeringRow(tenantId, modelId, id)) === null) return false;
    return this.#commit(
      tenantId,
      scope,
      "remove",
      "offerings",
      { id, tenant_id: tenantId },
      this.#db
        .prepare(
          "DELETE FROM catalog_model_offerings WHERE tenant_id = ? AND model_id = ? AND id = ?",
        )
        .bind(tenantId, modelId, id),
    );
  }

  async getOffering(tenantId: string, modelId: string, id: string): Promise<CatalogRecord | null> {
    const row = await this.#offeringRow(tenantId, modelId, id);
    return row === null ? null : offeringRecord(row);
  }

  #validateOffering(
    input: Pick<ModelOfferingInput, "role" | "canary_percent" | "shadow_percent">,
  ): void {
    const role = input.role ?? "fallback";
    if (!["primary", "fallback", "canary", "shadow"].includes(role)) {
      throw new TenantCatalogValidationError(`unsupported offering role: ${role}`);
    }
    if (
      role === "canary" &&
      (input.canary_percent === undefined || input.canary_percent === null)
    ) {
      throw new TenantCatalogValidationError("canary_percent is required for canary offerings");
    }
    if (
      role === "shadow" &&
      (input.shadow_percent === undefined || input.shadow_percent === null)
    ) {
      throw new TenantCatalogValidationError("shadow_percent is required for shadow offerings");
    }
  }

  #validatedOffering(input: ModelOfferingInput): {
    role: string;
    priority: number;
    weight: number;
    canary_percent: number | null;
    shadow_percent: number | null;
    shadow_max_requests: number | null;
  } {
    this.#validateOffering(input);
    return {
      role: input.role ?? "fallback",
      priority: input.priority ?? 100,
      weight: input.weight ?? 1,
      canary_percent: input.canary_percent ?? null,
      shadow_percent: input.shadow_percent ?? null,
      shadow_max_requests: input.shadow_max_requests ?? null,
    };
  }

  async #offeringRows(tenantId: string, modelId?: string): Promise<readonly OfferingRow[]> {
    const suffix =
      modelId === undefined ? "WHERE o.tenant_id = ?" : "WHERE o.tenant_id = ? AND o.model_id = ?";
    const statement = this.#db.prepare(
      `${OFFERING_SELECT} ${suffix} ORDER BY o.priority ASC, o.id ASC`,
    );
    return modelId === undefined
      ? (await statement.bind(tenantId).all<OfferingRow>()).results
      : (await statement.bind(tenantId, modelId).all<OfferingRow>()).results;
  }

  async #offeringRow(tenantId: string, modelId: string, id: string): Promise<OfferingRow | null> {
    return this.#db
      .prepare(`${OFFERING_SELECT} WHERE o.tenant_id = ? AND o.model_id = ? AND o.id = ?`)
      .bind(tenantId, modelId, id)
      .first<OfferingRow>();
  }

  async #requireModelAndProvider(
    tenantId: string,
    modelId: string,
    providerId: string,
  ): Promise<void> {
    if ((await this.#modelRow(tenantId, modelId)) === null) {
      throw new TenantCatalogNotFoundError(`model ${modelId} not found`);
    }
    if ((await this.#providerRow(tenantId, providerId)) === null) {
      throw new TenantCatalogNotFoundError(`provider ${providerId} not found`);
    }
  }

  async #commit(
    tenantId: string,
    scope: CallerScope,
    action: AuditAction,
    collection: string,
    record: StoreRecord,
    mutation: D1PreparedStatement,
    requireMutation = false,
  ): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    await reconcileTenantCatalogAudit(this.#db, this.#controlDatabase, tenantId);
    const outboxId = crypto.randomUUID();
    const auditJson = controlPlaneAuditJson({ action, collection, record, revision: 0, scope });
    let results: readonly D1Result<unknown>[];
    try {
      results = await this.#db.batch([
        this.#db
          .prepare(
            `INSERT OR IGNORE INTO catalog_revisions (tenant_id, id, revision, updated_at_unix)
             VALUES (?, 1, 0, ?)`,
          )
          .bind(tenantId, now),
        mutation,
        this.#db
          .prepare(
            `UPDATE catalog_revisions
                SET revision = revision + 1, updated_at_unix = ?
              WHERE tenant_id = ? AND id = 1 AND changes() > 0
              RETURNING revision`,
          )
          .bind(now, tenantId),
        this.#db
          .prepare(
            `INSERT INTO catalog_audit_outbox
                (id, tenant_id, revision, action, collection, record_json, audit_json,
                 request_id, actor_scope, actor_tenant_id, created_at_unix)
             SELECT ?, tenant_id, revision, ?, ?, ?, json_set(?, '$.revision', revision), ?, ?, ?, ?
               FROM catalog_revisions
              WHERE tenant_id = ? AND id = 1 AND changes() > 0`,
          )
          .bind(
            outboxId,
            action,
            collection,
            JSON.stringify(record),
            auditJson,
            this.#requestId,
            scope.kind,
            scope.kind === "tenant" ? scope.tenantId : null,
            now,
            tenantId,
          ),
      ]);
    } catch (error) {
      if (isConstraintError(error)) {
        throw new TenantCatalogConflictError("tenant model catalog constraint violated");
      }
      throw error;
    }
    const mutationResult = results[1];
    if (requireMutation && Number(mutationResult?.meta.changes ?? 0) === 0) {
      throw new TenantCatalogConflictError("tenant model catalog constraint violated");
    }
    const bump = results[2];
    if (bump === undefined || Number(bump.meta.changes ?? 0) === 0) return false;
    const revision = Number(
      (bump.results[0] as { revision?: number | string } | undefined)?.revision ?? 0,
    );
    if (revision <= 0) {
      throw new Error("tenant model catalog revision bump did not return its revision");
    }
    const outbox = results[3];
    if (outbox === undefined || Number(outbox.meta.changes ?? 0) === 0) {
      throw new Error("tenant model catalog audit outbox did not record the mutation");
    }
    await reconcileTenantCatalogAudit(this.#db, this.#controlDatabase, tenantId);
    return true;
  }
}
