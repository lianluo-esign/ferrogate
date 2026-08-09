import type { ReactNode } from "react";
import type { InterpolationValues, TranslationKey } from "@/i18n";

/**
 * Translator shape (the subset of `useI18n().t` the framework needs) used to
 * resolve the optional `*Key` catalog indirections below. Kept as a local type
 * so this pure-data module never imports the React i18n runtime (#348).
 */
export type ResourceTranslator = (
  key: TranslationKey,
  values?: InterpolationValues,
) => string;

/**
 * Resolve operator-facing config copy, preferring a typed catalog `key` (a
 * resource whose per-resource copy has migrated to the i18n catalog, #348) and
 * falling back to a legacy inline `literal` for resources not yet migrated.
 * Mirrors how `nav-config.ts` gained `titleKey` in slice 2: the config carries
 * the key, the component resolves it at render time under the active locale.
 */
export function resolveConfigText(
  t: ResourceTranslator,
  key: TranslationKey | undefined,
  literal: string | undefined,
): string {
  if (key) return t(key);
  return literal ?? "";
}

/** Optional-copy variant: preserves `undefined` so callers can branch on it. */
export function resolveOptionalConfigText(
  t: ResourceTranslator,
  key: TranslationKey | undefined,
  literal: string | undefined,
): string | undefined {
  if (key) return t(key);
  return literal;
}

export type ScalarFieldType =
  | "text"
  | "number"
  | "boolean"
  | "select"
  | "textarea"
  | "json"
  | "csv";

export type EntityReferenceTarget =
  | "tenant-accounts"
  | "projects"
  | "workspaces"
  | "permissions"
  | "roles"
  | "payment-methods"
  | "models"
  | "providers"
  | "plans"
  | "virtual-keys"
  | "plugins"
  | "tools"
  | "mcp-servers"
  | "prompt-templates"
  | "agent-workflows"
  | "guardrail-policies";

export interface FieldOption {
  /** Legacy inline label; migrated resources use `labelKey` instead (#348). */
  label?: string;
  /** Typed catalog key resolved under the active locale (#348). */
  labelKey?: TranslationKey;
  value: string;
}

export interface EntityReferenceDependency {
  /** Name of another field in the same form. */
  field: string;
  /** Query parameter used to scope this lookup, for example `tenant_id`. */
  queryKey: string;
  /** Human label used when the parent must be selected first. */
  label?: string;
}

/**
 * How a target row declares that it is disabled/suspended (#340 acceptance box
 * 5: "Disabled/deleted targets are visibly marked and cannot be newly
 * selected"). The *deleted* half is the unresolved badge; this is the *disabled*
 * half, which the reference layer previously had no way to express — a model
 * with `enabled: false` or a `status: "suspended"` project listed
 * indistinguishably from a live one and was freely selectable.
 *
 * A row is disabled when the value at `key` is present and outside
 * `activeValues` (compared case-insensitively on the stringified value). An
 * absent/empty value means "no signal", never "disabled": several detail
 * endpoints project fewer fields than their list endpoint, and a missing signal
 * must not silently lock an operator out of a legitimate target.
 */
export interface EntityReferenceDisabledRule {
  /** Row property carrying the enabled/status signal, e.g. `enabled`/`status`. */
  key: string;
  /** Stringified values that mean selectable, e.g. `["true"]` / `["active"]`. */
  activeValues: string[];
}

/** Catalog rows gated by a boolean `enabled` flag (models, providers). */
export const DISABLED_WHEN_NOT_ENABLED: EntityReferenceDisabledRule = {
  key: "enabled",
  activeValues: ["true"],
};

/**
 * Control-plane hierarchy rows gated by a lifecycle `status`
 * (tenant-accounts, projects, workspaces — the Admin API defaults each to
 * `"active"` and lets an operator park a row in any other state).
 */
export const DISABLED_WHEN_STATUS_NOT_ACTIVE: EntityReferenceDisabledRule = {
  key: "status",
  activeValues: ["active"],
};

export interface EntityReferenceConfig {
  /** Adapter key from the shared entity-reference registry. */
  target: EntityReferenceTarget;
  /** Canonical property submitted to the Admin API. */
  valueKey: string;
  /** Human-readable property shown as the option's primary label. */
  primaryLabelKey: string;
  /** Additional properties shown below the primary label when present. */
  secondaryLabelKeys?: string[];
  /** Server-side search query parameter. */
  queryKey?: string;
  /** Offset pagination query parameter. */
  offsetKey?: string;
  /** Page-size query parameter. */
  limitKey?: string;
  pageSize?: number;
  dependencies?: EntityReferenceDependency[];
  /** Escape hatch for references that legitimately have no list/get API. */
  allowRawValue?: boolean;
  /** Marks disabled/suspended targets so they cannot be newly selected (#340). */
  disabledWhen?: EntityReferenceDisabledRule;
}

/**
 * Scope-kind-driven reference (#341): the target entity kind is chosen at
 * render time by a sibling field's value rather than being fixed. Quota and
 * access-policy scope pickers use this so `scope_id` targets a tenant, project,
 * workspace, or key depending on the selected `scope_type`. Because the picker
 * only ever lists rows of the currently-selected kind, submitting an ID that
 * belongs to a different scope is structurally impossible, and changing the
 * scope kind clears the stale selection (see {@link clearDependentReferenceValues}).
 */
export interface ScopedEntityReference {
  /** Sibling field whose value selects the active target reference. */
  field: string;
  /** Reference config keyed by the sibling field's value; an unmatched value disables the picker. */
  byValue: Record<string, EntityReferenceConfig>;
}

interface FieldConfigBase {
  name: string;
  /** Legacy inline label; migrated resources use `labelKey` instead (#348). */
  label?: string;
  /** Typed catalog key for the field label, resolved per locale (#348). */
  labelKey?: TranslationKey;
  required?: boolean;
  placeholder?: string;
  /** Typed catalog key for the placeholder, resolved per locale (#348). */
  placeholderKey?: TranslationKey;
  description?: string;
  /** Typed catalog key for the helper description, resolved per locale (#348). */
  descriptionKey?: TranslationKey;
  autoComplete?: string;
  inputMode?: "none" | "text" | "decimal" | "numeric" | "tel" | "search" | "email" | "url";
  spellCheck?: boolean;
  /** Excluded from the edit form (e.g. immutable identifiers). */
  createOnly?: boolean;
}

export interface ScalarFieldConfig extends FieldConfigBase {
  type: ScalarFieldType;
  options?: FieldOption[];
  reference?: never;
}

export interface EntityReferenceFieldConfig extends FieldConfigBase {
  type: "entity" | "entities";
  /** Fixed target reference. Mutually exclusive with `scopedReference`. */
  reference?: EntityReferenceConfig;
  /**
   * Scope-kind-driven target selected by a sibling field's value (#341).
   * Exactly one of `reference` / `scopedReference` must be set on a field.
   */
  scopedReference?: ScopedEntityReference;
  options?: never;
}

/**
 * One selectable kind inside a {@link ReferenceListFieldConfig} row (#342). The
 * `value` is the discriminant written to the row's `discriminantKey` (e.g. a
 * skill-package capability `kind` such as `plugin`/`mcp_server`). When
 * `reference` is set the row's id is chosen from that entity catalog with a
 * resolved human label; kinds with no list/get API (e.g. an MCP sub-tool) omit
 * it and fall back to a validated raw-id text input, so no reference kind is
 * silently excluded.
 */
export interface ReferenceListKind {
  value: string;
  /** Legacy inline label; migrated configs use `labelKey` (#348). */
  label?: string;
  labelKey?: TranslationKey;
  reference?: EntityReferenceConfig;
}

/** A non-reference scalar preserved verbatim per row (e.g. a description). */
export interface ReferenceListExtraField {
  key: string;
  label?: string;
  labelKey?: TranslationKey;
  type: "text" | "textarea";
  placeholder?: string;
  placeholderKey?: TranslationKey;
}

/**
 * Structured editor for an array of typed references embedded in a JSON
 * document (#342): each row is `{ [discriminantKey]: kind, [valueKey]: id,
 * ...extraFields }`. The reference id is edited through the shared #337 picker
 * (per-kind target) while unrelated per-row fields (`extraFields`) and any keys
 * the console does not model round-trip unchanged, satisfying the acceptance
 * that reference arrays are editable via structured controls without disturbing
 * neighbouring free-form document fields.
 */
export interface ReferenceListFieldConfig extends FieldConfigBase {
  type: "reference-list";
  /** Row property that selects the kind, e.g. `kind`. */
  discriminantKey: string;
  /** Row property holding the referenced entity id, e.g. `id`. */
  valueKey: string;
  kinds: ReferenceListKind[];
  extraFields?: ReferenceListExtraField[];
  reference?: never;
  options?: never;
}

/**
 * Structured reference panel for an agent-workflow `nodes` array (#342). Each
 * node is `{ id, kind, model?, providers?, tool?, max_iterations?, token_budget? }`
 * (the `AgentWorkflowNode` contract, which is `deny_unknown_fields`, so the node
 * has a fixed, fully-modelled shape and no free-form extension). The editor
 * surfaces the per-node ENTITY REFERENCES — the model (models catalog), its
 * providers (providers catalog) and, for tool nodes, the tool (tools catalog) —
 * through the shared #337 picker so operators pick known entities by name
 * instead of hand-writing ids, while the non-reference node fields (id, the
 * numeric limits) round-trip unchanged. The workflow EDGES / topology stay a raw
 * JSON field: rewiring the graph is the explicit "visual DAG editor" non-goal,
 * so only the node reference arrays are structured here.
 */
export interface WorkflowNodesFieldConfig extends FieldConfigBase {
  type: "workflow-nodes";
  reference?: never;
  options?: never;
}

export type FieldConfig =
  | ScalarFieldConfig
  | EntityReferenceFieldConfig
  | ReferenceListFieldConfig
  | WorkflowNodesFieldConfig;

export interface ColumnConfig<T> {
  key: string;
  /** Legacy inline header; migrated resources use `headerKey` instead (#348). */
  header?: string;
  /** Typed catalog key for the column header, resolved per locale (#348). */
  headerKey?: TranslationKey;
  /**
   * Custom cell renderer. Receives the active `t` (#385) so cell-derived copy
   * — boolean Yes/No, Enabled/Disabled, and any other display string built in
   * the callback — localizes with the rest of the table instead of hard-coding
   * English. Prefer the declarative {@link booleanColumn} helper for the common
   * boolean case; reach for a raw callback only for bespoke derived text.
   */
  render?: (row: T, t: ResourceTranslator) => ReactNode;
  /** Information hierarchy used by the compact record view. */
  priority?: "primary" | "secondary" | "detail";
  /** Minimum desktop column width in pixels. */
  minWidth?: number;
  /** Alternate value for the compact record view; also receives the active `t` (#385). */
  compactRender?: (row: T, t: ResourceTranslator) => ReactNode;
  /** Truncate the visible value and expose a named copy-full-value action. */
  copyable?: boolean;
  /** Explicit small-screen visibility; defaults from priority and column order. */
  mobileVisibility?: "always" | "details" | "hidden";
}

/**
 * Build a column whose cell shows a localized label for a boolean field (#385).
 *
 * The framework resolves `trueKey`/`falseKey` under the active locale at render
 * time (via the `t` now threaded into `render`), so the cell tracks the table's
 * locale instead of the hard-coded English "Yes"/"No" the inline render
 * callbacks emitted before this. `trueKey`/`falseKey` are `TranslationKey`-typed,
 * so a mistyped key fails `tsc` rather than falling through at runtime.
 *
 * The boolean is read from `row[key]` by default; pass `value` for rows whose
 * flag lives behind an accessor (e.g. an unwrapped nested record).
 */
export function booleanColumn<T extends Record<string, unknown>>(
  config: Omit<ColumnConfig<T>, "render" | "compactRender"> & {
    /** Reads the boolean from the row; defaults to `Boolean(row[key])`. */
    value?: (row: T) => boolean | null | undefined;
    /** Catalog key for the truthy cell; defaults to `common.yes`. */
    trueKey?: TranslationKey;
    /** Catalog key for the falsy cell; defaults to `common.no`. */
    falseKey?: TranslationKey;
  },
): ColumnConfig<T> {
  const { value, trueKey = "common.yes", falseKey = "common.no", ...column } = config;
  const read = value ?? ((row: T) => Boolean(row[column.key]));
  return {
    ...column,
    render: (row, t) => t(read(row) ? trueKey : falseKey),
  };
}

export interface ResourceListRequest {
  offset: number;
  limit: number;
}

export interface ResourceListResult<T> {
  data: T[];
  total?: number | null;
  offset?: number | null;
  limit?: number | null;
}

export interface ResourceConfig<T extends Record<string, unknown>> {
  key: string;
  /** Legacy inline title; migrated resources use `titleKey` instead (#348). */
  title?: string;
  /** Typed catalog key for the resource title, resolved per locale (#348). */
  titleKey?: TranslationKey;
  description?: string;
  /** Typed catalog key for the resource description, resolved per locale (#348). */
  descriptionKey?: TranslationKey;
  /** Path relative to the gateway admin base URL, e.g. "/admin/v1/tenants". */
  basePath: string;
  idField: keyof T & string;
  columns: ColumnConfig<T>[];
  fields: FieldConfig[];
  /** View-only resources (logs, audit events, usage/billing history) hide create/edit/delete. */
  readOnly?: boolean;
  /**
   * Model-catalog resources (providers, models) whose scope — tenant vs the
   * PLATFORM default catalog — is chosen at render time by a superadmin (#912).
   * When set, ResourcePage picks its API key via `useCatalogApiKey()` (so every
   * request under `"platform"` scope carries the operator key with NO
   * `tenant_id`), renders the `<CatalogScopeToggle>`, and keys its list query on
   * the active scope so toggling refetches. Non-scopable resources are
   * unaffected.
   */
  platformScopable?: boolean;
  /** Resources that support create but no update/delete API. */
  noEditDelete?: boolean;
  /**
   * Resources that support create + delete but no update API (e.g. RBAC
   * roles/permissions, whose contract exposes POST + DELETE but no PUT/PATCH).
   * Independent of `noDelete`, which disables delete while keeping edit.
   */
  noUpdate?: boolean;
  /**
   * Resources that support edit but not delete (e.g. tenant accounts,
   * where deleting a tenant is a large destructive operation this
   * console deliberately doesn't expose at all -- the backend has no
   * DELETE handler for it either). Independent of `noEditDelete`, which
   * disables both.
   */
  noDelete?: boolean;
  /** Path segment appended to basePath for update/delete; defaults to row[idField]. */
  resolveDetailPath?: (row: T) => string;
  /** Unwraps a nested list envelope, e.g. row => row.workflow for agent-workflows. */
  unwrapRow?: (row: T) => Record<string, unknown>;
  /**
   * When set, the create response is inspected for this key (e.g. "secret")
   * and shown once in a dismiss-to-confirm dialog, since some resources
   * (virtual keys) never expose the plaintext secret again after creation.
   */
  secretResponseKey?: string;
  /** Offset pagination is the default for legacy list endpoints. */
  pagination?: "offset" | "none";
  /** Accessible record label for row actions; defaults to the first column value. */
  rowLabel?: (row: T) => string;
  /**
   * When set, each list row's FIRST column becomes a `<Link>` to this target
   * (#912): the minimal row-nav affordance the generic table otherwise lacks.
   * Used by the models list to reach a model's nested offerings page. The
   * returned string is a client-side route path (e.g. `/app/models/{id}/offerings`),
   * not an operator-facing copy string, so it is built here rather than via the
   * i18n catalog.
   */
  rowHref?: (row: T) => string;
  /**
   * Typed list fetcher backed by the generated OpenAPI client (#314):
   * migrated resources implement this with `adminGet(apiKey, "<contract
   * path>")` so contract drift becomes a type error; ResourcePage falls
   * back to the untyped `gatewayGet(basePath)` until a resource's slice
   * migrates. Exemplars: tenant-accounts, plans, virtual-keys.
   */
  fetchList?: (
    apiKey: string,
    request: ResourceListRequest,
  ) => Promise<ResourceListResult<T>>;
}

export function defaultFieldValues(fields: FieldConfig[]): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  for (const field of fields) {
    switch (field.type) {
      case "boolean":
        values[field.name] = false;
        break;
      case "number":
        values[field.name] = undefined;
        break;
      case "entities":
      case "reference-list":
      case "workflow-nodes":
        values[field.name] = [];
        break;
      default:
        values[field.name] = "";
    }
  }
  return values;
}

/**
 * Resolve the active reference for an entity field under the current form
 * values (#341). Fixed-target fields return their static `reference`; scoped
 * fields return the per-value reference chosen by their sibling field, or
 * `undefined` when the sibling has no (or an unmatched) value.
 */
export function resolveActiveReference(
  field: EntityReferenceFieldConfig,
  values: Record<string, unknown>,
): EntityReferenceConfig | undefined {
  if (field.scopedReference) {
    const key = String(values[field.scopedReference.field] ?? "");
    return field.scopedReference.byValue[key];
  }
  return field.reference;
}

/** True when a field's selection depends on the given parent field. */
function referenceDependsOn(field: FieldConfig, parent: string): boolean {
  if (field.type !== "entity" && field.type !== "entities") return false;
  if (field.scopedReference?.field === parent) return true;
  if (field.reference?.dependencies?.some((dependency) => dependency.field === parent)) {
    return true;
  }
  return Object.values(field.scopedReference?.byValue ?? {}).some((reference) =>
    reference.dependencies?.some((dependency) => dependency.field === parent),
  );
}

export function clearDependentReferenceValues(
  fields: FieldConfig[],
  values: Record<string, unknown>,
  changedField: string,
): Record<string, unknown> {
  const next = { ...values };
  const pending = [changedField];
  const cleared = new Set<string>();

  while (pending.length > 0) {
    const parent = pending.shift()!;
    for (const field of fields) {
      if (cleared.has(field.name) || !referenceDependsOn(field, parent)) {
        continue;
      }
      next[field.name] = field.type === "entities" ? [] : "";
      cleared.add(field.name);
      pending.push(field.name);
    }
  }

  return next;
}
