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
  | "models"
  | "providers"
  | "plans";

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
  reference: EntityReferenceConfig;
  options?: never;
}

export type FieldConfig = ScalarFieldConfig | EntityReferenceFieldConfig;

export interface ColumnConfig<T> {
  key: string;
  /** Legacy inline header; migrated resources use `headerKey` instead (#348). */
  header?: string;
  /** Typed catalog key for the column header, resolved per locale (#348). */
  headerKey?: TranslationKey;
  render?: (row: T) => ReactNode;
  /** Information hierarchy used by the compact record view. */
  priority?: "primary" | "secondary" | "detail";
  /** Minimum desktop column width in pixels. */
  minWidth?: number;
  /** Alternate value for the compact record view. */
  compactRender?: (row: T) => ReactNode;
  /** Truncate the visible value and expose a named copy-full-value action. */
  copyable?: boolean;
  /** Explicit small-screen visibility; defaults from priority and column order. */
  mobileVisibility?: "always" | "details" | "hidden";
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
        values[field.name] = [];
        break;
      default:
        values[field.name] = "";
    }
  }
  return values;
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
      if (
        cleared.has(field.name) ||
        !field.reference?.dependencies?.some((dependency) => dependency.field === parent)
      ) {
        continue;
      }
      next[field.name] = field.type === "entities" ? [] : "";
      cleared.add(field.name);
      pending.push(field.name);
    }
  }

  return next;
}
