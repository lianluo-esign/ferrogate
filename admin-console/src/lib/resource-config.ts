export type FieldType = "text" | "number" | "boolean" | "select" | "textarea" | "json" | "csv";

export interface FieldOption {
  label: string;
  value: string;
}

export interface FieldConfig {
  name: string;
  label: string;
  type: FieldType;
  options?: FieldOption[];
  required?: boolean;
  placeholder?: string;
  description?: string;
  /** Excluded from the edit form (e.g. immutable identifiers). */
  createOnly?: boolean;
}

export interface ColumnConfig<T> {
  key: string;
  header: string;
  render?: (row: T) => string;
}

export interface ResourceConfig<T extends Record<string, unknown>> {
  key: string;
  title: string;
  description?: string;
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
  /**
   * Typed list fetcher backed by the generated OpenAPI client (#314):
   * migrated resources implement this with `adminGet(apiKey, "<contract
   * path>")` so contract drift becomes a type error; ResourcePage falls
   * back to the untyped `gatewayGet(basePath)` until a resource's slice
   * migrates. Exemplars: tenant-accounts, plans, virtual-keys.
   */
  fetchList?: (apiKey: string) => Promise<{ data: T[] }>;
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
      default:
        values[field.name] = "";
    }
  }
  return values;
}
