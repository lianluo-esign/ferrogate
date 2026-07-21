import { gatewayGet } from "@/lib/gateway-client";
import type {
  EntityReferenceConfig,
  EntityReferenceTarget,
  ResourceListResult,
} from "@/lib/resource-config";
import { ApiError } from "@/types/auth";

export interface EntityReferenceOption {
  value: string;
  primaryLabel: string;
  secondaryLabel?: string;
  unresolved?: boolean;
  resolutionError?: boolean;
}

export interface EntityReferencePage {
  options: EntityReferenceOption[];
  nextOffset?: number;
}

export interface EntityReferenceListRequest {
  search: string;
  offset: number;
  filters: Record<string, string>;
  signal?: AbortSignal;
}

export interface EntityReferenceAdapter {
  listPath: string;
  detailPath?: (value: string) => string;
  detailValueKey?: string;
  unwrapDetail?: (body: Record<string, unknown>) => Record<string, unknown> | undefined;
}

export type EntityReferenceRegistry = Record<EntityReferenceTarget, EntityReferenceAdapter>;

function unwrapNamedRecord(
  key: string,
): (body: Record<string, unknown>) => Record<string, unknown> | undefined {
  return (body) => {
    const value = body[key];
    return value && typeof value === "object" ? (value as Record<string, unknown>) : undefined;
  };
}

export const entityReferenceRegistry: EntityReferenceRegistry = {
  "tenant-accounts": {
    listPath: "/admin/v1/tenant-accounts",
    detailPath: (value) => `/admin/v1/tenant-accounts/${encodeURIComponent(value)}`,
    unwrapDetail: unwrapNamedRecord("tenant"),
  },
  projects: {
    listPath: "/admin/v1/projects",
    detailPath: (value) => `/admin/v1/projects/${encodeURIComponent(value)}`,
    unwrapDetail: unwrapNamedRecord("project"),
  },
  workspaces: {
    listPath: "/admin/v1/workspaces",
    detailPath: (value) => `/admin/v1/workspaces/${encodeURIComponent(value)}`,
    unwrapDetail: unwrapNamedRecord("workspace"),
  },
  permissions: {
    listPath: "/admin/v1/permissions",
    detailPath: (value) => `/admin/v1/permissions/${encodeURIComponent(value)}`,
    unwrapDetail: unwrapNamedRecord("permission"),
  },
};

function adapterFor(
  reference: EntityReferenceConfig,
  registry: EntityReferenceRegistry,
): EntityReferenceAdapter {
  const adapter = registry[reference.target];
  if (!adapter) throw new Error(`Unknown entity reference target: ${reference.target}`);
  return adapter;
}

function recordValue(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  return value === null || value === undefined ? "" : String(value);
}

export function toEntityReferenceOption(
  record: Record<string, unknown>,
  reference: EntityReferenceConfig,
): EntityReferenceOption | undefined {
  const value = recordValue(record, reference.valueKey);
  const primaryLabel = recordValue(record, reference.primaryLabelKey);
  if (!value || !primaryLabel) return undefined;

  const secondaryLabel = reference.secondaryLabelKeys
    ?.map((key) => recordValue(record, key))
    .filter(Boolean)
    .join(" · ");

  return { value, primaryLabel, secondaryLabel: secondaryLabel || undefined };
}

export async function loadEntityReferencePage(
  apiKey: string,
  reference: EntityReferenceConfig,
  request: EntityReferenceListRequest,
  registry: EntityReferenceRegistry = entityReferenceRegistry,
): Promise<EntityReferencePage> {
  const adapter = adapterFor(reference, registry);
  const pageSize = reference.pageSize ?? 20;
  const response = await gatewayGet<ResourceListResult<Record<string, unknown>>>(
    apiKey,
    adapter.listPath,
    {
      query: {
        [reference.queryKey ?? "search"]: request.search || undefined,
        [reference.offsetKey ?? "offset"]: request.offset,
        [reference.limitKey ?? "limit"]: pageSize,
        ...request.filters,
      },
      signal: request.signal,
    },
  );
  const options = response.data
    .map((record) => toEntityReferenceOption(record, reference))
    .filter((option): option is EntityReferenceOption => Boolean(option));
  const responseOffset = response.offset ?? request.offset;
  const responseLimit = response.limit ?? pageSize;
  const nextOffset =
    response.total != null
      ? responseOffset + response.data.length < response.total
        ? responseOffset + responseLimit
        : undefined
      : options.length === pageSize
        ? request.offset + pageSize
        : undefined;

  return { options, nextOffset };
}

export async function hydrateEntityReference(
  apiKey: string,
  reference: EntityReferenceConfig,
  value: string,
  filters: Record<string, string> = {},
  signal?: AbortSignal,
  registry: EntityReferenceRegistry = entityReferenceRegistry,
): Promise<EntityReferenceOption> {
  const adapter = adapterFor(reference, registry);
  if (
    !adapter.detailPath ||
    !adapter.unwrapDetail ||
    (adapter.detailValueKey ?? "id") !== reference.valueKey
  ) {
    const page = await loadEntityReferencePage(
      apiKey,
      reference,
      { search: value, offset: 0, filters, signal },
      registry,
    );
    return (
      page.options.find((option) => option.value === value) ?? {
        value,
        primaryLabel: value,
        unresolved: true,
      }
    );
  }

  try {
    const body = await gatewayGet<Record<string, unknown>>(
      apiKey,
      adapter.detailPath(value),
      { signal },
    );
    const record = adapter.unwrapDetail(body);
    const matchesFilters =
      record &&
      Object.entries(filters).every(([key, expected]) => recordValue(record, key) === expected);
    const option = matchesFilters && record ? toEntityReferenceOption(record, reference) : undefined;
    if (!option || option.value !== value) {
      return { value, primaryLabel: value, unresolved: true };
    }
    return option;
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return { value, primaryLabel: value, unresolved: true };
    }
    throw error;
  }
}
