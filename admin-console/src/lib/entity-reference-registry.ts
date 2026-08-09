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
  /**
   * The target row exists but is disabled/suspended (#340 acceptance box 5).
   * Rendered with the same visible marking as `unresolved` and not selectable,
   * while an already-stored value stays inspectable and removable.
   */
  disabled?: boolean;
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
  /**
   * Lift the option-bearing record out of a wrapped list row (#342). Some list
   * endpoints envelope each item (e.g. agent-workflows returns
   * `{ workflow, counters }`), so the flat `valueKey`/`primaryLabelKey` live one
   * level down. Applied to every list row before it becomes an option; adapters
   * over flat rows omit it.
   */
  unwrapListItem?: (record: Record<string, unknown>) => Record<string, unknown>;
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
  // #340: tenant-role bindings reference an RBAC role by its canonical `id`. The
  // roles collection exposes GET/POST (+ DELETE per id) but no per-item GET and
  // no server-side search/offset params, so this adapter has no detailPath —
  // `hydrateEntityReference` resolves an existing value from the (full) list
  // response, and a deleted role that no longer appears stays inspectable as an
  // unresolved badge on the binding.
  roles: {
    listPath: "/admin/v1/roles",
  },
  // #340: wallet-charge selects a tenant's already-registered payment method by
  // its canonical `id`. The list endpoint requires a `tenant_id` query param
  // (supplied by the picker's tenant dependency filter) and exposes no per-item
  // GET, so this adapter has no detailPath — `hydrateEntityReference` resolves an
  // existing value from the tenant-scoped list. Only the non-secret provider
  // metadata is surfaced as labels; the opaque provider payment-method token is
  // never used as a selector (issue non-goal).
  "payment-methods": {
    listPath: "/admin/v1/payment-methods",
  },
  // #340: tenant accounts reference a sellable plan by its canonical `id`
  // (tenant-accounts.plan_id). The plans list endpoint exposes no server-side
  // search/offset params (same shape as models/providers below), so the picker
  // loads the full plan catalog; an existing value is hydrated to its label via
  // the per-plan GET at /admin/v1/plans/{plan_id} (wrapped under `plan`).
  plans: {
    listPath: "/admin/v1/plans",
    detailPath: (value) => `/admin/v1/plans/${encodeURIComponent(value)}`,
    unwrapDetail: unwrapNamedRecord("plan"),
  },
  // #341: routing/policy/quota reference the model and provider catalogs by
  // their canonical `name`. The list endpoints expose no per-item GET, so these
  // adapters have no detailPath — `hydrateEntityReference` resolves an existing
  // value by locating it in the list response instead. These collections do not
  // yet honour server-side search/offset params (that is #337-style Rust work
  // on the routing endpoints, out of scope here); the picker still loads the
  // full catalog, renders human labels and submits the canonical name.
  models: {
    listPath: "/admin/v1/models",
  },
  providers: {
    listPath: "/admin/v1/providers",
  },
  // #341: quota/policy scope pickers target a virtual key by its canonical `id`
  // when scope_type is `key`. The list endpoint returns the full key set with no
  // server-side search/offset (same shape as the routing catalogs above), so
  // this adapter has no detailPath — `hydrateEntityReference` resolves an
  // existing value from the list response. Only non-secret metadata (name,
  // prefix) is surfaced; the plaintext secret is never listed.
  "virtual-keys": {
    listPath: "/admin/v1/virtual-keys",
  },
  // #342: skill-package capabilities reference these catalogs by a canonical id
  // so the structured capability editor can resolve human labels instead of
  // requiring hand-copied ids. Like the #341 routing catalogs, none of these
  // list endpoints expose server-side search/offset or a per-item GET, so the
  // adapters carry no detailPath — `hydrateEntityReference` resolves an existing
  // value from the (full) list response instead.
  plugins: {
    listPath: "/admin/v1/plugins",
  },
  tools: {
    listPath: "/admin/v1/tools",
  },
  "mcp-servers": {
    listPath: "/admin/v1/mcp-servers",
  },
  "prompt-templates": {
    listPath: "/admin/v1/prompt-templates",
  },
  // #341: the guardrail-evaluations observability log filters by the policy that
  // produced a row. GET /admin/v1/guardrail-policies returns the flat revision
  // list (one row per revision), so many rows share a `policy_id`; the picker
  // dedupes by value and keeps whichever revision's `name` it saw as the label.
  // Like the routing catalogs above this endpoint exposes no per-item GET and no
  // server-side search/offset, so the adapter carries no detailPath —
  // `hydrateEntityReference` resolves an existing filter value from the (full)
  // list, and a policy that has been fully deleted stays visible as an
  // unresolved badge instead of a silently-dropped raw id.
  "guardrail-policies": {
    listPath: "/admin/v1/guardrail-policies",
  },
  // agent-workflows envelopes each list row as `{ workflow, counters }`, so the
  // canonical `id`/`name` live under `workflow` (see unwrapListItem).
  "agent-workflows": {
    listPath: "/admin/v1/agent-workflows",
    unwrapListItem: (record) => {
      const workflow = record.workflow;
      return workflow && typeof workflow === "object"
        ? (workflow as Record<string, unknown>)
        : record;
    },
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

/**
 * #340: whether a row declares itself disabled/suspended. An absent or empty
 * signal is treated as "no signal" (selectable) rather than as disabled — some
 * detail endpoints project fewer fields than their list endpoint, and a missing
 * value must never lock an operator out of a legitimate target.
 */
export function isDisabledEntityRecord(
  record: Record<string, unknown>,
  reference: EntityReferenceConfig,
): boolean {
  const rule = reference.disabledWhen;
  if (!rule) return false;
  const signal = recordValue(record, rule.key).trim().toLowerCase();
  if (!signal) return false;
  return !rule.activeValues.some((active) => active.toLowerCase() === signal);
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

  return {
    value,
    primaryLabel,
    secondaryLabel: secondaryLabel || undefined,
    disabled: isDisabledEntityRecord(record, reference) || undefined,
  };
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
    .map((record) => (adapter.unwrapListItem ? adapter.unwrapListItem(record) : record))
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
    const body = await gatewayGet<Record<string, unknown>>(apiKey, adapter.detailPath(value), {
      signal,
    });
    const record = adapter.unwrapDetail(body);
    const matchesFilters =
      record &&
      Object.entries(filters).every(([key, expected]) => recordValue(record, key) === expected);
    const option =
      matchesFilters && record ? toEntityReferenceOption(record, reference) : undefined;
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
