/**
 * The `ctl <group> <verb>` command registry — DATA, not hand-written commands.
 *
 * Clean-room port of `ferrogate-control-plane-client`'s
 * `command` / `resource` / `registry_helpers` / `dispatch` modules and its 12
 * resource-family modules (docs/legacy/inventory-edge-control.md §2.1–§2.2).
 *
 * Every group declares its verbs as data (name, help, OpenAPI `operationId`,
 * effect, confirmation policy, response mode, positional query arity) plus one
 * `build(verb, input) -> RequestSpec` function. Adding a resource family is a
 * new entry in `GROUPS`; no parser, transport, renderer, or dispatcher changes.
 *
 * The **effect** field is what the #505 render gate consumes: a `mutating` verb
 * can only ever emit a `MutationReceipt` (see `receipt.ts`).
 */
import type { JsonValue } from "@ferrogate/core";
import { CliError } from "./errors.js";
import type { HttpMethod, MultipartUpload, RequestSpec } from "./ports.js";

// ---------------------------------------------------------------------------
// Descriptors
// ---------------------------------------------------------------------------

/** Whether a verb changes Control-Plane state (drives the render gate). */
export type VerbEffect = "read" | "mutating" | "local";

/** Whether the client must confirm intent before the request leaves. */
export type ConfirmationPolicy = "none" | "required";

/** How a successful response body must leave the process. */
export type ResponseMode =
  | { readonly kind: "structured" }
  | { readonly kind: "raw"; readonly mediaType: string };

/**
 * The `multipart/form-data` shape an upload verb builds from CLI flags.
 *
 * The bytes come from `--input-file`; each named text field is read from its own
 * `--<field>` flag (e.g. `createFile` declares `fileField: "file"` and
 * `textFields: ["purpose"]`, so it consumes `--input-file` and `--purpose`).
 */
export interface UploadForm {
  /** The multipart field name the uploaded bytes are sent under. */
  readonly fileField: string;
  /** Required text form fields, each supplied via `--<name>`. */
  readonly textFields: readonly string[];
}

export interface VerbDescriptor {
  readonly name: string;
  readonly about: string;
  /** `null` for a purely local verb the coverage gate must not expect. */
  readonly operationId: string | null;
  readonly effect: VerbEffect;
  readonly confirmation: ConfirmationPolicy;
  readonly responseMode: ResponseMode;
  /** Required query values supplied as positional segments (asset-channels set). */
  readonly positionalQuerySegments: number;
  /** Set on a multipart byte-upload verb (`createFile`); drives ctl's flags. */
  readonly upload?: UploadForm;
}

export interface GroupDescriptor {
  readonly name: string;
  readonly about: string;
  readonly verbs: readonly VerbDescriptor[];
  /** Verb → request mapping for this family. */
  readonly build: (verb: string, input: ResourceInput) => RequestSpec;
  /** Response fields redacted from read output and error details. */
  readonly secretFields?: readonly string[];
}

const base = {
  confirmation: "none" as ConfirmationPolicy,
  responseMode: { kind: "structured" } as ResponseMode,
  positionalQuerySegments: 0,
};

/** A read-only verb bound to one Control Plane operation. */
export function read(name: string, about: string, operationId: string): VerbDescriptor {
  return { ...base, name, about, operationId, effect: "read" };
}

/** A read whose success is an export artifact, not a renderable document. */
export function rawRead(
  name: string,
  about: string,
  operationId: string,
  mediaType: string,
): VerbDescriptor {
  return {
    ...base,
    name,
    about,
    operationId,
    effect: "read",
    responseMode: { kind: "raw", mediaType },
  };
}

/** A state-changing verb; its only renderable output is a `MutationReceipt`. */
export function mutating(name: string, about: string, operationId: string): VerbDescriptor {
  return { ...base, name, about, operationId, effect: "mutating" };
}

/**
 * A state-changing verb whose request body is a `multipart/form-data` byte
 * upload rather than a JSON document (`createFile`).
 *
 * It is `mutating` like any other write, so it still emits a `MutationReceipt`;
 * the `upload` form only tells the dispatcher to gather bytes + text fields from
 * `--input-file`/`--<field>` instead of `--data`/`--file`.
 */
export function upload(
  name: string,
  about: string,
  operationId: string,
  form: UploadForm,
): VerbDescriptor {
  return { ...base, name, about, operationId, effect: "mutating", upload: form };
}

/** A state-changing verb gated behind an explicit `--yes`/prompt. */
export function mutatingWithConfirmation(
  name: string,
  about: string,
  operationId: string,
): VerbDescriptor {
  return {
    ...base,
    name,
    about,
    operationId,
    effect: "mutating",
    confirmation: "required",
  };
}

/** Declare that a verb consumes N trailing positionals as query values. */
export function withPositionalQuerySegments(verb: VerbDescriptor, count: number): VerbDescriptor {
  return { ...verb, positionalQuerySegments: count };
}

/** Whether the verb needs `--yes` or an interactive acknowledgement. */
export function requiresConfirmation(verb: VerbDescriptor): boolean {
  return verb.confirmation === "required";
}

/** The media type of a raw-export verb, if it is one. */
export function rawResponseMediaType(verb: VerbDescriptor): string | undefined {
  return verb.responseMode.kind === "raw" ? verb.responseMode.mediaType : undefined;
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------

/** Pagination + server-side filters and sorts for a list verb. */
export interface PageRequest {
  readonly offset: number;
  readonly limit?: number;
}

export class ListParams {
  readonly page?: PageRequest;
  readonly filters: readonly (readonly [string, string])[];
  readonly sorts: readonly string[];

  constructor(
    init: {
      page?: PageRequest;
      filters?: readonly (readonly [string, string])[];
      sorts?: readonly string[];
    } = {},
  ) {
    if (init.page !== undefined) this.page = init.page;
    this.filters = init.filters ?? [];
    this.sorts = init.sorts ?? [];
  }

  /** Fold pagination, filters, and sorts into a query list. */
  apply(query: (readonly [string, string])[]): (readonly [string, string])[] {
    const out = [...query];
    if (this.page !== undefined) {
      out.push(["offset", String(this.page.offset)]);
      if (this.page.limit !== undefined) out.push(["limit", String(this.page.limit)]);
    }
    for (const [key, value] of this.filters) out.push([key, value]);
    // Sort keys pass through verbatim, leading `-` included: the client never
    // reinterprets them, because re-sorting a page would present a per-page
    // ordering as a collection ordering.
    for (const key of this.sorts) out.push(["sort", key]);
    return out;
  }
}

/** The typed inputs a resolved `ctl` command contributes to the request. */
export interface ResourceInput {
  readonly segments: readonly string[];
  readonly body?: JsonValue;
  readonly list: ListParams;
  /** The gathered multipart payload for an upload verb (`createFile`). */
  readonly upload?: MultipartUpload;
}

export function resourceInput(init: Partial<ResourceInput> = {}): ResourceInput {
  return {
    segments: init.segments ?? [],
    ...(init.body === undefined ? {} : { body: init.body }),
    list: init.list ?? new ListParams(),
    ...(init.upload === undefined ? {} : { upload: init.upload }),
  };
}

/** The body a write verb requires, or a usage error naming the verb. */
function requireBody(input: ResourceInput, verb: string): JsonValue {
  if (input.body === undefined) {
    throw CliError.usage(
      `verb '${verb}' requires a JSON request document (provide one via --data, --file, or --file -)`,
    );
  }
  return input.body;
}

/** The gathered multipart payload, or a usage error naming the verb. */
function requireUpload(input: ResourceInput, verb: string): MultipartUpload {
  if (input.upload === undefined) {
    throw CliError.usage(
      `verb '${verb}' is a byte upload; provide the file with --input-file and its form fields`,
    );
  }
  return input.upload;
}

/** The first id segment, or a usage error naming the resource. */
function firstSegment(input: ResourceInput, resource: string): string {
  const segment = input.segments[0];
  if (segment === undefined || segment.trim() === "") {
    throw CliError.usage(`this ${resource} verb requires a target id`);
  }
  return segment;
}

/** One declarative resource collection on the Control Plane API. */
export class ResourceApi {
  constructor(readonly collection: string) {}

  /**
   * Absolute path for trailing item segments. Each segment is percent-encoded,
   * so an id containing `/` or `?` cannot smuggle extra path structure into the
   * URL; an empty segment is a usage error, never a collapsed `//`.
   */
  itemPath(segments: readonly string[]): string {
    let path = this.collection;
    for (const segment of segments) {
      if (segment.trim() === "") {
        throw CliError.usage(`resource path segment for '${this.collection}' must not be empty`);
      }
      path += `/${encodeURIComponent(segment)}`;
    }
    return path;
  }

  read(segments: readonly string[], list: ListParams): RequestSpec {
    return { method: "GET", path: this.itemPath(segments), query: list.apply([]) };
  }

  get(segments: readonly string[]): RequestSpec {
    return this.read(segments, new ListParams());
  }

  mutate(method: HttpMethod, segments: readonly string[], body?: JsonValue): RequestSpec {
    return {
      method,
      path: this.itemPath(segments),
      query: [],
      ...(body === undefined ? {} : { body }),
    };
  }

  create(body: JsonValue): RequestSpec {
    return this.mutate("POST", [], body);
  }

  replace(segments: readonly string[], body: JsonValue): RequestSpec {
    return this.mutate("PUT", segments, body);
  }

  update(segments: readonly string[], body: JsonValue): RequestSpec {
    return this.mutate("PATCH", segments, body);
  }

  delete(segments: readonly string[]): RequestSpec {
    return this.mutate("DELETE", segments, undefined);
  }

  action(segments: readonly string[], body?: JsonValue): RequestSpec {
    return this.mutate("POST", segments, body);
  }

  /** `POST` a `multipart/form-data` byte upload to the collection or item path. */
  uploadTo(segments: readonly string[], upload: MultipartUpload): RequestSpec {
    return { method: "POST", path: this.itemPath(segments), query: [], upload };
  }
}

/**
 * Reject a target verb that was not given its complete key.
 *
 * `itemPath([])` returns the BARE COLLECTION path, so an omitted id silently
 * retargets the whole collection — `ctl projects delete` would have issued a
 * collection-level DELETE. `list` and `create` are deliberately unguarded.
 */
function requireTargetSegments(
  api: ResourceApi,
  verb: string,
  segments: readonly string[],
  required: number,
): readonly string[] {
  const taken = segments.slice(0, required);
  if (taken.length < required || taken.some((segment) => segment.trim() === "")) {
    const requirement = required === 1 ? "a target id" : `${required} non-empty target segments`;
    throw CliError.usage(
      `verb '${verb}' requires ${requirement} under ${api.collection}; received ${segments.length} segment(s)`,
    );
  }
  return taken;
}

/** Map one of the six uniform CRUD verbs onto a request. */
function buildCrud(api: ResourceApi, verb: string, input: ResourceInput): RequestSpec {
  return buildCrudWithItemSegments(api, verb, input, 1);
}

function buildCrudWithItemSegments(
  api: ResourceApi,
  verb: string,
  input: ResourceInput,
  requiredItemSegments: number,
): RequestSpec {
  const segments = input.segments;
  switch (verb) {
    case "list":
      return api.read(segments, input.list);
    case "get":
      return api.get(requireTargetSegments(api, verb, segments, requiredItemSegments));
    case "create":
      return api.create(requireBody(input, verb));
    case "replace":
      return api.replace(
        requireTargetSegments(api, verb, segments, requiredItemSegments),
        requireBody(input, verb),
      );
    case "update":
      return api.update(
        requireTargetSegments(api, verb, segments, requiredItemSegments),
        requireBody(input, verb),
      );
    case "delete":
      return api.delete(requireTargetSegments(api, verb, segments, requiredItemSegments));
    default:
      throw CliError.usage(`verb '${verb}' is not a standard CRUD verb for ${api.collection}`);
  }
}

/** Map the catalog's issue-facing aliases onto the standard CRUD verbs. */
function buildAliasedCrud(api: ResourceApi, verb: string, input: ResourceInput): RequestSpec {
  switch (verb) {
    case "show":
      return api.get(requireTargetSegments(api, verb, input.segments, 1));
    case "add":
      return api.create(requireBody(input, verb));
    case "replace":
      return api.replace(
        requireTargetSegments(api, verb, input.segments, 1),
        requireBody(input, verb),
      );
    case "update":
      return api.update(
        requireTargetSegments(api, verb, input.segments, 1),
        requireBody(input, verb),
      );
    case "rm":
      return api.delete(requireTargetSegments(api, verb, input.segments, 1));
    default:
      throw CliError.usage(`verb '${verb}' is not a catalog CRUD verb for ${api.collection}`);
  }
}

/** `POST .../{id}/{action}` with the target id from the first segment. */
function buildItemAction(
  api: ResourceApi,
  resource: string,
  action: string,
  input: ResourceInput,
): RequestSpec {
  return api.action([firstSegment(input, resource), action], input.body);
}

/** `DELETE .../{id}` lifecycle verb. */
function buildItemDelete(api: ResourceApi, resource: string, input: ResourceInput): RequestSpec {
  return api.mutate("DELETE", [firstSegment(input, resource)], undefined);
}

/** The uniform six-verb CRUD descriptor set. */
function crudVerbs(nounLower: string, nounPascal: string, listOp: string): VerbDescriptor[] {
  return [
    read("list", `List ${nounLower}s`, listOp),
    read("get", `Show a ${nounLower}`, `get${nounPascal}`),
    mutating("create", `Create a ${nounLower}`, `create${nounPascal}`),
    mutating("replace", `Replace a ${nounLower}`, `replace${nounPascal}`),
    mutating("update", `Update a ${nounLower}`, `update${nounPascal}`),
    mutating("delete", `Delete a ${nounLower}`, `delete${nounPascal}`),
  ];
}

// ---------------------------------------------------------------------------
// Resource collections (paths mirrored from the Rust family modules)
// ---------------------------------------------------------------------------

const TENANT_ACCOUNTS = new ResourceApi("/admin/v1/tenant-accounts");
const TENANTS = new ResourceApi("/admin/v1/tenants");
const PROJECTS = new ResourceApi("/admin/v1/projects");
const WORKSPACES = new ResourceApi("/admin/v1/workspaces");
const PLANS = new ResourceApi("/admin/v1/plans");
const QUOTA_POLICIES = new ResourceApi("/admin/v1/quota-policies");

const VIRTUAL_KEYS = new ResourceApi("/admin/v1/virtual-keys");
const API_KEYS = new ResourceApi("/admin/v1/api-keys");
const ROLES = new ResourceApi("/admin/v1/roles");
const PERMISSIONS = new ResourceApi("/admin/v1/permissions");
const ACCESS_POLICIES = new ResourceApi("/admin/v1/policies");
const TENANT_ROLES = new ResourceApi("/admin/v1/tenant-roles");

const AGENT_WORKFLOWS = new ResourceApi("/admin/v1/agent-workflows");
const AGENT_SCHEDULES = new ResourceApi("/admin/v1/agent-schedules");
const AGENT_UPSTREAMS = new ResourceApi("/admin/v1/agent-upstreams");
const AGENT_RUNS = new ResourceApi("/admin/v1/agent-runs");
const AGENT_RUNS_RUNTIME = new ResourceApi("/v1/agent-runs");
const AGENT_JOBS = new ResourceApi("/v1/agent-jobs");

const SELF_HOSTED_WORKERS = new ResourceApi("/admin/v1/self-hosted-workers");
const MANAGED_WORKERS = new ResourceApi("/admin/v1/managed-workers");
const MANAGED_WORKER_SESSIONS = new ResourceApi("/admin/v1/managed-worker-sessions");
const SELF_HOSTED_WORKER_RECORDS = new ResourceApi("/admin/v1/self-hosted-worker-records");
const SELF_HOSTED_RUNS = new ResourceApi("/admin/v1/self-hosted-runs");

const MCP_SERVERS = new ResourceApi("/admin/v1/mcp-servers");
const MCP_IDENTITY = new ResourceApi("/v1/mcp/identity");
const TOOL_SESSIONS = new ResourceApi("/admin/v1/tool-sessions");
const TOOLS = new ResourceApi("/admin/v1/tools");

const TOOL_APPROVALS = new ResourceApi("/admin/v1/tool-approvals");

const GUARDRAIL_POLICIES = new ResourceApi("/admin/v1/guardrail-policies");
const GUARDRAIL_EVALUATIONS = new ResourceApi("/admin/v1/guardrail-evaluations");
const INVESTIGATIONS = new ResourceApi("/admin/v1/investigations");

const ASSETS = new ResourceApi("/v1/assets");
const ASSET_PRESIGN = new ResourceApi("/v1/assets/presign");
const SITE_DOMAINS = new ResourceApi("/admin/v1/site-domains");
/** #743 — the OPERATOR asset surface, distinct from the tenant `/v1/assets`. */
const ASSET_FLEET = new ResourceApi("/admin/v1/assets");

// #698 — the OpenAI-compatible Files and Batch data-plane surfaces. Files are
// backed by the tenant's reserved asset family; a batch references an uploaded
// `input_file_id` and yields an `output_file_id`, so the two land as one group.
const FILES = new ResourceApi("/v1/files");
const BATCHES = new ResourceApi("/v1/batches");

const PROMPT_TEMPLATES = new ResourceApi("/admin/v1/prompt-templates");
const PROMPTS = new ResourceApi("/v1/prompts");
const SKILL_PACKAGES = new ResourceApi("/admin/v1/skill-packages");
const PLUGINS = new ResourceApi("/admin/v1/plugins");
const MODELS = new ResourceApi("/admin/v1/models");
const PROVIDERS = new ResourceApi("/admin/v1/providers");
const PROVIDER_MODELS = new ResourceApi("/admin/v1/provider-models");
const BILLING_GROUPS = new ResourceApi("/admin/v1/billing-groups");
const BILLING_FLEET = new ResourceApi("/admin/v1/billing-fleet");
const EXTENSIONS = new ResourceApi("/admin/v1/extensions");
const FRAMEWORK_ADAPTERS = new ResourceApi("/admin/v1/framework-adapters");

function buildOfferingRequest(verb: string, input: ResourceInput): RequestSpec {
  const modelId = requireTargetSegments(MODELS, verb, input.segments, 1)[0] as string;
  switch (verb) {
    case "list":
      return MODELS.read([modelId, "offerings"], input.list);
    case "show":
      return MODELS.get(requireTargetSegments(MODELS, verb, input.segments, 2));
    case "add":
      return MODELS.mutate("POST", [modelId, "offerings"], requireBody(input, verb));
    case "replace": {
      const [targetModel, offeringId] = requireTargetSegments(MODELS, verb, input.segments, 2);
      return MODELS.replace(
        [targetModel as string, "offerings", offeringId as string],
        requireBody(input, verb),
      );
    }
    case "update": {
      const [targetModel, offeringId] = requireTargetSegments(MODELS, verb, input.segments, 2);
      return MODELS.update(
        [targetModel as string, "offerings", offeringId as string],
        requireBody(input, verb),
      );
    }
    case "rm": {
      const [targetModel, offeringId] = requireTargetSegments(MODELS, verb, input.segments, 2);
      return MODELS.delete([targetModel as string, "offerings", offeringId as string]);
    }
    default:
      throw CliError.usage(`verb '${verb}' is not a model-offerings verb`);
  }
}

/**
 * Billing groups (#942, epic #941). CRUD on the group plus the two-segment
 * provider-binding sub-resource `PUT/DELETE .../{id}/providers/{providerId}`:
 * `bind`/`unbind` take the group id and the provider id as two positionals and
 * the "providers" segment is injected between them, the same shape
 * {@link buildOfferingRequest} uses for `.../{model}/offerings/{id}`.
 */
function buildBillingGroupRequest(verb: string, input: ResourceInput): RequestSpec {
  switch (verb) {
    case "list":
      return BILLING_GROUPS.read(input.segments, input.list);
    case "show":
      return BILLING_GROUPS.get(requireTargetSegments(BILLING_GROUPS, verb, input.segments, 1));
    case "add":
      return BILLING_GROUPS.create(requireBody(input, verb));
    case "update":
      return BILLING_GROUPS.update(
        requireTargetSegments(BILLING_GROUPS, verb, input.segments, 1),
        requireBody(input, verb),
      );
    case "rm":
      return BILLING_GROUPS.delete(requireTargetSegments(BILLING_GROUPS, verb, input.segments, 1));
    case "bind-provider": {
      const [groupId, providerId] = requireTargetSegments(BILLING_GROUPS, verb, input.segments, 2);
      return BILLING_GROUPS.mutate("PUT", [groupId as string, "providers", providerId as string]);
    }
    case "unbind-provider": {
      const [groupId, providerId] = requireTargetSegments(BILLING_GROUPS, verb, input.segments, 2);
      return BILLING_GROUPS.mutate("DELETE", [
        groupId as string,
        "providers",
        providerId as string,
      ]);
    }
    default:
      throw CliError.usage(`verb '${verb}' is not a billing-groups verb`);
  }
}

const WALLETS = new ResourceApi("/admin/v1/wallets");
const PAYMENT_METHODS = new ResourceApi("/admin/v1/payment-methods");
const BILLING_EVENTS = new ResourceApi("/admin/v1/billing-events");
const BILLING_DEAD_LETTERS = new ResourceApi("/admin/v1/billing-outbox-dead-letters");
const USAGE_AGGREGATES = new ResourceApi("/admin/v1/usage-aggregates");
const USAGE_REPORTS = new ResourceApi("/admin/v1/usage-reports");
const METERING_EVENTS = new ResourceApi("/admin/v1/metering-events");
const METERING_EXPORT_STATUS = new ResourceApi("/admin/v1/metering-export-status");
const AGENT_COST_BURN = new ResourceApi("/admin/v1/agent-cost-burn");
// #697 — the burn-rate/forecast EPISODE ledger. A sibling of the cost-burn
// report above and deliberately a different verb: cost-burn answers "how much",
// this answers "is that unlike this tenant's own recent self, and were we told".
const SPEND_ANOMALIES = new ResourceApi("/admin/v1/spend-anomalies");
const PAYMENT_ATTEMPTS = new ResourceApi("/admin/v1/payment-attempts");

const REQUEST_LOGS = new ResourceApi("/admin/v1/request-logs");
const EXPERIMENTS = new ResourceApi("/admin/v1/experiments");
const REQUEST_LOG_EXPORTS = new ResourceApi("/admin/v1/request-log-exports");
const AUDIT_EVENTS = new ResourceApi("/admin/v1/audit-events");
const OBSERVED_AGENT_ACTIVITY = new ResourceApi("/admin/v1/observed-agent-activity");

const HEALTHZ = new ResourceApi("/healthz");
const READYZ = new ResourceApi("/readyz");
const ADMIN_STATUS = new ResourceApi("/admin/v1/status");
const ADMIN_STATUS_ALIAS = new ResourceApi("/admin/status");
const OBSERVABILITY = new ResourceApi("/admin/v1/observability");
const PROVIDER_HEALTH = new ResourceApi("/admin/v1/provider-health");
const CONFIG = new ResourceApi("/admin/v1/config");
const DRAIN = new ResourceApi("/admin/v1/drain");
const GATEWAY_CONFIGS = new ResourceApi("/admin/v1/gateway-configs");

/** Fields redacted from `virtual-keys` / `api-keys` read output. */
export const VIRTUAL_KEY_SECRET_FIELDS = ["key", "secret"] as const;
/** Presigned URLs are bearer-equivalent; never render them into diagnostics. */
export const ASSET_TRANSFER_SECRET_FIELDS = ["upload_url", "download_url"] as const;

/** Require the composite `{asset_type}/{name}/{version}` asset key. */
function assetVersionRef(input: ResourceInput, verb: string): [string, string, string] {
  const [assetType, name, version] = input.segments;
  if (
    assetType === undefined ||
    name === undefined ||
    version === undefined ||
    [assetType, name, version].some((segment) => segment.trim() === "")
  ) {
    throw CliError.usage(`verb '${verb}' requires <asset_type> <name> <version>`);
  }
  return [assetType, name, version];
}

/** Require the `{asset_type}/{name}` asset key. */
function assetNameRef(input: ResourceInput, verb: string): [string, string] {
  const [assetType, name] = input.segments;
  if (
    assetType === undefined ||
    name === undefined ||
    [assetType, name].some((segment) => segment.trim() === "")
  ) {
    throw CliError.usage(`verb '${verb}' requires <asset_type> <name>`);
  }
  return [assetType, name];
}

/** Require the `{policy}/{revision}` guardrail key. */
function policyAndRevision(input: ResourceInput, verb: string): [string, string] {
  const [policy, revision] = input.segments;
  if (
    policy === undefined ||
    revision === undefined ||
    [policy, revision].some((segment) => segment.trim() === "")
  ) {
    throw CliError.usage(`verb '${verb}' requires <policy_id> <revision_id>`);
  }
  return [policy, revision];
}

// ---------------------------------------------------------------------------
// The 54 registered command groups (12 family modules)
// ---------------------------------------------------------------------------

/** Every registered `ctl` group, in registration order. */
export const GROUPS: readonly GroupDescriptor[] = [
  // --- organization ------------------------------------------------------
  {
    name: "tenant-accounts",
    about: "Manage tenant accounts",
    verbs: [
      read("list", "List tenant accounts", "listTenantAccounts"),
      read("get", "Show a tenant account", "getTenantAccount"),
      mutating("create", "Create a tenant account", "createTenantAccount"),
      mutating("replace", "Replace a tenant account", "replaceTenantAccount"),
      mutating("update", "Update a tenant account", "updateTenantAccount"),
      read("resolved-defaults", "Show a tenant's resolved defaults", "getTenantResolvedDefaults"),
      mutating("assign-plan", "Assign a subscription plan to a tenant", "assignTenantPlan"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "resolved-defaults":
          return TENANT_ACCOUNTS.get([firstSegment(input, "tenant-accounts"), "resolved-defaults"]);
        case "assign-plan":
          return TENANT_ACCOUNTS.replace(
            [firstSegment(input, "tenant-accounts"), "plan"],
            requireBody(input, verb),
          );
        default:
          return buildCrud(TENANT_ACCOUNTS, verb, input);
      }
    },
  },
  {
    name: "tenants",
    about: "List gateway tenants (admin view)",
    verbs: [read("list", "List tenants", "listAdminTenants")],
    build: (verb, input) => buildCrud(TENANTS, verb, input),
  },
  {
    name: "projects",
    about: "Manage projects",
    verbs: crudVerbs("project", "Project", "listProjects"),
    build: (verb, input) => buildCrud(PROJECTS, verb, input),
  },
  {
    name: "workspaces",
    about: "Manage workspaces",
    verbs: crudVerbs("workspace", "Workspace", "listWorkspaces"),
    build: (verb, input) => buildCrud(WORKSPACES, verb, input),
  },
  {
    name: "plans",
    about: "Manage plans",
    verbs: [
      read("list", "List plans", "listPlans"),
      read("get", "Show a plan", "getPlan"),
      mutating("create", "Create a plan", "createPlan"),
      mutating("replace", "Replace a plan", "replacePlan"),
      mutating("update", "Update a plan", "updatePlan"),
    ],
    build: (verb, input) => buildCrud(PLANS, verb, input),
  },
  {
    name: "quota-policies",
    about: "Manage quota policies",
    verbs: [
      read("list", "List quota policies", "listQuotaPolicies"),
      read("get", "Show a quota policy", "getQuotaPolicy"),
      mutating("create", "Create a quota policy", "createQuotaPolicy"),
      mutating("replace", "Replace a quota policy", "replaceQuotaPolicy"),
      mutating("update", "Update a quota policy", "updateQuotaPolicy"),
      mutating("delete", "Delete a quota policy", "deleteQuotaPolicy"),
    ],
    // Items are addressed by the composite `scope_type/scope_id` key.
    build: (verb, input) => buildCrudWithItemSegments(QUOTA_POLICIES, verb, input, 2),
  },

  // --- iam ---------------------------------------------------------------
  {
    name: "virtual-keys",
    about: "Manage virtual API keys and their lifecycle",
    secretFields: VIRTUAL_KEY_SECRET_FIELDS,
    verbs: [
      read("list", "List virtual keys", "listVirtualKeys"),
      read("get", "Show a virtual key", "getVirtualKey"),
      mutating("create", "Create a virtual key", "createVirtualKey"),
      mutating("revoke", "Revoke (delete) a virtual key", "revokeVirtualKey"),
      mutating("rotate", "Rotate a virtual key's secret", "rotateVirtualKey"),
      mutating("enable", "Enable a virtual key", "enableVirtualKey"),
      mutating("disable", "Disable a virtual key", "disableVirtualKey"),
      mutating(
        "revoke-action",
        "Revoke a virtual key via the revoke action",
        "revokeVirtualKeyAction",
      ),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "revoke":
          return buildItemDelete(VIRTUAL_KEYS, "virtual-key", input);
        case "rotate":
          return buildItemAction(VIRTUAL_KEYS, "virtual-key", "rotate", input);
        case "enable":
          return buildItemAction(VIRTUAL_KEYS, "virtual-key", "enable", input);
        case "disable":
          return buildItemAction(VIRTUAL_KEYS, "virtual-key", "disable", input);
        case "revoke-action":
          return buildItemAction(VIRTUAL_KEYS, "virtual-key", "revoke", input);
        default:
          return buildCrud(VIRTUAL_KEYS, verb, input);
      }
    },
  },
  {
    name: "api-keys",
    about: "Manage gateway admin API keys",
    secretFields: VIRTUAL_KEY_SECRET_FIELDS,
    verbs: [
      read("list", "List admin API keys", "listAdminApiKeys"),
      read("get", "Show an admin API key", "getAdminApiKey"),
      mutating("create", "Create an admin API key", "createAdminApiKey"),
      mutating("replace", "Replace an admin API key", "putAdminApiKey"),
      mutating("update", "Update an admin API key", "patchAdminApiKey"),
      mutating("delete", "Delete an admin API key", "deleteAdminApiKey"),
    ],
    build: (verb, input) => buildCrud(API_KEYS, verb, input),
  },
  {
    name: "roles",
    about: "Manage RBAC roles",
    verbs: [
      read("list", "List roles", "listRoles"),
      read("get", "Show a role", "getRole"),
      mutating("create", "Create a role", "createRole"),
      mutating("delete", "Delete a role", "deleteRole"),
    ],
    build: (verb, input) => buildCrud(ROLES, verb, input),
  },
  {
    name: "permissions",
    about: "Manage RBAC permissions",
    verbs: [
      read("list", "List permissions", "listPermissions"),
      read("get", "Show a permission", "getPermission"),
      mutating("create", "Create a permission", "createPermission"),
      mutating("delete", "Delete a permission", "deletePermission"),
    ],
    build: (verb, input) => buildCrud(PERMISSIONS, verb, input),
  },
  {
    name: "access-policies",
    about: "Manage named access policies",
    verbs: [
      read("list", "List access policies", "listAdminPolicies"),
      read("get", "Show an access policy", "getAdminPolicy"),
      mutating("create", "Create an access policy", "createAdminPolicy"),
      mutating("replace", "Replace an access policy", "putAdminPolicy"),
      mutating("update", "Update an access policy", "patchAdminPolicy"),
      mutating("delete", "Delete an access policy", "deleteAdminPolicy"),
    ],
    build: (verb, input) => buildCrud(ACCESS_POLICIES, verb, input),
  },
  {
    name: "tenant-roles",
    about: "Manage tenant role bindings",
    verbs: [
      read("list", "List a tenant's role bindings", "listTenantRoles"),
      mutating("bind", "Bind a role to a tenant", "bindTenantRole"),
      mutating("unbind", "Unbind a role from a tenant", "unbindTenantRole"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "list":
          firstSegment(input, "tenant-role");
          return TENANT_ROLES.read(input.segments, input.list);
        case "bind":
          return TENANT_ROLES.action(
            requireTargetSegments(TENANT_ROLES, verb, input.segments, 1),
            requireBody(input, verb),
          );
        case "unbind":
          return TENANT_ROLES.delete(requireTargetSegments(TENANT_ROLES, verb, input.segments, 2));
        default:
          return buildCrud(TENANT_ROLES, verb, input);
      }
    },
  },

  // --- agent -------------------------------------------------------------
  {
    name: "agent-workflows",
    about: "Manage agent workflow definitions",
    verbs: [
      read("list", "List agent workflows", "listAdminAgentWorkflows"),
      read("get", "Show an agent workflow", "getAdminAgentWorkflow"),
      mutating("create", "Create an agent workflow", "createAdminAgentWorkflow"),
      mutating("replace", "Replace an agent workflow", "putAdminAgentWorkflow"),
      mutating("update", "Update an agent workflow", "patchAdminAgentWorkflow"),
      mutating("delete", "Delete an agent workflow", "deleteAdminAgentWorkflow"),
    ],
    build: (verb, input) => buildCrud(AGENT_WORKFLOWS, verb, input),
  },
  {
    name: "agent-schedules",
    about: "Manage agent run schedules and their fire history",
    verbs: [
      read("list", "List agent schedules", "listAdminAgentSchedules"),
      read("get", "Show an agent schedule", "getAdminAgentSchedule"),
      mutating("create", "Create an agent schedule", "createAdminAgentSchedule"),
      mutating("replace", "Replace an agent schedule", "putAdminAgentSchedule"),
      mutating("update", "Update an agent schedule", "patchAdminAgentSchedule"),
      mutating("delete", "Delete an agent schedule", "deleteAdminAgentSchedule"),
      mutating("run-now", "Trigger a schedule to run immediately", "runAdminAgentScheduleNow"),
      read("fires", "List a schedule's fire history", "listAdminAgentScheduleFires"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "run-now":
          return buildItemAction(AGENT_SCHEDULES, "agent-schedule", "run-now", input);
        case "fires":
          return AGENT_SCHEDULES.read([firstSegment(input, "agent-schedule"), "fires"], input.list);
        default:
          return buildCrud(AGENT_SCHEDULES, verb, input);
      }
    },
  },
  {
    name: "agent-upstreams",
    about: "Manage agent upstream bindings",
    verbs: [
      read("list", "List agent upstreams", "listAdminAgentUpstreams"),
      read("get", "Show an agent upstream", "getAdminAgentUpstream"),
      mutating("create", "Create an agent upstream", "createAdminAgentUpstream"),
      mutating("replace", "Replace an agent upstream", "putAdminAgentUpstream"),
      mutating("update", "Update an agent upstream", "patchAdminAgentUpstream"),
      mutating("delete", "Delete an agent upstream", "deleteAdminAgentUpstream"),
    ],
    build: (verb, input) => buildCrud(AGENT_UPSTREAMS, verb, input),
  },
  {
    name: "agent-runs",
    about: "Start and inspect agent runs",
    verbs: [
      read("list", "List agent runs", "listAdminAgentRuns"),
      read("get", "Show an agent run timeline", "getAdminAgentRunTimeline"),
      mutating("start", "Start an agent run", "createAgentRun"),
    ],
    build: (verb, input) =>
      verb === "start"
        ? AGENT_RUNS_RUNTIME.create(requireBody(input, verb))
        : buildCrud(AGENT_RUNS, verb, input),
  },
  {
    name: "agent-jobs",
    about: "Submit, observe, collect, and cancel long-running agent jobs",
    verbs: [
      mutating(
        "submit",
        "Submit a long-running agent job (idempotent on the submitted idempotency_key)",
        "submitAgentJob",
      ),
      read("get", "Show an agent job's status", "getAgentJob"),
      read("events", "Read an agent job's incremental timeline events", "listAgentJobEvents"),
      read("result", "Collect a terminal agent job's result", "getAgentJobResult"),
      mutating("cancel", "Cancel an in-flight agent job", "cancelAgentJob"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "submit":
          return AGENT_JOBS.create(requireBody(input, verb));
        case "get":
          return AGENT_JOBS.get([firstSegment(input, "agent-job")]);
        case "events":
          return AGENT_JOBS.read([firstSegment(input, "agent-job"), "events"], input.list);
        case "result":
          return AGENT_JOBS.get([firstSegment(input, "agent-job"), "result"]);
        case "cancel":
          return buildItemAction(AGENT_JOBS, "agent-job", "cancel", input);
        default:
          throw CliError.usage(`verb '${verb}' is not an agent-jobs verb`);
      }
    },
  },

  // --- worker ------------------------------------------------------------
  {
    name: "self-hosted-workers",
    about: "Manage self-hosted workers and their lifecycle",
    verbs: [
      read("list", "List self-hosted workers", "listAdminSelfHostedWorkers"),
      read("get", "Show a self-hosted worker", "getAdminSelfHostedWorker"),
      mutating("register", "Register a self-hosted worker", "registerSelfHostedWorker"),
      mutating(
        "rotate",
        "Rotate a worker's identity/certificate",
        "rotateAdminSelfHostedWorkerIdentity",
      ),
      mutating("heartbeat", "Record a worker heartbeat", "recordAdminSelfHostedWorkerHeartbeat"),
      read(
        "events",
        "List a worker's telemetry events",
        "listAdminSelfHostedWorkerTelemetryEvents",
      ),
      mutating(
        "record-event",
        "Record a worker telemetry event",
        "recordAdminSelfHostedWorkerTelemetryEvent",
      ),
      mutating("checkpoint", "Record a worker checkpoint", "recordAdminSelfHostedWorkerCheckpoint"),
      mutating("artifact", "Record a worker artifact", "recordAdminSelfHostedWorkerArtifact"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "register":
          return SELF_HOSTED_WORKERS.create(requireBody(input, verb));
        case "rotate":
          return buildItemAction(SELF_HOSTED_WORKERS, "self-hosted-worker", "rotate", input);
        case "heartbeat":
          return buildItemAction(SELF_HOSTED_WORKERS, "self-hosted-worker", "heartbeat", input);
        case "record-event":
          return buildItemAction(SELF_HOSTED_WORKERS, "self-hosted-worker", "events", input);
        case "checkpoint":
          return buildItemAction(SELF_HOSTED_WORKERS, "self-hosted-worker", "checkpoints", input);
        case "artifact":
          return buildItemAction(SELF_HOSTED_WORKERS, "self-hosted-worker", "artifacts", input);
        case "events":
          return SELF_HOSTED_WORKERS.read(
            [firstSegment(input, "self-hosted-worker"), "events"],
            input.list,
          );
        default:
          return buildCrud(SELF_HOSTED_WORKERS, verb, input);
      }
    },
  },
  {
    name: "managed-workers",
    about: "List managed worker pools",
    verbs: [read("list", "List managed workers", "listAdminManagedWorkers")],
    build: (verb, input) => buildCrud(MANAGED_WORKERS, verb, input),
  },
  {
    name: "managed-worker-sessions",
    about: "List managed worker sessions",
    verbs: [read("list", "List managed worker sessions", "listAdminManagedWorkerSessions")],
    build: (verb, input) => buildCrud(MANAGED_WORKER_SESSIONS, verb, input),
  },
  {
    name: "self-hosted-worker-records",
    about: "List immutable self-hosted worker records",
    verbs: [read("list", "List self-hosted worker records", "listAdminSelfHostedWorkerRecords")],
    build: (verb, input) => buildCrud(SELF_HOSTED_WORKER_RECORDS, verb, input),
  },
  {
    name: "self-hosted-runs",
    about: "Inspect self-hosted run timelines",
    verbs: [read("get", "Show a self-hosted run timeline", "getAdminSelfHostedRunTimeline")],
    build: (verb, input) => buildCrud(SELF_HOSTED_RUNS, verb, input),
  },

  // --- mcp ---------------------------------------------------------------
  {
    name: "mcp-servers",
    about: "Manage registered MCP servers",
    verbs: [
      read("list", "List MCP servers", "listAdminMcpServers"),
      read("get", "Show an MCP server", "getAdminMcpServer"),
      mutating("create", "Register an MCP server", "createAdminMcpServer"),
      mutating("replace", "Replace an MCP server", "putAdminMcpServer"),
      mutating("update", "Update an MCP server", "patchAdminMcpServer"),
      mutating("delete", "Deregister an MCP server", "deleteAdminMcpServer"),
    ],
    build: (verb, input) => buildCrud(MCP_SERVERS, verb, input),
  },
  {
    name: "mcp-identity",
    about: "Manage per-server MCP identity grants",
    verbs: [
      mutating("authorize", "Authorize an MCP identity for a server", "authorizeMcpIdentity"),
      read("get", "Show an MCP identity grant", "getMcpIdentity"),
      mutating("revoke", "Revoke an MCP identity grant", "revokeMcpIdentity"),
      mutating("callback", "Complete an MCP identity OAuth callback", "completeMcpIdentityOauth"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "authorize":
          return buildItemAction(MCP_IDENTITY, "mcp-identity", "authorize", input);
        case "get":
          return MCP_IDENTITY.get([firstSegment(input, "mcp-identity")]);
        case "revoke":
          return buildItemDelete(MCP_IDENTITY, "mcp-identity", input);
        case "callback":
          return MCP_IDENTITY.read(["callback"], input.list);
        default:
          return buildCrud(MCP_IDENTITY, verb, input);
      }
    },
  },
  {
    name: "tool-sessions",
    about: "Inspect tool session event streams",
    verbs: [read("events", "List a tool session's events", "listAdminToolSessionEvents")],
    build: (verb, input) =>
      verb === "events"
        ? TOOL_SESSIONS.read([firstSegment(input, "tool-session")], input.list)
        : buildCrud(TOOL_SESSIONS, verb, input),
  },
  {
    name: "tools",
    about: "Inspect the admin tool catalog",
    verbs: [
      read("list", "List all tools", "listAdminTools"),
      read("plugin-tools", "List a plugin's tools", "listAdminPluginTools"),
    ],
    build: (verb, input) =>
      verb === "plugin-tools"
        ? PLUGINS.read([firstSegment(input, "plugin"), "tools"], input.list)
        : buildCrud(TOOLS, verb, input),
  },

  // --- tool approvals ----------------------------------------------------
  {
    name: "tool-approvals",
    about: "Review and resolve pending tool-call approvals",
    verbs: [
      read("list", "List pending tool-call approvals", "listAdminToolApprovals"),
      read("get", "Show a tool-call approval", "getAdminToolApproval"),
      mutating(
        "approve",
        "Approve a pending tool call (fingerprint must still match)",
        "approveAdminToolApproval",
      ),
      mutating("deny", "Deny a pending tool call", "denyAdminToolApproval"),
      mutating("expire", "Expire a pending tool call", "expireAdminToolApproval"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "approve":
          return buildItemAction(TOOL_APPROVALS, "tool-approval", "approve", input);
        case "deny":
          return buildItemAction(TOOL_APPROVALS, "tool-approval", "deny", input);
        case "expire":
          return buildItemAction(TOOL_APPROVALS, "tool-approval", "expire", input);
        default:
          return buildCrud(TOOL_APPROVALS, verb, input);
      }
    },
  },

  // --- guardrail ---------------------------------------------------------
  {
    name: "guardrail-policies",
    about: "Manage guardrail policies and their immutable revisions",
    verbs: [
      read("list", "List guardrail policies", "listGuardrailPolicyRevisions"),
      mutating(
        "create",
        "Create a guardrail policy (first revision)",
        "createGuardrailPolicyRevision",
      ),
      read("get", "List one policy's immutable revisions", "listGuardrailPolicyRevisionsByPolicy"),
      read("revisions", "List a policy's revision history", "listGuardrailPolicyRevisionHistory"),
      mutating(
        "create-revision",
        "Append the next revision to a policy",
        "createNextGuardrailPolicyRevision",
      ),
      read("get-revision", "Show one immutable policy revision", "getGuardrailPolicyRevision"),
      mutating(
        "archive",
        "Archive one immutable policy revision",
        "archiveGuardrailPolicyRevision",
      ),
      mutating(
        "activate",
        "Activate a policy revision (make it live)",
        "activateGuardrailPolicyRevision",
      ),
      mutating(
        "rollback",
        "Roll back to an archived policy revision",
        "rollbackGuardrailPolicyRevision",
      ),
      mutating(
        "dry-run",
        "Inspect a revision without dispatching detectors or actions",
        "dryRunGuardrailPolicyRevision",
      ),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "get":
          return GUARDRAIL_POLICIES.get([firstSegment(input, "guardrail-policy")]);
        case "revisions":
          return GUARDRAIL_POLICIES.read(
            [firstSegment(input, "guardrail-policy"), "revisions"],
            input.list,
          );
        case "create-revision":
          return GUARDRAIL_POLICIES.action(
            [firstSegment(input, "guardrail-policy"), "revisions"],
            requireBody(input, verb),
          );
        case "get-revision": {
          const [policy, revision] = policyAndRevision(input, verb);
          return GUARDRAIL_POLICIES.get([policy, "revisions", revision]);
        }
        case "archive": {
          const [policy, revision] = policyAndRevision(input, verb);
          return GUARDRAIL_POLICIES.delete([policy, "revisions", revision]);
        }
        case "activate":
          return buildItemAction(GUARDRAIL_POLICIES, "guardrail-policy", "activate", input);
        case "rollback":
          return buildItemAction(GUARDRAIL_POLICIES, "guardrail-policy", "rollback", input);
        case "dry-run":
          return buildItemAction(GUARDRAIL_POLICIES, "guardrail-policy", "dry-run", input);
        default:
          return buildCrud(GUARDRAIL_POLICIES, verb, input);
      }
    },
  },
  {
    name: "guardrail-evaluations",
    about: "Inspect the guardrail evaluation event stream",
    verbs: [read("list", "List guardrail evaluations", "listGuardrailEvaluations")],
    build: (verb, input) => buildCrud(GUARDRAIL_EVALUATIONS, verb, input),
  },
  {
    name: "investigations",
    about: "Join cross-plane evidence for one request, trace, or agent run",
    verbs: [
      read(
        "get",
        "Join evidence for a request_id/trace_id/agent_run_id",
        "getGuardrailInvestigation",
      ),
    ],
    build: (verb, input) =>
      verb === "get" ? INVESTIGATIONS.read([], input.list) : buildCrud(INVESTIGATIONS, verb, input),
  },

  // --- asset -------------------------------------------------------------
  {
    name: "assets",
    about: "Manage the asset registry, versions, and lifecycle",
    verbs: [
      read("list", "List all assets", "listAssets"),
      read("list-by-type", "List assets of one type", "listAssetsByType"),
      read("get", "Show one asset version", "getAsset"),
      mutating("put", "Publish or replace an asset version", "putAsset"),
      mutating("delete", "Delete an asset version", "deleteAsset"),
      read("manifest", "Show an asset's resolved manifest", "getAssetManifest"),
      read("storage-summary", "Show asset storage/retention summary", "getAssetStorageSummary"),
      read("withheld", "List withheld (pending_scan/quarantined) assets", "listWithheldAssets"),
      mutating("yank", "Yank an asset version", "yankAssetVersion"),
      mutating("unyank", "Reverse a yank on an asset version", "unyankAssetVersion"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "list":
          return ASSETS.read([], input.list);
        case "list-by-type":
          return ASSETS.read([firstSegment(input, "asset")], input.list);
        case "get":
          return ASSETS.get(assetVersionRef(input, verb));
        case "put":
          return ASSETS.replace(assetVersionRef(input, verb), requireBody(input, verb));
        case "delete":
          return ASSETS.delete(assetVersionRef(input, verb));
        case "manifest": {
          const [assetType, name] = assetNameRef(input, verb);
          return ASSETS.read([assetType, name, "manifest"], input.list);
        }
        case "storage-summary":
          return ASSETS.read(["storage", "summary"], input.list);
        case "withheld":
          return ASSETS.read(["withheld"], input.list);
        case "yank": {
          const [assetType, name, version] = assetVersionRef(input, verb);
          return ASSETS.action([assetType, name, version, "yank"], input.body);
        }
        case "unyank": {
          const [assetType, name, version] = assetVersionRef(input, verb);
          return ASSETS.mutate("DELETE", [assetType, name, version, "yank"], undefined);
        }
        default:
          return buildCrud(ASSETS, verb, input);
      }
    },
  },
  {
    name: "asset-transfer",
    about: "Presigned asset upload and download flows",
    secretFields: ASSET_TRANSFER_SECRET_FIELDS,
    verbs: [
      mutating("upload-intent", "Request a presigned upload target", "createAssetUploadIntent"),
      mutating("commit", "Commit a completed presigned upload", "commitAssetUpload"),
      mutating(
        "abort",
        "Release a presigned upload intent that will not be committed",
        "abortAssetUpload",
      ),
      read("download-url", "Request a presigned download URL", "getAssetDownloadUrl"),
    ],
    build: (verb, input) => {
      const [assetType, name, version] = assetVersionRef(input, verb);
      switch (verb) {
        case "upload-intent":
          return ASSET_PRESIGN.action(
            ["upload", assetType, name, version],
            requireBody(input, verb),
          );
        case "commit":
          return ASSET_PRESIGN.action(
            ["commit", assetType, name, version],
            requireBody(input, verb),
          );
        case "abort":
          return ASSET_PRESIGN.action(
            ["abort", assetType, name, version],
            requireBody(input, verb),
          );
        case "download-url":
          return ASSET_PRESIGN.read(["download", assetType, name, version], input.list);
        default:
          throw CliError.usage(`verb '${verb}' is not an asset-transfer verb`);
      }
    },
  },
  {
    name: "asset-channels",
    about: "Manage asset release channels and promotion",
    verbs: [
      read("list", "List an asset's channels", "listAssetChannels"),
      withPositionalQuerySegments(
        mutating("set", "Point a channel at a version", "putAssetChannel"),
        1,
      ),
      mutating("delete", "Delete a channel", "deleteAssetChannel"),
    ],
    build: (verb, input) => {
      const segments = input.segments;
      switch (verb) {
        case "list": {
          const [assetType, name] = assetNameRef(input, verb);
          return ASSETS.read([assetType, name, "channels"], input.list);
        }
        case "set": {
          const [assetType, name, channel, version] = segments;
          if (
            assetType === undefined ||
            name === undefined ||
            channel === undefined ||
            version === undefined
          ) {
            throw CliError.usage("verb 'set' requires <asset_type> <name> <channel> <version>");
          }
          const spec = ASSETS.mutate("PUT", [assetType, name, "channels", channel], undefined);
          return { ...spec, query: [...spec.query, ["version", version] as const] };
        }
        case "delete": {
          const [assetType, name, channel] = segments;
          if (assetType === undefined || name === undefined || channel === undefined) {
            throw CliError.usage("verb 'delete' requires <asset_type> <name> <channel>");
          }
          return ASSETS.mutate("DELETE", [assetType, name, "channels", channel], undefined);
        }
        default:
          throw CliError.usage(`verb '${verb}' is not an asset-channels verb`);
      }
    },
  },
  {
    name: "site-domains",
    about: "Manage static-site custom domain bindings",
    verbs: [
      read("list", "List bound site domains", "listSiteDomains"),
      read("get", "Show a site domain binding", "getSiteDomain"),
      mutating("bind", "Bind a custom domain to a site", "bindSiteDomain"),
      mutating("verify", "Verify DNS ownership of a bound custom domain", "verifySiteDomain"),
      mutating("unbind", "Unbind a custom domain", "unbindSiteDomain"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "list":
          return SITE_DOMAINS.read([], input.list);
        case "get":
          return SITE_DOMAINS.get([firstSegment(input, "site-domain")]);
        case "bind":
          return SITE_DOMAINS.create(requireBody(input, verb));
        case "verify":
          return SITE_DOMAINS.action([firstSegment(input, "site-domain"), "verify"], input.body);
        case "unbind":
          return SITE_DOMAINS.delete([firstSegment(input, "site-domain")]);
        default:
          throw CliError.usage(`verb '${verb}' is not a site-domains verb`);
      }
    },
  },
  /**
   * The OPERATOR view of what tenants are hosting (#743) — distinct from the
   * `assets` resource above, which is the tenant's own `/v1/assets` surface.
   *
   * Two things about these verbs are worth knowing before using them:
   *
   *  - **The cross-tenant view needs a scope the ordinary operator key does not
   *    have.** `admin.assets.fleet` must be held EXACTLY; the admin wildcard
   *    does not grant it. A 403 here names the scope to mint.
   *  - **`review` requires `--yes`.** It is a moderation verdict on somebody
   *    else's artifact, it is recorded against the owning tenant's audit chain
   *    with the operator's reason, and `release` makes a withheld artifact
   *    servable on the public internet. That is not a verb to fire from shell
   *    history by accident. The reason is part of the request document
   *    (`--data '{"tenant_id":"…","decision":"release","reason":"…"}'`) and the
   *    API refuses the call without it.
   */
  {
    name: "asset-fleet",
    about: "Inspect the asset fleet and review quarantined versions (operator surface)",
    verbs: [
      read("list", "List stored asset versions across tenants (metadata only)", "listFleetAssets"),
      read("quarantine", "List asset versions withheld by the screener", "listQuarantinedAssets"),
      mutatingWithConfirmation(
        "review",
        "Release or reject one withheld asset version, with a reason",
        "reviewQuarantinedAsset",
      ),
      withPositionalQuerySegments(
        mutatingWithConfirmation(
          "delete",
          "Force-delete one asset version — row, bundle index and stored objects (irreversible)",
          "forceDeleteAssetVersion",
        ),
        2,
      ),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "list":
          return ASSET_FLEET.read([], input.list);
        case "quarantine":
          return ASSET_FLEET.read(["quarantine"], input.list);
        case "review":
          return ASSET_FLEET.action(
            ["quarantine", firstSegment(input, "asset")],
            requireBody(input, verb),
          );
        case "delete": {
          // `<asset_id> <tenant_id> <reason> [force]`. The tenant and the reason
          // are POSITIONAL rather than optional flags because the API refuses
          // the call without either, and a verb that can only fail without an
          // argument should not let you type it without one. `force` is the
          // exception: it means "take a live site down", so it is opt-in and
          // spelled out.
          const [assetId, tenantId, reason, force] = input.segments;
          if (assetId === undefined || tenantId === undefined || reason === undefined) {
            throw CliError.usage("verb 'delete' requires <asset_id> <tenant_id> <reason> [force]");
          }
          if (force !== undefined && force !== "force") {
            throw CliError.usage(
              `verb 'delete' takes 'force' as its optional fourth argument (got ${JSON.stringify(force)})`,
            );
          }
          const spec = ASSET_FLEET.mutate("DELETE", [assetId], undefined);
          return {
            ...spec,
            query: [
              ...spec.query,
              ["tenant_id", tenantId] as const,
              ["reason", reason] as const,
              ...(force === "force" ? [["force", "true"] as const] : []),
            ],
          };
        }
        default:
          throw CliError.usage(`verb '${verb}' is not an asset-fleet verb`);
      }
    },
  },

  // --- files & batches (OpenAI-compatible data plane, #698) --------------
  /**
   * The OpenAI-compatible Files surface (`/v1/files`).
   *
   * `create` is a MULTIPART byte upload (`--input-file PATH --purpose VALUE`)
   * and `download` writes the stored bytes to stdout or `--output-file`; the
   * other three are ordinary JSON reads/deletes. The upload and download halves
   * ship together with `batches` because a batch consumes an uploaded
   * `input_file_id` and returns an `output_file_id` the caller downloads.
   */
  {
    name: "files",
    about: "Upload, list, download, and delete OpenAI-compatible files",
    verbs: [
      read("list", "List files", "listFiles"),
      upload(
        "create",
        "Upload a file (multipart: --input-file PATH --purpose VALUE)",
        "createFile",
        { fileField: "file", textFields: ["purpose"] },
      ),
      read("get", "Show a file's metadata", "getFile"),
      rawRead(
        "download",
        "Download a file's raw bytes (to stdout, or --output-file PATH)",
        "getFileContent",
        "application/octet-stream",
      ),
      mutating("delete", "Delete a file", "deleteFile"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "list":
          return FILES.read([], input.list);
        case "create":
          return FILES.uploadTo([], requireUpload(input, verb));
        case "get":
          return FILES.get([firstSegment(input, "file")]);
        case "download":
          return FILES.read([firstSegment(input, "file"), "content"], input.list);
        case "delete":
          return buildItemDelete(FILES, "file", input);
        default:
          throw CliError.usage(`verb '${verb}' is not a files verb`);
      }
    },
  },
  {
    name: "batches",
    about: "Create, list, retrieve, and cancel OpenAI-compatible batch jobs",
    verbs: [
      read("list", "List batch jobs", "listBatches"),
      mutating(
        "create",
        "Create a batch job (references an uploaded input_file_id)",
        "createBatch",
      ),
      read("get", "Retrieve one batch job", "retrieveBatch"),
      mutating("cancel", "Cancel a batch job", "cancelBatch"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "list":
          return BATCHES.read([], input.list);
        case "create":
          return BATCHES.create(requireBody(input, verb));
        case "get":
          return BATCHES.get([firstSegment(input, "batch")]);
        case "cancel":
          return buildItemAction(BATCHES, "batch", "cancel", input);
        default:
          throw CliError.usage(`verb '${verb}' is not a batches verb`);
      }
    },
  },

  // --- catalog -----------------------------------------------------------
  {
    name: "prompt-templates",
    about: "Manage the prompt-template catalog",
    verbs: [
      read("list", "List prompt templates", "listAdminPromptTemplates"),
      read("get", "Show one prompt template", "getAdminPromptTemplate"),
      mutating("create", "Create a prompt template", "createAdminPromptTemplate"),
      mutating("replace", "Replace a prompt template", "putAdminPromptTemplate"),
      mutating("update", "Patch a prompt template", "patchAdminPromptTemplate"),
      mutating("archive", "Archive a prompt template", "archiveAdminPromptTemplate"),
      mutating("render", "Render a prompt template with inputs", "renderPromptTemplate"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "archive":
          return PROMPT_TEMPLATES.delete([firstSegment(input, "prompt-template")]);
        case "render":
          return PROMPTS.action(
            [firstSegment(input, "prompt-template"), "render"],
            requireBody(input, verb),
          );
        default:
          return buildCrud(PROMPT_TEMPLATES, verb, input);
      }
    },
  },
  {
    name: "skill-packages",
    about: "Manage the skill-package catalog",
    verbs: [
      read("list", "List skill packages", "listAdminSkillPackages"),
      read("get", "Show one skill package", "getAdminSkillPackage"),
      mutating("create", "Create a skill package", "createAdminSkillPackage"),
      mutating("replace", "Replace a skill package", "putAdminSkillPackage"),
      mutating("update", "Patch a skill package", "patchAdminSkillPackage"),
      mutating("delete", "Delete a skill package", "deleteAdminSkillPackage"),
    ],
    build: (verb, input) => buildCrud(SKILL_PACKAGES, verb, input),
  },
  {
    name: "plugins",
    about: "Manage the plugin catalog",
    verbs: [
      read("list", "List plugins", "listAdminPlugins"),
      read("get", "Show one plugin", "getAdminPlugin"),
      mutating("create", "Register a plugin", "createAdminPlugin"),
      mutating("update", "Patch a plugin", "updateAdminPlugin"),
      mutating("delete", "Delete a plugin", "deleteAdminPlugin"),
    ],
    build: (verb, input) => buildCrud(PLUGINS, verb, input),
  },
  {
    name: "providers",
    about: "Manage provider channels",
    verbs: [
      read("show", "Show a provider channel", "getAdminProvider"),
      mutating("add", "Create a provider channel", "createAdminProvider"),
      mutating("replace", "Replace a provider channel", "replaceAdminProvider"),
      mutating("update", "Patch a provider channel", "patchAdminProvider"),
      mutating("rm", "Delete a provider channel", "deleteAdminProvider"),
      mutating("sync-models", "Import the provider's upstream model list", "syncProviderModels"),
    ],
    build: (verb, input) =>
      verb === "sync-models"
        ? buildItemAction(PROVIDERS, "provider", "sync-models", input)
        : buildAliasedCrud(PROVIDERS, verb, input),
  },
  {
    name: "billing-groups",
    about: "Manage billing groups and their per-group price multipliers",
    verbs: [
      read("list", "List billing groups", "listBillingGroups"),
      read("show", "Show a billing group", "getBillingGroup"),
      mutating("add", "Create a billing group", "createBillingGroup"),
      mutating("update", "Patch a billing group", "patchBillingGroup"),
      mutating("rm", "Delete a billing group", "deleteBillingGroup"),
      mutating("bind-provider", "Bind a provider to a billing group", "bindBillingGroupProvider"),
      mutating(
        "unbind-provider",
        "Unbind a provider from a billing group",
        "unbindBillingGroupProvider",
      ),
    ],
    build: (verb, input) => buildBillingGroupRequest(verb, input),
  },
  {
    name: "billing-fleet",
    about: "Cross-tenant billing fleet aggregate over Analytics Engine (platform operator)",
    verbs: [
      read(
        "report",
        "Aggregate fleet billing; filter group_by/since/until, page with --limit",
        "queryBillingFleet",
      ),
    ],
    // group_by/since/until arrive as `--filter k=v` (→ `?k=v`) and the row cap as
    // `--limit`; the endpoint reads them straight off the query string.
    build: (_verb, input) => BILLING_FLEET.read([], input.list),
  },
  {
    name: "models",
    about: "Manage logical models",
    verbs: [
      read("show", "Show a logical model", "getAdminModel"),
      mutating("add", "Create a logical model", "createAdminModel"),
      mutating("replace", "Replace a logical model", "replaceAdminModel"),
      mutating("update", "Patch a logical model", "patchAdminModel"),
      mutating("rm", "Delete a logical model", "deleteAdminModel"),
    ],
    build: (verb, input) => buildAliasedCrud(MODELS, verb, input),
  },
  {
    name: "model-offerings",
    about: "Manage model offerings",
    verbs: [
      read("list", "List offerings for a model", "listAdminModelOfferings"),
      read("show", "Show a model offering", "getAdminModelOffering"),
      mutating("add", "Attach a model offering", "createAdminModelOffering"),
      mutating("replace", "Replace a model offering", "replaceAdminModelOffering"),
      mutating("update", "Patch a model offering", "patchAdminModelOffering"),
      mutating("rm", "Delete a model offering", "deleteAdminModelOffering"),
    ],
    build: (verb, input) => buildOfferingRequest(verb, input),
  },
  {
    name: "catalog",
    about: "Inspect read-only model/provider/extension catalogs",
    verbs: [
      read("models", "List resolved models", "listAdminModels"),
      read("providers", "List providers", "listAdminProviders"),
      read("provider-models", "List provider models", "listAdminProviderModels"),
      read("extensions", "List extensions", "listAdminExtensions"),
      read("framework-adapters", "List framework adapters", "listAdminFrameworkAdapters"),
    ],
    build: (verb, input) => {
      const api =
        verb === "models"
          ? MODELS
          : verb === "providers"
            ? PROVIDERS
            : verb === "provider-models"
              ? PROVIDER_MODELS
              : verb === "extensions"
                ? EXTENSIONS
                : verb === "framework-adapters"
                  ? FRAMEWORK_ADAPTERS
                  : undefined;
      if (api === undefined) throw CliError.usage(`verb '${verb}' is not a catalog verb`);
      return api.read([], input.list);
    },
  },
  {
    name: "dashboard",
    about: "Read the admin dashboard aggregate summary",
    verbs: [
      read("show", "Show the admin dashboard", "getAdminDashboard"),
      read("alias", "Show the admin dashboard (/admin/dashboard alias)", "getAdminDashboardAlias"),
      read("root", "Show the admin dashboard (/admin/ alias)", "getAdminDashboardSlash"),
    ],
    build: (verb) => {
      const path =
        verb === "show"
          ? "/admin"
          : verb === "alias"
            ? "/admin/dashboard"
            : verb === "root"
              ? "/admin/"
              : undefined;
      if (path === undefined) throw CliError.usage(`verb '${verb}' is not a dashboard verb`);
      return { method: "GET", path, query: [] };
    },
  },

  // --- billing -----------------------------------------------------------
  {
    name: "wallets",
    about: "Manage tenant credit wallets and settlement",
    verbs: [
      read("list", "List wallets", "listWallets"),
      read("get", "Show a tenant's wallet", "getWallet"),
      mutating("create", "Create a tenant wallet", "createWallet"),
      mutating("update", "Update a wallet's recharge settings", "updateWallet"),
      mutatingWithConfirmation(
        "adjust",
        "Atomically adjust wallet credits (irreversible; requires confirmation)",
        "adjustWallet",
      ),
      mutatingWithConfirmation(
        "charge",
        "Charge a payment method and credit a wallet (irreversible; requires confirmation)",
        "chargeWallet",
      ),
      read("ledger", "List a wallet's ledger entries", "listWalletLedger"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "adjust":
          return WALLETS.action(
            [firstSegment(input, "wallet"), "adjust"],
            requireBody(input, verb),
          );
        case "charge":
          return WALLETS.action(
            [firstSegment(input, "wallet"), "charge"],
            requireBody(input, verb),
          );
        case "ledger":
          return WALLETS.read([firstSegment(input, "wallet"), "ledger"], input.list);
        default:
          return buildCrud(WALLETS, verb, input);
      }
    },
  },
  {
    name: "payment-methods",
    about: "Manage stored payment methods",
    verbs: [
      read("list", "List payment methods", "listPaymentMethods"),
      mutating("create", "Register a payment method", "createPaymentMethod"),
      mutating("delete", "Delete a payment method", "deletePaymentMethod"),
    ],
    build: (verb, input) => buildCrud(PAYMENT_METHODS, verb, input),
  },
  {
    name: "billing-events",
    about: "Inspect billing events and outbox dead letters",
    verbs: [
      read("list", "List billing events", "listAdminBillingEventsCompat"),
      read("dead-letters", "List billing outbox dead letters", "listBillingOutboxDeadLetters"),
      mutatingWithConfirmation(
        "replay",
        "Replay a dead-lettered billing outbox record (state-changing; requires confirmation)",
        "replayBillingOutboxDeadLetter",
      ),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "dead-letters":
          return BILLING_DEAD_LETTERS.read([], input.list);
        case "replay":
          return BILLING_DEAD_LETTERS.action(
            [firstSegment(input, "billing dead-letter"), "replay"],
            input.body,
          );
        default:
          return buildCrud(BILLING_EVENTS, verb, input);
      }
    },
  },
  {
    name: "usage",
    about: "Inspect usage aggregates, reports, metering, cost-burn, and spend anomalies",
    verbs: [
      read("aggregates", "List usage aggregates", "listAdminUsageAggregates"),
      read("reports", "List usage reports", "listUsageReports"),
      read("metering-events", "List raw metering events", "listAdminMeteringEvents"),
      read(
        "metering-export-status",
        "Show metering exporter status",
        "listAdminMeteringExportStatus",
      ),
      read(
        "cost-burn",
        "List per-agent runtime cost-burn for a billing period (--filter period=YYYY-MM)",
        "listAdminAgentCostBurn",
      ),
      read(
        "spend-anomalies",
        "List spend burn-rate and forecast-overrun episodes " +
          "(--filter status=open|resolved [--filter signal=…] [--filter severity=…] " +
          "[--filter scope_id=…] [--filter since=UNIX])",
        "listAdminSpendAnomalies",
      ),
    ],
    build: (verb, input) => {
      const api =
        verb === "aggregates"
          ? USAGE_AGGREGATES
          : verb === "reports"
            ? USAGE_REPORTS
            : verb === "metering-events"
              ? METERING_EVENTS
              : verb === "metering-export-status"
                ? METERING_EXPORT_STATUS
                : verb === "cost-burn"
                  ? AGENT_COST_BURN
                  : verb === "spend-anomalies"
                    ? SPEND_ANOMALIES
                    : undefined;
      if (api === undefined) throw CliError.usage(`verb '${verb}' is not a usage verb`);
      return api.read([], input.list);
    },
  },
  {
    name: "payment-attempts",
    about: "Inspect durable x402 payment attempts and their wallet holds",
    verbs: [
      read(
        "list",
        "List a tenant's payment attempts — CURSOR-paged, so --offset and --all-pages do not apply (--filter tenant_id=… [--filter limit=…] [--filter cursor=…])",
        "listPaymentAttempts",
      ),
      read(
        "get",
        "Show one payment attempt with its wallet reservation and settlement",
        "getPaymentAttemptLinks",
      ),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "list":
          return PAYMENT_ATTEMPTS.read([], input.list);
        case "get":
          return PAYMENT_ATTEMPTS.read([firstSegment(input, "payment attempt")], input.list);
        default:
          throw CliError.usage(`verb '${verb}' is not a payment-attempts verb`);
      }
    },
  },

  // --- evidence ----------------------------------------------------------
  {
    name: "request-logs",
    about: "Inspect and export retained request logs",
    verbs: [
      read("list", "List retained request logs", "listAdminRequestLogs"),
      rawRead(
        "export",
        "Export request logs as redacted JSONL",
        "exportAdminRequestLogsJsonl",
        "application/x-ndjson",
      ),
    ],
    build: (verb, input) =>
      verb === "export"
        ? REQUEST_LOG_EXPORTS.read([], input.list)
        : buildCrud(REQUEST_LOGS, verb, input),
  },
  {
    name: "audit-events",
    about: "List retained Admin API audit events",
    verbs: [read("list", "List audit events", "listAdminAuditEvents")],
    build: (verb, input) => buildCrud(AUDIT_EVENTS, verb, input),
  },
  {
    // #693 — canary/shadow outcome metrics. Both verbs go through
    // `EXPERIMENTS.read` rather than `buildCrud`, because `get` must carry the
    // query string: `--filter variant=canary`, `--filter min_samples=100` and
    // `--filter since=…` are what select the comparison, and `buildCrud`'s
    // `get` leg drops the query. A verb that silently discarded `variant` would
    // report whichever arm the server picked, which is the one thing that
    // surface refuses to do.
    name: "experiments",
    about: "Read canary/shadow split outcomes: per-arm cost, latency, errors and quality",
    verbs: [
      read("list", "List traffic-splitting experiments", "listAdminExperiments"),
      read("get", "Report one experiment's arms and quality verdict", "getAdminExperiment"),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "list":
          return EXPERIMENTS.read([], input.list);
        case "get":
          return EXPERIMENTS.read([firstSegment(input, "experiment")], input.list);
        default:
          throw CliError.usage(`verb '${verb}' is not an experiments verb`);
      }
    },
  },
  {
    name: "observed-agent-activity",
    about: "List observed agent/run activity correlations",
    verbs: [read("list", "List observed agent activity", "listAdminObservedAgentActivity")],
    build: (verb, input) => buildCrud(OBSERVED_AGENT_ACTIVITY, verb, input),
  },

  // --- ops ---------------------------------------------------------------
  {
    name: "system",
    about: "Inspect system status, readiness, and observability",
    verbs: [
      read("status", "Show admin system status", "getAdminStatus"),
      read("status-alias", "Show admin system status (compat alias)", "getAdminStatusAlias"),
      read("ready", "Check readiness", "getReadyz"),
      read("health", "Check liveness", "getHealthz"),
      read("observability", "Show the observability snapshot", "listAdminObservability"),
    ],
    build: (verb, input) => {
      const api =
        verb === "status"
          ? ADMIN_STATUS
          : verb === "status-alias"
            ? ADMIN_STATUS_ALIAS
            : verb === "ready"
              ? READYZ
              : verb === "health"
                ? HEALTHZ
                : verb === "observability"
                  ? OBSERVABILITY
                  : undefined;
      if (api === undefined) throw CliError.usage(`verb '${verb}' is not a system verb`);
      return api.read([], input.list);
    },
  },
  {
    name: "provider-health",
    about: "List provider health status",
    verbs: [read("list", "List provider health", "listAdminProviderHealth")],
    build: (verb, input) => buildCrud(PROVIDER_HEALTH, verb, input),
  },
  {
    name: "config",
    about: "Validate and reload gateway configuration",
    verbs: [
      mutating("validate", "Validate a candidate config without committing", "validateAdminConfig"),
      mutatingWithConfirmation(
        "reload",
        "Validate and apply a config reload (state-changing; requires confirmation)",
        "reloadAdminConfig",
      ),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "validate":
          return CONFIG.action(["validate"], requireBody(input, verb));
        case "reload":
          return CONFIG.action(["reload"], input.body);
        default:
          throw CliError.usage(`verb '${verb}' is not a config verb`);
      }
    },
  },
  {
    name: "drain",
    about: "Inspect and control node drain mode",
    verbs: [
      read("get", "Show current drain state", "getAdminDrain"),
      mutatingWithConfirmation(
        "set",
        "Set or clear node drain mode (state-changing; requires confirmation)",
        "setAdminDrain",
      ),
    ],
    build: (verb, input) => {
      switch (verb) {
        case "get":
          return DRAIN.read([], input.list);
        case "set":
          return DRAIN.action([], requireBody(input, verb));
        default:
          throw CliError.usage(`verb '${verb}' is not a drain verb`);
      }
    },
  },
  {
    name: "gateway-configs",
    about: "Manage gateway config profiles",
    verbs: [
      read("list", "List gateway config profiles", "listAdminGatewayConfigs"),
      read("get", "Show a gateway config profile", "getAdminGatewayConfig"),
      mutating("create", "Create a gateway config profile", "createAdminGatewayConfig"),
      mutating("replace", "Replace a gateway config profile", "putAdminGatewayConfig"),
      mutating("update", "Update a gateway config profile", "patchAdminGatewayConfig"),
      mutating("delete", "Delete a gateway config profile", "deleteAdminGatewayConfig"),
    ],
    build: (verb, input) => buildCrud(GATEWAY_CONFIGS, verb, input),
  },
];

// ---------------------------------------------------------------------------
// Registry lookups
// ---------------------------------------------------------------------------

const GROUPS_BY_NAME: ReadonlyMap<string, GroupDescriptor> = new Map(
  GROUPS.map((group) => [group.name, group]),
);

/** Every registered group name, in registration order. */
export const GROUP_NAMES: readonly string[] = GROUPS.map((group) => group.name);

export function findGroup(name: string): GroupDescriptor | undefined {
  return GROUPS_BY_NAME.get(name);
}

/** Resolve `group verb` to its descriptor, or a usage error naming the miss. */
export function resolveVerb(
  group: string,
  verb: string,
): {
  group: GroupDescriptor;
  verb: VerbDescriptor;
} {
  const descriptor = GROUPS_BY_NAME.get(group);
  if (descriptor === undefined) {
    throw CliError.usage(
      `unknown resource group '${group}'; run \`ferrogate ctl --help\` for the command list`,
    );
  }
  const found = descriptor.verbs.find((candidate) => candidate.name === verb);
  if (found === undefined) {
    const known = descriptor.verbs.map((candidate) => candidate.name).join(", ");
    throw CliError.usage(`unknown verb '${verb}' for group '${group}'; known verbs: ${known}`);
  }
  return { group: descriptor, verb: found };
}

/** Build the HTTP request for a resolved `group verb` plus its typed input. */
export function buildRequest(group: string, verb: string, input: ResourceInput): RequestSpec {
  const { group: descriptor } = resolveVerb(group, verb);
  return descriptor.build(verb, input);
}

/** Response fields that must be redacted for a group's reads and diagnostics. */
export function secretFieldsFor(group: string): readonly string[] {
  return GROUPS_BY_NAME.get(group)?.secretFields ?? [];
}

/**
 * The OpenAPI coverage manifest: every `operationId` the registry claims.
 *
 * The #365 parity gate that diffs this against
 * `docs/openapi/admin-api.openapi.json` — including the `x-ferrogate-data-plane`
 * exclusion (#390) — lives in `parity.ts` and is enforced by
 * `test/parity.test.ts`. This function stays the de-duplicated view; `parity.ts`
 * keeps the per-verb sites so duplicate mappings are detectable.
 */
export function coverageManifest(): readonly string[] {
  const ids = new Set<string>();
  for (const group of GROUPS) {
    for (const verb of group.verbs) {
      if (verb.operationId !== null) ids.add(verb.operationId);
    }
  }
  return [...ids].sort();
}

/** Recursively replace `secretFields` values with `<redacted>` in place. */
export function redactSecretFields(value: JsonValue, secretFields: readonly string[]): JsonValue {
  if (secretFields.length === 0) return value;
  if (Array.isArray(value)) {
    return value.map((item) => redactSecretFields(item, secretFields));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, JsonValue> = {};
    for (const [key, field] of Object.entries(value)) {
      out[key] =
        secretFields.includes(key) && field !== null
          ? "<redacted>"
          : redactSecretFields(field, secretFields);
    }
    return out;
  }
  return value;
}

/** Redact secret response fields, but only for safe (GET) reads. */
export function redactResponse(group: string, spec: RequestSpec, body: JsonValue): JsonValue {
  if (spec.method !== "GET") return body;
  return redactSecretFields(body, secretFieldsFor(group));
}
