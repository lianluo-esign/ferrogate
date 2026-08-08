import type { JsonValue } from "@ferrogate/core";
import { ClientActionIdentity, fingerprintEnvFrom } from "../action-identity.js";
import type { Args, FlagSpec } from "../args.js";
import type { EffectiveContext, OutputFormat } from "../context.js";
import { reportError } from "../diagnostics.js";
import { CliError, asCliError } from "../errors.js";
import { GLOBAL_FLAGS, resolveEffective } from "../global-args.js";
import { Table, renderJson, renderTable } from "../output.js";
import type { ApiResponse, RequestContext, RequestSpec } from "../ports.js";
import { redactSecretFields } from "../registry.js";
import type { CliRuntime, CommandNode } from "../runtime.js";
import { requestContextFor } from "./ctl.js";

const PROVIDERS_PATH = "/admin/v1/providers";
const MODELS_PATH = "/admin/v1/models";
const OFFERINGS_SUFFIX = "offerings";

const CATALOG_SECRET_FIELDS = [
  "api_key",
  "api_key_value",
  "credential",
  "secret",
  "token",
] as const;

const JSON_FLAG: FlagSpec = {
  name: "json",
  kind: "boolean",
  help: "Output JSON (same payload as --output json)",
  conflictsWith: ["output"],
};

/**
 * Address the platform-wide catalog instead of a tenant's (#893).
 *
 * The Admin catalog route resolves platform-vs-tenant scope from the caller's
 * key plus a `tenant_id` query/body parameter (#889), NOT from the
 * `x-ferrogate-tenant` header the global `--tenant` flag rides — so these leaves
 * emit `tenant_id` explicitly (see `stampScope`). `--platform` is the operator
 * saying "no tenant": it drops any `--tenant`/`FERROGATE_TENANT` narrowing so a
 * platform operator reaches the platform catalog, and it conflicts with an
 * explicit `--tenant` because naming both scopes at once is incoherent.
 */
const PLATFORM_FLAG: FlagSpec = {
  name: "platform",
  kind: "boolean",
  help: "Address the platform-wide catalog (omit any tenant scope)",
  conflictsWith: ["tenant"],
};

const PROVIDER_FIELD_FLAGS: readonly FlagSpec[] = [
  { name: "name", kind: "string", valueName: "NAME", help: "Provider channel name" },
  { name: "kind", kind: "string", valueName: "KIND", help: "Provider kind" },
  { name: "base-url", kind: "string", valueName: "URL", help: "Provider base URL" },
  {
    name: "api-key-var",
    kind: "string",
    valueName: "BINDING",
    help: "Binding/reference name for the provider key; never the key itself",
  },
  { name: "byok-alias", kind: "string", valueName: "ALIAS", help: "BYOK alias" },
  {
    name: "auth-scheme",
    kind: "string",
    valueName: "SCHEME",
    help: "Provider authentication scheme",
  },
  { name: "region", kind: "string", valueName: "REGION", help: "Provider region" },
  {
    name: "zero-data-retention",
    kind: "boolean",
    help: "Whether the provider guarantees zero data retention",
  },
  {
    name: "openrouter-http-referer",
    kind: "string",
    valueName: "URL",
    help: "OpenRouter HTTP referer metadata",
  },
  {
    name: "openrouter-x-title",
    kind: "string",
    valueName: "TITLE",
    help: "OpenRouter X-Title metadata",
  },
  {
    name: "cloudflare-ai-gateway",
    kind: "string",
    valueName: "JSON",
    help: "Cloudflare AI Gateway configuration as JSON",
  },
  { name: "enabled", kind: "boolean", help: "Enable the provider or model" },
];

const MODEL_FIELD_FLAGS: readonly FlagSpec[] = [
  { name: "name", kind: "string", valueName: "NAME", help: "Logical model name" },
  { name: "family", kind: "string", valueName: "FAMILY", help: "Model family" },
  { name: "owned-by", kind: "string", valueName: "OWNER", help: "Model owner" },
  {
    name: "context-window",
    kind: "number",
    valueName: "TOKENS",
    help: "Model context window",
  },
  {
    name: "capabilities",
    kind: "string",
    valueName: "LIST",
    help: "Comma-separated model capabilities",
  },
  {
    name: "routing-strategy",
    kind: "string",
    valueName: "STRATEGY",
    help: "Model routing strategy",
  },
  { name: "enabled", kind: "boolean", help: "Enable the model" },
];

const OFFERING_FIELD_FLAGS: readonly FlagSpec[] = [
  { name: "provider", kind: "string", valueName: "CHANNEL", help: "Provider channel id" },
  {
    name: "upstream-model",
    kind: "string",
    valueName: "ID",
    help: "Provider's upstream model id",
  },
  { name: "role", kind: "string", valueName: "ROLE", help: "Offering routing role" },
  { name: "priority", kind: "number", valueName: "N", help: "Offering priority" },
  { name: "weight", kind: "number", valueName: "N", help: "Offering weight" },
  { name: "canary-percent", kind: "number", valueName: "PERCENT", help: "Canary percentage" },
  {
    name: "shadow-percent",
    kind: "number",
    valueName: "PERCENT",
    help: "Shadow sampling percentage",
  },
  {
    name: "shadow-max-requests",
    kind: "number",
    valueName: "N",
    help: "Maximum shadow requests",
  },
  {
    name: "capabilities",
    kind: "string",
    valueName: "LIST",
    help: "Comma-separated offering capabilities",
  },
  {
    name: "context-window",
    kind: "number",
    valueName: "TOKENS",
    help: "Offering context window",
  },
  { name: "region", kind: "string", valueName: "REGION", help: "Offering region" },
  {
    name: "zero-data-retention",
    kind: "boolean",
    help: "Whether the offering guarantees zero data retention",
  },
  { name: "input-price", kind: "number", valueName: "USD", help: "Input price per 1M" },
  { name: "output-price", kind: "number", valueName: "USD", help: "Output price per 1M" },
  {
    name: "cached-input-price",
    kind: "number",
    valueName: "USD",
    help: "Cached input price per 1M",
  },
  {
    name: "cache-write-price",
    kind: "number",
    valueName: "USD",
    help: "Cache write price per 1M",
  },
  {
    name: "reasoning-price",
    kind: "number",
    valueName: "USD",
    help: "Reasoning price per 1M",
  },
  {
    name: "audio-second-price",
    kind: "number",
    valueName: "USD",
    help: "Audio second price per 1M",
  },
  {
    name: "audio-character-price",
    kind: "number",
    valueName: "USD",
    help: "Audio character price per 1M",
  },
  { name: "currency", kind: "string", valueName: "CODE", help: "Price currency" },
  { name: "source", kind: "string", valueName: "SOURCE", help: "Price source" },
  { name: "enabled", kind: "boolean", help: "Enable the offering" },
];

function catalogFlags(extra: readonly FlagSpec[] = []): readonly FlagSpec[] {
  return [...extra, PLATFORM_FLAG, ...GLOBAL_FLAGS, JSON_FLAG];
}

function pathFor(base: string, ...segments: string[]): string {
  return [base, ...segments]
    .map((segment, index) => (index === 0 ? segment : encodeURIComponent(segment)))
    .join("/");
}

function isObject(value: JsonValue | undefined): value is Record<string, JsonValue> {
  return (
    value !== undefined && value !== null && typeof value === "object" && !Array.isArray(value)
  );
}

function objectValue(value: JsonValue | undefined): Record<string, JsonValue> {
  return isObject(value) ? value : {};
}

function stringValue(value: JsonValue | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function arrayValue(value: JsonValue | undefined): JsonValue[] {
  return Array.isArray(value) ? [...value] : [];
}

function itemBody(body: JsonValue, key: string): Record<string, JsonValue> {
  const envelope = objectValue(body);
  const item = envelope[key];
  return isObject(item) ? item : envelope;
}

function listBody(body: JsonValue): JsonValue[] {
  if (Array.isArray(body)) return [...body];
  return arrayValue(objectValue(body).data);
}

function requiredPosition(args: Args, noun: string, index = 0): string {
  const value = args.positionals[index];
  if (value === undefined || value.trim() === "") {
    throw CliError.usage(`${noun} requires a target ${index === 0 ? "id" : "offering id"}`);
  }
  return value;
}

function exactPositionCount(args: Args, max: number, noun: string): void {
  if (args.positionals.length > max) {
    throw CliError.usage(`${noun} accepts at most ${max} positional id(s)`);
  }
}

function setString(body: Record<string, JsonValue>, args: Args, flag: string, field = flag): void {
  if (!args.present(flag)) return;
  const value = args.requireString(flag);
  body[field] = value;
}

function setNumber(body: Record<string, JsonValue>, args: Args, flag: string, field: string): void {
  if (!args.present(flag)) return;
  body[field] = args.getNumber(flag) as number;
}

function setBoolean(body: Record<string, JsonValue>, args: Args, flag: string, field = flag): void {
  if (args.present(flag)) body[field] = args.getBoolean(flag);
}

function setCapabilities(
  body: Record<string, JsonValue>,
  args: Args,
  flag: string,
  field = "capabilities",
): void {
  if (!args.present(flag)) return;
  body[field] = (args.getString(flag) ?? "")
    .split(",")
    .map((capability) => capability.trim())
    .filter((capability) => capability !== "");
}

function setJsonValue(
  body: Record<string, JsonValue>,
  args: Args,
  flag: string,
  field: string,
): void {
  if (!args.present(flag)) return;
  const raw = args.requireString(flag);
  try {
    body[field] = JSON.parse(raw) as JsonValue;
  } catch (error) {
    throw CliError.usage(
      `--${flag} must be valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function rejectCredentialShaped(value: string): void {
  if (/^sk-[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value.trim())) {
    throw CliError.usage(
      "refusing --api-key-var because it looks like a credential; provide a binding/reference name",
    );
  }
}

function setApiKeyVar(body: Record<string, JsonValue>, args: Args, required: boolean): void {
  if (!args.present("api-key-var") && !required) return;
  const value = args.requireString("api-key-var");
  rejectCredentialShaped(value);
  body.api_key_var = value;
}

function providerBody(args: Args, required: boolean): Record<string, JsonValue> {
  const body: Record<string, JsonValue> = {};
  if (required) {
    const name = args.requireString("name");
    body.id = name;
    body.name = name;
    body.kind = args.requireString("kind");
    body.base_url = args.requireString("base-url");
  } else {
    setString(body, args, "name");
    setString(body, args, "kind");
    setString(body, args, "base-url", "base_url");
  }
  setApiKeyVar(body, args, required);
  setString(body, args, "byok-alias", "byok_alias");
  setString(body, args, "auth-scheme", "auth_scheme");
  setString(body, args, "region");
  setBoolean(body, args, "zero-data-retention", "zero_data_retention");
  setString(body, args, "openrouter-http-referer", "openrouter_http_referer");
  setString(body, args, "openrouter-x-title", "openrouter_x_title");
  setJsonValue(body, args, "cloudflare-ai-gateway", "cloudflare_ai_gateway");
  setBoolean(body, args, "enabled");
  return body;
}

function modelBody(args: Args, required: boolean): Record<string, JsonValue> {
  const body: Record<string, JsonValue> = {};
  if (required) {
    const name = args.requireString("name");
    body.id = name;
    body.name = name;
  } else {
    setString(body, args, "name");
  }
  setString(body, args, "family");
  setString(body, args, "owned-by", "owned_by");
  setNumber(body, args, "context-window", "context_window");
  setCapabilities(body, args, "capabilities");
  setString(body, args, "routing-strategy", "routing_strategy");
  setBoolean(body, args, "enabled");
  return body;
}

function offeringBody(args: Args, required: boolean): Record<string, JsonValue> {
  const body: Record<string, JsonValue> = {};
  if (required) {
    body.provider_id = args.requireString("provider");
    body.upstream_model_id = args.requireString("upstream-model");
  } else {
    setString(body, args, "provider", "provider_id");
    setString(body, args, "upstream-model", "upstream_model_id");
  }
  setString(body, args, "role");
  setNumber(body, args, "priority", "priority");
  setNumber(body, args, "weight", "weight");
  setNumber(body, args, "canary-percent", "canary_percent");
  setNumber(body, args, "shadow-percent", "shadow_percent");
  setNumber(body, args, "shadow-max-requests", "shadow_max_requests");
  setCapabilities(body, args, "capabilities");
  setNumber(body, args, "context-window", "context_window");
  setString(body, args, "region");
  setBoolean(body, args, "zero-data-retention", "zero_data_retention");
  setNumber(body, args, "input-price", "input_price_per_1m");
  setNumber(body, args, "output-price", "output_price_per_1m");
  setNumber(body, args, "cached-input-price", "cached_input_price_per_1m");
  setNumber(body, args, "cache-write-price", "cache_write_price_per_1m");
  setNumber(body, args, "reasoning-price", "reasoning_price_per_1m");
  setNumber(body, args, "audio-second-price", "audio_second_price_per_1m");
  setNumber(body, args, "audio-character-price", "audio_character_price_per_1m");
  setString(body, args, "currency");
  setString(body, args, "source");
  setBoolean(body, args, "enabled");
  return body;
}

interface CatalogSession {
  readonly runtime: CliRuntime;
  readonly effective: EffectiveContext;
  readonly identity: ClientActionIdentity;
  readonly context: RequestContext;
  readonly format: OutputFormat;
  /**
   * The `tenant_id` every catalog request carries, or `undefined` for the
   * platform catalog. `undefined` covers BOTH `--platform` (an operator dropping
   * a tenant narrowing on purpose) and "no tenant selected at all" — in either
   * case no `tenant_id` is sent and the route's key-derived scope decides.
   */
  readonly scopeTenantId?: string;
}

/**
 * Resolve which catalog the leaf addresses.
 *
 * `--platform` wins and forces the platform catalog by SUPPRESSING any tenant
 * (including one from `FERROGATE_TENANT`/a context), which is why it cannot be
 * expressed as "just omit `--tenant`": an env tenant would otherwise silently
 * re-narrow the call. Otherwise the effective tenant (flag > env > context) is
 * the scope; when none is set, `undefined` lets the caller's key decide.
 */
function scopeTenantId(args: Args, effective: EffectiveContext): string | undefined {
  return args.getBoolean("platform") ? undefined : effective.tenant;
}

async function openSession(runtime: CliRuntime, args: Args): Promise<CatalogSession> {
  const effective = await resolveEffective(runtime, args);
  const identity = ClientActionIdentity.mint(effective, runtime.io, fingerprintEnvFrom(runtime.io));
  const baseContext = await requestContextFor(runtime, effective, identity);
  const tenantId = scopeTenantId(args, effective);
  // Under `--platform` the `x-ferrogate-tenant` header would name a tenant the
  // scope explicitly abandons; drop it so the header cannot contradict the body.
  const { tenant: _headerTenant, ...withoutTenant } = baseContext;
  const context = tenantId === undefined ? withoutTenant : baseContext;
  return {
    runtime,
    effective,
    identity,
    context,
    format: args.getBoolean("json") ? "json" : effective.output,
    ...(tenantId === undefined ? {} : { scopeTenantId: tenantId }),
  };
}

/**
 * Stamp the resolved scope onto a request the way #889's route reads it:
 * `tenant_id` as a query parameter on reads/deletes, and as a body field on
 * writes. A platform scope (`tenantId === undefined`) stamps nothing, so the
 * request carries no tenant and the operator key addresses the platform catalog.
 */
function stampScope(spec: RequestSpec, tenantId: string | undefined): RequestSpec {
  if (tenantId === undefined) return spec;
  if (spec.method === "POST" || spec.method === "PATCH" || spec.method === "PUT") {
    const base = isObject(spec.body) ? spec.body : {};
    return { ...spec, body: { ...base, tenant_id: tenantId } };
  }
  return { ...spec, query: [...spec.query, ["tenant_id", tenantId]] };
}

async function send(session: CatalogSession, spec: RequestSpec): Promise<ApiResponse> {
  const response = await session.runtime.client.send(
    stampScope(spec, session.scopeTenantId),
    session.context,
  );
  if (response.requestId !== undefined)
    session.runtime.io.stderr(`request-id: ${response.requestId}\n`);
  if (response.traceId !== undefined) session.runtime.io.stderr(`trace-id: ${response.traceId}\n`);
  return response;
}

function safeBody(body: JsonValue): JsonValue {
  return redactSecretFields(body, CATALOG_SECRET_FIELDS);
}

function emit(session: CatalogSession, body: JsonValue): void {
  const safe = safeBody(body);
  session.runtime.io.stdout(
    `${session.format === "json" ? renderJson(safe) : renderTable(safe)}\n`,
  );
}

function emitModelShow(
  session: CatalogSession,
  model: Record<string, JsonValue>,
  offerings: JsonValue[],
): void {
  const safeModel = objectValue(safeBody({ ...model, offerings }));
  if (session.format === "json") {
    session.runtime.io.stdout(`${renderJson(safeModel)}\n`);
    return;
  }

  const metadataRows = Object.entries(safeModel)
    .filter(([key]) => key !== "offerings")
    .map(([key, value]) => [key, renderCell(value)] as const);
  const offeringColumns = [
    "id",
    "provider",
    "provider_id",
    "upstream_model_id",
    "role",
    "priority",
    "weight",
    "input_price_per_1m",
    "output_price_per_1m",
    "cached_input_price_per_1m",
    "cache_write_price_per_1m",
    "reasoning_price_per_1m",
    "audio_second_price_per_1m",
    "audio_character_price_per_1m",
    "currency",
  ];
  const offeringRows = offerings.map((value) => {
    const offering = objectValue(value);
    return offeringColumns.map((column) => renderCell(offering[column]));
  });
  const metadata = Table.create(["MODEL", "VALUE"], metadataRows).render();
  const prices =
    offeringRows.length === 0
      ? "(no offerings)"
      : Table.create(
          offeringColumns.map((column) => column.toUpperCase()),
          offeringRows,
        ).render();
  session.runtime.io.stdout(`MODEL\n${metadata}\n\nOFFERINGS\n${prices}\n`);
}

function renderCell(value: JsonValue | undefined): string {
  if (value === undefined || value === null) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return JSON.stringify(value);
}

async function emitRequest(session: CatalogSession, spec: RequestSpec): Promise<number> {
  const response = await send(session, spec);
  emit(session, response.body);
  return 0;
}

async function providerList(runtime: CliRuntime, args: Args): Promise<number> {
  const session = await openSession(runtime, args);
  return emitRequest(session, { method: "GET", path: PROVIDERS_PATH, query: [] });
}

async function providerAdd(runtime: CliRuntime, args: Args): Promise<number> {
  const body = providerBody(args, true);
  const session = await openSession(runtime, args);
  return emitRequest(session, { method: "POST", path: PROVIDERS_PATH, query: [], body });
}

async function providerShow(runtime: CliRuntime, args: Args): Promise<number> {
  exactPositionCount(args, 1, "provider show");
  const session = await openSession(runtime, args);
  return emitRequest(session, {
    method: "GET",
    path: pathFor(PROVIDERS_PATH, requiredPosition(args, "provider")),
    query: [],
  });
}

async function providerUpdate(runtime: CliRuntime, args: Args): Promise<number> {
  exactPositionCount(args, 1, "provider update");
  const body = providerBody(args, false);
  if (Object.keys(body).length === 0)
    throw CliError.usage("provider update requires at least one field");
  const session = await openSession(runtime, args);
  return emitRequest(session, {
    method: "PATCH",
    path: pathFor(PROVIDERS_PATH, requiredPosition(args, "provider")),
    query: [],
    body,
  });
}

async function providerRemove(runtime: CliRuntime, args: Args): Promise<number> {
  exactPositionCount(args, 1, "provider rm");
  const session = await openSession(runtime, args);
  return emitRequest(session, {
    method: "DELETE",
    path: pathFor(PROVIDERS_PATH, requiredPosition(args, "provider")),
    query: [],
  });
}

async function modelList(runtime: CliRuntime, args: Args): Promise<number> {
  const session = await openSession(runtime, args);
  return emitRequest(session, { method: "GET", path: MODELS_PATH, query: [] });
}

async function modelAdd(runtime: CliRuntime, args: Args): Promise<number> {
  const body = modelBody(args, true);
  const session = await openSession(runtime, args);
  return emitRequest(session, { method: "POST", path: MODELS_PATH, query: [], body });
}

async function modelShow(runtime: CliRuntime, args: Args): Promise<number> {
  exactPositionCount(args, 1, "model show");
  const session = await openSession(runtime, args);
  const modelId = requiredPosition(args, "model");
  const modelResponse = await send(session, {
    method: "GET",
    path: pathFor(MODELS_PATH, modelId),
    query: [],
  });
  const offeringResponse = await send(session, {
    method: "GET",
    path: pathFor(MODELS_PATH, modelId, OFFERINGS_SUFFIX),
    query: [],
  });
  const model = itemBody(modelResponse.body, "model");
  emitModelShow(session, model, listBody(offeringResponse.body));
  return 0;
}

async function modelUpdate(runtime: CliRuntime, args: Args): Promise<number> {
  exactPositionCount(args, 1, "model update");
  const body = modelBody(args, false);
  if (Object.keys(body).length === 0)
    throw CliError.usage("model update requires at least one field");
  const session = await openSession(runtime, args);
  return emitRequest(session, {
    method: "PATCH",
    path: pathFor(MODELS_PATH, requiredPosition(args, "model")),
    query: [],
    body,
  });
}

async function modelRemove(runtime: CliRuntime, args: Args): Promise<number> {
  exactPositionCount(args, 1, "model rm");
  const session = await openSession(runtime, args);
  return emitRequest(session, {
    method: "DELETE",
    path: pathFor(MODELS_PATH, requiredPosition(args, "model")),
    query: [],
  });
}

async function resolveOfferingModel(session: CatalogSession, offeringId: string): Promise<string> {
  const modelResponse = await send(session, { method: "GET", path: MODELS_PATH, query: [] });
  const models = listBody(modelResponse.body).map(objectValue);
  for (const model of models) {
    const modelId = stringValue(model.id);
    if (modelId === undefined) continue;
    if (
      arrayValue(model.offerings).some(
        (offering) => stringValue(objectValue(offering).id) === offeringId,
      )
    ) {
      return modelId;
    }
    const offeringsResponse = await send(session, {
      method: "GET",
      path: pathFor(MODELS_PATH, modelId, OFFERINGS_SUFFIX),
      query: [],
    });
    if (
      listBody(offeringsResponse.body).some(
        (offering) => stringValue(objectValue(offering).id) === offeringId,
      )
    ) {
      return modelId;
    }
  }
  throw CliError.usage(`could not find offering '${offeringId}' through the Admin API`);
}

async function offeringTarget(
  session: CatalogSession,
  args: Args,
  noun: string,
): Promise<{ readonly modelId: string; readonly offeringId: string }> {
  exactPositionCount(args, 2, noun);
  const first = requiredPosition(args, noun);
  const second = args.positionals[1];
  if (second !== undefined && second.trim() !== "") return { modelId: first, offeringId: second };
  return { modelId: await resolveOfferingModel(session, first), offeringId: first };
}

async function offeringList(runtime: CliRuntime, args: Args): Promise<number> {
  exactPositionCount(args, 1, "model offering list");
  const session = await openSession(runtime, args);
  return emitRequest(session, {
    method: "GET",
    path: pathFor(MODELS_PATH, requiredPosition(args, "model"), OFFERINGS_SUFFIX),
    query: [],
  });
}

async function offeringAdd(runtime: CliRuntime, args: Args): Promise<number> {
  exactPositionCount(args, 1, "model offering add");
  const body = offeringBody(args, true);
  const session = await openSession(runtime, args);
  return emitRequest(session, {
    method: "POST",
    path: pathFor(MODELS_PATH, requiredPosition(args, "model"), OFFERINGS_SUFFIX),
    query: [],
    body,
  });
}

async function offeringShow(runtime: CliRuntime, args: Args): Promise<number> {
  const session = await openSession(runtime, args);
  const target = await offeringTarget(session, args, "model offering show");
  return emitRequest(session, {
    method: "GET",
    path: pathFor(MODELS_PATH, target.modelId, OFFERINGS_SUFFIX, target.offeringId),
    query: [],
  });
}

async function offeringUpdate(runtime: CliRuntime, args: Args): Promise<number> {
  const body = offeringBody(args, false);
  if (Object.keys(body).length === 0)
    throw CliError.usage("model offering update requires at least one field");
  const session = await openSession(runtime, args);
  const target = await offeringTarget(session, args, "model offering update");
  return emitRequest(session, {
    method: "PATCH",
    path: pathFor(MODELS_PATH, target.modelId, OFFERINGS_SUFFIX, target.offeringId),
    query: [],
    body,
  });
}

async function offeringRemove(runtime: CliRuntime, args: Args): Promise<number> {
  const session = await openSession(runtime, args);
  const target = await offeringTarget(session, args, "model offering rm");
  return emitRequest(session, {
    method: "DELETE",
    path: pathFor(MODELS_PATH, target.modelId, OFFERINGS_SUFFIX, target.offeringId),
    query: [],
  });
}

function envArray(runtime: CliRuntime, variable: string): Record<string, JsonValue>[] {
  const raw = runtime.io.env[variable];
  if (raw === undefined || raw.trim() === "") return [];
  let decoded: JsonValue;
  try {
    decoded = JSON.parse(raw) as JsonValue;
  } catch (error) {
    throw CliError.usage(
      `${variable} must be a JSON array: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!Array.isArray(decoded)) throw CliError.usage(`${variable} must be a JSON array`);
  return decoded.map((item) => objectValue(item));
}

function copyString(
  source: Record<string, JsonValue>,
  target: Record<string, JsonValue>,
  from: string,
  to = from,
): void {
  const value = source[from];
  if (value !== undefined && typeof value === "string") target[to] = value;
}

function copyNumber(
  source: Record<string, JsonValue>,
  target: Record<string, JsonValue>,
  from: string,
  to = from,
): void {
  const value = source[from];
  if (value !== undefined && typeof value === "number") target[to] = value;
}

function copyBoolean(
  source: Record<string, JsonValue>,
  target: Record<string, JsonValue>,
  from: string,
  to = from,
): void {
  const value = source[from];
  if (value !== undefined && typeof value === "boolean") target[to] = value;
}

function importProviderBody(source: Record<string, JsonValue>): Record<string, JsonValue> {
  const body: Record<string, JsonValue> = {};
  const name = stringValue(source.name);
  if (name !== undefined) {
    body.id = name;
    body.name = name;
  }
  copyString(source, body, "kind");
  copyString(source, body, "base_url");
  const apiKeyVar = stringValue(source.api_key_var);
  if (apiKeyVar !== undefined) {
    rejectCredentialShaped(apiKeyVar);
    body.api_key_var = apiKeyVar;
  }
  copyString(source, body, "byok_alias");
  copyString(source, body, "auth_scheme");
  copyString(source, body, "region");
  copyBoolean(source, body, "zero_data_retention");
  copyString(source, body, "openrouter_http_referer");
  copyString(source, body, "openrouter_x_title");
  if (source.cloudflare_ai_gateway !== undefined)
    body.cloudflare_ai_gateway = source.cloudflare_ai_gateway;
  copyBoolean(source, body, "enabled");
  return body;
}

function importModelBody(source: Record<string, JsonValue>): Record<string, JsonValue> {
  const body: Record<string, JsonValue> = {};
  const name = stringValue(source.name);
  if (name !== undefined) {
    body.id = name;
    body.name = name;
  }
  copyString(source, body, "family");
  copyString(source, body, "owned_by");
  copyNumber(source, body, "context_window");
  if (Array.isArray(source.capabilities)) body.capabilities = source.capabilities;
  copyString(source, body, "routing_strategy");
  copyBoolean(source, body, "enabled");
  return body;
}

const ROUTE_FIELDS: readonly (readonly [string, string])[] = [
  ["capabilities", "capabilities"],
  ["context_window", "context_window"],
  ["region", "region"],
  ["zero_data_retention", "zero_data_retention"],
  ["input_price_per_1m", "input_price_per_1m"],
  ["output_price_per_1m", "output_price_per_1m"],
  ["cached_input_price_per_1m", "cached_input_price_per_1m"],
  ["cache_write_price_per_1m", "cache_write_price_per_1m"],
  ["reasoning_price_per_1m", "reasoning_price_per_1m"],
  ["audio_second_price_per_1m", "audio_second_price_per_1m"],
  ["audio_character_price_per_1m", "audio_character_price_per_1m"],
];

function routeOffering(
  model: Record<string, JsonValue>,
  route: Record<string, JsonValue>,
  role: string,
  index: number,
  providerIds: ReadonlyMap<string, string>,
  modelId: string,
): Record<string, JsonValue> {
  const body: Record<string, JsonValue> = {
    id: `${modelId}--${role}--${index}`,
    role,
    source: "env",
  };
  const providerName = stringValue(route.provider) ?? stringValue(model.provider);
  const providerId =
    providerName === undefined ? undefined : (providerIds.get(providerName) ?? providerName);
  if (providerId !== undefined) body.provider_id = providerId;
  const upstream = stringValue(route.provider_model) ?? stringValue(model.provider_model);
  if (upstream !== undefined) body.upstream_model_id = upstream;
  for (const [from, to] of ROUTE_FIELDS) {
    if (route[from] !== undefined) body[to] = route[from] as JsonValue;
    else if (model[from] !== undefined) body[to] = model[from] as JsonValue;
  }
  return body;
}

function importedOfferings(
  model: Record<string, JsonValue>,
  providerIds: ReadonlyMap<string, string>,
  modelId: string,
): Record<string, JsonValue>[] {
  const offerings: Record<string, JsonValue>[] = [];
  const primary = routeOffering(model, model, "primary", 0, providerIds, modelId);
  if (primary.provider_id !== undefined || primary.upstream_model_id !== undefined)
    offerings.push(primary);
  for (const [index, value] of arrayValue(model.fallbacks).entries()) {
    const route = objectValue(value);
    offerings.push(routeOffering(model, route, "fallback", index, providerIds, modelId));
  }
  const canary = objectValue(model.canary);
  if (Object.keys(canary).length > 0) {
    const offering = routeOffering(model, canary, "canary", 0, providerIds, modelId);
    if (canary.percent !== undefined) offering.canary_percent = canary.percent;
    offerings.push(offering);
  }
  const shadow = objectValue(model.shadow);
  if (Object.keys(shadow).length > 0) {
    const offering = routeOffering(model, shadow, "shadow", 0, providerIds, modelId);
    if (shadow.sample_percent !== undefined) offering.shadow_percent = shadow.sample_percent;
    if (shadow.max_requests !== undefined) offering.shadow_max_requests = shadow.max_requests;
    offerings.push(offering);
  }
  return offerings;
}

function sameIdentity(
  existing: Record<string, JsonValue>,
  desired: Record<string, JsonValue>,
): boolean {
  const desiredId = stringValue(desired.id);
  const desiredName = stringValue(desired.name);
  return (
    (desiredId !== undefined && stringValue(existing.id) === desiredId) ||
    (desiredName !== undefined &&
      (stringValue(existing.id) === desiredName || stringValue(existing.name) === desiredName))
  );
}

function providerIdFor(source: Record<string, JsonValue>, fallback: string): string {
  return stringValue(source.id) ?? stringValue(source.name) ?? fallback;
}

async function providerImport(runtime: CliRuntime, args: Args): Promise<number> {
  if (!args.getBoolean("from-env")) throw CliError.usage("provider import requires --from-env");
  const providerRows = envArray(runtime, "GATEWAY_PROVIDERS");
  const modelRows = envArray(runtime, "GATEWAY_MODELS");
  const providerBodies = providerRows.map(importProviderBody);
  const modelPlans = modelRows.map((source) => ({ source, body: importModelBody(source) }));

  // The complete input is checked before the first list request, so a bad
  // binding cannot leave a partially imported catalog behind.
  for (const body of providerBodies) {
    const apiKeyVar = stringValue(body.api_key_var);
    if (apiKeyVar !== undefined) rejectCredentialShaped(apiKeyVar);
  }

  const session = await openSession(runtime, args);
  const existingProviders = listBody(
    (await send(session, { method: "GET", path: PROVIDERS_PATH, query: [] })).body,
  ).map(objectValue);
  const providerIds = new Map<string, string>();
  let providersCreated = 0;
  let providersExisting = 0;
  for (const [index, desired] of providerBodies.entries()) {
    const name = stringValue(desired.name);
    const existing = existingProviders.find((candidate) => sameIdentity(candidate, desired));
    let providerId = existing === undefined ? undefined : stringValue(existing.id);
    if (existing === undefined) {
      const created = await send(session, {
        method: "POST",
        path: PROVIDERS_PATH,
        query: [],
        body: desired,
      });
      providerId =
        stringValue(itemBody(created.body, "provider").id) ?? providerIdFor(desired, String(index));
      providersCreated += 1;
    } else {
      providersExisting += 1;
    }
    if (name !== undefined) providerIds.set(name, providerId ?? name);
  }

  const existingModels = listBody(
    (await send(session, { method: "GET", path: MODELS_PATH, query: [] })).body,
  ).map(objectValue);
  let modelsCreated = 0;
  let modelsExisting = 0;
  let offeringsCreated = 0;
  let offeringsExisting = 0;
  for (const plan of modelPlans) {
    const desired = plan.body;
    const existing = existingModels.find((candidate) => sameIdentity(candidate, desired));
    let modelId = existing === undefined ? undefined : stringValue(existing.id);
    let modelRecord = existing;
    if (existing === undefined) {
      const created = await send(session, {
        method: "POST",
        path: MODELS_PATH,
        query: [],
        body: desired,
      });
      modelRecord = itemBody(created.body, "model");
      modelId = stringValue(modelRecord.id) ?? providerIdFor(desired, "model");
      modelsCreated += 1;
    } else {
      modelsExisting += 1;
    }
    if (modelId === undefined) continue;

    const desiredOfferings = importedOfferings(plan.source, providerIds, modelId);
    const existingOfferings =
      modelRecord?.offerings === undefined
        ? listBody(
            (
              await send(session, {
                method: "GET",
                path: pathFor(MODELS_PATH, modelId, OFFERINGS_SUFFIX),
                query: [],
              })
            ).body,
          ).map(objectValue)
        : arrayValue(modelRecord.offerings).map(objectValue);
    for (const offering of desiredOfferings) {
      const alreadyExists = existingOfferings.some(
        (candidate) =>
          stringValue(candidate.id) === stringValue(offering.id) ||
          (stringValue(candidate.provider_id) === stringValue(offering.provider_id) &&
            stringValue(candidate.upstream_model_id) === stringValue(offering.upstream_model_id) &&
            stringValue(candidate.role) === stringValue(offering.role)),
      );
      if (alreadyExists) {
        offeringsExisting += 1;
        continue;
      }
      await send(session, {
        method: "POST",
        path: pathFor(MODELS_PATH, modelId, OFFERINGS_SUFFIX),
        query: [],
        body: offering,
      });
      offeringsCreated += 1;
    }
  }

  emit(session, {
    object: "catalog_import",
    providers: { created: providersCreated, existing: providersExisting },
    models: { created: modelsCreated, existing: modelsExisting },
    offerings: { created: offeringsCreated, existing: offeringsExisting },
  });
  return 0;
}

type CatalogAction = (runtime: CliRuntime, args: Args) => Promise<number>;

function guarded(action: CatalogAction): CatalogAction {
  return async (runtime, args) => {
    try {
      return await action(runtime, args);
    } catch (error) {
      const cliError = asCliError(error);
      reportError(runtime.io, cliError, CATALOG_SECRET_FIELDS);
      return cliError.exitCode();
    }
  };
}

function leaf(init: {
  readonly name: string;
  readonly about: string;
  readonly positionals?: readonly string[];
  readonly flags?: readonly FlagSpec[];
  readonly run: CatalogAction;
  readonly aliases?: readonly string[];
}): CommandNode {
  return {
    name: init.name,
    about: init.about,
    ...(init.aliases === undefined ? {} : { aliases: init.aliases }),
    ...(init.positionals === undefined ? {} : { positionals: init.positionals }),
    flags: catalogFlags(init.flags),
    run: guarded(init.run),
  };
}

export const providerCommand: CommandNode = {
  name: "provider",
  about: "Manage provider channels through the Admin API",
  sub: [
    leaf({ name: "list", about: "List provider channels", run: providerList }),
    leaf({
      name: "add",
      about: "Create a provider channel",
      flags: PROVIDER_FIELD_FLAGS,
      run: providerAdd,
    }),
    leaf({
      name: "show",
      about: "Show a provider channel",
      positionals: ["<name>"],
      run: providerShow,
    }),
    leaf({
      name: "update",
      about: "Patch a provider channel",
      positionals: ["<name>"],
      flags: PROVIDER_FIELD_FLAGS,
      run: providerUpdate,
    }),
    leaf({
      name: "rm",
      about: "Delete a provider channel",
      positionals: ["<name>"],
      run: providerRemove,
    }),
    leaf({
      name: "import",
      about: "Import provider and model catalog rows from gateway environment JSON",
      flags: [
        { name: "from-env", kind: "boolean", help: "Read GATEWAY_PROVIDERS and GATEWAY_MODELS" },
      ],
      run: providerImport,
    }),
  ],
};

export const modelCommand: CommandNode = {
  name: "model",
  about: "Manage logical models and provider offerings through the Admin API",
  sub: [
    leaf({ name: "list", about: "List logical models", run: modelList }),
    leaf({ name: "add", about: "Create a logical model", flags: MODEL_FIELD_FLAGS, run: modelAdd }),
    leaf({
      name: "show",
      about: "Show a logical model and every offering price",
      positionals: ["<name>"],
      run: modelShow,
    }),
    leaf({
      name: "update",
      about: "Patch a logical model",
      positionals: ["<name>"],
      flags: MODEL_FIELD_FLAGS,
      run: modelUpdate,
    }),
    leaf({
      name: "rm",
      about: "Delete a logical model",
      positionals: ["<name>"],
      run: modelRemove,
    }),
    {
      name: "offering",
      about: "Manage offerings attached to a logical model",
      sub: [
        leaf({
          name: "add",
          about: "Attach an offering to a model",
          positionals: ["<model>"],
          flags: OFFERING_FIELD_FLAGS,
          run: offeringAdd,
        }),
        leaf({
          name: "list",
          aliases: ["ls"],
          about: "List a model's offerings",
          positionals: ["<model>"],
          run: offeringList,
        }),
        leaf({
          name: "show",
          about: "Show an offering",
          positionals: ["<model> [offering]"],
          run: offeringShow,
        }),
        leaf({
          name: "update",
          about: "Patch an offering",
          positionals: ["<model> [offering]"],
          flags: OFFERING_FIELD_FLAGS,
          run: offeringUpdate,
        }),
        leaf({
          name: "rm",
          about: "Delete an offering",
          positionals: ["<model> [offering]"],
          run: offeringRemove,
        }),
      ],
    },
  ],
};
