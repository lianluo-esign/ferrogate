/**
 * The OPERATOR surface for the durable MCP upstream catalog.
 *
 * ## What this closes
 *
 * `src/durable.ts`'s `loadServerCatalog` carried
 * `PORT_TODO(inventory-edge-control §MCP "server catalog")`: the reader, the
 * decoder, `resolveUpstreams` and the `MCP_SESSION` Durable Object were all
 * implemented, mounted and green — against `mcp_servers` rows the TESTS insert,
 * because **nothing in this repo wrote one**. A deployed tenant therefore read
 * an empty catalog forever and the MCP tool plane served zero upstream tools.
 * That is this repo's recurring defect class one level up: the code is mounted,
 * the DATA path into it is not.
 *
 * The operator surface that ought to feed it already existed and already writes
 * into the database this Worker already binds as `env.DB`:
 * `apps/control-plane`'s `admin_mcp_server` group (`GET/POST/PUT/PATCH/DELETE
 * /admin/v1/mcp-servers`, `routes/admin_mcp_server.ts`) stores each server as a
 * `control_plane_resources` document of kind `mcp-servers` in the CONTROL
 * database. So the catalog was reachable from here all along and the reader was
 * missing — exactly the shape `src/approvals.ts` closed for the approval queue,
 * and closed the same way: no new binding, no new service, one more read of a
 * table this Worker is already talking to.
 *
 * ## The four decisions the marker said had to be made deliberately
 *
 * 1. **SCOPE — tenant-scoped documents ONLY.** The SQL filters
 *    `json_extract(document_json, '$.tenant_id') = ?` against the AUTHENTICATED
 *    tenant, as a bound parameter. A document with a null/absent `tenant_id` is
 *    PLATFORM-scoped in the admin model, and serving those to every tenant would
 *    hand every tenant an upstream by default — so they are served to NOBODY
 *    here. Deny-by-default: a platform-wide upstream is a product feature that
 *    has to be asked for, not a side effect of a null column.
 * 2. **VOCABULARY — `http` is mapped EXPLICITLY, `stdio` is never coerced.**
 *    The admin schema's enum is `http | sse | stdio`; this app's `McpTransport`
 *    is `streamable_http | sse | stdio`. Both `http` and `streamable_http` mean
 *    "MCP over network HTTP", so `http` maps to `streamable_http` by an explicit
 *    table entry, never by a `?? "streamable_http"` default. Anything not in
 *    {@link ADMIN_TRANSPORTS} REFUSES the document. `stdio` stays decodable and
 *    is refused at DISPATCH by `transport.ts` — the platform limit is that
 *    Workers cannot spawn a process, and the honest place to report it is the
 *    call, not the config (see the kept marker there).
 * 3. **ALLOWLISTS — absent means EMPTY, never "all tools".** `tools_to_execute`
 *    and `tools_to_auto_execute` are deny-by-default in Rust
 *    (`#[serde(default)] Vec<String>`), and an operator who forgets the field
 *    must get a server that lists nothing, not one that exposes everything.
 * 4. **UNKNOWN ENUM VALUES REFUSE THE ROW.** Same rule as
 *    `decodeServerRow`: an unrecognized `auth_type` is not downgraded to
 *    `none` (that would strip an upstream's identity requirement) and an
 *    unrecognized `transport` is not read as HTTP (that would send a local
 *    process server's traffic over the network).
 *
 * ## Failure direction
 *
 * Every failure here REMOVES an upstream and none adds one: an undecodable
 * document is skipped, a database this reader cannot query yields no documents,
 * and a name already held by a typed `mcp_servers` row is left alone. So the
 * worst case is the pre-existing empty catalog, which denies — never a widened
 * one.
 */
import { RESOURCE_TABLE } from "./approvals.js";
import type { McpAuthType, McpOauthConfig, McpServerConfig, McpTransport } from "./ports.js";

/** The `control_plane_resources.resource_kind` `routes/admin_mcp_server.ts` writes. */
export const MCP_SERVER_COLLECTION = "mcp-servers";

/**
 * Rust `default_timeout_ms()` (`crates/ferrogate-mcp/src/config.rs`).
 *
 * The admin document does not have to carry one; a missing timeout must be the
 * reference default rather than `0` (which would abort every dispatch) or
 * `Infinity` (which would hold an isolate open until the platform kills it).
 */
export const DEFAULT_UPSTREAM_TIMEOUT_MS = 30_000;

/**
 * Admin transport vocabulary → this app's {@link McpTransport}.
 *
 * An explicit total map, not a fallback: a value absent from it REFUSES the
 * document. `http` and `streamable_http` are the same wire protocol under two
 * names (the control plane's schema calls it `http`), and `stdio` is carried
 * through unchanged so the platform limit is reported at dispatch.
 */
export const ADMIN_TRANSPORTS: Readonly<Record<string, McpTransport>> = {
  http: "streamable_http",
  streamable_http: "streamable_http",
  sse: "sse",
  stdio: "stdio",
};

/**
 * Auth modes an admin document may name.
 *
 * `headers` is accepted as an alias of `shared_headers` because Rust's
 * `McpAuthType` declares exactly that alias (`#[serde(alias = "headers")]`), so
 * a config an operator could write against the Rust gateway keeps working. It
 * is an alias in a TOTAL map, not a permissive fallback.
 */
export const ADMIN_AUTH_TYPES: Readonly<Record<string, McpAuthType>> = {
  none: "none",
  headers: "shared_headers",
  shared_headers: "shared_headers",
  oauth: "oauth",
  per_user_oauth: "per_user_oauth",
  per_user_headers: "per_user_headers",
  original_bearer: "original_bearer",
  ferrogate_signed_jwt: "ferrogate_signed_jwt",
};

type Document = Record<string, unknown>;

function isObject(value: unknown): value is Document {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * A deny-by-default string allowlist.
 *
 * Absent/null ⇒ `[]`. A non-array, or an array holding anything that is not a
 * string, is a REFUSAL (`undefined`) rather than a filtered-down list: silently
 * dropping the malformed entries of an allowlist changes what it permits.
 */
function readAllowlist(value: unknown): string[] | undefined {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return undefined;
  const out: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") return undefined;
    out.push(entry);
  }
  return out;
}

/** Static headers. Refuses a non-string value rather than stringifying it. */
function readHeaders(value: unknown): Record<string, string> | undefined | null {
  if (value === undefined || value === null) return undefined;
  if (!isObject(value)) return null;
  const out: Record<string, string> = {};
  for (const [name, entry] of Object.entries(value)) {
    if (typeof entry !== "string") return null;
    out[name] = entry;
  }
  return out;
}

/**
 * OAuth block. Requires the two fields that make a grant addressable at all
 * (`issuer`, `client_id`); anything less is a refusal, because a half-configured
 * per-user upstream that decodes would advertise tools nobody can ever call.
 */
function readOauth(value: unknown): McpOauthConfig | undefined | null {
  if (value === undefined || value === null) return undefined;
  if (!isObject(value)) return null;
  const issuer = value.issuer ?? value.iss;
  const clientId = value.client_id ?? value.clientId;
  if (typeof issuer !== "string" || issuer === "") return null;
  if (typeof clientId !== "string" || clientId === "") return null;
  const scopes = readAllowlist(value.scopes ?? value.scope);
  if (scopes === undefined) return null;
  const config: McpOauthConfig = {
    issuer,
    clientId,
    // Rust `default_oauth_scopes()`.
    scopes: scopes.length === 0 ? ["openid", "profile", "email"] : scopes,
  };
  const secretRef = value.client_secret_ref ?? value.clientSecretRef;
  if (typeof secretRef === "string" && secretRef !== "") config.clientSecretRef = secretRef;
  const redirect = value.redirect_uri ?? value.redirectUri;
  if (typeof redirect === "string" && redirect !== "") config.redirectUri = redirect;
  if (typeof value.audience === "string" && value.audience !== "") {
    config.audience = value.audience;
  }
  return config;
}

/**
 * Decode ONE `/admin/v1/mcp-servers` document into an upstream config.
 *
 * `undefined` means "this document is not an upstream", and every path that
 * returns it is a refusal that shrinks the catalog. The caller skips the
 * document; it never substitutes a default server.
 *
 * `enabled: false` is a refusal too — an operator who disables a server in the
 * admin API must stop seeing its tools, and leaving it in the catalog would make
 * the toggle decorative.
 */
export function decodeServerDocument(document: unknown): McpServerConfig | undefined {
  if (!isObject(document)) return undefined;
  const name = document.name ?? document.id;
  if (typeof name !== "string" || name.trim() === "") return undefined;
  if (document.enabled === false) return undefined;

  const rawTransport = document.transport;
  if (typeof rawTransport !== "string") return undefined;
  const transport = ADMIN_TRANSPORTS[rawTransport];
  if (transport === undefined) return undefined;

  const rawAuth = document.auth_type ?? document.authType ?? "none";
  if (typeof rawAuth !== "string") return undefined;
  const authType = ADMIN_AUTH_TYPES[rawAuth];
  if (authType === undefined) return undefined;

  const toolsToExecute = readAllowlist(document.tools_to_execute ?? document.toolsToExecute);
  if (toolsToExecute === undefined) return undefined;
  const toolsToAutoExecute = readAllowlist(
    document.tools_to_auto_execute ?? document.toolsToAutoExecute,
  );
  if (toolsToAutoExecute === undefined) return undefined;

  const headers = readHeaders(document.headers);
  if (headers === null) return undefined;
  const oauth = readOauth(document.oauth);
  if (oauth === null) return undefined;

  const rawTimeout = document.timeout_ms ?? document.timeoutMs;
  let timeoutMs = DEFAULT_UPSTREAM_TIMEOUT_MS;
  if (rawTimeout !== undefined && rawTimeout !== null) {
    if (typeof rawTimeout !== "number" || !Number.isFinite(rawTimeout) || rawTimeout <= 0) {
      return undefined;
    }
    timeoutMs = Math.floor(rawTimeout);
  }

  const config: McpServerConfig = {
    name: name.trim(),
    transport,
    authType,
    toolsToExecute,
    toolsToAutoExecute,
    timeoutMs,
  };
  if (typeof document.url === "string" && document.url !== "") config.url = document.url;
  if (headers !== undefined) config.headers = headers;
  if (oauth !== undefined) config.oauth = oauth;
  const audience = document.signed_jwt_audience ?? document.signedJwtAudience;
  if (typeof audience === "string" && audience !== "") config.signedJwtAudience = audience;
  return config;
}

/**
 * Read one tenant's `/admin/v1/mcp-servers` documents out of the CONTROL
 * database and decode them into upstream configs.
 *
 * The tenant filter is a BOUND parameter against the authenticated tenant, so a
 * caller can never widen it, and a document naming no tenant is not returned to
 * anyone (decision 1 above).
 *
 * A read failure yields `[]` rather than throwing. That is not a swallowed
 * error in the dangerous direction: the ONLY effect of returning nothing is
 * fewer upstreams, i.e. the fail-closed empty catalog this app already had
 * before the reader existed. Throwing would instead take down `tools/list` for
 * a tenant whose typed rows are perfectly readable.
 */
export async function loadAdminServerCatalog(
  db: D1Database,
  tenantId: string,
): Promise<McpServerConfig[]> {
  let rows: { results: Array<{ document_json: string }> };
  try {
    rows = await db
      .prepare(
        `SELECT document_json FROM ${RESOURCE_TABLE}
           WHERE resource_kind = ?
             AND json_extract(document_json, '$.tenant_id') = ?
           ORDER BY resource_id`,
      )
      .bind(MCP_SERVER_COLLECTION, tenantId)
      .all<{ document_json: string }>();
  } catch (error) {
    console.warn("mcp: admin server catalog unreadable; serving typed rows only", error);
    return [];
  }
  const configs: McpServerConfig[] = [];
  for (const row of rows.results) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(row.document_json);
    } catch {
      continue;
    }
    const config = decodeServerDocument(parsed);
    if (config !== undefined) configs.push(config);
  }
  return configs;
}
