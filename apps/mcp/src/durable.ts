/**
 * The DURABLE half of `src/ports.ts` — the implementations that survive an
 * isolate recycle.
 *
 * `InMemoryCredentialStore` is a dev convenience with a security-relevant
 * defect the Rust store does not have: a grant the operator REVOKED comes back
 * when the isolate recycles, and an OAuth callback redirected to a different
 * isolate than the one that started the flow is refused. This module closes
 * both by putting the same data where the Rust `McpCredentialRepository` put it
 * — durable storage — translated Postgres→D1/KV per PORT-PLAN.md.
 *
 * Ported from `crates/ferrogate-gateway/src/state_mcp_identity.rs` (the
 * `mcp_oauth_flows` / `mcp_oauth_credentials` repository) and
 * `crates/ferrogate-mcp/src/config.rs` (the upstream server catalog).
 *
 * Division of labour, and why:
 *
 *  - **Flows → a Durable Object** (`MCP_OAUTH_FLOWS`, `src/oauth-flow.ts`).
 *    The flow record must be time-bounded AND claimed exactly once, and the
 *    single-use half is an ATOMIC claim that only a single-threaded actor can
 *    give. {@link KvOauthFlowStore} below is the KV fallback for a deployment
 *    that binds the namespace but not the DO; it is retained (and still
 *    tested) but is no longer what `resolvePorts` prefers, precisely because
 *    KV has no compare-and-swap.
 *  - **Grants + generations + the server catalog → `TenantDataObject`**. The
 *    object is addressed by the authenticated tenant and supplies the same
 *    SQLite transaction semantics without a flat identity database or an
 *    isolate-local schema cache.
 */
import { DurableObjectD1Database } from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import { loadAdminServerCatalog } from "./catalog.js";
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import {
  type IdentityCipherPort,
  type McpCredentialStorePort,
  type McpIdentityActor,
  type McpServerConfig,
  type McpTransport,
  type McpAuthType,
  type McpOauthConfig,
  type StoredMcpOauthCredential,
  type StoredMcpOauthFlow,
  credentialId,
  webCryptoIdentityCipher,
} from "./ports.js";

// ---------------------------------------------------------------------------
// Tenant object database
// ---------------------------------------------------------------------------

/** Resolve exactly one tenant object; schema application happens in its ledger. */
function tenantDatabase(namespace: TenantDataNamespace, tenantId: string): D1Database {
  if (typeof tenantId !== "string" || tenantId.trim() === "") {
    throw new Error("MCP tenant storage requires a non-empty tenant id");
  }
  return new DurableObjectD1Database(
    tenantId,
    namespace.get(namespace.idFromName(tenantId)),
  ).asD1Database();
}

// ---------------------------------------------------------------------------
// Byte <-> text codecs
// ---------------------------------------------------------------------------

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(text: string): Uint8Array {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

// ---------------------------------------------------------------------------
// Flow half — Workers KV
// ---------------------------------------------------------------------------

/** KV key prefix. Namespaced so the binding can be shared without collision. */
export const OAUTH_FLOW_KEY_PREFIX = "mcp:oauth-flow:";

/**
 * KV's minimum accepted `expirationTtl`. A flow shorter-lived than this still
 * expires on time — {@link KvOauthFlowStore.consumeOauthFlow} enforces the
 * bound in code and the TTL is only the garbage collector — but KV rejects the
 * write outright below 60, so the floor is applied to the TTL, never to
 * `expiresAtUnix`.
 */
export const KV_MIN_EXPIRATION_TTL_SECS = 60;

interface EncodedFlow {
  id: string;
  actor: McpIdentityActor;
  serverName: string;
  pkceNonce: string;
  pkceCiphertext: string;
  oidcNonce: string;
  authorizationGeneration: number;
  createdAtUnix: number;
  expiresAtUnix: number;
}

export function encodeFlow(flow: StoredMcpOauthFlow): string {
  const encoded: EncodedFlow = {
    id: flow.id,
    actor: flow.actor,
    serverName: flow.serverName,
    pkceNonce: toBase64(flow.pkceNonce),
    pkceCiphertext: toBase64(flow.pkceCiphertext),
    oidcNonce: flow.oidcNonce,
    authorizationGeneration: flow.authorizationGeneration,
    createdAtUnix: flow.createdAtUnix,
    expiresAtUnix: flow.expiresAtUnix,
  };
  return JSON.stringify(encoded);
}

export function decodeFlow(raw: string): StoredMcpOauthFlow {
  const encoded = JSON.parse(raw) as EncodedFlow;
  return {
    id: encoded.id,
    actor: encoded.actor,
    serverName: encoded.serverName,
    pkceNonce: fromBase64(encoded.pkceNonce),
    pkceCiphertext: fromBase64(encoded.pkceCiphertext),
    oidcNonce: encoded.oidcNonce,
    authorizationGeneration: encoded.authorizationGeneration,
    createdAtUnix: encoded.createdAtUnix,
    expiresAtUnix: encoded.expiresAtUnix,
  };
}

/**
 * The in-flight OAuth authorization store, over Workers KV.
 *
 * The anonymous `GET /v1/mcp/identity/callback` has NO FerroGate credential;
 * its entire authorization is this record being single-use, time-bounded, and
 * keyed by the sha256 of a state the browser holds. Both properties are
 * enforced here:
 *
 *  - **time-bounded** — checked against `expiresAtUnix` on read (authoritative,
 *    and independent of KV's TTL granularity), with `expirationTtl` set so an
 *    unconsumed record is also reaped rather than accumulating.
 *  - **single-use** — the key is DELETED as part of the consume, so a replay
 *    finds nothing.
 *
 * ## This class is the FALLBACK, not the bound path
 *
 * Workers KV exposes no compare-and-swap and no conditional write, so the
 * `get` + `delete` below is NOT one atomic claim the way the Rust store's
 * `UPDATE mcp_oauth_flows SET consumed_at = now WHERE consumed_at IS NULL
 * RETURNING *` is: two callbacks arriving with the same `state` in the same
 * instant can both observe the record before either delete lands.
 *
 * That gap is now CLOSED by `src/oauth-flow.ts`
 * ({@link McpOauthFlowClaim} + `DurableOauthFlowStore`), a Durable Object
 * keyed by the state digest whose read+delete runs inside
 * `blockConcurrencyWhile` — an indivisible claim, which is what `resolvePorts`
 * binds whenever `MCP_OAUTH_FLOWS` is present. This KV implementation is kept
 * as the degraded path for a deployment that binds the namespace but not the
 * DO, and it still narrows the exposure the same way it always did: both
 * racers must already hold the state secret, the record still expires, and the
 * second commit is refused downstream by the `authorizationGeneration` guard
 * in {@link TenantObjectCredentialGrants}.
 */
export class KvOauthFlowStore {
  readonly #kv: KVNamespace;

  constructor(kv: KVNamespace) {
    this.#kv = kv;
  }

  async begin(flow: StoredMcpOauthFlow): Promise<void> {
    const lifetime = flow.expiresAtUnix - flow.createdAtUnix;
    await this.#kv.put(OAUTH_FLOW_KEY_PREFIX + flow.id, encodeFlow(flow), {
      expirationTtl: Math.max(KV_MIN_EXPIRATION_TTL_SECS, lifetime),
    });
  }

  async consume(stateId: string, nowUnix: number): Promise<StoredMcpOauthFlow | undefined> {
    const key = OAUTH_FLOW_KEY_PREFIX + stateId;
    const raw = await this.#kv.get(key, "text");
    if (raw === null) return undefined;
    let flow: StoredMcpOauthFlow;
    try {
      flow = decodeFlow(raw);
    } catch {
      // An undecodable record is not a usable authorization. Drop it rather
      // than leaving a poison key that fails every callback for its whole TTL.
      await this.#kv.delete(key);
      return undefined;
    }
    // Delete FIRST, so an expired record is also cleaned up and the consume is
    // as close to single-use as KV allows.
    await this.#kv.delete(key);
    if (flow.expiresAtUnix <= nowUnix) return undefined;
    return flow;
  }
}

// ---------------------------------------------------------------------------
// Grant half — TenantDataObject
// ---------------------------------------------------------------------------

interface CredentialRow {
  id: string;
  tenant_id: string;
  workspace_id: string;
  user_id: string;
  server_name: string;
  issuer: string;
  subject: string;
  token_type: string;
  scopes: string;
  access_token_nonce: string;
  access_token_ciphertext: string;
  refresh_token_nonce: string | null;
  refresh_token_ciphertext: string | null;
  expires_at_unix: number;
  key_version: number;
  version: number;
  authorization_generation: number;
  created_at_unix: number;
  updated_at_unix: number;
  revoked_at_unix: number | null;
  last_refresh_outcome: string | null;
  last_revocation_outcome: string | null;
}

function rowToCredential(row: CredentialRow): StoredMcpOauthCredential {
  const credential: StoredMcpOauthCredential = {
    id: row.id,
    actor: {
      tenantId: row.tenant_id,
      workspaceId: row.workspace_id,
      userId: row.user_id,
    },
    serverName: row.server_name,
    issuer: row.issuer,
    subject: row.subject,
    tokenType: row.token_type,
    scopes: JSON.parse(row.scopes) as string[],
    accessTokenNonce: fromBase64(row.access_token_nonce),
    accessTokenCiphertext: fromBase64(row.access_token_ciphertext),
    expiresAtUnix: row.expires_at_unix,
    keyVersion: row.key_version,
    version: row.version,
    authorizationGeneration: row.authorization_generation,
    createdAtUnix: row.created_at_unix,
    updatedAtUnix: row.updated_at_unix,
  };
  const optional: Partial<StoredMcpOauthCredential> = {};
  if (row.refresh_token_nonce !== null && row.refresh_token_ciphertext !== null) {
    optional.refreshTokenNonce = fromBase64(row.refresh_token_nonce);
    optional.refreshTokenCiphertext = fromBase64(row.refresh_token_ciphertext);
  }
  if (row.revoked_at_unix !== null) optional.revokedAtUnix = row.revoked_at_unix;
  if (row.last_refresh_outcome !== null) optional.lastRefreshOutcome = row.last_refresh_outcome;
  if (row.last_revocation_outcome !== null) {
    optional.lastRevocationOutcome = row.last_revocation_outcome;
  }
  return { ...credential, ...optional };
}

/** The 21 bound values an upsert writes, in column order. */
function credentialBindings(credential: StoredMcpOauthCredential): unknown[] {
  return [
    credential.id,
    credential.actor.tenantId,
    credential.actor.workspaceId,
    credential.actor.userId,
    credential.serverName,
    credential.issuer,
    credential.subject,
    credential.tokenType,
    JSON.stringify(credential.scopes),
    toBase64(credential.accessTokenNonce),
    toBase64(credential.accessTokenCiphertext),
    credential.refreshTokenNonce === undefined ? null : toBase64(credential.refreshTokenNonce),
    credential.refreshTokenCiphertext === undefined
      ? null
      : toBase64(credential.refreshTokenCiphertext),
    credential.expiresAtUnix,
    credential.keyVersion,
    credential.version,
    credential.authorizationGeneration,
    credential.createdAtUnix,
    credential.updatedAtUnix,
    credential.revokedAtUnix ?? null,
    credential.lastRefreshOutcome ?? null,
    credential.lastRevocationOutcome ?? null,
  ];
}

const UPSERT_SET = `
  issuer = excluded.issuer,
  subject = excluded.subject,
  token_type = excluded.token_type,
  scopes = excluded.scopes,
  access_token_nonce = excluded.access_token_nonce,
  access_token_ciphertext = excluded.access_token_ciphertext,
  refresh_token_nonce = excluded.refresh_token_nonce,
  refresh_token_ciphertext = excluded.refresh_token_ciphertext,
  expires_at_unix = excluded.expires_at_unix,
  key_version = excluded.key_version,
  version = excluded.version,
  authorization_generation = excluded.authorization_generation,
  updated_at_unix = excluded.updated_at_unix,
  revoked_at_unix = excluded.revoked_at_unix,
  last_refresh_outcome = excluded.last_refresh_outcome,
  last_revocation_outcome = excluded.last_revocation_outcome`;

const CREDENTIAL_COLUMNS = `id, tenant_id, workspace_id, user_id, server_name, issuer, subject,
  token_type, scopes, access_token_nonce, access_token_ciphertext, refresh_token_nonce,
  refresh_token_ciphertext, expires_at_unix, key_version, version, authorization_generation,
  created_at_unix, updated_at_unix, revoked_at_unix, last_refresh_outcome, last_revocation_outcome`;

const CREDENTIAL_PLACEHOLDERS = Array.from({ length: 22 }, () => "?").join(", ");

/** The per-user grant half of {@link McpCredentialStorePort}, over a tenant object. */
export class TenantObjectCredentialGrants {
  readonly #namespace: TenantDataNamespace;

  constructor(namespace: TenantDataNamespace) {
    this.#namespace = namespace;
  }

  async authorizationGeneration(actor: McpIdentityActor, serverName: string): Promise<number> {
    const db = tenantDatabase(this.#namespace, actor.tenantId);
    const row = await db
      .prepare(
        `SELECT generation FROM mcp_identity_generations
          WHERE tenant_id = ? AND workspace_id = ? AND user_id = ? AND server_name = ?`,
      )
      .bind(actor.tenantId, actor.workspaceId, actor.userId, serverName)
      .first<{ generation: number }>();
    return row?.generation ?? 0;
  }

  /** Record an access change. Port of the Rust generation bump. */
  async bumpGeneration(actor: McpIdentityActor, serverName: string): Promise<void> {
    const db = tenantDatabase(this.#namespace, actor.tenantId);
    await db
      .prepare(
        `INSERT INTO mcp_identity_generations
           (tenant_id, workspace_id, user_id, server_name, generation)
         VALUES (?, ?, ?, ?, 1)
         ON CONFLICT (tenant_id, workspace_id, user_id, server_name)
           DO UPDATE SET generation = generation + 1`,
      )
      .bind(actor.tenantId, actor.workspaceId, actor.userId, serverName)
      .run();
  }

  async get(
    actor: McpIdentityActor,
    serverName: string,
  ): Promise<StoredMcpOauthCredential | undefined> {
    const db = tenantDatabase(this.#namespace, actor.tenantId);
    const row = await db
      .prepare(
        `SELECT * FROM mcp_oauth_credentials
          WHERE tenant_id = ? AND workspace_id = ? AND user_id = ? AND server_name = ?`,
      )
      .bind(actor.tenantId, actor.workspaceId, actor.userId, serverName)
      .first<CredentialRow>();
    return row === null ? undefined : rowToCredential(row);
  }

  async put(credential: StoredMcpOauthCredential): Promise<void> {
    const db = tenantDatabase(this.#namespace, credential.actor.tenantId);
    await db
      .prepare(
        `INSERT INTO mcp_oauth_credentials (${CREDENTIAL_COLUMNS})
         VALUES (${CREDENTIAL_PLACEHOLDERS})
         ON CONFLICT (tenant_id, workspace_id, user_id, server_name) DO UPDATE SET ${UPSERT_SET}`,
      )
      .bind(...credentialBindings(credential))
      .run();
  }

  /**
   * Commit the callback grant IFF the actor's authorization generation has not
   * moved since the flow began.
   *
   * The guard is inside the same statement as the write — `INSERT … SELECT …
   * WHERE (SELECT generation …) = ?` — so a revocation landing between a
   * separate read and write cannot be overwritten. That is the D1 equivalent of
   * the Rust repository's single-transaction commit; `SELECT`-then-`INSERT` in
   * two round trips would NOT be, and is exactly the race the marker on
   * {@link KvOauthFlowStore} describes for the KV half.
   */
  async commit(
    flow: StoredMcpOauthFlow,
    credential: StoredMcpOauthCredential,
  ): Promise<boolean> {
    if (
      flow.serverName !== credential.serverName ||
      flow.actor.tenantId !== credential.actor.tenantId ||
      flow.actor.workspaceId !== credential.actor.workspaceId ||
      flow.actor.userId !== credential.actor.userId
    ) {
      return false;
    }
    const db = tenantDatabase(this.#namespace, flow.actor.tenantId);
    const result = await db
      .prepare(
        `INSERT INTO mcp_oauth_credentials (${CREDENTIAL_COLUMNS})
         SELECT ${CREDENTIAL_PLACEHOLDERS}
          WHERE (SELECT COALESCE(
                   (SELECT generation FROM mcp_identity_generations
                     WHERE tenant_id = ? AND workspace_id = ? AND user_id = ? AND server_name = ?),
                   0)) = ?
         ON CONFLICT (tenant_id, workspace_id, user_id, server_name) DO UPDATE SET ${UPSERT_SET}`,
      )
      .bind(
        ...credentialBindings(credential),
        flow.actor.tenantId,
        flow.actor.workspaceId,
        flow.actor.userId,
        flow.serverName,
        flow.authorizationGeneration,
      )
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  /**
   * Revoke, returning the revoked row — or `undefined` when there was nothing
   * to revoke OR it was ALREADY revoked. The `revoked_at_unix IS NULL` guard
   * lives in the `UPDATE`'s own `WHERE`, so a double revoke is naturally
   * idempotent and cannot rewrite the original revocation timestamp.
   */
  async revoke(
    actor: McpIdentityActor,
    serverName: string,
    nowUnix: number,
    outcome: string,
  ): Promise<StoredMcpOauthCredential | undefined> {
    const db = tenantDatabase(this.#namespace, actor.tenantId);
    const row = await db
      .prepare(
        `UPDATE mcp_oauth_credentials
            SET revoked_at_unix = ?, updated_at_unix = ?, last_revocation_outcome = ?
          WHERE tenant_id = ? AND workspace_id = ? AND user_id = ? AND server_name = ?
            AND revoked_at_unix IS NULL
        RETURNING *`,
      )
      .bind(nowUnix, nowUnix, outcome, actor.tenantId, actor.workspaceId, actor.userId, serverName)
      .first<CredentialRow>();
    return row === null ? undefined : rowToCredential(row);
  }

  async updateRevocationOutcome(
    actor: McpIdentityActor,
    serverName: string,
    outcome: string,
  ): Promise<void> {
    const db = tenantDatabase(this.#namespace, actor.tenantId);
    await db
      .prepare(
        `UPDATE mcp_oauth_credentials SET last_revocation_outcome = ?
          WHERE tenant_id = ? AND workspace_id = ? AND user_id = ? AND server_name = ?`,
      )
      .bind(outcome, actor.tenantId, actor.workspaceId, actor.userId, serverName)
      .run();
  }
}

/**
 * The two operations the flow half needs, whichever primitive provides them.
 *
 * Declared as an interface so {@link DurableCredentialStore} can be handed the
 * ATOMIC Durable-Object claim (`DurableOauthFlowStore`) or the degraded KV one
 * ({@link KvOauthFlowStore}) without knowing which — and so a future third
 * implementation cannot silently omit `consume`'s single-use contract.
 */
export interface OauthFlowStore {
  begin(flow: StoredMcpOauthFlow): Promise<void>;
  consume(stateId: string, nowUnix: number): Promise<StoredMcpOauthFlow | undefined>;
}

/**
 * The durable {@link McpCredentialStorePort}: TenantDataObject for grants, and for flows
 * whichever {@link OauthFlowStore} the deployment bound.
 *
 * This is the implementation `resolvePorts` binds when the Worker is NOT
 * running the dev bundle, and it is what makes a revoked grant STAY revoked
 * across an isolate recycle.
 *
 * `flows` is the SECOND positional argument and is optional only so the KV
 * fallback stays constructible; `resolvePorts` always passes the Durable-Object
 * claim when `MCP_OAUTH_FLOWS` is bound.
 */
export class DurableCredentialStore implements McpCredentialStorePort {
  readonly #flows: OauthFlowStore;
  readonly #grants: TenantObjectCredentialGrants;

  constructor(kv: KVNamespace, namespace: TenantDataNamespace, flows?: OauthFlowStore) {
    this.#flows = flows ?? new KvOauthFlowStore(kv);
    this.#grants = new TenantObjectCredentialGrants(namespace);
  }

  beginOauthFlow(flow: StoredMcpOauthFlow): Promise<void> {
    return this.#flows.begin(flow);
  }

  consumeOauthFlow(stateId: string, nowUnix: number): Promise<StoredMcpOauthFlow | undefined> {
    return this.#flows.consume(stateId, nowUnix);
  }

  commitOauthCallback(
    flow: StoredMcpOauthFlow,
    credential: StoredMcpOauthCredential,
  ): Promise<boolean> {
    return this.#grants.commit(flow, credential);
  }

  getCredential(
    actor: McpIdentityActor,
    serverName: string,
  ): Promise<StoredMcpOauthCredential | undefined> {
    return this.#grants.get(actor, serverName);
  }

  putCredential(credential: StoredMcpOauthCredential): Promise<void> {
    return this.#grants.put(credential);
  }

  revokeCredential(
    actor: McpIdentityActor,
    serverName: string,
    nowUnix: number,
    outcome: string,
  ): Promise<StoredMcpOauthCredential | undefined> {
    return this.#grants.revoke(actor, serverName, nowUnix, outcome);
  }

  updateRevocationOutcome(
    actor: McpIdentityActor,
    serverName: string,
    outcome: string,
  ): Promise<void> {
    return this.#grants.updateRevocationOutcome(actor, serverName, outcome);
  }

  authorizationGeneration(actor: McpIdentityActor, serverName: string): Promise<number> {
    return this.#grants.authorizationGeneration(actor, serverName);
  }

  /** Record an access change for the actor (the Rust generation bump). */
  bumpGeneration(actor: McpIdentityActor, serverName: string): Promise<void> {
    return this.#grants.bumpGeneration(actor, serverName);
  }
}

// ---------------------------------------------------------------------------
// Upstream server catalog — TenantDataObject
// ---------------------------------------------------------------------------

interface ServerRow {
  name: string;
  transport: string;
  url: string | null;
  auth_type: string;
  tools_to_execute: string;
  tools_to_auto_execute: string;
  /**
   * The #687 exclude list, as JSON. NULLABLE on purpose: this column was added
   * after `mcp_servers` shipped, so a row written before the migration reads
   * `null` and must decode to a server that excludes nothing.
   */
  tools_to_exclude?: string | null;
  headers: string | null;
  oauth: string | null;
  signed_jwt_audience: string | null;
  timeout_ms: number;
}

const TRANSPORTS: readonly McpTransport[] = ["streamable_http", "sse", "stdio"];
const AUTH_TYPES: readonly McpAuthType[] = [
  "none",
  "shared_headers",
  "oauth",
  "per_user_oauth",
  "per_user_headers",
  "original_bearer",
  "ferrogate_signed_jwt",
];

/**
 * Decode one catalog row.
 *
 * An unrecognized `transport` or `auth_type` is REFUSED (`undefined`), never
 * coerced to a default: silently downgrading an unknown auth mode to `none`
 * would strip a server's identity requirement, and silently reading an unknown
 * transport as `streamable_http` would send a stdio upstream's traffic over
 * the network. Rust's `serde` enum decoding fails the same way.
 */
export function decodeServerRow(row: ServerRow): McpServerConfig | undefined {
  if (!TRANSPORTS.includes(row.transport as McpTransport)) return undefined;
  if (!AUTH_TYPES.includes(row.auth_type as McpAuthType)) return undefined;
  // #687: the exclude list. `null`/absent is a database that predates the
  // column, which excludes nothing; anything that is not a JSON array OF
  // STRINGS REFUSES the row, because silently dropping a malformed entry of a
  // DENY list permits more than the operator wrote.
  const excluded = decodeExcludeColumn(row.tools_to_exclude);
  if (excluded === REFUSED) return undefined;
  const config: McpServerConfig = {
    name: row.name,
    transport: row.transport as McpTransport,
    authType: row.auth_type as McpAuthType,
    toolsToExecute: JSON.parse(row.tools_to_execute) as string[],
    toolsToAutoExecute: JSON.parse(row.tools_to_auto_execute) as string[],
    timeoutMs: row.timeout_ms,
  };
  const optional: Partial<McpServerConfig> = {};
  if (row.url !== null) optional.url = row.url;
  if (row.headers !== null) optional.headers = JSON.parse(row.headers) as Record<string, string>;
  if (row.oauth !== null) optional.oauth = JSON.parse(row.oauth) as McpOauthConfig;
  if (row.signed_jwt_audience !== null) optional.signedJwtAudience = row.signed_jwt_audience;
  if (excluded !== undefined) optional.toolsToExclude = excluded;
  return { ...config, ...optional };
}

/** Sentinel distinguishing "no exclude list" from "an exclude list I refuse". */
const REFUSED = Symbol("refused");

function decodeExcludeColumn(
  raw: string | null | undefined,
): string[] | undefined | typeof REFUSED {
  if (raw === null || raw === undefined) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return REFUSED;
  }
  if (!Array.isArray(parsed)) return REFUSED;
  for (const entry of parsed) {
    if (typeof entry !== "string") return REFUSED;
  }
  return parsed as string[];
}

/**
 * Read one tenant's upstream MCP server catalog (Rust `config.mcp_servers`).
 *
 * The result feeds `new HttpMcpUpstreams(configs)`; the catalog is per-TENANT
 * because a tenant must never see another tenant's upstreams, and the filter is
 * a bound parameter rather than a caller-supplied SQL fragment.
 *
 * The catalog is authoritative in the tenant object. The control plane writes
 * the same row when an admin resource changes and the cutover helper copies
 * legacy control documents once, so request-time reads never consult the flat
 * control database. Typed rows remain fail-closed: malformed transport, auth,
 * allowlist or JSON values are skipped rather than coerced.
 */
export async function loadServerCatalog(
  namespace: TenantDataNamespace,
  tenantId: string,
  controlDb?: D1Database,
  tenantRouter?: TenantDatabaseRouter,
): Promise<McpServerConfig[]> {
  const db = tenantDatabase(namespace, tenantId);
  const rows = await db
    .prepare(
      `SELECT name, transport, url, auth_type, tools_to_execute, tools_to_auto_execute,
              tools_to_exclude, headers, oauth, signed_jwt_audience, timeout_ms
         FROM mcp_servers WHERE tenant_id = ? ORDER BY name`,
    )
    .bind(tenantId)
    .all<ServerRow>();
  const configs: McpServerConfig[] = [];
  const seen = new Set<string>();
  for (const row of rows.results) {
    const config = decodeServerRow(row);
    if (config === undefined) continue;
    configs.push(config);
    seen.add(config.name);
  }
  if (controlDb !== undefined) {
    // The object-local document table is authoritative whenever the object
    // router is present. A control-table read remains only for an explicitly
    // un-routed compatibility/projection posture.
    for (const config of await loadAdminServerCatalog(controlDb, tenantId, tenantRouter)) {
      if (seen.has(config.name)) continue;
      configs.push(config);
      seen.add(config.name);
    }
  }
  return configs;
}

// ---------------------------------------------------------------------------
// Identity key material
// ---------------------------------------------------------------------------

/** The AEAD key length `webCryptoIdentityCipher` requires (AES-256). */
export const IDENTITY_KEY_BYTES = 32;

/**
 * Decode `FERROGATE_MCP_IDENTITY_KEY` — base64 or lowercase/uppercase hex.
 *
 * Returns `undefined` for ANY input that is not exactly
 * {@link IDENTITY_KEY_BYTES} bytes. That is deliberate: a truncated or
 * mistyped secret must make the Worker report NOT READY, not silently seal
 * every stored grant under a short, attacker-guessable key.
 */
export function decodeIdentityKey(raw: string | undefined): Uint8Array | undefined {
  if (raw === undefined) return undefined;
  const text = raw.trim();
  if (text.length === 0) return undefined;
  if (/^[0-9a-fA-F]{64}$/.test(text)) {
    const bytes = new Uint8Array(IDENTITY_KEY_BYTES);
    for (let i = 0; i < IDENTITY_KEY_BYTES; i += 1) {
      bytes[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return undefined;
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(text);
  } catch {
    return undefined;
  }
  return bytes.length === IDENTITY_KEY_BYTES ? bytes : undefined;
}

/**
 * Build the identity cipher from deploy-time key material.
 *
 * Returns `undefined` when the secret is absent or malformed so the caller can
 * fail closed. There is deliberately NO ephemeral fallback on this path — the
 * random-key fallback inside {@link webCryptoIdentityCipher} exists only for
 * the dev bundle, and using it in production would mean every stored grant
 * becomes undecryptable on the next isolate.
 */
export function identityCipherFrom(raw: string | undefined): IdentityCipherPort | undefined {
  const key = decodeIdentityKey(raw);
  return key === undefined ? undefined : webCryptoIdentityCipher(key);
}

export { credentialId };
