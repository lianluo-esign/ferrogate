/**
 * The DURABLE adapters — the real-implementation branch this app did not have.
 *
 * `docs/rewrite/parity-audit-dead-packages.md` §7.1 found that
 * `resolveDeps` had **exactly one branch**: the in-memory dev bundle. There was
 * no real-adapter path anywhere in `apps/agent-runtime` — "not unbound,
 * UNWRITTEN" — so everything a self-hosted worker authenticates against, and
 * every tenant credential this Worker admits, was a JSON `[vars]` entry that
 * dies with the isolate. This module is that missing branch.
 *
 * Two authorities, two databases, matching the split `apps/gateway` already
 * deploys (`apps/gateway/wrangler.toml`):
 *
 * | port | binding | table | schema |
 * |---|---|---|---|
 * | {@link d1ApiKeyPort} | `DB` | `api_keys` | `sql/d1-ts/tenant` |
 * | {@link d1WorkerIdentityPort} | `CONTROL_DB` | `self_hosted_worker_registrations` | `sql/d1-ts/control` |
 *
 * The split is not cosmetic. `api_keys` is the tenant's own credential table
 * and lives in the tenant database; the self-hosted worker registry is
 * account-global operator state (a worker is registered by the control plane,
 * not by the tenant's data plane) and lives in the control database. Reading
 * them from one binding would collapse a boundary the storage design draws
 * deliberately (`apps/gateway/src/tenancy/ports.ts` §"split rule").
 *
 * ## What does NOT change here
 *
 * The refusal taxonomies are the ones `src/ports.ts` already declares and
 * `src/middleware/auth.ts` already renders — `unknown` vs `key_suspended`
 * collapsing onto one 401, `unknown_worker` (401) vs `inactive_worker` (403),
 * the constant-time secret compare. Swapping the storage under a port must not
 * move a status code, and these adapters are written so that it cannot: they
 * produce the same `ApiKeyResolution` / `WorkerIdentityResolution` values the
 * in-memory ports produce, and every HTTP decision stays in the middleware.
 */
import {
  D1TwoHopApiKeyDirectory,
  type TenantDatabaseRouter,
  type TwoHopApiKeyDirectory,
} from "@ferrogate/storage";
import { normalizedCapabilities } from "../capabilities.js";
import { timingSafeEqualStrings } from "../crypto.js";
// TYPE-ONLY, and it has to stay that way: `../ports.ts` imports the two
// factories below, so a VALUE import back into it would close a module cycle.
// The one runtime helper both need lives in the leaf `../capabilities.ts`.
import type {
  ApiKeyPort,
  ApiKeyResolution,
  AuthContext,
  RegisteredSelfHostedWorker,
  SelfHostedWorkerIdentity,
  WorkerIdentityPort,
  WorkerIdentityResolution,
} from "../ports.js";
import { type FrameOpenResult, type SealedWorkerFrame, openWorkerFrame } from "../workers/frame.js";
import { sha256Hex, verifyStoredKeyHash, virtualApiKeyPrefix } from "./hash.js";

// ---------------------------------------------------------------------------
// Tenant credentials — `api_keys`, the TENANT database
// ---------------------------------------------------------------------------

/**
 * The prefix lookup, mirroring Rust `find_api_key_records_by_prefix`.
 *
 * `key_prefix` is indexed (`idx_api_keys_prefix`), so this is one index seek
 * regardless of table size. It is a plain equality bind — never string
 * interpolation, never `LIKE` — so a presented value cannot become SQL and
 * cannot widen the candidate set with a wildcard character.
 *
 * It deliberately does NOT filter on `enabled` / `revoked_at_unix` /
 * `expires_at_unix` in SQL: Rust evaluates liveness after the fetch, and
 * keeping that in code the tests can reach is what makes the 401-vs-403
 * decision reviewable instead of hidden in a WHERE clause.
 */
const FIND_KEYS_BY_PREFIX_SQL =
  "SELECT id, tenant_id, workspace_id, project_id, key_hash, last4, enabled, " +
  "scopes_json, request_limit_per_minute, expires_at_unix, revoked_at_unix " +
  "FROM api_keys WHERE key_prefix = ?";

/** A row of `api_keys` as D1 hands it back. */
interface ApiKeyRow {
  readonly id: string;
  readonly tenant_id: string | null;
  readonly workspace_id: string | null;
  readonly project_id: string | null;
  readonly key_hash: string | null;
  readonly last4: string | null;
  readonly enabled: number | null;
  readonly scopes_json: string | null;
  /** TOK-12 per-credential RPM cap. NULL ⇒ the credential imposes none. */
  readonly request_limit_per_minute: number | null;
  readonly expires_at_unix: number | null;
  readonly revoked_at_unix: number | null;
}

/**
 * `serde(default)` for a `Vec<String>` column: NULL, blank, malformed or
 * non-array reads as the EMPTY list.
 *
 * For `scopes` the empty list is the "durable key minted without explicit
 * scopes" state, which `hasScope` already handles (data-plane scopes yes,
 * `admin.*` never). A corrupted `scopes_json` therefore degrades to the LEAST
 * privileged interpretation, never to a wildcard.
 */
function parseScopes(raw: string | null): readonly string[] {
  if (raw === null || raw.trim() === "") return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry): entry is string => typeof entry === "string");
  } catch {
    return [];
  }
}

/** Rust `api_key_record_is_active`. */
function keyRowIsActive(row: ApiKeyRow, nowUnixSeconds: number): boolean {
  if ((row.enabled ?? 0) === 0) return false;
  if (row.revoked_at_unix !== null && row.revoked_at_unix !== undefined) return false;
  // Rust: `expires_at.is_none_or(|expires_at| expires_at > now)` — an expiry
  // exactly equal to now is EXPIRED.
  if (
    row.expires_at_unix !== null &&
    row.expires_at_unix !== undefined &&
    row.expires_at_unix <= nowUnixSeconds
  ) {
    return false;
  }
  return true;
}

/** Rust `api_key_record_last4_matches`: a blank `last4` column matches anything. */
function last4Matches(row: ApiKeyRow, presentedKey: string): boolean {
  const last4 = row.last4 ?? "";
  return last4 === "" || presentedKey.endsWith(last4);
}

/**
 * Rust `authenticate_durable`'s `AuthContext`, narrowed to what this Worker
 * carries.
 *
 * `platformOperator` is the LITERAL `false` and reads no row field to get
 * there. Rust invariant `durable_virtual_key_is_never_platform_root`: a durable
 * key declares a tenant, and `api_keys` has no column that could declare
 * anything else. Writing the literal makes it structural — no D1 value,
 * hostile or corrupted, can turn a tenant key into an operator key.
 */
function authContextFromRow(row: ApiKeyRow): AuthContext {
  return {
    subject: row.id,
    tenancy: {
      tenantId: row.tenant_id ?? null,
      workspaceId: row.workspace_id ?? null,
      projectId: row.project_id ?? null,
    },
    scopes: parseScopes(row.scopes_json),
    platformOperator: false,
    // The column that made this a live control rather than dead schema: before
    // the admission ladder existed, `D1ApiKeyResolver` read the row and DROPPED
    // this value, so `api_keys.request_limit_per_minute` was inert on this
    // Worker. `undefined` (no cap) and `0` (refuse everything) are different
    // answers, so NULL is mapped explicitly rather than through `?? 0`.
    requestLimitPerMinute:
      row.request_limit_per_minute === null || row.request_limit_per_minute === undefined
        ? undefined
        : Number(row.request_limit_per_minute),
  };
}

/** Injectable unix-seconds clock, so expiry is testable without sleeping. */
export interface D1ApiKeyPortOptions {
  readonly nowUnixSeconds?: () => number;
}

/**
 * The durable {@link ApiKeyPort}: `api_keys` in the tenant D1 database.
 *
 * Resolution order is Rust's, and the outcomes are the ones `resolveOrThrow`
 * already renders:
 *
 * | presented credential                    | outcome         | HTTP |
 * |-----------------------------------------|-----------------|------|
 * | no `key_prefix` (blank) / no row matches | `unknown`       | 401  |
 * | prefix matches, `key_hash` does not      | `unknown`       | 401  |
 * | hash matches, `enabled = 0`              | `key_suspended` | 401  |
 * | hash matches, `revoked_at_unix` set      | `key_suspended` | 401  |
 * | hash matches, `expires_at_unix <= now`   | `key_suspended` | 401  |
 * | hash matches, live                       | `resolved`      | —    |
 * | D1 unreachable / query failed            | `unavailable`   | 503  |
 *
 * **`key_suspended` is 401, not 403.** It is a distinct outcome purely so the
 * reason is nameable in code; `src/middleware/auth.ts::resolveOrThrow`
 * collapses it onto the identical `401 invalid_api_key` an unknown key gets, so
 * key state is never disclosed. Static operator-authored keys are the
 * documented 403 exception and they do not live in this table.
 *
 * A hash MATCH is decided before liveness so a suspended key is reported as
 * suspended rather than silently as unknown; both answer 401, so this is
 * observability, not a behavior difference.
 */
export function d1ApiKeyPort(db: D1Database, options: D1ApiKeyPortOptions = {}): ApiKeyPort {
  const nowUnixSeconds = options.nowUnixSeconds ?? (() => Math.floor(Date.now() / 1000));

  return {
    async resolve(presentedKey: string): Promise<ApiKeyResolution> {
      const prefix = virtualApiKeyPrefix(presentedKey);
      if (prefix === null) return { outcome: "unknown" };

      let rows: ApiKeyRow[];
      try {
        const result = await db.prepare(FIND_KEYS_BY_PREFIX_SQL).bind(prefix).all<ApiKeyRow>();
        rows = result.results ?? [];
      } catch (error) {
        // FAIL CLOSED, and say so: a credential authority that could not be
        // consulted has admitted nobody. 503, never a silent fallback to a
        // permissive table.
        return {
          outcome: "unavailable",
          detail: `api_keys lookup failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }

      const now = nowUnixSeconds();
      for (const row of rows) {
        if (!last4Matches(row, presentedKey.trim())) continue;
        const storedHash = row.key_hash;
        if (storedHash === null || storedHash === undefined) continue;
        if (!(await verifyStoredKeyHash(presentedKey.trim(), storedHash))) continue;
        // From here the caller HOLDS this key. Everything below is state.
        if (!keyRowIsActive(row, now)) return { outcome: "key_suspended" };
        return { outcome: "resolved", auth: authContextFromRow(row) };
      }
      return { outcome: "unknown" };
    },
  };
}

/**
 * The durable {@link ApiKeyPort} over the TWO-HOP directory model (#821).
 *
 * The single-hop {@link d1ApiKeyPort} read `api_keys` straight off `env.DB` — the
 * ferrogate-tenant D1. That premise ("a Worker cannot open a tenant database by
 * uuid at runtime, so credentials must live in one flat table") was wrong: a
 * Worker selects a database by BINDING NAME, and the credential→tenant map lives
 * in `api_key_directory` in the CONTROL database. So resolution is now the same
 * two hops the control plane and the gateway take, factored into the ONE shared
 * `@ferrogate/storage` implementation `D1TwoHopApiKeyDirectory`:
 *
 *  1. `api_key_directory` (CONTROL) maps the hash to its tenant;
 *  2. the routed tenant `TenantDataObject` supplies the authoritative `api_keys`
 *     row this Worker reads `scopes_json` / the RPM cap off.
 *
 * The refusal taxonomy `src/middleware/auth.ts::resolveOrThrow` renders is
 * UNCHANGED — the point of the migration was to move the SOURCE, not a status
 * code:
 *
 * | two-hop fact                              | outcome         | HTTP |
 * |-------------------------------------------|-----------------|------|
 * | no directory row / unprovisioned tenant   | `unknown`       | 401  |
 * | directory OR tenant row retired / gone    | `key_suspended` | 401  |
 * | live                                      | `resolved`      | —    |
 * | control object / tenant DB unreachable    | `unavailable`   | 503  |
 *
 * As with the gateway, only `sha256:`-tagged hashes resolve via the directory —
 * the documented, KEPT divergence from the `blake2b:` verify path (`./hash.ts`).
 * `platformOperator` is the literal `false` in {@link authContextFromRow}, so no
 * row value can promote a durable/virtual key to platform root (#515).
 */
export function twoHopApiKeyPort(
  controlDb: D1Database,
  router: TenantDatabaseRouter,
  options: D1ApiKeyPortOptions = {},
): ApiKeyPort {
  const directory: TwoHopApiKeyDirectory = new D1TwoHopApiKeyDirectory(controlDb, router, {
    now: options.nowUnixSeconds,
  });

  return {
    async resolve(presentedKey: string): Promise<ApiKeyResolution> {
      const trimmed = presentedKey.trim();
      if (trimmed === "") return { outcome: "unknown" };

      const twoHop = await directory.resolve(`sha256:${await sha256Hex(trimmed)}`);
      switch (twoHop.kind) {
        // No durable key here, or its tenant is not provisioned: 401, and NEVER a
        // silent fallback — inventing a scope for an unroutable tenant is the one
        // thing that must not happen.
        case "no_directory_row":
        case "unroutable":
          return { outcome: "unknown" };
        // Disabled/revoked/expired on either half, or a directory whose tenant
        // row is gone. All 401, indistinguishable from an unknown key.
        case "suspended":
          return { outcome: "key_suspended" };
        // FAIL CLOSED, and say so: a credential authority that could not be
        // consulted has admitted nobody.
        case "unavailable":
          return { outcome: "unavailable", detail: twoHop.detail };
        case "resolved":
          // Tenant identity comes from the tenant-database `api_keys` ROW here,
          // deliberately — this Worker treats the row an operator edits as the
          // authority and refuses a blank `tenant_id` downstream (a key that
          // routes through a real object but names no tenant on its row). The
          // gateway instead attributes from `directory.tenant_id`; in production
          // the two are written from the same dual-write and always agree, so the
          // difference is observable only in fixtures. Unifying the authority is a
          // deliberate cross-Worker decision, not made here (see PR #921 review).
          return { outcome: "resolved", auth: authContextFromRow(twoHop.row) };
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Worker-plane identities — `self_hosted_worker_registrations`, CONTROL database
// ---------------------------------------------------------------------------

/**
 * The registration document stored in
 * `self_hosted_worker_registrations.registration_json`.
 *
 * Field-for-field Rust `SelfHostedWorkerRegistration`
 * (`crates/ferrogate-runtime/src/self_hosted_worker.rs`) plus the `active` bit
 * `RegisteredSelfHostedWorker` carries. `status` is accepted as the alternative
 * spelling of `active` because Rust's stored row
 * (`StoredSelfHostedWorkerRegistration`) names it that way.
 *
 * ## The former `PORT_TODO(inventory-edge-control §agent-worker §8.1)` — CLOSED
 *
 * It read "WRITE HALF NOT PORTED": this module READS the registry, and **no TS
 * code wrote this table**, so every deployment admitted NO worker on any of the
 * six internal callbacks and rows had to be provisioned out of band.
 *
 * `apps/control-plane/src/store/worker_registry.ts` is the write half.
 * `POST /admin/v1/self-hosted-workers` (and its `POST /admin/v1/status` alias)
 * now mints a transport credential — Rust `generate_transport_token_secret`,
 * 256 CSPRNG bits, hex — stores the admin document WITHOUT the secret, and
 * projects the typed row read below into the same control database this Worker
 * binds as `CONTROL_DB`. `/rotate` mints a FRESH secret (so a leak stops
 * working) and `/heartbeat` re-projects `active` while PRESERVING the
 * credential. The field names in {@link RegistrationDocument} are the contract
 * between the two apps and are asserted from the writer's side by
 * `apps/control-plane/test/worker-registry.test.ts`.
 *
 * The read side is unchanged and still fails closed on an empty table: an
 * unprovisioned deployment admits NO worker rather than any caller.
 *
 * What is NOT ported, and is not a platform limit: there is no
 * DEACTIVATION verb. The contract declares no `DELETE`/`PATCH` for
 * `/admin/v1/self-hosted-workers`, so `active: false` is reachable only by
 * registering with `status: "draining"`/`"inactive"`. Rust reaches it the same
 * way (status is a field on the registration it upserts), so this is a contract
 * surface gap rather than a port gap — closing it means adding the operation to
 * `docs/openapi/runtime-api-contract.json`, which the anti-drift gate makes a
 * deliberate act.
 */
interface RegistrationDocument {
  readonly tenant_id?: unknown;
  readonly workspace_id?: unknown;
  readonly worker_id?: unknown;
  readonly framework_adapter?: unknown;
  readonly token_id?: unknown;
  readonly token_secret?: unknown;
  readonly identity_expires_at_unix?: unknown;
  readonly capabilities?: unknown;
  readonly active?: unknown;
  readonly status?: unknown;
}

/** A registry row with its secret — never leaves this module. */
interface RegistryRow extends RegisteredSelfHostedWorker {
  readonly token_secret: string;
}

/**
 * `id` is the `worker_id` (Rust reads this table with
 * `repositories.self_hosted_worker_registration(worker_id)`), so this is a
 * primary-key point lookup, not a scan. The tenancy triple is then checked
 * against the DOCUMENT — see {@link rowFor}.
 */
const FIND_REGISTRATION_SQL =
  "SELECT registration_json FROM self_hosted_worker_registrations WHERE id = ?";

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

/** Document → registry row, or `null` when the document cannot be trusted. */
function registryRowFromDocument(document: RegistrationDocument): RegistryRow | null {
  const tenantId = asString(document.tenant_id);
  const workspaceId = asString(document.workspace_id);
  const workerId = asString(document.worker_id);
  const tokenId = asString(document.token_id);
  const tokenSecret = asString(document.token_secret);
  // A row missing any credential field cannot authenticate anyone. Returning
  // `null` makes it indistinguishable from an absent row, which is the same
  // fail-closed answer Rust's `#[serde(default)] token_secret` empty-string
  // case produces (the transport rejects a secret below the minimum length).
  if (
    tenantId === null ||
    workspaceId === null ||
    workerId === null ||
    tokenId === null ||
    tokenSecret === null
  ) {
    return null;
  }
  const expires = document.identity_expires_at_unix;
  const capabilities = Array.isArray(document.capabilities)
    ? document.capabilities.filter((entry): entry is string => typeof entry === "string")
    : [];
  return {
    tenant_id: tenantId,
    workspace_id: workspaceId,
    worker_id: workerId,
    framework_adapter: asString(document.framework_adapter) ?? "native",
    token_id: tokenId,
    token_secret: tokenSecret,
    identity_expires_at_unix:
      typeof expires === "number" && Number.isFinite(expires) ? expires : null,
    capabilities: normalizedCapabilities(capabilities),
    // `active` wins; `status` is the stored-row spelling; a document carrying
    // neither is a plain registration and is active, exactly as Rust
    // `register_worker` leaves it.
    active:
      typeof document.active === "boolean"
        ? document.active
        : typeof document.status === "string"
          ? document.status.trim().toLowerCase() === "active"
          : true,
  };
}

/**
 * Rust `validate_identity_shape`: every field non-blank. Rejecting a blank
 * field before the lookup keeps a partially-filled envelope from matching a
 * partially-filled row.
 */
function identityShapeError(identity: SelfHostedWorkerIdentity): string | null {
  const fields: ReadonlyArray<[string, unknown]> = [
    ["tenant_id", identity.tenant_id],
    ["workspace_id", identity.workspace_id],
    ["worker_id", identity.worker_id],
    ["token_id", identity.token_id],
    ["token_secret", identity.token_secret],
  ];
  for (const [name, value] of fields) {
    if (typeof value !== "string" || value.trim() === "") {
      return `self-hosted worker identity ${name} must not be empty`;
    }
  }
  return null;
}

/**
 * The durable {@link WorkerIdentityPort}: `self_hosted_worker_registrations` in
 * the CONTROL D1 database.
 *
 * Behaviourally identical to `inMemoryWorkerIdentityPort`, including:
 *
 *  - the constant-time `token_secret` compare (#114) — a differing-PREFIX
 *    attempt must not be distinguishable from a differing-SUFFIX one by timing;
 *  - `unknown_worker` (401) kept distinct from `inactive_worker` (403);
 *  - a TENANCY MISMATCH answering `unknown_worker`, never a different code:
 *    `id` is the worker id, so tenant B naming tenant A's worker finds the row
 *    and must not learn that it exists;
 *  - {@link WorkerIdentityPort.unseal} answering ONE opaque refusal for an
 *    unknown, inactive or wrong-`token_id` frame header, because that header is
 *    attacker-controlled and answering it differently would make the sealed
 *    path an enumeration oracle for the registry;
 *  - an EMPTY table rejecting everything.
 *
 * A D1 failure is `unavailable` (503), never an admission.
 */
export function d1WorkerIdentityPort(db: D1Database): WorkerIdentityPort {
  /** Load the row for a tenancy triple. `undefined` = no usable row. */
  async function rowFor(
    tenantId: string,
    workspaceId: string,
    workerId: string,
  ): Promise<RegistryRow | undefined> {
    const record = await db
      .prepare(FIND_REGISTRATION_SQL)
      .bind(workerId)
      .first<{ registration_json: string | null }>();
    if (record === null || record.registration_json === null) return undefined;
    let document: RegistrationDocument;
    try {
      const parsed: unknown = JSON.parse(record.registration_json);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
      document = parsed as RegistrationDocument;
    } catch {
      return undefined;
    }
    const row = registryRowFromDocument(document);
    if (row === null) return undefined;
    // The tenancy triple is the registry key (Rust `worker_key`). A row whose
    // document disagrees with the presented tenancy is NOT this caller's row.
    if (row.tenant_id !== tenantId || row.workspace_id !== workspaceId) return undefined;
    if (row.worker_id !== workerId) return undefined;
    return row;
  }

  return {
    async validate(identity: SelfHostedWorkerIdentity): Promise<WorkerIdentityResolution> {
      const shape = identityShapeError(identity);
      if (shape !== null) {
        return { outcome: "rejected", failure: { reason: "invalid_shape", detail: shape } };
      }
      let row: RegistryRow | undefined;
      try {
        row = await rowFor(identity.tenant_id, identity.workspace_id, identity.worker_id);
      } catch (error) {
        return {
          outcome: "rejected",
          failure: {
            reason: "unavailable",
            detail: `self-hosted worker registry lookup failed: ${
              error instanceof Error ? error.message : String(error)
            }`,
          },
        };
      }
      if (row === undefined) {
        return { outcome: "rejected", failure: { reason: "unknown_worker" } };
      }
      if (!row.active) {
        return { outcome: "rejected", failure: { reason: "inactive_worker" } };
      }
      const secretMatches = timingSafeEqualStrings(row.token_secret, identity.token_secret);
      if (row.token_id !== identity.token_id || !secretMatches) {
        return {
          outcome: "rejected",
          failure: {
            reason: "invalid_identity",
            detail: "worker token does not match registered identity envelope",
          },
        };
      }
      if (
        row.identity_expires_at_unix !== null &&
        observedAtOrNow(identity) >= row.identity_expires_at_unix
      ) {
        return {
          outcome: "rejected",
          failure: { reason: "invalid_identity", detail: "worker identity has expired" },
        };
      }
      const { token_secret: _secret, ...worker } = row;
      return { outcome: "resolved", worker };
    },

    async unseal(frame: SealedWorkerFrame): Promise<FrameOpenResult> {
      let row: RegistryRow | undefined;
      try {
        row = await rowFor(
          frame.header.tenant_id,
          frame.header.workspace_id,
          frame.header.worker_id,
        );
      } catch {
        row = undefined;
      }
      if (row === undefined || !row.active || row.token_id !== frame.header.token_id) {
        return {
          outcome: "rejected",
          failure: { reason: "unopenable", detail: "sealed worker transport frame did not open" },
        };
      }
      return openWorkerFrame(frame, row.token_secret);
    },
  };
}

/**
 * The clock an identity's expiry is judged against.
 *
 * Rust security fix #113, verbatim: *"identity expiry must be judged against
 * the server's trusted clock. A client-supplied `observed_at_unix` (e.g.
 * `Some(0)`) must never satisfy the expiry check."* Rust overwrites the field
 * unconditionally before validating; `src/middleware/auth.ts` does the same on
 * the request path.
 *
 * This is the SECOND half of that defence, at the port: an identity that
 * carries NO `observed_at_unix` at all is judged against wall-clock now, so an
 * expired registration can never be admitted by simply OMITTING the field.
 * A caller-supplied number is still honoured when present because the middleware
 * has already replaced it with the server's, and unit tests need to drive
 * expiry deterministically.
 */
function observedAtOrNow(identity: SelfHostedWorkerIdentity): number {
  return typeof identity.observed_at_unix === "number"
    ? identity.observed_at_unix
    : Math.floor(Date.now() / 1000);
}
