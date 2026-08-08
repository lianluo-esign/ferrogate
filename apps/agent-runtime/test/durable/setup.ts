/**
 * Shared setup + fixtures for the DURABLE-PORTS suite.
 *
 * Applies the DEPLOYED migrations (`sql/d1-ts/tenant` + `sql/d1-ts/control`,
 * read by `harness/vitest.config.ts` with `readD1Migrations`) to the REAL D1
 * databases `workerd` bound from `harness/wrangler.toml`, then seeds the two
 * credential tables the durable adapters read.
 *
 * Nothing here fakes a database, a binding, a port or a router. Every request
 * a spec makes goes through `SELF` into the real `src/worker.ts`.
 *
 * Rows are written with the WRITE construction the resolver verifies against
 * ({@link hashVirtualApiKeySecret}), not a hand-rolled second copy — so a
 * change to the hash format breaks these specs instead of silently passing.
 */
import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter, controlDataObjectDatabase } from "@ferrogate/storage";
import {
  hashVirtualApiKeySecret,
  virtualApiKeyLast4,
  virtualApiKeyPrefix,
} from "../../src/durable/hash.js";

/**
 * Zero-D1 S5 (#881): the CONTROL schema is the singleton `ControlDataObject`,
 * bound cross-script as `env.CONTROL_DATA` (`harness/wrangler.toml`). The
 * durable specs still seed and assert through `env.CONTROL_DB`, so that name is
 * aliased AT MODULE LOAD to a fresh-per-access facade over the object the code
 * reads. A lazy Proxy avoids reusing a request-bound DO stub across requests,
 * and the object self-migrates its whole control schema on construction, so no
 * `applyD1Migrations` seeds it.
 */
const harnessBindings = env as unknown as { CONTROL_DATA?: unknown; CONTROL_DB?: D1Database };
if (harnessBindings.CONTROL_DATA === undefined) {
  throw new Error(
    "durable harness: `CONTROL_DATA` is not bound — harness/vitest.config.ts must publish the " +
      "cross-script ControlDataObject (Zero-D1 S5, #881).",
  );
}
const controlAlias = new Proxy({} as D1Database, {
  get(_target, prop) {
    const db = controlDataObjectDatabase(harnessBindings.CONTROL_DATA as never) as unknown as Record<
      string | symbol,
      unknown
    >;
    const value = db[prop];
    return typeof value === "function" ? value.bind(db) : value;
  },
});
harnessBindings.CONTROL_DB = controlAlias;

/**
 * The six internal callbacks and the body builder for each, re-exported from
 * the app suite's fixtures rather than copied.
 *
 * Sharing is deliberate: `test/internal-auth.test.ts` (in-memory registry) and
 * `test/durable/identity.spec.ts` (D1 registry) must be asserting about the
 * SAME six requests, or "a tenant key is refused" and "a worker is admitted"
 * stop being two halves of one invariant.
 */
export { INTERNAL_ROUTES as INTERNAL_PATHS, workerEnvelopeFor } from "../fixtures.js";

export const BASE = "https://agent-runtime-durable.test";

/** Far past / far future, so no spec depends on when it runs. */
const LONG_AGO = 1_000_000_000;
const FAR_FUTURE = 4_000_000_000;

/** The tenant every legacy fixture in this file belongs to. */
export const TENANT_A = "tenant-a";
/** A second, unrelated tenant — the other side of every tenancy fence. */
export const TENANT_B = "tenant-b";

export const TENANT_RESOURCE_TABLE = "tenant_resources";

/** The object-local document database used by tenant-private durable fixtures. */
export async function tenantResourceDb(tenantId: string): Promise<D1Database> {
  const namespace = (
    env as unknown as {
      TENANT_DATA?: import("@ferrogate/storage/durable-objects").TenantDataNamespace;
    }
  ).TENANT_DATA;
  if (namespace === undefined) throw new Error("durable harness requires TENANT_DATA");
  return (
    await new DurableObjectTenantDatabaseRouter(namespace, env.CONTROL_DB).forTenant(tenantId)
  ).db;
}

// ---------------------------------------------------------------------------
// Tenant credentials — seeded into `api_keys` in the TENANT database
// ---------------------------------------------------------------------------

/** Live, fully scoped for every operation this Worker owns. */
export const KEY_LIVE = "fg_durable_tenant_alpha";
/** Live, but holds only `agent.runs.read` — the scope gate, not the credential gate. */
export const KEY_READONLY = "fg_durable_readonly_key";
/** `enabled = 0`. MUST answer 401, never 403. */
export const KEY_DISABLED = "fg_durable_disabled_key";
/** `revoked_at_unix` set. MUST answer 401. */
export const KEY_REVOKED = "fg_durable_revoked_0key";
/** `expires_at_unix` in the past. MUST answer 401. */
export const KEY_EXPIRED = "fg_durable_expired_0key";
/** Row stored with a `blake2b:` hash tag — the documented, KEPT divergence. */
export const KEY_BLAKE2B = "fg_durable_blake2b_hash";
/** Live, but `tenant_id` is blank: authenticated, yet cannot address tenancy. */
export const KEY_NO_TENANT = "fg_durable_no_tenant_ky";
/**
 * Live and fully scoped, but seeded under a SECOND tenant.
 *
 * It exists so a cross-tenant refusal can be shown to be a FENCE rather than an
 * empty table: `agent-upstream-withdrawal.spec.ts` reaches a row with this key
 * and is refused the same row with {@link KEY_LIVE}. Without the positive half
 * the negative half would pass against a Worker that resolves no upstream at
 * all — the vacuous shape this repository keeps catching.
 *
 * The first 16 characters are deliberately NOT `KEY_LIVE`'s: `key_prefix` is a
 * 16-char index seek (`VIRTUAL_API_KEY_PREFIX_CHARS`), and two fixtures sharing
 * a prefix would make this suite depend on the multi-candidate branch of the
 * resolver instead of on the tenancy fence it is about.
 */
export const KEY_TENANT_B = "fg_durable_beta_tenant1";
/** Never seeded. The negative control for every positive assertion. */
export const KEY_UNKNOWN = "fg_durable_never_seeded1";

const AGENT_SCOPES = ["agents.invoke", "agent.runs.create", "agent.runs.read"];

interface SeedKey {
  readonly id: string;
  readonly secret: string;
  readonly tenantId?: string;
  readonly scopes?: readonly string[];
  readonly enabled?: boolean;
  readonly expiresAtUnix?: number | null;
  readonly revokedAtUnix?: number | null;
  /** Override the stored hash entirely (used for the `blake2b:` row). */
  readonly keyHashOverride?: string;
}

const SEED_KEYS: readonly SeedKey[] = [
  { id: "key_live", secret: KEY_LIVE, scopes: AGENT_SCOPES },
  { id: "key_tenant_b", secret: KEY_TENANT_B, tenantId: TENANT_B, scopes: AGENT_SCOPES },
  { id: "key_readonly", secret: KEY_READONLY, scopes: ["agent.runs.read"] },
  { id: "key_disabled", secret: KEY_DISABLED, scopes: AGENT_SCOPES, enabled: false },
  { id: "key_revoked", secret: KEY_REVOKED, scopes: AGENT_SCOPES, revokedAtUnix: LONG_AGO },
  { id: "key_expired", secret: KEY_EXPIRED, scopes: AGENT_SCOPES, expiresAtUnix: LONG_AGO },
  {
    id: "key_blake2b",
    secret: KEY_BLAKE2B,
    scopes: AGENT_SCOPES,
    // A well-formed BLAKE2b-512 tag. `apps/gateway` accepts this construction;
    // this Worker refuses it — see the module marker on `src/durable/hash.ts`.
    keyHashOverride: `blake2b:${"a".repeat(128)}`,
  },
  { id: "key_no_tenant", secret: KEY_NO_TENANT, scopes: AGENT_SCOPES, tenantId: "" },
];

const INSERT_KEY_SQL =
  "INSERT OR REPLACE INTO api_keys (id, workspace_id, tenant_id, project_id, name, " +
  "key_prefix, key_hash, last4, enabled, scopes_json, expires_at_unix, revoked_at_unix) " +
  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

// ---------------------------------------------------------------------------
// Worker-plane identities — seeded into `self_hosted_worker_registrations`
// ---------------------------------------------------------------------------

/** 64-hex CSPRNG-shaped transport secrets (Rust `generate_transport_token_secret`). */
const SECRET_A = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
const SECRET_B = "ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211";

/**
 * The five-field identity envelope a worker presents.
 *
 * A type alias over an index signature rather than an `interface` so it stays
 * assignable to `Readonly<Record<string, unknown>>` — the parameter type
 * `workerEnvelopeFor` takes.
 */
export type WorkerIdentityFixture = Readonly<{
  tenant_id: string;
  workspace_id: string;
  worker_id: string;
  token_id: string;
  token_secret: string;
}>;

/** Registered and active. */
export const DURABLE_WORKER_A: WorkerIdentityFixture = {
  tenant_id: "tenant-a",
  workspace_id: "ws-a",
  worker_id: "durable-worker-a",
  token_id: "tok-durable-a",
  token_secret: SECRET_A,
};

/** Registered but `active: false` — 403, distinct from the 401 an unknown gets. */
export const DURABLE_WORKER_RETIRED: WorkerIdentityFixture = {
  tenant_id: "tenant-a",
  workspace_id: "ws-a",
  worker_id: "durable-worker-retired",
  token_id: "tok-durable-retired",
  token_secret: SECRET_B,
};

/** Registered, active, but its identity expired long ago (Rust #113). */
export const DURABLE_WORKER_EXPIRED: WorkerIdentityFixture = {
  tenant_id: "tenant-a",
  workspace_id: "ws-a",
  worker_id: "durable-worker-expired",
  token_id: "tok-durable-expired",
  token_secret: SECRET_B,
};

const INSERT_REGISTRATION_SQL =
  "INSERT OR REPLACE INTO self_hosted_worker_registrations " +
  "(id, registered_at_unix, registration_json) VALUES (?, ?, ?)";

function registrationDocument(
  identity: WorkerIdentityFixture,
  overrides: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    ...identity,
    framework_adapter: "native",
    capabilities: ["coding"],
    identity_expires_at_unix: null,
    active: true,
    ...overrides,
  });
}

// ---------------------------------------------------------------------------

let prepared = false;

/**
 * Apply both migration sets and seed both tables. Idempotent:
 * `applyD1Migrations` is bookkept in `d1_migrations` and the inserts are
 * `INSERT OR REPLACE`.
 */
export async function setupDurablePorts(): Promise<void> {
  if (prepared) return;
  await applyD1Migrations(env.DB, env.TENANT_MIGRATIONS);
  // The CONTROL schema self-applies inside the ControlDataObject; nothing to
  // migrate here. `env.CONTROL_DB` is the facade aliased above (#881).

  for (const row of SEED_KEYS) {
    const secret = row.secret;
    await env.DB.prepare(INSERT_KEY_SQL)
      .bind(
        row.id,
        "ws-a",
        row.tenantId ?? TENANT_A,
        "proj-a",
        row.id,
        virtualApiKeyPrefix(secret),
        row.keyHashOverride ?? (await hashVirtualApiKeySecret(secret)),
        virtualApiKeyLast4(secret),
        (row.enabled ?? true) ? 1 : 0,
        JSON.stringify(row.scopes ?? []),
        row.expiresAtUnix ?? null,
        row.revokedAtUnix ?? null,
      )
      .run();
  }

  const registrations: ReadonlyArray<[WorkerIdentityFixture, Record<string, unknown>]> = [
    [DURABLE_WORKER_A, {}],
    [DURABLE_WORKER_RETIRED, { active: false }],
    [DURABLE_WORKER_EXPIRED, { identity_expires_at_unix: LONG_AGO }],
  ];
  for (const [identity, overrides] of registrations) {
    await env.CONTROL_DB.prepare(INSERT_REGISTRATION_SQL)
      .bind(identity.worker_id, FAR_FUTURE, registrationDocument(identity, overrides))
      .run();
  }
  prepared = true;
}

// ---------------------------------------------------------------------------
// Request helpers (the same shapes `test/fixtures.ts` uses)
// ---------------------------------------------------------------------------

export function bearer(key: string): Record<string, string> {
  return { authorization: `Bearer ${key}`, "content-type": "application/json" };
}

export function workerHeaders(): Record<string, string> {
  return {
    "x-ferrogate-transport-security": "symmetric_aead",
    "content-type": "application/json",
  };
}

export async function post(
  path: string,
  headers: Record<string, string>,
  body: unknown,
): Promise<Response> {
  return await SELF.fetch(`${BASE}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

export async function get(path: string, headers: Record<string, string>): Promise<Response> {
  return await SELF.fetch(`${BASE}${path}`, { method: "GET", headers });
}

/** `POST /v1/agent-jobs` — the cheapest bearer operation with a real scope. */
export async function submitJob(key: string): Promise<Response> {
  return await post("/v1/agent-jobs", bearer(key), {
    input: "write the patch",
    required_capabilities: ["coding"],
    idempotency_key: `durable-${key}-${Math.random().toString(36).slice(2)}`,
  });
}

/** `POST /v1/self-hosted-workers/heartbeat` — the cheapest internal callback. */
export async function heartbeat(
  identity: Record<string, unknown>,
  extra: Record<string, unknown> = {},
): Promise<Response> {
  return await post("/v1/self-hosted-workers/heartbeat", workerHeaders(), {
    protocol_version: 1,
    identity,
    status: "idle",
    reported_at_unix: 1_800_000_000,
    ...extra,
  });
}

/** The `error.code` of a FerroGate error envelope. */
export async function errorCode(response: Response): Promise<string | undefined> {
  const body = (await response.json()) as { error?: { code?: string } };
  return body.error?.code;
}
