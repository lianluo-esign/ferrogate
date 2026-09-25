import { type TenantDatabaseRouter, readTenantWorkerIdentity } from "@ferrogate/storage";
/** Self-hosted worker transport credentials live only in the tenant object.
 * The platform registry contains worker, tenant and workspace identifiers for
 * discovery. Runtime authentication always resolves the tenant identity.
 * Secrets are returned once on registration/rotation and stripped from admin
 * documents. A missing tenant identity is never restored from a platform copy. */
import type { StoreRecord } from "../ports.js";

/** The typed registry table `apps/agent-runtime`'s `d1WorkerIdentityPort` reads. */
export const WORKER_REGISTRATION_TABLE = "self_hosted_worker_registrations";

/** Rust `generate_transport_token_secret`: 32 CSPRNG bytes, hex (64 chars). */
export const TRANSPORT_TOKEN_SECRET_BYTES = 32;

/** Fields an operator must never be able to set or read through the document. */
export const CREDENTIAL_FIELDS = ["token_secret"] as const;

export interface TransportCredential {
  /** Non-secret lookup key, carried in cleartext in every worker frame. */
  readonly token_id: string;
  /** The secret. Returned to the caller ONCE; never in a GET/list body. */
  readonly token_secret: string;
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * Provision a fresh transport credential.
 *
 * The secret is independent CSPRNG output, NOT a hash or slice of the
 * `token_id`, the worker id or the identity fingerprint — see the module
 * docblock for the Rust comment explaining why that distinction is the whole
 * point of the function.
 */
export function mintTransportCredential(): TransportCredential {
  return {
    token_id: crypto.randomUUID(),
    token_secret: hex(crypto.getRandomValues(new Uint8Array(TRANSPORT_TOKEN_SECRET_BYTES))),
  };
}

/**
 * Drop credential fields from an operator-supplied body.
 *
 * Returns a NEW object; the caller's body is untouched. This is the guard that
 * keeps `passthrough()` from turning `POST {"token_secret": "..."}` into a
 * secret published in every `admin.read` listing of the collection.
 */
export function stripCredentialFields(body: Record<string, unknown>): Record<string, unknown> {
  const copy = { ...body };
  for (const field of CREDENTIAL_FIELDS) delete copy[field];
  return copy;
}

function text(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

function finiteNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * The document `apps/agent-runtime`'s `registryRowFromDocument` decodes.
 *
 * Every field name here is that decoder's, not a name invented in this app: a
 * rename on either side must break something. `tenant_id`, `workspace_id`,
 * `worker_id`, `token_id` and `token_secret` are ALL required over there — a row
 * missing any one of them is treated as absent — so this builder supplies all
 * five or the projection is not attempted at all.
 */
export interface WorkerRegistrationDocument {
  readonly tenant_id: string;
  readonly workspace_id: string;
  readonly worker_id: string;
  readonly framework_adapter: string;
  readonly token_id: string;
  readonly token_secret: string;
  readonly identity_expires_at_unix: number | null;
  readonly capabilities: string[];
  readonly active: boolean;
  readonly identity_fingerprint: string | null;
  readonly registered_at_unix: number;
}

/**
 * `active` from the admin document's `status`.
 *
 * The admin schema's enum is `active | inactive | draining`, and only `active`
 * is active: `draining` means "finish what you have and stop taking work", and
 * admitting a draining worker's NEW dispatch leases would defeat the state. A
 * document with no `status` at all is active, matching Rust `register_worker`,
 * which leaves a fresh registration usable.
 */
export function activeFromStatus(status: unknown): boolean {
  if (typeof status !== "string") return true;
  return status.trim().toLowerCase() === "active";
}

export function workerRegistrationDocument(
  record: StoreRecord,
  credential: TransportCredential,
  nowUnix: number,
): WorkerRegistrationDocument {
  const workerId = String(record.id);
  const capabilities = Array.isArray(record.capabilities)
    ? record.capabilities.filter((entry): entry is string => typeof entry === "string")
    : [];
  const fingerprint = record.identity_fingerprint;
  return {
    // The tenancy triple is the registry key on the read side. A
    // platform-scoped document (no tenant) still needs a NON-EMPTY value or the
    // reader discards the row; the empty-string fallbacks below would produce
    // exactly that, so they are never used — `projectWorkerRegistration`
    // refuses a record with no tenant instead (see below).
    tenant_id: text(record.tenant_id, ""),
    workspace_id: text(record.workspace_id, ""),
    worker_id: workerId,
    framework_adapter: text(record.framework_adapter, "native"),
    token_id: credential.token_id,
    token_secret: credential.token_secret,
    identity_expires_at_unix: finiteNumber(record.identity_expires_at_unix),
    capabilities,
    active: activeFromStatus(record.status),
    identity_fingerprint: typeof fingerprint === "string" ? fingerprint : null,
    registered_at_unix: nowUnix,
  };
}

/**
 * Whether a stored worker document can become a registry row at all.
 *
 * Both halves of the tenancy pair are REQUIRED, because the reader keys on the
 * `(tenant_id, workspace_id, worker_id)` triple and treats a row whose document
 * disagrees with the presented tenancy as absent. Projecting a row with an
 * empty `workspace_id` would write a credential nothing can ever present — a
 * silent half-registration that looks provisioned in the admin listing. The
 * route refuses instead, so the operator learns what is missing.
 */
export function registrationBlocker(record: StoreRecord): string | null {
  if (text(record.tenant_id, "") === "") {
    return "tenant_id is required to provision a self-hosted worker transport identity";
  }
  if (text(record.workspace_id, "") === "") {
    return "workspace_id is required to provision a self-hosted worker transport identity";
  }
  return null;
}

/**
 * Write (or overwrite) the typed registry row.
 *
 * `INSERT … ON CONFLICT (id) DO UPDATE` because rotation and heartbeat both
 * re-project an existing worker, and because a retried registration must not
 * fail on the leg the document write already accepted.
 *
 * `id` is the WORKER id, matching the reader's
 * `SELECT registration_json … WHERE id = ?` point lookup.
 */
export async function projectWorkerRegistration(
  db: D1Database,
  document: WorkerRegistrationDocument,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO ${WORKER_REGISTRATION_TABLE} (id, registered_at_unix, registration_json)
       VALUES (?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         registration_json = excluded.registration_json
       WHERE ${WORKER_REGISTRATION_TABLE}.registration_json <> excluded.registration_json`,
    )
    .bind(
      document.worker_id,
      document.registered_at_unix,
      JSON.stringify({
        worker_id: document.worker_id,
        tenant_id: document.tenant_id,
        workspace_id: document.workspace_id,
      }),
    )
    .run();
}

/** Resolve ownership without opening the tenant object or reading credentials. */
export async function readWorkerDirectory(
  db: D1Database,
  workerId: string,
): Promise<{ tenant_id: string; workspace_id: string } | null> {
  const row = await db
    .prepare(`SELECT registration_json FROM ${WORKER_REGISTRATION_TABLE} WHERE id = ?`)
    .bind(workerId)
    .first<{ registration_json: string | null }>();
  if (row?.registration_json === null || row === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.registration_json);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const directory = parsed as { tenant_id?: unknown; workspace_id?: unknown };
  if (
    typeof directory.tenant_id !== "string" ||
    directory.tenant_id.trim() === "" ||
    typeof directory.workspace_id !== "string"
  )
    return null;
  return { tenant_id: directory.tenant_id, workspace_id: directory.workspace_id };
}

/** Read credentials only from their authoritative tenant identity. */
export async function readWorkerRegistration(
  db: D1Database,
  workerId: string,
  router?: TenantDatabaseRouter,
): Promise<WorkerRegistrationDocument | null> {
  if (router === undefined) return null;
  const directory = await readWorkerDirectory(db, workerId);
  if (directory === null) return null;
  return (await readTenantWorkerIdentity(
    router,
    directory.tenant_id,
    workerId,
  )) as WorkerRegistrationDocument | null;
}
