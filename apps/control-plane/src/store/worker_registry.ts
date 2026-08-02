/**
 * The WRITE half of the self-hosted worker registry.
 *
 * ## What this closes
 *
 * `apps/agent-runtime/src/durable/adapters.ts` carried
 * `PORT_TODO(inventory-edge-control §agent-worker §8.1)`: `d1WorkerIdentityPort`
 * READS `self_hosted_worker_registrations` in the CONTROL database, and **no TS
 * code wrote that table**. So the six `auth.kind: "internal"`
 * `/v1/self-hosted-workers/*` callbacks admitted NOBODY on any deployment, and
 * the ten `/admin/v1/self-hosted-workers` operations here stored a
 * `control_plane_resources` document that reached nothing. Same defect class as
 * the MCP server catalog: the reader mounted, the data path into it absent.
 *
 * The write belongs HERE — `apps/control-plane` owns `env.DB`, which IS the
 * control database `apps/agent-runtime` binds as `CONTROL_DB` — so this module
 * projects the admin document into the typed row that app reads, exactly as
 * `store/tenancy.ts` projects `projects`/`workspaces` into a tenant database.
 *
 * ## The credential, and Rust's rule about it
 *
 * Rust `AgentRuntimeState::register_self_hosted_worker` provisions a transport
 * secret with `generate_transport_token_secret()` — 256 bits of CSPRNG, hex —
 * and its doc comment is explicit about WHY it must not be derived from
 * anything public:
 *
 * > the `identity_fingerprint` / `token_id` are non-secret lookup keys returned
 * > in admin listings and carried in cleartext in every frame, so reusing them
 * > (as the pre-fix wiring did) makes the AEAD/bearer secret public and lets
 * > anyone forge and decrypt frames.
 *
 * {@link mintTransportCredential} reproduces that: `token_id` is a UUID (a
 * lookup key, freely visible) and `token_secret` is 32 independent CSPRNG bytes,
 * hex-encoded. Neither is derived from the other or from the worker id.
 *
 * `rotate_self_hosted_worker_identity` mints a FRESH secret on every rotation,
 * so a leaked one stops working — that is what makes rotation a remediation and
 * not just a relabelling.
 *
 * ## Where the secret lives, and where it must never live
 *
 * Rust returns the secret to the caller **exactly once** (at registration and at
 * rotation) and never includes it in the record `GET`/`list` surfaces. Two
 * consequences are enforced here and by the routes:
 *
 *  * the secret is written ONLY into `self_hosted_worker_registrations.registration_json`
 *    — the row a `token_id`+`token_secret` presentation is compared against —
 *    and NEVER into the `control_plane_resources` document, which every
 *    `admin.read` caller can list;
 *  * {@link stripCredentialFields} removes `token_secret` from an operator-supplied
 *    body before the document is stored, because `adminRecordSchema` is
 *    `passthrough()` and an operator who pastes one in would otherwise publish
 *    it to every reader of the collection.
 *
 * ## Ordering, and what a crash between the two writes leaves
 *
 * The document (control database, `control_plane_resources`) and the typed
 * registry row (control database, `self_hosted_worker_registrations`) are two
 * statements. They are in the SAME database, but the document goes through
 * `ControlPlaneStore` (which may be the in-memory store) while the row is raw
 * D1, so they are not one commit in every posture. The document is written
 * FIRST and the registry row second, deliberately:
 *
 * | crash point | residue | why it is the safe direction |
 * |---|---|---|
 * | after the document, before the row | a worker visible to the operator that authenticates nobody | fail-CLOSED — the internal callbacks refuse, and re-POSTing/rotating repairs it |
 * | (the inverse) | a registry row that authenticates a worker no operator can see or rotate | an invisible live credential — never acceptable |
 */
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
         registered_at_unix = excluded.registered_at_unix,
         registration_json = excluded.registration_json`,
    )
    .bind(document.worker_id, document.registered_at_unix, JSON.stringify(document))
    .run();
}

/** Read the stored registry document back, for rotation and for tests. */
export async function readWorkerRegistration(
  db: D1Database,
  workerId: string,
): Promise<WorkerRegistrationDocument | null> {
  const row = await db
    .prepare(`SELECT registration_json FROM ${WORKER_REGISTRATION_TABLE} WHERE id = ?`)
    .bind(workerId)
    .first<{ registration_json: string | null }>();
  if (row === null || row.registration_json === null) return null;
  try {
    const parsed: unknown = JSON.parse(row.registration_json);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    return parsed as WorkerRegistrationDocument;
  } catch {
    return null;
  }
}
