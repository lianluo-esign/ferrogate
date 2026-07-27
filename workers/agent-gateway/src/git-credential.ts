// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: FerroGate brokered per-operation git credential route (issue #475). The
//   container's git credential helper calls back here per git operation with a
//   RUN-SCOPED capability; the Worker loads the grant from the run's Durable Object
//   (never from the request), authorizes the operation, mints a repo-scoped GitHub App
//   installation token from a Secrets Store-bound App private key, answers git, records
//   a material-free audit row, and revokes the token at run close.

import { getAgentByName } from "agents";

import { json, requireBearer, timingSafeEqual } from "./auth";
import type { AgentGateway, Env } from "./index";

/**
 * Why this route exists on the WORKER and not in the container.
 *
 * Cloudflare Secrets Store values are write-only over REST (decision #423);
 * the only read path is a Workers binding, and `env.<BINDING>.get()` takes no
 * arguments — the secret NAME is fixed at deploy time. That makes a Worker the
 * only place a Secrets Store value can be read at all, and it makes a
 * per-user secret unreadable by construction. Both facts point at the same
 * design: store ONE platform credential (the GitHub App private key), and
 * express per-user authorization as a non-secret installation id.
 *
 * The App private key is a ~1.7 KB RSA PEM and therefore CANNOT live in
 * Secrets Store (1024-byte per-value cap). It is a Worker secret
 * (`wrangler secret put GITHUB_APP_PRIVATE_KEY`, 5 KB limit). The Secrets
 * Store binding below is kept for the short values that do fit and for the
 * GA migration, and the route works with either — see
 * docs/cloudflare-git-credential-broker.md.
 */

/** GitHub's fixed installation-token lifetime. Not configurable by the caller. */
const GITHUB_TOKEN_TTL_SECS = 3600;

/** Username git must present alongside an installation token over HTTPS. */
const INSTALLATION_TOKEN_USERNAME = "x-access-token";

/** Ceiling on the App JWT's own lifetime (GitHub rejects > 10 minutes). */
const APP_JWT_TTL_SECS = 540;

/** Per-run cap on credential callbacks; mirrors the Rust broker's default. */
const OPERATION_BUDGET = 32;

/** How many audit rows one run retains in its Durable Object. */
const AUDIT_RING_CAPACITY = 64;

/** The #472 delivery variant that has a callback to serve. */
const BROKERED_DELIVERY = "brokered_per_operation";

/**
 * A grant, as the control plane registered it before the run started.
 *
 * This record is written ONLY by `/git-credential/register`, which is gated by
 * `GATEWAY_CONTROL_TOKEN`, and it lives in the run's Durable Object. The
 * credential-helper callback path NEVER accepts a grant from the request body:
 * the container is the untrusted party, so a grant it could supply is a grant
 * it could forge.
 */
export interface BrokerGrantRecord {
  /** Tenant the run belongs to; carried on the audience and every audit row. */
  tenantId: string;
  runId: string;
  grantId: string;
  /** `provider:host/namespace/name`. */
  repoId: string;
  host: string;
  namespace: string;
  name: string;
  /** GitHub App installation authorizing this run. NOT a secret. */
  installationId: number;
  /** `contents`/`pull_requests` → `read`/`write`, derived from the Rust scope. */
  permissions: Record<string, "read" | "write">;
  writeCapable: boolean;
  expiresAtUnix: number;
  /** #472 delivery variant; only `brokered_per_operation` has a callback. */
  delivery: string;
  /** `sha256:…` of the grant's `cf://` reference — never the value. */
  credentialFingerprint: string;
}

/**
 * What `/git-credential/register` accepts. The capability itself is NOT a
 * field: the control plane hands the raw capability to the container and posts
 * only its FINGERPRINT here, so the callback secret never transits this route
 * and cannot be read back out of the Durable Object.
 */
export interface BrokerGrantRegistration {
  grant: BrokerGrantRecord;
  /** Lowercase hex SHA-256 of `"<audience>\n<capability>"`. 64 chars. */
  capabilityFingerprint: string;
}

/** A material-free audit row. Twin of the Rust `GitCredentialAuditEvent`. */
export interface GitCredentialAuditRow {
  tenantId: string;
  runId: string;
  grantId: string;
  repoId: string;
  operation: "fetch" | "push";
  decisionCode: string;
  operationId?: string;
  credentialFingerprint: string;
  sequence: number;
  occurredAtUnix: number;
}

/**
 * The run's persisted broker state. `outstanding` is the ONLY place a minted
 * token is retained, and it exists for exactly one reason: `DELETE
 * /installation/token` needs the token in order to revoke it, and GitHub
 * offers no other way to kill an installation token before its hour is up.
 * It is platform-side (Durable Object storage), never reachable from the
 * container, never returned by any route, and dropped the moment it is
 * superseded or revoked.
 */
export interface BrokerRunRecord {
  grant: BrokerGrantRecord;
  audience: string;
  capabilityFingerprint: string;
  operationsUsed: number;
  audit: GitCredentialAuditRow[];
  outstanding?: { token: string; operationId: string; expiresAtUnix: number };
}

/**
 * The slice of the agent Durable Object the broker verbs need. `AgentGateway`
 * satisfies it structurally, which keeps the verbs out of index.ts
 * (engineering standard #429) and unit-testable without a Durable Object.
 */
export interface GitCredentialHost {
  name: string;
  brokerRecordGet(): Promise<BrokerRunRecord | undefined>;
  brokerRecordPut(record: BrokerRunRecord): Promise<void>;
  brokerRecordDelete(): Promise<void>;
}

/**
 * The `key=value` block git hands its credential helper, as the helper
 * forwards it. Note: no password field, ever.
 *
 * This is the VALIDATED form. The wire form is `unknown` until
 * {@link invalidCallback} has proven every field's type — see the note on
 * {@link CredentialCallback}.
 *
 * `path`/`username` are `string | null | undefined` rather than `string |
 * undefined`, and the `| null` is the load-bearing half. The Rust twin
 * `GitCredentialQuery` declares them `Option<String>` with `#[serde(default)]`
 * and NO `skip_serializing_if`, so a serialized pathless query is `"path":
 * null` on the wire, not an absent key. Declaring the null makes `?? ""` in
 * {@link authorizeCallback} legitimate instead of defensive, and — the point —
 * makes a future `callback.query.path.trim()` a COMPILE error rather than a
 * second #501. Rejecting the null in the validator would have bought the same
 * safety at the price of answering `invalid_callback` for the single most
 * likely real misconfiguration, where the charged, audited, documented
 * `path_missing` deny code is what an operator needs to see.
 */
export interface CredentialQuery {
  protocol: string;
  host: string;
  path?: string | null;
  username?: string | null;
}

/**
 * One credential-helper callback, **after** validation. Twin of the Rust
 * `GitCredentialCallback`.
 *
 * The type distinction this interface carries is load-bearing, and #501 is what
 * happens without it. On the Rust side the equivalent type is `Deserialize`, so
 * `{"query":{"protocol":123}}` never becomes a `GitCredentialCallback` at all —
 * serde rejects it at the boundary. TypeScript has no such boundary: a `as
 * CredentialCallback` cast is a promise to the compiler and nothing to the
 * runtime, so `query.protocol.toLowerCase()` on a number threw a `TypeError`
 * out of the Durable Object, past the budget charge and past the audit write.
 *
 * So the rule for this module: a value of this type has been through
 * {@link invalidCallback}. Anything that has not is typed `unknown`.
 */
export interface CredentialCallback {
  runId: string;
  grantId: string;
  operation: "fetch" | "push";
  query: CredentialQuery;
}

/** Stable denial codes; mirror `broker_deny_codes` in the Rust module. */
const DENY = {
  RUN_MISMATCH: "run_mismatch",
  GRANT_MISMATCH: "grant_mismatch",
  GRANT_EXPIRED: "grant_expired",
  DELIVERY_NOT_BROKERED: "delivery_not_brokered",
  PROTOCOL_NOT_HTTPS: "protocol_not_https",
  HOST_NOT_GRANTED: "host_not_granted",
  PATH_MISSING: "path_missing",
  REPO_NOT_GRANTED: "repo_not_granted",
  WRITE_NOT_GRANTED: "write_not_granted",
  OPERATION_BUDGET_EXHAUSTED: "operation_budget_exhausted",
} as const;

type DenyCode = (typeof DENY)[keyof typeof DENY];

/**
 * The audience a run's callback capability is minted for. Mirrors the Rust
 * `BrokerCallbackBinding::audience`, and it is load-bearing rather than
 * decorative: it is mixed into {@link capabilityFingerprint}, so a capability
 * minted for one tenant/run cannot authenticate a different one even if the
 * same secret string were reused.
 */
export function brokerAudience(tenantId: string, runId: string): string {
  return `ferrogate:git-credential:${tenantId}:${runId}`;
}

/** Lowercase hex SHA-256 of `"<audience>\n<capability>"`. */
export async function capabilityFingerprint(
  audience: string,
  capability: string,
): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${audience}\n${capability}`),
  );
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Authorize one callback against the grant. Pure and side-effect free so it is
 * testable without a GitHub round trip; it is the TypeScript twin of
 * `GitCredentialBroker::decide` and MUST stay in step with it — the same ten
 * codes in the same order, and the caller charges the budget on denials too.
 *
 * `callback` is a VALIDATED {@link CredentialCallback}: every field access below
 * is total over that type, which is why there is no defensive `?.` left in this
 * function. Handing it an unvalidated body is the #501 defect.
 */
export function authorizeCallback(
  grant: BrokerGrantRecord,
  callback: CredentialCallback,
  sequence: number,
  nowUnix: number,
): { ok: true } | { ok: false; code: DenyCode; detail: string } {
  const deny = (code: DenyCode, detail: string) => ({ ok: false as const, code, detail });

  if (sequence > OPERATION_BUDGET) {
    return deny(DENY.OPERATION_BUDGET_EXHAUSTED, `run used its ${OPERATION_BUDGET} operations`);
  }
  if (callback.runId !== grant.runId) return deny(DENY.RUN_MISMATCH, "callback names another run");
  if (callback.grantId !== grant.grantId) {
    return deny(DENY.GRANT_MISMATCH, "callback names an unknown grant");
  }
  if (nowUnix >= grant.expiresAtUnix) {
    return deny(DENY.GRANT_EXPIRED, `grant expired at ${grant.expiresAtUnix}`);
  }
  if (grant.delivery !== BROKERED_DELIVERY) {
    return deny(DENY.DELIVERY_NOT_BROKERED, "grant is not a brokered grant");
  }
  if (callback.query.protocol.toLowerCase() !== "https") {
    return deny(DENY.PROTOCOL_NOT_HTTPS, "credentials are brokered over TLS only");
  }
  const host = callback.query.host.toLowerCase().split(":")[0];
  if (host !== grant.host.toLowerCase()) {
    return deny(DENY.HOST_NOT_GRANTED, `host ${host} is not the granted host`);
  }
  // `credential.useHttpPath=true` is what makes this field present. Without it
  // the answer could not be scoped to one repo, so a pathless callback fails
  // closed rather than degrading to host scoping.
  const rawPath = (callback.query.path ?? "").trim().replace(/^\/+|\/+$/g, "");
  const path = rawPath.replace(/\.git$/, "");
  if (!path) {
    return deny(DENY.PATH_MISSING, "set credential.useHttpPath=true on the container's git");
  }
  if (path.toLowerCase() !== `${grant.namespace}/${grant.name}`.toLowerCase()) {
    return deny(DENY.REPO_NOT_GRANTED, `repo ${path} is not the granted repo`);
  }
  if (callback.operation === "push" && !grant.writeCapable) {
    return deny(DENY.WRITE_NOT_GRANTED, "push requires a write-back-backed grant");
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Durable Object verbs — the authoritative side of the broker
// ---------------------------------------------------------------------------

/** Discriminated envelope: DO RPC strips a thrown error's class identity. */
export type BrokerResult<T> = ({ ok: true } & T) | { ok: false; code: string; detail: string };

const HEX64 = /^[0-9a-f]{64}$/;

/** Reject a registration the control plane got wrong, field by field. */
function invalidRegistration(candidate: unknown): string | null {
  const registration = candidate as Partial<BrokerGrantRegistration> | null;
  if (!registration || typeof registration !== "object") return "registration must be an object";
  const grant = registration.grant as Partial<BrokerGrantRecord> | undefined;
  if (!grant || typeof grant !== "object") return "registration.grant is required";
  for (const field of [
    "tenantId",
    "runId",
    "grantId",
    "repoId",
    "host",
    "namespace",
    "name",
    "delivery",
    "credentialFingerprint",
  ] as const) {
    const value = grant[field];
    if (typeof value !== "string" || value.trim() === "") return `grant.${field} is required`;
  }
  if (!Number.isInteger(grant.installationId) || (grant.installationId as number) <= 0) {
    return "grant.installationId must be a positive integer";
  }
  if (!Number.isInteger(grant.expiresAtUnix) || (grant.expiresAtUnix as number) <= 0) {
    return "grant.expiresAtUnix must be a unix timestamp";
  }
  if (!grant.permissions || typeof grant.permissions !== "object") {
    return "grant.permissions is required";
  }
  if (
    typeof registration.capabilityFingerprint !== "string" ||
    !HEX64.test(registration.capabilityFingerprint)
  ) {
    return "capabilityFingerprint must be lowercase hex sha256 (64 chars)";
  }
  return null;
}

/**
 * Reject a callback whose fields are the wrong TYPE, field by field, exactly as
 * {@link invalidRegistration} does for the control-plane half (#501).
 *
 * Optional chaining is NOT a type check: `(123)?.toLowerCase` is `undefined`,
 * and calling it throws. This function is the only thing standing between a
 * JSON body and the string operations in {@link authorizeCallback}, so it must
 * stay exhaustive over every field that function touches.
 *
 * `operation` is required and must be one of the two literals — the Rust twin
 * deserializes it into a `GitOperation` enum, which has no default either. It
 * is checked here rather than coerced because a coerced operation would land in
 * the audit row as fact.
 *
 * Empty strings in `protocol`/`host` are deliberately NOT rejected: they are
 * well-typed and the authorization denies them with `protocol_not_https` /
 * `host_not_granted`, which is a charged, audited denial rather than a
 * discarded body.
 *
 * `null` in `path`/`username` is ACCEPTED, and that is deliberate rather than
 * an oversight: the Rust twin serializes `Option<String>` without
 * `skip_serializing_if`, so `"path": null` is what a pathless query looks like
 * on the wire. A pathless callback must reach `authorizeCallback` and come back
 * `path_missing` — charged, audited, and naming the fix
 * (`credential.useHttpPath=true`) — not `invalid_callback`, which names
 * nothing. The safety that rejecting it would have bought is bought instead by
 * the `| null` in {@link CredentialQuery}: the validated form is exactly the
 * declared form, so this validator stays total, and a later
 * `callback.query.path.trim()` fails to compile.
 */
function invalidCallback(candidate: unknown): string | null {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    return "callback must be an object";
  }
  const callback = candidate as Partial<CredentialCallback>;
  for (const field of ["runId", "grantId"] as const) {
    const value = callback[field];
    if (typeof value !== "string" || value.trim() === "") return `${field} is required`;
  }
  if (callback.operation !== "fetch" && callback.operation !== "push") {
    return 'operation must be "fetch" or "push"';
  }
  const query = callback.query as Partial<CredentialQuery> | undefined;
  if (!query || typeof query !== "object" || Array.isArray(query)) return "query is required";
  for (const field of ["protocol", "host"] as const) {
    if (typeof query[field] !== "string") return `query.${field} must be a string`;
  }
  for (const field of ["path", "username"] as const) {
    const value = query[field];
    if (value !== undefined && value !== null && typeof value !== "string") {
      return `query.${field} must be a string`;
    }
  }
  return null;
}

/**
 * The operation the body actually PRESENTED, or `undefined` when it presented
 * neither literal.
 *
 * Deliberately not a coercion. A malformed callback still gets an audit row
 * when the operation is knowable, and gets none when it is not: an audit row
 * asserting `fetch` for a body that never said `fetch` is a wrong value, and a
 * wrong value in the audit trail is worse than an absent row.
 */
function presentedOperation(candidate: unknown): "fetch" | "push" | undefined {
  const operation = (candidate as { operation?: unknown } | null | undefined)?.operation;
  if (operation === "push") return "push";
  if (operation === "fetch") return "fetch";
  return undefined;
}

/**
 * Register the run's grant. Control-plane only — the route gates this verb on
 * `GATEWAY_CONTROL_TOKEN`, and the callback path cannot reach it.
 *
 * Re-registering a run replaces the record; a token still outstanding under the
 * previous record is handed back so the route revokes it rather than orphaning
 * it.
 */
export async function brokerRegister(
  host: GitCredentialHost,
  candidate: unknown,
): Promise<BrokerResult<{ audience: string; supersededToken: string | null }>> {
  const problem = invalidRegistration(candidate);
  if (problem) return { ok: false, code: "invalid_registration", detail: problem };
  const registration = candidate as BrokerGrantRegistration;
  const grant = registration.grant;
  if (grant.runId !== host.name) {
    return {
      ok: false,
      code: "invalid_registration",
      detail: `grant.runId ${grant.runId} does not address this run (${host.name})`,
    };
  }
  const previous = await host.brokerRecordGet();
  const audience = brokerAudience(grant.tenantId, grant.runId);
  await host.brokerRecordPut({
    grant,
    audience,
    capabilityFingerprint: registration.capabilityFingerprint,
    operationsUsed: 0,
    audit: [],
  });
  return { ok: true, audience, supersededToken: previous?.outstanding?.token ?? null };
}

/** What the route gets back from an authorization: never a bare boolean. */
export interface BrokerAuthorization {
  decision: "approve" | "deny";
  code: string;
  detail: string;
  audit: GitCredentialAuditRow;
  /** Mint parameters, present only on approval. Carries no key material. */
  mint?: {
    installationId: number;
    repository: string;
    permissions: Record<string, "read" | "write">;
    expiresAtUnix: number;
    operationId: string;
  };
  /** A token left over from the previous operation, for the route to revoke. */
  supersededToken: string | null;
}

/**
 * Authorize one callback against the run's REGISTERED grant, and charge the
 * budget. The read-modify-write of the record happens inside this single
 * Durable Object method, so concurrent callbacks cannot race past the budget.
 *
 * `presentedCapability` is verified here rather than in the route because the
 * fingerprint it is checked against lives in the record: there is no
 * gateway-wide shared secret anywhere on this path.
 */
export async function brokerAuthorize(
  host: GitCredentialHost,
  callbackCandidate: unknown,
  presentedCapability: string,
  nowUnix: number,
): Promise<BrokerResult<BrokerAuthorization>> {
  const record = await host.brokerRecordGet();
  // The SAME answer for "no grant registered" and "wrong capability": this
  // route must not become an oracle for which run ids exist.
  if (!record) return { ok: false, code: "unauthorized", detail: "no run capability" };
  const presented = await capabilityFingerprint(record.audience, presentedCapability);
  if (!timingSafeEqual(presented, record.capabilityFingerprint)) {
    return { ok: false, code: "unauthorized", detail: "no run capability" };
  }
  // Belt and braces: a record whose audience was not derived from its own
  // tenant/run pair could otherwise accept a capability minted elsewhere.
  if (record.audience !== brokerAudience(record.grant.tenantId, record.grant.runId)) {
    return { ok: false, code: "unauthorized", detail: "no run capability" };
  }

  const grant = record.grant;
  const sequence = record.operationsUsed + 1;
  // Charged BEFORE the body is looked at. A capability holder posting a
  // malformed callback is probing, and #501 is precisely the case where the
  // probe cost nothing: the throw landed between this line and the
  // `brokerRecordPut` below, so neither the charge nor the row was persisted.
  record.operationsUsed = sequence;
  const row = (operation: "fetch" | "push", decisionCode: string): GitCredentialAuditRow => ({
    tenantId: grant.tenantId,
    runId: grant.runId,
    grantId: grant.grantId,
    repoId: grant.repoId,
    operation,
    decisionCode,
    credentialFingerprint: grant.credentialFingerprint,
    sequence,
    occurredAtUnix: nowUnix,
  });
  const append = (audit: GitCredentialAuditRow) => {
    record.audit = [...record.audit, audit].slice(-AUDIT_RING_CAPACITY);
  };

  // The type boundary. Past this point `callbackCandidate` is a
  // `CredentialCallback` for real, not by assertion.
  const problem = invalidCallback(callbackCandidate);
  if (problem !== null) {
    // The cap is enforced AHEAD of the validator (#501 review item 7). Without
    // this line the budget check lives only inside `authorizeCallback`, which
    // this branch returns before, so a malformed probe was charged forever and
    // never refused: `operation_budget_exhausted` was unreachable on the one
    // path that does not even have to be well-typed to reach it.
    const exhausted = sequence > OPERATION_BUDGET;
    const code = exhausted ? DENY.OPERATION_BUDGET_EXHAUSTED : "invalid_callback";
    const detail = exhausted ? `run used its ${OPERATION_BUDGET} operations` : problem;
    const presentedOp = presentedOperation(callbackCandidate);
    if (presentedOp) append(row(presentedOp, code));
    // `outstanding` is untouched: a body this broken must not supersede — and
    // therefore must not cause the revocation of — a token a live operation is
    // still using. It is still revoked at run close.
    await host.brokerRecordPut(record);
    return { ok: false, code, detail };
  }
  const callback = callbackCandidate as CredentialCallback;
  const operation = callback.operation;

  const decision = authorizeCallback(grant, callback, sequence, nowUnix);
  const audit = row(operation, decision.ok ? "approved" : decision.code);

  let mint: BrokerAuthorization["mint"];
  if (decision.ok) {
    audit.operationId = await capabilityFingerprint(
      record.audience,
      `${grant.grantId}|${grant.repoId}|${operation}|${sequence}`,
    );
    mint = {
      installationId: grant.installationId,
      repository: grant.name,
      permissions: grant.permissions,
      expiresAtUnix: Math.min(grant.expiresAtUnix, nowUnix + GITHUB_TOKEN_TTL_SECS),
      operationId: audit.operationId,
    };
  }

  // The audit row is written on both AUTHORIZED paths — approve and deny, and
  // the denied one is the interesting one — and it is written BEFORE the mint,
  // so there is no ordering in which a token is issued without a row already
  // recorded. There is a THIRD path since #501: a body too broken to name an
  // `operation` is charged and returns above WITHOUT a row, because an audit
  // row asserting `fetch` for a body that never said `fetch` is a wrong value.
  // So `operationsUsed` may exceed the row count, and the gap it leaves in
  // `sequence` is the only trace of such a body. The doc states this as the
  // reconciliation rule.
  append(audit);
  const supersededToken = record.outstanding?.token ?? null;
  if (supersededToken) delete record.outstanding;
  await host.brokerRecordPut(record);

  return {
    ok: true,
    decision: decision.ok ? "approve" : "deny",
    code: audit.decisionCode,
    detail: decision.ok ? "approved" : decision.detail,
    audit,
    mint,
    supersededToken,
  };
}

/** Retain the just-minted token so it can be revoked. Never read back out. */
export async function brokerRecordMint(
  host: GitCredentialHost,
  operationId: string,
  token: string,
  expiresAtUnix: number,
): Promise<BrokerResult<{ recorded: true }>> {
  const record = await host.brokerRecordGet();
  if (!record) return { ok: false, code: "unauthorized", detail: "no run capability" };
  record.outstanding = { token, operationId, expiresAtUnix };
  await host.brokerRecordPut(record);
  return { ok: true, recorded: true };
}

/**
 * Close the run: delete the grant so no further token can ever be minted, and
 * hand the outstanding token back so the route revokes it at GitHub. Driven on
 * the success path AND the failure path, and idempotent on both.
 */
export async function brokerClose(
  host: GitCredentialHost,
): Promise<BrokerResult<{ outstandingToken: string | null; operationsUsed: number }>> {
  const record = await host.brokerRecordGet();
  await host.brokerRecordDelete();
  return {
    ok: true,
    outstandingToken: record?.outstanding?.token ?? null,
    operationsUsed: record?.operationsUsed ?? 0,
  };
}

/** Read the run's material-free audit rows (control plane only). */
export async function brokerAudit(
  host: GitCredentialHost,
): Promise<BrokerResult<{ rows: GitCredentialAuditRow[]; operationsUsed: number }>> {
  const record = await host.brokerRecordGet();
  if (!record) return { ok: false, code: "no_grant", detail: "no grant registered for this run" };
  return { ok: true, rows: record.audit, operationsUsed: record.operationsUsed };
}

// ---------------------------------------------------------------------------
// GitHub App plumbing
// ---------------------------------------------------------------------------

/** Base64url without padding, for JWT segments. */
function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strip a PEM's armour and decode the DER body. */
function pemToDer(pem: string): ArrayBuffer {
  const body = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  const raw = atob(body);
  const der = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) der[i] = raw.charCodeAt(i);
  return der.buffer;
}

/**
 * Sign the short-lived App JWT that authenticates the token mint.
 *
 * NOTE: WebCrypto imports PKCS#8 only. GitHub hands out PKCS#1 ("BEGIN RSA
 * PRIVATE KEY"); convert once at onboarding with
 * `openssl pkcs8 -topk8 -nocrypt -in app.pem -out app.pkcs8.pem`, and store the
 * PKCS#8 form. This throws rather than guessing if the wrong form is supplied.
 */
async function appJwt(appId: string, privateKeyPem: string, nowUnix: number): Promise<string> {
  if (!privateKeyPem.includes("BEGIN PRIVATE KEY")) {
    throw new Error("GitHub App key must be PKCS#8 ('BEGIN PRIVATE KEY'); convert with openssl");
  }
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(privateKeyPem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const encoder = new TextEncoder();
  const header = base64url(encoder.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const payload = base64url(
    encoder.encode(
      // 60s of backdate absorbs clock skew, per GitHub's own guidance.
      JSON.stringify({ iat: nowUnix - 60, exp: nowUnix + APP_JWT_TTL_SECS, iss: appId }),
    ),
  );
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    encoder.encode(signingInput),
  );
  return `${signingInput}.${base64url(new Uint8Array(signature))}`;
}

/** Read the App private key: Secrets Store binding first, Worker secret second. */
async function appPrivateKey(env: Env): Promise<string | null> {
  if (env.GITHUB_APP_PRIVATE_KEY_STORE) {
    // Secrets Store binding: `get()` takes NO arguments — the secret name is
    // fixed in wrangler config at deploy time. This is exactly why a per-user
    // secret cannot be read this way.
    const value = await env.GITHUB_APP_PRIVATE_KEY_STORE.get();
    if (value) return value;
  }
  return env.GITHUB_APP_PRIVATE_KEY ?? null;
}

function apiBaseUrl(env: Env): string {
  return (env.GITHUB_API_BASE_URL ?? "https://api.github.com").replace(/\/+$/, "");
}

/**
 * Mint a repo-scoped installation token.
 * `POST /app/installations/{id}/access_tokens` with a single-element
 * `repositories` array. GitHub fixes the expiry at one hour, which is exactly
 * why {@link revokeInstallationToken} — not the response's `expiresAtUnix`
 * field — is the real bound on the token's life.
 */
async function mintInstallationToken(
  env: Env,
  mint: NonNullable<BrokerAuthorization["mint"]>,
  nowUnix: number,
): Promise<{ token: string; expiresAt: string }> {
  const appId = env.GITHUB_APP_ID;
  const privateKey = await appPrivateKey(env);
  if (!appId || !privateKey) throw new Error("github_app_unbound");
  const jwt = await appJwt(appId, privateKey, nowUnix);
  const response = await fetch(
    `${apiBaseUrl(env)}/app/installations/${mint.installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${jwt}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "content-type": "application/json",
        "user-agent": "ferrogate-agent-gateway",
      },
      body: JSON.stringify({ repositories: [mint.repository], permissions: mint.permissions }),
    },
  );
  if (!response.ok) {
    // The body can echo request detail; status only, never the response text.
    throw new Error(`installation_token_mint_failed_${response.status}`);
  }
  const body = (await response.json()) as { token: string; expires_at: string };
  return { token: body.token, expiresAt: body.expires_at };
}

/** Outcome vocabulary of the Rust `RevocationOutcome`. */
type RevocationOutcome = "revoked" | "already_expired" | "failed";

/**
 * `DELETE /installation/token` — authenticated WITH the token being revoked.
 * HTTP 401 means the token is already dead, which IS neutralization, so it is
 * reported as `already_expired` rather than a failure.
 */
async function revokeInstallationToken(
  env: Env,
  token: string,
): Promise<{ outcome: RevocationOutcome; code?: string }> {
  try {
    const response = await fetch(`${apiBaseUrl(env)}/installation/token`, {
      method: "DELETE",
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "ferrogate-agent-gateway",
      },
    });
    if (response.status === 204) return { outcome: "revoked" };
    if (response.status === 401) return { outcome: "already_expired" };
    return { outcome: "failed", code: `http_${response.status}` };
  } catch {
    // Never the exception text: it can carry request detail.
    return { outcome: "failed", code: "revocation_call_failed" };
  }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

function runStub(env: Env, runId: string) {
  return getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, runId);
}

/** Bearer value as presented, or `""`. The callback path checks it itself. */
function presentedBearer(request: Request): string {
  const header = request.headers.get("authorization") ?? "";
  return header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
}

/**
 * Ceiling on a callback body, in characters of decoded JSON text.
 *
 * A credential-helper callback is four short strings; 16 KiB is three orders of
 * magnitude of headroom. The cap exists because the body is passed as a Durable
 * Object RPC ARGUMENT, and DO RPC arguments are size-limited: an oversize body
 * throws at the RPC boundary, i.e. outside `brokerAuthorize`, where no budget
 * can be charged and no row written (#501 review item 3). Refusing it here is
 * the only place that class can be removed rather than merely re-labelled.
 *
 * Counted in UTF-16 code units rather than UTF-8 bytes deliberately: a code
 * unit is at most 3 UTF-8 bytes, so this is a hard bound either way, and it
 * costs no second pass over the body.
 */
const MAX_CALLBACK_BODY_CHARS = 16 * 1024;

/**
 * JSON body or a 400 — never an uncaught Worker exception (1101).
 *
 * `maxChars` also buys a 413. It is applied on the untrusted callback path and
 * not on the control-plane verbs, which are already gated on
 * `GATEWAY_CONTROL_TOKEN`.
 */
async function parseJsonBody(
  request: Request,
  maxChars?: number,
): Promise<{ body?: unknown; error?: Response }> {
  const tooLarge = () =>
    json({ error: "body_too_large", detail: `callback body exceeds ${maxChars} characters` }, 413);
  if (maxChars !== undefined) {
    // Cheapest refusal first, when the caller declared a length at all.
    const declared = Number(request.headers.get("content-length") ?? "");
    if (Number.isFinite(declared) && declared > maxChars * 3) return { error: tooLarge() };
  }
  let text: string;
  try {
    text = await request.text();
  } catch {
    // The read error's text is deliberately not echoed: it can quote the body.
    return { error: json({ error: "invalid_json", detail: "body must be JSON" }, 400) };
  }
  if (maxChars !== undefined && text.length > maxChars) return { error: tooLarge() };
  try {
    return { body: JSON.parse(text) };
  } catch {
    // The parse error's text is deliberately not echoed: it can quote the body.
    return { error: json({ error: "invalid_json", detail: "body must be JSON" }, 400) };
  }
}

/**
 * The `/git-credential/*` surface.
 *
 * | verb | who may call it | authenticated by |
 * |---|---|---|
 * | `register` | control plane | `GATEWAY_CONTROL_TOKEN` |
 * | `get` | the container's git credential helper | the RUN-SCOPED capability |
 * | `revoke` | control plane, at run finalize | `GATEWAY_CONTROL_TOKEN` |
 * | `audit` | control plane | `GATEWAY_CONTROL_TOKEN` |
 *
 * `get` is the only verb the untrusted container can reach, and it is
 * deliberately NOT gated on `GATEWAY_CONTROL_TOKEN`: that token also opens
 * `/control/*`, `/container/*`, `/memory/*` and `/schedule/*`, so handing it to
 * a container would give model-authored code the whole gateway. The run-scoped
 * capability is verified against a fingerprint that lives in the run's Durable
 * Object and is mixed with the run's audience, so it is worthless against any
 * other run, tenant, or route.
 *
 * `get` never reads a grant from the request body. The grant is loaded from the
 * run's Durable Object, where only `register` can have put it.
 */
export async function handleGitCredential(
  request: Request,
  env: Env,
  url: URL,
  ctx: ExecutionContext,
): Promise<Response> {
  const verb = url.pathname.slice("/git-credential/".length);
  const expectedMethod = verb === "audit" ? "GET" : "POST";
  if (request.method !== expectedMethod) return json({ error: "method not allowed" }, 405);

  // Fail closed: an unbound GitHub App means NO credential path exists, which
  // must never degrade into "run without one" or "fall back to an env token".
  // `revoke`/`audit` are exempt — closing out a run has to work regardless.
  const appBound =
    Boolean(env.GITHUB_APP_ID) &&
    Boolean(env.GITHUB_APP_PRIVATE_KEY_STORE || env.GITHUB_APP_PRIVATE_KEY);

  switch (verb) {
    case "register": {
      const denied = requireBearer(request, env.GATEWAY_CONTROL_TOKEN);
      if (denied) return denied;
      if (!appBound) return json({ error: "github_app_unbound" }, 501);
      const parsed = await parseJsonBody(request);
      if (parsed.error) return parsed.error;
      const registration = parsed.body as Partial<BrokerGrantRegistration> | null;
      const runId = registration?.grant?.runId;
      if (typeof runId !== "string" || runId.trim() === "") {
        return json({ error: "invalid_registration", detail: "grant.runId is required" }, 400);
      }
      const stub = await runStub(env, runId);
      const result = await stub.gitCredentialRegister(registration);
      if (!result.ok) return json({ error: result.code, detail: result.detail }, 400);
      if (result.supersededToken) {
        // A re-registration must not orphan a live token.
        ctx.waitUntil(revokeInstallationToken(env, result.supersededToken));
      }
      return json({ registered: true, audience: result.audience });
    }

    case "get": {
      if (!appBound) return json({ error: "github_app_unbound" }, 501);
      const capability = presentedBearer(request);
      if (!capability) {
        return json({ error: "unauthorized", detail: "no run capability" }, 401);
      }
      const parsed = await parseJsonBody(request, MAX_CALLBACK_BODY_CHARS);
      if (parsed.error) return parsed.error;
      const callback = parsed.body as Partial<CredentialCallback> | null;
      const runId = callback?.runId;
      if (typeof runId !== "string" || runId.trim() === "") {
        // A FREE REFUSAL, documented as such rather than claimed away (#501).
        // A body that names no run cannot address a Durable Object, so there is
        // no record to charge and no audit ring to write to: a charge is
        // structurally impossible here, not merely skipped.
        //
        // The code is `invalid_request`, which is what `revoke` and `audit`
        // already answer for a missing runId, and deliberately neither of the
        // two codes it sits between. Not `run_mismatch`: that is a DENY CODE,
        // which the Durable Object emits charged and audited, and spending it
        // on a request that never reached an authorization would give one code
        // two accountings. Not `invalid_callback` either: that code is the
        // Durable Object's, and it is worth keeping it to mean exactly one
        // thing — the capability verified, the body did not, and the budget was
        // charged for the attempt.
        return json({ error: "invalid_request", detail: "callback names no run" }, 400);
      }

      const stub = await runStub(env, runId);
      let authorized: Awaited<ReturnType<typeof stub.gitCredentialAuthorize>>;
      try {
        authorized = await stub.gitCredentialAuthorize(
          callback,
          capability,
          Math.floor(Date.now() / 1000),
        );
      } catch {
        // Belt and braces behind `invalidCallback`: an unexpected throw inside
        // the Durable Object becomes a typed 502, never an uncaught Worker
        // exception (1101) that leaks a stack and skips the budget. The
        // exception text is not echoed — it can quote the callback body — but
        // the event IS logged, because a 502 written to no row and no log is
        // less visible than the 1101 it replaced: that was at least a stack in
        // Workers error analytics. The run id is a non-secret identifier and is
        // the only thing that makes such a report actionable.
        console.error("gitCredentialAuthorize threw", { runId });
        return json({ error: "authorize_failed", detail: "callback could not be authorized" }, 502);
      }
      if (!authorized.ok) {
        // A body the broker could not even read is the caller's mistake (400);
        // anything else here is `unauthorized`, which stays 403.
        //
        // Be plain about what the split leaks (#501): the SAME malformed body
        // answers `invalid_callback` with a valid capability and `unauthorized`
        // with an invalid one, because this code is only reachable after
        // `timingSafeEqual` accepted the capability. `invalid_callback`
        // therefore IMPLIES a verified capability and a charged budget unit.
        // That is accepted, not denied: the capability is high-entropy and
        // run-scoped, and a valid one already yields a 200 carrying a token,
        // which is a far louder signal than a status code.
        const status = authorized.code === "invalid_callback" ? 400 : 403;
        return json({ error: authorized.code, detail: authorized.detail }, status);
      }
      if (authorized.supersededToken) {
        // The previous operation's token dies the moment a new one is asked for.
        ctx.waitUntil(revokeInstallationToken(env, authorized.supersededToken));
      }
      if (authorized.decision === "deny" || !authorized.mint) {
        return json({ error: authorized.code, detail: authorized.detail }, 403);
      }

      const nowUnix = Math.floor(Date.now() / 1000);
      try {
        const minted = await mintInstallationToken(env, authorized.mint, nowUnix);
        const githubExpiry = Math.floor(Date.parse(minted.expiresAt) / 1000);
        const expiresAtUnix = Math.min(
          authorized.mint.expiresAtUnix,
          Number.isFinite(githubExpiry) && githubExpiry > 0
            ? githubExpiry
            : nowUnix + GITHUB_TOKEN_TTL_SECS,
        );
        // Retain the revocation handle BEFORE answering: if the response is
        // lost in flight the token must still be revocable at run close.
        await stub.gitCredentialRecordMint(
          authorized.mint.operationId,
          minted.token,
          expiresAtUnix,
        );
        return json({
          username: INSTALLATION_TOKEN_USERNAME,
          password: minted.token,
          expiresAtUnix,
          operationId: authorized.mint.operationId,
        });
      } catch (err) {
        // `(err as Error).message` is one of our own fixed strings — never a
        // GitHub response body, which could echo request material.
        return json({ error: (err as Error).message }, 502);
      }
    }

    case "revoke": {
      // Control-plane only, driven at run finalize on BOTH the success and the
      // failure path. Deletes the grant (so no further mint is possible) and
      // revokes the token still outstanding at GitHub. A failure here is the
      // incident, so it is reported (502), never swallowed.
      const denied = requireBearer(request, env.GATEWAY_CONTROL_TOKEN);
      if (denied) return denied;
      const parsed = await parseJsonBody(request);
      if (parsed.error) return parsed.error;
      const runId = (parsed.body as { runId?: string } | null)?.runId;
      if (typeof runId !== "string" || runId.trim() === "") {
        return json({ error: "invalid_request", detail: "runId is required" }, 400);
      }
      const stub = await runStub(env, runId);
      const closed = await stub.gitCredentialClose();
      if (!closed.ok) return json({ error: closed.code, detail: closed.detail }, 400);
      if (!closed.outstandingToken) {
        // Nothing was ever minted, or the last one was superseded and already
        // revoked. Either way no live credential remains for this run.
        return json({ outcome: "already_expired", operationsUsed: closed.operationsUsed });
      }
      const outcome = await revokeInstallationToken(env, closed.outstandingToken);
      return json(
        { ...outcome, operationsUsed: closed.operationsUsed },
        outcome.outcome === "failed" ? 502 : 200,
      );
    }

    case "audit": {
      // Control-plane only. Material-free by construction: the rows are the
      // TypeScript twin of the Rust `GitCredentialAuditEvent`, which has no
      // field a token could be written into.
      const denied = requireBearer(request, env.GATEWAY_CONTROL_TOKEN);
      if (denied) return denied;
      const runId = url.searchParams.get("runId");
      if (!runId) return json({ error: "invalid_request", detail: "runId is required" }, 400);
      const stub = await runStub(env, runId);
      const result = await stub.gitCredentialAudit();
      if (!result.ok) return json({ error: result.code, detail: result.detail }, 404);
      return json({ rows: result.rows, operationsUsed: result.operationsUsed });
    }

    default:
      return json({ error: `unknown git-credential verb: ${verb}` }, 404);
  }
}
