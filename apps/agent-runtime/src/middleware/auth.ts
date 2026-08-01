/**
 * ONE contract-driven auth middleware — and the tenant/worker credential split.
 *
 * `ROUTE-MAP.md` invariant 1 says to port auth as contract-driven middleware
 * rather than per-route guards. This is that middleware: it looks the request up
 * in `contract.ts` and enforces whatever the matched operation *declares*
 * (`auth.kind`, `auth.scope`). Nothing here names a path.
 *
 * ## The security invariant (ROUTE-MAP invariant 2)
 *
 * The six `/v1/self-hosted-workers/*` operations are `auth.kind: "internal"` —
 * worker-plane callbacks. **A normal tenant bearer key must NOT be able to call
 * them.** That is enforced structurally, not by a check that could be forgotten:
 *
 *  - `bearerAuth` is only ever reached for `auth.kind === "bearer"`. It is the
 *    ONLY consumer of {@link ApiKeyPort}.
 *  - `internalAuth` is only ever reached for `auth.kind === "internal"`. It is
 *    the ONLY consumer of {@link WorkerIdentityPort}, and it NEVER looks at
 *    `Authorization` / `x-api-key` at all.
 *  - The two write different context variables (`auth` vs `worker`), so a
 *    handler cannot accidentally accept the wrong one.
 *  - There is no fallback: an operation whose `auth.kind` the dispatcher does
 *    not recognise is refused 500 rather than passed through.
 *
 * A tenant bearer key presented to a worker-plane route therefore fails on the
 * FIRST gate — the missing `x-ferrogate-transport-security` header — with
 * `401 invalid_self_hosted_worker_transport_security`, and even a caller that
 * forges that header still has to produce a registered worker's
 * `{token_id, token_secret}` envelope, which no tenant key is or grants.
 *
 * ## The 401-vs-403 invariant
 *
 * A *suspended* native API key returns 401, not 403: the Rust durable
 * authenticator returns `None` for a disabled/revoked/expired key, so the
 * request falls through to the same `401 invalid_api_key` an unknown key gets.
 * Key state is not disclosed. Operator-authored *static config* keys are the
 * documented exception (403 `api_key_disabled` / `api_key_expired`), and
 * *tenancy* suspension is an authenticated-but-forbidden 403.
 *
 * Ported from `crates/ferrogate-gateway/src/auth.rs`,
 * `server/local.rs::handle_self_hosted_worker_transport`, and
 * `crates/ferrogate-runtime/src/self_hosted_worker.rs`.
 */
import type { Context, MiddlewareHandler } from "hono";
import { type ApiOperation, allowedMethods, isOwnedPath, matchOperation } from "../contract.js";
import {
  type AgentRuntimeDeps,
  type AgentRuntimeEnv,
  type ApiKeyResolution,
  type AuthContext,
  type SelfHostedWorkerIdentity,
  type WorkerIdentityFailure,
  resolveDeps,
} from "../ports.js";
import { frameIdentityMismatch, readSealedFrame } from "../workers/frame.js";
import { HttpError } from "./errors.js";

// ---------------------------------------------------------------------------
// Credential extraction
// ---------------------------------------------------------------------------

/**
 * Rust `auth::extract_api_key`: `x-api-key` wins over `Authorization: Bearer`,
 * both trimmed, and a blank value counts as absent.
 */
export function extractApiKey(headers: Headers): string | null {
  const apiKeyHeader = headers.get("x-api-key");
  if (apiKeyHeader !== null) {
    const trimmed = apiKeyHeader.trim();
    if (trimmed !== "") return trimmed;
  }
  const authorization = headers.get("authorization");
  if (authorization === null) return null;
  const value = authorization.trim();
  if (!value.toLowerCase().startsWith("bearer ")) return null;
  const token = value.slice("bearer ".length).trim();
  return token === "" ? null : token;
}

/** The Rust message for an absent credential, verbatim. */
const MISSING_API_KEY_MESSAGE = "missing API key; use Authorization: Bearer or x-api-key";

/** Rust `WILDCARD_SCOPE`. */
export const WILDCARD_SCOPE = "*";

/**
 * Rust `scope_set_allows` / `AuthContext::has_scope`.
 *
 * An EMPTY scope set grants data-plane scopes only and never an `admin.*`
 * scope. That asymmetry is load-bearing: a durable/virtual key with no scopes
 * must not become an admin key.
 */
export function hasScope(auth: AuthContext, required: string): boolean {
  if (auth.platformOperator) return true;
  if (auth.scopes.includes(WILDCARD_SCOPE)) return true;
  if (auth.scopes.length === 0) return !required.startsWith("admin.");
  return auth.scopes.includes(required);
}

/** `ApiKeyResolution` → the `AuthContext` or the exact Rust refusal. */
function resolveOrThrow(resolution: ApiKeyResolution): AuthContext {
  switch (resolution.outcome) {
    case "resolved":
      return resolution.auth;
    // `unknown` and `key_suspended` deliberately collapse onto the SAME 401:
    // that indistinguishability IS the invariant.
    case "unknown":
    case "key_suspended":
      throw new HttpError(401, "invalid_api_key", "invalid API key");
    case "static_key_disabled":
      throw new HttpError(403, "api_key_disabled", "API key is disabled");
    case "static_key_expired":
      throw new HttpError(403, "api_key_expired", "API key is expired");
    case "tenancy_suspended":
      throw new HttpError(403, "tenancy_suspended", "tenancy is suspended");
    case "unavailable":
      throw new HttpError(
        503,
        "agent_runtime_unavailable",
        `credential authority is unavailable: ${resolution.detail}`,
      );
  }
}

// ---------------------------------------------------------------------------
// Worker-plane transport security
// ---------------------------------------------------------------------------

/** Rust header name + accepted values. */
export const TRANSPORT_SECURITY_HEADER = "x-ferrogate-transport-security";
const TRANSPORT_SECURITY_MTLS = "mutual_tls";
const TRANSPORT_SECURITY_SYMMETRIC_AEAD = "symmetric_aead";

/**
 * Rust `SelfHostedTransportChannel`.
 *
 * `unverified_mutual_tls_marker` and `symmetric_aead` are CLAIMS the gateway
 * has not verified at the TLS layer for this request. `verified_mutual_tls` is
 * the real thing: the EDGE validated a client certificate chain against the
 * zone's mTLS CA and reported the outcome in `request.cf.tlsClientAuth`, which
 * this Worker reads rather than asserts. See {@link verifiedMutualTls}.
 */
export type TransportChannel =
  | "verified_mutual_tls"
  | "unverified_mutual_tls_marker"
  | "symmetric_aead";

/**
 * The subset of `IncomingRequestCfProperties["tlsClientAuth"]` that decides
 * whether a client certificate was actually verified.
 */
export interface TlsClientAuth {
  readonly certPresented?: string;
  readonly certVerified?: string;
  readonly certRevoked?: string;
}

/**
 * Rust `SelfHostedTransportChannel::VerifiedMutualTls`, re-founded on the edge.
 *
 * A Worker cannot validate an X.509 chain in-process — it never sees the TLS
 * handshake, and `crypto.subtle` has no chain builder. Cloudflare's answer is
 * that the ZONE validates the client certificate against a configured mTLS CA
 * and hands the Worker the verdict on `request.cf.tlsClientAuth`. Reading that
 * verdict is a real verification; asserting one from a header is not, which is
 * why the marker path stays a separate, refused channel.
 *
 * All THREE conditions are required, and every one of them is load-bearing:
 *
 *  - `certPresented === "1"` — a certificate was actually offered.
 *  - `certVerified === "SUCCESS"` — it chained to the zone's CA. The other
 *    values (`FAILED`, `NONE`, and the various `CERT_*` reasons) are failures.
 *  - `certRevoked !== "1"` — it is not revoked. Cloudflare reports `SUCCESS`
 *    with `certRevoked: "1"` for a revoked-but-otherwise-valid certificate, so
 *    checking only `certVerified` would admit a revoked client.
 *
 * `request.cf` is UNDEFINED under `wrangler dev --local` and in the offline
 * test pool unless a test supplies it, so a local run naturally reports `false`
 * and the production posture fails closed — the same answer the Rust build
 * gives when no mTLS server is configured.
 */
export function verifiedMutualTls(request: Request): boolean {
  const properties = (request as { cf?: { tlsClientAuth?: TlsClientAuth } }).cf;
  const tls = properties?.tlsClientAuth;
  if (tls === undefined) return false;
  return tls.certPresented === "1" && tls.certVerified === "SUCCESS" && tls.certRevoked !== "1";
}

/** Rust `self_hosted_transport_security_header`. */
export function transportChannel(headers: Headers): TransportChannel | null {
  const raw = headers.get(TRANSPORT_SECURITY_HEADER);
  if (raw === null) return null;
  switch (raw.trim()) {
    case TRANSPORT_SECURITY_MTLS:
      return "unverified_mutual_tls_marker";
    case TRANSPORT_SECURITY_SYMMETRIC_AEAD:
      return "symmetric_aead";
    default:
      return null;
  }
}

/**
 * The channel this request ACTUALLY arrived on: the declared marker, upgraded
 * to `verified_mutual_tls` when — and only when — the edge says it verified a
 * client certificate.
 *
 * A `symmetric_aead` declaration is NEVER upgraded, even over verified mTLS.
 * The header is the worker's own statement about which transport contract it is
 * speaking, and silently promoting a declared downgrade would let a
 * misconfigured worker pass the production posture it was meant to fail.
 */
export function resolveTransportChannel(request: Request): TransportChannel | null {
  const declared = transportChannel(request.headers);
  if (declared === "unverified_mutual_tls_marker" && verifiedMutualTls(request)) {
    return "verified_mutual_tls";
  }
  return declared;
}

/** Rust `SelfHostedTransportPosture`. */
export type TransportPosture = "marker_contract" | "require_production_mtls";

/** Rust `parse_require_production_mtls`. */
export function transportPosture(raw: string | undefined): TransportPosture {
  return raw?.trim() === "1" || raw?.trim().toLowerCase() === "true"
    ? "require_production_mtls"
    : "marker_contract";
}

/**
 * Rust `SelfHostedTransportPolicy::admit`.
 *
 * Under `marker_contract` every channel is admitted (the pre-production
 * contract behaviour). Under `require_production_mtls`:
 *
 *  - `verified_mutual_tls` is ADMITTED — the edge validated the client
 *    certificate chain and {@link verifiedMutualTls} read that verdict off
 *    `request.cf.tlsClientAuth`.
 *  - `symmetric_aead` is an explicit DOWNGRADE (403).
 *  - the bare `mutual_tls` marker is an unverified CLAIM (501) — better to
 *    reject than to accept an unverifiable claim as production-grade.
 *
 * // PORT-TODO(L: inventory-edge-control §agent-worker §8.4): what remains
 * // unportable is the SERVER, not the decision. Rust's
 * // `self_hosted_mtls::SelfHostedMtlsServer` terminates mutual TLS itself,
 * // owning the CA bundle, the chain build and the revocation check in
 * // process. A Worker never sees the handshake and `crypto.subtle` has no
 * // chain builder, so that server has no CF equivalent and cannot be written
 * // here at any effort. Implemented instead: Cloudflare zone-level mTLS does
 * // the validation and the Worker CONSUMES the verdict
 * // (`certPresented`/`certVerified`/`certRevoked`) — see
 * // {@link verifiedMutualTls}, pinned by `test/mtls.test.ts`. Two consequences
 * // follow and neither can be coded away: (1) the trust anchor is the ZONE's
 * // mTLS CA configured at deploy time, not a CA bundle this Worker chooses at
 * // runtime; (2) `request.cf` is absent under `wrangler dev --local` and in
 * // the offline test pool, so a LOCAL run can never reach this channel and
 * // correctly fails closed.
 */
export function admitTransport(
  posture: TransportPosture,
  channel: TransportChannel,
): HttpError | null {
  if (posture === "marker_contract") return null;
  if (channel === "verified_mutual_tls") return null;
  if (channel === "symmetric_aead") {
    return new HttpError(
      403,
      "self_hosted_worker_transport_downgrade_rejected",
      "self-hosted worker transport downgrade rejected: symmetric_aead transport is a downgrade path; production mode requires a verified mutual-TLS channel for self-hosted worker transport",
    );
  }
  return new HttpError(
    501,
    "self_hosted_worker_production_mtls_not_implemented",
    "self-hosted worker production mTLS not implemented: the mutual_tls header is an unverified marker; this request did not arrive on a verified mutual-TLS channel (certificate validation + encrypted-channel proof) and is refused",
  );
}

/** Rust `write_self_hosted_worker_transport_error`, failure-for-failure. */
export function workerIdentityError(failure: WorkerIdentityFailure): HttpError {
  switch (failure.reason) {
    case "unknown_worker":
      return new HttpError(
        401,
        "invalid_self_hosted_worker_identity",
        "self-hosted worker is not registered",
      );
    case "invalid_identity":
      return new HttpError(401, "invalid_self_hosted_worker_identity", failure.detail);
    case "inactive_worker":
      return new HttpError(
        403,
        "inactive_self_hosted_worker",
        "self-hosted worker registration is inactive",
      );
    case "invalid_shape":
      return new HttpError(400, "invalid_self_hosted_worker_transport", failure.detail);
    case "unavailable":
      return new HttpError(503, "agent_runtime_unavailable", failure.detail);
  }
}

// ---------------------------------------------------------------------------
// Body envelope
// ---------------------------------------------------------------------------

/**
 * The worker-plane frame every internal callback carries.
 *
 * Rust ships `SelfHostedWorkerTransportFrame` — a ChaCha20-Poly1305 AEAD
 * envelope whose associated data is the `{protocol_version, tenant_id,
 * workspace_id, worker_id, token_id}` header — OR the same document in the
 * clear under the `mutual_tls` marker path. Both carry the identity envelope
 * this port reads.
 *
 * The AEAD frame IS implemented — `workers/frame.ts` — in BOTH shapes, and both
 * are unsealed here before anything reads an identity: Rust's own
 * XChaCha20-Poly1305 `encrypted_payload` document (so an unmodified Rust worker
 * binary interoperates) and this port's `{sealed: …}` AES-256-GCM wrapper. The
 * registry does the opening so the transport secret never leaves it, and the
 * PLAINTEXT is what the handlers read. A cleartext body stays supported because
 * Rust supports it too on the `mutual_tls` marker path.
 *
 * Note what the frame does and does not buy: the *credential* check
 * (`token_id` + constant-time `token_secret`) is what gates admission either
 * way. The frame adds confidentiality and header integrity, not authorization.
 */
export interface WorkerTransportEnvelope {
  readonly protocol_version?: number;
  readonly identity: SelfHostedWorkerIdentity;
  readonly [key: string]: unknown;
}

/** Read + shape-check the internal callback body. */
async function readWorkerBody(
  c: Context<AgentRuntimeEnv>,
  maxBytes: number,
): Promise<Record<string, unknown>> {
  const declaredLength = Number(c.req.header("content-length") ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new HttpError(
      413,
      "self_hosted_worker_payload_too_large",
      `request body exceeds maximum size of ${maxBytes} bytes`,
    );
  }
  const raw = await c.req.text();
  if (new TextEncoder().encode(raw).length > maxBytes) {
    throw new HttpError(
      413,
      "self_hosted_worker_payload_too_large",
      `request body exceeds maximum size of ${maxBytes} bytes`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new HttpError(
      400,
      "invalid_self_hosted_worker_transport",
      `invalid self-hosted worker transport JSON: ${String(error)}`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new HttpError(
      400,
      "invalid_self_hosted_worker_transport",
      "self-hosted worker transport body must be a JSON object",
    );
  }
  return parsed as Record<string, unknown>;
}

/** Shape-check the (possibly unsealed) transport document. */
function requireIdentityEnvelope(envelope: Record<string, unknown>): WorkerTransportEnvelope {
  const identity = envelope.identity;
  if (typeof identity !== "object" || identity === null || Array.isArray(identity)) {
    // Deliberately NOT 401: the caller presented no identity envelope at all,
    // which is a malformed frame, not a rejected credential. A tenant bearer
    // key never reaches this line — it is refused by the transport-security
    // gate above.
    throw new HttpError(
      400,
      "invalid_self_hosted_worker_transport",
      "self-hosted worker transport body must carry an identity envelope",
    );
  }
  if (
    envelope.protocol_version !== undefined &&
    (typeof envelope.protocol_version !== "number" || !Number.isInteger(envelope.protocol_version))
  ) {
    throw new HttpError(
      400,
      "invalid_self_hosted_worker_transport",
      "protocol_version must be an integer",
    );
  }
  return envelope as unknown as WorkerTransportEnvelope;
}

// ---------------------------------------------------------------------------
// The middleware
// ---------------------------------------------------------------------------

/** Resolve the dependency bundle or fail CLOSED. */
export function depsOrThrow(c: Context<AgentRuntimeEnv>): AgentRuntimeDeps {
  const existing = c.get("deps");
  if (existing !== undefined) return existing;
  const deps = resolveDeps(c.env);
  if (deps === undefined) {
    throw new HttpError(
      503,
      "agent_runtime_unavailable",
      "agent runtime dependencies are not bound; refusing to serve",
    );
  }
  c.set("deps", deps);
  return deps;
}

/**
 * PORT-TODO(`gateway/auth.rs::finalize_auth`): the ADMISSION half of Rust's
 * `authenticate()` is missing on this Worker, so the nine bearer operations it
 * owns are rate-limit-free and spend-free.
 *
 * In the Rust tree `/v1/agent-runs`, `/v1/agent-jobs/**` and `/v1/agents/**`
 * were served by the SAME process as `/v1/chat/completions` and went through
 * the same `authenticate()` → `finalize_auth` chain, which charges, in order:
 * `403 tenant_identity_required`, the lifecycle-suspension gate,
 * `503 quota_resolution_unavailable`, `403 quota_scope_disabled`,
 * `429 monthly_budget_exceeded`, `429 wallet_balance_exhausted`,
 * `429 rate_limit_exceeded` (the per-key RPM counter) and
 * `503 governance_counter_unavailable`.
 *
 * Splitting the data plane across Workers moved only the CREDENTIAL half here.
 * `apps/gateway/src/ratelimit/` is the port of the admission half and it is
 * mounted on the gateway alone: `grep -rn "rate_limit_exceeded\|
 * monthly_budget_exceeded\|wallet_balance_exhausted" apps/agent-runtime/src
 * apps/mcp/src` returns nothing. The suspension ladder below IS ported, so the
 * gap is specifically MONEY AND RATE, not identity. Consequence: a tenant whose
 * RPM cap and monthly budget stop it dead on `/v1/chat/completions` can submit
 * unbounded agent jobs on the same key, and each job then spends real provider
 * money through the gateway on the run's behalf.
 *
 * Not a platform limit. `rateLimit()` is ordinary Hono middleware over a DO
 * counter and a D1 quota source; what it needs here is the SAME counter
 * namespace as the gateway (a shared `RATE_LIMIT` DO binding or a Service
 * Binding into the gateway), because a per-Worker counter would give each
 * surface its own full quota rather than sharing one.
 */
/** The bearer leg. The ONLY consumer of the tenant API-key authority. */
async function bearerAuth(c: Context<AgentRuntimeEnv>, operation: ApiOperation): Promise<void> {
  const presented = extractApiKey(c.req.raw.headers);
  if (presented === null) {
    throw new HttpError(401, "missing_api_key", MISSING_API_KEY_MESSAGE);
  }
  const deps = depsOrThrow(c);
  const auth = resolveOrThrow(await deps.apiKeys.resolve(presented));

  const required = operation.auth.scope;
  if (required !== null && !hasScope(auth, required)) {
    throw new HttpError(403, "scope_denied", `API key is missing required scope ${required}`);
  }
  // A tenant credential that names no tenant cannot address tenant-scoped
  // state. Rust `CallerScope`: an unclassified credential is confined to a
  // tenant id that matches no row (#515), never promoted to platform root.
  if (!auth.platformOperator && (auth.tenancy.tenantId ?? "") === "") {
    throw new HttpError(
      403,
      "tenant_scope_denied",
      "API key names no tenant and cannot address tenant-scoped agent state",
    );
  }
  c.set("auth", auth);
}

/**
 * The internal leg. The ONLY consumer of the worker-plane credential authority.
 *
 * Note what is NOT here: any read of `Authorization`, `x-api-key`, or
 * {@link ApiKeyPort}. There is no code path from a tenant bearer key to a
 * `RegisteredSelfHostedWorker`.
 */
async function internalAuth(c: Context<AgentRuntimeEnv>): Promise<void> {
  const channel = resolveTransportChannel(c.req.raw);
  if (channel === null) {
    throw new HttpError(
      401,
      "invalid_self_hosted_worker_transport_security",
      `self-hosted worker transport requires ${TRANSPORT_SECURITY_HEADER}: ${TRANSPORT_SECURITY_MTLS} or ${TRANSPORT_SECURITY_SYMMETRIC_AEAD}`,
    );
  }
  const refusal = admitTransport(transportPosture(c.env.FG_REQUIRE_PRODUCTION_MTLS), channel);
  if (refusal !== null) throw refusal;

  const deps = depsOrThrow(c);
  const limits = deps.config.agentRuntime();
  const body = await readWorkerBody(c, limits.workerTransportBodyMaxBytes);

  // A sealed AEAD frame is opened BEFORE anything reads an identity out of it.
  // The registry does the opening because the frame key is derived from the
  // transport secret, which never leaves `ports.ts`.
  const sealed = readSealedFrame(body);
  let document = body;
  if (sealed !== undefined) {
    if (channel !== "symmetric_aead") {
      throw new HttpError(
        400,
        "invalid_self_hosted_worker_transport",
        `a sealed transport frame requires ${TRANSPORT_SECURITY_HEADER}: ${TRANSPORT_SECURITY_SYMMETRIC_AEAD}`,
      );
    }
    const opened = await deps.workerIdentities.unseal(sealed);
    if (opened.outcome === "rejected") {
      throw opened.failure.reason === "invalid_shape"
        ? new HttpError(400, "invalid_self_hosted_worker_transport", opened.failure.detail)
        : // An unopenable frame is a REJECTED CREDENTIAL, not a malformed one:
          // the sender did not hold the derived key. 401 matches the answer an
          // unknown worker gets, so the sealed path is not an oracle either.
          new HttpError(401, "invalid_self_hosted_worker_identity", opened.failure.detail);
    }
    document = opened.envelope;
  }

  const envelope = requireIdentityEnvelope(document);
  if (sealed !== undefined) {
    // Rust `decode_json` → `validate_identity`: the CLEARTEXT header selected
    // the registry row whose secret opened the frame, so the enclosed identity
    // must be that same worker. Without this, a frame could be attributed to
    // one worker and authorized by another's key schedule.
    const mismatch = frameIdentityMismatch(
      sealed.header,
      envelope.identity as unknown as Record<string, unknown>,
    );
    if (mismatch !== null) {
      throw new HttpError(
        400,
        "invalid_self_hosted_worker_transport",
        `self-hosted worker encrypted frame identity does not match enclosed request: ${mismatch}`,
      );
    }
  }
  // Rust security fix #113 (`validate_worker_identity`): identity expiry is
  // judged against the SERVER's trusted clock, so `observed_at_unix` is
  // overwritten UNCONDITIONALLY here. Honouring the caller's value would let a
  // worker whose registration has expired keep authenticating forever by
  // reporting `0` — or by omitting the field entirely.
  const resolution = await deps.workerIdentities.validate({
    ...envelope.identity,
    observed_at_unix: deps.clock.nowUnix(),
  });
  if (resolution.outcome === "rejected") throw workerIdentityError(resolution.failure);
  c.set("worker", resolution.worker);
  // Publish the PLAINTEXT document so the six callbacks read the unsealed
  // payload rather than re-parsing the ciphertext wrapper off the raw body.
  c.set("workerEnvelope", document);
}

/**
 * Contract-driven auth for every request this Worker serves.
 *
 * Order matters: match the contract FIRST, then dispatch on the declared
 * `auth.kind`. A path this Worker owns but with a method the contract does not
 * document is a 405 with `Allow`; a path it does not own is a 404.
 */
export const contractAuth: MiddlewareHandler<AgentRuntimeEnv> = async (c, next) => {
  const path = new URL(c.req.url).pathname;
  const matched = matchOperation(c.req.method, path);

  if (matched === undefined) {
    if (!isOwnedPath(path)) {
      throw new HttpError(404, "not_found", "resource not found");
    }
    const allowed = allowedMethods(path);
    if (allowed.length > 0) {
      throw new HttpError(
        405,
        "method_not_allowed",
        `method ${c.req.method} is not allowed on ${path}`,
        { allow: allowed.join(", ") },
      );
    }
    throw new HttpError(404, "not_found", "resource not found");
  }

  const { operation } = matched;
  c.set("operationId", operation.operationId);

  switch (operation.auth.kind) {
    case "bearer":
      await bearerAuth(c, operation);
      break;
    case "internal":
      await internalAuth(c);
      break;
    default:
      // No operation this Worker owns is `anonymous` or `method_dependent`.
      // Refusing rather than falling through keeps a future contract change
      // from silently opening a surface.
      throw new HttpError(
        500,
        "internal_error",
        `operation ${operation.operationId} declares unsupported auth kind ${operation.auth.kind}`,
      );
  }

  await next();
};

/** The authenticated tenant caller, for a bearer-guarded handler. */
export function requireAuth(c: Context<AgentRuntimeEnv>): AuthContext {
  const auth = c.get("auth");
  if (auth === undefined) {
    throw new HttpError(401, "missing_api_key", MISSING_API_KEY_MESSAGE);
  }
  return auth;
}

/** The tenant a bearer-guarded handler operates within. */
export function tenantIdOf(auth: AuthContext): string {
  const tenantId = auth.tenancy.tenantId ?? "";
  if (tenantId === "") {
    throw new HttpError(
      403,
      "tenant_scope_denied",
      "API key names no tenant and cannot address tenant-scoped agent state",
    );
  }
  return tenantId;
}
