/**
 * The delegation LINK — one signed "A authorised B" statement, and the wire
 * form a chain of them travels in (#691).
 *
 * ============================================================================
 * WHAT PROBLEM THIS SOLVES, STATED PRECISELY
 * ============================================================================
 *
 * An agent run acts with the caller's key. When agent A calls on behalf of user
 * U and then calls agent B, the gateway sees exactly ONE credential — B's — and
 * every audit answer downstream therefore names the last credential to touch
 * the request rather than the principal ultimately responsible. #677 and #678
 * built per-request cost attribution on top of that identity, so a chargeback
 * row can say "key_b spent $4,200" and cannot say "user U's session did".
 *
 * ## The thing that makes this a CHAIN and not a CLAIM
 *
 * A delegation the caller can WRITE is not evidence of anything. If the header
 * were `x-ferrogate-on-behalf-of: user:ceo`, any key holder could type it, and
 * the audit trail would record a fabrication with the same confidence it
 * records the truth. So every link here is SIGNED, the gateway VERIFIES rather
 * than trusts, and a link that fails any check refuses the request instead of
 * being dropped from the record.
 *
 * **What signs.** {@link ../delegation/sign.ts::mintDelegationLink}, running in
 * the delegation authority — the Worker that authenticated the DELEGATOR before
 * it agreed to issue the link (today `apps/agent-runtime`, when it spawns a
 * sub-agent on behalf of a caller it has already authenticated). The signature
 * is HMAC-SHA-256 over the exact transmitted `header.payload` bytes.
 *
 * **What verifies.** `../delegation/verify.ts::verifyDelegationChain`, called by
 * the gateway's `src/delegation/middleware.ts` on the authenticated request
 * path, before the request may spend anything.
 *
 * **Where the key lives.** One secret, `DELEGATION_SIGNING_KEY`, sourced from
 * the **Cloudflare Secrets Store** — the owner directive is that credentials,
 * including per-user ones, belong there once the fleet is fully on Cloudflare.
 * Secrets Store bindings are resolved at DEPLOY time, not at request time,
 * which is the constraint that shapes the two honest limitations below.
 *
 * ## Two honest limitations, stated here rather than implied away
 *
 *  1. **The signature is the AUTHORITY's, not the delegator's own private key.**
 *     Because a Secrets Store binding is deploy-time, there is no way to bind
 *     N per-agent private keys for an N that changes when a tenant creates an
 *     agent. So this is the RFC 8693 token-exchange shape: the delegator proves
 *     who it is to the mint with its OWN credential, and the mint — which the
 *     gateway trusts, and which is the only thing holding the key — signs a
 *     statement naming that delegator. What the signature proves is therefore
 *     "an authenticated delegator asked for this link", not "this keypair
 *     signed it". That is strictly stronger than a caller-written header and
 *     strictly weaker than delegator-held keys, and the format is deliberately
 *     compact-JWS so swapping HS256 for Ed25519/ES256 later is a change to the
 *     `alg` table and the key source, not to the chain semantics.
 *  2. **A chain proves AUTHORISATION, never BEHAVIOUR.** A verified chain says
 *     user U authorised agent A which authorised agent B. It says nothing about
 *     whether B did what it was asked, stayed on task, or was itself
 *     prompt-injected. Nothing in this directory should be read, or sold, as
 *     agent behavioural assurance.
 *
 * ## Why symmetric, and what that costs
 *
 * HMAC-SHA-256 is one `crypto.subtle.verify` per link (single-digit
 * microseconds on workerd) against ECDSA's hundreds, and this runs on every
 * delegated inference request. The cost is that any Worker holding the binding
 * can MINT as well as verify, so the binding is given only to the delegation
 * authority and the gateway. That is a deployment constraint, and it is the
 * reason limitation 1 above is written down instead of assumed.
 */
import { bytesToBase64Url, decodeBase64UrlJson } from "../oidc/base64url.js";

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/**
 * The format version carried in every payload.
 *
 * A verifier that meets a version it does not know REFUSES, rather than
 * ignoring the fields it does not recognise. An unknown version may have added
 * a constraint (a new bound, a new claim that narrows authority), and a lenient
 * reader would silently discard exactly the field that made the link safe.
 */
export const DELEGATION_FORMAT_VERSION = 1;

/** The JOSE `typ` this format claims, so a link cannot be replayed as an ID token. */
export const DELEGATION_JWS_TYPE = "ferrogate-delegation+jws";

/**
 * The only signature algorithm this format accepts, chosen from an ALLOW-LIST
 * and never from the token — the rule `oidc/jws.ts` states and this file obeys
 * for the same reason: `alg: "none"` is a forgery primitive, and reading the
 * algorithm out of attacker-controlled bytes is how algorithm confusion works.
 */
export const DELEGATION_JWS_ALGORITHM = "HS256";

/** The separator between links in the header value. */
export const DELEGATION_LINK_SEPARATOR = "~";

/** The request header a chain travels in. */
export const DELEGATION_HEADER = "x-ferrogate-delegation";

/**
 * The separator in the rendered principal PATH (`user:u>agent:a>agent:b`).
 *
 * `>` reads as "delegated to", is not legal inside a principal (which is
 * `{kind}:{id}` over a restricted alphabet), and is safe in a URL query value
 * and in a CSV cell — the path is written into `request_logs.delegation_chain`
 * and exported to finance, so a separator that needed escaping in either place
 * would eventually corrupt a chargeback file.
 */
export const DELEGATION_PATH_SEPARATOR = ">";

/**
 * Maximum links in one chain.
 *
 * **Why a bound at all.** Verification is O(depth): one HMAC verify and one
 * revocation lookup per link, on the request path, decided entirely by bytes
 * the caller supplies. An unbounded chain is therefore a denial-of-service on
 * our own verifier — a single 1 MiB header would be tens of thousands of
 * signature verifications before the request is even refused.
 *
 * **Why 8.** Real agent topologies are shallow: an orchestrator delegating to a
 * specialist that delegates to a tool-runner is depth 3, and published
 * multi-agent patterns (planner → worker → tool) do not exceed 4. 8 is double
 * the deepest shape anyone has asked for, which leaves room for a topology we
 * have not seen without leaving room for an attack; and it bounds the worst
 * case at 8 verifies plus one batched revocation read, which is a few hundred
 * microseconds rather than an unbounded amount.
 *
 * A chain longer than this is REFUSED, never truncated. Truncating would drop
 * the leaf — the link that binds the chain to the presenting credential — and
 * so would turn a too-deep chain into an unbound one.
 */
export const MAX_DELEGATION_DEPTH = 8;

/**
 * Maximum bytes of the raw header, checked BEFORE anything is split or parsed.
 *
 * The depth bound alone is not enough: `"a".repeat(1_000_000)` is one "link"
 * and would be base64-decoded and JSON-parsed before the depth check could ever
 * fire. This is one `.length` comparison on a string the runtime already
 * materialised, so an oversized header costs a comparison and nothing else.
 *
 * 8 KiB is roughly double the depth-8 worst case (~400 B per link once
 * base64url-expanded) and comfortably under the ~16 KiB per-header ceiling
 * edge proxies enforce, so a legal chain can never be one that the network
 * would have truncated anyway.
 */
export const MAX_DELEGATION_HEADER_BYTES = 8 * 1024;

/**
 * Maximum lifetime of a single link, in seconds.
 *
 * **Why a bound at all.** A signed statement with no freshness is a replay
 * primitive: one captured header would authorise its bearer for as long as the
 * mint said, and there is no revocation-free way to take it back. Freshness is
 * what turns "compromise is permanent" into "compromise is bounded".
 *
 * **Why 900 (15 minutes).** A delegation is issued FOR AN AGENT RUN, not as a
 * standing grant; 15 minutes covers a long multi-step run (tool calls, retries,
 * a slow reasoning model) without becoming a session token. Paired with the
 * presenter binding — a replayed chain also needs the leaf's API key, see
 * `verify.ts` — the practical replay window for a stolen header alone is zero
 * and for a stolen header PLUS a stolen key is at most this.
 *
 * **What this is not.** It is not per-request one-time use. Burning a nonce per
 * request would need a Durable Object or KV write on the hot path of every
 * delegated inference call; the deliberate trade is a bounded window plus the
 * presenter binding plus revocation, and this comment exists so nobody reads
 * the feature as stronger than it is.
 */
export const MAX_DELEGATION_LIFETIME_SECONDS = 900;

/**
 * Clock tolerance, in seconds. Deliberately the same 60 s
 * `oidc/claims.ts::ID_TOKEN_CLOCK_SKEW_SECONDS` allows an IdP: the mint and the
 * gateway are different Workers in different colos, and two values for "how far
 * apart may two of our clocks be" in one package would be a bug waiting to be
 * argued about.
 */
export const DELEGATION_CLOCK_SKEW_SECONDS = 60;

/**
 * A principal — `"{kind}:{id}"`, the SAME namespacing rule
 * `apps/agent-runtime/src/admission/keys.ts` enforces on counter keys, and for
 * a related reason: an unnamespaced identifier can be made to collide with a
 * differently-typed one. A tenant that could name an agent `user:ceo` would be
 * able to render a chain whose path reads as a human's authority.
 *
 * Only the FIRST `:` separates, so an id containing a colon stays entirely
 * inside the id half and can never be re-read as a kind.
 */
export const DELEGATION_PRINCIPAL_KINDS = ["user", "agent", "service", "key"] as const;
export type DelegationPrincipalKind = (typeof DELEGATION_PRINCIPAL_KINDS)[number];

/** `{kind, id}` when `value` is a legal principal, else `null`. */
export function parseDelegationPrincipal(
  value: unknown,
): { readonly kind: DelegationPrincipalKind; readonly id: string } | null {
  if (typeof value !== "string") return null;
  const separator = value.indexOf(":");
  if (separator <= 0) return null;
  const kind = DELEGATION_PRINCIPAL_KINDS.find(
    (candidate) => candidate === value.slice(0, separator),
  );
  if (kind === undefined) return null;
  const id = value.slice(separator + 1);
  // A blank id, or one carrying the path separator, would make the rendered
  // chain ambiguous — `user:>agent:a` cannot be read back.
  if (id === "" || id.includes(DELEGATION_PATH_SEPARATOR)) return null;
  return { kind, id };
}

/** `true` iff `value` is a legal principal. */
export function isDelegationPrincipal(value: unknown): boolean {
  return parseDelegationPrincipal(value) !== null;
}

// ---------------------------------------------------------------------------
// The claims
// ---------------------------------------------------------------------------

/**
 * One link's payload.
 *
 * Field names track RFC 8693 / RFC 7519 where those specs already have a name
 * for the concept (`jti`, `iss`, `sub`, `act`, `iat`, `exp`, `scope`), because
 * the issue's instruction is to build the RECORD now and adopt the wire format
 * once `draft-aap-oauth-profile` settles — and a record whose field names
 * already match the draft is a rename away from being the protocol, rather than
 * a translation layer away.
 */
export interface DelegationClaims {
  /** {@link DELEGATION_FORMAT_VERSION}. */
  readonly v: number;
  /** Unique link id. THE REVOCATION HANDLE — see `revocation.ts`. */
  readonly jti: string;
  /** The mint that issued this link. */
  readonly iss: string;
  /** The tenant this delegation is confined to. A cross-tenant chain is refused. */
  readonly tenant: string;
  /** RFC 8693 `act`: the DELEGATOR — who granted this authority. */
  readonly act: string;
  /** The DELEGATE — who receives it. */
  readonly sub: string;
  /**
   * The api-key id the delegate authenticates with.
   *
   * Only the LEAF link's value is PROVEN by a request (it must equal the
   * credential that presented the chain — the binding that stops a captured
   * header from being replayed by a different key). The inner links' values are
   * recorded evidence of which credential each hop used; the gateway cannot
   * re-prove them, because those hops happened on earlier requests. The
   * distinction is stated rather than blurred: an audit reader must know which
   * half of the row is proof and which half is testimony.
   */
  readonly sub_key: string;
  /** The scopes this link grants. Never empty — see {@link parseDelegationClaims}. */
  readonly scope: readonly string[];
  readonly iat: number;
  readonly exp: number;
  /** The parent link's `jti`. Absent on the root link, and only there. */
  readonly prev?: string | undefined;
  /** The agent run this delegation was issued for, when there is one. */
  readonly run?: string | undefined;
}

/** Why a payload was rejected before any signature was even considered. */
export type DelegationClaimsFailure =
  | "not_an_object"
  | "version"
  | "jti"
  | "iss"
  | "tenant"
  | "act"
  | "sub"
  | "sub_key"
  | "scope"
  | "iat"
  | "exp"
  | "prev"
  | "run";

export type DelegationClaimsResult =
  | { readonly ok: true; readonly claims: DelegationClaims }
  | { readonly ok: false; readonly field: DelegationClaimsFailure };

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 200;
}

function finiteUnixSecond(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

/**
 * Structural validation of one decoded payload. Total; never throws.
 *
 * Runs BEFORE the signature is checked in {@link verifyDelegationChain}? No —
 * deliberately after. Parsing attacker-controlled JSON is cheap and safe here
 * (it is already a plain object by this point), but the ORDER that matters is
 * that nothing is BELIEVED before the signature verifies; this function only
 * decides whether the bytes are shaped like claims.
 */
export function parseDelegationClaims(input: unknown): DelegationClaimsResult {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, field: "not_an_object" };
  }
  const raw = input as Record<string, unknown>;

  if (raw.v !== DELEGATION_FORMAT_VERSION) return { ok: false, field: "version" };
  if (!nonEmptyString(raw.jti)) return { ok: false, field: "jti" };
  if (!nonEmptyString(raw.iss)) return { ok: false, field: "iss" };
  if (!nonEmptyString(raw.tenant)) return { ok: false, field: "tenant" };
  if (!isDelegationPrincipal(raw.act)) return { ok: false, field: "act" };
  if (!isDelegationPrincipal(raw.sub)) return { ok: false, field: "sub" };
  if (!nonEmptyString(raw.sub_key)) return { ok: false, field: "sub_key" };

  const scope = raw.scope;
  // An EMPTY scope array is refused rather than read as "grants nothing" or
  // "grants everything". Both readings are defensible, which is exactly why the
  // format must not contain the question: `ports.ts::hasScope` already gives an
  // empty CREDENTIAL scope set a third meaning ("data-plane scopes only"), and
  // a delegation link that inherited that meaning by accident would widen
  // authority through an omission.
  if (!Array.isArray(scope) || scope.length === 0 || scope.length > 64) {
    return { ok: false, field: "scope" };
  }
  if (!scope.every((entry) => nonEmptyString(entry))) return { ok: false, field: "scope" };

  if (!finiteUnixSecond(raw.iat)) return { ok: false, field: "iat" };
  if (!finiteUnixSecond(raw.exp)) return { ok: false, field: "exp" };
  if (raw.exp <= raw.iat) return { ok: false, field: "exp" };

  const prev = raw.prev;
  if (prev !== undefined && !nonEmptyString(prev)) return { ok: false, field: "prev" };
  const run = raw.run;
  if (run !== undefined && !nonEmptyString(run)) return { ok: false, field: "run" };

  return {
    ok: true,
    claims: {
      v: DELEGATION_FORMAT_VERSION,
      jti: raw.jti as string,
      iss: raw.iss as string,
      tenant: raw.tenant as string,
      act: raw.act as string,
      sub: raw.sub as string,
      sub_key: raw.sub_key as string,
      scope: (scope as string[]).slice(),
      iat: raw.iat as number,
      exp: raw.exp as number,
      ...(prev === undefined ? {} : { prev: prev as string }),
      ...(run === undefined ? {} : { run: run as string }),
    },
  };
}

// ---------------------------------------------------------------------------
// Compact encoding
// ---------------------------------------------------------------------------

/** The fixed JOSE header this format emits, and the only one it accepts. */
export const DELEGATION_JWS_HEADER = {
  alg: DELEGATION_JWS_ALGORITHM,
  typ: DELEGATION_JWS_TYPE,
} as const;

const TEXT = new TextEncoder();

/** `base64url(utf8(JSON.stringify(value)))`. */
export function encodeSegment(value: unknown): string {
  return bytesToBase64Url(TEXT.encode(JSON.stringify(value)));
}

/**
 * The bytes a signature covers: the TRANSMITTED `header.payload` string.
 *
 * Signing the transmitted bytes rather than a re-serialised object is what
 * makes canonical JSON unnecessary — there is no re-encoding step at which a
 * verifier and a signer could disagree about key order, number formatting or
 * unicode escaping, which is a whole class of signature-bypass bug that
 * canonicalisation schemes exist to fight and this format simply does not have.
 */
export function signingInput(headerSegment: string, payloadSegment: string): Uint8Array {
  return TEXT.encode(`${headerSegment}.${payloadSegment}`);
}

/** A compact link split into its three segments, or `null` if it is not one. */
export interface SplitDelegationLink {
  readonly headerSegment: string;
  readonly payloadSegment: string;
  readonly signature: string;
}

/**
 * Split one compact link, enforcing the header allow-list.
 *
 * The `alg`/`typ` check happens HERE, before a key is imported and before the
 * payload is believed, so a token asserting `alg: "none"` is refused by
 * structure rather than by a downstream branch that could be reordered.
 */
export function splitDelegationLink(token: string): SplitDelegationLink | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerSegment, payloadSegment, signature] = parts as [string, string, string];
  if (headerSegment === "" || payloadSegment === "" || signature === "") return null;

  const header = decodeBase64UrlJson(headerSegment);
  if (header === null) return null;
  if (header.alg !== DELEGATION_JWS_ALGORITHM) return null;
  if (header.typ !== DELEGATION_JWS_TYPE) return null;

  return { headerSegment, payloadSegment, signature };
}

/** Render a verified chain's principal path: `user:u>agent:a>agent:b`. */
export function delegationPath(links: readonly DelegationClaims[]): string {
  if (links.length === 0) return "";
  const first = links[0] as DelegationClaims;
  return [first.act, ...links.map((link) => link.sub)].join(DELEGATION_PATH_SEPARATOR);
}
