/**
 * Minting and signature verification — the half that holds the key.
 *
 * ## Where the key comes from, and what happens when it is absent
 *
 * One secret, `DELEGATION_SIGNING_KEY`, bound from the **Cloudflare Secrets
 * Store** at DEPLOY time (the owner directive: credentials belong in Secrets
 * Store once the fleet is fully on Cloudflare; a Secrets Store binding is
 * resolved when the Worker is deployed, not per request). In `wrangler dev` and
 * in the test pool it is an ordinary var, which is the same shape the resolver
 * reads.
 *
 * A deployment with NO key bound cannot verify a chain. That case is
 * `unavailable` here and a **503** at the gateway, never an admission and never
 * a silently-ignored header: "the verifier is not configured" must not be a way
 * to have a delegation header treated as decoration. Requests carrying no
 * header are unaffected, so an operator who has not adopted delegation pays
 * nothing.
 *
 * ## Why a minimum key length is enforced
 *
 * HMAC accepts a key of any length, including one byte, and `crypto.subtle`
 * will happily import it. A short shared secret is brute-forcible offline from
 * a single captured link, and every forged chain that follows verifies
 * perfectly — the failure would be invisible precisely because the signature
 * check still "works". 32 bytes is the SHA-256 block-security level and the
 * length `crypto.randomUUID()`-style generators already produce.
 */
import { base64UrlToBytes, bytesToBase64Url } from "../oidc/base64url.js";
import {
  DELEGATION_CLOCK_SKEW_SECONDS,
  DELEGATION_FORMAT_VERSION,
  DELEGATION_JWS_HEADER,
  DELEGATION_LINK_SEPARATOR,
  type DelegationClaims,
  MAX_DELEGATION_LIFETIME_SECONDS,
  encodeSegment,
  isDelegationPrincipal,
  signingInput,
  splitDelegationLink,
} from "./link.js";

/** The minimum shared-secret length, in bytes. See the header comment. */
export const MIN_DELEGATION_KEY_BYTES = 32;

/** A key that could not be used, said out loud rather than returned as `null`. */
export type DelegationKeyResolution =
  | { readonly ok: true; readonly key: CryptoKey }
  | { readonly ok: false; readonly detail: string };

const TEXT = new TextEncoder();

/**
 * Import the shared secret as an HMAC-SHA-256 key usable for both sign and
 * verify.
 *
 * The secret is interpreted as UTF-8 bytes, not as base64: an operator pasting
 * a secret into the Secrets Store types characters, and silently base64-decoding
 * whatever they typed would give two deployments different keys from the same
 * visible value whenever the string happened to be valid base64.
 */
export async function importDelegationKey(secret: string): Promise<DelegationKeyResolution> {
  const bytes = TEXT.encode(secret);
  if (bytes.byteLength < MIN_DELEGATION_KEY_BYTES) {
    return {
      ok: false,
      detail: `DELEGATION_SIGNING_KEY is ${bytes.byteLength} bytes; at least ${MIN_DELEGATION_KEY_BYTES} are required, because a shorter shared secret is recoverable offline from one captured link and every forgery after that verifies`,
    };
  }
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      bytes as unknown as ArrayBuffer,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
    return { ok: true, key };
  } catch (error) {
    return { ok: false, detail: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * Verify one compact link's signature.
 *
 * `crypto.subtle.verify` is used rather than "compute and compare", because the
 * comparison it does internally is constant-time; a `===` on two base64 strings
 * is not, and a timing oracle on a signature check is a forgery oracle given
 * enough attempts.
 *
 * Returns `false` for every failure, including a malformed signature segment.
 * Nothing throws: a caller must never be able to mistake an exception path for
 * a verified one.
 */
export async function verifyDelegationSignature(
  key: CryptoKey,
  headerSegment: string,
  payloadSegment: string,
  signature: string,
): Promise<boolean> {
  const bytes = base64UrlToBytes(signature);
  if (bytes === null) return false;
  try {
    return await crypto.subtle.verify(
      "HMAC",
      key,
      bytes as unknown as ArrayBuffer,
      signingInput(headerSegment, payloadSegment) as unknown as ArrayBuffer,
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Minting
// ---------------------------------------------------------------------------

/** What a caller of {@link mintDelegationLink} must state. */
export interface DelegationGrant {
  readonly jti: string;
  readonly iss: string;
  readonly tenant: string;
  /** The DELEGATOR, already authenticated by the mint. */
  readonly act: string;
  /** The DELEGATE. */
  readonly sub: string;
  /** The api-key id the delegate will authenticate with. */
  readonly subKey: string;
  readonly scope: readonly string[];
  readonly issuedAtUnix: number;
  readonly lifetimeSeconds: number;
  /** The parent link, when this extends an existing chain. */
  readonly parent?: DelegationClaims | undefined;
  readonly run?: string | undefined;
}

export type DelegationMintResult =
  | { readonly ok: true; readonly token: string; readonly claims: DelegationClaims }
  | { readonly ok: false; readonly reason: DelegationMintFailure; readonly detail: string };

export type DelegationMintFailure =
  | "invalid_principal"
  | "invalid_scope"
  | "scope_widened"
  | "lifetime_excessive"
  | "outlives_delegator"
  | "delegator_mismatch"
  | "tenant_mismatch";

/**
 * `true` iff every scope in `narrower` is held by `wider`.
 *
 * `"*"` in the WIDER set holds everything, mirroring `ports.ts::hasScope`'s
 * `WILDCARD_SCOPE`. `"*"` in the NARROWER set is only held by a wider set that
 * also has `"*"` — so a link cannot promote itself to the wildcard, which is the
 * single most valuable widening an attacker could attempt.
 *
 * Note what is deliberately absent: prefix matching. `admin.read` does NOT
 * imply `admin.read.keys`, because `hasScope` does not imply it either, and a
 * subset rule more generous than the credential check it guards would let a
 * chain reach an operation the credential itself could not.
 */
export function delegationScopeSubset(
  narrower: readonly string[],
  wider: readonly string[],
): boolean {
  if (wider.includes("*")) return true;
  return narrower.every((scope) => wider.includes(scope));
}

/**
 * Issue one signed link.
 *
 * **Attenuation is enforced here as well as at the verifier, and the verifier
 * is the one that matters.** A mint-only check protects an honest mint from
 * issuing a bad link; it protects nothing against a mint that is compromised,
 * buggy, or simply a different version. The verifier re-derives the same
 * predicate over the whole chain from the signed bytes, so this check is a
 * usability control ("you asked for something you cannot have, here is why")
 * and the verifier's is the security control.
 */
export async function mintDelegationLink(
  key: CryptoKey,
  grant: DelegationGrant,
): Promise<DelegationMintResult> {
  if (!isDelegationPrincipal(grant.act) || !isDelegationPrincipal(grant.sub)) {
    return {
      ok: false,
      reason: "invalid_principal",
      detail: `act ${JSON.stringify(grant.act)} and sub ${JSON.stringify(grant.sub)} must both be "{kind}:{id}"`,
    };
  }
  if (grant.scope.length === 0) {
    return {
      ok: false,
      reason: "invalid_scope",
      detail: "a delegation must grant at least one scope",
    };
  }
  if (grant.lifetimeSeconds <= 0 || grant.lifetimeSeconds > MAX_DELEGATION_LIFETIME_SECONDS) {
    return {
      ok: false,
      reason: "lifetime_excessive",
      detail: `lifetime ${grant.lifetimeSeconds}s is outside (0, ${MAX_DELEGATION_LIFETIME_SECONDS}]`,
    };
  }

  const exp = grant.issuedAtUnix + grant.lifetimeSeconds;
  const parent = grant.parent;
  if (parent !== undefined) {
    if (parent.tenant !== grant.tenant) {
      return {
        ok: false,
        reason: "tenant_mismatch",
        detail: `parent link belongs to tenant ${parent.tenant}, not ${grant.tenant}`,
      };
    }
    // The delegator of the new link must be the delegate of the parent. A mint
    // that skipped this could issue a chain in which B grants authority it was
    // never given by A, and the path would still render as A>B>C.
    if (parent.sub !== grant.act) {
      return {
        ok: false,
        reason: "delegator_mismatch",
        detail: `parent delegated to ${parent.sub}, so ${grant.act} cannot extend the chain`,
      };
    }
    if (!delegationScopeSubset(grant.scope, parent.scope)) {
      return {
        ok: false,
        reason: "scope_widened",
        detail: `cannot delegate ${JSON.stringify(grant.scope)}; the delegator holds only ${JSON.stringify(parent.scope)}`,
      };
    }
    if (exp > parent.exp) {
      return {
        ok: false,
        reason: "outlives_delegator",
        detail: `a delegated link may not outlive its delegator (parent exp ${parent.exp}, requested ${exp})`,
      };
    }
  }

  const claims: DelegationClaims = {
    v: DELEGATION_FORMAT_VERSION,
    jti: grant.jti,
    iss: grant.iss,
    tenant: grant.tenant,
    act: grant.act,
    sub: grant.sub,
    sub_key: grant.subKey,
    scope: grant.scope.slice(),
    iat: grant.issuedAtUnix,
    exp,
    ...(parent === undefined ? {} : { prev: parent.jti }),
    ...(grant.run === undefined ? {} : { run: grant.run }),
  };

  const headerSegment = encodeSegment(DELEGATION_JWS_HEADER);
  const payloadSegment = encodeSegment(claims);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    signingInput(headerSegment, payloadSegment) as unknown as ArrayBuffer,
  );
  const token = `${headerSegment}.${payloadSegment}.${bytesToBase64Url(new Uint8Array(signature))}`;
  return { ok: true, token, claims };
}

/**
 * Join links into the header value a client presents.
 *
 * ROOT FIRST. The order is part of the format: the verifier walks root → leaf
 * accumulating attenuation, and a chain whose order the verifier had to infer
 * would be a chain whose attenuation direction an attacker could choose.
 */
export function encodeDelegationChain(tokens: readonly string[]): string {
  return tokens.join(DELEGATION_LINK_SEPARATOR);
}

/** Re-export so a caller building a chain never has to re-implement the split. */
export { splitDelegationLink, DELEGATION_CLOCK_SKEW_SECONDS };
