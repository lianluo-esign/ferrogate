/**
 * Chain-building fixtures for the #691 suite.
 *
 * Two builders, and the difference between them is the point of the whole
 * issue:
 *
 *  - {@link chain} mints through the real `mintDelegationLink`, i.e. what an
 *    HONEST delegation authority produces. It refuses to issue a widened or
 *    over-long link, so it cannot be used to construct the attacks;
 *  - {@link forge} signs ARBITRARY claims with the same key, i.e. what a
 *    compromised or buggy mint — or an attacker who has the shared secret —
 *    would produce. Everything the verifier claims to enforce has to be
 *    falsifiable against `forge`, because a rule that only the mint enforces is
 *    a rule that protects nobody.
 */
import {
  DELEGATION_FORMAT_VERSION,
  DELEGATION_JWS_HEADER,
  type DelegationClaims,
  bytesToBase64Url,
  encodeDelegationChain,
  encodeSegment,
  importDelegationKey,
  mintDelegationLink,
  signingInput,
} from "@ferrogate/identity";

/** ≥ 32 bytes — `importDelegationKey` refuses anything shorter. */
export const SIGNING_SECRET = "delegation-test-secret-0123456789abcdef";
/** A DIFFERENT key of legal length: what a caller who wrote its own chain has. */
export const ATTACKER_SECRET = "attacker-forged-secret-0123456789abcdef";

export const TENANT = "tenant_a";
export const MINT = "ferrogate/agent-runtime";

export async function keyFrom(secret: string): Promise<CryptoKey> {
  const resolved = await importDelegationKey(secret);
  if (!resolved.ok) throw new Error(resolved.detail);
  return resolved.key;
}

/** One honest link's inputs. */
export interface LinkSpec {
  readonly jti: string;
  readonly act: string;
  readonly sub: string;
  readonly subKey: string;
  readonly scope: readonly string[];
  readonly lifetimeSeconds?: number;
  readonly run?: string;
  readonly tenant?: string;
}

export interface BuiltChain {
  readonly header: string;
  readonly tokens: readonly string[];
  readonly claims: readonly DelegationClaims[];
}

/** Mint a chain the honest authority would issue. Root first. */
export async function chain(
  secret: string,
  specs: readonly LinkSpec[],
  nowUnix: number,
): Promise<BuiltChain> {
  const key = await keyFrom(secret);
  const tokens: string[] = [];
  const claims: DelegationClaims[] = [];
  let parent: DelegationClaims | undefined;
  for (const spec of specs) {
    const minted = await mintDelegationLink(key, {
      jti: spec.jti,
      iss: MINT,
      tenant: spec.tenant ?? TENANT,
      act: spec.act,
      sub: spec.sub,
      subKey: spec.subKey,
      scope: spec.scope,
      issuedAtUnix: nowUnix,
      lifetimeSeconds: spec.lifetimeSeconds ?? 600,
      parent,
      ...(spec.run === undefined ? {} : { run: spec.run }),
    });
    if (!minted.ok) throw new Error(`${minted.reason}: ${minted.detail}`);
    tokens.push(minted.token);
    claims.push(minted.claims);
    parent = minted.claims;
  }
  return { header: encodeDelegationChain(tokens), tokens, claims };
}

/**
 * Sign arbitrary claims — the compromised/buggy mint.
 *
 * Deliberately does NO validation: every constraint the verifier enforces has
 * to be reachable from here, or the corresponding test would be proving that
 * `mintDelegationLink` refuses to build the attack rather than that the gateway
 * refuses to serve it.
 */
export async function forge(
  secret: string,
  claims: Record<string, unknown>,
): Promise<{ token: string; claims: Record<string, unknown> }> {
  const key = await keyFrom(secret);
  const payload = { v: DELEGATION_FORMAT_VERSION, iss: MINT, tenant: TENANT, ...claims };
  const headerSegment = encodeSegment(DELEGATION_JWS_HEADER);
  const payloadSegment = encodeSegment(payload);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    signingInput(headerSegment, payloadSegment) as unknown as ArrayBuffer,
  );
  return {
    token: `${headerSegment}.${payloadSegment}.${bytesToBase64Url(new Uint8Array(signature))}`,
    claims: payload,
  };
}
