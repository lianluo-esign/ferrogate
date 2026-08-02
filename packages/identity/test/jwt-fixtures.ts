/**
 * Real WebCrypto key material + real JWS signing for the OIDC tests.
 *
 * Deliberately NOT a hand-rolled fake: the fixtures mint keys and signatures
 * with the same `crypto.subtle` primitives the verifier under test uses, so a
 * token that verifies here verifies on workerd. A fixture that "signed" by
 * concatenating strings would let a verifier that never calls
 * `crypto.subtle.verify` pass every test in this suite.
 */

export interface SigningKey {
  /** The private half — used only to mint fixtures. */
  readonly privateKey: CryptoKey;
  /** The public half in JWKS form, `kid`/`alg`/`use` stamped. */
  readonly jwk: JsonWebKey & { kid: string; alg: string; use: string };
  readonly kid: string;
  readonly alg: string;
}

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlJson(value: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(value)));
}

/** Mints an RS256 signing key with the given `kid`. */
export async function generateRs256Key(kid: string): Promise<SigningKey> {
  const pair = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  // Strip the private-only members `exportKey` never emits for a public key,
  // and stamp the JWKS metadata an IdP publishes.
  return {
    privateKey: pair.privateKey,
    jwk: { ...jwk, kid, alg: "RS256", use: "sig" },
    kid,
    alg: "RS256",
  };
}

/** Mints an ES256 signing key with the given `kid`. */
export async function generateEs256Key(kid: string): Promise<SigningKey> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return {
    privateKey: pair.privateKey,
    jwk: { ...jwk, kid, alg: "ES256", use: "sig" },
    kid,
    alg: "ES256",
  };
}

/**
 * Signs a compact JWS with `key`. `headerOverrides` lets a test forge a header
 * (a wrong `kid`, `alg: "none"`, a missing `kid`) while the signature stays a
 * real signature over the real signing input.
 */
export async function signJwt(
  key: SigningKey,
  payload: Record<string, unknown>,
  headerOverrides: Record<string, unknown> = {},
): Promise<string> {
  const header = { alg: key.alg, typ: "JWT", kid: key.kid, ...headerOverrides };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const algorithm =
    key.alg === "ES256"
      ? { name: "ECDSA", hash: "SHA-256" }
      : { name: "RSASSA-PKCS1-v1_5" as const };
  const signature = new Uint8Array(
    await crypto.subtle.sign(algorithm, key.privateKey, new TextEncoder().encode(signingInput)),
  );
  return `${signingInput}.${b64url(signature)}`;
}

/** An unsigned `alg: "none"` token — the classic JWS downgrade. */
export function unsignedJwt(payload: Record<string, unknown>, kid = "k1"): string {
  return `${b64urlJson({ alg: "none", typ: "JWT", kid })}.${b64urlJson(payload)}.`;
}

/** A JWKS document containing the public halves of `keys`. */
export function jwksDocument(keys: readonly SigningKey[]): { keys: JsonWebKey[] } {
  return { keys: keys.map((key) => key.jwk) };
}
