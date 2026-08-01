/**
 * The OIDC discovery document (`/.well-known/openid-configuration`).
 *
 * NOT cached, on purpose. It is one fetch per authorize/callback leg, and its
 * contents are the three endpoint URLs this service is about to send an
 * authorization code and a client secret to — precisely the values that must
 * not be stale if an IdP migrates hosts. The JWKS behind it IS cached (see
 * `jwks.ts`), because that is the per-request hot path and its contents are
 * keys, which have a defined rotation story.
 */
import type { FetchLike } from "../ports.js";

export interface OidcDiscoveryDocument {
  issuer: string | null;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
}

function httpsUrl(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    // https only: the token leg carries the client secret and the JWKS leg
    // carries the keys every login is verified against, so plaintext for
    // either is a downgrade an operator should not be able to configure into.
    return new URL(value).protocol === "https:" ? value : null;
  } catch {
    return null;
  }
}

/**
 * Fetches and validates the discovery document for `issuer`. Returns `null` on
 * ANY failure (unreachable, non-2xx, not JSON, missing or non-https endpoint)
 * — the caller turns that into a refusal.
 */
export async function fetchOidcDiscovery(
  fetchImpl: FetchLike,
  issuer: string,
): Promise<OidcDiscoveryDocument | null> {
  const url = `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
  let response: Response;
  try {
    response = await fetchImpl(url, { method: "GET", headers: { accept: "application/json" } });
  } catch {
    return null;
  }
  if (!response.ok) return null;
  let document: unknown;
  try {
    document = await response.json();
  } catch {
    return null;
  }
  if (typeof document !== "object" || document === null) return null;
  const raw = document as Record<string, unknown>;
  const authorizationEndpoint = httpsUrl(raw.authorization_endpoint);
  const tokenEndpoint = httpsUrl(raw.token_endpoint);
  const jwksUri = httpsUrl(raw.jwks_uri);
  if (!authorizationEndpoint || !tokenEndpoint || !jwksUri) return null;
  return {
    issuer: typeof raw.issuer === "string" ? raw.issuer : null,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
  };
}
