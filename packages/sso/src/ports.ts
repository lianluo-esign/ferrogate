/**
 * The seams `apps/control-plane` must fill.
 *
 * This package holds the SAML PROTOCOL and nothing else. It deliberately does
 * not know about D1, sessions, admin users, memberships or gateway API keys —
 * `sso.rs::complete_sso_login` (the tail shared with OIDC: JIT provisioning,
 * the cross-tenant account-takeover guard, the tier-scoped key mint, session
 * issuance) belongs to the control plane, which owns those tables. `handleSamlAcs`
 * therefore stops at a validated identity and hands it over.
 */

/**
 * `ferrogate_storage::StoredSsoProviderConfig`. The OIDC fields are carried,
 * unread by this package, so the control plane can persist ONE row per tenant
 * exactly as the Rust service did — a second table would let a tenant be
 * configured for both protocols at once, which the `provider_kind` discriminant
 * exists to prevent.
 */
export interface StoredSsoProviderConfig {
  readonly tenantId: string;
  readonly providerKind: string;
  readonly defaultRole: string;
  readonly groupRoleMapping: Record<string, string>;
  readonly oidcIssuer: string | null;
  readonly oidcClientId: string | null;
  readonly oidcClientSecretRef: string | null;
  readonly oidcRedirectUri: string | null;
  readonly oidcGroupClaim: string | null;
  readonly samlIdpEntityId: string | null;
  readonly samlIdpSsoUrl: string | null;
  readonly samlIdpCertificate: string | null;
  readonly samlSpEntityId: string | null;
  readonly samlAcsUrl: string | null;
  readonly samlEmailAttribute: string | null;
  readonly samlNameAttribute: string | null;
  readonly samlGroupsAttribute: string | null;
  readonly createdAtUnix: number;
  readonly updatedAtUnix: number;
}

/** `ferrogate_storage::StoredSsoPendingFlow`. */
export interface SsoPendingFlow {
  readonly state: string;
  readonly tenantId: string;
  readonly providerKind: string;
  /** OIDC PKCE verifier; always `null` for a SAML flow. */
  readonly codeVerifier: string | null;
  /** The `AuthnRequest` ID this flow expects back in `InResponseTo`. */
  readonly requestId: string | null;
  readonly createdAtUnix: number;
  readonly expiresAtUnix: number;
}

export interface SsoProviderConfigStore {
  /** `null` when the tenant has no SSO config, or the store errored. */
  get(tenantId: string): Promise<StoredSsoProviderConfig | null>;
}

/**
 * The pending-flow store. **`take` is the SAML replay defence** and its
 * contract is not negotiable:
 *
 *  * it returns the flow ONLY if `state` matches and `expiresAtUnix > nowUnix`;
 *  * it CONSUMES the flow — a second `take` of the same state returns `null`,
 *    even if the two calls race;
 *  * an expired flow is `null`, not a stale hit.
 *
 * A durable implementation must make the read-and-delete atomic (a D1
 * `DELETE ... WHERE state = ? AND expires_at_unix > ? RETURNING *` is one
 * statement and does this; a `SELECT` followed by a `DELETE` does not).
 * `samlPendingFlowStoreContract` in `store-contract.ts` is exported so every
 * implementation can be held to this — running it against only the in-memory
 * reference would leave the durable twin unproven, which is exactly the
 * two-implementations trap this repo keeps falling into.
 */
export interface SsoPendingFlowStore {
  insert(flow: SsoPendingFlow): Promise<void>;
  take(state: string, nowUnix: number): Promise<SsoPendingFlow | null>;
}

/** Everything the SAML handlers need from the outside world. */
export interface SamlPorts {
  readonly configs: SsoProviderConfigStore;
  readonly flows: SsoPendingFlowStore;
  /** Unix seconds. One clock for the whole flow. */
  now(): number;
  /** `byteCount` cryptographically random bytes, hex-encoded (`util.rs::generate_random_hex`). */
  randomHex(byteCount: number): string;
}

/** The default `randomHex`, over `crypto.getRandomValues`. */
export function webCryptoRandomHex(byteCount: number): string {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}
