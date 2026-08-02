/**
 * `@ferrogate/identity` — the OIDC relying-party and SCIM 2.0 provisioning
 * halves of `crates/ferrogate-auth-service`.
 *
 * ## Why this package exists
 *
 * OIDC and SCIM had **no TypeScript implementation at all** for seventeen
 * rewrite waves. `crates/ferrogate-auth-service/src/sso.rs` (970 lines, the
 * OIDC half) and `scim.rs` (598 lines) matched ZERO TS files; the only two
 * repo hits for `scim` were a comment in `apps/gateway/src/keys/scopes.ts` and
 * a "still to come" note in `apps/control-plane/src/index.ts`. The gap was
 * invisible because `PORT-PLAN.md` maps CRATES to packages, and both modules
 * live inside a crate that already had a row — so nothing in the control was
 * ever wrong, it was merely silent.
 *
 * ## What is here
 *
 * - **OIDC relying party** (`oidc/`): Authorization Code + PKCE, discovery,
 *   WebCrypto JWS verification against the provider JWKS with `kid` respected
 *   and rotation handled, and full `iss`/`aud`/`azp`/`exp`/`iat`/`nbf`/`nonce`
 *   validation. Every failure path returns a refusal; nothing throws.
 * - **SCIM 2.0** (`scim/`): Users + Groups, RFC 7644 filtering, and the
 *   tenant-scoped authorization and deprovisioning semantics of issues
 *   #161/#232/#517.
 * - **The mount seam** (`routes.ts`): a Hono sub-app plus the exact wiring
 *   line and mount gate for the composition root.
 *
 * ## What is NOT here
 *
 * - **SAML** — `packages/sso`, a sibling package. The two share
 *   `completeSsoLogin` (exported below) so the JIT-provisioning and
 *   cross-tenant-takeover rules have exactly one implementation, as the Rust
 *   reference does.
 * - **Persistence** — every store is an interface in `ports.ts`. The D1
 *   implementation belongs to the composition root, which keeps every
 *   authorization predicate in this package single-implementation.
 * - **`/v1/admin/team/sso-config`** — the row is shared with SAML, so a single
 *   owner must mount that route. Its OIDC validation is
 *   `validateOidcConfigInput`.
 */

// --- ports + shared vocabulary -----------------------------------------
export type {
  AdminSessionPort,
  ApiKeyAuthenticatorPort,
  ApiKeyDecision,
  FetchLike,
  IdentityClock,
  IdentityRandom,
  IdentityRepository,
  IdentityResponse,
  LifecycleSeam,
  SecretResolverPort,
  StoredAdminUser,
  StoredAdminUserMembership,
  StoredApiKeyRecord,
  StoredSsoPendingFlow,
  StoredSsoProviderConfig,
  StoredTenantAccount,
  StoredWorkspaceRef,
  TenancyRefs,
} from "./ports.js";

export {
  ACCEPTED_MEMBERSHIP_ROLES,
  MEMBERSHIP_ROLES,
  type MembershipRole,
  isOwnerRole,
  membershipRoleFromStored,
  parseMembershipRole,
} from "./membership-role.js";

export { isValidEmail, nextId } from "./util.js";

// --- OIDC ---------------------------------------------------------------
export {
  ID_TOKEN_CLOCK_SKEW_SECONDS,
  type ClaimFailureReason,
  type IdTokenExpectations,
  validateIdTokenClaims,
} from "./oidc/claims.js";
export {
  DEFAULT_GROUP_CLAIM,
  DEFAULT_SSO_ROLE,
  type OidcConfigInput,
  type ResolvedOidcConfig,
  resolveOidcConfig,
  validateOidcConfigInput,
} from "./oidc/config.js";
export { type OidcDiscoveryDocument, fetchOidcDiscovery } from "./oidc/discovery.js";
export {
  OIDC_SCOPE,
  SSO_FLOW_TTL_SECONDS,
  type CompleteSsoLoginArgs,
  type OidcDeps,
  completeOidcCallback,
  completeSsoLogin,
  startOidcAuthorize,
} from "./oidc/flow.js";
export {
  SUPPORTED_JWS_ALGORITHMS,
  type JwsVerification,
  decodeJwsHeader,
  verifyCompactJws,
} from "./oidc/jws.js";
export {
  JWKS_CACHE_TTL_SECONDS,
  JWKS_FORCED_REFRESH_COOLDOWN_SECONDS,
  JwksCache,
  type JwksCacheOptions,
} from "./oidc/jwks.js";
export { generateNonce, generatePkcePair, generateState } from "./oidc/pkce.js";
export { base64UrlToBytes, bytesToBase64Url, decodeBase64UrlJson } from "./oidc/base64url.js";

// --- delegation chain (#691) --------------------------------------------
export {
  DELEGATION_CLOCK_SKEW_SECONDS,
  DELEGATION_FORMAT_VERSION,
  DELEGATION_HEADER,
  DELEGATION_JWS_ALGORITHM,
  DELEGATION_JWS_HEADER,
  DELEGATION_JWS_TYPE,
  DELEGATION_LINK_SEPARATOR,
  DELEGATION_PATH_SEPARATOR,
  DELEGATION_PRINCIPAL_KINDS,
  MAX_DELEGATION_DEPTH,
  MAX_DELEGATION_HEADER_BYTES,
  MAX_DELEGATION_LIFETIME_SECONDS,
  type DelegationClaims,
  type DelegationPrincipalKind,
  delegationPath,
  // `encodeSegment` and `signingInput` are the RAW encoder halves, exported so
  // a test can FORGE a link the mint would refuse to issue — which is the only
  // way to prove the verifier re-derives every rule itself instead of trusting
  // that the mint checked. Production code should mint through
  // `mintDelegationLink`.
  encodeSegment,
  signingInput,
  isDelegationPrincipal,
  parseDelegationClaims,
  parseDelegationPrincipal,
  splitDelegationLink,
} from "./delegation/link.js";
export {
  MIN_DELEGATION_KEY_BYTES,
  type DelegationGrant,
  type DelegationKeyResolution,
  type DelegationMintFailure,
  type DelegationMintResult,
  delegationScopeSubset,
  encodeDelegationChain,
  importDelegationKey,
  mintDelegationLink,
  verifyDelegationSignature,
} from "./delegation/sign.js";
export {
  DELEGATION_REVOCATION_TABLE,
  DELEGATION_REVOCATION_TTL_MS,
  NO_DELEGATION_REVOCATIONS,
  type DelegationRevocationDatabase,
  type DelegationRevocationResolution,
  type DelegationRevocationSource,
  cachedDelegationRevocationSource,
  d1DelegationRevocationSource,
} from "./delegation/revocation.js";
export {
  type DelegationFailureCode,
  type DelegationVerification,
  type DelegationVerificationInput,
  type VerifiedDelegationChain,
  verifyDelegationChain,
} from "./delegation/verify.js";

// --- SCIM ---------------------------------------------------------------
export {
  SCIM_PROVISION_SCOPE,
  type ScimTenantResolution,
  bearerToken,
  resolveScimTenant,
} from "./scim/auth.js";
export {
  type ScimFilter,
  matchesScimFilter,
  parseScimFilter,
} from "./scim/filter.js";
export {
  SCIM_GROUP_SCHEMA,
  SCIM_LIST_RESPONSE_SCHEMA,
  SCIM_USER_SCHEMA,
  type ScimUserResource,
  scimUserResource,
  scimUserResourceWithActive,
} from "./scim/resources.js";
export {
  type ScimDeps,
  type ScimListOptions,
  type ScimUserRequest,
  mintScimToken,
  parseScimActivePatch,
  scimGroupsList,
  scimUserCreate,
  scimUserDelete,
  scimUserGet,
  scimUserPatch,
  scimUsersList,
} from "./scim/service.js";

// --- the mount seam -----------------------------------------------------
export {
  type IdentityDeps,
  type IdentityRouteRecord,
  type IdentityRoutesApp,
  createIdentityRoutes,
} from "./routes.js";
