/**
 * Projecting a stored SSO row into the OIDC runtime shape, and validating an
 * operator-supplied OIDC configuration before it is persisted.
 *
 * Clean-room port of `resolve_oidc_config` and the `"oidc"` arm of
 * `handle_admin_sso_config_set` (`sso.rs`, issues #160 / #283 / #517).
 */
import { parseMembershipRole } from "../membership-role.js";
import type { StoredSsoProviderConfig } from "../ports.js";

/** The IdP claim carrying group memberships when the tenant does not say. */
export const DEFAULT_GROUP_CLAIM = "groups";

/** The tier assigned on first login when no group maps. */
export const DEFAULT_SSO_ROLE = "member";

export interface ResolvedOidcConfig {
  issuer: string;
  clientId: string;
  /** A secret REFERENCE. The value is resolved just-in-time at callback. */
  clientSecretRef: string;
  redirectUri: string;
  groupRoleMapping: Record<string, string>;
  defaultRole: string;
  groupClaim: string;
}

/**
 * Projects a stored config into the OIDC runtime shape, or `null` when the
 * tenant is configured for a different provider kind or is missing a required
 * OIDC field. **Fails closed**: a half-written row yields no configuration at
 * all rather than a configuration with a blank client id.
 */
export function resolveOidcConfig(stored: StoredSsoProviderConfig): ResolvedOidcConfig | null {
  if (stored.providerKind !== "oidc") return null;
  const issuer = stored.oidcIssuer?.trim().replace(/\/+$/, "");
  const clientId = stored.oidcClientId?.trim();
  const clientSecretRef = stored.oidcClientSecretRef?.trim();
  const redirectUri = stored.oidcRedirectUri?.trim();
  if (!issuer || !clientId || !clientSecretRef || !redirectUri) return null;
  return {
    issuer,
    clientId,
    clientSecretRef,
    redirectUri,
    groupRoleMapping: { ...stored.groupRoleMapping },
    defaultRole: stored.defaultRole,
    groupClaim: stored.oidcGroupClaim?.trim() || DEFAULT_GROUP_CLAIM,
  };
}

export interface OidcConfigInput {
  issuer?: string | null;
  clientId?: string | null;
  clientSecretRef?: string | null;
  redirectUri?: string | null;
  groupClaim?: string | null;
  defaultRole?: string | null;
  groupRoleMapping?: Record<string, string> | null;
}

export type OidcConfigValidation =
  | { ok: true; config: Omit<ResolvedOidcConfig, "clientSecretRef"> & { clientSecretRef: string } }
  | { ok: false; message: string };

/**
 * Validates an operator-supplied OIDC configuration BEFORE it is persisted.
 *
 * Exported for whoever owns the shared `POST /v1/admin/team/sso-config` route
 * (the row is shared with the SAML half, which lives in `packages/sso`), so
 * there is one OIDC validator rather than one per caller.
 *
 * The role validation is issue #517: `defaultRole` and every
 * `groupRoleMapping` VALUE is written verbatim into
 * `admin_user_tenant_memberships.role` on a first SSO login, so an unvalidated
 * one is an unvalidated role write with an IdP round trip in between — and D1
 * carries no `CHECK` to catch it on the way in.
 */
export function validateOidcConfigInput(input: OidcConfigInput): OidcConfigValidation {
  const issuer = (input.issuer ?? "").trim().replace(/\/+$/, "");
  const clientId = (input.clientId ?? "").trim();
  const clientSecretRef = (input.clientSecretRef ?? "").trim();
  const redirectUri = (input.redirectUri ?? "").trim();
  if (!issuer || !clientId || !clientSecretRef || !redirectUri) {
    return {
      ok: false,
      message: "issuer, client_id, client_secret_ref, and redirect_uri are required for oidc",
    };
  }
  // The client secret is a `@ferrogate/secrets` REFERENCE, never a plaintext
  // secret — so a config write can never put a live IdP credential in the
  // control-plane row (#283).
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(clientSecretRef)) {
    return {
      ok: false,
      message: "client_secret_ref must be a secret reference URI (e.g. env://NAME), not a secret",
    };
  }
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    return { ok: false, message: "issuer must be an absolute URL" };
  }
  if (issuerUrl.protocol !== "https:") {
    return { ok: false, message: "issuer must be https" };
  }
  const defaultRole = (input.defaultRole ?? DEFAULT_SSO_ROLE).trim();
  if (!parseMembershipRole(defaultRole)) {
    return { ok: false, message: `default_role: unknown role ${JSON.stringify(defaultRole)}` };
  }
  const groupRoleMapping: Record<string, string> = {};
  for (const [group, role] of Object.entries(input.groupRoleMapping ?? {})) {
    const parsed = parseMembershipRole(role.trim());
    if (!parsed) {
      return {
        ok: false,
        message: `group_role_mapping[${JSON.stringify(group)}]: unknown role ${JSON.stringify(role)}`,
      };
    }
    groupRoleMapping[group] = parsed;
  }
  return {
    ok: true,
    config: {
      issuer,
      clientId,
      clientSecretRef,
      redirectUri,
      defaultRole,
      groupRoleMapping,
      groupClaim: (input.groupClaim ?? DEFAULT_GROUP_CLAIM).trim() || DEFAULT_GROUP_CLAIM,
    },
  };
}
