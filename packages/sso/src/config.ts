import { SamlError, samlFlowError } from "./errors.js";
import type { StoredSsoProviderConfig } from "./ports.js";
import { parseIdpPublicKey } from "./x509.js";

/**
 * The SAML branch of `sso.rs::handle_set_sso_config`
 * (`POST /v1/admin/team/sso-config`, issues #160/#283).
 *
 * Only the SAML branch: the OIDC branch belongs to `packages/identity`, and the
 * owner-only RBAC gate plus the `default_role`/`group_role_mapping` validation
 * (issue #517) belong to the control plane's authorization layer, which already
 * owns membership tiers. This function is the part that requires knowing what a
 * SAML config MEANS.
 */
export interface SamlConfigRequest {
  readonly providerKind?: string;
  readonly defaultRole?: string;
  readonly groupRoleMapping?: Record<string, string>;
  readonly idpEntityId?: string | null;
  readonly idpSsoUrl?: string | null;
  /** PEM or bare base64 DER. */
  readonly idpCertificate?: string | null;
  readonly spEntityId?: string | null;
  readonly acsUrl?: string | null;
  readonly emailAttribute?: string | null;
  readonly nameAttribute?: string | null;
  readonly groupsAttribute?: string | null;
}

export interface SamlConfigTimestamps {
  readonly nowUnix: number;
  /** The existing row's `created_at`, or `nowUnix` for a first write. */
  readonly createdAtUnix: number;
}

function trimmed(value: string | null | undefined): string {
  return (value ?? "").trim();
}

function optional(value: string | null | undefined): string | null {
  const text = trimmed(value);
  return text.length === 0 ? null : text;
}

export function admitSamlConfig(
  tenantId: string,
  payload: SamlConfigRequest,
  timestamps: SamlConfigTimestamps,
): StoredSsoProviderConfig {
  const providerKind = payload.providerKind ?? "oidc";
  if (providerKind !== "saml") {
    throw samlFlowError(
      "not_saml_config",
      422,
      `provider_kind ${JSON.stringify(providerKind)} is not "saml"`,
    );
  }

  const idpSsoUrl = trimmed(payload.idpSsoUrl);
  const idpCertificate = trimmed(payload.idpCertificate);
  const spEntityId = trimmed(payload.spEntityId);
  const acsUrl = trimmed(payload.acsUrl);
  if (
    idpSsoUrl.length === 0 ||
    idpCertificate.length === 0 ||
    spEntityId.length === 0 ||
    acsUrl.length === 0
  ) {
    throw samlFlowError(
      "saml_config_incomplete_fields",
      422,
      "idp_sso_url, idp_certificate, sp_entity_id, and acs_url are required for saml",
    );
  }

  // Fail closed AT CONFIG TIME if the certificate cannot be parsed into a
  // usable verification key — otherwise the tenant's first user discovers it as
  // an unexplained 401.
  try {
    parseIdpPublicKey(idpCertificate);
  } catch (error) {
    const detail = error instanceof SamlError ? error.message : String(error);
    throw samlFlowError(
      "saml_certificate_unusable",
      422,
      `idp_certificate is not a usable X.509 certificate: ${detail}`,
    );
  }

  return {
    tenantId,
    providerKind: "saml",
    defaultRole: payload.defaultRole ?? "member",
    groupRoleMapping: { ...(payload.groupRoleMapping ?? {}) },
    oidcIssuer: null,
    oidcClientId: null,
    oidcClientSecretRef: null,
    oidcRedirectUri: null,
    oidcGroupClaim: null,
    samlIdpEntityId: optional(payload.idpEntityId),
    samlIdpSsoUrl: idpSsoUrl,
    samlIdpCertificate: idpCertificate,
    samlSpEntityId: spEntityId,
    samlAcsUrl: acsUrl,
    samlEmailAttribute: payload.emailAttribute ?? null,
    samlNameAttribute: payload.nameAttribute ?? null,
    samlGroupsAttribute: payload.groupsAttribute ?? null,
    createdAtUnix: timestamps.createdAtUnix,
    updatedAtUnix: timestamps.nowUnix,
  };
}
