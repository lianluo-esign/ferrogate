/**
 * SCIM authorization — clean-room port of `resolve_scim_tenant` (`scim.rs`),
 * issues #161 / #232.
 *
 * This is the ONE place a SCIM request acquires a tenant, and the tenant it
 * acquires is the one stamped on the provisioning key. Nothing downstream ever
 * takes a tenant id from the request: no path segment, no query parameter, no
 * body field. That is the whole cross-tenant story — a SCIM token cannot ask
 * for another tenant because there is no channel through which to ask.
 */
import { forbidden, internalError, lifecycleError, unauthorized } from "../errors.js";
import type { ApiKeyAuthenticatorPort, IdentityRepository, IdentityResponse } from "../ports.js";

/**
 * The scope that marks a virtual API key as a SCIM provisioning credential.
 *
 * Deliberately NOT `admin.write`: a console session key is an interactive
 * human credential and a SCIM token is a long-lived machine credential handed
 * to a third-party IdP. Separating them means revoking one does not revoke the
 * other, and — more importantly — that the far more numerous `admin.write`
 * holders are not silently also directory administrators.
 */
export const SCIM_PROVISION_SCOPE = "scim.provision";

export interface ScimAuthDeps {
  repository: IdentityRepository;
  apiKeys: ApiKeyAuthenticatorPort;
}

export type ScimTenantResolution =
  | { ok: true; tenantId: string }
  | { ok: false; response: IdentityResponse };

/**
 * Resolves the tenant a SCIM request may operate on, from its bearer token.
 *
 * Reuses the same prefix+hash+active-check api-key resolution the gateway uses
 * for virtual keys rather than a separate credential store, so revoking or
 * rotating a SCIM token through the normal `/admin/v1/virtual-keys` endpoints
 * takes effect here with no second code path.
 */
export async function resolveScimTenant(
  deps: ScimAuthDeps,
  bearerToken: string | null,
): Promise<ScimTenantResolution> {
  if (!bearerToken) {
    return { ok: false, response: unauthorized("missing bearer token") };
  }
  let decision: Awaited<ReturnType<ApiKeyAuthenticatorPort["authenticate"]>>;
  try {
    decision = await deps.apiKeys.authenticate(bearerToken);
  } catch {
    return { ok: false, response: unauthorized("invalid SCIM provisioning token") };
  }
  if (!decision) {
    return { ok: false, response: unauthorized("invalid SCIM provisioning token") };
  }
  // EXACT scope match. Not `startsWith`, not case-insensitive: `scim` and
  // `scim.provisioning` are different scopes, and a prefix test would grant
  // this surface to both.
  if (!decision.scopes.some((scope) => scope === SCIM_PROVISION_SCOPE)) {
    return { ok: false, response: forbidden("token is not scoped for SCIM provisioning") };
  }
  const tenantId = decision.tenant.organizationId;
  if (!tenantId) {
    return { ok: false, response: internalError("SCIM token has no tenant scope") };
  }
  try {
    await deps.repository.requireUsableTenancy("request", {
      tenantId,
      projectId: decision.tenant.projectId,
      workspaceId: decision.tenant.workspaceId,
    });
  } catch (error) {
    return { ok: false, response: lifecycleError(error) };
  }
  return { ok: true, tenantId };
}

/** Extracts a bearer token from an `Authorization` header value. */
export function bearerToken(headerValue: string | null | undefined): string | null {
  if (!headerValue) return null;
  const match = /^Bearer\s+(.+)$/i.exec(headerValue.trim());
  const token = match?.[1]?.trim();
  return token && token.length > 0 ? token : null;
}
