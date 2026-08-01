/**
 * SCIM 2.0 resource projections (RFC 7643).
 *
 * The single place a SCIM user representation is built — so the `ferrogateRole`
 * normalisation below covers list/get/create/patch at once.
 */
import { membershipRoleFromStored } from "../membership-role.js";
import type { StoredAdminUser } from "../ports.js";

export const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
export const SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
export const SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

export interface ScimUserResource extends Record<string, unknown> {
  schemas: string[];
  id: string;
  userName: string;
  displayName: string;
  active: boolean;
  ferrogateRole: string;
  meta: { resourceType: "User" };
}

/**
 * A SCIM user, with an EXPLICIT `active`.
 *
 * The explicit form exists for tenant-scoped deprovisioning (issue #232): a
 * user removed from THIS tenant is inactive here even when their global
 * account stays enabled for their other tenants, so `active` cannot simply be
 * read off `disabled_at_unix`.
 *
 * `ferrogateRole` is the RESOLVED tier, never the raw stored column (issue
 * #517). A legacy or D1-written value outside the four tiers resolves to
 * `viewer` — which is the authority that user's session and gateway key
 * actually get. Echoing the raw string would tell the IdP its user holds a
 * tier this service does not implement, and IdP-side reconciliation would then
 * believe a role assignment took effect that never did.
 */
export function scimUserResourceWithActive(
  user: StoredAdminUser,
  role: string,
  active: boolean,
): ScimUserResource {
  return {
    schemas: [SCIM_USER_SCHEMA],
    id: user.id,
    userName: user.email,
    displayName: user.displayName,
    active,
    ferrogateRole: membershipRoleFromStored(role),
    meta: { resourceType: "User" },
  };
}

/** A SCIM user whose `active` is its global account state. */
export function scimUserResource(user: StoredAdminUser, role: string): ScimUserResource {
  return scimUserResourceWithActive(user, role, user.disabledAtUnix === null);
}

export interface ScimListResponse extends Record<string, unknown> {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: Record<string, unknown>[];
}

/**
 * The SCIM `ListResponse` envelope. `totalResults` is the count BEFORE
 * pagination (RFC 7644 §3.4.2.4) — reporting the page size there is how an IdP
 * concludes it has synced the whole directory after one page.
 */
export function scimListResponse(
  resources: Record<string, unknown>[],
  totalResults: number,
  startIndex: number,
): ScimListResponse {
  return {
    schemas: [SCIM_LIST_RESPONSE_SCHEMA],
    totalResults,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}
