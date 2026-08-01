/**
 * The SAML legs and the SHARED `sso-config` row.
 *
 * `packages/identity` mounts the OIDC + SCIM surface itself
 * (`createIdentityRoutes`). Three routes cannot live in either package:
 *
 * | route | why it is here |
 * |---|---|
 * | `GET /v1/admin/auth/saml/authorize` | needs the control plane's stores |
 * | `GET /v1/admin/auth/saml/acs` | ends in `completeSsoLogin`, which owns tables neither package has |
 * | `GET\|POST\|DELETE /v1/admin/team/sso-config` | ONE row, TWO provider kinds — a single owner must validate both |
 *
 * `handleSamlAcs` stops at a VALIDATED identity and hands it to
 * `completeSsoLogin` — the same function the OIDC callback ends in. That is the
 * point of the split: the #232 cross-tenant account-takeover guard, the JIT
 * provisioning rule and the #514/#517 key ladder have one implementation, not
 * one per protocol.
 */
import {
  type CompleteSsoLoginArgs,
  completeSsoLogin,
  isOwnerRole,
  membershipRoleFromStored,
  validateOidcConfigInput,
} from "@ferrogate/identity";
import { SamlFlowError, admitSamlConfig, handleSamlAcs, handleSamlAuthorize } from "@ferrogate/sso";
import type { Context, Hono } from "hono";
import { HttpError } from "../middleware/errors.js";
import type { ControlPlaneEnv } from "../ports.js";
import { type ResolvedIdentity, identityClock, resolveIdentityDeps } from "./adapters.js";

type Ctx = Context<ControlPlaneEnv>;

/** One entry per `app.on(...)` this module actually performed. */
export interface SsoRouteRecord {
  readonly method: string;
  readonly path: string;
}

export const SSO_ROUTES: readonly SsoRouteRecord[] = [
  { method: "GET", path: "/v1/admin/auth/saml/authorize" },
  { method: "GET", path: "/v1/admin/auth/saml/acs" },
  { method: "GET", path: "/v1/admin/team/sso-config" },
  { method: "POST", path: "/v1/admin/team/sso-config" },
  { method: "DELETE", path: "/v1/admin/team/sso-config" },
];

/**
 * `SamlFlowError` → the control plane's envelope, statuses PRESERVED.
 *
 * 401 vs 422 vs 404 vs 500 is the ported contract, and collapsing them is how
 * a tampered assertion (401) becomes indistinguishable from a misconfigured
 * tenant (422) in an operator's logs.
 */
function asHttpError(error: unknown): HttpError {
  if (error instanceof SamlFlowError) {
    return new HttpError(error.status, error.code, error.message);
  }
  if (error instanceof HttpError) return error;
  return new HttpError(
    500,
    "internal_error",
    error instanceof Error ? error.message : String(error),
  );
}

/** Renders an `IdentityResponse` (the shape `completeSsoLogin` returns). */
function renderIdentity(c: Ctx, response: { status: number; body: unknown }): Response {
  return c.body(JSON.stringify(response.body), response.status as 200, {
    "content-type": "application/json",
  });
}

/** The caller's console session, or a 401. Owner-only surfaces check the tier after. */
async function requireSession(identity: ResolvedIdentity, c: Ctx) {
  const header = c.req.header("authorization") ?? null;
  const match = /^Bearer\s+(.+)$/i.exec((header ?? "").trim());
  const token = match?.[1]?.trim();
  if (!token) throw new HttpError(401, "unauthorized", "missing bearer token");
  const current = await identity.session.currentAdminSession(token);
  if (current === null) throw new HttpError(401, "unauthorized", "invalid session");
  return current;
}

/** Owner-only, per `sso.rs::handle_set_sso_config`. */
async function requireOwnerSession(identity: ResolvedIdentity, c: Ctx) {
  const current = await requireSession(identity, c);
  if (!isOwnerRole(membershipRoleFromStored(current.membership.role))) {
    throw new HttpError(403, "forbidden", "only a tenant owner can manage the SSO configuration");
  }
  return current;
}

async function readJson(c: Ctx): Promise<Record<string, unknown>> {
  const raw = await c.req.text();
  if (raw.trim() === "") return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new HttpError(400, "invalid_json", "request body must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, "invalid_json", "request body is not valid JSON");
  }
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

function stringMap(value: unknown): Record<string, string> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (typeof entry === "string") out[key] = entry;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/** `GET /v1/admin/auth/saml/authorize?tenant_id=…` — anonymous by design. */
async function samlAuthorize(c: Ctx): Promise<Response> {
  const identity = resolveIdentityDeps(c);
  const tenantId = c.req.query("tenant_id")?.trim() ?? "";
  if (tenantId === "") throw new HttpError(422, "invalid_request", "tenant_id is required");
  try {
    const result = await handleSamlAuthorize(identity.saml, tenantId);
    return c.json({ authorize_url: result.authorizeUrl, state: result.state }, 200);
  } catch (error) {
    throw asHttpError(error);
  }
}

/**
 * `GET /v1/admin/auth/saml/acs` — anonymous by design (the browser is not
 * logged in yet; the `RelayState` is the credential).
 *
 * **`new URL(c.req.url).search.slice(1)` is load-bearing.** The HTTP-Redirect
 * binding signs the RAW query octets, so `c.req.query()` — which decodes — would
 * hand the verifier a re-serialised string and defeat the entire signature
 * check. `test/saml-mount.test.ts` holds this with a tampered assertion.
 */
async function samlAcs(c: Ctx): Promise<Response> {
  const identity = resolveIdentityDeps(c);
  let validated: Awaited<ReturnType<typeof handleSamlAcs>>;
  try {
    validated = await handleSamlAcs(identity.saml, new URL(c.req.url).search.slice(1));
  } catch (error) {
    throw asHttpError(error);
  }
  const args: CompleteSsoLoginArgs = {
    tenantId: validated.tenantId,
    email: validated.email,
    displayName: validated.displayName,
    groups: validated.groups,
    groupRoleMapping: validated.groupRoleMapping,
    defaultRole: validated.defaultRole,
  };
  // The SHARED tail. Identical to the OIDC callback's, deliberately.
  const response = await completeSsoLogin(identity, args);
  return renderIdentity(c, response);
}

/** `GET /v1/admin/team/sso-config` — owner-only; never returns a secret. */
async function getSsoConfig(c: Ctx): Promise<Response> {
  const identity = resolveIdentityDeps(c);
  const current = await requireOwnerSession(identity, c);
  const stored = await identity.repository.getSsoProviderConfig(current.membership.tenantId);
  if (stored === null)
    throw new HttpError(404, "not_found", "SSO is not configured for this tenant");
  return c.json(
    {
      tenant_id: stored.tenantId,
      provider_kind: stored.providerKind,
      default_role: stored.defaultRole,
      group_role_mapping: stored.groupRoleMapping,
      oidc_issuer: stored.oidcIssuer,
      oidc_client_id: stored.oidcClientId,
      // The REFERENCE, which is all that is ever stored. There is no branch
      // here that could return a resolved secret.
      oidc_client_secret_ref: stored.oidcClientSecretRef,
      oidc_redirect_uri: stored.oidcRedirectUri,
      oidc_group_claim: stored.oidcGroupClaim,
      saml_idp_entity_id: stored.samlIdpEntityId,
      saml_idp_sso_url: stored.samlIdpSsoUrl,
      saml_sp_entity_id: stored.samlSpEntityId,
      saml_acs_url: stored.samlAcsUrl,
      saml_email_attribute: stored.samlEmailAttribute,
      saml_name_attribute: stored.samlNameAttribute,
      saml_groups_attribute: stored.samlGroupsAttribute,
      created_at_unix: stored.createdAtUnix,
      updated_at_unix: stored.updatedAtUnix,
    },
    200,
  );
}

/**
 * `POST /v1/admin/team/sso-config` — owner-only.
 *
 * ONE row per tenant, and `provider_kind` is the discriminant that stops a
 * tenant being configured for both protocols at once. The tenant id comes from
 * the SESSION, never from the body: a body-supplied tenant would let any owner
 * configure another tenant's IdP, which is the takeover this surface exists to
 * make impossible.
 */
async function setSsoConfig(c: Ctx): Promise<Response> {
  const identity = resolveIdentityDeps(c);
  const current = await requireOwnerSession(identity, c);
  const tenantId = current.membership.tenantId;
  const body = await readJson(c);
  const providerKind = optionalString(body.provider_kind) ?? "oidc";
  const now = identityClock.nowUnix();
  const existing = await identity.repository.getSsoProviderConfig(tenantId);
  const createdAtUnix = existing?.createdAtUnix ?? now;

  if (providerKind === "saml") {
    let admitted: ReturnType<typeof admitSamlConfig>;
    try {
      admitted = admitSamlConfig(
        tenantId,
        {
          providerKind,
          defaultRole: optionalString(body.default_role) ?? "member",
          groupRoleMapping: stringMap(body.group_role_mapping),
          idpEntityId: optionalString(body.saml_idp_entity_id),
          idpSsoUrl: optionalString(body.saml_idp_sso_url),
          idpCertificate: optionalString(body.saml_idp_certificate),
          spEntityId: optionalString(body.saml_sp_entity_id),
          acsUrl: optionalString(body.saml_acs_url),
          emailAttribute: optionalString(body.saml_email_attribute),
          nameAttribute: optionalString(body.saml_name_attribute),
          groupsAttribute: optionalString(body.saml_groups_attribute),
        },
        { nowUnix: now, createdAtUnix },
      );
    } catch (error) {
      throw asHttpError(error);
    }
    // #517: the role fields are written verbatim into a membership row on a
    // first SSO login, and D1 carries no CHECK on this table. Validate the
    // SAML branch's roles with the SAME validator the OIDC branch uses.
    const roles = validateOidcConfigInput({
      issuer: "https://placeholder.invalid",
      clientId: "placeholder",
      clientSecretRef: "env://PLACEHOLDER",
      redirectUri: "https://placeholder.invalid/cb",
      defaultRole: admitted.defaultRole,
      groupRoleMapping: admitted.groupRoleMapping,
    });
    if (!roles.ok) throw new HttpError(422, "invalid_request", roles.message);
    await identity.repository.putSsoProviderConfig({
      ...admitted,
      defaultRole: roles.config.defaultRole,
      groupRoleMapping: roles.config.groupRoleMapping,
    });
    return c.json({ tenant_id: tenantId, provider_kind: "saml" }, 200);
  }

  if (providerKind !== "oidc") {
    throw new HttpError(
      422,
      "invalid_request",
      `provider_kind ${JSON.stringify(providerKind)} is not "oidc" or "saml"`,
    );
  }

  const validation = validateOidcConfigInput({
    issuer: optionalString(body.oidc_issuer),
    clientId: optionalString(body.oidc_client_id),
    clientSecretRef: optionalString(body.oidc_client_secret_ref),
    redirectUri: optionalString(body.oidc_redirect_uri),
    groupClaim: optionalString(body.oidc_group_claim),
    defaultRole: optionalString(body.default_role),
    groupRoleMapping: stringMap(body.group_role_mapping),
  });
  if (!validation.ok) throw new HttpError(422, "invalid_request", validation.message);
  await identity.repository.putSsoProviderConfig({
    tenantId,
    providerKind: "oidc",
    defaultRole: validation.config.defaultRole,
    groupRoleMapping: validation.config.groupRoleMapping,
    oidcIssuer: validation.config.issuer,
    oidcClientId: validation.config.clientId,
    oidcClientSecretRef: validation.config.clientSecretRef,
    oidcRedirectUri: validation.config.redirectUri,
    oidcGroupClaim: validation.config.groupClaim,
    samlIdpEntityId: null,
    samlIdpSsoUrl: null,
    samlIdpCertificate: null,
    samlSpEntityId: null,
    samlAcsUrl: null,
    samlEmailAttribute: null,
    samlNameAttribute: null,
    samlGroupsAttribute: null,
    createdAtUnix,
    updatedAtUnix: now,
  });
  return c.json({ tenant_id: tenantId, provider_kind: "oidc" }, 200);
}

/** `DELETE /v1/admin/team/sso-config` — owner-only. */
async function deleteSsoConfig(c: Ctx): Promise<Response> {
  const identity = resolveIdentityDeps(c);
  const current = await requireOwnerSession(identity, c);
  const removed = await identity.repository.deleteSsoProviderConfig(current.membership.tenantId);
  if (!removed) throw new HttpError(404, "not_found", "SSO is not configured for this tenant");
  return c.body(null, 204);
}

/**
 * THE seam. Returns what it actually mounted, so the composition root's gate
 * asserts against what happened rather than against this module's list.
 */
export function mountSsoRoutes(app: Hono<ControlPlaneEnv>): readonly SsoRouteRecord[] {
  const handlers: Record<string, (c: Ctx) => Promise<Response>> = {
    "GET /v1/admin/auth/saml/authorize": samlAuthorize,
    "GET /v1/admin/auth/saml/acs": samlAcs,
    "GET /v1/admin/team/sso-config": getSsoConfig,
    "POST /v1/admin/team/sso-config": setSsoConfig,
    "DELETE /v1/admin/team/sso-config": deleteSsoConfig,
  };
  const mounted: SsoRouteRecord[] = [];
  for (const route of SSO_ROUTES) {
    const handler = handlers[`${route.method} ${route.path}`];
    if (handler === undefined) {
      throw new Error(`no handler for SSO route ${route.method} ${route.path}`);
    }
    app.on([route.method], route.path, handler);
    mounted.push(route);
  }
  return mounted;
}
