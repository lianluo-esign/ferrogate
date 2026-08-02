import { buildAuthnRequestRedirect } from "./authn-request.js";
import { SamlError, samlFlowError } from "./errors.js";
import type { SamlPorts } from "./ports.js";
import { parseRedirectBindingParams, verifyRedirectSignature } from "./redirect-binding.js";
import { parseAndValidateResponse } from "./response.js";

/**
 * `sso.rs::SSO_FLOW_TTL_SECS` — an in-flight SSO flow may sit in the browser
 * for a while (IdP login, possibly MFA); 10 minutes is generous without leaving
 * stale entries around indefinitely.
 */
export const SSO_FLOW_TTL_SECS = 600;

/**
 * `sso.rs::SAML_CLOCK_SKEW_SECS` — permitted skew (either direction) on
 * `NotBefore`/`NotOnOrAfter`. IdP and SP clocks are rarely aligned.
 */
export const SAML_CLOCK_SKEW_SECS = 300;

export interface SamlAuthorizeResult {
  /** The IdP URL the console should redirect the browser to. */
  readonly authorizeUrl: string;
  /** The opaque flow token, carried as `RelayState`. */
  readonly state: string;
}

/**
 * A validated SAML login, handed to the control plane.
 *
 * This is deliberately NOT a session. `sso.rs::complete_sso_login` — the tail
 * shared with OIDC — does the JIT user provisioning, the cross-tenant
 * account-takeover guard, the tier-scoped gateway-key mint (#514/#517) and the
 * session issuance, all against tables this package does not own. Splitting
 * here keeps the protocol testable without a database and keeps the
 * takeover guard in one place for both protocols instead of two.
 */
export interface SamlAcsResult {
  readonly tenantId: string;
  readonly email: string;
  readonly displayName: string;
  readonly groups: string[];
  /** Carried through so the caller resolves the tier the same way OIDC does. */
  readonly groupRoleMapping: Record<string, string>;
  readonly defaultRole: string;
}

/**
 * `sso.rs::handle_saml_authorize` — starts a SAML 2.0 SP-initiated login
 * (issue #283) over the HTTP-Redirect binding.
 *
 * Unauthenticated by design (the browser is not logged in yet) and returns
 * JSON rather than a 302, so a JSON-only client can drive the flow too.
 */
export async function handleSamlAuthorize(
  ports: SamlPorts,
  tenantId: string,
): Promise<SamlAuthorizeResult> {
  const stored = await ports.configs.get(tenantId);
  if (!stored) {
    throw samlFlowError("sso_not_configured", 404, "SSO is not configured for this tenant");
  }
  if (stored.providerKind !== "saml") {
    throw samlFlowError(
      "not_saml_tenant",
      422,
      "this tenant is not configured for SAML SSO; use the OIDC authorize endpoint",
    );
  }
  const { samlIdpSsoUrl, samlSpEntityId, samlAcsUrl } = stored;
  if (!samlIdpSsoUrl || !samlSpEntityId || !samlAcsUrl) {
    throw samlFlowError("saml_config_incomplete", 500, "SAML configuration is incomplete");
  }

  const state = ports.randomHex(24);
  const requestId = `_${ports.randomHex(20)}`;
  const now = ports.now();
  const authorizeUrl = await buildAuthnRequestRedirect({
    idpSsoUrl: samlIdpSsoUrl,
    acsUrl: samlAcsUrl,
    spEntityId: samlSpEntityId,
    requestId,
    relayState: state,
    nowUnix: now,
  });
  await ports.flows.insert({
    state,
    tenantId,
    providerKind: "saml",
    codeVerifier: null,
    requestId,
    createdAtUnix: now,
    expiresAtUnix: now + SSO_FLOW_TTL_SECS,
  });
  return { authorizeUrl, state };
}

/**
 * `sso.rs::handle_saml_acs` — the assertion consumer service (issue #283).
 *
 * `rawQuery` MUST be the verbatim request query string (everything after the
 * `?`, still percent-encoded). Passing a re-serialised or already-decoded query
 * here defeats the signature check; see `redirect-binding.ts`.
 *
 * FAILS CLOSED on every one of: missing `RelayState`, unknown/expired/replayed
 * flow, a non-SAML flow or config, a missing certificate, a missing or invalid
 * redirect-binding signature, and any assertion-validation failure. There is no
 * path out of this function that reaches an authenticated state without the
 * signature having verified.
 */
export async function handleSamlAcs(ports: SamlPorts, rawQuery: string): Promise<SamlAcsResult> {
  const params = parseRedirectBindingParams(rawQuery);
  const state = params.relayState;
  if (state === null || state.length === 0) {
    throw samlFlowError("missing_relay_state", 422, "missing RelayState");
  }

  const now = ports.now();
  // Single-use: the state is consumed here, so a byte-identical replay of a
  // still-cryptographically-valid redirect finds nothing. This is the ONLY
  // replay defence — the signature stays valid forever.
  const flow = await ports.flows.take(state, now);
  if (!flow) {
    throw samlFlowError("unknown_saml_state", 401, "unknown, expired, or already-used SAML state");
  }
  if (flow.providerKind !== "saml") {
    throw samlFlowError("flow_not_saml", 422, "this pending flow is not a SAML flow");
  }
  const stored = await ports.configs.get(flow.tenantId);
  if (!stored) {
    throw samlFlowError(
      "saml_config_removed_mid_flow",
      500,
      "SAML configuration was removed mid-flow",
    );
  }
  if (stored.providerKind !== "saml") {
    throw samlFlowError("sso_config_no_longer_saml", 500, "SSO configuration is no longer SAML");
  }
  const certificate = stored.samlIdpCertificate;
  if (!certificate) {
    throw samlFlowError(
      "saml_config_missing_certificate",
      500,
      "SAML configuration is missing the IdP certificate",
    );
  }

  // 1. Verify the redirect-binding signature over the exact received octets,
  //    against the configured IdP certificate. This is FIRST: nothing below
  //    parses attacker-controlled XML until the bytes are authenticated.
  try {
    await verifyRedirectSignature(params, certificate);
  } catch (error) {
    throw samlFlowError(
      "saml_signature_verification_failed",
      401,
      `SAML signature verification failed: ${messageOf(error)}`,
    );
  }

  // 2. Inflate + parse the now-authenticated Response.
  const samlResponse = params.samlResponse;
  if (samlResponse === null) {
    // Unreachable in practice — step 1 refuses a query with no SAMLResponse
    // when it reconstructs the octet string — but the Rust handler kept the
    // check and so does this, because "an earlier check makes this impossible"
    // is exactly the assumption that stops being true after a refactor.
    throw samlFlowError("missing_saml_response_param", 422, "missing SAMLResponse");
  }
  let assertion: Awaited<ReturnType<typeof parseAndValidateResponse>>;
  try {
    assertion = await parseAndValidateResponse(samlResponse, {
      spEntityId: stored.samlSpEntityId ?? "",
      idpEntityId: stored.samlIdpEntityId,
      inResponseTo: flow.requestId,
      emailAttribute: stored.samlEmailAttribute,
      nameAttribute: stored.samlNameAttribute,
      groupsAttribute: stored.samlGroupsAttribute,
      nowUnix: now,
      clockSkewSecs: SAML_CLOCK_SKEW_SECS,
    });
  } catch (error) {
    throw samlFlowError(
      "saml_assertion_rejected",
      401,
      `SAML assertion rejected: ${messageOf(error)}`,
    );
  }

  return {
    tenantId: flow.tenantId,
    email: assertion.email,
    displayName: assertion.displayName,
    groups: assertion.groups,
    groupRoleMapping: { ...stored.groupRoleMapping },
    defaultRole: stored.defaultRole,
  };
}

function messageOf(error: unknown): string {
  if (error instanceof SamlError) return error.message;
  return error instanceof Error ? error.message : String(error);
}
