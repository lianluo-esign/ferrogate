import { beforeEach, describe, expect, test } from "vitest";
import {
  SamlFlowError,
  type SamlPorts,
  type StoredSsoProviderConfig,
  createInMemorySsoStores,
  handleSamlAcs,
  handleSamlAuthorize,
} from "../src/index.js";
import { IDP_CERT_PEM, IDP_KEY_PKCS8_PEM, OTHER_KEY_PKCS8_PEM } from "./fixtures.js";
import {
  SIG_ALG_SHA256,
  deflateRaw,
  idpPercentEncode,
  sampleResponseXml,
  signedQuery,
  toBase64,
} from "./support.js";

const TENANT = "tenant_acme";

function samlConfig(overrides: Partial<StoredSsoProviderConfig> = {}): StoredSsoProviderConfig {
  return {
    tenantId: TENANT,
    providerKind: "saml",
    defaultRole: "member",
    groupRoleMapping: { Admins: "admin" },
    oidcIssuer: null,
    oidcClientId: null,
    oidcClientSecretRef: null,
    oidcRedirectUri: null,
    oidcGroupClaim: null,
    samlIdpEntityId: "https://idp.example/entity",
    samlIdpSsoUrl: "https://idp.example/sso",
    samlIdpCertificate: IDP_CERT_PEM,
    samlSpEntityId: "sp-entity-id",
    samlAcsUrl: "https://sp.example/acs",
    samlEmailAttribute: "email",
    samlNameAttribute: "displayName",
    samlGroupsAttribute: "groups",
    createdAtUnix: 1_700_000_000,
    updatedAtUnix: 1_700_000_000,
    ...overrides,
  };
}

interface Harness {
  ports: SamlPorts;
  stores: ReturnType<typeof createInMemorySsoStores>;
  setNow: (value: number) => void;
}

function harness(config: StoredSsoProviderConfig | null = samlConfig()): Harness {
  const stores = createInMemorySsoStores();
  if (config) stores.configs.put(config);
  let now = 1_704_067_200; // 2024-01-01T00:00:00Z
  let counter = 0;
  const ports: SamlPorts = {
    configs: stores.configs,
    flows: stores.flows,
    now: () => now,
    randomHex: (bytes) => {
      counter += 1;
      return counter.toString(16).padStart(bytes * 2, "0");
    },
  };
  return {
    ports,
    stores,
    setNow: (value) => {
      now = value;
    },
  };
}

async function expectFlowRefusal(
  work: Promise<unknown>,
  code: string,
  status: number,
  message?: string | RegExp,
): Promise<SamlFlowError> {
  const error = await work.then(
    () => null,
    (caught: unknown) => caught,
  );
  expect(error, "the flow must REFUSE, never fall through to authenticated").toBeInstanceOf(
    SamlFlowError,
  );
  const flowError = error as SamlFlowError;
  expect(flowError.code).toBe(code);
  expect(flowError.status).toBe(status);
  if (typeof message === "string") expect(flowError.message).toBe(message);
  else if (message) expect(flowError.message).toMatch(message);
  return flowError;
}

describe("SP-initiated authorize", () => {
  test("returns the IdP redirect and records a single-use pending flow", async () => {
    const { ports, stores } = harness();
    const result = await handleSamlAuthorize(ports, TENANT);

    expect(result.authorizeUrl).toMatch(/^https:\/\/idp\.example\/sso\?SAMLRequest=/);
    expect(result.authorizeUrl).toContain(`&RelayState=${result.state}`);
    const flow = stores.flows.peek(result.state);
    expect(flow?.tenantId).toBe(TENANT);
    expect(flow?.providerKind).toBe("saml");
    expect(flow?.requestId).toMatch(/^_/);
    expect(flow?.expiresAtUnix).toBe(flow ? flow.createdAtUnix + 600 : -1);
  });

  test("an unconfigured tenant is a 404, not an empty redirect", async () => {
    const { ports } = harness(null);
    await expectFlowRefusal(
      handleSamlAuthorize(ports, TENANT),
      "sso_not_configured",
      404,
      "SSO is not configured for this tenant",
    );
  });

  test("an OIDC tenant is refused at the SAML authorize endpoint", async () => {
    const { ports } = harness(samlConfig({ providerKind: "oidc" }));
    await expectFlowRefusal(
      handleSamlAuthorize(ports, TENANT),
      "not_saml_tenant",
      422,
      "this tenant is not configured for SAML SSO; use the OIDC authorize endpoint",
    );
  });

  test("an incomplete SAML config is refused", async () => {
    const { ports } = harness(samlConfig({ samlAcsUrl: null }));
    await expectFlowRefusal(
      handleSamlAuthorize(ports, TENANT),
      "saml_config_incomplete",
      500,
      "SAML configuration is incomplete",
    );
  });
});

describe("assertion consumer service (ACS)", () => {
  let fixture: Harness;
  let state: string;
  let requestId: string;

  beforeEach(async () => {
    fixture = harness();
    const authorize = await handleSamlAuthorize(fixture.ports, TENANT);
    state = authorize.state;
    requestId = fixture.stores.flows.peek(state)?.requestId ?? "";
    expect(requestId).not.toBe("");
  });

  async function idpRedirect(options: { key?: string; relayState?: string } = {}): Promise<string> {
    const xml = sampleResponseXml({ inResponseTo: requestId });
    return signedQuery(
      options.key ?? IDP_KEY_PKCS8_PEM,
      toBase64(await deflateRaw(xml)),
      options.relayState ?? state,
    );
  }

  test("a valid signed assertion is accepted and yields the identity", async () => {
    const result = await handleSamlAcs(fixture.ports, await idpRedirect());
    expect(result).toEqual({
      tenantId: TENANT,
      email: "user@example.com",
      displayName: "Ada Lovelace",
      groups: ["Engineering", "Admins"],
      groupRoleMapping: { Admins: "admin" },
      defaultRole: "member",
    });
  });

  test("a REPLAYED assertion is refused — the pending flow is single-use", async () => {
    const query = await idpRedirect();
    await expect(handleSamlAcs(fixture.ports, query)).resolves.toMatchObject({
      email: "user@example.com",
    });
    // Byte-identical replay of a redirect whose signature is still perfectly
    // valid. Only the consumed state stops it.
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "unknown_saml_state",
      401,
      "unknown, expired, or already-used SAML state",
    );
  });

  test("an EXPIRED pending flow is refused", async () => {
    const query = await idpRedirect();
    fixture.setNow(1_704_067_200 + 601);
    await expectFlowRefusal(handleSamlAcs(fixture.ports, query), "unknown_saml_state", 401);
  });

  test("an unknown RelayState is refused", async () => {
    const query = await idpRedirect({ relayState: "never-issued-state" });
    await expectFlowRefusal(handleSamlAcs(fixture.ports, query), "unknown_saml_state", 401);
  });

  test("a missing RelayState is refused", async () => {
    const query = (await idpRedirect()).replace(/RelayState=[^&]*&/, "");
    expect(query).not.toContain("RelayState=");
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "missing_relay_state",
      422,
      "missing RelayState",
    );
  });

  test("an assertion signed by an UNKNOWN issuer's key is refused with 401", async () => {
    const query = await idpRedirect({ key: OTHER_KEY_PKCS8_PEM });
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "saml_signature_verification_failed",
      401,
      /^SAML signature verification failed: signature does not verify/,
    );
  });

  test("a TAMPERED assertion is refused with 401", async () => {
    // Swap the signed payload for a DIFFERENT, well-formed assertion that
    // claims a different email. The RelayState is left intact so the flow still
    // resolves and the refusal can only come from the signature check.
    const query = await idpRedirect();
    const evil = toBase64(
      await deflateRaw(sampleResponseXml({ inResponseTo: requestId, email: "victim@example.com" })),
    );
    const tampered = query.replace(/SAMLResponse=[^&]*/, `SAMLResponse=${idpPercentEncode(evil)}`);
    expect(tampered).not.toBe(query);
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, tampered),
      "saml_signature_verification_failed",
      401,
    );
    // ...and the flow was still consumed, so the tamper cannot be retried into
    // a race with the honest redirect.
    expect(fixture.stores.flows.peek(state)).toBeNull();
  });

  test("a refused signature never reaches assertion parsing (order is load-bearing)", async () => {
    // An assertion whose CONTENT is fine but whose signature is wrong must be
    // refused by the signature check. If the order were reversed, an attacker
    // could probe assertion-validation behaviour with unsigned payloads.
    const query = await idpRedirect({ key: OTHER_KEY_PKCS8_PEM });
    const error = await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "saml_signature_verification_failed",
      401,
    );
    expect(error.message).not.toMatch(/assertion/);
  });

  test("an expired ASSERTION (valid signature, stale Conditions) is refused with 401", async () => {
    const xml = sampleResponseXml({
      inResponseTo: requestId,
      notBefore: "2020-01-01T00:00:00Z",
      notOnOrAfter: "2020-01-01T01:00:00Z",
    });
    const query = await signedQuery(IDP_KEY_PKCS8_PEM, toBase64(await deflateRaw(xml)), state);
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "saml_assertion_rejected",
      401,
      /^SAML assertion rejected: assertion has expired \(NotOnOrAfter\)$/,
    );
  });

  test("a response replaying ANOTHER flow's InResponseTo is refused", async () => {
    const other = await handleSamlAuthorize(fixture.ports, TENANT);
    const otherRequestId = fixture.stores.flows.peek(other.state)?.requestId ?? "";
    expect(otherRequestId).not.toBe(requestId);
    const xml = sampleResponseXml({ inResponseTo: otherRequestId });
    const query = await signedQuery(IDP_KEY_PKCS8_PEM, toBase64(await deflateRaw(xml)), state);
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "saml_assertion_rejected",
      401,
      /InResponseTo/,
    );
  });

  test("a config removed mid-flow refuses rather than proceeding unverified", async () => {
    const query = await idpRedirect();
    fixture.stores.configs.remove(TENANT);
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "saml_config_removed_mid_flow",
      500,
      "SAML configuration was removed mid-flow",
    );
  });

  test("a config switched to OIDC mid-flow refuses", async () => {
    const query = await idpRedirect();
    fixture.stores.configs.put(samlConfig({ providerKind: "oidc" }));
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "sso_config_no_longer_saml",
      500,
      "SSO configuration is no longer SAML",
    );
  });

  test("a config with no certificate refuses rather than skipping verification", async () => {
    const query = await idpRedirect();
    fixture.stores.configs.put(samlConfig({ samlIdpCertificate: null }));
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "saml_config_missing_certificate",
      500,
      "SAML configuration is missing the IdP certificate",
    );
  });

  test("a pending flow belonging to the OIDC flow kind is refused", async () => {
    fixture.stores.flows.insertRaw({
      state: "oidc-state",
      tenantId: TENANT,
      providerKind: "oidc",
      codeVerifier: "v",
      requestId: null,
      createdAtUnix: 1_704_067_200,
      expiresAtUnix: 1_704_067_800,
    });
    const xml = sampleResponseXml({ inResponseTo: requestId });
    const query = await signedQuery(
      IDP_KEY_PKCS8_PEM,
      toBase64(await deflateRaw(xml)),
      "oidc-state",
    );
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "flow_not_saml",
      422,
      "this pending flow is not a SAML flow",
    );
  });

  test("an ACS with no query at all is refused", async () => {
    await expectFlowRefusal(handleSamlAcs(fixture.ports, ""), "missing_relay_state", 422);
  });

  test("a redirect with NO SAMLResponse at all is refused at the signature step", async () => {
    // The signed octet string cannot even be reconstructed, so verification
    // refuses before anything downstream sees a missing payload.
    const query =
      `RelayState=${idpPercentEncode(state)}` +
      `&SigAlg=${idpPercentEncode(SIG_ALG_SHA256)}&Signature=AAAA`;
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "saml_signature_verification_failed",
      401,
      /missing SAMLResponse/,
    );
  });

  test("an unsupported SigAlg is refused at the ACS boundary too", async () => {
    const query = `SAMLResponse=AAAA&RelayState=${idpPercentEncode(state)}&SigAlg=x&Signature=AAAA`;
    await expectFlowRefusal(
      handleSamlAcs(fixture.ports, query),
      "saml_signature_verification_failed",
      401,
      /unsupported SigAlg "x"/,
    );
  });
});
