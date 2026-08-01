import { describe, expect, test } from "vitest";
import { SamlFlowError, admitSamlConfig } from "../src/index.js";
import { EC_CERT_PEM, IDP_CERT_PEM } from "./fixtures.js";

const BASE = {
  providerKind: "saml",
  defaultRole: "member",
  groupRoleMapping: { Admins: "admin" },
  idpEntityId: "https://idp.example/entity",
  idpSsoUrl: "https://idp.example/sso",
  idpCertificate: IDP_CERT_PEM,
  spEntityId: "sp-entity-id",
  acsUrl: "https://sp.example/acs",
  emailAttribute: "email",
  nameAttribute: "displayName",
  groupsAttribute: "groups",
};

function refusal(payload: Record<string, unknown>, code: string, message?: RegExp): SamlFlowError {
  let caught: unknown = null;
  try {
    admitSamlConfig("tenant_acme", payload as never, { nowUnix: 100, createdAtUnix: 100 });
  } catch (error) {
    caught = error;
  }
  expect(caught, "the config must be REFUSED").toBeInstanceOf(SamlFlowError);
  const flowError = caught as SamlFlowError;
  expect(flowError.code).toBe(code);
  expect(flowError.status).toBe(422);
  if (message) expect(flowError.message).toMatch(message);
  return flowError;
}

describe("SAML SSO config admission (POST /v1/admin/team/sso-config)", () => {
  test("a complete config is admitted and trimmed", () => {
    const stored = admitSamlConfig(
      "tenant_acme",
      { ...BASE, idpSsoUrl: "  https://idp.example/sso  " },
      { nowUnix: 200, createdAtUnix: 100 },
    );
    expect(stored).toMatchObject({
      tenantId: "tenant_acme",
      providerKind: "saml",
      defaultRole: "member",
      samlIdpSsoUrl: "https://idp.example/sso",
      samlSpEntityId: "sp-entity-id",
      samlAcsUrl: "https://sp.example/acs",
      samlIdpEntityId: "https://idp.example/entity",
      createdAtUnix: 100,
      updatedAtUnix: 200,
    });
    expect(stored.oidcIssuer).toBeNull();
    expect(stored.samlIdpCertificate).toBe(IDP_CERT_PEM);
  });

  test("an empty idp_entity_id is stored as null (issuer check disabled), not as ''", () => {
    const stored = admitSamlConfig(
      "tenant_acme",
      { ...BASE, idpEntityId: "   " },
      { nowUnix: 1, createdAtUnix: 1 },
    );
    expect(stored.samlIdpEntityId).toBeNull();
  });

  test.each(["idpSsoUrl", "idpCertificate", "spEntityId", "acsUrl"])(
    "a missing %s is refused",
    (field) => {
      refusal(
        { ...BASE, [field]: "   " },
        "saml_config_incomplete_fields",
        /idp_sso_url, idp_certificate, sp_entity_id, and acs_url are required for saml/,
      );
    },
  );

  test("an UNPARSEABLE certificate is refused AT CONFIG TIME, not at first login", () => {
    // The Rust port validated here deliberately: a tenant that saves a broken
    // certificate and only discovers it when a user cannot log in has a
    // fail-closed outage with no diagnosis.
    refusal(
      { ...BASE, idpCertificate: "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----" },
      "saml_certificate_unusable",
      /^idp_certificate is not a usable X\.509 certificate: certificate is not valid base64: /,
    );
  });

  test("a NON-RSA certificate is refused at config time", () => {
    refusal(
      { ...BASE, idpCertificate: EC_CERT_PEM },
      "saml_certificate_unusable",
      /idp_certificate is not a usable X\.509 certificate: invalid X\.509 certificate: /,
    );
  });

  test("a non-saml provider_kind is not this admitter's business", () => {
    refusal({ ...BASE, providerKind: "oidc" }, "not_saml_config", /provider_kind/);
  });
});
