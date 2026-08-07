// Wire-contract drift alarm for the site-domain admin surface (issues #345,
// #488, #738), modelled on overview.contract.test.ts (#343).
//
// Why this exists: the generated client declares `AdminSiteDomain.serving` and
// `.verification_state` OPTIONAL, while the server serializes both on every
// binding it returns. `tsc` therefore accepts a fixture that omits them, i.e. a
// wire message the server never sends — which is exactly how the console's
// domain tests stayed green while the drawer rendered a hostname the gateway
// REFUSES identically to a live one. Making the console's own fixtures
// `Required` closes the console half; this file pins the CONTRACT half: if the
// served shape renames, retypes, or drops either liveness field — or any other
// field the console parses — this fails with the diff instead of the console
// silently printing `Unknown` (or worse) forever.
//
// RE-ANCHORED (2026-08): this test used to read the Rust server structs
// (`crates/ferrogate-gateway/src/server/site_domains.rs` +
// `site_domain_verification.rs`); the Rust tree was deleted on 2026-08-02. The
// surviving authorities are the shared contract,
// `docs/openapi/admin-api.openapi.json` (the AdminSiteDomain* schemas, which
// carry every previously-pinned field), and the TS backend route
// `apps/control-plane/src/routes/site_domain.ts`. The pins below hold the
// schemas, field-for-field, with `additionalProperties: false` making each
// field list exhaustive in BOTH directions.
//
// Two deliberate contract-alignment notes, per the re-anchor rules:
//
//  * The old "no `skip_serializing_if`" pin has no schema equivalent — Rust's
//    unconditional serialization became "declared but NOT required" in the
//    contract (#488 declared the liveness pair optional). That required-list is
//    pinned exactly below, and the console keeps rendering an absent value as
//    `Unknown` (src/components/site-domain-liveness.tsx), never as a verdict.
//  * The #738 detail read (`AdminSiteDomainReadResponse`, GET
//    /admin/v1/site-domains/{hostname}) replaced the old `acme`/`verification`
//    posture with `certificate_status` + `certificate`; the bind/verify
//    mutation responses (`AdminSiteDomainResponse`) still carry `acme` and the
//    optional `verification` block. Both envelopes are pinned.
import { describe, expect, it } from "vitest";
import {
  contractOperation,
  contractSchema,
  fieldShapes,
  responseSchemaRef,
  sortedRequired,
} from "@/lib/contract-pin";

/**
 * The serialized shapes the console parses: `field -> descriptor` (see
 * `fieldShape` in src/lib/contract-pin.ts), plus each schema's exact
 * `required` list. Keys are the contract schema names — the same names the
 * deleted Rust structs carried.
 */
const EXPECTED: Record<string, { fields: Record<string, string>; required: string[] }> = {
  // src/components/site-domain-liveness.tsx renders `serving` +
  // `verification_state`; site-domains.tsx and static-sites.tsx render the rest.
  AdminSiteDomain: {
    fields: {
      object: "const:site_domain",
      hostname: "string",
      tenant_id: "string",
      site: "string",
      serve_path: "string",
      // `no_verification` is the binding-level extra state: "no proof record
      // exists at all" (Rust's `verification.map_or("no_verification", …)`).
      verification_state:
        "enum:no_verification|pending_verification|verified|grandfathered|expired",
      serving: "boolean",
      created_at_unix: "integer:int64",
      updated_at_unix: "integer:int64",
    },
    required: [
      "created_at_unix",
      "hostname",
      "object",
      "serve_path",
      "site",
      "tenant_id",
      "updated_at_unix",
    ],
  },
  AdminSiteDomainAcme: {
    fields: {
      enabled: "boolean",
      reload_triggered: "boolean",
    },
    required: ["enabled", "reload_triggered"],
  },
  // Bind/verify mutation envelope. `verification` was Rust's
  // `Option<AdminSiteDomainVerification>`: declared, not required.
  AdminSiteDomainResponse: {
    fields: {
      object: "const:site_domain",
      site_domain: "ref:AdminSiteDomain",
      acme: "ref:AdminSiteDomainAcme",
      verification: "ref:AdminSiteDomainVerification",
    },
    required: ["acme", "object", "site_domain"],
  },
  // The challenge record the console shows an operator to publish. The
  // `required` split reproduces the Rust field list exactly: every non-Option
  // field is required, every `Option<…>` field is nullable-and-optional.
  AdminSiteDomainVerification: {
    fields: {
      object: "const:site_domain_verification",
      state: "enum:pending_verification|verified|grandfathered|expired",
      serves: "boolean",
      tenant_id: "string",
      hostname: "string",
      site: "string",
      challenge_record_name: "string",
      challenge_record_type: "const:TXT",
      challenge_record_value: "string",
      issued_at_unix: "integer:int64",
      token_expires_at_unix: "integer:int64",
      verified_at_unix: "integer:int64|null",
      verification_expires_at_unix: "integer:int64|null",
      last_checked_at_unix: "integer:int64|null",
      last_failure_reason: "string|null",
      attempt_count: "integer:int64",
    },
    required: [
      "attempt_count",
      "challenge_record_name",
      "challenge_record_type",
      "challenge_record_value",
      "hostname",
      "issued_at_unix",
      "object",
      "serves",
      "site",
      "state",
      "tenant_id",
      "token_expires_at_unix",
    ],
  },
  // #738: the per-hostname detail read. `certificate_status` + `certificate`
  // stand where the old read carried the acme/verification posture; the
  // certificate is REQUIRED here (and deliberately absent from the list read —
  // N bindings would be N outbound Cloudflare calls per page).
  AdminSiteDomainReadResponse: {
    fields: {
      object: "const:site_domain",
      site_domain: "ref:AdminSiteDomain",
      certificate_status: "ref:AdminSiteDomainCertificateStatus",
      certificate: "ref:AdminSiteDomainCertificate",
      verification: "ref:AdminSiteDomainVerification",
    },
    required: ["certificate", "certificate_status", "object", "site_domain"],
  },
  AdminSiteDomainCertificate: {
    fields: {
      backend: "string",
      hostname_status: "string|null",
      ssl_status: "string|null",
      detail: "string|null",
      validation_records: "array<ref:AdminSiteDomainCertificateRecord>|null",
    },
    required: ["backend"],
  },
  AdminSiteDomainCertificateRecord: {
    fields: {
      name: "string",
      type: "string",
      value: "string",
    },
    required: ["name", "type", "value"],
  },
  AdminSiteDomainList: {
    fields: {
      object: "const:list",
      data: "array<ref:AdminSiteDomain>",
    },
    required: ["data", "object"],
  },
};

describe("site-domain admin wire contract", () => {
  for (const [name, expected] of Object.entries(EXPECTED)) {
    it(`${name} still declares the fields the console parses`, () => {
      const schema = contractSchema(name);
      expect(fieldShapes(schema)).toEqual(expected.fields);
      expect(sortedRequired(schema)).toEqual(expected.required);
      // Closed schemas: the field lists above are exhaustive in both
      // directions, so an ADDED field fails here too and must be triaged into
      // the console (or deliberately excluded) rather than silently ignored.
      expect(schema.additionalProperties, `${name} additionalProperties`).toBe(false);
    });
  }

  it("every site-domain operation still answers with the pinned envelopes", () => {
    expect(
      responseSchemaRef(contractOperation("/admin/v1/site-domains", "get"), "200"),
    ).toBe("#/components/schemas/AdminSiteDomainList");
    expect(
      responseSchemaRef(contractOperation("/admin/v1/site-domains", "post"), "201"),
    ).toBe("#/components/schemas/AdminSiteDomainResponse");
    // #738: the detail read is the ONE surface that carries the certificate.
    expect(
      responseSchemaRef(contractOperation("/admin/v1/site-domains/{hostname}", "get"), "200"),
    ).toBe("#/components/schemas/AdminSiteDomainReadResponse");
    expect(
      responseSchemaRef(
        contractOperation("/admin/v1/site-domains/{hostname}/verify", "post"),
        "200",
      ),
    ).toBe("#/components/schemas/AdminSiteDomainResponse");
  });

  it("declares a binding's liveness pair on every AdminSiteDomain (optional, rendered Unknown when absent)", () => {
    // Successor to the Rust "no skip_serializing_if" pin. The contract keeps
    // `serving`/`verification_state` OPTIONAL (#488 declared them so), which
    // the console honours by treating an ABSENT value as "unknown" — never as
    // either verdict (src/components/site-domain-liveness.tsx). What must not
    // drift: the pair stays DECLARED with these exact names, and never becomes
    // required silently (fixtures and the tri-state rendering both hang off
    // optionality). Both halves are pinned by the shape maps above; this spells
    // the optionality out so a required-list change reads as deliberate.
    const domain = contractSchema("AdminSiteDomain");
    expect(Object.keys(domain.properties ?? {})).toContain("serving");
    expect(Object.keys(domain.properties ?? {})).toContain("verification_state");
    expect(sortedRequired(domain)).not.toContain("serving");
    expect(sortedRequired(domain)).not.toContain("verification_state");
  });

  it("verification_state ranges over exactly the states the console labels", () => {
    // src/components/site-domain-liveness.tsx maps every state to a label
    // (exhaustive by construction over the generated union). The binding-level
    // enum must stay the verification-record enum PLUS `no_verification` —
    // Rust's `verification.map_or("no_verification", …)`, now a schema fact.
    const domainStates = contractSchema("AdminSiteDomain").properties?.verification_state?.enum;
    const recordStates = contractSchema("AdminSiteDomainVerification").properties?.state?.enum;
    expect(new Set(recordStates)).toEqual(
      new Set(["pending_verification", "verified", "grandfathered", "expired"]),
    );
    expect(new Set(domainStates)).toEqual(new Set([...(recordStates ?? []), "no_verification"]));
  });

  it("certificate_status ranges over exactly the states the console classifies (#738)", () => {
    // `livenessOf` (src/pages/static-sites.tsx) folds this enum into the ACME
    // tri-state: `unconfigured`/`unknown`/`unavailable` mean "cannot know",
    // `active`/`issued_not_routing` mean "certificate is live", the rest mean
    // "not working yet, with a named next action". A renamed or added value
    // must be re-triaged there, so the whole enum is pinned.
    const status = contractSchema("AdminSiteDomainCertificateStatus");
    expect(new Set(status.enum)).toEqual(
      new Set([
        "unconfigured",
        "not_provisioned",
        "unavailable",
        "pending_validation",
        "provisioning",
        "issued_not_routing",
        "active",
        "timed_out",
        "expired",
        "blocked",
        "inactive",
        "unknown",
      ]),
    );
  });
});
