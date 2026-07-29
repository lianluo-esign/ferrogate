// Wire-contract drift alarm for the site-domain admin surface (issues #345,
// #488), modelled on overview.contract.test.ts (#343).
//
// Why this exists: the generated client declares `AdminSiteDomain.serving` and
// `.verification_state` OPTIONAL, while the gateway serializes both on EVERY
// binding it returns — `admin_site_domain()` sets them unconditionally and the
// struct carries no `skip_serializing_if`. `tsc` therefore accepts a fixture
// that omits them, i.e. a wire message the gateway never sends. That is exactly
// how the console's domain tests stayed green while the drawer rendered a
// hostname the gateway REFUSES identically to a live one: the fixtures simply
// never mentioned liveness, so nothing could observe that the console dropped
// it. Making the console's own fixtures `Required` closes the console half; this
// closes the server half — if the gateway renames, retypes, or starts skipping
// either field, this fails with the diff instead of the console silently
// printing `Unknown` (or worse) forever.
//
// It reads the SERVER structs directly, so there is no second artifact to
// forget to update.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Vitest runs with `admin-console/` as its root, so the gateway sources sit one
// directory up.
const GATEWAY = resolve(process.cwd(), "../crates/ferrogate-gateway/src/server");
const SITE_DOMAINS = resolve(GATEWAY, "site_domains.rs");
const VERIFICATION = resolve(GATEWAY, "site_domain_verification.rs");
const STORAGE_STATE = resolve(
  process.cwd(),
  "../crates/ferrogate-storage/src/site_domain_verification.rs",
);

/**
 * The serialized shapes the console parses. Keys are Rust struct names; values
 * map each serialized field to its Rust type as written.
 */
const EXPECTED: Record<string, Record<string, string>> = {
  // src/components/site-domain-liveness.tsx renders `serving` +
  // `verification_state`; site-domains.tsx and static-sites.tsx render the rest.
  AdminSiteDomain: {
    object: "&'static str",
    hostname: "String",
    tenant_id: "String",
    site: "String",
    serve_path: "String",
    verification_state: "&'static str",
    serving: "bool",
    created_at_unix: "i64",
    updated_at_unix: "i64",
  },
  AdminSiteDomainAcme: {
    enabled: "bool",
    reload_triggered: "bool",
  },
  AdminSiteDomainResponse: {
    object: "&'static str",
    site_domain: "AdminSiteDomain",
    acme: "AdminSiteDomainAcme",
    verification: "Option<AdminSiteDomainVerification>",
  },
  // The challenge record the console shows an operator to publish.
  AdminSiteDomainVerification: {
    object: "&'static str",
    state: "&'static str",
    serves: "bool",
    tenant_id: "String",
    hostname: "String",
    site: "String",
    challenge_record_name: "String",
    challenge_record_type: "&'static str",
    challenge_record_value: "String",
    issued_at_unix: "i64",
    token_expires_at_unix: "i64",
    verified_at_unix: "Option<i64>",
    verification_expires_at_unix: "Option<i64>",
    last_checked_at_unix: "Option<i64>",
    last_failure_reason: "Option<String>",
    attempt_count: "i64",
  },
};

/** The struct body of `[pub(...)] struct <name> { … }`, verbatim. */
function structBody(source: string, name: string): string {
  const match = new RegExp(
    `(?:pub(?:\\([^)]*\\))? )?struct ${name} \\{\\n([\\s\\S]*?)\\n\\}`,
    "m",
  ).exec(source);
  if (!match) throw new Error(`struct ${name} not found`);
  return match[1];
}

/** Extract `field: Type` pairs, ignoring doc comments and attributes. */
function structFields(source: string, name: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const line of structBody(source, name).split("\n")) {
    const field = /^\s*(?:pub(?:\([^)]*\))? )?(\w+): (.+),$/.exec(line);
    if (field) fields[field[1]] = field[2];
  }
  return fields;
}

describe("site-domain admin wire contract", () => {
  const siteDomains = readFileSync(SITE_DOMAINS, "utf8");
  const verification = readFileSync(VERIFICATION, "utf8");
  const sourceFor = (name: string) =>
    name === "AdminSiteDomainVerification" ? verification : siteDomains;

  for (const [name, expected] of Object.entries(EXPECTED)) {
    it(`${name} still serializes the fields the console parses`, () => {
      expect(structFields(sourceFor(name), name)).toEqual(expected);
    });
  }

  it("emits a binding's liveness unconditionally (no skip_serializing_if)", () => {
    // The console treats an ABSENT `serving`/`verification_state` as "unknown"
    // and its fixtures declare both required. Both rest on the gateway never
    // omitting them; a `skip_serializing_if` here would turn "the gateway did
    // not tell us" into an indistinguishable, permanently-Unknown row.
    expect(structBody(siteDomains, "AdminSiteDomain")).not.toContain(
      "skip_serializing_if",
    );
  });

  it("verification_state ranges over exactly the states the console labels", () => {
    // src/components/site-domain-liveness.tsx maps every state to a label, plus
    // `no_verification` for a binding with no proof record at all
    // (`verification_state: verification.map_or("no_verification", …)`).
    const state = readFileSync(STORAGE_STATE, "utf8");
    const wireStates = [...state.matchAll(/=> "([a-z_]+)",\n/g)].map(
      (match) => match[1],
    );
    expect(new Set(wireStates)).toEqual(
      new Set([
        "pending_verification",
        "verified",
        "grandfathered",
        "expired",
      ]),
    );
    expect(siteDomains).toContain('verification.map_or("no_verification"');
  });
});
