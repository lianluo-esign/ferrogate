/**
 * #738 — the write half: a completed DNS proof has to land in the TYPED tables
 * `apps/gateway` routes an inbound hostname through, or the whole challenge is
 * ceremony.
 *
 * `routes/site_domain.ts` used to store `control_plane_resources` DOCUMENTS and
 * nothing else. `site_domains` had no writer at all and
 * `D1SiteDomainVerificationStore` was imported by no application module, so a
 * tenant could complete the challenge and the gateway — which reads the typed
 * tables — would see an empty directory. This file drives the real admin API
 * over `SELF.fetch` against the real control database and asserts the rows the
 * DATA PLANE reads, not the documents the admin surface returns.
 *
 * The challenge is completed for REAL: the token is minted by the route, read
 * back out of the store, and the digest the tenant would publish is computed
 * with the same `challengeTxtValue` the verifier uses and served through the
 * `static` resolver backend. Nothing is stubbed past the DNS boundary.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { challengeRecordName, challengeTxtValue } from "../src/site_domain_txt.js";
import {
  SITE_DOMAIN_CLAIM_SQL,
  claimSiteDomain,
  releaseSiteDomain,
} from "../src/store/site_domain.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, tenantKey } from "./harness.js";
import { rawTenantDocument } from "./tenant-object.js";

const HOST = "docs.acme.test";
const A = { tenant: "tenant_a", key: "key-tenant-a" };
const B = { tenant: "tenant_b", key: "key-tenant-b" };

type MutableEnv = Record<string, string | undefined>;

function armBoth(): void {
  arm({
    store: "d1",
    nativeKeys: [tenantKey(A.key, A.tenant), tenantKey(B.key, B.tenant)],
  });
}

/** Point the resolver at a curated answer document, or at nothing. */
function publishTxt(document: string | undefined): void {
  const bindings = env as unknown as MutableEnv;
  bindings.SITE_DOMAIN_RESOLVER = "static";
  bindings.SITE_DOMAIN_TXT_ANSWERS = document;
}

interface SiteDomainRow {
  hostname: string;
  tenant_id: string;
  site: string;
}

async function siteDomainRows(): Promise<SiteDomainRow[]> {
  const rows = await db()
    .prepare("SELECT hostname, tenant_id, site FROM site_domains ORDER BY hostname")
    .all<SiteDomainRow>();
  return rows.results;
}

async function verificationRow(
  tenantId: string,
): Promise<{ state: string; attempt_count: number } | null> {
  return await db()
    .prepare(
      "SELECT state, attempt_count FROM site_domain_verifications WHERE tenant_id = ? AND hostname = ?",
    )
    .bind(tenantId, HOST)
    .first<{ state: string; attempt_count: number }>();
}

/**
 * Bind the hostname, mint the challenge, publish the exact digest, and verify.
 * Returns the final `POST …/verify` response.
 */
async function proveOwnership(who: { tenant: string; key: string }): Promise<Response> {
  const bound = await SELF.fetch(
    `${BASE}/admin/v1/site-domains`,
    jsonRequest(who.key, "POST", { hostname: HOST, site_id: "acme" }),
  );
  expect(bound.status).toBe(201);

  // The first verify never verifies: it mints the per-(tenant, hostname) token
  // and answers 409 with the record to publish.
  publishTxt(undefined);
  const issued = await SELF.fetch(`${BASE}/admin/v1/site-domains/${HOST}/verify`, {
    method: "POST",
    headers: bearer(who.key),
  });
  expect(issued.status).toBe(409);

  // The verification document lives in the proving tenant's object (#861).
  const record = await rawTenantDocument(
    who.tenant,
    "site-domain-verifications",
    `${who.tenant}:${HOST}`,
  );
  const token = String(record?.challenge_token ?? "");
  expect(token).not.toBe("");

  // What the tenant would put in DNS — computed with the verifier's own
  // derivation, so this proves the round trip and not a re-implementation.
  const value = await challengeTxtValue(who.tenant, HOST, token);
  publishTxt(`${challengeRecordName(HOST)} ${value}`);

  return await SELF.fetch(`${BASE}/admin/v1/site-domains/${HOST}/verify`, {
    method: "POST",
    headers: bearer(who.key),
  });
}

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  await db().prepare("DELETE FROM site_domains").run();
  await db().prepare("DELETE FROM site_domain_verifications").run();
  armBoth();
});

describe("a completed proof lands in the tables the data plane reads (#738)", () => {
  it("writes BOTH typed rows, and the claim names the proving tenant", async () => {
    const verified = await proveOwnership(A);
    expect(verified.status).toBe(200);
    expect((await verified.json()) as { verified: boolean }).toMatchObject({ verified: true });

    // The row `apps/gateway/src/sites/domains.ts` joins on. Before this slice it
    // was never written by anything.
    expect(await siteDomainRows()).toEqual([{ hostname: HOST, tenant_id: A.tenant, site: "acme" }]);
    expect(await verificationRow(A.tenant)).toMatchObject({ state: "verified" });
  });

  it("a FAILED check writes the evidence but takes no claim", async () => {
    const bound = await SELF.fetch(
      `${BASE}/admin/v1/site-domains`,
      jsonRequest(A.key, "POST", { hostname: HOST, site_id: "acme" }),
    );
    expect(bound.status).toBe(201);
    publishTxt(undefined);
    expect(
      (
        await SELF.fetch(`${BASE}/admin/v1/site-domains/${HOST}/verify`, {
          method: "POST",
          headers: bearer(A.key),
        })
      ).status,
    ).toBe(409);

    // A resolver that answers, with the WRONG value: a real "not proven".
    publishTxt(`${challengeRecordName(HOST)} ferrogate-site-verification=deadbeef`);
    const failed = await SELF.fetch(`${BASE}/admin/v1/site-domains/${HOST}/verify`, {
      method: "POST",
      headers: bearer(A.key),
    });
    expect(failed.status).toBe(200);
    expect((await failed.json()) as { verified: boolean }).toMatchObject({ verified: false });

    // Evidence yes — `attempt_count` is what an operator triages from.
    expect(await verificationRow(A.tenant)).toMatchObject({ state: "pending_verification" });
    // Claim no. A hostname nobody proved must not become servable.
    expect(await siteDomainRows()).toEqual([]);
  });
});

describe("one domain, one owner", () => {
  it("the second tenant to BIND the hostname is refused, deterministically", async () => {
    expect((await proveOwnership(A)).status).toBe(200);

    // The document store keys `site-domains` on the hostname ALONE
    // (`control_plane_resources` is `(resource_kind, resource_id)`), so the
    // exclusion is decided at bind time and the loser is told with a 409 rather
    // than left with a binding that quietly never serves. First bind wins.
    //
    // Recorded rather than admired: the `site_domain_verifications` schema note
    // says several tenants may hold a PENDING challenge for one hostname so a
    // squatter cannot block the real owner, and a hostname-keyed DOCUMENT does
    // block them. That is pre-existing behaviour of the generic CRUD store, it
    // is not what #738 changed, and the typed claim below is the fence that
    // still holds if the document identity is ever made tenant-scoped.
    const second = await SELF.fetch(
      `${BASE}/admin/v1/site-domains`,
      jsonRequest(B.key, "POST", { hostname: HOST, site_id: "acme" }),
    );
    expect(second.status).toBe(409);

    expect(await siteDomainRows()).toEqual([{ hostname: HOST, tenant_id: A.tenant, site: "acme" }]);
  });

  it("claimSiteDomain refuses a hostname another tenant already holds", async () => {
    const now = 1_800_000_000;
    expect(await claimSiteDomain(db(), HOST, A.tenant, "acme", now)).toBe(true);
    // Re-verification by the SAME tenant renews the claim and may move the site.
    expect(await claimSiteDomain(db(), HOST, A.tenant, "acme-v2", now + 1)).toBe(true);
    // Another tenant cannot take it, even holding a completed proof of its own.
    expect(await claimSiteDomain(db(), HOST, B.tenant, "acme", now + 2)).toBe(false);
    expect(await siteDomainRows()).toEqual([
      { hostname: HOST, tenant_id: A.tenant, site: "acme-v2" },
    ]);
  });

  it("the ownership predicate is in the SQL that actually runs", () => {
    // The behavioural case above would also pass against a read-then-write,
    // which two concurrent verifications would both slip through.
    expect(SITE_DOMAIN_CLAIM_SQL).toContain("WHERE site_domains.tenant_id = excluded.tenant_id");
  });
});

describe("unbinding stops the serving", () => {
  it("DELETE drops the claim AND the evidence behind it", async () => {
    expect((await proveOwnership(A)).status).toBe(200);
    expect(await siteDomainRows()).toHaveLength(1);

    const removed = await SELF.fetch(`${BASE}/admin/v1/site-domains/${HOST}`, {
      method: "DELETE",
      headers: bearer(A.key),
    });
    expect(removed.status).toBe(200);

    // Both, or the operator is told a change took effect that did not: a
    // residual `site_domains` row keeps the hostname serving, and a residual
    // verification row would let a later re-bind serve on a proof nobody
    // re-established.
    expect(await siteDomainRows()).toEqual([]);
    expect(await verificationRow(A.tenant)).toBeNull();
  });

  it("releaseSiteDomain is fenced on the tenant", async () => {
    expect((await proveOwnership(A)).status).toBe(200);
    // The release another tenant's DELETE would produce. It must touch nothing:
    // an unfenced release is a way to knock a competitor's verified domain
    // offline.
    await releaseSiteDomain(db(), HOST, B.tenant);
    expect(await siteDomainRows()).toEqual([{ hostname: HOST, tenant_id: A.tenant, site: "acme" }]);
    expect(await verificationRow(A.tenant)).toMatchObject({ state: "verified" });
  });
});
