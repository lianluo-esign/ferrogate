/**
 * `/control/v1/*` and `/admin/v1/*` are ONE surface.
 *
 * `ROUTE-MAP.md` invariant 7. The fold happens at the fetch boundary, before
 * Hono routes, so the two spellings must be indistinguishable end to end: same
 * handler, same guard, same status, same body — including on the failure paths,
 * where a divergence would be a way to bypass a check by spelling the URL
 * differently.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { canonicalizeAliasRequest, canonicalizeAliasUrl } from "../src/middleware/alias.js";
import { BASE, arm, bearer, jsonRequest, operatorKey } from "./harness.js";

beforeEach(() => {
  arm({ staticKeys: [operatorKey] });
});

/** Both spellings of the same operation must answer identically. */
async function bothSpellings(
  suffix: string,
  init?: RequestInit,
): Promise<{ admin: Response; alias: Response }> {
  const admin = await SELF.fetch(`${BASE}/admin/v1${suffix}`, init);
  const alias = await SELF.fetch(`${BASE}/control/v1${suffix}`, init);
  return { admin, alias };
}

describe("alias canonicalization (URL level)", () => {
  it("preserves the query string and never redirects", () => {
    expect(canonicalizeAliasUrl("https://x.test/control/v1/plans?limit=5&offset=2")).toBe(
      "https://x.test/admin/v1/plans?limit=5&offset=2",
    );
    const rewritten = canonicalizeAliasRequest(
      new Request("https://x.test/control/v1/plans", { method: "POST", body: "{}" }),
    );
    expect(new URL(rewritten.url).pathname).toBe("/admin/v1/plans");
    expect(rewritten.method).toBe("POST");
  });

  it("leaves a non-alias request object untouched (same instance)", () => {
    const request = new Request("https://x.test/admin/v1/plans");
    expect(canonicalizeAliasRequest(request)).toBe(request);
  });
});

describe("/control/v1/* == /admin/v1/*", () => {
  it("reaches the same handler for a list read", async () => {
    const { admin, alias } = await bothSpellings("/plans", { headers: bearer(operatorKey.secret) });
    expect(admin.status).toBe(200);
    expect(alias.status).toBe(200);
    expect(await alias.json()).toEqual(await admin.json());
  });

  it("reaches the same handler for a status read", async () => {
    const { admin, alias } = await bothSpellings("/status", {
      headers: bearer(operatorKey.secret),
    });
    expect(admin.status).toBe(200);
    expect(alias.status).toBe(200);
    expect(await alias.json()).toEqual(await admin.json());
  });

  it("applies the SAME guard — an unauthenticated alias request is still 401", async () => {
    const { admin, alias } = await bothSpellings("/plans");
    expect(admin.status).toBe(401);
    expect(alias.status).toBe(401);
    const adminBody = (await admin.json()) as { error: { code: string } };
    const aliasBody = (await alias.json()) as { error: { code: string } };
    expect(aliasBody.error.code).toBe(adminBody.error.code);
    expect(aliasBody.error.code).toBe("missing_api_key");
  });

  it("applies the SAME 405 for an undocumented method", async () => {
    const { admin, alias } = await bothSpellings("/plans/plan_x", {
      method: "DELETE",
      headers: bearer(operatorKey.secret),
    });
    // The contract declares GET/PUT/PATCH on a plan, never DELETE.
    expect(admin.status).toBe(405);
    expect(alias.status).toBe(405);
  });

  it("round-trips a write made through the alias and read through the canonical path", async () => {
    const created = await SELF.fetch(
      `${BASE}/control/v1/plans`,
      jsonRequest(operatorKey.secret, "POST", { id: "plan_alias", name: "Alias Plan" }),
    );
    expect(created.status).toBe(201);

    const read = await SELF.fetch(`${BASE}/admin/v1/plans/plan_alias`, {
      headers: bearer(operatorKey.secret),
    });
    expect(read.status).toBe(200);
    expect((await read.json()) as { plan: { name: string } }).toMatchObject({
      object: "plan",
      plan: { id: "plan_alias", name: "Alias Plan" },
    });
  });

  it("does NOT capture a path that merely shares the prefix", async () => {
    // `/control/v1x/...` is a different resource; folding it would route an
    // unrelated URL onto the admin surface.
    const response = await SELF.fetch(`${BASE}/control/v1x/plans`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.status).toBe(404);
  });
});
