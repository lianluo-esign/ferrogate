/**
 * `GET /v1/skills` + `GET /v1/skills/{id}` — the skill-package catalog.
 *
 * ## What makes the deployed cases MOUNT GATES
 *
 * These two operations answered `501 not_implemented` until this slice, and the
 * failure mode this project keeps hitting is a handler that is written, unit
 * tested, and never reached. So the `SELF` cases below do not assert "200" —
 * a 200 would also come from a stub that returns an empty list. They assert a
 * package id, version and capability list that exist ONLY in
 * `GATEWAY_SKILL_PACKAGES`, so the only way to satisfy them is for
 * `listAgentSkillsHandler` / `getAgentSkillHandler` to be the handler the
 * contract router actually mounted and for it to have read that var.
 *
 * Remove either `router.register(...)` line in `src/routes/index.ts` and the
 * deployed cases go red (the contract anti-drift test in `test/contract.test.ts`
 * goes red too); swap the handler for `registerDropped` and they go red with a
 * 501.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  agentSkillListDocument,
  agentSkillPackage,
  parseSkillPackages,
  skillPackageVisibleToAuth,
} from "../../src/routes/skills.js";
import type { AuthContext } from "../../src/ports.js";

const BASE = "https://ferrogate.test";

/**
 * Three packages that exercise all three visibility legs at once:
 * public, key-pinned to the fixture key, and disabled.
 */
const SKILL_PACKAGES = [
  {
    id: "pkg_public",
    name: "Public Package",
    version: "2.3.1",
    description: "visible to every caller",
    capabilities: [
      { kind: "tool", id: "cap_search", description: "search the corpus" },
      { kind: "prompt_template", id: "cap_summarize" },
    ],
    compatibility: { min_gateway_version: "1.4.0", agent_runtimes: ["workers"] },
    // NOT projected onto the wire — the assertions below prove that.
    permissions: { shell: true, secrets: true },
    metadata: { internal_owner: "platform-team" },
  },
  {
    id: "pkg_pinned",
    name: "Pinned Package",
    version: "0.9.0",
    api_key_ids: ["key_readonly"],
    capabilities: [{ kind: "mcp_server", id: "cap_mcp" }],
  },
  {
    id: "pkg_other_key",
    name: "Someone Else's Package",
    version: "1.0.0",
    api_key_ids: ["key_tools"],
  },
  { id: "pkg_disabled", name: "Disabled Package", version: "1.0.0", enabled: false },
];

const mutable = env as unknown as Record<string, unknown>;
let originalVar: unknown;

beforeAll(() => {
  originalVar = mutable["GATEWAY_SKILL_PACKAGES"];
  mutable["GATEWAY_SKILL_PACKAGES"] = JSON.stringify(SKILL_PACKAGES);
});

afterAll(() => {
  mutable["GATEWAY_SKILL_PACKAGES"] = originalVar;
});

function auth(subject: string | null): AuthContext {
  return {
    subject,
    tenancy: { tenantId: "tenant_a" },
    scopes: ["skills.read"],
    platformOperator: false,
    source: "durable_native",
  };
}

interface ErrorEnvelope {
  error: { message: string; type: string; code: string; request_id: string | null };
}

// ---------------------------------------------------------------------------
// The projection, as pure functions
// ---------------------------------------------------------------------------

describe("parseSkillPackages — fail-closed, entry by entry", () => {
  it("treats absent, blank, non-JSON and non-array values as NO packages", () => {
    expect(parseSkillPackages(undefined)).toEqual([]);
    expect(parseSkillPackages("   ")).toEqual([]);
    expect(parseSkillPackages("{not json")).toEqual([]);
    expect(parseSkillPackages('{"id":"pkg"}')).toEqual([]);
  });

  it("drops only the entry the schema refuses, never the whole table", () => {
    const parsed = parseSkillPackages(
      JSON.stringify([{ id: "good", name: "Good" }, { name: "no id" }, 7, null]),
    );
    expect(parsed.map((pkg) => pkg.id)).toEqual(["good"]);
    // The config schema's own defaults, not a private re-declaration here.
    expect(parsed[0]?.version).toBe("0.1.0");
    expect(parsed[0]?.enabled).toBe(true);
    expect(parsed[0]?.api_key_ids).toEqual([]);
  });
});

describe("skillPackageVisibleToAuth", () => {
  const packages = parseSkillPackages(JSON.stringify(SKILL_PACKAGES));
  const find = (id: string) => packages.find((pkg) => pkg.id === id)!;

  it("hides a DISABLED package from everyone, allowlist or not", () => {
    expect(skillPackageVisibleToAuth(find("pkg_disabled"), auth("key_readonly"))).toBe(false);
    expect(skillPackageVisibleToAuth(find("pkg_disabled"), auth(null))).toBe(false);
  });

  it("shows an unpinned package to every caller, including one with no subject", () => {
    expect(skillPackageVisibleToAuth(find("pkg_public"), auth("key_readonly"))).toBe(true);
    expect(skillPackageVisibleToAuth(find("pkg_public"), auth(null))).toBe(true);
    expect(skillPackageVisibleToAuth(find("pkg_public"), null)).toBe(true);
  });

  it("matches a pinned package against the API-KEY id, not the tenant", () => {
    // Both callers below are tenant_a; only the named KEY sees the package.
    expect(skillPackageVisibleToAuth(find("pkg_pinned"), auth("key_readonly"))).toBe(true);
    expect(skillPackageVisibleToAuth(find("pkg_pinned"), auth("key_tools"))).toBe(false);
    expect(skillPackageVisibleToAuth(find("pkg_pinned"), auth(null))).toBe(false);
  });
});

describe("agentSkillPackage", () => {
  const pkg = parseSkillPackages(JSON.stringify(SKILL_PACKAGES))[0]!;

  it("projects exactly the six Rust fields", () => {
    expect(Object.keys(agentSkillPackage(pkg)).sort()).toEqual([
      "capabilities",
      "compatibility",
      "description",
      "id",
      "name",
      "version",
    ]);
  });

  it("never leaks permissions, resources, metadata or the allowlist", () => {
    const projected = agentSkillPackage(pkg) as unknown as Record<string, unknown>;
    expect(projected["permissions"]).toBeUndefined();
    expect(projected["resources"]).toBeUndefined();
    expect(projected["metadata"]).toBeUndefined();
    expect(projected["api_key_ids"]).toBeUndefined();
  });

  it("serializes an absent description as an explicit null", () => {
    const pinned = parseSkillPackages(JSON.stringify(SKILL_PACKAGES))[1]!;
    expect(agentSkillPackage(pinned).description).toBeNull();
  });
});

describe("agentSkillListDocument", () => {
  it("keeps declared order and filters by visibility", () => {
    const document = agentSkillListDocument(
      parseSkillPackages(JSON.stringify(SKILL_PACKAGES)),
      auth("key_readonly"),
    );
    expect(document.object).toBe("list");
    expect(document.data.map((pkg) => pkg.id)).toEqual(["pkg_public", "pkg_pinned"]);
  });
});

// ---------------------------------------------------------------------------
// MOUNT — the app the Worker exports
// ---------------------------------------------------------------------------

describe("MOUNT: the deployed Worker serves the skill catalog", () => {
  it("GET /v1/skills returns the CONFIGURED packages, not an empty list", async () => {
    const res = await SELF.fetch(`${BASE}/v1/skills`, {
      headers: { authorization: "Bearer fg_tenant_readonly" },
    });
    // 501 here means the stub is still mounted; 404 means nothing is.
    expect(res.status).toBe(200);
    const body = (await res.json()) as { object: string; data: Record<string, unknown>[] };
    expect(body.object).toBe("list");
    // Values that exist ONLY in GATEWAY_SKILL_PACKAGES: an empty-list stub or a
    // handler that never read the var cannot produce them.
    expect(body.data.map((pkg) => pkg["id"])).toEqual(["pkg_public", "pkg_pinned"]);
    expect(body.data[0]).toMatchObject({
      name: "Public Package",
      version: "2.3.1",
      description: "visible to every caller",
      compatibility: { min_gateway_version: "1.4.0", agent_runtimes: ["workers"] },
    });
    expect(body.data[0]?.["capabilities"]).toEqual([
      { kind: "tool", id: "cap_search", description: "search the corpus" },
      { kind: "prompt_template", id: "cap_summarize", description: null },
    ]);
  });

  it("GET /v1/skills/{id} returns the single package the router's path param named", async () => {
    const res = await SELF.fetch(`${BASE}/v1/skills/pkg_pinned`, {
      headers: { authorization: "Bearer fg_tenant_readonly" },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      id: "pkg_pinned",
      name: "Pinned Package",
      version: "0.9.0",
      description: null,
      capabilities: [{ kind: "mcp_server", id: "cap_mcp", description: null }],
      compatibility: { min_gateway_version: null, agent_runtimes: [] },
    });
  });

  it("404s a package pinned to ANOTHER key — never 403, so ids cannot be enumerated", async () => {
    const res = await SELF.fetch(`${BASE}/v1/skills/pkg_other_key`, {
      headers: { authorization: "Bearer fg_tenant_readonly" },
    });
    expect(res.status).toBe(404);
    expect(res.status).not.toBe(403);
    const body = (await res.json()) as ErrorEnvelope;
    expect(body.error.code).toBe("skill_package_not_found");
    // Byte-identical to a genuinely unknown id: the two are indistinguishable.
    const unknown = await SELF.fetch(`${BASE}/v1/skills/pkg_no_such_thing`, {
      headers: { authorization: "Bearer fg_tenant_readonly" },
    });
    expect(unknown.status).toBe(404);
    expect((await unknown.json() as ErrorEnvelope).error.message).toBe(
      body.error.message.replace("pkg_other_key", "pkg_no_such_thing"),
    );
  });

  it("404s a DISABLED package even though it is declared", async () => {
    const res = await SELF.fetch(`${BASE}/v1/skills/pkg_disabled`, {
      headers: { authorization: "Bearer fg_tenant_readonly" },
    });
    expect(res.status).toBe(404);
  });

  it("still refuses an anonymous caller BEFORE the handler runs", async () => {
    // The auth ladder the 501 stub used to prove is preserved by the real
    // handler: `contractAuth` answers first, so no catalog leaks.
    const anonymous = await SELF.fetch(`${BASE}/v1/skills`);
    expect(anonymous.status).toBe(401);
    expect((await anonymous.json() as ErrorEnvelope).error.code).toBe("missing_api_key");

    const underScoped = await SELF.fetch(`${BASE}/v1/skills`, {
      // fg_tenant_tools holds tools.read/tools.execute, never skills.read.
      headers: { authorization: "Bearer fg_tenant_tools" },
    });
    expect(underScoped.status).toBe(403);
    expect((await underScoped.json() as ErrorEnvelope).error.code).toBe("scope_denied");
  });
});
