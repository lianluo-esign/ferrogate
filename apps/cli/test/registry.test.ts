import { describe, expect, test } from "vitest";
import { CliError } from "../src/errors.js";
import {
  GROUPS,
  GROUP_NAMES,
  ListParams,
  buildRequest,
  coverageManifest,
  redactResponse,
  resolveVerb,
  resourceInput,
  secretFieldsFor,
} from "../src/registry.js";

describe("the registry is data, and complete", () => {
  test("every family module's groups are registered", () => {
    // The 12 Rust family modules registered these groups; a group vanishing
    // from the data table silently removes a whole command surface.
    for (const expected of [
      "tenant-accounts",
      "tenants",
      "projects",
      "workspaces",
      "plans",
      "quota-policies",
      "virtual-keys",
      "api-keys",
      "roles",
      "permissions",
      "access-policies",
      "tenant-roles",
      "agent-workflows",
      "agent-schedules",
      "agent-upstreams",
      "agent-runs",
      "agent-jobs",
      "self-hosted-workers",
      "managed-workers",
      "managed-worker-sessions",
      "self-hosted-worker-records",
      "self-hosted-runs",
      "mcp-servers",
      "mcp-identity",
      "tool-sessions",
      "tools",
      "tool-approvals",
      "guardrail-policies",
      "guardrail-evaluations",
      "investigations",
      "assets",
      "asset-transfer",
      "asset-channels",
      "site-domains",
      "prompt-templates",
      "skill-packages",
      "plugins",
      "catalog",
      "dashboard",
      "wallets",
      "payment-methods",
      "billing-events",
      "usage",
      "payment-attempts",
      "request-logs",
      "audit-events",
      "observed-agent-activity",
      "system",
      "provider-health",
      "config",
      "drain",
      "gateway-configs",
    ]) {
      expect(GROUP_NAMES).toContain(expected);
    }
  });

  test("group names are unique and every group has at least one verb", () => {
    expect(new Set(GROUP_NAMES).size).toBe(GROUP_NAMES.length);
    for (const group of GROUPS) expect(group.verbs.length).toBeGreaterThan(0);
  });

  test("verb names are unique within a group", () => {
    for (const group of GROUPS) {
      const names = group.verbs.map((verb) => verb.name);
      expect(new Set(names).size, `duplicate verb in ${group.name}`).toBe(names.length);
    }
  });

  test("every verb declares an operationId for the coverage gate", () => {
    for (const group of GROUPS) {
      for (const verb of group.verbs) {
        expect(verb.operationId, `${group.name} ${verb.name}`).not.toBeNull();
      }
    }
    expect(coverageManifest().length).toBeGreaterThan(200);
  });
});

describe("ctl dispatch: verb -> request", () => {
  const cases: readonly {
    readonly name: string;
    readonly group: string;
    readonly verb: string;
    readonly segments?: readonly string[];
    readonly body?: Record<string, string>;
    readonly method: string;
    readonly path: string;
  }[] = [
    {
      name: "list is a collection GET",
      group: "projects",
      verb: "list",
      method: "GET",
      path: "/admin/v1/projects",
    },
    {
      name: "get addresses one item",
      group: "projects",
      verb: "get",
      segments: ["p1"],
      method: "GET",
      path: "/admin/v1/projects/p1",
    },
    {
      name: "create POSTs the collection",
      group: "projects",
      verb: "create",
      body: { name: "x" },
      method: "POST",
      path: "/admin/v1/projects",
    },
    {
      name: "replace PUTs the item",
      group: "projects",
      verb: "replace",
      segments: ["p1"],
      body: { name: "x" },
      method: "PUT",
      path: "/admin/v1/projects/p1",
    },
    {
      name: "update PATCHes the item",
      group: "projects",
      verb: "update",
      segments: ["p1"],
      body: { name: "x" },
      method: "PATCH",
      path: "/admin/v1/projects/p1",
    },
    {
      name: "delete DELETEs the item",
      group: "projects",
      verb: "delete",
      segments: ["p1"],
      method: "DELETE",
      path: "/admin/v1/projects/p1",
    },
    {
      name: "action verbs POST a sub-path",
      group: "virtual-keys",
      verb: "rotate",
      segments: ["vk1"],
      method: "POST",
      path: "/admin/v1/virtual-keys/vk1/rotate",
    },
    {
      name: "revoke is a DELETE, not an action",
      group: "virtual-keys",
      verb: "revoke",
      segments: ["vk1"],
      method: "DELETE",
      path: "/admin/v1/virtual-keys/vk1",
    },
    {
      name: "nested reads",
      group: "tenant-accounts",
      verb: "resolved-defaults",
      segments: ["t1"],
      method: "GET",
      path: "/admin/v1/tenant-accounts/t1/resolved-defaults",
    },
    {
      name: "agent-runs start targets the runtime path",
      group: "agent-runs",
      verb: "start",
      body: { agent: "a" },
      method: "POST",
      path: "/v1/agent-runs",
    },
    {
      name: "guardrail revision reads",
      group: "guardrail-policies",
      verb: "get-revision",
      segments: ["g1", "7"],
      method: "GET",
      path: "/admin/v1/guardrail-policies/g1/revisions/7",
    },
    {
      name: "composite asset keys",
      group: "assets",
      verb: "get",
      segments: ["skill", "pack", "1.2.3"],
      method: "GET",
      path: "/v1/assets/skill/pack/1.2.3",
    },
    {
      name: "dashboard aliases are literal paths",
      group: "dashboard",
      verb: "alias",
      method: "GET",
      path: "/admin/dashboard",
    },
    {
      name: "ops health is unversioned",
      group: "system",
      verb: "health",
      method: "GET",
      path: "/healthz",
    },
  ];

  for (const testCase of cases) {
    test(testCase.name, () => {
      const spec = buildRequest(
        testCase.group,
        testCase.verb,
        resourceInput({
          segments: testCase.segments ?? [],
          ...(testCase.body === undefined ? {} : { body: testCase.body }),
        }),
      );
      expect(spec.method).toBe(testCase.method);
      expect(spec.path).toBe(testCase.path);
    });
  }

  test("asset-channels set carries the version as a query parameter", () => {
    const spec = buildRequest(
      "asset-channels",
      "set",
      resourceInput({ segments: ["skill", "pack", "stable", "1.2.3"] }),
    );
    expect(spec.method).toBe("PUT");
    expect(spec.path).toBe("/v1/assets/skill/pack/channels/stable");
    expect(spec.query).toEqual([["version", "1.2.3"]]);
  });

  test("list params fold pagination, filters, and sorts into the query", () => {
    const spec = buildRequest(
      "projects",
      "list",
      resourceInput({
        list: new ListParams({
          page: { offset: 20, limit: 10 },
          filters: [["tenant", "t1"]],
          sorts: ["tier", "-created_at"],
        }),
      }),
    );
    expect(spec.query).toEqual([
      ["offset", "20"],
      ["limit", "10"],
      ["tenant", "t1"],
      ["sort", "tier"],
      ["sort", "-created_at"],
    ]);
  });
});

describe("ctl dispatch refuses rather than retargeting", () => {
  test("`get` without an id does NOT fall back to the collection", () => {
    expect(() => buildRequest("projects", "get", resourceInput())).toThrowError(
      /requires a target id/,
    );
  });

  test("`delete` without an id does NOT issue a collection DELETE", () => {
    expect(() => buildRequest("projects", "delete", resourceInput())).toThrowError(
      /requires a target id/,
    );
  });

  test("a composite-key resource demands its full key", () => {
    expect(() =>
      buildRequest("quota-policies", "get", resourceInput({ segments: ["tenant"] })),
    ).toThrowError(/2 non-empty target segments/);
  });

  test("a write verb without a document refuses", () => {
    expect(() => buildRequest("projects", "create", resourceInput())).toThrowError(
      /requires a JSON request document/,
    );
  });

  test("an id segment cannot smuggle path structure", () => {
    const spec = buildRequest("projects", "get", resourceInput({ segments: ["a/b?c=d"] }));
    expect(spec.path).toBe("/admin/v1/projects/a%2Fb%3Fc%3Dd");
  });

  test("an empty id segment refuses instead of collapsing to //", () => {
    expect(() =>
      buildRequest("projects", "get", resourceInput({ segments: ["   "] })),
    ).toThrowError(CliError);
  });

  test("unknown group and unknown verb are usage errors", () => {
    expect(() => resolveVerb("nope", "list")).toThrowError(/unknown resource group 'nope'/);
    expect(() => resolveVerb("projects", "frobnicate")).toThrowError(
      /unknown verb 'frobnicate' for group 'projects'/,
    );
  });
});

describe("effects and confirmation are registry metadata", () => {
  test("reads are read, writes are mutating", () => {
    expect(resolveVerb("projects", "list").verb.effect).toBe("read");
    expect(resolveVerb("projects", "create").verb.effect).toBe("mutating");
  });

  test("irreversible money and ops verbs require confirmation", () => {
    for (const [group, verb] of [
      ["wallets", "adjust"],
      ["wallets", "charge"],
      ["billing-events", "replay"],
      ["config", "reload"],
      ["drain", "set"],
    ] as const) {
      expect(resolveVerb(group, verb).verb.confirmation, `${group} ${verb}`).toBe("required");
    }
  });

  test("ordinary mutations do not require confirmation", () => {
    expect(resolveVerb("projects", "delete").verb.confirmation).toBe("none");
  });

  test("the request-log export declares a raw response mode", () => {
    expect(resolveVerb("request-logs", "export").verb.responseMode).toEqual({
      kind: "raw",
      mediaType: "application/x-ndjson",
    });
  });
});

describe("secret redaction", () => {
  test("key material is redacted from safe reads", () => {
    expect(secretFieldsFor("virtual-keys")).toEqual(["key", "secret"]);
    const body = redactResponse(
      "virtual-keys",
      { method: "GET", path: "/admin/v1/virtual-keys", query: [] },
      { data: [{ id: "vk1", key: "sk-live-xyz", secret: "s3cr3t" }] },
    );
    expect(JSON.stringify(body)).not.toContain("sk-live-xyz");
    expect(JSON.stringify(body)).not.toContain("s3cr3t");
  });

  test("presigned transfer URLs are treated as secrets", () => {
    expect(secretFieldsFor("asset-transfer")).toEqual(["upload_url", "download_url"]);
  });

  test("a group with no secret fields is untouched", () => {
    const body = { id: "p1", key: "not-a-secret-here" };
    expect(
      redactResponse("projects", { method: "GET", path: "/admin/v1/projects", query: [] }, body),
    ).toEqual(body);
  });
});
