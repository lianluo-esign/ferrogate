/**
 * #522 governed actions on the asset surface — the ENFORCEMENT half of
 * `resolve_asset_action_id` (`crates/ferrogate-gateway/src/server/assets.rs`).
 *
 * The correlation-join leg (validate the header, thread it onto every audit
 * row) was already ported and is pinned elsewhere. What is pinned here is the
 * optional per-tenant switch that turns an ABSENT `x-ferrogate-agent-run-id`
 * into a refusal instead of an unjoinable action — Rust
 * `FG_REQUIRE_AGENT_RUN_ID`, default OFF.
 *
 * Two properties matter more than the happy path and are asserted directly:
 *
 *  - the switch keys on the AUTHENTICATED identity
 *    (`governedActionTenantKey`), never on anything the client sends, so a
 *    caller cannot name a different tenant to escape enforcement;
 *  - it NEVER fabricates an id. A synthesized correlation id would make an
 *    unjoinable action look joined, which is worse than admitting the gap.
 */
import { describe, expect, test } from "vitest";
import {
  assetRouteModule,
  governedActionTenantKey,
  tenantRequiresDeclaredActionId,
} from "../../src/assets/handlers.js";
import type { AuthContext } from "../../src/ports.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { FakePresigner, harness } from "./helpers.js";

const KEYS = JSON.stringify([
  { key: "fg_a", id: "key_a", tenant_id: "tenant_a", scopes: ["assets.read", "assets.write"] },
  { key: "fg_b", id: "key_b", tenant_id: "tenant_b", scopes: ["assets.read", "assets.write"] },
]);
const ENTITLEMENTS = JSON.stringify({
  tenant_a: { asset_hosting_enabled: true },
  tenant_b: { asset_hosting_enabled: true },
});

function gateway(requireVar?: string) {
  const h = harness();
  const { app } = createGatewayApp({
    modules: [
      assetRouteModule({
        deps: {
          objects: h.objects,
          metadata: h.metadata,
          audit: h.audit,
          presigner: new FakePresigner(),
        },
      }),
    ],
  });
  const env: Record<string, string> = {
    GATEWAY_NATIVE_API_KEYS: KEYS,
    ASSET_ENTITLEMENTS: ENTITLEMENTS,
  };
  if (requireVar !== undefined) env.FG_REQUIRE_AGENT_RUN_ID = requireVar;
  return (token: string, version: string, runId?: string): Promise<Response> => {
    const headers = new Headers({
      authorization: `Bearer ${token}`,
      "content-type": "application/octet-stream",
    });
    if (runId !== undefined) headers.set("x-ferrogate-agent-run-id", runId);
    return Promise.resolve(
      app.request(
        `https://gw.test/v1/assets/cli/ferrogate/${version}`,
        { method: "PUT", body: "artifact-bytes", headers },
        env,
      ),
    );
  };
}

async function code(response: Response): Promise<string> {
  const body = (await response.json()) as { error?: { code?: string } };
  return body.error?.code ?? "";
}

// ---------------------------------------------------------------------------
// the parser + the key
// ---------------------------------------------------------------------------

describe("tenantRequiresDeclaredActionId — Rust `tenant_requires_declared_action_id`", () => {
  test("unset or empty is OFF for every tenant", () => {
    expect(tenantRequiresDeclaredActionId(undefined, "tenant_a")).toBe(false);
    expect(tenantRequiresDeclaredActionId("", "tenant_a")).toBe(false);
    expect(tenantRequiresDeclaredActionId("   ", "tenant_a")).toBe(false);
  });

  test("every global form is ON for every tenant, case-insensitively", () => {
    for (const value of ["1", "true", "TRUE", "yes", "on", "all", "*", " On "]) {
      expect(tenantRequiresDeclaredActionId(value, "tenant_a")).toBe(true);
      // Including a credential with no tenant attribution at all: that is
      // exactly the caller an operator running `all` wants to refuse.
      expect(tenantRequiresDeclaredActionId(value, "")).toBe(true);
    }
  });

  test("a list matches ONLY the named tenant keys", () => {
    const list = "tenant_a, tenant_c";
    expect(tenantRequiresDeclaredActionId(list, "tenant_a")).toBe(true);
    expect(tenantRequiresDeclaredActionId(list, "tenant_c")).toBe(true);
    expect(tenantRequiresDeclaredActionId(list, "tenant_b")).toBe(false);
    // Whitespace is a separator too (Rust splits on `,` OR whitespace).
    expect(tenantRequiresDeclaredActionId("tenant_a tenant_c", "tenant_c")).toBe(true);
    // A prefix is not a match — `tenant_a2` must not be swept in by `tenant_a`.
    expect(tenantRequiresDeclaredActionId("tenant_a", "tenant_a2")).toBe(false);
    // An unattributed credential matches no LIST entry.
    expect(tenantRequiresDeclaredActionId(list, "")).toBe(false);
  });
});

describe("governedActionTenantKey — Rust `governed_action_tenant_key`", () => {
  const auth = (
    tenancy: Partial<AuthContext["tenancy"]>,
    subject: string | null = null,
  ): AuthContext => ({
    subject,
    tenancy: {
      tenantId: tenancy.tenantId ?? null,
      projectId: tenancy.projectId ?? null,
      workspaceId: tenancy.workspaceId ?? null,
      userId: tenancy.userId ?? null,
    },
    scopes: [],
    platformOperator: false,
    source: "durable_native",
  });

  test("prefers the broadest authenticated scope, down to the api key id", () => {
    expect(governedActionTenantKey(auth({ tenantId: "org-1", projectId: "p-1" }))).toBe("org-1");
    expect(governedActionTenantKey(auth({ projectId: "p-1", workspaceId: "w-1" }))).toBe("p-1");
    expect(governedActionTenantKey(auth({ workspaceId: "w-1", userId: "u-1" }))).toBe("w-1");
    expect(governedActionTenantKey(auth({ userId: "u-1" }))).toBe("u-1");
    expect(governedActionTenantKey(auth({}, "key-9"))).toBe("key-9");
  });

  test("is empty for an identity with no attribution, and for no identity", () => {
    expect(governedActionTenantKey(auth({}))).toBe("");
    expect(governedActionTenantKey(null)).toBe("");
    expect(governedActionTenantKey(undefined)).toBe("");
  });
});

// ---------------------------------------------------------------------------
// the wire behaviour
// ---------------------------------------------------------------------------

describe("the switch, through the real asset routes", () => {
  test("default OFF: a governed push with no declared id is admitted", async () => {
    const res = await gateway()("fg_a", "1.0.0");
    expect(res.status).toBe(200);
  });

  test("ON: the same push is refused 400 agent_run_id_required", async () => {
    const res = await gateway("all")("fg_a", "1.0.0");
    expect(res.status).toBe(400);
    expect(await code(res)).toBe("agent_run_id_required");
  });

  test("ON: declaring the id admits it — nothing is fabricated on the refusal path", async () => {
    const push = gateway("all");
    const refused = await push("fg_a", "1.0.0");
    expect(refused.status).toBe(400);
    const accepted = await push("fg_a", "1.0.0", "run_42");
    expect(accepted.status).toBe(200);
    // The refusal stored nothing, so the accepted push publishes cleanly
    // rather than conflicting with a row the refused one left behind.
    expect(await code(accepted)).toBe("");
  });

  test("enforcement is per AUTHENTICATED tenant, not per anything the client sends", async () => {
    const push = gateway("tenant_a");
    expect((await push("fg_a", "1.0.0")).status).toBe(400);
    // tenant_b is not listed: the identical request is admitted. A caller
    // cannot move itself between these two buckets — the key comes from the
    // resolved credential.
    expect((await push("fg_b", "1.0.0")).status).toBe(200);
  });

  test("a MALFORMED id is still 400 invalid_agent_run_id_header, switch or no switch", async () => {
    for (const requireVar of [undefined, "all"]) {
      const res = await gateway(requireVar)("fg_a", "1.0.0", "not a valid id!");
      expect(res.status).toBe(400);
      expect(await code(res)).toBe("invalid_agent_run_id_header");
    }
  });
});
