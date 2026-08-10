/**
 * THE anti-drift gate (`ROUTE-MAP.md`: "Add a test asserting … that every
 * contract `operation_id` has a handler").
 *
 * This test reads the contract document INDEPENDENTLY of `src/contract.ts` —
 * raw JSON in, expectations out — so it cannot be satisfied by a bug in the
 * parser it is supposed to police. If `src/contract.ts` silently dropped an
 * operation, the derived table would agree with itself and disagree with this.
 *
 * It fails LISTING the offending operation ids, because "200 !== 199" tells you
 * nothing at 3am.
 *
 * SCOPE, precisely: this file proves every contract operation has a HANDLER,
 * and that the handler table and the contract agree. It does NOT prove those
 * handlers are MOUNTED on the app `src/index.ts` puts under `export default` —
 * `registeredRoutes()` is a projection of the contract, and the handler table is
 * built at module load whether or not `registerRoutes(app)` is ever called.
 * That second half — the `apps/gateway` empty-module-list defect — is
 * `test/wiring.test.ts`, which reads Hono's own `app.routes` and drives the
 * deployed Worker through `SELF.fetch`. Both are required; neither subsumes the
 * other.
 */
import { describe, expect, it } from "vitest";
import contractDocument from "../../../docs/openapi/runtime-api-contract.json";
import {
  CONTROL_PLANE_GROUPS,
  CONTROL_PLANE_OPERATIONS,
  EXPECTED_CONTROL_PLANE_OPERATION_COUNT,
  EXPECTED_TOTAL_OPERATION_COUNT,
  canonicalizeAliasPath,
  isControlPlanePath,
  matchOperation,
  toHonoPath,
} from "../src/contract.js";
import {
  GROUP_MODULES,
  diffAgainstContract,
  registeredOperationIds,
  registeredRoutes,
} from "../src/routes/index.js";

interface RawOperation {
  path: string;
  method: string;
  operation_id: string;
  visibility: string;
  auth: { kind: string; scope: string | null };
  rbac_action: string | null;
}

const RAW = contractDocument as unknown as {
  version: number;
  route_patterns: { pattern: string; group: string }[];
  operations: RawOperation[];
  dynamic_surfaces: { pattern: string }[];
};

/**
 * The app's slice, computed from the raw document by `ROUTE-MAP.md`'s own
 * definition: `/admin/v1/**` plus the five un-versioned paths.
 */
const OWNED_RAW = RAW.operations.filter(
  (operation) =>
    operation.path === "/admin/v1" ||
    operation.path.startsWith("/admin/v1/") ||
    ["/admin", "/admin/", "/admin/dashboard", "/admin/status", "/metrics"].includes(operation.path),
);

describe("contract document", () => {
  it("is version 1 and carries all 320 operations", () => {
    expect(RAW.version).toBe(1);
    expect(RAW.operations).toHaveLength(EXPECTED_TOTAL_OPERATION_COUNT);
  });

  it("assigns exactly 248 operations to apps/control-plane", () => {
    expect(OWNED_RAW).toHaveLength(EXPECTED_CONTROL_PLANE_OPERATION_COUNT);
    expect(CONTROL_PLANE_OPERATIONS).toHaveLength(EXPECTED_CONTROL_PLANE_OPERATION_COUNT);
  });

  it("declares exactly 48 route groups", () => {
    // `ROUTE-MAP.md` line 4 designates itself the source of truth and states
    // the group count in PROSE, where nothing held it: it read "40 route
    // groups" for two merges after the 41st group appeared, because a group
    // count is not a length any existing assertion takes. This is that prose,
    // asserted — an added or renamed `route_patterns[].group` now fails here
    // before the document it documents can drift from it.
    //
    // 42 -> 43 when #693's `admin_experiment` and #697's `admin_spend_anomaly`
    // both landed: this assertion was written on a branch that only knew about
    // the first, so 43 is COUNTED off the merged `route_patterns`, not
    // incremented off the 42 this test first shipped with. 46 -> 47 with
    // #698's `batches` group, counted off the merged document the same way.
    // 47 -> 48 with #943's `admin_billing_group` group (main + this slice
    // alone; #944 adds no new group).
    expect(new Set(RAW.route_patterns.map((pattern) => pattern.group)).size).toBe(48);
  });

  it("ownership predicate agrees with the raw document, path by path", () => {
    const rawOwned = new Set(OWNED_RAW.map((operation) => operation.path));
    const disagreements = RAW.operations
      .filter((operation) => isControlPlanePath(operation.path) !== rawOwned.has(operation.path))
      .map((operation) => `${operation.method.toUpperCase()} ${operation.path}`);
    expect(disagreements).toEqual([]);
  });
});

describe("anti-drift: every contract operation has a registered route", () => {
  it("registers every one of this app's 248 operation ids", () => {
    const registered = new Set(registeredOperationIds());
    const missing = OWNED_RAW.map((operation) => operation.operation_id)
      .filter((operationId) => !registered.has(operationId))
      .sort();

    // The message is the point: it names what fell off.
    expect(missing, `unregistered contract operations: ${missing.join(", ")}`).toEqual([]);
    expect(registered.size).toBe(EXPECTED_CONTROL_PLANE_OPERATION_COUNT);
  });

  it("registers NOTHING that is not in this app's contract slice", () => {
    const owned = new Set(OWNED_RAW.map((operation) => operation.operation_id));
    const extra = registeredOperationIds()
      .filter((operationId) => !owned.has(operationId))
      .sort();
    expect(extra, `routes with no contract operation: ${extra.join(", ")}`).toEqual([]);
  });

  it("mounts each route at the contract's own path template and method", () => {
    const byId = new Map(registeredRoutes().map((route) => [route.operationId, route]));
    const mismatched = OWNED_RAW.filter((operation) => {
      const route = byId.get(operation.operation_id);
      return (
        route === undefined ||
        route.method !== operation.method.toUpperCase() ||
        route.honoPath !== toHonoPath(operation.path)
      );
    }).map((operation) => operation.operation_id);
    expect(mismatched).toEqual([]);
  });

  it("NAMES the operations that fell off, rather than just counting them", () => {
    // Driven with a synthetic handler set so the failure path is exercised
    // directly — a green suite must not depend on the listing code being
    // unreachable. This is the message an engineer sees when a contract
    // operation loses its route.
    const complete = registeredOperationIds();
    const dropped = complete.filter(
      (operationId) => operationId !== "runAdminAgentScheduleNow" && operationId !== "getMetrics",
    );
    const diff = diffAgainstContract([...dropped, "notAContractOperation"]);
    expect(diff.missing).toEqual(["getMetrics", "runAdminAgentScheduleNow"]);
    expect(diff.extra).toEqual(["notAContractOperation"]);

    // …and the real, live table has neither.
    expect(diffAgainstContract(complete)).toEqual({ missing: [], extra: [] });
  });

  it("has exactly one route module per owned contract group", () => {
    const claimed = GROUP_MODULES.map((module) => module.group).sort();
    expect(claimed).toEqual([...CONTROL_PLANE_GROUPS].sort());
    expect(new Set(claimed).size).toBe(claimed.length);
  });
});

describe("anti-drift: the auth metadata is carried, not re-invented", () => {
  it("preserves visibility / auth.kind / scope / rbac_action verbatim", () => {
    const byId = new Map(
      CONTROL_PLANE_OPERATIONS.map((operation) => [operation.operationId, operation]),
    );
    const drifted = OWNED_RAW.filter((raw) => {
      const parsed = byId.get(raw.operation_id);
      return (
        parsed === undefined ||
        parsed.visibility !== raw.visibility ||
        parsed.auth.kind !== raw.auth.kind ||
        parsed.auth.scope !== (raw.auth.scope ?? null) ||
        parsed.rbacAction !== (raw.rbac_action ?? null)
      );
    }).map((raw) => raw.operation_id);
    expect(drifted).toEqual([]);
  });

  it("keeps GET /metrics internal-but-bearer, with an admin.read scope", () => {
    const metrics = CONTROL_PLANE_OPERATIONS.find((op) => op.operationId === "getMetrics");
    expect(metrics).toBeDefined();
    expect(metrics?.visibility).toBe("internal");
    expect(metrics?.auth.kind).toBe("bearer");
    expect(metrics?.auth.scope).toBe("admin.read");
  });

  it("has exactly three anonymous operations, all of them the dashboard", () => {
    const anonymous = CONTROL_PLANE_OPERATIONS.filter(
      (operation) => operation.auth.kind === "anonymous",
    ).map((operation) => operation.path);
    expect(anonymous.sort()).toEqual(["/admin", "/admin/", "/admin/dashboard"]);
  });

  it("guards every other operation with a bearer scope", () => {
    const unguarded = CONTROL_PLANE_OPERATIONS.filter(
      (operation) =>
        operation.auth.kind !== "anonymous" &&
        (operation.auth.kind !== "bearer" || operation.auth.scope === null),
    ).map((operation) => operation.operationId);
    expect(unguarded).toEqual([]);
  });

  it("carries the guardrail rbac_actions the contract declares", () => {
    const withRbac = CONTROL_PLANE_OPERATIONS.filter(
      (operation) => operation.rbacAction !== null,
    ).map((operation) => operation.rbacAction);
    // 12 operations, all in the guardrails vocabulary.
    expect(withRbac).toHaveLength(12);
    expect(withRbac.every((action) => action?.startsWith("guardrails."))).toBe(true);
  });
});

describe("path matching (the matchit radix tree, re-implemented)", () => {
  it("prefers a static segment over a parameter", () => {
    // `/admin/v1/x402-spend-policies/effective` is static and must not be
    // swallowed by any parameterised sibling.
    expect(
      matchOperation("GET", "/admin/v1/x402-spend-policies/effective")?.operation.operationId,
    ).toBe("getEffectiveX402SpendPolicy");
  });

  it("captures path parameters", () => {
    const matched = matchOperation("GET", "/admin/v1/quota-policies/project/proj_1");
    expect(matched?.operation.operationId).toBe("getQuotaPolicy");
    expect(matched?.params).toEqual({ scope_type: "project", scope_id: "proj_1" });
  });

  it("keeps /admin and /admin/ as two distinct operations", () => {
    expect(matchOperation("GET", "/admin")?.operation.operationId).toBe("getAdminDashboard");
    expect(matchOperation("GET", "/admin/")?.operation.operationId).toBe("getAdminDashboardSlash");
  });

  it("does not match another app's operations", () => {
    expect(matchOperation("POST", "/v1/chat/completions")).toBeUndefined();
    expect(matchOperation("GET", "/healthz")).toBeUndefined();
  });
});

describe("canonicalize_alias_path (ported from control_plane_test.rs)", () => {
  it("folds whole alias segments", () => {
    expect(canonicalizeAliasPath("/control/v1")).toBe("/admin/v1");
    expect(canonicalizeAliasPath("/control/v1/status")).toBe("/admin/v1/status");
    expect(canonicalizeAliasPath("/control/v1/providers")).toBe("/admin/v1/providers");
    expect(canonicalizeAliasPath("/control/v1/config/reload")).toBe("/admin/v1/config/reload");
    expect(canonicalizeAliasPath("/control/v1/guardrail-policies/p_1/revisions/2")).toBe(
      "/admin/v1/guardrail-policies/p_1/revisions/2",
    );
  });

  it("never captures a path that merely shares the textual prefix", () => {
    for (const path of ["/control/v1x", "/control/v1x/y", "/control", "/controlled/v1"]) {
      expect(canonicalizeAliasPath(path), path).toBeNull();
    }
  });

  it("leaves already-canonical and unrelated paths untouched", () => {
    for (const path of [
      "/admin/v1/providers",
      "/admin/v1",
      "/v1/chat/completions",
      "/healthz",
      "/",
    ]) {
      expect(canonicalizeAliasPath(path), path).toBeNull();
    }
  });
});

describe("dynamic surfaces are NOT contract operations", () => {
  it("declares the admin CORS preflight as dynamic, not as an operation", () => {
    const patterns = RAW.dynamic_surfaces.map((surface) => surface.pattern);
    expect(patterns).toContain("OPTIONS /admin/{*rest}");
    expect(RAW.operations.some((operation) => operation.method.toUpperCase() === "OPTIONS")).toBe(
      false,
    );
  });
});
