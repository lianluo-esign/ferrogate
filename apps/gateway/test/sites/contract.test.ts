/**
 * The contract half of issue #737.
 *
 * `docs/openapi/runtime-api-contract.json` reserved `/sites/{*rest}` as a route
 * PATTERN with `group: "site"` and zero operations — a route group that
 * documents nothing and serves nothing. Every other reserved group in that
 * document carries at least one operation; `site` was the only one that did
 * not, which is exactly why `docs/product-overview.md` could claim a shipped
 * serve mode for four months without a single test noticing.
 *
 * This file pins the group's operation table itself, separately from the
 * behaviour suite in `./serve.test.ts`, because the two fail for different
 * reasons: this one goes red when the contract loses the operation, that one
 * when the bytes stop being served.
 */
import { describe, expect, test } from "vitest";
import { matchOperation, matchRouteGroup, operationById } from "../../src/contract.js";
import { SITE_OPERATION_IDS } from "../../src/routes/index.js";

describe("the `site` route group carries the serve operation", () => {
  test("GET /sites/{site}/{path} matches a contract operation", () => {
    const matched = matchOperation("GET", "/sites/docs/assets/app.js");
    expect(matched?.operation.operationId).toBe("serveSite");
    expect(matched?.operation.group).toBe("site");
  });

  test("the reserved catch-all really is what matches, at any depth", () => {
    for (const path of ["/sites/docs", "/sites/docs/", "/sites/docs/a/b/c/d.png"]) {
      expect(matchRouteGroup(path), path).toBe("site");
      expect(matchOperation("GET", path)?.operation.operationId, path).toBe("serveSite");
    }
  });

  test("HEAD is the same operation as GET, never a second one", () => {
    // RFC 9110 §9.3.2: HEAD is identical to GET with the content omitted. A
    // separate contract row would be a second place for the scope, the
    // visibility and the RBAC action to drift apart.
    expect(matchOperation("HEAD", "/sites/docs/")?.operation.operationId).toBe("serveSite");
  });

  test("the operation is anonymous at the contract layer, by decision", () => {
    // The credential requirement for a site is DATA (per site, per channel),
    // not a static property of the route, and `auth.kind` has no way to say
    // "bearer unless this particular site opted out". Declaring `bearer` here
    // would make the anonymous opt-in unreachable; declaring `anonymous` puts
    // the ladder in the handler, which reuses the middleware's own
    // `authenticateBearer` rather than re-implementing it.
    const operation = operationById("serveSite");
    expect(operation?.auth).toEqual({ kind: "anonymous", scope: null, scopeDiscriminator: null });
    expect(operation?.visibility).toBe("public");
    expect(operation?.rbacAction).toBeNull();
  });

  test("the gateway owns exactly one site operation", () => {
    expect([...SITE_OPERATION_IDS]).toEqual(["serveSite"]);
  });
});
