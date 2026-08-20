/**
 * Anti-drift gate (ROUTE-MAP.md "Porting guidance").
 *
 * The contract table is generated from the SAME JSON the Rust runtime consumed,
 * so a contract change cannot silently diverge from the implementation. These
 * assertions are the tripwire: shape of the table, the documented auth/
 * visibility/method census, the matcher's specificity rules, and the guarantee
 * that every gateway-owned operation is actually mounted.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  AUTH_KINDS,
  type AuthKind,
  EXPECTED_OPERATION_COUNT,
  type HttpMethod,
  OPERATIONS,
  type Visibility,
  canonicalizeAliasPath,
  matchOperation,
  matchRouteGroup,
  methodDependentScope,
  methodsForPath,
  operationById,
  operationIds,
  pathIsDocumented,
  toHonoPath,
} from "../src/contract.js";
import { GATEWAY_ROUTE_MODULES, gatewayRouter } from "../src/index.js";
import { hasScope } from "../src/ports.js";
import {
  ASSET_OPERATION_IDS,
  BATCH_OPERATION_IDS,
  FILES_OPERATION_IDS,
  GATEWAY_OWNED_OPERATION_IDS,
  INFERENCE_OPERATION_IDS,
  OBSERVABILITY_OPERATION_IDS,
  PENDING_MODULE_OPERATION_IDS,
  SHARED_OPERATION_IDS,
  SITE_OPERATION_IDS,
  createGatewayApp,
} from "../src/routes/index.js";

function census<T extends string>(values: readonly T[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

describe("contract table", () => {
  it("carries exactly 313 operations", () => {
    expect(OPERATIONS).toHaveLength(EXPECTED_OPERATION_COUNT);
  });

  it("has 313 unique operation ids", () => {
    expect(new Set(operationIds()).size).toBe(EXPECTED_OPERATION_COUNT);
  });

  it("reproduces the documented auth-kind census", () => {
    // ROUTE-MAP.md: bearer 252 · internal 6 · anonymous 6 · method_dependent 1.
    // bearer went 238 -> 239 with `countMessageTokens` (issue #671), which is
    // bearer-`messages.create` like the `createMessage` it pre-flights, then
    // 239 -> 242 with the three prompt-deployment-label operations (issue
    // #694), which are bearer-guarded like the rest of the prompt registry.
    // From that shared 242 three independent slices landed: the three
    // `/admin/v1/provider-credentials*` BYOK-alias operations (issue #682, ->
    // 245), the six `/admin/v1/semantic-cache-policies/**` operations (issue
    // #695, `admin.read` / `admin.write` like every other admin surface, ->
    // 251), and `getModel` (issue #670, bearer-`models.read` like the
    // `listModels` it narrows, -> 252), then #677's two chargeback reads
    // (`listAdminCostRecords` / `exportAdminCostRecords`, -> 254), which are
    // `admin.read` like every other evidence read, and `createRerank` (issue
    // #676, bearer-`embeddings.create`, -> 255), and the three audio operations
    // (issue #703, bearer-`audio.create`, -> 258). All twenty additions since
    // 238 are bearer; none is anonymous or internal.
    //
    // 258 is COUNTED off the merged document, not summed: #677 and #676 were
    // parallel and each parent wrote its own increment, which is the collision
    // this file's header warns about. `Counter(o["auth"]["kind"] for o in
    // operations)` over the merged JSON is what produced it, and #703 re-ran the
    // same count rather than adding three to a number it had not verified.
    //
    // `anonymous` moves 6 -> 7 with `serveSite` (issue #737) — the FIRST
    // addition since the cutover that is not bearer, and a deliberate one. See
    // the "may skip auth" case below for why the site serve route cannot be
    // declared `bearer` and what enforces its credential instead. #703 and #737
    // landed in parallel: bearer 258 and anonymous 7 are both COUNTED off the
    // MERGED document, which is the only side that holds both.
    //
    // Two more parallel slices then landed on top of that 258, and NEITHER
    // parent's number survives:
    //   - `getResponse` / `deleteResponse` (issue #689), bearer on the existing
    //     `responses.create` scope like the `createResponse` whose state they
    //     read and end — see the note beside their registration in
    //     `src/inference/handlers.ts` for why the scope is a reuse and not two
    //     new ones. That branch wrote 260.
    //   - #743's four asset-fleet operations, all bearer: an operator inventory
    //     of what tenants are hosting has no anonymous reading, and neither has
    //     its force-delete. That branch wrote 262.
    // Both landed, so the truth is 264 — a third number, RE-COUNTED with
    // `Counter(o["auth"]["kind"] for o in operations)` over the merged
    // `docs/openapi/runtime-api-contract.json`, never summed.
    //
    // And then a THIRD pair: #693's two experiment reads
    // (`listAdminExperiments` / `getAdminExperiment`), `admin.read` like every
    // other evidence read, against #743's four. The #693 branch wrote 262
    // against its own 276-operation document; main wrote 264 against its
    // 278-operation one. Neither holds both, and the merged count is 266 —
    // re-run over the merged JSON, not incremented off either parent.
    //
    // And a FOURTH pair: #697's `listAdminSpendAnomalies` — bearer, because a
    // burn-rate episode ledger is an operator read behind the same admin
    // bearer as the rest of `/admin/v1` — landed on main while #693 was still
    // open. That gave 266 on this branch and 265 on main; the merged document
    // has 267, which is neither. RE-COUNTED with
    // `Counter(o["auth"]["kind"] for o in operations)` over the merged
    // `docs/openapi/runtime-api-contract.json`, never summed.
    // #813 adds fifteen bearer-guarded tenant model catalog operations: five
    // provider operations, five model operations and five offering operations.
    // #892 adds one more bearer op: `POST /admin/v1/config/import-model-catalog`,
    // the platform-catalog bootstrap import (admin.write, like the config ops
    // beside it), taking bearer 298 -> 299.
    // #943 adds seven bearer-guarded `admin_billing_group` operations (two
    // reads at `admin.read`, five writes at `admin.write`), taking bearer
    // 299 -> 306. CORRECT for main + this slice alone; #944's parallel op is
    // reconciled at integration.
    // #948 adds five bearer-guarded `admin_announcement` operations (two reads
    // at `admin.read`, three writes at `admin.write`), taking bearer 308 -> 313.
    // The tenant-scoped `GET /admin/v1/shared-billing-groups` is one more bearer
    // read (`admin.read`), taking bearer 313 -> 314.
    // The control-plane-D1 migration's `POST /admin/v1/control-backfill` is one
    // more bearer write (`admin.write`, like the config ops beside it), taking
    // bearer 314 -> 315.
    expect(census(OPERATIONS.map<AuthKind>((operation) => operation.auth.kind))).toEqual({
      bearer: 315,
      internal: 6,
      anonymous: 7,
      method_dependent: 1,
    });
  });

  it("reproduces the documented visibility census", () => {
    expect(census(OPERATIONS.map<Visibility>((operation) => operation.visibility))).toEqual({
      // 193 -> 196 with the three prompt-deployment-label operations (issue
      // #694): prompt-registry management is admin-visibility. From that 196
      // `main` reached 199 with the three #682 BYOK-alias operations and this
      // branch reached 202 with the six #695 semantic-cache-policy operations,
      // all admin for the same reason. BOTH sets landed, so that leg is
      // 196 + 3 + 6 = 205 and not either parent's number; #677's two
      // chargeback reads then take it to 207, admin because a per-request cost
      // record is the most identity-dense report in the product. #743's four
      // asset-fleet operations then take it to 211 — admin because a fleet
      // inventory, a quarantine verdict and an operator takedown are operator
      // surfaces, never caller-facing ones. COUNTED off the merged document.
      // #693's two experiment reads take it to 213 — an experiment report names
      // a customer's models, their spend and their measured quality, so it is
      // admin-visibility for the same reason a cost record is — and #697's
      // spend-anomaly episode ledger takes it to 214, admin for the same
      // reason again. Those two landed in parallel, so this branch wrote 213
      // and main wrote 212 and NEITHER is the merged truth: 214 is what
      // `Counter(o["visibility"] for o in operations)` returns over the merged
      // `docs/openapi/runtime-api-contract.json`.
      // #813 adds fifteen admin-visible catalog operations.
      // #892 adds one admin-visible op (the platform-catalog bootstrap import),
      // taking admin 236 -> 237.
      // #943 adds seven admin-visible `admin_billing_group` operations, taking
      // admin 237 -> 244 (main + this slice alone; #944 reconciled later).
      // #948 adds five admin-visible `admin_announcement` operations, taking
      // admin 246 -> 251.
      // The tenant-scoped `GET /admin/v1/shared-billing-groups` is one more
      // admin-visible read, taking admin 251 -> 252.
      // The control-plane-D1 migration's `POST /admin/v1/control-backfill` is one
      // more admin-visible op, taking admin 252 -> 253.
      admin: 253,
      // 51 -> 52 with `countMessageTokens` (issue #671): a data-plane
      // operation, publicly reachable, bearer-guarded; then 52 -> 53 with
      // `getModel` (issue #670), public for the same reason as `listModels`.
      // Both parents independently wrote 52, so git merged that clean — 53 was
      // the merged truth, and `createRerank` (issue #676) takes it to 54: a
      // data-plane operation, publicly reachable, bearer-guarded. The three
      // audio operations (issue #703) take it to 57 for the same reason — a
      // voice client is a data-plane caller like any other — and `serveSite`
      // (issue #737) takes it to 58, publicly reachable in the strongest sense
      // of the word, since an opted-in site may be read with no credential at
      // all. 58 is COUNTED off the merged document: neither parent's own number
      // (57, 55) holds both slices. `getResponse` / `deleteResponse` (issue
      // #689) take it to 60 — data-plane operations on data-plane state, as
      // publicly reachable as the `createResponse` that produced it. Neither
      // #693 nor #743 adds a `public` operation, so both parents of THAT merge
      // wrote 60 and git merged it with no marker. That agreement is not the
      // evidence — the merged document was re-counted and it is still 60. Same
      // again for #697, whose spend-anomaly read is admin, not public: both
      // parents of THIS merge also wrote 60, and re-counting the merged
      // document is still what says 60 is right.
      public: 69,
      internal: 7,
    });
  });

  it("reproduces the documented method census", () => {
    expect(census(OPERATIONS.map<HttpMethod>((operation) => operation.method))).toEqual({
      // GET/PUT/DELETE each +1 with the prompt-deployment-label operations
      // (issue #694: list/read, upsert, delete of a label pointer), moving
      // GET/DELETE/PUT from 116/24/17 to 117/25/18. Then THREE slices moved the
      // same counters again, each written against that same 117/25/18 base:
      // #682's GET /provider-credentials plus PUT and DELETE
      // /provider-credentials/{alias}; the six #695 semantic-cache-policy
      // operations (GET +2 / POST +2 / PUT +1 / DELETE +1, whose POSTs are
      // `create` and `invalidate`); and #670's GET /v1/models/{model}. Because
      // parents had independently written the same intermediate figures for
      // their own increment, git merged those lines with NO conflict — the true
      // combined figures are 121/27/20, which is no parent's number and had to
      // be re-derived from `docs/openapi/runtime-api-contract.json`. #677 then
      // adds two more GETs (`/admin/v1/cost-records` and
      // `/admin/v1/cost-record-exports`) for 123, and #676 one more POST
      // (`/v1/rerank`) for 82. Both landed in parallel, so both figures were
      // re-counted off the merged document rather than added up. #737's
      // `GET /sites/{*rest}` then takes GET to 124 — the contract's first
      // operation whose path is a CATCH-ALL, because a static site is a tree of
      // unknown depth and a fixed segment count cannot address it. Then two
      // parallel slices moved GET and DELETE again from that same 124/27 base:
      // #689's `GET`/`DELETE /v1/responses/{response_id}` (one path, two
      // methods — that branch wrote GET 125 / DELETE 28) and #743's
      // `GET /admin/v1/assets` + `GET /admin/v1/assets/quarantine` and
      // `DELETE /admin/v1/assets/{asset_id}`, the operator force-delete (that
      // branch wrote GET 126 / DELETE 28). BOTH branches wrote `DELETE: 28`, so
      // git merged that line with NO conflict marker and it was WRONG: the
      // merged truth is GET 127 / DELETE 29, counted off
      // `docs/openapi/runtime-api-contract.json`, not summed.
      //
      // IT HAPPENED AGAIN, on GET, on the very next merge. #693's two
      // experiment reads are both GETs. The #693 branch reached 127 from its
      // own 124/#689 base and main reached 127 from its 124/#689/#743 base —
      // the SAME LITERAL from two different arithmetics — so git merged
      // `GET: 127` clean, with no marker, and neither number was right. The
      // document that merge produced has GET 129. An identical figure on both
      // sides of a merge is evidence of nothing; only re-counting the merged
      // artifact is.
      //
      // Then #697's `GET /admin/v1/spend-anomalies` landed on main, a third
      // GET-moving slice in a row: this branch stood at 129 and main at 128,
      // and the merged document has GET 130 — again no parent's number, again
      // `Counter(o["method"] for o in operations)` over the merged JSON.
      // #813 adds three reads: provider/model item reads and offering lists.
      // #892's bootstrap import is a POST (see below); GET is unchanged.
      // #943 adds two GETs (billing-group list + item read), 140 -> 142.
      // #948 adds two GETs (announcement list + item read), 143 -> 145.
      // The tenant-scoped `GET /admin/v1/shared-billing-groups` is one more GET,
      // 145 -> 146.
      GET: 146,
      // 78 -> 79 with `POST /v1/messages/count_tokens` (issue #671), then
      // 79 -> 81 with the two #695 semantic-cache-policy POSTs, then 82 with
      // #676's `/v1/rerank` and 85 with #703's three audio POSTs, then 86 with
      // #743's `POST /admin/v1/assets/quarantine/{asset_id}`. Re-counted off
      // the merged document, never summed. #892's
      // `POST /admin/v1/config/import-model-catalog` takes POST 96 -> 97.
      // #943 adds one POST (billing-group create, 97 -> 98), two DELETEs
      // (billing-group delete + provider unbind, 33 -> 35), one PUT (provider
      // bind, 24 -> 25) and one PATCH (billing-group patch, 19 -> 20). CORRECT
      // for main + this slice alone; #944 reconciled at integration.
      // #948 adds one POST (announcement create, 99 -> 100), one DELETE
      // (announcement delete, 35 -> 36) and one PATCH (announcement patch,
      // 20 -> 21). GET is handled above (+2).
      // The control-plane-D1 migration's `POST /admin/v1/control-backfill` is one
      // more POST, taking POST 100 -> 101.
      POST: 101,
      DELETE: 36,
      PUT: 25,
      PATCH: 21,
    });
  });

  it("names exactly the 7 operations that may skip auth", () => {
    // ROUTE-MAP invariant 3 — nothing else may be unauthenticated.
    //
    // ## `serveSite` is the SEVENTH, and it is a decision (issue #737)
    //
    // It was 6 for the whole port. `serveSite` is added here deliberately, and
    // this comment is the record of why, because "an operation moved into the
    // anonymous set" is otherwise indistinguishable from an auth hole.
    //
    // A site's credential requirement is DATA, not a property of the route: a
    // site is PRIVATE by default (bearer + `assets.read`, tenant-scoped), and
    // anonymous serving is a per-site, per-channel operator opt-in. `auth.kind`
    // has exactly four values and none of them can say that. Declaring
    // `bearer` would make the opt-in unreachable — the middleware would 401
    // every anonymous reader before a handler ran — so the only expressible
    // choice is `anonymous` at the contract layer with the ladder in the
    // handler.
    //
    // What keeps that from being a bypass is that the handler does NOT
    // re-implement the ladder: `src/sites/index.ts` calls
    // `authenticateBearer` — the exact function `contractAuth` itself calls —
    // so key resolution, scope, tenancy-lifecycle admission and RBAC are the
    // same code, not a copy that can drift. `test/sites/serve.test.ts` proves
    // the refusals on the wire (no credential, wrong scope, other tenant), and
    // `test/sites/access.test.ts` proves the opt-in is the ONLY thing that
    // opens a site to an anonymous reader.
    const anonymous = OPERATIONS.filter((operation) => operation.auth.kind === "anonymous").map(
      (operation) => operation.operationId,
    );
    expect(new Set(anonymous)).toEqual(
      new Set([
        "getHealthz",
        "getReadyz",
        "getAdminDashboard",
        "getAdminDashboardSlash",
        "getAdminDashboardAlias",
        "completeMcpIdentityOauth",
        "serveSite",
      ]),
    );
  });

  it("confines auth.kind: internal to the 6 self-hosted-worker callbacks", () => {
    // ROUTE-MAP invariant 2.
    const internal = OPERATIONS.filter((operation) => operation.auth.kind === "internal");
    expect(internal).toHaveLength(6);
    for (const operation of internal) {
      expect(operation.path.startsWith("/v1/self-hosted-workers/")).toBe(true);
    }
  });

  it("gives every bearer operation a scope", () => {
    for (const operation of OPERATIONS) {
      if (operation.auth.kind !== "bearer") continue;
      expect(operation.auth.scope, operation.operationId).toBeTruthy();
    }
    // ...and never a scope on any other kind.
    for (const operation of OPERATIONS) {
      if (operation.auth.kind === "bearer") continue;
      expect(operation.auth.scope, operation.operationId).toBeNull();
    }
  });

  it("keeps GET /metrics internal-but-bearer-guarded", () => {
    // ROUTE-MAP invariant 5.
    const metrics = matchOperation("GET", "/metrics")?.operation;
    expect(metrics?.visibility).toBe("internal");
    expect(metrics?.auth.kind).toBe("bearer");
  });

  it("only recognises the four documented auth kinds", () => {
    for (const operation of OPERATIONS) {
      expect(AUTH_KINDS).toContain(operation.auth.kind);
    }
  });
});

describe("lookup helpers", () => {
  it("resolves by operation id", () => {
    const operation = operationById("createChatCompletion");
    expect(operation?.method).toBe("POST");
    expect(operation?.path).toBe("/v1/chat/completions");
    expect(operation?.auth.scope).toBe("chat.completions");
  });

  it("returns undefined for an unknown operation id", () => {
    expect(operationById("noSuchOperation")).toBeUndefined();
  });

  it("resolves by (method, path) and captures path params", () => {
    const matched = matchOperation("GET", "/v1/assets/skill/hello/1.0.0");
    expect(matched?.operation.operationId).toBe("getAsset");
    expect(matched?.params).toEqual({ asset_type: "skill", name: "hello", version: "1.0.0" });
  });

  it("is method-sensitive on a shared path", () => {
    expect(matchOperation("PUT", "/v1/assets/skill/hello/1.0.0")?.operation.operationId).toBe(
      "putAsset",
    );
    expect(matchOperation("DELETE", "/v1/assets/skill/hello/1.0.0")?.operation.operationId).toBe(
      "deleteAsset",
    );
  });

  it("prefers a static segment over a parameter (matchit specificity)", () => {
    // `/v1/assets/withheld` must win over `/v1/assets/{asset_type}`.
    expect(matchOperation("GET", "/v1/assets/withheld")?.operation.operationId).toBe(
      "listWithheldAssets",
    );
    expect(matchOperation("GET", "/v1/assets/skill")?.operation.operationId).toBe(
      "listAssetsByType",
    );
    // ...and at a deeper position too.
    expect(matchOperation("GET", "/v1/assets/skill/hello/manifest")?.operation.operationId).toBe(
      "getAssetManifest",
    );
    expect(matchOperation("GET", "/v1/assets/skill/hello/channels")?.operation.operationId).toBe(
      "listAssetChannels",
    );
    expect(matchOperation("GET", "/v1/assets/skill/hello/1.0.0")?.operation.operationId).toBe(
      "getAsset",
    );
  });

  it("distinguishes /admin from /admin/", () => {
    expect(matchOperation("GET", "/admin")?.operation.operationId).toBe("getAdminDashboard");
    expect(matchOperation("GET", "/admin/")?.operation.operationId).toBe("getAdminDashboardSlash");
  });

  it("reports documented paths and their methods", () => {
    expect(pathIsDocumented("/v1/tools")).toBe(true);
    expect(pathIsDocumented("/v1/definitely/not/a/route")).toBe(false);
    expect(methodsForPath("/v1/tools")).toEqual(["GET"]);
    expect(new Set(methodsForPath("/v1/assets/skill/hello/1.0.0"))).toEqual(
      new Set(["GET", "PUT", "DELETE"]),
    );
  });

  it("maps every path to a route group", () => {
    for (const operation of OPERATIONS) {
      expect(operation.group, operation.operationId).toBeTruthy();
    }
    expect(matchRouteGroup("/v1/chat/completions")).toBe("inference");
    expect(matchRouteGroup("/healthz")).toBe("health");
  });

  it("resolves the method_dependent scope from the contract discriminator", () => {
    // ROUTE-MAP invariant 4 — read the contract, never assume.
    expect(methodDependentScope("POST", "/v1/mcp", "tools/call")).toBe("tools.execute");
    expect(methodDependentScope("POST", "/v1/mcp", "tools/list")).toBe("tools.read");
    expect(methodDependentScope("POST", "/v1/mcp", "resources/read")).toBe("assets.read");
    // An unmapped value yields no scope — callers must treat that as a denial.
    expect(methodDependentScope("POST", "/v1/mcp", "tools/destroy")).toBeUndefined();
    // ...including inherited Object keys, which must not leak through.
    expect(methodDependentScope("POST", "/v1/mcp", "toString")).toBeUndefined();
  });

  it("translates contract templates to Hono syntax", () => {
    expect(toHonoPath("/v1/assets/{asset_type}/{name}/{version}")).toBe(
      "/v1/assets/:asset_type/:name/:version",
    );
    expect(toHonoPath("/v1/agent-jobs/{*rest}")).toBe("/v1/agent-jobs/*");
    expect(toHonoPath("/healthz")).toBe("/healthz");
  });

  it("canonicalizes the /control/v1 alias onto /admin/v1", () => {
    // ROUTE-MAP invariant 7.
    expect(canonicalizeAliasPath("/control/v1/status")).toBe("/admin/v1/status");
    expect(canonicalizeAliasPath("/control/v1")).toBe("/admin/v1");
    expect(canonicalizeAliasPath("/control/v1x/status")).toBeNull();
    expect(canonicalizeAliasPath("/admin/v1/status")).toBeNull();
  });
});

describe("scope semantics", () => {
  it("grants an exact or wildcard scope", () => {
    expect(hasScope(["tools.read"], "tools.read")).toBe(true);
    expect(hasScope(["*"], "admin.write")).toBe(true);
  });

  it("denies a scope the key does not hold", () => {
    expect(hasScope(["skills.read"], "tools.read")).toBe(false);
  });

  it("lets an EMPTY scope set reach data-plane scopes but never admin.*", () => {
    // The durable/virtual-key asymmetry: no scopes must not become admin.
    expect(hasScope([], "tools.read")).toBe(true);
    expect(hasScope([], "admin.read")).toBe(false);
    expect(hasScope([], "admin.write")).toBe(false);
  });
});

describe("route registration", () => {
  // The PRODUCTION router — the one `src/index.ts` hands to `export default`.
  // Deliberately NOT a bespoke `createGatewayApp({ modules: [...] })` built
  // here: a local module list is exactly how the deployed Worker came to mount
  // 7 of its 38 operations while this suite stayed green.
  const router = gatewayRouter;
  const registered = new Set(router.registeredOperationIds());

  it("owns exactly the 49 operations ROUTE-MAP assigns to apps/gateway", () => {
    // 31 -> 32 with `countMessageTokens` (issue #671), 32 -> 33 with `getModel`
    // (issue #670) and 33 -> 34 with `createRerank` (issue #676). Both #671 and
    // #670 wrote 32 independently, so the merge kept 32 with no conflict — the
    // number here is re-derived by COUNTING the list, never incremented.
    //
    // From that shared 34 two slices landed in PARALLEL: the three audio
    // operations (issue #703, -> 37) and `serveSite` (issue #737, the `site`
    // route group's first operation, -> 35). 38 is neither parent's number; it
    // is COUNTED off `GATEWAY_OWNED_OPERATION_IDS` after the merge, which is now
    // four lists rather than three.
    // 38 -> 40 with #689's `getResponse` / `deleteResponse`, COUNTED off
    // `GATEWAY_OWNED_OPERATION_IDS` after the merge like every number above it.
    expect(GATEWAY_OWNED_OPERATION_IDS).toHaveLength(49);
    for (const operationId of GATEWAY_OWNED_OPERATION_IDS) {
      expect(operationById(operationId), operationId).toBeDefined();
    }
  });

  it("registers every gateway-owned operation that is not pending another agent", () => {
    const missing = GATEWAY_OWNED_OPERATION_IDS.filter(
      (operationId) =>
        !registered.has(operationId) && !PENDING_MODULE_OPERATION_IDS.includes(operationId),
    );
    expect(missing).toEqual([]);
  });

  it("mounts ALL 49 gateway-owned operations on the app the Worker exports", () => {
    // THE gate. Nothing may be excused by a pending list: every operation
    // ROUTE-MAP assigns to apps/gateway is registered on the exported app.
    const missing = GATEWAY_OWNED_OPERATION_IDS.filter(
      (operationId) => !registered.has(operationId),
    );
    expect(missing).toEqual([]);
    // ...and the registry is exactly the 49 owned + the 2 shared health ops +
    // `getMetrics`, so a stray registration is caught in the same breath.
    //
    // `getMetrics` is deliberately its OWN list rather than a 39th owned
    // operation or a third "shared" one. ROUTE-MAP assigns the operation to
    // `apps/control-plane`; the cutover certification found that leaving it
    // ONLY there means the 47 `ferrogate_*` series a dashboard queries have no
    // producer, because the counters live in this Worker. Mounting it here is
    // an addition with a reason, and this line is where that reason has to be
    // re-stated if anyone ever adds another.
    expect(new Set(registered)).toEqual(
      new Set([
        ...SHARED_OPERATION_IDS,
        ...OBSERVABILITY_OPERATION_IDS,
        ...GATEWAY_OWNED_OPERATION_IDS,
      ]),
    );
  });

  it("does not smuggle getMetrics into the OWNED or SHARED lists", () => {
    // The exact-set assertion above would still pass if `getMetrics` were
    // quietly appended to either list, and the distinction is the whole
    // argument: `SHARED_OPERATION_IDS` means "every Worker implements this",
    // and `apps/mcp` / `apps/telemetry` do not.
    expect(GATEWAY_OWNED_OPERATION_IDS).not.toContain("getMetrics");
    expect([...SHARED_OPERATION_IDS]).not.toContain("getMetrics");
    expect([...OBSERVABILITY_OPERATION_IDS]).toEqual(["getMetrics"]);
  });

  it("builds the production registry from the module list src/index.ts exports", () => {
    // The modules are the ones the composition root uses, not a copy.
    const fromModules = GATEWAY_ROUTE_MODULES.flatMap((module) => module.operationIds);
    expect(new Set(fromModules)).toEqual(
      new Set([
        ...INFERENCE_OPERATION_IDS,
        ...ASSET_OPERATION_IDS,
        ...FILES_OPERATION_IDS,
        ...BATCH_OPERATION_IDS,
        ...SITE_OPERATION_IDS,
      ]),
    );
    // Every id a module claims is actually registered by that module.
    for (const operationId of fromModules) {
      expect(registered.has(operationId), operationId).toBe(true);
    }
  });

  it("registers the shared health operations", () => {
    for (const operationId of SHARED_OPERATION_IDS) {
      expect(registered.has(operationId), operationId).toBe(true);
    }
  });

  it("never registers a route that is not in the contract", () => {
    for (const operationId of router.registeredOperationIds()) {
      expect(operationById(operationId), operationId).toBeDefined();
    }
  });

  it("keeps the pending list honest — and it is now EMPTY", () => {
    // Every pending id is gateway-owned...
    for (const operationId of PENDING_MODULE_OPERATION_IDS) {
      expect(GATEWAY_OWNED_OPERATION_IDS).toContain(operationId);
      // ...and is NOT already mounted (otherwise the list is stale).
      expect(registered.has(operationId), operationId).toBe(false);
    }
    // Nothing is outstanding: the inference and asset modules are both wired
    // into `src/index.ts`, so no gateway-owned operation may be excused.
    expect(PENDING_MODULE_OPERATION_IDS).toEqual([]);
  });

  it("refuses an operation id that is not in the contract", () => {
    const { router: fresh } = createGatewayApp();
    expect(() => fresh.register("noSuchOperation", () => new Response())).toThrow(
      /not in the runtime API contract/,
    );
  });

  it("refuses to register the same operation twice", () => {
    const { router: fresh } = createGatewayApp();
    expect(() => fresh.register("getHealthz", () => new Response())).toThrow(/already registered/);
  });
});

/**
 * The registry assertions above prove `src/index.ts` REGISTERED the 24 module
 * operations. These prove the deployed Worker actually SERVES them: every
 * request below goes through `SELF.fetch`, i.e. the real `export default app`
 * in real `workerd`, with a credential that clears the contract guard. A
 * contract path that is guarded but not mounted answers `404 not_found` from
 * `gatewayNotFoundHandler` — so "not 404" is the mount proof, and the exact
 * status/code asserted alongside it proves the module's own pipeline ran.
 */
const BASE = "https://ferrogate.test";
/** Operator-authored static key with no scope list => every scope. */
const ROOT = { authorization: "Bearer fg_root" } as const;

async function envelope(response: Response): Promise<{ code: string; message: string }> {
  const body = (await response.json()) as { error: { code: string; message: string } };
  return body.error;
}

describe("the deployed Worker serves the mounted modules", () => {
  it("mounts the 9 inference operations", async () => {
    // GET /v1/models reaches the inference handler: an empty catalog, not a 404.
    const models = await SELF.fetch(`${BASE}/v1/models`, { headers: ROOT });
    expect(models.status).toBe(200);
    expect(await models.json()).toEqual({ object: "list", data: [] });

    // GET /v1/models/{model} reaches the same handler: the deployed catalog is
    // empty, so the answer is the INFERENCE module's own `model_not_found`
    // envelope — distinct from `gatewayNotFoundHandler`'s `not_found`, which is
    // what an unmounted contract path would produce.
    const model = await SELF.fetch(`${BASE}/v1/models/anything`, { headers: ROOT });
    expect(model.status).toBe(404);
    expect((await envelope(model)).code).toBe("model_not_found");

    // Every POST reaches the inner body-reader + Zod chain: an empty object is
    // the module's own `400 invalid_request`, which only that chain produces.
    const posts = [
      "/v1/chat/completions",
      "/v1/responses",
      "/v1/messages",
      // `count_tokens` shares the Messages schema, so `{}` is the same
      // `invalid_request` (issue #671).
      "/v1/messages/count_tokens",
      "/v1/embeddings",
      "/v1/images/generations",
    ];
    for (const path of posts) {
      const res = await SELF.fetch(`${BASE}${path}`, {
        method: "POST",
        headers: { ...ROOT, "content-type": "application/json" },
        body: "{}",
      });
      expect(res.status, path).toBe(400);
      expect((await envelope(res)).code, path).toBe("invalid_request");
    }

    // ...and the reader's `invalid_json` stays distinct from `invalid_request`,
    // which is the behavior a plain Zod validator would have lost.
    const malformed = await SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: { ...ROOT, "content-type": "application/json" },
      body: "{not json",
    });
    expect(malformed.status).toBe(400);
    expect((await envelope(malformed)).code).toBe("invalid_json");
  });

  it("mounts the 18 /v1/assets/** operations", async () => {
    // Reach EVERY asset operation at its contract path with its contract
    // method. `fg_root` has no tenant attribution, so the asset service — which
    // only runs once the route is mounted — answers `403 tenant_required`.
    const probes: readonly (readonly [string, string, string])[] = [
      ["listAssets", "GET", "/v1/assets"],
      ["getAssetStorageSummary", "GET", "/v1/assets/storage/summary"],
      ["listWithheldAssets", "GET", "/v1/assets/withheld"],
      ["listAssetsByType", "GET", "/v1/assets/skill"],
      ["getAsset", "GET", "/v1/assets/skill/hello/1.0.0"],
      ["putAsset", "PUT", "/v1/assets/skill/hello/1.0.0"],
      ["deleteAsset", "DELETE", "/v1/assets/skill/hello/1.0.0"],
      ["getAssetManifest", "GET", "/v1/assets/skill/hello/manifest"],
      ["listAssetChannels", "GET", "/v1/assets/skill/hello/channels"],
      ["putAssetChannel", "PUT", "/v1/assets/skill/hello/channels/stable?version=1.0.0"],
      ["deleteAssetChannel", "DELETE", "/v1/assets/skill/hello/channels/stable"],
      ["yankAssetVersion", "POST", "/v1/assets/skill/hello/1.0.0/yank"],
      ["unyankAssetVersion", "DELETE", "/v1/assets/skill/hello/1.0.0/yank"],
      ["promoteAssetVisibility", "POST", "/v1/assets/skill/hello/1.0.0/visibility"],
      ["createAssetUploadIntent", "POST", "/v1/assets/presign/upload/skill/hello/1.0.0"],
      ["commitAssetUpload", "POST", "/v1/assets/presign/commit/skill/hello/1.0.0"],
      ["abortAssetUpload", "POST", "/v1/assets/presign/abort/skill/hello/1.0.0"],
      ["getAssetDownloadUrl", "GET", "/v1/assets/presign/download/skill/hello/1.0.0"],
    ];
    // The probe table is the contract's asset set, so a renamed operation
    // cannot quietly drop out of this test.
    expect(new Set(probes.map(([operationId]) => operationId))).toEqual(
      new Set(ASSET_OPERATION_IDS),
    );

    for (const [operationId, method, path] of probes) {
      const operation = operationById(operationId);
      expect(operation?.method, operationId).toBe(method);
      const res = await SELF.fetch(`${BASE}${path}`, {
        method,
        headers: { ...ROOT, "content-type": "application/json" },
        ...(method === "POST" || method === "PUT" ? { body: "{}" } : {}),
      });
      // The mount proof: never the app's "no route" answer.
      expect(res.status, `${operationId} ${method} ${path}`).not.toBe(404);
      const { code } = await envelope(res);
      expect(code, `${operationId} ${method} ${path}`).not.toBe("not_found");
    }
  });

  it("still answers 404 for a contract path this Worker does not own", async () => {
    // The control for the two tests above: `not 404` is only a mount proof
    // because a contracted-but-unmounted path, reached with a credential that
    // clears the guard, really does answer 404 here.
    const unowned = operationById("getAdminStatus");
    expect(unowned?.path).toBe("/admin/v1/status");
    expect(GATEWAY_OWNED_OPERATION_IDS).not.toContain("getAdminStatus");

    const res = await SELF.fetch(`${BASE}/admin/v1/status`, { headers: ROOT });
    expect(res.status).toBe(404);
    expect((await envelope(res)).code).toBe("not_found");
  });
});
