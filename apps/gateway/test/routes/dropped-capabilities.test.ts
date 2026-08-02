/**
 * THE DROP IS A CONTRACT — the anti-un-drop gate for clusters S1 and S2.
 *
 * ## What this file is for
 *
 * On 2026-08-02 the owner **dropped** two capabilities rather than porting
 * them, which was one of the three exits `docs/rewrite/CUTOVER-READINESS.md`
 * §0.3 offered per spec-bound cluster (build / drop / transcribe):
 *
 *   * **S1 · `executeFunction`** — the brokered edge-function egress path.
 *   * **S2 · `listTools` / `executeTool`** — the native tool catalogue and the
 *     governed dispatch into it.
 *
 * Before that decision these three operations answered `501 not_implemented`
 * with a `PORT-TODO(...)` note — an *accident*, and a promise. After it they
 * answer `501 capability_not_offered` with a body that says the deployment does
 * not offer the capability. **A 501 nobody decided and a 501 somebody chose
 * look identical in the code and completely different to an operator**, so the
 * difference has to be observable on the wire, which is what this file asserts.
 *
 * ## Why it is written the way it is
 *
 * Every expectation below is **hard-coded here, not imported from `../../src`**.
 * That is deliberate and it is the whole point of the gate: a test that read
 * the dropped-operation list out of the module it is gating would follow any
 * edit to that module and could never go red. This file states the owner's
 * decision independently — the three operation ids, the status, the error code,
 * the decision date — so that *changing the code to match a different decision*
 * is what turns it red. Re-enabling one of these operations, re-routing it to a
 * real handler, softening the refusal back into a promise, or quietly dropping
 * a fourth operation are then all RED, and each is fixed by editing this file
 * and `docs/rewrite/DROPPED-CAPABILITIES.md` — i.e. by recording a decision.
 *
 * ## Why the status is still 501
 *
 * The runtime API contract (`docs/openapi/runtime-api-contract.json`) carries
 * **no response-status vocabulary at all** — an operation is
 * `{path, method, operation_id, visibility, auth, rbac_action}` — so it does not
 * prescribe a status for an unsupported-but-known operation and nothing had to
 * change on that axis. 501 is also the house precedent: it is the only 501 the
 * Rust gateway originates (`crates/ferrogate-gateway/src/server/local.rs:11835`
 * `self_hosted_worker_production_mtls_not_implemented`). And it is the only
 * status whose definition fits: the route EXISTS, is contract-matched and is
 * auth-guarded, so 404 would lie about the route and 403 would blame the
 * caller; the refusal is permanent, so 503 would promise "try later". What was
 * wrong was never the status — it was the body.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { createGatewayApp } from "../../src/routes/index.js";

declare global {
  interface ImportMeta {
    glob(pattern: string, options: object): Record<string, string>;
  }
}

const BASE = "https://gateway.test";

/**
 * The owner's decision, restated here so the gate is independent of the code.
 * `method`/`path` are the contract's own, quoted rather than looked up for the
 * same reason.
 */
const DROPPED = [
  {
    operationId: "executeFunction",
    cluster: "S1",
    method: "POST",
    path: "/v1/functions/execute",
    /** A credential entitled to the operation — the refusal must be reached. */
    entitled: "fg_root",
  },
  {
    operationId: "listTools",
    cluster: "S2",
    method: "GET",
    path: "/v1/tools",
    entitled: "fg_tenant_tools",
  },
  {
    operationId: "executeTool",
    cluster: "S2",
    method: "POST",
    path: "/v1/tools/execute",
    entitled: "fg_tenant_tools",
  },
] as const;

/** The decided answer. */
const DROPPED_STATUS = 501;
const DROPPED_CODE = "capability_not_offered";
/** The date the owner made the call, which the message and the doc must carry. */
const DECIDED_ON = "2026-08-02";
/** Where the reasoning lives. An operator who hits this must be able to find it. */
const DECISION_DOC = "docs/rewrite/DROPPED-CAPABILITIES.md";

/**
 * Language that turns a decision back into a promise. `not_implemented` is on
 * this list because it was the literal code these three used to answer with.
 */
const PROMISE_LANGUAGE = [
  /not[ _]implemented/i,
  /not yet/i,
  /PORT-TODO/i,
  /coming soon/i,
  /\bTODO\b/,
  /\bWIP\b/i,
  /unfinished/i,
  /in progress/i,
];

interface Envelope {
  readonly error: {
    readonly message: string;
    readonly type: string;
    readonly code: string;
    readonly request_id: string | null;
  };
}

async function call(entry: (typeof DROPPED)[number], init: RequestInit = {}): Promise<Response> {
  return await SELF.fetch(`${BASE}${entry.path}`, {
    method: entry.method,
    ...init,
  });
}

async function callEntitled(entry: (typeof DROPPED)[number]): Promise<Response> {
  const headers: Record<string, string> = { authorization: `Bearer ${entry.entitled}` };
  if (entry.method === "POST") {
    headers["content-type"] = "application/json";
    return await call(entry, { headers, body: JSON.stringify({}) });
  }
  return await call(entry, { headers });
}

async function envelope(res: Response): Promise<Envelope> {
  return (await res.json()) as Envelope;
}

describe("the dropped set is exactly the owner's decision", () => {
  it("names three operations and no others", () => {
    // Vacuity guard for every loop below: an empty table would make this file
    // assert nothing at all while still reporting green.
    expect(DROPPED.map((entry) => entry.operationId)).toEqual([
      "executeFunction",
      "listTools",
      "executeTool",
    ]);
  });

  it("mounts all three — a dropped operation stays MATCHED, never a 404", async () => {
    // The refusal has to come from a decision, not from the route table having
    // forgotten the operation. Deleting the mount would answer 404 `not_found`
    // through `gatewayNotFoundHandler`, which tells an operator the endpoint
    // does not exist — a different and false claim.
    const { router } = createGatewayApp();
    const registered = new Set(router.registeredOperationIds());
    for (const entry of DROPPED) {
      expect(registered, entry.operationId).toContain(entry.operationId);
    }
  });
});

describe("each dropped operation refuses EXPLICITLY", () => {
  for (const entry of DROPPED) {
    it(`${entry.operationId} (${entry.cluster}) answers ${DROPPED_STATUS} ${DROPPED_CODE}`, async () => {
      const res = await callEntitled(entry);
      expect(res.status).toBe(DROPPED_STATUS);
      const body = await envelope(res);
      expect(body.error.code).toBe(DROPPED_CODE);
      expect(body.error.type).toBe("ferrogate_error");
    });

    it(`${entry.operationId} says the capability is NOT OFFERED by this deployment`, async () => {
      const { error } = await envelope(await callEntitled(entry));
      // The operator-facing half: what happened, and that it is a posture of
      // this deployment rather than a fault of this request.
      expect(error.message).toContain(entry.operationId);
      expect(error.message).toContain("not offered by this deployment");
    });

    it(`${entry.operationId} cites the decision, its date and where it is written down`, async () => {
      const { error } = await envelope(await callEntitled(entry));
      // The auditor-facing half: WHO decided, WHEN, and where the reasoning is.
      expect(error.message).toContain(DECIDED_ON);
      expect(error.message).toContain(DECISION_DOC);
    });

    it(`${entry.operationId} makes no PROMISE — the body must not imply "later"`, async () => {
      const { error } = await envelope(await callEntitled(entry));
      for (const pattern of PROMISE_LANGUAGE) {
        expect(error.message, `${entry.operationId} / ${pattern}`).not.toMatch(pattern);
      }
      // The machine-readable half is where this bit most: a client switching on
      // `not_implemented` is being told to retry after the next release.
      expect(error.code).not.toMatch(/not[ _]implemented/i);
    });

    it(`${entry.operationId} is refused the same way twice — the answer is a posture, not a race`, async () => {
      const first = await envelope(await callEntitled(entry));
      const second = await envelope(await callEntitled(entry));
      expect(first.error.code).toBe(second.error.code);
      expect(first.error.message).toBe(second.error.message);
    });
  }
});

describe("the drop is NOT an auth shortcut", () => {
  // The refusal sits BEHIND the contract guard, exactly where the real handler
  // would have. If a future edit ever answers the drop before `contractAuth`,
  // the three operations become an unauthenticated oracle for which operations
  // this deployment offers — so both denials below must keep winning.
  for (const entry of DROPPED) {
    it(`${entry.operationId} answers 401 to an anonymous caller, not ${DROPPED_STATUS}`, async () => {
      const res = await call(entry, {
        headers: entry.method === "POST" ? { "content-type": "application/json" } : {},
        ...(entry.method === "POST" ? { body: "{}" } : {}),
      });
      expect(res.status).toBe(401);
      expect((await envelope(res)).error.code).toBe("missing_api_key");
    });
  }

  it("answers 403 scope_denied to an authenticated but under-scoped caller", async () => {
    // `fg_tenant_readonly` holds `skills.read`; `GET /v1/tools` wants
    // `tools.read`. Scope is still adjudicated before the capability answer.
    const res = await SELF.fetch(`${BASE}/v1/tools`, {
      headers: { authorization: "Bearer fg_tenant_readonly" },
    });
    expect(res.status).toBe(403);
    expect((await envelope(res)).error.code).toBe("scope_denied");
  });
});

describe("no FOURTH capability is dropped without a decision", () => {
  /**
   * The three assertions above are per-operation, so they cannot see a drop
   * that was ADDED. This block derives the dropped set from the source instead
   * of restating it, and requires it to be exactly the owner's three — so
   * quietly refusing a fourth operation is red here even though no existing
   * assertion mentions it.
   *
   * Source-derived, not authored: `?raw` over every module this Worker is built
   * from, the same mechanism `test/env-var-drift.test.ts` uses for the
   * `wrangler.toml` contract.
   */
  const SOURCES = import.meta.glob("../../src/**/*.ts", {
    query: "?raw",
    import: "default",
    eager: true,
  });

  it("globbed the source at all — an empty scan would assert nothing", () => {
    expect(Object.keys(SOURCES).length).toBeGreaterThan(20);
  });

  it("mounts a refusal for EXACTLY the three decided operations", () => {
    const mounted = Object.values(SOURCES)
      .flatMap((source) => [...source.matchAll(/registerDropped\(\s*"([^"]+)"/g)])
      .map((match) => match[1])
      .sort();
    expect(mounted).toEqual(DROPPED.map((entry) => entry.operationId).sort());
  });

  it("originates the refusal in ONE place, so the wording cannot fork", () => {
    // A hand-rolled `capability_not_offered` somewhere else would be a drop
    // that never passed through the decision table — the exact drift that put
    // three different PORT-TODO paragraphs on these three operations before.
    const originators = Object.entries(SOURCES)
      .filter(([, source]) => source.includes('"capability_not_offered"'))
      .map(([path]) => path);
    expect(originators).toEqual(["../../src/routes/index.ts"]);
  });
});

describe("the decision is WRITTEN DOWN, and the two records agree", () => {
  // `?raw` is a Vite transform, not a runtime read: the bytes are inlined at
  // build time, which is the only way a workerd test with no filesystem can see
  // a file at all. Same mechanism as `test/env-var-drift.test.ts`.
  const DOCS = import.meta.glob("../../../../docs/rewrite/DROPPED-CAPABILITIES.md", {
    query: "?raw",
    import: "default",
    eager: true,
  });

  function decisionDoc(): string {
    const values = Object.values(DOCS);
    expect(values.length, "docs/rewrite/DROPPED-CAPABILITIES.md must exist").toBe(1);
    const text = values[0];
    expect(typeof text).toBe("string");
    return text as string;
  }

  it("the decision document exists and is not a stub", () => {
    expect(decisionDoc().length).toBeGreaterThan(2000);
  });

  it("records the owner and the date of the decision", () => {
    const doc = decisionDoc();
    expect(doc).toContain(DECIDED_ON);
    expect(doc.toLowerCase()).toContain("owner");
  });

  it("documents EXACTLY the operations the code drops — both directions", () => {
    // The machine-readable ledger the doc carries, one HTML comment per entry:
    //   <!-- DROPPED-OPERATION-ID: executeFunction -->
    // Dropping a fourth operation without writing it down is red HERE; writing
    // down an operation the code still serves is red here too.
    const documented = [...decisionDoc().matchAll(/<!--\s*DROPPED-OPERATION-ID:\s*(\S+)\s*-->/g)]
      .map((match) => match[1])
      .sort();
    expect(documented).toEqual(DROPPED.map((entry) => entry.operationId).sort());
  });

  it("cites the Rust each dropped capability came from, so the delete costs no pointer", () => {
    // `crates/**` is about to be deleted. After that these citations are the
    // only place a future implementer learns where the behaviour used to live.
    const doc = decisionDoc();
    for (const anchor of [
      "crates/ferrogate-gateway/src/server/local.rs:3219",
      "crates/ferrogate-runtime/src/function_egress.rs",
      "crates/ferrogate-runtime/src/function_token.rs",
      "crates/ferrogate-gateway/src/server/local.rs:2890",
      "crates/ferrogate-gateway/src/extensions.rs:214",
    ]) {
      expect(doc, anchor).toContain(anchor);
    }
  });

  it("carries the certification's warning that S2's hook model must be designed fresh", () => {
    // `extensions.rs`'s `RequestHook` has exactly one variant (`Noop`) and
    // `EventSink` one (`AuditLog`). A future implementer who copies that shape
    // inherits an abstraction that was never exercised.
    const doc = decisionDoc();
    expect(doc).toContain("RequestHook");
    expect(doc).toContain("Noop");
    expect(doc.toLowerCase()).toContain("designed fresh");
  });
});
