/**
 * The `guardrail_policy` WRITE half: admission, projection, and the two
 * behaviours a `201` used to promise and never deliver.
 *
 * ## What this file exists to stop
 *
 * Before this slice, `POST /admin/v1/guardrail-policies` accepted almost any
 * JSON object, answered `201`, and wrote a `control_plane_resources` DOCUMENT.
 * `apps/gateway` resolves the policies it actually enforces from two TYPED
 * tables — `guardrail_policy_revisions` and `guardrail_policy_bindings` — and
 * nothing in this app wrote either one. A complete, audited, RBAC-gated
 * revision history therefore existed that no request was ever evaluated
 * against, and `activate` moved a pointer the data plane does not read.
 *
 * Projecting the OLD documents was not an option and that is why wave 16 left
 * this open: `apps/gateway/src/guardrails/binding.ts::policySourceFromStore`
 * compiles every active revision EAGERLY at construction, so a partial revision
 * in the table would take the gateway's whole guardrail source down at boot.
 *
 * The close is therefore in two halves, and BOTH are asserted here:
 *
 *  1. **Admission is tightened**, not compilation loosened. A revision the data
 *     plane could never enforce is a `400` at create — carrying Rust's
 *     `invalid_guardrail_policy` code (`crates/ferrogate-gateway/src/server/
 *     guardrail_policies.rs::write_guardrail_error`, the `None =>` arm) and the
 *     FIELD PATH that made it unenforceable — not a `201` followed by silence.
 *     Rust does exactly this: `create_guardrail_policy_revision` calls
 *     `build_guardrail_policy_runtime(revision, ..)?` — it COMPILES the
 *     candidate at create time — before it inserts anything.
 *  2. **A valid revision is projected** into the two typed tables, in the exact
 *     shape `apps/gateway/src/guardrails/d1.ts` reads them back.
 *
 * ## The correlation join
 *
 * This file can only prove the WRITE side: `apps/control-plane` cannot import
 * `apps/gateway` (they are sibling workspaces, neither depends on the other).
 * The read side — "and the gateway then compiles it and BLOCKS the request" —
 * is `apps/gateway/test/guardrails/control-plane-projection.test.ts`. The two
 * are joined by three things asserted here in terms of the READER rather than
 * the writer:
 *
 *  - the rows are read back with the gateway's own `SELECT` statements, copied
 *    verbatim below;
 *  - `revision_json` is re-parsed with `policyRevisionSchema` and re-checked
 *    with `validatePolicyRevision` — the exact pair
 *    `InMemoryGuardrailPolicyStore.putRevision` runs on the gateway's boot
 *    path, so a document that would throw there fails here instead;
 *  - `created_by` is asserted NON-EMPTY, because `validatePolicyRevision`
 *    rejects an empty one and that is the single field the old document shape
 *    never carried.
 */

import { SELF } from "cloudflare:test";
import {
  type PolicyRevision,
  policyRevisionSchema,
  validatePolicyRevision,
} from "@ferrogate/guardrails";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey } from "./harness.js";

const KEY = operatorKey.secret;

/**
 * Copied VERBATIM from `apps/gateway/src/guardrails/d1.ts`
 * (`GUARDRAIL_REVISION_LIST_ALL_SQL` / `GUARDRAIL_BINDING_LIST_SQL`). Reading
 * the projection back through the reader's own statements is what makes this a
 * join and not two independent fixtures: a column this app writes that the
 * gateway does not select would not be seen by either half otherwise.
 */
const GATEWAY_REVISION_SELECT =
  "SELECT revision_json FROM guardrail_policy_revisions ORDER BY policy_id ASC, revision ASC";
const GATEWAY_BINDING_SELECT =
  "SELECT policy_id, active_revision, generation, binding_json " +
  "FROM guardrail_policy_bindings ORDER BY policy_id ASC";

interface ErrorEnvelope {
  readonly error: { readonly code: string; readonly message: string };
}

async function envelope(response: Response): Promise<ErrorEnvelope> {
  return (await response.json()) as ErrorEnvelope;
}

/** A COMPLETE, enforceable revision body — everything `PolicyRevision` needs. */
function enforceableBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: "block launch codes",
    checks: [
      {
        id: "kw",
        enabled: true,
        stage: "request",
        sources: ["user"],
        detector: { kind: "local", keywords: ["launch codes"], regex: [], secret_patterns: [] },
      },
    ],
    on_pass: [{ kind: "allow" }],
    on_fail: [{ kind: "block", code: "guardrail_blocked", message: "blocked by policy" }],
    on_error: [{ kind: "block", code: "guardrail_unavailable", message: "detector unavailable" }],
    ...overrides,
  };
}

function createPolicy(body: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/guardrail-policies`, jsonRequest(KEY, "POST", body));
}

function createNext(policyId: string, body: unknown): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/guardrail-policies/${policyId}/revisions`,
    jsonRequest(KEY, "POST", body),
  );
}

function activate(policyId: string, revision: number): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/guardrail-policies/${policyId}/activate`,
    jsonRequest(KEY, "POST", { revision }),
  );
}

async function resetGuardrailTables(): Promise<void> {
  await db().batch([
    db().prepare("DELETE FROM guardrail_policy_bindings"),
    db().prepare("DELETE FROM guardrail_policy_revisions"),
  ]);
}

/** Every projected revision, read with the GATEWAY's statement. */
async function projectedRevisions(): Promise<PolicyRevision[]> {
  const rows = await db().prepare(GATEWAY_REVISION_SELECT).all<{ revision_json: string }>();
  return (rows.results ?? []).map(
    (row) => policyRevisionSchema.parse(JSON.parse(row.revision_json)) as PolicyRevision,
  );
}

interface BindingRow {
  readonly policy_id: string;
  readonly active_revision: number | null;
  readonly generation: number;
  readonly binding_json: string;
}

async function projectedBindings(): Promise<BindingRow[]> {
  const rows = await db().prepare(GATEWAY_BINDING_SELECT).all<BindingRow>();
  return rows.results ?? [];
}

beforeAll(applySchema);

// ---------------------------------------------------------------------------
// 1. ADMISSION — an unenforceable revision is refused, not stored
// ---------------------------------------------------------------------------

describe("guardrail policy admission: a revision the data plane could never enforce is a 400", () => {
  beforeEach(async () => {
    await resetD1();
    await resetGuardrailTables();
    arm({ staticKeys: [operatorKey], store: "d1" });
  });

  it("REFUSES a revision with no checks — Rust's code, and the field path", async () => {
    const response = await createPolicy(enforceableBody({ policy_id: "gp_nochecks", checks: [] }));
    expect(response.status).toBe(400);
    const body = await envelope(response);
    // Rust `write_guardrail_error`'s `None =>` arm for a `validate()` failure.
    expect(body.error.code).toBe("invalid_guardrail_policy");
    expect(body.error.message).toContain("checks");
    // And nothing was written: a refusal that still stored the document would
    // leave exactly the row this slice exists to keep out of the table.
    expect(await projectedRevisions()).toHaveLength(0);
  });

  it("REFUSES a local detector with no deterministic constraint, naming checks[0].detector", async () => {
    const response = await createPolicy(
      enforceableBody({
        policy_id: "gp_emptydet",
        checks: [
          {
            id: "kw",
            enabled: true,
            stage: "request",
            sources: ["user"],
            detector: { kind: "local", keywords: [], regex: [], secret_patterns: [] },
          },
        ],
      }),
    );
    expect(response.status).toBe(400);
    const body = await envelope(response);
    expect(body.error.code).toBe("invalid_guardrail_policy");
    expect(body.error.message).toContain("checks[0].detector");
    expect(body.error.message).toContain("at least one deterministic constraint");
  });

  it("REFUSES a regex the data plane cannot compile, naming checks[0].detector", async () => {
    const response = await createPolicy(
      enforceableBody({
        policy_id: "gp_badregex",
        checks: [
          {
            id: "re",
            enabled: true,
            stage: "request",
            sources: ["user"],
            detector: { kind: "local", keywords: [], regex: ["("], secret_patterns: [] },
          },
        ],
      }),
    );
    expect(response.status).toBe(400);
    const body = await envelope(response);
    expect(body.error.code).toBe("invalid_guardrail_policy");
    expect(body.error.message).toContain("checks[0].detector");
  });

  it("REFUSES a custom_http detector aimed inside the network (the SSRF fence)", async () => {
    const response = await createPolicy(
      enforceableBody({
        policy_id: "gp_ssrf",
        checks: [
          {
            id: "http",
            enabled: true,
            stage: "request",
            sources: ["user"],
            detector: { kind: "custom_http", endpoint: "http://169.254.169.254/latest/meta-data" },
          },
        ],
      }),
    );
    expect(response.status).toBe(400);
    const body = await envelope(response);
    expect(body.error.code).toBe("invalid_guardrail_policy");
    expect(body.error.message).toContain("checks[0].detector");
  });

  it("REFUSES an empty on_fail — 'no posture declared' is unrepresentable", async () => {
    const response = await createPolicy(enforceableBody({ policy_id: "gp_noaction", on_fail: [] }));
    expect(response.status).toBe(400);
    const body = await envelope(response);
    expect(body.error.code).toBe("invalid_guardrail_policy");
    expect(body.error.message).toContain("on_fail");
  });

  it("REFUSES the shape that used to be accepted: `{policy_id, detectors: []}`", async () => {
    // This is the exact body `crud.test.ts` posted before this slice and got a
    // `201` for. `detectors` is not a field of Rust's `PolicyRevision` (which is
    // `deny_unknown_fields`), and `name` / `checks` / `on_*` are all missing, so
    // this is the SERDE leg: Rust answers `invalid_request_body` here, not
    // `invalid_guardrail_policy`.
    const response = await createPolicy({ policy_id: "gp_legacy", detectors: [] });
    expect(response.status).toBe(400);
    expect((await envelope(response)).error.code).toBe("invalid_request_body");
  });

  it("REFUSES an unenforceable revision on the SECOND create op too", async () => {
    const first = await createPolicy(enforceableBody({ policy_id: "gp_two" }));
    expect(first.status).toBe(201);

    const response = await createNext("gp_two", enforceableBody({ checks: [] }));
    expect(response.status).toBe(400);
    expect((await envelope(response)).error.code).toBe("invalid_guardrail_policy");

    // The refusal must not have advanced the revision chain either.
    const revisions = await projectedRevisions();
    expect(revisions.map((r) => r.revision)).toEqual([1]);
  });

  it("REFUSES a body policy_id that disagrees with the path", async () => {
    await createPolicy(enforceableBody({ policy_id: "gp_path" }));
    const response = await createNext("gp_path", enforceableBody({ policy_id: "gp_other" }));
    expect(response.status).toBe(400);
    expect((await envelope(response)).error.code).toBe("guardrail_policy_id_mismatch");
  });

  it("ACCEPTS a complete, enforceable revision", async () => {
    const response = await createPolicy(enforceableBody({ policy_id: "gp_ok" }));
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({
      object: "guardrail_policy_revision",
      policy: { policy_id: "gp_ok", revision: 1, status: "draft" },
    });
  });
});

// ---------------------------------------------------------------------------
// 2. PROJECTION — the typed tables the gateway actually reads
// ---------------------------------------------------------------------------

describe("guardrail policy projection: the revision reaches the tables the gateway reads", () => {
  beforeEach(async () => {
    await resetD1();
    await resetGuardrailTables();
    arm({ staticKeys: [operatorKey], store: "d1" });
  });

  it("writes a revision row the gateway's own SELECT finds and can PUT into its store", async () => {
    expect((await createPolicy(enforceableBody({ policy_id: "gp_proj" }))).status).toBe(201);

    const revisions = await projectedRevisions();
    expect(revisions).toHaveLength(1);
    const revision = revisions[0] as PolicyRevision;
    expect(revision.policy_id).toBe("gp_proj");
    expect(revision.revision).toBe(1);
    expect(revision.checks[0]?.id).toBe("kw");

    // `created_by` is the one field the old document shape never carried, and
    // `validatePolicyRevision` refuses an empty one — which is exactly how a
    // projected legacy document would have killed the gateway at boot.
    expect(revision.created_by.trim()).not.toBe("");

    // The gateway's boot path is `InMemoryGuardrailPolicyStore.putRevision`,
    // whose first statement is this call. If it throws, the Worker does not
    // start.
    expect(() => {
      validatePolicyRevision(revision);
    }).not.toThrow();
  });

  it("pins the columns the gateway's reader keys on", async () => {
    await createPolicy(enforceableBody({ policy_id: "gp_cols" }));
    const row = await db()
      .prepare(
        "SELECT policy_id, revision, immutable_id, created_by FROM guardrail_policy_revisions",
      )
      .first<{
        policy_id: string;
        revision: number;
        immutable_id: string;
        created_by: string;
      }>();
    expect(row).not.toBeNull();
    expect(row?.policy_id).toBe("gp_cols");
    expect(row?.revision).toBe(1);
    // `immutableId(revision)` in `@ferrogate/guardrails` — the `UNIQUE` key.
    expect(row?.immutable_id).toBe("gp_cols@1");
    expect(row?.created_by.trim()).not.toBe("");
  });

  it("ACTIVATE moves the binding row — the one row the data plane enforces from", async () => {
    await createPolicy(enforceableBody({ policy_id: "gp_act" }));
    await createNext("gp_act", enforceableBody({ name: "second" }));

    expect(await projectedBindings()).toHaveLength(0);

    expect((await activate("gp_act", 2)).status).toBe(200);
    const bindings = await projectedBindings();
    expect(bindings).toHaveLength(1);
    expect(bindings[0]?.policy_id).toBe("gp_act");
    expect(bindings[0]?.active_revision).toBe(2);
    // The CAS token the gateway's `activate` guards on. An INSERT is
    // generation 0 -> 1; anything else means the write did not go through the
    // compare-and-swap.
    expect(bindings[0]?.generation).toBe(1);
  });

  it("ROLLBACK moves the binding back and advances the generation", async () => {
    await createPolicy(enforceableBody({ policy_id: "gp_roll" }));
    await createNext("gp_roll", enforceableBody({ name: "second" }));
    await activate("gp_roll", 2);

    const rolled = await SELF.fetch(
      `${BASE}/admin/v1/guardrail-policies/gp_roll/rollback`,
      jsonRequest(KEY, "POST", {}),
    );
    expect(rolled.status).toBe(200);

    const bindings = await projectedBindings();
    expect(bindings[0]?.active_revision).toBe(1);
    expect(bindings[0]?.generation).toBe(2);
  });

  it("ARCHIVING the ACTIVE revision stops the data plane enforcing it", async () => {
    await createPolicy(enforceableBody({ policy_id: "gp_arch" }));
    await activate("gp_arch", 1);
    expect((await projectedBindings())[0]?.active_revision).toBe(1);

    const archived = await SELF.fetch(`${BASE}/admin/v1/guardrail-policies/gp_arch/revisions/1`, {
      method: "DELETE",
      headers: bearer(KEY),
    });
    expect(archived.status).toBe(200);

    // The operator has been told the revision is archived. A residual
    // `active_revision` would mean it is still being enforced on every request.
    const bindings = await projectedBindings();
    expect(bindings[0]?.active_revision).toBeNull();
  });

  it("REFUSES to activate a legacy document the data plane could not compile", async () => {
    // A revision that predates the admission tightening: seeded straight into
    // the document table, exactly as wave 16 left it. Activating it must not
    // publish an uncompilable revision into the enforcement tables.
    await db()
      .prepare(
        "INSERT INTO control_plane_resources " +
          "(resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix) " +
          "VALUES (?, ?, ?, 1, 1, 1)",
      )
      .bind(
        "guardrail-policy-revisions",
        "gp_legacy@1",
        JSON.stringify({
          id: "gp_legacy@1",
          policy_id: "gp_legacy",
          revision: 1,
          status: "draft",
          detectors: [],
        }),
      )
      .run();
    await db()
      .prepare(
        "INSERT INTO control_plane_resources " +
          "(resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix) " +
          "VALUES (?, ?, ?, 1, 1, 1)",
      )
      .bind(
        "guardrail-policies",
        "gp_legacy",
        JSON.stringify({
          id: "gp_legacy",
          policy_id: "gp_legacy",
          head_revision: 1,
          active_revision: null,
        }),
      )
      .run();

    const response = await activate("gp_legacy", 1);
    expect(response.status).toBe(400);
    expect((await envelope(response)).error.code).toBe("invalid_guardrail_policy");
    expect(await projectedBindings()).toHaveLength(0);
  });
});
