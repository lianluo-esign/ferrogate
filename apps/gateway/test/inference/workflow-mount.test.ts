/**
 * ANTI-UNMOUNT for the workflow GRAPH gate — certification finding **D2**, as
 * the DEPLOYED Worker runs it.
 *
 * ## Why this file was written during the wave-17 integrate step
 *
 * `test/inference/workflow-graph.test.ts` is thorough about the thirteen
 * refusals, and `test/inference/workflow-ledger.test.ts` is thorough about the
 * durable catalog and the step ledger. Neither drives the app the Worker
 * exports:
 *
 *  - `workflow-graph.test.ts` builds its own router with `harness({ workflows })`
 *    and hands the catalog in explicitly (`fixtures.ts::harness` →
 *    `createInferenceRouter`);
 *  - `workflow-ledger.test.ts`'s strongest mount assertion calls
 *    `resolveDeps({}, env)` directly.
 *
 * That is precisely the factory-vs-mount confusion `docs/rewrite/MOUNT-SEAMS.md`
 * §1 is organised around, and it was measured rather than assumed. Against the
 * full 1866-test gateway suite, replacing
 *
 *     deps.workflows ?? workflowCatalogFromEnv(env as WorkflowGateBindings)
 *
 * in `src/inference/defaults.ts` with an always-empty catalog left **1865 of
 * 1866 green** — only `workflow-ledger.test.ts`'s `resolveDeps` probe caught
 * it, and nothing at all asserted that a real HTTP request through
 * `src/worker.ts` is gated. For a HIGH policy-bypass finding that is not
 * enough: the whole defect D2 named was a gate that existed and never ran.
 *
 * Everything below goes through `SELF.fetch` — `src/worker.ts` → `src/index.ts`
 * → `createGatewayApp` → the mounted `inferenceRouteModule` → `contractAuth`
 * → the real `resolveDeps` over the real `wrangler.toml` bindings — so the
 * `CONTROL_DB` read here is the deployed one and the workflow document is the
 * one `apps/control-plane` writes.
 *
 * ## What each case pins
 *
 * | case | what its RED means |
 * |---|---|
 * | ghost node ⇒ 400 `workflow_node_not_found` | the gate runs on the deployed request path at all |
 * | no upstream call on the refusal | it runs BEFORE dispatch — a bypass would already have spent provider money |
 * | tool node ⇒ 403 `workflow_node_not_model` | the refusal is decided from the SEEDED document, not a constant |
 * | legal node ⇒ 200 | the gate is not a blanket refusal (the control that makes the rest meaningful) |
 * | no workflow headers ⇒ 200 | an ordinary request is untouched, so "gated" cannot be faked by breaking inference |
 * | a step is written to `control_plane_resources` | the DEPLOYED path uses the durable ledger, not `NO_WORKFLOW_HISTORY` |
 */
import { SELF, env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  AGENT_WORKFLOW_COLLECTION,
  WORKFLOW_RUN_STEP_COLLECTION,
} from "../../src/inference/index.js";

const BASE = "https://gw.test";
const CHAT = `${BASE}/v1/chat/completions`;
const UPSTREAM_HOST = "api.workflow-mount.example";

const DB = (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB;
const TENANT_RESOURCE_TABLE = "tenant_resources";

async function tenantDb(): Promise<D1Database> {
  const namespace = (
    env as unknown as {
      TENANT_DATA?: import("@ferrogate/storage/durable-objects").TenantDataNamespace;
    }
  ).TENANT_DATA;
  if (namespace === undefined) throw new Error("workflow mount test expects TENANT_DATA");
  return (await new DurableObjectTenantDatabaseRouter(namespace, DB).forTenant(TENANT_ID)).db;
}

const PROVIDERS = JSON.stringify([
  { name: "wfp", kind: "openai", base_url: `https://${UPSTREAM_HOST}/v1` },
]);
const MODELS = JSON.stringify([
  { name: "wf-probe", provider: "wfp", provider_model: "wf-probe-physical" },
]);
/** A TENANT key: the catalog is read `forTenant`, so the subject must carry one. */
const TENANT_ID = "tenant_wf";
const KEYS = JSON.stringify([{ key: "fg_wf", id: "key_wf", tenant_id: TENANT_ID, scopes: [] }]);

const OVERRIDES: Record<string, string> = {
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: KEYS,
};

const ORIGINAL: Record<string, unknown> = {};
const mutable = env as unknown as Record<string, unknown>;

beforeAll(() => {
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

const WF_ID = "x-ferrogate-workflow-id";
const WF_VERSION = "x-ferrogate-workflow-version";
const WF_NODE = "x-ferrogate-workflow-node-id";
const WF_RUN = "x-ferrogate-workflow-run-id";
const AGENT_RUN = "x-ferrogate-agent-run-id";

/**
 * The seeded graph.
 *
 * `start` is a plain model node; `hitl` is a `human` node, which
 * `workflow_node_not_model` refuses. Both refusals below are therefore decided
 * from THIS document — a hard-coded 400 could not tell them apart.
 */
const GRAPH_DOCUMENT = {
  id: "wf_mount",
  version: 1,
  enabled: true,
  tenant_id: TENANT_ID,
  nodes: [{ id: "start" }, { id: "hitl", kind: "human" }],
  edges: [{ from: "start", to: "hitl" }],
};

async function seedWorkflow(): Promise<void> {
  await (await tenantDb())
    .prepare(
      `INSERT INTO ${TENANT_RESOURCE_TABLE}
       (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
     VALUES (?, ?, ?, 1, 0, 0)
     ON CONFLICT (resource_kind, resource_id)
       DO UPDATE SET document_json = excluded.document_json`,
    )
    .bind(AGENT_WORKFLOW_COLLECTION, GRAPH_DOCUMENT.id, JSON.stringify(GRAPH_DOCUMENT))
    .run();
}

async function clearWorkflowRows(): Promise<void> {
  await Promise.all([
    DB.prepare("DELETE FROM control_plane_resources WHERE resource_kind IN (?, ?)")
      .bind(AGENT_WORKFLOW_COLLECTION, WORKFLOW_RUN_STEP_COLLECTION)
      .run(),
    (async () => {
      const objectDb = await tenantDb();
      await objectDb
        .prepare(`DELETE FROM ${TENANT_RESOURCE_TABLE} WHERE resource_kind IN (?, ?)`)
        .bind(AGENT_WORKFLOW_COLLECTION, WORKFLOW_RUN_STEP_COLLECTION)
        .run();
    })(),
  ]);
}

async function stepRowCount(): Promise<number> {
  const row = await (await tenantDb())
    .prepare(`SELECT COUNT(*) AS n FROM ${TENANT_RESOURCE_TABLE} WHERE resource_kind = ?`)
    .bind(WORKFLOW_RUN_STEP_COLLECTION)
    .first<{ n: number }>();
  return row === null ? 0 : Number(row.n);
}

/** Count every outbound provider call and answer each one with a completion. */
function interceptUpstream(): { calls: () => number; restore: () => void } {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.includes(UPSTREAM_HOST)) {
      calls += 1;
      return new Response(
        JSON.stringify({
          id: "chatcmpl-mount",
          object: "chat.completion",
          model: "wf-probe-physical",
          choices: [
            { index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" },
          ],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return await original(input as RequestInfo, init);
  }) as typeof fetch;
  return {
    calls: () => calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

async function post(headers: Record<string, string>): Promise<Response> {
  return await SELF.fetch(CHAT, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: "Bearer fg_wf",
      ...headers,
    },
    body: JSON.stringify({ model: "wf-probe", messages: [{ role: "user", content: "hi" }] }),
  });
}

async function codeOf(response: Response): Promise<string> {
  const body = (await response.json()) as { error?: { code?: string } };
  return body.error?.code ?? "";
}

beforeEach(async () => {
  await clearWorkflowRows();
  await seedWorkflow();
});

describe("the workflow graph gate is mounted on the app the Worker exports", () => {
  it("refuses a ghost node with 400 workflow_node_not_found — through SELF", async () => {
    const upstream = interceptUpstream();
    try {
      const response = await post({
        [WF_ID]: GRAPH_DOCUMENT.id,
        [WF_VERSION]: "1",
        [WF_NODE]: "ghost",
        [AGENT_RUN]: "run_mount_1",
      });
      expect(response.status).toBe(400);
      expect(await codeOf(response)).toBe("workflow_node_not_found");
      // BEFORE dispatch. A gate that refused after paying the provider would
      // still be a money bypass even though the status code looked right.
      expect(upstream.calls()).toBe(0);
    } finally {
      upstream.restore();
    }
  });

  it("refuses a NON-MODEL node with 403 workflow_node_not_model — the seeded document decides", async () => {
    const upstream = interceptUpstream();
    try {
      const response = await post({
        [WF_ID]: GRAPH_DOCUMENT.id,
        [WF_VERSION]: "1",
        [WF_NODE]: "hitl",
        [AGENT_RUN]: "run_mount_2",
      });
      expect(response.status).toBe(403);
      expect(await codeOf(response)).toBe("workflow_node_not_model");
      expect(upstream.calls()).toBe(0);
    } finally {
      upstream.restore();
    }
  });

  it("refuses a workflow id that is in NO document with 400 workflow_not_found", async () => {
    const upstream = interceptUpstream();
    try {
      const response = await post({
        [WF_ID]: "wf_never_seeded",
        [WF_VERSION]: "1",
        [WF_NODE]: "start",
        [AGENT_RUN]: "run_mount_3",
      });
      expect(response.status).toBe(400);
      expect(await codeOf(response)).toBe("workflow_not_found");
      expect(upstream.calls()).toBe(0);
    } finally {
      upstream.restore();
    }
  });

  it("CONTROL: a LEGAL step is admitted and dispatched — the gate is not a blanket refusal", async () => {
    const upstream = interceptUpstream();
    try {
      const response = await post({
        [WF_ID]: GRAPH_DOCUMENT.id,
        [WF_VERSION]: "1",
        [WF_NODE]: "start",
        [AGENT_RUN]: "run_mount_4",
      });
      expect(response.status).toBe(200);
      expect(upstream.calls()).toBe(1);
    } finally {
      upstream.restore();
    }
  });

  it("a REFERENCE-SHAPED client reaches the gate — the run-id alias", async () => {
    // The residue `src/inference/workflow.ts` documented and the wave-17
    // integrate step closed. `src/ratelimit/workflow.ts::workflowDeclarationFrom`
    // required `x-ferrogate-workflow-run-id` among three headers that must
    // appear together, so a client sending Rust's `x-ferrogate-agent-run-id`
    // instead met THAT middleware first and was answered
    // `400 invalid_workflow_declaration` — the graph gate was unreachable for
    // exactly the clients it was ported for. Every case in this file was that
    // 400 before the alias landed.
    const upstream = interceptUpstream();
    try {
      const response = await post({
        [WF_ID]: GRAPH_DOCUMENT.id,
        [WF_VERSION]: "1",
        [WF_NODE]: "ghost",
        [AGENT_RUN]: "run_alias",
      });
      expect(response.status).toBe(400);
      const code = await codeOf(response);
      expect(code).not.toBe("invalid_workflow_declaration");
      expect(code).toBe("workflow_node_not_found");
    } finally {
      upstream.restore();
    }
  });

  it("the TypeScript-only run id still works, and still keys the budget row", async () => {
    const upstream = interceptUpstream();
    try {
      const response = await post({
        [WF_ID]: GRAPH_DOCUMENT.id,
        [WF_VERSION]: "1",
        [WF_NODE]: "ghost",
        [WF_RUN]: "run_ts_only",
      });
      expect(response.status).toBe(400);
      expect(await codeOf(response)).toBe("workflow_node_not_found");
    } finally {
      upstream.restore();
    }
  });

  it("a bare correlation id is NOT a workflow declaration — the load-bearing guard", async () => {
    // Assets and MCP send `x-ferrogate-agent-run-id` on ordinary requests
    // (#305/#522). An unguarded alias would make every one of them a PARTIAL
    // declaration, i.e. a 400 on traffic that declares no workflow at all.
    const upstream = interceptUpstream();
    try {
      const response = await post({ [AGENT_RUN]: "run_correlation_only" });
      expect(response.status).toBe(200);
      expect(upstream.calls()).toBe(1);
    } finally {
      upstream.restore();
    }
  });

  it("CONTROL: a request with NO workflow headers is untouched", async () => {
    const upstream = interceptUpstream();
    try {
      const response = await post({});
      expect(response.status).toBe(200);
      expect(upstream.calls()).toBe(1);
    } finally {
      upstream.restore();
    }
  });

  it("writes the admitted step to the DURABLE ledger, not an inert default", async () => {
    // `NO_WORKFLOW_HISTORY.recordStep` is a no-op, so this row existing is the
    // proof that the composition root resolved `workflowHistoryFromEnv`.
    expect(await stepRowCount()).toBe(0);
    const upstream = interceptUpstream();
    try {
      expect(
        (
          await post({
            [WF_ID]: GRAPH_DOCUMENT.id,
            [WF_VERSION]: "1",
            [WF_NODE]: "start",
            [AGENT_RUN]: "run_mount_5",
          })
        ).status,
      ).toBe(200);
    } finally {
      upstream.restore();
    }
    expect(await stepRowCount()).toBeGreaterThan(0);
  });
});
