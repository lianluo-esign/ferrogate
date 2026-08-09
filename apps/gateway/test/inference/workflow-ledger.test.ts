/**
 * The DURABLE half of the workflow graph gate, against a real migrated D1.
 *
 * `workflow-graph.test.ts` injects the four run facts so that one refusal is
 * one HTTP call. This file does the opposite and asserts the thing that file
 * cannot: that the catalog and the step ledger are REAL — the admin documents
 * `apps/control-plane` writes are the ones the gate reads, and a step admitted
 * by one request is the step the NEXT request's edge gate sees.
 *
 * That loop is the failure mode this repository keeps finding one level up: a
 * mounted gate reading a table nothing writes. Here the same code path writes
 * and reads it, and `describe("the write/read loop")` drives it through the
 * real router with the D1-backed sources injected.
 *
 * `env.CONTROL_DB` carries the deployed control migration (`test/setup-d1.ts`
 * applies `sql/d1-ts/control/0001_init_control.sql`), so
 * `control_plane_resources` here is the production table, not a fixture.
 */
import { env } from "cloudflare:test";
import type { WorkflowGraph, WorkflowRunFacts } from "@ferrogate/policy";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import { beforeEach, describe, expect, it } from "vitest";
import {
  AGENT_WORKFLOW_COLLECTION,
  WORKFLOW_RUN_STEP_COLLECTION,
  d1WorkflowCatalog,
  d1WorkflowRunHistory,
  decodeWorkflowDocument,
  mergeWorkflowTables,
  resolveDeps,
  workflowsFromSkillPackages,
} from "../../src/inference/index.js";
import type {
  InferenceDeps,
  WorkflowCatalogResult,
  WorkflowCatalogSource,
  WorkflowFactsResult,
  WorkflowRunHistory,
} from "../../src/inference/index.js";
import { errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const DB = (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB;
const TENANT_RESOURCE_TABLE = "tenant_resources";

async function tenantDb(tenantId: string): Promise<D1Database> {
  const namespace = (
    env as unknown as {
      TENANT_DATA?: import("@ferrogate/storage/durable-objects").TenantDataNamespace;
    }
  ).TENANT_DATA;
  if (namespace === undefined) throw new Error("workflow ledger test expects TENANT_DATA");
  return (await new DurableObjectTenantDatabaseRouter(namespace, DB).forTenant(tenantId)).db;
}

/**
 * Narrow a catalog read to its workflows, ASSERTING it succeeded.
 *
 * A helper rather than a cast: an `{ ok: false }` result must fail the test
 * loudly, not be reinterpreted as an empty table — the failure this gate's
 * whole 503 posture exists to prevent.
 */
function workflowsOf(
  loaded: Awaited<ReturnType<WorkflowCatalogSource["forTenant"]>>,
): readonly WorkflowGraph[] {
  if (Array.isArray(loaded)) return loaded;
  const result = loaded as WorkflowCatalogResult;
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(`catalog read failed: ${result.detail}`);
  return result.workflows;
}

/** The same, for a run-facts read. */
function factsOf(loaded: Awaited<ReturnType<WorkflowRunHistory["factsFor"]>>): WorkflowRunFacts {
  if (!("ok" in loaded)) return loaded;
  const result = loaded as WorkflowFactsResult;
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(`history read failed: ${result.detail}`);
  return result.facts;
}

const COMPLETION = {
  id: "chatcmpl-led",
  object: "chat.completion",
  model: "gpt-4o-mini-2024-07-18",
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 4, completion_tokens: 2, total_tokens: 6 },
};

/** Write one admin `agent-workflows` document, exactly as the control plane does. */
async function seedWorkflow(id: string, document: Record<string, unknown>): Promise<void> {
  await DB.prepare(
    `INSERT INTO control_plane_resources
       (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
     VALUES (?, ?, ?, 1, 0, 0)
     ON CONFLICT (resource_kind, resource_id)
       DO UPDATE SET document_json = excluded.document_json`,
  )
    .bind(AGENT_WORKFLOW_COLLECTION, id, JSON.stringify(document))
    .run();
  const tenantId = document.tenant_id;
  if (typeof tenantId === "string" && tenantId.trim() !== "") {
    await (await tenantDb(tenantId))
      .prepare(
        `INSERT INTO ${TENANT_RESOURCE_TABLE}
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, 1, 0, 0)
         ON CONFLICT (resource_kind, resource_id)
           DO UPDATE SET document_json = excluded.document_json`,
      )
      .bind(AGENT_WORKFLOW_COLLECTION, id, JSON.stringify(document))
      .run();
  }
}

async function clearWorkflowRows(): Promise<void> {
  await Promise.all([
    DB.prepare("DELETE FROM control_plane_resources WHERE resource_kind IN (?, ?)")
      .bind(AGENT_WORKFLOW_COLLECTION, WORKFLOW_RUN_STEP_COLLECTION)
      .run(),
    (async () => {
      const objectDb = await tenantDb("acme");
      await objectDb
        .prepare(`DELETE FROM ${TENANT_RESOURCE_TABLE} WHERE resource_kind IN (?, ?)`)
        .bind(AGENT_WORKFLOW_COLLECTION, WORKFLOW_RUN_STEP_COLLECTION)
        .run();
    })(),
  ]);
}

const GRAPH_DOCUMENT = {
  id: "wf_pipeline",
  version: 1,
  enabled: true,
  nodes: [{ id: "start" }, { id: "review", model: "gpt-4o-mini" }],
  edges: [{ from: "start", to: "review" }],
};

beforeEach(async () => {
  await clearWorkflowRows();
});

describe("the durable catalog", () => {
  it("reads the admin documents the control plane writes", async () => {
    await seedWorkflow("wf_pipeline", { ...GRAPH_DOCUMENT, tenant_id: "acme" });
    const catalog = d1WorkflowCatalog(DB, undefined);
    const loaded = await catalog.forTenant("acme");
    expect(loaded).toEqual({
      ok: true,
      workflows: [
        {
          id: "wf_pipeline",
          version: 1,
          enabled: true,
          organization_ids: [],
          project_ids: [],
          api_key_ids: [],
          nodes: [
            { id: "start", kind: "model", providers: [] },
            { id: "review", kind: "model", model: "gpt-4o-mini", providers: [] },
          ],
          edges: [{ from: "start", to: "review" }],
        },
      ],
    });
  });

  it("fences by tenant — another tenant's workflow is invisible", async () => {
    await seedWorkflow("wf_pipeline", { ...GRAPH_DOCUMENT, tenant_id: "acme" });
    const catalog = d1WorkflowCatalog(DB, undefined);
    const other = await catalog.forTenant("globex");
    expect(other).toEqual({ ok: true, workflows: [] });
  });

  it("serves an un-attributed document to the PLATFORM operator only", async () => {
    await seedWorkflow("wf_pipeline", GRAPH_DOCUMENT);
    const catalog = d1WorkflowCatalog(DB, undefined);
    const operator = await catalog.forTenant(null);
    const tenant = await catalog.forTenant("acme");
    expect(workflowsOf(operator)).toHaveLength(1);
    expect(workflowsOf(tenant)).toHaveLength(0);
  });

  it("REFUSES to become empty when the read fails — 503, never an ungated pass", async () => {
    const broken = {
      prepare(): never {
        throw new Error("D1_ERROR: no such table");
      },
    } as unknown as D1Database;
    const loaded = await d1WorkflowCatalog(broken, undefined).forTenant("acme");
    expect(loaded).toEqual({ ok: false, detail: "D1_ERROR: no such table" });
  });

  it("skips an undecodable document rather than taking the table down", async () => {
    await seedWorkflow("wf_pipeline", { ...GRAPH_DOCUMENT, tenant_id: "acme" });
    await seedWorkflow("wf_broken", { id: "wf_broken", tenant_id: "acme", nodes: "not-a-list" });
    const loaded = await d1WorkflowCatalog(DB, undefined).forTenant("acme");
    expect(workflowsOf(loaded).map((w) => w.id)).toEqual(["wf_pipeline"]);
  });

  it("materialises an enabled skill package's workflows OVER the durable rows", async () => {
    await seedWorkflow("wf_pipeline", { ...GRAPH_DOCUMENT, tenant_id: "acme" });
    const packages = JSON.stringify([
      {
        id: "pkg",
        enabled: true,
        resources: {
          agent_workflows: [{ ...GRAPH_DOCUMENT, nodes: [{ id: "replaced" }], edges: [] }],
        },
      },
    ]);
    const loaded = await d1WorkflowCatalog(DB, packages).forTenant("acme");
    const workflows = workflowsOf(loaded);
    expect(workflows).toHaveLength(1);
    expect(workflows[0]?.nodes.map((n) => n.id)).toEqual(["replaced"]);
  });

  it("ignores a DISABLED skill package's workflows", () => {
    const packages = JSON.stringify([
      { id: "pkg", enabled: false, resources: { agent_workflows: [GRAPH_DOCUMENT] } },
    ]);
    expect(workflowsFromSkillPackages(packages)).toEqual([]);
  });
});

describe("decodeWorkflowDocument", () => {
  it("refuses an unrecognised node kind rather than defaulting it to `model`", () => {
    // Defaulting is the dangerous direction: it would let a mistyped `toool`
    // node dispatch model traffic, which `workflow_node_not_model` exists to
    // stop.
    expect(
      decodeWorkflowDocument({ id: "w", nodes: [{ id: "n", kind: "toool" }] }),
    ).toBeUndefined();
    expect(decodeWorkflowDocument({ id: "w", nodes: [{ id: "n", kind: "tool" }] })).toBeDefined();
  });

  it("refuses a malformed allowlist rather than filtering it down", () => {
    expect(decodeWorkflowDocument({ id: "w", nodes: [], api_key_ids: ["a", 7] })).toBeUndefined();
  });

  it("defaults version to 1 and enabled to true, matching the config schema", () => {
    const decoded = decodeWorkflowDocument({ id: "w", nodes: [] });
    expect(decoded?.version).toBe(1);
    expect(decoded?.enabled).toBe(true);
  });
});

describe("mergeWorkflowTables", () => {
  const base: WorkflowGraph = {
    id: "w",
    version: 1,
    enabled: true,
    organization_ids: [],
    project_ids: [],
    api_key_ids: [],
    nodes: [],
    edges: [],
  };

  it("upserts by (id, version) and appends a new version", () => {
    const replacement = { ...base, enabled: false };
    expect(mergeWorkflowTables([base], [replacement])).toEqual([replacement]);
    const v2 = { ...base, version: 2 };
    expect(mergeWorkflowTables([base], [v2])).toEqual([base, v2]);
  });
});

describe("the durable step ledger", () => {
  const query = {
    workflowId: "wf_pipeline",
    workflowVersion: 1,
    runId: "run_a",
    nodeId: "review",
    tenantId: "acme" as string | null,
  };

  it("starts with empty facts", async () => {
    const facts = await d1WorkflowRunHistory(DB).factsFor(query);
    expect(facts).toEqual({
      ok: true,
      facts: { modelCallCount: 0, tokensUsed: 0, nodeTokensUsed: 0 },
    });
  });

  it("counts model calls per workflow@version and tokens per node", async () => {
    const history = d1WorkflowRunHistory(DB);
    await history.recordStep({
      ...query,
      nodeId: "start",
      requestId: "r1",
      occurredAtUnix: 100,
      totalTokens: 10,
      succeeded: true,
    });
    await history.recordStep({
      ...query,
      nodeId: "review",
      requestId: "r2",
      occurredAtUnix: 200,
      totalTokens: 5,
      succeeded: true,
    });
    const loaded = await history.factsFor(query);
    expect(loaded).toEqual({
      ok: true,
      facts: {
        previousSuccessfulNodeId: "review",
        runStartedAtUnix: 100,
        modelCallCount: 2,
        tokensUsed: 15,
        nodeTokensUsed: 5,
      },
    });
  });

  it("only SUCCEEDED steps advance the graph's last node", async () => {
    const history = d1WorkflowRunHistory(DB);
    await history.recordStep({
      ...query,
      nodeId: "start",
      requestId: "r1",
      occurredAtUnix: 100,
      totalTokens: 1,
      succeeded: true,
    });
    await history.recordStep({
      ...query,
      nodeId: "review",
      requestId: "r2",
      occurredAtUnix: 200,
      totalTokens: 1,
      succeeded: false,
    });
    const loaded = await history.factsFor(query);
    expect(factsOf(loaded).previousSuccessfulNodeId).toBe("start");
    // …but it still counted against the model-call limit.
    expect(factsOf(loaded).modelCallCount).toBe(2);
  });

  it("re-recording the SAME request id updates the row instead of duplicating it", async () => {
    const history = d1WorkflowRunHistory(DB);
    const step = {
      ...query,
      requestId: "r1",
      occurredAtUnix: 100,
      totalTokens: 3,
      succeeded: false,
    };
    await history.recordStep(step);
    await history.recordStep({ ...step, totalTokens: 42, succeeded: true });
    const loaded = await history.factsFor(query);
    expect(loaded).toEqual({
      ok: true,
      facts: {
        previousSuccessfulNodeId: "review",
        runStartedAtUnix: 100,
        modelCallCount: 1,
        tokensUsed: 42,
        nodeTokensUsed: 42,
      },
    });
  });

  it("fences the run facts by tenant — a guessed run id reads nothing", async () => {
    const history = d1WorkflowRunHistory(DB);
    await history.recordStep({
      ...query,
      requestId: "r1",
      occurredAtUnix: 100,
      totalTokens: 9,
      succeeded: true,
    });
    const otherTenant = await history.factsFor({ ...query, tenantId: "globex" });
    expect(otherTenant).toEqual({
      ok: true,
      facts: { modelCallCount: 0, tokensUsed: 0, nodeTokensUsed: 0 },
    });
  });

  it("scopes the run-level facts to the RUN, while the limits span the workflow", async () => {
    const history = d1WorkflowRunHistory(DB);
    await history.recordStep({
      ...query,
      runId: "run_a",
      requestId: "r1",
      occurredAtUnix: 100,
      totalTokens: 4,
      succeeded: true,
    });
    const otherRun = await history.factsFor({ ...query, runId: "run_b" });
    const facts = factsOf(otherRun) as unknown as Record<string, unknown>;
    // A different run has no previous node and no start time …
    expect(facts.previousSuccessfulNodeId).toBeUndefined();
    expect(facts.runStartedAtUnix).toBeUndefined();
    // … but `max_model_calls` and the token budget are per WORKFLOW in Rust,
    // so those still see the earlier run's spend.
    expect(facts.modelCallCount).toBe(1);
    expect(facts.tokensUsed).toBe(4);
  });

  it("REFUSES rather than reporting an empty run when the read fails", async () => {
    const broken = {
      prepare(): never {
        throw new Error("D1_ERROR: unreachable");
      },
    } as unknown as D1Database;
    expect(await d1WorkflowRunHistory(broken).factsFor(query)).toEqual({
      ok: false,
      detail: "D1_ERROR: unreachable",
    });
  });
});

describe("the write/read loop, through the real router", () => {
  function durableHarness(): ReturnType<typeof harness> {
    const deps: InferenceDeps = {
      workflows: d1WorkflowCatalog(DB, undefined),
      workflowHistory: d1WorkflowRunHistory(DB),
      caller: () => ({ scope: { kind: "tenant", tenantId: "acme" } }),
    };
    return harness(deps);
  }

  it("a step admitted by one request is the step the NEXT request's edge gate sees", async () => {
    await seedWorkflow("wf_pipeline", { ...GRAPH_DOCUMENT, tenant_id: "acme" });
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = durableHarness();
      const headers = (nodeId: string): Record<string, string> => ({
        "x-ferrogate-workflow-id": "wf_pipeline",
        "x-ferrogate-workflow-version": "1",
        "x-ferrogate-workflow-node-id": nodeId,
        "x-ferrogate-agent-run-id": "run_live",
      });
      const body = { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] };

      // `review` has an incoming edge, so it cannot OPEN the run.
      const early = await h.post("/v1/chat/completions", body, { headers: headers("review") });
      expect(early.status).toBe(403);
      expect((await errorBody(early)).error.code).toBe("workflow_edge_not_allowed");

      // `start` opens it, and the ledger records the successful step.
      expect(
        (await h.post("/v1/chat/completions", body, { headers: headers("start") })).status,
      ).toBe(200);

      // Now — and ONLY now — `start -> review` is a legal transition.
      const late = await h.post("/v1/chat/completions", body, { headers: headers("review") });
      expect(late.status).toBe(200);

      const facts = await d1WorkflowRunHistory(DB).factsFor({
        workflowId: "wf_pipeline",
        workflowVersion: 1,
        runId: "run_live",
        nodeId: "review",
        tenantId: "acme",
      });
      expect(factsOf(facts).previousSuccessfulNodeId).toBe("review");
    } finally {
      provider.restore();
    }
  });

  it("the ledger settles the provider's REAL token usage, not the estimate", async () => {
    await seedWorkflow("wf_pipeline", { ...GRAPH_DOCUMENT, tenant_id: "acme" });
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = durableHarness();
      await h.post(
        "/v1/chat/completions",
        { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] },
        {
          headers: {
            "x-ferrogate-workflow-id": "wf_pipeline",
            "x-ferrogate-workflow-version": "1",
            "x-ferrogate-workflow-node-id": "start",
            "x-ferrogate-agent-run-id": "run_tokens",
          },
        },
      );
      const facts = await d1WorkflowRunHistory(DB).factsFor({
        workflowId: "wf_pipeline",
        workflowVersion: 1,
        runId: "run_tokens",
        nodeId: "start",
        tenantId: "acme",
      });
      // `COMPLETION.usage.total_tokens`, which is what the provider reported.
      expect(factsOf(facts).tokensUsed).toBe(6);
    } finally {
      provider.restore();
    }
  });
});

describe("the mount", () => {
  it("resolveDeps builds the D1-backed catalog and ledger from a bound CONTROL_DB", async () => {
    await seedWorkflow("wf_pipeline", { ...GRAPH_DOCUMENT, tenant_id: "acme" });
    const resolved = resolveDeps({}, env as never);
    const loaded = await resolved.workflows.forTenant("acme");
    expect(workflowsOf(loaded).map((w) => w.id)).toEqual(["wf_pipeline"]);
    // And the history is the durable one, not the inert default: a step written
    // through it is visible on the next read.
    await resolved.workflowHistory.recordStep({
      workflowId: "wf_pipeline",
      workflowVersion: 1,
      runId: "run_mount",
      nodeId: "start",
      tenantId: "acme",
      requestId: "r-mount",
      occurredAtUnix: 5,
      totalTokens: 2,
      succeeded: true,
    });
    const facts = await resolved.workflowHistory.factsFor({
      workflowId: "wf_pipeline",
      workflowVersion: 1,
      runId: "run_mount",
      nodeId: "start",
      tenantId: "acme",
    });
    expect(factsOf(facts).modelCallCount).toBe(1);
  });
});
