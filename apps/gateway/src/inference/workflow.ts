/**
 * THE WORKFLOW GRAPH GATE, MOUNTED — the ingress, the catalog and the run
 * history behind `@ferrogate/policy`'s `enforceWorkflowGraphPolicy`.
 *
 * ## The defect this closes (cutover certification finding D2, marker P41)
 *
 * Quoting it: *"`[[agent_workflows]]` is parsed and validated by
 * `packages/config` and read by NOTHING (`grep -rn
 * "agent_workflows\|agentWorkflows" apps/` returns nothing). Consequently node
 * pinning, edge transitions, iteration limits, model-call limits and the
 * workflow timeout are ALL unenforced while the config is cheerfully accepted
 * … 13 Rust refusal codes are absent."*
 *
 * `src/ratelimit/workflow.ts` had ported the run BUDGET envelope
 * (`402 workflow_budget_exceeded`), which is a different control: it caps what
 * a run may SPEND. The graph gate is what makes a workflow a graph rather than
 * a spend cap — without it a caller inside a legitimate, well-funded run can
 * invoke any node's model in any order.
 *
 * ## THE HEADER CONTRACT — decided here, and why the RUST names win
 *
 * The certification recorded a rename:
 *
 * | Rust | TypeScript before this file |
 * |---|---|
 * | `x-ferrogate-workflow-id` | same |
 * | `x-ferrogate-workflow-version` | same |
 * | `x-ferrogate-workflow-node-id` | **no reader** |
 * | `x-ferrogate-workflow-iteration` | **no reader** |
 * | run identity: `x-ferrogate-agent-run-id` | `x-ferrogate-workflow-run-id` (new, required) |
 * | `400 invalid_workflow_header` | `400 invalid_workflow_declaration` |
 *
 * **The Rust names are correct and this module implements them.** Three
 * reasons, in decreasing order of weight:
 *
 *  1. `node-id` and `iteration` are not decoration — they are the gate's
 *     INPUTS. `node-id` selects the node whose model pin, provider pin, token
 *     budget and edge position are checked; `iteration` is the value
 *     `max_iterations` is compared against. A port that drops them does not
 *     rename a header, it deletes two controls. There is no version of this
 *     gate in which they are absent, so the only question was what to call
 *     them, and the answer for a port is "what the reference calls them".
 *  2. The run identity was never workflow-specific in the reference.
 *     `enforce_ai_workflow_policy` takes `request.agent_run_id`, which
 *     `build_ai_ingress_plan` reads from `x-ferrogate-agent-run-id` — the SAME
 *     correlation id `src/assets/handlers.ts` and `apps/mcp/src/protocol.ts`
 *     already read (#305/#522). Minting a second, workflow-only run id splits
 *     one correlation chain into two and makes "which model calls belong to
 *     this agent run" unanswerable across surfaces.
 *  3. A client written against the reference gateway must keep working. Under
 *     the TypeScript-only names such a client was refused `400` outright, which
 *     is the loudest possible form of the divergence.
 *
 * **The one thing that is NOT reverted** is the existence of
 * `x-ferrogate-workflow-run-id`. It is the primary key of the durable
 * `workflow_run_budgets` row (`workflowRunBudgetId(workflowId, version, runId)`)
 * and `src/ratelimit/` is shipped, tested and outside this slice. So this
 * module accepts EITHER header as the run identity, preferring the Rust one:
 * see {@link workflowRunIdFrom}. A client sending only the Rust header is
 * gated; a client sending only the TypeScript one is gated identically; a
 * client sending both must agree with itself or it is refused, because two
 * different run ids on one request means the graph gate and the budget gate
 * would be measuring two different runs.
 *
 * ### The residue — CLOSED by the wave-17 integrate step
 *
 * `src/ratelimit/workflow.ts::workflowDeclarationFrom` refused a PARTIAL
 * declaration with `400 invalid_workflow_declaration`, and it counted
 * `x-ferrogate-workflow-run-id` among the three headers that must appear
 * together. A pure Rust-shaped client (`-id` + `-version` + `-node-id` +
 * `-agent-run-id`, no `-run-id`) therefore met that middleware FIRST and was
 * answered `400 invalid_workflow_declaration` before it ever reached this gate:
 * **this gate was unreachable on the deployed Worker for exactly the clients it
 * was ported for.** No suite saw it, because every workflow test built its own
 * router and none ran the rate-limit middleware.
 *
 * The integrate step applied the recipe recorded here verbatim — the run-id
 * alias in `workflowDeclarationFrom`, whose `workflowId === ""` guard is
 * LOAD-BEARING (a plain request carrying `x-ferrogate-agent-run-id` purely for
 * correlation, assets/MCP #305/#522, must stay `absent`; an unguarded alias
 * would turn every one of them into a partial declaration, i.e. a 400) — and
 * added the SELF-driven gate `test/inference/workflow-mount.test.ts`. All nine
 * of its cases answered `400 invalid_workflow_declaration` before the alias
 * landed. Both controls now measure ONE run, and every existing assertion in
 * `test/ratelimit/guards.test.ts` is still true (re-run under the mutation:
 * green either way).
 *
 * A SECOND, larger change is still needed for full reference shape: Rust's
 * `x-ferrogate-workflow-version` is `Option<u32>`, while the budget declaration
 * requires it because `workflowRunBudgetId(workflowId, version, runId)` is a
 * primary key. A Rust client that omits the version is therefore still refused.
 * Deciding that means deciding what version an unversioned run's budget row is
 * keyed by, which is a budget-slice decision, not this one's.
 *
 * ## Where the workflow TABLE comes from
 *
 * Two sources, composed exactly as the reference composes them:
 *
 *  1. **`control_plane_resources` of kind `agent-workflows` in `CONTROL_DB`** —
 *     the documents `apps/control-plane`'s `admin_agent_workflow` group
 *     (`GET/POST/PUT/PATCH/DELETE /admin/v1/agent-workflows`) already writes.
 *     This is the same "the operator surface that ought to feed it already
 *     wrote into a table this Worker already binds" shape that
 *     `apps/mcp/src/catalog.ts` used to close the MCP server-catalog gap, and
 *     it needs no new binding and no new var.
 *  2. **`GATEWAY_SKILL_PACKAGES`** — a skill package OWNS the workflows in its
 *     `resources.agent_workflows`, and Rust's
 *     `Config::materialize_skill_package_resources` re-projects them over the
 *     top-level table (`packages/config/src/validate/plugins.ts` ports it).
 *     Enabled packages' workflows therefore UPSERT over the durable rows by
 *     `(id, version)`, which is that function's own precedence.
 *
 * A deployment with neither configured has an empty table, and an empty table
 * gates nothing — which is precisely the pre-existing behaviour for a caller
 * that declares no workflow, and a refusal (`workflow_not_found`) for a caller
 * that declares one. That asymmetry is deliberate and is Rust's: naming a
 * workflow the gateway cannot see is an error, not a licence.
 *
 * ## Where the RUN HISTORY comes from
 *
 * Four facts (`WorkflowRunFacts`) that Rust derives from `AppState`'s request
 * logs, audit events and metering events. This Worker has none of those three
 * in a form keyed by workflow, so the gate keeps its OWN durable step ledger:
 * one `control_plane_resources` document of kind `workflow-run-steps` per
 * admitted model call, written after the step is admitted and updated with the
 * settled token usage when the response lands. Same table, same database, same
 * pattern as `apps/mcp/src/approvals.ts` (which keeps a runtime queue there,
 * not config).
 *
 * The four readers are then the direct analogues of the Rust helpers, and the
 * mapping is written on {@link D1WorkflowRunHistory}. The important property is
 * that the ledger is written by the SAME code path that reads it, so there is
 * no "durable but nobody writes it" gap of the kind this project keeps finding.
 *
 * ## Failure direction
 *
 * A catalog read that fails answers `503 workflow_catalog_unavailable` rather
 * than an empty table. This is the opposite of `apps/mcp`'s catalog, and on
 * purpose: there, an unreadable table removes upstreams (fail-closed); here, an
 * unreadable table would remove REFUSALS. A history read that fails answers
 * `503 workflow_history_unavailable` for the same reason — losing the run's
 * last node silently converts every step into a legal run-opening step.
 */
import {
  type WorkflowGraph,
  type WorkflowGraphNode,
  type WorkflowGraphRejection,
  type WorkflowNodeKind,
  type WorkflowProviderConstraint,
  type WorkflowRunFacts,
  applyWorkflowProviderConstraint,
  enforceWorkflowGraphPolicy,
} from "@ferrogate/policy";
import { DurableObjectTenantDatabaseRouter, type TenantDatabaseRouter } from "@ferrogate/storage";
import { reject } from "./errors.js";
import type { InferenceRejection } from "./errors.js";
import type { Caller } from "./ports.js";

// ---------------------------------------------------------------------------
// Headers — Rust's names
// ---------------------------------------------------------------------------

/** `chat.rs::WORKFLOW_ID_HEADER`. */
export const WORKFLOW_ID_HEADER = "x-ferrogate-workflow-id";
/** `chat.rs::WORKFLOW_VERSION_HEADER`. */
export const WORKFLOW_VERSION_HEADER = "x-ferrogate-workflow-version";
/** `chat.rs::WORKFLOW_NODE_ID_HEADER` — had NO reader before this file. */
export const WORKFLOW_NODE_ID_HEADER = "x-ferrogate-workflow-node-id";
/** `chat.rs::WORKFLOW_ITERATION_HEADER` — had NO reader before this file. */
export const WORKFLOW_ITERATION_HEADER = "x-ferrogate-workflow-iteration";
/** `chat.rs::AGENT_RUN_ID_HEADER` — the reference's run identity. */
export const AGENT_RUN_ID_HEADER = "x-ferrogate-agent-run-id";
/** The TypeScript-only run key `src/ratelimit/workflow.ts` shipped; an ALIAS. */
export const WORKFLOW_RUN_ID_HEADER = "x-ferrogate-workflow-run-id";

/** `chat.rs` answers this for every malformed workflow header. */
export const INVALID_WORKFLOW_HEADER_CODE = "invalid_workflow_header";

/** The parsed workflow declaration, or the reason it is malformed. */
export type WorkflowHeaderResult =
  | { readonly kind: "absent" }
  | {
      readonly kind: "declared";
      readonly workflowId: string;
      readonly workflowVersion: number | undefined;
      readonly workflowNodeId: string | undefined;
      readonly workflowIteration: number | undefined;
    }
  | { readonly kind: "invalid"; readonly detail: string };

/**
 * `requested_optional_id_header` — trimmed, and a header PRESENT but blank is
 * an error rather than "absent". Rust's own rule; it stops a client silently
 * un-gating itself by sending an empty string.
 */
function optionalIdHeader(headers: Headers, name: string): string | undefined | null {
  const raw = headers.get(name);
  if (raw === null) return undefined;
  const trimmed = raw.trim();
  return trimmed === "" ? null : trimmed;
}

/**
 * `requested_optional_u32_header` — an unsigned integer, and NOT zero.
 *
 * Rust rejects `0` explicitly (`if parsed == 0 { return Err(...) }`) for both
 * the version and the iteration, so `@0` and iteration 0 are wire errors rather
 * than sentinels. `Number.parseInt` would accept `"3abc"`, so the whole string
 * is required to be digits.
 */
function optionalU32Header(
  headers: Headers,
  name: string,
): { ok: true; value: number | undefined } | { ok: false; detail: string } {
  const raw = headers.get(name);
  if (raw === null) return { ok: true, value: undefined };
  const trimmed = raw.trim();
  if (trimmed === "") return { ok: false, detail: `${name} must not be blank` };
  if (!/^\d+$/.test(trimmed) || !Number.isSafeInteger(Number(trimmed))) {
    return { ok: false, detail: `${name} must be an unsigned integer` };
  }
  const parsed = Number(trimmed);
  if (parsed === 0) return { ok: false, detail: `${name} must be greater than zero` };
  return { ok: true, value: parsed };
}

/**
 * The run identity, preferring Rust's header.
 *
 * `null` = the two headers are present and DISAGREE, which is refused: the
 * graph gate and the budget envelope would then be measuring different runs,
 * and the caller would be inside one run for spend and another for ordering.
 */
export function workflowRunIdFrom(headers: Headers): string | undefined | null {
  const agentRun = headers.get(AGENT_RUN_ID_HEADER)?.trim() ?? "";
  const workflowRun = headers.get(WORKFLOW_RUN_ID_HEADER)?.trim() ?? "";
  if (agentRun !== "" && workflowRun !== "" && agentRun !== workflowRun) return null;
  if (agentRun !== "") return agentRun;
  if (workflowRun !== "") return workflowRun;
  return undefined;
}

/** `requested_agent_run_id`'s charset and length rule. */
const RUN_ID_CHARSET = /^[A-Za-z0-9_.:-]+$/;
const RUN_ID_MAX_LENGTH = 128;

/**
 * `chat.rs::requested_agent_run_id` — the run id, DEFAULTED to `run-{requestId}`
 * when the caller supplies none.
 *
 * The default is not cosmetic and getting it wrong is a real hole. Rust gives an
 * un-correlated request its OWN run, so the edge gate sees no previous node and
 * only an ENTRY node of the graph may run. Leaving the run id absent instead
 * would put every such request in one shared bucket, where an unrelated
 * caller's last node would license a transition it has nothing to do with —
 * looser, and non-deterministically so.
 *
 * `null` = the supplied id is malformed (Rust `400 invalid_agent_run_id_header`).
 */
export function resolveWorkflowRunId(headers: Headers, requestId: string): string | null {
  const supplied = workflowRunIdFrom(headers);
  if (supplied === null) return null;
  if (supplied === undefined) return `run-${requestId}`;
  if (supplied.length > RUN_ID_MAX_LENGTH || !RUN_ID_CHARSET.test(supplied)) return null;
  return supplied;
}

/**
 * `build_ai_ingress_plan`'s four `requested_*_header` calls plus the
 * cross-header rule that follows them.
 *
 * The cross-header rule is the reason this is one function rather than four:
 * `workflow-id` absent while `version` / `node-id` / `iteration` is present is
 * an error, because such a request LOOKS gated to whoever wrote the client and
 * is not.
 */
export function workflowHeadersFrom(headers: Headers): WorkflowHeaderResult {
  const workflowId = optionalIdHeader(headers, WORKFLOW_ID_HEADER);
  if (workflowId === null) {
    return { kind: "invalid", detail: `${WORKFLOW_ID_HEADER} must not be blank` };
  }
  const version = optionalU32Header(headers, WORKFLOW_VERSION_HEADER);
  if (!version.ok) return { kind: "invalid", detail: version.detail };
  const nodeId = optionalIdHeader(headers, WORKFLOW_NODE_ID_HEADER);
  if (nodeId === null) {
    return { kind: "invalid", detail: `${WORKFLOW_NODE_ID_HEADER} must not be blank` };
  }
  const iteration = optionalU32Header(headers, WORKFLOW_ITERATION_HEADER);
  if (!iteration.ok) return { kind: "invalid", detail: iteration.detail };

  if (
    workflowId === undefined &&
    (version.value !== undefined || nodeId !== undefined || iteration.value !== undefined)
  ) {
    return {
      kind: "invalid",
      detail:
        `${WORKFLOW_ID_HEADER} is required when workflow version, node, or iteration ` +
        "headers are set",
    };
  }
  if (workflowId === undefined) return { kind: "absent" };

  return {
    kind: "declared",
    workflowId,
    workflowVersion: version.value,
    workflowNodeId: nodeId,
    workflowIteration: iteration.value,
  };
}

// ---------------------------------------------------------------------------
// The catalog seam
// ---------------------------------------------------------------------------

/** What a catalog read produced. */
export type WorkflowCatalogResult =
  | { readonly ok: true; readonly workflows: readonly WorkflowGraph[] }
  | { readonly ok: false; readonly detail: string };

/**
 * The seam the gate codes against.
 *
 * `tenantId` is `null` for a platform-operator caller, which selects the
 * documents that carry no `tenant_id` — the operator's own workflows. A
 * tenant-scoped caller sees only its own. This is the same fence
 * `apps/mcp/src/catalog.ts` applies and for the same reason: a workflow
 * document is a policy, and one tenant must not be gated by (or able to name)
 * another tenant's.
 */
export interface WorkflowCatalogSource {
  forTenant(tenantId: string | null): Promise<WorkflowCatalogResult | readonly WorkflowGraph[]>;
}

/** A deployment that has configured no workflows at all. */
export const NO_WORKFLOWS: WorkflowCatalogSource = {
  async forTenant(): Promise<WorkflowCatalogResult> {
    return { ok: true, workflows: [] };
  },
};

/** Bindings this module reads. */
export interface WorkflowGateBindings {
  /** The CONTROL database: `control_plane_resources`. */
  readonly CONTROL_DB?: D1Database | undefined;
  /** The object namespace for tenant-private workflow documents. */
  readonly TENANT_DATA?: import("@ferrogate/storage/durable-objects").TenantDataNamespace;
  /** `[[skill_packages]]`, whose `resources.agent_workflows` upsert over it. */
  readonly GATEWAY_SKILL_PACKAGES?: string | undefined;
}

/** `control_plane_resources.resource_kind` `admin_agent_workflow` writes. */
export const AGENT_WORKFLOW_COLLECTION = "agent-workflows";
/** `control_plane_resources.resource_kind` this module's step ledger uses. */
export const WORKFLOW_RUN_STEP_COLLECTION = "workflow-run-steps";
/** The generic document table, in the CONTROL database. */
export const RESOURCE_TABLE = "control_plane_resources";
/** The object-local document table for tenant-private resource kinds. */
export const TENANT_RESOURCE_TABLE = "tenant_resources";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringList(value: unknown): readonly string[] | undefined {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return undefined;
  const out: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") return undefined;
    out.push(entry);
  }
  return out;
}

function positiveInt(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

const NODE_KINDS: readonly WorkflowNodeKind[] = ["model", "tool", "router", "human", "checkpoint"];

/**
 * Decode one admin document into a {@link WorkflowGraph}.
 *
 * `undefined` REFUSES the document, and every refusal is in the safe direction
 * for a gate: an undecodable workflow is one the caller cannot name, so a step
 * declaring it is `workflow_not_found` (400) rather than an ungated 200.
 *
 * An unrecognised node `kind` refuses the whole document rather than falling
 * back to `model`. Defaulting would be the dangerous direction: it would let a
 * `tool`-ish node typed `toool` dispatch model traffic, which is exactly what
 * `workflow_node_not_model` exists to stop.
 */
export function decodeWorkflowDocument(value: unknown): WorkflowGraph | undefined {
  if (!isObject(value)) return undefined;
  const id = value["id"];
  if (typeof id !== "string" || id === "") return undefined;

  const version = value["version"] === undefined ? 1 : positiveInt(value["version"]);
  if (version === undefined) return undefined;

  const enabled = value["enabled"] === undefined ? true : value["enabled"];
  if (typeof enabled !== "boolean") return undefined;

  const organizationIds = stringList(value["organization_ids"]);
  const projectIds = stringList(value["project_ids"]);
  const apiKeyIds = stringList(value["api_key_ids"]);
  if (organizationIds === undefined || projectIds === undefined || apiKeyIds === undefined) {
    return undefined;
  }

  const rawNodes = value["nodes"];
  if (!Array.isArray(rawNodes)) return undefined;
  const nodes: WorkflowGraphNode[] = [];
  for (const raw of rawNodes) {
    if (!isObject(raw)) return undefined;
    const nodeId = raw["id"];
    if (typeof nodeId !== "string" || nodeId === "") return undefined;
    const kind = raw["kind"] === undefined ? "model" : raw["kind"];
    if (typeof kind !== "string" || !NODE_KINDS.includes(kind as WorkflowNodeKind)) {
      return undefined;
    }
    const providers = stringList(raw["providers"]);
    if (providers === undefined) return undefined;
    const model = raw["model"];
    if (model !== undefined && model !== null && typeof model !== "string") return undefined;
    const tool = raw["tool"];
    if (tool !== undefined && tool !== null && typeof tool !== "string") return undefined;
    nodes.push({
      id: nodeId,
      kind: kind as WorkflowNodeKind,
      ...(typeof model === "string" ? { model } : {}),
      providers,
      ...(typeof tool === "string" ? { tool } : {}),
      ...(raw["max_iterations"] === undefined || raw["max_iterations"] === null
        ? {}
        : { max_iterations: positiveInt(raw["max_iterations"]) }),
      ...(raw["token_budget"] === undefined || raw["token_budget"] === null
        ? {}
        : { token_budget: positiveInt(raw["token_budget"]) }),
    });
  }

  const rawEdges = value["edges"];
  if (rawEdges !== undefined && rawEdges !== null && !Array.isArray(rawEdges)) return undefined;
  const edges: { from: string; to: string }[] = [];
  for (const raw of (rawEdges as unknown[] | undefined) ?? []) {
    if (!isObject(raw)) return undefined;
    const from = raw["from"];
    const to = raw["to"];
    if (typeof from !== "string" || typeof to !== "string") return undefined;
    edges.push({ from, to });
  }

  const optional = (key: string): number | undefined =>
    value[key] === undefined || value[key] === null ? undefined : positiveInt(value[key]);

  return {
    id,
    version,
    enabled,
    organization_ids: organizationIds,
    project_ids: projectIds,
    api_key_ids: apiKeyIds,
    nodes,
    edges,
    ...(optional("max_model_calls") === undefined
      ? {}
      : { max_model_calls: optional("max_model_calls") }),
    ...(optional("max_iterations") === undefined
      ? {}
      : { max_iterations: optional("max_iterations") }),
    ...(optional("timeout_millis") === undefined
      ? {}
      : { timeout_millis: optional("timeout_millis") }),
    ...(optional("token_budget") === undefined ? {} : { token_budget: optional("token_budget") }),
  };
}

/**
 * `Config::materialize_skill_package_resources` — an ENABLED skill package's
 * workflows upsert over the base table by `(id, version)`.
 *
 * Exported so the precedence is assertable directly; a package that ships a
 * workflow the operator has also written must WIN, because that is the rule the
 * reference applies when it materialises the merged config, and disagreeing
 * would mean the gateway gates against a graph no one can see in one place.
 */
export function mergeWorkflowTables(
  base: readonly WorkflowGraph[],
  fromPackages: readonly WorkflowGraph[],
): readonly WorkflowGraph[] {
  const merged = [...base];
  for (const workflow of fromPackages) {
    const index = merged.findIndex(
      (existing) => existing.id === workflow.id && existing.version === workflow.version,
    );
    if (index === -1) merged.push(workflow);
    else merged[index] = workflow;
  }
  return merged;
}

/**
 * The workflows an ENABLED skill package owns, out of `GATEWAY_SKILL_PACKAGES`.
 *
 * Parsed defensively rather than through `skillPackageSchema`: this reader only
 * needs `enabled` and `resources.agent_workflows`, and a package whose OTHER
 * members fail a strict parse must not take its workflows down with it — that
 * would silently remove refusals.
 */
export function workflowsFromSkillPackages(raw: string | undefined): readonly WorkflowGraph[] {
  if (raw === undefined || raw.trim() === "") return [];
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(decoded)) return [];
  const out: WorkflowGraph[] = [];
  for (const entry of decoded) {
    if (!isObject(entry)) continue;
    if (entry["enabled"] === false) continue;
    const resources = entry["resources"];
    if (!isObject(resources)) continue;
    const workflows = resources["agent_workflows"];
    if (!Array.isArray(workflows)) continue;
    for (const document of workflows) {
      const decodedWorkflow = decodeWorkflowDocument(document);
      if (decodedWorkflow !== undefined) out.push(decodedWorkflow);
    }
  }
  return out;
}

/**
 * The durable catalog: admin documents from `CONTROL_DB`, with the skill
 * packages' own workflows materialised over them.
 *
 * A read failure returns `{ ok: false }`, which the gate turns into
 * `503 workflow_catalog_unavailable`. See the failure-direction note at the top
 * of this file: an empty table here would DELETE refusals.
 */
export function d1WorkflowCatalog(
  db: D1Database,
  skillPackagesVar: string | undefined,
  router?: TenantDatabaseRouter,
): WorkflowCatalogSource {
  const decodeRows = (
    rows: readonly { document_json: string }[],
    tenantId?: string,
  ): WorkflowGraph[] => {
    const workflows: WorkflowGraph[] = [];
    for (const row of rows) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(row.document_json);
      } catch {
        continue;
      }
      if (tenantId !== undefined && (!isObject(parsed) || parsed["tenant_id"] !== tenantId)) {
        continue;
      }
      const decoded = decodeWorkflowDocument(parsed);
      if (decoded !== undefined) workflows.push(decoded);
    }
    return workflows;
  };

  const readControl = async (tenantId: string): Promise<WorkflowCatalogResult> => {
    let rows: { results: Array<{ document_json: string }> };
    try {
      rows = await db
        .prepare(
          `SELECT document_json FROM ${RESOURCE_TABLE}
             WHERE resource_kind = ?
               AND json_extract(document_json, '$.tenant_id') = ?
             ORDER BY resource_id`,
        )
        .bind(AGENT_WORKFLOW_COLLECTION, tenantId)
        .all<{ document_json: string }>();
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return { ok: false, detail };
    }
    return { ok: true, workflows: decodeRows(rows.results) };
  };

  const readControlProjection = async (): Promise<WorkflowCatalogResult> => {
    let rows: { results: Array<{ document_json: string }> };
    try {
      rows = await db
        .prepare(
          `SELECT document_json FROM ${RESOURCE_TABLE}
             WHERE resource_kind = ?
               AND json_extract(document_json, '$.tenant_id') IS NULL
             ORDER BY resource_id`,
        )
        .bind(AGENT_WORKFLOW_COLLECTION)
        .all<{ document_json: string }>();
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return { ok: false, detail };
    }
    return { ok: true, workflows: decodeRows(rows.results) };
  };

  const readObject = async (tenantId: string): Promise<WorkflowGraph[]> => {
    const handle = await (router as TenantDatabaseRouter).forTenant(tenantId);
    const rows = await handle.db
      .prepare(
        `SELECT document_json FROM ${TENANT_RESOURCE_TABLE}
           WHERE resource_kind = ?
           ORDER BY resource_id`,
      )
      .bind(AGENT_WORKFLOW_COLLECTION)
      .all<{ document_json: string }>();
    return decodeRows(rows.results, tenantId);
  };

  return {
    async forTenant(tenantId: string | null): Promise<WorkflowCatalogResult> {
      if (router !== undefined) {
        try {
          if (tenantId === null || tenantId.trim() === "") {
            const objectRows: WorkflowGraph[] = [];
            for (const provisionedTenant of await router.provisionedTenants()) {
              objectRows.push(...(await readObject(provisionedTenant)));
            }
            const projection = await readControlProjection();
            if (!projection.ok) return projection;
            return {
              ok: true,
              workflows: mergeWorkflowTables(
                mergeWorkflowTables(projection.workflows, objectRows),
                workflowsFromSkillPackages(skillPackagesVar),
              ),
            };
          }
          const objectRows = await readObject(tenantId);
          return {
            ok: true,
            workflows: mergeWorkflowTables(
              objectRows,
              workflowsFromSkillPackages(skillPackagesVar),
            ),
          };
        } catch (error) {
          const detail = error instanceof Error ? error.message : String(error);
          return { ok: false, detail };
        }
      }

      let base: readonly WorkflowGraph[];
      if (tenantId === null) {
        let rows: { results: Array<{ document_json: string }> };
        try {
          rows = await db
            .prepare(
              `SELECT document_json FROM ${RESOURCE_TABLE}
                 WHERE resource_kind = ?
                   AND json_extract(document_json, '$.tenant_id') IS NULL
                 ORDER BY resource_id`,
            )
            .bind(AGENT_WORKFLOW_COLLECTION)
            .all<{ document_json: string }>();
        } catch (error) {
          const detail = error instanceof Error ? error.message : String(error);
          return { ok: false, detail };
        }
        base = decodeRows(rows.results);
      } else {
        const control = await readControl(tenantId);
        if (!control.ok) return control;
        base = control.workflows;
      }
      return {
        ok: true,
        workflows: mergeWorkflowTables(base, workflowsFromSkillPackages(skillPackagesVar)),
      };
    },
  };
}

/**
 * The catalog for a Worker `env`.
 *
 * With no `CONTROL_DB` the skill-package table is still read, so a deployment
 * that configures workflows through `GATEWAY_SKILL_PACKAGES` alone is gated
 * with no database at all.
 */
export function workflowCatalogFromEnv(env: WorkflowGateBindings): WorkflowCatalogSource {
  const db = env.CONTROL_DB;
  const skillPackages = env.GATEWAY_SKILL_PACKAGES;
  if (db === undefined || typeof db.prepare !== "function") {
    const workflows = workflowsFromSkillPackages(skillPackages);
    return {
      async forTenant(): Promise<WorkflowCatalogResult> {
        return { ok: true, workflows };
      },
    };
  }
  const router =
    env.TENANT_DATA === undefined
      ? undefined
      : new DurableObjectTenantDatabaseRouter(env.TENANT_DATA, db);
  return d1WorkflowCatalog(db, skillPackages, router);
}

// ---------------------------------------------------------------------------
// The run-history seam
// ---------------------------------------------------------------------------

/** Which run's facts to compute. */
export interface WorkflowRunQuery {
  readonly workflowId: string;
  readonly workflowVersion: number;
  readonly runId: string;
  readonly nodeId: string;
  readonly tenantId: string | null;
}

/** One admitted step, as the ledger records it. */
export interface WorkflowStepRecord extends WorkflowRunQuery {
  readonly requestId: string;
  readonly occurredAtUnix: number;
  /** Settled total tokens; the pre-dispatch estimate until the response lands. */
  readonly totalTokens: number;
  /** `false` until the step's response is known to be a success. */
  readonly succeeded: boolean;
}

export type WorkflowFactsResult =
  | { readonly ok: true; readonly facts: WorkflowRunFacts }
  | { readonly ok: false; readonly detail: string };

/** The seam the gate codes against for the four run facts. */
export interface WorkflowRunHistory {
  factsFor(query: WorkflowRunQuery): Promise<WorkflowFactsResult | WorkflowRunFacts>;
  recordStep(step: WorkflowStepRecord): Promise<void>;
}

/** Everything is the first step of a fresh run, and nothing is recorded. */
export const NO_WORKFLOW_HISTORY: WorkflowRunHistory = {
  async factsFor(): Promise<WorkflowFactsResult> {
    return {
      ok: true,
      facts: { modelCallCount: 0, tokensUsed: 0, nodeTokensUsed: 0 },
    };
  },
  async recordStep(): Promise<void> {
    // No durable store bound; the counters cannot be kept.
  },
};

interface StepDocument {
  readonly workflow_id: string;
  readonly workflow_version: number;
  readonly run_id: string;
  readonly node_id: string;
  readonly tenant_id: string | null;
  readonly request_id: string;
  readonly occurred_at_unix: number;
  readonly total_tokens: number;
  readonly succeeded: boolean;
}

/** `${workflowId}@${version}/${runId}/${requestId}` — stable and collision-free. */
export function workflowStepDocumentId(step: WorkflowStepRecord): string {
  return `${step.workflowId}@${step.workflowVersion}/${step.runId}/${step.requestId}`;
}

/**
 * The durable step ledger, on `control_plane_resources` in the CONTROL database.
 *
 * The four readers, and the Rust helper each one replaces:
 *
 * | fact | derived as | Rust |
 * |---|---|---|
 * | `previousSuccessfulNodeId` | the `node_id` of the newest SUCCEEDED row of this run | `workflow_run_last_successful_node_id` |
 * | `runStartedAtUnix` | the smallest `occurred_at_unix` of this run | `workflow_run_started_at` |
 * | `modelCallCount` | rows for this `workflow@version` | `workflow_model_call_count` |
 * | `tokensUsed` | `sum(total_tokens)` for this `workflow@version` | `workflow_token_usage(.., None)` |
 * | `nodeTokensUsed` | the same, narrowed to `node_id` | `workflow_token_usage(.., Some(node))` |
 *
 * Two properties are load-bearing and are the reference's:
 *
 *  - the run-scoped facts are filtered by `tenant_id` as a BOUND parameter, so
 *    a client-supplied run id cannot pull another tenant's node history into
 *    this tenant's edge gate (Rust's `tenant_filter()`, issues #185/#228); and
 *  - `previousSuccessfulNodeId` counts only SUCCEEDED steps, so a step that was
 *    admitted and then failed upstream does not advance the graph.
 */
export function d1WorkflowRunHistory(
  db: D1Database,
  router?: TenantDatabaseRouter,
): WorkflowRunHistory {
  type Row = { resource_id: string; document_json: string };

  const readRows = async (
    source: D1Database,
    table: string,
    query: WorkflowRunQuery,
    controlScope: boolean,
  ): Promise<readonly Row[]> => {
    const scope = controlScope
      ? query.tenantId === null
        ? { sql: "AND json_extract(document_json, '$.tenant_id') IS NULL", params: [] }
        : { sql: "AND json_extract(document_json, '$.tenant_id') = ?", params: [query.tenantId] }
      : { sql: "", params: [] };
    const rows = await source
      .prepare(
        `SELECT resource_id, document_json FROM ${table}
           WHERE resource_kind = ?
             AND json_extract(document_json, '$.workflow_id') = ?
             AND json_extract(document_json, '$.workflow_version') = ?
             ${scope.sql}
           ORDER BY resource_id`,
      )
      .bind(WORKFLOW_RUN_STEP_COLLECTION, query.workflowId, query.workflowVersion, ...scope.params)
      .all<Row>();
    return rows.results;
  };

  const factsFrom = (rows: readonly Row[], query: WorkflowRunQuery): WorkflowFactsResult => {
    let previousSuccessfulNodeId: string | undefined;
    let previousAt = -1;
    let runStartedAtUnix: number | undefined;
    let modelCallCount = 0;
    let tokensUsed = 0;
    let nodeTokensUsed = 0;
    for (const row of rows) {
      let document: StepDocument;
      try {
        document = JSON.parse(row.document_json) as StepDocument;
      } catch {
        continue;
      }
      if (query.tenantId !== null && document.tenant_id !== query.tenantId) continue;
      modelCallCount += 1;
      tokensUsed += document.total_tokens;
      if (document.node_id === query.nodeId) nodeTokensUsed += document.total_tokens;
      if (document.run_id !== query.runId) continue;
      if (runStartedAtUnix === undefined || document.occurred_at_unix < runStartedAtUnix) {
        runStartedAtUnix = document.occurred_at_unix;
      }
      if (document.succeeded && document.occurred_at_unix >= previousAt) {
        previousAt = document.occurred_at_unix;
        previousSuccessfulNodeId = document.node_id;
      }
    }
    return {
      ok: true,
      facts: {
        ...(previousSuccessfulNodeId === undefined ? {} : { previousSuccessfulNodeId }),
        ...(runStartedAtUnix === undefined ? {} : { runStartedAtUnix }),
        modelCallCount,
        tokensUsed,
        nodeTokensUsed,
      },
    };
  };

  return {
    async factsFor(query: WorkflowRunQuery): Promise<WorkflowFactsResult> {
      try {
        let rows: readonly Row[];
        if (router !== undefined) {
          if (query.tenantId === null || query.tenantId.trim() === "") {
            const objectRows: Row[] = [];
            for (const provisionedTenant of await router.provisionedTenants()) {
              const handle = await router.forTenant(provisionedTenant);
              objectRows.push(...(await readRows(handle.db, TENANT_RESOURCE_TABLE, query, false)));
            }
            const projectionRows = await readRows(db, RESOURCE_TABLE, query, true);
            const byId = new Map<string, Row>();
            for (const row of [...projectionRows, ...objectRows]) {
              if (!byId.has(row.resource_id)) byId.set(row.resource_id, row);
            }
            rows = [...byId.values()];
          } else {
            const handle = await router.forTenant(query.tenantId);
            rows = await readRows(handle.db, TENANT_RESOURCE_TABLE, query, false);
          }
        } else {
          rows = await readRows(db, RESOURCE_TABLE, query, true);
        }
        return factsFrom(rows, query);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { ok: false, detail };
      }
    },

    async recordStep(step: WorkflowStepRecord): Promise<void> {
      const document: StepDocument = {
        workflow_id: step.workflowId,
        workflow_version: step.workflowVersion,
        run_id: step.runId,
        node_id: step.nodeId,
        tenant_id: step.tenantId,
        request_id: step.requestId,
        occurred_at_unix: step.occurredAtUnix,
        total_tokens: step.totalTokens,
        succeeded: step.succeeded,
      };
      try {
        let target = db;
        let table = RESOURCE_TABLE;
        if (router !== undefined) {
          if (step.tenantId === null || step.tenantId.trim() === "") {
            console.warn("gateway: tenant workflow step missing tenant destination");
            return;
          }
          target = (await router.forTenant(step.tenantId)).db;
          table = TENANT_RESOURCE_TABLE;
        }
        // `DO UPDATE`, not `DO NOTHING`: admission writes an estimate and the
        // response later rewrites the same row with settled usage.
        await target
          .prepare(
            `INSERT INTO ${table}
               (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
             VALUES (?, ?, ?, 1, ?, ?)
             ON CONFLICT (resource_kind, resource_id)
               DO UPDATE SET document_json = excluded.document_json,
                             revision = ${table}.revision + 1,
                             updated_at_unix = excluded.updated_at_unix`,
          )
          .bind(
            WORKFLOW_RUN_STEP_COLLECTION,
            workflowStepDocumentId(step),
            JSON.stringify(document),
            step.occurredAtUnix,
            step.occurredAtUnix,
          )
          .run();
      } catch (error) {
        // A ledger write that fails must not fail a request already admitted by
        // the gate; it is still logged so the missing counter is observable.
        console.warn("gateway: workflow step ledger write failed", error);
      }
    },
  };
}

/** The history for a Worker `env`; {@link NO_WORKFLOW_HISTORY} with no `CONTROL_DB`. */
export function workflowHistoryFromEnv(env: WorkflowGateBindings): WorkflowRunHistory {
  const db = env.CONTROL_DB;
  return db === undefined || typeof db.prepare !== "function"
    ? NO_WORKFLOW_HISTORY
    : d1WorkflowRunHistory(
        db,
        env.TENANT_DATA === undefined
          ? undefined
          : new DurableObjectTenantDatabaseRouter(env.TENANT_DATA, db),
      );
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/** What the gate decided about a request. */
export type WorkflowGateOutcome =
  | { readonly kind: "ungated" }
  | {
      readonly kind: "admitted";
      readonly constraint: WorkflowProviderConstraint | null;
      readonly step: WorkflowRunQuery;
    }
  | { readonly kind: "refused"; readonly rejection: InferenceRejection };

/** `AuthContext` → the three facets `can_use_workflow` reads. */
export function workflowCallerFrom(caller: Caller): {
  apiKeyId?: string | undefined;
  organizationId?: string | undefined;
  projectId?: string | undefined;
} {
  return {
    ...(caller.apiKeyId === undefined ? {} : { apiKeyId: caller.apiKeyId }),
    ...(caller.scope.kind === "tenant" ? { organizationId: caller.scope.tenantId } : {}),
    ...(caller.projectId === undefined ? {} : { projectId: caller.projectId }),
  };
}

function rejectionOf(rejection: WorkflowGraphRejection): InferenceRejection {
  return reject(rejection.status, rejection.code, rejection.message);
}

/** Everything the gate needs from the request. */
export interface WorkflowGateRequest {
  readonly headers: Headers;
  /** `ProxyContext.request_id` — the run id's fallback source. */
  readonly requestId: string;
  readonly caller: Caller;
  readonly logicalModel: string;
  readonly estimatedTotalTokens: number;
  readonly nowUnixSeconds: number;
}

/**
 * Run the ladder for one inference request.
 *
 * Returns `ungated` for a request that declares no workflow — the overwhelming
 * majority — after ONE header read and no I/O at all. The catalog and the
 * history are touched only once a workflow has actually been declared, so this
 * gate costs a non-workflow request nothing.
 */
export async function enforceWorkflowGate(
  catalog: WorkflowCatalogSource,
  history: WorkflowRunHistory,
  request: WorkflowGateRequest,
): Promise<WorkflowGateOutcome> {
  const declaration = workflowHeadersFrom(request.headers);
  if (declaration.kind === "absent") return { kind: "ungated" };
  if (declaration.kind === "invalid") {
    return {
      kind: "refused",
      rejection: reject(400, INVALID_WORKFLOW_HEADER_CODE, declaration.detail),
    };
  }

  // `requested_agent_run_id`: an absent id defaults to `run-{requestId}` so an
  // un-correlated step opens its OWN run (see `resolveWorkflowRunId`); a
  // malformed one is Rust's `400 invalid_agent_run_id_header`. Both are decided
  // only once a workflow IS declared, so this slice adds no refusal to the
  // ordinary inference path.
  const runId = resolveWorkflowRunId(request.headers, request.requestId);
  if (runId === null) {
    return {
      kind: "refused",
      rejection: reject(
        400,
        "invalid_agent_run_id_header",
        `${AGENT_RUN_ID_HEADER} must be at most ${RUN_ID_MAX_LENGTH} characters of letters, ` +
          `numbers, _, -, . or :, and must agree with ${WORKFLOW_RUN_ID_HEADER} when both are sent`,
      ),
    };
  }

  const tenantId = request.caller.scope.kind === "tenant" ? request.caller.scope.tenantId : null;

  const loaded = await catalog.forTenant(tenantId);
  const catalogResult: WorkflowCatalogResult = Array.isArray(loaded)
    ? { ok: true, workflows: loaded as readonly WorkflowGraph[] }
    : (loaded as WorkflowCatalogResult);
  if (!catalogResult.ok) {
    return {
      kind: "refused",
      rejection: reject(
        503,
        "workflow_catalog_unavailable",
        `agent workflow configuration could not be read: ${catalogResult.detail}`,
      ),
    };
  }

  // The node id is needed to scope the token facts, and the ladder refuses a
  // missing one itself (`workflow_node_required`). `""` never matches a node,
  // so the facts read for a nodeless request is harmless and the refusal is
  // still the ladder's.
  const nodeId = declaration.workflowNodeId ?? "";
  const workflowVersion = declaration.workflowVersion;

  // The facts are keyed by the RESOLVED version, so a request that sends no
  // version header is counted against the version the ladder actually selects.
  const selected = catalogResult.workflows
    .filter((workflow) => workflow.id === declaration.workflowId)
    .filter((workflow) => workflowVersion === undefined || workflow.version === workflowVersion)
    .reduce<number | undefined>(
      (highest, workflow) =>
        highest === undefined || workflow.version > highest ? workflow.version : highest,
      undefined,
    );

  const query: WorkflowRunQuery = {
    workflowId: declaration.workflowId,
    workflowVersion: selected ?? workflowVersion ?? 0,
    runId,
    nodeId,
    tenantId,
  };

  const loadedFacts = await history.factsFor(query);
  const factsResult: WorkflowFactsResult =
    "ok" in loadedFacts
      ? (loadedFacts as WorkflowFactsResult)
      : { ok: true, facts: loadedFacts as WorkflowRunFacts };
  if (!factsResult.ok) {
    return {
      kind: "refused",
      rejection: reject(
        503,
        "workflow_history_unavailable",
        `agent workflow run history could not be read: ${factsResult.detail}`,
      ),
    };
  }

  const decision = enforceWorkflowGraphPolicy(
    catalogResult.workflows,
    {
      caller: workflowCallerFrom(request.caller),
      workflowId: declaration.workflowId,
      ...(workflowVersion === undefined ? {} : { workflowVersion }),
      ...(declaration.workflowNodeId === undefined
        ? {}
        : { workflowNodeId: declaration.workflowNodeId }),
      ...(declaration.workflowIteration === undefined
        ? {}
        : { workflowIteration: declaration.workflowIteration }),
      logicalModel: request.logicalModel,
      estimatedTotalTokens: request.estimatedTotalTokens,
      nowUnixSeconds: request.nowUnixSeconds,
    },
    factsResult.facts,
  );

  if (!decision.ok) return { kind: "refused", rejection: rejectionOf(decision.rejection) };
  return { kind: "admitted", constraint: decision.constraint, step: query };
}

/**
 * `apply_workflow_provider_constraint`, re-exported through this module so the
 * handler reaches `@ferrogate/policy`'s implementation and is never tempted to
 * re-derive the intersection.
 */
export function narrowByWorkflowProviders<R extends { readonly provider: string }>(
  constraint: WorkflowProviderConstraint | null,
  logicalModel: string,
  routes: readonly R[],
): { ok: true; routes: readonly R[] } | { ok: false; rejection: InferenceRejection } {
  const narrowed = applyWorkflowProviderConstraint(constraint, logicalModel, routes);
  return narrowed.ok
    ? { ok: true, routes: narrowed.routes }
    : { ok: false, rejection: rejectionOf(narrowed.rejection) };
}
