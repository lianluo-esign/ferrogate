/**
 * OpenAPI-to-CLI parity report (issue #365, coverage-manifest slice).
 *
 * Clean-room port of `ferrogate-control-plane-client::parity`
 * (docs/legacy/inventory-edge-control.md §2.1 `parity`, §2.3).
 *
 * The problem this solves: the `ferrogate` client must cover every
 * operator-facing Control Plane API operation. Nothing stops the OpenAPI
 * contract from growing a new operation while `registry.ts` silently fails to
 * bind a verb to it — a coverage gap no type checker catches. This module turns
 * that into a machine-checkable gate:
 *
 * 1. {@link parseOpenApiSurface} enumerates the *coverable public surface* of
 *    `docs/openapi/admin-api.openapi.json` — every operation whose
 *    `x-ferrogate-contract.visibility` is `public` or `admin`. `internal`
 *    operations (gateway-internal self-hosted-worker plumbing, metrics scrape)
 *    are deliberately excluded: they are not operator commands, so a CLI verb
 *    for one would be wrong, not missing.
 *
 *    Runtime **data-plane** operations leave the surface on a second axis. The
 *    OpenAI-compatible inference and MCP/tool-execution endpoints
 *    (`createChatCompletion`, `executeTool`, `mcpJsonRpc`, …) and the
 *    agent-runtime invoke/messaging endpoints are publicly reachable — their
 *    HTTP `visibility` is legitimately `public` — but they *move AI traffic*
 *    rather than *manage Control-Plane configuration*. They carry the
 *    operation-level {@link DATA_PLANE_MARKER} extension and are placed
 *    structurally outside the coverable surface (issue #390).
 * 2. {@link cliMapping} collects the `operationId` every registered CLI verb
 *    claims, keyed so a *duplicate* mapping (two verbs claiming one operation)
 *    is visible rather than silently de-duplicated the way
 *    {@link coverageManifest} is.
 * 3. {@link buildReport} diffs the two into covered / missing / extra /
 *    duplicate buckets, honouring the checked-in {@link REVIEWED_EXCLUSIONS}
 *    table so *known, owned, reasoned* gaps do not fail the gate while *new,
 *    unreviewed* drift does.
 *
 * The gate itself lives in `test/parity.test.ts`. Everything here is pure over
 * its inputs (a JSON string, a group list, an exclusion list) so the gate can
 * prove it fails on a synthetic gap or duplicate without touching global state.
 */
import type { GroupDescriptor } from "./registry.js";

/** OpenAPI HTTP method keys that denote an operation object under a path item. */
const HTTP_METHODS: readonly string[] = [
  "get",
  "put",
  "post",
  "delete",
  "options",
  "head",
  "patch",
  "trace",
];

/**
 * Contract visibilities whose operations the CLI is expected to cover. An
 * `internal` operation is gateway-internal and intentionally has no operator
 * command, so it is not part of the coverable surface.
 */
const COVERABLE_VISIBILITIES: readonly string[] = ["public", "admin"];

/**
 * Operation-level OpenAPI extension flag marking a runtime data-plane
 * operation. When `true` the operation is AI-traffic (OpenAI-compatible
 * inference, MCP/tool execution, agent invoke) rather than a Control-Plane
 * management verb, so it is structurally outside the coverable CLI surface
 * regardless of its (public) HTTP `visibility`. See issue #390.
 */
export const DATA_PLANE_MARKER = "x-ferrogate-data-plane";

/**
 * The OpenAPI document the parity gate enforces against, relative to the repo
 * root. Kept here so the gate and any tooling agree on the single source of
 * public `operationId`s.
 */
export const OPENAPI_DOCUMENT_PATH = "docs/openapi/admin-api.openapi.json";

/**
 * One intentionally-unmapped OpenAPI operation. An entry here is a reviewed,
 * owned decision that the operation carries no CLI verb *yet* (or ever) — it
 * removes the operation from the "missing" gap set so the gate stays green,
 * while keeping the reason auditable in source control.
 */
export interface ReviewedExclusion {
  /** The OpenAPI `operationId` that intentionally has no CLI verb. */
  readonly operationId: string;
  /** Who owns closing (or permanently justifying) the gap. */
  readonly owner: string;
  /** Why it is unmapped today; cite the follow-up issue. */
  readonly reason: string;
}

/**
 * The reviewed exclusion list, ported row-for-row from the Rust
 * `REVIEWED_EXCLUSIONS`.
 *
 * Keep it minimal and shrinking. When a family lands its verbs, delete the
 * corresponding rows — {@link buildReport} flags stale rows (an exclusion whose
 * operation is now covered, or no longer in the contract) so this table cannot
 * rot into a rubber stamp.
 */
export const REVIEWED_EXCLUSIONS: readonly ReviewedExclusion[] = [
  // x402 spend-policy diagnostics (#351). Read-only: two GETs (declared and
  // effective policy + revision) plus a POST that is a dry-run evaluator and
  // mutates nothing. The policy itself is authored in config, not through this
  // API. These are policy-family resources, so their verbs belong with the rest
  // of the policy surface in #361 rather than as a one-off group. (The x402
  // payment track is separately DEPRIORITIZED by the product owner.)
  {
    operationId: "listX402SpendPolicies",
    owner: "policy resource family (#361)",
    reason:
      "read-only x402 spend-policy declarations; verbs land with the #361 policy family rather than forking it",
  },
  {
    operationId: "getEffectiveX402SpendPolicy",
    owner: "policy resource family (#361)",
    reason:
      "read-only effective-policy diagnostics (policy in force + revision); verbs land with the #361 policy family",
  },
  {
    operationId: "evaluateX402SpendPolicy",
    owner: "policy resource family (#361)",
    reason: "dry-run policy evaluator that mutates nothing; verbs land with the #361 policy family",
  },
  // Agent skill/discovery reads — verbs not yet built.
  {
    operationId: "getAgentDiscovery",
    owner: "agent family (#362)",
    reason: "agent skill/discovery read verbs not yet implemented; tracked as #362 follow-up",
  },
  {
    operationId: "getAgentSkill",
    owner: "agent family (#362)",
    reason: "agent skill/discovery read verbs not yet implemented; tracked as #362 follow-up",
  },
  {
    operationId: "listAgentSkills",
    owner: "agent family (#362)",
    reason: "agent skill/discovery read verbs not yet implemented; tracked as #362 follow-up",
  },
  {
    operationId: "registerAdminSelfHostedWorker",
    owner: "worker family (#362)",
    reason: "self-hosted worker registration verb not yet implemented; tracked as #362 follow-up",
  },
  {
    operationId: "promoteAssetVisibility",
    owner: "asset family (#363)",
    reason: "asset visibility-promotion verb not yet implemented; tracked as #363 follow-up",
  },
  // Scoped control-plane overview read (#339): a single aggregate read whose
  // consumer is the admin-console dashboard (#343), not an operator CLI verb.
  {
    operationId: "getAdminOverview",
    owner: "control-plane console (#343)",
    reason:
      "dashboard-facing control-plane overview aggregate; ctl verb is optional follow-up, tracked with the #343 console UI",
  },
  // ---------------------------------------------------------------------
  // #734 — the twelve operations that were ROUTED but never DESCRIBED.
  //
  // These are not new gaps. #682 (BYOK), #694 (prompt deployment labels) and
  // #695 (semantic-cache policy) all merged while
  // `.github/workflows/api-contract-drift.yml` was disabled, so their
  // operations never reached `admin-api.openapi.json` and this gate never saw
  // them — the CLI has been missing these verbs since those PRs landed, silently.
  // #734 restores the OpenAPI descriptions, which is what makes the shortfall
  // visible here for the first time.
  //
  // They are excluded rather than mapped in #734 because that issue is scoped to
  // the published contract and its enforcement: minting twelve operator verbs
  // (with their argument grammar, help text, output shaping and golden tests) as
  // a side effect of a documentation-integrity fix would ship an un-designed CLI
  // surface. Each row below names the family that owns the verbs and must be
  // deleted when they land — `buildReport` flags a stale exclusion, so this table
  // cannot rot.
  // ---------------------------------------------------------------------
  // #682 — per-tenant BYOK. `ctl provider-credentials put` would take a provider
  // API KEY as an argument, so its verb design has to settle how the secret is
  // supplied (stdin/env, never argv, where a shell history would keep it) before
  // it can be built. That is a credential-handling decision, not a mapping.
  {
    operationId: "listProviderCredentials",
    owner: "provider/BYOK family (#682, #365 parity chain)",
    reason:
      "BYOK registration verbs are unbuilt; the group's write verb takes a provider secret, so its argument grammar must first settle how the value is supplied without reaching argv — tracked as the #682 CLI follow-up",
  },
  {
    operationId: "putProviderCredential",
    owner: "provider/BYOK family (#682, #365 parity chain)",
    reason:
      "registers or rotates a provider API key; the verb must read the secret from stdin or the environment rather than argv, which is an unmade credential-handling decision — tracked as the #682 CLI follow-up",
  },
  {
    operationId: "revokeProviderCredential",
    owner: "provider/BYOK family (#682, #365 parity chain)",
    reason:
      "BYOK revocation lands with the rest of the provider-credentials verbs rather than shipping alone — tracked as the #682 CLI follow-up",
  },
  // #694 — prompt deployment labels are a SUB-resource of an existing group
  // (`/admin/v1/prompt-templates/{id}/labels/{label}`). Every mapped group in
  // `registry.ts` today addresses a top-level collection, so covering these
  // needs a nested-resource verb shape the registry does not yet have.
  {
    operationId: "listAdminPromptTemplateLabels",
    owner: "prompt family (#694, #365 parity chain)",
    reason:
      "prompt-template labels are a nested sub-resource; the registry has no nested-collection verb shape yet, so the verbs land with that shape rather than as a bespoke group — tracked as the #694 CLI follow-up",
  },
  {
    operationId: "putAdminPromptTemplateLabel",
    owner: "prompt family (#694, #365 parity chain)",
    reason:
      "label deployment is the call that replaces a deploy; it belongs with the nested prompt-template verb shape — tracked as the #694 CLI follow-up",
  },
  {
    operationId: "deleteAdminPromptTemplateLabel",
    owner: "prompt family (#694, #365 parity chain)",
    reason:
      "label retirement belongs with the nested prompt-template verb shape — tracked as the #694 CLI follow-up",
  },
  // #695 — semantic-cache policy. Composite `{scope_type}/{scope_id}` key like
  // `quota-policies`, plus an `invalidate` action verb that is a purge, not a
  // CRUD leg; the group's verbs land together so `invalidate` is never the one
  // that is missing when an operator needs it.
  {
    operationId: "listSemanticCachePolicies",
    owner: "cache/policy family (#695, #365 parity chain)",
    reason:
      "semantic-cache policy verbs are unbuilt; the group carries a purge action alongside its CRUD legs and lands as one set — tracked as the #695 CLI follow-up",
  },
  {
    operationId: "createSemanticCachePolicy",
    owner: "cache/policy family (#695, #365 parity chain)",
    reason:
      "semantic-cache policy verbs land as one set with the purge action — tracked as the #695 CLI follow-up",
  },
  {
    operationId: "getSemanticCachePolicy",
    owner: "cache/policy family (#695, #365 parity chain)",
    reason:
      "semantic-cache policy verbs land as one set with the purge action — tracked as the #695 CLI follow-up",
  },
  {
    operationId: "replaceSemanticCachePolicy",
    owner: "cache/policy family (#695, #365 parity chain)",
    reason:
      "semantic-cache policy verbs land as one set with the purge action — tracked as the #695 CLI follow-up",
  },
  {
    operationId: "deleteSemanticCachePolicy",
    owner: "cache/policy family (#695, #365 parity chain)",
    reason:
      "semantic-cache policy verbs land as one set with the purge action — tracked as the #695 CLI follow-up",
  },
  {
    operationId: "invalidateSemanticCachePolicy",
    owner: "cache/policy family (#695, #365 parity chain)",
    reason:
      "cache purge action rather than a CRUD leg; lands with the rest of the semantic-cache policy verbs — tracked as the #695 CLI follow-up",
  },
  // ---------------------------------------------------------------------
  // #677 — per-request cost attribution, surfaced here by #747.
  //
  // Same shape as the #734 rows above and for the same reason: #677 routed
  // `listAdminCostRecords` and `exportAdminCostRecords` without describing
  // them, so this gate — which derives its surface FROM
  // `admin-api.openapi.json` — could not see either operation. The CLI has had
  // no cost-attribution verbs since #677 landed; #747 describing the contract
  // is what makes that visible for the first time. It is a pre-existing gap
  // with a name now, not a regression.
  //
  // The two are excluded TOGETHER because an operator handed a `list` with no
  // way to pull the file would ask for the export immediately, and the export
  // is the half that needs design: it answers CSV, JSONL or a binary Parquet
  // body with a `content-disposition` filename, none of which the CLI's
  // JSON-shaping output path can render. Deciding whether that verb streams to
  // a `--output` file, refuses a TTY, or prints bytes is a UX decision, and
  // making it inside a documentation-integrity fix would ship an undesigned
  // surface. Both rows must be DELETED when the verbs land — `buildReport`
  // fails on a stale exclusion, so this cannot rot into a rubber stamp.
  // ---------------------------------------------------------------------
  {
    operationId: "listAdminCostRecords",
    owner: "cost attribution family (#677, #365 parity chain)",
    reason:
      "per-request chargeback read; its verb lands together with the export half rather than shipping a list an operator cannot then download — tracked as the #677 CLI follow-up",
  },
  {
    operationId: "exportAdminCostRecords",
    owner: "cost attribution family (#677, #365 parity chain)",
    reason:
      "downloads a CSV, JSONL or binary Parquet attachment rather than a JSON document, so the verb first needs an output-file grammar the CLI does not have — tracked as the #677 CLI follow-up",
  },
];

/** The coverable and non-coverable operation sets parsed from an OpenAPI document. */
export interface OperationSurface {
  /** `operationId`s of `public`/`admin` operations — what the CLI must cover. */
  readonly coverable: readonly string[];
  /** `operationId`s of `internal` operations, so an accidental verb reads as `extra`. */
  readonly internal: readonly string[];
  /** `operationId`s carrying {@link DATA_PLANE_MARKER} — AI traffic, not management. */
  readonly dataPlane: readonly string[];
}

function sorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

/**
 * Parse the coverable public surface out of an OpenAPI document (as a JSON
 * string).
 *
 * Fails closed: any operation object missing an `operationId` or a recognisable
 * `x-ferrogate-contract.visibility` throws, because the parity gate must not
 * silently drop operations from the surface it enforces.
 */
export function parseOpenApiSurface(json: string): OperationSurface {
  let document: unknown;
  try {
    document = JSON.parse(json);
  } catch (error) {
    throw new Error(
      `failed to parse OpenAPI JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const paths =
    document !== null && typeof document === "object" && !Array.isArray(document)
      ? (document as Record<string, unknown>).paths
      : undefined;
  if (paths === null || paths === undefined || typeof paths !== "object" || Array.isArray(paths)) {
    throw new Error("OpenAPI document has no `paths` object");
  }

  const coverable: string[] = [];
  const internal: string[] = [];
  const dataPlane: string[] = [];

  for (const [route, pathItem] of Object.entries(paths as Record<string, unknown>)) {
    if (pathItem === null || typeof pathItem !== "object" || Array.isArray(pathItem)) continue;
    for (const [method, rawOperation] of Object.entries(pathItem as Record<string, unknown>)) {
      if (!HTTP_METHODS.includes(method)) continue;
      if (
        rawOperation === null ||
        typeof rawOperation !== "object" ||
        Array.isArray(rawOperation)
      ) {
        continue;
      }
      const operation = rawOperation as Record<string, unknown>;
      const operationId = operation.operationId;
      if (typeof operationId !== "string" || operationId === "") {
        throw new Error(`${method.toUpperCase()} ${route} is missing operationId`);
      }
      // Runtime data-plane operations leave the coverable surface on a second
      // axis, independent of their (public) HTTP visibility (#390).
      if (operation[DATA_PLANE_MARKER] === true) {
        dataPlane.push(operationId);
        continue;
      }
      const contract = operation["x-ferrogate-contract"];
      const visibility =
        contract !== null && typeof contract === "object" && !Array.isArray(contract)
          ? (contract as Record<string, unknown>).visibility
          : undefined;
      if (typeof visibility !== "string") {
        throw new Error(
          `${method.toUpperCase()} ${route} (${operationId}) is missing x-ferrogate-contract.visibility`,
        );
      }
      if (COVERABLE_VISIBILITIES.includes(visibility)) coverable.push(operationId);
      else internal.push(operationId);
    }
  }

  if (coverable.length === 0) {
    throw new Error("OpenAPI document declared no coverable (public/admin) operations");
  }
  return { coverable: sorted(coverable), internal: sorted(internal), dataPlane: sorted(dataPlane) };
}

/**
 * The `operationId`s claimed by the registered CLI verbs, mapped to the
 * `"group verb"` sites that claim each one. A key with more than one site is a
 * duplicate mapping.
 */
export interface CliMapping {
  readonly byOperation: ReadonlyMap<string, readonly string[]>;
}

/**
 * Collect the CLI coverage mapping from every registered command family.
 *
 * Unlike `coverageManifest()` (a de-duplicated set) this preserves *which*
 * verbs claim an operation, which is what makes duplicate detection possible.
 */
export function cliMapping(groups: readonly GroupDescriptor[]): CliMapping {
  const byOperation = new Map<string, string[]>();
  for (const group of groups) {
    for (const verb of group.verbs) {
      if (verb.operationId === null) continue;
      const sites = byOperation.get(verb.operationId) ?? [];
      sites.push(`${group.name} ${verb.name}`);
      byOperation.set(verb.operationId, sites);
    }
  }
  for (const sites of byOperation.values()) sites.sort();
  return { byOperation };
}

/** The de-duplicated, sorted set of covered `operationId`s. */
export function mappedOperationIds(mapping: CliMapping): readonly string[] {
  return sorted(mapping.byOperation.keys());
}

/** Operations claimed by more than one verb, mapped to the offending sites. */
export function duplicateMappings(mapping: CliMapping): ReadonlyMap<string, readonly string[]> {
  const duplicates = new Map<string, readonly string[]>();
  for (const [id, sites] of [...mapping.byOperation.entries()].sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  )) {
    if (sites.length > 1) duplicates.set(id, sites);
  }
  return duplicates;
}

/**
 * The parity verdict: how the CLI mapping lines up with the coverable OpenAPI
 * surface after applying the reviewed exclusions.
 */
export interface CoverageReport {
  /** Coverable operations a CLI verb maps. */
  readonly covered: readonly string[];
  /** Coverable operations with no verb and no reviewed exclusion — must be empty. */
  readonly missing: readonly string[];
  /** Coverable operations with no verb that ARE on the exclusion list. Not a failure. */
  readonly excludedMissing: readonly string[];
  /** `operationId`s a verb claims that are not in the coverable surface. */
  readonly extra: readonly string[];
  /** Operations mapped by more than one verb, keyed to the offending sites. */
  readonly duplicates: ReadonlyMap<string, readonly string[]>;
  /** Exclusion rows that no longer describe a real gap; stale rows must be pruned. */
  readonly staleExclusions: readonly string[];
}

/** True when there is no unreviewed gap, duplicate, extra mapping, or stale row. */
export function isClean(report: CoverageReport): boolean {
  return (
    report.missing.length === 0 &&
    report.extra.length === 0 &&
    report.duplicates.size === 0 &&
    report.staleExclusions.length === 0
  );
}

/** Diff the coverable surface against the CLI mapping, applying the exclusions. */
export function buildReport(
  surface: OperationSurface,
  mapping: CliMapping,
  exclusions: readonly ReviewedExclusion[] = REVIEWED_EXCLUSIONS,
): CoverageReport {
  const coveredIds = new Set(mappedOperationIds(mapping));
  const coverableIds = new Set(surface.coverable);
  const excluded = new Set(exclusions.map((entry) => entry.operationId));

  const covered: string[] = [];
  const missing: string[] = [];
  const excludedMissing: string[] = [];
  for (const id of surface.coverable) {
    if (coveredIds.has(id)) covered.push(id);
    else if (excluded.has(id)) excludedMissing.push(id);
    else missing.push(id);
  }

  const extra = [...coveredIds].filter((id) => !coverableIds.has(id));

  // A reviewed exclusion is stale if the operation it names is now covered by a
  // verb, or is no longer a coverable operation in the contract.
  const staleExclusions = [...excluded].filter(
    (id) => !(coverableIds.has(id) && !coveredIds.has(id)),
  );

  return {
    covered: sorted(covered),
    missing: sorted(missing),
    excludedMissing: sorted(excludedMissing),
    extra: sorted(extra),
    duplicates: duplicateMappings(mapping),
    staleExclusions: sorted(staleExclusions),
  };
}

function pushList(lines: string[], label: string, ids: readonly string[]): void {
  if (ids.length === 0) return;
  lines.push(`  ${label}:`);
  for (const id of ids) lines.push(`    - ${id}`);
}

/** A stable, human-readable rendering for test failure output. */
export function renderReport(report: CoverageReport): string {
  const lines = [
    "OpenAPI-to-CLI parity report",
    `  covered: ${report.covered.length}`,
    `  missing (unreviewed gap): ${report.missing.length}`,
    `  excluded (reviewed gap): ${report.excludedMissing.length}`,
    `  extra (verb -> unknown op): ${report.extra.length}`,
    `  duplicate mappings: ${report.duplicates.size}`,
    `  stale exclusions: ${report.staleExclusions.length}`,
  ];
  pushList(lines, "missing (unreviewed gap)", report.missing);
  pushList(lines, "extra (verb -> unknown op)", report.extra);
  pushList(lines, "stale exclusions", report.staleExclusions);
  if (report.duplicates.size > 0) {
    lines.push("  duplicate mappings:");
    for (const [id, sites] of report.duplicates) lines.push(`    - ${id}: ${sites.join(", ")}`);
  }
  return `${lines.join("\n")}\n`;
}
