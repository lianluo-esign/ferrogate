import {
  DESIRED_STATE_API_VERSION,
  type DesiredRecord,
  DesiredStateError,
  type PlannedChange,
  type ResourceKindShape,
  parseDesiredState,
  planKind,
  planSummary,
  renderPlan,
} from "@ferrogate/config";
/**
 * `ferrogate apply -f <file>` — declarative (GitOps) config sync, issue #702.
 *
 * Guardrail revisions and quota policies were API-driven only: an operator
 * could change them one `ctl` call at a time, but could not check a file in,
 * diff it in CI and converge a deployment onto it. Kong decK, Envoy CRDs and
 * APISIX YAML all do exactly that, and it is what an enterprise platform team
 * expects of a gateway.
 *
 * This command is COMPOSITION, not a new client. Everything underneath it
 * already existed and is reused verbatim:
 *
 *   * `@ferrogate/config`'s {@link parseDesiredState} owns the document schema
 *     and {@link planKind} owns the diff — both pure, both testable serverless;
 *   * `registry.ts` owns the request shapes: every read and every write below
 *     is `buildRequest(group, verb, input)` for a verb `ctl` already exposes,
 *     so `apply` can never reach an endpoint the registry does not describe and
 *     the OpenAPI parity gate keeps covering;
 *   * `receipt.ts`'s `MutationPlan` owns the audit artifact and `--dry-run`, so
 *     an applied change produces the SAME attested `MutationReceipt` the
 *     equivalent `ctl` invocation would.
 *
 * ## The deletion decision (the interesting failure)
 *
 * A resource that exists on the server and is ABSENT from the file is, by
 * default, reported as an `orphan` and left alone: the run exits 0, names it,
 * and tells the operator that `--prune` is what deletes it. Deleting it
 * silently is how people lose production config; hiding it would make the file
 * a lie about the deployment. `--prune` opts into deletion and is treated as a
 * guarded mutation — it needs `--yes` (or an interactive confirmation), exactly
 * like `ctl`'s own confirmation-required verbs.
 */
import type { JsonValue } from "@ferrogate/core";
import { ClientActionIdentity, fingerprintEnvFrom } from "../action-identity.js";
import type { Args, FlagSpec } from "../args.js";
import type { EffectiveContext } from "../context.js";
import { CliError, exitCode } from "../errors.js";
import { GLOBAL_FLAGS, resolveEffective } from "../global-args.js";
import { renderJson } from "../output.js";
import { DEFAULT_PAGE_SIZE, pageEnvelope } from "../paging.js";
import type { ConfigTextParsers, RequestContext, RequestSpec } from "../ports.js";
import { runtimeConfigTextParsers } from "../ports.js";
import { MutationPlan, type VerbOutput, renderGate } from "../receipt.js";
import { buildRequest, resolveVerb, resourceInput } from "../registry.js";
import type { CliRuntime, CommandNode } from "../runtime.js";
import { requestContextFor, sendAllPages } from "./ctl.js";

// ---------------------------------------------------------------------------
// The resource-kind table
// ---------------------------------------------------------------------------

/** One step of the write sequence a planned change expands to. */
interface ApplyStep {
  /** A verb of {@link ApplyKind.group} as `registry.ts` names it. */
  readonly verb: string;
  readonly segments: readonly string[];
  /**
   * The request document, or a function of the responses the EARLIER steps of
   * this same change produced.
   *
   * The function form exists for exactly one reason: a guardrail revision's
   * number is minted by the server, so `activate` cannot be built until
   * `create` has answered. Under `--dry-run` no response exists and the
   * function is called with an empty list, so it must fall back to the number
   * the server will mint — which the policy's `head_revision` already tells us.
   */
  readonly body?: JsonValue | ((responses: readonly JsonValue[]) => JsonValue);
}

/** How one resource family is read, keyed, diffed and written. */
interface ApplyKind {
  readonly shape: ResourceKindShape;
  /** The `ctl` registry group whose verbs build every request for this kind. */
  readonly group: string;
  /** Read the server's current state for this kind. */
  fetchActual(reader: ServerReader): Promise<readonly DesiredRecord[]>;
  /** Expand one planned change into ordered write steps. */
  stepsFor(change: PlannedChange): readonly ApplyStep[];
}

/** Reads the CLI performs while building the plan (never a mutation). */
interface ServerReader {
  /** Send a registry-built GET and return the decoded body. */
  read(group: string, verb: string, segments: readonly string[]): Promise<JsonValue>;
}

function asRecord(value: JsonValue): DesiredRecord | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as DesiredRecord)
    : undefined;
}

/** The rows of a list body, whatever envelope it arrived in. */
function itemsOf(body: JsonValue): readonly DesiredRecord[] {
  const envelope = pageEnvelope(body);
  const items = envelope?.items ?? [];
  return items.map(asRecord).filter((item): item is DesiredRecord => item !== undefined);
}

function requiredString(record: DesiredRecord, field: string): string | undefined {
  const value = record[field];
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

/**
 * Bookkeeping every admin collection carries. Stripped from BOTH sides of the
 * diff so a server-minted `id` or a null `tenant_id` never reads as drift the
 * operator caused — which would make every apply non-idempotent.
 */
const COMMON_SERVER_FIELDS = ["id", "tenant_id", "object", "created_at", "updated_at"] as const;

/**
 * `quota-policies` — the composite `(scope_type, scope_id)` key.
 *
 * The item path is two segments, not an opaque id (see
 * `apps/control-plane/src/routes/quota_policy.ts`), so the identity string is
 * `scope_type:scope_id` and the segments are the pair.
 */
const QUOTA_POLICIES: ApplyKind = {
  group: "quota-policies",
  shape: {
    kind: "quota-policies",
    serverManaged: [...COMMON_SERVER_FIELDS],
    identity: (record) => {
      const scopeType = requiredString(record, "scope_type");
      const scopeId = requiredString(record, "scope_id");
      if (scopeType === undefined || scopeId === undefined) {
        return {
          error:
            "every entry needs a non-empty scope_type (tenant|project|workspace|key) and " +
            `scope_id -- they ARE the resource's identity; got ${JSON.stringify(record)}`,
        };
      }
      return { id: `${scopeType}:${scopeId}` };
    },
  },
  fetchActual: async (reader) => itemsOf(await reader.read("quota-policies", "list", [])),
  stepsFor: (change) => {
    const segments = change.id.split(":");
    switch (change.action) {
      case "create":
        return [{ verb: "create", segments: [], body: change.desired as JsonValue }];
      case "update":
        // PUT, not PATCH. The plan already showed every field that would be
        // dropped, so a full replace is what the operator was shown and agreed
        // to; a merge would silently keep state the file no longer declares.
        return [{ verb: "replace", segments, body: change.desired as JsonValue }];
      case "delete":
        return [{ verb: "delete", segments }];
      default:
        return [];
    }
  },
};

/**
 * `gateway-configs` — plain id-keyed CRUD, and the second family proves the
 * engine is generic rather than shaped around quota policies.
 */
const GATEWAY_CONFIGS: ApplyKind = {
  group: "gateway-configs",
  shape: {
    kind: "gateway-configs",
    serverManaged: ["tenant_id", "object", "created_at", "updated_at"],
    identity: (record) => {
      const id = requiredString(record, "id");
      return id === undefined
        ? { error: `every entry needs a non-empty id; got ${JSON.stringify(record)}` }
        : { id };
    },
  },
  fetchActual: async (reader) => itemsOf(await reader.read("gateway-configs", "list", [])),
  stepsFor: (change) => {
    switch (change.action) {
      case "create":
        return [{ verb: "create", segments: [], body: change.desired as JsonValue }];
      case "update":
        return [{ verb: "replace", segments: [change.id], body: change.desired as JsonValue }];
      case "delete":
        return [{ verb: "delete", segments: [change.id] }];
      default:
        return [];
    }
  },
};

/**
 * Fields of a stored guardrail revision that the SERVER owns.
 *
 * `revision`, `created_at_unix` and `created_by` are stamped at create time and
 * `status`/`archived_at` are lifecycle. Comparing them would make every apply
 * report drift against a policy nobody had touched — the exact failure that
 * turns a GitOps tool into noise nobody reads.
 */
const GUARDRAIL_SERVER_FIELDS = [
  ...COMMON_SERVER_FIELDS,
  "revision",
  "status",
  "archived_at",
  "created_at_unix",
  "created_by",
  "head_revision",
  "active_revision",
  "activated_at",
] as const;

/** The revision number a policy record says is live, or `null`. */
function activeRevisionOf(policy: DesiredRecord): number | null {
  const value = policy.active_revision;
  return typeof value === "number" ? value : null;
}

function headRevisionOf(policy: DesiredRecord): number {
  const value = policy.head_revision;
  return typeof value === "number" ? value : 0;
}

/** Read the `revision` a create/append response minted, when one is there. */
function mintedRevision(responses: readonly JsonValue[]): number | undefined {
  for (const response of [...responses].reverse()) {
    const envelope = asRecord(response);
    const policy = envelope === undefined ? undefined : asRecord(envelope.policy as JsonValue);
    const revision = policy?.revision;
    if (typeof revision === "number") return revision;
  }
  return undefined;
}

/**
 * `guardrail-policies` — an append-only revision chain plus an activation
 * pointer, so "sync" is NOT CRUD and must not be pretended to be one.
 *
 * The record this kind diffs is **the content of the revision that is currently
 * ACTIVE**, because that is the only thing the data plane enforces. A policy
 * with revisions but nothing activated is therefore represented by a stub
 * carrying only its `policy_id`: nothing of it is live, so every declared field
 * is an addition. That reads correctly in the plan ("these fields become
 * enforced") and, crucially, converges — the next apply sees the newly-active
 * revision and reports `unchanged`.
 */
const GUARDRAIL_POLICIES: ApplyKind = {
  group: "guardrail-policies",
  shape: {
    kind: "guardrail-policies",
    serverManaged: [...GUARDRAIL_SERVER_FIELDS],
    identity: (record) => {
      const id = requiredString(record, "policy_id");
      return id === undefined
        ? { error: `every entry needs a non-empty policy_id; got ${JSON.stringify(record)}` }
        : { id };
    },
  },
  fetchActual: async (reader) => {
    const policies = itemsOf(await reader.read("guardrail-policies", "list", []));
    const actual: DesiredRecord[] = [];
    for (const policy of policies) {
      const policyId = requiredString(policy, "policy_id") ?? requiredString(policy, "id");
      if (policyId === undefined) continue;
      const active = activeRevisionOf(policy);
      if (active === null) {
        // Known policy, nothing enforced. The head revision is deliberately NOT
        // used as the comparison basis: a draft the operator never activated is
        // not the deployment's state, and treating it as such would let an
        // apply report `unchanged` for a policy that screens nothing.
        actual.push({ policy_id: policyId, head_revision: headRevisionOf(policy) });
        continue;
      }
      const revisions = itemsOf(await reader.read("guardrail-policies", "revisions", [policyId]));
      const live = revisions.find((revision) => revision.revision === active);
      actual.push(
        live === undefined
          ? { policy_id: policyId, head_revision: headRevisionOf(policy) }
          : { ...live, policy_id: policyId, head_revision: headRevisionOf(policy) },
      );
    }
    return actual;
  },
  stepsFor: (change) => {
    const activate: ApplyStep = {
      verb: "activate",
      segments: [change.id],
      body: (responses) => {
        const minted = mintedRevision(responses);
        // The dry-run fallback: the server always mints `head + 1`, and the
        // policy record we just read carries `head_revision`. A receipt that
        // named a revision the server would not mint is worse than none, so
        // this fallback is the SAME arithmetic the control plane performs.
        const predicted = headRevisionOf(change.actual ?? {}) + 1;
        return { revision: minted ?? predicted };
      },
    };
    switch (change.action) {
      case "create":
        // One call creates the policy AND its revision 1; activation is a
        // second, deliberate operation in this contract, so a created policy
        // that was never activated would enforce nothing.
        return [{ verb: "create", segments: [], body: change.desired as JsonValue }, activate];
      case "update":
        return [
          { verb: "create-revision", segments: [change.id], body: change.desired as JsonValue },
          activate,
        ];
      case "delete": {
        const active = activeRevisionOf(change.actual ?? {});
        // Archiving the ACTIVE revision is the strongest removal this contract
        // offers: there is no delete-the-policy operation, and history is
        // immutable by design. A policy with nothing active is already pruned.
        return active === null ? [] : [{ verb: "archive", segments: [change.id, String(active)] }];
      }
      default:
        return [];
    }
  },
};

/** Every kind `apply` can converge, in the order it applies them. */
const APPLY_KINDS: readonly ApplyKind[] = [QUOTA_POLICIES, GATEWAY_CONFIGS, GUARDRAIL_POLICIES];

/**
 * Kinds an operator will reasonably reach for and that this command REFUSES by
 * name, because the Control Plane contract has no write operation for them.
 *
 * Silently ignoring an unknown key would be the worst outcome for a file whose
 * whole purpose is to be the source of truth, and inventing a write endpoint
 * for `models` would be worse still.
 */
const REFUSED_KINDS: Readonly<Record<string, string>> = {
  models: [
    "`models` is read-only in the Control Plane contract -- `listAdminModels` is the only",
    "operation that exists, there is no create/replace/delete. The model catalogue is part of",
    "the gateway's own configuration document, so declare it there and roll it out with",
    "`ferrogate reload -c <config>` (or a `gateway-configs` entry in this same file).",
  ].join(" "),
  providers: [
    "`providers` is read-only in the Control Plane contract (`listAdminProviders` only);",
    "providers are declared in the gateway configuration document, not through the admin API.",
  ].join(" "),
};

// ---------------------------------------------------------------------------
// Document loading
// ---------------------------------------------------------------------------

/**
 * Decode the file's TEXT into a raw object.
 *
 * JSON is handled in-process; YAML goes through the injected `Bun.YAML.parse`
 * for the same reason `createFerrogateConfigValidator` does it that way — the
 * shipped `ferrogate` is a Bun binary and there is no portable cross-runtime
 * YAML parser. A runtime with no YAML parser REFUSES a `.yaml` file by name
 * rather than guessing, because applying a guessed parse would change a
 * production deployment on the strength of a guess.
 */
export function decodeDesiredStateText(
  path: string,
  source: string,
  parsers: ConfigTextParsers,
): unknown {
  const lowered = (path.split(/[\\/]/).pop() ?? path).toLowerCase();
  if (lowered.endsWith(".json")) {
    try {
      return JSON.parse(source) as unknown;
    } catch (error) {
      throw new DesiredStateError(
        `${path} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  if (lowered.endsWith(".yaml") || lowered.endsWith(".yml")) {
    if (parsers.yaml === undefined) {
      throw new DesiredStateError(
        `cannot read ${path}: this runtime provides no YAML parser. The shipped 'ferrogate' ` +
          "binary is a Bun binary and uses Bun.YAML; under a non-Bun runtime pass the desired " +
          "state as JSON rather than have the CLI guess at it",
      );
    }
    try {
      return parsers.yaml(source);
    } catch (error) {
      throw new DesiredStateError(
        `${path} is not valid YAML: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  throw new DesiredStateError(
    `cannot infer the format of ${path}: give it a .yaml, .yml or .json extension`,
  );
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

const APPLY_FLAGS: readonly FlagSpec[] = [
  {
    name: "file",
    short: "f",
    kind: "string",
    valueName: "PATH",
    env: "FERROGATE_APPLY_FILE",
    help: "Desired-state document (.yaml/.yml/.json); '-' reads stdin as JSON",
  },
  { name: "dry-run", kind: "boolean", help: "Print the plan and send no mutation" },
  {
    name: "prune",
    kind: "boolean",
    help: "DELETE resources that exist on the server but not in the file (guarded)",
  },
  {
    name: "yes",
    kind: "boolean",
    help: "Acknowledge --prune's deletions without prompting",
  },
  ...GLOBAL_FLAGS,
];

/** The result of executing one planned change. */
interface AppliedChange {
  readonly change: PlannedChange;
  readonly receipts: readonly VerbOutput[];
}

/**
 * Guarded-deletion consent, mirroring `ctl`'s `requireConfirmation`: a
 * non-interactive run and a non-TTY stdin both REFUSE rather than assume
 * consent. An unattended pipeline has to say `--yes` out loud before it deletes
 * anything.
 */
async function confirmPrune(
  runtime: CliRuntime,
  doomed: readonly PlannedChange[],
  confirmed: boolean,
  nonInteractive: boolean,
): Promise<void> {
  if (doomed.length === 0 || confirmed) return;
  const named = doomed.map((change) => `${change.kind}/${change.id}`).join(", ");
  if (nonInteractive || !runtime.io.isStdinTty()) {
    throw CliError.usage(
      `refusing to prune ${doomed.length} resource(s) without an explicit acknowledgement ` +
        `(${named}); rerun with --yes, or drop --prune to keep them`,
    );
  }
  runtime.io.stderr(`Delete ${doomed.length} resource(s) absent from the file (${named})? [y/N] `);
  const answer = (await runtime.io.readStdin()).trim().toLowerCase();
  if (answer === "y" || answer === "yes") return;
  throw CliError.usage("apply cancelled before any request was sent");
}

/** Build the plan for every declared kind, refusing unknown/unwritable ones first. */
async function buildPlan(
  document: ReturnType<typeof parseDesiredState>,
  reader: ServerReader,
  prune: boolean,
): Promise<{ changes: PlannedChange[]; kinds: Map<string, ApplyKind> }> {
  const byName = new Map(APPLY_KINDS.map((kind) => [kind.shape.kind, kind]));

  // Validate EVERY declared kind before a single request leaves: a document
  // half-applied because its fourth section named an unsupported resource is
  // strictly worse than one that was refused outright.
  for (const name of Object.keys(document.resources)) {
    const refusal = REFUSED_KINDS[name];
    if (refusal !== undefined) throw CliError.usage(refusal);
    if (!byName.has(name)) {
      throw CliError.usage(
        `unknown resource kind '${name}'; this build of apply understands: ` +
          `${[...byName.keys()].join(", ")}`,
      );
    }
  }

  const changes: PlannedChange[] = [];
  const kinds = new Map<string, ApplyKind>();
  // Iterate the TABLE, not the document, so the apply order is deterministic
  // and independent of key order in the file.
  for (const kind of APPLY_KINDS) {
    const desired = document.resources[kind.shape.kind];
    if (desired === undefined) continue;
    kinds.set(kind.shape.kind, kind);
    const actual = await kind.fetchActual(reader);
    changes.push(
      ...planKind({
        shape: kind.shape,
        desired: desired as readonly DesiredRecord[],
        actual,
        prune,
      }),
    );
  }
  return { changes, kinds };
}

/** Execute one change's write steps, threading each response into the next. */
async function applyChange(
  runtime: CliRuntime,
  kind: ApplyKind,
  change: PlannedChange,
  effective: EffectiveContext,
  identity: ClientActionIdentity,
  context: RequestContext,
  dryRun: boolean,
): Promise<readonly VerbOutput[]> {
  const outputs: VerbOutput[] = [];
  const responses: JsonValue[] = [];

  for (const step of kind.stepsFor(change)) {
    const { verb } = resolveVerb(kind.group, step.verb);
    const gate = renderGate(verb);
    if (gate.kind !== "receipt") {
      // Unreachable while the table names only mutating verbs, and a loud
      // refusal if that ever stops being true: a write routed through the read
      // renderer would print a server document where an audit receipt belongs.
      throw CliError.usage(
        `internal: apply step '${kind.group} ${step.verb}' is a ${verb.effect} verb`,
      );
    }
    const body = typeof step.body === "function" ? step.body(responses) : step.body;
    const spec: RequestSpec = buildRequest(
      kind.group,
      step.verb,
      resourceInput({ segments: step.segments, ...(body === undefined ? {} : { body }) }),
    );
    const plan = await MutationPlan.create({
      renderer: gate.renderer,
      group: kind.group,
      spec,
      segments: step.segments,
      effective,
      identity,
      dryRun,
    });
    if (dryRun) {
      outputs.push(plan.dryRun());
      continue;
    }
    const report = await plan.send(runtime.client, { ...context, headers: identity.headers() });
    outputs.push(report.output);
    // A failed step aborts THIS resource and the whole run. Continuing would
    // apply the rest of a file whose earlier half is in an unknown state.
    if (report.failure !== undefined) throw report.failure;
    const response = report.output.receipt?.response;
    if (response !== undefined && response !== null) responses.push(response);
  }
  return outputs;
}

async function runApply(runtime: CliRuntime, args: Args): Promise<number> {
  const path = args.requireString("file");
  const dryRun = args.getBoolean("dry-run");
  const prune = args.getBoolean("prune");

  const source = path === "-" ? await runtime.io.readStdin() : await readDocument(runtime, path);
  const document = parseDesiredState(
    path === "-"
      ? decodeDesiredStateText("stdin.json", source, {})
      : decodeDesiredStateText(path, source, runtime.documentParsers ?? runtimeConfigTextParsers()),
  );

  const effective = await resolveEffective(runtime, args);
  const identity = ClientActionIdentity.mint(effective, runtime.io, fingerprintEnvFrom(runtime.io));
  const context = await requestContextFor(runtime, effective, identity);

  const reader: ServerReader = {
    read: async (group, verb, segments) => {
      const spec = buildRequest(group, verb, resourceInput({ segments }));
      const response = await sendAllPages(runtime, spec, context, identity, DEFAULT_PAGE_SIZE);
      return response.body;
    },
  };

  const { changes, kinds } = await buildPlan(document, reader, prune);
  const summary = planSummary(changes);
  const asJson = effective.output === "json";
  if (!asJson) runtime.io.stdout(`${renderPlan(changes)}\n`);

  const orphans = changes.filter((change) => change.action === "orphan");
  if (orphans.length > 0) {
    runtime.io.stderr(
      `note: ${orphans.length} resource(s) exist on the server and are absent from ${path}; ` +
        "they were KEPT. Pass --prune to delete them, or declare them in the file.\n",
    );
  }

  const doomed = changes.filter((change) => change.action === "delete");
  if (!dryRun)
    await confirmPrune(runtime, doomed, args.getBoolean("yes"), effective.nonInteractive);

  const applied: AppliedChange[] = [];
  for (const change of changes) {
    const kind = kinds.get(change.kind);
    if (kind === undefined) continue;
    const receipts = await applyChange(runtime, kind, change, effective, identity, context, dryRun);
    if (receipts.length > 0) applied.push({ change, receipts });
    if (receipts.length > 0 && !asJson) {
      runtime.io.stdout(
        `${dryRun ? "would apply" : "applied"} ${change.action} ${change.kind}/${change.id}\n`,
      );
    }
  }

  if (asJson) {
    runtime.io.stdout(
      `${renderJson({
        object: "apply_result",
        api_version: DESIRED_STATE_API_VERSION,
        dry_run: dryRun,
        prune,
        summary: summary as unknown as JsonValue,
        plan: changes as unknown as JsonValue,
        receipts: applied.flatMap((entry) =>
          entry.receipts.map((output) => output.receipt as unknown as JsonValue),
        ),
      })}\n`,
    );
  } else {
    runtime.io.stdout(
      `summary: ${dryRun ? "planned" : "applied"} ${summary.create} created, ` +
        `${summary.update} updated, ${summary.delete} deleted, ${summary.unchanged} unchanged, ` +
        `${summary.orphan} orphan\n`,
    );
  }
  return 0;
}

async function readDocument(runtime: CliRuntime, path: string): Promise<string> {
  if (!(await runtime.io.fileExists(path))) {
    throw CliError.usage(`desired-state file '${path}' does not exist`);
  }
  return runtime.io.readFile(path);
}

export const applyCommand: CommandNode = {
  name: "apply",
  about: "Converge the Control Plane onto a declarative desired-state file (GitOps)",
  flags: APPLY_FLAGS,
  run: async (runtime, args) => {
    try {
      return await runApply(runtime, args);
    } catch (error) {
      // A malformed or unhonourable DOCUMENT is a validation-class exit (5):
      // the operator typed a correct command and the file is wrong. Usage
      // errors (an unsupported kind, a missing --yes) stay class 2, and every
      // transport/server failure keeps whatever class `CliError` gave it.
      if (error instanceof DesiredStateError) {
        runtime.io.stderr(`error: ${error.message}\n`);
        return exitCode("validation");
      }
      throw error;
    }
  },
};
