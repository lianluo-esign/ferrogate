/**
 * The declarative ("GitOps") desired-state document and the pure plan engine
 * that diffs it against what a control plane currently holds — issue #702.
 *
 * Guardrail revisions and quota policies were API-driven only: there was no
 * "check this file in, diff it in CI, apply it". Kong decK, Envoy CRDs and
 * APISIX YAML all offer that, and an enterprise platform team expects it.
 *
 * This module is the SCHEMA and the DIFF, and nothing else. It performs no I/O,
 * knows no HTTP verb and holds no resource table: `apps/cli`'s `apply` command
 * owns the transport, the per-kind request builders and the mutation receipts.
 * Splitting it that way is what lets the interesting half — "given desired and
 * actual, what changes, and is applying twice really a no-op?" — be tested with
 * no server at all.
 *
 * ## Why a partial document still yields a full-replace plan
 *
 * A desired-state entry declares the fields the operator owns. The server adds
 * bookkeeping the operator never wrote (`id`, `tenant_id`, revision counters,
 * timestamps). The diff therefore compares the desired record against the
 * actual record with a per-kind {@link ResourceKindShape.serverManaged} field
 * list removed — so bookkeeping never shows up as drift, and a field the
 * operator DELETED from the file shows up as a removal rather than being
 * silently kept. That is the property that makes the file the source of truth
 * instead of a suggestion.
 *
 * The mirror image of that is {@link ResourceKindShape.normalizeDesired}: where
 * the server's own write schema FILLS a field the file omitted, the file is
 * compared after running that schema, so a default the server supplies is not
 * mistaken for a field the operator deleted. Without it, a family with schema
 * defaults writes on every single apply.
 */
import { z } from "zod";

/**
 * The one accepted `apiVersion`.
 *
 * `v1alpha1` and not `v1`: the resource-kind table below is deliberately small
 * (it covers only families whose write operations actually exist in the
 * contract), and pinning the version means a future widening cannot be mistaken
 * for the current one by a file that was written against this shape.
 */
export const DESIRED_STATE_API_VERSION = "ferrogate.io/v1alpha1";

/** The one accepted `kind` of the document itself (not of a resource in it). */
export const DESIRED_STATE_KIND = "DesiredState";

/** A JSON-ish scalar or container as it appears in a resource record. */
export type DesiredValue =
  | string
  | number
  | boolean
  | null
  | readonly DesiredValue[]
  | { readonly [key: string]: DesiredValue };

/** One declared resource: an untyped bag of fields the per-kind shape validates. */
export type DesiredRecord = Readonly<Record<string, DesiredValue>>;

const desiredValueSchema: z.ZodType<DesiredValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(desiredValueSchema),
    z.record(desiredValueSchema),
  ]),
);

/**
 * The document schema.
 *
 * `.strict()` at the top level on purpose: a misspelled `resource:` key that
 * silently applied nothing would be the worst possible failure for a file whose
 * entire job is to be the source of truth.
 */
export const desiredStateSchema = z
  .object({
    apiVersion: z.literal(DESIRED_STATE_API_VERSION),
    kind: z.literal(DESIRED_STATE_KIND),
    resources: z.record(z.string(), z.array(z.record(desiredValueSchema))).default({}),
  })
  .strict();

export type DesiredState = z.infer<typeof desiredStateSchema>;

/** A refusal carrying the operator-facing reason; the caller maps it to an exit class. */
export class DesiredStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DesiredStateError";
  }
}

/**
 * Parse an already-decoded document (JSON/YAML/TOML text is decoded by the
 * caller, which owns the runtime's parsers).
 *
 * Every failure is reported with the Zod path, because "your file is wrong" is
 * useless for a 400-line inventory.
 */
export function parseDesiredState(raw: unknown): DesiredState {
  const parsed = desiredStateSchema.safeParse(raw);
  if (parsed.success) return parsed.data;
  const detail = parsed.error.issues
    .map(
      (issue) => `${issue.path.length === 0 ? "(root)" : issue.path.join(".")}: ${issue.message}`,
    )
    .join("; ");
  throw new DesiredStateError(`not a ${DESIRED_STATE_KIND} document: ${detail}`);
}

// ---------------------------------------------------------------------------
// Per-kind shape
// ---------------------------------------------------------------------------

/**
 * What the diff needs to know about ONE resource family. Everything that is
 * transport (paths, verbs, receipts) stays out of this module.
 */
export interface ResourceKindShape {
  /** The document key, e.g. `quota-policies`. */
  readonly kind: string;
  /**
   * The natural key of a record, or a refusal message when the record does not
   * carry one. Returning the reason rather than throwing keeps the refusal
   * attributable to a specific entry.
   */
  identity(record: DesiredRecord): { readonly id: string } | { readonly error: string };
  /**
   * Fields the SERVER owns. They are stripped from both sides before
   * comparison, so bookkeeping never reads as operator drift.
   */
  readonly serverManaged: readonly string[];
  /**
   * Fill in what the SERVER'S OWN SCHEMA would fill in, so the record the file
   * declares is compared against the record the server will actually hold.
   *
   * This is not a convenience: without it a family whose write schema has
   * defaults is **not idempotent**. The server stores the parsed record, so an
   * omitted field comes back set; {@link diffFields} sees a field the server has
   * and the file has not, which is a REMOVAL by construction — and every apply
   * of an unchanged file therefore writes. For an append-only family like
   * guardrail revisions that means a new revision, and an activation, per CI
   * run.
   *
   * Stripping the defaulted names via {@link serverManaged} would be the wrong
   * cure twice over: it goes blind to a field the operator really did change,
   * it cannot reach defaults NESTED inside an array element (a check binding's
   * `enabled`/`sources`), and it is a hand-written list that silently rots the
   * next time a default is added. Running the real schema is derivation, so
   * there is nothing to keep in sync.
   *
   * MUST be total: a record the schema rejects is returned unchanged, because
   * the server — not this diff — is the authority on what it refuses, and a
   * plan is not the place to relitigate admission.
   *
   * Comparison only. The request body stays exactly as the operator wrote it,
   * so a CLI whose idea of the defaults has drifted from the deployment's
   * cannot freeze its own version of them into the stored record.
   */
  normalizeDesired?(record: DesiredRecord): DesiredRecord;
}

/** How one field differs between the file and the server. */
export interface FieldChange {
  readonly field: string;
  /** Absent when the field does not exist on the server yet. */
  readonly from?: DesiredValue;
  /** Absent when the file no longer declares the field. */
  readonly to?: DesiredValue;
}

/** What `apply` intends to do with one resource. */
export type ChangeAction = "create" | "update" | "delete" | "unchanged" | "orphan";

export interface PlannedChange {
  readonly kind: string;
  readonly id: string;
  readonly action: ChangeAction;
  /** Empty for `unchanged`; the full field-level diff otherwise. */
  readonly fields: readonly FieldChange[];
  /** The desired record, when the file declares one. */
  readonly desired?: DesiredRecord;
  /** The record the server currently holds, when it has one. */
  readonly actual?: DesiredRecord;
}

/** Counts per action, for the one-line summary and the exit decision. */
export type PlanSummary = Readonly<Record<ChangeAction, number>>;

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

/**
 * Structural equality with ORDER-INSENSITIVE object keys and order-SENSITIVE
 * arrays.
 *
 * Arrays stay ordered because every ordered thing in this tree is ordered on
 * purpose — a guardrail policy's `checks` run in sequence, so reordering them
 * is a real change, not a formatting one. Treating them as sets here would make
 * `apply` report `unchanged` for a policy whose evaluation order the operator
 * had just rewritten.
 */
export function valuesEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (left === null || right === null) return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right)) return false;
    return left.length === right.length && left.every((item, i) => valuesEqual(item, right[i]));
  }
  if (typeof left !== "object" || typeof right !== "object") return false;
  const a = left as Record<string, unknown>;
  const b = right as Record<string, unknown>;
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const key of keys) {
    if (!valuesEqual(a[key], b[key])) return false;
  }
  return true;
}

/** Drop the fields the server owns, so only operator-authored state is compared. */
export function comparableFields(
  record: DesiredRecord,
  serverManaged: readonly string[],
): Record<string, DesiredValue> {
  const managed = new Set(serverManaged);
  const out: Record<string, DesiredValue> = {};
  for (const [key, value] of Object.entries(record)) {
    if (!managed.has(key)) out[key] = value;
  }
  return out;
}

/**
 * The field-level diff, sorted by field name so two runs of `--dry-run` over
 * the same inputs produce byte-identical output (a diff you cannot compare
 * across CI runs is not a diff).
 */
export function diffFields(
  desired: DesiredRecord,
  actual: DesiredRecord,
  serverManaged: readonly string[],
): readonly FieldChange[] {
  const left = comparableFields(desired, serverManaged);
  const right = comparableFields(actual, serverManaged);
  const changes: FieldChange[] = [];
  for (const field of [...new Set([...Object.keys(left), ...Object.keys(right)])].sort()) {
    const to = left[field];
    const from = right[field];
    if (field in left && field in right) {
      if (!valuesEqual(to, from)) changes.push({ field, from, to });
      continue;
    }
    changes.push(field in left ? { field, to } : { field, from });
  }
  return changes;
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

export interface PlanKindInput {
  readonly shape: ResourceKindShape;
  readonly desired: readonly DesiredRecord[];
  readonly actual: readonly DesiredRecord[];
  /**
   * Whether a server-only resource is planned for deletion.
   *
   * This is THE dangerous knob and it is deliberately not a default. With
   * `prune: false` a resource that exists on the server and is absent from the
   * file is planned as `orphan`: reported by name, left alone. Deleting it
   * silently is how production config disappears; omitting it from the report
   * entirely would make the file a lie about what the deployment contains.
   */
  readonly prune: boolean;
}

/**
 * Diff one resource family. Pure, total, and independent of every other family.
 *
 * Output order is: the desired entries in FILE order (so the plan reads like
 * the document the operator wrote), then the server-only entries sorted by id
 * (which have no file order to preserve).
 */
export function planKind(input: PlanKindInput): readonly PlannedChange[] {
  const { shape, prune } = input;

  const actualById = new Map<string, DesiredRecord>();
  for (const record of input.actual) {
    const identity = shape.identity(record);
    // A server record we cannot key is skipped rather than fatal: the file is
    // authoritative for what it declares, and an unkeyable row on the server is
    // not something this document can be asked to reconcile. It is surfaced as
    // an orphan only if it HAS an id, which by definition it does not.
    if ("id" in identity) actualById.set(identity.id, record);
  }

  const changes: PlannedChange[] = [];
  const claimed = new Set<string>();

  for (const record of input.desired) {
    const identity = shape.identity(record);
    if ("error" in identity) throw new DesiredStateError(`${shape.kind}: ${identity.error}`);
    const { id } = identity;
    if (claimed.has(id)) {
      throw new DesiredStateError(
        `${shape.kind}: '${id}' is declared twice in the same document; a desired state ` +
          "cannot name one resource two ways",
      );
    }
    claimed.add(id);

    // Compare what the server WILL hold, not the shorthand the file carries:
    // see {@link ResourceKindShape.normalizeDesired}. `desired` below stays the
    // authored record, because that is what gets sent.
    const comparable = shape.normalizeDesired?.(record) ?? record;

    const actual = actualById.get(id);
    if (actual === undefined) {
      changes.push({
        kind: shape.kind,
        id,
        action: "create",
        fields: diffFields(comparable, {}, shape.serverManaged),
        desired: record,
      });
      continue;
    }
    const fields = diffFields(comparable, actual, shape.serverManaged);
    changes.push({
      kind: shape.kind,
      id,
      action: fields.length === 0 ? "unchanged" : "update",
      fields,
      desired: record,
      actual,
    });
  }

  for (const id of [...actualById.keys()].sort()) {
    if (claimed.has(id)) continue;
    const actual = actualById.get(id) as DesiredRecord;
    changes.push({
      kind: shape.kind,
      id,
      action: prune ? "delete" : "orphan",
      fields: prune ? diffFields({}, actual, shape.serverManaged) : [],
      actual,
    });
  }

  return changes;
}

/** Tally a plan. Every action key is always present, so a caller cannot read `undefined` as zero. */
export function planSummary(changes: readonly PlannedChange[]): PlanSummary {
  const summary: Record<ChangeAction, number> = {
    create: 0,
    update: 0,
    delete: 0,
    unchanged: 0,
    orphan: 0,
  };
  for (const change of changes) summary[change.action] += 1;
  return summary;
}

/** Whether the plan asks for any server-changing work at all. */
export function planIsNoop(changes: readonly PlannedChange[]): boolean {
  return changes.every((change) => change.action === "unchanged" || change.action === "orphan");
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderValue(value: DesiredValue | undefined): string {
  if (value === undefined) return "(absent)";
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** One `<action> <kind>/<id>` heading plus an indented line per changed field. */
export function renderChange(change: PlannedChange): string {
  const lines = [`${change.action} ${change.kind}/${change.id}`];
  for (const field of change.fields) {
    if (field.from === undefined) lines.push(`  + ${field.field}: ${renderValue(field.to)}`);
    else if (field.to === undefined) lines.push(`  - ${field.field}: ${renderValue(field.from)}`);
    else lines.push(`  ~ ${field.field}: ${renderValue(field.from)} -> ${renderValue(field.to)}`);
  }
  return lines.join("\n");
}

/** The whole plan as text, ending in the one-line tally. */
export function renderPlan(changes: readonly PlannedChange[]): string {
  const summary = planSummary(changes);
  const body = changes.map(renderChange);
  const tally =
    `plan: ${summary.create} to create, ${summary.update} to update, ` +
    `${summary.delete} to delete, ${summary.unchanged} unchanged, ${summary.orphan} orphan`;
  return [...body, tally].join("\n");
}
