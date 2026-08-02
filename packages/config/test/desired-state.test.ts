/**
 * The pure half of `ferrogate apply` (#702): the desired-state document schema
 * and the diff/plan engine.
 *
 * These are the properties the CLI's end-to-end suite CANNOT isolate — it can
 * only observe them through requests that did or did not leave. Here they are
 * asserted directly, with no server anywhere.
 */
import { policyRevisionSchema } from "@ferrogate/guardrails";
import { describe, expect, test } from "vitest";
import {
  DESIRED_STATE_API_VERSION,
  type DesiredRecord,
  DesiredStateError,
  type ResourceKindShape,
  diffFields,
  parseDesiredState,
  planIsNoop,
  planKind,
  planSummary,
  renderPlan,
  valuesEqual,
} from "../src/desired-state.js";

/** An id-keyed family with two server-owned fields. */
const SHAPE: ResourceKindShape = {
  kind: "widgets",
  serverManaged: ["id", "created_at"],
  identity: (record) =>
    typeof record.name === "string" && record.name.trim() !== ""
      ? { id: record.name.trim() }
      : { error: "every entry needs a name" },
};

const plan = (desired: DesiredRecord[], actual: DesiredRecord[], prune = false) =>
  planKind({ shape: SHAPE, desired, actual, prune });

describe("the document schema", () => {
  test("a well-formed document round-trips", () => {
    const parsed = parseDesiredState({
      apiVersion: DESIRED_STATE_API_VERSION,
      kind: "DesiredState",
      resources: { widgets: [{ name: "a" }] },
    });
    expect(parsed.resources.widgets).toEqual([{ name: "a" }]);
  });

  test("an unknown apiVersion is refused, not coerced", () => {
    expect(() =>
      parseDesiredState({ apiVersion: "ferrogate.io/v99", kind: "DesiredState", resources: {} }),
    ).toThrow(DesiredStateError);
  });

  test("an unknown top-level key is refused rather than ignored", () => {
    // A misspelled `resource:` that silently applied nothing would be the worst
    // possible failure for a file whose entire job is to be the source of truth.
    expect(() =>
      parseDesiredState({
        apiVersion: DESIRED_STATE_API_VERSION,
        kind: "DesiredState",
        resource: { widgets: [] },
      }),
    ).toThrow(/resource/);
  });

  test("the failure names the offending path", () => {
    try {
      parseDesiredState({
        apiVersion: DESIRED_STATE_API_VERSION,
        kind: "DesiredState",
        resources: { widgets: "not-a-list" },
      });
      throw new Error("expected a refusal");
    } catch (error) {
      expect((error as Error).message).toContain("resources.widgets");
    }
  });
});

describe("comparison", () => {
  test("object key order is irrelevant but ARRAY order is not", () => {
    expect(valuesEqual({ a: 1, b: 2 }, { b: 2, a: 1 })).toBe(true);
    // A guardrail policy's checks run in sequence, so a reorder is a real
    // change. Treating arrays as sets would report `unchanged` for a policy
    // whose evaluation order had just been rewritten.
    expect(valuesEqual([1, 2], [2, 1])).toBe(false);
  });

  test("server-managed fields are invisible to the diff on BOTH sides", () => {
    const changes = diffFields(
      { name: "a", size: 1 },
      { name: "a", size: 1, id: "srv-1", created_at: 1700 },
      SHAPE.serverManaged,
    );
    expect(changes).toEqual([]);
  });

  test("a field the file dropped is reported as a removal", () => {
    const changes = diffFields({ name: "a" }, { name: "a", size: 9 }, SHAPE.serverManaged);
    expect(changes).toEqual([{ field: "size", from: 9 }]);
  });

  test("changed fields carry both sides and come out sorted", () => {
    const changes = diffFields(
      { name: "a", z: 2, b: 3 },
      { name: "a", z: 1, b: 3 },
      SHAPE.serverManaged,
    );
    expect(changes).toEqual([{ field: "z", from: 1, to: 2 }]);
  });
});

describe("planning", () => {
  test("absent on the server is a create; identical is unchanged", () => {
    const changes = plan([{ name: "a", size: 1 }], [{ name: "a", size: 1, id: "x" }]);
    expect(changes.map((change) => change.action)).toEqual(["unchanged"]);
    expect(planIsNoop(changes)).toBe(true);

    const fresh = plan([{ name: "b" }], []);
    expect(fresh[0]?.action).toBe("create");
    expect(planIsNoop(fresh)).toBe(false);
  });

  test("a server-only resource is an ORPHAN by default and a DELETE only with prune", () => {
    const kept = plan([{ name: "a" }], [{ name: "a" }, { name: "legacy", id: "l" }]);
    expect(kept.map((change) => `${change.action} ${change.id}`)).toEqual([
      "unchanged a",
      "orphan legacy",
    ]);
    // An orphan is NOT server-changing work: the run converges and exits 0.
    expect(planIsNoop(kept)).toBe(true);

    const pruned = plan([{ name: "a" }], [{ name: "a" }, { name: "legacy", id: "l" }], true);
    expect(pruned[1]?.action).toBe("delete");
    expect(planIsNoop(pruned)).toBe(false);
  });

  test("declaring one resource twice is refused", () => {
    expect(() => plan([{ name: "a" }, { name: "a" }], [])).toThrow(DesiredStateError);
  });

  test("an entry with no identity is refused before any change is planned", () => {
    expect(() => plan([{ size: 1 }], [])).toThrow(/needs a name/);
  });

  test("desired entries keep FILE order; orphans are sorted", () => {
    const changes = plan(
      [{ name: "z" }, { name: "a" }],
      [{ name: "z" }, { name: "a" }, { name: "m2" }, { name: "m1" }],
      true,
    );
    expect(changes.map((change) => change.id)).toEqual(["z", "a", "m1", "m2"]);
  });

  test("planning is idempotent against the state a previous plan described", () => {
    // The engine-level statement of the CLI's end-to-end idempotence test: feed
    // the create's own desired record back as the server's state.
    const first = plan([{ name: "a", size: 1 }], []);
    expect(first[0]?.action).toBe("create");
    const converged = [{ ...(first[0]?.desired as DesiredRecord), id: "server-minted" }];
    const second = plan([{ name: "a", size: 1 }], converged);
    expect(second.map((change) => change.action)).toEqual(["unchanged"]);
  });
});

describe("rendering", () => {
  test("every action and every field lands in the text, with a tally", () => {
    const changes = plan(
      [{ name: "new", size: 1 }, { name: "same" }, { name: "changed", size: 2 }],
      [{ name: "same" }, { name: "changed", size: 1, extra: true }, { name: "gone" }],
      true,
    );
    const text = renderPlan(changes);
    expect(text).toContain("create widgets/new");
    expect(text).toContain("  + size: 1");
    expect(text).toContain("unchanged widgets/same");
    expect(text).toContain("update widgets/changed");
    expect(text).toContain("  ~ size: 1 -> 2");
    expect(text).toContain("  - extra: true");
    expect(text).toContain("delete widgets/gone");
    expect(text).toContain("plan: 1 to create, 1 to update, 1 to delete, 1 unchanged, 0 orphan");
    expect(planSummary(changes)).toEqual({
      create: 1,
      update: 1,
      delete: 1,
      unchanged: 1,
      orphan: 0,
    });
  });

  test("the rendered plan is byte-stable across runs over the same inputs", () => {
    const inputs: [DesiredRecord[], DesiredRecord[]] = [
      [{ name: "a", z: 1, b: 2 }],
      [{ name: "a", b: 9, z: 9 }],
    ];
    expect(renderPlan(plan(...inputs))).toBe(renderPlan(plan(...inputs)));
  });
});

describe("a server whose write schema FILLS defaults", () => {
  // The real thing: `policyRevisionSchema` is what `apps/control-plane`'s
  // `admitRevision` runs on every guardrail write, and the control plane stores
  // its OUTPUT. Six top-level fields are defaulted there, plus two inside each
  // check binding. Nothing here is a stand-in.
  const DECLARED: DesiredRecord = {
    policy_id: "pii",
    name: "pii-redaction",
    enforced: true,
    checks: [{ id: "ssn", stage: "request", detector: { kind: "local", regex: ["\\d{3}"] } }],
    on_pass: [{ kind: "allow" }],
    on_fail: [{ kind: "block", code: "pii", message: "no" }],
    on_error: [{ kind: "allow" }],
  };
  /** What the server holds after admitting {@link DECLARED}. */
  const STORED = policyRevisionSchema.parse({
    ...DECLARED,
    revision: 1,
    created_by: "operator",
    created_at_unix: 1,
  }) as unknown as DesiredRecord;

  const SERVER_OWNED = ["revision", "created_by", "created_at_unix"];
  const shapeOf = (normalize: boolean): ResourceKindShape => ({
    kind: "guardrail-policies",
    serverManaged: SERVER_OWNED,
    identity: (record) => ({ id: String(record.policy_id) }),
    normalizeDesired: normalize
      ? (record) => {
          const parsed = policyRevisionSchema.safeParse(record);
          return parsed.success ? (parsed.data as unknown as DesiredRecord) : record;
        }
      : undefined,
  });

  test("without normalization an UNCHANGED file diffs to phantom removals", () => {
    // The defect, stated. Every one of these would be a write — and for an
    // append-only family, a new revision and a new ACTIVATION — per apply.
    const changes = planKind({
      shape: shapeOf(false),
      desired: [DECLARED],
      actual: [STORED],
      prune: false,
    });
    expect(changes[0]?.action).toBe("update");
    expect(changes[0]?.fields.map((field) => field.field)).toEqual([
      "aggregation",
      "checks",
      "deadline_ms",
      "execution",
      "mode",
      "scope",
      "streaming",
    ]);
    // …and `checks` is there because of defaults NESTED in an array element,
    // which no list of top-level server-managed names could ever have reached.
    const check = changes[0]?.fields.find((field) => field.field === "checks");
    expect(check?.from).not.toEqual(check?.to);
  });

  test("with normalization the same pair is unchanged, and a real edit still shows", () => {
    const shape = shapeOf(true);
    expect(
      planKind({ shape, desired: [DECLARED], actual: [STORED], prune: false }).map((c) => c.action),
    ).toEqual(["unchanged"]);

    // Normalization must not blind the diff: a field the operator actually
    // changed — including one the schema also has a default for — still reads
    // as drift.
    const edited = { ...DECLARED, enforced: false, mode: "shadow" };
    const fields = planKind({
      shape,
      desired: [edited],
      actual: [STORED],
      prune: false,
    })[0];
    expect(fields?.action).toBe("update");
    expect(fields?.fields.map((field) => field.field)).toEqual(["enforced", "mode"]);
  });

  test("a record the server's schema REFUSES is planned on unchanged, not rewritten", () => {
    // The planner is not a second validator: an inadmissible record is passed
    // through as authored so the CONTROL PLANE gets to refuse it, with its own
    // message.
    const nonsense: DesiredRecord = { policy_id: "pii", name: 7 as unknown as string };
    const changes = planKind({
      shape: shapeOf(true),
      desired: [nonsense],
      actual: [],
      prune: false,
    });
    expect(changes[0]?.action).toBe("create");
    expect(changes[0]?.fields.map((field) => field.field)).toEqual(["name", "policy_id"]);
  });
});
