/**
 * The pure half of `ferrogate apply` (#702): the desired-state document schema
 * and the diff/plan engine.
 *
 * These are the properties the CLI's end-to-end suite CANNOT isolate — it can
 * only observe them through requests that did or did not leave. Here they are
 * asserted directly, with no server anywhere.
 */
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
