/**
 * Reference-guarded deletes — the pure decision rule and its in-memory
 * reference backend (inventory §1.5.7, issue #328 finding 4).
 *
 * The durable proof lives in `test/d1/references-d1.test.ts`: this backend is
 * atomic because a single JS thread never yields mid-operation, which is a
 * reason D1 does not have. These tests pin the CONTRACT both backends expose.
 */
import { describe, expect, test } from "vitest";
import {
  MemoryReferenceGuardedDeletes,
  projectDeleteOutcomeFromCounts,
  workspaceDeleteOutcomeFromCounts,
} from "../src/index.js";

function store(): MemoryReferenceGuardedDeletes {
  const s = new MemoryReferenceGuardedDeletes();
  s.addProject({ id: "proj_1" });
  return s;
}

describe("the decision rule", () => {
  test("a missing project is not_found even when stale rows carry its id", () => {
    // Reporting `referenced` here would suggest a retry that can never work:
    // there is nothing to delete.
    expect(
      projectDeleteOutcomeFromCounts({ present: 0, workspaces: 3, virtualKeys: 2 }),
    ).toEqual({ kind: "not_found" });
  });

  test("either kind of reference blocks, and both counts are reported", () => {
    expect(
      projectDeleteOutcomeFromCounts({ present: 1, workspaces: 2, virtualKeys: 0 }),
    ).toEqual({ kind: "referenced", workspaces: 2, virtualKeys: 0 });
    expect(
      projectDeleteOutcomeFromCounts({ present: 1, workspaces: 0, virtualKeys: 5 }),
    ).toEqual({ kind: "referenced", workspaces: 0, virtualKeys: 5 });
    expect(
      projectDeleteOutcomeFromCounts({ present: 1, workspaces: 2, virtualKeys: 5 }),
    ).toEqual({ kind: "referenced", workspaces: 2, virtualKeys: 5 });
  });

  test("only a present, unreferenced project is deletable", () => {
    expect(
      projectDeleteOutcomeFromCounts({ present: 1, workspaces: 0, virtualKeys: 0 }),
    ).toEqual({ kind: "deleted" });
  });

  test("a workspace is blocked by virtual keys alone", () => {
    expect(workspaceDeleteOutcomeFromCounts({ present: 0, virtualKeys: 0 })).toEqual({
      kind: "not_found",
    });
    expect(workspaceDeleteOutcomeFromCounts({ present: 1, virtualKeys: 1 })).toEqual({
      kind: "referenced",
      virtualKeys: 1,
    });
    expect(workspaceDeleteOutcomeFromCounts({ present: 1, virtualKeys: 0 })).toEqual({
      kind: "deleted",
    });
  });
});

describe("MemoryReferenceGuardedDeletes — projects", () => {
  test("an unreferenced project is deleted and really removed", () => {
    const s = store();
    expect(s.deleteProjectIfUnreferenced("proj_1")).toEqual({ kind: "deleted" });
    expect(s.hasProject("proj_1")).toBe(false);
  });

  test("a workspace reference REFUSES and LEAVES THE PROJECT IN PLACE", () => {
    const s = store();
    s.addWorkspace({ id: "ws_1", projectId: "proj_1" });
    expect(s.deleteProjectIfUnreferenced("proj_1")).toEqual({
      kind: "referenced",
      workspaces: 1,
      virtualKeys: 0,
    });
    // The refusal is only meaningful if the row survived it: a "referenced"
    // outcome that still deleted would orphan the workspace.
    expect(s.hasProject("proj_1")).toBe(true);
  });

  test("a virtual-key reference refuses too, and the counts are separate", () => {
    const s = store();
    s.addWorkspace({ id: "ws_1", projectId: "proj_1" });
    s.addApiKey({ id: "key_1", projectId: "proj_1", workspaceId: "ws_1" });
    s.addApiKey({ id: "key_2", projectId: "proj_1", workspaceId: "ws_1" });
    expect(s.deleteProjectIfUnreferenced("proj_1")).toEqual({
      kind: "referenced",
      workspaces: 1,
      virtualKeys: 2,
    });
  });

  test("references to a DIFFERENT project do not block", () => {
    const s = store();
    s.addProject({ id: "proj_2" });
    s.addWorkspace({ id: "ws_other", projectId: "proj_2" });
    s.addApiKey({ id: "key_other", projectId: "proj_2", workspaceId: "ws_other" });
    expect(s.deleteProjectIfUnreferenced("proj_1")).toEqual({ kind: "deleted" });
    expect(s.hasProject("proj_2")).toBe(true);
  });

  test("an unknown id is not_found, and a second delete of the same id is too", () => {
    const s = store();
    expect(s.deleteProjectIfUnreferenced("nope")).toEqual({ kind: "not_found" });
    expect(s.deleteProjectIfUnreferenced("proj_1")).toEqual({ kind: "deleted" });
    expect(s.deleteProjectIfUnreferenced("proj_1")).toEqual({ kind: "not_found" });
  });

  test("removing the last reference makes the delete succeed", () => {
    const s = store();
    s.addWorkspace({ id: "ws_1", projectId: "proj_1" });
    expect(s.deleteProjectIfUnreferenced("proj_1").kind).toBe("referenced");
    expect(s.deleteWorkspaceIfUnreferenced("ws_1")).toEqual({ kind: "deleted" });
    expect(s.deleteProjectIfUnreferenced("proj_1")).toEqual({ kind: "deleted" });
  });
});

describe("MemoryReferenceGuardedDeletes — workspaces", () => {
  test("a key in the workspace refuses the delete and keeps the row", () => {
    const s = store();
    s.addWorkspace({ id: "ws_1", projectId: "proj_1" });
    s.addApiKey({ id: "key_1", projectId: "proj_1", workspaceId: "ws_1" });
    expect(s.deleteWorkspaceIfUnreferenced("ws_1")).toEqual({
      kind: "referenced",
      virtualKeys: 1,
    });
    expect(s.hasWorkspace("ws_1")).toBe(true);
  });

  test("a key in a SIBLING workspace does not block", () => {
    const s = store();
    s.addWorkspace({ id: "ws_1", projectId: "proj_1" });
    s.addWorkspace({ id: "ws_2", projectId: "proj_1" });
    s.addApiKey({ id: "key_1", projectId: "proj_1", workspaceId: "ws_2" });
    expect(s.deleteWorkspaceIfUnreferenced("ws_1")).toEqual({ kind: "deleted" });
    expect(s.hasWorkspace("ws_2")).toBe(true);
  });
});
