import { describe, expect, test } from "vitest";
import { main } from "../src/index.js";
import {
  Table,
  cursorOffsetRefusal,
  renderJson,
  renderOutput,
  renderTable,
  truncationNotice,
} from "../src/output.js";
import { mergePages, nextPage, pageCursorState, pageEnvelope } from "../src/paging.js";
import { createTestRuntime, ok } from "./helpers.js";

describe("table rendering", () => {
  test("an array of objects becomes a column table with uppercase headers", () => {
    const rendered = renderTable([
      { id: "a", name: "one" },
      { id: "b", name: "two" },
    ]);
    expect(rendered.split("\n")[0]).toContain("ID");
    expect(rendered).toContain("one");
  });

  test("a union of keys is used, with '-' for missing cells", () => {
    const rendered = renderTable([{ id: "a" }, { id: "b", extra: "x" }]);
    expect(rendered).toContain("EXTRA");
    expect(rendered).toContain("-");
  });

  test("a list envelope renders items then the metadata block", () => {
    const rendered = renderTable({ data: [{ id: "a" }], total: 1, limit: 10 });
    expect(rendered).toContain("ID");
    expect(rendered).toContain("total");
  });

  test("an empty list says so instead of rendering a bare header", () => {
    expect(renderTable([])).toBe("(no results)");
    expect(renderTable(null)).toBe("(empty)");
  });

  test("a mismatched row count is a usage error, not a ragged table", () => {
    expect(() => Table.create(["A", "B"], [["only-one"]])).toThrowError(/has 1 columns/);
  });
});

describe("json rendering", () => {
  test("renderJson is stable, indented JSON", () => {
    expect(renderJson({ b: 1, a: 2 })).toBe('{\n  "b": 1,\n  "a": 2\n}');
  });

  test("renderOutput refuses an output carrying neither body nor receipt", () => {
    expect(() => renderOutput("json", {})).toThrowError(/neither a body nor a receipt/);
  });
});

describe("page envelope introspection", () => {
  test("a bare array is a page with no window", () => {
    expect(pageEnvelope([1, 2])?.items).toHaveLength(2);
  });

  test("a data envelope exposes total/limit/offset", () => {
    const envelope = pageEnvelope({ data: [1], total: 5, limit: 1, offset: 2 });
    expect(envelope).toMatchObject({ total: 5, limit: 1, offset: 2, cursor: false });
  });

  test("any cursor key marks the endpoint as cursor-paginated", () => {
    expect(pageEnvelope({ data: [], next_cursor: "x" })?.cursor).toBe(true);
    expect(pageEnvelope({ data: [], has_more: false })?.cursor).toBe(true);
  });

  test("a non-list body is not a page", () => {
    expect(pageEnvelope({ id: "x" })).toBeUndefined();
  });

  test("cursor state distinguishes resume, exhausted, and unknown", () => {
    expect(pageCursorState({ next_cursor: "c" })).toEqual({
      kind: "resume",
      key: "next_cursor",
      value: "c",
    });
    expect(pageCursorState({ has_more: false, next_cursor: "c" })).toEqual({ kind: "exhausted" });
    expect(pageCursorState({ next_cursor: null })).toEqual({ kind: "exhausted" });
    expect(pageCursorState({ has_more: true })).toEqual({ kind: "unknown" });
    expect(pageCursorState({ data: [] })).toBeUndefined();
  });

  test("nextPage stops at the total and on a short page", () => {
    expect(nextPage({ offset: 0, limit: 2 }, 2, 4)).toEqual({ offset: 2, limit: 2 });
    expect(nextPage({ offset: 2, limit: 2 }, 2, 4)).toBeUndefined();
    expect(nextPage({ offset: 0, limit: 5 }, 3, undefined)).toBeUndefined();
    expect(nextPage({ offset: 0, limit: 5 }, 0, undefined)).toBeUndefined();
  });

  test("merged pages drop the stale window so they cannot read as page one", () => {
    const merged = mergePages(
      { data: [1], total: 3, offset: 0, limit: 1, next_cursor: "x" },
      "data",
      [1, 2, 3],
    ) as Record<string, unknown>;
    expect(merged.data).toEqual([1, 2, 3]);
    expect(merged.offset).toBeUndefined();
    expect(merged.limit).toBeUndefined();
    expect(merged.next_cursor).toBeUndefined();
    expect(merged.total).toBe(3);
  });
});

describe("honesty notices", () => {
  test("no notice when the page is complete", () => {
    expect(truncationNotice({ data: [1, 2], total: 2 }, 0, undefined)).toBeUndefined();
  });

  test("a full page with no total warns that more may exist", () => {
    expect(truncationNotice({ data: [1, 2] }, 0, 2)).toContain("more rows may exist");
  });

  test("a cursor endpoint with no continuation either way is reported honestly", () => {
    expect(truncationNotice({ data: [1], has_more: true }, 0, undefined)).toContain(
      "reported no continuation either way",
    );
  });

  test("an exhausted cursor produces no notice", () => {
    expect(truncationNotice({ data: [1], has_more: false }, 0, undefined)).toBeUndefined();
  });

  test("cursorOffsetRefusal only fires for a non-zero offset on a cursor body", () => {
    expect(cursorOffsetRefusal({ data: [], next_cursor: "c" }, 0, "/p")).toBeUndefined();
    expect(cursorOffsetRefusal({ data: [], total: 1 }, 5, "/p")).toBeUndefined();
    expect(cursorOffsetRefusal({ data: [], next_cursor: "c" }, 5, "/p")).toContain("page ONE");
  });
});

describe("--json output shape", () => {
  test("a read's --output json is exactly the server document", async () => {
    const body = { data: [{ id: "p1", nested: { deep: true } }], total: 1 };
    const runtime = createTestRuntime({
      env: { TOK: "t" },
      store: {
        contexts: [
          {
            name: "c",
            endpoint: "https://x",
            tlsInsecureSkipVerify: false,
            auth: { kind: "env", var: "TOK" },
          },
        ],
        current: "c",
      },
      script: { "GET /admin/v1/projects": ok(body) },
    });
    await main(["ctl", "projects", "list", "--output", "json"], runtime);
    expect(JSON.parse(runtime.stdout())).toEqual(body);
  });

  test("a mutation's --output json is a receipt with the documented top-level keys", async () => {
    const runtime = createTestRuntime({
      env: { TOK: "t" },
      store: {
        contexts: [
          {
            name: "c",
            endpoint: "https://x",
            tlsInsecureSkipVerify: false,
            auth: { kind: "env", var: "TOK" },
          },
        ],
        current: "c",
      },
      script: { "POST /admin/v1/projects": ok({ id: "p1" }) },
    });
    await main(["ctl", "projects", "create", "--data", "{}", "--output", "json"], runtime);
    const receipt = JSON.parse(runtime.stdout());
    expect(Object.keys(receipt).sort()).toEqual(
      [
        "actor",
        "approval_id",
        "audit_id",
        "client_identity",
        "correlation",
        "decision",
        "dry_run",
        "failure",
        "group",
        "http_status",
        "idempotency_key",
        "object",
        "operation_id",
        "outcome",
        "receipt_version",
        "response",
        "rollback",
        "target",
        "verb",
      ].sort(),
    );
  });

  test("the default (table) rendering of a receipt is field/value rows", async () => {
    const runtime = createTestRuntime({
      env: { TOK: "t" },
      store: {
        contexts: [
          {
            name: "c",
            endpoint: "https://x",
            tlsInsecureSkipVerify: false,
            auth: { kind: "env", var: "TOK" },
          },
        ],
        current: "c",
      },
      script: { "POST /admin/v1/projects": ok({ id: "p1" }) },
    });
    await main(["ctl", "projects", "create", "--data", "{}"], runtime);
    expect(runtime.stdout()).toContain("FIELD");
    expect(runtime.stdout()).toContain("mutation_receipt");
    expect(runtime.stdout()).toContain("target.action_fingerprint");
  });
});
