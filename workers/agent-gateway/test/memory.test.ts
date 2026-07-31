// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Worker-side tests for the agent memory surface (issue #427). Two layers,
//   deliberately: pure-function unit tests against a fake AgentMemoryHost — the seam
//   memory.ts justifies on the grounds that it makes the verbs testable without a Durable
//   Object — and route-level E2E against the REAL Worker booted in workerd, which is what
//   proves the governance guards actually hold on the deployed artifact rather than on a
//   stand-in. No Docker, no Cloudflare account, no network.
//
//   The guards under test are the ones a bounce found unenforced or untested:
//     * validateStateChange / persistedMessageCap / memoryChatHistoryPrune arithmetic;
//     * /memory/sql/query must not reach the Agents SDK control tables — writing
//       cf_agents_state would bypass validateStateChange, and inserting a
//       cf_agents_schedules row would defeat the SCHEDULE_DISPATCH_METHOD pin;
//     * the Vectorize namespace must fit the platform's 64-BYTE cap;
//     * layer 3 has a writer, so prune has something to evict.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

import {
  CHAT_MESSAGES_TABLE,
  DEFAULT_MAX_PERSISTED_MESSAGES,
  MAX_VECTORIZE_NAMESPACE_BYTES,
  isChatMessageInput,
  memoryChatHistoryAppend,
  memoryChatHistoryPrune,
  persistedMessageCap,
  reservedTableViolation,
  validateStateChange,
  vectorizeNamespace,
} from "../src/memory";
import type { AgentMemoryHost, RawSqlResult, SqlBinding } from "../src/memory";
import type { AgentGatewayState } from "../src/index";

const TOKEN = "test-control-secret";
const BASE = "https://agent-gateway.test";

function authed(body: unknown): RequestInit {
  return {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify(body),
  };
}

/** A state object that passes {@link validateStateChange}. */
function validState(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    status: "running",
    runId: "run-1",
    sessionId: "sess-1",
    workerTemplateId: "tmpl-1",
    frameworkAdapter: "native",
    capabilityEnvelopeId: "env-1",
    resolvedModel: null,
    resolvedSystemPrompt: null,
    resolvedLocationHint: null,
    cancelReason: null,
    lastMessage: null,
    resolvedTools: [],
    exitCode: null,
    recordedRoutingRetry: null,
    cancelRequested: false,
    updatedAt: 1,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Fake AgentMemoryHost
// ---------------------------------------------------------------------------

/**
 * In-memory stand-in for the Durable Object host.
 *
 * It models the chat table as an ordered array and answers ONLY the three
 * statement shapes the layer-3 verbs issue (create-if-absent, count, keep-newest
 * delete, insert-or-replace); anything else throws, so a verb that started
 * issuing different SQL fails loudly here instead of silently passing. It is a
 * fake, not a SQLite substitute — which is why every behaviour it asserts is
 * also asserted end-to-end against the real Durable Object below.
 */
class FakeMemoryHost implements AgentMemoryHost {
  name = "fg.tenant-a.sess-1.run-1";
  state: AgentGatewayState;
  maxPersistedMessages: number;
  rows: { id: string; message: string }[] = [];
  /** Every statement the verbs issued, in order. */
  statements: string[] = [];

  constructor(rowCount: number, maxPersistedMessages = DEFAULT_MAX_PERSISTED_MESSAGES) {
    this.state = validState() as unknown as AgentGatewayState;
    this.maxPersistedMessages = maxPersistedMessages;
    for (let i = 0; i < rowCount; i += 1) {
      this.rows.push({ id: `m-${i}`, message: JSON.stringify({ n: i }) });
    }
  }

  setState(state: AgentGatewayState): void {
    this.state = state;
  }

  /**
   * Models `ctx.storage.transactionSync`: a throw inside `body` must leave the
   * table exactly as it was, so a half-written batch cannot be observed.
   */
  transactionSync<T>(body: () => T): T {
    const snapshot = this.rows.map((r) => ({ ...r }));
    try {
      return body();
    } catch (err) {
      this.rows = snapshot;
      throw err;
    }
  }

  rawSql(query: string, bindings: SqlBinding[]): RawSqlResult {
    this.statements.push(query);
    const sql = query.trim().toLowerCase();
    if (sql.startsWith("create table if not exists")) {
      return { columns: [], rows: [] };
    }
    if (sql.startsWith("select count(*)")) {
      return { columns: ["n"], rows: [{ n: this.rows.length }] };
    }
    if (sql.startsWith("insert or replace into")) {
      const [id, message] = bindings as [string, string];
      const existing = this.rows.findIndex((r) => r.id === id);
      if (existing >= 0) this.rows[existing] = { id, message };
      else this.rows.push({ id, message });
      return { columns: [], rows: [] };
    }
    if (sql.startsWith("delete from")) {
      // Keep the newest `cap` rows, exactly as the "rowid not in (… order by
      // rowid desc limit ?)" statement does on insertion-ordered rows.
      const cap = Number(bindings[0]);
      this.rows = this.rows.slice(Math.max(0, this.rows.length - cap));
      return { columns: [], rows: [] };
    }
    if (sql.startsWith("select id, message")) {
      const limit = Number(bindings[0]);
      const newest = this.rows.slice(Math.max(0, this.rows.length - limit)).reverse();
      return {
        columns: ["id", "message", "created_at"],
        rows: newest.map((r) => ({ id: r.id, message: r.message, created_at: null })),
      };
    }
    throw new Error(`FakeMemoryHost: unmodelled statement: ${query}`);
  }
}

// ---------------------------------------------------------------------------
// Pure verbs against the fake host
// ---------------------------------------------------------------------------

describe("validateStateChange", () => {
  it("accepts a well-formed whole-object state", () => {
    expect(validateStateChange(validState())).toBeNull();
  });

  it("rejects a non-object candidate", () => {
    expect(validateStateChange(null)).toMatch(/must be a JSON object/);
    expect(validateStateChange([])).toMatch(/must be a JSON object/);
    expect(validateStateChange("{}")).toMatch(/must be a JSON object/);
  });

  it("rejects an unknown run status", () => {
    expect(validateStateChange(validState({ status: "sprinting" }))).toMatch(/state.status/);
  });

  it("rejects a mistyped nullable string field", () => {
    expect(validateStateChange(validState({ runId: 7 }))).toMatch(/state.runId/);
  });

  it("rejects a dropped or mistyped cancelRequested latch", () => {
    // The DURABLE half of the #414 cancel latch: losing it would let a
    // cancelled run be re-invoked, so it is not optional.
    const { cancelRequested: _dropped, ...withoutLatch } = validState();
    expect(validateStateChange(withoutLatch)).toMatch(/cancelRequested/);
    expect(validateStateChange(validState({ cancelRequested: "false" }))).toMatch(
      /cancelRequested/,
    );
  });

  it("rejects resolvedTools that is not an array of strings", () => {
    expect(validateStateChange(validState({ resolvedTools: ["ok", 3] }))).toMatch(
      /resolvedTools/,
    );
  });

  it("measures the 2 MB value limit in bytes, not UTF-16 code units", () => {
    // 1.5 M astral characters ≈ 6 MB of UTF-8 in 3 M code units. A code-unit
    // check at the same threshold would let this through.
    const huge = validState({ lastMessage: "𝕏".repeat(1_500_000) });
    expect(validateStateChange(huge)).toMatch(/value limit/);
  });
});

describe("persistedMessageCap", () => {
  it("defaults when the var is absent or unparseable", () => {
    expect(persistedMessageCap(undefined)).toBe(DEFAULT_MAX_PERSISTED_MESSAGES);
    expect(persistedMessageCap("many")).toBe(DEFAULT_MAX_PERSISTED_MESSAGES);
    expect(persistedMessageCap("12.5")).toBe(DEFAULT_MAX_PERSISTED_MESSAGES);
  });

  it("treats a blank var as unconfigured, not as a retain-nothing cap", () => {
    // `Number("")` is 0, and a cap of 0 makes every prune delete the whole
    // history — a declared-but-empty env var must not mean that.
    expect(persistedMessageCap("")).toBe(DEFAULT_MAX_PERSISTED_MESSAGES);
    expect(persistedMessageCap("   ")).toBe(DEFAULT_MAX_PERSISTED_MESSAGES);
  });

  it("defaults on a negative cap rather than accepting it", () => {
    expect(persistedMessageCap("-1")).toBe(DEFAULT_MAX_PERSISTED_MESSAGES);
  });

  it("honours a configured cap, including zero", () => {
    expect(persistedMessageCap("25")).toBe(25);
    expect(persistedMessageCap("0")).toBe(0);
  });
});

describe("memoryChatHistoryPrune", () => {
  it("evicts down to the deployment cap and reports measured counts", () => {
    const host = new FakeMemoryHost(10, 4);
    const result = memoryChatHistoryPrune(host);
    expect(result).toMatchObject({ ok: true, cap: 4, pruned: 6, remaining: 4 });
    expect(host.rows.length).toBe(4);
    // Oldest-first eviction: the newest 4 survive.
    expect(host.rows.map((r) => r.id)).toEqual(["m-6", "m-7", "m-8", "m-9"]);
  });

  it("lets a caller tighten the cap but never loosen it", () => {
    const tightened = memoryChatHistoryPrune(new FakeMemoryHost(10, 8), 2);
    expect(tightened).toMatchObject({ ok: true, cap: 2, remaining: 2 });

    const loosened = memoryChatHistoryPrune(new FakeMemoryHost(10, 3), 500);
    expect(loosened).toMatchObject({ ok: true, cap: 3, remaining: 3 });
  });

  it("is a no-op below the cap and issues no DELETE", () => {
    const host = new FakeMemoryHost(3, 100);
    const result = memoryChatHistoryPrune(host);
    expect(result).toMatchObject({ ok: true, cap: 100, pruned: 0, remaining: 3 });
    expect(host.statements.some((s) => s.trim().toLowerCase().startsWith("delete"))).toBe(
      false,
    );
  });

  it("reports remaining from a re-COUNT, not from assumed arithmetic", () => {
    // A host whose DELETE removes nothing must NOT be reported as having
    // evicted: the outcome has to be an observation of the table.
    const host = new FakeMemoryHost(10, 4);
    host.rawSql = ((query: string, bindings: SqlBinding[]) => {
      const sql = query.trim().toLowerCase();
      if (sql.startsWith("delete from")) return { columns: [], rows: [] };
      return FakeMemoryHost.prototype.rawSql.call(host, query, bindings);
    }) as AgentMemoryHost["rawSql"];
    const result = memoryChatHistoryPrune(host);
    expect(result).toMatchObject({ ok: true, cap: 4, pruned: 0, remaining: 10 });
  });

  it("surfaces a storage failure as a typed sql_error", () => {
    const host = new FakeMemoryHost(1);
    host.rawSql = (() => {
      throw new Error("storage exploded");
    }) as AgentMemoryHost["rawSql"];
    expect(memoryChatHistoryPrune(host)).toMatchObject({
      ok: false,
      code: "sql_error",
    });
  });
});

describe("memoryChatHistoryAppend", () => {
  it("writes rows and applies the cap in the same call", () => {
    const host = new FakeMemoryHost(0, 3);
    const result = memoryChatHistoryAppend(host, [
      { id: "a", message: { text: "1" } },
      { id: "b", message: { text: "2" } },
      { id: "c", message: { text: "3" } },
      { id: "d", message: { text: "4" } },
    ]);
    expect(result).toMatchObject({ ok: true, appended: 4, cap: 3, remaining: 3 });
    expect(host.rows.map((r) => r.id)).toEqual(["b", "c", "d"]);
  });

  it("treats a repeated id as a replace, not a duplicate", () => {
    const host = new FakeMemoryHost(0, 10);
    memoryChatHistoryAppend(host, [{ id: "a", message: { v: 1 } }]);
    const second = memoryChatHistoryAppend(host, [{ id: "a", message: { v: 2 } }]);
    expect(second).toMatchObject({ ok: true, remaining: 1 });
    expect(host.rows).toEqual([{ id: "a", message: JSON.stringify({ v: 2 }) }]);
  });

  it("maps a full database onto the typed sqlite_full code", () => {
    const host = new FakeMemoryHost(0);
    host.rawSql = (() => {
      throw new Error("SQLITE_FULL: database or disk is full");
    }) as AgentMemoryHost["rawSql"];
    expect(memoryChatHistoryAppend(host, [{ id: "a", message: 1 }])).toMatchObject({
      ok: false,
      code: "sqlite_full",
    });
  });

  it("rolls the whole batch back when one message fails mid-write", () => {
    // A per-row loop would leave the rows before the failure persisted. The
    // batch is one transaction, so a failure anywhere leaves the table
    // untouched — no partially applied append is observable.
    const host = new FakeMemoryHost(0, 10);
    const original = host.rawSql.bind(host);
    let inserts = 0;
    host.rawSql = ((query: string, bindings: SqlBinding[]) => {
      if (query.trim().toLowerCase().startsWith("insert or replace into")) {
        inserts += 1;
        if (inserts === 3) throw new Error("value too large");
      }
      return original(query, bindings);
    }) as AgentMemoryHost["rawSql"];

    const result = memoryChatHistoryAppend(host, [
      { id: "a", message: 1 },
      { id: "b", message: 2 },
      { id: "c", message: 3 },
      { id: "d", message: 4 },
    ]);
    expect(result).toMatchObject({ ok: false, code: "sql_error" });
    expect(host.rows).toEqual([]);
  });

  it("still leaves history at or below the cap when the batch fails", () => {
    // The post-condition "history <= cap once append returns" has to hold on
    // the failure path too — the table can already be over cap from a layer-2
    // INSERT, and a rolled-back batch does not fix that on its own.
    const host = new FakeMemoryHost(9, 4);
    const original = host.rawSql.bind(host);
    host.rawSql = ((query: string, bindings: SqlBinding[]) => {
      if (query.trim().toLowerCase().startsWith("insert or replace into")) {
        throw new Error("value too large");
      }
      return original(query, bindings);
    }) as AgentMemoryHost["rawSql"];

    expect(memoryChatHistoryAppend(host, [{ id: "x", message: 1 }])).toMatchObject({
      ok: false,
      code: "sql_error",
    });
    expect(host.rows.length).toBeLessThanOrEqual(host.maxPersistedMessages);
  });
});

describe("isChatMessageInput", () => {
  it("requires a non-empty id and a message field", () => {
    expect(isChatMessageInput({ id: "a", message: null })).toBe(true);
    expect(isChatMessageInput({ id: "", message: 1 })).toBe(false);
    expect(isChatMessageInput({ id: "a" })).toBe(false);
    expect(isChatMessageInput({ message: 1 })).toBe(false);
    expect(isChatMessageInput(null)).toBe(false);
    expect(isChatMessageInput([{ id: "a", message: 1 }])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The SQL governance guard
// ---------------------------------------------------------------------------

describe("reservedTableViolation", () => {
  it("permits FerroGate's own tables", () => {
    expect(reservedTableViolation("select * from fg_schedule_task_runs")).toBeNull();
    expect(
      reservedTableViolation(`select id from ${CHAT_MESSAGES_TABLE} order by rowid`),
    ).toBeNull();
    expect(reservedTableViolation("create table notes (id text primary key)")).toBeNull();
  });

  it("refuses a write that would bypass validateStateChange", () => {
    expect(
      reservedTableViolation("insert or replace into cf_agents_state (id, state) values (1, '{}')"),
    ).toMatch(/cf_agents_state/);
  });

  it("refuses a write that would defeat the schedule-callback pin", () => {
    expect(
      reservedTableViolation(
        "insert into cf_agents_schedules (id, callback) values ('x', 'destroyRun')",
      ),
    ).toMatch(/cf_agents_schedules/);
  });

  it("refuses reads of the control tables too", () => {
    expect(reservedTableViolation("select * from cf_agents_state")).toMatch(/cf_agents_state/);
  });

  it("sees through identifier quoting", () => {
    for (const quoted of [
      'delete from "cf_agents_state"',
      "delete from `cf_agents_state`",
      "delete from [cf_agents_state]",
    ]) {
      expect(reservedTableViolation(quoted)).toMatch(/cf_agents_state/);
    }
  });

  it("sees through comments splicing an identifier together", () => {
    expect(reservedTableViolation("delete from cf/*x*/_agents_state")).toMatch(
      /cf_agents_state/,
    );
    expect(reservedTableViolation("select 1 -- ok\n; delete from cf_agents_state")).toMatch(
      /cf_agents_state/,
    );
  });

  it("catches a reserved table in a trailing statement, not just the first", () => {
    expect(reservedTableViolation("select 1; delete from cf_agents_schedules")).toMatch(
      /cf_agents_schedules/,
    );
  });

  it("refuses a single-quoted token naming the table — SQLite reads it as an identifier", () => {
    // A single-quoted token IS an identifier wherever an identifier is legal
    // and a string is not, so this statement really does write the control
    // table. Skipping single-quoted regions let it straight through.
    expect(
      reservedTableViolation(
        "insert into 'cf_agents_schedules' (id, callback, type, time) values ('x','destroyRun','scheduled',1)",
      ),
    ).toMatch(/cf_agents_schedules/);
    // The blunt consequence: a literal that only mentions the name is refused
    // too. Bound parameters are the escape hatch — they are never scanned.
    expect(
      reservedTableViolation("insert into notes (id, body) values ('n1', 'cf_agents_state')"),
    ).toMatch(/cf_agents_state/);
    expect(reservedTableViolation("insert into notes (id, body) values (?, ?)")).toBeNull();
  });

  it("does not let a quoted identifier desynchronize the scan", () => {
    // SQLite treats `--`, `/*` and `'` inside a quoted identifier as ordinary
    // characters. A scanner that does not swallows the rest of the statement
    // and reports the reserved name it never reached.
    for (const construction of [
      `with t as (select 1 as "a--b") insert into cf_agents_state (id, state) values ('x','{}')`,
      `with t as (select 1 as "a/*b") insert into cf_agents_state (id, state) values ('x','{}')`,
      `with t as (select 1 as "a'b") insert into cf_agents_state (id, state) select 'x','{}'`,
      `select 1 as \`a--b\`; delete from cf_agents_state`,
      `select 1 as [a--b]; delete from cf_agents_state`,
      `select "a'b", * from cf_agents_state where c='d'`,
    ]) {
      expect(reservedTableViolation(construction)).toMatch(/cf_agents_/);
    }
  });

  it("keeps a quoted body from splicing onto the preceding token", () => {
    // `from"cf_agents_state"` is valid SQLite. Unwrapping the quotes in place
    // would put `from` immediately before the name and break the \b anchor.
    expect(reservedTableViolation('delete from"cf_agents_state"')).toMatch(
      /cf_agents_state/,
    );
  });

  it("refuses a statement it cannot tokenize to the end", () => {
    // Fail-closed: running off the end of an unterminated region used to mean
    // "found nothing, allow". Unterminated quoting is a SQLite syntax error
    // anyway, so nothing valid is lost.
    expect(reservedTableViolation("select 1 /* never closed")).toMatch(/unterminated/);
    expect(reservedTableViolation("select 'never closed")).toMatch(/unterminated/);
    expect(reservedTableViolation('select "never closed')).toMatch(/unterminated/);
    expect(reservedTableViolation("select [never closed")).toMatch(/unterminated/);
    expect(reservedTableViolation("select `never closed")).toMatch(/unterminated/);
  });

  it("still reads a doubled quote as an escape, not as a closer", () => {
    expect(reservedTableViolation("select 'it''s fine' as note")).toBeNull();
    expect(reservedTableViolation('select 1 as "a""b"')).toBeNull();
  });

  it("does not fire on a table that merely ends with the reserved prefix", () => {
    expect(reservedTableViolation("select * from mycf_agents_state")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The Vectorize namespace cap
// ---------------------------------------------------------------------------

describe("vectorizeNamespace", () => {
  it("passes a short instance name through verbatim", async () => {
    expect(await vectorizeNamespace("fg.t.s.r")).toBe("fg.t.s.r");
  });

  it("keeps a realistic UUID-triple name inside the 64-byte platform cap", async () => {
    // The shape that made the pilot fail: ~110 bytes against a 64-byte cap.
    const instance = `fg.${"a".repeat(36)}.${"b".repeat(36)}.${"c".repeat(36)}`;
    expect(instance.length).toBeGreaterThan(MAX_VECTORIZE_NAMESPACE_BYTES);
    const namespace = await vectorizeNamespace(instance);
    expect(new TextEncoder().encode(namespace).length).toBe(MAX_VECTORIZE_NAMESPACE_BYTES);
    expect(namespace).toMatch(/^fgh_[0-9a-f]{60}$/);
  });

  it("caps the worst case the naming scheme can mint", async () => {
    // 2 (`fg`) + 3 separators + 3 components of AGENT_INSTANCE_COMPONENT_MAX_LEN.
    const component = "a".repeat(64);
    const instance = `fg.${component}.${component}.${component}`;
    expect(instance.length).toBe(197);
    expect(new TextEncoder().encode(await vectorizeNamespace(instance)).length).toBe(64);
  });

  it("matches the Rust client's recipe byte for byte", async () => {
    // The SAME expectation is pinned in
    // `crates/ferrogate-runtime/src/cloudflare_agent_memory_test.rs`
    // (`vectorize_namespace_matches_the_worker_recipe`). Both sides derive the
    // namespace independently, so a divergence would silently partition writes
    // from reads; pinning the literal on both sides turns that into a failure.
    const component = "a".repeat(64);
    expect(await vectorizeNamespace(`fg.${component}.${component}.${component}`)).toBe(
      "fgh_73e51c31d07ae87dda7fb74b74bbd972d68250ef373c80be85f86d88c090",
    );
  });

  it("is deterministic, and keeps distinct tenants in distinct namespaces", async () => {
    const a = `fg.${"t".repeat(64)}.sess.run`;
    const b = `fg.${"u".repeat(64)}.sess.run`;
    expect(await vectorizeNamespace(a)).toBe(await vectorizeNamespace(a));
    expect(await vectorizeNamespace(a)).not.toBe(await vectorizeNamespace(b));
  });

  it("measures the cap in bytes, so a multi-byte name is not left oversized", async () => {
    // 30 astral characters: 60 UTF-16 code units (63 with the `fg.` prefix, so
    // UNDER the cap by a code-unit count) but 123 bytes — nearly double it. A
    // `.length`-based check would pass this through verbatim and the platform
    // would reject the query.
    const instance = `fg.${"𝕏".repeat(30)}`;
    expect(instance.length).toBeLessThanOrEqual(MAX_VECTORIZE_NAMESPACE_BYTES);
    expect(new TextEncoder().encode(instance).length).toBeGreaterThan(
      MAX_VECTORIZE_NAMESPACE_BYTES,
    );
    const namespace = await vectorizeNamespace(instance);
    expect(new TextEncoder().encode(namespace).length).toBe(MAX_VECTORIZE_NAMESPACE_BYTES);
  });
});

// ---------------------------------------------------------------------------
// Route-level E2E against the real Worker + real Durable Object SQLite
// ---------------------------------------------------------------------------

describe("memory routes (Worker-side E2E)", () => {
  it("rejects an unauthenticated memory call before touching a DO", async () => {
    const res = await SELF.fetch(`${BASE}/memory/state/get`, {
      method: "POST",
      body: JSON.stringify({ instance: "fg.t.s.r" }),
    });
    expect(res.status).toBe(401);
  });

  it("round-trips a validated state write and refuses an invalid one", async () => {
    const instance = "fg.tenant-e2e.sess.state";
    const ok = await SELF.fetch(
      `${BASE}/memory/state/set`,
      authed({ instance, state: validState({ lastMessage: "hello" }) }),
    );
    expect(ok.status).toBe(200);

    const read = await SELF.fetch(`${BASE}/memory/state/get`, authed({ instance }));
    expect(await read.json()).toMatchObject({
      ok: true,
      instance,
      state: { lastMessage: "hello", status: "running" },
    });

    const bad = await SELF.fetch(
      `${BASE}/memory/state/set`,
      authed({ instance, state: validState({ status: "sprinting" }) }),
    );
    expect(bad.status).toBe(422);
    expect(await bad.json()).toMatchObject({ error: "invalid_state" });

    // The refused write ABORTED: the earlier value is still there.
    const after = await SELF.fetch(`${BASE}/memory/state/get`, authed({ instance }));
    expect(await after.json()).toMatchObject({ state: { status: "running" } });
  });

  it("refuses SQL that would write agent state behind validateStateChange", async () => {
    const instance = "fg.tenant-e2e.sess.bypass";
    const res = await SELF.fetch(
      `${BASE}/memory/sql/query`,
      authed({
        instance,
        sql: "insert or replace into cf_agents_state (id, state) values ('x', '{}')",
      }),
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "sql_forbidden" });
  });

  it("refuses SQL that would schedule an arbitrary callback", async () => {
    const res = await SELF.fetch(
      `${BASE}/memory/sql/query`,
      authed({
        instance: "fg.tenant-e2e.sess.sched",
        sql: "insert into cf_agents_schedules (id, callback, type, time) values ('x', 'destroyRun', 'scheduled', 1)",
      }),
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "sql_forbidden" });
  });

  it("refuses a quoting construction that desynchronizes a naive scan", async () => {
    // End-to-end proof for the lexer fix: the `"a--b"` alias made the guard
    // discard the rest of the line, so this single statement reached
    // `sql.exec` and wrote `cf_agents_state` past `validateStateChange`.
    const instance = "fg.tenant-e2e.sess.desync";
    const seed = await SELF.fetch(
      `${BASE}/memory/state/set`,
      authed({ instance, state: validState({ lastMessage: "before" }) }),
    );
    expect(seed.status).toBe(200);

    const res = await SELF.fetch(
      `${BASE}/memory/sql/query`,
      authed({
        instance,
        sql: `with t as (select 1 as "a--b") insert into cf_agents_state (id, state) values ('x', '{}')`,
      }),
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "sql_forbidden" });

    // The state the statement targeted is untouched.
    const after = await SELF.fetch(`${BASE}/memory/state/get`, authed({ instance }));
    expect(await after.json()).toMatchObject({ state: { lastMessage: "before" } });
  });

  it("refuses a single-quoted control-table name", async () => {
    const res = await SELF.fetch(
      `${BASE}/memory/sql/query`,
      authed({
        instance: "fg.tenant-e2e.sess.quoted",
        sql: "insert into 'cf_agents_schedules' (id, callback, type, time) values ('x', 'destroyRun', 'scheduled', 1)",
      }),
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "sql_forbidden" });
  });

  it("still serves FerroGate's own tables through the same route", async () => {
    const instance = "fg.tenant-e2e.sess.sql";
    const create = await SELF.fetch(
      `${BASE}/memory/sql/query`,
      authed({ instance, sql: "create table if not exists notes (id text primary key, body text)" }),
    );
    expect(create.status).toBe(200);

    const insert = await SELF.fetch(
      `${BASE}/memory/sql/query`,
      authed({
        instance,
        sql: "insert or replace into notes (id, body) values (?, ?)",
        params: ["n1", "remember this"],
      }),
    );
    expect(insert.status).toBe(200);

    const read = await SELF.fetch(
      `${BASE}/memory/sql/query`,
      authed({ instance, sql: "select id, body from notes" }),
    );
    expect(await read.json()).toMatchObject({
      ok: true,
      rowCount: 1,
      rows: [{ id: "n1", body: "remember this" }],
    });
  });

  it("appends chat history, reads it back oldest-first, and prunes it", async () => {
    const instance = "fg.tenant-e2e.sess.chat";
    const append = await SELF.fetch(
      `${BASE}/memory/chat/append`,
      authed({
        instance,
        messages: [
          { id: "m1", message: { role: "user", content: "one" } },
          { id: "m2", message: { role: "assistant", content: "two" } },
          { id: "m3", message: { role: "user", content: "three" } },
        ],
      }),
    );
    expect(append.status).toBe(200);
    expect(await append.json()).toMatchObject({ ok: true, appended: 3, remaining: 3 });

    const read = await SELF.fetch(`${BASE}/memory/chat/get`, authed({ instance }));
    const history = (await read.json()) as {
      count: number;
      messages: { id: string; message: { content: string } }[];
    };
    expect(history.count).toBe(3);
    expect(history.messages.map((m) => m.id)).toEqual(["m1", "m2", "m3"]);
    expect(history.messages[0].message.content).toBe("one");

    // Prune to 1 — the eviction counters must describe the real table.
    const pruned = await SELF.fetch(
      `${BASE}/memory/chat/prune`,
      authed({ instance, maxMessages: 1 }),
    );
    expect(await pruned.json()).toMatchObject({
      ok: true,
      cap: 1,
      pruned: 2,
      remaining: 1,
    });

    const afterPrune = await SELF.fetch(`${BASE}/memory/chat/get`, authed({ instance }));
    const remaining = (await afterPrune.json()) as { messages: { id: string }[] };
    // Oldest-first eviction leaves the NEWEST message.
    expect(remaining.messages.map((m) => m.id)).toEqual(["m3"]);
  });

  it("rejects a malformed append batch", async () => {
    const instance = "fg.tenant-e2e.sess.badappend";
    const empty = await SELF.fetch(`${BASE}/memory/chat/append`, authed({ instance, messages: [] }));
    expect(empty.status).toBe(400);

    const malformed = await SELF.fetch(
      `${BASE}/memory/chat/append`,
      authed({ instance, messages: [{ message: "no id" }] }),
    );
    expect(malformed.status).toBe(400);

    const oversized = await SELF.fetch(
      `${BASE}/memory/chat/append`,
      authed({
        instance,
        messages: Array.from({ length: 101 }, (_, i) => ({ id: `m${i}`, message: i })),
      }),
    );
    expect(oversized.status).toBe(413);

    // Over the 2 MB Durable Object value limit: 413, the same status
    // `state/set` and `sql/query` report — not a 400 `sql_error` from the DO.
    const oversizeMessage = await SELF.fetch(
      `${BASE}/memory/chat/append`,
      authed({
        instance,
        messages: [{ id: "big", message: { text: "x".repeat(2 * 1024 * 1024 + 16) } }],
      }),
    );
    expect(oversizeMessage.status).toBe(413);

    const longId = await SELF.fetch(
      `${BASE}/memory/chat/append`,
      authed({ instance, messages: [{ id: "i".repeat(257), message: 1 }] }),
    );
    expect(longId.status).toBe(400);

    // None of the refused batches reached the table.
    const read = await SELF.fetch(`${BASE}/memory/chat/get`, authed({ instance }));
    expect(await read.json()).toMatchObject({ count: 0 });
  });

  it("keeps two instances' memory disjoint", async () => {
    const a = "fg.tenant-a.sess.run";
    const b = "fg.tenant-b.sess.run";
    await SELF.fetch(
      `${BASE}/memory/chat/append`,
      authed({ instance: a, messages: [{ id: "only-a", message: "secret" }] }),
    );
    const readB = await SELF.fetch(`${BASE}/memory/chat/get`, authed({ instance: b }));
    expect(await readB.json()).toMatchObject({ count: 0, messages: [] });
  });

  it("keeps the semantic pilot off by default", async () => {
    const res = await SELF.fetch(
      `${BASE}/memory/semantic/query`,
      authed({ instance: "fg.t.s.r", query: "anything" }),
    );
    expect(res.status).toBe(501);
    expect(await res.json()).toMatchObject({ error: "semantic_memory_disabled", beta: true });
  });
});
