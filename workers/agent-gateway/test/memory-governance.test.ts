// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: ADVERSARIAL coverage for the agent memory surface (issue #427), added by
//   the test gate on top of test/memory.test.ts. It targets the paths that survived a
//   green run of the existing suite:
//
//     * the reserved-table guard as a RUNTIME invariant rather than a string check —
//       a corpus of bypass constructions is replayed against the real Durable Object
//       and the SDK control tables are then OBSERVED (agent state, /schedule/list) to
//       have not moved. A guard that merely returns the right string while the write
//       lands is exactly the #188 write-path/read-path failure mode;
//     * every one of the SDK's OWN control tables, enumerated from the pinned
//       agents@0.0.109 bundle, not just the two the docs name;
//     * per-instance isolation across two tenants over ALL THREE layers, in BOTH
//       directions (the existing test only proves tenant B's chat is empty);
//     * the deployment retention cap — `maxPersistedMessages` read from the ENV var,
//       and enforced with NO caller-supplied cap (the existing prune E2E always passes
//       `maxMessages`, so an ignored deployment cap stayed green);
//     * the semantic pilot BEYOND the default-off check: with bindings injected, the
//       Vectorize query must be namespace-scoped to the instance, which is the only
//       thing making semantic recall tenant-isolated;
//     * the route's own rejection surface (auth, method, body, verb, param limits).

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";

import {
  DEFAULT_MAX_PERSISTED_MESSAGES,
  handleMemory,
  persistedMessageCap,
  reservedTableViolation,
  vectorizeNamespace,
} from "../src/memory";
import type { AgentGateway, Env } from "../src/index";

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

async function post(path: string, body: unknown) {
  const res = await SELF.fetch(`${BASE}${path}`, authed(body));
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

const sql = (instance: string, statement: string, params?: unknown[]) =>
  post("/memory/sql/query", { instance, sql: statement, params });

// ---------------------------------------------------------------------------
// INVARIANT 1 — the guard is a RUNTIME barrier, not a string result
//
// `reservedTableViolation` returning a message proves nothing on its own: what
// the issue's tethered principle requires is that the SDK control tables do not
// MOVE. Every construction below is replayed against a real Durable Object and
// the control tables are then observed through the surfaces that read them
// (/memory/state/get for cf_agents_state, /schedule/list for
// cf_agents_schedules). Each construction is also asserted at the pure-function
// level, so a regression says which layer broke.
// ---------------------------------------------------------------------------

/**
 * Constructions that reach an SDK control table. Each is a SINGLE statement or
 * a `;`-chain that the Durable Object's `sql.exec` really would execute — the
 * route allows multi-statement input (proved by
 * "executes a multi-statement chain" below), so a chain is not a strawman.
 */
const BYPASS_CORPUS: { why: string; sql: string }[] = [
  { why: "plain write", sql: "insert into cf_agents_state (id, state) values ('x', '{}')" },
  { why: "upper case", sql: "INSERT INTO CF_AGENTS_STATE (id, state) VALUES ('x','{}')" },
  { why: "mixed case", sql: "delete from Cf_Agents_State" },
  { why: "schema qualified", sql: `insert into main.cf_agents_state (id, state) values ('x','{}')` },
  {
    why: "schema qualified, both parts double-quoted",
    sql: `insert into "main"."cf_agents_state" (id, state) values ('x','{}')`,
  },
  { why: "double-quoted identifier", sql: `delete from "cf_agents_state"` },
  { why: "backquoted identifier", sql: "delete from `cf_agents_state`" },
  { why: "bracketed identifier", sql: "delete from [cf_agents_state]" },
  {
    why: "single-quoted identifier (SQLite reads it as one here)",
    sql: "insert into 'cf_agents_schedules' (id, callback, type, time) values ('x','destroyRun','scheduled',1)",
  },
  {
    why: "no space between keyword and quoted name",
    sql: `delete from"cf_agents_state"`,
  },
  {
    why: "single quote inside a double-quoted alias desynchronizes a naive literal scan",
    sql: `with q as (select "a'b" as z) insert into cf_agents_schedules (id, callback, type, time) select 'x','destroyRun','scheduled',1 from q`,
  },
  {
    why: "line comment inside a double-quoted alias",
    sql: `select 1 as "a--b"; delete from cf_agents_state`,
  },
  {
    why: "block-comment opener inside a bracketed alias",
    sql: `select 1 as [a/*b]; delete from cf_agents_state`,
  },
  {
    why: "bracket closer inside a double-quoted alias",
    sql: `select 1 as "a]b"; delete from cf_agents_state`,
  },
  {
    why: "double quote inside a bracketed alias",
    sql: `select 1 as [a"b]; delete from cf_agents_state`,
  },
  {
    why: "doubled quote escape must not be read as a closer",
    sql: `select 1 as "a""b"; delete from cf_agents_state`,
  },
  {
    why: "blob literal prefix — x'..' is a literal, not an identifier opener",
    sql: `select x'41', * from cf_agents_state`,
  },
  {
    why: "backslash is NOT an escape in SQLite, so the literal ends at the second quote",
    sql: `insert into notes values ('a\\'); delete from cf_agents_state; select ('`,
  },
  {
    why: "trailing statement after a legitimate one",
    sql: "select 1; delete from cf_agents_schedules",
  },
  {
    why: "comment splices the identifier back together",
    sql: "delete from cf/*x*/_agents_state",
  },
  {
    why: "rename an owned table onto a control table",
    sql: "alter table notes rename to cf_agents_state",
  },
  {
    why: "trigger body reaches the control table later",
    sql: "create trigger tg after insert on notes begin insert into cf_agents_state (id, state) values ('x','{}'); end",
  },
  {
    why: "view over the control table",
    sql: "create view leak as select * from cf_agents_state",
  },
  {
    why: "read the control table into an owned table",
    sql: "insert into notes select id, state from cf_agents_state",
  },
];

describe("reserved-table guard (runtime invariant)", () => {
  it("refuses every bypass construction at the pure-function layer", () => {
    for (const { why, sql: statement } of BYPASS_CORPUS) {
      expect(reservedTableViolation(statement), why).not.toBeNull();
    }
  });

  it("leaves the SDK control tables unmoved after the whole corpus", async () => {
    const instance = "fg.tenant-guard.sess.run";
    // Seed observable state through the GOVERNED path, plus an owned table the
    // constructions reference so nothing fails for the wrong reason.
    expect(
      (await post("/memory/state/set", { instance, state: validState({ lastMessage: "seeded" }) }))
        .status,
    ).toBe(200);
    expect(
      (await sql(instance, "create table if not exists notes (id text primary key, body text)"))
        .status,
    ).toBe(200);

    for (const { why, sql: statement } of BYPASS_CORPUS) {
      const res = await sql(instance, statement);
      expect(res.status, `${why}: ${statement}`).toBe(403);
      expect(res.body.error, why).toBe("sql_forbidden");
    }

    // The observation, not the status code: agent state is byte-identical and
    // no schedule row was smuggled in. Either one moving means the guard
    // reported a refusal the storage did not honour.
    const state = await post("/memory/state/get", { instance });
    expect(state.body).toMatchObject({ state: { lastMessage: "seeded", status: "running" } });
    const schedules = await post("/schedule/list", { instance });
    expect(schedules.status).toBe(200);
    expect(schedules.body.tasks ?? schedules.body.schedules ?? []).toEqual([]);
  });

  it("covers every control table the pinned Agents SDK creates, not just the documented two", async () => {
    // Enumerated from agents@0.0.109's own `CREATE TABLE IF NOT EXISTS` sites:
    // cf_agents_state, cf_agents_schedules, cf_agents_queues,
    // cf_agents_mcp_servers. `cf_ai_chat_agent_messages` is layer 3 and is
    // deliberately NOT reserved — the memory routes own it.
    const instance = "fg.tenant-guard.sess.sdk-tables";
    for (const table of [
      "cf_agents_state",
      "cf_agents_schedules",
      "cf_agents_queues",
      "cf_agents_mcp_servers",
    ]) {
      const res = await sql(instance, `select * from ${table}`);
      expect(res.status, table).toBe(403);
      expect(String(res.body.message), table).toContain(table);
    }
    // The chat table stays reachable through layer 2: it is FerroGate's, and
    // the SQLITE_FULL recovery documented for layer 2 depends on being able to
    // DELETE from it while writes are failing.
    expect(
      (await post("/memory/chat/append", { instance, messages: [{ id: "c1", message: 1 }] })).status,
    ).toBe(200);
    const chat = await sql(instance, "select count(*) as n from cf_ai_chat_agent_messages");
    expect(chat.status).toBe(200);
    expect(chat.body).toMatchObject({ rows: [{ n: 1 }] });
    const deleted = await sql(instance, "delete from cf_ai_chat_agent_messages");
    expect(deleted.status).toBe(200);
  });

  it("executes a multi-statement chain, so `;` chaining in the corpus is real", async () => {
    const instance = "fg.tenant-guard.sess.multi";
    const chained = await sql(
      instance,
      "create table if not exists chain (a); insert into chain values (1); insert into chain values (2)",
    );
    expect(chained.status).toBe(200);
    const read = await sql(instance, "select count(*) as n from chain");
    expect(read.body).toMatchObject({ rows: [{ n: 2 }] });
  });

  it("refuses a statement it cannot tokenize instead of scanning past the end", async () => {
    const instance = "fg.tenant-guard.sess.unterminated";
    for (const statement of [
      "select 1 /* never closed",
      "select 'never closed",
      'select "never closed',
      "select [never closed",
      "select `never closed",
    ]) {
      const res = await sql(instance, statement);
      expect(res.status, statement).toBe(403);
      expect(String(res.body.message), statement).toMatch(/unterminated/);
    }
  });

  it("still allows the statements a tenant actually needs", async () => {
    // The guard's cost has to stay bounded, or it is a different bug: these all
    // survive a green run only if the scan does NOT over-refuse.
    for (const statement of [
      "select * from notes where id = ?",
      "create table if not exists my_cf_agents_notes (id text)",
      "select * from mycf_agents_state",
      "select 'it''s fine' as note",
      "select 1 -- trailing comment naming nothing",
      "insert into notes (id, body) values (?, ?)",
    ]) {
      expect(reservedTableViolation(statement), statement).toBeNull();
    }
  });
});

// ---------------------------------------------------------------------------
// INVARIANT 2 — per-instance isolation IS tenant isolation, in both directions
//
// The existing E2E writes to tenant A and finds tenant B empty. That stays green
// if writes silently go nowhere. Here BOTH tenants write all three layers and
// each must read back exactly its own.
// ---------------------------------------------------------------------------

describe("cross-tenant isolation over all three layers", () => {
  it("keeps state, SQL tables and chat history disjoint between two tenants", async () => {
    const a = "fg.tenant-alpha.sess-1.run-1";
    const b = "fg.tenant-beta.sess-1.run-1";

    // Layer 1
    expect((await post("/memory/state/set", { instance: a, state: validState({ lastMessage: "alpha-secret" }) })).status).toBe(200);
    expect((await post("/memory/state/set", { instance: b, state: validState({ lastMessage: "beta-secret", status: "queued" }) })).status).toBe(200);

    // Layer 2 — same table name, different rows, plus a table only A has.
    for (const [instance, body] of [[a, "alpha-row"], [b, "beta-row"]] as const) {
      expect((await sql(instance, "create table if not exists shared (id text primary key, body text)")).status).toBe(200);
      expect((await sql(instance, "insert or replace into shared (id, body) values (?, ?)", ["k", body])).status).toBe(200);
    }
    expect((await sql(a, "create table if not exists alpha_only (id text)")).status).toBe(200);

    // Layer 3
    expect((await post("/memory/chat/append", { instance: a, messages: [{ id: "c1", message: "alpha-msg" }] })).status).toBe(200);
    expect((await post("/memory/chat/append", { instance: b, messages: [{ id: "c1", message: "beta-msg" }] })).status).toBe(200);

    // Each side reads its own, and only its own.
    expect((await post("/memory/state/get", { instance: a })).body).toMatchObject({
      state: { lastMessage: "alpha-secret", status: "running" },
    });
    expect((await post("/memory/state/get", { instance: b })).body).toMatchObject({
      state: { lastMessage: "beta-secret", status: "queued" },
    });

    expect((await sql(a, "select body from shared")).body).toMatchObject({ rows: [{ body: "alpha-row" }] });
    expect((await sql(b, "select body from shared")).body).toMatchObject({ rows: [{ body: "beta-row" }] });

    // A table created in A's instance does not exist in B's database at all.
    const missing = await sql(b, "select * from alpha_only");
    expect(missing.status).toBe(400);
    expect(String(missing.body.message)).toMatch(/no such table/i);

    const chatA = (await post("/memory/chat/get", { instance: a })).body as {
      messages: { message: unknown }[];
    };
    const chatB = (await post("/memory/chat/get", { instance: b })).body as {
      messages: { message: unknown }[];
    };
    expect(chatA.messages.map((m) => m.message)).toEqual(["alpha-msg"]);
    expect(chatB.messages.map((m) => m.message)).toEqual(["beta-msg"]);

    // And a destructive prune on B leaves A's history intact — isolation has to
    // survive a WRITE from the other tenant, not just a read.
    expect((await post("/memory/chat/prune", { instance: b, maxMessages: 0 })).body).toMatchObject({
      cap: 0,
      pruned: 1,
      remaining: 0,
    });
    expect((await post("/memory/chat/get", { instance: a })).body).toMatchObject({ count: 1 });
  });
});

// ---------------------------------------------------------------------------
// INVARIANT 3 — the DEPLOYMENT cap (maxPersistedMessages) is enforced with no
// caller cap, and it is read from the env var rather than hard-coded
// ---------------------------------------------------------------------------

describe("maxPersistedMessages (deployment retention cap)", () => {
  it("caps history at the deployment cap when the caller supplies none", async () => {
    const instance = "fg.tenant-cap.sess.deployment";
    const batch = (from: number) =>
      Array.from({ length: 100 }, (_, i) => ({
        id: `m${String(from + i).padStart(3, "0")}`,
        message: { n: from + i },
      }));

    const first = await post("/memory/chat/append", { instance, messages: batch(0) });
    expect(first.body).toMatchObject({ appended: 100, cap: DEFAULT_MAX_PERSISTED_MESSAGES, pruned: 0, remaining: 100 });

    const second = await post("/memory/chat/append", { instance, messages: batch(100) });
    expect(second.body).toMatchObject({ pruned: 0, remaining: 200 });

    // The third batch crosses the cap: the append itself must evict, without
    // any caller-supplied maxMessages anywhere in this test.
    const third = await post("/memory/chat/append", { instance, messages: batch(200) });
    expect(third.body).toMatchObject({
      appended: 100,
      cap: DEFAULT_MAX_PERSISTED_MESSAGES,
      pruned: 100,
      remaining: DEFAULT_MAX_PERSISTED_MESSAGES,
    });

    const read = (await post("/memory/chat/get", { instance, limit: 1000 })).body as {
      count: number;
      messages: { id: string }[];
    };
    expect(read.count).toBe(DEFAULT_MAX_PERSISTED_MESSAGES);
    // Oldest-first eviction: m000..m099 are gone, the newest 200 survive in order.
    expect(read.messages[0].id).toBe("m100");
    expect(read.messages[read.count - 1].id).toBe("m299");
  });

  it("reads the cap from MEMORY_MAX_PERSISTED_MESSAGES, not from a constant", async () => {
    // The var is unbound in this harness, so the E2E above can only ever
    // observe the default. Setting it on the live Durable Object's env proves
    // the getter is actually wired to the deployment var — a hard-coded 200
    // would keep every other test green.
    const name = "fg.tenant-cap.sess.envvar";
    const stub = env.AGENT_GATEWAY.get(env.AGENT_GATEWAY.idFromName(name));
    await runInDurableObject(stub, async (agent: AgentGateway) => {
      // The SDK reads `this.name` lazily and throws until the stub is named;
      // `getAgentByName` does this on the route path.
      await (agent as unknown as { setName(n: string): Promise<void> }).setName(name);
      const withEnv = agent as unknown as { env: Env; maxPersistedMessages: number };
      expect(withEnv.maxPersistedMessages).toBe(DEFAULT_MAX_PERSISTED_MESSAGES);
      withEnv.env.MEMORY_MAX_PERSISTED_MESSAGES = "3";
      expect(withEnv.maxPersistedMessages).toBe(3);

      const appended = await agent.memoryChatHistoryAppend([
        { id: "a", message: 1 },
        { id: "b", message: 2 },
        { id: "c", message: 3 },
        { id: "d", message: 4 },
        { id: "e", message: 5 },
      ]);
      expect(appended).toMatchObject({ ok: true, cap: 3, pruned: 2, remaining: 3 });

      const history = await agent.memoryChatHistoryGet();
      expect(history.ok && history.messages.map((m) => m.id)).toEqual(["c", "d", "e"]);

      // A caller may tighten the deployment cap, never loosen it — against the
      // real table, not the fake host.
      const loosened = await agent.memoryChatHistoryPrune(1000);
      expect(loosened).toMatchObject({ ok: true, cap: 3, remaining: 3 });
      withEnv.env.MEMORY_MAX_PERSISTED_MESSAGES = undefined;
    });
    expect(persistedMessageCap("3")).toBe(3);
  });

  it("re-appending an existing id replaces the row and moves it to the newest position", async () => {
    // `insert or replace` deletes and re-inserts, so the row gets a NEW rowid
    // and the history reorders. Pinned deliberately: the read path orders by
    // rowid, so this is what a caller re-sending an edited message observes.
    const instance = "fg.tenant-cap.sess.replace";
    await post("/memory/chat/append", {
      instance,
      messages: [
        { id: "m1", message: "one" },
        { id: "m2", message: "two" },
        { id: "m3", message: "three" },
      ],
    });
    const again = await post("/memory/chat/append", {
      instance,
      messages: [{ id: "m1", message: "one-edited" }],
    });
    // No duplicate row: the id is the idempotency key.
    expect(again.body).toMatchObject({ appended: 1, remaining: 3 });
    const read = (await post("/memory/chat/get", { instance })).body as {
      messages: { id: string; message: unknown }[];
    };
    expect(read.messages.map((m) => m.id)).toEqual(["m2", "m3", "m1"]);
    expect(read.messages[2].message).toBe("one-edited");
  });

  it("clamps chat/get to the newest `limit`, oldest-first", async () => {
    const instance = "fg.tenant-cap.sess.limit";
    await post("/memory/chat/append", {
      instance,
      messages: [
        { id: "a", message: 1 },
        { id: "b", message: 2 },
        { id: "c", message: 3 },
      ],
    });
    const two = (await post("/memory/chat/get", { instance, limit: 2 })).body as {
      messages: { id: string }[];
    };
    expect(two.messages.map((m) => m.id)).toEqual(["b", "c"]);
    // A nonsense limit falls back to the route maximum rather than returning
    // nothing (a silently empty history reads as "no memory", not as an error).
    const zero = (await post("/memory/chat/get", { instance, limit: 0 })).body as {
      messages: { id: string }[];
    };
    expect(zero.messages.map((m) => m.id)).toEqual(["a", "b", "c"]);
  });
});

// ---------------------------------------------------------------------------
// INVARIANT 4 — the semantic pilot is namespace-scoped (its only isolation)
//
// Nothing beyond the default-off 501 was exercised. With bindings injected, the
// pilot's Vectorize call must be scoped to the instance's namespace: an
// unscoped query would return another tenant's vectors while every existing
// test stayed green, since the pilot is off in the harness.
// ---------------------------------------------------------------------------

interface RecordedQuery {
  vector: number[];
  options: { topK?: number; namespace?: string; returnMetadata?: string };
}

function pilotEnv(overrides: {
  vector?: number[] | undefined;
  matches?: { id: string; score: number; metadata?: unknown }[];
  throws?: string;
  bound?: boolean;
} = {}) {
  const queries: RecordedQuery[] = [];
  const embedCalls: { model: string; input: unknown }[] = [];
  const vectorize = {
    query: async (vector: number[], options: RecordedQuery["options"]) => {
      queries.push({ vector, options });
      if (overrides.throws) throw new Error(overrides.throws);
      return { matches: overrides.matches ?? [] };
    },
  };
  const ai = {
    run: async (model: string, input: unknown) => {
      embedCalls.push({ model, input });
      return { data: overrides.vector === undefined ? [[0.1, 0.2]] : [overrides.vector] };
    },
  };
  const pilot = {
    ...env,
    MEMORY_SEMANTIC_ENABLED: "true",
    ...(overrides.bound === false ? { VECTORIZE: undefined, AI: undefined } : { VECTORIZE: vectorize, AI: ai }),
  } as unknown as Env;
  return { pilot, queries, embedCalls };
}

async function semantic(pilot: Env, body: unknown) {
  const url = new URL(`${BASE}/memory/semantic/query`);
  const res = await handleMemory(
    new Request(url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify(body),
    }),
    pilot,
    url,
  );
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe("semantic-memory pilot (beta, default off)", () => {
  it("stays off when the flag is set but the bindings are missing", async () => {
    const { pilot } = pilotEnv({ bound: false });
    const res = await semantic(pilot, { instance: "fg.t.s.r", query: "hello" });
    expect(res.status).toBe(501);
    expect(res.body).toMatchObject({ error: "semantic_memory_unbound", beta: true });
  });

  it("scopes the Vectorize query to the instance's namespace", async () => {
    const { pilot, queries, embedCalls } = pilotEnv({
      matches: [{ id: "v1", score: 0.9, metadata: { text: "remembered" } }],
    });
    const res = await semantic(pilot, { instance: "fg.tenant-a.sess.run", query: "what did I say" });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      ok: true,
      beta: true,
      instance: "fg.tenant-a.sess.run",
      namespace: "fg.tenant-a.sess.run",
      matches: [{ id: "v1", score: 0.9, metadata: { text: "remembered" } }],
    });
    expect(queries).toHaveLength(1);
    expect(queries[0].options.namespace).toBe("fg.tenant-a.sess.run");
    expect(queries[0].options.returnMetadata).toBe("all");
    expect(embedCalls[0].input).toMatchObject({ text: ["what did I say"] });
  });

  it("never queries one tenant's namespace for another's instance", async () => {
    const { pilot, queries } = pilotEnv();
    await semantic(pilot, { instance: "fg.tenant-a.sess.run", query: "q" });
    await semantic(pilot, { instance: "fg.tenant-b.sess.run", query: "q" });
    expect(queries.map((q) => q.options.namespace)).toEqual([
      "fg.tenant-a.sess.run",
      "fg.tenant-b.sess.run",
    ]);
    expect(new Set(queries.map((q) => q.options.namespace)).size).toBe(2);
  });

  it("uses the HASHED namespace for a name over Vectorize's 64-byte cap, and reports it", async () => {
    const component = "a".repeat(64);
    const instance = `fg.${component}.${component}.${component}`;
    const expected = await vectorizeNamespace(instance);
    const { pilot, queries } = pilotEnv();
    const res = await semantic(pilot, { instance, query: "q" });
    // The response echoes the namespace actually searched, so a caller can tell
    // which partition a result came from instead of assuming it is the name.
    expect(res.body.namespace).toBe(expected);
    expect(queries[0].options.namespace).toBe(expected);
    expect(new TextEncoder().encode(String(queries[0].options.namespace)).length).toBe(64);
  });

  it("clamps topK and defaults it", async () => {
    const { pilot, queries } = pilotEnv();
    await semantic(pilot, { instance: "fg.t.s.r", query: "q" });
    await semantic(pilot, { instance: "fg.t.s.r", query: "q", topK: 500 });
    await semantic(pilot, { instance: "fg.t.s.r", query: "q", topK: 3 });
    await semantic(pilot, { instance: "fg.t.s.r", query: "q", topK: 0 });
    expect(queries.map((q) => q.options.topK)).toEqual([5, 20, 3, 5]);
  });

  it("fails as a gateway error when the embedding model returns no vector", async () => {
    const { pilot, queries } = pilotEnv({ vector: undefined });
    const empty = { ...pilot, AI: { run: async () => ({ data: [] }) } } as unknown as Env;
    const res = await semantic(empty, { instance: "fg.t.s.r", query: "q" });
    expect(res.status).toBe(502);
    // And nothing was searched — a failed embedding must not become an
    // unscoped query.
    expect(queries).toHaveLength(0);
  });

  it("maps a Vectorize failure to 502 rather than leaking it as success", async () => {
    const { pilot } = pilotEnv({ throws: "vectorize unavailable" });
    const res = await semantic(pilot, { instance: "fg.t.s.r", query: "q" });
    expect(res.status).toBe(502);
    expect(String(res.body.error)).toMatch(/semantic query failed/);
  });

  it("requires a query string and an instance", async () => {
    const { pilot } = pilotEnv();
    expect((await semantic(pilot, { instance: "fg.t.s.r" })).status).toBe(400);
    expect((await semantic(pilot, { instance: "fg.t.s.r", query: "" })).status).toBe(400);
    expect((await semantic(pilot, { query: "q" })).status).toBe(400);
  });

  it("is bearer-gated like every other memory route", async () => {
    const { pilot, queries } = pilotEnv();
    const url = new URL(`${BASE}/memory/semantic/query`);
    const res = await handleMemory(
      new Request(url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer wrong" },
        body: JSON.stringify({ instance: "fg.t.s.r", query: "q" }),
      }),
      pilot,
      url,
    );
    expect(res.status).toBe(403);
    expect(queries).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// INVARIANT 5 — the route's rejection surface
// ---------------------------------------------------------------------------

describe("memory route surface", () => {
  it("separates a MISSING bearer token (401) from a WRONG one (403)", async () => {
    const missing = await SELF.fetch(`${BASE}/memory/state/get`, {
      method: "POST",
      body: JSON.stringify({ instance: "fg.t.s.r" }),
    });
    expect(missing.status).toBe(401);
    const wrong = await SELF.fetch(`${BASE}/memory/state/get`, {
      method: "POST",
      headers: { authorization: "Bearer not-the-secret" },
      body: JSON.stringify({ instance: "fg.t.s.r" }),
    });
    expect(wrong.status).toBe(403);
    // A token of the RIGHT length but wrong bytes is refused too — the
    // comparison is constant-time, not a length check.
    const sameLength = await SELF.fetch(`${BASE}/memory/state/get`, {
      method: "POST",
      headers: { authorization: `Bearer ${"x".repeat(TOKEN.length)}` },
      body: JSON.stringify({ instance: "fg.t.s.r" }),
    });
    expect(sameLength.status).toBe(403);
  });

  it("is POST-only", async () => {
    const res = await SELF.fetch(`${BASE}/memory/state/get`, {
      method: "GET",
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(res.status).toBe(405);
  });

  it("rejects a malformed body, a missing instance and an overlong one", async () => {
    const bad = await SELF.fetch(`${BASE}/memory/state/get`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: "{not json",
    });
    expect(bad.status).toBe(400);

    expect((await post("/memory/state/get", {})).status).toBe(400);
    expect((await post("/memory/state/get", { instance: "" })).status).toBe(400);
    expect((await post("/memory/state/get", { instance: 42 })).status).toBe(400);
    expect((await post("/memory/state/get", { instance: "x".repeat(513) })).status).toBe(400);
  });

  it("404s an unknown memory verb", async () => {
    expect((await post("/memory/state/forget", { instance: "fg.t.s.r" })).status).toBe(404);
  });

  it("rejects missing sql and non-binding params", async () => {
    const instance = "fg.tenant-surface.sess.run";
    expect((await post("/memory/sql/query", { instance })).status).toBe(400);
    expect((await post("/memory/sql/query", { instance, sql: "" })).status).toBe(400);
    expect(
      (await post("/memory/sql/query", { instance, sql: "select 1", params: { a: 1 } })).status,
    ).toBe(400);
    expect(
      (await post("/memory/sql/query", { instance, sql: "select 1", params: [{ nested: true }] }))
        .status,
    ).toBe(400);
  });

  it("rejects an oversized SQL param with 413, measured in bytes", async () => {
    const instance = "fg.tenant-surface.sess.oversize";
    expect((await sql(instance, "create table if not exists big (id integer primary key, body text)")).status).toBe(200);
    // Just over 2 MB of UTF-8 in HALF as many UTF-16 code units: a `.length`
    // check at the same threshold would pass this straight to the DO.
    const astral = "𝕏".repeat(600_000);
    expect(astral.length).toBeLessThan(2 * 1024 * 1024);
    expect(new TextEncoder().encode(astral).length).toBeGreaterThan(2 * 1024 * 1024);
    const res = await post("/memory/sql/query", {
      instance,
      sql: "insert into big (body) values (?)",
      params: [astral],
    });
    expect(res.status).toBe(413);
    // And it did not land.
    expect((await sql(instance, "select count(*) as n from big")).body).toMatchObject({
      rows: [{ n: 0 }],
    });
  });

  it("rejects a state object over the 2 MB value limit without touching the stored state", async () => {
    const instance = "fg.tenant-surface.sess.bigstate";
    expect((await post("/memory/state/set", { instance, state: validState({ lastMessage: "small" }) })).status).toBe(200);
    const huge = await post("/memory/state/set", {
      instance,
      state: validState({ lastMessage: "x".repeat(2 * 1024 * 1024 + 64) }),
    });
    expect(huge.status).toBe(422);
    expect((await post("/memory/state/get", { instance })).body).toMatchObject({
      state: { lastMessage: "small" },
    });
  });
});
