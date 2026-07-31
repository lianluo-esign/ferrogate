// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: FerroGate agent memory routes (issue #427): governed read/write/query over the
//   three per-instance memory layers of a Cloudflare agent (synced JSON state, embedded
//   SQLite, chat history) plus a default-off Vectorize semantic-memory pilot. Cloudflare has
//   NO first-party memory REST API — these bearer-gated Worker routes are the only tethered
//   path FerroGate uses to touch an agent's memory.

import { getAgentByName } from "agents";

import { json, requireBearer } from "./auth";
import type { AgentGateway, AgentGatewayState, Env, RunStatus } from "./index";

// ---------------------------------------------------------------------------
// Limits (Durable Object memory-layer facts, issue #427)
// ---------------------------------------------------------------------------

/**
 * Hard Durable Object limit: a single SQLite row/value may not exceed 2 MB.
 * The synced JSON state persists as ONE SQLite value, so a whole-object state
 * replace is rejected up front when it would exceed this.
 */
export const MAX_SQL_VALUE_BYTES = 2 * 1024 * 1024;

/**
 * Default chat-history retention cap. The pinned Agents SDK (0.0.109) predates
 * the SDK-side `maxPersistedMessages` option, so the gateway enforces the cap
 * itself in the prune path; override per deployment with the
 * `MEMORY_MAX_PERSISTED_MESSAGES` var.
 */
export const DEFAULT_MAX_PERSISTED_MESSAGES = 200;

/**
 * The chat-history table. Schema is IDENTICAL to the one `AIChatAgent` creates
 * and persists `this.messages` into, so on a chat-capable agent class these
 * routes read/prune the SDK's own history; on the plain `Agent` gateway class
 * the table simply starts empty.
 */
export const CHAT_MESSAGES_TABLE = "cf_ai_chat_agent_messages";

/** Upper bound accepted for `chat/get` limits and semantic `topK`. */
const MAX_CHAT_GET_LIMIT = 1000;
const MAX_SEMANTIC_TOP_K = 20;

/** Upper bound on messages accepted by one `chat/append` call. */
const MAX_CHAT_APPEND_BATCH = 100;

/**
 * Upper bound on a chat message's `id`. The id is the table's primary key and
 * is otherwise caller-chosen and unbounded; a cap keeps a single row's key from
 * being an unbounded allocation of its own.
 */
export const MAX_CHAT_MESSAGE_ID_CHARS = 256;

/** Workers AI embedding model used by the semantic-memory pilot (beta). */
export const SEMANTIC_EMBEDDING_MODEL = "@cf/baai/bge-m3";

/**
 * Vectorize caps a namespace name at 64 BYTES. A minted instance name
 * (`fg.{tenant}.{session}.{run}`, components up to 64 chars each) reaches 197
 * bytes, so the name cannot be used as the namespace verbatim — see
 * {@link vectorizeNamespace}.
 */
export const MAX_VECTORIZE_NAMESPACE_BYTES = 64;

// ---------------------------------------------------------------------------
// RPC-safe result envelope
// ---------------------------------------------------------------------------

/**
 * Error vocabulary carried across the Durable Object RPC boundary. Class-based
 * exceptions lose their identity over DO RPC, so the memory methods return a
 * discriminated result instead of throwing; the route maps each code onto an
 * HTTP status (`invalid_state` → 422, `sqlite_full` → 507, `sql_error` → 400,
 * `sql_forbidden` → 403).
 */
export type MemoryErrorCode =
  | "invalid_state"
  | "sqlite_full"
  | "sql_error"
  | "sql_forbidden";

/** Discriminated success/failure envelope returned by every memory RPC verb. */
export type MemoryResult<T> =
  | ({ ok: true } & T)
  | { ok: false; code: MemoryErrorCode; message: string };

/** SQL bindings accepted over the wire (the SqlStorage binding vocabulary). */
export type SqlBinding = string | number | boolean | null;

/** Raw rows handed back by the host's SqlStorage exec. */
export interface RawSqlResult {
  columns: string[];
  rows: Record<string, unknown>[];
}

/**
 * The slice of the agent the memory verbs need. `AgentGateway` satisfies it
 * structurally; keeping the verbs against this seam keeps them out of index.ts
 * (engineering standard #429) and unit-testable without a Durable Object.
 */
export interface AgentMemoryHost {
  /** The agent instance name — the isolation unit. */
  name: string;
  /** Layer 1: the synced JSON state (whole-object replace via setState). */
  state: AgentGatewayState;
  setState(state: AgentGatewayState): void;
  /** Layer 2: the embedded per-agent SQLite (DO SqlStorage exec). */
  rawSql(query: string, bindings: SqlBinding[]): RawSqlResult;
  /**
   * Run `body` as ONE all-or-nothing SQLite transaction: a throw rolls back
   * every statement it issued. A multi-row write needs this — see
   * {@link memoryChatHistoryAppend}, whose retention cap is only a guarantee if
   * a half-written batch cannot survive.
   */
  transactionSync<T>(body: () => T): T;
  /** The enforced chat-history retention cap (layer 3). */
  maxPersistedMessages: number;
}

/**
 * Parse the `MEMORY_MAX_PERSISTED_MESSAGES` var, falling back to the default.
 *
 * A blank value counts as UNCONFIGURED, not as zero. `Number("")` is `0`, so
 * without this an env var that is declared but left empty would set the cap to
 * zero — and a cap of zero means every prune deletes the entire chat history.
 * A misconfiguration must not silently become a retain-nothing policy; an
 * explicit `"0"` still selects it.
 */
export function persistedMessageCap(raw: string | undefined): number {
  if (raw === undefined || raw.trim().length === 0) {
    return DEFAULT_MAX_PERSISTED_MESSAGES;
  }
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0) {
    return DEFAULT_MAX_PERSISTED_MESSAGES;
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Layer 1: synced JSON state
// ---------------------------------------------------------------------------

const RUN_STATUSES: readonly string[] = [
  "queued",
  "running",
  "completed",
  "failed",
  "stopped",
  "cleaned_up",
];

/** Keys of {@link AgentGatewayState} that must be `string | null`. */
const NULLABLE_STRING_KEYS = [
  "runId",
  "sessionId",
  "workerTemplateId",
  "frameworkAdapter",
  "capabilityEnvelopeId",
  "resolvedModel",
  "resolvedSystemPrompt",
  "resolvedLocationHint",
  "cancelReason",
  "lastMessage",
] as const;

/**
 * Server-side state validation (the `validateStateChange` principle: a failed
 * validation ABORTS the write). Checks shape against {@link AgentGatewayState}
 * — state is a whole-object replace, so a partial or mistyped object would
 * silently corrupt the lifecycle record — and enforces the 2 MB value limit.
 * Returns an error message, or `null` when the candidate is acceptable.
 */
export function validateStateChange(candidate: unknown): string | null {
  if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) {
    return "state must be a JSON object (whole-object replace)";
  }
  const bytes = new TextEncoder().encode(JSON.stringify(candidate)).length;
  if (bytes > MAX_SQL_VALUE_BYTES) {
    return `state is ${bytes} bytes; the Durable Object SQLite value limit is ${MAX_SQL_VALUE_BYTES}`;
  }
  const record = candidate as Record<string, unknown>;
  if (typeof record.status !== "string" || !RUN_STATUSES.includes(record.status)) {
    return `state.status must be one of ${RUN_STATUSES.join("/")}`;
  }
  for (const key of NULLABLE_STRING_KEYS) {
    const value = record[key];
    if (value !== null && typeof value !== "string") {
      return `state.${key} must be a string or null`;
    }
  }
  const tools = record.resolvedTools;
  if (!Array.isArray(tools) || tools.some((t) => typeof t !== "string")) {
    return "state.resolvedTools must be an array of strings";
  }
  if (record.exitCode !== null && typeof record.exitCode !== "number") {
    return "state.exitCode must be a number or null";
  }
  if (record.recordedRoutingRetry !== null && typeof record.recordedRoutingRetry !== "number") {
    return "state.recordedRoutingRetry must be a number or null";
  }
  // The DURABLE half of the #414 cancel latch. A memory write that dropped or
  // mistyped it would let a cancelled run be re-invoked, so it is validated like
  // every other lifecycle field rather than trusted.
  if (typeof record.cancelRequested !== "boolean") {
    return "state.cancelRequested must be a boolean";
  }
  if (typeof record.updatedAt !== "number") {
    return "state.updatedAt must be a number";
  }
  return null;
}

/** RPC verb: read the synced JSON state (layer 1). */
export function memoryStateGet(
  host: AgentMemoryHost,
): MemoryResult<{ instance: string; state: AgentGatewayState }> {
  return { ok: true, instance: host.name, state: host.state };
}

/**
 * RPC verb: whole-object state replace (layer 1). Validation failure aborts
 * the write — nothing is persisted, matching `validateStateChange` semantics.
 */
export function memoryStateSet(
  host: AgentMemoryHost,
  candidate: unknown,
): MemoryResult<{ instance: string; state: AgentGatewayState }> {
  const violation = validateStateChange(candidate);
  if (violation) {
    return { ok: false, code: "invalid_state", message: violation };
  }
  const next = candidate as unknown as AgentGatewayState;
  host.setState({ ...next, status: next.status as RunStatus });
  return { ok: true, instance: host.name, state: host.state };
}

// ---------------------------------------------------------------------------
// Layer 2: embedded per-agent SQLite
// ---------------------------------------------------------------------------

/** True when a SqlStorage failure is the 10 GB-full condition (SQLITE_FULL). */
function isSqliteFull(message: string): boolean {
  return /SQLITE_FULL|database or disk is full/i.test(message);
}

/**
 * Identifier prefix owned by the Agents SDK's own control tables inside the
 * per-instance SQLite (`cf_agents_state`, `cf_agents_schedules`, …).
 *
 * These tables are the STORAGE BEHIND governance decisions made elsewhere, so
 * caller-supplied SQL must not reach them at all — see {@link reservedTableViolation}.
 */
const RESERVED_TABLE_PREFIX = "cf_agents_";

/**
 * The quoted regions SQLite's tokenizer recognises, and how each one ends.
 *
 * Inside any of these, the OTHER openers are ordinary characters: `--` in
 * `"a--b"` starts no comment, `'` in `` `a'b` `` starts no literal. A scanner
 * that misses that desynchronizes from SQLite's tokenizer, and the region it
 * wrongly swallows is exactly where a reserved name hides.
 *
 * `[…]` has no escape — SQLite ends the identifier at the first `]`. The other
 * three double their closer to escape it.
 */
const QUOTED_REGIONS: Record<string, { close: string; doubled: boolean; label: string }> = {
  "'": { close: "'", doubled: true, label: "string literal" },
  '"': { close: '"', doubled: true, label: "quoted identifier" },
  "`": { close: "`", doubled: true, label: "backquoted identifier" },
  "[": { close: "]", doubled: false, label: "bracketed identifier" },
};

/** A quoted region's body plus the offset just past its closer. */
interface QuotedRegion {
  body: string;
  next: number;
}

/** Read the quoted region opening at `start`, or `null` when it never closes. */
function readQuotedRegion(
  sql: string,
  start: number,
  close: string,
  doubled: boolean,
): QuotedRegion | null {
  let body = "";
  let i = start + 1;
  while (i < sql.length) {
    if (sql[i] === close) {
      if (doubled && sql[i + 1] === close) {
        body += close;
        i += 2;
        continue;
      }
      return { body, next: i + 1 };
    }
    body += sql[i];
    i += 1;
  }
  return null;
}

/** Everything the reserved-name scan must read, or the reason it cannot. */
type ScanSubject = { text: string } | { unterminated: string };

/**
 * Reduce `sql` to the text a reserved-name scan must read, tokenizing exactly
 * where SQLite does.
 *
 * What survives, and why:
 *
 * - **Code** — verbatim; this is where an unquoted table name appears.
 * - **Every quoted region's body**, space-padded — including single-quoted
 *   ones. SQLite accepts a single-quoted token as an IDENTIFIER wherever an
 *   identifier is legal and a string is not, so `insert into
 *   'cf_agents_schedules' …` really does name the control table. Telling that
 *   apart from a string that merely mentions the name needs a full parser, so
 *   the guard reads both and refuses both — a caller that legitimately needs
 *   the text passes it as a bound parameter, which is never scanned.
 *   The padding matters: `from"cf_agents_state"` is valid SQLite, and joining
 *   the body to `from` would put a word character before the name and defeat
 *   the scan's `\b` anchor.
 * - **Comments** — dropped. A comment separates tokens rather than splicing
 *   them, so `cf/*x*\/_agents_state` is two tokens, not a reference; dropping
 *   splices them into one and the guard refuses. That is a false positive, and
 *   the safe direction: removal can only create matches, never destroy one.
 *
 * A region that never closes is reported instead of swallowed. Unterminated
 * quoting is a SQLite syntax error anyway, so refusing it costs nothing and
 * turns the guard's worst failure mode — scan past the end, find nothing,
 * allow — into a refusal.
 */
function scanSubject(sql: string): ScanSubject {
  let out = "";
  let i = 0;
  while (i < sql.length) {
    const two = sql.slice(i, i + 2);
    if (two === "--") {
      const nl = sql.indexOf("\n", i);
      i = nl === -1 ? sql.length : nl;
      continue;
    }
    if (two === "/*") {
      const end = sql.indexOf("*/", i + 2);
      if (end === -1) return { unterminated: "block comment" };
      i = end + 2;
      continue;
    }
    const region = QUOTED_REGIONS[sql[i]];
    if (region) {
      const read = readQuotedRegion(sql, i, region.close, region.doubled);
      if (!read) return { unterminated: region.label };
      out += ` ${read.body} `;
      i = read.next;
      continue;
    }
    out += sql[i];
    i += 1;
  }
  return { text: out };
}

/**
 * Reject caller SQL that names an Agents SDK control table.
 *
 * Without this the `/memory/sql/query` route is a hole under two invariants
 * this same surface documents as enforced:
 *
 * 1. `validateStateChange` "aborts the write" — but the SDK persists the synced
 *    state in `cf_agents_state`, so an
 *    `insert or replace into cf_agents_state ...` writes unvalidated state
 *    straight past {@link memoryStateSet}.
 * 2. {@link SCHEDULE_DISPATCH_METHOD} pins the only method a schedule may
 *    dispatch — but the SDK's alarm invokes `this[row.callback]` from a
 *    `cf_agents_schedules` row, so an INSERT there re-opens the arbitrary-verb
 *    dispatch that pin closes.
 *
 * The rule is deliberately blunt — a reserved identifier ANYWHERE in the
 * statement is refused, reads included, in code AND inside every form of
 * quoting — because "which position is a write" needs a SQL parser, and a
 * partial parser is exactly how this kind of guard fails. {@link scanSubject}
 * therefore reads quoted bodies rather than skipping them, and refuses a
 * statement it cannot tokenize to the end.
 *
 * Nothing legitimate is lost: layer 1 is served by
 * {@link memoryStateGet}/{@link memoryStateSet} and schedules by the #426
 * routes, both of which apply their governance; a statement that needs the
 * literal text `cf_agents_…` as DATA passes it as a bound parameter, which the
 * scan never sees.
 *
 * Returns a refusal message, or `null` when the statement is acceptable.
 */
export function reservedTableViolation(sql: string): string | null {
  const subject = scanSubject(sql);
  if ("unterminated" in subject) {
    return (
      `statement has an unterminated ${subject.unterminated}; ` +
      `it cannot be checked against the reserved Agents SDK control tables and is refused`
    );
  }
  const match = new RegExp(`\\b${RESERVED_TABLE_PREFIX}\\w*`).exec(
    subject.text.toLowerCase(),
  );
  if (!match) return null;
  return (
    `statement references the reserved Agents SDK control table '${match[0]}'; ` +
    `use /memory/state/* for agent state and the /schedule/* routes for schedules`
  );
}

/**
 * RPC verb: run one SQL statement against the agent's embedded SQLite
 * (layer 2). On SQLITE_FULL the failure is surfaced as a typed code so the
 * FerroGate client can run its prune path — reads and DELETEs still succeed
 * on a full database, which is exactly what pruning relies on.
 *
 * The statement is refused up front when it names an SDK control table
 * ({@link reservedTableViolation}); the guard sits here rather than in the
 * route so it also covers the direct Durable Object RPC entry point.
 */
export function memorySqlQuery(
  host: AgentMemoryHost,
  sql: string,
  params: SqlBinding[],
): MemoryResult<{
  instance: string;
  columns: string[];
  rows: Record<string, unknown>[];
  rowCount: number;
}> {
  const forbidden = reservedTableViolation(sql);
  if (forbidden) {
    // A governance refusal is an auditable event, not just a status code: the
    // issue's tethered principle makes memory access an auth/quota/AUDIT
    // operation, and a 403 that leaves no trace tells an operator nothing
    // about WHICH instance tried to reach the SDK control tables. The refusal
    // message (which names the reserved table) is logged; the caller's SQL is
    // NOT, because it can carry tenant data.
    console.warn("memory.sql_forbidden", {
      instance: host.name,
      reason: forbidden,
    });
    return { ok: false, code: "sql_forbidden", message: forbidden };
  }
  try {
    const result = host.rawSql(sql, params);
    return {
      ok: true,
      instance: host.name,
      columns: result.columns,
      rows: result.rows,
      rowCount: result.rows.length,
    };
  } catch (err) {
    const message = (err as Error).message ?? String(err);
    if (isSqliteFull(message)) {
      return { ok: false, code: "sqlite_full", message };
    }
    return { ok: false, code: "sql_error", message };
  }
}

// ---------------------------------------------------------------------------
// Layer 3: chat history
// ---------------------------------------------------------------------------

/** Create the SDK-identical chat table when absent (plain-Agent instances). */
function ensureChatTable(host: AgentMemoryHost): void {
  host.rawSql(
    `create table if not exists ${CHAT_MESSAGES_TABLE} (
      id text primary key,
      message text not null,
      created_at datetime default current_timestamp
    )`,
    [],
  );
}

/** Current row count of the chat table (the table must already exist). */
function countChatMessages(host: AgentMemoryHost): number {
  const result = host.rawSql(`select count(*) as n from ${CHAT_MESSAGES_TABLE}`, []);
  return Number(result.rows[0]?.n ?? 0);
}

/** One chat-history record; `message` is the SDK's persisted JSON, parsed. */
export interface ChatHistoryRecord {
  id: string;
  message: unknown;
  createdAt: string | null;
}

/** One message accepted by {@link memoryChatHistoryAppend}. */
export interface ChatMessageInput {
  /** Caller-chosen id; the table's primary key. */
  id: string;
  /** Message payload. Persisted as the SDK does: JSON text in `message`. */
  message: unknown;
}

/** True when `value` is a usable {@link ChatMessageInput}. */
export function isChatMessageInput(value: unknown): value is ChatMessageInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.id === "string" && record.id.length > 0 && "message" in record
  );
}

/**
 * RPC verb: append messages to the chat history (layer 3).
 *
 * Layer 3 needs a writer for the rest of the layer to mean anything: the
 * deployed class is a plain `Agent`, not `AIChatAgent`, so nothing else in this
 * Worker ever INSERTs into {@link CHAT_MESSAGES_TABLE}. Without this verb the
 * table is permanently empty, which makes `chat/prune` delete nothing and the
 * client's SQLITE_FULL recovery path free no bytes — a documented eviction
 * mechanism that cannot evict.
 *
 * The retention cap is applied in the SAME call, so history cannot exceed
 * `maxPersistedMessages` between an append and some later prune. That holds on
 * BOTH paths, which is why the batch is atomic: a per-row loop that failed
 * halfway would leave the earlier rows persisted and never reach the prune,
 * parking the table above the cap while reporting failure. The batch is one
 * `transactionSync`, and the failure path still prunes before returning, so
 * "history is at or below the cap once this returns" is true either way.
 *
 * A row whose id already exists is REPLACEd, keeping the id the caller's
 * idempotency key.
 */
export function memoryChatHistoryAppend(
  host: AgentMemoryHost,
  messages: ChatMessageInput[],
): MemoryResult<{
  instance: string;
  appended: number;
  cap: number;
  pruned: number;
  remaining: number;
}> {
  try {
    ensureChatTable(host);
    host.transactionSync(() => {
      for (const entry of messages) {
        host.rawSql(
          `insert or replace into ${CHAT_MESSAGES_TABLE} (id, message) values (?, ?)`,
          [entry.id, JSON.stringify(entry.message ?? null)],
        );
      }
    });
  } catch (err) {
    const message = (err as Error).message ?? String(err);
    // The batch rolled back, but the table can already have been over the cap
    // before this call (layer 2 can INSERT into it directly), so the
    // post-condition still needs a prune. Best-effort: a prune that also fails
    // must not replace the error the caller actually needs to see.
    memoryChatHistoryPrune(host);
    if (isSqliteFull(message)) {
      return { ok: false, code: "sqlite_full", message };
    }
    return { ok: false, code: "sql_error", message };
  }
  const pruned = memoryChatHistoryPrune(host);
  if (!pruned.ok) return pruned;
  return {
    ok: true,
    instance: host.name,
    appended: messages.length,
    cap: pruned.cap,
    pruned: pruned.pruned,
    remaining: pruned.remaining,
  };
}

/** RPC verb: read the newest `limit` chat messages, oldest-first (layer 3). */
export function memoryChatHistoryGet(
  host: AgentMemoryHost,
  limit?: number,
): MemoryResult<{ instance: string; messages: ChatHistoryRecord[]; count: number }> {
  const effective =
    Number.isInteger(limit) && (limit as number) > 0
      ? Math.min(limit as number, MAX_CHAT_GET_LIMIT)
      : MAX_CHAT_GET_LIMIT;
  try {
    ensureChatTable(host);
    // Newest N by insertion order, then reversed so callers read oldest-first.
    const result = host.rawSql(
      `select id, message, created_at from ${CHAT_MESSAGES_TABLE} order by rowid desc limit ?`,
      [effective],
    );
    const messages = result.rows
      .map((row) => ({
        id: String(row.id),
        message: parseMessage(row.message),
        createdAt: row.created_at === null || row.created_at === undefined
          ? null
          : String(row.created_at),
      }))
      .reverse();
    return { ok: true, instance: host.name, messages, count: messages.length };
  } catch (err) {
    const message = (err as Error).message ?? String(err);
    return { ok: false, code: "sql_error", message };
  }
}

function parseMessage(raw: unknown): unknown {
  if (typeof raw !== "string") return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

/**
 * RPC verb: prune chat history down to a retention cap (layer 3). The
 * effective cap never exceeds the deployment's `maxPersistedMessages`; callers
 * may only tighten it. Pruning DELETEs oldest-first, which remains possible
 * even when the database is at the SQLITE_FULL limit.
 */
export function memoryChatHistoryPrune(
  host: AgentMemoryHost,
  maxMessages?: number,
): MemoryResult<{ instance: string; cap: number; pruned: number; remaining: number }> {
  const requested =
    Number.isInteger(maxMessages) && (maxMessages as number) >= 0
      ? (maxMessages as number)
      : host.maxPersistedMessages;
  const cap = Math.min(requested, host.maxPersistedMessages);
  try {
    ensureChatTable(host);
    const total = countChatMessages(host);
    if (total > cap) {
      host.rawSql(
        `delete from ${CHAT_MESSAGES_TABLE} where rowid not in (
          select rowid from ${CHAT_MESSAGES_TABLE} order by rowid desc limit ?
        )`,
        [cap],
      );
    }
    // Re-COUNT rather than reporting `Math.min(total, cap)`: the eviction
    // outcome FerroGate records has to be an observation of the table, not an
    // assumption about what the DELETE did.
    const remaining = countChatMessages(host);
    return {
      ok: true,
      instance: host.name,
      cap,
      pruned: total - remaining,
      remaining,
    };
  } catch (err) {
    const message = (err as Error).message ?? String(err);
    return { ok: false, code: "sql_error", message };
  }
}

// ---------------------------------------------------------------------------
// Route dispatch
// ---------------------------------------------------------------------------

const ERROR_STATUS: Record<MemoryErrorCode, number> = {
  invalid_state: 422,
  sqlite_full: 507,
  sql_error: 400,
  sql_forbidden: 403,
};

/**
 * Structural (non-generic) envelope view: DO RPC stubs intersect returns with
 * `Disposable`, which defeats `MemoryResult<T>` inference at the call sites.
 */
type MemoryResultLike =
  | { ok: true }
  | { ok: false; code: MemoryErrorCode; message: string };

function memoryResponse(result: MemoryResultLike): Response {
  if (!result.ok) {
    return json(
      { error: result.code, message: result.message },
      ERROR_STATUS[result.code],
    );
  }
  return json(result);
}

interface MemoryRequestBody {
  instance?: unknown;
  state?: unknown;
  sql?: unknown;
  params?: unknown;
  limit?: unknown;
  maxMessages?: unknown;
  messages?: unknown;
  query?: unknown;
  topK?: unknown;
}

function isSqlBinding(value: unknown): value is SqlBinding {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  );
}

/**
 * Memory routes (issue #427), all POST + bearer-gated. POST bodies (never
 * query strings) carry the instance name, since names embed tenant identity:
 *
 *   POST /memory/state/get      { instance }                  layer 1 read
 *   POST /memory/state/set      { instance, state }           layer 1 whole-object replace
 *   POST /memory/sql/query      { instance, sql, params? }    layer 2 (507 on SQLITE_FULL)
 *   POST /memory/chat/append    { instance, messages }        layer 3 write (capped)
 *   POST /memory/chat/get       { instance, limit? }          layer 3 read
 *   POST /memory/chat/prune     { instance, maxMessages? }    layer 3 eviction
 *   POST /memory/semantic/query { instance, query, topK? }    Vectorize pilot (default OFF)
 *
 * The `instance` name is minted by the Rust side's naming scheme
 * (`fg.{tenant}.{session}.{run}`): per-instance DO isolation therefore IS
 * tenant isolation, and the Worker never derives names itself.
 */
export async function handleMemory(request: Request, env: Env, url: URL): Promise<Response> {
  const denied = requireBearer(request, env.GATEWAY_CONTROL_TOKEN);
  if (denied) return denied;
  if (request.method !== "POST") {
    return json({ error: "memory routes are POST-only" }, 405);
  }

  let body: MemoryRequestBody;
  try {
    body = (await request.json()) as MemoryRequestBody;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const instance = body.instance;
  if (typeof instance !== "string" || instance.length === 0 || instance.length > 512) {
    return json({ error: "missing or invalid instance name" }, 400);
  }

  const verb = url.pathname.slice("/memory/".length);
  if (verb === "semantic/query") {
    return handleSemanticQuery(env, instance, body);
  }

  try {
    const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, instance);
    switch (verb) {
      case "state/get":
        return memoryResponse(await agent.memoryStateGet());
      case "state/set":
        return memoryResponse(await agent.memoryStateSet(body.state));
      case "sql/query": {
        if (typeof body.sql !== "string" || body.sql.length === 0) {
          return json({ error: "missing sql" }, 400);
        }
        const params = body.params ?? [];
        if (!Array.isArray(params) || !params.every(isSqlBinding)) {
          return json({ error: "params must be string|number|boolean|null" }, 400);
        }
        // Measured in BYTES, matching the Durable Object's own limit — a
        // `.length` check counts UTF-16 code units and lets a multi-byte
        // string several times over the limit through the pre-check.
        const encoder = new TextEncoder();
        const oversize = params.find(
          (p) => typeof p === "string" && encoder.encode(p).length > MAX_SQL_VALUE_BYTES,
        );
        if (oversize !== undefined) {
          return json(
            { error: "param exceeds the 2 MB Durable Object value limit" },
            413,
          );
        }
        return memoryResponse(await agent.memorySqlQuery(body.sql, params));
      }
      case "chat/append": {
        const messages = body.messages;
        if (!Array.isArray(messages) || messages.length === 0) {
          return json({ error: "messages must be a non-empty array" }, 400);
        }
        if (messages.length > MAX_CHAT_APPEND_BATCH) {
          return json(
            { error: `messages exceeds the ${MAX_CHAT_APPEND_BATCH}-message batch limit` },
            413,
          );
        }
        if (!messages.every(isChatMessageInput)) {
          return json({ error: "each message needs a non-empty id and a message field" }, 400);
        }
        if (messages.some((m) => m.id.length > MAX_CHAT_MESSAGE_ID_CHARS)) {
          return json(
            { error: `message id exceeds the ${MAX_CHAT_MESSAGE_ID_CHARS}-character limit` },
            400,
          );
        }
        // Same 2 MB pre-check the other two write paths apply, measured in
        // BYTES on the JSON actually persisted — without it an oversize
        // message reaches the Durable Object and comes back as a 400
        // `sql_error`, when the limit it hit is the one `state/set` and
        // `sql/query` both report as 413.
        const chatEncoder = new TextEncoder();
        const oversizeMessage = messages.some(
          (m) =>
            chatEncoder.encode(JSON.stringify(m.message ?? null)).length >
            MAX_SQL_VALUE_BYTES,
        );
        if (oversizeMessage) {
          return json(
            { error: "message exceeds the 2 MB Durable Object value limit" },
            413,
          );
        }
        return memoryResponse(await agent.memoryChatHistoryAppend(messages));
      }
      case "chat/get":
        return memoryResponse(
          await agent.memoryChatHistoryGet(
            typeof body.limit === "number" ? body.limit : undefined,
          ),
        );
      case "chat/prune":
        return memoryResponse(
          await agent.memoryChatHistoryPrune(
            typeof body.maxMessages === "number" ? body.maxMessages : undefined,
          ),
        );
      default:
        return json({ error: `unknown memory verb: ${verb}` }, 404);
    }
  } catch (err) {
    return json({ error: `memory call failed: ${(err as Error).message}` }, 502);
  }
}

// ---------------------------------------------------------------------------
// Semantic-memory pilot (Vectorize + Workers AI embeddings) — BETA, default OFF
// ---------------------------------------------------------------------------

/**
 * Semantic long-term memory over Vectorize (open beta). The pilot ships
 * DEFAULT-OFF: it activates only when `MEMORY_SEMANTIC_ENABLED="true"` AND the
 * `VECTORIZE` + `AI` bindings are configured (both are commented out in
 * wrangler.toml). Queries embed via Workers AI and search the index scoped to
 * the instance's Vectorize NAMESPACE ({@link vectorizeNamespace}), so semantic
 * recall inherits the same per-instance (= per-tenant) isolation as layers 1–3.
 */
/**
 * Prefix marking a HASHED Vectorize namespace. Minted instance names always
 * begin `fg.`, and `.` is not in this prefix's charset, so a hashed namespace
 * can never collide with a verbatim one.
 */
const HASHED_NAMESPACE_PREFIX = "fgh_";

/**
 * Map an agent instance name onto the Vectorize namespace that isolates its
 * vectors.
 *
 * The namespace IS the only isolation mechanism semantic memory has, and
 * Vectorize caps it at {@link MAX_VECTORIZE_NAMESPACE_BYTES} bytes — but a
 * minted `fg.{tenant}.{session}.{run}` name reaches 197 bytes (a realistic UUID
 * triple is ~110), so passing the name through verbatim makes every real query
 * fail at the platform. Names that fit are used verbatim; longer ones collapse
 * to `fgh_` + 60 hex chars of their SHA-256, which is exactly 64 bytes and stays
 * injective in practice (240 bits of digest).
 *
 * Write-side indexing is a follow-up (the pilot is query-only), so this is the
 * single place the recipe is defined — a writer must derive its namespace the
 * same way or it will index into a namespace no query can see.
 */
export async function vectorizeNamespace(instance: string): Promise<string> {
  const encoded = new TextEncoder().encode(instance);
  if (encoded.length <= MAX_VECTORIZE_NAMESPACE_BYTES) {
    return instance;
  }
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  const hex = [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return (
    HASHED_NAMESPACE_PREFIX +
    hex.slice(0, MAX_VECTORIZE_NAMESPACE_BYTES - HASHED_NAMESPACE_PREFIX.length)
  );
}

async function handleSemanticQuery(
  env: Env,
  instance: string,
  body: MemoryRequestBody,
): Promise<Response> {
  if (env.MEMORY_SEMANTIC_ENABLED !== "true") {
    return json(
      {
        error: "semantic_memory_disabled",
        beta: true,
        hint: "set MEMORY_SEMANTIC_ENABLED=\"true\" and bind VECTORIZE + AI to enable the pilot",
      },
      501,
    );
  }
  if (!env.VECTORIZE || !env.AI) {
    return json(
      { error: "semantic_memory_unbound", beta: true, hint: "VECTORIZE and AI bindings are required" },
      501,
    );
  }
  if (typeof body.query !== "string" || body.query.length === 0) {
    return json({ error: "missing query" }, 400);
  }
  const topK =
    typeof body.topK === "number" && Number.isInteger(body.topK) && body.topK > 0
      ? Math.min(body.topK, MAX_SEMANTIC_TOP_K)
      : 5;

  try {
    // The Ai model catalog types churn per workers-types release; the pilot
    // calls through a narrow structural view instead of the generated catalog.
    const ai = env.AI as unknown as {
      run(model: string, input: unknown): Promise<unknown>;
    };
    const embedding = (await ai.run(SEMANTIC_EMBEDDING_MODEL, {
      text: [body.query],
    })) as { data?: number[][] };
    const vector = embedding.data?.[0];
    if (!vector) {
      return json({ error: "embedding model returned no vector" }, 502);
    }
    const namespace = await vectorizeNamespace(instance);
    const matches = await env.VECTORIZE.query(vector, {
      topK,
      namespace,
      returnMetadata: "all",
    });
    return json({
      ok: true,
      instance,
      namespace,
      beta: true,
      matches: matches.matches.map((m) => ({
        id: m.id,
        score: m.score,
        metadata: m.metadata ?? null,
      })),
    });
  } catch (err) {
    return json({ error: `semantic query failed: ${(err as Error).message}` }, 502);
  }
}
