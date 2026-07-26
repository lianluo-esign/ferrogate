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

/** Workers AI embedding model used by the semantic-memory pilot (beta). */
export const SEMANTIC_EMBEDDING_MODEL = "@cf/baai/bge-m3";

// ---------------------------------------------------------------------------
// RPC-safe result envelope
// ---------------------------------------------------------------------------

/**
 * Error vocabulary carried across the Durable Object RPC boundary. Class-based
 * exceptions lose their identity over DO RPC, so the memory methods return a
 * discriminated result instead of throwing; the route maps each code onto an
 * HTTP status (`invalid_state` → 422, `sqlite_full` → 507, `sql_error` → 400).
 */
export type MemoryErrorCode = "invalid_state" | "sqlite_full" | "sql_error";

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
  /** The enforced chat-history retention cap (layer 3). */
  maxPersistedMessages: number;
}

/** Parse the `MEMORY_MAX_PERSISTED_MESSAGES` var, falling back to the default. */
export function persistedMessageCap(raw: string | undefined): number {
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
 * RPC verb: run one SQL statement against the agent's embedded SQLite
 * (layer 2). On SQLITE_FULL the failure is surfaced as a typed code so the
 * FerroGate client can run its prune path — reads and DELETEs still succeed
 * on a full database, which is exactly what pruning relies on.
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

/** One chat-history record; `message` is the SDK's persisted JSON, parsed. */
export interface ChatHistoryRecord {
  id: string;
  message: unknown;
  createdAt: string | null;
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
    const before = host.rawSql(
      `select count(*) as n from ${CHAT_MESSAGES_TABLE}`,
      [],
    );
    const total = Number(before.rows[0]?.n ?? 0);
    if (total > cap) {
      host.rawSql(
        `delete from ${CHAT_MESSAGES_TABLE} where rowid not in (
          select rowid from ${CHAT_MESSAGES_TABLE} order by rowid desc limit ?
        )`,
        [cap],
      );
    }
    const remaining = Math.min(total, cap);
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
        const oversize = params.find(
          (p) => typeof p === "string" && p.length > MAX_SQL_VALUE_BYTES,
        );
        if (oversize !== undefined) {
          return json(
            { error: "param exceeds the 2 MB Durable Object value limit" },
            413,
          );
        }
        return memoryResponse(await agent.memorySqlQuery(body.sql, params));
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
 * the instance's Vectorize NAMESPACE, so semantic recall inherits the same
 * per-instance (= per-tenant) isolation as layers 1–3.
 */
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
    const matches = await env.VECTORIZE.query(vector, {
      topK,
      namespace: instance,
      returnMetadata: "all",
    });
    return json({
      ok: true,
      instance,
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
