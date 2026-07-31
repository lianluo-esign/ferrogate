/**
 * The DURABLE {@link ApprovalPort} — the human step-up gate for a tool that is
 * NOT `auto_execute`.
 *
 * ## What this closes, and why it mattered
 *
 * `AutoApproval` returned `undefined` for every call, i.e. it APPROVED
 * everything. The marker on it read "NOT a platform limit — a deferral on
 * ANOTHER APP … binding it means a `[[services]]` service binding or a shared
 * D1 read, neither of which this Worker can create unilaterally." The second
 * option needs nothing new: `apps/control-plane` keeps tool approvals as
 * `control_plane_resources` rows of kind `tool-approvals`
 * (`routes/admin_tool.ts`, `GET/POST /admin/v1/tool-approvals/…`) in the
 * CONTROL database, and this Worker already binds that database as `env.DB`.
 * So the queue was reachable from here all along; the reader was missing, and
 * meanwhile every non-auto-execute MCP tool ran with NO approval at all.
 *
 * ## The one behavior that genuinely could not be ported, and what replaces it
 *
 * Rust's `crates/ferrogate-gateway/src/approval.rs` creates the pending record
 * and then **blocks the caller** on a `tokio::sync::Notify` until a reviewer
 * decides or `approval_timeout_secs` elapses. A Worker cannot do that and must
 * not pretend to: an isolate has a wall-clock/CPU budget measured in seconds,
 * `Notify` is process-local while an approval may be decided in a different
 * colo entirely, and holding the request open would burn duration billing
 * waiting on a human. There is no cross-isolate "wake me" primitive that is
 * free while idle.
 *
 * IMPLEMENTED INSTEAD — a POLL, which is the same state machine without the
 * blocking edge:
 *
 *  1. no record for this fingerprint ⇒ CREATE the pending row (so it appears in
 *     `GET /admin/v1/tool-approvals` for a reviewer) and refuse this call with
 *     `approval_pending`;
 *  2. `pending` ⇒ refuse with `approval_pending` (and never re-create the row —
 *     the fingerprint is the idempotency key, so a client retry loop cannot
 *     flood the reviewer's queue);
 *  3. `approved` and not past `expires_at` ⇒ ALLOW;
 *  4. `denied` / `expired` / anything unrecognized ⇒ refuse.
 *
 * The caller retries and is admitted on the retry that follows the approval.
 * The refusal is a `403 tool_denied`-class answer either way, so a client that
 * cannot distinguish them is no worse off than under Rust's timeout arm.
 *
 * ## FAIL CLOSED, always
 *
 * A database this gate cannot read refuses the call. That is deliberate and is
 * the opposite of what a cache would do: the entire point of the port is that a
 * risky tool does not run without a decision, so "we could not check" must mean
 * "not approved". The previous behavior — approve everything — is precisely the
 * failure mode this replaces.
 *
 * ## The fingerprint
 *
 * Rust hashes a canonical JSON of (request_id, trace_id, tenant, actor key,
 * tool, server, route, policy, config snapshot, canonicalized arguments) with
 * Blake2b and keeps the leading 8 bytes. Two deliberate divergences, both
 * recorded rather than silent:
 *
 *  * **SHA-256, not Blake2b.** WebCrypto in workerd has no Blake2b, and the
 *    hash here is an identity/idempotency key rather than a MAC, so the
 *    substitution is safe. Same treatment as the AES-GCM-for-XChaCha20
 *    substitution in `src/ports.ts`.
 *  * **`request_id` is NOT in the input.** In Rust the approval is bound to one
 *    invocation because the caller BLOCKS inside that invocation. Here the
 *    caller must come back on a LATER request, so including the request id
 *    would make every retry a brand-new pending record and no approval could
 *    ever be redeemed. The fingerprint is therefore over the tenant, the actor
 *    key, the tool and the exact arguments — which is what makes "approve THIS
 *    call with THESE arguments" mean what it says: change one argument byte and
 *    the approval no longer applies.
 */
import type { JsonValue } from "@ferrogate/core";

import type { ApprovalPort, AuthContext, DispatchContext, McpTool } from "./ports.js";

/** The `control_plane_resources.resource_kind` `apps/control-plane` uses. */
export const TOOL_APPROVAL_COLLECTION = "tool-approvals";
/** The document store this Worker shares with `apps/control-plane`. */
export const RESOURCE_TABLE = "control_plane_resources";

/** Statuses `routes/admin_tool.ts` can record. Anything else refuses. */
export type ToolApprovalStatus = "pending" | "approved" | "denied" | "expired";

/** The refusal code the chokepoint renders as `403`. */
const REFUSAL_CODE = "tool_denied";

/** Default review window, mirroring Rust's `approval_timeout_secs` default. */
export const DEFAULT_APPROVAL_TIMEOUT_SECS = 900;

/**
 * The stored document. Field names are the ones `routes/admin_tool.ts` writes
 * on a decision (`status`, `decided_at`, `decided_by`, `decision_reason`), so a
 * record created here round-trips through that surface without translation.
 */
export interface ToolApprovalDocument {
  id: string;
  tenant_id?: string;
  object: "tool_approval";
  fingerprint: string;
  status: ToolApprovalStatus;
  tool_name: string;
  server_name: string;
  actor_api_key_id?: string;
  request_id: string;
  trace_id?: string;
  /** #522: the approval joins the caller's correlation chain like every other row. */
  agent_run_id?: string;
  arguments_summary: string;
  risk_reason: string;
  requested_at: number;
  expires_at: number;
  decided_at?: number;
  decided_by?: string | null;
  decision_reason?: string | null;
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/**
 * Canonical JSON: objects with their keys sorted, recursively. Two payloads
 * that differ only in key ORDER must produce the SAME fingerprint, or a client
 * that re-serializes its arguments would need a second approval for a call the
 * reviewer already approved.
 */
export function canonicalizeJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map((entry) => canonicalizeJson(entry));
  if (value === null || typeof value !== "object") return value;
  const sorted: Record<string, JsonValue> = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = canonicalizeJson((value as Record<string, JsonValue>)[key] as JsonValue);
  }
  return sorted;
}

const UTF8 = new TextEncoder();

/** Lowercase hex SHA-256 over the canonical approval input. */
export async function approvalFingerprint(
  auth: AuthContext,
  tool: McpTool,
  args: JsonValue,
): Promise<string> {
  const input = JSON.stringify({
    // The tenancy triple, so one tenant's approval can never redeem another
    // tenant's call even for a byte-identical payload.
    organization_id: auth.organizationId ?? null,
    workspace_id: auth.workspaceId ?? null,
    project_id: auth.projectId ?? null,
    actor_api_key_id: auth.apiKeyId ?? null,
    server_name: tool.serverName,
    tool_name: tool.name,
    arguments: canonicalizeJson(args),
  });
  const digest = await crypto.subtle.digest("SHA-256", UTF8.encode(input));
  let hex = "";
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/** Bounded, non-echoing evidence of what was asked for. */
export function argumentsSummary(args: JsonValue, limit = 256): string {
  const encoded = typeof args === "string" ? args : JSON.stringify(args ?? null);
  return encoded.length <= limit ? encoded : `${encoded.slice(0, limit)}…`;
}

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

export interface D1ToolApprovalsOptions {
  /** Injected unix-SECONDS clock, so the review window is deterministic in tests. */
  readonly now?: () => number;
  /** Review window written onto a newly created record. */
  readonly timeoutSecs?: number;
}

export class D1ToolApprovals implements ApprovalPort {
  readonly #db: D1Database;
  readonly #now: () => number;
  readonly #timeoutSecs: number;

  constructor(db: D1Database, options: D1ToolApprovalsOptions = {}) {
    this.#db = db;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.#timeoutSecs = options.timeoutSecs ?? DEFAULT_APPROVAL_TIMEOUT_SECS;
  }

  async require(
    context: DispatchContext,
    tool: McpTool,
    args: JsonValue,
  ): Promise<{ code: string; message: string } | undefined> {
    const fingerprint = await approvalFingerprint(context.auth, tool, args);
    let record: ToolApprovalDocument | undefined;
    try {
      record = await this.#load(fingerprint);
    } catch (error) {
      // FAIL CLOSED. "Could not check" is not "approved".
      return {
        code: REFUSAL_CODE,
        message: `the approval queue could not be read, so ${tool.name} is refused: ${
          error instanceof Error ? error.message : String(error)
        }`,
      };
    }

    if (record === undefined) {
      try {
        await this.#createPending(fingerprint, context, tool, args);
      } catch (error) {
        return {
          code: REFUSAL_CODE,
          message: `an approval for ${tool.name} could not be raised: ${
            error instanceof Error ? error.message : String(error)
          }`,
        };
      }
      return {
        code: "approval_pending",
        message: `${tool.name} requires an approval; one has been raised and is awaiting a decision`,
      };
    }

    if (record.status === "approved") {
      // An approval that outlived its window is NOT an approval. Checking the
      // window here rather than trusting `status` alone means an approval nobody
      // ever expired cannot be redeemed a month later.
      if (record.expires_at <= this.#now()) {
        return {
          code: REFUSAL_CODE,
          message: `the approval for ${tool.name} expired at ${record.expires_at}`,
        };
      }
      return undefined;
    }

    if (record.status === "pending") {
      return {
        code: "approval_pending",
        message: `${tool.name} is awaiting an approval decision (${record.id})`,
      };
    }
    // `denied`, `expired`, and — deliberately — any status this code does not
    // recognize. An unknown status must never be treated as an approval.
    return {
      code: REFUSAL_CODE,
      message: `the approval for ${tool.name} was ${record.status}`,
    };
  }

  /**
   * The most recent record for this fingerprint.
   *
   * `resource_kind` + a `json_extract` on the document, because
   * `control_plane_resources` is a document table with no typed columns beyond
   * its key — the same access shape `apps/control-plane`'s own store uses. The
   * ordering makes the newest decision win when a fingerprint has been through
   * more than one review cycle.
   */
  async #load(fingerprint: string): Promise<ToolApprovalDocument | undefined> {
    const row = await this.#db
      .prepare(
        `SELECT document_json FROM ${RESOURCE_TABLE}
           WHERE resource_kind = ?
             AND json_extract(document_json, '$.fingerprint') = ?
           ORDER BY updated_at_unix DESC, resource_id DESC
           LIMIT 1`,
      )
      .bind(TOOL_APPROVAL_COLLECTION, fingerprint)
      .first<{ document_json: string }>();
    if (row === null) return undefined;
    const parsed: unknown = JSON.parse(row.document_json);
    if (parsed === null || typeof parsed !== "object") return undefined;
    return parsed as ToolApprovalDocument;
  }

  /**
   * Raise the pending record.
   *
   * `INSERT ... ON CONFLICT DO NOTHING` on the `(resource_kind, resource_id)`
   * primary key, with the resource id DERIVED from the fingerprint: two
   * isolates racing the same un-approved call converge on ONE queue entry
   * instead of two, without needing a transaction.
   */
  async #createPending(
    fingerprint: string,
    context: DispatchContext,
    tool: McpTool,
    args: JsonValue,
  ): Promise<void> {
    const now = this.#now();
    const id = `mcp-${fingerprint.slice(0, 32)}`;
    const document: ToolApprovalDocument = {
      id,
      object: "tool_approval",
      fingerprint,
      status: "pending",
      tool_name: tool.name,
      server_name: tool.serverName,
      request_id: context.requestId,
      // Bounded evidence, never the raw secret-bearing payload beyond the cap.
      arguments_summary: argumentsSummary(args),
      risk_reason: "mcp tool is not marked auto_execute",
      requested_at: now,
      expires_at: now + this.#timeoutSecs,
      // Rust's #306 stored canonical decision pair for `Pending`, written at
      // creation rather than re-derived at read time
      // (`approval.rs::ApprovalStatus::stored_decision`).
      decision_reason: "approval_pending",
    };
    if (context.auth.organizationId !== undefined) document.tenant_id = context.auth.organizationId;
    if (context.auth.apiKeyId !== undefined) document.actor_api_key_id = context.auth.apiKeyId;
    if (context.traceId !== undefined) document.trace_id = context.traceId;
    if (context.agentRunId !== undefined) document.agent_run_id = context.agentRunId;

    await this.#db
      .prepare(
        `INSERT INTO ${RESOURCE_TABLE}
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, 1, ?, ?)
         ON CONFLICT (resource_kind, resource_id) DO NOTHING`,
      )
      .bind(TOOL_APPROVAL_COLLECTION, id, JSON.stringify(document), now, now)
      .run();
  }
}
