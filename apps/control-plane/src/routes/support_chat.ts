import type { Context } from "hono";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import {
  type CallerScope,
  type ControlPlaneEnv,
  StoreConflictError,
  type StoreRecord,
} from "../ports.js";
import { adminListPaginated, parseListQuery } from "../responses.js";
import { tenantDatabaseFor } from "../store/tenancy.js";
import {
  type GroupModule,
  type Handler,
  crudGroup,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

const SUPPORT_INDEX = "support-chat-conversations";
const SUPPORT_PRESENCE = "support-chat-presence";
const PLATFORM_SCOPE: CallerScope = { kind: "platform_operator" };
const MAX_MESSAGE_LENGTH = 4_000;

const messageBodySchema = z
  .object({
    body: z.string().trim().min(1).max(MAX_MESSAGE_LENGTH),
    sender_id: z.string().trim().min(1).max(200).optional(),
    sender_name: z.string().trim().min(1).max(200).optional(),
    message_kind: z.enum(["text", "support_ticket"]).optional(),
    ticket_title: z.string().trim().min(1).max(160).optional(),
    reply_to_message_id: z.string().trim().min(1).max(200).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.message_kind === "support_ticket" && value.ticket_title === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["ticket_title"],
        message: "ticket_title is required for support tickets",
      });
    }
  });

const presenceBodySchema = z.object({
  operator_id: z.string().trim().min(1).max(200).optional(),
  display_name: z.string().trim().min(1).max(200).optional(),
});

export interface SupportMessage {
  readonly id: string;
  readonly seq: number;
  readonly conversation_id: string;
  readonly tenant_id: string;
  readonly sender_type: "tenant_user" | "platform_operator";
  readonly sender_id: string;
  readonly sender_name: string | null;
  readonly body: string;
  readonly metadata_json: string;
  readonly created_at_unix: number;
}

type SupportMessageRow = SupportMessage;

function requireTenantScope(c: Context<ControlPlaneEnv>): string {
  const scope = scopeOf(c);
  if (scope.kind !== "tenant" || scope.tenantId.trim() === "") {
    throw new HttpError(
      403,
      "tenant_scope_required",
      "this support route requires a tenant session",
    );
  }
  return scope.tenantId;
}

function requireOperatorScope(c: Context<ControlPlaneEnv>): void {
  if (scopeOf(c).kind !== "platform_operator") {
    throw new HttpError(
      403,
      "operator_scope_required",
      "this support route requires an operator session",
    );
  }
}

async function tenantDb(c: Context<ControlPlaneEnv>, tenantId: string): Promise<D1Database> {
  const deps = c.get("deps");
  const handle = await tenantDatabaseFor(deps.tenantStorage ?? deps.tenantDatabases, tenantId);
  if (handle === null || handle.source !== "durable_object") {
    throw new HttpError(
      503,
      "tenant_support_storage_unavailable",
      `tenant ${tenantId} has no reachable Durable Object support storage`,
    );
  }
  return handle.db;
}

async function messagesFor(
  db: D1Database,
  conversationId: string,
  cursor: number,
  limit: number,
): Promise<readonly SupportMessage[]> {
  const result = await db
    .prepare(
      `SELECT seq, id, conversation_id, ?1 AS tenant_id, sender_type, sender_id,
              sender_name, body, metadata_json, created_at_unix
         FROM im_messages
        WHERE conversation_id = ?2 AND seq > ?3
        ORDER BY seq ASC
        LIMIT ?4`,
    )
    .bind(conversationId.slice("support:".length), conversationId, cursor, limit)
    .all<SupportMessageRow>();
  return result.results;
}

async function appendMessage(
  db: D1Database,
  tenantId: string,
  senderType: SupportMessage["sender_type"],
  senderId: string,
  senderName: string | null,
  body: string,
  metadata: Readonly<Record<string, string>> = {},
): Promise<SupportMessage> {
  const createdAtUnix = Math.floor(Date.now() / 1_000);
  const conversationId = `support:${tenantId}`;
  const id = crypto.randomUUID();
  await db
    .prepare(
      `INSERT OR IGNORE INTO im_conversations
        (id, tenant_id, kind, title, status, created_by_type, created_by_id,
         metadata_json, created_at_unix, updated_at_unix)
       VALUES (?1, ?2, 'support', 'Platform support', 'open', ?3, ?4, '{}', ?5, ?5)`,
    )
    .bind(conversationId, tenantId, senderType, senderId, createdAtUnix)
    .run();
  await db
    .prepare(
      `INSERT OR IGNORE INTO im_conversation_participants
        (conversation_id, participant_type, participant_id, role, joined_at_unix, last_read_seq, updated_at_unix)
       VALUES (?1, ?2, ?3, ?4, ?5, 0, ?5)`,
    )
    .bind(
      conversationId,
      senderType,
      senderId,
      senderType === "platform_operator" ? "operator" : "member",
      createdAtUnix,
    )
    .run();
  await db
    .prepare(
      `INSERT INTO im_messages
        (id, conversation_id, sender_type, sender_id, sender_name, content_type,
         body, metadata_json, created_at_unix)
       VALUES (?1, ?2, ?3, ?4, ?5, 'text', ?6, ?7, ?8)`,
    )
    .bind(
      id,
      conversationId,
      senderType,
      senderId,
      senderName,
      body,
      JSON.stringify(metadata),
      createdAtUnix,
    )
    .run();
  await db
    .prepare("UPDATE im_conversations SET updated_at_unix = ?2 WHERE id = ?1")
    .bind(conversationId, createdAtUnix)
    .run();
  const message = await db
    .prepare(
      `SELECT seq, id, conversation_id, ?1 AS tenant_id, sender_type, sender_id,
              sender_name, body, metadata_json, created_at_unix
         FROM im_messages WHERE id = ?2`,
    )
    .bind(tenantId, id)
    .first<SupportMessageRow>();
  if (message === null) {
    throw new HttpError(500, "support_message_write_failed", "support message was not persisted");
  }
  return message;
}

async function ticketReplyTarget(
  db: D1Database,
  conversationId: string,
  requestedId?: string,
): Promise<string | null> {
  if (requestedId !== undefined) {
    const requested = await db
      .prepare(
        `SELECT id
           FROM im_messages
          WHERE conversation_id = ?1
            AND id = ?2
            AND sender_type = 'tenant_user'
            AND json_extract(metadata_json, '$.kind') = 'support_ticket'`,
      )
      .bind(conversationId, requestedId)
      .first<{ id: string }>();
    if (requested === null) {
      throw new HttpError(400, "invalid_ticket_reply", "reply target is not a support ticket");
    }
    return requested.id;
  }

  const latestTenantMessage = await db
    .prepare(
      `SELECT id, metadata_json
         FROM im_messages
        WHERE conversation_id = ?1 AND sender_type = 'tenant_user'
        ORDER BY seq DESC
        LIMIT 1`,
    )
    .bind(conversationId)
    .first<{ id: string; metadata_json: string }>();
  if (latestTenantMessage === null) return null;
  try {
    const metadata = JSON.parse(latestTenantMessage.metadata_json) as { kind?: unknown };
    return metadata.kind === "support_ticket" ? latestTenantMessage.id : null;
  } catch {
    return null;
  }
}

async function upsertConversationIndex(
  c: Context<ControlPlaneEnv>,
  message: SupportMessage,
): Promise<void> {
  const store = c.get("deps").store;
  const existing = await store.get(SUPPORT_INDEX, PLATFORM_SCOPE, message.tenant_id);
  if (existing?.last_message_id === message.id) return;
  const now = message.created_at_unix;
  const patch: StoreRecord = {
    id: message.tenant_id,
    tenant_id: message.tenant_id,
    status: "open",
    last_message_id: message.id,
    last_message_at_unix: now,
    last_sender_type: message.sender_type,
    last_message_preview: message.body.slice(0, 180),
    updated_at_unix: now,
    operator_unread_count:
      message.sender_type === "tenant_user" ? Number(existing?.operator_unread_count ?? 0) + 1 : 0,
    tenant_unread_count:
      message.sender_type === "platform_operator"
        ? Number(existing?.tenant_unread_count ?? 0) + 1
        : Number(existing?.tenant_unread_count ?? 0),
  };
  if (existing === null) {
    try {
      await store.create(SUPPORT_INDEX, PLATFORM_SCOPE, {
        ...patch,
        created_at_unix: now,
      });
    } catch (error) {
      if (!(error instanceof StoreConflictError)) throw error;
      await store.merge(SUPPORT_INDEX, PLATFORM_SCOPE, message.tenant_id, patch);
    }
    return;
  }
  await store.merge(SUPPORT_INDEX, PLATFORM_SCOPE, message.tenant_id, patch);
}

async function operatorOnline(c: Context<ControlPlaneEnv>): Promise<boolean> {
  const deps = c.get("deps");
  const now = Math.floor(Date.now() / 1_000);
  const page = await deps.store.list(SUPPORT_PRESENCE, PLATFORM_SCOPE, {
    offset: 0,
    limit: 100,
    paginate: true,
    search: null,
    filters: {},
  });
  return page.items.some((record) => Number(record.online_until_unix ?? 0) >= now);
}

function cursorAndLimit(c: Context<ControlPlaneEnv>): { cursor: number; limit: number } {
  const url = new URL(c.req.url);
  const rawCursor = Number.parseInt(url.searchParams.get("cursor") ?? "0", 10);
  const rawLimit = Number.parseInt(url.searchParams.get("limit") ?? "200", 10);
  return {
    cursor: Number.isSafeInteger(rawCursor) && rawCursor >= 0 ? rawCursor : 0,
    limit: Number.isSafeInteger(rawLimit) ? Math.min(500, Math.max(1, rawLimit)) : 200,
  };
}

const getSupportConversation: Handler = async (c) => {
  const tenantId = requireTenantScope(c);
  const db = await tenantDb(c, tenantId);
  const { cursor, limit } = cursorAndLimit(c);
  const conversationId = `support:${tenantId}`;
  const [messages, online] = await Promise.all([
    messagesFor(db, conversationId, cursor, limit),
    operatorOnline(c),
  ]);
  if (messages.length > 0) {
    await upsertConversationIndex(c, messages.at(-1)!);
    await c
      .get("deps")
      .store.merge(SUPPORT_INDEX, PLATFORM_SCOPE, tenantId, {
        id: tenantId,
        tenant_unread_count: 0,
      })
      .catch(() => null);
  }
  return json(c, 200, {
    object: "support_conversation",
    tenant_id: tenantId,
    status: "open",
    operator_online: online,
    messages,
    next_cursor: messages.at(-1)?.seq ?? cursor,
  });
};

const createSupportMessage: Handler = async (c) => {
  const tenantId = requireTenantScope(c);
  const auth = c.get("auth");
  const body = await readJson(c, messageBodySchema);
  const db = await tenantDb(c, tenantId);
  const senderId = auth?.tenancy.userId ?? auth?.subject ?? tenantId;
  const metadata: Readonly<Record<string, string>> =
    body.message_kind === "support_ticket"
      ? { kind: "support_ticket", title: body.ticket_title! }
      : {};
  const message = await appendMessage(
    db,
    tenantId,
    "tenant_user",
    senderId,
    null,
    body.body,
    metadata,
  );
  await upsertConversationIndex(c, message);
  return json(c, 201, { object: "support_message", message });
};

const listSupportConversations: Handler = async (c) => {
  requireOperatorScope(c);
  const deps = c.get("deps");
  const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
  const page = await deps.store.list(SUPPORT_INDEX, PLATFORM_SCOPE, query);
  const sorted = [...page.items].sort(
    (a, b) => Number(b.last_message_at_unix ?? 0) - Number(a.last_message_at_unix ?? 0),
  );
  const data = await Promise.all(
    sorted.map(async (record) => {
      const tenant = await deps.store.get("tenant-accounts", PLATFORM_SCOPE, record.id);
      return {
        ...record,
        tenant_name:
          typeof tenant?.name === "string" && tenant.name.trim() !== "" ? tenant.name : null,
      };
    }),
  );
  return json(c, 200, adminListPaginated(data, page.total, query.offset, query.limit));
};

const listOperatorMessages: Handler = async (c) => {
  requireOperatorScope(c);
  const tenantId = pathParam(c, "tenant_id");
  const db = await tenantDb(c, tenantId);
  const { cursor, limit } = cursorAndLimit(c);
  const messages = await messagesFor(db, `support:${tenantId}`, cursor, limit);
  await c
    .get("deps")
    .store.merge(SUPPORT_INDEX, PLATFORM_SCOPE, tenantId, {
      id: tenantId,
      operator_unread_count: 0,
    })
    .catch(() => null);
  return json(c, 200, {
    object: "support_conversation",
    tenant_id: tenantId,
    status: "open",
    messages,
    next_cursor: messages.at(-1)?.seq ?? cursor,
  });
};

const createOperatorMessage: Handler = async (c) => {
  requireOperatorScope(c);
  const tenantId = pathParam(c, "tenant_id");
  const auth = c.get("auth");
  const body = await readJson(c, messageBodySchema);
  const db = await tenantDb(c, tenantId);
  const senderId = body.sender_id ?? auth?.subject ?? "operator";
  const replyToMessageId = await ticketReplyTarget(
    db,
    `support:${tenantId}`,
    body.reply_to_message_id,
  );
  const message = await appendMessage(
    db,
    tenantId,
    "platform_operator",
    senderId,
    body.sender_name ?? senderId,
    body.body,
    replyToMessageId === null ? {} : { reply_to_message_id: replyToMessageId },
  );
  await upsertConversationIndex(c, message);
  return json(c, 201, { object: "support_message", message });
};

const heartbeatSupportOperator: Handler = async (c) => {
  requireOperatorScope(c);
  const deps = c.get("deps");
  const auth = c.get("auth");
  const body = await readJson(c, presenceBodySchema);
  const operatorId = body.operator_id ?? auth?.subject ?? "operator";
  const now = Math.floor(Date.now() / 1_000);
  const record: StoreRecord = {
    id: operatorId,
    display_name: body.display_name ?? operatorId,
    online_until_unix: now + 45,
    updated_at_unix: now,
  };
  const existing = await deps.store.get(SUPPORT_PRESENCE, PLATFORM_SCOPE, operatorId);
  if (existing === null) {
    try {
      await deps.store.create(SUPPORT_PRESENCE, PLATFORM_SCOPE, {
        ...record,
        created_at_unix: now,
      });
    } catch (error) {
      if (!(error instanceof StoreConflictError)) throw error;
      await deps.store.merge(SUPPORT_PRESENCE, PLATFORM_SCOPE, operatorId, record);
    }
  } else {
    await deps.store.merge(SUPPORT_PRESENCE, PLATFORM_SCOPE, operatorId, record);
  }
  return json(c, 200, { object: "support_operator_presence", online_until_unix: now + 45 });
};

export const supportChatRoutes: GroupModule = crudGroup("support_chat", [], {
  getSupportConversation,
  createSupportMessage,
  listSupportConversations,
  listSupportConversationMessages: listOperatorMessages,
  createOperatorSupportMessage: createOperatorMessage,
  heartbeatSupportOperator,
});
