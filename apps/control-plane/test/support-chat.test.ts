import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, OPERATOR_KEY, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import { privilegedTenantBatch, registerDurableObjectTenant } from "./tenant-object.js";

const TENANT_ID = "tenant_a";
const TENANT_SECRET = "tenant-a-support-secret";
const SUPPORT_INDEX = "support-chat-conversations";

beforeAll(applySchema);

describe("support chat conversation index", () => {
  beforeEach(async () => {
    await resetD1();
    await registerDurableObjectTenant(TENANT_ID);
    await privilegedTenantBatch(TENANT_ID, [
      { sql: "DELETE FROM im_messages", params: [] },
      { sql: "DELETE FROM im_conversation_participants", params: [] },
      { sql: "DELETE FROM im_conversations", params: [] },
    ]);
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(TENANT_SECRET, TENANT_ID)],
    });
  });

  it("repairs a missing operator inbox row from tenant history without duplicating unread count", async () => {
    const sent = await SELF.fetch(
      `${BASE}/admin/v1/support/messages`,
      jsonRequest(TENANT_SECRET, "POST", { body: "Need help" }),
    );
    expect(sent.status).toBe(201);

    await db()
      .prepare("DELETE FROM control_plane_resources WHERE resource_kind = ? AND resource_id = ?")
      .bind(SUPPORT_INDEX, TENANT_ID)
      .run();

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const history = await SELF.fetch(`${BASE}/admin/v1/support/conversation?cursor=0&limit=100`, {
        headers: bearer(TENANT_SECRET),
      });
      expect(history.status).toBe(200);
    }

    const inbox = await SELF.fetch(`${BASE}/admin/v1/support/conversations?offset=0&limit=100`, {
      headers: bearer(OPERATOR_KEY),
    });
    expect(inbox.status).toBe(200);
    const body = (await inbox.json()) as {
      data: Array<{ tenant_id: string; operator_unread_count: number }>;
    };
    expect(body.data).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ tenant_id: TENANT_ID, operator_unread_count: 1 }),
      ]),
    );
  });

  it("persists support tickets in the tenant conversation and links operator replies", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/support/messages`,
      jsonRequest(TENANT_SECRET, "POST", {
        body: "The payment completed but the balance did not change.",
        message_kind: "support_ticket",
        ticket_title: "Balance not credited",
      }),
    );
    expect(created.status).toBe(201);
    const createdBody = (await created.json()) as {
      message: { id: string; metadata_json: string };
    };
    expect(JSON.parse(createdBody.message.metadata_json)).toEqual({
      kind: "support_ticket",
      title: "Balance not credited",
    });

    const replied = await SELF.fetch(
      `${BASE}/admin/v1/support/conversations/${TENANT_ID}/messages`,
      jsonRequest(OPERATOR_KEY, "POST", { body: "The balance has now been credited." }),
    );
    expect(replied.status).toBe(201);
    const repliedBody = (await replied.json()) as {
      message: { metadata_json: string };
    };
    expect(JSON.parse(repliedBody.message.metadata_json)).toEqual({
      reply_to_message_id: createdBody.message.id,
    });

    const history = await SELF.fetch(`${BASE}/admin/v1/support/conversation?cursor=0&limit=100`, {
      headers: bearer(TENANT_SECRET),
    });
    expect(history.status).toBe(200);
    const historyBody = (await history.json()) as {
      messages: Array<{ id: string; metadata_json: string }>;
    };
    expect(historyBody.messages).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: createdBody.message.id }),
        expect.objectContaining({ metadata_json: repliedBody.message.metadata_json }),
      ]),
    );
  });

  it("does not attach a normal chat reply to an older support ticket", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/support/messages`,
      jsonRequest(TENANT_SECRET, "POST", {
        body: "Ticket body",
        message_kind: "support_ticket",
        ticket_title: "Ticket title",
      }),
    );
    expect(created.status).toBe(201);

    const chat = await SELF.fetch(
      `${BASE}/admin/v1/support/messages`,
      jsonRequest(TENANT_SECRET, "POST", { body: "A separate chat question" }),
    );
    expect(chat.status).toBe(201);

    const replied = await SELF.fetch(
      `${BASE}/admin/v1/support/conversations/${TENANT_ID}/messages`,
      jsonRequest(OPERATOR_KEY, "POST", { body: "Chat response" }),
    );
    expect(replied.status).toBe(201);
    const body = (await replied.json()) as { message: { metadata_json: string } };
    expect(JSON.parse(body.message.metadata_json)).toEqual({});
  });
});
