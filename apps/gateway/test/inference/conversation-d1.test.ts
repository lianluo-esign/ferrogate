/**
 * `D1ConversationStore` against a REAL D1 (#689).
 *
 * The unit suite (`responses-conversation.test.ts`) drives the request path
 * over `InMemoryConversationStore`, which shares `assembleChain` with this one
 * but NOT the SQL. The tenant fence lives in the SQL — in both terms of the
 * recursive CTE — so it can only be proven here: an in-memory fence would go
 * green against a deployed statement that reads every tenant's rows.
 *
 * The schema is the DEPLOYED migration (`sql/d1-ts/tenant/0005_*.sql`, applied
 * by `test/setup-d1.ts` through `readD1Migrations`), never a fixture copy.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  D1ConversationStore,
  sweepResponseConversations,
} from "../../src/inference/conversation-store.js";
import type { StoredResponseTurn } from "../../src/inference/conversation-store.js";
import type { ConversationOwner } from "../../src/inference/conversation.js";

const DB = (env as unknown as { DB: D1Database }).DB;

const ACME: ConversationOwner = { tenantId: "acme", projectId: "" };
const GLOBEX: ConversationOwner = { tenantId: "globex", projectId: "" };
const ACME_PROJECT: ConversationOwner = { tenantId: "acme", projectId: "project_b" };

const FOREVER = 4_000_000_000;

function turn(
  responseId: string,
  previousResponseId: string | null,
  turnIndex: number,
  text: string,
  expiresAtUnix = FOREVER,
): StoredResponseTurn {
  return {
    responseId,
    previousResponseId,
    screeningApiKeyId: "key_test",
    turnIndex,
    model: "gpt-4o-mini",
    input: [{ role: "user", content: `ask ${turnIndex}` }],
    response: {
      id: responseId,
      object: "response",
      output: [
        {
          type: "message",
          role: "assistant",
          status: "completed",
          content: [{ type: "output_text", text }],
        },
      ],
    },
    createdAtUnix: 1_000,
    expiresAtUnix,
  };
}

describe("D1ConversationStore", () => {
  const store = new D1ConversationStore(DB);

  beforeEach(async () => {
    await DB.prepare("DELETE FROM responses_conversations").run();
  });

  it("walks a chain root-first in ONE recursive query", async () => {
    await store.append(ACME, turn("resp_a", null, 0, "first"));
    await store.append(ACME, turn("resp_b", "resp_a", 1, "second"));
    await store.append(ACME, turn("resp_c", "resp_b", 2, "third"));

    const chain = await store.chain(ACME, "resp_c", 0);
    expect(chain.ok).toBe(true);
    expect(chain.ok && chain.turns.map((t) => t.responseId)).toEqual([
      "resp_a",
      "resp_b",
      "resp_c",
    ]);
    expect(chain.ok && chain.turns.map((t) => t.screeningApiKeyId)).toEqual([
      "key_test",
      "key_test",
      "key_test",
    ]);
    // The stored body round-trips through JSON intact — the chain replays the
    // OUTPUT ITEMS, so a lossy round trip would silently flatten the transcript.
    expect(chain.ok && chain.turns[0]?.response.output).toEqual([
      {
        type: "message",
        role: "assistant",
        status: "completed",
        content: [{ type: "output_text", text: "first" }],
      },
    ]);
  });

  describe("the tenant fence", () => {
    it("does not resolve another tenant's response id", async () => {
      await store.append(ACME, turn("resp_secret", null, 0, "acme only"));

      const chain = await store.chain(GLOBEX, "resp_secret", 0);
      expect(chain).toEqual({ ok: false, reason: "not_found" });
      expect(await store.get(GLOBEX, "resp_secret", 0)).toBeNull();
      expect(await store.remove(GLOBEX, "resp_secret", 0)).toBe(false);
      // ...and the row is still acme's.
      expect(await store.get(ACME, "resp_secret", 0)).not.toBeNull();
    });

    it("does not follow a chain OUT of the caller's tenant part-way up", async () => {
      // The recursive term needs its own fence, independently of the anchor:
      // here the child is globex's and its parent is acme's, which is exactly
      // what a forged `previous_response_id` graph looks like once two tenants
      // share one physical database.
      await store.append(ACME, turn("resp_acme_root", null, 0, "acme secret"));
      await store.append(GLOBEX, turn("resp_globex_child", "resp_acme_root", 1, "mine"));

      const chain = await store.chain(GLOBEX, "resp_globex_child", 0);
      // The parent is unreachable, so the chain is BROKEN — refused, never
      // served as a conversation that quietly starts at turn two.
      expect(chain).toEqual({ ok: false, reason: "broken" });
    });

    it("fences on project as well as tenant", async () => {
      await store.append(ACME, turn("resp_default_project", null, 0, "default"));
      expect(await store.get(ACME_PROJECT, "resp_default_project", 0)).toBeNull();
      expect(await store.get(ACME, "resp_default_project", 0)).not.toBeNull();
    });
  });

  it("refuses an EXPIRED chain on read, without waiting for the sweep", async () => {
    await store.append(ACME, turn("resp_old", null, 0, "stale", 1_500));
    expect(await store.chain(ACME, "resp_old", 2_000)).toEqual({ ok: false, reason: "expired" });
    expect(await store.get(ACME, "resp_old", 2_000)).toBeNull();
    // Still readable INSIDE the window.
    expect(await store.get(ACME, "resp_old", 1_400)).not.toBeNull();
  });

  it("refuses a chain whose ancestor was deleted", async () => {
    await store.append(ACME, turn("resp_1", null, 0, "one"));
    await store.append(ACME, turn("resp_2", "resp_1", 1, "two"));
    expect(await store.remove(ACME, "resp_1", 0)).toBe(true);

    expect(await store.chain(ACME, "resp_2", 0)).toEqual({ ok: false, reason: "broken" });
  });

  it("sweeps expired rows and only expired rows", async () => {
    await store.append(ACME, turn("resp_live", null, 0, "live", FOREVER));
    await store.append(ACME, turn("resp_dead", null, 0, "dead", 1_500));
    await store.append(GLOBEX, turn("resp_dead_other", null, 0, "dead", 1_500));

    // The sweep is tenant-AGNOSTIC by design: it is the Cron reaper, and it
    // reclaims every tenant's expired state in one statement.
    const removed = await sweepResponseConversations(env, 2_000);
    expect(removed).toBe(2);
    expect(await store.get(ACME, "resp_live", 2_000)).not.toBeNull();
    expect(await store.get(ACME, "resp_dead", 1_000)).toBeNull();
  });
});
