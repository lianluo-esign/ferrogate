-- ===========================================================================
-- `responses_conversations` — server-side state for `POST /v1/responses` (#689)
--
-- The Responses API is STATEFUL: `previous_response_id` continues a
-- conversation the SERVER remembers. FerroGate relayed both `store` and
-- `previous_response_id` straight to whichever provider happened to serve the
-- call, so a second turn either 404'd upstream or — on a provider that answers
-- anyway — was served from half a conversation. This table is the state.
--
-- ## Why D1 and not a Durable Object per conversation
--
-- The issue proposes a DO per conversation, #687 landed a DO per MCP session,
-- and this slice deliberately does NOT follow it. Four reasons, in order of
-- weight:
--
--  1. **There is no read-modify-write to serialize.** A DO buys a
--     single-threaded actor. An MCP session needs one because it IS mutable
--     shared state (the initialize handshake, the tool list, subscriptions,
--     both legs of a bidirectional transport). A Responses turn is
--     APPEND-ONLY under a fresh identifier: every turn mints a new
--     `response_id` and points at its parent, so two concurrent continuations
--     of one parent are two INSERTs of two different primary keys. They cannot
--     conflict, cannot lose an update, and need no ordering.
--  2. **Retention.** #681 makes conversation state governed data — it is
--     prompt content by another name — and the gateway ALREADY runs a
--     retention sweep on its Cron tick (`gatewayScheduled` →
--     `sweepRequestLogs`). A sweep over a table is a `DELETE … WHERE
--     expires_at_unix <= ?`. DO storage is invisible to it: a DO namespace
--     cannot be enumerated, so expiry would need a per-object alarm — which is
--     exactly #765, where MCP sessions are never evicted because nothing walks
--     the namespace. Choosing a DO here would create the second instance of a
--     defect the first one is still open on.
--  3. **Tenancy.** `previous_response_id` is CALLER-SUPPLIED. Here the fence is
--     `WHERE tenant_id = ? AND project_id = ?` on the same statement that
--     resolves the id — one place, and a mutation of that one place turns the
--     cross-tenant test red. A DO addressed by `idFromName(response_id)` is
--     reachable with the id ALONE; the fence would then be a check inside the
--     object, after the caller has already routed to another tenant's state.
--  4. **Evidence.** An operator answering "what does this tenant have stored,
--     and when does it expire" needs one SQL query. Over a DO namespace there
--     is no such query.
--
-- The cost we accept: reconstructing a chain is a walk, not a single object
-- read. It is ONE query (a recursive CTE, see `conversation-store.ts`) and it
-- is depth-bounded, so the cost is bounded too.
--
-- ## Keys and the fence
--
-- The primary key is `(tenant_id, project_id, response_id)`, and the tenant and
-- project columns are FIRST because they are the fence, not decoration:
-- `scopeCanSeeModel` already treats a project as an isolation boundary inside a
-- tenant, and this table follows that precedent rather than inventing a second
-- one. Under `GATEWAY_TENANT_DB_ROUTING = "off"` one physical database holds
-- many tenants and the predicate IS the isolation; under `"binding"` the rows
-- also live in the tenant's own database and the predicate is the second fence.
--
-- ## Why the whole served body is stored, not just the text
--
-- `GET /v1/responses/{id}` has to answer with the response the caller was
-- served, and a chain has to replay the assistant's OUTPUT ITEMS — reasoning
-- items, tool calls and all — not a flattened transcript. Storing the body is
-- what makes both exact; deriving `output` from `response_json` (rather than
-- keeping a second copy) is what keeps them from disagreeing.
--
-- ## No FOREIGN KEY on `previous_response_id`
--
-- The rest of this schema declares none (see `0001_init_tenant.sql`): D1 does
-- not enforce them by default, so a declared constraint would read as an
-- enforced one. The dangling-parent case is handled where it matters — a chain
-- whose parent row is gone is REFUSED at resolution time
-- (`conversation_chain_broken`), never silently truncated into a fresh
-- conversation, which is the exact context-loss failure #689 exists to prevent.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS responses_conversations (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    response_id TEXT NOT NULL,
    previous_response_id TEXT,
    -- 0 for the first turn of a chain; parent + 1 thereafter. Carried so the
    -- depth bound is an O(1) read off the parent instead of a walk.
    turn_index INTEGER NOT NULL,
    model TEXT NOT NULL,
    -- This turn's own input items, as a JSON array. The turn DELTA, never the
    -- accumulated prefix: storing the prefix on every row would make a chain
    -- quadratic in the number of turns.
    input_json TEXT NOT NULL,
    -- The response body served to the caller, verbatim (with the gateway's own
    -- `id`). `GET /v1/responses/{id}` returns this; the chain replays its
    -- `output` array.
    response_json TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    -- The retention horizon. Enforced on READ as well as by the sweep, so a
    -- deployment whose Cron is not firing still refuses expired state rather
    -- than serving it.
    expires_at_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, project_id, response_id)
);

-- The retention sweep's whole predicate.
CREATE INDEX IF NOT EXISTS idx_responses_conversations_expiry
    ON responses_conversations(expires_at_unix);
