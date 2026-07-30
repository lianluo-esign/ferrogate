# Agent action correlation: declaring a run id so the gateway joins your chain

Issue #522. FerroGate reconstructs the full chain of one agent action —
inference calls, tool calls, MCP calls, asset fetches/pushes, guardrail
verdicts, approvals — at the **gateway** layer. All of your agent's traffic
transits the gateway, so the gateway is where the chain is assembled. Your only
obligation is to **declare which action a request belongs to**, by sending one
header. This page is the customer-facing contract: which header, on which
endpoints, the allowed format, how to link a child action to its parent, and
what you get back.

> Non-goal: FerroGate does **not** propagate a W3C `traceparent` into your agent
> and does not require you to run a tracer. Declaring the run id below is the
> whole integration.

## The header: `x-ferrogate-agent-run-id`

Send `x-ferrogate-agent-run-id: <your run id>` on every request that belongs to
the same logical agent run. Reuse the **same** value across every call of that
run (the model call, each tool/MCP call, each asset fetch/push) so they join
into one chain.

- **Authority:** client-declared. It is a correlation label, not a credential.
- **Attribution is always the authenticated tenant.** The run id never changes
  who a record belongs to — the tenant is taken from your API key, never from
  this header. Declaring another tenant's run-id string cannot move your records
  into their chain, nor surface your records in their investigation view (see
  [Tenant isolation](#tenant-isolation)).
- **Absent is allowed.** If you omit the header the request is still served; it
  simply cannot be joined to a run. The gateway counts these as *unjoinable
  actions* (see [What operators see](#what-operators-see)). A run id is never
  fabricated on your behalf.

### Allowed format

| rule | value |
|---|---|
| characters | `A`–`Z`, `a`–`z`, `0`–`9`, and `_ - . :` |
| max length | 128 characters |
| encoding | visible ASCII header text; surrounding whitespace is trimmed |

A value that violates the charset or length is rejected with HTTP `400`
`invalid_agent_run_id_header`. An empty/whitespace-only value is treated as
"not declared".

Examples: `run_2026-07-30.42`, `agent:planner:0f3a`, `job-1193`.

## Where to send it

The header is accepted on every governed agent surface:

| endpoint | what it correlates |
|---|---|
| `POST /v1/chat/completions` | inference call |
| `POST /v1/messages` | inference call |
| `POST /v1/agent-runs` | agent run |
| the reverse proxy / A2A message endpoints | agent-to-agent exchange |
| `POST /v1/mcp` (JSON-RPC: `tools/call`, `resources/read`, `resources/list`, …) | MCP tool/resource action |
| `PUT /v1/assets/{type}/{name}/{version}` | asset push |
| `GET /v1/assets/{type}/{name}/{version}` and the presigned download endpoint | asset fetch |

Send the identical value on all of them for one run, and the gateway stitches
the inference call, its MCP tool calls, and any asset it pulled or published
into a single joinable chain.

## Linking a child action to its parent

When one governed action is a downstream effect of another (a tool call spawned
by a model turn; an A2A message triggered by a tool result), declare the
parent's action fingerprint with:

```
x-ferrogate-parent-action-fingerprint: sha256:<64 hex chars>
```

The value is the parent action's `canonical_target_sha256` fingerprint, which
the gateway returns on the parent's receipt/investigation record. A malformed
value is a `400`; an absent header simply records no parent link (never
fabricated). Parent linkage lets an investigation walk parent → child across
surfaces.

## What you get back

Query the investigation/evidence view with any of `request_id`, `trace_id`, or
`agent_run_id`. When you filter by the run id you declared, the response joins,
for that run and **within your tenant only**:

- the request logs for each call,
- the audit rows for each MCP tool/resource action and each asset push/pull,
- guardrail evaluations and their verdicts,
- approvals,
- and, via `x-ferrogate-parent-action-fingerprint`, the parent → child links.

Records you never declared a run id for are absent from these joins — that is
the cost of omitting the header.

## Tenant isolation

The tenant on every stored record is derived from your authenticated API key,
never from the run id you send. The investigation join filters on **tenant plus
the run id**, so:

- another tenant borrowing your run-id string cannot make their records appear
  in your chain, and
- your records can never leak into another tenant's investigation view.

## Optional: making the run id mandatory

Operators can require a declared run id on governed agent traffic per tenant.
This is **off by default**. When an operator turns it on for your tenant, a
governed request without a valid `x-ferrogate-agent-run-id` is rejected with
HTTP `400` `agent_run_id_required`; add the header to comply. When it is off (the
default), omitting the header only forgoes correlation.

## What operators see

Every governed action that arrives without a declared run id increments a
low-cardinality gateway metric, exported on `/metrics`:

```
ferrogate_unjoinable_actions_total{tenant="<tenant>",surface="<mcp|asset|…>"}
```

The labels are the authenticated tenant and the ingress surface only — never the
(absent) id and never any client-supplied value — so operators can alert on
"agents that are not declaring run ids" per tenant and per surface without the
metric ever exploding in cardinality.
