<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-18
  description: Operator guide for the guardrail investigation view (/admin/v1/investigations).
-->

---
title: Guardrail Investigation View
description: How an operator answers who / why / target / action / cost for a blocked or failed request.
permalink: /guardrails/investigation-view/
---

# Guardrail Investigation View

When a request is blocked or fails, `GET /admin/v1/investigations` joins every
piece of evidence for that request into a single JSON timeline — identity,
route, guardrail policy, approvals, execution, usage, cost, and outcome — so a
security engineer can answer **who / why / target / action / cost** without
reading gateway source. This guide is the operator-facing companion to the
OpenAPI definition in
[`docs/openapi/admin-api.openapi.json`](../openapi/admin-api.openapi.json).

## Configuring a guardrail to test against

The built-in guardrail engine runs in-process (no external detector) for
keyword, regex, and max-input-length rules. A minimal deterministic keyword-deny
rule (also in [`config/ferrogate.example.toml`](../../config/ferrogate.example.toml)):

```toml
[[guardrails]]
id = "no-exfil-keyword"          # required; surfaces as `policy_id` in evidence
name = "Block EXFILTRATE keyword" # required
stage = "request"                # "request" (inbound prompt) | "response" (model output). Default: request
effect = "deny"                  # "deny" (HTTP 403) | "redact" (mask the span). Default: deny
keywords = ["EXFILTRATE"]        # case-insensitive substring match
```

Use `regex = ["..."]` for patterns or `max_input_bytes = N` for a length cap.
A request whose content contains `EXFILTRATE` is rejected with HTTP `403` and
body `error.code = "guardrail_denied"`; the request id is returned both in the
`x-request-id` response header and in `error.request_id`.

> Caveat: `ferrogate validate` does **not** reject unknown or misspelled config
> fields (see "Config validation caveat" below), so copy guardrail field names
> exactly — a typo silently disables the rule with no error.

## Querying the investigation view

Look up a request by `request_id` (also accepts `trace_id` or `agent_run_id`).
The bearer token is any key with the `admin.read` scope (see RBAC below):

```bash
curl -sS \
  -H "Authorization: Bearer $FERROGATE_ADMIN_KEY" \
  "http://127.0.0.1:8080/admin/v1/investigations?request_id=fg-b9248c19b09b7a25"
```

One JSON object (`"object": "guardrail_investigation"`) is returned. When no
evidence matches the selector the endpoint returns `404`
(`guardrail_investigation_not_found`).

## Response field map (who / why / target / action / cost)

Every answer comes from the single response. JSON paths below are exact and
match the `GuardrailInvestigationTimeline` schema in the OpenAPI document.

| Question | Answer from | Key JSON paths |
|---|---|---|
| **WHO** | The calling identity | top-level `identity.{api_key_id, team_id, project_id, organization_id, user_id}`; repeated per event as `tenant{...}` and `guardrail_evaluations[0].subject_id` |
| **WHY** | The guardrail verdict + human-readable cause | `guardrail_evaluations[0].{policy_id, policy_revision, verdict, action, enforcement_status, mode, stage, checks[]}`; `audit_events[].{action, target, outcome, message}` (the `message` pinpoints the matched span, e.g. `segment chat:0 bytes 7..17`) |
| **TARGET** | The provider/model that was called | `requests[0].{provider, logical_model, provider_model, route}`; also `guardrail_evaluations[0].target` (e.g. `model=fast-chat;provider=openai`) |
| **ACTION** | What kind of request and how it ended | `requests[0].{route, status_code, error_code}`; `guardrail_evaluations[0].{protocol, stage}`; top-level `final_outcome` (`blocked` / `failed` / `succeeded` / `decision_only`) |
| **COST** | Money billed (zero for a pre-provider block) | top-level `total_cost_usd`; `billing_events[]` (empty when the request was blocked before reaching the provider) |

`approvals[]` is always empty on a Workers deployment: there is no approvals
table in `sql/d1-ts/control/`. The field is present because the response schema
requires it, not because the reader knows anything about approvals.

## What the evidence stores, and what it deliberately does not (#665)

Raw prompt/response content is **never** stored. A guardrail that blocks a
prompt for carrying a secret and then keeps that secret in a table every
`guardrails.evidence.read` holder can list has moved the leak rather than
stopped it.

Each evaluation carries a keyed, non-reversible `input_fingerprint`
(`hmac-sha256:<hex>` over the envelope's per-segment content fingerprints), and
each check carries its detector id, detector version, config digest and a
`findings[]` array of:

| field | what it answers |
|---|---|
| `category` / `severity` | which detector rule fired |
| `confidence` | how sure the detector was (`0`–`1`, clamped) |
| `segment_id`, `byte_start`, `byte_end` | where in the request it fired |
| `redacted_excerpt` | the SHAPE of the match — `[category] segment:start..end ****` |

`redacted_excerpt` is a **reconstruction, not a snippet**: it is built from the
finding's structure plus a run of `*` as wide as the matched bytes, so it tells
you "a 20-byte AWS access key at bytes 13..33 of the first user message" without
telling you which one. `Finding.matched_text` is dropped at
`apps/gateway/src/guardrails/evidence.ts::sanitizedFindings` and has no column,
no document field and no wire field to land in — including when an external
detector volunteers it, which
`apps/gateway/test/guardrails/evidence-write.test.ts` proves by scripting a
detector that does.

Storage is `sql/d1-ts/control/0004_guardrail_evaluations.sql`
(`guardrail_evaluations` + `guardrail_check_evaluations`) in the CONTROL
database, written by the gateway through the same Queue and the same retention
window as the request log (`REQUEST_LOG_RETENTION_DAYS` /
`REQUEST_LOG_RETENTION_POLICIES`). Evidence and traffic logs age out together on
purpose: an investigation that can only half-answer is the failure this surface
exists to remove.

## RBAC: which key can read investigation evidence

`GET /admin/v1/investigations` requires the `admin.read` scope **and** the
`guardrails.evidence.read` RBAC action. How that action is granted depends on
whether the API key is tenant-scoped:

- **Platform-operator key (no `organization_id`)** — a config API key with
  `organization_id` unset (or created through the Admin API with
  `organization_id: null`) is treated as a platform operator. It passes the
  evidence-read check unconditionally and can read investigations for every
  tenant. This is the simplest key to use for incident response.
- **Tenant-scoped key (`organization_id` set)** — the key must additionally
  hold a role binding that grants the `guardrails.evidence.read` permission for
  its tenant. Without it, the endpoint returns HTTP `403`
  `guardrail_rbac_denied` ("tenant roles do not grant required action
  guardrails.evidence.read"). Role and binding management
  (`/admin/v1/roles`, `/admin/v1/permissions`) is itself platform-operator-only
  (`platform_operator_required`), so a platform operator must grant the role
  before a tenant-scoped key can read its own evidence.

Reference: the check lives in `require_guardrail_evidence_auth`
(`crates/ferrogate-gateway/src/server/local.rs`) and
`require_platform_operator` (`crates/ferrogate-gateway/src/auth.rs`).

The example config's `key_dev` key is tenant-scoped (`organization_id =
"org_demo"`), so it will get `guardrail_rbac_denied` for this endpoint until a
role grants `guardrails.evidence.read`; drop `organization_id` (or use a
separate org-less key) to investigate as a platform operator.

## Config validation caveat (unknown fields)

`ferrogate validate` parses config with serde defaults and does **not** reject
unknown or misspelled fields. A typo'd guardrail field (e.g. `keyword` instead
of `keywords`) is silently ignored, which disables that part of the rule with no
diagnostic. Most config structs deliberately omit
`#[serde(deny_unknown_fields)]` so that older binaries tolerate newer
forward-compatible fields; `GuardrailRule` does declare it, but a
`#[serde(flatten)]` runtime sub-config defeats it (a documented serde
limitation). Until strict validation lands, after editing a guardrail:

1. Re-read the field names against
   [`config/ferrogate.example.toml`](../../config/ferrogate.example.toml) or the
   `GuardrailRule` struct in `crates/ferrogate-config/src/config/types.rs`.
2. Confirm the rule actually fired by sending a probe request that should trip
   it and checking `guardrail_evaluations[]` in the investigation view.
