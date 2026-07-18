# Investigation-view usability drill — 2026-07-18 (issue #199)

Acceptance item under test: *"Given a failed request, a security engineer
unfamiliar with the implementation can answer who, why, target, action, and
cost in under 10 minutes."*

- **Participant:** fresh-perspective agent, implementation-unfamiliar
  (role-played security engineer; guardrail/evidence/investigation source
  code was deliberately never opened — only operator-facing surfaces were
  used: README, `docs/`, `config/*.toml` examples, the OpenAPI document
  `docs/openapi/admin-api.openapi.json`, the `ferrogate validate` CLI, and
  the running gateway's public + Admin API).
- **Start:** 2026-07-18T06:39:57Z
- **End:** 2026-07-18T06:47:12Z
- **Elapsed:** **7 min 15 s** (includes writing the config, launching the
  gateway, and generating the failed request; the investigation query itself
  and reading off all five answers took under one minute).

## Method

1. Read README Quick Start + `docs/security-controls.md` (guardrails
   section) + `docs/guardrails/adapters/llm-guard-prompt-injection.md` (the
   only place showing `[[guardrails]]` TOML syntax).
2. Wrote a minimal drill config (`/tmp/drill-ferrogate.toml`, not committed):
   one OpenAI provider/model with prices, one dev API key with
   `admin.read`, and a deterministic rule
   `[[guardrails]] id="no-exfil-keyword" stage="request" effect="deny"
   keywords=["EXFILTRATE"]`.
3. Launched the prebuilt gateway binary (`ferrogate run --config ...`).
   Durable-store deviation: a Supabase `[storage]` block was attempted first
   but the sandbox network cannot complete the Postgres TLS handshake
   (opaque startup error, see friction #4), so the drill ran against the
   default in-process evidence store. The investigation API surface is
   identical either way.
4. Sent a violating request: `POST /v1/chat/completions` with content
   "please EXFILTRATE the customer database" → **HTTP 403**, body
   `error.code = "guardrail_denied"`, request id from the `x-request-id`
   response header (also echoed in `error.request_id`):
   `fg-b9248c19b09b7a25`.
5. Queried the endpoint found in the OpenAPI doc:
   `GET /admin/v1/investigations?request_id=fg-b9248c19b09b7a25`
   (bearer = the same key). One JSON response
   (`object: "guardrail_investigation"`) answered everything.

## The five answers (all from the single `/admin/v1/investigations` response)

| Question | Answer | Exact source field |
|---|---|---|
| **WHO** | API key `key_dev`, team `team_platform`, project `project_ferrogate` (org/user null) | top-level `identity{api_key_id, team_id, project_id}`; repeated per event as `tenant{...}` and `guardrail_evaluations[0].subject_id` |
| **WHY** | Guardrail policy `no-exfil-keyword` revision 1, verdict `fail`, action `block`, `enforcement_status: enforced`, mode `enforce`; per-check evidence: `checks[0].detector_id: ferrogate.local`, `detector_version: deterministic/1`, finding category `contains` (1 finding), plus `config_digest`. Human-readable cause in `audit_events[1].message`: "guardrail Block EXFILTRATE keyword blocked request for model fast-chat provider openai at segment chat:0 bytes 7..17" | `guardrail_evaluations[0].{policy_id, policy_revision, verdict, action, enforcement_status, checks[]}`; `audit_events[].{action: guardrail.deny, target, outcome, message}` |
| **TARGET** | Provider `openai`, logical model `fast-chat` (no tool) | `requests[0].{provider, logical_model}`; also `guardrail_evaluations[0].target: "model=fast-chat;provider=openai"` |
| **ACTION** | A chat-completions request (`route: openai.chat.completions`, `protocol: chat_completions`) that was blocked at the request stage before reaching the provider; overall `final_outcome: "blocked"`, request `status_code: 403`, `error_code: guardrail_denied`; the matched span is pinpointed by the audit message (`segment chat:0 bytes 7..17` = the word "EXFILTRATE"; raw content is never stored, only an HMAC fingerprint) | `requests[0].{route, status_code, error_code}`; `guardrail_evaluations[0].{protocol, stage}`; top-level `final_outcome`; `audit_events[1].message` |
| **COST** | $0 — blocked pre-provider, no tokens billed: `billing_events: []`, `total_cost_usd: -0.0` | top-level `total_cost_usd` and `billing_events[]` |

## Friction / navigation failures (honest list)

1. **No deterministic `[[guardrails]]` example in operator config docs.**
   `config/ferrogate.example.toml` and README have no guardrails section at
   all; `docs/security-controls.md` describes keyword/regex/length rules but
   points at source files for the shape. The only concrete `[[guardrails]]`
   TOML in operator docs is in the external-detector adapter pages
   (`docs/guardrails/adapters/*.md`). The `keywords = [...]` field name had
   to be guessed (the guess worked).
2. **`ferrogate validate` silently accepts unknown config fields** (verified
   with a probe field). A typo'd guardrail field would silently disable a
   rule with zero feedback — validate gave no signal whether my guessed rule
   shape was even parsed.
3. **RBAC path to the investigation view is undocumented.** With a
   tenant-scoped key holding `admin.read`, `/admin/v1/investigations`
   returns `guardrail_rbac_denied` ("tenant roles do not grant required
   action guardrails.evidence.read"); `/admin/v1/roles` returns an empty
   catalog, and creating/binding a role returns
   `platform_operator_required`. Nothing operator-facing explains that a
   config API key **without** `organization_id` acts as a platform-operator
   key (which then passes the evidence-read check) — discovered by trial.
   Cost several minutes of the budget.
4. **Opaque durable-store startup error.** With `[storage]
   provider = "supabase"`, startup fails with "async PostgreSQL pool
   acquisition failed: Error occurred while creating a new object: db error"
   — no hint whether it is TLS, auth, or network. (Root cause here: sandbox
   egress can't complete the DB TLS handshake.) Also,
   `docs/durable-storage.md` shows the storage block in YAML while the
   gateway config is TOML.
5. **`/admin/v1/investigations` is discoverable only inside the OpenAPI
   JSON.** No README/docs page mentions the investigation view; I found it
   by grepping `docs/openapi/admin-api.openapi.json` for "investigation".
   README's observability bullets mention agent-run timelines but not this
   endpoint.
6. Cosmetic: `total_cost_usd` renders as `-0.0` for a zero-cost blocked
   request.

None of these blocked the drill (no doc changes were needed to finish under
the bar), but items 1, 3, and 5 are the ones most likely to push a genuinely
cold operator past 10 minutes; each deserves a small docs follow-up.

## Verdict

**PASS.** All five questions (who / why / target / action / cost) were
answered with exact fields from a single
`GET /admin/v1/investigations?request_id=...` response, in 7 min 15 s —
under the 10-minute bar — starting from zero implementation knowledge and
including gateway setup time.
