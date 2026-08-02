# SPEC-TRANSCRIPTS — behaviour that must survive `git rm -r crates/`

**Wave 24 · 2026-08-01 · branch `main-ts` · worktree `/home/dev/ferrogate-ts`**

This file exists for exactly one reason. `CUTOVER-READINESS.md` §3 names five
clusters (S1–S5) whose only complete specification is Rust source that is about
to be deleted, and §6 states the practical consequence: after the delete, parity
checking degrades from *comparison* to *archaeology*. Two of those clusters —
**S3** and **S4** — were classified as **transcription rather than
construction**: the behaviour need not be built now, but its DEFINITION must
survive.

**This document is that definition.** It is written for an implementer who has
**no access to `crates/**`** and no intention of checking out `legacy-rs` into a
scratch directory. Every claim carries a `crates/…:line` citation so a reader
can check me *while the tree still exists*. After the delete those citations
become provenance rather than verification — which is precisely why they are
here now.

## What this document is NOT

* It is **not** a port plan, a diff against the TypeScript, or a summary of the
  Rust. It is a statement of required behaviour.
* It is **not** an argument that this behaviour must be built. The owner has
  released this project from parity with an unfinished system. Building S3 and
  S4, or explicitly dropping them, are both legitimate; **losing the ability to
  decide** is what is not.
* It does **not** cover S2 or S5. S5 is tracked separately; S2 was dropped by
  the owner in wave 25 and no transcript was requested for it.
* **PART D (wave 25) covers S1**, which the owner has **dropped**. That part is
  insurance on a dropped capability, not a case for building it — see its
  preamble.

## Reading conventions

* **`MUST`** = the Rust enforced it and an implementer reproducing this surface
  has to as well, or the behaviour is not the behaviour described here.
* **`OPEN`** = the Rust is unfinished at this point. It is flagged, not
  transcribed as if it were a specification. Do **not** treat an `OPEN` marker
  as a requirement — treat it as a design decision the TypeScript gets to make
  freely.
* Line numbers are as of this wave's `main-ts` worktree.

---

# PART A — S3 · the config-backed control-plane transaction

**Cluster:** the 25 control-plane operations in groups `skill` (6),
`admin_plugin` (7), `admin_policy` (6), `prompt` (6).
**Rust that is lost:** `crates/ferrogate-gateway/src/state.rs` (the
`SharedAppState` mutation methods and the reload machinery),
`crates/ferrogate-gateway/src/server/local.rs` (the HTTP handlers),
`crates/ferrogate-config/src/config/validate.rs` (the validator the transaction
runs), `crates/ferrogate-runtime/src/reload.rs` (the commit coordinator).

**What is actually valuable here is not the CRUD. It is the TRANSACTION SHAPE.**
The cert calls it: *persist → clone config → apply snapshot → `validate()` →
reload → roll back on error → re-read and answer `409 …_reload_rejected`*. That
sequence, its ordering guarantees, and the three places it deliberately does
**not** roll back are the specification. Everything else is field plumbing.

---

## A1. The transaction, stated as an algorithm

This is the shape shared by all 25 operations. Rust implements it once per
resource kind as a `SharedAppState` method; the per-kind differences are
enumerated in §A2.

Reference implementation for the shape: **`state.rs:1334-1353`**
(`upsert_skill_package`) — the exemplar the certification names.

### A1.1 The UPSERT algorithm

```
UPSERT(resource):
  1. active  := snapshot of the currently-serving runtime state      # state.rs:1338
  2. try:
  3.     repositories.upsert_control_plane_<kind>(id(resource),      # state.rs:1340
                                                  json(resource))
  4.     candidate := deep clone of active.config                     # state.rs:1344
  5.     apply_control_plane_snapshot_to_config(candidate)            # state.rs:1345
  6.     candidate.validate()            -> may fail                  # state.rs:1346
  7.     result := reload_process_local(candidate)                    # state.rs:1347
  8.     if result.committed and <kind> is cluster-published:
  9.         publish_shared_control_plane(current().config)           # state.rs:1238
 10.     return Ok(result)
 11. on any error raised in 3..9:
 12.     sync_control_plane_storage_from_config(active.config)   # ROLLBACK, state.rs:1350
 13.     return Err
```

**Step 3 lands the durable write BEFORE anything is validated.** This is not an
oversight; it is what makes step 5 meaningful — `apply_control_plane_snapshot_to_config`
rebuilds the candidate from the *store*, so the row just written is what gets
validated. An implementation that validates first and writes second is a
different system with different failure modes, and in particular loses the
property in §A1.5.

**Step 12 is a full-collection rewrite, not a targeted undo.** See §A1.6.

### A1.2 The DELETE algorithm

```
DELETE(id):
  1. active := snapshot of currently-serving runtime state
  2. if not repositories.delete_control_plane_<kind>(id):            # state.rs:1360
  3.     return Ok(None)              # -> caller answers 404
  4. try:
  5.     candidate := clone(active.config)
  6.     apply_control_plane_snapshot_to_config(candidate)
  7.     <kind>-specific in-memory retain/removal, if any             # see A2
  8.     candidate.validate()
  9.     result := reload_process_local(candidate)
 10.     return Ok(Some(result))
 11. on error: sync_control_plane_storage_from_config(active.config); return Err
```

`delete` distinguishes **"the store had no such row"** (`Ok(None)` → `404`) from
**"the row was removed but the runtime refused the resulting config"**
(`Ok(Some(result))` with `committed = false` → `409`). Those MUST NOT collapse
into one answer: an operator retrying a `404` is doing something safe, and an
operator retrying a `409` is not.

### A1.3 `apply_control_plane_snapshot_to_config` — the reconcile

`state.rs:4960-4986`. This is the single point where durable control-plane state
becomes serving config. It **REPLACES**, wholesale, nine collections on the
candidate:

| candidate field | source | line |
|---|---|---|
| `api_keys` | `snapshot.api_keys` | 4969 |
| `policies` | `snapshot.policies` | 4972 |
| `gateway_configs` | `snapshot.gateway_configs` | 4973 |
| `agent_workflows` | `snapshot.agent_workflows` | 4974 |
| `skill_packages` | `snapshot.skill_packages` | 4975 |
| `prompt_templates` | `snapshot.prompt_templates` | 4976 |
| `plugins` | `snapshot.plugin_registrations` | 4977 |
| `mcp_servers` | `snapshot.mcp_servers` | 4979 |
| `agent_upstreams` | `snapshot.agent_upstreams` | 4980 |

Plus three effects that are easy to miss and are load-bearing:

1. **`config.api_keys_are_control_plane_documents = true`** (`state.rs:4968`).
   Documented at the call site: without it, one pre-#515 durable key fails
   validation and **400s every admin mutation, including the one that would
   repair it**. Any port that keeps a "is this config-declared or durable"
   distinction MUST set the durable flag here.
2. **`config.extensions.clear()`** (`state.rs:4978`). `extensions` is the legacy
   alias collection for `plugins`; the reconcile empties it so a legacy entry
   cannot resurrect a deleted plugin. See §A2.2.
3. **`config.materialize_skill_package_resources_with_previous(previous_skill_packages)`**
   (`state.rs:4984`), where `previous_skill_packages` was captured from the
   candidate **before** the snapshot overwrote it (`state.rs:4961`). This is the
   ownership algorithm in §A1.4 and it is the single most re-derivation-resistant
   piece of S3.

Deserialisation of any stored document that no longer parses fails the whole
reconcile with `"failed to decode control-plane storage document: {error}"`
(`state.rs:1969-1980`, error string at 1977) — i.e. **one corrupt row blocks every mutation of every
kind**. That is fail-closed, and it is stated here so a port choosing
per-row-skip instead does so knowingly.

There is a **second, near-identical** copy of this function used on the boot path:
`apply_control_plane_snapshot_to_config_from_repositories` (`state.rs:2101-2139`).
It differs in exactly one way — it also calls
`config.warn_undeclared_control_plane_api_keys()` (`state.rs:2136`), because boot
does not re-validate and this is the only place a pre-#515 durable row can be
reported before traffic arrives. The duplication is deliberate and documented
inline at `state.rs:2124-2135`.

### A1.4 Skill-package resource ownership — MUST, and non-obvious

`crates/ferrogate-config/src/config/validate.rs:34-87`.

A `SkillPackage` **owns** four kinds of child resource — plugins, MCP servers,
prompt templates and agent workflows — declared inline under
`package.resources`. Materialisation is a two-phase operation and both phases
matter:

**Phase 1 — evict (validate.rs:43-65).** Build the set of resource ids owned by
`previous_packages ∪ current_packages` (the union, *not* just the current set),
then `retain` every top-level collection to exclude those ids:

* `config.plugins` and `config.extensions` lose any plugin whose id is owned
  (validate.rs:53-56);
* `config.mcp_servers` loses any server whose **name** is owned (57-58);
* `config.prompt_templates` loses any template whose id is owned (59-60);
* `config.agent_workflows` loses any workflow matching **either** the bare
  `workflow.id` **or** the composite `skill_package_workflow_resource_id(workflow)`
  (61-65) — workflows are keyed by id+version elsewhere, so both spellings must
  be evicted.

The union with `previous_packages` is the invariant that makes **package
deletion actually withdraw its children**. Delete a package, and its ids are no
longer in `current`, so a naive implementation would leave the child plugins and
workflows materialised in the top-level collections forever. Rust prevents that
by passing the pre-reconcile package list in
(`state.rs:4961` → `state.rs:4984`). **This is enforced by control flow, not by
a named check, and it is exactly the class of invariant this document exists to
preserve.**

**Phase 2 — re-materialise (validate.rs:67-86).** For each package **where
`enabled == true`**, upsert-or-replace each child into the corresponding
top-level collection. A **disabled** package is evicted in phase 1 and not
re-added in phase 2: disabling a package withdraws its resources, and
re-enabling restores them, with no separate code path.

`upsert_or_replace_*` semantics: replace in place if the key already exists,
otherwise append (`state.rs:2062-2071` for the gateway's copy). **Order within
the collection is therefore stable across updates**, which matters because
`plugins[].order` ties are rejected by the validator (§A1.7) and because
`prompt_templates` are matched by first-hit lookup.

### A1.5 `reload_process_local` — the commit

`state.rs:880-926`.

```
reload_process_local(candidate) -> RuntimeReloadResult:
  active            := current()
  candidate_snapshot := config_snapshot_id(candidate)
  coordinator.lock()                                 # serialises commits
  reload_candidate  := coordinator.prepare(candidate_snapshot)

  # GATE 1: listener-level rejection
  if reason := process_local_reload_rejection(active.config, candidate):
      outcome := coordinator.reject(reload_candidate, reason)
      return { committed: false, mode: "listener-level-required", reason }

  # GATE 2: runtime construction
  next := active.with_reloaded_config(candidate)     # may fail
  if failed:
      outcome := coordinator.reject(reload_candidate, error.to_string())
      return { committed: false, mode: "process-local", reason: error }

  inner.write() = next                               # THE SWAP
  outcome := coordinator.commit(reload_candidate)
  return { committed: true, mode: "process-local", reason: null }
```

`RuntimeReloadResult` (`state.rs:365-371`) is the shape every one of the 25
handlers keys its response off:

| field | type | meaning |
|---|---|---|
| `active_snapshot` | string | snapshot id serving **after** this call |
| `candidate_snapshot` | string | snapshot id of the config that was offered |
| `committed` | bool | whether the swap happened |
| `mode` | `"process-local"` \| `"listener-level-required"` | `state.rs:118,120` |
| `reason` | string \| null | present iff `committed == false` |

**`config_snapshot_id`** (`crates/ferrogate-config/src/config/snapshot.rs:9-21`)
is `FNV-1a-64` over `serde_json::to_vec(config)`, rendered `{:016x}`. Offset
basis `0xcbf29ce484222325`, prime `0x00000100000001b3`. It is content-addressed:
two configs that serialise identically produce the same id, and the id is
therefore **not** a monotonically-increasing revision. Any port that uses it as
an ordering key is wrong.

**`ReloadCoordinator`** (`crates/ferrogate-runtime/src/reload.rs:27-72`) holds
one `RuntimeSnapshot { id, generation }` starting at `generation = 1`.
`prepare` returns a candidate at `active.generation + 1` **without mutating
anything** (reload.rs:45-52); `commit` replaces active (54-62); `reject` returns
an outcome naming the unchanged active (64-71). The property the coordinator
exists to hold is stated by its own test at reload.rs:78-86:
**the candidate snapshot id is never published as active before commit.** The
lock around it (`state.rs:883`) is what serialises concurrent admin mutations at
the swap point.

**GATE 1 — `process_local_reload_rejection`** (`state.rs:5446-5449`, delegating
to `state.rs:5477-5501`) compares only a `ListenerRuntimeConfig` projection:
`listen`, `tls.is_enabled()`, `tls.cert_path`, `tls.key_path`, `tls.http2`,
`tls.acme`. It returns:

* `"listen address changes require listener-level reload: active={} candidate={}"`
  when `listen` differs (state.rs:5478-5485, message at 5480);
* `"TLS listener changes require listener-level reload"` when any TLS field
  differs (state.rs:5486-5492, message at 5491).

**For all 25 S3 operations this gate is structurally unreachable** — none of
them can alter `listen` or `tls`. It is transcribed because the `mode` field it
sets is on the wire, and because a port that reuses this transaction for a
config-reload endpoint will need it.

**GATE 2 — `with_reloaded_config`** (`state.rs:4906-4938`) rebuilds the whole
`AppState` from the candidate and is where a semantically-valid-but-
unconstructible config fails (e.g. an unresolvable provider secret). It
**deliberately carries eleven pieces of state across the swap** rather than
rebuilding them (4909-4934): cluster identity, cluster counters, provider
routing metrics, metering events, metrics accumulator, analytics export, both
response caches, the MCP manager (then `reconfigure`d against the new
`mcp_servers` at 4924), approvals, guardrail evidence permits, the evidence
writer, request-id counter, drain flag, ACME state, and the unauthenticated rate
limiter. **The drain flag and the rate limiters surviving reload is a security
property**: an operator who has drained a node MUST NOT have the drain lifted by
an unrelated skill-package upsert, and an in-flight rate-limit window MUST NOT
be reset by one.

**`with_reloaded_config` also re-writes the whole control-plane store from the
NEW config on success** (`state.rs:4936`, `let _ = self.sync_control_plane_storage_from_config(&next.config)`).
The result is discarded — a failed write here does **not** fail the reload
(fail-open, stated explicitly so a port does not silently make it fail-closed).

### A1.6 Rollback — what it actually is, and its three holes

`sync_control_plane_storage_from_config` (`state.rs:4954-4958`) calls
`repositories.replace_control_plane(control_plane_documents_from_config(config))`.

`control_plane_documents_from_config` (`state.rs:1874-1905`) serialises the
**entire** control plane out of the in-memory config — all ten document
collections, each keyed by:

| collection | key |
|---|---|
| `api_keys` | `key.id` |
| `tenants` | `tenant.api_key_id` (derived from api keys) |
| `policies` | `policy.name` ← **name, not id** |
| `gateway_configs` | `profile.id` |
| `agent_workflows` | `workflow_resource_id(workflow)` (id+version composite) |
| `skill_packages` | `package.id` |
| `prompt_templates` | `template.id` |
| `plugin_registrations` | `plugin.id`, over `config.plugin_registrations()` = `plugins ++ extensions` (validate.rs:3083-3087) |
| `mcp_servers` | `server.name` ← **name, not id** |
| `agent_upstreams` | `upstream.id` |

So **rollback is "reset the store to the last-known-good serving config"**, not
"undo the one row". Consequences an implementer MUST know:

* It is **atomic in effect** for the failed operation, because the failed row
  was never in `active.config`.
* It also **silently reverts any concurrent write** that landed after `active`
  was snapshotted and before the failure. Rust accepts this; the alternative
  (per-row compensation) was not implemented. Flag it, do not copy it blindly.
* Serialisation is **lossy on failure**: `serialize_control_plane_documents`
  uses `filter_map` over `to_string().ok()` (`state.rs:1955-1967`), so a record
  that fails to serialise is **dropped from the store without an error**. This
  is a genuine fail-open in the rollback path.

**Hole 1 — a rejected reload does not roll back.** In `UPSERT`, step 7 returns
`Ok(result)` even when `result.committed == false`; `result.is_err()` is
false, so step 12 never runs. The durable row **stays written** while the
serving config does not contain it. A subsequent restart or reload will then
pick it up. This asymmetry is real and is observable: `409 …_reload_rejected`
means *"not serving, but persisted"*, not *"nothing happened"*.

**Hole 2 — the cluster publish is best-effort.** `publish_shared_control_plane`
failures propagate into the closure and DO trigger rollback for the kinds that
call it (`policy`, `plugin`, `api_key`, `mcp_server`) — but the sibling
`signal_binding_change_to_peers` used by guardrail activation explicitly does
NOT unwind (`state.rs:654-672`), with the reason stated inline: *"the binding is
already durably committed and the local runtime reloaded, so a best-effort
failure to publish must NOT unwind it — the admin endpoint's `committed=true`
stays truthful."* If a port unifies these two paths it MUST pick one posture
knowingly.

**Hole 3 — the rollback's own result is discarded** (`let _ =` at
`state.rs:1350` and every sibling). A failed rollback is invisible.

### A1.7 `validate()` — the ordering is load-bearing

`crates/ferrogate-config/src/config/validate.rs:89-124`. The candidate is
validated as a **whole config**, not as one resource, and the order is a
dependency order — each stage produces the name sets the later ones check
against:

```
listen / admin.listen parse            (90-97)
validate_providers()   -> provider_names   (99)
validate_models(provider_names) -> model_names (100)
validate_mcp_servers()                     (101)
validate_auth_service()                    (102)
validate_admin_api()                       (103)
add_mcp_policy_targets(model_names, provider_names)  (104)
validate_api_keys(model_names, provider_names) -> api_key_ids (105)
ensure_every_key_declares_tenant_identity()          (106)
warn_implicit_platform_operators()                   (107)
validate_policies(api_key_ids, model_names, provider_names)   (108)  <-- S3
validate_gateway_configs(api_key_ids)                         (109)
validate_plugins()                                            (110)  <-- S3
tool_names := workflow_tool_names()                           (111)
validate_agent_workflows(api_key_ids, model_names, provider_names, tool_names) (112)
validate_prompt_templates(model_names)                        (113)  <-- S3
validate_skill_packages(api_key_ids, tool_names)              (114)  <-- S3
validate_agent_upstreams / guardrails / tls / telemetry / …    (115-124)
```

**The cross-collection references are the point.** A policy naming an api-key id
that no longer exists fails validation; a prompt template naming a model that
was removed fails validation; a skill package naming a capability id that
resolves to nothing fails validation. Since the transaction validates the
**post-reconcile whole config**, a mutation to one collection can be rejected
because of the state of another. An implementer building this per-resource will
not reproduce it.

The per-kind rules for the four S3 collections are in §A3.

---

## A2. The four resource kinds — per-kind divergences from the shape

### A2.1 `skill` — `state.rs:1334` (upsert), `state.rs:1355` (delete)

* Cluster publish: **NO**.
* Extra in-memory step: **none** — `apply_control_plane_snapshot_to_config`
  already replaces `skill_packages` from the snapshot, and materialisation
  (§A1.4) is inside it.
* Delete does **not** need a `retain`, for the same reason.
* **Unique to `skill`: a post-commit visibility re-read** (`local.rs:1932-1948`).
  After `committed == true`, the handler re-reads `self.state.current()` and
  looks for the package by id in the freshly-committed config. If it is absent,
  it answers `409 skill_package_reload_rejected` with
  `"skill package {id} was not visible after reload"`. This catches the case
  where the package committed but was *materialised away* — i.e. the transaction
  succeeded and the resource still is not there. **No other kind does this, and
  it is the one place the transaction checks its own effect rather than its own
  return value.** A port that keeps only the `committed` flag loses it.

### A2.2 `admin_plugin` — `state.rs:674` (upsert), `state.rs:702` (delete)

* Cluster publish: **YES** — `publish_shared_control_plane` on commit
  (`state.rs:692`).
* **Extra in-memory step on upsert:** `upsert_or_replace_plugin_registration(&mut candidate.plugins, plugin)`
  at `state.rs:688`, applied **AFTER** `apply_control_plane_snapshot_to_config`
  (687) and therefore **after** skill-package materialisation. The snapshot
  already contains the row that was just written at 682-685, so this is
  redundant *except* for its ordering effect: **an admin-registered plugin
  overrides a skill-package-owned plugin of the same id.** That precedence is
  established by nothing but statement order. It is an implicit invariant and it
  is transcribed here because it is invisible in any per-function reading.
* **Extra in-memory step on delete:** BOTH
  `candidate.plugins.retain(|p| p.id != id)` and
  `candidate.extensions.retain(|p| p.id != id)` (`state.rs:716-717`) — the
  legacy `extensions` alias must be swept too, or a deleted plugin resurrects
  through `plugin_registrations()` = `plugins ++ extensions`.
* Delete returns `Ok(None)` (→ 404) when the repository reports no row removed
  (`state.rs:707-712`).

### A2.3 `admin_policy` — `state.rs:1223` (upsert), `state.rs:1248` (delete)

* Cluster publish: **YES**, on both upsert (`state.rs:1238`) and delete
  (`state.rs:1259`).
* **Keyed by `name`, not `id`** — `repositories.upsert_control_plane_policy(policy.name, …)`
  (`state.rs:1229-1232`). The wire path is `/admin/v1/policies/{name}`.
* No extra in-memory step; the snapshot replace covers it.

### A2.4 `prompt` — `state.rs:1404` (upsert), `state.rs:1425` (archive)

* Cluster publish: **NO**.
* **`DELETE` is not a delete.** `archive_prompt_template` (`state.rs:1425-1454`)
  finds the template in the *serving config*, sets
  `status = PromptTemplateStatus::Archived`, and runs the **upsert** path
  (`state.rs:1441`). The row is never removed from the store.
  * Not-found is decided against `active.config.prompt_templates`, not the store
    (`state.rs:1430-1438`) → `Ok(None)` → `404`.
  * The response is `AdminDeleteResponse { object: "prompt_template", id,
    deleted: **false** }` (`local.rs:2507-2512`). **`deleted: false` on a
    successful `DELETE` is the contract**, and it is the one wire fact most
    likely to be lost.

---

## A3. Validation rules for the four S3 collections

Every message below is the exact string the Rust emits. They surface to the
operator as the `message` of `400 invalid_<kind>` (see §A4). `{index}` is the
**0-based position in the post-reconcile collection**, which is a rebuilt array
and therefore not stable across mutations — a port that wants stable pointers
must change this deliberately.

### A3.1 `policies` — `validate.rs:2119-2167`

`PolicyRule` (`crates/ferrogate-config/src/config/types.rs:1673-1693`):

| field | type | default | notes |
|---|---|---|---|
| `name` | string | required | primary key |
| `effect` | string | `"deny"` | **only `deny` accepted**, case-insensitive |
| `organization_ids` | string[] | `[]` | empty = wildcard |
| `project_ids` | string[] | `[]` | empty = wildcard |
| `api_key_ids` | string[] | `[]` | empty = wildcard |
| `models` | string[] | `[]` | must all resolve |
| `providers` | string[] | `[]` | must all resolve |
| `code` | string | `"policy_denied"` | client-visible error code |
| `message` | string | `"request denied by policy"` | client-visible message |
| `enabled` | bool | `true` | |

`PolicyRule` is **NOT** `#[serde(deny_unknown_fields)]` (contrast
`GatewayConfigProfile` at types.rs:1696, `PromptTemplate` at 1781,
`AgentWorkflowPolicy` at 1711 — all of which are). Unknown keys on a policy
document are silently dropped. Flagged, not endorsed.

Rules, in order:
1. `name` non-empty after trim → `"field policies[{i}].name: cannot be empty"`
2. `name` unique → `"field policies[{i}].name: duplicate policy name {name}"`
3. `effect.eq_ignore_ascii_case("deny")` → `"field policies[{i}].effect: only deny is supported in the MVP"`
4. every `api_key_ids[j]` ∈ known api-key ids → `"field policies[{i}].api_key_ids: policy {name} references unknown api key {id}"`
5. every `models[j]` ∈ known model names → `"field policies[{i}].models: policy {name} references unknown model {m}"`
6. every `providers[j]` ∈ known provider names → `"field policies[{i}].providers: policy {name} references unknown provider {p}"`

**`OPEN` — rule 3 marks the Rust as unfinished here.** `"only deny is supported
in the MVP"` is the Rust telling you `allow` was never built. Do not transcribe
a hypothetical allow semantics; if the TypeScript wants `allow`, that is a fresh
design.

### A3.2 `prompt_templates` — `validate.rs:2593-2707`

`PromptTemplate` (types.rs:1782-1792, `deny_unknown_fields`):
`id`, `name`, `status` (`draft`|`active`|`archived`, default `active`,
types.rs:1797-1803), `target` (`chat_completions`|`responses`, default
`chat_completions`, types.rs:1805-1811), `model`, `variables[]`, `versions[]`.

`PromptTemplateVariable` (types.rs:1814-1824): `name`, `required` (default
`true`), `default?`, `description?`.
`PromptTemplateVersion` (types.rs:1826-1840): `revision` (default `1`),
`status` (`draft`|`active`|`archived`, default `active`), `messages[]`,
`temperature?`, `top_p?`, `max_tokens?`.
`PromptTemplateMessage` (types.rs:1851-1855): `role`, `content`.

Rules:
1. `id` non-empty → `"field prompt_templates[{i}].id: cannot be empty"`
2. `id` unique → `"…: duplicate prompt template id {id}"`
3. `name` non-empty → `"field prompt_templates[{i}].name: cannot be empty"`
4. `model` non-empty → `"field prompt_templates[{i}].model: cannot be empty"`
5. `model` ∈ known model names → `"field prompt_templates[{i}].model: prompt template {id} references unknown model {m}"`
6. `versions` non-empty → `"field prompt_templates[{i}].versions: at least one version is required"`
7. per variable: non-empty name; `is_prompt_variable_name` (letters, numbers,
   `_`, `-`) → `"…variables[{j}].name: must use letters, numbers, _, or -"`;
   unique name; `default`, if present, non-empty
8. per version: `revision != 0` → `"…: must be greater than zero"`; `revision`
   unique within the template; `messages` non-empty; per message a valid role
   and non-empty `content`; **placeholder validation** — every `{{var}}` in
   `content` must name a declared variable (`validate_prompt_placeholders`,
   called at validate.rs:2677, defined at validate.rs:3809)
9. `temperature ∈ [0.0, 2.0]` inclusive → `"…temperature: must be between 0 and 2"`
10. `top_p ∈ [0.0, 1.0]` inclusive → `"…top_p: must be between 0 and 1"`
11. `max_tokens != Some(0)` → `"…max_tokens: must be greater than zero"`

**Revision assignment on write** — `normalize_appended_prompt_template_revision`
(`local.rs:11372-11388`): when appending to an existing template, if the
submitted `revision` is `<= max(existing revisions)` it is **silently rewritten**
to `max + 1` (saturating). Only after that is a duplicate-revision collision an
error. So an operator who posts `revision: 1` against a template that already
has revisions 1–3 gets revision **4**, not a `400`. That is deliberate
append-only behaviour and is invisible from the type definition.

**Active-revision selection** — `active_prompt_template_version`
(`local.rs:11403-11415`): the **highest-`revision` version whose `status ==
Active`**; if none is `Active`, the **highest-`revision` version regardless of
status**. The fallback is what makes a template with only `draft` versions still
renderable. `AdminPromptTemplate.active_revision` is this version's `revision`,
or `null` for an empty `versions` array (`local.rs:11117-11127`).

### A3.3 `plugins` — `validate.rs:3029-3080`

The validated set is `plugins ++ extensions` via
`plugin_registrations_for_validation` (validate.rs:3089-3102), which tags each
entry with its section name so messages read `field plugins[…]` or
`field extensions[…]`.

`ExtensionKind` (types.rs:2004-2008): `request_hook` | `tool_provider` |
`event_sink`.

Rules:
1. `id` non-empty → `"field {section}[{i}].id: cannot be empty"`
2. `id` unique **across both sections** → `"field {section}[{i}].id: duplicate plugin id {id}"`
3. `source` non-empty → `"field {section}[{i}].source: cannot be empty"`
4. **`source == "builtin"`** → `"field {section}[{i}].source: only builtin plugins are supported in this phase"`
5. among **enabled** plugins, `(kind, order)` MUST be unique →
   `"field {section}[{i}].order: duplicate enabled plugin order {order} for kind {kind:?}"`.
   Disabled plugins are exempt, so two disabled plugins may share an order and
   enabling the second becomes the failure. **That is a deferred failure by
   construction** and worth knowing before an operator hits it.
6. `permissions.tools` and `permissions.network` name validation
7. `validate_plugin_tenant_scope_permission`, `validate_plugin_secret_permission`,
   `validate_plugin_manifest` (validate.rs:3072-3074)
8. `validate_builtin_plugin_shape` (validate.rs:3862+) — a **closed set** of
   known builtin ids:
   * `tool.echo`, `tool.health_check` → MUST be `tool_provider`
   * `mcp.http` → MUST be `tool_provider`; `config.endpoint` required, must
     parse as a URI, **scheme MUST be `http`**, must include a host, and
     `permissions.network` MUST contain `*` or that exact host. Message
     (validate.rs:3893), on one line so it stays greppable:
     `field {section}[{i}].config.endpoint: mcp.http supports http endpoints only in this phase`
   * `event.audit_log` → MUST be `event_sink`
   * `hook.noop` / `hook.noop.*` → the only accepted `request_hook`

**`OPEN` — the plugin RUNTIME is unfinished and MUST NOT be transcribed as a
specification.** `crates/ferrogate-gateway/src/extensions.rs:711-713` defines
`enum RequestHook { Noop(HookConfig) }` — one variant, a no-op — and
`extensions.rs:824-826` defines `EventSink` with `AuditLog` as its only arm
(`extensions.rs:551-563` is the whole builtin dispatch). Rule 4 above
(`source == "builtin"` only) is the same statement from the config side. So:
**`admin_plugin`'s write path is complete and its ENFORCEMENT surface is a
skeleton.** Building the CRUD faithfully is defensible; building the hook model
by copying `RequestHook` is not — it should be designed fresh, exactly as
`CUTOVER-READINESS.md` §3 says for S2's hook half.

### A3.4 `skill_packages` — `validate.rs:2418-2591`

`SkillPackage` (types.rs:2061-2083 — **not** `deny_unknown_fields`):

| field | type | default |
|---|---|---|
| `id` | string | required |
| `name` | string | required |
| `version` | string | `default_skill_package_version()` |
| `description` | string? | `null` |
| `enabled` | bool | `true` |
| `compatibility` | `{ min_gateway_version?, agent_runtimes[] }` (types.rs:2097-2103) | `{}` |
| `permissions` | `ExtensionPermissions { tools[], network[], filesystem }` (types.rs:2124+) | `{}` |
| `capabilities` | `SkillPackageCapability[]` (types.rs:2105-2110) | `[]` |
| `resources` | `{ plugins[], mcp_servers[], prompt_templates[], agent_workflows[] }` (types.rs:2085-2095) | `{}` |
| `api_key_ids` | string[] | `[]` |
| `metadata` | map<string, toml::Value> | `{}` |

`SkillPackageCapabilityKind` (types.rs:2114-2121): `plugin` | `tool` |
`mcp_server` | `mcp_tool` | `prompt_template` | `agent_workflow`.

The validator first builds four resolution sets **that include the packages' own
embedded resources** (validate.rs:2423-2469), so a package may declare a
capability pointing at a resource it itself ships. For MCP servers it also
synthesises two tool spellings per declared tool: the bare `tool` and
`"{server.name}-{tool}"` (validate.rs:2454-2456).

Rules:
1. `id` non-empty; `id` unique → `"…: duplicate skill package id {id}"`
2. `name` non-empty; `version` non-empty
3. **`capabilities` MUST be non-empty** →
   `"field skill_packages[{i}].capabilities: at least one capability is required"`
4. every `api_key_ids[j]` ∈ known api-key ids
5. `permissions.tools` / `permissions.network` name validation
6. every `compatibility.agent_runtimes[k]` non-empty
7. `validate_skill_package_resource_capabilities(i, package)`
8. per capability: `id` non-empty, and **`id` MUST resolve in the set selected
   by `kind`** — `plugin`→plugin ids, `tool`/`mcp_tool`→workflow tool names ∪
   embedded tool names, `mcp_server`→server names, `prompt_template`→template
   ids, `agent_workflow`→workflow ids. Message form:
   `"field skill_packages[{i}].capabilities[{j}].id: skill package {id} references unknown {kind-noun} {cap_id}"`.

---

## A4. The HTTP contract — status codes, error codes, trigger conditions

All 25 operations live under `/admin/v1/**`. All 25 reads require scope
`admin.read`; all 25 writes require scope `admin.write` **and then**
`require_platform_operator` (`crates/ferrogate-gateway/src/auth.rs:478-487`),
which answers `403 platform_operator_required` with
`"this endpoint is restricted to platform-operator API keys"` for any credential
whose `caller_scope()` is not `PlatformOperator`.

`caller_scope()` (`auth.rs:237-254`): **platform-operator status is a declared
property of the credential, never an inference from a missing tenant.** A
context with neither is given `UNSCOPED_TENANT_ID` — an id no `tenants.id` can
equal — so it is denied everything and filtered to nothing. That is the
fail-closed default and it is documented inline at auth.rs:241-248.

### A4.1 Write ladder (identical for all four kinds)

In this exact order:

| # | Condition | Status | `code` | `message` |
|---|---|---|---|---|
| 1 | authentication fails | from `AuthError` | from `AuthError` | from `AuthError` |
| 2 | caller is not a platform operator | 403 | `platform_operator_required` | fixed string above |
| 3 | body exceeds `limits().admin_body_max_bytes()` | 413 | `payload_too_large` | `"request body exceeds maximum size of {n} bytes"` — and the connection is **closed** (`write_json_error_and_close`) |
| 4 | body is not valid JSON for the mutation type | 400 | `invalid_request_body` | `"request body must be a JSON {kind} object"` |
| 5 | path id ≠ body id | 400 | `invalid_{kind}` | `"request path id and body id must match"` (policy: `"request path name and body name must match"`) |
| 6 | payload→resource coercion fails | 400 | `invalid_{kind}` | the coercion error |
| 7 | transaction returns `Err` (validation, storage, serialisation) | 400 | `invalid_{kind}` | `error.to_string()` |
| 8 | transaction returns `committed = false` | **409** | `{kind}_reload_rejected` | `result.reason`, else the per-kind default below |
| 9 | (skill only) committed but not visible after reload | **409** | `skill_package_reload_rejected` | `"skill package {id} was not visible after reload"` |
| 10 | success | **201** if no path id, **200** if path id | — | the resource envelope |

Per-kind code fragments and `reason` defaults:

| kind | `invalid_*` code | `409` code | default reason |
|---|---|---|---|
| skill | `invalid_skill_package` | `skill_package_reload_rejected` | `"runtime rejected candidate skill package"` |
| plugin | `invalid_plugin` | `plugin_reload_rejected` | `"runtime rejected candidate plugin config"` |
| policy | `invalid_policy` | `policy_reload_rejected` | `"runtime rejected candidate policy config"` |
| prompt | `invalid_prompt_template` | `prompt_template_reload_rejected` | `"runtime rejected candidate prompt template"` |

Note the **skill upsert's step-5 check is inline in the deserialise arm**
(`local.rs:1898-1907`) and emits `invalid_skill_package`, whereas the other
three do it inside `*_from_mutation` and reach the same code by step 6. Same
observable result, different code path.

**201 vs 200 is decided by `path_id.is_some()`, not by whether the resource
existed** (`local.rs:1962-1966`, `2409-2413`, `9130-9133`, `7743-7746`). `POST` to the
collection is always `201` even when it replaces an existing resource; `PUT`/
`PATCH` to `/{id}` is always `200` even when it creates one.

### A4.2 Delete ladder

| Condition | Status | `code` | `message` |
|---|---|---|---|
| auth / operator | as above | | |
| repository reports no such row (`Ok(None)`) | 404 | `{kind}_not_found` | `"{kind} {id} was not found"` |
| `committed = false` | 409 | `{kind}_reload_rejected` | reason, or per-kind default (`"runtime rejected skill package delete"` / `"runtime rejected candidate plugin config"` / `"runtime rejected candidate policy config"` / `"runtime rejected prompt template archive"`) |
| `Err` | 400 | `invalid_{kind}_delete` (skill: `invalid_skill_package_delete`; plugin: `invalid_plugin_delete`; policy: `invalid_policy_delete`; prompt: `invalid_prompt_template_archive`) | `error.to_string()` |
| success | 200 | — | `AdminDeleteResponse { object, id, deleted }` |

`deleted` is `true` for skill/plugin/policy and **`false` for prompt** (§A2.4).

### A4.3 Method-not-allowed

Each router arm has a distinct message, all under `405 method_not_allowed`:

* skill: `"skill package endpoint supports GET, POST, PUT, PATCH, and DELETE"` (local.rs:1836)
* prompt: `"prompt template endpoint supports GET, POST, PUT, PATCH, and DELETE"` (local.rs:2270)
* policy: `"policy endpoint supports GET, POST, PUT, PATCH, and DELETE"` (local.rs:8992)
* plugin list: `"plugin list endpoint supports GET and POST"` (local.rs:7516)
* plugin legacy alias: `"legacy extensions alias supports GET only"` (local.rs:7487)
* plugin unmatched subpath: **404 `plugin_endpoint_not_found`**, `"plugin endpoint not found"` (local.rs:7588-7592) — note this is a 404, not a 405.

### A4.4 The `admin_plugin` route surface (7 operations)

`handle_admin_plugins` (`local.rs:7470`) authenticates **once at the top** with
`admin.read`, then dispatches — so **every** plugin route, including the writes,
requires `admin.read` before the write handler re-authenticates with
`admin.write`. That double gate is deliberate and is why a read-only key gets
`403 platform_operator_required` from the inner handler rather than a scope
error from the outer.

| # | route | notes |
|---|---|---|
| 1 | `GET /admin/v1/extensions` | legacy alias; body is `AdminList::new(state.extension_statuses())`, **GET only** |
| 2 | `GET /admin/v1/plugins` | same body as (1) |
| 3 | `POST /admin/v1/plugins` | upsert, no path id → 201 |
| 4 | `GET /admin/v1/plugins/{id}` | `state.plugin_status(id)`, else `404 plugin_not_found` `"plugin {id} is not registered"` |
| 5 | `POST\|PUT\|PATCH /admin/v1/plugins/{id}` | upsert with path id → 200 |
| 6 | `DELETE /admin/v1/plugins/{id}` | |
| 7 | `GET /admin/v1/plugins/{id}/tools` | `404 plugin_not_found` if unregistered, else `AdminList::new(state.plugin_tools(id))` |

`RegisteredTool` (`extensions.rs:41-50`) is
`{ name, description?, input_schema, extension_id, approval_policy,
tenant_allowlist[], api_key_allowlist[], route_allowlist[] }` — the three
allowlists are the per-tool governance selectors S2 depends on.

---

## A5. Read-side scoping — #535, and why it is part of S3

The list and single-get reads of `skill` and `admin_policy` are **not** plain
projections. They run the `ConfigCatalogScope` narrowing, which is transcribed
in full in **§B3** because `admin_model` (S4) depends on the same machinery.
Summary of the S3-specific bindings:

* `GET /admin/v1/skill-packages` → `scope.visible_skill_package(package)`
  (list arm `local.rs:1744`; by-id arm `local.rs:1788-1793`).
* `GET /admin/v1/skill-packages/{id}` → `visible` is `None` **and**
  `!scope.is_full()` ⇒ `403 tenant_scope_denied` via
  `write_config_scope_denied(session, "skill package", …)` (`local.rs:1794-1797`);
  `None` with a full scope ⇒ `404 skill_package_not_found`.
* `GET /admin/v1/policies` → `scope.visible_policy(rule)` (`local.rs:8908-8912`).
* `GET /admin/v1/policies/{name}` → same 403-vs-404 discrimination
  (`local.rs:8955-8957`), entity string `"policy"`.
* `config_catalog_scope` failure ⇒ **`503 storage_unavailable`** with
  `error.to_string()` as the message (e.g. `local.rs:1727-1739`, `1770-1782`, `8895`, `8937`, `8254-8266`). **Storage failure does NOT degrade to an unfiltered scope**
  (`rbac.rs:1463-1465`, stated in the docblock). Fail-closed.

`admin_plugin` and `prompt` reads are **NOT** scoped — they render the whole
collection to any `admin.read` caller. That asymmetry is real: #535 swept the
surfaces carrying cross-tenant selectors (`api_key_ids`,
`visible_*_ids`), and `PluginConfig` / `PromptTemplate` carry none.

## A6. Projections — what the wire actually carries

* **`admin_skill_package`** (`local.rs:10566-10580`) → `AdminSkillPackage`
  (`responses.rs:813-825`): `id, name, version, description, enabled,
  compatibility, permissions, capabilities, resources, api_key_ids, metadata`,
  where `resources` goes through `admin_skill_package_resources`
  (`local.rs:10815-10823`) which **redacts each embedded plugin's `config`**,
  and `metadata` goes through `redact_plugin_config` directly.
* **`agent_skill_package`** (`local.rs:10825-10834`) — the **data-plane**
  `/v1/skills` projection, deliberately narrower: `id, name, version,
  description, capabilities, compatibility` only. No `permissions`, no
  `resources`, no `api_key_ids`, no `metadata`.
* **`skill_package_visible_to_auth`** (`local.rs:10836-10845`) — the data-plane
  predicate: **disabled packages are hidden**, and a non-empty `api_key_ids`
  must contain the caller's `api_key_id`. Contrast `visible_skill_package`
  (§B3), which does **not** hide disabled packages because the admin console
  needs to render them; the reason is stated at `rbac.rs:1356-1360`.
* **`admin_plugin`** (`local.rs:11012-11049`) → `AdminPlugin`
  (`responses.rs:893-911`). Merges the **config** record with the **runtime**
  `ExtensionStatus`. When the plugin is not loaded it synthesises a status with
  `active: false`, `health: "unknown"`, `last_error: Some("plugin is not
  loaded")`. `config` is redacted. `lifecycle` is derived by `plugin_lifecycle`
  (`local.rs:11052-11065`): `"disabled"` if `!enabled`; `"enabled"` if active;
  otherwise the health string mapped through
  `version_incompatible|failed|degraded`, defaulting to `"registered"`.
* **`admin_prompt_template`** (`local.rs:11117-11127`) → adds the derived
  `active_revision` (§A3.2) to the stored fields.

### A6.1 Secret redaction — `redact_plugin_config`

`local.rs:11067-11101`, predicate at `local.rs:11103-11115`.

A key is a secret if its **lowercased** form **contains** any of:
`secret`, `token`, `password`, `credential`, `api_key`, `auth`.
Matching keys have their value replaced with the literal string `"[redacted]"`.
Redaction **recurses through arrays and tables** (`redact_plugin_config_value`),
and is applied to: `AdminPlugin.config`, `AdminSkillPackage.metadata`, and every
embedded plugin `config` inside `AdminSkillPackage.resources`.

**Substring, not equality** — `oauth_client` matches (`auth`), `bearer` does
not. That is the rule; port it exactly or change it deliberately.

---

# PART B — S4 · `admin_provider` (3) + `admin_model` (1)

**Cluster:** four **read-only** operations. There is no write half in Rust —
providers and models are operator config (`[[providers]]`, `[[models]]`), never
admin-mutable. Anyone porting this MUST NOT infer a missing write path.

| # | route | handler | `state` source |
|---|---|---|---|
| 1 | `GET /admin/v1/providers` | `local.rs:5019` | `config.providers` projection |
| 2 | `GET /admin/v1/provider-health` | `local.rs:7445` | live TCP probe + circuit + routing metrics |
| 3 | `GET /admin/v1/provider-models` | `local.rs:5062` | **live per-provider catalog fetch** |
| 4 | `GET /admin/v1/models` | `local.rs:8227` | `config.models` through the **#535 redaction** |

Routing is exact-path (`server/route_groups.rs:601-623` and `758-769`) — no
path parameters anywhere in this cluster.

**The certification's judgement, restated: the redaction (§B3) is the part whose
loss is a credential-disclosure regression.** The projections are re-derivable;
the narrowing rules are not.

---

## B1. `GET /admin/v1/providers` — `local.rs:5019-5059`

Auth: `admin.read` only. **No `require_platform_operator`, no scope narrowing.**

Query parameters:
* `search` — case-insensitive **substring** match against `provider.name` **or**
  `provider.kind` (`matches_search`, `server/admin_list_query.rs:11-19`;
  `query_value` at 3-9 trims and treats empty as absent).
* `offset`, `limit` — see §B4.

Per provider, the projection is `AdminProvider` (`responses.rs:730-738`):

| field | value | source |
|---|---|---|
| `name` | `provider.name` | |
| `kind` | `provider.kind` | |
| `compatibility` | `"openai-compatible"` or `"dedicated"` | `crates/ferrogate-providers/src/types.rs:350-356` |
| `base_url` | `provider.base_url` | |
| `has_api_key` | `provider.api_key_env.is_some()` | **a boolean, never the value or the env-var name** |
| `enabled` | `provider.enabled` | |

`has_api_key` is the whole credential posture of this endpoint. **The response
carries no credential, no secret reference and no environment-variable name.**
Reproduce that.

`provider_compatibility_kind` returns `"openai-compatible"` iff
`canonical_provider_adapter_family(kind) == OpenAiCompatible`
(providers/types.rs:346-348), else `"dedicated"`.

---

## B2. `GET /admin/v1/provider-models` — `local.rs:5062-5183`

Auth: `admin.read` only. **No scope narrowing.** This is the only operation in
this cluster that performs **outbound network I/O on an admin read**, and that
is the fact most worth carrying forward.

### B2.1 Algorithm

```
provider_filter := query "provider=<name>"        # local.rs:11130-11137, exact match
providers := config.providers filtered by provider_filter
catalogs  := []
for provider in providers:
    if not provider.enabled:
        catalogs += { provider, kind, base_url, enabled:false,
                      status:"disabled", models:[], error:null }
        continue
    request := state.prepare_model_catalog(provider)          # may Err
    if Err(e):        catalogs += provider_catalog_error(provider, e); continue
    response := dispatch_provider_catalog_request(request,
                    state.provider_dispatch_timeout(),
                    PROVIDER_CATALOG_BODY_MAX_BYTES)          # may Err
    if Err(e):        catalogs += { …, status:"error", models:[], error:e }; continue
    if not response.status.is_success():
                      catalogs += { …, status:"error", models:[],
                                    error:"provider catalog returned HTTP {code}" }; continue
    models := state.parse_model_catalog(provider.kind, response.body)   # may Err
    if Err(e):        catalogs += provider_catalog_error(provider, e); continue
    catalogs += { …, status:"ok", models, error:null }

if provider_filter is set and catalogs is empty:
    404 provider_not_found  "provider was not found"
else:
    200 AdminList::new(catalogs)          # UNPAGED — see B4
```

### B2.2 Ordering, isolation and the failure posture

* Providers are contacted **sequentially, in config order** (`local.rs:5083`,
  a plain `for` loop) — not concurrently. Worst-case latency is
  `providers × provider_dispatch_timeout`.
* **Every failure is per-provider and returns 200.** A dead provider yields one
  catalog entry with `status: "error"` and a populated `error` string; the
  other providers are unaffected. The **only** non-200 is the filtered-and-empty
  `404`. This is fail-*open* for the endpoint and fail-*visible* per row, and it
  is the right posture for an operator diagnostic — but it is a posture, so it
  is stated: **`local.rs:5170-5178`.**
* `status` is one of exactly four strings: `"disabled"`, `"ok"`, `"error"`,
  and — via `provider_catalog_error` (`local.rs:11139-11152`) — `"error"` again
  with `enabled` copied from the provider rather than hard-coded `true`. Note
  the inconsistency: the two inline error arms hard-code `enabled: true`
  (local.rs:5140, 5152) while `provider_catalog_error` uses `provider.enabled`.
  For an enabled provider these agree; a disabled provider never reaches them.

### B2.3 Transport rules

`dispatch_provider_catalog_request` (`crates/ferrogate-gateway/src/server/dispatch.rs:131-155`):

* Method **GET**, with the adapter-supplied headers.
* Timeout = `state.provider_dispatch_timeout()` =
  `reliability.provider_dispatch_timeout_secs`, **default 10 seconds**
  (`state_routing.rs:644-651`).
* Body cap = `PROVIDER_CATALOG_BODY_MAX_BYTES` = **2 MiB**
  (`local.rs:82`, `2 * 1024 * 1024`).
* The cap is enforced **twice**: an early reject on `Content-Length >
  max_body_bytes` → `"provider_catalog_body_too_large: provider model catalog
  exceeds {n} bytes"` (dispatch.rs:145-150), and a **chunk-bounded read**
  (`read_bounded_response_body`) because *"the post-read length check alone did
  not bound a chunked / Content-Length-lying catalog response"* (dispatch.rs:152-154).
  **Both are required.** A port that trusts `Content-Length` has an unbounded
  memory read against a hostile or broken upstream.
* Transport errors are classified before being surfaced
  (`provider_transport_failure_class`, dispatch.rs:167-186): `connect`,
  `timeout`, `redirect`, `body`, `decode`, `request`, `transport`, checked in
  that order — `is_connect` **before** `is_timeout` on purpose, because a TCP
  connect deadline reports both and "connect" is the more actionable. The class
  is wrapped as `"provider model catalog request failed ({class})"`. The
  motivation (issue #384) is that `Display` on an `anyhow::Error` prints only
  the outermost context, so a refused connection and an elapsed timeout
  otherwise collapse to one indistinguishable string.
* **The `base_url` never appears in a client-visible message** — deliberate,
  because it can carry a credential (dispatch.rs:180-183).

### B2.4 Which providers can answer at all

`ProviderAdapter::prepare_model_catalog` has a **default implementation that
errors**: `AdapterError::UnsupportedProviderKind { kind }`
(`crates/ferrogate-providers/src/types.rs:424-437`), and so does
`parse_model_catalog`. Only two adapters override it:

* **`openai`/openai-compatible** (`crates/ferrogate-providers/src/openai.rs:103-117`):
  endpoint = `format!("{}/models", base_url.trim_end_matches('/'))`
  (openai.rs:310-312); headers = the standard provider auth headers.
* **`openrouter`** (`crates/ferrogate-providers/src/openrouter.rs:63-78`):
  delegates to the openai-compatible adapter after rewriting `kind` to
  `"openai-compatible"`, then **appends** `http-referer` and `x-title` headers
  when `openrouter_http_referer` / `openrouter_x_title` are configured and
  non-empty (openrouter.rs:104-119).

**Everything else — Anthropic, Bedrock, Vertex, … — returns `status: "error"`
with an `UnsupportedProviderKind` message.** That is not a defect to fix on
port; it is the surface as it exists.

### B2.5 Catalog parsing — `parse_openai_model_catalog`

`openai.rs:314-350`.

* Body MUST be JSON → `"provider model catalog must be JSON: {err}"`
* MUST have a top-level `data` array → `"provider model catalog must include a data array"`
* Per entry: `id` MUST be a non-blank string → `"provider model catalog entry missing id"`
  (**one bad entry fails the whole catalog** — `.collect::<Result<Vec<_>,_>>()`
  at openai.rs:349, not a per-entry skip)
* `owned_by` ← `owned_by` (string) or `null`
* `created` ← `created` (u64) or `null`
* `context_window` ← **`context_length` first, then `context_window`**
  (openai.rs:342-345) — the fallback order matters, OpenRouter uses the former
* `capabilities` ← `catalog_capabilities` (openai.rs:352-373): the union of the
  string members of `capabilities`, `supported_modalities`, `input_modalities`
  and `output_modalities`, blank entries dropped, then **sorted and deduped**.
  The sort makes the output order deterministic and independent of the
  upstream's key order.

Wire shape `AdminProviderModelCatalog` (`responses.rs:741-749`):
`{ provider, kind, base_url, enabled, status, models[], error? }`;
`AdminProviderModelCandidate` (`responses.rs:752-758`):
`{ id, owned_by?, created?, context_window?, capabilities[] }`.

---

## B3. `GET /admin/v1/models` — the #535 field-level redaction

`local.rs:8227-8281`. **This is the S4 item the certification calls spec-bound.**

### B3.1 What the handler does

1. Authenticate with `admin.read` (`local.rs:8241`).
2. Resolve `config_catalog_scope(&state, &auth)` (`local.rs:8254`); on error →
   **`503 storage_unavailable`** with the error string.
3. Filter by `search` — substring over `model.name`, `model.provider`,
   `model.provider_model` (`local.rs:8267-8276`).
4. **`.filter_map(|model| scope.visible_model(model))`** (`local.rs:8278`) —
   visibility and redaction decided together.
5. Paginate (§B4) and answer 200.

The inline comment at `local.rs:8228-8234` states the defect this closed:
`.cloned()` returned the whole `Model`, which carries
`visible_organization_ids` / `visible_project_ids`, **and those are in the
response schema, so the leak was not theoretical.** `GET /v1/models` had
filtered on exactly this since #515 via `can_tenant_use_model`; the admin
listing did not, and it also rendered the two id lists themselves.

### B3.2 `config_catalog_scope` — resolving the caller's slice

`crates/ferrogate-gateway/src/server/rbac.rs:1467-1512`.

```
if auth.caller_scope() is not Tenant(t):  return Full          # rbac.rs:1471-1473
api_key_ids := { k.id  | k in config.api_keys, k.organization_id == Some(t) }
project_ids := { k.project_id | same keys, where present }
api_key_ids += { k.id | k in state.list_virtual_api_keys(), k.tenant_id == t }
project_ids += { p.id | p in state.list_projects(),        p.tenant_id == t }
return Tenant { tenant_id: t, api_key_ids, project_ids }
```

Three properties MUST hold:

1. **Classification comes from `auth.caller_scope()`, never from
   `organization_id.is_none()`** (rbac.rs:1461-1462). Only a credential that
   *declared* platform root gets `Full`.
2. The owned sets union **static config keys** and **durable/virtual keys**. An
   id in neither set is treated as another tenant's — **fail closed**
   (rbac.rs:1258-1262).
3. **Storage failures propagate** (the `?` on `list_virtual_api_keys` and
   `list_projects`, rbac.rs:1495-1507) and become `503 storage_unavailable` at
   every call site. They do **not** degrade to an unfiltered scope. Stated in
   the docblock at rbac.rs:1463-1465.

### B3.3 The two narrowing primitives

**`narrow(selector, owned)`** — `rbac.rs:1276-1288`:

```
if selector is empty:            return Some([])          # wildcard preserved
kept := [ id for id in selector if id in owned ]
if kept is empty:                return None              # ENTRY HIDDEN
else:                            return Some(kept)
```

**`narrow_organizations(selector, tenant_id)`** — `rbac.rs:1292-1303`:

```
if selector is empty:            return Some([])
if tenant_id in selector:        return Some([tenant_id])  # REBUILT, not filtered
else:                            return None
```

The organization arm **rebuilds** the list from the caller's own id rather than
filtering the stored one, *"so no value that was in the stored selector can
survive into the response even if the caller's id were to appear there in some
other spelling"* (rbac.rs:1289-1291).

**The invariant that makes this correct, and that is trivially destroyed by a
careless port:** `narrow` returns `None` — hide the entry — rather than an empty
vector, whenever a **non-empty** selector loses all of its entries. Because an
empty selector means *wildcard*, returning `Some([])` there would re-render an
entry scoped to tenant B as one that reads as applying to **everyone**, tenant A
included. Stated at rbac.rs:1244-1249. **A port that maps "no matches" to `[]`
has silently converted a scoped rule into a global one.**

### B3.4 `visible_model`

`rbac.rs:1334-1349`:

```
if scope is Full:  return Some(model.clone())
return Some(Model {
    visible_organization_ids: narrow_organizations(model.visible_organization_ids, tenant_id)?,
    visible_project_ids:      narrow(model.visible_project_ids, project_ids)?,
    ..model.clone()
})
```

The `?` on each field **is the AND**: either narrowing yielding `None` hides the
whole model. This mirrors the runtime's own reader — `ModelVisibility::allows` →
`allows_optional_scope` (`state.rs:5518-5521` and `state.rs:6839-6849`): empty is a wildcard, non-empty
is an allow-list, and the two are ANDed. **The admin read and the request path
therefore agree by construction.** Any port MUST keep them agreeing; a
divergence here is either a leak or a phantom.

`Model`'s narrowed fields (`crates/ferrogate-config/src/config/types.rs:1462-1509`)
are `visible_organization_ids` (1493) and `visible_project_ids` (1495). Every
other field passes through verbatim — including `input_price_per_1m` /
`output_price_per_1m`, `context_window`, `capabilities`, `canary`, `shadow`,
`fallbacks`, `routing_strategy`, `enabled`, `cache_enabled`. **Only the two id
lists are cross-tenant identifiers**; the rest are operator config the caller is
entitled to see once the model is visible at all.

### B3.5 The rest of the family, for consistency

`ConfigCatalogScope` has six `visible_*` methods and they are one pattern with
per-type selector bindings. Reproducing `visible_model` alone will drift; the
whole table is:

| method | line | narrowed fields |
|---|---|---|
| `visible_policy` | rbac.rs:1306 | `organization_ids` (org-narrow), `project_ids`, `api_key_ids` |
| `visible_model` | rbac.rs:1334 | `visible_organization_ids` (org-narrow), `visible_project_ids` |
| `visible_skill_package` | rbac.rs:1362 | `api_key_ids` only |
| `visible_agent_upstream` | rbac.rs:1383 | `tenant_ids` — **narrowed against `api_key_ids`** |
| `visible_gateway_config` | rbac.rs:1398 | `api_key_ids` |
| `visible_agent_workflow` | rbac.rs:1435 | `organization_ids` (org-narrow), `project_ids`, `api_key_ids` |

Two traps documented in the Rust and worth carrying:

* **`AgentUpstreamConfig::tenant_ids` is a misnomer** (rbac.rs:1372-1382): the
  runtime matches it against `AuthContext::api_key_id`, so it is an **api-key**
  allow-list. Narrowing it against the tenant id — which the field name invites
  — *"would hide every upstream from every caller."*
* **`visible_skill_package` deliberately does NOT hide disabled packages**
  (rbac.rs:1353-1361), unlike the data-plane `skill_package_visible_to_auth`.
  `enabled` is operator-authored state on a package the caller can already see;
  only the *selector* is a cross-tenant identifier, and the admin console needs
  to render disabled entries.

### B3.6 The single-object oracle rule

`write_config_scope_denied` (`rbac.rs:1514-1528`) answers
**`403 tenant_scope_denied`** with
`"API key is not authorized to read this {entity}"`.

The rule at every by-id read: if the entry is not visible **and**
`!scope.is_full()`, answer `403`. If it is not visible and the scope **is**
full, answer the ordinary `404`. Stated at rbac.rs:1509-1513 and again inline at
local.rs:1783-1787 and local.rs:8951-8954: **out-of-scope and nonexistent are
the same answer for a tenant-scoped caller**, so the ids the list no longer
discloses cannot be walked back one probe at a time; `!scope.is_full()` is what
preserves a platform operator's genuine `404`.

`GET /admin/v1/models` has **no by-id route**, so this rule reaches S4 only
through the shared helper. It is transcribed here because the helper is shared
and losing it breaks §A5's skill and policy reads.

---

## B4. `GET /admin/v1/provider-health` — `local.rs:7445-7468`

Auth: `admin.read` only. No query parameters, **no pagination**, no scope
narrowing. Body is `AdminList::new(state.provider_health_checks())`.

`provider_health_checks` (`state_routing.rs:678-684`) maps every configured
provider through `provider_health_check` (`state_routing.rs:720-767`):

**Disabled provider** — returns immediately with `status: "disabled"`,
`reachable: false`, `error: null`, and the routing metrics still attached.

**Enabled provider:**

1. `probe := probe_provider_endpoint(base_url, 500ms)` — `state.rs:6812-6837`.
   This is a **raw TCP `connect` with a 500 ms timeout**, not an HTTP request:
   parse the URI, require a scheme (`http`→80, `https`→443, anything else →
   `"unsupported provider base_url scheme {s}"`), require an authority, resolve
   to a socket address, `TcpStream::connect_timeout`. Error strings:
   `"invalid provider base_url: {e}"`, `"provider base_url is missing scheme"`,
   `"provider base_url is missing authority"`,
   `"failed to resolve provider endpoint: {e}"`,
   `"provider endpoint resolved no addresses"`,
   `"failed to connect provider endpoint: {e}"`.
2. `reachable := probe.is_ok()`
3. `status :=` `"circuit_open"` if the breaker is open, else `"healthy"` if
   reachable, else `"unreachable"` (state_routing.rs:744-750) — **the circuit
   takes precedence over reachability**.

`ProviderHealthCheck` (`state.rs:3958-3972`):
`{ name, kind, base_url, enabled, status, reachable, circuit_open,
consecutive_failures, checked_at_unix?, error?, routing, local_observations,
cluster_observations? }`.

`ProviderRoutingHealth` (`state.rs:3418-3426`):
`{ observed_requests, successful_requests, failed_requests,
average_latency_ms?, failure_rate, health_rank, health_reason }`.

Derivations:
* `score()` (`state.rs:3389-3403`): `observed_requests = successful + failed`
  (saturating); `average_latency_ms = total_latency_ms / successful_requests`
  (**checked division — `None` when `successful_requests == 0`**);
  `failure_rate = failed / total`, or `0.0` when `total == 0`.
* `health_rank` (`state.rs:6974-6982`): **`2`** if the circuit disallows;
  **`1`** if `observed_requests >= 3 && failure_rate >= 0.5`; else **`0`**.
  Lower is healthier. A disabled provider is pinned to rank `3`
  (state_routing.rs:781).
* `health_reason` (`state.rs:6984-6995`): `"circuit_open"` |
  `"observed_failure_rate"` | `"no_observations"` | `"healthy_observations"`,
  in that precedence order. Disabled providers get `"disabled"`
  (state_routing.rs:781).

**`OPEN` — `cluster_observations` is always `null`.** It is hard-coded `None` at
both return sites (`state_routing.rs:738` and `state_routing.rs:765`) and
nothing else ever populates it. `routing` and `local_observations` are the
**same value duplicated** under two names. This is unfinished Rust: the field
exists for a cross-node aggregate that was never built. **Do not transcribe a
cluster-observation semantics; there isn't one.** A port may legitimately drop
the field, or keep it null for wire compatibility.

---

## B5. Pagination and list envelope — shared by B1 and B3

`AdminList<T>` (`responses.rs:132-141`):
`{ object: "list", data: T[], total?, offset?, limit? }`, with the three
optional members **omitted entirely** when absent (`skip_serializing_if`).

`list_response` (`server/admin_list_query.rs:21-37`) has a shape that is easy to
get wrong:

```
if query is None:   return AdminList::new(data)        # UNPAGED, no total/offset/limit
total := data.len()                                    # BEFORE the page slice
page  := data.skip(offset).take(limit)
return AdminList::paginated(page, total, offset, limit)
```

**The presence of ANY query string switches the response into paginated shape**
— including a query string that contains only `search=`, or an unrelated
parameter. There is no `?page=` opt-in. `total` counts the **post-filter,
pre-slice** population.

`AdminPagination::from_query` (`state.rs:3478-3503`):
* `offset` and `limit` are read by naive `split('&')` / `split_once('=')` —
  **no URL decoding**; contrast `query_value`, which parses properly. A `limit`
  that fails to parse silently keeps the previous value.
* `limit == 0` ⇒ reset to `storage.admin_list_default_limit`.
* `limit` is then clamped: `limit = min(limit, storage.admin_list_max_limit)`.
* `offset` is **not** clamped and is not validated against `total`; an
  out-of-range offset yields an empty `data` with a truthful `total`.

Bound by `state.admin_pagination(query)` (`state.rs:5207-5213`) from
`storage.admin_list_default_limit` / `storage.admin_list_max_limit`.

**`GET /admin/v1/provider-models` and `GET /admin/v1/provider-health` are
UNPAGED regardless of query string** — both call `AdminList::new` directly
(`local.rs:5181`, `local.rs:7455`). Only `providers` and `models` paginate.

---

# PART C — the honest ledger

## C1. Where the Rust is unfinished (do NOT transcribe these as specification)

| # | Location | What is unfinished |
|---|---|---|
| 1 | `validate.rs:2137` | Policy `effect` accepts **only** `deny`; the message literally says *"in the MVP"*. `allow` was never designed. |
| 2 | `extensions.rs:711-713`, `824-826`, `551-563` | The plugin runtime is a skeleton: one `RequestHook` variant (`Noop`), one `EventSink` (`AuditLog`), a closed builtin id list. `admin_plugin`'s **write** path is complete; what it writes into is not. |
| 3 | `validate.rs:3046-3050` | `source` MUST be `"builtin"` — *"only builtin plugins are supported in this phase"*. There is no loader for anything else. |
| 4 | `validate.rs:3892-3894` | `mcp.http` accepts **http only** — *"supports http endpoints only in this phase"*. Do not read this as a security decision about https; it is an unfinished one. |
| 5 | `state_routing.rs:738,765` | `ProviderHealthCheck.cluster_observations` is hard-coded `None`; `routing` and `local_observations` are the same value twice. |
| 6 | providers `types.rs:424-437` | `prepare_model_catalog` / `parse_model_catalog` are unimplemented for every adapter except openai-compatible and openrouter. |
| 7 | `state.rs:1955-1967` | Rollback serialisation drops unserialisable records silently (`filter_map` over `.ok()`). A fail-open in a recovery path. |
| 8 | `state.rs:1350` and siblings | Every rollback result is discarded with `let _ =`. A failed rollback is unobservable. |

## C2. Fail-open / fail-closed, each with the line it was read from

| Behaviour | Posture | Read from |
|---|---|---|
| `config_catalog_scope` storage failure | **CLOSED** — 503, never an unfiltered scope | `rbac.rs:1463-1465`; call sites `local.rs:1727-1739`, `1770-1782`, `8254-8266`, `8895`, `8937` |
| `narrow` on a fully-filtered non-empty selector | **CLOSED** — hide the entry, never emit `[]` | `rbac.rs:1276-1288`, rationale at `1244-1249` |
| An api-key id in neither owned set | **CLOSED** — treated as another tenant's | `rbac.rs:1258-1262` |
| `caller_scope()` on a credential declaring neither tenant nor root | **CLOSED** — `UNSCOPED_TENANT_ID`, denies everything | `auth.rs:241-253` |
| Undecodable control-plane document | **CLOSED** — blocks every mutation of every kind | `state.rs:1969-1980` |
| `validate()` failure anywhere in the candidate | **CLOSED** — 400, running config untouched | `state.rs:1346`, `validate.rs:89` |
| Reload rejection (`committed=false`) | **PARTIAL** — serving config untouched (closed) but the durable row **stays written** (open) | `state.rs:1347` returns `Ok`, so `state.rs:1349` never fires |
| `with_reloaded_config`'s store re-sync | **OPEN** — result discarded, reload succeeds anyway | `state.rs:4936` |
| `signal_binding_change_to_peers` publish failure | **OPEN**, deliberately — logged, never unwinds a committed reload | `state.rs:654-672` |
| Provider catalog fetch failure | **OPEN per row** — 200 with `status:"error"`; other providers unaffected | `local.rs:5170-5178` |
| Provider catalog body cap | **CLOSED, twice** — `Content-Length` check **and** chunk-bounded read | `dispatch.rs:145-154` |
| `provider-health` TCP probe failure | **OPEN** — reported as `unreachable`, never an error status | `state_routing.rs:744-750` |
| Snapshot replay floor: failed **write** | **OPEN** — logged at `error`, does not block activation | `state.rs:1070-1089`, rationale `state.rs:354-360` |
| Snapshot replay floor: failed **read** at boot | **CLOSED** — refuses to start | `state.rs:462-483` |

## C3. Invariants held by control flow rather than by a named check

These are the claims that do not survive a function-by-function reading, and
they are the reason this document exists.

1. **Deleting a skill package withdraws its child resources** — only because
   `materialize_skill_package_resources_with_previous` is passed the
   **pre-reconcile** package list and evicts over the **union** of previous and
   current owners. `validate.rs:43-51`, fed by `state.rs:4961` → `4984`.
   No named check enforces this.
2. **An admin-registered plugin outranks a skill-package-owned plugin of the
   same id** — only because `upsert_or_replace_plugin_registration` is called
   *after* `apply_control_plane_snapshot_to_config` (and therefore after
   materialisation). `state.rs:687-688`. Swap those two statements and the
   precedence silently inverts.
3. **A disabled skill package's resources are withdrawn** — phase 1 evicts
   unconditionally, phase 2 re-adds only `enabled` packages. `validate.rs:53-72`.
   There is no "disable" code path; the effect falls out of the two phases.
4. **`config.extensions` cannot resurrect a deleted plugin** — the reconcile
   clears it (`state.rs:4978`) and the delete path also `retain`s it
   (`state.rs:717`). Either alone would leave a hole, because
   `plugin_registrations()` is `plugins ++ extensions` (`validate.rs:3083-3087`).
5. **The drain flag, the unauthenticated rate limiter and the evidence writer
   survive every config reload** — `with_reloaded_config` clones the `Arc`s
   across (`state.rs:4926-4934`). Nothing names this as a security requirement;
   it is a sequence of eleven assignments. Drop one and an admin write silently
   un-drains a node or resets a rate-limit window.
6. **The admin model read and the request-path model gate agree** — because
   `visible_model`'s two narrowings are the same wildcard/allow-list/AND shape
   as `ModelVisibility::allows`. `rbac.rs:1326-1333` says so in prose;
   nothing enforces it mechanically.
7. **A tenant cannot use by-id reads as an existence oracle** — because
   `!scope.is_full()` converts *both* "absent" and "out of scope" into `403`.
   `local.rs:1794-1797`, `8955-8957`. The `is_full()` term is what preserves the
   operator's genuine `404`, and deleting it looks like a simplification.
8. **The durable write precedes validation, and validation reads the store** —
   so what is validated is what is persisted. `state.rs:1340-1346`. Reordering
   these two "for safety" changes the semantics of every one of the 25
   operations.

## C4. Scope statement

Written in `/home/dev/ferrogate-ts` on `main-ts`. **No `cargo` was run; no Rust
was compiled, imported, linked or executed.** `crates/**` was **read only**, for
transcription. No file under `crates/` or `workers/` was modified or deleted.
No composition root (`apps/*/src/index.ts`, `apps/*/src/worker.ts`,
`apps/*/wrangler.toml`) was touched. No test was written, weakened, skipped or
deleted. No `git` command was run. **The only file this task created is this
one.**

This document makes no claim about the TypeScript's current behaviour and
contains no test evidence, because it asserts nothing about the running tree —
it transcribes a specification out of source that is about to be deleted. The
verifiable claims here are the `crates/…:line` citations, and every one of them
can be checked against the working tree until the moment `crates/**` is removed.

---

# PART D — S1 · the function egress broker (`POST /v1/functions/execute`)

**Wave 25 · 2026-08-02 · appended after the owner dropped S1 and S2.**

**Read this preamble before the specification.**

The owner has **dropped S1**. `POST /v1/functions/execute` answers `501` in
TypeScript and stays that way. That decision was one of the three exits
`CUTOVER-READINESS.md` §3 offered per cluster (build / drop / transcribe) and it
is made. **Nothing below reverses it, re-litigates it, or asks for it to be
built.** No code and no test was written for this part.

What is transcribed here is a **security definition**, and it is transcribed for
one reason: `CUTOVER-READINESS.md:455` records that nothing in `docs/`
reproduces S1's egress-allowlist semantics or its token claim set, and once
`crates/**` is deleted that definition is gone. An egress allowlist and a token
claim set are the specific kind of artefact that looks correct when rebuilt from
memory and is subtly permissive. If FerroGate ever offers gateway-brokered
function execution again — under any name — the implementer should be able to
read what the original actually enforced instead of inventing it fresh.

**Rust that is lost:**
`crates/ferrogate-runtime/src/function_egress.rs` (197 lines),
`crates/ferrogate-runtime/src/function_token.rs` (200),
`crates/ferrogate-runtime/src/supabase_edge_function.rs` (262),
`crates/ferrogate-runtime/src/cloudflare_worker_target.rs` (307),
`crates/ferrogate-gateway/src/function_egress.rs` (363),
`crates/ferrogate-gateway/src/function_egress_cloudflare.rs` (222), and the
`handle_function_execute` / `handle_function_execute_cloudflare` region of
`crates/ferrogate-gateway/src/server/local.rs:3219-3571`. Zero `todo!()` in any
of them — this is finished work, not a stub.

## D0. What already survives the delete, and what it does not say

Two files outside `crates/**` survive and must be read alongside this part:

1. **`docs/design/function-egress-broker.md`** (170 lines) — the design
   rationale, the trust-domain decision (both self-hosted and cloud-managed
   workers are gateway-brokered, no special case, §4), the `FG_FN_*` env table
   (§5a), TOK-6 single-project enforcement, TOK-7 malformed-allowlist handling,
   and the deny/audit status-code summary. It is genuinely good and it stays.
2. **`docs/openapi/runtime-api-contract.json:2173-2182`** — the operation
   record: `path` `/v1/functions/execute`, `method` `post`, `operation_id`
   `executeFunction`, `visibility` `public`, `auth.kind` `bearer`, `auth.scope`
   `functions.execute`, `rbac_action` **`null`**. This file is loaded by
   `include_str!` at `crates/ferrogate-gateway/src/server/api_contract.rs:15-17`,
   i.e. the contract really was the source of truth, not documentation about it.

**What neither file states, and what is therefore lost without this part:**

* the allowlist **matching algorithm** — whether a rule matches by exact host,
  by suffix, by prefix, with or without port and scheme;
* the difference between "this tenant has no rule" and "this tenant has rules
  but not this one", which is observable to the caller;
* the **exact claim set** of the minted JWT: field names, field order, what is
  in `aud`, what is *absent* (there is no `sub`, no `jti`, no `nbf`);
* the TTL ceiling and default, and the clamping rule;
* what `verify()` checks and — more importantly — what it does **not** check;
* redirect policy, DNS policy, private-range policy, response-size policy;
* the fail-open/fail-closed posture of each individual check;
* several invariants the Rust holds through **control flow and type shape only**
  (§D11) — the kind that vanish silently in a reimplementation because there is
  no named check to notice missing.

## D1. Surface

`POST /v1/functions/execute`, resolved to `RouteGroup::Tool` by the contract
router (`docs/openapi/runtime-api-contract.json:82-84`) and dispatched at
`crates/ferrogate-gateway/src/server/route_groups.rs:335-339`.

Gates that run **before** the handler, in order:

| Order | Gate | Where | Effect |
|---|---|---|---|
| 1 | Source-IP allowlist / unauthenticated flood limiter | `crates/ferrogate-gateway/src/server/handlers.rs:68-92` | `403 ip_denied` / `429 unauthenticated_rate_limited` |
| 2 | `/control/v1` → `/admin/v1` alias folding (no effect on this path) | `handlers.rs:59-61` | — |
| 3 | Pre-request hooks | `handlers.rs:125-135` | handler-supplied status |
| 4 | **Documented-method check** | `handlers.rs:139-149` | any method other than `POST` ⇒ `405 method_not_allowed`, message `"{method} is not documented for /v1/functions/execute"` |

Because of gate 4, the handler's own `POST`-only check at
`crates/ferrogate-gateway/src/server/local.rs:3226-3235` (`405
method_not_allowed`, message `"function execute endpoint requires POST"`) is
**unreachable through the server**. It is defense in depth for a caller that
enters the handler directly. An implementer MAY collapse the two, but MUST keep
one of them.

**There is no RBAC check** (`rbac_action: null`) and **no rate limit, no quota
check and no billing/metering call** anywhere in `local.rs:3219-3571`. See §D13.

## D2. Configuration — the enable ladder, and its two mutually exclusive branches

All configuration is **process environment**, read **once** per process through
`OnceLock` (`crates/ferrogate-gateway/src/function_egress.rs:177-182`,
`crates/ferrogate-gateway/src/function_egress_cloudflare.rs:180-186`). There is
no hot reload and no per-tenant database-backed allowlist: **changing the
allowlist requires restarting the gateway.** An implementer who moves this to a
durable store is making a real change, not a translation.

Branch selection happens at `local.rs:3241-3247`: the Cloudflare branch is
tested first, and if it is configured the Supabase branch is never reached.
Symmetrically, `FunctionEgressGatewayConfig::from_env` returns `None` unless the
discriminant resolves to `Supabase`
(`crates/ferrogate-gateway/src/function_egress.rs:88-100`). **Exactly one branch
is live per process.**

`FG_FN_TARGET_KIND` parsing (`function_egress_cloudflare.rs:58-71`):

| Value | Result |
|---|---|
| absent, `""`, or `"supabase"` (after `trim`) | `Some(Supabase)` |
| `"cloudflare_worker"` | `Some(CloudflareWorker)` |
| anything else | `None` + `tracing::warn!` ⇒ **both branches disabled** |

MUST: an unrecognised discriminant disables **both** branches. It MUST NOT fall
back to the default.

**Supabase branch enables only if ALL hold** (`function_egress.rs:102-147`):

1. `FG_FN_TARGET_KIND` resolves to `Supabase` (`:88-94`).
2. `FG_FN_JWT_SECRET` is set and not whitespace-only (`:107`).
3. `FG_FN_APIKEY` is set and not whitespace-only (`:111`). The comment at
   `:108-110` states the reason: enabling without an apikey would surface as a
   misleading per-call denial instead of a clear `503`.
4. `FunctionTokenMinter::new` succeeds (`:112`) — i.e. issuer and secret are
   non-blank.
5. `FG_FN_ALLOWLIST`, if present, parses as a JSON array of rules (`:113-125`).
   **Malformed JSON ⇒ warn and stay disabled** (TOK-7). Absent ⇒ an empty
   ruleset, which is legal and denies everything.
6. The ruleset is **single-project**: all rules' `base_url` normalise to one
   value (`:134-141`, predicate at `:163-174`). An empty ruleset is trivially
   single-project. Two or more distinct normalised base URLs ⇒ warn and stay
   disabled (TOK-6).

**Cloudflare branch enables only if ALL hold**
(`function_egress_cloudflare.rs:105-175`):

1. `FG_FN_TARGET_KIND` == `cloudflare_worker` (`:111-115`).
2. `FG_FN_JWT_SECRET` set and non-blank (`:116`).
3. `FG_FN_CF_WORKER` set, non-blank, and valid JSON for
   `{"base_url","invoke_path","auth_key_ref"}` (`:117-127`).
4. That target passes the same fail-closed `validate()` the runtime applies per
   call (`:131-138`) — https-only, single clean segment, non-empty key ref.
5. Minter constructs (`:139`).
6. `FG_FN_ALLOWLIST`, if present, parses (`:140-153`).
7. **Single-worker rule**: every allowlist rule's normalised `base_url` equals
   the configured Worker's normalised `base_url` (`:158-169`).

`FG_FN_APIKEY` is Supabase-only; the Worker request never emits an `apikey`
header (`cloudflare_worker_target.rs:191-196` builds only `authorization` and
`content-type`).

MUST: every one of these failures is **fail-closed** — the branch stays `None`
and the route answers `503 function_egress_disabled` (`local.rs:3250-3259`). No
partial enablement exists.

## D3. The egress allowlist — how it is expressed and how it matches

### D3.1 Shape

`crates/ferrogate-runtime/src/function_egress.rs:24-38`:

```
FunctionEgressRule { tenant: String, base_url: String, function_slugs: Vec<String> }
FunctionEgressAllowlist { rules: Vec<FunctionEgressRule> }
```

`ANY_FUNCTION_SLUG = "*"` (`:21`). Serialised as a JSON array in
`FG_FN_ALLOWLIST`; field names on the wire are exactly `tenant`, `base_url`,
`function_slugs`.

### D3.2 Normalisation

`normalize_base_url` (`function_egress.rs:80-82`): `trim()` surrounding
whitespace, then strip **all** trailing `/` characters
(`trim_end_matches('/')` — `https://h///` and `https://h` normalise equal).
That is the **only** normalisation. There is:

* **no** lowercasing — `https://Example.com` and `https://example.com` are
  DIFFERENT allowlist entries;
* **no** URL parsing, punycode/IDNA folding, percent-decoding, default-port
  elision (`https://h:443` ≠ `https://h`), or userinfo stripping;
* **no** normalisation of the scheme beyond the `https://` prefix test in §D4.

The gateway re-exports the same function for the Cloudflare branch
(`crates/ferrogate-gateway/src/function_egress.rs:153-155`) so config-time and
request-time comparison cannot drift apart.

Slug/path comparison uses `trim()` on both sides and nothing else
(`function_egress.rs:132`, `:146`).

### D3.3 The matching algorithm (the part that must not be re-invented)

`FunctionEgressAllowlist::authorize_validated`,
`crates/ferrogate-runtime/src/function_egress.rs:125-160`. Stated exactly:

```
requested_base = normalize_base_url(target.base_url)
requested_slug = target.function_slug.trim()
tenant_has_rule = false
for rule in rules (in declaration order):
    if rule.tenant != tenant                      -> continue      # EXACT, case-sensitive, untrimmed
    tenant_has_rule = true
    if normalize_base_url(rule.base_url) != requested_base -> continue   # EXACT string equality
    if any slug in rule.function_slugs where slug == "*" OR slug.trim() == requested_slug:
        return ALLOW
if !tenant_has_rule: return DENY NoRuleForTenant(tenant)
return DENY TargetNotAllowed { tenant, base_url: requested_base, function_slug: requested_slug }
```

MUST, and each of these is a place a fresh design goes wrong:

* **Base-URL match is EXACT string equality after normalisation. It is NOT a
  suffix, prefix, domain, or wildcard match.** `https://a.example.com` does not
  match a rule for `https://example.com`. There is no `*.example.com` syntax —
  the only wildcard anywhere in this system is the slug `"*"`, and it never
  applies to the base URL.
* **Scheme and port are matched implicitly, by being part of the compared
  string.** There is no separate scheme or port check in the allowlist. A rule
  for `https://h` therefore does not authorise `https://h:8443`, and vice versa.
* **Tenant match is exact and case-sensitive**, with no trimming of either side
  (`:136`). A rule whose `tenant` has a stray space never matches anything.
* **The slug wildcard `"*"` is compared UNTRIMMED, while the literal comparison
  is trimmed** (`:143-146`: `slug == ANY_FUNCTION_SLUG || slug.trim() ==
  requested_slug`). A rule entry written as `" * "` therefore does **not** take
  the wildcard branch; it falls through to the literal branch and matches only a
  request whose slug is exactly `*`. That is a silent, total narrowing of an
  entry the operator meant as "any function here" — from every slug to one.
  Reproduce the asymmetry, or normalise both sides deliberately; do not
  accidentally trim only one.
* Relatedly, **`*` is a legal requested slug.** `validate()` (§D4) rejects
  whitespace, `/`, `?`, `#` and `..` but not `*`, so a caller may request the
  literal slug `*` and the composed URL becomes `{base}/functions/v1/*`. Against
  a genuine `"*"` wildcard rule that request is allowed.
* **A `"*"` entry authorises any slug at that ONE base URL only.** It is not a
  global wildcard.
* An **empty allowlist denies everything**, and `is_empty()` is exposed
  (`:89-91`) purely so callers can assert that.
* Rules are additive: the first rule that matches allows. There is **no deny
  rule and no precedence order** — an implementer adding "deny" entries is
  extending the model, not reproducing it.

### D3.4 The two denial reasons are observable, and that is an oracle

`FunctionEgressDenied` (`function_egress.rs:42-55`) distinguishes
`NoRuleForTenant(tenant)` from `TargetNotAllowed { tenant, base_url,
function_slug }`, and their `Display` strings are
`"no function egress rule for tenant {tenant}"` and `"tenant {tenant} may not
invoke {function_slug} at {base_url}"` (`:62-72`). The handler puts
`error.to_string()` straight into the client-visible `403` body
(`local.rs:3358-3365`, `:3519-3526`).

**Consequence an implementer should decide about deliberately:** an
authenticated caller can distinguish "my tenant is not configured for function
egress at all" from "my tenant is configured but not for this target", and the
second message **echoes back the resolved tenant id and the requested base
URL**. That is a deliberate operator-debuggability trade in the Rust, not an
oversight — but it is a trade, and the Rust never wrote it down.

### D3.5 Target validation runs BEFORE allowlist matching

`authorize` (`:96-105`) calls `target.validate()` first and returns
`InvalidTarget(_)` before any rule is consulted; `authorize_cloudflare_worker`
(`:111-120`) does the same with `InvalidWorkerTarget(_)`. So a malformed target
is rejected identically whether or not the tenant has rules. The runtime test
`invalid_target_is_rejected_before_allowlist_match`
(`crates/ferrogate-runtime/src/function_egress_test.rs:119`) pins this ordering.

### D3.6 One allowlist, two target types

`authorize_cloudflare_worker` matches the Worker's **`invoke_path` in the slot a
Supabase `function_slug` would occupy** (`:119`). One allowlist governs both
platforms. An implementer supporting a second target platform MUST reuse the
same rule table rather than introduce a parallel one — that was the #416 design
decision.

## D4. Target validation — scheme, host, path, and what happens to the awkward cases

Supabase: `SupabaseEdgeFunctionTarget::validate`,
`crates/ferrogate-runtime/src/supabase_edge_function.rs:171-195`.
Cloudflare: `CloudflareWorkerTarget::validate`,
`crates/ferrogate-runtime/src/cloudflare_worker_target.rs:114-140`. The two are
character-for-character the same ladder with different error names.

```
base = base_url.trim()
if base.is_empty()                 -> EmptyBaseUrl
if !base.starts_with("https://")   -> InsecureBaseUrl(base)
seg = function_slug.trim()   (Supabase)  /  invoke_path.trim()  (Cloudflare)
if seg.is_empty() || seg.contains('/') || seg.contains('?') || seg.contains('#')
   || seg.contains("..") || seg.contains(char::is_whitespace)
                                   -> InvalidSlug(seg) / InvalidInvokePath(seg)
if auth_key_ref.trim().is_empty()  -> EmptyAuthKeyRef
ok
```

Answering the questions directly:

* **Scheme.** Enforced **twice**, both fail-closed. Once here as a literal
  `starts_with("https://")` prefix test on the trimmed string — note this is a
  *string* test, not a parsed-URL test, and it is **case-sensitive**, so
  `HTTPS://h` is rejected. Once again at execution time after real URL parsing:
  `crates/ferrogate-gateway/src/function_egress.rs:233-237` parses the URL and
  `bail!`s unless `url.scheme() == "https"`. Tests
  `rejects_unsupported_scheme` and `rejects_plaintext_http_scheme`
  (`crates/ferrogate-gateway/src/function_egress_test.rs:218`, `:230`) pin the
  second one.
* **Port.** Never inspected. It is simply part of the base-URL string and is
  therefore pinned by the exact allowlist match (§D3.3). There is no port
  allowlist and no "443 only" rule.
* **Path.** The caller supplies exactly **one path segment** and cannot supply
  more. `/`, `?`, `#`, `..` and any whitespace are all rejected, so there is no
  traversal, no nesting, and **no way to attach a query string**. The final URL
  is composed, not passed through: `{base}/functions/v1/{slug}`
  (`supabase_edge_function.rs:198-204`) or `{base}/{invoke_path}`
  (`cloudflare_worker_target.rs:143-149`), each with the base's trailing slashes
  stripped and the segment trimmed.
* **Redirects.** **Never followed.** `Policy::none()` on the shared client
  (`crates/ferrogate-gateway/src/function_egress.rs:341-346`) with a nine-line
  comment at `:335-340` giving the reason: the https + allowlist check runs once
  on the initial URL, so following a `3xx` to an attacker-chosen `Location` —
  their example is a tenant-authored edge function returning
  `302 http://169.254.169.254/…` — would bypass the allowlist, exfiltrate the
  internal response, and forward the `apikey` header. **The upstream must reach
  its result in one hop.** A `3xx` is returned to the caller as-is: `status_code`
  = 302 with whatever body the upstream sent. Pinned by
  `does_not_follow_redirect_to_internal_metadata_endpoint`
  (`function_egress_test.rs:103`).
* **Private ranges — hostnames.** A custom `reqwest` DNS resolver,
  `FunctionEgressDnsResolver`
  (`crates/ferrogate-gateway/src/function_egress.rs:300-329`), resolves the host
  and then **drops every address** for which
  `ferrogate_guardrails::is_disallowed_detector_ip` is true. If the filtered set
  is empty it returns `PermissionDenied` ("function egress DNS resolved only
  disallowed (internal) addresses"). The comment at `:295-299` states the threat
  it closes: the allowlist constrains only the *hostname*, so without this a
  DNS-rebound allowlisted host still reaches an internal service. The
  classification, `crates/ferrogate-guardrails/src/net.rs:53-87`, rejects:
  IPv4 private, loopback, link-local (**including `169.254.169.254`**),
  unspecified, multicast, broadcast, documentation, CGNAT `100.64.0.0/10`,
  `192.0.0.0/16`, benchmarking `198.18.0.0/15`, and everything `>= 240.0.0.0`;
  IPv6 loopback, unspecified, multicast, ULA `fc00::/7`, link-local `fe80::/10`,
  site-local `fec0::/10`, documentation `2001:db8::/32`, and **any IPv4-mapped
  address recursively re-checked as IPv4** (`net.rs:77-79`).
* **IP literals — `OPEN`, and the sharpest thing in this part.** The DNS guard
  is a *resolver*; a base URL whose host is already an IP literal
  (`https://169.254.169.254`, `https://10.0.0.5`) does not go through name
  resolution and is therefore **not** filtered by it. Nothing in
  `validate()` (`supabase_edge_function.rs:171-195`) or in the allowlist
  (`function_egress.rs:125-160`) rejects an IP-literal host either. The only
  thing standing between that and an internal call is that an **operator** must
  have put the literal in `FG_FN_ALLOWLIST` — the caller cannot introduce it,
  because the wire target must match an allowlist entry exactly. So this is not
  a caller-reachable hole in the Rust; it is a **missing config-time check**. A
  reimplementation SHOULD reject IP-literal hosts at config-parse time, and MUST
  NOT assume the DNS guard covers them. Flagged as `OPEN` because the Rust never
  decided it either way.
* **Compression.** Disabled on the client — `.no_gzip().no_brotli().no_zstd()
  .no_deflate()` (`function_egress.rs:341-346`) — so the response-size cap in
  §D7 cannot be defeated by a decompression bomb.
* **TLS.** `rustls` with the `ring` provider installed on first use
  (`function_egress.rs:334`), default (i.e. verifying) certificate policy.
  **`#[cfg(test)]` swaps in `danger_accept_invalid_certs(true)` and drops the DNS
  guard** (`:347-352`, and the module comment at `:34-40`) because the test
  upstream is loopback with a self-signed cert. That is a **test-build-only**
  divergence. Do not port it, and do not read the tests as evidence that the
  production client accepts invalid certificates.

## D5. The token claim set

`crates/ferrogate-runtime/src/function_token.rs`. This is the artefact
`CUTOVER-READINESS.md:455` specifically named as unrecoverable.

### D5.1 Algorithm and encoding

* **HS256 only.** The header is the fixed byte string
  `{"alg":"HS256","typ":"JWT"}` (`:75`) — serialised as a constant, never
  re-derived, so there is no `alg` negotiation and no `none` acceptance path.
* Encoding is **base64url without padding** throughout (`URL_SAFE_NO_PAD`,
  `:15`).
* Signing input is `b64url(header_json) + "." + b64url(claims_json)` (`:146-150`);
  the token is `signing_input + "." + b64url(hmac_sha256(secret, signing_input))`
  (`:152`).
* The MAC key is the raw UTF-8 bytes of the secret string (`:109`), fed to
  `Hmac<Sha256>` with no derivation, stretching or length requirement
  (`:156-157`).

### D5.2 The claims — exactly six, in this order

`FunctionTokenClaims`, `crates/ferrogate-runtime/src/function_token.rs:29-43`.
Because `serde_json` emits struct fields in declaration order, the claims JSON
is byte-for-byte:

```
{"iss":…,"aud":…,"tenant":…,"capability":…,"iat":…,"exp":…}
```

| Claim | Type | Value the broker sets | Citation |
|---|---|---|---|
| `iss` | string | `"ferrogate"` — the constant `FUNCTION_TOKEN_ISSUER`, shared by both branches | `crates/ferrogate-gateway/src/function_egress.rs:47`, `:112`; `function_egress_cloudflare.rs:42`, `:139` |
| `aud` | string | the **trimmed function slug** (Supabase) or the **trimmed invoke path** (Cloudflare) — NOT a URL, NOT the base URL, NOT an origin | `function_egress.rs:198-208`; `cloudflare_worker_target.rs:274-283` |
| `tenant` | string | the tenant key derived from the **authenticated identity** (§D11 item 1), never the wire `tenant` field | `local.rs:3312-3319` → `function_egress.rs:193-208` |
| `capability` | string | the constant `"function"` for **both** branches | `crates/ferrogate-gateway/src/function_egress.rs:44`; `crates/ferrogate-runtime/src/cloudflare_worker_target.rs:39` |
| `iat` | u64 unix seconds | wall clock at request time | `local.rs:3331-3334` |
| `exp` | u64 unix seconds | `iat.saturating_add(ttl)` | `function_token.rs:142` |

**There is no `sub`, no `jti`, no `nbf`, no `scope`, no key id, and no `kid` in
the header.** That is not an omission in this transcript — those claims do not
exist. The consequences (no replay defense, no per-token revocation, no key
rotation identifier) are recorded in §D13.

### D5.3 Lifetime

* `MAX_FUNCTION_TOKEN_TTL_SECS = 300` (`function_token.rs:24`).
* `DEFAULT_FUNCTION_TOKEN_TTL_SECS = 60` (`:26`).
* `mint` rejects `ttl_secs == 0` with `ZeroTtl` (`:132-134`) and otherwise
  **silently clamps**: `ttl = ttl_secs.min(300)` (`:135`). A caller asking for an
  hour gets five minutes and no error. Pinned by `ttl_is_clamped_to_max`
  (`crates/ferrogate-runtime/src/function_token_test.rs:33`).
* **Both broker branches always pass the 60 s default** and expose no way to
  change it: `function_egress.rs:206`, `function_egress_cloudflare.rs:211`. The
  300 s ceiling is therefore currently unreachable through the route.

### D5.4 Who can mint

Only the gateway process, and only through a `FunctionTokenMinter` constructed
at config load from `FG_FN_JWT_SECRET`
(`crates/ferrogate-gateway/src/function_egress.rs:112`,
`function_egress_cloudflare.rs:139`). `FunctionTokenMinter::new` rejects a blank
issuer (`EmptyField("iss")`) and a blank secret (`EmptySigningSecret`)
(`function_token.rs:101-106`). `mint` rejects blank `tenant`, blank slug
(reported as `EmptyField("aud")`), and blank `capability` (`:123-131`).

The secret **never leaves the gateway**: it is stored as `Vec<u8>` in a struct
whose hand-written `Debug` prints `signing_secret: "<redacted>"`
(`function_token.rs:84-92`, pinned by `minter_debug_redacts_secret`,
`function_token_test.rs:127`). It is never persisted to the control-plane
database — the module doc at
`crates/ferrogate-gateway/src/function_egress.rs:50-54` states this as a
deliberate property of sourcing it from the environment.

**One secret per process.** That is the whole reason for the TOK-6
single-project and single-worker rules in §D2: with one shared signing secret
and one shared apikey, an allowlist spanning two projects would hand every
project a token at most one of them can verify.

### D5.5 What `verify()` checks — and what it does NOT

`FunctionTokenMinter::verify`, `function_token.rs:164-195`:

1. Split on `.`; require **exactly** three parts — a fourth part is
   `MalformedToken` (`:169-175`).
2. Recompute the MAC over `header.claims` and compare against the decoded
   signature **in constant time**, after a length check
   (`subtle::ConstantTimeEq`, `:182`) ⇒ `BadSignature`.
3. **Only then** decode and deserialise the claims (`:186-190`) ⇒
   `MalformedToken` on failure. Signature-before-parse is the correct ordering
   and MUST be preserved.
4. Reject if `now_unix >= claims.exp` ⇒ `Expired` (`:191-193`). Note `>=`, not
   `>`: a token expiring exactly now is invalid. **There is no clock-skew
   leeway** — zero seconds.

**`verify()` does NOT check `iss`, `aud`, `tenant`, `capability`, or `iat`.** It
returns the claims and leaves every semantic check to the caller. An implementer
who ports `verify` as a complete validator will have built a token that
authorises **any** function for **any** tenant as long as the signature and
expiry hold. The header is not re-parsed or checked either, so `alg` confusion is
prevented only by the fact that verification recomputes HS256 unconditionally —
which is the right construction, but is a property of *not* reading the header,
not of validating it.

Note also that the JWT header is **not** covered by any check beyond being part
of the signed input, and that no `alg` value is ever read from a presented
token.

### D5.6 Trust boundary implied by the claim set

Because `aud` is a bare slug and the signing secret is shared across every
allowlisted target of one project/worker, a token minted for slug `X` is
cryptographically valid at **any** endpoint that knows the same secret and
verifies the same way. The isolation between functions therefore rests on the
**receiving function** re-checking `aud`, `iss` and `tenant` — which
`docs/design/function-egress-broker.md:148-149` states as an expectation of the
edge function, and which the gateway cannot enforce. An implementer choosing a
different claim shape (e.g. `aud` = full invocation URL) is *strengthening* this,
and should know that is what they are doing.

## D6. The governed HTTP request that is built

No caller-supplied header ever reaches the upstream (§D11 item 3). The header
set is constructed from nothing but the credential and a constant:

**Supabase** (`crates/ferrogate-runtime/src/supabase_edge_function.rs:235-257`),
keys lower-cased in a `BTreeMap` so ordering is deterministic:

| Header | Value |
|---|---|
| `authorization` | `Bearer {minted JWT}` |
| `apikey` | `FG_FN_APIKEY` verbatim |
| `content-type` | `application/json` |

**Cloudflare Worker**
(`crates/ferrogate-runtime/src/cloudflare_worker_target.rs:182-203`): the same
minus `apikey` — Workers have no such concept and the header is deliberately
never emitted (`:285-287`).

Build-time ladder, both branches:

1. `target.validate()` again (`supabase_edge_function.rs:239`,
   `cloudflare_worker_target.rs:186`) — the third fail-closed application of §D4.
2. Method normalisation: `trim().to_ascii_uppercase()`, then membership in
   `ALLOWED_METHODS = ["POST", "GET"]`
   (`supabase_edge_function.rs:166`, `:218-227`;
   `cloudflare_worker_target.rs:108`, `:163-172`). Anything else ⇒
   `UnsupportedMethod`. **`POST` and `GET` only** — no `PUT`, `DELETE`, `PATCH`,
   `HEAD`, `OPTIONS`.
3. Credential usability: Supabase requires **both** bearer and apikey non-blank
   (`FunctionCredential::is_usable`, `supabase_edge_function.rs:124-126`, checked
   at `:241-243` ⇒ `EmptyResolvedKey`); Cloudflare requires only the bearer
   (`cloudflare_worker_target.rs:188-190` ⇒ `EmptyResolvedBearer`).
4. URL composed as in §D4.
5. `body` = `body_json` verbatim.

Two properties worth stating because they are easy to lose:

* **`body_json` is an opaque string and is never validated as JSON**, despite
  `content-type: application/json` being sent unconditionally
  (`supabase_edge_function.rs:250`). The field is `String`, not a parsed value
  (`:55`, `crates/ferrogate-runtime/src/function_egress.rs:175`).
* **The body is sent even for `GET`**, and `content-type` is set even when the
  body is empty. There is no branch on method after normalisation.

Both credential-carrying structs have hand-written `Debug` impls that never
print secrets: `EdgeFunctionHttpRequest` prints header **names** only plus
`body_len` (`supabase_edge_function.rs:69-79`), and `FunctionCredential` prints
`"<redacted>"` plus lengths (`:94-103`). MUST reproduce, or the credential leaks
into any structured log that formats the value.

## D7. Execution

`execute_edge_function_request`,
`crates/ferrogate-gateway/src/function_egress.rs:225-282`.

1. Parse method and URL; `bail!` on either being invalid (`:231-234`).
2. **Re-assert https** on the parsed URL (`:235-237`).
3. Build the `HeaderMap`, rejecting invalid names or values (`:284-293`).
4. Send on the shared singleton client (§D4) with a per-call `timeout`.
5. **Response size cap, two layers:** if `Content-Length` is present and exceeds
   the cap, fail immediately (`:250-255`); then read the body chunk by chunk and
   fail the moment the accumulated length **would** exceed the cap (`:256-270`),
   so a chunked or `Content-Length`-lying upstream can never force unbounded
   buffering. The error text is
   `edge_function_response_body_too_large: exceeds {n} bytes`. Both layers are
   pinned — `rejects_oversized_response_body` (`function_egress_test.rs:145`)
   and `rejects_oversized_chunked_response_without_content_length` (`:170`).
6. Excerpt the body: `String::from_utf8_lossy` then `.chars().take(2048)`
   (`:272-275`). **`BODY_EXCERPT_MAX_BYTES = 2048` is applied as a CHARACTER
   count, not a byte count** (`:42`) — the name is wrong and the excerpt can
   reach ~8 KiB of UTF-8. Reproduce the behaviour or fix it deliberately;
   do not assume the constant name.

Numbers:

| Quantity | Value | Citation |
|---|---|---|
| Request-body cap (inbound, from the caller) | `limits.tool_body_max_bytes`, default **64 KiB** | `local.rs:3262`, `:3425`; `crates/ferrogate-config/src/config/types.rs:2532`, `:2559-2562` |
| Response-body cap (from the upstream) | **256 KiB** | `local.rs:83`, used at `:3373`, `:3534` |
| Body excerpt returned to the caller | **2048 chars** | `crates/ferrogate-gateway/src/function_egress.rs:42`, `:272-275` |
| Per-call upstream timeout | **30 000 ms** | `supabase_edge_function.rs:25`; `cloudflare_worker_target.rs:34` |

The timeout is a constant on both paths — `SupabaseEdgeFunctionInvocation` is
built with `DEFAULT_EDGE_FUNCTION_TIMEOUT_MILLIS`
(`crates/ferrogate-gateway/src/function_egress.rs:215`) and the Worker path with
`DEFAULT_WORKER_INVOCATION_TIMEOUT_MILLIS`
(`cloudflare_worker_target.rs:292`). Neither is caller-settable, although the
`timeout_millis` field exists on both invocation structs.

**Response shape on success** — `FunctionInvocationOutcome`,
`crates/ferrogate-runtime/src/function_egress.rs:183-189`, serialised at
`local.rs:3409` / `:3570` with HTTP **200 regardless of the upstream status**:

```
{ "function_slug": "<slug or invoke_path>", "status_code": <u16 upstream status>, "body_excerpt": "<≤2048 chars>" }
```

Note the field is named `function_slug` on **both** branches; the Cloudflare
branch puts the invoke path in it (`local.rs:3530-3532`). And note that a
`4xx`/`5xx` from the upstream is a **200 from the gateway** with the status in
the body — only a transport/policy failure produces `502`.

## D8. HTTP contract

| Status | `code` | Trigger | Citation |
|---|---|---|---|
| `405` | `method_not_allowed` | any method but POST (contract layer, message `"{m} is not documented for …"`) | `handlers.rs:139-149` |
| `405` | `method_not_allowed` | any method but POST (handler layer, unreachable via the server) | `local.rs:3226-3235` |
| `503` | `function_egress_disabled` | neither branch configured | `local.rs:3250-3259` |
| `413` | `payload_too_large` | request body over `tool_body_max_bytes`; **connection is closed** (`write_json_error_and_close`) | `local.rs:3266-3278`, `:3429-3441` |
| `400` | `invalid_json` | body does not deserialise; message embeds the serde error | `local.rs:3283-3292`, `:3446-3455` |
| `401` | `missing_api_key` | no `Authorization: Bearer` / `x-api-key` | `crates/ferrogate-gateway/src/auth.rs:1223-1229` |
| `403` | `scope_denied` | key lacks `functions.execute` | `auth.rs:1243-1249` |
| `403` | `no_tenant` | authenticated identity resolves to an empty tenant key | `local.rs:3320-3329`, `:3483-3492` |
| `403` | `function_denied` | allowlist denial, target validation failure, token-mint failure, or request-build failure — **all four collapse to one code**, message = the underlying `Display` | `local.rs:3358-3365`, `:3519-3526` |
| `502` | `function_upstream_error` | transport failure, non-https URL at execute time, timeout, or oversized response | `local.rs:3387-3394`, `:3548-3555` |
| `200` | — | outcome envelope, **whatever the upstream status was** | `local.rs:3409`, `:3570` |

The collapse of four distinct broker failures into `function_denied` is
deliberate — `FunctionBrokerError` (`crates/ferrogate-gateway/src/function_egress.rs:63-77`)
and `WorkerBrokerError` (`cloudflare_worker_target.rs:228-244`) both `Display`
to their inner error and the handler does not discriminate. The *message* still
distinguishes them (§D3.4).

**Authorisation.** Scope `functions.execute`, checked by
`scope_set_allows` (`crates/ferrogate-gateway/src/auth.rs:304-312`):

```
scopes.contains("functions.execute") -> allow
scopes.contains(WILDCARD_SCOPE)      -> allow
scopes.is_empty() && !scope.starts_with("admin.")  -> allow
otherwise -> deny
```

MUST be stated explicitly because it is the single most permissive line in this
whole part: **a key with an EMPTY scope set is granted function egress**, since
`is_privileged_scope` is `scope.starts_with("admin.")`
(`auth.rs:132-134`) and `functions.execute` does not start with `admin.`. Only
`admin.*` scopes are protected from the empty-set default. An implementer who
treats an empty scope set as "no permissions" is *tightening* the model — which
is probably right, and is a change.

## D9. Audit

Every post-authentication broker decision is written to the control-plane audit
store via `state.record_admin_audit_event(admin_audit_event_draft_for_target(…))`
with action `"function.execute"`:

| Outcome | Result string | Detail | Citation |
|---|---|---|---|
| broker refused | `denied` | the `Display` of the broker error | `local.rs:3350-3357`, `:3511-3518` |
| transport failed | `upstream_error` | the anyhow error text | `local.rs:3379-3386`, `:3540-3547` |
| executed | `executed` | `"edge function {slug} returned status {n}"` / `"cloudflare worker {path} returned status {n}"` | `local.rs:3398-3408`, `:3559-3569` |

Audit target string: `supabase_edge_function:{slug}` (`local.rs:3337-3340`) or
`cloudflare_worker:{invoke_path}` (`local.rs:3501`).

Two properties:

* The target is computed from the **caller-supplied, not-yet-authorised** slug —
  deliberately, so a denial records what was attempted. It is attacker-influenced
  text bounded only by the 64 KiB request-body cap, so the audit sink MUST treat
  it as untrusted.
* **Nothing before authentication is audited here**: `405`, `503`, `413`,
  `400 invalid_json`, `401`, `403 scope_denied` and `403 no_tenant` produce **no
  audit event**. An authenticated caller probing the allowlist leaves a trail; an
  unauthenticated one does not (beyond generic request logging).

## D10. Fail-open / fail-closed posture, each with the line it was read from

Every decision in S1 is **fail-closed**. Stated individually so a
reimplementation can be checked line by line:

| # | Check | Posture | Citation |
|---|---|---|---|
| 1 | Broker unconfigured | **CLOSED** — `503`, no call | `crates/ferrogate-gateway/src/function_egress.rs:107-111`; `local.rs:3250-3259` |
| 2 | `FG_FN_TARGET_KIND` unrecognised | **CLOSED** — both branches disabled | `function_egress_cloudflare.rs:62-69` |
| 3 | `FG_FN_ALLOWLIST` malformed JSON | **CLOSED** — disabled, not "deny everything, stay up" | `crates/ferrogate-gateway/src/function_egress.rs:113-125`; `function_egress_cloudflare.rs:140-153` |
| 4 | `FG_FN_ALLOWLIST` absent | **CLOSED** — empty ruleset, every call denied | `crates/ferrogate-gateway/src/function_egress.rs:124`; `crates/ferrogate-runtime/src/function_egress.rs:152-159` |
| 5 | Allowlist spans >1 project / ≠ declared worker | **CLOSED** — disabled | `crates/ferrogate-gateway/src/function_egress.rs:134-141`; `function_egress_cloudflare.rs:158-169` |
| 6 | `FG_FN_CF_WORKER` invalid target | **CLOSED** — disabled at startup | `function_egress_cloudflare.rs:131-138` |
| 7 | Tenant absent from allowlist | **CLOSED** — `NoRuleForTenant` | `crates/ferrogate-runtime/src/function_egress.rs:152-154` |
| 8 | Tenant present, target not listed | **CLOSED** — `TargetNotAllowed` | `crates/ferrogate-runtime/src/function_egress.rs:155-159` |
| 9 | Target invalid (scheme/slug/key-ref) | **CLOSED**, and checked *before* rule matching | `crates/ferrogate-runtime/src/function_egress.rs:101-104`, `:116-119` |
| 10 | Method not POST/GET | **CLOSED** | `supabase_edge_function.rs:218-227`; `cloudflare_worker_target.rs:163-172` |
| 11 | Credential blank | **CLOSED** | `supabase_edge_function.rs:241-243`; `cloudflare_worker_target.rs:188-190` |
| 12 | Token mint failure | **CLOSED** — `403`, no call | `crates/ferrogate-gateway/src/function_egress.rs:199-208` |
| 13 | Non-https at execute time | **CLOSED** — `bail!` before any socket | `crates/ferrogate-gateway/src/function_egress.rs:235-237` |
| 14 | Redirect | **CLOSED** — never followed; the `3xx` is surfaced | `crates/ferrogate-gateway/src/function_egress.rs:335-346` |
| 15 | DNS resolves only to internal addresses | **CLOSED** — `PermissionDenied`, no connection | `crates/ferrogate-gateway/src/function_egress.rs:316-325` |
| 16 | DNS resolution itself fails | **CLOSED** — error, no connection | `crates/ferrogate-gateway/src/function_egress.rs:309-315` |
| 17 | Response exceeds 256 KiB | **CLOSED** — `502`, body discarded | `crates/ferrogate-gateway/src/function_egress.rs:250-270` |
| 18 | Identity has no tenant scope | **CLOSED** — `403 no_tenant` | `local.rs:3320-3329` |
| 19 | Token expiry | **CLOSED** — `>=`, zero skew | `function_token.rs:191-193` |
| 20 | Signature comparison | **CLOSED**, constant-time | `function_token.rs:182` |

The two places posture is **not** determined by a check, and an implementer
should decide them explicitly:

* **IP-literal hosts** — §D4. Not open to the caller, but not closed at config
  time either. `OPEN`.
* **Empty scope set** — `auth.rs:311`. This is the one genuinely **permissive**
  default in the path: absence of declared scopes is read as "unrestricted for
  everything non-admin", including function egress.

## D11. Invariants the Rust enforces through control flow or type shape, not a named check

These survive only if someone writes them down, because there is no function to
grep for.

1. **The wire `tenant` field is never trusted.** `FunctionInvocationRequest`
   *has* a `tenant` field (`crates/ferrogate-runtime/src/function_egress.rs:170`,
   documented at `:163-166` as "advisory only"), and the handler simply never
   reads it: it computes `tenant_key` from `auth.tenant_context()` and passes
   *that* to `prepare_brokered_invocation` (`local.rs:3312-3319` → `:3341-3347`).
   The protection is that the wire field is dead code. Delete the derivation and
   pass `request.tenant` and every test still describes the same shapes — while
   any caller can now assume any tenant's allowlist.
2. **Tenant identity is a fixed precedence chain, and mismatching it silently
   denies everything.** `organization_id` → `project_id` → `team_id` →
   `user_id` → `api_key_id`, first non-`None` wins, empty ⇒ `403 no_tenant`
   (`local.rs:3312-3319`, `:3476-3482`; `TenantContext` built at
   `auth.rs:151-160`). The allowlist's `tenant` field must contain **whatever
   this chain selects**. An operator who writes a project id in a rule for a key
   that also carries an organization id gets `NoRuleForTenant` forever, with no
   diagnostic pointing at the precedence. This is the most likely
   misconfiguration in the whole feature and nothing in the Rust warns about it.
3. **No caller-supplied header can reach the upstream — because there is nowhere
   to put one.** Neither `FunctionInvocationRequest`
   (`crates/ferrogate-runtime/src/function_egress.rs:167-176`) nor
   `WorkerInvocationRequest` (`cloudflare_worker_target.rs:211-220`) has a
   headers field, and the built header map is constructed fresh from three
   constants plus the credential (`supabase_edge_function.rs:244-250`). Adding a
   pass-through `headers` map — an obvious convenience — would let a caller
   override `authorization`, or set `x-forwarded-for`, or inject a second
   `apikey`.
4. **The caller cannot influence the URL beyond one path segment.** The URL is
   *composed* (`{base}/functions/v1/{slug}`), never taken from the request, and
   the segment cannot contain `/ ? # ..` or whitespace (§D4). There is therefore
   no query-string channel and no path-traversal channel — enforced by string
   composition plus a character blacklist, not by a URL builder.
5. **The Cloudflare branch's request URL still comes from the WIRE target, not
   from `FG_FN_CF_WORKER`.** `prepare_cloudflare_invocation`
   (`function_egress_cloudflare.rs:193-218`) overwrites **only**
   `governed.target.auth_key_ref` from the config (`:203-204`) and then passes
   the caller's `base_url` and `invoke_path` into the governed pipeline. What
   confines the call to the declared Worker is the *combination* of the
   config-time single-worker rule (`:158-169`) and the per-call allowlist match.
   An implementer who drops the config-time rule, believing the config target
   pins the URL, opens the caller's `base_url` to anything the allowlist happens
   to contain.
6. **The wire `auth_key_ref` is never authoritative** — it is replaced with the
   operator-declared one before the pipeline runs
   (`function_egress_cloudflare.rs:199-204`), so a future credential
   dereference can never be steered by the caller. Today the field is validated
   non-empty and otherwise unused (§D12), which means this substitution is
   currently *inert* and is very easy to "simplify" away — precisely when
   `auth_key_ref` becomes live is when it starts mattering.
7. **Function egress is unreachable when authentication is switched off.** Under
   `[auth] disabled = true` the synthesised `AuthContext` sets every tenant
   field to `None` (`auth.rs:1194-1220`), so the precedence chain yields the
   empty string and the handler answers `403 no_tenant`. An open gateway
   therefore cannot broker functions at all. That is a genuinely good property
   and it is an accident of two unrelated pieces of code agreeing — the tenancy
   fields being `None` and the emptiness check at `local.rs:3320`.
8. **Exactly one broker branch can ever be live**, enforced from both ends: the
   Cloudflare config is consulted first and returns early (`local.rs:3241-3247`),
   *and* the Supabase config refuses to load unless the discriminant says
   Supabase (`crates/ferrogate-gateway/src/function_egress.rs:88-94`). Either
   guard alone would leave a window where both are configured.
9. **The body is read and parsed BEFORE authentication.** `local.rs:3261-3293`
   (read + deserialise) runs ahead of `:3296` (`authenticate`); same ordering in
   the Cloudflare branch (`:3424-3456` before `:3459`). An unauthenticated caller
   can therefore get a `400 invalid_json` — a parser-shaped response — without
   presenting a credential, and can make the gateway buffer up to
   `tool_body_max_bytes`. The pre-auth flood limiter (§D1 gate 1) is the only
   thing bounding it. A reimplementation SHOULD authenticate first; this is
   recorded as observed behaviour, not as a requirement to reproduce.
10. **The `OnceLock` config makes the allowlist immutable for the process
    lifetime** (`crates/ferrogate-gateway/src/function_egress.rs:177-182`). No
    admin route, no config reload, and no database write can change it. Any
    reimplementation that makes the allowlist dynamic acquires a whole class of
    concerns — cache invalidation, read-your-writes on revocation — that the Rust
    simply does not have.

## D12. `OPEN` — where the Rust is unfinished

Do **not** transcribe these as settled specification.

1. **`auth_key_ref` is reserved and never dereferenced.** Both targets validate
   it non-empty and then ignore it; the credential comes from process-wide env
   (`crates/ferrogate-runtime/src/supabase_edge_function.rs:36-45`;
   `cloudflare_worker_target.rs:51-59`;
   `docs/design/function-egress-broker.md:82-92`). The whole per-tenant secret
   store it points at **does not exist**. A future implementation gets to design
   secret resolution freely — and on Cloudflare, Secrets Store binding is
   deploy-time, which is a materially different constraint from the Rust's
   runtime env read.
2. **Single-project / single-worker is a limitation, not a design.** TOK-6 and
   its Worker mirror exist to refuse a configuration the credential model cannot
   serve (`crates/ferrogate-gateway/src/function_egress.rs:126-141`;
   `function_egress_cloudflare.rs:154-169`). With per-target credentials the
   rule should disappear, not be ported.
3. **`capability` is a constant.** Both branches always mint `"function"`
   (`crates/ferrogate-gateway/src/function_egress.rs:44`;
   `cloudflare_worker_target.rs:39`) even though the claim, the parameter and
   `FunctionTokenClaims.capability` are all shaped for a variable. The
   capability model was never built.
4. **The 300 s TTL ceiling is unreachable.** Both branches hard-code the 60 s
   default with no override
   (`crates/ferrogate-gateway/src/function_egress.rs:206`;
   `function_egress_cloudflare.rs:211`). Whether TTL should be
   caller-, tenant- or target-scoped is undecided.
5. **`timeout_millis` is a field nobody sets.** Present on both invocation
   structs, always filled from the 30 s constant. Per-target timeouts are
   unbuilt.
6. **The design doc's own step 3 was never realised as written.**
   `docs/design/function-egress-broker.md:62-65` says the route "reuses the
   external-action authorizer governance logic
   (`GatewayExternalActionAuthorizer`) so policy/tenant checks are identical to
   other governed actions." It does not: `handle_function_execute`
   (`local.rs:3219-3410`) calls the allowlist directly and never touches the
   external-action authorizer. Governance here is the allowlist plus the auth
   scope — nothing more. **The design doc that survives the delete is wrong on
   this point**, which is exactly why it needed this transcript.
7. **IP-literal hosts** — §D4. Undecided.
8. **`docs/design/function-egress-broker.md:152-153` lists per-tenant and
   per-function rate limiting, request timeouts, idempotency keys, and
   credential/signing-key rotation under "defense in depth".** Of those, only the
   request timeout exists. See §D13.

## D13. Controls that do NOT exist — record these so nobody assumes them

An implementer reading only the design doc would reasonably assume several of
these were present. None of them are anywhere in `local.rs:3219-3571` or the
five runtime/gateway modules.

* **No rate limit and no quota check on this route.** Not per tenant, not per
  function, not per key. The only limiter that touches it is the pre-auth
  source-IP flood limiter, which stops applying once a caller is authenticated.
* **No billing or metering.** No usage record is written; the design doc's
  step (6) "record audit + billing" is realised as audit only (§D9).
* **No RBAC.** `rbac_action: null` in the contract
  (`docs/openapi/runtime-api-contract.json:2181`).
* **No idempotency key**, so a retried call re-invokes the function.
* **No replay defense on the token** — no `jti`, no nonce, no one-time
  redemption. Within its 60 s window a captured token is fully reusable by
  anyone who has it.
* **No revocation.** Nothing can invalidate an outstanding token before `exp`.
* **No key rotation identifier** — no `kid` in the header, so two valid signing
  secrets cannot coexist during a rotation.
* **No clock-skew tolerance** (`function_token.rs:191`), which makes minting and
  verification across hosts sensitive to clock drift in the strict direction.
* **No response header inspection or forwarding** — only status and a body
  excerpt cross back (`crates/ferrogate-runtime/src/function_egress.rs:183-189`).
* **No streaming.** The response is fully buffered up to the cap; there is no
  SSE or chunked pass-through.
* **No per-target concurrency limit or circuit breaker.**

## D14. Scope statement

Written in `/home/dev/ferrogate-ts` on `main-ts`, wave 25. **No `cargo` was run;
no Rust was compiled, imported, linked or executed.** `crates/**` was **read
only**, for transcription. No file under `crates/` or `workers/` was modified or
deleted. No code and no test was written, weakened, skipped or deleted. No
composition root was touched. No `git` command was run. **`docs/rewrite/SPEC-TRANSCRIPTS.md`
is the only file this task wrote.**

**This part does not reverse, qualify, or reopen the owner's decision to drop
S1.** `POST /v1/functions/execute` answers `501` and this document asks for no
change to that. It records a definition that expires with `crates/**`, so that
the decision stays reversible on evidence rather than on memory.

Every claim above carries a `crates/…:line`, a `docs/…:line`, or an explicit
`OPEN` marker. The citations are checkable against the working tree until the
moment `crates/**` is removed; after that they are provenance.
