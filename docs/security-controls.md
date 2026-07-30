# Security Controls

This page maps FerroGate's shipped capabilities to the control families a
security/procurement reviewer typically asks about. It documents what exists
today; it is not a compliance certification. See [`../SECURITY.md`](../SECURITY.md)
for the vulnerability-disclosure process, and [`roadmap.md`](roadmap.md) for
gaps still being closed.

## Audit Logging

Admin-console mutations that go through virtual-key and quota-policy CRUD
(`crates/ferrogate-gateway/src/server/virtual_keys.rs`,
`crates/ferrogate-gateway/src/server/quota_policies.rs`) write an append-only
`StoredAuditEvent` (`crates/ferrogate-storage/src/lib.rs:5864`) through
`AuditLogRepository` (`crates/ferrogate-storage/src/lib.rs:434`). Events are
readable via the Admin API and the admin-console's read-only Audit Events
page. Coverage is not yet universal across every resource type — tracked
separately.

### CLI action attribution

Every request the `ferrogate` CLI issues — reads included — carries a
client-minted `action_id`, a client fingerprint that names the credential
*source* but never the credential, and the client's own clock reading under a
header whose name ends in `-unverified` (issue #548). Enforcement is a compile
error rather than a review convention: the two functions that materialize an
outbound request each take a `ClientActionIdentity` as a required argument, and
that type has no public constructor other than `mint`.

The audit instant is **server-issued or `null` with a stated reason** — the
client clock never stands in for it. **No FerroGate deployment issues a time
token today**, so every CLI receipt currently reports `client_sent_at: null`
with the code `no_server_issued_time_token`; the issuing endpoint is server-side
work #548 defers. Two PII-bearing fields (a machine label and a client-reported
address) are opt-in and off by default, and neither can blind the trail, because
`action_id` is unconditional and the authoritative source IP is the one the
server observes.

See [`docs/cli-audit-attribution.md`](cli-audit-attribution.md) for the headers,
the two environment variables, and what a receipt shows.

## Authentication & Credential Storage

Gateway authentication is **required by default and stated, never inferred**
(issue #542). Whether a request must present a credential is one field,
`[auth] disabled` (`crates/ferrogate-config/src/config/types.rs`
`Config::auth_required`); the open posture — every request admitted as an
unrestricted platform operator — is reachable only by writing
`[auth] disabled = true`. It used to be derived from
`auth_service.enabled || !api_keys.is_empty()`, which counted static config
keys only: a deployment whose credentials were all durable/virtual keys, or one
that simply omitted `[[api_keys]]`, had authentication switched off by that
omission. A config that requires authentication but has no credential source at
all refuses to start, naming the switch, rather than running open
(`crates/ferrogate-gateway/src/lifecycle.rs` `ensure_auth_posture_is_declared`,
mirroring the same gate on the Control Plane API service, and run by
`ferrogate check` as well as by `ferrogate run` so the refusal surfaces before
a restart rather than during one).

A **credential source** is a static `[[api_keys]]` entry, an enabled
`[auth_service]`, or a durable `[storage]` backend that can hold virtual keys:
`postgres`, `supabase` or `cloudflare_d1` (`Config::durable_api_key_store`,
`crates/ferrogate-config/src/config/types.rs`, an exhaustive match over
`StorageProviderKind` so a new backend cannot be omitted by accident — the
first version of this predicate listed only Postgres and Supabase and refused
to start a fully-authenticating D1 deployment). In a Caddyfile, which has no
`[auth]` section to write, the open posture is stated as `auth off` in the
global options block; omitting it means authentication is required, as
everywhere else. `[auth] disabled = true` is refused outright next to a
declared static credential source, and allowed — with a startup warning naming
the store whose keys are being ignored — next to a durable `[storage]` backend,
since such a backend also holds request logs, audit events and routes and so is
not by itself a statement about authentication.

**Platform root is declared, never inherited** (issues #515, #540). An API key
holds unrestricted, cross-tenant access only if it says `platform_operator =
true`; a key that names an `organization_id` is that tenant and nothing else.
Until #540 a key that said *neither* was silently promoted to platform root — an
omitted config field granted root — and `[tenancy] implicit_platform_operator`
defaulted to `true` to preserve it. That default is now `false`:

- a static `[[api_keys]]` entry with no declared identity **refuses to load**,
  naming the key by id and printing both fixes plus the legacy switch
  (`Config::ensure_every_key_declares_tenant_identity`,
  `crates/ferrogate-config/src/config/validate.rs`), so an upgrade stops at
  `ferrogate check`/`ferrogate run` rather than 403-ing live traffic afterwards;
- the same refusal applies in every dialect a config can be written in — TOML,
  YAML, and a Caddyfile — because it lives in `Config::validate`, which all
  three loaders and `POST /admin/v1/config/validate` run;
- a credential the config cannot enumerate — a durable/virtual key, or one from
  the external auth service — is refused at authentication with
  `403 tenant_identity_required` (`finalize_auth`,
  `crates/ferrogate-gateway/src/auth.rs`), and an `organization_id` that is
  present but blank is refused there too: it names no tenant, and the blank
  string is what `UNSCOPED_TENANT_ID` means;
- a pre-#515 row already in the **durable control plane** is not a config
  document an operator can edit, so it does not stop the gateway or the admin
  API — refusing there would block the `PUT` that repairs it. It is named by id
  in a startup warning instead (`Config::warn_undeclared_control_plane_api_keys`,
  called from the boot snapshot path in
  `crates/ferrogate-gateway/src/state.rs`), and it is still refused at
  authentication like any other unclassified credential;
- `resolve_platform_operator` (same file) is the single chokepoint every auth
  source funnels through, so a new source cannot reintroduce "no tenant means
  root";
- a Caddyfile states the same thing as `platform_operator on` /
  `organization_id <tenants.id>` inside an `api_key` block; the bridge carries
  the declaration across and invents nothing;
- `[tenancy] implicit_platform_operator = true` restores the pre-#515 behaviour
  for a deployment mid-migration, and every key it promotes is logged by id at
  startup.

`[tenancy] require_registered_tenant` remains `false` by default: a misspelled
`organization_id` **cannot reach another tenant** — the key is scoped to an
island of its own — so it is a data-integrity setting rather than a privilege
one, and whether a tenant row exists is a fact about the control-plane store
that no load-time check can warn about first. Stated precisely rather than as
"fails closed": such a key still serves the data plane, and because
`resolve_lifecycle_chain`
(`crates/ferrogate-storage/src/lifecycle_gate.rs`) skips an id that
names no row, it also escapes the tenant suspension gate and every
tenant-scoped quota policy. It is unreachable *by* other tenants and ungoverned
*by* its own, which is why the setting exists at all.

Admin-console user passwords are hashed with Argon2 (`argon2` crate) before
storage — never stored or compared in plain text
(`crates/ferrogate-auth-service/src/lib.rs:1253` `hash_password`,
`crates/ferrogate-auth-service/src/lib.rs:1261` `verify_password`, called from
registration and login at `crates/ferrogate-auth-service/src/lib.rs:802` and `:918`).
Sessions use short-lived JWT access tokens plus durable, hashed,
single-use-rotated refresh tokens; logout and refresh-token reuse both revoke
the stored token (`crates/ferrogate-auth-service/src/lib.rs` `issue_session`,
`handle_admin_refresh`, `handle_admin_logout`).

External IdP login via OIDC Authorization Code + PKCE is supported —
discovery-document and JWKS-based ID token verification, group-claim-to-role
mapping, and just-in-time user provisioning on first login
(`crates/ferrogate-auth-service/src/lib.rs` `handle_sso_authorize`,
`handle_sso_callback`). SAML and MFA are not yet implemented.

User provisioning also supports a simplified SCIM 2.0 endpoint
(`/scim/v2/Users`, `/scim/v2/Groups`) authenticated by a dedicated
`scim.provision`-scoped credential, for IdP-driven user lifecycle management
(`crates/ferrogate-auth-service/src/lib.rs` `handle_scim_user_create`,
`handle_scim_user_patch`).

## Authorization

Gateway request authorization is enforced by a generic RBAC engine —
`Permission` (`crates/ferrogate-auth-service/src/lib.rs:105`), `Role`
(`crates/ferrogate-auth-service/src/lib.rs:111`), and `PolicyBinding`
(`crates/ferrogate-auth-service/src/lib.rs:119`) — matched by `RbacAuthService` with
wildcard action/resource support. Virtual API keys additionally carry
per-key/workspace/project/tenant scopes, model/provider allowlists and
denylists, request-rate limits, and token budgets, enforced in
`crates/ferrogate-gateway/src/auth.rs`.

Roles and bindings are managed at runtime through the Admin API
(`/v1/rbac/roles`, `/v1/rbac/bindings`) without a process restart, and
non-owner console users can be invited, promoted/demoted, and revoked from a
tenant's team, with a last-owner guard preventing a tenant from being left
without an owner (`crates/ferrogate-auth-service/src/lib.rs`
`handle_admin_team_invite`, `handle_admin_team_change_role`,
`handle_admin_team_revoke`).

## Transport Security

FerroGate terminates TLS itself: manual certificate configuration, ACME
HTTP-01, and ACME DNS-01 (built-in Cloudflare provider) with renewal
scheduling and graceful-upgrade handoff on listener/certificate change
(`crates/ferrogate-gateway/src/acme.rs`).

## Tenant Isolation

Durable control-plane storage defaults billing and auth services to
dedicated Supabase/PostgreSQL schemas (`search_path`,
`crates/ferrogate-storage/src/lib.rs:124`, schema-create/`SET search_path`
statements at `crates/ferrogate-storage/src/lib.rs:3695-3707`) rather than the
shared public schema. Multi-tenancy is modeled as a first-class hierarchy —
tenant account → project → workspace — each with its own storage table and
admin-console CRUD page.

## Data Retention & Minimization

The generalizable retention engine (`retention_policies` table +
`ferrogate-storage::asset_lifecycle`, issue #263) is adopted by the shared
asset-lifecycle sweeper (`crates/ferrogate-gateway/src/state_asset_lifecycle.rs`,
`sweep_asset_lifecycle_once`) to apply per-tenant TTL/purge to the high-write
compliance tables `request_logs` and `audit_events` (issue #284). Each table
resolves a per-tenant `retention_policies` row (`resource_type` =
`request_logs` / `audit_events`, `scope` = `*` for the tenant default) and
falls back to the deployment defaults on `[asset_lifecycle]`
(`default_request_log_max_age_secs`, `default_audit_event_max_age_secs`,
`default_response_body_max_age_secs`). Rows past their max-age (or beyond a
`keep_last_n` cap) are batch-deleted with the same fail-safe planner used for
assets (`plan_log_retention`): nothing inside the `retention_min_age_secs`
grace window / legal floor is ever pruned, so a longer floor on `audit_events`
lets those rows survive while `request_logs` expire. The purge is itself
audited (`request_logs.retention.prune` / `audit_events.retention.prune`
`StoredAuditEvent`s) as evidence of deletion, and folded into the
`ferrogate_asset_lifecycle_{scanned,pruned,failed}_total` Prometheus counters.

Defaults: retention is **disabled** until an operator opts in
(`[asset_lifecycle] enabled = true`), and enabling it starts in `dry_run`
report-only mode. Response-body captures (`response_recorded`) get the
shortest TTL via `default_response_body_max_age_secs`
(scope `response_body`), minimizing retention of the highest-sensitivity data.

SOC2 mapping: this control implements the data-minimization / defined-retention
expectations scoped in `docs/soc2-audit-scoping.md` — bounded growth of
operational/audit data, a per-tenant retention policy, and tamper-evident
audit records of each purge.

`self_hosted_run_dispatches` has its own reclaim
(`crates/ferrogate-gateway/src/state_self_hosted_dispatch_sweeper.rs`,
`sweep_self_hosted_dispatches_once`, issue #545), because nothing else prunes
that table and its four on-demand release points (issue #502) all need some
actor to touch the run: a worker that leases a job and then vanishes leaves an
unacked `cancel_run` and a superseded `start_run` behind, and the per-tenant
open-job cap never trips on them because the run is already terminal. The
sweeper reclaims a run's rows only once the run is terminal **and** no row of
that run holds a live lease (`lease_expires_at_unix + lease_grace_secs`) —
terminal status alone would delete the `start_run` row a live run's
lease-ownership check (issue #503) reads for its whole life, and lease expiry
alone would delete a running job's row.

A dead lease is not sufficient for one shape. A `cancel_run` that nobody has
acked, on a run whose `start_run` was assigned to a worker, is the
NOT-WITHDRAWABLE cancel: that row is deliberately retained because collecting
it is the only thing that stops a worker already executing the run, and its
delivery is bounded by that worker's next poll rather than by the lease (leases
are 30–60s and are never renewed, so they expire while long jobs are still
running). Those groups are additionally gated on how long the run has been
terminal (`pending_cancel_grace_secs`), so a cancel the caller already saw
succeed cannot be silently deleted before it is delivered.

The reclaim is audited and metered like the asset lifecycle purge: each run's
reclaim emits a `self_hosted_dispatch.reclaim` admin audit event scoped to the
dispatch's tenant, and every sweep folds into
`ferrogate_self_hosted_dispatch_reclaim_{scanned,reclaimed,failed}_total`. A
sweep that found candidates and reclaimed nothing logs at `warn!`, because
nothing else prunes this table and a stalled sweeper is otherwise invisible.

Defaults on `[self_hosted_dispatch_sweeper]`: `enabled = true` (this reclaim
only ever deletes rows of an already-terminal run), `tick_interval_secs = 300`,
`max_runs_per_tick = 200` — a bound on runs actually RECLAIMED, not on
candidates examined, so candidates that can never become terminal cannot spend
the budget and stall the sweeper — `max_scanned_rows = 20000` (the per-tick work
bound; the durable read has no pushdown filter yet and exceeding this logs at
`warn!`), `lease_grace_secs = 300`, and `pending_cancel_grace_secs = 3600`. Both
grace windows are clamped to 86400s, since an unbounded grace is a silent off
switch rather than a conservative setting.

## Secrets Management

Upstream provider API keys and ACME DNS-provider credentials can be
referenced indirectly via `env://` or `vault://` secret references, resolved
at startup through `ferrogate-secrets` (`SecretRef`, `SecretResolverRegistry`)
rather than only accepted as plain config values — including HashiCorp Vault
KV v2 lookups when `VAULT_ADDR`/`VAULT_TOKEN` are configured
(`crates/ferrogate-secrets/src/lib.rs`). Do not set `ApiKey.key` (the
plain-value field) or a literal credential in production; use `key_env` or a
`secret_ref` instead.

## Network-Level Controls

Every request-level limit (rate limits, token budgets) is keyed off an
authenticated virtual API key. In addition, an optional pre-authentication
IP/CIDR allowlist and a per-IP unauthenticated-request rate limiter are
enforced as the first check on every request, before any credential is
parsed (`crates/ferrogate-config/src/config/network_access.rs`,
`AppState::check_network_access`). Operators without `network_access`
configured should still place FerroGate behind a network-level control
(security group, WAF, or reverse-proxy rate limiting) as defense in depth.

## Content Safety / Guardrails

The built-in guardrail engine supports keyword, regex, and max-input-length
rules with deny or redact effects, scoped by tenant/model/provider
(`crates/ferrogate-config/src/config/types.rs` `GuardrailRule`,
`crates/ferrogate-gateway/src/state_quota_and_policy.rs` `match_guardrail`). A rule can instead
delegate detection to an external HTTP endpoint (`provider: custom_http`) —
e.g. a dedicated PII/jailbreak/toxicity classifier that can't be expressed as
a regex — through the async `GuardrailDetector` contract in
`ferrogate-guardrails`. The external runtime uses a pooled `reqwest` client,
one parent deadline, a per-detector semaphore and circuit breaker, bounded
request/response bodies, at most one opt-in retry, typed findings, and
validated UTF-8 content patches. It does not call the synchronous secret HTTP
helper from the Pingora request path.

`provider_on_error` is explicit: `block` is the fail-closed default, `record`
allows the request while emitting detector-error evidence, and
`fallback_detector` evaluates the rule's local keyword/regex/length matcher.
Detector credentials use `provider_secret_ref` (`env://` or `vault://`) and
are resolved once when runtime state is built. Debug, audit, and client error
surfaces do not contain the credential or configured endpoint path.

External detector URLs reject credentials, query strings, fragments,
localhost, private/link-local/special-use addresses, and cloud metadata IPs by
default. Redirects are disabled, and every DNS resolution filters disallowed
addresses so a hostname cannot rebind to a private target. An operator must
set `provider_allow_private_network: true` for a deliberately configured
private detector endpoint. Detector timeouts cannot exceed 30 seconds.

To investigate a blocked or failed request end to end (who / why / target /
action / cost), use `GET /admin/v1/investigations?request_id=...` — see the
operator guide [`docs/guardrails/investigation-view.md`](guardrails/investigation-view.md)
for a copy-paste example, the response field map, and the RBAC needed to read
investigation evidence.

## Supply-Chain Security

Every change is gated by `scripts/security-check.sh`: `cargo fmt --check`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo metadata --locked`, a high-confidence secret scan (private key
material, AWS/GitHub/OpenAI/Anthropic/Google key patterns), `cargo deny check
licenses bans sources`, and `cargo audit`. CI runs this gate in strict mode
(`FERROGATE_SECURITY_REQUIRE_TOOLS=1`), so a missing tool or a new advisory
fails the build rather than silently skipping —
see [`.github/workflows/rust-quality.yml`](../.github/workflows/rust-quality.yml).

The secret scan lives in
[`scripts/check-secret-scan.sh`](../scripts/check-secret-scan.sh). It prefers
ripgrep and falls back to `git grep -I`, which ships wherever the repository
does; if neither is available it exits non-zero naming both tools rather than
skipping (#525 — the scan previously hard-coded `rg` and died on any box
without it, so the gate looked green while never running). Before either engine
runs, the gate rejects tracked files that git classifies as binary; this keeps
ripgrep's `binary file matches` behaviour from diverging from `git grep -I`'s
silent omission. A necessary binary exception must name an owner and reason and
pin the exact file by SHA-256; a stale or changed entry fails. The scan reports
its admitted-file count, and the self-test compares that count with an
independent `git ls-files` enumeration plus anchors in `admin-console/`,
`crates/`, `scripts/`, and `workers/`.

The root `Cargo.lock` is the one file intentionally outside that enumeration:
it is generated dependency inventory covered by `cargo metadata --locked`, the
protobuf advisory floor, cargo-audit, cargo-deny, and release-attestation digest
checks rather than by the authored-source credential patterns. Nested lockfile
fixtures remain in scope. `scripts/test-check-secret-scan.sh` drives the script
with each tool shadowed out of `PATH`. When ripgrep is installed it also diffs
both engines over a planted-credential corpus; CI installs ripgrep explicitly,
while a box without it reports the skipped equivalence assertions in the
self-test's final pass/skip counts.

A handful of test fixtures legitimately match — a synthetic token a leak test
asserts never leaves the Worker, for instance. Those are reviewed exceptions in
a table inside the scan (`--list-allowlist` prints it), and each one exempts a
single line, pinned by the SHA-256 of that line's own content, with a written
reason (#566). The digest is what keeps an exception from becoming a hole: a
file-scoped exemption would let a real key pasted anywhere in a credential test
scan clean, and the test suite plants a realistic key in an allowlisted file —
both beside the reviewed line and on top of it — and requires the scan to
report it. An entry that stops matching fails the scan as stale rather than
lingering, and an allowlisted line that has *changed* is reported as a finding
with a note saying so, because "this file was edited" and "a credential leaked"
have opposite fixes. Nothing else can suppress a match. The first choice is
still to make the fixture not look like a credential at all, which is how #566
itself was closed.

Published release images (`.github/workflows/ci-image.yml` and
`.github/workflows/package.yml`, both reached only from a published release)
are additionally covered by a shared `.github/actions/image-supply-chain`
step: an SPDX SBOM
(`anchore/sbom-action`), a keyless `cosign` signature over the image digest
using GitHub Actions OIDC identity (no stored private key), and a GitHub
build-provenance attestation (`actions/attest-build-provenance`) (issue
#189). **Status: implemented and pushed, not yet verified end-to-end** — the
self-hosted CI runners were offline at implementation time, so no real
signed/attested image has been produced and verified yet; see
[`docs/security/supply-chain.md`](security/supply-chain.md) for the
real `cosign verify` / `gh attestation verify` commands an operator will run
once a CI-built image exists, and issue #189 for the outstanding
verification step.

## Agent Sandbox / Capability Boundary

Managed agent/tool execution is bounded by a three-layer model in
`crates/ferrogate-runtime/src/`: `isolation.rs` (execution boundary — a
multi-backend abstraction over Firecracker microVM, Kata Containers, gVisor,
and rootless Docker), `capability_boundary.rs` (authorization boundary — ten
`CapabilityAction` classes, evaluated independently of which isolation
backend is in use), and `function_egress.rs` (fail-closed, per-tenant
allowlist governance for gateway-brokered Supabase edge-function
invocation). A red-team regression test proves this boundary denies a
CVE-2025-53967-shaped escalation attempt (an MCP/agent tool call trying to
reach a shell, filesystem, or network target outside its granted capability
class) fail-closed, with an inspectable audit trail (issue #190). See
[`docs/security/agent-sandbox-model.md`](security/agent-sandbox-model.md)
for the full architecture writeup and its explicit "proven vs.
architecturally present but untested" boundary — notably, authorization is
class-level only today (e.g. granting `Filesystem` does not itself restrict
to one path or to read-only access).

## Compliance Certifications

FerroGate does not currently hold SOC 2, HIPAA, ISO 27001, or GDPR-specific
certifications. This page documents the underlying controls; a formal audit
program is a separate, future initiative from the documentation groundwork
here. See [`soc2-audit-scoping.md`](soc2-audit-scoping.md) for a scoped
recommendation on audit path, cost/timeline, and vendor options.
