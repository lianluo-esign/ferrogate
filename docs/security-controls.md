# Security Controls

This page maps FerroGate's shipped capabilities to the control families a
security/procurement reviewer typically asks about. It documents what exists
today; it is not a compliance certification. See [`../SECURITY.md`](../SECURITY.md)
for the vulnerability-disclosure process, and [`roadmap.md`](roadmap.md) for
gaps still being closed.

## Audit Logging

Admin-console mutations that go through virtual-key and quota-policy CRUD
(`crates/ferrogate-cli/src/gateway/virtual_keys.rs`,
`crates/ferrogate-cli/src/gateway/quota_policies.rs`) write an append-only
`StoredAuditEvent` (`crates/ferrogate-storage/src/lib.rs:5864`) through
`AuditLogRepository` (`crates/ferrogate-storage/src/lib.rs:434`). Events are
readable via the Admin API and the admin-console's read-only Audit Events
page. Coverage is not yet universal across every resource type — tracked
separately.

## Authentication & Credential Storage

Admin-console user passwords are hashed with Argon2 (`argon2` crate) before
storage — never stored or compared in plain text
(`crates/ferrogate-auth/src/lib.rs:1253` `hash_password`,
`crates/ferrogate-auth/src/lib.rs:1261` `verify_password`, called from
registration and login at `crates/ferrogate-auth/src/lib.rs:802` and `:918`).
Sessions use short-lived JWT access tokens plus durable, hashed,
single-use-rotated refresh tokens; logout and refresh-token reuse both revoke
the stored token (`crates/ferrogate-auth/src/lib.rs` `issue_session`,
`handle_admin_refresh`, `handle_admin_logout`).

External IdP login via OIDC Authorization Code + PKCE is supported —
discovery-document and JWKS-based ID token verification, group-claim-to-role
mapping, and just-in-time user provisioning on first login
(`crates/ferrogate-auth/src/lib.rs` `handle_sso_authorize`,
`handle_sso_callback`). SAML and MFA are not yet implemented.

User provisioning also supports a simplified SCIM 2.0 endpoint
(`/scim/v2/Users`, `/scim/v2/Groups`) authenticated by a dedicated
`scim.provision`-scoped credential, for IdP-driven user lifecycle management
(`crates/ferrogate-auth/src/lib.rs` `handle_scim_user_create`,
`handle_scim_user_patch`).

## Authorization

Gateway request authorization is enforced by a generic RBAC engine —
`Permission` (`crates/ferrogate-auth/src/lib.rs:105`), `Role`
(`crates/ferrogate-auth/src/lib.rs:111`), and `PolicyBinding`
(`crates/ferrogate-auth/src/lib.rs:119`) — matched by `RbacAuthService` with
wildcard action/resource support. Virtual API keys additionally carry
per-key/workspace/project/tenant scopes, model/provider allowlists and
denylists, request-rate limits, and token budgets, enforced in
`crates/ferrogate-cli/src/auth.rs`.

Roles and bindings are managed at runtime through the Admin API
(`/v1/rbac/roles`, `/v1/rbac/bindings`) without a process restart, and
non-owner console users can be invited, promoted/demoted, and revoked from a
tenant's team, with a last-owner guard preventing a tenant from being left
without an owner (`crates/ferrogate-auth/src/lib.rs`
`handle_admin_team_invite`, `handle_admin_team_change_role`,
`handle_admin_team_revoke`).

## Transport Security

FerroGate terminates TLS itself: manual certificate configuration, ACME
HTTP-01, and ACME DNS-01 (built-in Cloudflare provider) with renewal
scheduling and graceful-upgrade handoff on listener/certificate change
(`crates/ferrogate-cli/src/acme.rs`).

## Tenant Isolation

Durable control-plane storage defaults billing and auth services to
dedicated Supabase/PostgreSQL schemas (`search_path`,
`crates/ferrogate-storage/src/lib.rs:124`, schema-create/`SET search_path`
statements at `crates/ferrogate-storage/src/lib.rs:3695-3707`) rather than the
shared public schema. Multi-tenancy is modeled as a first-class hierarchy —
tenant account → project → workspace — each with its own storage table and
admin-console CRUD page.

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
parsed (`crates/ferrogate-cli/src/network_access.rs`,
`AppState::check_network_access`). Operators without `network_access`
configured should still place FerroGate behind a network-level control
(security group, WAF, or reverse-proxy rate limiting) as defense in depth.

## Content Safety / Guardrails

The built-in guardrail engine supports keyword, regex, and max-input-length
rules with deny or redact effects, scoped by tenant/model/provider
(`crates/ferrogate-cli/src/config/types.rs` `GuardrailRule`,
`crates/ferrogate-cli/src/state.rs` `match_guardrail`). A rule can instead
delegate detection to an external HTTP endpoint (`provider: custom_http`) —
e.g. a dedicated PII/jailbreak/toxicity classifier that can't be expressed as
a regex — via a JSON callout (`crates/ferrogate-cli/src/state.rs`
`call_guardrail_provider`). If the external provider is unreachable or
returns a malformed response, the rule fails closed (denies) regardless of
its configured effect, since there is nothing to safely redact without a
detection result.

## Supply-Chain Security

Every change is gated by `scripts/security-check.sh`: `cargo fmt --check`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo metadata --locked`, a high-confidence secret scan (private key
material, AWS/GitHub/OpenAI/Anthropic/Google key patterns), `cargo deny check
licenses bans sources`, and `cargo audit`. CI runs this gate in strict mode
(`FERROGATE_SECURITY_REQUIRE_TOOLS=1`), so a missing tool or a new advisory
fails the build rather than silently skipping —
see [`.github/workflows/rust-quality.yml`](../.github/workflows/rust-quality.yml).

## Compliance Certifications

FerroGate does not currently hold SOC 2, HIPAA, ISO 27001, or GDPR-specific
certifications. This page documents the underlying controls; a formal audit
program is a separate, future initiative from the documentation groundwork
here. See [`soc2-audit-scoping.md`](soc2-audit-scoping.md) for a scoped
recommendation on audit path, cost/timeline, and vendor options.
