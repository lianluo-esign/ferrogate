// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway -- the gateway data-plane
// subsystems extracted out of ferrogate-cli (issue #553).

//! FerroGate gateway subsystems.
//!
//! # What this crate is for
//!
//! `ferrogate-cli` grew to 154,329 lines across 200 files -- 42% of the
//! workspace -- because it was bin-only and therefore had no API boundary that
//! anything could violate. Stage 1 of issue #553 gave it a `lib.rs`. This crate
//! is stage 2: the first subsystems actually leave.
//!
//! The eventual shape is that the Pingora data plane, the Admin API surface and
//! the control-plane state live here, and `ferrogate-cli` shrinks to the binary
//! entry point plus command wiring. That is not what this crate is yet. What is
//! here today is the set of gateway modules that could move WITHOUT anything
//! having to be redesigned to let them: every module below reaches only into
//! other modules below, or into crates that already sit under `ferrogate-cli`.
//!
//! # The public surface, and why it is this and not more
//!
//! Every module here arrived with its items marked `pub(super)` -- gateway-wide
//! visibility inside the old crate. Re-exporting all of that as this crate's
//! API would publish the same 200-file blob under a new name and create exactly
//! the boundary-that-binds-nothing the extraction exists to fix. So the modules
//! are `pub`, and inside them `pub(super)` became `pub(crate)` -- an
//! IDENTICAL-meaning rewrite, since these modules now hang off the crate root
//! -- and only the items `ferrogate-cli` actually calls were then promoted to
//! `pub`, one at a time, each because a compile error named it.
//!
//! The consequence worth stating: the promoted set is the contract. When stage
//! 3 moves the trunk (`local.rs`, `chat.rs`, `state.rs`) the callers come with
//! it, and each promotion should be demoted again rather than inherited. A
//! `pub` here is a debt entry, not an endorsement.
//!
//! # What is deliberately NOT here
//!
//! The other 85 modules under `ferrogate-cli/src/gateway/` all reach back into
//! `crate::state`, `crate::config`, `crate::responses`, `crate::approval`, or
//! into the `FerroGateway` / `ProxyContext` types defined in `gateway/mod.rs`.
//! Moving any of them today would need `ferrogate-gateway -> ferrogate-cli`,
//! which is a cycle. (`crate::auth` was on that list until stage 3b-0; see
//! [`auth`] for which half of it came and which half could not.) Three
//! near-misses are worth naming, because each is a one-type problem and each is
//! somebody's next slice:
//!
//! * `asset_publish_gate` + `asset_security` need only
//!   `crate::approval::ApprovalStatus`. That enum cannot simply move down,
//!   because `impl From<ApprovalStatus> for ferrogate_runtime::ActionDecision`
//!   is an orphan-rule-legal impl only while `ApprovalStatus` is local to
//!   `ferrogate-cli`. Moving the type means moving that impl too, which is a
//!   design decision, not a `git mv`.
//! * `admin_list_query` needs `crate::responses::AdminList` and
//!   `crate::state::AdminPagination` -- the admin pagination vocabulary, which
//!   belongs with the Admin API surface in stage 3.
//! * `api_key_tenancy` needed `crate::config::ApiKey`, which was
//!   `ferrogate-cli`'s own config type rather than anything from the
//!   `ferrogate-config` crate. #553 stage 3a moved that type into
//!   `ferrogate-config`, so this one is now unblocked: `api_key_tenancy` can
//!   come here as soon as a slice picks it up.
//!
//! Several further modules (`a2a`, `asset_admission`, `agent_cost_burn`) are
//! themselves clean but have `_test.rs` siblings that build a `Config` or an
//! `AppState`. A dev-dependency back onto `ferrogate-cli` would make them
//! compile; it was rejected. A crate whose tests depend on the crate it was
//! extracted from has not been extracted.
//!
//! # Open question, answered: what belongs in `ferrogate-core`?
//!
//! Issue #553 left "which types belong in `ferrogate-core`, e.g. `AuthContext`
//! and `CallerScope`?" open. The answer, for the record:
//!
//! **`CallerScope`: yes.** It is a two-state enum -- `PlatformOperator` or
//! `Tenant(&str)` over a `tenants.id` -- and it is the ONE interpreter of
//! "which tenant is this caller, and is it root?". That is the entire point of
//! issue #515: before `CallerScope` existed the question was asked as
//! `organization_id.is_none()` at a dozen call sites, which made "the operator
//! omitted a field" and "the operator asked for platform root" the same value.
//! A vocabulary type with exactly one interpreter must not be duplicated across
//! a crate boundary, and the moment the Admin API handlers live here while
//! `ctl` and the standalone admin-api service live in `ferrogate-cli`, BOTH
//! sides need to read a caller's scope. If the type is not shared, one side
//! re-derives it, and #515's defect returns by construction. It belongs in
//! `ferrogate-core` next to `TenantContext` and `WorkspaceScope`, which are the
//! attribution reading of the same identity that `CallerScope` is the
//! authorization reading of. `UNSCOPED_TENANT_ID` moves with it: the sentinel
//! is part of the type's meaning, not a caller's detail.
//!
//! **`AuthContext`: no.** It is not vocabulary; it is the OUTPUT of
//! `ferrogate-cli`'s authentication pipeline. It carries a
//! `ferrogate_policy::EffectiveQuota`, a `ferrogate_auth::PolicySubject`, model
//! and provider allow/deny sets, RPM and monthly-token budgets --- i.e. it
//! depends on `ferrogate-policy` and `ferrogate-auth`, both of which sit ABOVE
//! `ferrogate-core`. Moving it down would drag those crates underneath the
//! layer they are built on and invert the graph to buy nothing: no consumer
//! needs `AuthContext` who does not also need the authenticator that produces
//! it. `AuthContext` should travel WITH the Admin API surface into this crate
//! in stage 3, not downward into `ferrogate-core`.
//!
//! Neither move is performed here. Point 4 of the stage-2 brief allows the
//! `CallerScope` move only if it is what unblocks the leaf extraction; it is
//! not -- none of the eleven files moved in this commit touch auth -- so the
//! decision is recorded (here and in `ferrogate-core/src/lib.rs`) and the move
//! is left to the slice that needs it.
//!
//! **Stage 3b-0 update.** `CallerScope` and `AuthContext` are both in
//! [`auth`] now, which settles the `AuthContext` half of the question the way
//! it was called: it travelled with the vocabulary rather than down into
//! `ferrogate-core`. `CallerScope` is still owed its move to `ferrogate-core`,
//! and 3b-0 deliberately did not make it. It would not have fallen out: the
//! type is returned by `AuthContext::caller_scope()` and read by the four
//! deciders next to it, so moving it alone splits one vocabulary across two
//! crates for no caller that exists yet. It becomes worth doing when `ctl` or
//! the standalone admin-api service has to read a caller's scope without
//! depending on this crate -- and `UNSCOPED_TENANT_ID` goes with it when it
//! does.

/// Asset registry version/variant resolution: semver range and channel
/// resolution over published asset versions, and platform-variant selection.
pub mod asset_registry;

/// Who a caller is and what it may do: the `AuthContext`/`CallerScope`/
/// `AuthError` vocabulary and its tenant-isolation deciders, the credential
/// primitives, and the external auth-service client. NOT the request-admission
/// pipeline -- see the module docs for why `authenticate()` stayed behind.
pub mod auth;

/// Malware screening for uploaded asset content: the scanner trait, the
/// EICAR/clamd/HTTP backends, and the scanner-unavailable fail-open/closed
/// policy that decides an object's visible scan state.
pub mod asset_scan;

/// Publisher signature verification for assets: the minisign/ed25519 key
/// registry, the canonical verification manifest, and the signature verdict.
pub mod asset_signature;

/// Bounded request-body reads off a Pingora session.
pub mod body;

/// Brokered edge-function egress: the broker config, the invocation token, and
/// the outbound request with its SSRF-guarded resolver.
pub mod function_egress;

/// The gateway's HTTP adapter over the shared #514 lifecycle gate: the one
/// mapping from `ferrogate_storage`'s refusal onto [`auth::AuthError`]. It came
/// here with `AuthError` because the orphan rule required it -- neither type is
/// `ferrogate-cli`'s any more. Private, because it publishes no items: a trait
/// impl is reachable wherever both of its types are.
mod lifecycle_gate;

/// The Cloudflare Workers flavour of [`function_egress`]: target-kind
/// selection and the Cloudflare-shaped invocation.
pub mod function_egress_cloudflare;

/// Anthropic Messages streaming: OpenAI-chat SSE to a Messages response, a
/// Messages response to Anthropic SSE, and the streaming normalizer.
pub mod messages_stream;

/// OpenAI Responses streaming: the provider-kind discriminator and the
/// streaming normalizer that renders a Responses-shaped SSE sequence.
pub mod responses_stream;
