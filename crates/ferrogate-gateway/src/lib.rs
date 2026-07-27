// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway -- the gateway data plane,
// the Admin API surface and the control-plane state, extracted out of
// ferrogate-cli (issue #553).

//! FerroGate's gateway: the Pingora data plane, the Admin/Control API handler
//! surface, and the control-plane state both of them run over.
//!
//! # What this crate is for
//!
//! `ferrogate-cli` grew to 154,329 lines across 200 files -- 42% of the
//! workspace -- because it was bin-only and therefore had no API boundary that
//! anything could violate. Stage 1 of issue #553 gave it a `lib.rs`; stage 2
//! created this crate and moved eleven leaf subsystems into it; stage 3a moved
//! the operator-facing configuration out to `ferrogate-config`. Stage 3b, the
//! commit this doc describes, is the trunk.
//!
//! # Why the trunk had to move in one piece
//!
//! `ferrogate-cli/src/gateway/` reached `crate::state` 132 times and
//! `state*.rs` reached back into `crate::gateway` 27 times. That is a genuine
//! cycle, so no ordering split them: moving `gateway/` alone would have needed
//! `ferrogate-gateway -> ferrogate-cli` for `state`, while
//! `ferrogate-cli -> ferrogate-gateway` already existed, and cargo refuses
//! crate cycles.
//!
//! The same argument -- once, per module -- is why fourteen further modules
//! came with them rather than staying behind: [`responses`], `auth`'s
//! request-admission half, [`builtin_tools`], [`approval`], [`tokenizer`],
//! [`extensions`], [`acme`], [`lifecycle`], [`dashboard`], [`billing_client`],
//! [`budget_alerts`], [`metering`], [`telemetry`] and [`service_storage`]. Each
//! is reached BY the trunk (`state` alone reaches `responses` 107 times), so
//! each would have been a `ferrogate-gateway -> ferrogate-cli` edge. None was
//! dodged with a trait: a host trait with exactly one implementor buys an
//! abstraction the next slice deletes, and it would have put dynamic dispatch
//! on the per-request path.
//!
//! # The public surface, and why it is this and not more
//!
//! The rule this crate has used since stage 2: start from an empty export
//! list, compile, and promote exactly the names the compiler reports missing.
//! A `pub` here is a debt entry, not an endorsement -- and stage 2 said that
//! when the trunk arrived, its own promotions should be DEMOTED rather than
//! inherited, because their callers were arriving with it. That is what
//! happened: `asset_registry`, `asset_scan`, `asset_signature`, `body`,
//! `function_egress`, `function_egress_cloudflare`, `messages_stream` and
//! `responses_stream` were all `pub` modules with `pub` items for
//! `ferrogate-cli`'s benefit; module and items alike are `pub(crate)` again,
//! because the ~30 modules that use them now live here. The same demotion ran
//! over `auth`, which had thirty-odd `pub` items for the same reason and now
//! has four.
//!
//! The result, exactly: **22 `pub` declarations in 135k lines** -- five `pub
//! mod` here, `server::assets`, and sixteen items -- against 1,301 that are
//! `pub(crate)` or narrower. What `ferrogate-cli` names is the whole of it,
//! and it is eleven references from four files: [`server::serve`] and
//! `server::assets::INLINE_ASSET_MAX_BYTES`,
//! [`state::runtime_storage_repositories`], the four [`lifecycle`]
//! report/reload entry points, [`service_storage`]'s three, and [`auth`]'s
//! `hash_api_key_secret` / `authenticate_admin_gate` /
//! `build_auth_service_target` / `AuthError` / `AuthServiceTarget` /
//! `AuthServiceClientError` for the standalone control-api service. There is
//! deliberately no `ferrogate_cli::gateway` or `ferrogate_cli::state` shim;
//! `ferrogate-cli` names the new home.
//!
//! # `auth` is one module again
//!
//! Stage 3b-0 split `auth.rs` in half and said so in its doc comment: the
//! authorization vocabulary came here, and `authenticate()`,
//! `finalize_auth()`, `authenticate_durable()`, `require_request_budget()`,
//! `authorize_scoped_resource()` and `authorize_self_hosted_worker_scope()`
//! stayed in `ferrogate-cli` because between them they reach twelve distinct
//! `AppState` accessors. `AppState` is here now, so the residue merged back
//! into [`auth`] and there is exactly one module named `auth` in the
//! workspace again. Its two test files stayed separate files under one module
//! (`auth_test.rs`, `auth_admission_test.rs`) so that neither set of cases had
//! to be renamed to avoid the other's helpers.
//!
//! # `CallerScope` is still owed a move to `ferrogate-core`
//!
//! Recorded in stage 2 and unchanged: `CallerScope` is the one interpreter of
//! "which tenant is this caller, and is it root?" and belongs in
//! `ferrogate-core` next to `TenantContext`, with `UNSCOPED_TENANT_ID`. It is
//! still not moved, and still for the same reason -- it is returned by
//! `AuthContext::caller_scope()` and read by the deciders next to it, so
//! moving it alone splits one vocabulary for no caller that exists yet. It
//! becomes worth doing when `ctl` or the standalone control-api service has to
//! read a caller's scope without depending on this crate. `AuthContext`
//! itself is settled: it travelled with the vocabulary rather than down.
//!
//! # What is NOT here, and should be
//!
//! This crate is now 135k lines and is the blob `ferrogate-cli` used to be,
//! moved. #553 stage 3b bought the crate boundary, not the decomposition:
//! `server/` still holds the Pingora proxy and the ~50-resource Admin API
//! handler surface in one directory, and [`state`] is still one `AppState`
//! with twenty-odd `state_*` submodules hanging off it. Splitting either is a
//! design decision with real answers to argue about, and doing it inside a
//! move-only slice would have made the move unreviewable. It is the next
//! stage's work, and the module names above are the seams to cut along.

/// Certificate lifecycle: ACME issuance/renewal against the configured
/// directory, the on-disk certificate paths, and the renewal scheduler the
/// server starts.
mod acme;

/// Human-in-the-loop tool approval: the `ApprovalStatus` verdict, the approval
/// record, and the mapping onto `ferrogate_runtime::ActionDecision`. That
/// mapping is why the type could not move down alone -- the impl is
/// orphan-rule-legal only where `ApprovalStatus` is local.
mod approval;

/// Asset registry version/variant resolution: semver range and channel
/// resolution over published asset versions, and platform-variant selection.
mod asset_registry;

/// Malware screening for uploaded asset content: the scanner trait, the
/// EICAR/clamd/HTTP backends, and the scanner-unavailable fail-open/closed
/// policy that decides an object's visible scan state.
mod asset_scan;

/// Publisher signature verification for assets: the minisign/ed25519 key
/// registry, the canonical verification manifest, and the signature verdict.
mod asset_signature;

/// Who a caller is, what it may do, and how a presented credential becomes an
/// authorized request: the `AuthContext`/`CallerScope`/`AuthError` vocabulary
/// and its tenant-isolation deciders, the credential primitives, the external
/// auth-service client, and the request-admission pipeline that reads
/// [`state::AppState`].
pub mod auth;

/// The metering usage reporter's HTTP client onto the standalone billing
/// service.
mod billing_client;

/// Bounded request-body reads off a Pingora session.
mod body;

/// Wallet/budget threshold alerting: the webhook payload and its dispatch.
mod budget_alerts;

/// The built-in MCP tools the gateway serves itself, including `fetch_asset`
/// and the asset resource descriptors behind it.
mod builtin_tools;

/// The single-file operator dashboard served from the admin surface.
mod dashboard;

/// Optional gateway extensions and the status they report to the admin
/// surface.
mod extensions;

/// Brokered edge-function egress: the broker config, the invocation token, and
/// the outbound request with its SSRF-guarded resolver.
mod function_egress;

/// The Cloudflare Workers flavour of [`function_egress`]: target-kind
/// selection and the Cloudflare-shaped invocation.
mod function_egress_cloudflare;

/// Configuration validation, reload and graceful-upgrade reporting: the
/// authentication-posture gate `ferrogate check` runs, the admin-triggered
/// reload, and the upgrade handoff. `ferrogate-cli` drives all four of these
/// from its subcommands; the server drives the posture gate at boot.
pub mod lifecycle;

/// The gateway's HTTP adapter over the shared #514 lifecycle gate: the one
/// mapping from `ferrogate_storage`'s refusal onto [`auth::AuthError`].
/// Private, because it publishes no items: a trait impl is reachable wherever
/// both of its types are.
mod lifecycle_gate;

/// Anthropic Messages streaming: OpenAI-chat SSE to a Messages response, a
/// Messages response to Anthropic SSE, and the streaming normalizer.
mod messages_stream;

/// Usage metering export: the exporter and the status it reports.
mod metering;

/// The gateway's own HTTP response vocabulary -- error envelopes, the admin
/// list/pagination shapes, and the JSON bodies the handlers return.
mod responses;

/// OpenAI Responses streaming: the provider-kind discriminator and the
/// streaming normalizer that renders a Responses-shaped SSE sequence.
mod responses_stream;

/// The Pingora service and everything served over it: the proxy filters, the
/// LLM API surfaces (chat/messages/embeddings/images/MCP/A2A), and the
/// Admin/Control API resource handlers.
pub mod server;

/// Supabase repository construction and the inline-or-`$ENV` secret resolver
/// shared by the gateway, the billing service and the auth service.
pub mod service_storage;

/// The control plane the gateway runs over: `AppState`, its storage
/// repositories, and the routing/quota/wallet/asset/agent-runtime subsystems
/// that hang off it.
pub mod state;

/// Analytics and OTLP telemetry: the background senders the server starts and
/// the spans/metrics they ship.
mod telemetry;

/// Token counting for usage accounting and budget enforcement.
mod tokenizer;
