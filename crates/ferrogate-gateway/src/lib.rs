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
//! `ferrogate-cli` grew to **154,329 lines across 200 files -- 36.97% of the
//! 417,477 lines under `crates/`** because it was bin-only and therefore had no
//! API boundary that anything could violate. Measured at **`6145c07`**, the
//! founding measurement already recorded on issue #553, over
//! `crates/ferrogate-cli/src`, with the ref-pinned command at the head of the
//! next section. The old 154,329/200 count was reproducible; only its attached
//! "42%" was false. Stage 1 (`3348868`) was already the first move: adding the
//! library boundary changed the tree to 154,389 lines across 201 files, so it
//! is not the pre-move anchor.
//! Stage 1 of issue #553 gave it a `lib.rs`; stage 2
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
//! **Provenance of the move, corrected here because a commit message cannot
//! be.** Stage 3b (`a772842`) says "146 renames with byte-identical content".
//! 146 is the rename count; the byte-identical count is **93**.
//! `git diff -M --name-status a772842^ a772842` gives 93 `R100` and 53 renames
//! at 93-99% similarity, and the 53 are exactly the files whose `use crate::`
//! lines had to become `use ferrogate_gateway::` or `use ferrogate_config::`
//! for the move to compile at all. Nothing was silently rewritten; the claim
//! was simply stronger than the diff. A reviewer re-deriving the histogram
//! gets 93, and this paragraph is why that is not a discrepancy.
//!
//! # Testing a move this size: `-p ferrogate-gateway` is not enough
//!
//! Every count in this section was taken at **`4c2ba43`**, an ancestor of the
//! commit that last edited it. It names a commit rather than saying "on this
//! tree" because that phrasing went stale three review rounds running: the
//! numbers are true of a tree, and the tree moves. Reproduce with
//!
//! ```text
//! git ls-tree -r --name-only 4c2ba43 -- <dir> | grep '\.rs$' \
//!   | xargs -I{} git show 4c2ba43:{} | wc -l
//! ```
//!
//! and the same pipeline into `wc -l` on the file list for the file count. The
//! ref is in the command as well as in the sentence: this file used to publish
//! `git ls-files '<dir>/*.rs' | xargs cat | wc -l`, which reads the WORKING
//! TREE no matter which commit the number claims to describe, so a reader
//! obeying the instruction beside a ref-pinned figure got a different one --
//! 20,965 and 136,724 at `801b449` against the 20,961 and 136,681 published
//! here. A number pinned to a ref and a command that ignores the ref is the
//! same stale-figure defect one level down, and it is the seam this section
//! exists to close.
//!
//! Two counts below are NOT that command's output and say so where they are
//! made: `crates/ferrogate-cli/tests` is counted over the top level only
//! (`-maxdepth 1`), and the selected/unselected split has its own derivation.
//!
//! Recorded here because it is the instruction a reviewer or a gate gets
//! wrong. The code moved into this crate, so `cargo test -p
//! ferrogate-gateway` looks like the right selector. It is not sufficient:
//! `ferrogate-cli` kept its whole integration-test corpus, which is
//! **41,095 lines across 63 targets in `crates/ferrogate-cli/tests/`** --
//! TARGETS, so the count is the top level of that directory only; the
//! subtree is 64 files and 41,420 lines, the difference being
//! `tests/support/mod.rs` (325 lines), which is a shared helper module every
//! target `mod support;`es and is not a target of its own. Six and a half
//! times the 6,200 lines left in `crates/ferrogate-cli/src/`
//! -- and nearly all of it drives code that now lives here. Those targets
//! belong to the `ferrogate-cli` package and a `-p ferrogate-gateway` run
//! cannot see them, so a verification that omits **`-p ferrogate-cli`** leaves
//! the end-to-end suite for a 136k-line move unexecuted and still reports
//! green.
//!
//! **CI does not close this, and the gap was measured rather than assumed.**
//! `cargo test -p ferrogate-cli` is never run unfiltered anywhere; every
//! workflow names individual targets. Counting the `--test` selectors across
//! all of `.github/workflows/`, **13 of the 63 targets are selected (14,257
//! lines); 50 targets and 26,838 lines are run by no workflow at all** --
//! including `asset_presign_e2e` (3,278), `tenant_isolation_admin_api`
//! (1,703), `control_cli_crud_round_trip_e2e` (1,478) and
//! `config_catalog_scope_admin_api` (1,342). Derived, at `4c2ba43`, by
//! intersecting two lists rather than by any line count: the stems of the 63
//! top-level `.rs` files under `crates/ferrogate-cli/tests/`, and the values
//! matched by `--test[= ]+([A-Za-z0-9_]+)` over every file in
//! `.github/workflows/`, deduplicated. That second list has 14 entries; the
//! extra one is `firecracker_boot_validation`, which is not a `ferrogate-cli`
//! target, which is why 13 and not 14. The line counts are the sums of the two
//! resulting file lists. Several of those need live
//! credentials or a Postgres and could not run on a hosted runner as written,
//! which is a reason the corpus looks the way it does -- but it is not a
//! reason to describe the suite as covered. Anyone verifying a #553 stage by
//! hand should run `-p ferrogate-cli` explicitly, and anyone extending CI
//! should treat this list, not the target count, as the coverage number.
//!
//! **`-p ferrogate-gateway` was run by CI nowhere at all, and now is.** When
//! #553 created this crate, parsing every `package:` matrix key and every
//! `-p <crate>` selector in `.github/workflows/` found five packages no
//! workflow ever named: `ferrogate-gateway`, `ferrogate-cloudflare`,
//! `ferrogate-payments`, `ferrogate-secrets` and `ferrogate-sync-bridge`. For
//! this crate that is **965 `#[test]` plus 105 `#[tokio::test]` -- 1,070 test
//! attributes over 136,681 lines -- with no job that ran them** (counted with
//! the attribute anchored to its own line, `grep -cE '^\s*#\[test\]\s*$'`; the
//! unanchored count is two higher and the two are this paragraph, which is the
//! mistake the figures published before this rework made), including
//! `auth_test.rs`, `server/rbac_test.rs`, `server/guardrail_policies_test.rs`
//! and `tenant_scope_reads_fault.rs`. `scripts/local-test-modules.sh`, the
//! local mirror of the CI slices, had the same gap. #553 created the crate and
//! wiring it into CI was never part of any stage, so this file deferred the
//! job to **#561** on the grounds that adding one whose suite had never been
//! executed here would be asserting a green run nobody had seen.
//!
//! #561 closed it, and closed it the way the deferral asked for: it ran the
//! suite first (**1,067 passed, 0 failed, 0 filtered out**) and then landed
//! `rust-platform-crate-tests.yml`, whose `gateway` slice is
//! `cargo test -p ferrogate-gateway --all-features` with no `--skip`, plus the
//! matching local module. `scripts/check-ci-crate-coverage.py` now fails when
//! a workspace member is selected by nothing, and -- after #553's second
//! rework -- when a `cargo test` name filter matches no test, which is how the
//! #470 conformance runner spent this whole epic passing on zero tests.
//!
//! One qualification that belongs next to the relief: **`ci.yml` triggers only
//! on `release: published`.** No `push`, no `pull_request`, no
//! `workflow_dispatch`. So "run by CI" here means run when a release is cut,
//! not run on the commit that breaks it, and on an ordinary commit the only
//! thing that executes this crate is a developer typing
//! `scripts/local-test-modules.sh platform-crates`. That is the more severe
//! half of #561 and it is not fixed by a job; it is a decision about runner
//! spend recorded in `ci.yml` itself.
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
//! The result, exactly: **22 bare-`pub` item declarations in 136,681 lines**
//! -- five `pub mod` here, `server::assets`, and sixteen items -- against
//! **1,317 item declarations that are `pub(crate)` or narrower**. (Both
//! re-counted at `4c2ba43`, item declarations only: a `pub(crate)` struct
//! *field* is not an item and is not counted, which is why this number moves
//! when a struct does. Counting raw `pub`/`pub(` line starts instead gives
//! 115 and 3,139, so the rule is load-bearing rather than decorative. The
//! earlier "1,301" was measured a few commits back.)
//! What `ferrogate-cli` names is the whole of it,
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
//! Stage 4 removed the other half of that confusion: the crate formerly named
//! `ferrogate-auth` is now `ferrogate-auth-service`. It is the standalone
//! identity SERVICE this crate talks to over HTTP (and the home of SSO/SAML/
//! SCIM and the admin-console session API); [`auth`] is the *request
//! authenticator*. One word used to name both, in every import line in this
//! file.
//!
//! # `CallerScope` stays here, re-checked in stage 4
//!
//! Stage 2 recorded that `CallerScope` -- the one interpreter of "which tenant
//! is this caller, and is it root?" -- belongs in `ferrogate-core` next to
//! `TenantContext`, with `UNSCOPED_TENANT_ID`, and named the trigger: when
//! `ctl` or the standalone control-api service has to read a caller's scope
//! without depending on this crate. Stage 4 tested that trigger against the
//! finished split and it is not met. The control-api service
//! (`ferrogate-cli`'s `admin_api.rs`) authenticates at the edge through
//! [`auth::authenticate_admin_gate`] and forwards, deliberately leaving this
//! crate the single enforcement authority for tenant scoping; it never asks
//! the scope question. `ctl` speaks to the Control Plane API over HTTP and has
//! no caller to scope. Every use of `CallerScope` on the current tree is in
//! this crate, and the type is still `pub(crate)`. Counted rather than
//! estimated, because this is the number a future reader re-checks; at
//! `4c2ba43`, skipping lines that are wholly comment:
//! **35 occurrences in code across 7 files, 39 counting `UNSCOPED_TENANT_ID`
//! (8 files), and 12 files in this crate mention the type at all.** The only
//! file outside this crate that names it is `ferrogate-core`'s prose. (Stage
//! 4 wrote "~25 uses across 11 files"; that was an estimate carried forward,
//! and it was low.)
//!
//! So the move stays unmade, and now for a measured reason rather than a
//! deferred one: it would publish a `pub` type with no external reader, and
//! separate the enum from its only producer (`AuthContext::caller_scope()`,
//! which carries `EffectiveQuota`/`PolicySubject` and so cannot follow it
//! down) and from the deciders beside it. Re-test the trigger, not the
//! calendar: the day a crate that must NOT depend on `ferrogate-gateway` needs
//! the answer, move the enum and the sentinel together. `AuthContext` itself
//! is settled: it travelled with the vocabulary rather than down.
//!
//! # What is NOT here, and should be
//!
//! This crate is now 136,681 lines (at `4c2ba43`, as everywhere in this file
//! except the `3348868` figure at the top) and is the blob `ferrogate-cli` used to be,
//! moved. #553 stage 3b bought the crate boundary, not the decomposition:
//! `server/` still holds the Pingora proxy and the ~50-resource Admin API
//! handler surface in one directory, and [`state`] is still one `AppState`
//! with twenty-odd `state_*` submodules hanging off it. Splitting either is a
//! design decision with real answers to argue about, and doing it inside a
//! move-only slice would have made the move unreviewable. It is the next
//! stage's work, and the module names above are the seams to cut along.
//!
//! Two things #560 should NOT inherit as settled, written here because this
//! is the file its reader opens:
//!
//! 1. **#553's stop condition cannot see the defect that remains.** It was
//!    written as a measurement of `ferrogate-cli`, so it goes green when this
//!    crate absorbs the blob. Measured at `4c2ba43` (`.rs` lines in
//!    git-tracked files under `crates/`): `ferrogate-gateway` is
//!    **136,681 of 436,483 lines, 31.3%** -- down from `ferrogate-cli`'s
//!    pre-#553 share, but still the largest single crate by a factor of
//!    1.84 over `ferrogate-storage`'s 74,466. "One crate holds a third of the
//!    workspace" is a real defect and #553's own objective test is blind to
//!    it. #560's success criterion should measure *concentration*, not one
//!    crate's name.
//! 2. **`ferrogate-config` now exports data-plane primitives.** Five of them,
//!    `pub` on the crate everything depends on: `resolve_client_ip`, `IpCidr`
//!    and `UnauthenticatedIpRateLimiter` from `config::network_access`, and
//!    `build_target_uri` and `normalize_host` from `config::routing`. The last
//!    two are the ones an earlier round of this handoff left out, and they are
//!    the clearest case of the five -- both are read only by
//!    `ferrogate-gateway`'s `server::handlers` and `server::site_domains`,
//!    i.e. by the request path, and neither is consulted while a config file
//!    is being loaded or validated. `pub` is the forced minimum given their
//!    current placement -- each has a cross-crate reader -- but the placement
//!    itself is a leftover of stage 3a, not a decision. The reasoning is
//!    recorded next to both exports in `ferrogate-config`'s `lib.rs`.

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

/// Server authority for action-bound time tokens carried by CLI requests.
mod client_action_time;

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

/// Typed physical-model requirement filtering and request-correlated routing
/// evidence (issue #582).
mod model_routing;

/// The gateway's own HTTP response vocabulary -- error envelopes, the admin
/// list/pagination shapes, and the JSON bodies the handlers return.
mod responses;

/// OpenAI Responses streaming: the provider-kind discriminator and the
/// streaming normalizer that renders a Responses-shaped SSE sequence.
mod responses_stream;

/// Typed terminal outcome of a streamed provider response: how the stream
/// actually ended, which side broke it, and whether the client had already been
/// given bytes -- the replay boundary the durable evidence records (issue #571).
mod stream_terminal_outcome;

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

/// The control-plane read seam the tenant-scope resolvers go through (#543):
/// the reads `rbac_catalog_scope` and `authorize_scoped_resource` make to
/// decide how much of a catalog a caller may see, implemented once for
/// [`state::AppState`] and once, under `#[cfg(test)]`, by a store whose
/// individual reads can be armed to FAIL. Without it, the failure branch of a
/// scope decision -- the branch that must never degrade to an unfiltered
/// catalog -- is unreachable from any test.
mod tenant_scope_reads;

/// Token counting for usage accounting and budget enforcement.
mod tokenizer;
