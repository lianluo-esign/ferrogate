// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Client action identity: what the CLI sends about *itself* on every request
//! it issues, so an operator action is traceable to when and where it was made
//! (issue #548).
//!
//! # The half this closes
//!
//! #505 built the **response** side: [`crate::receipt::MutationReceipt`] renders
//! actor, target fingerprint, decision and outcome for every mutating verb, and
//! honestly reports `audit_id: null` because **none of the 135 mutating
//! operations in the contract returns an audit identifier**. The CLI could not
//! surface a correlation handle because nothing gave it one.
//!
//! This module mints the handle at the client and sends it. That is what makes
//! the two ends join: a client-generated [`ActionId`] on the request is
//! correlatable without waiting for a server-side audit-write path, which #505
//! declared out of scope and this issue declares out of scope again.
//!
//! # The three decisions, recorded
//!
//! ## 1. `action_id` is NOT the idempotency key
//!
//! They answer different questions and must not be merged:
//!
//! | | `action_id` | `idempotency_key` |
//! |---|---|---|
//! | question | "which operator action was this?" | "may this effect be applied again?" |
//! | scope | every request the invocation issues, reads included | one mutating request |
//! | minted by | this module, once per invocation | the caller, in the request document |
//! | coverage | universal (transport chokepoint) | only `billing` and `agent submit` today |
//! | on retry | **same** value — the retry is the same action | same value — that is its whole point |
//! | if absent | the action is untraceable | the effect may be applied twice |
//! | server may ignore it | yes, and does today | no, it is a correctness input |
//!
//! The overlap ("stable across retries") is why conflating them is tempting and
//! why it would hurt. An `--all-pages` walk issues up to 10 000 GETs under ONE
//! `action_id` and no idempotency key at all; a `billing` POST re-run by a shell
//! loop is two *different* actions carrying the *same* idempotency key, and an
//! audit trail that could not tell those apart would report one action where an
//! operator made two. Both fields are therefore carried, separately, and
//! [`crate::receipt::MutationReceipt`] renders both.
//!
//! ## 2. The fingerprint field set, and its privacy cost
//!
//! A hostname, a username or an IP is PII in some deployments and this reaches
//! the audit log of a multi-tenant control plane, so the field set is chosen by
//! subtraction rather than by collection:
//!
//! The third column used to read "verbatim" for every row. Since #548 that is
//! no longer true of the spelling: every field goes through
//! [`encode_header_value`] first, so the two operator-supplied fields — the only
//! ones that can contain anything outside `[A-Za-z0-9._~:/-]` — arrive
//! percent-escaped. It is a reversible spelling and **not** a digest, so a
//! privacy review should still read every row as "disclosed in full"; the column
//! now says so without claiming a byte-for-byte copy it does not make.
//!
//! | field | value | on the wire | default |
//! |---|---|---|---|
//! | `cli` | [`crate::version::CLI_VERSION`] | not hashed; percent-encoded (a fixed point today) | always |
//! | `os` | `std::env::consts::OS` | not hashed; percent-encoded (a fixed point today) | always |
//! | `arch` | `std::env::consts::ARCH` | not hashed; percent-encoded (a fixed point today) | always |
//! | `context` | the resolved context/profile name | not hashed; **percent-encoded**, operator-supplied | always, when one was selected |
//! | `cred` | [`AuthSource::audit_source`] (`env:VAR`, `stdin`, `inline`, `none`) | not hashed; percent-encoded (`:` is in the safe set, so `env:VAR` is unchanged) | always |
//! | `host` | an operator-supplied label, [`HOST_LABEL_ENV`] | not hashed; **percent-encoded**, operator-supplied | **opt-in, off** |
//! | client-reported IP | an operator-supplied address, [`REPORTED_IP_ENV`] | not hashed; **percent-encoded** (a dotted-quad or an IPv6 literal is a fixed point) | **opt-in, off** |
//!
//! **Nothing is hashed, because nothing collected needs to be.** A hash is the
//! right answer when a value must be *joinable but not readable*; every value
//! above is either non-identifying (build, platform, credential *source*) or
//! supplied by the operator on purpose. Hashing an operator-chosen label would
//! destroy its only purpose while leaving it just as re-identifiable by anyone
//! holding the candidate list.
//!
//! **The hostname is not detected.** The obvious candidate — read the machine's
//! hostname — is refused: it is the highest-PII field on the list, it is
//! collected without the operator ever deciding to disclose it, and in a
//! multi-tenant control plane it names the tenant's internal estate to whoever
//! reads the audit stream. What replaces it is [`HOST_LABEL_ENV`]: an
//! **operator-supplied** string, absent unless set, which may be a pseudonym, a
//! CI job id, or a real hostname — the operator's choice, made once, in their
//! own configuration.
//!
//! **The opt-out is the default, so the audit guarantee never depends on it.**
//! Because `host` and the reported IP start off, no part of the correlation
//! guarantee rests on them: `action_id` is always present, and *where* an action
//! came from is answered authoritatively by the **server-observed source IP**,
//! which no client can suppress. Opting in adds evidence; opting out removes
//! none that the server did not already hold. This is deliberate — an
//! opt-out that could blind an audit trail is not an opt-out, it is a hole.
//!
//! **The client is not the authority on its own IP.** It cannot reliably know
//! its public address, and anything it says is self-asserted and trivially
//! forged. So [`REPORTED_IP_ENV`] rides its own header,
//! [`CLIENT_REPORTED_IP_HEADER`], whose name says `client-reported`; it is never
//! folded into the fingerprint blob and must never be merged with the address
//! the server observes. Recording a self-reported IP as fact in a security-audit
//! trail is a false record, which is worse than an absent one.
//!
//! **No secret material, ever.** `cred` is the *source shape*
//! ([`AuthSource::audit_source`]), never the token — the same rule
//! [`crate::receipt`] already follows, and the same live defect class as #489,
//! #492 and #537.
//!
//! ## 3. Headers, not body
//!
//! Four reasons, in order of weight:
//!
//! 1. **Uniformity.** A read is also "what this CLI did", and a `GET`/`DELETE`
//!    has no body to put a field in. Headers are the only carrier that covers
//!    every verb, which is what makes the chokepoint total.
//! 2. **135 request schemas stay untouched.** A body field would have to be
//!    added to each, would collide with any resource that already spells a
//!    property `action_id`, and would be echoed back by create endpoints as if
//!    it were resource state.
//! 3. **The body is the operator's document.** [`crate::receipt::CliActionTarget`]
//!    fingerprints the request the transport sends; injecting client metadata
//!    into the body would make the audited document differ from the one the
//!    operator wrote.
//! 4. **The precedent already exists.** `x-ferrogate-tenant`,
//!    `x-ferrogate-skill-package` and the correlation ids are all headers.
//!
//! The cost, stated: ~250 bytes per request, and an intermediary that strips
//! unknown headers drops the attribution silently. Persisting the fields
//! server-side (where a body field would be easier) is the explicit non-goal.
//!
//! # The timestamp: server-issued, client-echoed, and a client reading beside it
//!
//! The owner's instruction is that the audit timestamp comes **from the server**
//! and is carried by the client, so a skewed or hostile client clock cannot
//! backdate an action. This module implements exactly that and adds one field
//! next to it:
//!
//! * [`ServerIssuedTime`] — parsed from a server-issued token, echoed verbatim.
//!   It is the value that reaches `client_sent_at`. **There is no code path from
//!   the local clock to this type**: it has no constructor taking an instant,
//!   only [`ServerIssuedTime::parse`].
//! * [`ClientClockReading`] — the client's own reading, in its own field, under
//!   a header whose name ends in `-unverified`. It is *evidence about the
//!   client*, never an input to ordering or authorization. The wrapper is not
//!   `Ord`, which stops a `sort()` on a collection of readings, but that is a
//!   speed bump and not a barrier: [`ClientClockReading::unverified_unix_seconds`]
//!   hands out a bare `u64` that compares like any other. The real barrier is
//!   the name — of the accessor, of the header, and of the receipt field — and
//!   it is stated here rather than dressed up as a type-level guarantee.
//!
//! **Why both (the hybrid).** One field cannot express clock skew. The
//! server-issued token proves when the *server* issued it; the client reading
//! proves what the *operator's machine* believed at the same moment. Their
//! difference is the finding — a host running hours behind, a suspended VM, a
//! deliberately backdated workstation — and it is invisible if only one of the
//! two is recorded. They are two authorities and are never merged, the same rule
//! as the two IPs.
//!
//! ## How the token is obtained, and what it costs
//!
//! **Piggy-back, never a preflight.** [`ClientActionIdentity::accept_server_time`]
//! harvests a token from any response that carries [`TIME_TOKEN_HEADER`], and
//! the next request of the same action presents it. The steady-state extra
//! round-trip cost is therefore **zero**: no `POST /v1/audit/time-token` is ever
//! issued, and the first request of an invocation simply has no token yet.
//!
//! **A cross-invocation cache was evaluated and rejected.** The TTL must be
//! seconds (otherwise an attacker pre-fetches tokens and replays them later to
//! backdate an action), and a CLI process lives for less than one command. A
//! token cached on disk between invocations is expired before the operator types
//! the next command, so it buys nothing and leaves a token at rest. What that
//! leaves is honest and measurable:
//!
//! | invocation shape | requests | requests carrying a server time |
//! |---|---|---|
//! | single-request verb (the common case) | 1 | 0 |
//! | `--all-pages` walk of N pages | N | N − 1 |
//! | any multi-request verb | N | N − 1 |
//!
//! **And what that N−1 is worth on a receipt today: nothing.** The table above
//! describes requests on the wire. A [`crate::receipt::MutationReceipt`] is
//! rendered only for a *mutating* verb, every mutating verb is a single request
//! (`--all-pages` is refused on a mutating method), and a token can only arrive
//! *with a response* — so the request that produces a receipt is always the
//! action's first, and `client_sent_at` on a receipt is structurally `null`.
//! The N−1 saving lands on reads, which produce no receipt. The
//! `(true, Some(_))` arm of [`crate::receipt::MutationPlan::client_identity`] is
//! therefore production-dead until the server issues tokens *and* something
//! makes a mutating verb the second request of an action; it is implemented and
//! tested anyway, because the alternative is discovering the shape only once a
//! server starts issuing.
//!
//! **Nothing issues a time token today.** No FerroGate deployment mints
//! [`TIME_TOKEN_HEADER`]: the issuing endpoint is server-side work this issue
//! defers, and the contract declares the header on zero responses (pinned by
//! `no_operation_yet_issues_a_server_time_token`, the same shape as
//! `tenant_scope_is_not_yet_an_openapi_parameter`). So in every deployment that
//! exists, every receipt reports `client_sent_at: null` with
//! [`crate::receipt::absence_codes::NO_SERVER_TIME_TOKEN`]. Said here, in
//! `docs/cli-audit-attribution.md`, and on the receipt itself, rather than left
//! for an operator to infer from a null.
//!
//! When no token is held, `client_sent_at` is `null` **with a stated reason**
//! ([`crate::receipt::absence_codes::NO_SERVER_TIME_TOKEN`]) — not backfilled
//! from the local clock. That is the point of the whole design, and it is why
//! the absence is a finding rather than a silence.
//!
//! **The narrower guarantee, stated.** A server-issued token proves when the
//! *server issued it*, not when the operator ran the command. It is bounded from
//! the other side by the server's own receive time, which the server records
//! without asking the client. Issued-time and receive-time together bound the
//! action; either alone can be gamed or delayed.
//!
//! ## Refusals
//!
//! [`ServerIssuedTime::accept_for`] refuses a token that is not this action's:
//!
//! * **Action-id mismatch** — refused unconditionally. This is the refusal that
//!   matters and the only one a client can make *without* trusting a clock, so
//!   it is the one that is authoritative here: a token minted for action A
//!   cannot be moved onto action B.
//! * **Outside its TTL, by more than [`CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS`]** —
//!   refused as a courtesy, judged against [`ClientClockReading`], which is by
//!   construction untrusted. **The authoritative TTL refusal is the server's**,
//!   against its own clock; this one exists only so the grossly-wrong case fails
//!   locally instead of on the wire.
//!
//!   The allowance is the correction of a defect this design shipped with. The
//!   reading is taken once, at [`ClientActionIdentity::mint`], and frozen for
//!   the invocation. A token the server issues one second later therefore has
//!   `issued_at > now` against that frozen reading, and a bare
//!   `now < issued_at` check called it "from the future" and dropped it — as it
//!   dropped *every* token under any positive server-minus-client skew, and any
//!   invocation that crossed a second boundary. The whole premise of the design
//!   is that the audit instant does not depend on the client clock; a check that
//!   consults the client clock with zero tolerance reintroduces the dependence
//!   and fails closed *against the feature*. So both ends now carry an explicit
//!   allowance, wide enough to cover the invocation's own duration and
//!   ordinary NTP-scale skew, and the check is documented as what it is: a
//!   filter for the absurd, not a validity decision.
//!
//! # Enforcement: a compile error, not a lint
//!
//! [`crate::receipt::RenderGate`] is the precedent, and this follows it:
//!
//! 1. [`ClientActionIdentity`] has **private fields and no public struct
//!    literal**. The only way to obtain one outside this module is
//!    [`ClientActionIdentity::mint`], which fills every field.
//! 2. [`crate::transport::prepare_request`] takes `&ClientActionIdentity` as a
//!    **required parameter**. A request cannot be built without one.
//! 3. [`crate::transport::PreparedRequest`]'s fields are `pub(crate)`, so no
//!    crate outside `ferrogate-control-plane-client` can construct one — and
//!    [`crate::transport::Transport::execute`] accepts nothing else. Every byte
//!    the CLI puts on the wire through this stack therefore came out of
//!    `prepare_request`, which had an identity in hand.
//!
//! Writing a new verb that issues a request without the identity is a type
//! error, not a review finding.
//!
//! ## The second chokepoint, and why there are two
//!
//! [`crate::transport::Transport`] is not the only way this repo puts bytes on
//! the wire. `ferrogate-cli`'s `assets` and `plans` command groups predate the
//! typed client and drive a hand-rolled raw-`TcpStream` HTTP client
//! (`ferrogate_cli::assets_cli::send_request`) rather than `reqwest`, because
//! `ferrogate-cli`'s `main()` is a synchronous entry point. Between them they
//! issue seven requests, four of which are **mutations** (`plans create` POSTs
//! `/admin/v1/plans`, `plans assign` PATCHes `/admin/v1/tenant-accounts/{id}`,
//! `assets push` PUTs and `assets delete` DELETEs an asset) and three of which
//! are reads (`assets pull`, `assets list`, `plans list`) — and this issue asks
//! for reads too. The first two are Control Plane mutations with no registry
//! family to route through instead.
//!
//! So `send_request` takes `&ClientActionIdentity` as a **required argument**,
//! for exactly the reason [`crate::transport::prepare_request`] does: it is the
//! single function that materializes those requests, and a required argument of
//! an un-forgeable type is a compile error rather than a convention. It writes
//! [`ClientActionIdentity::headers`] into the raw request line-by-line, which is
//! why [`encode_header_value`] escapes CR and LF rather than deleting them:
//! there is no `http::HeaderValue` between that string and the socket.
//!
//! The boundary that remains, named rather than implied. Two originating
//! requests still go out unattributed, and both are outside this slice:
//!
//! * **`ferrogate reload --admin-url …`** mutates a running gateway's live
//!   config through a *third* hand-rolled raw-TCP client, which lives in
//!   `ferrogate_gateway::lifecycle` rather than in `ferrogate-cli` — a crate
//!   this one must not depend on. Closing it means giving that function an
//!   identity argument too, which is a `ferrogate-gateway` change and is
//!   follow-up work, not a silence. It is the same command
//!   [`crate::receipt`]'s own scope section already names as receiptless.
//! * **`ferrogate storage migrate-to-supabase`** talks to PostgreSQL, not HTTP,
//!   and carries no header at all.
//!
//! `ferrogate admin-api`'s upstream socket is deliberately *not* on that list:
//! it is a reverse proxy relaying the admin console's request, and minting an
//! `action_id` there would record the console's action against the proxy
//! process. The proxy relays the caller's own `x-ferrogate-*` headers untouched
//! (they are not hop-by-hop, and the forward loop passes them through) — **but
//! the admin console sends none today**, so a console mutation reaching the
//! control plane through it is unattributed. That is console-side work, outside
//! this slice, and it is written down here and on the operator page rather than
//! presented as solved by the relay.
//!
//! Within `ferrogate-cli` the set is closed and checked: a source guard
//! (`every_outbound_http_call_goes_through_an_attributed_chokepoint`) holds an
//! allow-list of every `TcpStream::connect*` **and every `reqwest` client** in
//! that crate, so a fourth hand-rolled client there is a red test rather than a
//! silent hole. `reqwest` is on the needle list because it is already a declared
//! direct dependency of `ferrogate-cli` and was therefore a bypass requiring no
//! manifest change. The guard scans `crates/ferrogate-cli/src` and says so; it
//! does not and cannot speak for `ferrogate-gateway`, and a client from a crate
//! not yet in the manifest would need a `Cargo.toml` edit to exist at all.

use std::sync::{Arc, Mutex};

use crate::auth::AuthSource;
use crate::context::EffectiveContext;
use crate::error::{CliError, CliResult};

/// Header carrying the client-minted [`ActionId`].
pub const ACTION_ID_HEADER: &str = "x-ferrogate-action-id";

/// Header carrying the rendered [`ClientFingerprint`].
pub const CLIENT_FINGERPRINT_HEADER: &str = "x-ferrogate-client-fingerprint";

/// Header carrying the client's OWN clock reading.
///
/// The `-unverified` suffix is load-bearing: it is the one word standing
/// between this value and a downstream sink that treats it as the event time.
pub const CLIENT_CLOCK_HEADER: &str = "x-ferrogate-client-clock-unverified";

/// Header carrying the echoed [`ServerIssuedTime`] — the authoritative
/// `client_sent_at`. Present only when the server has issued one.
pub const TIME_TOKEN_HEADER: &str = "x-ferrogate-time-token";

/// Header carrying an operator-supplied, **client-asserted** address. Never to
/// be merged with the source IP the server observes.
pub const CLIENT_REPORTED_IP_HEADER: &str = "x-ferrogate-client-reported-ip";

/// Environment variable an operator sets to disclose a machine label. Absent by
/// default; see the module docs for why the hostname is not detected.
///
/// It is an environment variable and **not a clap flag**, so it cannot appear in
/// the generated `docs/cli-reference.md`, which is derived from the command
/// tree. It is documented by hand in `docs/cli-audit-attribution.md`, and
/// `the_opt_in_variables_are_documented_where_an_operator_will_find_them` pins
/// that so the two cannot drift.
pub const HOST_LABEL_ENV: &str = "FERROGATE_CLIENT_HOST_LABEL";

/// Environment variable an operator sets to report a client-side address.
/// Documented by hand in `docs/cli-audit-attribution.md`, for the same reason as
/// [`HOST_LABEL_ENV`].
pub const REPORTED_IP_ENV: &str = "FERROGATE_CLIENT_REPORTED_IP";

/// Prefix every minted [`ActionId`] carries, so a value is recognizable in a
/// log line without a schema.
pub const ACTION_ID_PREFIX: &str = "fgact_";

/// Hex characters in the random part of an [`ActionId`] (128 bits).
const ACTION_ID_HEX_LEN: usize = 32;

/// Schema marker leading every rendered fingerprint and time token, so a
/// consumer can refuse a shape it does not know instead of guessing.
pub const IDENTITY_SCHEMA_VERSION: &str = "v1";

/// The exact, ordered key set a [`ClientFingerprint`] declares. Pinned by a
/// test: a field added or removed without updating this list fails, which is
/// what makes "no secret material is in the fingerprint" checkable rather than
/// re-audited by a reader on every change.
pub const FINGERPRINT_FIELDS: [&str; 7] = [
    "cli",
    "os",
    "arch",
    "context",
    "cred",
    "host",
    "client_reported_ip",
];

/// Value recorded as the authority of a `client_sent_at`, so the serialized
/// receipt states where the instant came from instead of leaving it to a
/// reader's assumption.
pub const SERVER_TIME_AUTHORITY: &str = "server_issued_time_token";

/// How far outside its declared window a server-issued token may still be
/// accepted by the **client's** courtesy check.
///
/// Judged against [`ClientClockReading`], which is frozen at
/// [`ClientActionIdentity::mint`] and untrusted by construction. Five minutes
/// covers three things at once: the invocation's own duration (the reading is
/// older than every token the invocation harvests), ordinary NTP-scale skew
/// between the operator's machine and the control plane, and a second boundary
/// crossed between minting and the first response. Without it a token issued
/// one second into the invocation reads as "from the future" and is silently
/// dropped — which is the design failing closed against itself, since the whole
/// premise is that the audit instant does not depend on the client clock.
///
/// It is deliberately loose. **The authoritative TTL decision is the server's**,
/// against its own clock; this bound exists to catch the absurd (a token a day
/// stale) locally instead of on the wire, and nothing rests on it.
///
/// # The residual, stated rather than implied
///
/// This widens the symptom; it does not remove the cause. The comparison is
/// still made against a reading frozen at [`ClientActionIdentity::mint`], so
/// skew — or an invocation duration — beyond five minutes still refuses **every**
/// token, on exactly the hosts the design names as its target: "a host running
/// hours behind, a suspended VM, a backdated workstation". A machine an hour out
/// gets no `client_sent_at` at all, and the refusal is an `eprintln!` on stderr
/// rather than anything the receipt distinguishes from "no token was issued".
///
/// The honest fix is to stop judging a server-issued token against a client
/// clock the design already declares untrusted — the server's `ttl` is the
/// authority, and this check earns its place only by catching the absurd. That
/// is a change to what `accept_for` refuses, not to this number, and it is
/// deferred rather than done. `docs/cli-audit-attribution.md` says so where an
/// operator will read it.
pub const CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS: u64 = 300;

// ---------------------------------------------------------------------------
// Action id.
// ---------------------------------------------------------------------------

/// The identifier of one operator action: minted once per invocation, sent on
/// every request that invocation issues, reads included.
///
/// Private field: outside this module the only way to obtain one is
/// [`ActionId::mint`], so an id cannot be fabricated or copied off another
/// action.
#[derive(Clone, PartialEq, Eq)]
pub struct ActionId(String);

impl ActionId {
    /// Mint a fresh id from the OS CSPRNG.
    ///
    /// Fails loudly when the CSPRNG is unavailable rather than falling back to
    /// the clock or a counter: a predictable action id is worse than an absent
    /// one, because it can be claimed by someone else's log line.
    pub fn mint() -> CliResult<ActionId> {
        let mut bytes = [0u8; ACTION_ID_HEX_LEN / 2];
        getrandom::getrandom(&mut bytes).map_err(|error| {
            CliError::usage(format!(
                "could not mint an action id: the OS random source is unavailable ({error}); \
                 refusing to issue a request that cannot be audited"
            ))
        })?;
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(ActionId(format!("{ACTION_ID_PREFIX}{hex}")))
    }

    /// The wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `value` has the shape [`ActionId::mint`] produces: the prefix plus
/// exactly [`ACTION_ID_HEX_LEN`] lowercase hex characters.
pub fn is_well_formed_action_id(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(ACTION_ID_PREFIX) else {
        return false;
    };
    hex.len() == ACTION_ID_HEX_LEN
        && hex
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

impl std::fmt::Debug for ActionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ActionId({})", self.0)
    }
}

impl std::fmt::Display for ActionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Client clock reading — evidence about the client, never the event time.
// ---------------------------------------------------------------------------

/// The client's own clock, read once per invocation.
///
/// Not `Ord`/`PartialOrd`, which stops `sort()` on a collection of readings and
/// makes a comparison of two of them a deliberate act. That is a speed bump and
/// **not** a barrier, and it is worth saying so instead of over-claiming:
/// [`ClientClockReading::unverified_unix_seconds`] returns a bare `u64` that
/// compares like any other integer, so anyone who wants to order by this value
/// can, in one expression.
///
/// What actually guards the value is naming, in three places a reader cannot
/// miss: the accessor says `unverified`, the header
/// ([`CLIENT_CLOCK_HEADER`]) ends in `-unverified`, and the receipt field is
/// `client_clock_unverified_unix`. It is not `Serialize` either, so it cannot be
/// serialized anonymously into some other struct's field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientClockReading {
    unix_seconds: u64,
}

impl ClientClockReading {
    /// Read the local clock. **The only place in this crate that does.**
    ///
    /// Named for what it is so a reader of a call site knows an untrusted value
    /// was produced. `client_reading_is_the_only_local_clock_read` pins that
    /// this is the sole `SystemTime::now()` in the client stack, which is what
    /// stops the audit timestamp quietly reverting to the client clock.
    pub fn read_local_clock() -> ClientClockReading {
        let unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            // A clock set before 1970 is itself the finding, and 0 records it
            // without pretending the reading is usable.
            .unwrap_or(0);
        ClientClockReading { unix_seconds }
    }

    /// Build a reading from a known value. Test-only: production code must go
    /// through [`ClientClockReading::read_local_clock`] so the source-guard test
    /// can see every clock read.
    #[cfg(test)]
    pub fn from_unix_seconds(unix_seconds: u64) -> ClientClockReading {
        ClientClockReading { unix_seconds }
    }

    /// The reading, in seconds since the Unix epoch. Named `unverified` at
    /// every use site on purpose.
    pub fn unverified_unix_seconds(&self) -> u64 {
        self.unix_seconds
    }

    /// The header value.
    pub fn render(&self) -> String {
        self.unix_seconds.to_string()
    }
}

// ---------------------------------------------------------------------------
// Server-issued time.
// ---------------------------------------------------------------------------

/// Why a time token was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeTokenRefusal {
    /// The token did not parse: wrong schema marker, missing field, or a
    /// non-numeric instant.
    Malformed(String),
    /// The token was issued for a different action. Refused unconditionally —
    /// this check needs no clock, so it is the one the client can make
    /// authoritatively.
    ActionIdMismatch {
        issued_for: String,
        presented_for: String,
    },
    /// The token is outside its TTL by the client's own (untrusted) reading.
    /// The authoritative refusal is the server's.
    Expired {
        issued_at_unix: u64,
        ttl_seconds: u64,
        client_reading_unix: u64,
    },
}

impl TimeTokenRefusal {
    /// A stable code an audit consumer can select on.
    pub fn code(&self) -> &'static str {
        match self {
            TimeTokenRefusal::Malformed(_) => "time_token_malformed",
            TimeTokenRefusal::ActionIdMismatch { .. } => "time_token_action_id_mismatch",
            TimeTokenRefusal::Expired { .. } => "time_token_expired",
        }
    }
}

impl std::fmt::Display for TimeTokenRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeTokenRefusal::Malformed(detail) => {
                write!(f, "server time token is malformed: {detail}")
            }
            TimeTokenRefusal::ActionIdMismatch {
                issued_for,
                presented_for,
            } => write!(
                f,
                "server time token was issued for action {issued_for} but this action is \
                 {presented_for}; a token cannot be moved onto another action"
            ),
            TimeTokenRefusal::Expired {
                issued_at_unix,
                ttl_seconds,
                client_reading_unix,
            } => write!(
                f,
                "server time token issued at {issued_at_unix} with a {ttl_seconds}s TTL is \
                 outside its window by the client's own (unverified) reading \
                 {client_reading_unix}"
            ),
        }
    }
}

/// A time the **server** issued, bound to one [`ActionId`], echoed verbatim by
/// the client.
///
/// There is deliberately no constructor taking an instant: the only way to
/// obtain one is [`ServerIssuedTime::parse`] over bytes the server sent. That
/// is what makes "the CLI never reads its own clock for the audit timestamp" a
/// property of the type rather than of a convention.
///
/// Wire shape (one header value, no allocation-heavy encoding):
/// `v1;issued_at=<unix secs>;ttl=<secs>;action_id=<id>;sig=<opaque>`
///
/// `sig` is carried verbatim and **never validated here**: only the server holds
/// the key, so a client-side "validation" would be theatre. Its presence is
/// checked so a token stripped of its signature is refused as malformed rather
/// than accepted as an unsigned claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIssuedTime {
    issued_at_unix: u64,
    ttl_seconds: u64,
    action_id: String,
    signature: String,
    /// The token exactly as the server sent it. Held so [`ServerIssuedTime::render`]
    /// can echo it *verbatim* instead of reconstructing it from the parsed
    /// fields — a reconstruction drops the unknown segments [`ServerIssuedTime::parse`]
    /// deliberately tolerates, so the first forward-compatible field the server
    /// adds would silently invalidate every echoed token's signature.
    raw: String,
}

impl ServerIssuedTime {
    /// Parse a token from [`TIME_TOKEN_HEADER`].
    pub fn parse(raw: &str) -> Result<ServerIssuedTime, TimeTokenRefusal> {
        // The token is echoed back onto the wire verbatim, including through
        // `assets_cli::send_request`, which writes header lines into a socket
        // with no `http::HeaderValue` in between. A byte outside the printable
        // ASCII range is therefore either a request-splitting attempt or a
        // token no HTTP stack would accept; refuse it here, where the refusal
        // is a coded diagnostic, rather than at `.send()` as a builder error.
        if let Some(offending) = raw.chars().find(|ch| !matches!(*ch as u32, 0x20..=0x7E)) {
            return Err(TimeTokenRefusal::Malformed(format!(
                "token carries {offending:?}, which no HTTP header value may hold"
            )));
        }
        let mut parts = raw.split(';');
        let version = parts.next().unwrap_or_default().trim();
        if version != IDENTITY_SCHEMA_VERSION {
            return Err(TimeTokenRefusal::Malformed(format!(
                "expected schema '{IDENTITY_SCHEMA_VERSION}', got '{version}'"
            )));
        }
        let mut issued_at: Option<u64> = None;
        let mut ttl: Option<u64> = None;
        let mut action_id: Option<String> = None;
        let mut signature: Option<String> = None;
        for part in parts {
            let Some((key, value)) = part.split_once('=') else {
                return Err(TimeTokenRefusal::Malformed(format!(
                    "segment '{part}' is not key=value"
                )));
            };
            match key.trim() {
                "issued_at" => issued_at = value.trim().parse::<u64>().ok(),
                "ttl" => ttl = value.trim().parse::<u64>().ok(),
                "action_id" => action_id = Some(value.trim().to_string()),
                "sig" => signature = Some(value.trim().to_string()),
                // An unknown segment is ignored rather than refused, so the
                // server can add a field without breaking older clients.
                _ => {}
            }
        }
        let issued_at_unix = issued_at.ok_or_else(|| {
            TimeTokenRefusal::Malformed("missing or non-numeric issued_at".to_string())
        })?;
        let ttl_seconds = ttl
            .ok_or_else(|| TimeTokenRefusal::Malformed("missing or non-numeric ttl".to_string()))?;
        let action_id = action_id
            .ok_or_else(|| TimeTokenRefusal::Malformed("missing action_id".to_string()))?;
        let signature = signature
            .filter(|signature| !signature.is_empty())
            .ok_or_else(|| TimeTokenRefusal::Malformed("missing sig".to_string()))?;
        if action_id.is_empty() {
            return Err(TimeTokenRefusal::Malformed("empty action_id".to_string()));
        }
        Ok(ServerIssuedTime {
            issued_at_unix,
            ttl_seconds,
            action_id,
            signature,
            raw: raw.to_string(),
        })
    }

    /// Accept this token for `action_id`, or say why not.
    ///
    /// `reading` is the client's own clock and is used **only** for the TTL
    /// courtesy check; the binding check does not consult it, which is why a
    /// skewed client still cannot move a token between actions.
    ///
    /// Both ends of the window carry [`CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS`].
    /// The upper bound without it would be a client refusing a token the server
    /// would have honoured; the lower bound without it refused **every** token
    /// under any positive server-minus-client skew, and every token issued after
    /// the second in which the invocation minted its reading — which is most of
    /// them, since the reading is frozen at mint. That is the design failing
    /// closed against its own premise, and it is what the allowance corrects.
    pub fn accept_for(
        self,
        action_id: &ActionId,
        reading: &ClientClockReading,
    ) -> Result<ServerIssuedTime, TimeTokenRefusal> {
        if self.action_id != action_id.as_str() {
            return Err(TimeTokenRefusal::ActionIdMismatch {
                issued_for: self.action_id,
                presented_for: action_id.as_str().to_string(),
            });
        }
        let now = reading.unverified_unix_seconds();
        let not_after = self
            .issued_at_unix
            .saturating_add(self.ttl_seconds)
            .saturating_add(CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS);
        // The lower bound is kept, widened: only checking the upper one would
        // let a server (or a proxy) hand out tokens pre-dated by a year and have
        // the client forward them. Widened, because "issued one second after
        // this process started" is not a pre-dated token, it is the normal case.
        let not_before = self
            .issued_at_unix
            .saturating_sub(CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS);
        if now > not_after || now < not_before {
            return Err(TimeTokenRefusal::Expired {
                issued_at_unix: self.issued_at_unix,
                ttl_seconds: self.ttl_seconds,
                client_reading_unix: now,
            });
        }
        Ok(self)
    }

    /// The instant the server says it issued this token at.
    pub fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    /// The window, in seconds, the server declared this token valid for.
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// The action this token is bound to.
    pub fn bound_action_id(&self) -> &str {
        &self.action_id
    }

    /// The header value, byte-identical to what the server sent.
    ///
    /// Returns the stored `raw` rather than re-rendering the parsed fields.
    /// Re-rendering looked equivalent and was not: [`ServerIssuedTime::parse`]
    /// ignores unknown segments on purpose, so a server that added one
    /// forward-compatible field would have every echoed token come back missing
    /// it — a different byte string over which the `sig` no longer verifies, and
    /// a contradiction of this method's own doc and of the OpenAPI "echoed
    /// verbatim". Held in a private field, so the only way to obtain the string
    /// is still to have been handed it by a server.
    pub fn render(&self) -> String {
        self.raw.clone()
    }
}

// ---------------------------------------------------------------------------
// Client fingerprint.
// ---------------------------------------------------------------------------

/// Operator-supplied fingerprint inputs, injected so resolution is testable
/// without touching the process environment — the same shape
/// [`crate::auth::resolve_credential`] uses for secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FingerprintEnv {
    /// [`HOST_LABEL_ENV`], when the operator set it.
    pub host_label: Option<String>,
    /// [`REPORTED_IP_ENV`], when the operator set it.
    pub reported_ip: Option<String>,
}

impl FingerprintEnv {
    /// Read the opt-in variables from the real process environment.
    pub fn from_process() -> FingerprintEnv {
        let read = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        FingerprintEnv {
            host_label: read(HOST_LABEL_ENV),
            reported_ip: read(REPORTED_IP_ENV),
        }
    }
}

/// Where the action came from, as the client declares it.
///
/// **Not** the `canonical_target_sha256` action fingerprint
/// ([`crate::receipt::ACTION_FINGERPRINT_CONTRACT`]), which digests the *target*
/// of the call and is mirrored byte-for-byte from `ferrogate-runtime`. This
/// describes the *client*, is not a digest at all, and deliberately carries a
/// different name at every layer so the two can never be read as one.
///
/// `Debug` is hand-written rather than derived. A derived one would print
/// whatever fields a later change adds, which is precisely how a credential
/// reaches a log in this repo (#489, #492, #537); the hand-written one is a
/// place a reviewer must edit to leak something.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientFingerprint {
    cli_version: String,
    os: String,
    arch: String,
    context_name: Option<String>,
    credential_source: String,
    host_label: Option<String>,
    reported_ip: Option<String>,
}

impl ClientFingerprint {
    /// Derive the fingerprint from the resolved context and the operator's
    /// opt-in variables.
    ///
    /// The credential *source* is read from [`AuthSource`] — a value that can
    /// hold a plaintext token in its `Inline` variant. [`AuthSource::audit_source`]
    /// is the only thing between that token and this struct, which is why
    /// `fingerprint_never_carries_the_token_it_was_built_from` asserts on the
    /// rendered forms rather than on that function's return value.
    pub fn detect(context: &EffectiveContext, env: &FingerprintEnv) -> ClientFingerprint {
        ClientFingerprint {
            cli_version: crate::version::CLI_VERSION.to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            context_name: context.context_name.clone(),
            credential_source: context.auth.audit_source(),
            host_label: env.host_label.clone(),
            reported_ip: env.reported_ip.clone(),
        }
    }

    /// Every declared field, in [`FINGERPRINT_FIELDS`] order, with `None` for
    /// the ones this invocation carries no value for.
    ///
    /// This is the enumeration the privacy contract is checked against: a field
    /// added to the struct and not to this list, or vice versa, fails
    /// `fingerprint_declares_exactly_the_reviewed_field_set`.
    pub fn fields(&self) -> Vec<(&'static str, Option<String>)> {
        vec![
            ("cli", Some(self.cli_version.clone())),
            ("os", Some(self.os.clone())),
            ("arch", Some(self.arch.clone())),
            ("context", self.context_name.clone()),
            ("cred", Some(self.credential_source.clone())),
            ("host", self.host_label.clone()),
            ("client_reported_ip", self.reported_ip.clone()),
        ]
    }

    /// The [`CLIENT_FINGERPRINT_HEADER`] value.
    ///
    /// `client_reported_ip` is **excluded**: it rides its own header so a
    /// server-side sink cannot fold a client-asserted address into a blob it
    /// stores as one fingerprint value. Absent optional fields are omitted
    /// rather than rendered as empty, so a reader cannot mistake "not disclosed"
    /// for "disclosed as blank"; the *reason* an optional field is absent is
    /// carried by the receipt, which has an [`crate::receipt::Attested`] slot
    /// for it.
    pub fn render(&self) -> String {
        let mut rendered = String::from(IDENTITY_SCHEMA_VERSION);
        for (key, value) in self.fields() {
            if key == "client_reported_ip" {
                continue;
            }
            if let Some(value) = value {
                rendered.push(';');
                rendered.push_str(key);
                rendered.push('=');
                rendered.push_str(&encode_header_value(&value));
            }
        }
        rendered
    }

    /// The operator-supplied client address, when one was disclosed.
    /// Client-asserted: see the module docs.
    pub fn reported_ip(&self) -> Option<&str> {
        self.reported_ip.as_deref()
    }

    /// The operator-supplied machine label, when one was disclosed.
    pub fn host_label(&self) -> Option<&str> {
        self.host_label.as_deref()
    }
}

impl std::fmt::Debug for ClientFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientFingerprint")
            .field("cli_version", &self.cli_version)
            .field("os", &self.os)
            .field("arch", &self.arch)
            .field("context_name", &self.context_name)
            .field("credential_source", &self.credential_source)
            .field("host_label", &self.host_label)
            .field("reported_ip", &self.reported_ip)
            .finish()
    }
}

/// Characters an encoded header value carries unescaped: the RFC 3986
/// unreserved set plus `:` and `/`, so an IPv6 address and a path-like label
/// stay readable.
///
/// `;` and `=` are **not** in it. They are the fingerprint blob's own
/// delimiters, and leaving them through is how an operator-supplied label forges
/// a second field.
fn is_header_value_safe(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | '~' | ':' | '/')
}

/// Percent-encode `value` down to the characters [`is_header_value_safe`]
/// allows, escaping every other byte as `%XX`.
///
/// # Why encoding and not deletion
///
/// This replaced a filter that *deleted* `\r`, `\n`, `;` and anything
/// `char::is_control`, and it fixes two defects that filter had.
///
/// 1. **Deletion joins what it separates.** A label of
///    `box\r\nx-ferrogate-action-id: fgact_evil;cred=none` came out as
///    `boxx-ferrogate-action-id: fgact_evilcred=none` — no forged segment, but a
///    literal `cred=` welded into the middle of the value by the removal of the
///    `;` in front of it. Anything grepping the blob sees a field that was never
///    declared. Encoding cannot weld: `%3B` is one segment's worth of text and
///    reads back as one.
/// 2. **Nothing restricted the output to ASCII.** Two operator-reachable inputs
///    reach this function — [`HOST_LABEL_ENV`] and, since #548, the resolved
///    **context name**, which nothing in [`crate::context`] validates — so a
///    context named `生产` or `prod-café` put raw UTF-8 into a header value.
///    This project's own issues are written in Chinese; that is not a
///    hypothetical profile name.
///
///    An earlier revision of this doc said that broke the `reqwest` path,
///    because `http::HeaderValue`'s `TryFrom<&str>` "rejects every byte outside
///    `32..=126`". **That is wrong and is withdrawn.** The pinned `http` is
///    1.4.0 (one version in `Cargo.lock`) and its validator is
///    `b >= 32 && b != 127 || b == b'\t'`, which *accepts* 0x80–0xFF;
///    `is_visible_ascii` exists but is reached only from `from_static`,
///    `to_str` and `Debug`. `crate::transport` calls
///    `builder.header(name, &String)`, which selects `TryFrom<&String>` →
///    `from_bytes`, documented as permitting 128–255. So `reqwest` builds and
///    sends it.
///
///    What it actually breaks is worse for being quieter:
///
///    * **The raw-TCP chokepoint refuses outright.** `ferrogate-cli`'s
///      `assets_cli::render_header_block` bails on any character outside
///      `0x20..=0x7E`, because there is no `http::HeaderValue` between that
///      string and the socket. A `生产` context therefore fails all seven
///      `assets`/`plans` verbs before a byte is written — the brick, and it is
///      real, just one crate to the right of where the old doc put it.
///    * **On the `reqwest` path the bytes leave as obs-text**, which RFC 9110
///      §5.5 deprecates and leaves to the recipient to reject or reinterpret,
///      and which `HeaderValue::to_str` — the one `http` API that does apply
///      `is_visible_ascii` — refuses to read back. An intermediary or an audit
///      consumer may drop or mangle exactly the attribution this issue adds.
///
///    The encoding makes the output visible-ASCII by construction, so the name
///    survives as `%E7%94%9F%E4%BA%A7` on both paths.
///
/// Lossless, so an audit consumer can percent-decode back to what the operator
/// wrote. `%` itself is escaped to `%25`, or the encoding would be ambiguous.
pub fn encode_header_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        let ch = byte as char;
        if byte.is_ascii() && is_header_value_safe(ch) {
            encoded.push(ch);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

// ---------------------------------------------------------------------------
// The identity itself.
// ---------------------------------------------------------------------------

/// Everything the CLI asserts about itself for one operator action.
///
/// Private fields and no public struct literal: outside this module the only
/// way to obtain one is [`ClientActionIdentity::mint`]. That is the
/// [`crate::receipt::RenderGate`] pattern — the obligation is discharged by the
/// type system, not by a reviewer noticing.
///
/// `Clone` shares the server-time slot through an [`Arc`], so the copy the
/// transport holds and the copy the receipt reads are the *same* action: a token
/// harvested by one is visible to the other, and their `action_id`s cannot
/// diverge.
#[derive(Clone)]
pub struct ClientActionIdentity {
    action_id: ActionId,
    fingerprint: ClientFingerprint,
    clock: ClientClockReading,
    /// The freshest server-issued time this action holds. `None` until a
    /// response carries one; never backfilled from the local clock.
    server_time: Arc<Mutex<Option<ServerIssuedTime>>>,
}

impl ClientActionIdentity {
    /// Mint the identity for one operator action.
    ///
    /// Called once per invocation. Every request the invocation issues — reads
    /// included, and every page of an `--all-pages` walk — carries this same
    /// `action_id`, which is what makes a retry of the same logical action
    /// recognizable as one action rather than several.
    pub fn mint(
        context: &EffectiveContext,
        env: &FingerprintEnv,
    ) -> CliResult<ClientActionIdentity> {
        Ok(ClientActionIdentity {
            action_id: ActionId::mint()?,
            fingerprint: ClientFingerprint::detect(context, env),
            clock: ClientClockReading::read_local_clock(),
            server_time: Arc::new(Mutex::new(None)),
        })
    }

    /// A fixed identity for in-crate unit tests.
    ///
    /// `#[cfg(test)]`, so it exists only while compiling this crate's own test
    /// target and cannot weaken the guarantee for any consumer: `ferrogate-cli`
    /// still has exactly one way to build an identity.
    #[cfg(test)]
    pub fn fixture() -> ClientActionIdentity {
        ClientActionIdentity {
            action_id: ActionId(format!(
                "{ACTION_ID_PREFIX}{}",
                "0".repeat(ACTION_ID_HEX_LEN)
            )),
            fingerprint: ClientFingerprint {
                cli_version: crate::version::CLI_VERSION.to_string(),
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                context_name: Some("fixture".to_string()),
                credential_source: "none".to_string(),
                host_label: None,
                reported_ip: None,
            },
            clock: ClientClockReading::from_unix_seconds(1_800_000_000),
            server_time: Arc::new(Mutex::new(None)),
        }
    }

    /// The id of this action.
    pub fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    /// What the client declares about itself.
    pub fn fingerprint(&self) -> &ClientFingerprint {
        &self.fingerprint
    }

    /// The client's own clock reading — evidence about the client, never the
    /// event time.
    pub fn client_clock(&self) -> &ClientClockReading {
        &self.clock
    }

    /// The server-issued time this action currently holds, if any.
    pub fn server_issued_time(&self) -> Option<ServerIssuedTime> {
        self.server_time
            .lock()
            .ok()
            .and_then(|held| held.as_ref().cloned())
    }

    /// Harvest a time token off a response, replacing the held one.
    ///
    /// This is the piggy-back half: no preflight request is ever made, so the
    /// steady-state extra round-trip cost is zero and only the first request of
    /// an invocation goes without a server time. A token that does not parse, or
    /// is bound to a different action, or is outside its TTL by the client's own
    /// reading, is **not** stored — the held value stays whatever it was, and
    /// the refusal is returned for the caller to surface as a diagnostic.
    pub fn accept_server_time(&self, raw: &str) -> Result<ServerIssuedTime, TimeTokenRefusal> {
        let accepted = ServerIssuedTime::parse(raw)?.accept_for(&self.action_id, &self.clock)?;
        if let Ok(mut held) = self.server_time.lock() {
            *held = Some(accepted.clone());
        }
        Ok(accepted)
    }

    /// The headers every request of this action carries.
    ///
    /// [`ACTION_ID_HEADER`], [`CLIENT_FINGERPRINT_HEADER`] and
    /// [`CLIENT_CLOCK_HEADER`] are unconditional. [`TIME_TOKEN_HEADER`] appears
    /// only when the server has issued one, and [`CLIENT_REPORTED_IP_HEADER`]
    /// only when the operator opted in — an absent optional header is the honest
    /// rendering of "not disclosed", and the receipt states the reason.
    pub fn headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![
            (ACTION_ID_HEADER.to_string(), self.action_id.to_string()),
            (
                CLIENT_FINGERPRINT_HEADER.to_string(),
                self.fingerprint.render(),
            ),
            (CLIENT_CLOCK_HEADER.to_string(), self.clock.render()),
        ];
        if let Some(server_time) = self.server_issued_time() {
            headers.push((TIME_TOKEN_HEADER.to_string(), server_time.render()));
        }
        if let Some(reported_ip) = self.fingerprint.reported_ip() {
            headers.push((
                CLIENT_REPORTED_IP_HEADER.to_string(),
                encode_header_value(reported_ip),
            ));
        }
        headers
    }
}

impl std::fmt::Debug for ClientActionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientActionIdentity")
            .field("action_id", &self.action_id)
            .field("fingerprint", &self.fingerprint)
            .field("client_clock_unverified", &self.clock)
            .field("server_issued_time", &self.server_issued_time())
            .finish()
    }
}

impl AuthSource {
    /// The secret-free label an audit record may carry for this source.
    ///
    /// `Inline` holds a plaintext bearer token; this returns the *shape* of the
    /// source and never the material. It is the single definition shared by the
    /// fingerprint and by [`crate::receipt::ReceiptActor::credential_source`],
    /// so the two cannot drift into disagreeing about what is safe to print.
    pub fn audit_source(&self) -> String {
        match self {
            AuthSource::None => "none".to_string(),
            AuthSource::Env { var } => format!("env:{var}"),
            AuthSource::Stdin => "stdin".to_string(),
            AuthSource::Inline { .. } => "inline".to_string(),
        }
    }
}

#[cfg(test)]
#[path = "action_identity_test.rs"]
mod action_identity_test;
