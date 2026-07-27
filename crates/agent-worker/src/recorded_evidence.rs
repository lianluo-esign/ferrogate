// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The single place `agent-worker` turns raw bytes it observed into something
//! it is willing to RECORD — an event metadata value, a worker-stdout evidence
//! blob, a guest-frame field.
//!
//! # Why this module exists (#526)
//!
//! #353 fixed exactly one leak: `run_authorized_rest_action` was recording the
//! raw HTTP response — status line, every header, body — into the
//! `response_excerpt` of a `rest.requested` event and into the worker's stdout.
//! Any `authorization`, `cookie` or `set-cookie` an upstream returned was
//! written out verbatim. The fix ([`redact_bearer_headers`]) lived next to the
//! x402 client and had exactly one caller.
//!
//! That shape is the defect. Every other capability family builds its own
//! excerpt (`output_excerpt`, `value_excerpt`, `content_excerpt`,
//! `stdout_excerpt`, `page_state`, `serial_excerpt`, …) through its own
//! constructor, so a per-family fix protects one family and silently leaves the
//! rest — and a family added tomorrow inherits nothing.
//!
//! So the redaction is no longer a REST detail. It is the definition of
//! "recorded": every builder goes through [`recorded_metadata`] /
//! [`redact_recorded_values`], every excerpt through [`recorded_excerpt`] /
//! [`recorded_http_excerpt`] / [`recorded_line_excerpt`] / [`recorded_value`],
//! and every argument vector through [`recorded_argv`]. There is ONE
//! implementation of the redaction ([`redact_scoped`]); everything else in the
//! crate delegates to it.
//!
//! # The policy decision: names are recorded, bearer VALUES are not (#526)
//!
//! The alternatives considered were (a) record no header values at all, (b)
//! record only a whitelist of header values, (c) record every value except a
//! deny-list of bearer names. This module implements (c), deliberately:
//!
//! * (a) and (b) both destroy the evidence #354 depends on.
//!   `PAYMENT-REQUIRED` (the merchant's public challenge) and
//!   `PAYMENT-RESPONSE` (public on-chain settlement evidence) must survive
//!   VERBATIM to answer "why was this payment made and what happened to it?".
//!   A whitelist would have to enumerate them anyway, and would then have to
//!   grow a new entry for every diagnostic header anyone ever needs — a
//!   whitelist that is edited on every incident is a deny-list with worse
//!   ergonomics.
//! * The excerpts are diagnostics. Blanking every value turns
//!   "upstream answered 502 with `retry-after: 30`" into "upstream answered",
//!   which is the kind of un-actionable record that gets replaced by an
//!   engineer curl-ing the endpoint by hand and pasting the output into a
//!   ticket — a strictly worse leak.
//! * Header NAMES are kept on redacted headers too, so the record still shows
//!   that a credential (or a spendable payment proof) was present. An operator
//!   sees the shape of the exchange; the record does not become a way to spend
//!   the money.
//!
//! Residual risk, stated accurately (#526 rework). The deny-list is not
//! "everything except a name nobody has heard of": it must at minimum contain
//! every credential header FerroGate ITSELF sends, because a workload that
//! prints its own upstream call is the likeliest way one of them is observed.
//! [`is_bearer_header`] therefore names each one against its definition site in
//! this repo, and `recorded_evidence_test.rs` pins that list from the OTHER
//! side — it enumerates the header names the provider/secret crates emit, not
//! the deny-list, so dropping an entry here fails a test instead of passing one.
//!
//! What genuinely remains uncovered is (a) a credential header name that no
//! crate in this repo emits and that no upstream we call has yet used, and (b)
//! a credential echoed inside a BODY rather than on a header-shaped line. Both
//! are bounded by this being CENTRAL: one entry covers every family at once,
//! which was not true before this module existed.
//!
//! # Two scopes, one implementation, chosen by the SURFACE
//!
//! A raw HTTP message has a header section; a process's stdout does not. So
//! [`RedactionScope`] selects which lines are eligible, and nothing else:
//!
//! * [`RedactionScope::HttpMessage`] — line 0 is the status line and the
//!   header section ends at the first empty line. This is #353's behaviour,
//!   unchanged, and is what the REST response path uses.
//! * [`RedactionScope::AnyText`] — used for stdout, file content, serial
//!   console logs and metadata values, where there is no header/body structure
//!   to trust. EVERY line is eligible, because a credential-shaped line in the
//!   middle of a `curl -i` dump on a tool's stdout is exactly as spendable as
//!   one in a real header section.
//!
//! The scope is NOT a call-site argument. Every recording helper takes a
//! [`RecordedSurface`] and derives the scope from it, so "is this blob a raw
//! HTTP message?" is answered once per surface, in this module, where the
//! answer can be reviewed against the whole list at a glance. That also makes
//! the enum the crate's register of recorded-evidence surfaces: a surface added
//! tomorrow must name itself here, and the exhaustive match in
//! `external_actions_recorded_evidence_test.rs` does not compile until the new
//! surface is fed a credential and its artifact asserted clean.
//!
//! # Why the ORDER of redaction and truncation is not the safety property
//!
//! An earlier draft of this module claimed redaction-before-truncation was
//! load-bearing: truncating first would supposedly ship a usable PREFIX of a
//! proof. Against THIS redactor that claim is false, and it was withdrawn
//! rather than left as a comforting sentence no test could hold (#526 rework).
//!
//! The redactor is line-anchored and prefix-stable: a line's classification
//! depends only on the header NAME that precedes its value on the same line,
//! plus the classification of the complete lines before it. Truncation only
//! ever removes a SUFFIX. So for any surviving line, either it is a complete
//! original line (identical classification, identical redaction) or it is a
//! proper prefix of one — and a prefix of a bearer line either still contains
//! the colon, in which case it is classified and blanked exactly as before, or
//! it stops inside the header NAME, which carries no credential. Truncate-first
//! cannot leak here, and the two orderings differ only in the LENGTH of what is
//! recorded.
//!
//! The helpers still own both steps, for two reasons that ARE load-bearing:
//!
//! * A caller that owns truncation is a caller that can forget redaction
//!   entirely — which is precisely how every non-REST family got here.
//! * [`recorded_excerpt`]'s scan window must never be smaller than what it is
//!   about to record, which is only checkable in one place.
//!
//! If the redactor ever stops being prefix-stable — if it grows a value-shaped
//! rule (entropy, a bare `Bearer <token>` with no name anchor, a JSON path)
//! then a truncated prefix stops being recognizable and the ordering becomes
//! load-bearing for real. Restore the claim WITH a fixture that fails under the
//! swap; do not restore it on its own.
//!
//! # Where the audit lives, and what it still does not cover
//!
//! #526's per-site audit is not prose in an issue: it is
//! `RAW_CAPTURE_AUDIT` in `recorded_evidence_scan_test.rs`, a table the suite
//! reads. Every place in this crate that DECODES raw observed bytes into a
//! string must appear there with a verdict, including the ones found clean, and
//! the row records the exact number of occurrences — so one more decode added
//! inside an already-reviewed function fails too, which the first version of
//! that table did not hold. That guard is DETECTION, not impossibility, and its
//! own docs name the two things it still cannot see: a `fn` name that aliases
//! two bodies, and a recording path that never decodes at all (a `String` out of
//! `serde_json`, a `read_to_string`). For that second shape the guards are
//! [`RecordedSurface`]'s exhaustive match and [`recorded_metadata`], not the
//! scan.
//!
//! Two things are recorded as accepted rather than fixed, so the next reader
//! does not go looking:
//!
//! * `url` and `external_target` (`external_actions.rs`) are recorded verbatim,
//!   so a query-string token or a presigned URL still reaches event metadata.
//!   That is a different shape of leak — a secret in a path, with no header name
//!   to anchor on — and belongs to its own issue, not to this deny-list.
//! * Nothing rewrites events recorded BEFORE this module existed. The redaction
//!   is on the write path only; historical rows keep whatever they captured.

use std::collections::BTreeMap;

use ferrogate_payments::HEADER_PAYMENT_SIGNATURE;

/// Replacement written in place of a bearer header value.
pub(crate) const REDACTED_HEADER_VALUE: &str = "<redacted>";

/// How much of a byte buffer is decoded and scanned before truncation.
///
/// The window can never be smaller than the excerpt limit: the scanner must see
/// at least everything that could survive truncation, or a credential that fits
/// inside the record would never have been looked at. It is capped anyway so
/// that excerpting a 512-byte slice of a multi-gigabyte file does not decode the
/// whole file: any content beyond the window is dropped, never recorded, so the
/// cap can only over-redact relative to an unbounded scan.
const EVIDENCE_SCAN_BYTES: usize = 64 * 1024;

/// Which lines of a blob are eligible to be parsed as headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedactionScope {
    /// A raw HTTP message: line 0 is the status/request line and the header
    /// section ends at the first empty line.
    HttpMessage,
    /// Unstructured text (stdout, file bytes, a serial log, a metadata value):
    /// every line is eligible.
    AnyText,
}

/// Every place in this crate that turns observed bytes into RECORDED evidence.
///
/// This enum is the crate's register of recorded-evidence surfaces, and it is
/// not decoration: [`RecordedSurface::scope`] is what decides whether a blob is
/// parsed as a raw HTTP message or as unstructured text, so a surface cannot be
/// recorded without that question having been answered for it, here, in review.
///
/// It exists because #526's first attempt proved the redaction with an
/// exhaustive match over `ManagedExternalAction` — which is structurally blind
/// to every surface that is not a governed external action, and four of those
/// had no assertion at all. A new surface must now name itself here, and the
/// exhaustive match in `external_actions_recorded_evidence_test.rs` fails to
/// compile until that surface has been fed a credential and its ARTIFACT
/// asserted clean.
///
/// What this still does not force: a future recording path that reaches none of
/// this module's helpers at all. [`recorded_metadata`] is the net under that
/// case for anything that lands in event metadata; a path that is neither is a
/// genuine hole, and the reason `recorded_evidence.rs` is the only file in the
/// crate allowed to own a redactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordedSurface {
    /// `tool.requested` → `output_excerpt` (`external_actions.rs`).
    ToolOutput,
    /// `mcp.tool.requested` → `output_excerpt` (`external_actions.rs`).
    McpToolOutput,
    /// `skill.requested` → `output_excerpt` (`external_actions.rs`).
    SkillOutput,
    /// `memory.requested` → `value_excerpt` (`external_actions.rs`).
    MemoryValue,
    /// `filesystem.requested` → `content_excerpt` (`external_actions.rs`).
    FilesystemContent,
    /// `cli.requested` → `stdout_excerpt` / `stderr_excerpt`
    /// (`external_actions.rs`).
    CliOutput,
    /// `rest.requested` → `response_excerpt` (`external_actions.rs`). The ONLY
    /// surface whose blob is a raw HTTP message, and #353's original subject.
    RestResponse,
    /// A configured handler binary's stdout/stderr (`handlers.rs`). Recorded
    /// into `cli.requested` metadata AND printed straight to worker stdout by
    /// `smoke_handler_binary_command`, which no metadata sweep covers.
    HandlerBinaryOutput,
    /// A microVM guest workload's stdout/stderr
    /// (`firecracker_guest_exec.rs`). Recorded into the guest `run.completed`
    /// frame AND into the guest RPC response, which no metadata sweep covers.
    ///
    /// Also the surface for every guest-authored free-text field the HOST
    /// ingests — event metadata, event `message`, the response `message`,
    /// `output_excerpt` and `denial_reason` — because the capture and the
    /// redaction that used to protect it both ran inside the microVM, on the
    /// far side of the boundary this crate exists to distrust.
    GuestWorkloadOutput,
    /// A microVM serial console / Firecracker log (`backends.rs`), recorded as
    /// `FirecrackerBootEvidence` and serialized straight to worker stdout —
    /// there is NO downstream metadata sweep on this path at all.
    FirecrackerBootEvidence,
    /// A governed workload's output (`self_hosted_execution.rs`), recorded into
    /// `evidence_json()`, which no metadata sweep covers.
    GovernedWorkloadOutput,
    /// An argument vector recorded back into evidence, via [`recorded_argv`]:
    /// the CLI family's `args` and the handler runtime's `probe_args` /
    /// `task_args`. One variant for all three because they share the one
    /// implementation — the leak they can have is the JOIN, not the call site.
    Argv,
}

impl RecordedSurface {
    /// The register, in list form, for the tests that must walk every surface.
    ///
    /// Kept next to the variants deliberately: a variant added below and not
    /// added here is visible in the same screen of the same diff, and the
    /// exhaustive match in `external_actions_recorded_evidence_test.rs` will
    /// have forced the author to write an artifact arm for it regardless.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 12] = [
        Self::ToolOutput,
        Self::McpToolOutput,
        Self::SkillOutput,
        Self::MemoryValue,
        Self::FilesystemContent,
        Self::CliOutput,
        Self::RestResponse,
        Self::HandlerBinaryOutput,
        Self::GuestWorkloadOutput,
        Self::FirecrackerBootEvidence,
        Self::GovernedWorkloadOutput,
        Self::Argv,
    ];

    /// Whether this surface's blob may be trusted to have an HTTP header
    /// section.
    ///
    /// Exactly one surface may. Everything else is unstructured text where a
    /// credential-shaped line can appear anywhere, so narrowing any of them to
    /// [`RedactionScope::HttpMessage`] re-opens the leak below the first blank
    /// line.
    fn scope(self) -> RedactionScope {
        match self {
            Self::RestResponse => RedactionScope::HttpMessage,
            Self::ToolOutput
            | Self::McpToolOutput
            | Self::SkillOutput
            | Self::MemoryValue
            | Self::FilesystemContent
            | Self::CliOutput
            | Self::HandlerBinaryOutput
            | Self::GuestWorkloadOutput
            | Self::FirecrackerBootEvidence
            | Self::GovernedWorkloadOutput
            | Self::Argv => RedactionScope::AnyText,
        }
    }
}

/// Header names whose VALUE is bearer material: possession of the value alone
/// is enough to spend money or impersonate the caller, so it must never reach
/// an event, a log line, or a worker's stdout.
///
/// `PAYMENT-SIGNATURE` leads the list because it is the worst case: it carries
/// the base64 **signed SVM transaction**. Anyone who captures it can submit that
/// transaction. It is not merely sensitive, it is spendable.
///
/// `PAYMENT-REQUIRED` and `PAYMENT-RESPONSE` are deliberately NOT here. The
/// first is the merchant's public challenge and the second is public settlement
/// evidence (an on-chain transaction signature); both are exactly the audit
/// trail #354 needs in order to answer "why was this payment made and what
/// happened to it?". Redacting them would destroy evidence without protecting
/// anything.
///
/// The second block is the one the first #526 attempt got wrong. A deny-list
/// that does not contain the credential headers FERROGATE ITSELF sends is not a
/// deny-list with a bespoke-name gap, it is a deny-list with a hole where the
/// most likely observation goes: the blob most likely to be recorded is a
/// workload's own dump of its own upstream call. Each entry names its
/// definition site so the pairing can be re-checked, and
/// `recorded_evidence_test.rs` enumerates those emitters independently of this
/// list so removing an entry fails a test rather than passing one.
fn is_bearer_header(name: &str) -> bool {
    const BEARER_HEADERS: [&str; 13] = [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        // Not IANA-registered, but every one of these is a value whose mere
        // possession authenticates the holder — which is the whole criterion.
        "authentication",
        "x-api-key",
        "x-auth-token",
        // Credential headers this repository emits. `authorization` above
        // already covers openai.rs, vertex.rs and bedrock.rs's SigV4 header;
        // these are the ones that are NOT spelled `authorization`, and none of
        // them matched before the #526 rework.
        //
        // `api-key`              — ferrogate-providers/src/azure.rs
        // `x-goog-api-key`       — ferrogate-providers/src/gemini.rs
        // `x-amz-security-token` — ferrogate-providers/src/bedrock.rs
        // `cf-aig-authorization` — ferrogate-providers/src/cloudflare.rs
        //                          (a distinct token from `authorization`, and
        //                          not a substring match of it)
        // `x-vault-token`        — ferrogate-secrets/src/lib.rs
        // `x-access-token`       — ferrogate-runtime/src/coding_agent/
        //                          credential_broker.rs. There it is the git
        //                          USERNAME that carries an installation
        //                          token; it is listed because a line shaped
        //                          `x-access-token: <token>` is exactly how
        //                          that pair gets printed, and over-redacting a
        //                          username is free.
        "api-key",
        "x-goog-api-key",
        "x-amz-security-token",
        "cf-aig-authorization",
        "x-vault-token",
        "x-access-token",
    ];
    name.eq_ignore_ascii_case(HEADER_PAYMENT_SIGNATURE)
        || BEARER_HEADERS
            .iter()
            .any(|bearer| name.eq_ignore_ascii_case(bearer))
}

/// Strip bearer header VALUES out of a raw HTTP message before any of it is
/// recorded as worker evidence.
///
/// Header NAMES are preserved, so the record still shows that a credential or a
/// payment proof was present — an operator can see the shape of the exchange
/// without the record itself becoming a way to spend the money.
///
/// Fail-safe by construction:
///
/// * A message with no header/body separator (a truncated or malformed
///   response) is treated as ALL headers, which over-redacts rather than
///   under-redacts.
/// * An `obs-fold` continuation line (RFC 7230 §3.2.4 — deprecated, but still
///   emitted by real servers) has no colon of its own, so matching per line
///   would let the tail of a folded credential through untouched. A
///   continuation of a bearer header is redacted with it.
///
/// Scope limit, stated honestly: this redacts the header section only. A body
/// that echoes a credential back is not covered — guessing at secrets inside
/// arbitrary payloads is a different problem with a different failure mode.
///
/// Test-only entry point. Production reaches HTTP scope through
/// [`recorded_http_excerpt`] with [`RecordedSurface::RestResponse`], so the
/// scope decision cannot be made at a call site; #353's tests still address the
/// scope directly, and this is how.
#[cfg(test)]
pub(crate) fn redact_bearer_headers(raw_http_message: &str) -> String {
    redact_scoped(raw_http_message, RedactionScope::HttpMessage)
}

/// Redact bearer material out of UNSTRUCTURED recorded text.
///
/// Used for everything that is not a raw HTTP message: process stdout/stderr, a
/// file excerpt, a microVM serial log, a metadata value. There is no header
/// section to trust in any of those, so every line is eligible — a `curl -i`
/// dump three screens into a tool's stdout leaks exactly as hard as a real
/// response header would.
pub(crate) fn redact_recorded_text(text: &str) -> String {
    redact_scoped(text, RedactionScope::AnyText)
}

/// THE redaction. Every recorded-evidence path in this crate reaches this
/// function; there is deliberately no second implementation to keep in sync.
///
/// # The one shape this does not catch, and the obligation it creates
///
/// A header is recognised only when its NAME starts the line: the scan takes
/// `split_once(':')`, i.e. the FIRST colon. So
/// `"upstream said: authorization: Bearer SECRET"` parses as the field
/// `upstream said` and passes through verbatim.
///
/// That is deliberate — a scan that hunted for a bearer name anywhere in a line
/// would blank the tail of any prose containing the word `cookie:` — but it
/// makes a rule for CALLERS, not a footnote: anything that concatenates
/// independently-sourced strings into one recorded value must join them with a
/// NEWLINE, so each piece gets its own line and its own chance to be classified.
///
/// `args.join(" ")` is the exact defect this rule exists for: a handler invoked
/// with `["--header", "authorization: Bearer SECRET"]` joins to
/// `--header authorization: Bearer SECRET`, whose first colon belongs to
/// `--header authorization`, and the credential is recorded in full. Argument
/// vectors therefore go through [`recorded_argv`], which owns the separator.
fn redact_scoped(text: &str, scope: RedactionScope) -> String {
    let http = matches!(scope, RedactionScope::HttpMessage);
    let mut redacted = String::with_capacity(text.len());
    let mut in_header_section = true;
    // Whether the field this line may be continuing is bearer material.
    let mut folding_bearer_header = false;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        // In an HTTP message index 0 is the status/request line, which is never
        // a header even if it happens to contain a colon. Unstructured text has
        // no status line, so its first line is as eligible as any other.
        if !in_header_section || (http && index == 0) {
            redacted.push_str(line);
            continue;
        }
        let content = line.trim_end_matches(['\r', '\n']);
        if content.is_empty() {
            // Only an HTTP message has a header section that an empty line can
            // end. In unstructured text a blank line is just a blank line.
            in_header_section = !http;
            folding_bearer_header = false;
            redacted.push_str(line);
            continue;
        }
        // A leading space/tab means this line continues the PREVIOUS field's
        // value, so it inherits that field's classification instead of being
        // parsed as a header in its own right.
        if content.starts_with([' ', '\t']) {
            if folding_bearer_header {
                redacted.push(' ');
                redacted.push_str(REDACTED_HEADER_VALUE);
                redacted.push_str(&line[content.len()..]);
            } else {
                redacted.push_str(line);
            }
            continue;
        }
        match content.split_once(':') {
            Some((name, _)) if is_bearer_header(name.trim()) => {
                folding_bearer_header = true;
                redacted.push_str(name);
                redacted.push_str(": ");
                redacted.push_str(REDACTED_HEADER_VALUE);
                redacted.push_str(&line[content.len()..]);
            }
            _ => {
                folding_bearer_header = false;
                redacted.push_str(line);
            }
        }
    }
    redacted
}

/// Excerpt a RAW HTTP MESSAGE for recording: redact, then cap at `char_limit`
/// characters.
///
/// `surface` is what makes the blob eligible for HTTP parsing at all — see
/// [`RecordedSurface::scope`]. A surface that is not really a raw HTTP message
/// must not be excerpted here.
pub(crate) fn recorded_http_excerpt(
    surface: RecordedSurface,
    raw_http_message: &str,
    char_limit: usize,
) -> String {
    redact_scoped(raw_http_message, surface.scope())
        .chars()
        .take(char_limit)
        .collect()
}

/// Excerpt raw observed BYTES for recording: decode, redact, then cap at
/// `byte_limit` bytes on a character boundary.
///
/// This replaced a `String::from_utf8_lossy(&bytes[..limit])` that every
/// non-REST family used, which is how #353's fix missed them all.
pub(crate) fn recorded_excerpt(surface: RecordedSurface, bytes: &[u8], byte_limit: u64) -> String {
    let byte_limit = usize::try_from(byte_limit).unwrap_or(usize::MAX);
    // Never scan less than we are about to record: redaction has to see at
    // least everything that could survive truncation.
    let window = byte_limit.max(EVIDENCE_SCAN_BYTES).min(bytes.len());
    let redacted = redact_scoped(&String::from_utf8_lossy(&bytes[..window]), surface.scope());
    truncate_on_char_boundary(redacted, byte_limit)
}

/// Excerpt unstructured text by LINES (a microVM serial log, a hypervisor log):
/// redact, then keep the first `max_lines` lines.
pub(crate) fn recorded_line_excerpt(
    surface: RecordedSurface,
    text: &str,
    max_lines: usize,
) -> String {
    redact_scoped(text, surface.scope())
        .lines()
        .take(max_lines)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Redact a single already-assembled recorded value (a workload output blob, an
/// evidence field). Untruncated: callers that also truncate must use one of the
/// excerpt helpers, which own both steps.
pub(crate) fn recorded_value(surface: RecordedSurface, value: &str) -> String {
    redact_scoped(value, surface.scope())
}

/// Join an ARGUMENT VECTOR into one recorded value.
///
/// The separator is the whole point, which is why no caller is allowed to pick
/// it. [`redact_scoped`] classifies a line by the field name that STARTS it, so
/// `["--header", "authorization: Bearer SECRET"].join(" ")` produces
/// `--header authorization: Bearer SECRET` — first colon belongs to
/// `--header authorization`, not a bearer name, and the credential is recorded
/// verbatim. Joining with a newline gives every argument its own line and its
/// own classification.
///
/// This covers the CLI family's `args` and the handler runtime's `probe_args`
/// and `task_args`; the last two were joined with a SPACE until the #526
/// rework, so a handler binary invoked with a `--header` credential recorded it
/// in full on its `run.started` event.
pub(crate) fn recorded_argv<S: AsRef<str>>(args: &[S]) -> String {
    recorded_value(
        RecordedSurface::Argv,
        &args
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Build an event-metadata map whose VALUES have been swept for bearer
/// material.
///
/// This is the net under the excerpt helpers: an excerpt built the right way is
/// already clean and this pass is a no-op on it (redaction is idempotent), and a
/// family that assembles a value some other way — a new key, a `format!` over an
/// upstream string, a field nobody thought of as an "excerpt" — is at least
/// LOOKED AT, because it went into a metadata map.
///
/// How far that goes is exactly [`redact_scoped`]'s line rule, and no further.
/// A credential is found only where a bearer NAME starts a line, so
/// `format!("upstream said: {response}")` is covered when `response` begins with
/// a newline or already contains its header block on its own lines, and is NOT
/// covered when the whole exchange is flattened onto one line
/// (`"upstream said: authorization: Bearer …"` parses as the field
/// `upstream said`).
///
/// The two tests that exercise this shape
/// (`the_cli_failure_and_cancellation_builders_are_swept_too`,
/// `the_rest_rejection_builder_sweeps_its_upstream_derived_failure_reason`) put a
/// deliberate `\n` before the captured blob, and that `\n` is what makes them
/// pass — said plainly because it would otherwise read as a property of this
/// function. They are aimed at the BUILDER (does `failure_reason` get swept at
/// all?), not at the line rule, and they model a future error string rather than
/// a current one: no `failure_reason` built today embeds a raw upstream response
/// (`payment_required_failure` and its siblings interpolate a status code, a
/// challenge hash or a parse error).
///
/// So this is a net with a stated mesh size, not a catch-all. A builder that
/// concatenates an upstream string onto the SAME line as its own prose is the
/// hole; the obligation to join with a newline is documented on
/// [`redact_scoped`], and [`recorded_argv`] exists because argument vectors were
/// exactly that hole once already.
pub(crate) fn recorded_metadata<I>(pairs: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut metadata: BTreeMap<String, String> = pairs.into_iter().collect();
    redact_recorded_values(metadata.values_mut());
    metadata
}

/// Sweep bearer material out of already-collected metadata values in place, for
/// maps that are assembled incrementally rather than from a literal list.
pub(crate) fn redact_recorded_values<'a, I>(values: I)
where
    I: IntoIterator<Item = &'a mut String>,
{
    for value in values {
        let redacted = redact_recorded_text(value);
        if redacted != *value {
            *value = redacted;
        }
    }
}

/// Cut `text` to at most `byte_limit` bytes without splitting a character.
fn truncate_on_char_boundary(mut text: String, byte_limit: usize) -> String {
    if text.len() <= byte_limit {
        return text;
    }
    let mut cut = byte_limit;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text
}

#[cfg(test)]
#[path = "recorded_evidence_test.rs"]
mod recorded_evidence_test;

/// The pure half of the source audit: `(file_name, source_text)` in, verdicts
/// out, so the guard can be aimed at sources that MUST be rejected and not only
/// at a clean tree (#480's rule, applied to #526).
#[cfg(test)]
#[path = "recorded_evidence_scan_test_support.rs"]
mod recorded_evidence_scan_test_support;

#[cfg(test)]
#[path = "recorded_evidence_scan_test.rs"]
mod recorded_evidence_scan_test;
