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
//! [`redact_recorded_values`], and every excerpt through
//! [`recorded_excerpt`] / [`recorded_http_excerpt`] / [`recorded_line_excerpt`]
//! / [`recorded_value`]. There is ONE implementation of the redaction
//! ([`redact_scoped`]); everything else in the crate delegates to it.
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
//! Residual risk, stated rather than hidden: a deny-list cannot know a bespoke
//! credential header name (`x-acme-session`). That risk is now bounded by
//! being CENTRAL — adding one entry to [`is_bearer_header`] covers every
//! family at once, which was not true before this module existed.
//!
//! # Two scopes, one implementation
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
//! # Ordering is load-bearing
//!
//! Redaction happens BEFORE truncation in every helper here. Truncating first
//! and redacting after would ship a long usable PREFIX of a proof, which is not
//! meaningfully better than shipping the whole thing. The helpers own both
//! steps precisely so a caller cannot get the order wrong.

use std::collections::BTreeMap;

use ferrogate_payments::HEADER_PAYMENT_SIGNATURE;

/// Replacement written in place of a bearer header value.
pub(crate) const REDACTED_HEADER_VALUE: &str = "<redacted>";

/// How much of a byte buffer is decoded and scanned before truncation.
///
/// Redaction must precede truncation, so the scan window can never be smaller
/// than the excerpt limit. It is capped anyway so that excerpting a 512-byte
/// slice of a multi-gigabyte file does not decode the whole file: any content
/// beyond the window is dropped, never recorded, so the cap can only
/// over-redact relative to an unbounded scan.
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
fn is_bearer_header(name: &str) -> bool {
    const BEARER_HEADERS: [&str; 7] = [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        // Not IANA-registered, but every one of these is a value whose mere
        // possession authenticates the holder — which is the whole criterion.
        "authentication",
        "x-api-key",
        "x-auth-token",
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
/// * Redaction happens BEFORE truncation at the call site, so a truncated
///   excerpt can never carry a surviving prefix of a proof.
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
/// The order is the point. Capping first would leave a `char_limit`-long prefix
/// of a signed payment proof in the record.
pub(crate) fn recorded_http_excerpt(raw_http_message: &str, char_limit: usize) -> String {
    redact_bearer_headers(raw_http_message)
        .chars()
        .take(char_limit)
        .collect()
}

/// Excerpt raw observed BYTES for recording: decode, redact, then cap at
/// `byte_limit` bytes on a character boundary.
///
/// This replaced a `String::from_utf8_lossy(&bytes[..limit])` that every
/// non-REST family used, which is how #353's fix missed them all.
pub(crate) fn recorded_excerpt(bytes: &[u8], byte_limit: u64) -> String {
    let byte_limit = usize::try_from(byte_limit).unwrap_or(usize::MAX);
    // Never scan less than we are about to record: redaction has to see at
    // least everything that could survive truncation.
    let window = byte_limit.max(EVIDENCE_SCAN_BYTES).min(bytes.len());
    let redacted = redact_recorded_text(&String::from_utf8_lossy(&bytes[..window]));
    truncate_on_char_boundary(redacted, byte_limit)
}

/// Excerpt unstructured text by LINES (a microVM serial log, a hypervisor log):
/// redact, then keep the first `max_lines` lines.
pub(crate) fn recorded_line_excerpt(text: &str, max_lines: usize) -> String {
    redact_recorded_text(text)
        .lines()
        .take(max_lines)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Redact a single already-assembled recorded value (a workload output blob, an
/// evidence field). Untruncated: callers that also truncate must use one of the
/// excerpt helpers so the ordering stays correct.
pub(crate) fn recorded_value(value: &str) -> String {
    redact_recorded_text(value)
}

/// Build an event-metadata map whose VALUES have been swept for bearer
/// material.
///
/// This is the net under the excerpt helpers: an excerpt built the right way is
/// already clean and this pass is a no-op on it (redaction is idempotent), but a
/// family that assembles a value some other way — a new key, a `format!` over an
/// upstream string, a field nobody thought of as an "excerpt" — is still covered
/// because it went into a metadata map.
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
