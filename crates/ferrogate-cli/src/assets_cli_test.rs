// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The **second** audit chokepoint (issue #548).
//!
//! `ferrogate-control-plane-client`'s `prepare_request` is the chokepoint every
//! `ctl` verb goes through, and its guarantee is a compile error. It is not the
//! only way this binary puts bytes on the wire: `assets` and `plans` predate the
//! typed client and drive a hand-rolled raw-`TcpStream` HTTP client, because
//! `main()` is a synchronous entry point. Between them they issue seven
//! requests, four of them **mutations** — two of those Control Plane mutations
//! with no registry family to route through instead — and three of them reads,
//! which this issue asks for too.
//!
//! These tests hold the two halves of closing that: that `send_request` really
//! writes the identity into the request it builds, and that no *third*
//! hand-rolled client appears without a test going red.

use super::*;
use ferrogate_control_plane_client::action_identity::{
    ACTION_ID_HEADER, CLIENT_CLOCK_HEADER, CLIENT_FINGERPRINT_HEADER,
};

/// Pins: `render_header_block` emitting every header
/// `ClientActionIdentity::headers` returns, in `Name: value\r\n` form.
///
/// Catches: dropping the `request.push_str(&identity_headers)` line in
/// `send_request` (the header block would be empty and every assertion here
/// reds); and emitting a subset — the action id is what the whole correlation
/// rests on, and the fingerprint and clock are what make the record readable.
///
/// This is deliberately a test on the *rendered block* rather than on a live
/// socket: what `send_request` writes is `format!(...)` text, and asserting on
/// the text is what an assertion can do here without a listening server.
/// [`every_raw_tcp_command_mints_exactly_one_action_identity`] below covers the
/// other half — that a real command hands one in, exactly once per invocation.
#[test]
fn the_raw_tcp_client_writes_the_action_identity_into_its_request() {
    let identity = mint_action_identity("http://127.0.0.1:8080", "fgk_live_secret_value")
        .expect("the OS random source is available in the test env");
    let block = render_header_block(identity.headers()).expect("the identity renders");

    for header in [
        ACTION_ID_HEADER,
        CLIENT_FINGERPRINT_HEADER,
        CLIENT_CLOCK_HEADER,
    ] {
        assert!(
            block.contains(&format!("{header}: ")),
            "'{header}' is missing from the raw request's header block: {block:?}"
        );
    }
    assert!(
        block.contains(&format!("{ACTION_ID_HEADER}: {}\r\n", identity.action_id())),
        "the block must carry THIS invocation's action id: {block:?}"
    );
    assert!(
        block.ends_with("\r\n"),
        "each header line is CRLF-terminated or the request is malformed: {block:?}"
    );
    // The credential is handed to `mint_action_identity` as a plaintext value.
    // #489/#492/#537 are the live evidence that this repo gets that wrong, and
    // this is the surface where a leak would be written straight into a socket.
    assert!(
        !block.contains("fgk_live_secret_value"),
        "the raw request's identity block carries the API key: {block:?}"
    );
    assert!(
        !block.contains("fgk_"),
        "the raw request's identity block carries a prefix of the API key: {block:?}"
    );
    assert!(
        block.contains("cred=inline"),
        "the credential SOURCE is carried, and dropping it would make the two assertions above \
         vacuous: {block:?}"
    );
}

/// Every socket this binary opens is accounted for, by name.
///
/// Pins: the complete set of `TcpStream::connect*` sites in
/// `crates/ferrogate-cli/src`.
///
/// Catches: a fourth command group copying the raw client into a new file —
/// which is precisely how this hole was made. `send_request` is `pub(crate)`
/// with a doc that recommends reuse, so the *next* author does the same thing
/// the `plans` author did, and a copy would carry no identity and red nothing.
/// A source scan is the only assertion that can speak for code not yet written.
///
/// It scans for the connect call rather than for a header name, because the
/// defect is "bytes left the process through a path with no identity on it",
/// and a new client would not mention any of #548's constants at all.
///
/// Two sites are expected, and the list is an **allow-list with a reason**
/// rather than a count, so a new one is a decision someone has to write down:
///
/// * `assets_cli.rs::send_request` — the attributed raw client. Takes a
///   `&ClientActionIdentity` and writes its headers into the request.
/// * `admin_api.rs::connect_upstream` — **not** an originating CLI action.
///   `ferrogate admin-api` is a reverse proxy: it relays a request the admin
///   console made, and minting an `action_id` there would attribute the
///   console's action to the proxy process and put a false actor in the audit
///   trail. It forwards the caller's own headers, `x-forwarded-for` included.
///
/// Both spellings are matched. `connect_timeout` is a different method name and
/// scanning only for `TcpStream::connect` would have passed here by accident
/// while a new `connect_timeout` client slipped through.
///
/// **Scope, stated rather than implied:** this scans `crates/ferrogate-cli/src`
/// and nothing else. `ferrogate reload --admin-url …` mutates a running
/// gateway's live config through a third raw-TCP client that lives in
/// `ferrogate_gateway::lifecycle`, and it still goes out unattributed. Giving
/// that function an identity argument is a `ferrogate-gateway` change and is
/// follow-up work; it is named in `docs/cli-audit-attribution.md` and in
/// `action_identity`'s module docs rather than left for a reader to discover.
#[test]
fn every_outbound_http_call_goes_through_an_attributed_chokepoint() {
    /// Every sanctioned socket, and why each one is allowed.
    const SANCTIONED: [&str; 2] = [
        "admin_api.rs::connect_upstream",
        "assets_cli.rs::send_request",
    ];

    let source_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut connects: Vec<String> = Vec::new();
    let mut files_scanned = 0usize;
    let mut directories = vec![source_dir];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).expect("the crate's src/ is readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                directories.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<unnamed>")
                .to_string();
            // Test files are not the shipped command surface, and one of them
            // (`admin_api_test.rs`) drives a loopback listener on purpose.
            if name.ends_with("_test.rs") {
                continue;
            }
            files_scanned += 1;
            let source = std::fs::read_to_string(&path).expect("source file is UTF-8");
            let mut enclosing = String::from("<file scope>");
            for line in source.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if let Some(rest) = trimmed
                    .strip_prefix("pub fn ")
                    .or_else(|| trimmed.strip_prefix("fn "))
                    .or_else(|| trimmed.strip_prefix("pub(crate) fn "))
                    .or_else(|| trimmed.strip_prefix("async fn "))
                    .or_else(|| trimmed.strip_prefix("pub async fn "))
                {
                    enclosing = rest
                        .split(['(', '<'])
                        .next()
                        .unwrap_or("<unnamed>")
                        .to_string();
                }
                if trimmed.contains("TcpStream::connect") {
                    connects.push(format!("{name}::{enclosing}"));
                }
            }
        }
    }
    assert!(
        files_scanned > 5,
        "expected the whole crate's src/ tree, scanned only {files_scanned} files"
    );
    connects.sort();
    assert_eq!(
        connects,
        SANCTIONED.map(str::to_string).to_vec(),
        "an unaccounted socket in the CLI. Every request that ORIGINATES here carries a \
         ClientActionIdentity, because a new command group copying the raw client is how \
         `plans` came to POST /admin/v1/plans unattributed. If the new site is a relay rather \
         than an operator action, say so here — do not mint an identity for someone else's \
         request"
    );
}

/// Every command that issues a raw-TCP request mints an identity for it.
///
/// Pins: the `mint_action_identity(...)` call in each of the seven `execute_*`
/// functions across `assets_cli.rs` and `plans_cli.rs`.
///
/// Catches: an `execute_*` that reuses another command's identity by threading
/// one in from elsewhere, or one added tomorrow that forgets to mint. The
/// compiler already refuses a *missing* identity; what it cannot see is a
/// command minting **more than one**, or none of its own — and `action_id` means
/// "one operator action", so a command that minted per request would report
/// several actions where the operator took one.
///
/// The pairing is what is asserted: a file that names `send_request` must name
/// `mint_action_identity` exactly as many times as it has `execute_` entry
/// points that send.
#[test]
fn every_raw_tcp_command_mints_exactly_one_action_identity() {
    let source_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for (file, senders) in [("assets_cli.rs", 4usize), ("plans_cli.rs", 3usize)] {
        let source = std::fs::read_to_string(source_dir.join(file)).expect("source file");
        let statements: Vec<&str> = source
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with("//"))
            .collect();
        let mints = statements
            .iter()
            .filter(|line| line.contains("let identity = mint_action_identity("))
            .count();
        let sends = statements
            .iter()
            .filter(|line| line.starts_with("let response = send_request("))
            .count();
        assert_eq!(
            sends, senders,
            "{file} issues {sends} raw requests; update this test deliberately if that changed"
        );
        assert_eq!(
            mints, senders,
            "{file} mints {mints} identities for {sends} sending commands — one action per \
             invocation, no more and no fewer"
        );
    }
}

/// Pins: the printable-ASCII refusal in `render_header_block`.
///
/// Catches: deleting it, or replacing it with a silent strip. There is no
/// `http::HeaderValue` between this string and the socket — that is the whole
/// difference between this chokepoint and the typed one — so a CR or LF in a
/// value splices an attacker-chosen header into the request. A strip would
/// change what is sent without telling anyone; the refusal is loud.
///
/// The hostile pairs are built by hand, which is why `render_header_block` takes
/// a header list and not a `ClientActionIdentity`: the producing crate's encoder
/// already makes such a value unreachable through `mint`, and a check that can
/// only be fed values that cannot fail it is not a check. This is the
/// boundary's own defence and must hold even if the other crate's guarantee
/// changes.
#[test]
fn a_header_value_that_could_split_the_request_is_refused_not_stripped() {
    for (label, name, value) in [
        (
            "CRLF in the value",
            "x-ferrogate-client-host",
            "runner\r\nx-ferrogate-tenant: org_evil",
        ),
        ("bare LF in the value", "x-ferrogate-client-host", "a\nb"),
        ("NUL in the value", "x-ferrogate-client-host", "a\0b"),
        (
            "non-ASCII in the value",
            "x-ferrogate-client-host",
            "服务器",
        ),
        (
            "CRLF in the name",
            "x-host\r\nx-ferrogate-tenant",
            "org_evil",
        ),
    ] {
        let error = render_header_block(vec![(name.to_string(), value.to_string())])
            .expect_err(&format!("[{label}] must be refused"));
        let message = format!("{error}");
        assert!(
            message.contains("split this request into two"),
            "[{label}] the refusal must name what it prevents: {message}"
        );
    }

    // The mirror: a well-formed identity still renders, or the refusals above
    // would also be satisfied by a function that refused everything.
    let identity = mint_action_identity("http://127.0.0.1:8080", "key").expect("mint");
    let block = render_header_block(identity.headers()).expect("a real identity renders");
    assert!(block.contains(ACTION_ID_HEADER), "{block:?}");

    // The producing crate's encoder is what makes a hostile value unreachable
    // through `mint`; assert that too, so the two halves are joined rather than
    // each assuming the other holds.
    let escaped = ferrogate_control_plane_client::action_identity::encode_header_value(
        "runner\r\nx-ferrogate-tenant: org_evil",
    );
    assert!(
        escaped.chars().all(|ch| matches!(ch as u32, 0x20..=0x7E)),
        "the identity's own encoder must emit printable ASCII only: {escaped}"
    );
    assert!(
        render_header_block(vec![("x-probe".to_string(), escaped.clone())]).is_ok(),
        "an encoded hostile label passes the boundary check: {escaped}"
    );
}
