// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The **second** audit chokepoint (issue #548).
//!
//! `ferrogate-control-plane-client`'s `prepare_request` is the chokepoint every
//! `ctl` verb goes through; its closed request type proves attributed headers
//! enter the transport, and a separate loopback test proves the production
//! transport sends them. It is not the only way this binary puts bytes on the
//! wire: `assets` and `plans` predate the
//! typed client and drive a hand-rolled raw-`TcpStream` HTTP client, because
//! `main()` is a synchronous entry point. Between them they issue seven
//! requests, four of them **mutations** — two of those Control Plane mutations
//! with no registry family to route through instead — and three of them reads,
//! which this issue asks for too.
//!
//! These tests hold the two halves of closing that: that `send_request` really
//! writes the identity into the bytes it puts on a socket — asserted against a
//! loopback listener, because a test on the rendered block alone cannot see the
//! one line that moves the block into the request — and that no *third*
//! hand-rolled client appears without a test going red.

use super::*;
use ferrogate_control_plane_client::action_identity::{
    ACTION_ID_HEADER, CLIENT_CLOCK_HEADER, CLIENT_FINGERPRINT_HEADER,
};

/// The withheld warning belongs to `assets push`, not to the JSON helper also
/// used by list/delete and every plans command. The production push writer is
/// driven with in-memory streams so deleting the 202 branch, changing its
/// terminal, or sending the warning to stdout makes this assertion red.
#[test]
fn only_a_202_asset_push_emits_the_withheld_warning() {
    for status in [200, 201] {
        let response = RawHttpResponse {
            status,
            body: br#"{"asset":{"visibility":"visible"}}"#.to_vec(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        write_asset_push_response(&response, &mut stdout, &mut stderr)
            .expect("an ordinary successful push prints its response");
        let mut expected_stdout = response.body.clone();
        expected_stdout.push(b'\n');
        assert_eq!(
            stdout, expected_stdout,
            "the success body must remain machine-readable on stdout with one trailing newline"
        );
        assert!(
            stderr.is_empty(),
            "status {status} is not withheld and must not emit the 202 warning: {}",
            String::from_utf8_lossy(&stderr)
        );
    }

    let response = RawHttpResponse {
        status: 202,
        body: br#"{"asset":{"visibility":"pending_scan"}}"#.to_vec(),
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    write_asset_push_response(&response, &mut stdout, &mut stderr)
        .expect("a withheld push is still a successful write");

    let mut expected_stdout = response.body.clone();
    expected_stdout.push(b'\n');
    assert_eq!(
        stdout, expected_stdout,
        "the withheld response body must stay on stdout without warning text"
    );
    let warning = String::from_utf8(stderr).expect("the warning is UTF-8");
    assert!(
        warning.contains("asset is WITHHELD pending screening")
            && warning.contains("not downloadable until promoted"),
        "the 202 warning must state the actual asset consequence: {warning:?}"
    );
}

/// Pins: `render_header_block` emitting every header
/// `ClientActionIdentity::headers` returns, in `Name: value\r\n` form.
///
/// Catches: emitting a subset — the action id is what the whole correlation
/// rests on, and the fingerprint and clock are what make the record readable —
/// and a leak of the credential into the block.
///
/// **It does not catch dropping `request.push_str(&identity_headers)`.** An
/// earlier revision of this doc said it did, and that was written from intent
/// rather than from tracing it: this test never calls `send_request`, so
/// deleting that line and rebinding the render call to `let _ = ...` leaves it
/// green while all seven requests go out unattributed. The test that holds that
/// line is [`send_request_writes_the_identity_onto_the_socket`], which drives a
/// loopback listener and reads the head off the wire.
#[test]
fn the_raw_tcp_client_renders_the_action_identity_into_a_header_block() {
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

/// The bytes `send_request` actually writes to a socket carry the identity.
///
/// Pins: `assets_cli.rs`'s `request.push_str(&identity_headers);` — the single
/// line that moves the rendered block into the request.
///
/// Catches: deleting that line and rebinding the render call above it to
/// `let _ = render_header_block(identity.headers())?;`. That compiles clean and
/// warns about nothing, and it is invisible to every other test in this file:
/// [`the_raw_tcp_client_renders_the_action_identity_into_a_header_block`]
/// exercises the renderer, the socket census still finds `TcpStream::connect`,
/// and the mint census still counts lines. Under it all seven `assets`/`plans`
/// requests revert to unattributed with the suite green — which is the whole
/// hole issue #548 exists to close.
///
/// A loopback `TcpListener` is what makes this assertable, and it needs neither
/// Docker nor a database: `admin_api.rs` already binds one in this crate. The
/// server thread reads the head, answers a minimal response and half-closes,
/// because `send_request` reads to EOF.
///
/// It also asserts the *placement*, not just the presence: the identity must be
/// inside the head, before the blank line. A header written after `\r\n\r\n`
/// would be body bytes, and the `Content-Length: 0` on this request means no
/// server would ever read them.
#[test]
fn send_request_writes_the_identity_onto_the_socket() {
    const API_KEY: &str = "fgk_live_secret_value";

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port is free");
    listener
        .set_nonblocking(true)
        .expect("the loopback listener becomes nonblocking");
    let port = listener
        .local_addr()
        .expect("the listener reports its address")
        .port();

    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::yield_now();
                }
                Err(error) => panic!("the client did not connect: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("the accepted socket gets a read timeout");
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("the accepted socket gets a write timeout");
        let mut head: Vec<u8> = Vec::new();
        let mut byte = [0u8; 1];
        // Byte at a time: the head is a few hundred bytes and this needs no
        // buffering logic to know where it ends.
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => head.push(byte[0]),
                Err(error) => panic!("failed to read the request head: {error}"),
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            .expect("the loopback response is written");
        drop(stream);
        String::from_utf8(head).expect("the request head is UTF-8")
    });

    let gateway_url = format!("http://127.0.0.1:{port}");
    let endpoint = GatewayEndpoint::parse(&gateway_url).expect("a loopback URL parses");
    let identity = mint_action_identity(&gateway_url, API_KEY)
        .expect("the OS random source is available in the test env");
    let expected_action_id = identity.action_id().to_string();
    let expected_client_clock = identity.client_clock().render();

    let response = send_request(
        &endpoint,
        "GET",
        "/v1/assets",
        API_KEY,
        None,
        &[],
        &identity,
    )
    .expect("the loopback server answers");
    assert_eq!(
        response.status, 200,
        "the fixture server answered 200; a different status means this test read the wrong thing"
    );

    let head = server.join().expect("the server thread did not panic");

    // The head really is a head — without this the assertions below could be
    // satisfied by a truncated read.
    assert!(
        head.starts_with("GET /v1/assets HTTP/1.1\r\n"),
        "the request line is not what send_request claims to build: {head:?}"
    );
    assert!(
        head.ends_with("\r\n\r\n"),
        "the head was not read to its terminator: {head:?}"
    );

    let (head_only, _) = head
        .split_once("\r\n\r\n")
        .expect("the head terminator was just asserted");
    for header in [
        ACTION_ID_HEADER,
        CLIENT_FINGERPRINT_HEADER,
        CLIENT_CLOCK_HEADER,
    ] {
        assert!(
            head_only.contains(&format!("\r\n{header}: ")),
            "'{header}' never reached the socket: {head:?}"
        );
    }
    assert!(
        head_only.contains(&format!("\r\n{ACTION_ID_HEADER}: {expected_action_id}\r\n")),
        "the socket carries an action id, but not THIS invocation's ({expected_action_id}): \
         {head:?}"
    );
    assert!(
        !expected_client_clock.is_empty()
            && head_only.contains(&format!(
                "\r\n{CLIENT_CLOCK_HEADER}: {expected_client_clock}\r\n"
            )),
        "the socket must carry this invocation's non-empty client clock reading: {head:?}"
    );
    // The same leak check as the renderer test, at the place it would actually
    // matter: these are the bytes that left the process. The positive control is
    // the count — the key IS on the wire, exactly once, in the one header that
    // is supposed to carry it, so "not in the identity headers" is a real
    // restriction rather than a statement about an absent string.
    assert!(
        head_only.contains(&format!("Authorization: Bearer {API_KEY}\r\n")),
        "the request must still authenticate, or the leak check below is vacuous: {head:?}"
    );
    assert_eq!(
        head_only.matches(API_KEY).count(),
        1,
        "the credential appears more than once in the head; Authorization is the only header \
         that may carry it: {head:?}"
    );
    let identity_lines: Vec<&str> = head_only
        .lines()
        .filter(|line| line.starts_with("x-ferrogate-"))
        .collect();
    assert!(
        identity_lines.iter().all(|line| !line.contains("fgk_")),
        "an identity header on the wire carries a prefix of the API key: {identity_lines:?}"
    );
    assert!(
        identity_lines
            .iter()
            .any(|line| line.contains("cred=inline")),
        "the credential SOURCE must be on the wire, or the assertion above is vacuous: \
         {identity_lines:?}"
    );
}

/// Every HTTP client this crate constructs is accounted for, by name.
///
/// Pins: the complete set of `TcpStream::connect*` **and** `reqwest` client
/// sites in `crates/ferrogate-cli/src`.
///
/// Catches: a fourth command group copying the raw client into a new file —
/// which is precisely how this hole was made. `send_request` is `pub(crate)`
/// with a doc that recommends reuse, so the *next* author does the same thing
/// the `plans` author did, and a copy would carry no identity and red nothing.
/// A source scan is the only assertion that can speak for code not yet written.
///
/// It scans for the client-construction call rather than for a header name,
/// because the defect is "bytes left the process through a path with no identity
/// on it", and a new client would not mention any of #548's constants at all.
///
/// # Why `reqwest` is on the needle list
///
/// An earlier cut scanned only `TcpStream::connect` while calling itself "every
/// outbound HTTP call". It was not: `reqwest` is a **declared, currently unused
/// direct dependency** of `ferrogate-cli`, so a `reqwest::Client` in a new
/// command file was a bypass that reded nothing. Direct qualified calls and
/// `use reqwest...` imports are both scanned, so `Client::new()` through an
/// import or alias is still a review event.
///
/// `reqwest::Url` is deliberately *not* a needle — it is a URL parser, not a
/// client, and `ctl/fingerprint_parity_test.rs` uses it to build an expected
/// string. The residual is stated rather than implied: this is a lexical guard,
/// not Rust name resolution. A client re-exported from another already-linked
/// crate can still evade it, so the loopback tests remain the behavioral proof
/// for the two production chokepoints this file knows about.
///
/// # The allow-list
///
/// Two entries, each with a reason, so a new one is a decision someone has to
/// write down rather than a count someone has to bump:
///
/// * `assets_cli.rs::send_request` — the attributed raw client. Takes a
///   `&ClientActionIdentity` and writes its headers into the request.
/// * `admin_api.rs::connect_upstream` — **not** an originating CLI action.
///   `ferrogate admin-api` is a reverse proxy: it relays a request the admin
///   console made, and minting an `action_id` there would attribute the
///   console's action to the proxy process and put a false actor in the audit
///   trail. It forwards the caller's own headers, `x-forwarded-for` included.
///   See the boundary note in `docs/cli-audit-attribution.md`: the console
///   itself sends no identity header today, so a console mutation through this
///   proxy is unattributed. That is server-and-console work, not a hole in this
///   crate, and it is written down in both places rather than presented as
///   solved.
///
/// [`send_request_writes_the_identity_onto_the_socket`] binds a loopback
/// `TcpListener` and is deliberately **not** on the list: a listener is not an
/// outbound client, and the connect it provokes is `send_request`'s own, already
/// accounted for above. It is named here so a reader does not go looking for it.
///
/// `connect_timeout` is matched by the same needle because it shares the prefix;
/// scanning for the exact string `TcpStream::connect(` would have passed here by
/// accident while a new `connect_timeout` client slipped through.
///
/// # No file-path self-exemption
///
/// This scan used to skip `*_test.rs`, recorded as "one of them
/// (`admin_api_test.rs`) drives a loopback listener on purpose". That was false
/// at the time it was written — `admin_api_test.rs` contains no `TcpStream` at
/// all — and a file-path exemption is the #561 shape: it exempts exactly the
/// code most likely to normalise a bypass. The needles are assembled at runtime
/// instead, so this file's own scan lines are not hits and every file in the
/// tree is subject to the rule.
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
    /// Every sanctioned client site, and why each one is allowed.
    const SANCTIONED: [&str; 2] = [
        "admin_api.rs::connect_upstream",
        "assets_cli.rs::send_request",
    ];

    // Assembled at runtime so the lines below are not hits on themselves. The
    // alternative — skipping `*_test.rs` — exempts the code most likely to
    // normalise a bypass, and its recorded reason was false besides.
    let needles = [
        format!("{}{}", "TcpStream", "::connect"),
        format!("{}{}", "reqwest", "::Client"),
        format!("{}{}", "reqwest", "::blocking"),
        format!("{}{}", "reqwest", "::get("),
        format!("{}{}", "use ", "reqwest"),
        format!("{}{}", "use std::net::", "TcpStream as "),
        format!("{}{}", "use std::net::{", "TcpStream as "),
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
                if needles.iter().any(|needle| trimmed.contains(needle)) {
                    connects.push(format!("{name}::{enclosing}"));
                }
            }
        }
    }
    assert!(
        files_scanned > 5,
        "expected the whole crate's src/ tree, scanned only {files_scanned} files"
    );
    // A positive control on the matcher itself: a floor on the file count proves
    // the walk, not the detector. `TcpStream::connect` is real code in this
    // crate and the scan must be finding it, or `connects` could be empty for a
    // reason that has nothing to do with the rule.
    assert!(
        connects.contains(&"assets_cli.rs::send_request".to_string()),
        "the scan did not find the raw client it is written around; the needles no longer match \
         anything and this guard is green over a tree it cannot see: {connects:?}"
    );
    connects.sort();
    assert_eq!(
        connects,
        SANCTIONED.map(str::to_string).to_vec(),
        "an unaccounted HTTP client in the CLI. Every request that ORIGINATES here carries a \
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
        ("DEL in the value", "x-ferrogate-client-host", "a\u{7f}b"),
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
    let visible_boundary = render_header_block(vec![(
        "x-probe".to_string(),
        "visible~/boundary\u{7e}".to_string(),
    )])
    .expect("0x7E and the reviewed safe punctuation pass the raw boundary");
    assert!(
        visible_boundary.contains("x-probe: visible~/boundary~\r\n"),
        "the inclusive 0x7E boundary and safe '~'/'/' values are preserved: \
         {visible_boundary:?}"
    );
}
