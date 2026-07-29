use super::*;

use std::{
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};

use ferrogate_control_plane_client::{
    action_identity::{ClientActionIdentity, FingerprintEnv},
    auth::AuthSource,
    context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS},
    output::OutputFormat,
};

fn action_identity(endpoint: &str) -> ClientActionIdentity {
    let context = EffectiveContext {
        context_name: None,
        endpoint: endpoint.to_string(),
        tenant: None,
        project: None,
        workspace: None,
        ca_bundle_path: None,
        tls_insecure_skip_verify: false,
        timeout_millis: DEFAULT_TIMEOUT_MILLIS,
        auth: AuthSource::Inline {
            token: "admin-secret".to_string(),
        },
        output: OutputFormat::Json,
        non_interactive: true,
    };
    let identity = ClientActionIdentity::mint(
        &context,
        &FingerprintEnv {
            host_label: None,
            reported_ip: Some("203.0.113.9".to_string()),
        },
    )
    .unwrap();
    let token = format!(
        "v1;issued_at={};ttl=30;action_id={};sig=opaque",
        identity.client_clock().unverified_unix_seconds(),
        identity.action_id()
    );
    identity
        .accept_server_time(&token)
        .expect("the fixture identity holds an echoed server token");
    identity
}

#[test]
fn admin_reload_writes_every_client_action_identity_header_to_the_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port is free");
    listener
        .set_nonblocking(true)
        .expect("the loopback listener becomes nonblocking");
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::yield_now();
                }
                Err(error) => panic!("admin reload did not connect: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => head.push(byte[0]),
                Err(error) => panic!("failed to read admin reload request head: {error}"),
            }
        }
        let head = String::from_utf8(head).unwrap();
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or_default();
        let mut remaining = content_length;
        let mut body = [0_u8; 1024];
        while remaining > 0 {
            let chunk = remaining.min(body.len());
            stream
                .read_exact(&mut body[..chunk])
                .unwrap_or_else(|error| panic!("failed to drain admin reload body: {error}"));
            remaining -= chunk;
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .unwrap();
        head
    });

    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("candidate.toml");
    std::fs::write(&config_path, "").unwrap();
    let endpoint = format!("http://{address}");
    let identity = action_identity(&endpoint);
    let identity_headers = identity.headers();
    assert_eq!(
        identity_headers.len(),
        5,
        "the fixture exercises unconditional and optional identity headers"
    );

    execute_admin_reload(
        &endpoint,
        Some("admin-secret"),
        &config_path,
        &Config::default(),
        &identity,
    )
    .expect("the loopback admin API accepts the reload");
    let head = server.join().expect("the loopback server did not panic");
    assert!(head.starts_with("POST /admin/v1/config/reload HTTP/1.1\r\n"));
    assert!(head.ends_with("\r\n\r\n"));
    for (name, value) in identity_headers {
        assert!(
            head.contains(&format!("\r\n{name}: {value}\r\n")),
            "{name} did not reach the socket: {head:?}"
        );
    }
}
