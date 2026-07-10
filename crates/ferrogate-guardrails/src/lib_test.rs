// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Contract, failure, circuit, concurrency, patch, and SSRF tests for Guardrail detectors.

use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{atomic::AtomicUsize, Barrier},
    thread,
};

#[derive(Debug, Clone)]
struct TestResponse {
    status: u16,
    body: String,
    delay: Duration,
    headers: Vec<(String, String)>,
}

impl TestResponse {
    fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            delay: Duration::ZERO,
            headers: Vec::new(),
        }
    }
}

fn spawn_server(
    expected_requests: usize,
    responder: impl Fn(usize, &str) -> TestResponse + Send + Sync + 'static,
) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/check", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_requests = Arc::clone(&requests);
    let responder = Arc::new(responder);
    thread::spawn(move || {
        let mut workers = Vec::new();
        for index in 0..expected_requests {
            let (mut stream, _) = listener.accept().unwrap();
            let responder = Arc::clone(&responder);
            let requests = Arc::clone(&server_requests);
            workers.push(thread::spawn(move || {
                let raw = read_http_request(&mut stream);
                requests.lock().unwrap().push(raw.clone());
                let response = responder(index, &raw);
                if !response.delay.is_zero() {
                    thread::sleep(response.delay);
                }
                let reason = match response.status {
                    200 => "OK",
                    302 => "Found",
                    401 => "Unauthorized",
                    429 => "Too Many Requests",
                    500 => "Internal Server Error",
                    _ => "Response",
                };
                write!(
                    stream,
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    reason,
                    response.body.len()
                )
                .unwrap();
                for (name, value) in response.headers {
                    write!(stream, "{name}: {value}\r\n").unwrap();
                }
                write!(stream, "\r\n{}", response.body).unwrap();
                stream.flush().unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    });
    (endpoint, requests)
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "connection closed before request headers");
        raw.extend_from_slice(&buffer[..read]);
        if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8_lossy(&raw[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while raw.len() < header_end + content_length {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "connection closed before request body");
        raw.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(raw).unwrap()
}

fn detector_config(endpoint: String) -> CustomHttpDetectorConfig {
    CustomHttpDetectorConfig {
        id: "test-detector".to_string(),
        endpoint,
        timeout: Duration::from_millis(500),
        max_concurrency: 2,
        circuit_failure_threshold: 3,
        circuit_cooldown: Duration::from_millis(50),
        max_retries: 0,
        max_payload_bytes: 16 * 1024,
        max_response_bytes: 16 * 1024,
        allow_private_network: true,
        bearer_token: None,
    }
}

fn input<'a>(text: &'a str) -> DetectorInput<'a> {
    DetectorInput {
        stage: DetectorStage::Request,
        tenant: DetectorTenant {
            organization_id: Some("org-demo"),
            team_id: None,
            project_id: Some("project-demo"),
            user_id: None,
            api_key_id: Some("key-demo"),
        },
        model: Some("fast-chat"),
        provider: Some("openai"),
        text,
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn rejects_private_and_secret_bearing_endpoints_without_explicit_policy() {
    let mut config = detector_config("http://127.0.0.1:8080/check".to_string());
    config.allow_private_network = false;
    let error = CustomHttpDetector::new(config).unwrap_err();
    assert_eq!(error.kind, DetectorErrorKind::InvalidConfiguration);

    let config = detector_config("https://user:password@example.com/check".to_string());
    assert_eq!(
        CustomHttpDetector::new(config).unwrap_err().kind,
        DetectorErrorKind::InvalidConfiguration
    );

    let config = detector_config("https://example.com/check?token=secret".to_string());
    assert_eq!(
        CustomHttpDetector::new(config).unwrap_err().kind,
        DetectorErrorKind::InvalidConfiguration
    );
}

#[test]
fn sends_context_and_accepts_legacy_and_typed_contracts() {
    let (legacy_endpoint, captured) = spawn_server(1, |_, _| {
        TestResponse::json(
            200,
            r#"{"match":true,"matched_text":"john@example.com","category":"pii"}"#,
        )
    });
    let detector = CustomHttpDetector::new(detector_config(legacy_endpoint)).unwrap();
    let result = runtime()
        .block_on(detector.evaluate(
            &input("email john@example.com"),
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap();
    assert_eq!(result.verdict, DetectorVerdict::Fail);
    assert_eq!(result.findings[0].category, "pii");
    assert_eq!(result.first_matched_text(), Some("john@example.com"));
    let request = captured.lock().unwrap()[0].clone();
    assert!(request.contains("\"contract_version\":1"));
    assert!(request.contains("\"organization_id\":\"org-demo\""));
    assert!(request.contains("\"model\":\"fast-chat\""));

    let (typed_endpoint, _) = spawn_server(1, |_, _| {
        TestResponse::json(
            200,
            r#"{"verdict":"pass","findings":[],"detector_version":"vendor-7"}"#,
        )
    });
    let detector = CustomHttpDetector::new(detector_config(typed_endpoint)).unwrap();
    let result = runtime()
        .block_on(detector.evaluate(&input("safe"), Instant::now() + Duration::from_secs(1)))
        .unwrap();
    assert_eq!(result.verdict, DetectorVerdict::Pass);
    assert_eq!(result.detector_version, "vendor-7");
}

#[test]
fn applies_only_valid_non_overlapping_utf8_patches() {
    let text = "secret: José";
    let patches = vec![
        ContentPatch {
            byte_start: 0,
            byte_end: 6,
            replacement: "[REDACTED]".to_string(),
        },
        ContentPatch {
            byte_start: 8,
            byte_end: text.len(),
            replacement: "[NAME]".to_string(),
        },
    ];
    assert_eq!(
        apply_content_patches(text, &patches).unwrap(),
        "[REDACTED]: [NAME]"
    );

    let invalid = vec![ContentPatch {
        byte_start: 12,
        byte_end: 13,
        replacement: "x".to_string(),
    }];
    assert_eq!(
        apply_content_patches(text, &invalid).unwrap_err().kind,
        DetectorErrorKind::InvalidResponse
    );

    let overlapping = vec![
        ContentPatch {
            byte_start: 0,
            byte_end: 6,
            replacement: "x".to_string(),
        },
        ContentPatch {
            byte_start: 5,
            byte_end: 7,
            replacement: "y".to_string(),
        },
    ];
    assert!(validate_content_patches(text, &overlapping).is_err());
}

#[test]
fn classifies_status_invalid_json_and_response_size_failures() {
    for (status, kind) in [
        (401, DetectorErrorKind::Unauthorized),
        (429, DetectorErrorKind::Overloaded),
        (500, DetectorErrorKind::Unavailable),
        (302, DetectorErrorKind::InvalidResponse),
    ] {
        let (endpoint, _) = spawn_server(1, move |_, _| {
            let mut response = TestResponse::json(status, "{}");
            if status == 302 {
                response.headers.push((
                    "Location".to_string(),
                    "http://169.254.169.254/latest/meta-data".to_string(),
                ));
            }
            response
        });
        let detector = CustomHttpDetector::new(detector_config(endpoint)).unwrap();
        let error = runtime()
            .block_on(detector.evaluate(&input("hello"), Instant::now() + Duration::from_secs(1)))
            .unwrap_err();
        assert_eq!(error.kind, kind, "status {status}");
    }

    let (endpoint, _) = spawn_server(1, |_, _| TestResponse::json(200, "not-json"));
    let detector = CustomHttpDetector::new(detector_config(endpoint)).unwrap();
    assert_eq!(
        runtime()
            .block_on(detector.evaluate(&input("hello"), Instant::now() + Duration::from_secs(1),))
            .unwrap_err()
            .kind,
        DetectorErrorKind::InvalidResponse
    );

    let (endpoint, _) = spawn_server(1, |_, _| TestResponse::json(200, "x".repeat(256)));
    let mut config = detector_config(endpoint);
    config.max_response_bytes = 32;
    let detector = CustomHttpDetector::new(config).unwrap();
    assert_eq!(
        runtime()
            .block_on(detector.evaluate(&input("hello"), Instant::now() + Duration::from_secs(1),))
            .unwrap_err()
            .kind,
        DetectorErrorKind::PayloadTooLarge
    );
}

#[test]
fn enforces_deadline_and_request_size() {
    let (endpoint, _) = spawn_server(1, |_, _| {
        let mut response = TestResponse::json(200, r#"{"match":false}"#);
        response.delay = Duration::from_millis(150);
        response
    });
    let mut config = detector_config(endpoint);
    config.timeout = Duration::from_millis(30);
    let detector = CustomHttpDetector::new(config).unwrap();
    let started = Instant::now();
    let error = runtime()
        .block_on(detector.evaluate(&input("hello"), Instant::now() + Duration::from_millis(50)))
        .unwrap_err();
    assert_eq!(error.kind, DetectorErrorKind::Timeout);
    assert!(started.elapsed() < Duration::from_millis(120));

    let (endpoint, _) = spawn_server(0, |_, _| unreachable!());
    let mut config = detector_config(endpoint);
    config.max_payload_bytes = 64;
    let detector = CustomHttpDetector::new(config).unwrap();
    let error = runtime()
        .block_on(detector.evaluate(
            &input(&"x".repeat(512)),
            Instant::now() + Duration::from_secs(1),
        ))
        .unwrap_err();
    assert_eq!(error.kind, DetectorErrorKind::PayloadTooLarge);
}

#[test]
fn circuit_opens_and_allows_one_recovery_probe() {
    let (endpoint, _) = spawn_server(2, |index, _| {
        if index == 0 {
            TestResponse::json(500, "{}")
        } else {
            TestResponse::json(200, r#"{"match":false}"#)
        }
    });
    let mut config = detector_config(endpoint);
    config.circuit_failure_threshold = 1;
    config.circuit_cooldown = Duration::from_millis(30);
    let detector = CustomHttpDetector::new(config).unwrap();
    let runtime = runtime();

    let first = runtime
        .block_on(detector.evaluate(&input("first"), Instant::now() + Duration::from_secs(1)))
        .unwrap_err();
    assert_eq!(first.kind, DetectorErrorKind::Unavailable);
    assert!(detector.health().circuit_open);

    let second = runtime
        .block_on(detector.evaluate(&input("second"), Instant::now() + Duration::from_secs(1)))
        .unwrap_err();
    assert_eq!(second.kind, DetectorErrorKind::CircuitOpen);
    assert_eq!(detector.health().failure_total, 2);

    thread::sleep(Duration::from_millis(40));
    let recovered = runtime
        .block_on(detector.evaluate(&input("third"), Instant::now() + Duration::from_secs(1)))
        .unwrap();
    assert_eq!(recovered.verdict, DetectorVerdict::Pass);
    assert!(!detector.health().circuit_open);
}

#[test]
fn bulkhead_bounds_concurrent_slow_calls() {
    let barrier = Arc::new(Barrier::new(2));
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let server_barrier = Arc::clone(&barrier);
    let server_active = Arc::clone(&active);
    let server_max = Arc::clone(&max_active);
    let (endpoint, _) = spawn_server(1, move |_, _| {
        let current = server_active.fetch_add(1, Ordering::SeqCst) + 1;
        server_max.fetch_max(current, Ordering::SeqCst);
        server_barrier.wait();
        let mut response = TestResponse::json(200, r#"{"match":false}"#);
        response.delay = Duration::from_millis(100);
        server_active.fetch_sub(1, Ordering::SeqCst);
        response
    });
    let mut config = detector_config(endpoint);
    config.max_concurrency = 1;
    let detector = Arc::new(CustomHttpDetector::new(config).unwrap());
    let runtime = runtime();

    runtime.block_on(async {
        let first_detector = Arc::clone(&detector);
        let first = tokio::spawn(async move {
            first_detector
                .evaluate(&input("first"), Instant::now() + Duration::from_secs(1))
                .await
        });
        barrier.wait();
        let second = detector
            .evaluate(&input("second"), Instant::now() + Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(second.kind, DetectorErrorKind::Overloaded);
        assert_eq!(detector.health().failure_total, 1);
        assert_eq!(first.await.unwrap().unwrap().verdict, DetectorVerdict::Pass);
    });
    assert_eq!(max_active.load(Ordering::SeqCst), 1);
}

#[test]
fn bearer_token_is_sent_but_never_debugged() {
    let (endpoint, captured) =
        spawn_server(1, |_, _| TestResponse::json(200, r#"{"match":false}"#));
    let mut config = detector_config(endpoint.replace("/check", "/detector-path-secret"));
    config.bearer_token = Some(DetectorSecret::new("detector-super-secret".to_string()));
    let detector = CustomHttpDetector::new(config).unwrap();
    assert!(!format!("{detector:?}").contains("detector-super-secret"));
    assert!(!format!("{detector:?}").contains("detector-path-secret"));
    runtime()
        .block_on(detector.evaluate(&input("hello"), Instant::now() + Duration::from_secs(1)))
        .unwrap();
    let request = captured.lock().unwrap()[0].clone();
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer detector-super-secret"));
}

#[test]
fn rejects_private_and_special_use_ip_ranges() {
    for ip in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.1",
        "192.168.1.1",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(
            is_disallowed_detector_ip(ip.parse().unwrap()),
            "{ip} should be disallowed"
        );
    }
    for ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
        assert!(
            !is_disallowed_detector_ip(ip.parse().unwrap()),
            "{ip} should be allowed"
        );
    }
}

#[test]
fn dns_rebinding_to_private_addresses_is_filtered_on_every_resolution() {
    let public = filter_resolved_detector_addresses(["1.1.1.1:443".parse().unwrap()], false);
    assert_eq!(public.len(), 1);

    let rebound = filter_resolved_detector_addresses(
        [
            "127.0.0.1:443".parse().unwrap(),
            "169.254.169.254:80".parse().unwrap(),
        ],
        false,
    );
    assert!(rebound.is_empty());
}
