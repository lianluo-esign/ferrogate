// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Process-boundary proof that typed request capabilities filter
// physical model routes before strategy ordering and dispatch (issue #582).

mod support;

use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};

use serde_json::{json, Value};
use support::{free_addr, http_request, start_gateway, wait_for_gateway};

struct ObservedUpstream {
    addr: String,
    requests: Arc<Mutex<Vec<Value>>>,
    stop: mpsc::Sender<()>,
    handle: thread::JoinHandle<()>,
}

impl ObservedUpstream {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let (stop, stopped) = mpsc::channel();
        let handle = thread::spawn(move || loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = read_json_request(&mut stream);
                    observed.lock().unwrap().push(request);
                    let response = r#"{"id":"chatcmpl-route","object":"chat.completion","created":1,"model":"tool-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}"#;
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response.len(),
                        response
                    )
                    .unwrap();
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if stopped.recv_timeout(Duration::from_millis(10)).is_ok() {
                        break;
                    }
                }
                Err(error) => panic!("mock upstream accept failed: {error}"),
            }
        });
        Self {
            addr,
            requests,
            stop,
            handle,
        }
    }

    fn finish(self) -> Vec<Value> {
        let _ = self.stop.send(());
        self.handle.join().unwrap();
        Arc::try_unwrap(self.requests)
            .expect("mock request observer still referenced")
            .into_inner()
            .unwrap()
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

fn read_json_request(stream: &mut TcpStream) -> Value {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 2048];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "upstream request closed before its body arrived");
        request.extend_from_slice(&buffer[..read]);
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .expect("provider request has Content-Length");
        if request.len() >= body_start + content_length {
            return serde_json::from_slice(&request[body_start..body_start + content_length])
                .expect("provider request body is JSON");
        }
    }
}

fn response_json(response: &str) -> Value {
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    serde_json::from_str(body)
        .unwrap_or_else(|error| panic!("response body was not JSON ({error}): {response}"))
}

fn response_header<'a>(response: &'a str, expected: &str) -> &'a str {
    response
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(expected).then(|| value.trim())
        })
        .unwrap_or_else(|| panic!("missing {expected} header: {response}"))
}

#[test]
fn incompatible_cheaper_route_is_excluded_before_dispatch_and_explained() {
    let incompatible = ObservedUpstream::spawn();
    let compatible = ObservedUpstream::spawn();
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "incompatible"
kind = "openai"
base_url = "http://{}/v1"

[[providers]]
name = "compatible"
kind = "openai"
base_url = "http://{}/v1"

[[models]]
name = "tool-model"
provider = "incompatible"
provider_model = "tool-model"
routing_strategy = "lowest_cost"
capabilities = ["chat", "vision"]
context_window = 8192
input_price_per_1m = 0.01
output_price_per_1m = 0.01

[[models.fallbacks]]
provider = "compatible"
provider_model = "tool-model"
capabilities = ["chat", "tools", "vision"]
context_window = 32768
input_price_per_1m = 10.0
output_price_per_1m = 10.0

[[api_keys]]
id = "route-client"
name = "Route client"
key = "route-secret"
scopes = ["chat.completions"]
allowed_models = ["tool-model"]
platform_operator = true

[[api_keys]]
id = "route-admin"
name = "Route admin"
key = "admin-secret"
scopes = ["admin.read"]
platform_operator = true
"#,
            incompatible.addr, compatible.addr
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    let request = json!({
        "model": "tool-model",
        "stream": false,
        "messages": [{"role": "user", "content": "PROMPT_SECRET"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "description": "TOOL_ARGUMENT_SECRET",
                "parameters": {"type": "object", "properties": {}}
            }
        }]
    });
    let response = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer route-secret",
            "Content-Type: application/json",
        ],
        &request.to_string(),
    );
    assert!(response.contains("200 OK"), "{response}");
    let request_id = response_header(&response, "x-request-id").to_string();

    let investigation_response = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={request_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        investigation_response.contains("200 OK"),
        "{investigation_response}"
    );
    let investigation = response_json(&investigation_response);
    let events = investigation["audit_events"].as_array().unwrap();
    let exclusion = events
        .iter()
        .find(|event| event["action"] == "model_route.excluded")
        .unwrap_or_else(|| panic!("missing route exclusion evidence: {investigation}"));
    assert_eq!(exclusion["request_id"], request_id);
    assert_eq!(exclusion["actor_api_key_id"], "route-client");
    assert_eq!(exclusion["outcome"], "missing_capability");
    assert!(
        exclusion["target"]
            .as_str()
            .unwrap()
            .contains("provider=incompatible;provider_model=tool-model"),
        "{exclusion}"
    );
    assert!(
        exclusion["message"]
            .as_str()
            .unwrap()
            .contains("required_capability=tools"),
        "{exclusion}"
    );
    let selected = events
        .iter()
        .find(|event| event["action"] == "model_route.selected")
        .unwrap_or_else(|| panic!("missing selected-route evidence: {investigation}"));
    assert_eq!(selected["outcome"], "lowest_cost");
    assert!(
        selected["target"]
            .as_str()
            .unwrap()
            .contains("provider=compatible;provider_model=tool-model"),
        "{selected}"
    );
    let evidence = investigation.to_string();
    assert!(!evidence.contains("PROMPT_SECRET"), "{investigation}");
    assert!(
        !evidence.contains("TOOL_ARGUMENT_SECRET"),
        "{investigation}"
    );
    assert!(!evidence.contains("route-secret"), "{investigation}");

    let rejected_request = json!({
        "model": "tool-model",
        "messages": [{"role": "user", "content": "REJECTED_PROMPT_SECRET"}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "answer", "schema": {"type": "object"}}
        }
    });
    let rejected = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer route-secret",
            "Content-Type: application/json",
        ],
        &rejected_request.to_string(),
    );
    assert!(rejected.contains("400 Bad Request"), "{rejected}");
    let rejected_request_id = response_header(&rejected, "x-request-id");
    let rejected_investigation_response = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={rejected_request_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    );
    let rejected_investigation = response_json(&rejected_investigation_response);
    let rejected_events = rejected_investigation["audit_events"].as_array().unwrap();
    let structured_exclusions = rejected_events
        .iter()
        .filter(|event| {
            event["action"] == "model_route.excluded"
                && event["outcome"] == "missing_capability"
                && event["message"].as_str().is_some_and(|message| {
                    message.contains("required_capability=structured_output")
                })
        })
        .count();
    assert_eq!(structured_exclusions, 2, "{rejected_investigation}");
    assert!(
        !rejected_events
            .iter()
            .any(|event| event["action"] == "model_route.selected"),
        "{rejected_investigation}"
    );
    assert!(
        !rejected_investigation
            .to_string()
            .contains("REJECTED_PROMPT_SECRET"),
        "{rejected_investigation}"
    );

    let context_prompt = format!("CONTEXT_PROMPT_SECRET{}", "x".repeat(8_192));
    let context_request = json!({
        "model": "tool-model",
        "messages": [{
            "role": "user",
            "content": context_prompt.clone()
        }],
        "max_completion_tokens": 1
    });
    let expected_context_request = json!({
        "model": "tool-model",
        "stream": false,
        "messages": [{
            "role": "user",
            "content": context_prompt
        }],
        "max_completion_tokens": 1
    });
    let context_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer route-secret",
            "Content-Type: application/json",
        ],
        &context_request.to_string(),
    );
    assert!(context_response.contains("200 OK"), "{context_response}");
    let context_request_id = response_header(&context_response, "x-request-id");
    let context_investigation_response = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={context_request_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    );
    let context_investigation = response_json(&context_investigation_response);
    let context_events = context_investigation["audit_events"].as_array().unwrap();
    let context_exclusion = context_events
        .iter()
        .find(|event| {
            event["action"] == "model_route.excluded"
                && event["outcome"] == "context_window_too_small"
        })
        .unwrap_or_else(|| panic!("missing context exclusion: {context_investigation}"));
    assert!(
        context_exclusion["target"]
            .as_str()
            .unwrap()
            .contains("provider=incompatible;provider_model=tool-model"),
        "{context_exclusion}"
    );
    let context_message = context_exclusion["message"].as_str().unwrap();
    assert!(context_message.contains("declared_context_window=8192"));
    assert!(context_message.contains("input_token_upper_bound="));
    assert!(context_message.contains("explicit_output_tokens=1"));
    assert!(!context_message.contains("CONTEXT_PROMPT_SECRET"));
    let context_selected = context_events
        .iter()
        .find(|event| event["action"] == "model_route.selected")
        .unwrap_or_else(|| panic!("missing context selection: {context_investigation}"));
    assert!(
        context_selected["target"]
            .as_str()
            .unwrap()
            .contains("provider=compatible;provider_model=tool-model"),
        "{context_selected}"
    );
    assert!(
        !context_investigation
            .to_string()
            .contains("CONTEXT_PROMPT_SECRET"),
        "{context_investigation}"
    );

    let no_output_prompt = format!("NO_OUTPUT_PROMPT_SECRET{}", "y".repeat(40_000));
    let no_output_request = json!({
        "model": "tool-model",
        "messages": [{
            "role": "user",
            "content": no_output_prompt
        }]
    });
    let compatible_before_no_output = compatible.request_count();
    let no_output_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer route-secret",
            "Content-Type: application/json",
        ],
        &no_output_request.to_string(),
    );
    assert!(
        no_output_response.contains("400 Bad Request"),
        "{no_output_response}"
    );
    let no_output_request_id = response_header(&no_output_response, "x-request-id");
    let no_output_investigation_response = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={no_output_request_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    );
    let no_output_investigation = response_json(&no_output_investigation_response);
    let no_output_events = no_output_investigation["audit_events"].as_array().unwrap();
    let no_output_exclusions = no_output_events
        .iter()
        .filter(|event| {
            event["action"] == "model_route.excluded"
                && event["outcome"] == "context_window_too_small"
        })
        .collect::<Vec<_>>();
    assert_eq!(no_output_exclusions.len(), 2, "{no_output_investigation}");
    assert!(no_output_exclusions.iter().any(|event| event["target"]
        .as_str()
        .unwrap()
        .contains("provider=incompatible;provider_model=tool-model")));
    assert!(no_output_exclusions.iter().any(|event| event["target"]
        .as_str()
        .unwrap()
        .contains("provider=compatible;provider_model=tool-model")));
    let no_output_message = no_output_exclusions[0]["message"].as_str().unwrap();
    assert!(no_output_message.contains("input_token_upper_bound="));
    assert!(no_output_message.contains("explicit_output_tokens=none"));
    assert!(no_output_message.contains("required_context_window="));
    assert!(
        !no_output_events
            .iter()
            .any(|event| event["action"] == "model_route.selected"),
        "{no_output_investigation}"
    );
    assert!(
        !no_output_investigation
            .to_string()
            .contains("NO_OUTPUT_PROMPT_SECRET"),
        "{no_output_investigation}"
    );
    assert_eq!(compatible.request_count(), compatible_before_no_output);
    assert_eq!(incompatible.request_count(), 0);

    let image_request = json!({
        "model": "tool-model",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "IMAGE_PROMPT_SECRET"},
                {"type": "image_url", "image_url": {"url": "https://example.test/IMAGE_PROMPT_SECRET.png"}}
            ]
        }]
    });
    let compatible_before_image = compatible.request_count();
    let image_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer route-secret",
            "Content-Type: application/json",
        ],
        &image_request.to_string(),
    );
    assert!(
        image_response.contains("400 Bad Request"),
        "{image_response}"
    );
    let image_request_id = response_header(&image_response, "x-request-id");
    let image_investigation_response = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={image_request_id}"),
        &["Authorization: Bearer admin-secret"],
        "",
    );
    let image_investigation = response_json(&image_investigation_response);
    let image_events = image_investigation["audit_events"].as_array().unwrap();
    let image_exclusions = image_events
        .iter()
        .filter(|event| {
            event["action"] == "model_route.excluded"
                && event["outcome"] == "media_context_unbounded"
        })
        .collect::<Vec<_>>();
    assert_eq!(image_exclusions.len(), 2, "{image_investigation}");
    assert!(image_exclusions.iter().any(|event| event["target"]
        .as_str()
        .unwrap()
        .contains("provider=incompatible;provider_model=tool-model")));
    assert!(image_exclusions.iter().any(|event| event["target"]
        .as_str()
        .unwrap()
        .contains("provider=compatible;provider_model=tool-model")));
    for exclusion in image_exclusions {
        let message = exclusion["message"].as_str().unwrap();
        assert!(message.contains("media_kind=image"));
        assert!(message.contains("provider_neutral_token_upper_bound=unavailable"));
        assert!(message.contains("input_token_upper_bound=none"));
        assert!(message.contains("required_context_window=none"));
        assert!(message.contains("unbounded_media_context=true"));
    }
    assert!(
        !image_events
            .iter()
            .any(|event| event["action"] == "model_route.selected"),
        "{image_investigation}"
    );
    assert!(
        !image_investigation
            .to_string()
            .contains("IMAGE_PROMPT_SECRET"),
        "{image_investigation}"
    );
    assert_eq!(compatible.request_count(), compatible_before_image);
    assert_eq!(incompatible.request_count(), 0);

    let compatible_requests = compatible.finish();
    let incompatible_requests = incompatible.finish();
    assert_eq!(incompatible_requests, Vec::<Value>::new());
    assert_eq!(compatible_requests, [request, expected_context_request]);

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
