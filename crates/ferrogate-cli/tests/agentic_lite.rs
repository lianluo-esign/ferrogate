mod support;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
};

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

#[test]
fn agentic_lite_builtin_tools_are_visible_and_explicitly_executable() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, builtin_tools_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let admin_extensions = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/extensions",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(admin_extensions["data"].as_array().unwrap().len(), 4);
    assert!(admin_extensions["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|extension| extension["id"] == "tool.echo" && extension["active"] == true));
    assert!(admin_extensions["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|extension| extension["id"] == "tool.health_check" && extension["active"] == false));

    let admin_tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tools",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(admin_tools["data"][0]["name"], "tool.echo");
    assert!(admin_tools["data"][0].get("config").is_none());

    let tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/tools",
        &["Authorization: Bearer tool-secret"],
        "",
    ));
    assert_eq!(tools["data"][0]["name"], "tool.echo");

    let executed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"tool.echo","arguments":{"message":"hello"},"session_id":"session-1"}"#,
    ));
    assert_eq!(executed["object"], "tool_execution");
    assert_eq!(executed["name"], "tool.echo");
    assert_eq!(executed["content"]["echo"]["message"], "hello");
    assert_eq!(executed["session_id"], "session-1");

    let denied = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"tool.health_check","arguments":{}}"#,
    ));
    assert_eq!(denied["error"]["code"], "tool_not_found");

    let audit_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let events = audit_events["data"].as_array().unwrap();
    assert!(events.iter().any(|event| {
        event["action"] == "tool.execute"
            && event["target"] == "tool_session:session-1"
            && event["outcome"] == "success"
            && event["message"].as_str().unwrap().contains("tool.echo")
    }));
    assert!(events.iter().any(|event| {
        event["action"] == "tool.execute"
            && event["target"] == "tool.health_check"
            && event["outcome"] == "error"
    }));

    let session_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tool-sessions/session-1",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let session_events = session_events["data"].as_array().unwrap();
    assert_eq!(session_events.len(), 1);
    assert_eq!(session_events[0]["action"], "tool.execute");
    assert_eq!(session_events[0]["target"], "tool_session:session-1");
    assert_eq!(session_events[0]["outcome"], "success");
    assert!(session_events[0]["message"]
        .as_str()
        .unwrap()
        .contains("tool.echo"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn agentic_lite_mcp_http_provider_imports_and_executes_allowed_tools() {
    let (mcp_addr, mcp_handle) = spawn_mcp_server(2);
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, mcp_config(&gateway_addr, &mcp_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tools",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(tools["data"][0]["name"], "github.search");
    assert!(tools["data"][0].get("config").is_none());

    let extensions = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/extensions",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let mcp = extensions["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|extension| extension["id"] == "mcp.http")
        .unwrap();
    assert_eq!(mcp["active"], true);
    assert_eq!(mcp["health"], "ok");
    assert!(mcp.get("config").is_none());
    assert!(!extensions.to_string().contains("/mcp"));

    let executed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/tools/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"github.search","arguments":{"query":"ferrogate"}}"#,
    ));
    assert_eq!(executed["name"], "github.search");
    assert_eq!(
        executed["content"]["content"][0]["text"],
        "ferrogate-result"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let requests = mcp_handle.join().unwrap();
    assert!(requests
        .iter()
        .any(|request| request.contains("\"tools/list\"")));
    assert!(requests
        .iter()
        .any(|request| request.contains("\"tools/call\"")));
}

#[test]
fn agentic_lite_non_blocking_hook_failures_are_admin_visible() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(&config, non_blocking_hook_failure_config(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/tools",
        &["Authorization: Bearer tool-secret"],
        "",
    ));
    assert_eq!(tools["data"][0]["name"], "tool.echo");

    let extensions = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/extensions",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let hook = extensions["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|extension| extension["id"] == "hook.noop")
        .unwrap();
    assert_eq!(hook["active"], true);
    assert_eq!(hook["health"], "degraded");
    assert!(hook["last_error"].as_str().unwrap().contains("pre_request"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

fn builtin_tools_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute"]
organization_id = "org_demo"
project_id = "project_gateway"

[[extensions]]
id = "tool.echo"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10

[extensions.permissions]
tools = ["tool.echo"]
network = []
filesystem = false
shell = false

[extensions.config]
tenant_allowlist = ["org_demo"]

[[extensions]]
id = "hook.noop"
kind = "request_hook"
source = "builtin"
enabled = true
order = 20

[[extensions]]
id = "event.audit_log"
kind = "event_sink"
source = "builtin"
enabled = true
order = 30

[[extensions]]
id = "tool.health_check"
kind = "tool_provider"
source = "builtin"
enabled = false
order = 40

[extensions.permissions]
tools = ["tool.health_check"]
"#
    )
}

fn non_blocking_hook_failure_config(gateway_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read"]

[[extensions]]
id = "tool.echo"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10

[extensions.permissions]
tools = ["tool.echo"]

[[extensions]]
id = "hook.noop"
kind = "request_hook"
source = "builtin"
enabled = true
order = 20

[extensions.config]
fail_pre_request = true
"#
    )
}

fn mcp_config(gateway_addr: &str, mcp_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute"]

[[extensions]]
id = "mcp.http"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10

[extensions.permissions]
tools = ["github.search"]
network = ["127.0.0.1"]
filesystem = false
shell = false

[extensions.config]
endpoint = "http://{mcp_addr}/mcp"
timeout_ms = 3000
"#
    )
}

fn response_json(response: String) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn spawn_mcp_server(count: usize) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..count {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            let body = if request.contains("\"tools/list\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"github.search","description":"Search GitHub","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}]}}"#
            } else {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ferrogate-result"}]}}"#
            };
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
        requests
    });
    (addr, handle)
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_read = request.len().saturating_sub(header_end + 4);
            if body_read >= content_length(&request[..header_end]) {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

fn content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())
                    .flatten()
            })
        })
        .unwrap_or(0)
}
