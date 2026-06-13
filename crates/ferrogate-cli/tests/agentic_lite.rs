// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

mod support;

use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    thread::{self, JoinHandle},
    time::Duration,
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
fn p3_mcp_gateway_lists_injects_and_executes_http_tools_with_governance() {
    let (mcp_addr, mcp_handle) = spawn_mcp_server_with_tool(6, "search");
    let (provider_addr, provider_handle) = spawn_provider_upstream();
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        p3_mcp_config(&gateway_addr, &mcp_addr, &provider_addr),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let mcp_status = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/mcp-servers",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert_eq!(mcp_status["data"][0]["name"], "github");
    assert_eq!(mcp_status["data"][0]["connected"], true);
    assert_eq!(mcp_status["data"][0]["tools"], 1);

    let tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/tools",
        &["Authorization: Bearer tool-secret"],
        "",
    ));
    assert_eq!(tools["data"][0]["name"], "github-search");
    let tool_list_request_id = tools["request_id"].as_str().unwrap().to_string();

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"find ferrogate"}]}"#,
    );
    assert!(chat.contains("200 OK"), "{chat}");

    let executed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"github-search","arguments":{"query":"ferrogate"},"session_id":"mcp-session-1"}"#,
    ));
    assert_eq!(executed["object"], "tool_execution");
    assert_eq!(executed["name"], "github-search");
    assert_eq!(
        executed["content"]["content"][0]["text"],
        "ferrogate-result"
    );

    let denied = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"github-write","arguments":{}}"#,
    ));
    assert_eq!(denied["error"]["code"], "tool_denied");

    let policy_denied = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer blocked-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"github-search","arguments":{"query":"ferrogate"}}"#,
    ));
    assert_eq!(policy_denied["error"]["code"], "tool_denied");
    assert_eq!(policy_denied["error"]["message"], "MCP search is blocked");

    let audit_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let audit_events = audit_events["data"].as_array().unwrap();
    assert!(audit_events.iter().any(|event| {
        event["action"] == "tool.list"
            && event["request_id"] == tool_list_request_id
            && event["tenant"]["api_key_id"] == "tool-client"
            && event["target"] == "tools"
            && event["outcome"] == "success"
    }));
    assert!(audit_events.iter().any(|event| {
        event["action"] == "tool.execute"
            && event["target"] == "tool_session:mcp-session-1/mcp:github/tool:search"
            && event["outcome"] == "success"
            && event["tenant"]["organization_id"] == "org_demo"
            && event["tenant"]["project_id"] == "project_gateway"
            && event["tenant"]["api_key_id"] == "tool-client"
            && event["message"]
                .as_str()
                .unwrap()
                .contains("MCP upstream mcp:github tool search executed")
    }));
    assert!(audit_events.iter().any(|event| {
        event["action"] == "tool.execute"
            && event["target"] == "mcp:github/tool:search"
            && event["outcome"] == "error"
            && event["tenant"]["api_key_id"] == "blocked-client"
            && event["message"]
                .as_str()
                .unwrap()
                .contains("MCP upstream mcp:github tool search failed")
    }));

    let session_events = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tool-sessions/mcp-session-1",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let session_events = session_events["data"].as_array().unwrap();
    assert_eq!(session_events.len(), 1);
    assert_eq!(
        session_events[0]["target"],
        "tool_session:mcp-session-1/mcp:github/tool:search"
    );

    let billing = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/billing-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    assert!(billing["data"].as_array().unwrap().iter().any(|event| {
        event["provider"] == "mcp"
            && event["logical_model"] == "mcp_tool:github-search"
            && event["tenant"]["api_key_id"] == "tool-client"
    }));
    assert!(billing["data"].as_array().unwrap().iter().any(|event| {
        event["provider"] == "mcp"
            && event["logical_model"] == "mcp_tool:github-search"
            && event["tenant"]["api_key_id"] == "blocked-client"
            && event["status_code"] == 403
    }));

    let metrics = http_request(
        &gateway_addr,
        "GET",
        "/metrics",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        metrics.contains("ferrogate_mcp_tool_calls_total 2"),
        "{metrics}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_request = provider_handle.join().unwrap();
    assert!(provider_request.contains("\"tools\""), "{provider_request}");
    assert!(
        provider_request.contains("\"github-search\""),
        "{provider_request}"
    );

    let requests = mcp_handle.join().unwrap();
    assert!(requests
        .iter()
        .any(|request| request.contains("\"initialize\"")));
    assert!(requests
        .iter()
        .any(|request| request.contains("\"tools/list\"")));
    assert!(requests
        .iter()
        .any(|request| request.contains("\"tools/call\"")));
    assert!(requests.iter().any(|request| request.contains("\"ping\"")));
    assert!(!requests.join("\n").contains("tool-secret"));
}

#[test]
fn p3_mcp_gateway_connects_to_stdio_server() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("stdio_mcp.py");
    write_stdio_mcp_script(&script);
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        p3_stdio_mcp_config(&gateway_addr, script.as_path()),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let tools = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/tools",
        &["Authorization: Bearer tool-secret"],
        "",
    ));
    assert_eq!(tools["data"][0]["name"], "local-echo");

    let executed = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp/tool/execute",
        &[
            "Authorization: Bearer tool-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"local-echo","arguments":{"message":"stdio ok"}}"#,
    ));
    assert_eq!(executed["name"], "local-echo");
    assert_eq!(executed["content"]["content"][0]["text"], "stdio ok");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
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

fn p3_mcp_config(gateway_addr: &str, mcp_addr: &str, provider_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read"]

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "blocked-client"
name = "Blocked tool client"
key = "blocked-secret"
scopes = ["tools.execute"]
organization_id = "org_demo"
project_id = "project_gateway"

[[policies]]
name = "deny blocked client MCP search"
effect = "deny"
api_key_ids = ["blocked-client"]
models = ["mcp_tool:github-search"]
providers = ["mcp:github"]
code = "mcp_policy_denied"
message = "MCP search is blocked"

[[mcp_servers]]
name = "github"
transport = "streamable_http"
url = "http://{mcp_addr}/mcp"
auth_type = "headers"
tools_to_execute = ["search"]
tools_to_auto_execute = ["search"]
tool_include = ["search"]
timeout_ms = 3000
health_ping_interval_secs = 10
max_reconnect_attempts = 5
min_reconnect_backoff_secs = 1
max_reconnect_backoff_secs = 30

[[mcp_servers.headers]]
name = "Authorization"
value = "Bearer upstream-mcp-secret"
"#
    )
}

fn p3_stdio_mcp_config(gateway_addr: &str, script: &Path) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "tool-client"
name = "Tool client"
key = "tool-secret"
scopes = ["tools.read", "tools.execute"]

[[mcp_servers]]
name = "local"
transport = "stdio"
command = "python3"
args = ["{}"]
tools_to_execute = ["echo"]
timeout_ms = 3000
"#,
        script.display()
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
    spawn_mcp_server_with_tool(count, "github.search")
}

fn spawn_mcp_server_with_tool(
    count: usize,
    tool_name: &'static str,
) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..count {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == ErrorKind::WouldBlock => loop {
                    if std::time::Instant::now() >= deadline {
                        return requests;
                    }
                    thread::sleep(Duration::from_millis(10));
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
                        Err(error) => panic!("MCP mock accept failed: {error}"),
                    }
                },
                Err(error) => panic!("MCP mock accept failed: {error}"),
            };
            let request = read_http_request(&mut stream);
            let body = if request.contains("\"initialize\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"mock-mcp","version":"1.0.0"}}}"#
            } else if request.contains("\"ping\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#
            } else if request.contains("\"tools/list\"") {
                if tool_name == "search" {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"Search GitHub","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}]}}"#
                } else {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"github.search","description":"Search GitHub","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}]}}"#
                }
            } else if request.contains("\"github.write\"") || request.contains("\"write\"") {
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"tool not allowed"}}"#
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

fn spawn_provider_upstream() -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        let body = r#"{"id":"chatcmpl_tools","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        request
    });
    (addr, handle)
}

fn write_stdio_mcp_script(path: &Path) {
    std::fs::write(
        path,
        r#"
import json
import sys

for line in sys.stdin:
    req = json.loads(line)
    method = req.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "stdio-mcp", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {
            "tools": [{
                "name": "echo",
                "description": "Echo a message",
                "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}},
            }]
        }
    elif method == "tools/call":
        args = req.get("params", {}).get("arguments", {})
        result = {"content": [{"type": "text", "text": args.get("message", "")}]}
    elif method == "ping":
        result = {}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32601, "message": "unknown method"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": result}), flush=True)
"#,
    )
    .unwrap();
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
