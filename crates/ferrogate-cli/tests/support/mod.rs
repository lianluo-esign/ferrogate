// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

#[cfg(target_os = "linux")]
use std::cell::RefCell;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
const TEST_GUARDIAN_FD_ENV: &str = "FERROGATE_TEST_GUARDIAN_FD";

#[cfg(target_os = "linux")]
thread_local! {
    static TEST_GUARDIAN_FDS: RefCell<Vec<std::os::fd::OwnedFd>> = RefCell::new(Vec::new());
}

pub fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

pub fn start_gateway(config: &std::path::Path) -> Child {
    start_gateway_with_env(config, &[])
}

/// Constructs the real `ferrogate` binary command for integration tests.
///
/// Every test-spawned `ferrogate` process goes through this helper so #568's
/// death-signal arming, inherited test guardian, and once-per-binary backlog
/// sweep cannot be bypassed by a custom spawner.
pub fn ferrogate_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ferrogate"));
    reap_with_test(&mut command);
    inherit_test_guardian(&mut command);
    sweep_orphaned_gateways_once();
    command
}

/// Start a gateway with extra environment variables. Used by tests that need to
/// select an env-configured seam backend in the child process (e.g. the #488
/// site-domain zone-file DNS resolver).
pub fn start_gateway_with_env(config: &std::path::Path, env: &[(&str, &str)]) -> Child {
    let mut command = ferrogate_command();
    command
        .args(["run", "--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command.spawn().unwrap()
}

/// Runs the backlog sweep at most once per test binary, on the first gateway
/// spawn.
///
/// [`reap_with_test`] stops the leak from here on but cannot touch the orphans
/// already on the box -- 106 of them when #568 was filed, a large share of them
/// spawned by an entirely different checkout, the oldest 14 hours old. Nothing
/// else will ever reap those: there is no systemd unit behind them. Clearing
/// them is worth doing exactly once, where a developer will actually run it.
fn sweep_orphaned_gateways_once() {
    static SWEPT: std::sync::Once = std::sync::Once::new();
    SWEPT.call_once(|| {
        // Only the backlog, never something that just appeared: a gateway that
        // was reparented seconds ago may belong to a sibling suite that is at
        // this instant tearing itself down, and killing it would land as that
        // suite's flake. A real backlog entry is minutes to hours old.
        let swept = sweep_orphaned_gateways(automatic_sweep_min_age());
        if !swept.is_empty() {
            eprintln!(
                "#568: reaped {} orphaned gateway(s): {swept:?}",
                swept.len()
            );
        }
    });
}

fn automatic_sweep_min_age() -> Duration {
    std::env::var("FERROGATE_TEST_ORPHAN_SWEEP_MIN_AGE_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(120))
}

/// Kills every `ferrogate run --config /tmp/.tmp*` process that has already been
/// reparented to init and has been alive at least `min_age`, and returns the
/// pids it killed.
///
/// The conditions in [`is_orphaned_test_gateway`] are what make this safe to run
/// unconditionally. `PPID == 1` means the process that spawned it is already
/// gone, which for a test-spawned gateway is the definition of leaked -- a
/// gateway belonging to a suite that is *running*, here or in a sibling
/// checkout, is still parented to its test binary. The `/tmp/.tmp` config prefix
/// is `tempfile::tempdir`'s shape, so an operator's hand-started gateway with a
/// real config path is out of range.
#[cfg(target_os = "linux")]
pub fn sweep_orphaned_gateways(min_age: Duration) -> Vec<u32> {
    let mut killed = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return killed;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Some(pidfd) = open_pidfd(pid) else {
            continue;
        };
        if !is_orphaned_test_gateway(pid) || process_age(pid).is_none_or(|age| age < min_age) {
            continue;
        }
        if pidfd_send_sigkill(&pidfd) {
            killed.push(pid);
        }
    }
    killed
}

#[cfg(target_os = "linux")]
struct PidFd(std::os::fd::OwnedFd);

#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> Option<PidFd> {
    use std::os::fd::FromRawFd;

    // SAFETY: pidfd_open(2) is a pure kernel open by numeric pid. A failure
    // means this kernel or this pid cannot provide a stable process reference,
    // so the sweep fails closed and does not signal anything.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: fd was just returned by pidfd_open and is uniquely owned here.
    Some(PidFd(unsafe {
        std::os::fd::OwnedFd::from_raw_fd(fd as i32)
    }))
}

#[cfg(target_os = "linux")]
fn pidfd_send_sigkill(pidfd: &PidFd) -> bool {
    use std::os::fd::AsRawFd;

    // SAFETY: pidfd_send_signal(2) sends SIGKILL through the stable pidfd held
    // since before classification. A recycled numeric pid cannot be signalled.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.0.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        ) == 0
    }
}

#[cfg(not(target_os = "linux"))]
pub fn sweep_orphaned_gateways(_min_age: Duration) -> Vec<u32> {
    Vec::new()
}

/// How long `pid` has been running, from `/proc/<pid>/stat` field 22 (start
/// time, in clock ticks since boot) against `/proc/uptime`.
#[cfg(target_os = "linux")]
fn process_age(pid: u32) -> Option<Duration> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields are 1-based and `comm` (field 2) may contain spaces and parens, so
    // count from the last `)`: field 3 is the first token after it, making
    // starttime (field 22) the 20th.
    let starttime_ticks: f64 = stat
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()?;
    // SAFETY: sysconf is a pure query of a compile-time-fixed kernel constant.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    if ticks_per_second <= 0.0 {
        return None;
    }
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let uptime_seconds: f64 = uptime.split_whitespace().next()?.parse().ok()?;
    Some(Duration::from_secs_f64(
        (uptime_seconds - starttime_ticks / ticks_per_second).max(0.0),
    ))
}

/// Both halves of the sweep's safety condition, read straight from `/proc`.
///
/// Public so the safety condition itself can be asserted -- a sweep that
/// mis-classifies a *live* test's gateway would kill it mid-run and present as
/// a flake, which is the failure mode #568 says makes this class of bug
/// invisible.
#[cfg(target_os = "linux")]
pub fn is_orphaned_test_gateway(pid: u32) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    // A zombie has an empty cmdline, so it drops out here rather than being
    // signalled pointlessly.
    let argv: Vec<&[u8]> = cmdline.split(|byte| *byte == 0).collect();
    let is_gateway_run = argv
        .first()
        .is_some_and(|program| String::from_utf8_lossy(program).ends_with("/ferrogate"))
        && argv.iter().any(|arg| *arg == b"run")
        && argv
            .iter()
            .any(|arg| arg.starts_with(b"/tmp/.tmp") && arg.ends_with(b".toml"));
    is_gateway_run && parent_pid(pid) == Some(1)
}

/// The pid that will inherit `pid`. `Some(1)` is the #568 signature, and the
/// reaping tests report it in their failure messages.
#[cfg(target_os = "linux")]
pub fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` is parenthesised and may itself contain spaces and parens, so
    // split on the last `)`; ppid is the field after the state character.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// True while `pid` is a live `ferrogate run` process.
///
/// Reads `/proc/<pid>/cmdline` rather than sending signal 0, for two reasons: a
/// reaped pid can be recycled onto an unrelated process, and a zombie still
/// answers `kill(pid, 0)`. A zombie's `cmdline` is empty and a recycled pid
/// belongs to some other program, so both read as dead here.
#[allow(dead_code)]
#[cfg(target_os = "linux")]
pub fn gateway_process_alive(pid: u32) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let argv = String::from_utf8_lossy(&cmdline).replace('\0', " ");
    argv.contains("ferrogate") && argv.contains(" run ")
}

/// Smallest config that reaches a listening state: no storage, no upstream,
/// auth explicitly off (#542) so the process has nothing to wait on. Used by
/// the #568 lifetime tests, which care only that a gateway is running.
#[allow(dead_code)]
pub fn minimal_listening_config(addr: &str) -> String {
    format!("listen = \"{addr}\"\n\n[auth]\ndisabled = true\n")
}

/// Binds a long-lived child process's lifetime to the test that spawns it, so
/// it cannot outlive that test (#568).
///
/// Every long-running process a test starts must go through this. The suite's
/// only other cleanup is a plain `child.kill()` statement at the bottom of each
/// test body, and *that statement is the bug*: `std::process::Child` does not
/// kill on `Drop`, it detaches. A failed `assert!`, an `.unwrap()` on a
/// timed-out `http_request`, or the readiness panic all jump straight over the
/// `kill()` line, and the gateway is reparented to init and runs forever. On one
/// box that reached 106 orphans, the oldest 14 hours old, ~10.6% of memory and
/// the bulk of a load average above 300. `cargo test` killed by `timeout` or
/// Ctrl-C is worse still: no destructor runs at all, so no `Drop` guard --
/// however careful -- could have covered it.
///
/// The mechanism is `prctl(PR_SET_PDEATHSIG, SIGKILL)`, set in the child between
/// `fork` and `exec`. The kernel then kills the child when the *thread* that
/// spawned it terminates. That is precisely the lifetime wanted here: libtest
/// runs each `#[test]` on its own thread, so the gateway dies when its test
/// returns, panics, or is torn down with the harness -- and, because the kernel
/// owns the rule, it holds when the harness is `SIGKILL`ed, which is the one
/// case userspace cannot reach.
///
/// Killing the process group (the alternative in #568) was rejected: sending the
/// group signal still requires the harness to be alive to send it, so it leaves
/// the `SIGKILL` case exactly as leaky as `Drop` does.
///
/// **Non-Linux:** this is a no-op. `PR_SET_PDEATHSIG` is Linux-specific and has
/// no portable equivalent (macOS would need a `kqueue`/`EVFILT_PROC` watchdog
/// thread, which itself dies with a `SIGKILL`ed harness). CI is Linux, so the
/// gate holds where it is enforced; on a macOS or Windows workstation the
/// explicit `kill()` calls remain the only cleanup and the crash paths still
/// leak.
#[cfg(target_os = "linux")]
pub fn reap_with_test(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: `pre_exec` runs in the forked child before `exec`, where only
    // async-signal-safe calls are permitted. `prctl`, `getppid` and `_exit` all
    // are; nothing here allocates, locks, or touches inherited state.
    unsafe {
        command.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // `fork` and the `prctl` above are not atomic. If the whole test
            // process died in that window the death signal was armed against a
            // parent that no longer exists and would never fire, so leave now
            // rather than become the orphan this function exists to prevent.
            // (A window remains where only the spawning *thread* died -- the
            // child cannot observe that -- but it is bounded by the few
            // microseconds between `fork` and `prctl`.)
            if libc::getppid() == 1 {
                libc::_exit(1);
            }
            Ok(())
        });
    }
}

/// See the Linux implementation for why this cannot be provided portably.
#[cfg(not(target_os = "linux"))]
pub fn reap_with_test(_command: &mut Command) {}

#[cfg(target_os = "linux")]
fn inherit_test_guardian(command: &mut Command) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two fresh descriptors owned by this process. O_CLOEXEC
    // is cleared only on the read side below so the child and any grandchild can
    // observe EOF when the test thread drops the write end.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        panic!(
            "#568: failed to create ferrogate test guardian pipe: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: both fds were just returned by pipe2 and are uniquely owned here.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    clear_cloexec(read.as_raw_fd());
    command.env(TEST_GUARDIAN_FD_ENV, read.as_raw_fd().to_string());
    TEST_GUARDIAN_FDS.with(|held| {
        let mut held = held.borrow_mut();
        held.push(read);
        held.push(write);
    });
}

#[cfg(not(target_os = "linux"))]
fn inherit_test_guardian(_command: &mut Command) {}

#[cfg(target_os = "linux")]
fn clear_cloexec(fd: i32) {
    // SAFETY: fcntl is operating on a live fd we just created.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        panic!(
            "#568: failed to read guardian fd flags: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: fcntl is operating on a live fd we just created.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } != 0 {
        panic!(
            "#568: failed to clear guardian fd close-on-exec: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Suites that boot through [`start_ready_gateway`] never call this directly,
/// so it is dead code in those test binaries.
#[allow(dead_code)]
pub fn wait_for_gateway(addr: &str) {
    // Generous readiness window: a Supabase-backed gateway re-runs the full
    // idempotent schema batch and the ~150-probe validate_schema pass against
    // a REMOTE pooler before listening, which takes minutes at cross-region
    // round-trip latencies (~300ms/query). Fast (local/in-memory) environments
    // are unaffected -- this only bounds how long a genuinely broken startup
    // waits before failing.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(300) {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut buffer = [0_u8; 512];
            if stream.read(&mut buffer).unwrap_or(0) > 0 {
                return;
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("gateway did not become ready at {addr}");
}

/// Starts the gateway on a genuinely-free port, transparently retrying the
/// `free_addr()` bind race.
///
/// `free_addr()` picks an ephemeral port by binding then dropping a listener, so
/// there is a TOCTOU window before the spawned gateway re-binds it. Under
/// full-workspace parallel load two tests can be handed the same just-freed port
/// (or another process can grab it), and the gateway that loses the race fails
/// to bind and exits almost immediately. A plain `wait_for_gateway` would then
/// either stall on the 300s readiness window or, worse, observe a *different*
/// test's gateway answering on that address -- the classic load-sensitive,
/// different-subset-each-run flake.
///
/// This helper closes that window: it allocates a port, (re)writes the config
/// via `write_config_for`, spawns the gateway, and treats an early child exit as
/// a lost bind race -- relaunching on a fresh port. It only accepts readiness
/// while our own child is confirmed alive, so a stray gateway on the same port
/// can never be mistaken for ours. Returns the live child and the bound address.
#[allow(dead_code)]
pub fn start_ready_gateway(
    config: &std::path::Path,
    write_config_for: impl Fn(&str),
) -> (Child, String) {
    for _ in 0..20 {
        let addr = free_addr();
        write_config_for(&addr);
        let mut child = start_gateway(config);
        if gateway_ready_or_exited(&addr, &mut child) {
            return (child, addr);
        }
        // Lost the bind race (or a broken startup): reap and retry on a fresh
        // port. Killing an already-exited child is harmless.
        let _ = child.kill();
        let _ = child.wait();
    }
    panic!("gateway never bound a free port after 20 attempts");
}

/// Polls gateway readiness while watching for an early child exit. Returns
/// `true` once `/healthz` answers with our child still alive, `false` if the
/// child exits first (lost bind race / broken startup) or the readiness window
/// elapses.
fn gateway_ready_or_exited(addr: &str, child: &mut Child) -> bool {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(300) {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return false;
        }
        if let Ok(mut stream) = TcpStream::connect(addr) {
            if stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .is_ok()
            {
                let mut buffer = [0_u8; 512];
                if stream.read(&mut buffer).unwrap_or(0) > 0 {
                    // Confirm the readiness came from our own gateway, not a
                    // stray one that transiently held the port.
                    return !matches!(child.try_wait(), Ok(Some(_)));
                }
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

/// Like [`http_request`] but sends a binary request body and returns the raw
/// response bytes, for endpoints that push non-UTF-8 payloads (e.g. a zip site
/// bundle) or serve binary content.
#[allow(dead_code)]
pub fn http_request_bytes(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &[u8],
) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .unwrap();
    for header in headers {
        write!(stream, "{header}\r\n").unwrap();
    }
    write!(stream, "\r\n").unwrap();
    stream.write_all(body).unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

/// Like [`http_request`] but with an explicit `Host` header, for exercising
/// host-based resolution (e.g. custom-domain static-site serving, #265) --
/// `http_request` always sends `Host: localhost`.
#[allow(dead_code)]
pub fn http_request_with_host(
    addr: &str,
    host: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .unwrap();
    for header in headers {
        write!(stream, "{header}\r\n").unwrap();
    }
    write!(stream, "\r\n{body}").unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

pub fn http_request(addr: &str, method: &str, path: &str, headers: &[&str], body: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    // Generous read timeout: some endpoints (e.g. `/v1/tools/execute` gated on a
    // tool approval that is left to fail closed by its TTL) intentionally hold
    // the response until a server-side deadline elapses. The timeout only bounds
    // how long a genuinely hung request waits before failing; it never changes a
    // response, so keeping it well above any test's server-side wait avoids
    // coupling approval-TTL choices to the client read deadline.
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .unwrap();
    for header in headers {
        write!(stream, "{header}\r\n").unwrap();
    }
    write!(stream, "\r\n{body}").unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[allow(dead_code)]
pub fn spawn_provider_upstream(
    count: usize,
    response_body: &'static str,
) -> (String, JoinHandle<Vec<String>>) {
    spawn_provider_upstream_response(count, "200 OK", "application/json", response_body)
}

#[allow(dead_code)]
pub fn spawn_provider_upstream_response(
    count: usize,
    status: &'static str,
    content_type: &'static str,
    response_body: &'static str,
) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..count {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .unwrap();
        }
        requests
    });
    (addr, handle)
}

/// Spawns a plain-HTTP mock webhook receiver on `127.0.0.1` that accepts
/// any number of sequential `Connection: close` JSON POSTs, recording each
/// body in arrival order. Used to prove outbound webhook dispatch (e.g. the
/// proactive budget-threshold alerting in issue #170) against a real
/// gateway process rather than by reading the dispatch code.
#[allow(dead_code)]
pub fn spawn_webhook_capture_server() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/webhook", listener.local_addr().unwrap());
    let captured = Arc::new(Mutex::new(Vec::new()));
    let server_captured = Arc::clone(&captured);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let request = read_http_request(&mut stream);
            let Some(header_end) = find_header_end(request.as_bytes()) else {
                continue;
            };
            let body = &request.as_bytes()[header_end + 4..];
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
                server_captured.lock().unwrap().push(value);
            }
            let response =
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
            let _ = stream.write_all(response.as_bytes());
        }
    });

    (endpoint, captured)
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
        if let Some(header_end) = find_header_end(&request) {
            let content_length = parse_content_length(&request[..header_end]);
            let body_read = request.len().saturating_sub(header_end + 4);
            if body_read >= content_length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> usize {
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
