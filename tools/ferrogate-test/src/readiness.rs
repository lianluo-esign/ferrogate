// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Token4AI Cloud, FerroGate AI Gateway - single identity-checked readiness decision for every harness-started FerroGate child (#444).

use crate::http::{http_request_addr, HttpResponse};
use anyhow::{bail, Result};
use serde_json::Value;
use std::{
    path::Path,
    process::Child,
    thread,
    time::{Duration, Instant},
};

/// Readiness ceiling for a scenario-owned `ferrogate` child. Storage-backed
/// scenarios (Postgres/Supabase migrations, asset scanners) bind the listener
/// only after their control-plane bootstrap completes, so the ceiling is
/// generous; it is a deadline, never a sleep.
pub(crate) const GATEWAY_READINESS_TIMEOUT: Duration = Duration::from_secs(180);

/// Readiness poll interval. The only wait in the readiness path: every decision
/// below is taken from an observed answer, never from elapsed time.
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// #264: drain a child's piped stderr (best-effort) so a start failure can be
/// reported with the child's own diagnostics. Empty when stderr was not piped.
pub(crate) fn drain_child_stderr(child: &mut Child) -> String {
    use std::io::Read as _;
    child
        .stderr
        .take()
        .map(|mut stderr| {
            let mut buffer = String::new();
            let _ = stderr.read_to_string(&mut buffer);
            buffer
        })
        .unwrap_or_default()
}

/// Format drained child stderr as a bail-message suffix: the last few non-empty
/// lines, or nothing when stderr was empty/unpiped.
pub(crate) fn format_child_stderr(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let tail: Vec<&str> = trimmed.lines().rev().take(20).collect();
    let tail = tail.into_iter().rev().collect::<Vec<_>>().join("\n");
    format!("\n--- child stderr ---\n{tail}")
}

/// Is this a live FerroGate gateway answering its own `/healthz`?
fn healthz_identifies_ferrogate(response: &HttpResponse) -> bool {
    if response.status != 200 {
        return false;
    }
    let Ok(body) = serde_json::from_str::<Value>(&response.body) else {
        return false;
    };
    body["service"] == "ferrogate" && body["status"] == "ok"
}

/// Does this response body claim to be the FerroGate gateway at all, regardless
/// of readiness? FerroGate's `/healthz` is a static 200, so in practice a
/// claiming-but-not-ready body never occurs; this keeps the classifier from ever
/// misreading our own process as a squatter.
fn response_claims_ferrogate(response: &HttpResponse) -> bool {
    serde_json::from_str::<Value>(&response.body)
        .map(|body| body["service"] == "ferrogate")
        .unwrap_or(false)
}

/// The response header block, i.e. everything before the body separator.
fn header_block(raw: &str) -> &str {
    raw.split_once("\r\n\r\n")
        .map(|(head, _)| head)
        .unwrap_or(raw)
}

/// Response-level evidence that FerroGate produced this answer, independent of
/// readiness: every gateway-authored response, and every upstream response it
/// proxies, carries `x-ferrogate-runtime: pingora`
/// (`crates/ferrogate-gateway/src/responses.rs`, `server/proxy.rs`). A squatting
/// mock does not.
///
/// This is what separates "our gateway answered, just not with a ready healthz"
/// -- unauthenticated rate limit, IP deny, an error envelope -- from "a foreign
/// process holds the port". Without it, any non-`healthz` answer FerroGate can
/// legitimately give a readiness probe would be misread as a hijack and fail the
/// scenario at start.
fn response_carries_ferrogate_runtime_header(response: &HttpResponse) -> bool {
    header_block(&response.raw).lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("x-ferrogate-runtime")
            && value.trim().eq_ignore_ascii_case("pingora")
    })
}

/// Is this answer FerroGate's at all (ready or not)?
fn response_is_from_ferrogate(response: &HttpResponse) -> bool {
    response_carries_ferrogate_runtime_header(response) || response_claims_ferrogate(response)
}

/// The single per-probe readiness decision for a gateway `/healthz` response,
/// shared by every harness that starts a `ferrogate` child. [`wait_for_gateway_start`]
/// acts only on this value, so no scenario can regress to status-only acceptance
/// ("any HTTP 200 is ready") without editing the classifier the tests bite on
/// (#444). Covered in `readiness_test.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayReadiness {
    /// A live FerroGate answered `/healthz` with `status:ok`; proceed.
    Ready,
    /// No usable HTTP answer yet (connection refused / read timeout), or our own
    /// gateway answering with something other than a ready `/healthz`. Pingora
    /// has not served a ready `/healthz` on this port; keep polling the same
    /// address.
    Pending,
    /// A process that is provably not FerroGate answered `/healthz` on the
    /// configured gateway port. FerroGate serves `/healthz` only after Pingora
    /// binds and stamps every answer it writes, so an HTTP answer carrying
    /// neither the runtime header nor the service identity is a squatter that
    /// won the released ephemeral port (#444). It will not yield the port, so
    /// polling it can never succeed.
    PortHijacked,
}

/// Terminal outcome of one gateway spawn + readiness wait. `Pending` is not a
/// terminal state: [`wait_for_gateway_start`] keeps polling until the gateway is
/// `Ready`, the port is proven hijacked, the child exits, or the deadline passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayStartOutcome {
    Ready,
    PortHijacked,
}

pub(crate) fn classify_gateway_readiness(probe: &Result<HttpResponse>) -> GatewayReadiness {
    let Ok(response) = probe else {
        return GatewayReadiness::Pending;
    };
    if healthz_identifies_ferrogate(response) {
        return GatewayReadiness::Ready;
    }
    if response_is_from_ferrogate(response) {
        return GatewayReadiness::Pending;
    }
    GatewayReadiness::PortHijacked
}

/// Poll `/healthz` until a live FerroGate answers (`Ready`), the configured port
/// is proven to be held by a non-FerroGate squatter (`PortHijacked`), the child
/// exits, or `timeout` passes. `label` names the scenario in every failure so a
/// harness-level start failure is attributable without a debugger.
///
/// A `PortHijacked` return is deliberately *not* an error: a caller that can
/// re-render its config (see `LocalHarness::start_inner`) rotates to a fresh
/// gateway port instead of burning the deadline on a squatter it can never
/// reach. Callers that cannot rotate use [`require_gateway_ready`].
pub(crate) fn wait_for_gateway_start(
    gateway: &mut Child,
    gateway_addr: &str,
    label: &str,
    timeout: Duration,
) -> Result<GatewayStartOutcome> {
    let started = Instant::now();
    let mut last = String::new();
    while started.elapsed() < timeout {
        if let Some(status) = gateway.try_wait()? {
            let stderr = drain_child_stderr(gateway); // #264
            bail!(
                "{label}: ferrogate exited before readiness on {gateway_addr}: {status}{}",
                format_child_stderr(&stderr)
            );
        }
        let probe = http_request_addr(gateway_addr, "GET", "/healthz", &[], "");
        match classify_gateway_readiness(&probe) {
            GatewayReadiness::Ready => return Ok(GatewayStartOutcome::Ready),
            // A squatter holds the port and will not yield it; stop polling now
            // and let the caller decide (rotate, or fail by name).
            GatewayReadiness::PortHijacked => return Ok(GatewayStartOutcome::PortHijacked),
            GatewayReadiness::Pending => {
                last = match &probe {
                    Ok(response) => response.raw.clone(),
                    Err(error) => error.to_string(),
                };
            }
        }
        thread::sleep(READINESS_POLL_INTERVAL);
    }
    bail!("{label}: timed out waiting for ferrogate on {gateway_addr}; last response: {last}")
}

/// [`wait_for_gateway_start`] for a scenario that baked its gateway address into
/// an already-rendered config and therefore cannot rotate ports: a proven hijack
/// fails by name here instead of running the whole scenario against a squatting
/// mock, which is how #444 surfaced as `GET /v1/models` missing a configured
/// model instead of as a start failure.
pub(crate) fn require_gateway_ready(
    gateway: &mut Child,
    gateway_addr: &str,
    label: &str,
    timeout: Duration,
) -> Result<()> {
    match wait_for_gateway_start(gateway, gateway_addr, label, timeout)? {
        GatewayStartOutcome::Ready => Ok(()),
        GatewayStartOutcome::PortHijacked => bail!(
            "{label}: {gateway_addr} is answering HTTP but is not FerroGate, so a foreign \
             process (typically a parallel harness mock that won the released ephemeral \
             port) holds the gateway port; refusing to run the scenario against it (#444)"
        ),
    }
}

/// Wait for a filesystem path that the gateway itself creates only once it is
/// serving -- currently the managed-worker external-action-authorizer unix
/// socket. Bails on child exit (with the child's own stderr, #264) and on the
/// deadline; existence is observed, never inferred from elapsed time.
fn wait_for_gateway_path(
    gateway: &mut Child,
    path: &Path,
    label: &str,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    loop {
        if path.exists() {
            return Ok(());
        }
        if let Some(status) = gateway.try_wait()? {
            let stderr = drain_child_stderr(gateway); // #264
            bail!(
                "{label}: ferrogate exited before creating {}: {status}{}",
                path.display(),
                format_child_stderr(&stderr)
            );
        }
        if started.elapsed() >= timeout {
            bail!(
                "{label}: timed out waiting for ferrogate to create {}",
                path.display()
            );
        }
        thread::sleep(READINESS_POLL_INTERVAL);
    }
}

/// [`require_gateway_ready`] for a scenario whose gateway must also have
/// published a unix socket before the scenario can drive it (the managed-worker
/// external-action authorizer). Readiness is decided first -- so a squatter on
/// the gateway port fails by name instead of being waited on until the socket
/// deadline -- and both waits share the caller's single ceiling so composing
/// them cannot double a scenario's start budget.
pub(crate) fn require_gateway_ready_with_socket(
    gateway: &mut Child,
    gateway_addr: &str,
    socket: &Path,
    label: &str,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    require_gateway_ready(gateway, gateway_addr, label, timeout)?;
    wait_for_gateway_path(
        gateway,
        socket,
        label,
        timeout.saturating_sub(started.elapsed()),
    )
}

#[cfg(test)]
#[path = "readiness_test.rs"]
mod readiness_test;
