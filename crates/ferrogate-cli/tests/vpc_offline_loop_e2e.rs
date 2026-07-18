// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Offline-loop survival E2E for the customer-VPC data plane (issue #206).
//!
//! Spawns REAL `ferrogate` gateway processes split into the hybrid roles:
//!
//! - a **control-plane publisher** that signs the file-backed control-plane
//!   snapshots it publishes (`cluster.snapshot_signing_key`), and
//! - a **customer-VPC data plane** that holds only the *public* trust anchor
//!   (`cluster.snapshot_trusted_keys`) and activates a snapshot exclusively
//!   after signature/identity/revision/expiry verification.
//!
//! The tests then interrupt the control-plane source and prove, over live HTTP
//! against the data-plane process, the offline policy loop the issue demands:
//! last-known-good enforcement with no fail-open, pickup of a newer signed
//! snapshot on reconnect, live replay rejection, and (DSN-gated) the persisted
//! replay floor rejecting an older-but-authentically-signed snapshot after a
//! data-plane restart.

mod support;

use std::{
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use support::{free_addr, http_request, start_gateway, wait_for_gateway};

/// Deterministic ed25519 keypair for the test control plane (no rng in tests).
/// Returns `(seed_b64, public_key_b64)` in the exact formats
/// `cluster.snapshot_signing_key` / `cluster.snapshot_trusted_keys.public_key`
/// consume.
fn control_plane_keypair(seed_byte: u8) -> (String, String) {
    let b64 = base64::engine::general_purpose::STANDARD;
    let seed = [seed_byte; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    (
        b64.encode(seed),
        b64.encode(signing_key.verifying_key().to_bytes()),
    )
}

/// Kills the child process on drop so a failed assertion never leaks gateway
/// processes across the test binary.
struct Gateway(std::process::Child);

impl Gateway {
    /// Starts a gateway and waits for `/healthz` with the default (5s) budget.
    fn start(config: &Path, addr: &str) -> Self {
        let gateway = Self(start_gateway(config));
        wait_for_gateway(addr);
        gateway
    }

    /// Starts a gateway with a longer readiness budget: durable-storage-backed
    /// startup opens a real TLS Postgres pool, loads the persisted replay
    /// floor (fail-closed), and validates the schema before listening.
    fn start_with_durable_storage(config: &Path, addr: &str) -> Self {
        let gateway = Self(start_gateway(config));
        // Startup against live Supabase runs full schema validation over a
        // WAN; ~1 minute is normal, so the budget is deliberately generous.
        wait_until(
            "durable data plane becomes healthy",
            Duration::from_secs(180),
            || healthz_responds(addr),
        );
        gateway
    }

    fn stop(mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn healthz_responds(addr: &str) -> bool {
    use std::io::{Read as _, Write as _};
    let Ok(mut stream) = std::net::TcpStream::connect(addr) else {
        return false;
    };
    if stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buffer = [0_u8; 512];
    stream.read(&mut buffer).unwrap_or(0) > 0
}

/// GET `/v1/models` with an API key: the observable policy-enforcement probe.
/// Any authenticated data-plane request also triggers a shared-control-plane
/// sync attempt, so polling this doubles as the data plane's outbound
/// policy-poll loop.
fn models_response(addr: &str, secret: &str) -> String {
    let auth = format!("Authorization: Bearer {secret}");
    http_request(addr, "GET", "/v1/models", &[auth.as_str()], "")
}

fn admin_status_response(addr: &str, admin_secret: &str) -> String {
    let auth = format!("Authorization: Bearer {admin_secret}");
    http_request(addr, "GET", "/admin/v1/status", &[auth.as_str()], "")
}

/// Fires a readiness probe purely to trigger a shared-control-plane sync pass
/// on the target node; deliberately does not assert on the response (a node
/// with a failing control-plane source is expected to degrade here).
fn trigger_sync(addr: &str) {
    let _ = http_request(addr, "GET", "/readyz", &[], "");
}

fn wait_until(what: &str, timeout: Duration, mut probe: impl FnMut() -> bool) {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if probe() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out after {timeout:?} waiting for: {what}");
}

fn create_api_key(publisher_addr: &str, admin_secret: &str, id: &str, secret: &str) {
    let auth = format!("Authorization: Bearer {admin_secret}");
    let body = serde_json::json!({
        "id": id,
        "name": format!("issued key {id}"),
        "key": secret,
        "scopes": ["models.read"],
    })
    .to_string();
    let response = http_request(
        publisher_addr,
        "POST",
        "/admin/v1/api-keys",
        &[auth.as_str(), "Content-Type: application/json"],
        &body,
    );
    assert!(
        response.contains("201 Created"),
        "control-plane publisher failed to issue api key {id}: {response}"
    );
}

fn delete_api_key(publisher_addr: &str, admin_secret: &str, id: &str) {
    let auth = format!("Authorization: Bearer {admin_secret}");
    let response = http_request(
        publisher_addr,
        "DELETE",
        &format!("/admin/v1/api-keys/{id}"),
        &[auth.as_str()],
        "",
    );
    assert!(
        response.contains("200 OK"),
        "control-plane publisher failed to revoke api key {id}: {response}"
    );
}

/// Shared parameters for one publisher/data-plane pair. Everything is plain
/// data so each test can pick unique-per-run identities.
struct VpcPair<'a> {
    state_path: &'a Path,
    tenant: &'a str,
    deployment: &'a str,
    signing_seed_b64: &'a str,
    trusted_public_b64: &'a str,
    /// Extra top-level TOML (e.g. a `storage = {...}` inline table) injected
    /// before the `[cluster]` section of the data-plane config.
    data_plane_storage_toml: &'a str,
    /// First client key the control plane issues (id, secret).
    issued_key: (&'a str, &'a str),
    /// Bootstrap keys baked into the data-plane config, superseded on the
    /// first verified activation: (admin id, admin secret, client id, client
    /// secret).
    data_plane_seed: (&'a str, &'a str, &'a str, &'a str),
}

const CP_ADMIN_SECRET: &str = "cp-admin-secret";
const SIGNING_KEY_ID: &str = "vpc-key-1";

impl VpcPair<'_> {
    fn publisher_config(&self, addr: &str) -> String {
        let (client_id, client_secret) = self.issued_key;
        format!(
            r#"
listen = "{addr}"

[cluster]
enabled = true
cluster_id = "vpc-e2e"
node_id = "managed-control-plane"
state_backend = "file"
file_state_path = "{state_path}"
config_poll_interval_secs = 1
snapshot_signing_key = "{signing_seed}"
snapshot_signing_key_id = "{SIGNING_KEY_ID}"
snapshot_tenant_id = "{tenant}"
snapshot_deployment_id = "{deployment}"
snapshot_max_age_secs = 3600

[[api_keys]]
id = "cp-admin"
name = "Control-plane operator"
key = "{CP_ADMIN_SECRET}"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "{client_id}"
name = "Tenant client key"
key = "{client_secret}"
scopes = ["models.read"]
"#,
            state_path = self.state_path.display(),
            signing_seed = self.signing_seed_b64,
            tenant = self.tenant,
            deployment = self.deployment,
        )
    }

    fn data_plane_config(&self, addr: &str) -> String {
        let (admin_id, admin_secret, seed_id, seed_secret) = self.data_plane_seed;
        format!(
            r#"
listen = "{addr}"
{storage}
[cluster]
enabled = true
cluster_id = "vpc-e2e"
node_id = "customer-vpc-data-plane"
state_backend = "file"
file_state_path = "{state_path}"
config_poll_interval_secs = 1
snapshot_tenant_id = "{tenant}"
snapshot_deployment_id = "{deployment}"

[[cluster.snapshot_trusted_keys]]
key_id = "{SIGNING_KEY_ID}"
public_key = "{public_key}"

[[api_keys]]
id = "{admin_id}"
name = "Data-plane bootstrap admin"
key = "{admin_secret}"
scopes = ["admin.read"]

[[api_keys]]
id = "{seed_id}"
name = "Data-plane bootstrap key"
key = "{seed_secret}"
scopes = ["models.read"]
"#,
            storage = self.data_plane_storage_toml,
            state_path = self.state_path.display(),
            tenant = self.tenant,
            deployment = self.deployment,
            public_key = self.trusted_public_b64,
        )
    }
}

fn wait_for_signed_snapshot(state_path: &Path) {
    wait_until(
        "control plane publishes a signed snapshot",
        Duration::from_secs(10),
        || {
            std::fs::read_to_string(state_path)
                .map(|raw| raw.contains("\"signature\""))
                .unwrap_or(false)
        },
    );
}

/// Offline-loop survival (#206 acceptance: control-plane outage continues on
/// the last valid snapshot; forged/replayed snapshots never replace it):
///
/// 1. the data plane activates the control plane's signed snapshot (requests
///    become governed by the cryptographically authenticated payload, and the
///    data plane's bootstrap keys stop working);
/// 2. the control-plane process is killed and the shared snapshot made
///    unreadable -- the data plane keeps enforcing the last-known-good policy
///    (issued key works, unknown/bootstrap keys stay rejected: no fail-open)
///    and surfaces the sync failure over its admin API;
/// 3. on reconnect a NEWER signed snapshot (key issuance and key revocation)
///    is picked up;
/// 4. an older-but-authentically-signed snapshot written back into the channel
///    is rejected as a replay without disturbing the active policy.
#[test]
fn data_plane_survives_control_plane_interruption_on_last_known_good_snapshot() {
    let (seed_b64, public_b64) = control_plane_keypair(7);
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("control").join("cluster-state.json");
    let pair = VpcPair {
        state_path: &state_path,
        tenant: "tenant-vpc",
        deployment: "vpc-deploy-1",
        signing_seed_b64: &seed_b64,
        trusted_public_b64: &public_b64,
        data_plane_storage_toml: "",
        issued_key: ("vpc-client-v1", "vpc-client-secret-v1"),
        data_plane_seed: ("dp-admin", "dp-admin-secret", "dp-seed", "dp-seed-secret"),
    };

    let publisher_addr = free_addr();
    let publisher_config_path = dir.path().join("control-plane.toml");
    std::fs::write(
        &publisher_config_path,
        pair.publisher_config(&publisher_addr),
    )
    .unwrap();

    let data_plane_addr = free_addr();
    let data_plane_config_path = dir.path().join("data-plane.toml");
    std::fs::write(
        &data_plane_config_path,
        pair.data_plane_config(&data_plane_addr),
    )
    .unwrap();

    // Phase 1: control plane up; it publishes a SIGNED snapshot.
    let publisher = Gateway::start(&publisher_config_path, &publisher_addr);
    trigger_sync(&publisher_addr);
    wait_for_signed_snapshot(&state_path);

    // Phase 2: data plane up; it verifies + activates the signed snapshot.
    let data_plane = Gateway::start(&data_plane_config_path, &data_plane_addr);
    wait_until(
        "data plane activates the verified control-plane snapshot",
        Duration::from_secs(10),
        || models_response(&data_plane_addr, "vpc-client-secret-v1").contains("200 OK"),
    );
    // The authenticated payload replaced the bootstrap keys entirely: policy is
    // governed by the control plane, not by whatever the local seed file said.
    assert!(
        models_response(&data_plane_addr, "dp-seed-secret").contains("401 Unauthorized"),
        "bootstrap data-plane key must be superseded by the activated snapshot"
    );
    assert!(
        admin_status_response(&data_plane_addr, "dp-admin-secret").contains("401 Unauthorized"),
        "bootstrap admin key must be superseded by the activated snapshot"
    );
    let healthy_status = admin_status_response(&data_plane_addr, CP_ADMIN_SECRET);
    assert!(healthy_status.contains("200 OK"), "{healthy_status}");
    assert!(
        healthy_status.contains("\"last_sync_error\":null"),
        "healthy sync must report no error: {healthy_status}"
    );

    // Keep an authentic copy of the first signed snapshot for the replay
    // attempt in phase 5.
    let first_signed_snapshot = std::fs::read(&state_path).unwrap();

    // Phase 3: control-plane interruption. Kill the publisher AND make the
    // shared snapshot unreadable (torn/unavailable control channel).
    publisher.stop();
    std::fs::write(&state_path, b"{ \"corrupted\": tru").unwrap();

    trigger_sync(&data_plane_addr);
    for _ in 0..5 {
        assert!(
            models_response(&data_plane_addr, "vpc-client-secret-v1").contains("200 OK"),
            "data plane must keep enforcing the last-known-good snapshot offline"
        );
        assert!(
            models_response(&data_plane_addr, "dp-seed-secret").contains("401 Unauthorized"),
            "offline mode must not fail open to bootstrap keys"
        );
        assert!(
            models_response(&data_plane_addr, "attacker-guess").contains("401 Unauthorized"),
            "offline mode must not fail open to unknown keys"
        );
    }
    wait_until(
        "data plane surfaces the control-plane outage on its admin status",
        Duration::from_secs(10),
        || {
            let status = admin_status_response(&data_plane_addr, CP_ADMIN_SECRET);
            status.contains("invalid file cluster state JSON") && status.contains("\"stale\":true")
        },
    );

    // Phase 4: reconnect. Restore the channel, restart the control plane, and
    // distribute a NEWER signed snapshot: issue v2, then revoke v1.
    std::fs::write(&state_path, &first_signed_snapshot).unwrap();
    let publisher = Gateway::start(&publisher_config_path, &publisher_addr);
    create_api_key(
        &publisher_addr,
        CP_ADMIN_SECRET,
        "vpc-client-v2",
        "vpc-client-secret-v2",
    );
    wait_until(
        "data plane picks up the newer signed snapshot after reconnect",
        Duration::from_secs(10),
        || models_response(&data_plane_addr, "vpc-client-secret-v2").contains("200 OK"),
    );
    delete_api_key(&publisher_addr, CP_ADMIN_SECRET, "vpc-client-v1");
    wait_until(
        "control-plane revocation propagates to the data plane",
        Duration::from_secs(10),
        || models_response(&data_plane_addr, "vpc-client-secret-v1").contains("401 Unauthorized"),
    );
    assert!(
        models_response(&data_plane_addr, "vpc-client-secret-v2").contains("200 OK"),
        "the currently-issued key must survive the revocation publish"
    );

    // Phase 5: replay. Write the authentic-but-older first snapshot back into
    // the channel; its revision is at-or-below the data plane's replay floor,
    // so it must be rejected WITHOUT resurrecting the revoked v1 key.
    std::fs::write(&state_path, &first_signed_snapshot).unwrap();
    trigger_sync(&data_plane_addr);
    wait_until(
        "data plane reports the replayed snapshot as stale",
        Duration::from_secs(10),
        || {
            admin_status_response(&data_plane_addr, CP_ADMIN_SECRET)
                .contains("revision is stale or replayed")
        },
    );
    assert!(
        models_response(&data_plane_addr, "vpc-client-secret-v1").contains("401 Unauthorized"),
        "a replayed older snapshot must not resurrect a revoked key"
    );
    assert!(
        models_response(&data_plane_addr, "vpc-client-secret-v2").contains("200 OK"),
        "rejecting a replay must leave the active policy untouched"
    );

    publisher.stop();
    data_plane.stop();
}

/// DSN-gated (#206 acceptance: persisted replay floor): a data-plane RESTART
/// must not reopen the replay window. With a durable (Supabase/Postgres)
/// control-plane store, the floor survives the restart, so an
/// older-but-authentically-signed snapshot written into the channel while the
/// data plane was down is rejected on startup -- and a strictly newer signed
/// publish still supersedes it.
///
/// Skips (like every other DSN-gated suite) unless `FERROGATE_SUPABASE_DSN`
/// is set; the DSN is only ever written to a tempdir config file, never to the
/// repository. Identities and seeded key ids are unique per run so parallel or
/// repeated runs never collide in the shared database (the two bootstrap key
/// documents this seeds are inert: unique ids, unique secrets, no bindings).
#[test]
fn persisted_replay_floor_rejects_older_signed_snapshot_after_data_plane_restart() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping persisted_replay_floor_rejects_older_signed_snapshot_after_data_plane_restart: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };
    let run = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let tenant = format!("tenant-e2e-floor-{run}");
    let deployment = format!("vpc-dp-{run}");
    // Generous pool/connect/statement budgets: this test runs against a REAL
    // remote Postgres (Supabase) where the default 1s pool-acquisition
    // deadline is routinely exceeded during schema validation over a WAN.
    let storage_toml = format!(
        "storage = {{ provider = \"postgres\", required = true, postgres_dsn = \"{dsn}\", \
         postgres_schema = \"ferrogate_control\", postgres_pool_acquire_timeout_millis = 20000, \
         postgres_connect_timeout_secs = 30, postgres_statement_timeout_millis = 60000 }}\n"
    );
    let key_a_secret = format!("cp-issued-a-{run}");
    let key_b_secret = format!("cp-issued-b-{run}");
    let key_c_secret = format!("cp-issued-c-{run}");
    let dp_admin_id = format!("dp-admin-{run}");
    let dp_admin_secret = format!("dp-admin-secret-{run}");
    let dp_seed_id = format!("dp-seed-{run}");
    let dp_seed_secret = format!("dp-seed-secret-{run}");

    let (seed_b64, public_b64) = control_plane_keypair(11);
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("control").join("cluster-state.json");
    let pair = VpcPair {
        state_path: &state_path,
        tenant: &tenant,
        deployment: &deployment,
        signing_seed_b64: &seed_b64,
        trusted_public_b64: &public_b64,
        data_plane_storage_toml: &storage_toml,
        issued_key: ("cp-issued-a", &key_a_secret),
        data_plane_seed: (&dp_admin_id, &dp_admin_secret, &dp_seed_id, &dp_seed_secret),
    };

    let publisher_addr = free_addr();
    let publisher_config_path = dir.path().join("control-plane.toml");
    std::fs::write(
        &publisher_config_path,
        pair.publisher_config(&publisher_addr),
    )
    .unwrap();

    let data_plane_addr = free_addr();
    let data_plane_config_path = dir.path().join("data-plane.toml");
    std::fs::write(
        &data_plane_config_path,
        pair.data_plane_config(&data_plane_addr),
    )
    .unwrap();

    // Control plane publishes signed generation 1 (admin + key A).
    let publisher = Gateway::start(&publisher_config_path, &publisher_addr);
    trigger_sync(&publisher_addr);
    wait_for_signed_snapshot(&state_path);
    let generation_one = std::fs::read(&state_path).unwrap();

    // Data plane activates generation 1 (persisted floor -> 1)...
    let data_plane = Gateway::start_with_durable_storage(&data_plane_config_path, &data_plane_addr);
    wait_until(
        "data plane activates signed generation 1",
        Duration::from_secs(30),
        || models_response(&data_plane_addr, &key_a_secret).contains("200 OK"),
    );

    // ...then generation 2 (issue key B, floor -> 2) and generation 3 (REVOKE
    // key A, floor -> 3). Key A now exists ONLY inside older signed snapshots,
    // which makes it the observable replay probe.
    create_api_key(
        &publisher_addr,
        CP_ADMIN_SECRET,
        "cp-issued-b",
        &key_b_secret,
    );
    wait_until(
        "data plane activates signed generation 2",
        Duration::from_secs(30),
        || models_response(&data_plane_addr, &key_b_secret).contains("200 OK"),
    );
    delete_api_key(&publisher_addr, CP_ADMIN_SECRET, "cp-issued-a");
    wait_until(
        "data plane activates signed generation 3 (key A revoked)",
        Duration::from_secs(30),
        || models_response(&data_plane_addr, &key_a_secret).contains("401 Unauthorized"),
    );
    let generation_three = std::fs::read(&state_path).unwrap();

    // Restart-rollback attempt: while the data plane is down, an attacker with
    // channel write access replays the authentic generation-1 snapshot. If the
    // replay floor were process-local, the restarted node (floor reset to 0)
    // would activate it and resurrect revoked key A.
    data_plane.stop();
    std::fs::write(&state_path, &generation_one).unwrap();

    let data_plane = Gateway::start_with_durable_storage(&data_plane_config_path, &data_plane_addr);
    trigger_sync(&data_plane_addr);
    wait_until(
        "restarted data plane rejects the replayed older snapshot via the persisted floor",
        Duration::from_secs(30),
        || {
            admin_status_response(&data_plane_addr, &dp_admin_secret)
                .contains("revision is stale or replayed")
        },
    );
    assert!(
        models_response(&data_plane_addr, &key_a_secret).contains("401 Unauthorized"),
        "the replayed generation-1 snapshot must not activate after a restart"
    );
    // The durable store also persisted the last-known-good policy itself, so
    // the restarted data plane still enforces the newest activated snapshot.
    assert!(
        models_response(&data_plane_addr, &key_b_secret).contains("200 OK"),
        "the persisted last-known-good policy must survive the restart"
    );

    // A strictly newer signed publish supersedes the floor: restore the
    // channel to the latest snapshot (so the publisher's generation counter
    // resumes past the floor) and issue key C -> generation 4.
    std::fs::write(&state_path, &generation_three).unwrap();
    create_api_key(
        &publisher_addr,
        CP_ADMIN_SECRET,
        "cp-issued-c",
        &key_c_secret,
    );
    wait_until(
        "data plane activates signed generation 4 after the restart",
        Duration::from_secs(30),
        || models_response(&data_plane_addr, &key_c_secret).contains("200 OK"),
    );
    assert!(
        models_response(&data_plane_addr, &key_a_secret).contains("401 Unauthorized"),
        "revoked generation-1 keys must stay revoked after the floor-superseding publish"
    );

    publisher.stop();
    data_plane.stop();
}
