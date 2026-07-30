// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Official Tier-1 MCP SDK opponent for the released 2026-07-28 revision.

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::{cli::LocalArgs, constants::CLIENT_AUTH, local::LocalHarness};

const FIXTURE_DIRECTORY: &str = "tools/ferrogate-test/fixtures/mcp-candidate-client-official";
const SDK_PACKAGE: &str = "@modelcontextprotocol/client";
const SDK_VERSION: &str = "2.0.0";
const SDK_INTEGRITY: &str =
    "sha512-8f1OghQ2rjzIOfqgUCP+8GiUWqRs89njoWLNqAe8kWmDePv3s1fZXseej+QXemssEuuOvLLmLO/kqM3IQHtISw==";
const SDK_TARBALL: &str =
    "https://registry.npmjs.org/@modelcontextprotocol/client/-/client-2.0.0.tgz";
const SDK_REPOSITORY: &str = "modelcontextprotocol/typescript-sdk";
const SDK_TAG: &str = "@modelcontextprotocol/client@2.0.0";
const SDK_COMMIT: &str = "cc4b41617ce3601b1290d67216ea0b194a3cd9ac";
const SDK_TAG_OBJECT: &str = "ba0cd9ba0c5d56d1cf5635adece92349dff5af38";
/// Ingress pin: the released `schema/2026-07-28/schema.ts` artifact.
const SPEC_COMMIT: &str = "5f5440bb26a62e2cf3440b92da5a667efa03b267";
const SPEC_SCHEMA_PATH: &str = "schema/2026-07-28/schema.ts";
/// The opponent SDK's checked-in types were generated from the pre-release
/// `schema/draft/` artifact of the same revision, not from [`SPEC_COMMIT`].
/// Two artifacts under one revision name; folding them makes the recorded
/// evidence state something that is not true.
const SDK_SPEC_COMMIT: &str = "71e306956a4959c9655e5036be215d41986596e6";
const SDK_SPEC_SCHEMA_PATH: &str = "schema/draft/schema.ts";
const SDK_SPEC_GENERATED_SOURCE: &str = "packages/core-internal/src/types/spec.types.2026-07-28.ts";
const SPEC_TAG: &str = "2026-07-28";
const SPEC_VERSION: &str = "2026-07-28";

pub(crate) fn run_mcp_candidate_client_official(args: &LocalArgs) -> Result<()> {
    let root = repository_root()?;
    let source = root.join(FIXTURE_DIRECTORY);
    verify_provenance(&source)?;

    let temp = tempfile::tempdir().context("create isolated official MCP opponent checkout")?;
    let opponent = temp.path().join("opponent");
    copy_fixture(&source, &opponent)?;
    let cache = env::var_os("FERROGATE_TEST_NPM_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.path().join("npm-cache"));
    fs::create_dir_all(&cache)
        .with_context(|| format!("create isolated npm cache at {}", cache.display()))?;

    println!(
        "== mcp-candidate-client-official: install {SDK_PACKAGE}@{SDK_VERSION} from lockfile =="
    );
    run_npm_ci(&root.join("scripts/node-env.sh"), &cache, &opponent)?;

    let primary = LocalHarness::start(&args.ferrogate_bin, 0)?;
    let secondary = LocalHarness::start(&args.ferrogate_bin, 0)?;
    let primary_endpoint = format!("http://{}/v1/mcp", primary.gateway_addr);
    let secondary_endpoint = format!("http://{}/v1/mcp", secondary.gateway_addr);
    let token = CLIENT_AUTH
        .strip_prefix("Authorization: Bearer ")
        .context("CLIENT_AUTH no longer contains a bearer token")?;
    let output = run_official_client(
        &root.join("scripts/node-env.sh"),
        &opponent,
        &primary_endpoint,
        &secondary_endpoint,
        token,
    )?;
    let evidence: OpponentEvidence = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "official MCP client emitted invalid evidence JSON: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })?;
    validate_evidence(&evidence)?;

    println!(
        "mcp-candidate-client-official: opponent={SDK_PACKAGE}@{SDK_VERSION} sdk_commit={SDK_COMMIT}"
    );
    println!(
        "mcp-candidate-client-official: protocol_artifact=modelcontextprotocol/modelcontextprotocol@{SPEC_COMMIT} tag={SPEC_TAG} status=final schema_path={SPEC_SCHEMA_PATH}"
    );
    println!(
        "mcp-candidate-client-official: opponent_generated_from=modelcontextprotocol/modelcontextprotocol@{SDK_SPEC_COMMIT} schema_path={SDK_SPEC_SCHEMA_PATH}"
    );
    println!(
        "mcp-candidate-client-official: modern={} legacy={} two-instance discover/list/call + no-session wire contract passed",
        evidence.modern.protocol_version, evidence.legacy.protocol_version
    );
    Ok(())
}

fn repository_root() -> Result<PathBuf> {
    if let Some(root) = env::var_os("FERROGATE_TEST_REPO_ROOT") {
        let root = PathBuf::from(root);
        ensure_repo_root(&root)?;
        return Ok(root);
    }
    let current = env::current_dir().context("read current directory")?;
    for candidate in current.ancestors() {
        if ensure_repo_root(candidate).is_ok() {
            return Ok(candidate.to_path_buf());
        }
    }
    for candidate in Path::new(env!("CARGO_MANIFEST_DIR")).ancestors() {
        if ensure_repo_root(candidate).is_ok() {
            return Ok(candidate.to_path_buf());
        }
    }
    bail!(
        "cannot locate the FerroGate repository root; run from the checkout or set FERROGATE_TEST_REPO_ROOT"
    )
}

fn ensure_repo_root(root: &Path) -> Result<()> {
    ensure!(
        root.join("Cargo.toml").is_file()
            && root.join("scripts/node-env.sh").is_file()
            && root.join(FIXTURE_DIRECTORY).is_dir(),
        "{} is not a FerroGate repository root",
        root.display()
    );
    Ok(())
}

fn verify_provenance(source: &Path) -> Result<()> {
    let package = read_json(&source.join("package.json"))?;
    ensure!(
        package.pointer("/dependencies/@modelcontextprotocol~1client")
            == Some(&Value::String(SDK_VERSION.to_string())),
        "official MCP opponent package.json must pin {SDK_PACKAGE} exactly to {SDK_VERSION}"
    );
    let lock = read_json(&source.join("package-lock.json"))?;
    let locked = lock
        .pointer("/packages/node_modules~1@modelcontextprotocol~1client")
        .context("official MCP opponent lockfile has no client package entry")?;
    ensure!(
        locked["version"] == SDK_VERSION,
        "official SDK lock version drifted"
    );
    ensure!(
        locked["integrity"] == SDK_INTEGRITY,
        "official SDK npm integrity drifted"
    );
    ensure!(
        locked["resolved"] == SDK_TARBALL,
        "official SDK npm tarball drifted"
    );

    let provenance = read_json(&source.join("provenance.json"))?;
    for (pointer, expected) in [
        ("/opponent/package", SDK_PACKAGE),
        ("/opponent/version", SDK_VERSION),
        ("/opponent/npm_integrity", SDK_INTEGRITY),
        ("/opponent/repository", SDK_REPOSITORY),
        ("/opponent/tag", SDK_TAG),
        ("/opponent/commit", SDK_COMMIT),
        ("/opponent/tag_object", SDK_TAG_OBJECT),
        ("/protocol_artifact/status", "final"),
        ("/protocol_artifact/tag", SPEC_TAG),
        ("/protocol_artifact/revision", SPEC_VERSION),
        ("/protocol_artifact/commit", SPEC_COMMIT),
        ("/protocol_artifact/schema_path", SPEC_SCHEMA_PATH),
        ("/opponent_generated_from/commit", SDK_SPEC_COMMIT),
        ("/opponent_generated_from/schema_path", SDK_SPEC_SCHEMA_PATH),
        (
            "/opponent_generated_from/sdk_generated_source",
            SDK_SPEC_GENERATED_SOURCE,
        ),
    ] {
        ensure!(
            provenance.pointer(pointer).and_then(Value::as_str) == Some(expected),
            "official MCP opponent provenance {pointer} drifted"
        );
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<Value> {
    let input = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&input).with_context(|| format!("parse {}", path.display()))
}

fn copy_fixture(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).with_context(|| format!("create {}", destination.display()))?;
    for name in [
        "package.json",
        "package-lock.json",
        "provenance.json",
        "client.mjs",
    ] {
        fs::copy(source.join(name), destination.join(name)).with_context(|| {
            format!(
                "copy official opponent fixture {} to isolated checkout",
                source.join(name).display()
            )
        })?;
    }
    Ok(())
}

fn run_npm_ci(node_env: &Path, cache: &Path, opponent: &Path) -> Result<()> {
    let output = Command::new("bash")
        .args([
            "-c",
            concat!(
                ". \"$1\"; ",
                "ferrogate_require_node \"mcp-candidate-client-official\" || exit 1; ",
                "command -v timeout >/dev/null 2>&1 || { echo 'timeout is required for the official MCP opponent install' >&2; exit 1; }; ",
                "shift; exec timeout --signal=KILL \"${FERROGATE_TEST_MCP_OFFICIAL_NPM_TIMEOUT:-600}\" npm \"$@\""
            ),
            "ferrogate-test",
        ])
        .arg(node_env)
        .args(["ci", "--ignore-scripts", "--no-audit", "--no-fund"])
        .current_dir(opponent)
        .env("npm_config_cache", cache)
        .env("npm_config_legacy_peer_deps", "false")
        .env("npm_config_strict_peer_deps", "true")
        .env("npm_config_update_notifier", "false")
        .env("CI", "1")
        .output()
        .context("install the locked official MCP client")?;
    ensure!(
        output.status.success(),
        "locked official MCP client install failed with {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn run_official_client(
    node_env: &Path,
    opponent: &Path,
    primary_endpoint: &str,
    secondary_endpoint: &str,
    token: &str,
) -> Result<std::process::Output> {
    let output = Command::new("bash")
        .args([
            "-c",
            concat!(
                ". \"$1\"; ",
                "ferrogate_require_node \"mcp-candidate-client-official\" || exit 1; ",
                "command -v timeout >/dev/null 2>&1 || { echo 'timeout is required for the official MCP opponent' >&2; exit 1; }; ",
                "shift; exec timeout --signal=KILL \"${FERROGATE_TEST_MCP_OFFICIAL_TIMEOUT:-90}\" node \"$@\""
            ),
            "ferrogate-test",
        ])
        .arg(node_env)
        .arg("client.mjs")
        .current_dir(opponent)
        .env("FERROGATE_MCP_OFFICIAL_ENDPOINT", primary_endpoint)
        .env(
            "FERROGATE_MCP_OFFICIAL_SECONDARY_ENDPOINT",
            secondary_endpoint,
        )
        .env("FERROGATE_MCP_OFFICIAL_TOKEN", token)
        .output()
        .context("run the official MCP client against FerroGate")?;
    ensure!(
        output.status.success(),
        "official MCP client failed with {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpponentEvidence {
    opponent: OpponentIdentity,
    spec_version: String,
    modern: OpponentLeg,
    legacy: OpponentLeg,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpponentIdentity {
    package: String,
    version: String,
    commit: String,
    protocol_artifact_commit: String,
    protocol_artifact_status: String,
    sdk_spec_commit: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpponentLeg {
    era: String,
    protocol_version: String,
    tools: Vec<String>,
    call: Value,
    wire: Vec<ObservedRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObservedRequest {
    gateway_instance: usize,
    http_method: String,
    headers: BTreeMap<String, String>,
    body: Option<Value>,
    response: Option<Value>,
}

fn validate_evidence(evidence: &OpponentEvidence) -> Result<()> {
    ensure!(
        evidence.opponent.package == SDK_PACKAGE,
        "opponent package drifted"
    );
    ensure!(
        evidence.opponent.version == SDK_VERSION,
        "opponent version drifted"
    );
    ensure!(
        evidence.opponent.commit == SDK_COMMIT,
        "opponent commit drifted"
    );
    ensure!(
        evidence.opponent.protocol_artifact_commit == SPEC_COMMIT
            && evidence.opponent.protocol_artifact_status == "final"
            && evidence.spec_version == SPEC_VERSION,
        "opponent no longer reports the pinned final 2026-07-28 artifact"
    );
    ensure!(
        evidence.opponent.sdk_spec_commit == SDK_SPEC_COMMIT,
        "opponent no longer reports the pre-release artifact its types were generated from"
    );
    validate_leg_result(&evidence.modern, "modern", SPEC_VERSION)?;
    validate_leg_result(&evidence.legacy, "legacy", "2025-11-25")?;
    validate_modern_wire(&evidence.modern.wire)?;
    validate_legacy_wire(&evidence.legacy.wire)?;
    Ok(())
}

fn validate_leg_result(leg: &OpponentLeg, era: &str, version: &str) -> Result<()> {
    ensure!(
        leg.era == era,
        "official client selected {0} instead of {era}",
        leg.era
    );
    ensure!(
        leg.protocol_version == version,
        "official {era} client negotiated {} instead of {version}",
        leg.protocol_version
    );
    ensure!(
        leg.tools.iter().any(|tool| tool == "http-search"),
        "official {era} client did not discover http-search"
    );
    ensure!(
        leg.call["isError"].as_bool() == Some(false)
            && leg.call["content"].as_array().is_some_and(|content| {
                content
                    .iter()
                    .any(|item| item["text"] == "ferrogate-result")
            }),
        "official {era} client did not complete http-search: {}",
        leg.call
    );
    Ok(())
}

fn rpc_requests(wire: &[ObservedRequest]) -> Vec<&ObservedRequest> {
    wire.iter()
        .filter(|request| {
            request
                .body
                .as_ref()
                .and_then(|body| body.get("method"))
                .is_some()
        })
        .collect()
}

fn validate_modern_wire(wire: &[ObservedRequest]) -> Result<()> {
    ensure!(
        wire.iter()
            .all(|request| !request.headers.contains_key("mcp-session-id")),
        "official modern client emitted Mcp-Session-Id"
    );
    let requests = rpc_requests(wire);
    let methods: Vec<&str> = requests
        .iter()
        .filter_map(|request| request.body.as_ref()?.get("method")?.as_str())
        .collect();
    ensure!(
        methods == ["server/discover", "tools/list", "tools/call"],
        "official modern wire sequence was {methods:?}"
    );
    let gateway_instances: Vec<usize> = requests
        .iter()
        .map(|request| request.gateway_instance)
        .collect();
    ensure!(
        gateway_instances == [0, 1, 0],
        "official modern requests did not alternate across two FerroGate instances: {gateway_instances:?}"
    );
    for (request, method) in requests.into_iter().zip(methods) {
        ensure!(
            request.http_method == "POST",
            "{method} was not an HTTP POST"
        );
        ensure!(
            request.headers.get("authorization").map(String::as_str) == Some("<redacted>"),
            "{method} did not carry redacted authentication evidence"
        );
        ensure!(
            request
                .headers
                .get("mcp-protocol-version")
                .map(String::as_str)
                == Some(SPEC_VERSION),
            "{method} omitted the 2026-07-28 protocol header"
        );
        ensure!(
            request.headers.get("mcp-method").map(String::as_str) == Some(method),
            "{method} omitted its mirrored method header"
        );
        let body = request
            .body
            .as_ref()
            .context("modern request body missing")?;
        let metadata = body
            .pointer("/params/_meta")
            .and_then(Value::as_object)
            .with_context(|| format!("{method} omitted params._meta"))?;
        ensure!(
            metadata
                .get("io.modelcontextprotocol/protocolVersion")
                .and_then(Value::as_str)
                == Some(SPEC_VERSION),
            "{method} omitted per-request protocolVersion"
        );
        ensure!(
            metadata
                .get("io.modelcontextprotocol/clientCapabilities")
                .is_some_and(Value::is_object),
            "{method} omitted per-request clientCapabilities"
        );
        let client_info = metadata
            .get("io.modelcontextprotocol/clientInfo")
            .and_then(Value::as_object)
            .with_context(|| format!("{method} omitted per-request clientInfo"))?;
        ensure!(
            client_info.get("name").and_then(Value::as_str) == Some("ferrogate-official-modern")
                && client_info.get("version").and_then(Value::as_str) == Some("1.0.0"),
            "{method} emitted malformed or unexpected per-request clientInfo"
        );
        if method == "tools/call" {
            ensure!(
                request.headers.get("mcp-name").map(String::as_str) == Some("http-search"),
                "tools/call omitted its mirrored name header"
            );
        } else {
            ensure!(
                !request.headers.contains_key("mcp-name"),
                "{method} carried an inapplicable Mcp-Name header"
            );
        }
        if method == "tools/list" {
            let result = request
                .response
                .as_ref()
                .and_then(|response| response.get("result"))
                .with_context(|| "tools/list evidence omitted its JSON-RPC result")?;
            ensure!(
                result.get("ttlMs").and_then(Value::as_u64) == Some(5_000),
                "tools/list result omitted the bounded 2026-07-28 ttlMs"
            );
            ensure!(
                result.get("cacheScope").and_then(Value::as_str) == Some("private"),
                "tools/list result omitted its authorization-private cacheScope"
            );
        }
    }
    Ok(())
}

fn validate_legacy_wire(wire: &[ObservedRequest]) -> Result<()> {
    let requests = rpc_requests(wire);
    let methods: Vec<&str> = requests
        .iter()
        .filter_map(|request| request.body.as_ref()?.get("method")?.as_str())
        .collect();
    ensure!(
        methods
            .windows(3)
            .any(|methods| methods == ["initialize", "tools/list", "tools/call"])
            || methods.windows(4).any(|methods| {
                methods
                    == [
                        "initialize",
                        "notifications/initialized",
                        "tools/list",
                        "tools/call",
                    ]
            }),
        "official legacy wire did not initialize -> list -> call: {methods:?}"
    );
    ensure!(
        !methods.contains(&"server/discover"),
        "official legacy mode unexpectedly probed server/discover"
    );
    let initialize = requests
        .iter()
        .find(|request| {
            request
                .body
                .as_ref()
                .and_then(|body| body.get("method"))
                .and_then(Value::as_str)
                == Some("initialize")
        })
        .context("official legacy client emitted no initialize request")?;
    ensure!(
        initialize
            .body
            .as_ref()
            .and_then(|body| body.pointer("/params/protocolVersion"))
            .and_then(Value::as_str)
            == Some("2025-11-25"),
        "legacy initialize claimed a non-legacy protocol"
    );
    for request in requests {
        ensure!(
            request.gateway_instance == 0,
            "official legacy request escaped its initialized FerroGate instance"
        );
        ensure!(
            !request.headers.contains_key("mcp-method")
                && !request.headers.contains_key("mcp-name")
                && request
                    .headers
                    .get("mcp-protocol-version")
                    .map(String::as_str)
                    != Some(SPEC_VERSION),
            "legacy request carried 2026-07-28 routing headers"
        );
        ensure!(
            request
                .body
                .as_ref()
                .and_then(
                    |body| body.pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
                )
                .and_then(Value::as_str)
                != Some(SPEC_VERSION),
            "legacy request carried 2026-07-28 per-request metadata"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "mcp_candidate_official_test.rs"]
mod mcp_candidate_official_test;
