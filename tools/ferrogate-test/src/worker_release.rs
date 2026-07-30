// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Clean-checkout Cloudflare Worker release dependency and runtime gate (#468).

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;

const WRANGLER_VERSION: &str = "4.107.1";
const WORKERS_TYPES_VERSION: &str = "4.20260702.1";
const VITEST_POOL_VERSION: &str = "0.18.1";
const AGENTS_VERSION: &str = "0.0.109";

/// Overrides the npm cache this gate installs from.
const NPM_CACHE_ENV: &str = "FERROGATE_TEST_NPM_CACHE";
/// Overrides the wall-clock budget for a single npm invocation, in seconds.
const NPM_TIMEOUT_ENV: &str = "FERROGATE_TEST_NPM_TIMEOUT";
/// Budget applied when `NPM_TIMEOUT_ENV` is unset. Interpolated into the gate's
/// shell line *and* into the failure hint, so the number the hint blames is
/// always the number that actually killed the command.
const DEFAULT_NPM_TIMEOUT_SECS: &str = "600";
/// Cache location when `NPM_CACHE_ENV` is unset, relative to the repository
/// root. Under `target/`, which is already gitignored.
const DEFAULT_NPM_CACHE_DIR: &str = "target/ferrogate-test/npm-cache";

pub(crate) fn run_worker_release() -> Result<()> {
    let root = repository_root()?;

    verify_toolchain_pins(&root)?;
    verify_documented_resolution(&root)?;
    for worker in ["agent-gateway", "d1-proxy"] {
        verify_lockfile(&root.join("workers").join(worker).join("package-lock.json"))?;
    }
    run_workers_gate_contract(&root)?;

    let temp = tempfile::tempdir().context("create the clean Worker release checkout")?;
    // #595: the npm *cache* is not part of the clean-checkout contract — the
    // checkout is (`copy_worker` excludes node_modules, and `npm ci` wipes and
    // reinstalls strictly from the lockfile whose integrity hashes are verified
    // above). Cache entries are content-addressed and integrity-checked on read,
    // so persisting them across runs cannot smuggle in a package the lockfile
    // does not pin. Defaulting to a per-run temp directory did make every
    // invocation re-download the whole pinned wrangler/workerd tree, which is
    // what pushed `npm ci` past the timeout below and, as the first link in the
    // `ci` chain, took every Rust scenario down with it.
    let cache = env::var_os(NPM_CACHE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(DEFAULT_NPM_CACHE_DIR));
    fs::create_dir_all(&cache)
        .with_context(|| format!("create the npm cache at {}", cache.display()))?;

    let agent = copy_worker(&root, temp.path(), "agent-gateway")?;
    let d1_proxy = copy_worker(&root, temp.path(), "d1-proxy")?;
    let node_env = root.join("scripts/node-env.sh");

    for (name, worker) in [("agent-gateway", &agent), ("d1-proxy", &d1_proxy)] {
        println!("== worker-release: clean npm install for workers/{name} ==");
        run_npm(
            &node_env,
            &cache,
            worker,
            &["ci", "--no-audit", "--no-fund"],
        )?;
        verify_dependency_tree(&node_env, &cache, worker)?;
        run_npm(&node_env, &cache, worker, &["run", "typecheck"])?;
    }

    println!("== worker-release: agent-gateway Workerd/Vitest suite ==");
    run_npm_quiet(
        &node_env,
        &cache,
        &agent,
        &[
            "test",
            "--",
            "--reporter=json",
            "--outputFile=vitest-results.json",
        ],
    )?;
    verify_vitest_result(&agent.join("vitest-results.json"))?;
    println!("worker-release: OK");
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

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for candidate in manifest_dir.ancestors() {
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
            && root.join("workers/agent-gateway/package.json").is_file()
            && root.join("workers/d1-proxy/package.json").is_file()
            && root.join("scripts/node-env.sh").is_file(),
        "{} is not a FerroGate repository root",
        root.display()
    );
    Ok(())
}

fn verify_toolchain_pins(root: &Path) -> Result<()> {
    let agent_path = root.join("workers/agent-gateway/package.json");
    let agent = read_json(&agent_path)?;
    assert_dependency(
        &agent,
        &agent_path,
        "dependencies",
        "agents",
        AGENTS_VERSION,
    )?;
    assert_dependency(
        &agent,
        &agent_path,
        "devDependencies",
        "wrangler",
        WRANGLER_VERSION,
    )?;
    assert_dependency(
        &agent,
        &agent_path,
        "devDependencies",
        "@cloudflare/workers-types",
        WORKERS_TYPES_VERSION,
    )?;
    assert_dependency(
        &agent,
        &agent_path,
        "devDependencies",
        "@cloudflare/vitest-pool-workers",
        VITEST_POOL_VERSION,
    )?;

    let d1_path = root.join("workers/d1-proxy/package.json");
    let d1_proxy = read_json(&d1_path)?;
    assert_dependency(
        &d1_proxy,
        &d1_path,
        "devDependencies",
        "wrangler",
        WRANGLER_VERSION,
    )?;
    assert_dependency(
        &d1_proxy,
        &d1_path,
        "devDependencies",
        "@cloudflare/workers-types",
        WORKERS_TYPES_VERSION,
    )
}

fn assert_dependency(
    manifest: &Value,
    path: &Path,
    section: &str,
    dependency: &str,
    expected: &str,
) -> Result<()> {
    let actual = manifest
        .get(section)
        .and_then(Value::as_object)
        .and_then(|dependencies| dependencies.get(dependency))
        .and_then(Value::as_str)
        .with_context(|| format!("{} has no string {section}.{dependency}", path.display()))?;
    ensure!(
        actual == expected,
        "{} must pin {dependency} exactly to {expected}, got {actual}",
        path.display()
    );
    Ok(())
}

fn verify_lockfile(path: &Path) -> Result<()> {
    let lock = read_json(path)?;
    let packages = lock
        .get("packages")
        .and_then(Value::as_object)
        .with_context(|| format!("{} has no packages object", path.display()))?;
    let mut incomplete = Vec::new();

    for (package_path, package) in packages {
        if !package_path.starts_with("node_modules/") {
            continue;
        }
        let package = package
            .as_object()
            .with_context(|| format!("{package_path} in {} is not an object", path.display()))?;
        if package.get("link").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let resolved = package
            .get("resolved")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty());
        let integrity = package
            .get("integrity")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty());
        if !resolved || !integrity {
            incomplete.push(package_path.as_str());
        }
    }

    ensure!(
        incomplete.is_empty(),
        "{} has external packages without resolved + integrity: {}",
        path.display(),
        incomplete.join(", ")
    );
    Ok(())
}

fn verify_documented_resolution(root: &Path) -> Result<()> {
    let path = root.join("workers/agent-gateway/README.md");
    let readme = fs::read_to_string(&path).with_context(|| {
        format!(
            "read dependency-resolution documentation {}",
            path.display()
        )
    })?;
    for required in [
        "partyserver",
        "wrangler@4.108.0",
        WRANGLER_VERSION,
        WORKERS_TYPES_VERSION,
        VITEST_POOL_VERSION,
        "--legacy-peer-deps",
    ] {
        ensure!(
            readme.contains(required),
            "{} must document the #468 dependency resolution and is missing {required:?}",
            path.display()
        );
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<Value> {
    let input = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&input).with_context(|| format!("parse {}", path.display()))
}

fn run_workers_gate_contract(root: &Path) -> Result<()> {
    let script = root.join("scripts/test-check-workers.sh");
    let status = Command::new("bash")
        .arg(&script)
        .current_dir(root)
        .status()
        .with_context(|| format!("run {}", script.display()))?;
    ensure!(
        status.success(),
        "{} failed with {status}",
        script.display()
    );
    Ok(())
}

fn copy_worker(root: &Path, destination: &Path, worker: &str) -> Result<PathBuf> {
    let source = root.join("workers").join(worker);
    let destination = destination.join("workers").join(worker);
    copy_tree(&source, &destination)?;
    Ok(destination)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).with_context(|| format!("create {}", destination.display()))?;
    for entry in fs::read_dir(source).with_context(|| format!("read {}", source.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some("node_modules" | ".wrangler" | "coverage" | "dist" | ".dev.vars" | ".env")
        ) {
            continue;
        }
        let source_path = entry.path();
        let destination_path = destination.join(&name);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!(
                    "copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
        } else {
            bail!(
                "clean Worker checkout refuses non-file entry {}",
                source_path.display()
            );
        }
    }
    Ok(())
}

fn run_npm(node_env: &Path, cache: &Path, worker: &Path, arguments: &[&str]) -> Result<()> {
    let status = npm_command(node_env, cache, worker, arguments)
        .status()
        .with_context(|| format!("run npm {} in {}", arguments.join(" "), worker.display()))?;
    ensure!(
        status.success(),
        "npm {} failed in {} with {status}{}",
        arguments.join(" "),
        worker.display(),
        npm_timeout_hint(&status)
    );
    Ok(())
}

/// Explains an npm exit that came from `timeout` rather than from npm itself.
///
/// `timeout` reports its own kill as 124, or as 128 + the signal it sent — 137
/// for the `--signal=KILL` this gate uses. Both surface as a bare numeric exit
/// status that reads like an npm crash, which is how the #595 report arrived:
/// the gate had been dying on a cold-cache download that never fit in the
/// budget, and nothing in the output said so.
fn npm_timeout_hint(status: &ExitStatus) -> String {
    if !matches!(status.code(), Some(124) | Some(137)) {
        return String::new();
    }
    let budget = env::var(NPM_TIMEOUT_ENV).unwrap_or_else(|_| DEFAULT_NPM_TIMEOUT_SECS.to_string());
    format!(
        "\n\
         this is the {NPM_TIMEOUT_ENV} kill at {budget}s, not an npm failure: the command was \
         still running when the budget expired.\n\
         A cold npm cache has to re-download the whole pinned tree; keep the cache warm (default \
         <repository root>/{DEFAULT_NPM_CACHE_DIR}, override with {NPM_CACHE_ENV}) or raise \
         {NPM_TIMEOUT_ENV}."
    )
}

fn verify_dependency_tree(node_env: &Path, cache: &Path, worker: &Path) -> Result<()> {
    let arguments = ["ls", "--all", "--json"];
    let output = npm_command(node_env, cache, worker, &arguments)
        .output()
        .with_context(|| format!("run npm ls in {}", worker.display()))?;
    ensure!(
        output.status.success(),
        "npm ls found an invalid dependency tree in {}:\n{}",
        worker.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let tree: Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parse npm ls output for {}", worker.display()))?;
    let problems = tree
        .get("problems")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    ensure!(
        problems.is_empty(),
        "npm ls reported dependency problems in {}: {}",
        worker.display(),
        Value::Array(problems.to_vec())
    );
    Ok(())
}

fn run_npm_quiet(node_env: &Path, cache: &Path, worker: &Path, arguments: &[&str]) -> Result<()> {
    let output = npm_command(node_env, cache, worker, arguments)
        .output()
        .with_context(|| format!("run npm {} in {}", arguments.join(" "), worker.display()))?;
    ensure!(
        output.status.success(),
        "npm {} failed in {} with {}{}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        arguments.join(" "),
        worker.display(),
        output.status,
        npm_timeout_hint(&output.status),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn verify_vitest_result(path: &Path) -> Result<()> {
    let result = read_json(path)?;
    let total = result
        .get("numTotalTests")
        .and_then(Value::as_u64)
        .with_context(|| format!("{} has no numeric numTotalTests", path.display()))?;
    let passed = result
        .get("numPassedTests")
        .and_then(Value::as_u64)
        .with_context(|| format!("{} has no numeric numPassedTests", path.display()))?;
    ensure!(
        total > 0,
        "{} reports an empty Vitest suite",
        path.display()
    );
    ensure!(
        result.get("success").and_then(Value::as_bool) == Some(true) && passed == total,
        "{} reports {passed}/{total} passing tests",
        path.display()
    );
    println!("worker-release: Workerd/Vitest {passed}/{total} tests passed");
    Ok(())
}

fn npm_command(node_env: &Path, cache: &Path, worker: &Path, arguments: &[&str]) -> Command {
    // Built with `format!` rather than `concat!` so the timeout budget has one
    // definition: `npm_timeout_hint` names this exact number when it blames the
    // timeout, and a literal duplicated here would let the hint drift into
    // reporting a budget that is not the one enforcing.
    let script = format!(
        ". \"$1\"; \
         ferrogate_require_node \"worker-release gate\" || exit 1; \
         shift; \
         if command -v timeout >/dev/null 2>&1; then \
         exec timeout --signal=KILL \"${{{NPM_TIMEOUT_ENV}:-{DEFAULT_NPM_TIMEOUT_SECS}}}\" npm \"$@\"; \
         fi; \
         echo \"WARNING: worker-release gate has no timeout binary; npm is unbounded\" >&2; \
         exec npm \"$@\""
    );
    let mut command = Command::new("bash");
    command
        .arg("-c")
        .arg(script)
        .arg("ferrogate-test")
        .arg(node_env)
        .args(arguments)
        .current_dir(worker)
        .env("npm_config_cache", cache)
        .env("npm_config_legacy_peer_deps", "false")
        .env("npm_config_strict_peer_deps", "true")
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .env("npm_config_update_notifier", "false")
        .env("CI", "1");
    command
}

#[cfg(test)]
#[path = "worker_release_test.rs"]
mod worker_release_test;
