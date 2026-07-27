// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! On-disk persistence for the shared `ContextStore` (issue #360).
//!
//! `ferrogate-control-plane-client` deliberately keeps `ContextStore` an in-memory,
//! serializable model and leaves "where it lives on disk" to the composing
//! binary. This module is that binary-side layer: it resolves the config path,
//! loads a missing file as an empty store (first run is not an error), and
//! writes it back as owner-only TOML.
//!
//! Only *how to obtain* a credential (an [`AuthSource`]) is ever stored — never
//! a token value — so the file carries no secret material. The file is still
//! written `0600` on Unix: it names the environment variable a secret lives in,
//! which is itself worth keeping private.

use std::path::{Path, PathBuf};

use ferrogate_control_plane_client::context::{Context, ContextStore};
use ferrogate_control_plane_client::error::{CliError, CliResult};
use serde::{Deserialize, Serialize};

/// Environment variable that overrides the CLI config *directory* (the folder
/// holding `contexts.toml`). Lets tests and packagers relocate client state
/// without touching the operator's real home directory.
pub(crate) const CONFIG_HOME_VAR: &str = "FERROGATE_CLI_HOME";

/// File name for the persisted context store within the config directory.
pub(crate) const CONTEXTS_FILE: &str = "contexts.toml";

/// On-disk mirror of [`ContextStore`].
///
/// `current` is declared **before** `contexts` on purpose: TOML requires every
/// scalar at a given table level to be emitted before any array-of-tables, so
/// serializing the library's `{ contexts, current }` order directly would
/// produce invalid TOML (a scalar after `[[contexts]]`). This wrapper fixes the
/// field order at the persistence boundary and is otherwise identical.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedStore {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current: Option<String>,
    #[serde(default)]
    contexts: Vec<Context>,
}

impl PersistedStore {
    fn from_store(store: &ContextStore) -> PersistedStore {
        PersistedStore {
            current: store.current.clone(),
            contexts: store.contexts.clone(),
        }
    }

    fn into_store(self) -> ContextStore {
        ContextStore {
            contexts: self.contexts,
            current: self.current,
        }
    }
}

/// Resolve the path to `contexts.toml`.
///
/// Precedence: `FERROGATE_CLI_HOME` (explicit config dir) > `XDG_CONFIG_HOME` >
/// `HOME/.config`, each with `ferrogate/` appended only for the XDG/HOME cases
/// (an explicit `FERROGATE_CLI_HOME` is taken verbatim so a test/tempdir maps
/// one-to-one to the file).
pub(crate) fn contexts_path() -> CliResult<PathBuf> {
    if let Some(dir) = non_empty_os(CONFIG_HOME_VAR) {
        return Ok(PathBuf::from(dir).join(CONTEXTS_FILE));
    }
    let base = non_empty_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| non_empty_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| {
            CliError::usage(
                "cannot locate a config directory for contexts: set FERROGATE_CLI_HOME, \
                 XDG_CONFIG_HOME, or HOME",
            )
        })?;
    Ok(base.join("ferrogate").join(CONTEXTS_FILE))
}

fn non_empty_os(name: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

/// Load the store at the default path, treating a missing file as an empty
/// store (first run).
pub(crate) fn load() -> CliResult<ContextStore> {
    load_at(&contexts_path()?)
}

/// Persist the store to the default path.
pub(crate) fn save(store: &ContextStore) -> CliResult<()> {
    save_at(&contexts_path()?, store)
}

/// Load the store from an explicit path (missing file → empty store).
pub(crate) fn load_at(path: &Path) -> CliResult<ContextStore> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let persisted: PersistedStore = toml::from_str(&text).map_err(|error| {
                CliError::usage(format!(
                    "failed to parse the context store at {}: {error}",
                    path.display()
                ))
            })?;
            Ok(persisted.into_store())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ContextStore::default()),
        Err(error) => Err(CliError::usage(format!(
            "failed to read the context store at {}: {error}",
            path.display()
        ))),
    }
}

/// Persist the store to an explicit path, creating parent directories and
/// enforcing owner-only permissions.
pub(crate) fn save_at(path: &Path, store: &ContextStore) -> CliResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            CliError::usage(format!(
                "failed to create config directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    let text = toml::to_string_pretty(&PersistedStore::from_store(store))
        .map_err(|error| CliError::usage(format!("failed to serialize contexts: {error}")))?;
    write_private(path, text.as_bytes())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> CliResult<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| write_error(path, error))?;
    // `.mode()` only applies on creation; force 0600 in case the file already
    // existed with a looser mode.
    if let Ok(metadata) = file.metadata() {
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        let _ = file.set_permissions(perms);
    }
    file.write_all(bytes)
        .map_err(|error| write_error(path, error))
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> CliResult<()> {
    std::fs::write(path, bytes).map_err(|error| write_error(path, error))
}

fn write_error(path: &Path, error: std::io::Error) -> CliError {
    CliError::usage(format!(
        "failed to write the context store at {}: {error}",
        path.display()
    ))
}

#[cfg(test)]
#[path = "store_test.rs"]
mod store_test;
