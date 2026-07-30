// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The explicit safe output path for one-time secret material (issue #361).
//!
//! `redact_response` already blanks a group's one-time secret fields on every
//! **read**, but a create/rotate legitimately returns key material once, and
//! that single moment had no destination other than stdout: `ctl virtual-keys
//! create|rotate` and `ctl api-keys create` printed the key into terminal
//! scrollback and into any `tee`/CI log capturing the run. The contract bullet
//! asks for an explicit safe sink; this module is the filesystem half of it
//! (the pure extraction lives in
//! [`ferrogate_control_plane_client::resource::divert_secret_fields`]).
//!
//! Two properties make the sink safe rather than merely different:
//!
//! * **The file is created, never opened.** `create_new` fails if the path
//!   already exists, so the command cannot truncate an operator's file and
//!   cannot be aimed through a pre-planted symlink at one. A collision is a
//!   refusal with a message, not a silent overwrite.
//! * **The mode is set at creation on Unix**, so the key material is never
//!   momentarily world-readable in the window between `open` and a follow-up
//!   `chmod`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ferrogate_control_plane_client::error::{CliError, CliResult};
use ferrogate_control_plane_client::resource::DivertedSecret;
use serde_json::Value;

/// A secret file that already exists on disk, empty and 0600, waiting for the
/// key material its mutation has not been sent to fetch yet.
///
/// Reserving the path **before** the request leaves the process is the whole
/// point of the two-step: a path that already exists, a read-only directory,
/// or a bad parent is then a refusal with nothing sent and nothing lost. Doing
/// the same check after the call would mean discovering the sink is unusable
/// at the one moment the key is unrecoverable — the server has already issued
/// it and will never show it again.
#[derive(Debug)]
pub(crate) struct SecretFile {
    path: PathBuf,
    file: File,
}

impl SecretFile {
    /// Reserve `path`: create it 0600, refusing to touch an existing file.
    pub(crate) fn reserve(path: &Path) -> CliResult<SecretFile> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                CliError::usage(format!(
                    "--secret-file {} already exists; refusing to overwrite it. Nothing was \
                     sent — choose a path that does not exist and re-run",
                    path.display()
                ))
            } else {
                CliError::usage(format!(
                    "failed to create --secret-file {}: {error}. Nothing was sent",
                    path.display()
                ))
            }
        })?;
        Ok(SecretFile {
            path: path.to_path_buf(),
            file,
        })
    }

    /// The reserved path, for operator-facing messages.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Write the secret document into the reserved file.
    ///
    /// The receipt has already been rendered by the time this runs, so a
    /// failure here says plainly that the marker on stdout points at a file
    /// that does not hold the key: the operator must rotate rather than go
    /// looking for it.
    pub(crate) fn commit(mut self, document: &Value) -> CliResult<()> {
        let mut rendered = serde_json::to_vec_pretty(document).map_err(|error| {
            CliError::usage(format!("failed to render secret material: {error}"))
        })?;
        rendered.push(b'\n');
        self.file
            .write_all(&rendered)
            .and_then(|()| self.file.flush())
            .map_err(|error| {
                CliError::usage(format!(
                    "failed to write --secret-file {}: {error}. The mutation WAS applied and its \
                     one-time secret did not reach the file — rotate the credential",
                    self.path.display()
                ))
            })
    }

    /// Release the reservation when the call produced no key material — a
    /// refused mutation, or a family verb that simply returned none. Removing
    /// the empty file keeps a later run's `create_new` refusal meaningful
    /// instead of leaving a zero-byte tombstone in the way.
    pub(crate) fn discard(self) -> Option<String> {
        drop(self.file);
        match std::fs::remove_file(&self.path) {
            Ok(()) => None,
            Err(error) => Some(format!(
                "note: --secret-file {} received no key material and could not be removed \
                 ({error}); it is empty",
                self.path.display()
            )),
        }
    }
}

/// The stderr note confirming where secret material went.
pub(crate) fn wrote_notice(path: &Path, taken: &[DivertedSecret]) -> String {
    format!(
        "note: one-time secret material ({}) was written to {} with mode 0600 and kept off stdout",
        field_list(taken.iter().map(|secret| secret.field.as_str())),
        path.display()
    )
}

/// The stderr warning issued when a mutation returned one-time secret material
/// and no `--secret-file` was given, so the key did reach stdout.
///
/// The other half of "an explicit safe output path": an operator who does not
/// know the flag exists learns of it at the exact moment it mattered, rather
/// than after the key is already in their scrollback for good.
pub(crate) fn stdout_exposure_warning(fields: &[String]) -> String {
    format!(
        "warning: this response carries one-time secret material ({}) and it was printed to \
         stdout, where it lands in terminal scrollback and in any tee/CI log capturing this run; \
         re-run with --secret-file <PATH> to write it to a 0600 file instead",
        field_list(fields.iter().map(String::as_str))
    )
}

fn field_list<'a>(fields: impl Iterator<Item = &'a str>) -> String {
    let mut names: Vec<&str> = fields.collect();
    names.sort_unstable();
    names.dedup();
    names.join(", ")
}

#[cfg(test)]
#[path = "secret_sink_test.rs"]
mod secret_sink_test;
