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

    /// Build a sink over an already-open handle.
    ///
    /// Test-only. `commit`'s failure arm is what makes the stderr fallback in
    /// `resource_cmd.rs` load-bearing, and it is otherwise unreachable from a
    /// hermetic test: a handle this process created moments ago with
    /// `create_new` does not refuse a few hundred bytes on demand, and the
    /// conditions that would make it (ENOSPC, EDQUOT, EIO) cannot be produced
    /// without privileges. Handing in a handle that cannot be written to
    /// reproduces the same `write_all` error the real path returns.
    #[cfg(test)]
    pub(crate) fn from_open_handle(path: &Path, file: File) -> SecretFile {
        SecretFile {
            path: path.to_path_buf(),
            file,
        }
    }

    /// Write the secret document into the reserved file.
    ///
    /// The receipt has already been rendered by the time this runs, so a
    /// failure here says plainly that the marker on stdout points at a file
    /// that does not hold the key.
    ///
    /// Both failures are [`CliError::transport`], not `usage`: they happen
    /// AFTER the mutation took effect, and `usage` is exit 2 — "caller-side
    /// misuse or invalid local configuration", which a script reads as *the
    /// command was malformed and nothing happened*. That is the opposite of
    /// what an ENOSPC here means. `reserve` keeps `usage`, where a bad path
    /// genuinely is caller-side and genuinely did send nothing;
    /// `resource_cmd.rs`'s stdout-write failure is the same
    /// already-happened shape and already used `transport`.
    pub(crate) fn commit(mut self, document: &Value) -> CliResult<()> {
        let mut rendered = serde_json::to_vec_pretty(document).map_err(|error| {
            CliError::transport(format!("failed to render secret material: {error}"))
        })?;
        rendered.push(b'\n');
        self.file
            .write_all(&rendered)
            .and_then(|()| self.file.flush())
            .map_err(|error| {
                CliError::transport(format!(
                    "failed to write --secret-file {}: {error}. The mutation WAS applied and its \
                     one-time secret did not reach the file",
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
///
/// The permission clause is `#[cfg(unix)]` because the `mode(0o600)` that earns
/// it is: on a non-Unix target that call is compiled out and the file is
/// created under the platform's default ACL. Claiming 0600 there would tell an
/// operator the key is protected on exactly the platform where this code did
/// not protect it.
pub(crate) fn wrote_notice(path: &Path, taken: &[DivertedSecret]) -> String {
    let fields = field_list(taken.iter().map(|secret| secret.field.as_str()));
    let path = path.display();
    #[cfg(unix)]
    {
        format!(
            "note: one-time secret material ({fields}) was written to {path} with mode 0600 and \
             kept off stdout"
        )
    }
    #[cfg(not(unix))]
    {
        format!(
            "note: one-time secret material ({fields}) was written to {path} and kept off \
             stdout; its permissions are this platform's default for a new file — confirm they \
             restrict it before leaving the key there"
        )
    }
}

/// The stderr message that carries the one-time secret material when the sink
/// could not be written.
///
/// By the time `commit` fails the mutation has been applied, the key has been
/// issued, and the server will never show it again — but the material is still
/// in this process, one line above the `return Err(..)`. Dropping it there
/// forces the operator to rotate a credential that a full disk caused, so the
/// fallback prints it. stderr is the only safe landing place: it is outside
/// the #505 render gate and outside the stdout pipe `--output json` feeds, so
/// the fallback cannot corrupt a piped receipt.
///
/// Pure: returns the message rather than printing it, so what it carries is
/// assertable without capturing process stderr.
pub(crate) fn commit_failure_fallback(path: &Path, document: &Value) -> String {
    format!(
        "warning: --secret-file {} could not be written, so the one-time secret material follows \
         on stderr. Store it now — the mutation WAS applied and the server will not show it \
         again:\n{}",
        path.display(),
        serde_json::to_string_pretty(document).unwrap_or_else(|_| document.to_string())
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
