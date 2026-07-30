// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Per-field request-document assembly for small mutations (issue #361).
//!
//! Every mutating verb used to require a *complete* JSON document, so flipping
//! one field meant hand-writing the whole object — the "accept explicit flags
//! for small mutations" half of #361's contract was unimplemented. This module
//! is the field-level half: `--set KEY=VALUE` / `--set-json KEY=JSON` pairs are
//! folded into the same `serde_json::Value` the `--data`/`--file` path
//! produces, so nothing downstream — builders, receipts, fingerprints — learns
//! that a document was assembled rather than supplied.
//!
//! Two deliberate design choices:
//!
//! * **String and JSON assignment are separate flags.** A single `--set` with
//!   type inference has to guess whether `007`, `true`, or `null` is a scalar
//!   or a string, and it guesses wrong on exactly the values where being wrong
//!   is unrecoverable (a zero-padded id silently becoming the number 7). `--set`
//!   is therefore *always* a JSON string and `--set-json` is *always* parsed,
//!   so the operator states the type instead of the CLI inferring it.
//! * **Conflicting assignments are a usage error, never a merge.** Clap hands
//!   the two flags over as two separate lists, so their relative order on the
//!   command line is already lost; resolving `a=1 a=2` by "last wins" would be
//!   resolving it by an order this layer cannot see. Refusing both duplicate
//!   paths and scalar/object collisions (`--set a=1 --set a.b=2`) removes the
//!   question rather than answering it arbitrarily.
//!
//! Everything here is pure — no clock, no environment, no I/O — so the whole
//! assembly and its refusals are unit-testable without a parser or a network.

use serde_json::{Map, Value};

use crate::error::{CliError, CliResult};

/// Substrings that mark a request-document key as credential-bearing.
///
/// Matched case-insensitively as substrings so `upstream_api_key` and
/// `client_secret` are caught alongside the bare names. Deliberately **not**
/// containing `token`: in this codebase `token` overwhelmingly means metered
/// LLM tokens (`token_usage`, `tokens_per_minute`), so including it would fire
/// the warning on documents carrying no credential at all and train operators
/// to ignore it.
const CREDENTIAL_KEY_MARKERS: &[&str] = &[
    "api_key",
    "apikey",
    "secret",
    "password",
    "passphrase",
    "credential",
    "private_key",
    "access_key",
    "auth_token",
    "bearer_token",
];

/// One resolved `KEY=VALUE` assignment: the dotted key split into its object
/// path, plus the value to place there.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldAssignment {
    path: Vec<String>,
    value: Value,
    /// The key exactly as the operator typed it, for error messages that quote
    /// the command line rather than a reconstruction of it.
    raw_key: String,
}

impl FieldAssignment {
    /// The dotted object path this assignment targets.
    pub fn path(&self) -> &[String] {
        &self.path
    }

    /// The value to be placed at [`FieldAssignment::path`].
    pub fn value(&self) -> &Value {
        &self.value
    }
}

/// Parse one `KEY=VALUE` pair. `json_value` selects whether the right-hand side
/// is taken as a JSON string verbatim (`--set`) or parsed as a JSON literal
/// (`--set-json`).
///
/// The key is split on unescaped `.` into an object path; `\.` is a literal dot
/// in a field name. Only the **first** `=` separates key from value, so a value
/// may contain `=` freely.
pub fn parse_assignment(raw: &str, json_value: bool) -> CliResult<FieldAssignment> {
    let flag = if json_value { "--set-json" } else { "--set" };
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| CliError::usage(format!("{flag} must be KEY=VALUE, got '{raw}'")))?;
    let path = parse_key_path(key, flag)?;
    let value = if json_value {
        serde_json::from_str(value).map_err(|error| {
            CliError::usage(format!(
                "{flag} value for '{key}' is not valid JSON: {error} \
                 (use --set for a plain string)"
            ))
        })?
    } else {
        Value::String(value.to_string())
    };
    Ok(FieldAssignment {
        path,
        value,
        raw_key: key.to_string(),
    })
}

/// Split a dotted key into its object path, honouring `\.` as a literal dot.
fn parse_key_path(key: &str, flag: &str) -> CliResult<Vec<String>> {
    let mut path = Vec::new();
    let mut segment = String::new();
    let mut escaped = false;
    for character in key.chars() {
        match character {
            '\\' if !escaped => escaped = true,
            '.' if !escaped => {
                path.push(std::mem::take(&mut segment));
            }
            other => {
                // A backslash before anything but `.` is kept verbatim rather
                // than swallowed: field names are server-owned and this layer
                // must not invent an escape vocabulary it does not implement.
                if escaped && other != '.' {
                    segment.push('\\');
                }
                escaped = false;
                segment.push(other);
            }
        }
    }
    if escaped {
        return Err(CliError::usage(format!(
            "{flag} key '{key}' ends in a trailing backslash; write '\\\\' for a literal backslash"
        )));
    }
    path.push(segment);
    if path.iter().any(|part| part.trim().is_empty()) {
        return Err(CliError::usage(format!(
            "{flag} key '{key}' has an empty field name; write 'a.b' with a name on both sides \
             of every dot"
        )));
    }
    Ok(path)
}

/// Fold parsed assignments into one request document.
///
/// Returns `None` when there are no assignments, so a caller can distinguish
/// "no per-field flags were given" from "an empty document was requested".
pub fn build_document(assignments: &[FieldAssignment]) -> CliResult<Option<Value>> {
    if assignments.is_empty() {
        return Ok(None);
    }
    let mut root = Map::new();
    for assignment in assignments {
        insert_assignment(&mut root, assignment)?;
    }
    Ok(Some(Value::Object(root)))
}

/// Place one assignment into the document being built, refusing rather than
/// resolving any collision with an assignment already placed.
fn insert_assignment(root: &mut Map<String, Value>, assignment: &FieldAssignment) -> CliResult<()> {
    let (leaf, parents) = assignment
        .path
        .split_last()
        .expect("parse_key_path always yields at least one segment");
    let mut cursor = root;
    let mut walked: Vec<&str> = Vec::new();
    for parent in parents {
        walked.push(parent.as_str());
        let entry = cursor
            .entry(parent.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            return Err(collision_error(
                &assignment.raw_key,
                &walked.join("."),
                "a value",
                "a nested field",
            ));
        }
        cursor = entry
            .as_object_mut()
            .expect("the non-object case returned above");
    }
    if let Some(existing) = cursor.get(leaf.as_str()) {
        let (had, wants) = if existing.is_object() {
            ("a nested field", "a value")
        } else {
            ("a value", "a value")
        };
        walked.push(leaf.as_str());
        return Err(collision_error(
            &assignment.raw_key,
            &walked.join("."),
            had,
            wants,
        ));
    }
    cursor.insert(leaf.clone(), assignment.value.clone());
    Ok(())
}

fn collision_error(raw_key: &str, path: &str, had: &str, wants: &str) -> CliError {
    CliError::usage(format!(
        "--set/--set-json assign '{path}' twice: it already holds {had} and '{raw_key}' wants to \
         give it {wants}. Command-line flag order is not preserved across the two flags, so this \
         is refused rather than resolved; pass the whole document with --file instead"
    ))
}

/// Parse and fold both flag lists in one step: the shape a command layer wants.
pub fn document_from_flags(set: &[String], set_json: &[String]) -> CliResult<Option<Value>> {
    let mut assignments = Vec::with_capacity(set.len() + set_json.len());
    for raw in set {
        assignments.push(parse_assignment(raw, false)?);
    }
    for raw in set_json {
        assignments.push(parse_assignment(raw, true)?);
    }
    build_document(&assignments)
}

/// The operator-facing warning for a credential-bearing document passed on
/// argv, or `None` when the document carries nothing that looks like key
/// material.
///
/// `--data` puts the whole request document in `argv`, where it lands in shell
/// history and is readable by any local `ps` for the life of the process.
/// `--file`/stdin is the safe alternative but nothing said so. The scan is
/// keyed on the document the operator actually passed (plus the invoked group's
/// declared one-time secret fields), so the warning fires on the creates that
/// really do carry an upstream credential and stays silent otherwise.
///
/// Pure: returns the message instead of printing it, so the decision is
/// testable without capturing process stderr.
pub fn argv_credential_warning(document: &Value, secret_fields: &[&str]) -> Option<String> {
    let mut hits = Vec::new();
    collect_credential_keys(document, secret_fields, &mut hits);
    if hits.is_empty() {
        return None;
    }
    hits.sort();
    hits.dedup();
    Some(format!(
        "warning: --data puts this document in argv, where '{}' is visible to shell history and \
         to any local `ps` while the command runs; pass it with --file <PATH> or --file - \
         (stdin) instead",
        hits.join("', '")
    ))
}

fn collect_credential_keys(value: &Value, secret_fields: &[&str], hits: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, field) in map {
                if is_credential_key(key, secret_fields) && !field.is_null() {
                    hits.push(key.clone());
                }
                collect_credential_keys(field, secret_fields, hits);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_credential_keys(item, secret_fields, hits);
            }
        }
        _ => {}
    }
}

fn is_credential_key(key: &str, secret_fields: &[&str]) -> bool {
    if secret_fields.contains(&key) {
        return true;
    }
    let lowered = key.to_ascii_lowercase();
    CREDENTIAL_KEY_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

#[cfg(test)]
#[path = "field_set_test.rs"]
mod field_set_test;
