// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! CLI/API version reporting and a tested compatibility check (issue #360).
//!
//! FerroGate uses calendar versions (`YYYY.M.D`). The client refuses to talk
//! to a Control Plane API whose contract version predates the minimum it was
//! built against, failing with an actionable message rather than mis-decoding
//! responses shaped by an older or incompatible contract. Both sides are
//! surfaced by a `version` command so operators can see the mismatch directly.

use crate::error::{CliError, CliResult};

/// This client crate's own version (the workspace calendar version).
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Oldest Control Plane API contract version this client understands. Bumped
/// deliberately when a breaking contract change lands so an old server fails
/// closed instead of returning responses the client would silently mis-map.
pub const MIN_SUPPORTED_API_VERSION: &str = "2026.6.0";

/// The `User-Agent` the transport advertises.
pub fn user_agent() -> String {
    format!("ferrogate-cli/{CLI_VERSION}")
}

/// A parsed calendar version: `year.month.day`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CalendarVersion {
    pub year: u32,
    pub month: u32,
    pub day: u32,
}

impl CalendarVersion {
    /// Parse a `YYYY.M.D` string. A trailing pre-release/build suffix after a
    /// `-` or `+` is ignored so `2026.7.9-rc1` still parses.
    pub fn parse(raw: &str) -> CliResult<CalendarVersion> {
        let core = raw.split(['-', '+']).next().unwrap_or(raw).trim();
        let mut parts = core.split('.');
        let mut next = |field: &str| -> CliResult<u32> {
            parts
                .next()
                .and_then(|value| value.trim().parse::<u32>().ok())
                .ok_or_else(|| {
                    CliError::usage(format!(
                        "'{raw}' is not a valid YYYY.M.D calendar version (bad {field})"
                    ))
                })
        };
        let year = next("year")?;
        let month = next("month")?;
        let day = next("day")?;
        if parts.next().is_some() {
            return Err(CliError::usage(format!(
                "'{raw}' has too many version components; expected YYYY.M.D"
            )));
        }
        if month == 0 || month > 12 {
            return Err(CliError::usage(format!(
                "'{raw}' has an out-of-range month {month}"
            )));
        }
        Ok(CalendarVersion { year, month, day })
    }
}

/// A version compatibility verdict against the Control Plane API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityReport {
    pub cli_version: String,
    pub server_version: String,
    pub min_supported: String,
    pub compatible: bool,
}

/// Check whether the client can safely talk to a server reporting
/// `server_version`. Returns a populated [`CompatibilityReport`] on success
/// and an actionable usage error when the server is too old.
pub fn check_compatibility(server_version: &str) -> CliResult<CompatibilityReport> {
    let server = CalendarVersion::parse(server_version)?;
    let minimum = CalendarVersion::parse(MIN_SUPPORTED_API_VERSION)
        .expect("MIN_SUPPORTED_API_VERSION is a valid constant");
    if server < minimum {
        return Err(CliError::usage(format!(
            "Control Plane API version {server_version} is older than the minimum supported \
             {MIN_SUPPORTED_API_VERSION}; upgrade the server or use a matching CLI release \
             (this CLI is {CLI_VERSION})"
        )));
    }
    Ok(CompatibilityReport {
        cli_version: CLI_VERSION.to_string(),
        server_version: server_version.to_string(),
        min_supported: MIN_SUPPORTED_API_VERSION.to_string(),
        compatible: true,
    })
}

#[cfg(test)]
#[path = "version_test.rs"]
mod version_test;
