// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for version parsing and compatibility checking (#360).

use super::*;
use crate::error::ExitClass;

#[test]
fn calendar_version_parses_and_orders() {
    let a = CalendarVersion::parse("2026.6.22").unwrap();
    let b = CalendarVersion::parse("2026.7.9").unwrap();
    assert!(a < b);
    assert_eq!(a.year, 2026);
    assert_eq!(a.month, 6);
    assert_eq!(a.day, 22);
}

#[test]
fn calendar_version_ignores_prerelease_suffix() {
    let v = CalendarVersion::parse("2026.7.9-rc1").unwrap();
    assert_eq!(v, CalendarVersion::parse("2026.7.9").unwrap());
}

#[test]
fn calendar_version_rejects_garbage() {
    assert_eq!(
        CalendarVersion::parse("not-a-version")
            .unwrap_err()
            .exit_class(),
        ExitClass::Usage
    );
    assert_eq!(
        CalendarVersion::parse("2026.13.1")
            .unwrap_err()
            .exit_class(),
        ExitClass::Usage
    );
    assert_eq!(
        CalendarVersion::parse("2026.7.9.1")
            .unwrap_err()
            .exit_class(),
        ExitClass::Usage
    );
}

#[test]
fn current_versions_are_valid() {
    // The compiled-in constants must themselves be parseable, or the
    // compatibility check would panic at runtime.
    CalendarVersion::parse(CLI_VERSION).unwrap();
    CalendarVersion::parse(MIN_SUPPORTED_API_VERSION).unwrap();
    assert!(user_agent().contains(CLI_VERSION));
}

#[test]
fn compatible_server_passes() {
    let report = check_compatibility("2026.6.22").unwrap();
    assert!(report.compatible);
    assert_eq!(report.server_version, "2026.6.22");
    assert_eq!(report.cli_version, CLI_VERSION);
}

#[test]
fn newer_server_is_compatible() {
    assert!(check_compatibility("2027.1.1").unwrap().compatible);
}

#[test]
fn too_old_server_fails_closed_with_actionable_error() {
    let error = check_compatibility("2026.5.31").unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    let message = error.to_string();
    assert!(message.contains("older than the minimum supported"));
}
