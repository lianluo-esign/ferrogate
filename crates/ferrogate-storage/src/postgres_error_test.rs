// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-13
// description: Regression tests for safe PostgreSQL error rendering.

use super::*;

#[test]
fn postgres_database_details_are_not_exposed_in_storage_errors() {
    let rendered = postgres_database_error_message(
        "duplicate key value violates unique constraint",
        "23505",
        Some("Key (tenant_id, api_key)=(tenant-secret, key-secret) already exists."),
    );

    assert_eq!(
        rendered,
        "duplicate key value violates unique constraint (SQLSTATE 23505)"
    );
    assert!(!rendered.contains("tenant-secret"));
    assert!(!rendered.contains("key-secret"));
}
