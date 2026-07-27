// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for process-local application state reload behavior.

use super::*;

#[test]
fn process_local_reload_preserves_request_id_sequence() {
    let shared = SharedAppState::with_source_path(Config::default(), None);
    let first = shared.next_request_id();

    let result = shared.reload_process_local(Config::default());

    assert!(result.committed);
    let second = shared.next_request_id();
    let first = u64::from_str_radix(first.trim_start_matches("fg-"), 16).unwrap();
    let second = u64::from_str_radix(second.trim_start_matches("fg-"), 16).unwrap();
    assert_eq!(second, first.wrapping_add(1));
}
