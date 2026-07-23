// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Repository-level coverage for the #330 SQL-pushdown token
// sum (`sum_api_key_committed_tokens`), proving it returns exactly what the
// pre-#330 "load the whole table then filter+sum in Rust" gate returned for
// a given api_key_id on the in-memory backend.

use crate::schema_routing_test_support::block_on;
use crate::{RuntimeStorageRepositories, StorageProviderKind, StoredUsageAggregate, TokenUsage};

fn aggregate(
    id: &str,
    api_key_id: Option<&str>,
    prompt: u64,
    completion: u64,
    total: u64,
) -> StoredUsageAggregate {
    StoredUsageAggregate {
        id: id.into(),
        organization_id: Some("tenant-a".into()),
        project_id: None,
        api_key_id: api_key_id.map(str::to_string),
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        usage: TokenUsage::new(prompt, completion, total),
    }
}

/// The exact aggregation the pre-#330 `AppState::api_key_total_tokens_used`
/// performed after loading `usage_aggregates()` wholesale: filter to the
/// api_key_id, sum `total_tokens`. The new SQL/in-memory sum must equal it.
fn legacy_full_scan_sum(aggregates: &[StoredUsageAggregate], api_key_id: &str) -> u64 {
    aggregates
        .iter()
        .filter(|aggregate| aggregate.api_key_id.as_deref() == Some(api_key_id))
        .map(|aggregate| aggregate.usage.total_tokens)
        .sum()
}

#[test]
fn sum_api_key_committed_tokens_matches_full_scan_filter_sum() {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16);

    // Two rows for key_dev (must be summed), one row for a different key
    // (must be excluded), and one keyless row (must be excluded) -- the same
    // shapes the legacy full-scan filter had to skip over.
    let seed = [
        aggregate("agg-1", Some("key_dev"), 2, 6, 8),
        aggregate("agg-2", Some("key_dev"), 5, 9, 14),
        aggregate("agg-3", Some("key_other"), 100, 100, 200),
        aggregate("agg-4", None, 7, 7, 14),
    ];
    for record in &seed {
        block_on(repositories.replace_usage_aggregate(record.clone())).unwrap();
    }

    // Cross-check against a live full-table read + in-Rust filter/sum: the
    // pushdown must return the identical value the old gate would have.
    let full_scan = block_on(repositories.usage_aggregates());
    let expected = legacy_full_scan_sum(&full_scan, "key_dev");
    assert_eq!(expected, 22, "sanity: two key_dev rows sum to 8 + 14");

    let pushed_down = block_on(repositories.sum_api_key_committed_tokens("key_dev"));
    assert_eq!(
        pushed_down, expected,
        "SQL-pushdown sum must equal the legacy full-scan filter+sum for key_dev"
    );

    // A key with no rows is a definite zero (COALESCE / empty filter), not an
    // error or a leaked total from other keys.
    assert_eq!(
        block_on(repositories.sum_api_key_committed_tokens("key_absent")),
        0,
        "an api key with no usage rows sums to zero"
    );
    assert_eq!(
        block_on(repositories.sum_api_key_committed_tokens("key_other")),
        legacy_full_scan_sum(&full_scan, "key_other"),
    );
}
