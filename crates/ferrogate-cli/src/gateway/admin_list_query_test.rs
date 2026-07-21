use super::*;

#[test]
fn query_values_are_percent_decoded_and_empty_values_are_ignored() {
    assert_eq!(
        query_value(
            Some("search=hello%20world&tenant_id=tenant%2Facme"),
            "search"
        )
        .as_deref(),
        Some("hello world")
    );
    assert_eq!(
        query_value(
            Some("search=hello%20world&tenant_id=tenant%2Facme"),
            "tenant_id"
        )
        .as_deref(),
        Some("tenant/acme")
    );
    assert_eq!(query_value(Some("search="), "search"), None);
}

#[test]
fn search_is_case_insensitive_across_declared_fields() {
    assert!(matches_search(
        Some("ACME"),
        &["tenant-1", "Acme Production"]
    ));
    assert!(!matches_search(
        Some("staging"),
        &["tenant-1", "Acme Production"]
    ));
    assert!(matches_search(None, &["anything"]));
}

#[test]
fn list_response_preserves_legacy_unpaged_shape_and_pages_queries() {
    let legacy = list_response(
        vec![1, 2, 3],
        None,
        AdminPagination {
            offset: 1,
            limit: 1,
        },
    );
    assert_eq!(legacy.data, vec![1, 2, 3]);
    assert_eq!(legacy.total, None);

    let page = list_response(
        vec![1, 2, 3],
        Some("offset=1&limit=1"),
        AdminPagination {
            offset: 1,
            limit: 1,
        },
    );
    assert_eq!(page.data, vec![2]);
    assert_eq!(page.total, Some(3));
    assert_eq!(page.offset, Some(1));
    assert_eq!(page.limit, Some(1));
}
