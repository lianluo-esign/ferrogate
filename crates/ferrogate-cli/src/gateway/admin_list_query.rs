use crate::{responses::AdminList, state::AdminPagination};

pub(super) fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    let url = reqwest::Url::parse(&format!("http://localhost/?{}", query?)).ok()?;
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(super) fn matches_search(search: Option<&str>, values: &[&str]) -> bool {
    let Some(search) = search.map(str::trim).filter(|search| !search.is_empty()) else {
        return true;
    };
    let search = search.to_lowercase();
    values
        .iter()
        .any(|value| value.to_lowercase().contains(&search))
}

pub(super) fn list_response<T>(
    data: Vec<T>,
    query: Option<&str>,
    pagination: AdminPagination,
) -> AdminList<T> {
    if query.is_none() {
        return AdminList::new(data);
    }

    let total = data.len();
    let page = data
        .into_iter()
        .skip(pagination.offset)
        .take(pagination.limit)
        .collect();
    AdminList::paginated(page, total, pagination.offset, pagination.limit)
}

#[cfg(test)]
#[path = "admin_list_query_test.rs"]
mod tests;
