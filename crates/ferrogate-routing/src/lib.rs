//! Route matching and upstream selection boundaries.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch {
    pub route_name: String,
    pub upstream_name: String,
}

pub trait RouteMatcher {
    fn match_route(&self, host: Option<&str>, path: &str) -> Option<RouteMatch>;
}
