//! Logging, metrics, and tracing boundaries.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityConfig {
    pub service_name: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: "ferrogate".to_string(),
        }
    }
}
