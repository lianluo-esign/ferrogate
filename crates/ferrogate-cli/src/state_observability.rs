// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for OTLP/analytics observability export
// config accessors, export success/error bookkeeping, and status views.

use super::*;

impl AppState {
    pub(crate) fn state_service_name(&self) -> String {
        self.config.telemetry.service_name.clone()
    }

    pub(crate) fn otlp_endpoint(&self) -> Option<String> {
        self.observability_otlp_endpoint().or_else(|| {
            self.config
                .telemetry
                .otlp_endpoint
                .as_ref()
                .map(|endpoint| endpoint.trim().to_string())
                .filter(|endpoint| !endpoint.is_empty())
        })
    }

    pub(crate) fn otlp_timeout_secs(&self) -> u64 {
        self.config.observability.export_timeout_secs
    }

    pub(crate) fn analytics_vector_endpoint(&self) -> Option<String> {
        if !self.config.analytics.enabled
            || self.config.analytics.provider != AnalyticsProvider::Vector
        {
            return None;
        }
        self.config
            .analytics
            .vector_endpoint
            .as_ref()
            .map(|endpoint| endpoint.trim().to_string())
            .filter(|endpoint| !endpoint.is_empty())
    }

    pub(crate) fn analytics_clickhouse_url(&self) -> Option<String> {
        if !self.config.analytics.enabled
            || self.config.analytics.provider != AnalyticsProvider::Clickhouse
        {
            return None;
        }
        self.config
            .analytics
            .clickhouse_url
            .as_ref()
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty())
            .or_else(|| {
                self.config
                    .analytics
                    .clickhouse_url_env
                    .as_ref()
                    .and_then(|name| std::env::var(name).ok())
                    .map(|url| url.trim().to_string())
                    .filter(|url| !url.is_empty())
            })
    }

    pub(crate) fn analytics_timeout_secs(&self) -> u64 {
        self.config.analytics.export_timeout_secs
    }

    pub(crate) fn analytics_flush_interval_millis(&self) -> u64 {
        self.config.analytics.flush_interval_millis
    }

    pub(crate) fn analytics_batch_max_events(&self) -> usize {
        self.config.analytics.batch_max_events
    }

    pub(crate) fn record_observability_export_success(&self) {
        if let Ok(mut status) = self.observability_export.lock() {
            status.last_success_at_unix = now_unix_seconds();
            status.last_export_error = None;
        }
    }

    pub(crate) fn record_observability_export_error(&self, error: impl ToString) {
        if let Ok(mut status) = self.observability_export.lock() {
            status.last_export_error = Some(error.to_string());
        }
    }

    pub(crate) fn record_analytics_export_success(&self) {
        if let Ok(mut status) = self.analytics_export.lock() {
            status.last_success_at_unix = now_unix_seconds();
            status.last_export_error = None;
        }
    }

    pub(crate) fn record_analytics_export_error(&self, error: impl ToString) {
        if let Ok(mut status) = self.analytics_export.lock() {
            status.last_export_error = Some(error.to_string());
        }
    }

    pub(crate) fn observability_status(&self) -> Vec<ObservabilityStatus> {
        let explicit_endpoint = self.observability_otlp_endpoint();
        let legacy_endpoint = self
            .config
            .telemetry
            .otlp_endpoint
            .as_ref()
            .map(|endpoint| endpoint.trim().to_string())
            .filter(|endpoint| !endpoint.is_empty());
        let endpoint = explicit_endpoint
            .clone()
            .or_else(|| legacy_endpoint.clone());
        let enabled = self.config.observability.enabled || legacy_endpoint.is_some();
        let endpoint_source = if explicit_endpoint.is_some() {
            "observability"
        } else if legacy_endpoint.is_some() {
            "telemetry_legacy"
        } else {
            "none"
        };
        let provider = if self.config.observability.enabled {
            format!("{:?}", self.config.observability.provider).to_ascii_lowercase()
        } else if legacy_endpoint.is_some() {
            "otlp".to_string()
        } else {
            "none".to_string()
        };
        let export = self
            .observability_export
            .lock()
            .map(|status| status.clone())
            .unwrap_or_default();
        let health = if !enabled {
            "disabled"
        } else if export.last_export_error.is_some() {
            "degraded"
        } else if export.last_success_at_unix.is_some() {
            "ok"
        } else {
            "configured"
        };
        vec![ObservabilityStatus {
            provider,
            enabled,
            active: endpoint.is_some(),
            endpoint,
            endpoint_source,
            protocol: "otlp_http_json",
            signals: vec!["metrics", "logs", "traces"],
            prometheus_metrics_path: self.config.observability.prometheus_metrics_path.clone(),
            export_timeout_secs: self.config.observability.export_timeout_secs,
            health,
            last_success_at_unix: export.last_success_at_unix,
            last_export_error: export.last_export_error,
            queue_backpressure_events: export.queue_backpressure_events,
            dropped_events: export.dropped_events,
        }]
    }

    pub(crate) fn analytics_status(&self) -> AnalyticsStatus {
        let analytics = &self.config.analytics;
        let (provider, mode, sink_configured) = match analytics.provider {
            AnalyticsProvider::Vector => (
                "vector".to_string(),
                "pipeline",
                analytics
                    .vector_endpoint
                    .as_deref()
                    .is_some_and(|endpoint| !endpoint.trim().is_empty()),
            ),
            AnalyticsProvider::Clickhouse => (
                "clickhouse".to_string(),
                "direct_warehouse",
                analytics
                    .clickhouse_url
                    .as_deref()
                    .is_some_and(|url| !url.trim().is_empty())
                    || analytics
                        .clickhouse_url_env
                        .as_deref()
                        .is_some_and(|name| !name.trim().is_empty()),
            ),
            AnalyticsProvider::None => ("none".to_string(), "none", false),
        };
        let active =
            analytics.enabled && sink_configured && analytics.provider != AnalyticsProvider::None;
        let export = self
            .analytics_export
            .lock()
            .map(|status| status.clone())
            .unwrap_or_default();
        let health = if !analytics.enabled {
            "disabled"
        } else if export.last_export_error.is_some() {
            "degraded"
        } else if export.last_success_at_unix.is_some() {
            "ok"
        } else if active {
            "configured"
        } else {
            "not_configured"
        };
        AnalyticsStatus {
            provider,
            enabled: analytics.enabled,
            active,
            required: analytics.required,
            mode,
            sink_configured,
            signals: vec![
                "request_logs",
                "traces",
                "usage_metrics",
                "billing_metering",
                "dashboard_aggregates",
            ],
            export_timeout_secs: analytics.export_timeout_secs,
            batch_max_events: analytics.batch_max_events,
            flush_interval_millis: analytics.flush_interval_millis,
            queue_capacity: analytics.queue_capacity,
            request_log_retention_records: analytics.request_log_retention_records,
            audit_event_retention_records: analytics.audit_event_retention_records,
            billing_event_retention_records: analytics.billing_event_retention_records,
            health,
            last_success_at_unix: export.last_success_at_unix,
            last_export_error: export.last_export_error,
            contract_version: 1,
        }
    }

    fn observability_otlp_endpoint(&self) -> Option<String> {
        if !self.config.observability.enabled {
            return None;
        }
        self.config
            .observability
            .otlp_endpoint
            .as_ref()
            .map(|endpoint| endpoint.trim().to_string())
            .filter(|endpoint| !endpoint.is_empty())
    }
}
