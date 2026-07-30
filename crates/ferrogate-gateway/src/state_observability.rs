// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for OTLP/analytics observability export
// config accessors, export success/error bookkeeping, and status views.

use super::*;

use ferrogate_config::ObservabilityProvider;
use ferrogate_observability::{CloudflareBackend, OtlpBackend, TelemetryBackend};

impl AppState {
    pub(crate) fn state_service_name(&self) -> String {
        self.config.telemetry.service_name.clone()
    }

    /// Build the configured telemetry destination (issue #520).
    ///
    /// `None` means "no destination configured", which disables the export
    /// thread entirely. Notably, a `cloudflare` provider whose collector
    /// credential cannot be resolved returns `None` **rather than falling back
    /// to an unauthenticated OTLP post**: silently downgrading would either
    /// spin on 401s or ship telemetry to an endpoint that never agreed to
    /// authenticate it.
    pub(crate) fn telemetry_backend(&self) -> Option<Box<dyn TelemetryBackend>> {
        let endpoint = self.otlp_endpoint()?;

        if self.config.observability.enabled
            && self.config.observability.provider == ObservabilityProvider::Cloudflare
        {
            let token = self.cloudflare_collector_token()?;
            let backend = CloudflareBackend::new(endpoint, token)
                .with_default_tenant(self.config.observability.cloudflare_default_tenant.clone());
            if let Err(error) = backend.validate() {
                warn!(error = %error, "cloudflare telemetry backend rejected its configuration; observability export disabled");
                return None;
            }
            return Some(Box::new(backend));
        }

        Some(Box::new(OtlpBackend::new(endpoint)))
    }

    /// Resolve the collector Worker bearer token through the same
    /// `SecretResolverRegistry` seam used for provider API keys, so it can come
    /// from `env://`, Cloudflare Secrets Store (`cf://`), or any other
    /// registered scheme instead of plaintext config.
    fn cloudflare_collector_token(&self) -> Option<String> {
        let reference = self
            .config
            .observability
            .cloudflare_collector_token_ref
            .as_deref()
            .map(str::trim)
            .filter(|reference| !reference.is_empty());
        let Some(reference) = reference else {
            warn!("observability provider is `cloudflare` but no cloudflare_collector_token_ref is configured; observability export disabled");
            return None;
        };

        match ferrogate_secrets::SecretResolverRegistry::from_env().resolve(reference) {
            Ok(Some(token)) if !token.trim().is_empty() => Some(token),
            Ok(_) => {
                warn!("cloudflare_collector_token_ref resolved to no value; observability export disabled");
                None
            }
            Err(error) => {
                warn!(error = %error, "failed to resolve cloudflare_collector_token_ref; observability export disabled");
                None
            }
        }
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

    /// #522: record one governed action that reached a gateway surface without
    /// a declared `x-ferrogate-agent-run-id`, so it cannot be joined into a
    /// correlation chain. `tenant` is the authenticated tenant key (never a
    /// client-supplied value) and `surface` is a small fixed set (`mcp`,
    /// `asset`) — together they keep the exported metric low-cardinality.
    pub(crate) fn record_unjoinable_action(&self, tenant: &str, surface: &str) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_unjoinable_action(tenant, surface);
        }
    }

    /// #522: current unjoinable-action counters, appended to the `/metrics`
    /// body by [`render_unjoinable_actions_text`](ferrogate_observability::render_unjoinable_actions_text).
    pub(crate) fn unjoinable_action_metrics(
        &self,
    ) -> Vec<ferrogate_observability::UnjoinableActionMetricTotal> {
        self.metrics
            .lock()
            .map(|metrics| metrics.unjoinable_action_totals())
            .unwrap_or_default()
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
