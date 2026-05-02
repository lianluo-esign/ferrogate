use crate::config::{config_snapshot_id, Config};
use ferrogate_runtime::{ReloadCoordinator, ReloadOutcome};

pub(crate) fn format_validate_report(config: &Config) -> String {
    let summary = ConfigSummary::from_config(config);
    format!(
        "FerroGate config OK: listen={}, admin={}, runtime=pingora, snapshot={}, upstreams={}, routes={}, providers={}, models={}, api_keys={}, auth_required={}",
        summary.listen,
        summary.admin,
        summary.snapshot,
        summary.upstreams,
        summary.routes,
        summary.providers,
        summary.models,
        summary.api_keys,
        summary.auth_required
    )
}

pub(crate) fn format_reload_report(config: &Config) -> String {
    let summary = ConfigSummary::from_config(config);
    let report = ReloadReport::validate_only(summary.snapshot.clone());
    format!(
        "FerroGate reload config OK: listen={}, admin={}, runtime=pingora, snapshot={}, mode=validate-only, swap=false, routes={}, upstreams={}. Reload execution is planned for P2.",
        summary.listen, summary.admin, report.candidate_snapshot, summary.routes, summary.upstreams
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReloadReport {
    pub(crate) candidate_snapshot: String,
    pub(crate) active_snapshot: String,
    pub(crate) committed: bool,
    pub(crate) mode: &'static str,
}

impl ReloadReport {
    fn validate_only(candidate_snapshot: String) -> Self {
        let coordinator = ReloadCoordinator::new("unmanaged-active");
        let candidate = coordinator.prepare(candidate_snapshot);
        Self::from_outcome(coordinator.reject(candidate, "validate-only"))
    }

    fn from_outcome(outcome: ReloadOutcome) -> Self {
        Self {
            candidate_snapshot: outcome.candidate.id,
            active_snapshot: outcome.active.id,
            committed: outcome.committed,
            mode: "validate-only",
        }
    }
}

#[derive(Debug, Clone)]
struct ConfigSummary {
    listen: String,
    admin: String,
    snapshot: String,
    upstreams: usize,
    routes: usize,
    providers: usize,
    models: usize,
    api_keys: usize,
    auth_required: bool,
}

impl ConfigSummary {
    fn from_config(config: &Config) -> Self {
        Self {
            listen: config.listen.clone(),
            admin: config
                .admin
                .listen
                .clone()
                .unwrap_or_else(|| "off".to_string()),
            snapshot: config_snapshot_id(config),
            upstreams: config.upstreams.len(),
            routes: config.routes.len(),
            providers: config.providers.len(),
            models: config.models.len(),
            api_keys: config.api_keys.len(),
            auth_required: !config.api_keys.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::RuntimeSnapshot;

    #[test]
    fn validate_report_is_metadata_only() {
        let config = Config::default();

        let report = format_validate_report(&config);

        assert!(report.contains("FerroGate config OK"));
        assert!(report.contains("snapshot="));
        assert!(report.contains("auth_required=false"));
    }

    #[test]
    fn reload_report_declares_validate_only_no_swap_mode() {
        let config = Config::default();

        let report = format_reload_report(&config);

        assert!(report.contains("FerroGate reload config OK"));
        assert!(report.contains("mode=validate-only"));
        assert!(report.contains("swap=false"));
        assert!(report.contains("planned for P2"));
    }

    #[test]
    fn reload_report_uses_runtime_reject_without_publishing_candidate() {
        let config = Config::default();
        let candidate = config_snapshot_id(&config);

        let report = ReloadReport::validate_only(candidate.clone());

        assert_eq!(report.candidate_snapshot, candidate);
        assert_eq!(report.active_snapshot, "unmanaged-active");
        assert!(!report.committed);
        assert_eq!(report.mode, "validate-only");
    }

    #[test]
    fn reload_report_projects_committed_outcome_as_active_candidate() {
        let outcome = ReloadOutcome {
            active: RuntimeSnapshot {
                id: "candidate-b".to_string(),
                generation: 2,
            },
            candidate: RuntimeSnapshot {
                id: "candidate-b".to_string(),
                generation: 2,
            },
            committed: true,
            reason: None,
        };

        let report = ReloadReport::from_outcome(outcome);

        assert_eq!(report.active_snapshot, "candidate-b");
        assert_eq!(report.candidate_snapshot, "candidate-b");
        assert!(report.committed);
    }
}
