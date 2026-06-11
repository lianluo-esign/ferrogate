// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub id: String,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadCandidate {
    pub snapshot: RuntimeSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadOutcome {
    pub active: RuntimeSnapshot,
    pub candidate: RuntimeSnapshot,
    pub committed: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReloadCoordinator {
    active: RuntimeSnapshot,
}

impl ReloadCoordinator {
    pub fn new(active_snapshot_id: impl Into<String>) -> Self {
        Self {
            active: RuntimeSnapshot {
                id: active_snapshot_id.into(),
                generation: 1,
            },
        }
    }

    pub fn active_snapshot(&self) -> &RuntimeSnapshot {
        &self.active
    }

    pub fn prepare(&self, candidate_snapshot_id: impl Into<String>) -> ReloadCandidate {
        ReloadCandidate {
            snapshot: RuntimeSnapshot {
                id: candidate_snapshot_id.into(),
                generation: self.active.generation + 1,
            },
        }
    }

    pub fn commit(&mut self, candidate: ReloadCandidate) -> ReloadOutcome {
        self.active = candidate.snapshot.clone();
        ReloadOutcome {
            active: self.active.clone(),
            candidate: candidate.snapshot,
            committed: true,
            reason: None,
        }
    }

    pub fn reject(&self, candidate: ReloadCandidate, reason: impl Into<String>) -> ReloadOutcome {
        ReloadOutcome {
            active: self.active.clone(),
            candidate: candidate.snapshot,
            committed: false,
            reason: Some(reason.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_publish_candidate_snapshot_before_commit() {
        let coordinator = ReloadCoordinator::new("active-a");
        let candidate = coordinator.prepare("candidate-b");

        assert_eq!(coordinator.active_snapshot().id, "active-a");
        assert_eq!(candidate.snapshot.id, "candidate-b");
        assert_eq!(candidate.snapshot.generation, 2);
    }

    #[test]
    fn replaces_active_snapshot_only_after_successful_commit() {
        let mut coordinator = ReloadCoordinator::new("active-a");
        let candidate = coordinator.prepare("candidate-b");

        let outcome = coordinator.commit(candidate);

        assert!(outcome.committed);
        assert_eq!(outcome.active.id, "candidate-b");
        assert_eq!(coordinator.active_snapshot().id, "candidate-b");
    }

    #[test]
    fn returns_current_active_snapshot_after_failed_reload_attempt() {
        let coordinator = ReloadCoordinator::new("active-a");
        let candidate = coordinator.prepare("candidate-b");

        let outcome = coordinator.reject(candidate, "candidate validation failed");

        assert!(!outcome.committed);
        assert_eq!(outcome.active.id, "active-a");
        assert_eq!(outcome.candidate.id, "candidate-b");
        assert_eq!(
            outcome.reason.as_deref(),
            Some("candidate validation failed")
        );
        assert_eq!(coordinator.active_snapshot().id, "active-a");
    }
}
