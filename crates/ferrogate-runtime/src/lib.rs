//! Pingora runtime boundary.

mod reload;

pub use reload::{ReloadCandidate, ReloadCoordinator, ReloadOutcome, RuntimeSnapshot};

/// Runtime lifecycle commands exposed by the CLI and future control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCommand {
    Run,
    Validate,
    Reload,
}
