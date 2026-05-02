//! Admin API boundary.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayStatus {
    pub service: String,
    pub version: String,
    pub runtime: String,
}
