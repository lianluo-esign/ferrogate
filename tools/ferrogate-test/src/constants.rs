// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

pub(crate) const ADMIN_AUTH: &str = "Authorization: Bearer admin-secret";
pub(crate) const CLIENT_AUTH: &str = "Authorization: Bearer client-secret";
pub(crate) const OBSERVER_AUTH: &str = "Authorization: Bearer observer-secret";
pub(crate) const AUTH_TEST_CLIENT_2: &str = "Authorization: Bearer test-secret-2";
pub(crate) const JSON_CONTENT: &str = "Content-Type: application/json";
/// Shared secret used between the gateway and the billing service in the
/// billing-chain E2E (issue #136).
pub(crate) const BILLING_SERVICE_TOKEN: &str = "billing-service-secret";
pub(crate) const BILLING_AUTH: &str = "Authorization: Bearer billing-service-secret";
pub(crate) const SUPPORT_SKILL_HEADER: &str = "x-ferrogate-skill-package: support-skill";
pub(crate) const SELF_HOSTED_MTLS_HEADER: &str = "x-ferrogate-transport-security: mutual_tls";
pub(crate) const SELF_HOSTED_SYMMETRIC_AEAD_HEADER: &str =
    "x-ferrogate-transport-security: symmetric_aead";
