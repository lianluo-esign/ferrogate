// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: config-driven construction (RuntimeStorageRepositories + options, issue #440).

//! D1 backend: config-driven construction (RuntimeStorageRepositories + options, issue #440).
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use std::collections::BTreeMap;

use ferrogate_cloudflare::d1::D1Client;

use super::*;

impl RuntimeControlPlaneBackend {
    /// Wrap a D1 store as the active control-plane backend (issue #420).
    pub(crate) fn cloudflare_d1(store: D1ControlPlaneStore) -> Self {
        RuntimeControlPlaneBackend::CloudflareD1(Arc::new(store))
    }
}

impl RuntimeStorageRepositories {
    /// Assemble repositories backed by the per-tenant Cloudflare D1 backend
    /// (issue #420). The non-control-plane repositories (guardrail evidence)
    /// stay in-memory exactly as on the other durable backends.
    pub fn cloudflare_d1(store: D1ControlPlaneStore, audit_event_retention_records: usize) -> Self {
        Self {
            backend: RuntimeStorageBackend::in_memory(vec![StorageProviderKind::Memory]),
            control_plane: RuntimeControlPlaneBackend::cloudflare_d1(store),
            guardrail_evidence: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                audit_event_retention_records,
            )),
            guardrail_evaluation_retention_records: Mutex::new(audit_event_retention_records),
        }
    }

    /// The config-driven construction route (issue #440): build the D1
    /// control-plane backend from an already-assembled [`D1Client`] plus the
    /// operator-supplied [`CloudflareD1StorageOptions`], seeding the
    /// tenant->database registry from config so the backend is usable without
    /// a separate runtime bootstrap call.
    ///
    /// This is the storage half of the `storage.provider = "cloudflare_d1"`
    /// route. The caller (the CLI) owns the transport, so it builds the
    /// `CloudflareClient`/`D1Client` from the `[cloudflare]` block and passes
    /// it here — keeping this crate free of any HTTP/transport dependency and
    /// unit-testable against a scripted transport. See the module docs and
    /// `docs/cloudflare-d1-backend.md` for the exact CLI hook.
    pub fn cloudflare_d1_from_client(
        client: D1Client,
        options: CloudflareD1StorageOptions,
    ) -> Result<Self, StorageError> {
        let store = D1ControlPlaneStore::new(client, options.registry());
        Ok(Self::cloudflare_d1(
            store,
            options.audit_event_retention_records,
        ))
    }
}

/// Operator-supplied configuration for the config-driven D1 construction
/// route (issue #440). Seeds the tenant->database registry from config so a
/// deployment resuming against already-provisioned databases boots without a
/// live provisioning round trip; a control database that has not been
/// provisioned yet is expressed as an empty [`control_database_id`], which the
/// backend rejects on first control-plane access until
/// [`D1ControlPlaneStore::provision_control_database`] seeds it.
///
/// [`control_database_id`]: CloudflareD1StorageOptions::control_database_id
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudflareD1StorageOptions {
    /// D1 uuid of the control database (tenants + config documents + the
    /// registry document). Empty means "not provisioned yet".
    pub control_database_id: String,
    /// Pre-seeded `tenant_id -> D1 database uuid` registry entries, for a
    /// deployment resuming against existing tenant databases.
    pub tenant_databases: BTreeMap<String, String>,
    /// Retention bound for the in-memory guardrail-evidence repository, matching
    /// the other backends' `audit_event_retention_records`.
    pub audit_event_retention_records: usize,
}

impl CloudflareD1StorageOptions {
    /// Assemble the [`D1TenantDatabaseRegistry`] this config describes.
    fn registry(&self) -> D1TenantDatabaseRegistry {
        D1TenantDatabaseRegistry {
            control_database_id: self.control_database_id.clone(),
            tenant_databases: self.tenant_databases.clone(),
        }
    }
}
