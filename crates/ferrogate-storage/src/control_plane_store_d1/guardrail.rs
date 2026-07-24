// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: guardrail policy revisions + bindings (issue #449).

//! D1 backend: guardrail policy revisions + bindings (issue #449).
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use super::rows::*;
use super::*;

impl D1ControlPlaneStore {
    // --- Guardrail policy revisions / bindings (issue #449, control DB) ---
    //
    // Immutable revisions plus the mutable per-policy binding: account-global
    // guardrail configuration (like plans/RBAC), so the CONTROL database owns
    // them. Each row stores the full record as a `*_json` document; revisions
    // add a composite (policy_id, revision) key + immutable-id idempotency. The
    // generation-guarded activate/archive/restore CAS transitions stay
    // unimplemented (they need the transaction the D1 HTTP API lacks).

    pub(super) async fn insert_guardrail_policy_revision_async(
        &self,
        revision: &StoredGuardrailPolicyRevision,
    ) -> Result<(), StorageError> {
        let revision_json = serialize_storage_document(revision)?;
        let result = self
            .execute_control(
                "INSERT INTO guardrail_policy_revisions \
                 (policy_id, revision, immutable_id, created_at_unix, created_by, revision_json) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (policy_id, revision) DO NOTHING",
                vec![
                    revision.policy_id.clone(),
                    i64::from(revision.revision).to_string(),
                    revision.id.clone(),
                    saturating_i64(revision.created_at_unix).to_string(),
                    revision.created_by.clone(),
                    revision_json,
                ],
            )
            .await?;
        if result.changes() == 0 {
            return Err(StorageError::Conflict(format!(
                "guardrail policy revision {} already exists",
                revision.id
            )));
        }
        Ok(())
    }

    pub(super) async fn get_guardrail_policy_revision_async(
        &self,
        policy_id: &str,
        revision: u32,
    ) -> Result<Option<StoredGuardrailPolicyRevision>, StorageError> {
        let row: Option<DocumentRow> = self
            .fetch_control_optional(
                "SELECT revision_json AS document_json FROM guardrail_policy_revisions \
                 WHERE policy_id = ? AND revision = ?",
                vec![policy_id.to_string(), i64::from(revision).to_string()],
            )
            .await?;
        row.map(|row| deserialize_storage_document(row.document_json.as_str()))
            .transpose()
    }

    pub(super) async fn list_guardrail_policy_revisions_async(
        &self,
        policy_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailPolicyRevision>, StorageError> {
        match policy_id {
            Some(policy_id) => {
                self.fetch_control_documents(
                    "SELECT revision_json AS document_json FROM guardrail_policy_revisions \
                     WHERE policy_id = ? ORDER BY policy_id ASC, revision ASC",
                    vec![policy_id.to_string()],
                )
                .await
            }
            None => {
                self.fetch_control_documents(
                    "SELECT revision_json AS document_json FROM guardrail_policy_revisions \
                     ORDER BY policy_id ASC, revision ASC",
                    Vec::new(),
                )
                .await
            }
        }
    }

    pub(super) async fn get_guardrail_policy_binding_async(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredGuardrailPolicyBinding>, StorageError> {
        let row: Option<DocumentRow> = self
            .fetch_control_optional(
                "SELECT binding_json AS document_json FROM guardrail_policy_bindings \
                 WHERE policy_id = ?",
                vec![policy_id.to_string()],
            )
            .await?;
        row.map(|row| deserialize_storage_document(row.document_json.as_str()))
            .transpose()
    }

    pub(super) async fn list_guardrail_policy_bindings_async(
        &self,
    ) -> Result<Vec<StoredGuardrailPolicyBinding>, StorageError> {
        self.fetch_control_documents(
            "SELECT binding_json AS document_json FROM guardrail_policy_bindings \
             ORDER BY policy_id ASC",
            Vec::new(),
        )
        .await
    }

    // --- Guardrail binding CAS transitions over the proxy `/d1/query` binding
    // (issue #454) ---
    //
    // activate/archive/restore are generation-guarded compare-and-swaps against
    // the single mutable `guardrail_policy_bindings` row. The D1 REST query API
    // cannot express the guarded `UPDATE ... RETURNING` that atomically detects a
    // lost update (no `RETURNING`, no way to learn whether the guard matched in
    // the same round trip), which is why these stayed erroring on the REST-only
    // backend. They now route through the proxy Worker (issue #450) exactly like
    // the billing keystone, here via the SINGLE-statement `/d1/query` companion
    // to `/d1/batch` — each transition is one guarded statement whose presence or
    // absence of a `RETURNING` row is the success/conflict signal.
    //
    // Guardrail configuration is account-global (control DB, like plans/RBAC), so
    // the proxy's fixed control-DB binding serves these directly — NO per-tenant
    // binding is required (contrast the still-deferred tenant-scoped
    // wallet/payment/workflow-budget families). Each transition reuses the shared
    // pure planners (`next_guardrail_activation_binding` / `_archive_binding`)
    // that the Postgres backend uses, so the computed next-binding is row-for-row
    // identical across backends; only the durable CAS write differs. Fails closed
    // with the typed unimplemented-surface error when no proxy is bound.

    pub(super) async fn activate_guardrail_policy_revision_async(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
        rollback_only: bool,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        // Fail closed BEFORE any read: a REST-only deployment cannot serve the
        // guarded CAS, so it must not even reach the network (mirrors the billing
        // keystone's early `proxy_client` guard).
        self.proxy_client("activate_guardrail_policy_revision")?;
        // The activated revision must exist. This is a non-atomic point read, so
        // it stays on the REST path (the generation guard, not this read, is what
        // makes the transition safe against a concurrent writer).
        if self
            .get_guardrail_policy_revision_async(policy_id, revision)
            .await?
            .is_none()
        {
            return Err(StorageError::NotFound(format!(
                "guardrail policy revision {}",
                crate::guardrail_policy_revision_id(policy_id, revision)
            )));
        }
        let previous = self.get_guardrail_policy_binding_async(policy_id).await?;
        let current = crate::next_guardrail_activation_binding(
            previous.as_ref(),
            policy_id,
            revision,
            updated_by,
            updated_at_unix,
            rollback_only,
        )?;
        self.compare_and_swap_guardrail_policy_binding_proxy(
            "activate_guardrail_policy_revision",
            previous.as_ref().map(|binding| binding.generation),
            &current,
        )
        .await?;
        Ok(GuardrailPolicyBindingTransition { previous, current })
    }

    pub(super) async fn archive_guardrail_policy_revision_async(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        self.proxy_client("archive_guardrail_policy_revision")?;
        if self
            .get_guardrail_policy_revision_async(policy_id, revision)
            .await?
            .is_none()
        {
            return Err(StorageError::NotFound(format!(
                "guardrail policy revision {}",
                crate::guardrail_policy_revision_id(policy_id, revision)
            )));
        }
        let previous = self.get_guardrail_policy_binding_async(policy_id).await?;
        let current = crate::next_guardrail_archive_binding(
            previous.as_ref(),
            policy_id,
            revision,
            updated_by,
            updated_at_unix,
        )?;
        self.compare_and_swap_guardrail_policy_binding_proxy(
            "archive_guardrail_policy_revision",
            previous.as_ref().map(|binding| binding.generation),
            &current,
        )
        .await?;
        Ok(GuardrailPolicyBindingTransition { previous, current })
    }

    pub(super) async fn restore_guardrail_policy_binding_async(
        &self,
        policy_id: &str,
        expected_generation: Option<u64>,
        binding: Option<StoredGuardrailPolicyBinding>,
    ) -> Result<(), StorageError> {
        // The rollback restore path (issue #388): re-establish a captured
        // pre-transition binding under its expected generation, or delete the row
        // when there was none. Both are generation-guarded, mirroring
        // `PostgresControlPlaneStore::restore_guardrail_policy_binding`.
        match binding {
            Some(binding) => {
                let mut restored = binding;
                restored.generation = crate::next_guardrail_binding_generation(
                    expected_generation.unwrap_or_default(),
                )?;
                self.compare_and_swap_guardrail_policy_binding_proxy(
                    "restore_guardrail_policy_binding",
                    expected_generation,
                    &restored,
                )
                .await
            }
            None => {
                let expected_generation = expected_generation.ok_or_else(|| {
                    StorageError::Conflict(
                        crate::GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE.to_string(),
                    )
                })?;
                self.delete_guardrail_policy_binding_cas_proxy(
                    "restore_guardrail_policy_binding",
                    policy_id,
                    expected_generation,
                )
                .await
            }
        }
    }

    /// The generation-guarded upsert half of the CAS: a guarded `UPDATE ...
    /// WHERE generation = ?` when a prior binding is being replaced, else an
    /// `INSERT ... ON CONFLICT (policy_id) DO NOTHING` for the first write. Both
    /// carry `RETURNING policy_id`; an EMPTY `RETURNING` set means the guard did
    /// not match (a concurrent writer moved the generation, or raced the first
    /// insert) — the lost-update signal the REST query API cannot surface — which
    /// maps to the typed CAS [`StorageError::Conflict`]. The full binding is
    /// persisted as the `binding_json` document (the read path deserializes it),
    /// with `active_revision`/`updated_at_unix`/`generation` mirrored into the
    /// projection columns the guard and reads use.
    async fn compare_and_swap_guardrail_policy_binding_proxy(
        &self,
        method: &'static str,
        expected_generation: Option<u64>,
        current: &StoredGuardrailPolicyBinding,
    ) -> Result<(), StorageError> {
        let proxy = self.proxy_client(method)?;
        let binding_json = serialize_storage_document(current)?;
        let active_revision = optional_number_param(current.active_revision);
        let updated_at_unix = saturating_i64(current.updated_at_unix).to_string();
        let generation = saturating_i64(current.generation).to_string();
        let statement = match expected_generation {
            Some(expected_generation) => D1ProxyStatement::with_params(
                "UPDATE guardrail_policy_bindings SET \
                 active_revision = NULLIF(?, ''), updated_at_unix = ?, generation = ?, \
                 binding_json = ? \
                 WHERE policy_id = ? AND generation = ? \
                 RETURNING policy_id",
                vec![
                    active_revision,
                    updated_at_unix,
                    generation,
                    binding_json,
                    current.policy_id.clone(),
                    saturating_i64(expected_generation).to_string(),
                ],
            ),
            None => D1ProxyStatement::with_params(
                "INSERT INTO guardrail_policy_bindings \
                 (policy_id, active_revision, updated_at_unix, generation, binding_json) \
                 VALUES (?, NULLIF(?, ''), ?, ?, ?) \
                 ON CONFLICT (policy_id) DO NOTHING \
                 RETURNING policy_id",
                vec![
                    current.policy_id.clone(),
                    active_revision,
                    updated_at_unix,
                    generation,
                    binding_json,
                ],
            ),
        };
        let result = proxy.query(&statement).await.map_err(d1_error)?;
        if result.results.is_empty() {
            return Err(StorageError::Conflict(
                crate::GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE.to_string(),
            ));
        }
        Ok(())
    }

    /// The generation-guarded delete half of the CAS (`restore` back to "no
    /// binding"): `DELETE ... WHERE generation = ? RETURNING policy_id`. An empty
    /// `RETURNING` set means the guard missed → typed CAS conflict.
    async fn delete_guardrail_policy_binding_cas_proxy(
        &self,
        method: &'static str,
        policy_id: &str,
        expected_generation: u64,
    ) -> Result<(), StorageError> {
        let proxy = self.proxy_client(method)?;
        let statement = D1ProxyStatement::with_params(
            "DELETE FROM guardrail_policy_bindings \
             WHERE policy_id = ? AND generation = ? RETURNING policy_id",
            vec![
                policy_id.to_string(),
                saturating_i64(expected_generation).to_string(),
            ],
        );
        let result = proxy.query(&statement).await.map_err(d1_error)?;
        if result.results.is_empty() {
            return Err(StorageError::Conflict(
                crate::GUARDRAIL_POLICY_BINDING_CAS_CONFLICT_MESSAGE.to_string(),
            ));
        }
        Ok(())
    }
}
