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
}
