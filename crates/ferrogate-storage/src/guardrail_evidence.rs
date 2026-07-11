// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Durable, sanitized Guardrail evaluation evidence repositories.

use std::collections::BTreeMap;

use ferrogate_core::TenantContext;
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGuardrailEvaluation {
    pub id: String,
    pub request_id: String,
    pub trace_id: Option<String>,
    pub agent_run_id: Option<String>,
    pub subject_id: Option<String>,
    pub tenant: TenantContext,
    pub scope_type: String,
    pub scope_id: String,
    pub target: String,
    pub protocol: String,
    pub stage: String,
    pub mode: String,
    pub policy_id: String,
    pub policy_revision: u32,
    pub verdict: String,
    pub action: String,
    pub enforcement_status: String,
    pub latency_ms: u64,
    pub finding_category_counts: BTreeMap<String, u64>,
    pub finding_count: u64,
    pub transformed: bool,
    pub input_fingerprint: String,
    pub occurred_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGuardrailCheckEvaluation {
    pub id: String,
    pub evaluation_id: String,
    pub check_id: String,
    pub detector_id: String,
    pub detector_version: String,
    pub config_digest: String,
    pub verdict: String,
    pub action: String,
    pub enforcement_status: String,
    pub latency_ms: u64,
    pub finding_category_counts: BTreeMap<String, u64>,
    pub finding_count: u64,
    pub transformed: bool,
    pub used_fallback: bool,
    pub error_kind: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuardrailEvaluationQuery {
    pub tenant_id: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub agent_run_id: Option<String>,
    pub scope_type: Option<String>,
    pub scope_id: Option<String>,
    pub subject_id: Option<String>,
    pub policy_id: Option<String>,
    pub policy_revision: Option<u32>,
    pub detector_id: Option<String>,
    pub category: Option<String>,
    pub verdict: Option<String>,
    pub action: Option<String>,
    pub error_kind: Option<String>,
    pub since_unix: Option<u64>,
    pub until_unix: Option<u64>,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardrailEvaluationQueryPage {
    pub evaluations: Vec<StoredGuardrailEvaluation>,
    pub checks: Vec<StoredGuardrailCheckEvaluation>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub(super) struct StoredGuardrailEvidence {
    pub evaluation: StoredGuardrailEvaluation,
    pub checks: Vec<StoredGuardrailCheckEvaluation>,
}

pub trait GuardrailEvaluationRepository {
    fn append_guardrail_evaluation(
        &self,
        evaluation: StoredGuardrailEvaluation,
        checks: Vec<StoredGuardrailCheckEvaluation>,
    ) -> Result<(), StorageError>;

    fn query_guardrail_evaluations(
        &self,
        query: &GuardrailEvaluationQuery,
    ) -> Result<GuardrailEvaluationQueryPage, StorageError>;

    fn list_guardrail_evaluations(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailEvaluation>, StorageError>;

    fn list_guardrail_check_evaluations(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailCheckEvaluation>, StorageError>;
}

impl PostgresControlPlaneStore {
    fn append_guardrail_evidence(
        &self,
        evaluation: &StoredGuardrailEvaluation,
        checks: &[StoredGuardrailCheckEvaluation],
        retention_records: usize,
    ) -> Result<(), StorageError> {
        let evaluation_json = serialize_storage_document(evaluation)?;
        let policy_revision = i64::from(evaluation.policy_revision);
        let occurred_at_unix = saturating_i64(evaluation.occurred_at_unix);
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(postgres_error)?;
            set_guardrail_rls_context(
                &mut transaction,
                evaluation.tenant.organization_id.as_deref(),
            )?;
            transaction
                .execute(
                    "INSERT INTO guardrail_evaluations \
                     (id, request_id, trace_id, agent_run_id, subject_id, tenant_id, \
                      scope_type, scope_id, target, stage, mode, policy_id, policy_revision, \
                      verdict, action, enforcement_status, occurred_at_unix, evaluation_json) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                             $14, $15, $16, $17, $18::text::jsonb)",
                    &[
                        &evaluation.id,
                        &evaluation.request_id,
                        &evaluation.trace_id,
                        &evaluation.agent_run_id,
                        &evaluation.subject_id,
                        &evaluation.tenant.organization_id,
                        &evaluation.scope_type,
                        &evaluation.scope_id,
                        &evaluation.target,
                        &evaluation.stage,
                        &evaluation.mode,
                        &evaluation.policy_id,
                        &policy_revision,
                        &evaluation.verdict,
                        &evaluation.action,
                        &evaluation.enforcement_status,
                        &occurred_at_unix,
                        &evaluation_json,
                    ],
                )
                .map_err(postgres_error)?;
            for check in checks {
                let check_json = serialize_storage_document(check)?;
                transaction
                    .execute(
                        "INSERT INTO guardrail_check_evaluations \
                         (id, evaluation_id, check_id, detector_id, detector_version, \
                          verdict, action, enforcement_status, error_kind, check_json) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text::jsonb)",
                        &[
                            &check.id,
                            &check.evaluation_id,
                            &check.check_id,
                            &check.detector_id,
                            &check.detector_version,
                            &check.verdict,
                            &check.action,
                            &check.enforcement_status,
                            &check.error_kind,
                            &check_json,
                        ],
                    )
                    .map_err(postgres_error)?;
            }
            let retention_records = saturating_i64(retention_records as u64);
            transaction
                .execute(
                    "DELETE FROM guardrail_evaluations WHERE id IN (\
                       SELECT id FROM guardrail_evaluations \
                       ORDER BY occurred_at_unix DESC, id DESC OFFSET $1\
                     )",
                    &[&retention_records],
                )
                .map_err(postgres_error)?;
            transaction.commit().map_err(postgres_error)?;
            Ok(())
        })
    }

    fn guardrail_evaluations(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailEvaluation>, StorageError> {
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(postgres_error)?;
            set_guardrail_rls_context(&mut transaction, tenant_id)?;
            let evaluations = transaction
                .query(
                    "SELECT evaluation_json::text FROM guardrail_evaluations \
                     WHERE ($1::TEXT IS NULL OR tenant_id = $1) \
                     ORDER BY occurred_at_unix DESC, id DESC",
                    &[&tenant_id],
                )
                .map_err(postgres_error)?
                .into_iter()
                .map(|row| {
                    let value = row.get::<_, String>(0);
                    deserialize_storage_document(&value)
                })
                .collect::<Result<Vec<_>, _>>()?;
            transaction.commit().map_err(postgres_error)?;
            Ok(evaluations)
        })
    }

    fn query_guardrail_evidence(
        &self,
        query: &GuardrailEvaluationQuery,
    ) -> Result<GuardrailEvaluationQueryPage, StorageError> {
        const FILTER: &str = "($1::TEXT IS NULL OR evaluation.tenant_id = $1) \
            AND ($2::TEXT IS NULL OR evaluation.request_id = $2) \
            AND ($3::TEXT IS NULL OR evaluation.trace_id = $3) \
            AND ($4::TEXT IS NULL OR evaluation.agent_run_id = $4) \
            AND ($5::TEXT IS NULL OR evaluation.scope_type = $5) \
            AND ($6::TEXT IS NULL OR evaluation.scope_id = $6) \
            AND ($7::TEXT IS NULL OR evaluation.subject_id = $7) \
            AND ($8::TEXT IS NULL OR evaluation.policy_id = $8) \
            AND ($9::BIGINT IS NULL OR evaluation.policy_revision = $9) \
            AND ($13::TEXT IS NULL OR evaluation.verdict = $13) \
            AND ($14::TEXT IS NULL OR evaluation.action = $14) \
            AND ($15::BIGINT IS NULL OR evaluation.occurred_at_unix >= $15) \
            AND ($16::BIGINT IS NULL OR evaluation.occurred_at_unix <= $16) \
            AND (($10::TEXT IS NULL AND $11::TEXT IS NULL AND $12::TEXT IS NULL) OR EXISTS (\
                SELECT 1 FROM guardrail_check_evaluations AS matched_check \
                WHERE matched_check.evaluation_id = evaluation.id \
                  AND ($10::TEXT IS NULL OR matched_check.detector_id = $10) \
                  AND ($11::TEXT IS NULL OR jsonb_exists(\
                      matched_check.check_json -> 'finding_category_counts', $11\
                  )) \
                  AND ($12::TEXT IS NULL OR matched_check.error_kind = $12)\
            ))";

        let policy_revision = query.policy_revision.map(i64::from);
        let since_unix = query.since_unix.map(saturating_i64);
        let until_unix = query.until_unix.map(saturating_i64);
        let offset = saturating_i64(query.offset as u64);
        let limit = saturating_i64(query.limit as u64);
        let parameters: [&(dyn postgres::types::ToSql + Sync); 16] = [
            &query.tenant_id,
            &query.request_id,
            &query.trace_id,
            &query.agent_run_id,
            &query.scope_type,
            &query.scope_id,
            &query.subject_id,
            &query.policy_id,
            &policy_revision,
            &query.detector_id,
            &query.category,
            &query.error_kind,
            &query.verdict,
            &query.action,
            &since_unix,
            &until_unix,
        ];
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(postgres_error)?;
            set_guardrail_rls_context(&mut transaction, query.tenant_id.as_deref())?;

            let count_sql =
                format!("SELECT count(*) FROM guardrail_evaluations AS evaluation WHERE {FILTER}");
            let total = transaction
                .query_one(&count_sql, &parameters)
                .map_err(postgres_error)?
                .get::<_, i64>(0);
            let page_sql = format!(
                "SELECT evaluation.evaluation_json::text \
                 FROM guardrail_evaluations AS evaluation \
                 WHERE {FILTER} \
                 ORDER BY evaluation.occurred_at_unix DESC, evaluation.id DESC \
                 OFFSET $17 LIMIT $18"
            );
            let mut page_parameters = parameters.to_vec();
            page_parameters.push(&offset);
            page_parameters.push(&limit);
            let evaluations = transaction
                .query(&page_sql, &page_parameters)
                .map_err(postgres_error)?
                .into_iter()
                .map(|row| deserialize_storage_document(row.get::<_, String>(0).as_str()))
                .collect::<Result<Vec<StoredGuardrailEvaluation>, StorageError>>()?;
            let evaluation_ids = evaluations
                .iter()
                .map(|evaluation| evaluation.id.clone())
                .collect::<Vec<_>>();
            let checks = if evaluation_ids.is_empty() {
                Vec::new()
            } else {
                transaction
                    .query(
                        "SELECT check_row.check_json::text \
                         FROM guardrail_check_evaluations AS check_row \
                         WHERE check_row.evaluation_id = ANY($1) \
                         ORDER BY check_row.evaluation_id ASC, check_row.check_id ASC",
                        &[&evaluation_ids],
                    )
                    .map_err(postgres_error)?
                    .into_iter()
                    .map(|row| deserialize_storage_document(row.get::<_, String>(0).as_str()))
                    .collect::<Result<Vec<StoredGuardrailCheckEvaluation>, StorageError>>()?
            };
            transaction.commit().map_err(postgres_error)?;
            Ok(GuardrailEvaluationQueryPage {
                evaluations,
                checks,
                total: usize::try_from(total).unwrap_or(usize::MAX),
                offset: query.offset,
                limit: query.limit,
            })
        })
    }

    fn guardrail_check_evaluations(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailCheckEvaluation>, StorageError> {
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(postgres_error)?;
            set_guardrail_rls_context(&mut transaction, tenant_id)?;
            let checks = transaction
                .query(
                    "SELECT check_row.check_json::text FROM guardrail_check_evaluations AS check_row \
                     JOIN guardrail_evaluations AS evaluation ON evaluation.id = check_row.evaluation_id \
                     WHERE ($1::TEXT IS NULL OR evaluation.tenant_id = $1) \
                     ORDER BY check_row.evaluation_id DESC, check_row.check_id ASC",
                    &[&tenant_id],
                )
                .map_err(postgres_error)?
                .into_iter()
                .map(|row| {
                    let value = row.get::<_, String>(0);
                    deserialize_storage_document(&value)
                })
                .collect::<Result<Vec<_>, _>>()?;
            transaction.commit().map_err(postgres_error)?;
            Ok(checks)
        })
    }
}

fn set_guardrail_rls_context(
    transaction: &mut postgres::Transaction<'_>,
    tenant_id: Option<&str>,
) -> Result<(), StorageError> {
    let platform_mode = if tenant_id.is_some() { "off" } else { "on" };
    transaction
        .query_one(
            "SELECT set_config('ferrogate.tenant_id', COALESCE($1, ''), TRUE), \
                    set_config('ferrogate.platform_mode', $2, TRUE)",
            &[&tenant_id, &platform_mode],
        )
        .map_err(postgres_error)?;
    Ok(())
}

impl GuardrailEvaluationRepository for RuntimeStorageRepositories {
    fn append_guardrail_evaluation(
        &self,
        evaluation: StoredGuardrailEvaluation,
        checks: Vec<StoredGuardrailCheckEvaluation>,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                let retention_records = self
                    .guardrail_evaluation_retention_records
                    .lock()
                    .map(|limit| *limit)
                    .unwrap_or(10_000);
                control_plane.append_guardrail_evidence(&evaluation, &checks, retention_records)?;
            }
            RuntimeControlPlaneBackend::Memory(_) => {
                self.guardrail_evidence
                    .lock()
                    .map_err(|_| {
                        StorageError::Runtime("guardrail evidence repository lock poisoned".into())
                    })?
                    .append(StoredGuardrailEvidence { evaluation, checks });
            }
        }
        Ok(())
    }

    fn query_guardrail_evaluations(
        &self,
        query: &GuardrailEvaluationQuery,
    ) -> Result<GuardrailEvaluationQueryPage, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.query_guardrail_evidence(query)
            }
            RuntimeControlPlaneBackend::Memory(_) => {
                let mut records = self
                    .guardrail_evidence
                    .lock()
                    .map_err(|_| {
                        StorageError::Runtime("guardrail evidence repository lock poisoned".into())
                    })?
                    .list()
                    .into_iter()
                    .filter(|record| guardrail_record_matches_query(record, query))
                    .collect::<Vec<_>>();
                records.sort_by(|left, right| {
                    right
                        .evaluation
                        .occurred_at_unix
                        .cmp(&left.evaluation.occurred_at_unix)
                        .then_with(|| right.evaluation.id.cmp(&left.evaluation.id))
                });
                let total = records.len();
                let records = records
                    .into_iter()
                    .skip(query.offset)
                    .take(query.limit)
                    .collect::<Vec<_>>();
                let evaluations = records
                    .iter()
                    .map(|record| record.evaluation.clone())
                    .collect();
                let checks = records
                    .into_iter()
                    .flat_map(|record| record.checks)
                    .collect();
                Ok(GuardrailEvaluationQueryPage {
                    evaluations,
                    checks,
                    total,
                    offset: query.offset,
                    limit: query.limit,
                })
            }
        }
    }

    fn list_guardrail_evaluations(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailEvaluation>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.guardrail_evaluations(tenant_id)
            }
            RuntimeControlPlaneBackend::Memory(_) => Ok(self
                .guardrail_evidence
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("guardrail evidence repository lock poisoned".into())
                })?
                .list()
                .into_iter()
                .map(|record| record.evaluation)
                .filter(|evaluation| {
                    tenant_id.is_none_or(|tenant_id| {
                        evaluation.tenant.organization_id.as_deref() == Some(tenant_id)
                    })
                })
                .collect()),
        }
    }

    fn list_guardrail_check_evaluations(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailCheckEvaluation>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.guardrail_check_evaluations(tenant_id)
            }
            RuntimeControlPlaneBackend::Memory(_) => Ok(self
                .guardrail_evidence
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("guardrail evidence repository lock poisoned".into())
                })?
                .list()
                .into_iter()
                .filter(|record| {
                    tenant_id.is_none_or(|tenant_id| {
                        record.evaluation.tenant.organization_id.as_deref() == Some(tenant_id)
                    })
                })
                .flat_map(|record| record.checks)
                .collect()),
        }
    }
}

fn guardrail_record_matches_query(
    record: &StoredGuardrailEvidence,
    query: &GuardrailEvaluationQuery,
) -> bool {
    let evaluation = &record.evaluation;
    if query
        .tenant_id
        .as_ref()
        .is_some_and(|expected| evaluation.tenant.organization_id.as_ref() != Some(expected))
        || query
            .request_id
            .as_ref()
            .is_some_and(|expected| &evaluation.request_id != expected)
        || query
            .trace_id
            .as_ref()
            .is_some_and(|expected| evaluation.trace_id.as_ref() != Some(expected))
        || query
            .agent_run_id
            .as_ref()
            .is_some_and(|expected| evaluation.agent_run_id.as_ref() != Some(expected))
        || query
            .scope_type
            .as_ref()
            .is_some_and(|expected| &evaluation.scope_type != expected)
        || query
            .scope_id
            .as_ref()
            .is_some_and(|expected| &evaluation.scope_id != expected)
        || query
            .subject_id
            .as_ref()
            .is_some_and(|expected| evaluation.subject_id.as_ref() != Some(expected))
        || query
            .policy_id
            .as_ref()
            .is_some_and(|expected| &evaluation.policy_id != expected)
        || query
            .policy_revision
            .is_some_and(|expected| evaluation.policy_revision != expected)
        || query
            .verdict
            .as_ref()
            .is_some_and(|expected| &evaluation.verdict != expected)
        || query
            .action
            .as_ref()
            .is_some_and(|expected| &evaluation.action != expected)
        || query
            .since_unix
            .is_some_and(|since| evaluation.occurred_at_unix < since)
        || query
            .until_unix
            .is_some_and(|until| evaluation.occurred_at_unix > until)
    {
        return false;
    }
    if query.detector_id.is_none() && query.category.is_none() && query.error_kind.is_none() {
        return true;
    }
    record.checks.iter().any(|check| {
        query
            .detector_id
            .as_ref()
            .is_none_or(|expected| &check.detector_id == expected)
            && query
                .category
                .as_ref()
                .is_none_or(|expected| check.finding_category_counts.contains_key(expected))
            && query
                .error_kind
                .as_ref()
                .is_none_or(|expected| check.error_kind.as_ref() == Some(expected))
    })
}

impl RuntimeStorageRepositories {
    pub fn set_guardrail_evaluation_retention_records(&self, retention_records: usize) {
        if let Ok(mut limit) = self.guardrail_evaluation_retention_records.lock() {
            *limit = retention_records;
        }
        if let Ok(mut evidence) = self.guardrail_evidence.lock() {
            evidence.set_retention_limit(retention_records);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluation(id: &str, request_id: &str) -> StoredGuardrailEvaluation {
        StoredGuardrailEvaluation {
            id: id.to_string(),
            request_id: request_id.to_string(),
            trace_id: Some("trace-1".to_string()),
            agent_run_id: None,
            subject_id: Some("key-1".to_string()),
            tenant: TenantContext {
                organization_id: Some("tenant-1".to_string()),
                api_key_id: Some("key-1".to_string()),
                ..TenantContext::default()
            },
            scope_type: "api_key".to_string(),
            scope_id: "key-1".to_string(),
            target: "model=fast-chat;provider=test".to_string(),
            protocol: "chat_completions".to_string(),
            stage: "request".to_string(),
            mode: "enforce".to_string(),
            policy_id: "policy-1".to_string(),
            policy_revision: 1,
            verdict: "fail".to_string(),
            action: "block".to_string(),
            enforcement_status: "enforced".to_string(),
            latency_ms: 3,
            finding_category_counts: BTreeMap::from([("secret".to_string(), 1)]),
            finding_count: 1,
            transformed: false,
            input_fingerprint: "hmac-sha256:abcdef".to_string(),
            occurred_at_unix: 100,
        }
    }

    fn check(evaluation_id: &str) -> StoredGuardrailCheckEvaluation {
        StoredGuardrailCheckEvaluation {
            id: format!("{evaluation_id}/check-1"),
            evaluation_id: evaluation_id.to_string(),
            check_id: "check-1".to_string(),
            detector_id: "ferrogate.local".to_string(),
            detector_version: "ferrogate-local-v1".to_string(),
            config_digest: "sha256:1234".to_string(),
            verdict: "fail".to_string(),
            action: "block".to_string(),
            enforcement_status: "enforced".to_string(),
            latency_ms: 2,
            finding_category_counts: BTreeMap::from([("secret".to_string(), 1)]),
            finding_count: 1,
            transformed: false,
            used_fallback: false,
            error_kind: None,
        }
    }

    #[test]
    fn in_memory_guardrail_evidence_retains_complete_overall_and_check_records() {
        let repositories =
            RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 10, 10);
        repositories.set_guardrail_evaluation_retention_records(1);
        repositories
            .append_guardrail_evaluation(evaluation("eval-1", "request-1"), vec![check("eval-1")])
            .unwrap();
        repositories
            .append_guardrail_evaluation(evaluation("eval-2", "request-2"), vec![check("eval-2")])
            .unwrap();

        let evaluations = repositories.list_guardrail_evaluations(None).unwrap();
        let checks = repositories.list_guardrail_check_evaluations(None).unwrap();
        assert_eq!(evaluations.len(), 1);
        assert_eq!(evaluations[0].id, "eval-2");
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].evaluation_id, "eval-2");
    }

    #[test]
    fn guardrail_evidence_document_has_no_raw_content_or_credentials_fields() {
        let encoded =
            serde_json::to_string(&(evaluation("eval-1", "request-1"), vec![check("eval-1")]))
                .unwrap();
        for forbidden in [
            "prompt",
            "matched_text",
            "authorization",
            "credential",
            "detector_secret",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn guardrail_evidence_repository_filters_tenant_before_returning_rows() {
        let repositories =
            RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 10, 10);
        repositories
            .append_guardrail_evaluation(evaluation("eval-1", "request-1"), vec![check("eval-1")])
            .unwrap();
        let mut other = evaluation("eval-2", "request-2");
        other.tenant.organization_id = Some("tenant-2".into());
        repositories
            .append_guardrail_evaluation(other, vec![check("eval-2")])
            .unwrap();

        let evaluations = repositories
            .list_guardrail_evaluations(Some("tenant-1"))
            .unwrap();
        let checks = repositories
            .list_guardrail_check_evaluations(Some("tenant-1"))
            .unwrap();
        assert_eq!(evaluations.len(), 1);
        assert_eq!(evaluations[0].id, "eval-1");
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].evaluation_id, "eval-1");
    }

    #[test]
    fn guardrail_evidence_query_filters_counts_and_fetches_only_page_checks() {
        let repositories =
            RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 10, 10);
        let mut first = evaluation("eval-1", "request-1");
        first.agent_run_id = Some("run-1".into());
        let mut first_check = check("eval-1");
        first_check.error_kind = Some("timeout".into());
        repositories
            .append_guardrail_evaluation(first, vec![first_check])
            .unwrap();
        let mut second = evaluation("eval-2", "request-2");
        second.occurred_at_unix = 200;
        repositories
            .append_guardrail_evaluation(second, vec![check("eval-2")])
            .unwrap();

        let filtered = repositories
            .query_guardrail_evaluations(&GuardrailEvaluationQuery {
                tenant_id: Some("tenant-1".into()),
                request_id: Some("request-1".into()),
                trace_id: Some("trace-1".into()),
                agent_run_id: Some("run-1".into()),
                scope_type: Some("api_key".into()),
                scope_id: Some("key-1".into()),
                subject_id: Some("key-1".into()),
                policy_id: Some("policy-1".into()),
                policy_revision: Some(1),
                detector_id: Some("ferrogate.local".into()),
                category: Some("secret".into()),
                verdict: Some("fail".into()),
                action: Some("block".into()),
                error_kind: Some("timeout".into()),
                since_unix: Some(100),
                until_unix: Some(100),
                offset: 0,
                limit: 10,
            })
            .unwrap();
        assert_eq!(filtered.total, 1);
        assert_eq!(filtered.evaluations[0].id, "eval-1");
        assert_eq!(filtered.checks.len(), 1);
        assert_eq!(filtered.checks[0].evaluation_id, "eval-1");

        let paged = repositories
            .query_guardrail_evaluations(&GuardrailEvaluationQuery {
                tenant_id: Some("tenant-1".into()),
                offset: 1,
                limit: 1,
                ..GuardrailEvaluationQuery::default()
            })
            .unwrap();
        assert_eq!(paged.total, 2);
        assert_eq!(paged.evaluations[0].id, "eval-1");
        assert_eq!(paged.checks.len(), 1);
        assert_eq!(paged.checks[0].evaluation_id, "eval-1");
    }
}
