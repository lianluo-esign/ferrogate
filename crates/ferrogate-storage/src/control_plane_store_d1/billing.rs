// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: billing ledger, report outbox, settled metering events (issue #449).

//! D1 backend: billing ledger, report outbox, settled metering events (issue #449).
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use super::rows::*;
use super::*;

impl D1ControlPlaneStore {
    // --- Billing ledger / outbox / events (issue #449, control DB) ---
    //
    // Billing is account-global cross-tenant metering: the reads are
    // whole-table (list all, count(*)-paginated) and the tenant inside each
    // record is a composite storage key, not a routing tenant id, so like the
    // #447 observability families these route to the CONTROL database. Each row
    // stores the FULL record as a `*_json` document; the ledger/event tables add
    // filter/order projection columns and the outbox keeps its attempt/schedule
    // state as columns so reschedule/dead-letter/replay are single-statement
    // UPDATEs (the transaction-free equivalent of the Postgres backend).

    pub(super) async fn append_billing_ledger_entry_async(
        &self,
        entry: &ferrogate_billing::LedgerEntry,
    ) -> Result<bool, StorageError> {
        let entry_json = serialize_storage_document(entry)?;
        let result = self
            .execute_control(
                "INSERT INTO billing_ledger \
                 (id, organization_id, project_id, api_key_id, created_at_unix, entry_json) \
                 VALUES (?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), unixepoch(), ?) \
                 ON CONFLICT (id) DO NOTHING",
                vec![
                    entry.id.clone(),
                    entry.tenant.organization_id.clone().unwrap_or_default(),
                    entry.tenant.project_id.clone().unwrap_or_default(),
                    entry.tenant.api_key_id.clone().unwrap_or_default(),
                    entry_json,
                ],
            )
            .await?;
        if result.changes() > 0 {
            return Ok(true);
        }
        // Idempotent replay (issue #248 parity): reload and require the same
        // provider-attempt settlement, else surface a typed conflict. The D1
        // HTTP API has no nested-connection self-deadlock, so the reload is a
        // plain follow-up SELECT rather than the Postgres drop-then-reacquire.
        let existing = self
            .billing_ledger_entry_async(&entry.id)
            .await?
            .ok_or_else(|| {
                StorageError::Runtime(format!(
                    "billing ledger id {} conflicted but could not be reloaded",
                    entry.id
                ))
            })?;
        if ferrogate_billing::same_provider_attempt_settlement(&existing, entry) {
            Ok(false)
        } else {
            Err(StorageError::Conflict(format!(
                "billing ledger id {} was replayed with different provider-attempt settlement data",
                entry.id
            )))
        }
    }

    pub(super) async fn billing_ledger_entry_async(
        &self,
        id: &str,
    ) -> Result<Option<ferrogate_billing::LedgerEntry>, StorageError> {
        let row: Option<DocumentRow> = self
            .fetch_control_optional(
                "SELECT entry_json AS document_json FROM billing_ledger WHERE id = ?",
                vec![id.to_string()],
            )
            .await?;
        row.map(|row| deserialize_storage_document(row.document_json.as_str()))
            .transpose()
    }

    pub(super) async fn list_billing_ledger_entries_async(
        &self,
        filter: &ferrogate_billing::LedgerListFilter,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ferrogate_billing::LedgerEntry>, StorageError> {
        // Each filter dimension is pushed into the WHERE clause with the
        // empty-string sentinel `(? = '' OR column = ?)` idiom -- the
        // all-strings-params equivalent of the Postgres `$n::text IS NULL OR
        // column = $n` -- so one fixed statement serves the unfiltered and
        // per-scope cases and a scoped page never comes back lossy.
        let organization_id = filter.organization_id.clone().unwrap_or_default();
        let project_id = filter.project_id.clone().unwrap_or_default();
        let api_key_id = filter.api_key_id.clone().unwrap_or_default();
        let sql = format!(
            "SELECT entry_json AS document_json FROM billing_ledger \
             WHERE (? = '' OR organization_id = ?) \
               AND (? = '' OR project_id = ?) \
               AND (? = '' OR api_key_id = ?) \
             ORDER BY created_at_unix ASC, id ASC LIMIT {} OFFSET {}",
            saturating_i64(limit as u64),
            saturating_i64(offset as u64)
        );
        self.fetch_control_documents(
            &sql,
            vec![
                organization_id.clone(),
                organization_id,
                project_id.clone(),
                project_id,
                api_key_id.clone(),
                api_key_id,
            ],
        )
        .await
    }

    pub(super) async fn enqueue_billing_report_async(
        &self,
        id: &str,
        event: &ferrogate_billing::BillingEvent,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        let event_json = serialize_storage_document(event)?;
        self.execute_control(
            "INSERT INTO billing_report_outbox \
             (id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix, \
              updated_at_unix, event_json) \
             VALUES (?, 0, ?, NULL, unixepoch(), unixepoch(), ?) \
             ON CONFLICT (id) DO NOTHING",
            vec![id.to_string(), next_attempt_unix.to_string(), event_json],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn list_due_billing_reports_async(
        &self,
        now_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        let sql = format!(
            "{SELECT_BILLING_OUTBOX_COLUMNS} \
             WHERE next_attempt_unix <= ? AND dead_lettered_at_unix IS NULL \
             ORDER BY next_attempt_unix ASC LIMIT {}",
            saturating_i64(limit as u64)
        );
        let rows: Vec<BillingOutboxRow> = self
            .fetch_control_rows(&sql, vec![now_unix.to_string()])
            .await?;
        rows.into_iter()
            .map(BillingOutboxRow::into_stored)
            .collect()
    }

    pub(super) async fn reschedule_billing_report_async(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        self.execute_control(
            "UPDATE billing_report_outbox \
             SET attempts = attempts + 1, next_attempt_unix = ?, updated_at_unix = unixepoch() \
             WHERE id = ?",
            vec![next_attempt_unix.to_string(), id.to_string()],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn dead_letter_billing_report_async(
        &self,
        id: &str,
        dead_lettered_at_unix: i64,
    ) -> Result<(), StorageError> {
        self.execute_control(
            "UPDATE billing_report_outbox \
             SET dead_lettered_at_unix = ?, updated_at_unix = ? WHERE id = ?",
            vec![
                dead_lettered_at_unix.to_string(),
                dead_lettered_at_unix.to_string(),
                id.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn list_dead_lettered_billing_reports_async(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        let sql = format!(
            "{SELECT_BILLING_OUTBOX_COLUMNS} WHERE dead_lettered_at_unix IS NOT NULL \
             ORDER BY dead_lettered_at_unix DESC LIMIT {}",
            saturating_i64(limit as u64)
        );
        let rows: Vec<BillingOutboxRow> = self.fetch_control_rows(&sql, Vec::new()).await?;
        rows.into_iter()
            .map(BillingOutboxRow::into_stored)
            .collect()
    }

    pub(super) async fn replay_dead_lettered_billing_report_async(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<ReplayDeadLetterOutcome, StorageError> {
        // Conditional CAS (issue #388): the guarded UPDATE fires only from the
        // dead-lettered state; a follow-up SELECT then reports the exact
        // terminal state (the HTTP query API has no `UPDATE ... RETURNING`, as
        // with `take_sso_pending_flow`).
        let now = saturating_i64(now_unix_seconds());
        let updated = self
            .execute_control(
                "UPDATE billing_report_outbox \
                 SET dead_lettered_at_unix = NULL, attempts = 0, next_attempt_unix = ?, \
                     updated_at_unix = ? \
                 WHERE id = ? AND dead_lettered_at_unix IS NOT NULL",
                vec![
                    next_attempt_unix.to_string(),
                    now.to_string(),
                    id.to_string(),
                ],
            )
            .await?;
        let entry = self.get_billing_report_outbox_entry_async(id).await?;
        if updated.changes() > 0 {
            let entry = entry.ok_or_else(|| {
                StorageError::Runtime(format!(
                    "billing report outbox id {id} replayed but could not be reloaded"
                ))
            })?;
            return Ok(ReplayDeadLetterOutcome::Replayed(entry));
        }
        Ok(match entry {
            Some(entry) => ReplayDeadLetterOutcome::NotDeadLettered(entry),
            None => ReplayDeadLetterOutcome::NotFound,
        })
    }

    pub(super) async fn get_billing_report_outbox_entry_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredBillingReportOutboxEntry>, StorageError> {
        let row: Option<BillingOutboxRow> = self
            .fetch_control_optional(
                &format!("{SELECT_BILLING_OUTBOX_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        row.map(BillingOutboxRow::into_stored).transpose()
    }

    pub(super) async fn delete_billing_report_async(&self, id: &str) -> Result<(), StorageError> {
        self.execute_control(
            "DELETE FROM billing_report_outbox WHERE id = ?",
            vec![id.to_string()],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn append_billing_event_async(
        &self,
        event: &BillingEvent,
    ) -> Result<bool, StorageError> {
        let billing_event_id = ferrogate_billing::ledger::ledger_entry_id(event);
        let event_json = serialize_storage_document(event)?;
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));
        let result = self
            .execute_control(
                "INSERT INTO billing_events \
                 (billing_event_id, request_id, provider_attempt_index, occurred_at_unix, \
                  event_json) \
                 VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT (billing_event_id) DO NOTHING",
                vec![
                    billing_event_id.clone(),
                    event.request_id.clone(),
                    i64::from(event.provider_attempt.provider_attempt_index).to_string(),
                    occurred_at_unix.to_string(),
                    event_json,
                ],
            )
            .await?;
        if result.changes() > 0 {
            return Ok(true);
        }
        let existing = self
            .billing_event_by_id_async(&billing_event_id)
            .await?
            .ok_or_else(|| {
                StorageError::Runtime(format!(
                    "billing event id {billing_event_id} conflicted but could not be reloaded"
                ))
            })?;
        if same_billing_event_settlement(&existing, event) {
            Ok(false)
        } else {
            Err(StorageError::Conflict(format!(
                "billing event id {billing_event_id} was replayed with different provider-attempt \
                 settlement data"
            )))
        }
    }

    /// Atomic metering write + report-outbox enqueue (issue #150) over the
    /// proxy-Worker `/d1/batch` binding (issue #450) — the KEYSTONE atomic op.
    ///
    /// The D1 REST query API cannot commit the two inserts together (no
    /// multi-statement-with-params transaction, no `RETURNING`), which is why
    /// this family stayed erroring on the REST-only backend. It is now routed
    /// through the proxy Worker as TWO statements committed as one atomic unit by
    /// `env.DB.batch([...])`:
    ///
    /// 1. the metering-event insert, `ON CONFLICT (billing_event_id) DO NOTHING
    ///    RETURNING billing_event_id` — the RETURNING row is present iff the
    ///    event was NEWLY recorded (REST has no `RETURNING`, so a REST-only
    ///    backend cannot learn this in the same round trip);
    /// 2. the report-outbox enqueue, `ON CONFLICT (id) DO NOTHING` (idempotent
    ///    on the caller's `outbox_id`).
    ///
    /// If either statement fails, D1 rolls the WHOLE batch back — the #150
    /// atomicity guarantee: a metering write never lands without its outbox
    /// enqueue, so there is no partial-success case (`enqueue_error` stays `None`
    /// like Postgres). On an idempotent replay (metering row already present, no
    /// RETURNING row) the stored event's settlement is re-verified over the REST
    /// reload path, mirroring [`append_billing_event_async`]; a divergent replay
    /// is a typed [`StorageError::Conflict`].
    ///
    /// Fails closed with the typed unimplemented-surface error when no proxy
    /// Worker is bound (a REST-only deployment), exactly like the still-deferred
    /// atomic families.
    ///
    /// [`append_billing_event_async`]: Self::append_billing_event_async
    pub(super) async fn append_billing_event_with_outbox_enqueue_async(
        &self,
        event: &BillingEvent,
        outbox_id: &str,
        outbox_next_attempt_unix: i64,
    ) -> Result<BillingEventAppendOutcome, StorageError> {
        let proxy = self.proxy_client("append_billing_event_with_outbox_enqueue")?;
        let billing_event_id = ferrogate_billing::ledger::ledger_entry_id(event);
        let event_json = serialize_storage_document(event)?;
        let occurred_at_unix =
            saturating_i64(event.occurred_at_unix.unwrap_or_else(now_unix_seconds));

        // The two statements mirror the standalone `append_billing_event_async`
        // (metering insert) and `enqueue_billing_report_async` (outbox insert)
        // SQL verbatim, so the atomic path stays row-for-row consistent with the
        // non-atomic REST writes; the only addition is the `RETURNING` clause the
        // binding makes available.
        let statements = vec![
            D1ProxyStatement::with_params(
                "INSERT INTO billing_events \
                 (billing_event_id, request_id, provider_attempt_index, occurred_at_unix, \
                  event_json) \
                 VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT (billing_event_id) DO NOTHING \
                 RETURNING billing_event_id",
                vec![
                    billing_event_id.clone(),
                    event.request_id.clone(),
                    i64::from(event.provider_attempt.provider_attempt_index).to_string(),
                    occurred_at_unix.to_string(),
                    event_json.clone(),
                ],
            ),
            D1ProxyStatement::with_params(
                "INSERT INTO billing_report_outbox \
                 (id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix, \
                  updated_at_unix, event_json) \
                 VALUES (?, 0, ?, NULL, unixepoch(), unixepoch(), ?) \
                 ON CONFLICT (id) DO NOTHING",
                vec![
                    outbox_id.to_string(),
                    outbox_next_attempt_unix.to_string(),
                    event_json,
                ],
            ),
        ];

        let results = proxy.batch(&statements).await.map_err(d1_error)?;
        // Statement 0 is the metering insert; its RETURNING row is present iff
        // the event was newly recorded (ON CONFLICT DO NOTHING → no row on
        // replay). A short batch response is a proxy contract violation.
        let metering_result = results.first().ok_or_else(|| {
            StorageError::Runtime(
                "cloudflare d1 proxy: batch returned no per-statement results".to_string(),
            )
        })?;
        let recorded = !metering_result.results.is_empty();
        if recorded {
            return Ok(BillingEventAppendOutcome {
                recorded: true,
                enqueue_error: None,
            });
        }
        // Idempotent replay: verify the stored event settles the same way (the
        // reload is a non-atomic single read, so it stays on the REST path).
        let existing = self
            .billing_event_by_id_async(&billing_event_id)
            .await?
            .ok_or_else(|| {
                StorageError::Runtime(format!(
                    "billing event id {billing_event_id} conflicted but could not be reloaded"
                ))
            })?;
        if same_billing_event_settlement(&existing, event) {
            Ok(BillingEventAppendOutcome {
                recorded: false,
                enqueue_error: None,
            })
        } else {
            Err(StorageError::Conflict(format!(
                "billing event id {billing_event_id} was replayed with different provider-attempt \
                 settlement data"
            )))
        }
    }

    pub(super) async fn billing_event_by_id_async(
        &self,
        billing_event_id: &str,
    ) -> Result<Option<BillingEvent>, StorageError> {
        let row: Option<DocumentRow> = self
            .fetch_control_optional(
                "SELECT event_json AS document_json FROM billing_events WHERE billing_event_id = ?",
                vec![billing_event_id.to_string()],
            )
            .await?;
        row.map(|row| deserialize_storage_document(row.document_json.as_str()))
            .transpose()
    }

    pub(super) async fn billing_events_async(&self) -> Result<Vec<BillingEvent>, StorageError> {
        self.fetch_control_documents(
            "SELECT event_json AS document_json FROM billing_events \
             ORDER BY occurred_at_unix ASC, request_id ASC, provider_attempt_index ASC",
            Vec::new(),
        )
        .await
    }

    pub(super) async fn billing_events_page_async(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<StoragePage<BillingEvent>, StorageError> {
        let sql = format!(
            "SELECT event_json AS document_json, count(*) OVER() AS total FROM billing_events \
             ORDER BY occurred_at_unix ASC, request_id ASC, provider_attempt_index ASC \
             LIMIT {} OFFSET {}",
            saturating_i64(limit as u64),
            saturating_i64(offset as u64)
        );
        self.fetch_control_document_page(&sql, offset, limit).await
    }
}
