// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Bounded background evidence writer (issue #309) — persists
// per-request request-log / audit / agent-run evidence off the Pingora
// request path so async handlers never park a worker thread on synchronous
// Postgres I/O via block_in_place.

//! # Evidence writer (issue #309)
//!
//! Before this module, the sync `AppState` evidence wrappers
//! (`record_request_log`, `record_admin_audit_event`, `record_agent_run`,
//! `record_agent_run_event`) bridged their async Postgres writes with
//! `block_on_sync_bridge`, which uses `tokio::task::block_in_place` — parking
//! a Pingora worker thread on DB I/O on every request. This writer replaces
//! that bridge on the durable (Postgres) backend with a bounded MPSC queue
//! drained by ONE dedicated writer thread running its own current-thread
//! runtime, so:
//!
//! - **Enqueue never does DB I/O.** The hot path pays a `try_send` only.
//! - **Ordering holds.** All rows of one request are enqueued sequentially
//!   from the request's own task, and the single consumer preserves channel
//!   FIFO order — so the #304 chokepoint audit sequence (`tool.execute`
//!   success row, then the `tool.guardrail` redacted/withheld row) persists
//!   in emission order.
//! - **Backpressure is bounded, never silent.** When the queue is full the
//!   enqueue retries for up to [`EVIDENCE_ENQUEUE_FULL_TIMEOUT`]
//!   (block-with-timeout, on queue *capacity*, never on DB I/O) and then
//!   drops WITH accounting: a `warn!` plus the
//!   `ferrogate_evidence_writer_dropped_total` counter. Billing events are
//!   NEVER routed through this writer — they keep their inline awaited
//!   durable-outbox path (#137/#143/#150), so a stalled evidence writer
//!   cannot lose a charge.
//! - **Read-your-writes.** Evidence readers call [`EvidenceWriter::flush`]
//!   first, which waits until everything enqueued so far has been persisted
//!   (bounded by [`EVIDENCE_FLUSH_TIMEOUT`]).
//! - **Drain on shutdown.** Dropping the writer closes the channel and joins
//!   the thread, which finishes every queued job first.
//!
//! The in-memory (non-durable) backend keeps the inline write: it completes
//! without I/O, and unit tests rely on strict read-after-write.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ferrogate_storage::RuntimeStorageRepositories;
use tokio::sync::mpsc;
use tracing::warn;

/// Queue capacity in jobs. Generous enough to absorb request bursts while the
/// writer drains (a Postgres evidence insert is ~1ms), small enough to bound
/// memory when bodies are logged.
pub(crate) const EVIDENCE_WRITER_QUEUE_CAPACITY: usize = 4096;

/// How long a full queue blocks an enqueue before dropping the job with
/// accounting. This bounds the worst-case producer stall at seconds (versus
/// the old bridge, which blocked unboundedly on every single write), while
/// still preferring a short wait over losing compliance-valuable evidence.
pub(crate) const EVIDENCE_ENQUEUE_FULL_TIMEOUT: Duration = Duration::from_secs(2);

const EVIDENCE_ENQUEUE_FULL_RETRY_INTERVAL: Duration = Duration::from_millis(5);

/// Upper bound a flush (admin evidence read) waits for the queue to drain.
pub(crate) const EVIDENCE_FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// One deferred evidence write. Every variant is fire-and-forget from the
/// producer's perspective (persistence failures were already warn-and-continue
/// under the old bridged wrappers).
pub(crate) enum EvidenceWriteJob {
    RequestLog(ferrogate_storage::StoredRequestLog),
    AuditEvent(ferrogate_storage::StoredAuditEvent),
    AgentRun(ferrogate_storage::StoredAgentRun),
    AgentRunEvent(ferrogate_storage::StoredAgentRunEvent),
    /// #357: a coalesced observed-agent presence touch. Enqueued off the
    /// request hot path so the durable single-row upsert never parks a Pingora
    /// worker on DB I/O; folded into the presence row for (tenant, api_key).
    ObservedPresenceTouch(ferrogate_storage::ObservedAgentPresenceTouch),
    /// Test-only: parks the writer thread until the paired sender fires,
    /// simulating a stalled Postgres writer for backpressure tests. The
    /// writer signals `started` when it picks the gate up, then blocks on
    /// `release`.
    #[cfg(test)]
    Gate {
        started: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    },
}

impl EvidenceWriteJob {
    fn kind(&self) -> &'static str {
        match self {
            EvidenceWriteJob::RequestLog(_) => "request_log",
            EvidenceWriteJob::AuditEvent(_) => "audit_event",
            EvidenceWriteJob::AgentRun(_) => "agent_run",
            EvidenceWriteJob::AgentRunEvent(_) => "agent_run_event",
            EvidenceWriteJob::ObservedPresenceTouch(_) => "observed_presence_touch",
            #[cfg(test)]
            EvidenceWriteJob::Gate { .. } => "test_gate",
        }
    }
}

/// Counters surfaced on the Prometheus snapshot (issue #309): enqueued vs
/// written proves the queue drains; dropped is the alertable loss signal.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct EvidenceWriterMetrics {
    pub(crate) enqueued_total: u64,
    pub(crate) written_total: u64,
    pub(crate) dropped_total: u64,
}

struct WriterCore {
    sender: mpsc::Sender<EvidenceWriteJob>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[derive(Default)]
struct Progress {
    /// Jobs fully processed by the writer thread (persist attempted).
    processed: Mutex<u64>,
    condvar: Condvar,
}

pub(crate) struct EvidenceWriter {
    repositories: Arc<RuntimeStorageRepositories>,
    capacity: usize,
    enqueue_full_timeout: Duration,
    core: OnceLock<WriterCore>,
    /// Jobs successfully queued (excludes overflow drops).
    enqueued: AtomicU64,
    /// Jobs dropped because the queue stayed full past the timeout.
    dropped: AtomicU64,
    progress: Arc<Progress>,
}

impl std::fmt::Debug for EvidenceWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceWriter")
            .field("capacity", &self.capacity)
            .field("started", &self.core.get().is_some())
            .field("enqueued", &self.enqueued.load(Ordering::SeqCst))
            .field("dropped", &self.dropped.load(Ordering::SeqCst))
            .finish()
    }
}

impl EvidenceWriter {
    pub(crate) fn new(repositories: Arc<RuntimeStorageRepositories>) -> Self {
        Self::with_settings(
            repositories,
            EVIDENCE_WRITER_QUEUE_CAPACITY,
            EVIDENCE_ENQUEUE_FULL_TIMEOUT,
        )
    }

    pub(crate) fn with_settings(
        repositories: Arc<RuntimeStorageRepositories>,
        capacity: usize,
        enqueue_full_timeout: Duration,
    ) -> Self {
        Self {
            repositories,
            capacity: capacity.max(1),
            enqueue_full_timeout,
            core: OnceLock::new(),
            enqueued: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            progress: Arc::new(Progress::default()),
        }
    }

    /// Lazily spawns the dedicated writer thread on first use, so building an
    /// `AppState` (tests, config reloads) never costs a thread until the
    /// durable evidence path actually enqueues.
    fn core(&self) -> &WriterCore {
        self.core.get_or_init(|| {
            let (sender, mut receiver) = mpsc::channel::<EvidenceWriteJob>(self.capacity);
            let repositories = Arc::clone(&self.repositories);
            let progress = Arc::clone(&self.progress);
            let thread = std::thread::Builder::new()
                .name("ferrogate-evidence-writer".to_string())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("evidence writer runtime should build");
                    runtime.block_on(async move {
                        while let Some(job) = receiver.recv().await {
                            process_job(&repositories, job).await;
                            let mut processed = progress
                                .processed
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            *processed = processed.saturating_add(1);
                            progress.condvar.notify_all();
                        }
                    });
                })
                .expect("evidence writer thread should spawn");
            WriterCore {
                sender,
                thread: Some(thread),
            }
        })
    }

    /// Queue one evidence write. Non-blocking except when the queue is full,
    /// in which case it retries for up to `enqueue_full_timeout` and then
    /// drops the job with a warning and the dropped counter (never silently).
    /// Returns whether the job was accepted.
    pub(crate) fn enqueue(&self, job: EvidenceWriteJob) -> bool {
        let core = self.core();
        let mut job = job;
        let deadline = Instant::now() + self.enqueue_full_timeout;
        loop {
            match core.sender.try_send(job) {
                Ok(()) => {
                    self.enqueued.fetch_add(1, Ordering::SeqCst);
                    return true;
                }
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    if Instant::now() >= deadline {
                        self.dropped.fetch_add(1, Ordering::SeqCst);
                        warn!(
                            kind = returned.kind(),
                            capacity = self.capacity,
                            "evidence writer queue stayed full past the enqueue timeout; dropping evidence write (counted in ferrogate_evidence_writer_dropped_total)"
                        );
                        return false;
                    }
                    job = returned;
                    std::thread::sleep(EVIDENCE_ENQUEUE_FULL_RETRY_INTERVAL);
                }
                Err(mpsc::error::TrySendError::Closed(returned)) => {
                    self.dropped.fetch_add(1, Ordering::SeqCst);
                    warn!(
                        kind = returned.kind(),
                        "evidence writer channel is closed (shutdown); dropping evidence write"
                    );
                    return false;
                }
            }
        }
    }

    /// Wait (bounded by [`EVIDENCE_FLUSH_TIMEOUT`]) until every job enqueued
    /// so far has been persisted, giving evidence readers read-your-writes
    /// semantics. A no-op when the writer was never used.
    pub(crate) fn flush(&self) -> bool {
        self.flush_with_timeout(EVIDENCE_FLUSH_TIMEOUT)
    }

    pub(crate) fn flush_with_timeout(&self, timeout: Duration) -> bool {
        if self.core.get().is_none() {
            return true;
        }
        let target = self.enqueued.load(Ordering::SeqCst);
        let deadline = Instant::now() + timeout;
        let mut processed = self
            .progress
            .processed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *processed < target {
            let now = Instant::now();
            if now >= deadline {
                warn!(
                    pending = target.saturating_sub(*processed),
                    "evidence writer flush timed out with writes still pending"
                );
                return false;
            }
            let (guard, _) = self
                .progress
                .condvar
                .wait_timeout(processed, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            processed = guard;
        }
        true
    }

    pub(crate) fn metrics(&self) -> EvidenceWriterMetrics {
        EvidenceWriterMetrics {
            enqueued_total: self.enqueued.load(Ordering::SeqCst),
            written_total: *self
                .progress
                .processed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            dropped_total: self.dropped.load(Ordering::SeqCst),
        }
    }
}

impl Drop for EvidenceWriter {
    /// Graceful drain: closing the channel makes the writer loop finish every
    /// queued job and exit; the join guarantees nothing enqueued before
    /// shutdown is abandoned mid-write.
    fn drop(&mut self) {
        if let Some(mut core) = self.core.take() {
            drop(core.sender);
            if let Some(thread) = core.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

async fn process_job(repositories: &RuntimeStorageRepositories, job: EvidenceWriteJob) {
    match job {
        EvidenceWriteJob::RequestLog(log) => {
            repositories.append_request_log(log).await;
        }
        EvidenceWriteJob::AuditEvent(event) => {
            repositories.append_audit_event(event).await;
        }
        EvidenceWriteJob::AgentRun(run) => {
            if let Err(error) = repositories.upsert_agent_run(run).await {
                warn!("failed to persist agent run record: {error}");
            }
        }
        EvidenceWriteJob::AgentRunEvent(event) => {
            if let Err(error) = repositories.append_agent_run_event(event).await {
                warn!("failed to persist agent run event record: {error}");
            }
        }
        EvidenceWriteJob::ObservedPresenceTouch(touch) => {
            if let Err(error) = repositories.touch_observed_agent_presence(touch).await {
                warn!("failed to record observed agent presence touch: {error}");
            }
        }
        #[cfg(test)]
        EvidenceWriteJob::Gate { started, release } => {
            let _ = started.send(());
            let _ = release.recv();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_storage::{StoredAuditEvent, StoredRequestLog};

    fn memory_repositories() -> Arc<RuntimeStorageRepositories> {
        Arc::new(RuntimeStorageRepositories::in_memory(Vec::new(), 100, 100))
    }

    fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    fn audit_event(id: &str, action: &str, outcome: &str) -> StoredAuditEvent {
        StoredAuditEvent {
            action_fingerprint: None,
            decision: None,
            decision_reason: None,
            output_disposition: None,
            parent_action_fingerprint: None,
            id: id.to_string(),
            request_id: "fg-order".to_string(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            actor_api_key_id: None,
            tenant: ferrogate_core::TenantContext::default(),
            action: action.to_string(),
            target: "tool".to_string(),
            outcome: outcome.to_string(),
            message: format!("{action} {outcome}"),
            occurred_at_unix: Some(1),
        }
    }

    fn request_log(request_id: &str) -> StoredRequestLog {
        StoredRequestLog {
            request_id: request_id.to_string(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: ferrogate_core::TenantContext::default(),
            route: None,
            provider: None,
            logical_model: None,
            provider_model: None,
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 200,
            error_code: None,
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: None,
            completed_at_unix: None,
            parent_action_fingerprint: None,
        }
    }

    /// #304 regression at the writer layer: the chokepoint's ordered audit
    /// sequence (tool.execute success, then the tool.guardrail redacted /
    /// withheld row) must persist in enqueue order through the single-writer
    /// queue.
    #[test]
    fn persists_chokepoint_audit_rows_in_enqueue_order() {
        let repositories = memory_repositories();
        let writer = EvidenceWriter::new(Arc::clone(&repositories));

        assert!(writer.enqueue(EvidenceWriteJob::AuditEvent(audit_event(
            "audit-1",
            "tool.execute",
            "success"
        ))));
        assert!(writer.enqueue(EvidenceWriteJob::AuditEvent(audit_event(
            "audit-2",
            "tool.guardrail",
            "redacted"
        ))));
        assert!(writer.enqueue(EvidenceWriteJob::AuditEvent(audit_event(
            "audit-3",
            "tool.guardrail",
            "rejected"
        ))));
        assert!(writer.enqueue(EvidenceWriteJob::RequestLog(request_log("fg-order"))));
        assert!(writer.flush());

        let events = block_on(repositories.audit_events());
        let sequence: Vec<(String, String)> = events
            .iter()
            .map(|event| (event.action.clone(), event.outcome.clone()))
            .collect();
        assert_eq!(
            sequence,
            vec![
                ("tool.execute".to_string(), "success".to_string()),
                ("tool.guardrail".to_string(), "redacted".to_string()),
                ("tool.guardrail".to_string(), "rejected".to_string()),
            ],
            "chokepoint audit rows must persist in enqueue order"
        );
        let logs = block_on(repositories.request_logs());
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].request_id, "fg-order");
    }

    /// Backpressure policy: with the writer stalled and the queue full, an
    /// enqueue blocks only for the bounded timeout and then drops WITH
    /// accounting (dropped counter) — and everything that was accepted still
    /// persists, in order, once the writer resumes.
    #[test]
    fn full_queue_drops_are_bounded_and_counted_and_accepted_jobs_still_land() {
        let repositories = memory_repositories();
        let writer =
            EvidenceWriter::with_settings(Arc::clone(&repositories), 1, Duration::from_millis(50));

        // Park the writer thread on the gate job.
        let (started_sender, started) = std::sync::mpsc::channel();
        let (release, release_receiver) = std::sync::mpsc::channel();
        assert!(writer.enqueue(EvidenceWriteJob::Gate {
            started: started_sender,
            release: release_receiver,
        }));
        // Wait until the writer picked the gate up, so exactly `capacity`
        // slots remain.
        started
            .recv_timeout(Duration::from_secs(5))
            .expect("writer never picked up the gate");

        // Fills the single queue slot.
        assert!(writer.enqueue(EvidenceWriteJob::AuditEvent(audit_event(
            "audit-accepted",
            "tool.execute",
            "success"
        ))));
        // Queue full + writer stalled: bounded wait, then counted drop.
        let started = Instant::now();
        assert!(!writer.enqueue(EvidenceWriteJob::AuditEvent(audit_event(
            "audit-dropped",
            "tool.execute",
            "success"
        ))));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "overflow wait must be bounded"
        );
        assert_eq!(writer.metrics().dropped_total, 1);

        release.send(()).expect("writer thread must be alive");
        assert!(writer.flush());
        let events = block_on(repositories.audit_events());
        assert_eq!(events.len(), 1, "the accepted job must persist");
        assert_eq!(events[0].id, "audit-accepted");
        let metrics = writer.metrics();
        assert_eq!(metrics.enqueued_total, 2, "gate + accepted audit row");
        assert_eq!(metrics.dropped_total, 1);
    }

    /// Shutdown drain: dropping the writer must persist everything already
    /// queued before the thread exits.
    #[test]
    fn drop_drains_all_queued_jobs() {
        let repositories = memory_repositories();
        let writer = EvidenceWriter::new(Arc::clone(&repositories));
        for index in 0..25 {
            assert!(
                writer.enqueue(EvidenceWriteJob::RequestLog(request_log(&format!(
                    "fg-drain-{index}"
                ))))
            );
        }
        drop(writer);
        let logs = block_on(repositories.request_logs());
        assert_eq!(logs.len(), 25, "drop must drain the full queue");
        assert_eq!(logs[0].request_id, "fg-drain-0");
        assert_eq!(logs[24].request_id, "fg-drain-24");
    }

    /// Flush is a no-op (and cheap) when the writer never started.
    #[test]
    fn flush_without_use_is_a_no_op() {
        let writer = EvidenceWriter::new(memory_repositories());
        assert!(writer.flush());
        assert_eq!(writer.metrics().enqueued_total, 0);
    }
}
